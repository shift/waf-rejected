//! Differential harness between Coraza and the native engine.
//!
//! A mismatch is any difference between the two decisions, including a native
//! engine error where Coraza produced a decision. Mismatches are minimized with
//! delta debugging and can be persisted as a regression corpus.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::waf::coraza_corpus::CorpusRequest;

use super::generated::GeneratedRequest;
use super::{EngineOutcome, RuleEngine};

/// Current on-disk counterexample format version.
pub const COUNTEREXAMPLE_FORMAT_VERSION: u32 = 1;

/// Default location of the persisted regression corpus.
pub const DEFAULT_COUNTEREXAMPLE_PATH: &str = "tests/corpus/engine/counterexamples.json";

/// One engine disagreement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mismatch {
    /// Generated case id.
    pub id: String,
    /// Generator tags.
    pub tags: Vec<String>,
    /// Reference (Coraza) decision.
    pub reference: Option<EngineOutcome>,
    /// Native engine decision.
    pub candidate: Option<EngineOutcome>,
    /// Reference error, if any.
    pub reference_error: Option<String>,
    /// Native engine error, if any.
    pub candidate_error: Option<String>,
    /// The request that disagreed.
    pub request: CorpusRequest,
}

/// Result of a differential run.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DifferentialReport {
    /// Cases compared.
    pub compared: usize,
    /// Cases where both engines returned the same decision.
    pub agree: usize,
    /// Cases where the decisions differ or an engine errored.
    pub disagree: usize,
    /// Reference evaluations that errored.
    pub reference_errors: usize,
    /// Candidate evaluations that errored.
    pub candidate_errors: usize,
    /// Disagreements, capped for report size.
    pub mismatches: Vec<Mismatch>,
    /// Minimized counterexamples produced from the disagreements.
    pub counterexamples: Vec<GeneratedRequest>,
}

impl DifferentialReport {
    /// True when every compared case agreed and neither engine errored.
    pub fn is_clean(&self) -> bool {
        self.disagree == 0 && self.reference_errors == 0 && self.candidate_errors == 0
    }
}

/// Compares `candidate` against `reference` on every generated case.
pub fn compare(
    reference: &dyn RuleEngine,
    candidate: &dyn RuleEngine,
    cases: &[GeneratedRequest],
) -> DifferentialReport {
    let mut report = DifferentialReport {
        compared: cases.len(),
        ..DifferentialReport::default()
    };

    for case in cases {
        let reference_result = evaluate(reference, &case.request);
        let candidate_result = evaluate(candidate, &case.request);
        if reference_result.is_err() {
            report.reference_errors += 1;
        }
        if candidate_result.is_err() {
            report.candidate_errors += 1;
        }
        if results_agree(&reference_result, &candidate_result) {
            report.agree += 1;
            continue;
        }
        report.disagree += 1;
        if report.mismatches.len() < 1000 {
            report.mismatches.push(Mismatch {
                id: case.id.clone(),
                tags: case.tags.clone(),
                reference: reference_result.as_ref().ok().copied(),
                candidate: candidate_result.as_ref().ok().copied(),
                reference_error: reference_result.as_ref().err().cloned(),
                candidate_error: candidate_result.as_ref().err().cloned(),
                request: case.request.clone(),
            });
        }
    }

    report.counterexamples = report
        .mismatches
        .iter()
        .take(64)
        .map(|mismatch| {
            let case = GeneratedRequest {
                id: mismatch.id.clone(),
                tags: mismatch.tags.clone(),
                request: mismatch.request.clone(),
            };
            minimize_mismatch(reference, candidate, &case)
        })
        .collect();

    report
}

fn evaluate(engine: &dyn RuleEngine, request: &CorpusRequest) -> Result<EngineOutcome, String> {
    engine.evaluate(request).map_err(|error| error.to_string())
}

fn results_agree(
    reference: &Result<EngineOutcome, String>,
    candidate: &Result<EngineOutcome, String>,
) -> bool {
    match (reference, candidate) {
        (Ok(left), Ok(right)) => left == right,
        (Err(left), Err(right)) => left == right,
        _ => false,
    }
}

fn is_mismatch(
    reference: &dyn RuleEngine,
    candidate: &dyn RuleEngine,
    request: &CorpusRequest,
) -> bool {
    let reference = evaluate(reference, request);
    let candidate = evaluate(candidate, request);
    !results_agree(&reference, &candidate)
}

/// Minimizes a disagreeing request with greedy delta debugging.
///
/// The returned request still disagrees. Headers, URI and body are reduced
/// independently so the persisted corpus stays small and reviewable.
pub fn minimize_mismatch(
    reference: &dyn RuleEngine,
    candidate: &dyn RuleEngine,
    case: &GeneratedRequest,
) -> GeneratedRequest {
    let mut best = case.clone();

    loop {
        let mut changed = false;

        for name in best.request.headers.keys().cloned().collect::<Vec<_>>() {
            if name.eq_ignore_ascii_case("host") {
                continue;
            }
            let mut trial = best.clone();
            trial.request.headers.remove(&name);
            if is_mismatch(reference, candidate, &trial.request) {
                best = trial;
                changed = true;
                break;
            }
        }
        if changed {
            continue;
        }

        if let Some(body) = best.request.body.clone() {
            if let Some(reduced) = shrink(&body, |candidate_body| {
                let mut trial = best.clone();
                trial.request.body = Some(candidate_body.to_string());
                is_mismatch(reference, candidate, &trial.request)
            }) {
                best.request.body = Some(reduced);
                changed = true;
            }
        }
        if changed {
            continue;
        }

        if let Some(reduced) = shrink(&best.request.uri, |candidate_uri| {
            let mut trial = best.clone();
            trial.request.uri = candidate_uri.to_string();
            is_mismatch(reference, candidate, &trial.request)
        }) {
            best.request.uri = reduced;
            changed = true;
        }

        if !changed {
            break;
        }
    }

    best
}

/// Greedily removes chunks from `value` while `still_mismatch` holds.
fn shrink<F>(value: &str, mut still_mismatch: F) -> Option<String>
where
    F: FnMut(&str) -> bool,
{
    let mut chars: Vec<char> = value.chars().collect();
    if chars.is_empty() {
        return None;
    }
    let mut chunk = chars.len() / 2;

    while chunk > 0 {
        let mut index = 0;
        while index < chars.len() {
            let end = (index + chunk).min(chars.len());
            let mut trial: Vec<char> = Vec::with_capacity(chars.len() - (end - index));
            trial.extend_from_slice(&chars[..index]);
            trial.extend_from_slice(&chars[end..]);
            let trial: String = trial.into_iter().collect();
            if still_mismatch(&trial) {
                chars = trial.chars().collect();
            } else {
                index = end;
            }
        }
        chunk /= 2;
    }

    let best: String = chars.into_iter().collect();
    if best == value {
        None
    } else {
        Some(best)
    }
}

/// One persisted counterexample.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counterexample {
    /// Stable id.
    pub id: String,
    /// Generator tags.
    pub tags: Vec<String>,
    /// The minimal request.
    pub request: CorpusRequest,
    /// Reference decision.
    pub reference: Option<EngineOutcome>,
    /// Native decision.
    pub candidate: Option<EngineOutcome>,
    /// Reference error, if any.
    pub reference_error: Option<String>,
    /// Native engine error, if any.
    pub candidate_error: Option<String>,
}

/// On-disk counterexample corpus.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CounterexampleFile {
    /// Format version.
    pub format_version: u32,
    /// Minimal regression cases.
    pub cases: Vec<Counterexample>,
}

impl CounterexampleFile {
    /// Loads a corpus, returning an empty one when the file is absent.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, DifferentialError> {
        let path = path.as_ref();
        if !path.exists() {
            return Ok(Self {
                format_version: COUNTEREXAMPLE_FORMAT_VERSION,
                cases: Vec::new(),
            });
        }
        let text = fs::read_to_string(path).map_err(|source| DifferentialError::Io {
            path: path.display().to_string(),
            source,
        })?;
        let file: Self = serde_json::from_str(&text)?;
        if file.format_version != COUNTEREXAMPLE_FORMAT_VERSION {
            return Err(DifferentialError::UnsupportedFormat {
                found: file.format_version,
                supported: COUNTEREXAMPLE_FORMAT_VERSION,
            });
        }
        Ok(file)
    }

    /// Writes the corpus, creating parent directories.
    pub fn write(&self, path: impl AsRef<Path>) -> Result<(), DifferentialError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|source| DifferentialError::Io {
                    path: parent.display().to_string(),
                    source,
                })?;
            }
        }
        let mut text = serde_json::to_string_pretty(self)?;
        text.push('\n');
        fs::write(path, text).map_err(|source| DifferentialError::Io {
            path: path.display().to_string(),
            source,
        })
    }
}

/// Merges minimized counterexamples into the persisted corpus.
///
/// Existing cases are preserved and duplicates are removed by request bytes.
pub fn persist_counterexamples(
    path: impl AsRef<Path>,
    mismatches: &[Mismatch],
    counterexamples: &[GeneratedRequest],
) -> Result<usize, DifferentialError> {
    let path = path.as_ref();
    let mut file = CounterexampleFile::load(path)?;
    let mut known: BTreeSet<String> = file
        .cases
        .iter()
        .map(|case| fingerprint(&case.request))
        .collect();
    let mut added = 0;

    for (mismatch, counterexample) in mismatches.iter().zip(counterexamples.iter()) {
        let key = fingerprint(&counterexample.request);
        if !known.insert(key) {
            continue;
        }
        file.cases.push(Counterexample {
            id: counterexample.id.clone(),
            tags: counterexample.tags.clone(),
            request: counterexample.request.clone(),
            reference: mismatch.reference,
            candidate: mismatch.candidate,
            reference_error: mismatch.reference_error.clone(),
            candidate_error: mismatch.candidate_error.clone(),
        });
        added += 1;
    }

    file.cases.sort_by(|left, right| left.id.cmp(&right.id));
    file.write(path)?;
    Ok(added)
}

/// Returns the default counterexample path for a repository root.
pub fn default_counterexample_path(root: impl AsRef<Path>) -> PathBuf {
    root.as_ref().join(DEFAULT_COUNTEREXAMPLE_PATH)
}

fn fingerprint(request: &CorpusRequest) -> String {
    serde_json::to_string(request).unwrap_or_default()
}

/// Counterexample persistence errors.
#[derive(Debug, thiserror::Error)]
pub enum DifferentialError {
    /// File I/O failed.
    #[error("failed to access {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    /// JSON parsing or serialisation failed.
    #[error("counterexample JSON error: {0}")]
    Json(#[from] serde_json::Error),
    /// The on-disk format is unsupported.
    #[error("unsupported counterexample format version {found}; this binary supports {supported}")]
    UnsupportedFormat { found: u32, supported: u32 },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::EngineError;
    use std::collections::BTreeMap;

    struct ContainsEngine {
        needle: String,
        decision: EngineOutcome,
    }

    impl RuleEngine for ContainsEngine {
        fn name(&self) -> &str {
            "contains"
        }

        fn evaluate(&self, request: &CorpusRequest) -> Result<EngineOutcome, EngineError> {
            let haystack = format!(
                "{} {} {}",
                request.uri,
                request.body.as_deref().unwrap_or(""),
                request
                    .headers
                    .values()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(" ")
            );
            if haystack.contains(&self.needle) {
                Ok(self.decision)
            } else {
                Ok(EngineOutcome::Allow)
            }
        }
    }

    struct Always(EngineOutcome);

    impl RuleEngine for Always {
        fn name(&self) -> &str {
            "always"
        }

        fn evaluate(&self, _request: &CorpusRequest) -> Result<EngineOutcome, EngineError> {
            Ok(self.0)
        }
    }

    fn case(body: &str) -> GeneratedRequest {
        let mut headers = BTreeMap::new();
        headers.insert("Host".to_string(), "localhost".to_string());
        headers.insert("X-Noise".to_string(), "remove me".to_string());
        headers.insert(
            "Content-Type".to_string(),
            "application/x-www-form-urlencoded".to_string(),
        );
        GeneratedRequest {
            id: "gen-test".to_string(),
            tags: vec!["generated".to_string()],
            request: CorpusRequest {
                method: "POST".to_string(),
                uri: "/search?noise=1&q=keep".to_string(),
                http_version: "HTTP/1.1".to_string(),
                headers,
                body: Some(body.to_string()),
            },
        }
    }

    #[test]
    fn detects_decision_mismatch() {
        let reference = ContainsEngine {
            needle: "BLOCK".to_string(),
            decision: EngineOutcome::Block,
        };
        let candidate = Always(EngineOutcome::Allow);
        let report = compare(&reference, &candidate, &[case("noise=1&q=BLOCK&noise=2")]);
        assert_eq!(report.compared, 1);
        assert_eq!(report.disagree, 1);
        assert!(!report.is_clean());
        assert_eq!(report.mismatches[0].reference, Some(EngineOutcome::Block));
        assert_eq!(report.mismatches[0].candidate, Some(EngineOutcome::Allow));
    }

    #[test]
    fn minimizes_to_the_triggering_bytes() {
        let reference = ContainsEngine {
            needle: "BLOCK".to_string(),
            decision: EngineOutcome::Block,
        };
        let candidate = Always(EngineOutcome::Allow);
        let original = case("noise=1&q=BLOCK&noise=2");
        let minimized = minimize_mismatch(&reference, &candidate, &original);
        assert!(minimized
            .request
            .body
            .as_deref()
            .unwrap_or("")
            .contains("BLOCK"));
        assert!(
            minimized.request.body.as_deref().unwrap_or("").len()
                < original.request.body.as_deref().unwrap_or("").len()
        );
        assert!(!minimized.request.headers.contains_key("X-Noise"));
    }

    #[test]
    fn engine_errors_are_mismatches() {
        struct Broken;
        impl RuleEngine for Broken {
            fn name(&self) -> &str {
                "broken"
            }
            fn evaluate(&self, _request: &CorpusRequest) -> Result<EngineOutcome, EngineError> {
                Err(EngineError::Internal("boom".to_string()))
            }
        }
        let report = compare(&Always(EngineOutcome::Allow), &Broken, &[case("q=1")]);
        assert_eq!(report.candidate_errors, 1);
        assert_eq!(report.disagree, 1);
        assert!(report.mismatches[0]
            .candidate_error
            .as_deref()
            .unwrap_or("")
            .contains("boom"));
    }

    #[test]
    fn persists_and_deduplicates_counterexamples() {
        let directory = std::env::temp_dir().join(format!(
            "waf-engine-diff-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let path = directory.join("counterexamples.json");
        let reference = ContainsEngine {
            needle: "BLOCK".to_string(),
            decision: EngineOutcome::Block,
        };
        let candidate = Always(EngineOutcome::Allow);
        let original = case("q=BLOCK");
        let report = compare(&reference, &candidate, std::slice::from_ref(&original));

        let added = persist_counterexamples(&path, &report.mismatches, &report.counterexamples)
            .expect("persists");
        assert_eq!(added, 1);
        let loaded = CounterexampleFile::load(&path).expect("loads");
        assert_eq!(loaded.cases.len(), 1);

        let added_again =
            persist_counterexamples(&path, &report.mismatches, &report.counterexamples)
                .expect("persists again");
        assert_eq!(added_again, 0);
        let loaded = CounterexampleFile::load(&path).expect("loads");
        assert_eq!(loaded.cases.len(), 1);

        fs::remove_dir_all(directory).ok();
    }
}
