//! Versioned OWASP CRS detection corpus.
//!
//! The corpus is a decision-level projection of the upstream CRS regression
//! suite. It records the request bytes and whether the default PL1 rule bundle
//! is expected to block the request. The loader is deliberately strict: a
//! corpus without provenance, with duplicate case IDs or with an unknown
//! format version is rejected before a single request is evaluated.
//!
//! The on-disk format is documented in `docs/operations/detection-corpus.md`.

use std::collections::{BTreeMap, HashSet};
use std::path::Path;

use serde::{Deserialize, Serialize};

/// Current on-disk corpus format version.
pub const CORPUS_FORMAT_VERSION: u32 = 1;

/// Default corpus shipped with the repository.
pub const DEFAULT_CORPUS_PATH: &str = "tests/corpus/crs/corpus.json";

/// Expected engine decision for a corpus case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Expected {
    /// The request must be blocked.
    Block,
    /// The request must be allowed.
    Allow,
}

impl Expected {
    /// Human-readable label used in reports.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::Allow => "allow",
        }
    }
}

/// Decision observed from an engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Observed {
    /// The engine allowed the request.
    Allow,
    /// The engine blocked the request.
    Block,
}

impl Observed {
    /// Human-readable label used in reports.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Block => "block",
        }
    }
}

/// Result of comparing the expected and observed decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseResult {
    /// Expected and observed decisions agree.
    Pass,
    /// The corpus expected a block and the engine allowed the request.
    FalseNegative,
    /// The corpus expected an allow and the engine blocked the request.
    FalsePositive,
}

/// Maps an expected/observed pair to a corpus result.
pub fn judge(expected: Expected, observed: Observed) -> CaseResult {
    match (expected, observed) {
        (Expected::Block, Observed::Block) | (Expected::Allow, Observed::Allow) => CaseResult::Pass,
        (Expected::Block, Observed::Allow) => CaseResult::FalseNegative,
        (Expected::Allow, Observed::Block) => CaseResult::FalsePositive,
    }
}

/// Upstream provenance for a corpus.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorpusSource {
    /// Upstream project name.
    pub project: String,
    /// Upstream release version.
    pub version: String,
    /// Pinned upstream commit.
    pub commit: String,
    /// Downloadable upstream source URL.
    pub url: String,
    /// SHA-256 of the upstream source archive.
    pub sha256: String,
    /// SPDX licence identifier.
    #[serde(default)]
    pub license: Option<String>,
    /// Upstream path the cases were derived from.
    #[serde(default)]
    pub upstream_path: Option<String>,
    /// Counts of upstream cases excluded during conversion, by reason.
    #[serde(default)]
    pub exclusions: BTreeMap<String, u64>,
    /// SHA-256 of the sorted upstream test-file manifest.
    #[serde(default)]
    pub source_manifest_sha256: Option<String>,
    /// Converter that produced the corpus.
    #[serde(default)]
    pub converter: Option<String>,
    /// Short description of the conversion input.
    #[serde(default)]
    pub generated_from: Option<String>,
}

/// One request and its expected decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorpusCase {
    /// Stable case identifier.
    pub id: String,
    /// Short description copied from the upstream test.
    pub description: String,
    /// Request bytes sent to the engine.
    pub request: CorpusRequest,
    /// Expected engine decision.
    pub expected: Expected,
    /// Upstream rule IDs the case exercises.
    #[serde(default)]
    pub expected_rule_ids: Vec<u32>,
    /// Free-form tags used by `--filter`.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Upstream file and test ID.
    #[serde(default)]
    pub source: Option<CaseSource>,
}

/// Upstream location of a converted case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaseSource {
    /// Path relative to the upstream regression test directory.
    pub file: String,
    /// Upstream test ID within the file.
    pub test_id: serde_json::Value,
    /// Upstream rule ID.
    #[serde(default)]
    pub rule_id: Option<u32>,
}

/// Request representation shared by every engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorpusRequest {
    /// HTTP method.
    pub method: String,
    /// Raw request URI, exactly as sent by the upstream test client.
    pub uri: String,
    /// HTTP version string, e.g. `HTTP/1.1`.
    #[serde(default = "default_http_version")]
    pub http_version: String,
    /// Request headers.
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    /// Request body, if any.
    #[serde(default)]
    pub body: Option<String>,
}

fn default_http_version() -> String {
    "HTTP/1.1".to_string()
}

impl CorpusRequest {
    /// Serialises the request into the shared Coraza reactor/sidecar JSON
    /// envelope.
    ///
    /// The envelope is intentionally built here rather than through
    /// `RequestContext`: upstream cases contain raw URIs that `http::Uri`
    /// rejects (spaces, backslashes, non-ASCII), and the engines must see the
    /// same bytes the upstream client sent.
    pub fn to_payload(&self) -> Result<Vec<u8>, serde_json::Error> {
        let headers: Vec<(&str, &str)> = self
            .headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect();
        let body_size = self.body.as_ref().map(|body| body.len());
        serde_json::to_vec(&serde_json::json!({
            "method": self.method,
            "uri": self.uri,
            "http_version": self.http_version,
            "headers": headers,
            "body_size": body_size,
            "body_original_size": body_size,
            "body_encoding": "utf8",
            "body": self.body,
        }))
    }
}

/// A versioned corpus.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Corpus {
    /// On-disk format version.
    pub format_version: u32,
    /// Upstream provenance.
    pub source: CorpusSource,
    /// Cases in deterministic order.
    pub cases: Vec<CorpusCase>,
}

/// Corpus loading and validation errors.
#[derive(Debug, thiserror::Error)]
pub enum CorpusError {
    /// The corpus file could not be read.
    #[error("failed to read corpus `{path}`: {detail}")]
    Io { path: String, detail: String },
    /// The corpus is not valid JSON.
    #[error("failed to parse corpus JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// The format version is not supported by this binary.
    #[error("unsupported corpus format version {found}; this binary supports {supported}")]
    UnsupportedFormat { found: u32, supported: u32 },
    /// The corpus is empty.
    #[error("corpus contains no cases")]
    Empty,
    /// A required provenance field is missing or malformed.
    #[error("invalid corpus provenance: {0}")]
    Provenance(String),
    /// Two cases share the same ID.
    #[error("duplicate corpus case id `{0}`")]
    DuplicateId(String),
    /// A case is missing a required field.
    #[error("invalid corpus case `{id}`: {detail}")]
    InvalidCase { id: String, detail: String },
}

impl Corpus {
    /// Loads and validates a corpus from disk.
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, CorpusError> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path).map_err(|err| CorpusError::Io {
            path: path.display().to_string(),
            detail: err.to_string(),
        })?;
        Self::from_json_str(&text)
    }

    /// Parses and validates a corpus from a JSON string.
    pub fn from_json_str(text: &str) -> Result<Self, CorpusError> {
        let corpus: Self = serde_json::from_str(text)?;
        corpus.validate()?;
        Ok(corpus)
    }

    /// Validates format version, provenance and every case.
    pub fn validate(&self) -> Result<(), CorpusError> {
        if self.format_version != CORPUS_FORMAT_VERSION {
            return Err(CorpusError::UnsupportedFormat {
                found: self.format_version,
                supported: CORPUS_FORMAT_VERSION,
            });
        }
        validate_provenance(&self.source)?;
        if self.cases.is_empty() {
            return Err(CorpusError::Empty);
        }

        let mut ids = HashSet::with_capacity(self.cases.len());
        for case in &self.cases {
            if !ids.insert(case.id.as_str()) {
                return Err(CorpusError::DuplicateId(case.id.clone()));
            }
            if case.id.trim().is_empty() {
                return Err(CorpusError::InvalidCase {
                    id: case.id.clone(),
                    detail: "id is empty".to_string(),
                });
            }
            if case.request.method.trim().is_empty() {
                return Err(CorpusError::InvalidCase {
                    id: case.id.clone(),
                    detail: "request.method is empty".to_string(),
                });
            }
            if case.request.uri.trim().is_empty() {
                return Err(CorpusError::InvalidCase {
                    id: case.id.clone(),
                    detail: "request.uri is empty".to_string(),
                });
            }
            if case.tags.is_empty() {
                return Err(CorpusError::InvalidCase {
                    id: case.id.clone(),
                    detail: "tags is empty".to_string(),
                });
            }
        }
        Ok(())
    }

    /// Returns cases matching any of `tags`. An empty filter returns every
    /// case. Tag matching is case-insensitive.
    pub fn filter_by_tags<'a>(&'a self, tags: &[String]) -> Vec<&'a CorpusCase> {
        if tags.is_empty() {
            return self.cases.iter().collect();
        }
        let wanted: HashSet<String> = tags.iter().map(|tag| tag.to_ascii_lowercase()).collect();
        self.cases
            .iter()
            .filter(|case| {
                case.tags
                    .iter()
                    .any(|tag| wanted.contains(&tag.to_ascii_lowercase()))
            })
            .collect()
    }
}

fn validate_provenance(source: &CorpusSource) -> Result<(), CorpusError> {
    if source.project.trim().is_empty() {
        return Err(CorpusError::Provenance("project is empty".to_string()));
    }
    if source.version.trim().is_empty() {
        return Err(CorpusError::Provenance("version is empty".to_string()));
    }
    if source.commit.trim().is_empty() {
        return Err(CorpusError::Provenance("commit is empty".to_string()));
    }
    if source.url.trim().is_empty() {
        return Err(CorpusError::Provenance("url is empty".to_string()));
    }
    if source.sha256.len() != 64 || !source.sha256.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(CorpusError::Provenance(
            "sha256 must be a 64-character hex digest".to_string(),
        ));
    }
    if let Some(manifest) = &source.source_manifest_sha256 {
        if manifest.len() != 64 || !manifest.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(CorpusError::Provenance(
                "source_manifest_sha256 must be a 64-character hex digest".to_string(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = r#"{
        "format_version": 1,
        "source": {
            "project": "OWASP Core Rule Set",
            "version": "4.14.0",
            "commit": "b5b788b5bc50e68836e17995b191f72e848fed75",
            "url": "https://example.invalid/crs.tar.gz",
            "sha256": "c970605a62ae2dc9213d5de775fc5fbbed9423bf0435ce5456d2ffc769702123"
        },
        "cases": [{
            "id": "crs-942100-1",
            "description": "SQL injection",
            "request": {
                "method": "POST",
                "uri": "/post",
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "body": "var=1234 OR 1=1"
            },
            "expected": "block",
            "tags": ["crs", "sqli"]
        }]
    }"#;

    #[test]
    fn loads_a_valid_corpus() {
        let corpus = Corpus::from_json_str(VALID).expect("valid corpus");
        assert_eq!(corpus.cases.len(), 1);
        assert_eq!(corpus.cases[0].request.http_version, "HTTP/1.1");
        assert_eq!(corpus.cases[0].expected, Expected::Block);
    }

    #[test]
    fn rejects_unknown_format_version() {
        let text = VALID.replace("\"format_version\": 1", "\"format_version\": 2");
        assert!(matches!(
            Corpus::from_json_str(&text),
            Err(CorpusError::UnsupportedFormat { found: 2, .. })
        ));
    }

    #[test]
    fn rejects_missing_or_malformed_provenance() {
        let text = VALID.replace(
            "c970605a62ae2dc9213d5de775fc5fbbed9423bf0435ce5456d2ffc769702123",
            "not-a-digest",
        );
        assert!(matches!(
            Corpus::from_json_str(&text),
            Err(CorpusError::Provenance(_))
        ));
    }

    #[test]
    fn rejects_duplicate_ids() {
        let mut corpus = Corpus::from_json_str(VALID).expect("valid corpus");
        let duplicate = corpus.cases[0].clone();
        corpus.cases.push(duplicate);
        assert!(matches!(
            corpus.validate(),
            Err(CorpusError::DuplicateId(id)) if id == "crs-942100-1"
        ));
    }

    #[test]
    fn rejects_empty_cases() {
        let text = VALID.replace(
            r#""cases": [{
            "id": "crs-942100-1",
            "description": "SQL injection",
            "request": {
                "method": "POST",
                "uri": "/post",
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "body": "var=1234 OR 1=1"
            },
            "expected": "block",
            "tags": ["crs", "sqli"]
        }]"#,
            r#""cases": []"#,
        );
        assert!(matches!(
            Corpus::from_json_str(&text),
            Err(CorpusError::Empty)
        ));
    }

    #[test]
    fn maps_every_decision_pair() {
        assert_eq!(judge(Expected::Block, Observed::Block), CaseResult::Pass);
        assert_eq!(judge(Expected::Allow, Observed::Allow), CaseResult::Pass);
        assert_eq!(
            judge(Expected::Block, Observed::Allow),
            CaseResult::FalseNegative
        );
        assert_eq!(
            judge(Expected::Allow, Observed::Block),
            CaseResult::FalsePositive
        );
    }

    #[test]
    fn filters_tags_case_insensitively() {
        let corpus = Corpus::from_json_str(VALID).expect("valid corpus");
        assert_eq!(corpus.filter_by_tags(&[]).len(), 1);
        assert_eq!(corpus.filter_by_tags(&["SQLI".to_string()]).len(), 1);
        assert_eq!(corpus.filter_by_tags(&["xss".to_string()]).len(), 0);
    }

    #[test]
    fn shipped_smoke_corpus_is_valid() {
        let corpus = Corpus::from_json_str(include_str!("../../tests/corpus/crs/smoke.json"))
            .expect("shipped smoke corpus is valid");
        assert!(corpus.cases.len() >= 10);
        let categories: HashSet<&str> = corpus
            .cases
            .iter()
            .filter_map(|case| case.tags.get(2).map(String::as_str))
            .collect();
        for required in [
            "sqli", "xss", "lfi", "rfi", "rce", "php", "java", "protocol",
        ] {
            assert!(
                categories.contains(required),
                "missing {required} smoke case"
            );
        }
        for case in &corpus.cases {
            assert!(
                !case.expected_rule_ids.is_empty(),
                "{} has no upstream rule",
                case.id
            );
        }
    }

    #[test]
    fn shipped_full_corpus_is_valid() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(DEFAULT_CORPUS_PATH);
        let corpus = Corpus::from_path(&path).expect("shipped corpus is valid");
        assert!(corpus.cases.len() > 1000);
        assert!(corpus.source.sha256.len() == 64);
    }

    #[test]
    fn payload_uses_the_shared_envelope() {
        let corpus = Corpus::from_json_str(VALID).expect("valid corpus");
        let payload = corpus.cases[0]
            .request
            .to_payload()
            .expect("payload serialises");
        let value: serde_json::Value = serde_json::from_slice(&payload).expect("valid JSON");
        assert_eq!(value["method"], "POST");
        assert_eq!(value["uri"], "/post");
        assert_eq!(value["http_version"], "HTTP/1.1");
        assert_eq!(value["body"], "var=1234 OR 1=1");
        assert_eq!(value["body_size"], 15);
        assert_eq!(value["body_encoding"], "utf8");
        assert_eq!(value["headers"][0][0], "Content-Type");
    }
}
