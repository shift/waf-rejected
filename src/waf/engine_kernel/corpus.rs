//! Soundness harness over the pinned OWASP CRS corpus.
//!
//! The kernel implements a strict subset of CRS. "Coverage" here means a
//! corpus case whose expected rule ids are all implemented and whose request
//! does not need a body processor the prototype does not have (multipart).
//! False negatives on that subset are a hard failure.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::Deserialize;

use super::state::{Arena, RequestInput};
use super::{Decision, KernelEngine};

#[derive(Debug, Deserialize)]
struct Corpus {
    cases: Vec<CorpusCase>,
}

#[derive(Debug, Deserialize)]
struct CorpusCase {
    id: String,
    request: CorpusRequest,
    expected: String,
    #[serde(default)]
    expected_rule_ids: Vec<u32>,
    #[serde(default)]
    tags: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct CorpusRequest {
    method: String,
    uri: String,
    #[serde(default)]
    headers: BTreeMap<String, String>,
    #[serde(default)]
    body: Option<String>,
}

/// One case that did not match the expected decision.
#[derive(Debug, Clone)]
pub struct CaseFailure {
    pub id: String,
    pub expected_rule_ids: Vec<u32>,
    pub observed: Decision,
}

/// Aggregate result of a corpus run.
#[derive(Debug, Clone, Default)]
pub struct CorpusReport {
    pub total: usize,
    pub covered: usize,
    pub covered_block: usize,
    pub covered_allow: usize,
    pub passed: usize,
    pub false_negatives: Vec<CaseFailure>,
    pub false_positives: Vec<CaseFailure>,
    pub uncovered: usize,
    pub per_rule_cases: BTreeMap<u32, usize>,
}

impl CorpusReport {
    pub fn coverage_percent(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            self.covered as f64 * 100.0 / self.total as f64
        }
    }
}

/// Runs the corpus at `path` through the kernel.
pub fn run_path(path: impl AsRef<Path>) -> Result<CorpusReport, String> {
    let json = std::fs::read_to_string(path.as_ref())
        .map_err(|error| format!("read {}: {error}", path.as_ref().display()))?;
    run_json(&json)
}

/// Runs corpus JSON through the kernel.
pub fn run_json(json: &str) -> Result<CorpusReport, String> {
    let corpus: Corpus =
        serde_json::from_str(json).map_err(|error| format!("parse corpus: {error}"))?;
    let engine = KernelEngine::new()?;
    let implemented: BTreeSet<u32> = engine.rule_ids().iter().copied().collect();
    let mut arena = Arena::new();
    let mut report = CorpusReport {
        total: corpus.cases.len(),
        ..CorpusReport::default()
    };

    for case in &corpus.cases {
        let multipart = case.tags.iter().any(|tag| tag == "multipart")
            || case.request.headers.iter().any(|(name, value)| {
                name.eq_ignore_ascii_case("content-type")
                    && value.to_ascii_lowercase().contains("multipart/form-data")
            });
        let all_implemented = case
            .expected_rule_ids
            .iter()
            .all(|id| implemented.contains(id));
        let covered = !multipart
            && all_implemented
            && !case.expected_rule_ids.is_empty()
            && (case.expected == "block" || case.expected == "allow");
        if !covered {
            report.uncovered += 1;
            continue;
        }
        report.covered += 1;
        if case.expected == "block" {
            report.covered_block += 1;
            for id in &case.expected_rule_ids {
                *report.per_rule_cases.entry(*id).or_default() += 1;
            }
        } else {
            report.covered_allow += 1;
        }

        let headers: Vec<(&str, &str)> = case
            .request
            .headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect();
        let (path, query) = case
            .request
            .uri
            .split_once('?')
            .unwrap_or((case.request.uri.as_str(), ""));
        let body = case.request.body.as_deref().unwrap_or("").as_bytes();
        let request = RequestInput::new(case.request.method.as_str(), path, query, &headers, body);
        let decision = engine.evaluate(&request, &mut arena);
        let expected_block = case.expected == "block";
        if decision.is_block() == expected_block {
            report.passed += 1;
        } else if expected_block {
            report.false_negatives.push(CaseFailure {
                id: case.id.clone(),
                expected_rule_ids: case.expected_rule_ids.clone(),
                observed: decision,
            });
        } else {
            report.false_positives.push(CaseFailure {
                id: case.id.clone(),
                expected_rule_ids: case.expected_rule_ids.clone(),
                observed: decision,
            });
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn covered_subset_has_zero_false_negatives() {
        let report = run_path("tests/corpus/crs/corpus.json").expect("corpus");
        println!(
            "corpus: total={} covered={} ({:.1}%) block={} allow={} passed={} FN={} FP={}",
            report.total,
            report.covered,
            report.coverage_percent(),
            report.covered_block,
            report.covered_allow,
            report.passed,
            report.false_negatives.len(),
            report.false_positives.len()
        );
        for failure in &report.false_negatives {
            println!(
                "FN {} expected={:?} observed={:?}",
                failure.id, failure.expected_rule_ids, failure.observed
            );
        }
        for failure in &report.false_positives {
            println!(
                "FP {} expected={:?} observed={:?}",
                failure.id, failure.expected_rule_ids, failure.observed
            );
        }
        assert!(
            report.false_negatives.is_empty(),
            "{} false negatives on the covered subset",
            report.false_negatives.len()
        );
        assert!(
            report.covered > 500,
            "coverage unexpectedly small: {}",
            report.covered
        );
    }
}
