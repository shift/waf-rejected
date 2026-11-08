//! Determinism test runner.
//!
//! The same cases are evaluated repeatedly with shuffled order and multiple
//! threads. Any difference from the baseline decision is a failure. A factory
//! is used instead of a shared engine so engines that are not `Sync` (for
//! example a wasmtime store) can still be exercised per worker.

use std::sync::Arc;
use std::thread;

use serde::{Deserialize, Serialize};

use crate::waf::coraza_corpus::CorpusCase;

use super::generated::SplitMix64;
use super::{EngineError, EngineOutcome, RuleEngine};

/// One observed divergence from the baseline decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeterminismMismatch {
    /// Corpus case id.
    pub case_id: String,
    /// Iteration number.
    pub iteration: usize,
    /// Worker thread index.
    pub thread: usize,
    /// Baseline decision (`allow`, `block`, or `error: ...`).
    pub baseline: String,
    /// Decision observed in this iteration.
    pub observed: String,
}

/// Determinism run result.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DeterminismReport {
    /// Iterations per case.
    pub iterations: usize,
    /// Worker threads.
    pub threads: usize,
    /// Cases exercised.
    pub cases: usize,
    /// Total evaluations compared.
    pub comparisons: usize,
    /// Baseline evaluations that errored.
    pub errors: usize,
    /// Divergences, capped for report size.
    pub mismatches: Vec<DeterminismMismatch>,
    /// True when the mismatch list was capped.
    pub truncated: bool,
}

impl DeterminismReport {
    /// True when every repeated decision matched and no baseline errored.
    pub fn is_clean(&self) -> bool {
        self.mismatches.is_empty() && self.errors == 0
    }
}

/// Runs `iterations` shuffled, multi-threaded passes over `cases`.
pub fn run<F>(
    factory: F,
    cases: &[CorpusCase],
    iterations: usize,
    threads: usize,
    seed: u64,
) -> Result<DeterminismReport, EngineError>
where
    F: Fn() -> Result<Box<dyn RuleEngine>, EngineError> + Sync,
{
    let iterations = iterations.max(1);
    let threads = threads.max(1);
    let baseline_engine = factory()?;
    let baseline: Vec<Result<EngineOutcome, String>> = cases
        .iter()
        .map(|case| {
            baseline_engine
                .evaluate(&case.request)
                .map_err(|error| error.to_string())
        })
        .collect();

    let mut report = DeterminismReport {
        iterations,
        threads,
        cases: cases.len(),
        errors: baseline.iter().filter(|result| result.is_err()).count(),
        ..DeterminismReport::default()
    };

    let baseline = Arc::new(baseline);
    let results: Vec<Result<Vec<DeterminismMismatch>, EngineError>> = thread::scope(|scope| {
        let mut handles = Vec::with_capacity(threads);
        for worker in 0..threads {
            let baseline = Arc::clone(&baseline);
            let factory = &factory;
            handles.push(scope.spawn(move || {
                let engine = factory()?;
                let mut rng = SplitMix64::new(seed ^ (worker as u64).wrapping_mul(0x9e37_79b9));
                let mut indices: Vec<usize> = (worker..cases.len()).step_by(threads).collect();
                let mut mismatches = Vec::new();

                for iteration in 0..iterations {
                    rng.shuffle(&mut indices);
                    for &index in &indices {
                        let observed = engine
                            .evaluate(&cases[index].request)
                            .map_err(|error| error.to_string());
                        if !same_result(&baseline[index], &observed) {
                            mismatches.push(DeterminismMismatch {
                                case_id: cases[index].id.clone(),
                                iteration,
                                thread: worker,
                                baseline: describe(&baseline[index]),
                                observed: describe(&observed),
                            });
                        }
                    }
                }
                Ok(mismatches)
            }));
        }

        handles
            .into_iter()
            .map(|handle| {
                handle.join().unwrap_or_else(|_| {
                    Err(EngineError::Internal(
                        "determinism worker panicked".to_string(),
                    ))
                })
            })
            .collect()
    });

    for result in results {
        for mismatch in result? {
            if report.mismatches.len() < 1000 {
                report.mismatches.push(mismatch);
            } else {
                report.truncated = true;
            }
        }
    }
    report.comparisons = cases.len() * iterations;
    Ok(report)
}

fn same_result(
    left: &Result<EngineOutcome, String>,
    right: &Result<EngineOutcome, String>,
) -> bool {
    match (left, right) {
        (Ok(left), Ok(right)) => left == right,
        (Err(left), Err(right)) => left == right,
        _ => false,
    }
}

fn describe(result: &Result<EngineOutcome, String>) -> String {
    match result {
        Ok(outcome) => outcome.as_str().to_string(),
        Err(error) => format!("error: {error}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::waf::coraza_corpus::CorpusRequest;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn case(id: &str) -> CorpusCase {
        CorpusCase {
            id: id.to_string(),
            description: id.to_string(),
            request: CorpusRequest {
                method: "GET".to_string(),
                uri: format!("/{id}"),
                http_version: "HTTP/1.1".to_string(),
                headers: Default::default(),
                body: None,
            },
            expected: crate::waf::coraza_corpus::Expected::Allow,
            expected_rule_ids: Vec::new(),
            tags: vec!["test".to_string()],
            source: None,
        }
    }

    struct Fixed(EngineOutcome);

    impl RuleEngine for Fixed {
        fn name(&self) -> &str {
            "fixed"
        }
        fn evaluate(&self, _request: &CorpusRequest) -> Result<EngineOutcome, EngineError> {
            Ok(self.0)
        }
    }

    struct Alternating {
        counter: Arc<AtomicUsize>,
    }

    impl RuleEngine for Alternating {
        fn name(&self) -> &str {
            "alternating"
        }
        fn evaluate(&self, _request: &CorpusRequest) -> Result<EngineOutcome, EngineError> {
            let value = self.counter.fetch_add(1, Ordering::SeqCst);
            if value.is_multiple_of(2) {
                Ok(EngineOutcome::Allow)
            } else {
                Ok(EngineOutcome::Block)
            }
        }
    }

    #[test]
    fn deterministic_engine_is_clean() {
        let cases = vec![case("a"), case("b"), case("c")];
        let report = run(
            || Ok(Box::new(Fixed(EngineOutcome::Allow))),
            &cases,
            100,
            4,
            7,
        )
        .expect("run");
        assert!(report.is_clean());
        assert_eq!(report.comparisons, 300);
        assert_eq!(report.cases, 3);
    }

    #[test]
    fn alternating_engine_is_detected() {
        let cases = vec![case("a"), case("b")];
        let counter = Arc::new(AtomicUsize::new(0));
        let report = run(
            {
                let counter = Arc::clone(&counter);
                move || {
                    Ok(Box::new(Alternating {
                        counter: Arc::clone(&counter),
                    }))
                }
            },
            &cases,
            10,
            2,
            7,
        )
        .expect("run");
        assert!(!report.is_clean());
        assert!(!report.mismatches.is_empty());
    }

    #[test]
    fn factory_errors_are_returned() {
        let cases = vec![case("a")];
        let result = run(
            || Err(EngineError::Unavailable("not linked".to_string())),
            &cases,
            2,
            1,
            7,
        );
        assert!(matches!(result, Err(EngineError::Unavailable(_))));
    }

    #[test]
    fn deterministic_errors_are_reported() {
        struct Broken;
        impl RuleEngine for Broken {
            fn name(&self) -> &str {
                "broken"
            }
            fn evaluate(&self, _request: &CorpusRequest) -> Result<EngineOutcome, EngineError> {
                Err(EngineError::Internal("same error".to_string()))
            }
        }
        let cases = vec![case("a")];
        let report = run(|| Ok(Box::new(Broken)), &cases, 5, 2, 7).expect("run");
        assert_eq!(report.errors, 1);
        assert!(report.mismatches.is_empty());
        assert!(!report.is_clean());
    }
}
