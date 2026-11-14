//! Enforceable guarantees for the native Rust WAF engine.
//!
//! The native engine replacement is only acceptable if the guarantees below
//! are *tested*, not merely claimed:
//!
//! * [`accounting`] proves that every pinned CRS rule construct is either
//!   implemented or makes the build fail.
//! * [`differential`] compares the native decision against Coraza on the pinned
//!   corpus and on generated inputs, and persists minimal counterexamples.
//! * [`determinism`] proves that repeated, shuffled, multi-threaded evaluation
//!   returns identical decisions.
//! * [`budget`] bounds per-request work and fails closed when the budget is
//!   exhausted.
//! * [`failclosed`] maps every internal engine error to `Block`.
//!
//! The engine workstream plugs its implementation into [`backend`] (behind the
//! non-default `native-engine` feature). Nothing in this module depends on that
//! implementation being merged: the guarantees, the parser, the generator and
//! the tests all run against the reference Coraza backends or small test
//! doubles.

pub mod accounting;
pub mod budget;
pub mod determinism;
pub mod differential;
pub mod failclosed;
pub mod generated;

/// Feature that enables the native Rust engine adapter.
pub const ENGINE_FEATURE: &str = "native-engine";

#[cfg(feature = "native-engine")]
pub mod backend;

use serde::{Deserialize, Serialize};

use crate::waf::coraza_corpus::CorpusRequest;
use crate::waf::Decision;

/// Decision produced by a rule engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EngineOutcome {
    /// The request may proceed.
    Allow,
    /// The request must be blocked.
    Block,
}

impl EngineOutcome {
    /// Stable lowercase label used in reports.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Block => "block",
        }
    }
}

impl From<EngineOutcome> for Decision {
    fn from(outcome: EngineOutcome) -> Self {
        match outcome {
            EngineOutcome::Allow => Decision::Allow,
            EngineOutcome::Block => Decision::Block {
                status: 403,
                reason: "native engine rule match".to_string(),
            },
        }
    }
}

/// Errors an engine may surface. Every variant is fail-closed by
/// [`failclosed::decide`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EngineError {
    /// The native backend has not been linked into this build.
    #[error("native engine backend is unavailable: {0}")]
    Unavailable(String),
    /// A rule uses an operator the engine does not implement.
    #[error("unsupported operator `{0}`")]
    UnsupportedOperator(String),
    /// A rule uses a transform the engine does not implement.
    #[error("unsupported transform `{0}`")]
    UnsupportedTransform(String),
    /// A rule uses an action the engine does not implement.
    #[error("unsupported action `{0}`")]
    UnsupportedAction(String),
    /// The rule IR is structurally invalid.
    #[error("malformed rule IR: {0}")]
    MalformedRuleIr(String),
    /// A per-request resource budget was exhausted.
    #[error("request budget exhausted: {0}")]
    BudgetExhausted(#[from] budget::BudgetError),
    /// Any other internal failure.
    #[error("engine internal error: {0}")]
    Internal(String),
}

/// Minimal contract the native engine must implement for the guarantee tests.
pub trait RuleEngine: Send {
    /// Human-readable engine name.
    fn name(&self) -> &str;

    /// Evaluates one request. Errors are fail-closed and must never allow.
    fn evaluate(&self, request: &CorpusRequest) -> Result<EngineOutcome, EngineError>;
}

/// Maps an engine result to a WAF decision, blocking on every error.
pub fn decide(result: Result<EngineOutcome, EngineError>) -> Decision {
    failclosed::decide(result)
}

#[cfg(feature = "native-engine")]
pub use backend::NativeRustEngine;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::budget::{BudgetError, RequestBudget, ResourceLimits};

    fn request() -> CorpusRequest {
        CorpusRequest {
            method: "GET".to_string(),
            uri: "/".to_string(),
            http_version: "HTTP/1.1".to_string(),
            headers: Default::default(),
            body: None,
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

    #[test]
    fn outcome_maps_to_decision() {
        assert_eq!(decide(Ok(EngineOutcome::Allow)), Decision::Allow);
        assert!(matches!(
            decide(Ok(EngineOutcome::Block)),
            Decision::Block { status: 403, .. }
        ));
    }

    #[test]
    fn internal_errors_block() {
        for error in [
            EngineError::Unavailable("not linked".into()),
            EngineError::UnsupportedOperator("nope".into()),
            EngineError::UnsupportedTransform("nope".into()),
            EngineError::UnsupportedAction("nope".into()),
            EngineError::MalformedRuleIr("missing operator".into()),
            EngineError::Internal("boom".into()),
        ] {
            assert!(
                matches!(decide(Err(error)), Decision::Block { .. }),
                "error must fail closed"
            );
        }
    }

    #[test]
    fn budget_exhaustion_blocks() {
        let mut budget = RequestBudget::new(ResourceLimits {
            arena_bytes: 8,
            max_allocations: 2,
            max_rule_evaluations: 1,
            max_transforms: 1,
        });
        budget.try_alloc(8).expect("first allocation fits");
        let error: EngineError = budget.try_alloc(1).expect_err("arena is full").into();
        assert!(matches!(
            error,
            EngineError::BudgetExhausted(BudgetError::ArenaExhausted { .. })
        ));
        assert!(matches!(decide(Err(error)), Decision::Block { .. }));
    }

    #[test]
    fn fixed_engine_contract_is_usable() {
        let engine = Fixed(EngineOutcome::Allow);
        assert_eq!(engine.evaluate(&request()).unwrap(), EngineOutcome::Allow);
    }
}
