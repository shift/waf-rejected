//! Fail-closed policy and rule-IR validation.
//!
//! Every internal engine failure must produce a `Block`, never an `Allow`.
//! [`decide`] is the single mapping point. [`validate_rule_ir`] is a minimal
//! structural check the engine can run before accepting a compiled rule set;
//! malformed IR is treated like any other internal error.

use crate::waf::Decision;

use super::{EngineError, EngineOutcome};

/// Status returned when the engine itself fails. The request is blocked.
pub const FAIL_CLOSED_STATUS: u16 = 503;

/// Maps an engine result to a decision, blocking on every error.
pub fn decide(result: Result<EngineOutcome, EngineError>) -> Decision {
    match result {
        Ok(EngineOutcome::Allow) => Decision::Allow,
        Ok(EngineOutcome::Block) => Decision::Block {
            status: 403,
            reason: "native engine rule match".to_string(),
        },
        Err(error) => Decision::Block {
            status: FAIL_CLOSED_STATUS,
            reason: format!("native engine fail-closed: {error}"),
        },
    }
}

/// Minimal rule IR shape used to demonstrate malformed-IR handling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleIr {
    /// Rule id.
    pub id: u32,
    /// Operator name.
    pub operator: String,
    /// Target variables.
    pub targets: Vec<String>,
    /// Transform chain.
    pub transforms: Vec<String>,
}

impl RuleIr {
    /// Validates one rule.
    pub fn validate(&self) -> Result<(), EngineError> {
        if self.id == 0 {
            return Err(EngineError::MalformedRuleIr(
                "rule id must be non-zero".to_string(),
            ));
        }
        if self.operator.trim().is_empty() {
            return Err(EngineError::MalformedRuleIr(format!(
                "rule {} has an empty operator",
                self.id
            )));
        }
        if self.targets.is_empty() {
            return Err(EngineError::MalformedRuleIr(format!(
                "rule {} has no targets",
                self.id
            )));
        }
        if self.targets.iter().any(|target| target.trim().is_empty()) {
            return Err(EngineError::MalformedRuleIr(format!(
                "rule {} has an empty target",
                self.id
            )));
        }
        if self
            .transforms
            .iter()
            .any(|transform| transform.trim().is_empty())
        {
            return Err(EngineError::MalformedRuleIr(format!(
                "rule {} has an empty transform",
                self.id
            )));
        }
        Ok(())
    }
}

/// Validates a compiled rule set. An empty set is an internal error, not a
/// silent "allow everything" policy.
pub fn validate_rule_ir(rules: &[RuleIr]) -> Result<(), EngineError> {
    if rules.is_empty() {
        return Err(EngineError::MalformedRuleIr(
            "compiled rule set is empty".to_string(),
        ));
    }
    let mut ids = std::collections::BTreeSet::new();
    for rule in rules {
        rule.validate()?;
        if !ids.insert(rule.id) {
            return Err(EngineError::MalformedRuleIr(format!(
                "duplicate rule id {}",
                rule.id
            )));
        }
    }
    Ok(())
}

/// Validates a rule set and then evaluates a pre-computed outcome.
///
/// This keeps the malformed-IR path on the same fail-closed mapping as runtime
/// errors.
pub fn validate_then_decide(
    rules: &[RuleIr],
    outcome: Result<EngineOutcome, EngineError>,
) -> Decision {
    match validate_rule_ir(rules) {
        Ok(()) => decide(outcome),
        Err(error) => decide(Err(error)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_rule() -> RuleIr {
        RuleIr {
            id: 942100,
            operator: "rx".to_string(),
            targets: vec!["ARGS".to_string()],
            transforms: vec!["urlDecodeUni".to_string()],
        }
    }

    #[test]
    fn allow_and_block_map_directly() {
        assert_eq!(decide(Ok(EngineOutcome::Allow)), Decision::Allow);
        assert!(matches!(
            decide(Ok(EngineOutcome::Block)),
            Decision::Block { status: 403, .. }
        ));
    }

    #[test]
    fn unsupported_operator_at_runtime_blocks() {
        let decision = decide(Err(EngineError::UnsupportedOperator("nope".to_string())));
        assert!(matches!(
            decision,
            Decision::Block {
                status: FAIL_CLOSED_STATUS,
                ..
            }
        ));
    }

    #[test]
    fn arena_overflow_blocks() {
        use crate::engine::budget::{BudgetError, RequestBudget, ResourceLimits};

        let mut budget = RequestBudget::new(ResourceLimits {
            arena_bytes: 0,
            max_allocations: 1,
            max_rule_evaluations: 1,
            max_transforms: 1,
        });
        let error = budget.try_alloc(1).unwrap_err();
        assert_eq!(
            error,
            BudgetError::ArenaExhausted {
                requested: 1,
                remaining: 0
            }
        );
        assert!(matches!(
            decide(Err(error.into())),
            Decision::Block {
                status: FAIL_CLOSED_STATUS,
                ..
            }
        ));
    }

    #[test]
    fn malformed_rule_ir_blocks() {
        let mut rule = valid_rule();
        rule.operator.clear();
        assert!(matches!(
            validate_rule_ir(&[rule.clone()]),
            Err(EngineError::MalformedRuleIr(_))
        ));
        assert!(matches!(
            validate_then_decide(&[rule], Ok(EngineOutcome::Allow)),
            Decision::Block {
                status: FAIL_CLOSED_STATUS,
                ..
            }
        ));
    }

    #[test]
    fn empty_rule_set_blocks() {
        assert!(matches!(
            validate_rule_ir(&[]),
            Err(EngineError::MalformedRuleIr(_))
        ));
    }

    #[test]
    fn duplicate_rule_ids_are_malformed() {
        assert!(matches!(
            validate_rule_ir(&[valid_rule(), valid_rule()]),
            Err(EngineError::MalformedRuleIr(_))
        ));
    }

    #[test]
    fn valid_rule_ir_passes() {
        validate_rule_ir(&[valid_rule()]).expect("valid rule");
    }
}
