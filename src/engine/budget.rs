//! Per-request resource bounds for the native engine.
//!
//! The engine must not be able to turn one request into unbounded work. The
//! [`RequestBudget`] tracks arena bytes, allocation count, rule evaluations and
//! transform applications. Every check returns an error, and
//! [`crate::engine::failclosed`] turns that error into a `Block` decision.

use serde::{Deserialize, Serialize};

/// Hard limits for a single request evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceLimits {
    /// Maximum bytes that may be reserved in the request arena.
    pub arena_bytes: usize,
    /// Maximum number of arena allocations.
    pub max_allocations: usize,
    /// Maximum number of rule evaluations.
    pub max_rule_evaluations: usize,
    /// Maximum number of transform applications.
    pub max_transforms: usize,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            arena_bytes: 8 * 1024 * 1024,
            max_allocations: 65_536,
            max_rule_evaluations: 1_000_000,
            max_transforms: 1_000_000,
        }
    }
}

/// Budget failures. All of them are fail-closed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BudgetError {
    /// The arena cannot satisfy an allocation.
    #[error("arena exhausted: requested {requested} bytes, {remaining} remaining")]
    ArenaExhausted { requested: usize, remaining: usize },
    /// The allocation count limit was reached.
    #[error("allocation limit exhausted: {limit} allocations")]
    AllocationLimit { limit: usize },
    /// The rule-evaluation limit was reached.
    #[error("rule evaluation limit exhausted: {limit} evaluations")]
    RuleEvaluationLimit { limit: usize },
    /// The transform limit was reached.
    #[error("transform limit exhausted: {limit} transforms")]
    TransformLimit { limit: usize },
}

/// A reserved region of the request arena.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArenaAllocation {
    /// Byte offset from the start of the arena.
    pub offset: usize,
    /// Length in bytes.
    pub len: usize,
}

/// Tracks resource consumption for one request.
#[derive(Debug, Clone)]
pub struct RequestBudget {
    limits: ResourceLimits,
    arena_used: usize,
    allocations: usize,
    rule_evaluations: usize,
    transforms: usize,
}

impl RequestBudget {
    /// Creates a budget with explicit limits.
    pub fn new(limits: ResourceLimits) -> Self {
        Self {
            limits,
            arena_used: 0,
            allocations: 0,
            rule_evaluations: 0,
            transforms: 0,
        }
    }

    /// Returns the configured limits.
    pub fn limits(&self) -> ResourceLimits {
        self.limits
    }

    /// Bytes reserved in the arena.
    pub fn arena_used(&self) -> usize {
        self.arena_used
    }

    /// Remaining arena bytes.
    pub fn arena_remaining(&self) -> usize {
        self.limits.arena_bytes.saturating_sub(self.arena_used)
    }

    /// Number of allocations performed.
    pub fn allocations(&self) -> usize {
        self.allocations
    }

    /// Number of rule evaluations charged.
    pub fn rule_evaluations(&self) -> usize {
        self.rule_evaluations
    }

    /// Number of transform applications charged.
    pub fn transforms(&self) -> usize {
        self.transforms
    }

    /// Reserves `len` bytes, failing closed when the arena or allocation count
    /// limit would be exceeded.
    pub fn try_alloc(&mut self, len: usize) -> Result<ArenaAllocation, BudgetError> {
        if self.allocations >= self.limits.max_allocations {
            return Err(BudgetError::AllocationLimit {
                limit: self.limits.max_allocations,
            });
        }
        let remaining = self.arena_remaining();
        if len > remaining {
            return Err(BudgetError::ArenaExhausted {
                requested: len,
                remaining,
            });
        }
        let allocation = ArenaAllocation {
            offset: self.arena_used,
            len,
        };
        self.arena_used += len;
        self.allocations += 1;
        Ok(allocation)
    }

    /// Charges one rule evaluation.
    pub fn charge_rule(&mut self) -> Result<(), BudgetError> {
        if self.rule_evaluations >= self.limits.max_rule_evaluations {
            return Err(BudgetError::RuleEvaluationLimit {
                limit: self.limits.max_rule_evaluations,
            });
        }
        self.rule_evaluations += 1;
        Ok(())
    }

    /// Charges one transform application.
    pub fn charge_transform(&mut self) -> Result<(), BudgetError> {
        if self.transforms >= self.limits.max_transforms {
            return Err(BudgetError::TransformLimit {
                limit: self.limits.max_transforms,
            });
        }
        self.transforms += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn small() -> ResourceLimits {
        ResourceLimits {
            arena_bytes: 16,
            max_allocations: 2,
            max_rule_evaluations: 2,
            max_transforms: 2,
        }
    }

    #[test]
    fn allocates_within_the_arena() {
        let mut budget = RequestBudget::new(small());
        assert_eq!(
            budget.try_alloc(8).unwrap(),
            ArenaAllocation { offset: 0, len: 8 }
        );
        assert_eq!(
            budget.try_alloc(8).unwrap(),
            ArenaAllocation { offset: 8, len: 8 }
        );
        assert_eq!(budget.arena_used(), 16);
        assert_eq!(budget.arena_remaining(), 0);
    }

    #[test]
    fn arena_overflow_is_an_error() {
        let mut budget = RequestBudget::new(small());
        budget.try_alloc(16).unwrap();
        assert_eq!(
            budget.try_alloc(1),
            Err(BudgetError::ArenaExhausted {
                requested: 1,
                remaining: 0
            })
        );
    }

    #[test]
    fn allocation_count_is_bounded() {
        let mut budget = RequestBudget::new(small());
        budget.try_alloc(1).unwrap();
        budget.try_alloc(1).unwrap();
        assert_eq!(
            budget.try_alloc(1),
            Err(BudgetError::AllocationLimit { limit: 2 })
        );
    }

    #[test]
    fn rule_and_transform_work_is_bounded() {
        let mut budget = RequestBudget::new(small());
        budget.charge_rule().unwrap();
        budget.charge_rule().unwrap();
        assert_eq!(
            budget.charge_rule(),
            Err(BudgetError::RuleEvaluationLimit { limit: 2 })
        );
        budget.charge_transform().unwrap();
        budget.charge_transform().unwrap();
        assert_eq!(
            budget.charge_transform(),
            Err(BudgetError::TransformLimit { limit: 2 })
        );
    }

    #[test]
    fn regression_budget_exhaustion_fails_closed() {
        use crate::engine::{decide, EngineError};
        use crate::waf::Decision;

        let mut budget = RequestBudget::new(small());
        budget.try_alloc(16).unwrap();
        let error = EngineError::from(budget.try_alloc(16).unwrap_err());
        assert!(matches!(
            decide(Err(error)),
            Decision::Block { status: 503, .. }
        ));
    }
}
