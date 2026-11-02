//! Fixed per-request work and memory budget.
//!
//! The engine never allocates without charging the budget. When a bound is
//! crossed the evaluation stops with [`EngineError::Budget`] and the caller
//! turns that into a block (fail-closed).

use super::error::EngineError;

/// Compile-time limits copied into every request evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Maximum number of variable values materialised for one rule.
    pub max_values_per_rule: usize,
    /// Maximum size of one transformed value.
    pub max_value_bytes: usize,
    /// Maximum total bytes materialised for one request.
    pub max_total_bytes: usize,
    /// Maximum number of operator matches recorded for one rule.
    pub max_matches_per_rule: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_values_per_rule: 4_096,
            max_value_bytes: 1 << 20,
            max_total_bytes: 8 << 20,
            max_matches_per_rule: 4_096,
        }
    }
}

/// Mutable accounting for one request.
#[derive(Debug, Clone)]
pub struct Budget {
    limits: Limits,
    values: usize,
    bytes: usize,
    matches: usize,
}

impl Budget {
    /// Creates a budget with the supplied limits.
    pub fn new(limits: Limits) -> Self {
        Self {
            limits,
            values: 0,
            bytes: 0,
            matches: 0,
        }
    }

    /// Returns the configured limits.
    pub fn limits(&self) -> Limits {
        self.limits
    }

    /// Charges one materialised value.
    pub fn value(&mut self) -> Result<(), EngineError> {
        self.values += 1;
        if self.values > self.limits.max_values_per_rule {
            return Err(EngineError::Budget("too many variable values"));
        }
        Ok(())
    }

    /// Charges `len` bytes. Also enforces the per-value cap.
    pub fn bytes(&mut self, len: usize) -> Result<(), EngineError> {
        if len > self.limits.max_value_bytes {
            return Err(EngineError::OutputTooLarge);
        }
        self.bytes = self.bytes.saturating_add(len);
        if self.bytes > self.limits.max_total_bytes {
            return Err(EngineError::Budget("too many materialised bytes"));
        }
        Ok(())
    }

    /// Charges one operator match.
    pub fn matched(&mut self) -> Result<(), EngineError> {
        self.matches += 1;
        if self.matches > self.limits.max_matches_per_rule {
            return Err(EngineError::Budget("too many operator matches"));
        }
        Ok(())
    }

    /// Bytes charged so far (used by diagnostics/tests).
    pub fn used_bytes(&self) -> usize {
        self.bytes
    }
}
