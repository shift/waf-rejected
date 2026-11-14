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

impl Limits {
    /// Default per-value cap. Tests and embedders that do not know the
    /// transport body cap use this baseline.
    pub const DEFAULT_MAX_VALUE_BYTES: usize = 1 << 20;
    /// Default request-wide materialisation cap.
    pub const DEFAULT_MAX_TOTAL_BYTES: usize = 8 << 20;

    /// Limits aligned with the transport's accepted request-body size.
    ///
    /// The serving path derives the per-value cap from
    /// `server.max_body_size`, so anything the proxy accepts can be charged to
    /// the budget and inspected. The compiler default stays the floor: a
    /// config that accepts less than 1 MiB still gets the historical cap.
    ///
    /// The request-wide cap is 32 times the per-value cap. A body is charged
    /// once when it is processed, extracted values are charged when rules
    /// materialise them, and each distinct transform pipeline can materialise
    /// one more copy. The bound scales with the body, not with the number of
    /// rules: rules that never read the body cost nothing and share the cached
    /// transforms.
    pub fn for_body_cap(max_body_size: usize) -> Self {
        Self::for_value_cap(max_body_size)
    }

    /// Limits for an explicit per-value cap.
    ///
    /// Used when the operator configures `waf.coraza.max_value_bytes`; the
    /// compiler default remains the floor.
    pub fn for_value_cap(max_value_bytes: usize) -> Self {
        let max_value_bytes = max_value_bytes.max(Self::DEFAULT_MAX_VALUE_BYTES);
        Self {
            max_values_per_rule: 4_096,
            max_value_bytes,
            max_total_bytes: max_value_bytes
                .saturating_mul(32)
                .max(Self::DEFAULT_MAX_TOTAL_BYTES),
            max_matches_per_rule: 4_096,
        }
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_values_per_rule: 4_096,
            max_value_bytes: Self::DEFAULT_MAX_VALUE_BYTES,
            max_total_bytes: Self::DEFAULT_MAX_TOTAL_BYTES,
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

    /// Charges transform bytes that were already capped per value.
    ///
    /// The prefix cache applies its own per-value cap, so this only re-checks
    /// the request-wide total. It also skips aliased/memoised representations,
    /// which never materialised new bytes.
    pub(crate) fn materialised(&mut self, len: usize) -> Result<(), EngineError> {
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

    /// Adds bytes already charged in a parallel worker to this budget.
    ///
    /// The per-value cap was enforced where the value was produced, so only
    /// the request-wide total is re-checked here. Used by the experimental
    /// `parallel-args` reduction to keep the serial overflow point.
    #[cfg(feature = "parallel-args")]
    pub(crate) fn absorb(&mut self, len: usize) -> Result<(), EngineError> {
        self.bytes = self.bytes.saturating_add(len);
        if self.bytes > self.limits.max_total_bytes {
            return Err(EngineError::Budget("too many materialised bytes"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_cap_is_the_value_cap_and_honours_the_default_floor() {
        let limits = Limits::for_body_cap(10 << 20);
        assert_eq!(limits.max_value_bytes, 10 << 20);
        assert_eq!(limits.max_total_bytes, 320 << 20);

        let small = Limits::for_body_cap(4 << 10);
        assert_eq!(small.max_value_bytes, Limits::DEFAULT_MAX_VALUE_BYTES);
        assert_eq!(small.max_total_bytes, Limits::DEFAULT_MAX_VALUE_BYTES * 32);
    }

    #[test]
    fn a_body_at_the_configured_cap_is_chargeable() {
        let limits = Limits::for_body_cap(10 << 20);
        let mut budget = Budget::new(limits);
        budget.bytes(10 << 20).expect("body at the cap");
        assert_eq!(budget.used_bytes(), 10 << 20);
    }
}
