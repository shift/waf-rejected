//! Integration point for the native Rust engine.
//!
//! The engine workstream replaces the bodies below. The guarantee layer only
//! depends on this module through [`NativeRustEngine`] and
//! [`crate::engine::RuleEngine`], so the accounting, differential, determinism,
//! resource-bound and fail-closed tests can be wired up before the engine is
//! merged.

use crate::engine::accounting::{self, AccountingError, EngineSupport, Verification};
use crate::engine::{EngineError, EngineOutcome, RuleEngine};
use crate::waf::coraza_corpus::CorpusRequest;

/// Verifies the engine's declared support against the committed rule manifest.
///
/// The native engine build must call this before it can claim the pinned CRS
/// rule set is supported. It returns every unaccounted rule id, directive,
/// operator, transform, action and construct in one [`AccountingError`].
pub fn verify_pinned_rules(support: &EngineSupport) -> Result<Verification, AccountingError> {
    let manifest = accounting::Manifest::load(accounting::DEFAULT_MANIFEST_PATH)?;
    accounting::verify_complete(&manifest, support)
}

/// Returns whether a real native engine is linked into this build.
///
/// The scaffold returns `false`; the engine workstream returns `true` once
/// [`evaluate`] is implemented.
pub fn is_available() -> bool {
    false
}

/// Evaluates one request with the native engine.
///
/// Any error is fail-closed by [`crate::engine::failclosed::decide`].
pub fn evaluate(_request: &CorpusRequest) -> Result<EngineOutcome, EngineError> {
    Err(EngineError::Unavailable(
        "native Rust engine backend is not linked".to_string(),
    ))
}

/// Adapter that exposes the native backend through the guarantee-layer trait.
#[derive(Debug, Clone, Copy, Default)]
pub struct NativeRustEngine;

impl NativeRustEngine {
    /// Creates the adapter.
    pub fn new() -> Self {
        Self
    }

    /// True when the backend is actually linked.
    pub fn available() -> bool {
        is_available()
    }
}

impl RuleEngine for NativeRustEngine {
    fn name(&self) -> &str {
        "rust"
    }

    fn evaluate(&self, request: &CorpusRequest) -> Result<EngineOutcome, EngineError> {
        evaluate(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::accounting::{Manifest, DEFAULT_RULES_PATH};

    #[test]
    fn full_support_template_verifies_the_pinned_manifest() {
        let manifest = Manifest::from_path(DEFAULT_RULES_PATH).expect("manifest parses");
        let support = EngineSupport::from_manifest(&manifest);
        let verification = verify_pinned_rules(&support).expect("committed manifest is complete");
        assert_eq!(verification.entries, manifest.entries.len());
    }
}
