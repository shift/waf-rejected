//! Request/response body processors for the native engine.
//!
//! Coraza never selects these from `Content-Type`: `application/json` and
//! `text/xml` bodies are only parsed when a phase-1 rule runs
//! `ctl:requestBodyProcessor=JSON` (or `XML`). This module mirrors that
//! behaviour, so a bulk of request corpora that merely carry a JSON content
//! type stay byte-identical to the Coraza oracle.
//!
//! The implementations follow the vendored Coraza v3.3.3 processors:
//!
//! * [`json`] mirrors `internal/bodyprocessors/json.go` (gjson flattening with
//!   the `json` prefix, array length entries and raw scalars).
//! * [`xml`] mirrors `internal/bodyprocessors/xml.go` (attribute values under
//!   `//@*`, trimmed character data under `/*`), with a non-validating scanner
//!   that never fetches external DTDs or entities.

pub mod json;
pub mod xml;

/// Hard bounds for a body processor.
///
/// Coraza's JSON processor carries a `TODO add some anti DOS protection`;
/// these bounds are the native engine's guard against adversarial nesting.
/// They are generous enough that CRS/regression bodies never hit them. On
/// overflow the processor reports an error and leaves the collection empty
/// rather than recursing without bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessorLimits {
    /// Maximum nesting depth (root = 1).
    pub max_depth: usize,
    /// Maximum number of flattened values written to the collection.
    pub max_values: usize,
    /// Maximum decoded size of a single value.
    pub max_value_bytes: usize,
}

impl ProcessorLimits {
    /// Default per-value cap, matching [`super::budget::Limits::default`].
    pub const DEFAULT_MAX_VALUE_BYTES: usize = 1024 * 1024;

    /// Aligns the processor's per-value cap with the engine value cap.
    ///
    /// Body processors copy decoded values into owned storage, so the cap must
    /// cover anything the engine budget accepts. Depth and value-count bounds
    /// are unchanged: the body size is already bounded by the transport.
    pub fn for_value_cap(max_value_bytes: usize) -> Self {
        Self {
            max_value_bytes: max_value_bytes.max(Self::DEFAULT_MAX_VALUE_BYTES),
            ..Self::default()
        }
    }
}

impl Default for ProcessorLimits {
    fn default() -> Self {
        Self {
            max_depth: 64,
            max_values: 16_384,
            max_value_bytes: Self::DEFAULT_MAX_VALUE_BYTES,
        }
    }
}

/// A body processor failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessorError {
    /// The input was not valid for the processor.
    Malformed(&'static str),
    /// A configured bound was exceeded.
    Limit(&'static str),
}

impl std::fmt::Display for ProcessorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(detail) | Self::Limit(detail) => f.write_str(detail),
        }
    }
}

impl std::error::Error for ProcessorError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn processor_cap_tracks_the_engine_value_cap() {
        let limits = ProcessorLimits::for_value_cap(10 << 20);
        assert_eq!(limits.max_value_bytes, 10 << 20);
        assert_eq!(limits.max_depth, ProcessorLimits::default().max_depth);
        assert_eq!(limits.max_values, ProcessorLimits::default().max_values);

        assert_eq!(
            ProcessorLimits::for_value_cap(1).max_value_bytes,
            ProcessorLimits::DEFAULT_MAX_VALUE_BYTES
        );
    }
}
