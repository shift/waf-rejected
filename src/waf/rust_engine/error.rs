//! Errors for the native Rust CRS engine.
//!
//! Load errors are deliberately explicit: an unsupported construct aborts the
//! build of the rule program with the rule id and the construct, so a rule can
//! never be silently dropped. Runtime errors are fail-closed and surface as a
//! block in [`crate::waf::rust_engine::RustEngine::evaluate`].

/// A construct in the pinned CRS bundle that this slice cannot compile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsupportedConstruct {
    /// Rule id, when the directive had one (`SecAction`/`SecMarker` may not).
    pub rule_id: Option<u32>,
    /// Line in the source configuration.
    pub line: usize,
    /// Short construct name, e.g. `operator:@detectSQLi` or `action:exec`.
    pub construct: String,
    /// Human-readable explanation.
    pub reason: String,
}

impl UnsupportedConstruct {
    pub(crate) fn new(
        rule_id: Option<u32>,
        line: usize,
        construct: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            rule_id,
            line,
            construct: construct.into(),
            reason: reason.into(),
        }
    }
}

impl std::fmt::Display for UnsupportedConstruct {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.rule_id {
            Some(id) => write!(f, "rule {id} line {}: {}", self.line, self.construct)?,
            None => write!(f, "line {}: {}", self.line, self.construct)?,
        }
        if !self.reason.is_empty() {
            write!(f, " ({})", self.reason)?;
        }
        Ok(())
    }
}

/// Errors returned while parsing or compiling a rule bundle.
#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    /// The configuration file could not be read.
    #[error("failed to read `{path}`: {detail}")]
    Io {
        /// Path that failed.
        path: String,
        /// Underlying error.
        detail: String,
    },
    /// A directive could not be parsed.
    #[error("parse error at line {line}: {detail}")]
    Parse {
        /// Source line.
        line: usize,
        /// Description.
        detail: String,
    },
    /// A rule used a construct this slice does not implement.
    #[error("unsupported construct: {0}")]
    Unsupported(UnsupportedConstruct),
    /// A regular expression failed to compile.
    #[error("rule {rule_id:?} line {line}: invalid regex `{pattern}`: {detail}")]
    Regex {
        /// Rule id, if any.
        rule_id: Option<u32>,
        /// Source line.
        line: usize,
        /// Pattern text.
        pattern: String,
        /// Compiler error.
        detail: String,
    },
    /// A `@pmFromFile` data file could not be read.
    #[error("rule {rule_id:?} line {line}: cannot load data file `{path}`: {detail}")]
    DataFile {
        /// Rule id, if any.
        rule_id: Option<u32>,
        /// Source line.
        line: usize,
        /// Resolved path.
        path: String,
        /// Underlying error.
        detail: String,
    },
    /// A `skipAfter` action referenced an unknown marker.
    #[error("rule {rule_id:?} line {line}: unknown marker `{marker}`")]
    UnknownMarker {
        /// Rule id, if any.
        rule_id: Option<u32>,
        /// Source line.
        line: usize,
        /// Marker name.
        marker: String,
    },
    /// The bundle contained no request rules.
    #[error("no request-phase rules were compiled")]
    Empty,
}

/// Runtime failures. Every variant is converted to a block by the engine.
#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    /// A fixed per-request budget was exceeded.
    #[error("per-request budget exceeded: {0}")]
    Budget(&'static str),
    /// A transform produced an output larger than the configured cap.
    #[error("transform output exceeded the per-request byte cap")]
    OutputTooLarge,
    /// Internal invariant violated. Never expected in a compiled program.
    #[error("internal engine error: {0}")]
    Internal(&'static str),
}
