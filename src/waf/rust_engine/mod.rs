//! Native Rust replacement for the Coraza request engine (experimental).
//!
//! This module is the **core vertical slice** of the Coraza replacement:
//!
//! * [`parser`] compiles the pinned OWASP CRS 4.14 request rules from SecLang
//!   into a typed IR. Unsupported constructs abort the load with the rule id
//!   and construct; there is no silent rule loss.
//! * [`ir`] is the compiled representation. Regexes, phrase automata, selectors
//!   and transform chains are compiled once at load time.
//! * [`engine`] evaluates phases 1 and 2 in file order, maintains the CRS `TX`
//!   anomaly scores, honours `skipAfter`, and fails closed on every internal
//!   error or budget overflow.
//! * [`request`] mirrors the collection subset used by the WASI reactor
//!   (`ProcessURI`, headers, cookies, URLENCODED/MULTIPART body processing).
//! * [`operators`] and [`transforms`] implement the operator and transform
//!   surface used by the pinned bundle.
//!
//! Coraza remains the reference oracle. This engine is feature-gated behind
//! `rust-engine` and is not the default until differential parity is proven.
//!
//! # Determinism and bounds
//!
//! The decision path contains no wall clock, randomness or garbage collector.
//! Every request gets a fixed [`budget::Budget`]; crossing a bound returns
//! [`crate::waf::Decision::Block`] rather than allowing the request.

pub mod budget;
pub mod engine;
pub mod error;
pub mod ir;
pub mod operators;
pub mod parser;
pub mod request;
pub mod transforms;

pub use budget::{Budget, Limits};
pub use engine::{Outcome, RustEngine};
pub use error::{EngineError, LoadError, UnsupportedConstruct};
pub use ir::{CompiledRule, Phase, Program, ProgramItem, RuleGroup};
pub use parser::{parse_conf_path, parse_conf_str, CompilePolicy, ConstructUse, SupportReport};
pub use request::{Collections, EngineRequest, ResolvedValue};

use std::path::PathBuf;
use std::sync::Arc;

use crate::waf::{Decision, RequestContext, WafRule};

/// Repository-relative path of the pinned CRS bundle used by the reactor.
pub const CRS_CONF_RELATIVE: &str = "wasm/coraza_reactor/rules/crs/crs.conf";

/// Returns the pinned CRS bundle path for this checkout.
pub fn default_crs_conf_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(CRS_CONF_RELATIVE)
}

/// [`WafRule`] adapter for the native engine.
///
/// The adapter is intentionally small: the live proxy still defaults to the
/// Coraza backend. It exists so the engine can be selected explicitly and so
/// integration tests exercise the same `WafRule` contract.
pub struct RustEngineRule {
    engine: Arc<RustEngine>,
}

impl RustEngineRule {
    /// Wraps a compiled engine.
    pub fn new(engine: Arc<RustEngine>) -> Self {
        Self { engine }
    }

    /// Returns the underlying engine.
    pub fn engine(&self) -> &RustEngine {
        &self.engine
    }
}

impl WafRule for RustEngineRule {
    fn name(&self) -> &str {
        "rust-engine"
    }

    fn evaluate(&self, ctx: &RequestContext) -> Decision {
        let uri = ctx.uri.to_string();
        let headers: Vec<(String, String)> = ctx
            .headers
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_string(),
                    String::from_utf8_lossy(value.as_bytes()).into_owned(),
                )
            })
            .collect();
        let body = ctx.body.as_deref();
        self.engine.evaluate(&EngineRequest {
            method: ctx.method.as_str(),
            uri: &uri,
            http_version: &ctx.http_version,
            headers: &headers,
            body,
        })
    }
}
