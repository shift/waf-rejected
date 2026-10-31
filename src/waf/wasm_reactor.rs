//! Experimental request-in/decision-out WebAssembly reactor ABI.
//!
//! This module is compiled only with the non-default `wasm-reactor` feature.
//! It is a spike: it proves the host/module boundary with a pure-Rust
//! interpreter ([`wasmi`]) so that a real Coraza/TinyGo reactor can later be
//! dropped in without the historical Go-JS host. It does not replace any of
//! the built-in heuristic rules and is never enabled by default.
//!
//! See `docs/wasm-reactor-spike.md` for the ABI and migration notes.

use std::sync::Arc;

use tracing::warn;
use wasmi::{Config, Engine, Instance, Module, Store, StoreLimits, StoreLimitsBuilder};

use crate::waf::{Decision, RequestContext, WafRule};

/// Decision code returned by the reactor for "allow".
pub const DECISION_ALLOW: i32 = 0;
/// Decision code returned by the reactor for "block".
pub const DECISION_BLOCK: i32 = 1;

/// Offset in linear memory where the host writes the request payload.
pub const INPUT_BASE: usize = 1024;

/// Maximum request payload accepted by the spike host.
pub const DEFAULT_MAX_PAYLOAD_BYTES: usize = 32 * 1024;

/// Maximum linear memory the reactor is allowed to grow to.
pub const DEFAULT_MEMORY_LIMIT_BYTES: usize = 64 * 1024;

/// Fuel budget for one `init` + `eval` round trip.
pub const DEFAULT_FUEL: u64 = 1_000_000;

const SPIKE_WAT: &str = include_str!("../../wasm/reactor_spike.wat");

/// Resource limits applied to every reactor instance.
#[derive(Debug, Clone)]
pub struct ReactorLimits {
    /// Maximum number of payload bytes accepted by the host.
    pub max_payload_bytes: usize,
    /// Maximum linear-memory size in bytes.
    pub memory_limit_bytes: usize,
    /// Instruction budget for one evaluation.
    pub fuel: u64,
}

impl Default for ReactorLimits {
    fn default() -> Self {
        Self {
            max_payload_bytes: DEFAULT_MAX_PAYLOAD_BYTES,
            memory_limit_bytes: DEFAULT_MEMORY_LIMIT_BYTES,
            fuel: DEFAULT_FUEL,
        }
    }
}

/// Decision produced by a reactor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReactorDecision {
    /// The request is allowed.
    Allow,
    /// The request is blocked with an HTTP status and a human-readable reason.
    Block { status: u16, reason: String },
}

/// Errors raised by the reactor host.
#[derive(Debug, thiserror::Error)]
pub enum ReactorError {
    /// The module could not be parsed, validated or instantiated.
    #[error("failed to load reactor module: {0}")]
    Compile(String),
    /// A required ABI export is missing or has the wrong signature.
    #[error("reactor module is missing required export `{0}`")]
    MissingExport(&'static str),
    /// `init` returned a non-zero code.
    #[error("reactor initialisation failed with code {0}")]
    Init(i32),
    /// The payload exceeds the configured limit.
    #[error("request payload of {size} bytes exceeds the {limit} byte limit")]
    PayloadTooLarge { size: usize, limit: usize },
    /// The payload does not fit in the reactor's linear memory.
    #[error("request payload does not fit in reactor linear memory")]
    PayloadOutOfBounds,
    /// The reactor trapped, ran out of fuel, or otherwise failed while running.
    #[error("reactor execution failed: {0}")]
    Trap(String),
    /// The reactor returned a decision code the host does not understand.
    #[error("reactor returned unknown decision code {0}")]
    UnknownDecision(i32),
}

/// A compiled, reusable reactor module.
///
/// The compiled [`Module`] and [`Engine`] are shared across calls; a fresh
/// [`Store`] (and therefore a fresh linear memory) is created per evaluation,
/// which keeps evaluations isolated without sharing mutable state.
pub struct WasmReactor {
    engine: Engine,
    module: Module,
    limits: ReactorLimits,
}

impl std::fmt::Debug for WasmReactor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WasmReactor")
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl WasmReactor {
    /// Compiles a reactor from WAT or Wasm bytes.
    pub fn from_wat(wat: &str, limits: ReactorLimits) -> Result<Self, ReactorError> {
        Self::from_bytes(wat.as_bytes(), limits)
    }

    /// Compiles a reactor from Wasm bytes. WAT text is also accepted when the
    /// `wat` feature of `wasmi` is enabled (it is, for this spike).
    pub fn from_bytes(bytes: &[u8], limits: ReactorLimits) -> Result<Self, ReactorError> {
        let mut config = Config::default();
        config.consume_fuel(true);
        let engine = Engine::new(&config);
        let module =
            Module::new(&engine, bytes).map_err(|err| ReactorError::Compile(err.to_string()))?;
        let reactor = Self {
            engine,
            module,
            limits,
        };
        reactor.validate_exports()?;
        Ok(reactor)
    }

    /// Builds the reactor from the embedded hardcoded-rule spike module.
    pub fn spike() -> Result<Self, ReactorError> {
        Self::from_wat(SPIKE_WAT, ReactorLimits::default())
    }

    /// Returns the configured limits.
    pub fn limits(&self) -> &ReactorLimits {
        &self.limits
    }

    /// Checks the module's export section before the first evaluation so that
    /// configuration errors surface at load time rather than per request.
    fn validate_exports(&self) -> Result<(), ReactorError> {
        for name in ["memory", "init", "eval", "free"] {
            if self.module.get_export(name).is_none() {
                return Err(ReactorError::MissingExport(name));
            }
        }
        Ok(())
    }

    /// Runs `init` and `eval` for one request payload.
    pub fn evaluate(&self, payload: &[u8]) -> Result<ReactorDecision, ReactorError> {
        if payload.len() > self.limits.max_payload_bytes {
            return Err(ReactorError::PayloadTooLarge {
                size: payload.len(),
                limit: self.limits.max_payload_bytes,
            });
        }

        let store_limits = StoreLimitsBuilder::new()
            .memory_size(self.limits.memory_limit_bytes)
            .build();
        let mut store = Store::new(&self.engine, store_limits);
        store.limiter(|limits: &mut StoreLimits| limits);
        store
            .set_fuel(self.limits.fuel)
            .map_err(|err| ReactorError::Trap(err.to_string()))?;

        let instance = Instance::new(&mut store, &self.module, &[])
            .map_err(|err| ReactorError::Compile(err.to_string()))?;

        let memory = instance
            .get_memory(&store, "memory")
            .ok_or(ReactorError::MissingExport("memory"))?;
        let init = instance
            .get_typed_func::<(), i32>(&store, "init")
            .map_err(|_| ReactorError::MissingExport("init"))?;
        let eval = instance
            .get_typed_func::<(i32, i32), i32>(&store, "eval")
            .map_err(|_| ReactorError::MissingExport("eval"))?;
        let free = instance
            .get_typed_func::<(i32, i32), ()>(&store, "free")
            .map_err(|_| ReactorError::MissingExport("free"))?;

        let init_code = init
            .call(&mut store, ())
            .map_err(|err| ReactorError::Trap(err.to_string()))?;
        if init_code != 0 {
            return Err(ReactorError::Init(init_code));
        }

        let end = INPUT_BASE
            .checked_add(payload.len())
            .ok_or(ReactorError::PayloadOutOfBounds)?;
        if end > memory.data_size(&store) {
            return Err(ReactorError::PayloadOutOfBounds);
        }
        memory
            .write(&mut store, INPUT_BASE, payload)
            .map_err(|err| ReactorError::Trap(err.to_string()))?;

        let code = eval
            .call(&mut store, (INPUT_BASE as i32, payload.len() as i32))
            .map_err(|err| ReactorError::Trap(err.to_string()))?;

        // `free` is part of the ABI even though the spike does not allocate.
        // Ignore failures here: the store is discarded immediately afterwards.
        let _ = free.call(&mut store, (INPUT_BASE as i32, payload.len() as i32));

        match code {
            DECISION_ALLOW => Ok(ReactorDecision::Allow),
            DECISION_BLOCK => Ok(ReactorDecision::Block {
                status: 403,
                reason: "blocked by wasm reactor".to_string(),
            }),
            other => Err(ReactorError::UnknownDecision(other)),
        }
    }
}

/// A [`WafRule`] backed by a reactor.
///
/// The rule is experimental and must be registered explicitly; it never
/// replaces the built-in heuristic rules. Reactor failures fail closed with a
/// `503` because a security control that cannot evaluate must not silently
/// allow traffic.
pub struct WasmReactorRule {
    name: String,
    reactor: Arc<WasmReactor>,
}

impl WasmReactorRule {
    /// Creates a rule from a compiled reactor.
    pub fn new(name: impl Into<String>, reactor: Arc<WasmReactor>) -> Self {
        Self {
            name: name.into(),
            reactor,
        }
    }

    /// Creates a rule backed by the embedded spike module.
    pub fn spike() -> Result<Self, ReactorError> {
        Ok(Self::new(
            "wasm-reactor-spike",
            Arc::new(WasmReactor::spike()?),
        ))
    }
}

impl WafRule for WasmReactorRule {
    fn name(&self) -> &str {
        &self.name
    }

    fn evaluate(&self, ctx: &RequestContext) -> Decision {
        let payload = match build_payload(ctx) {
            Ok(payload) => payload,
            Err(err) => {
                warn!(rule = %self.name, error = %err, "failed to encode wasm reactor payload");
                return Decision::Block {
                    status: 503,
                    reason: "wasm reactor payload encoding failed".to_string(),
                };
            }
        };

        match self.reactor.evaluate(&payload) {
            Ok(ReactorDecision::Allow) => Decision::Allow,
            Ok(ReactorDecision::Block { status, reason }) => Decision::Block { status, reason },
            Err(err) => {
                warn!(rule = %self.name, error = %err, "wasm reactor evaluation failed");
                Decision::Block {
                    status: 503,
                    reason: format!("wasm reactor failure: {err}"),
                }
            }
        }
    }
}

/// Serialises the request context into the reactor's JSON payload.
fn build_payload(ctx: &RequestContext) -> Result<Vec<u8>, serde_json::Error> {
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

    let body = ctx
        .body
        .as_deref()
        .map(|bytes| String::from_utf8_lossy(bytes).into_owned());

    serde_json::to_vec(&serde_json::json!({
        "method": ctx.method.as_str(),
        "uri": ctx.uri.to_string(),
        "http_version": ctx.http_version,
        "headers": headers,
        "body_size": ctx.body_size,
        "body": body,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use hyper::{HeaderMap, Method, Uri};
    use std::net::{IpAddr, Ipv4Addr};

    fn payload(value: &serde_json::Value) -> Vec<u8> {
        serde_json::to_vec(value).expect("test payload must serialise")
    }

    fn benign_payload() -> Vec<u8> {
        payload(&serde_json::json!({
            "method": "GET",
            "uri": "/index.html",
            "headers": [["accept", "text/html"]],
            "body": null,
        }))
    }

    fn context(uri: &str, body: Option<&str>) -> RequestContext {
        let mut headers = HeaderMap::new();
        headers.insert("user-agent", "spike-test".parse().unwrap());
        let mut ctx = RequestContext::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            Method::GET,
            uri.parse::<Uri>().unwrap(),
            headers,
            body.map(str::len),
        );
        if let Some(body) = body {
            ctx = ctx.with_body(Some(Bytes::from(body.to_string())));
        }
        ctx
    }

    #[test]
    fn allows_benign_payload() {
        let reactor = WasmReactor::spike().expect("spike module must load");
        assert_eq!(
            reactor.evaluate(&benign_payload()).unwrap(),
            ReactorDecision::Allow
        );
    }

    #[test]
    fn blocks_xss_payload() {
        let reactor = WasmReactor::spike().expect("spike module must load");
        let body = payload(&serde_json::json!({
            "method": "GET",
            "uri": "/search?q=<script>alert(1)</script>",
        }));
        assert_eq!(
            reactor.evaluate(&body).unwrap(),
            ReactorDecision::Block {
                status: 403,
                reason: "blocked by wasm reactor".to_string(),
            }
        );
    }

    #[test]
    fn blocks_sql_injection_payload() {
        let reactor = WasmReactor::spike().expect("spike module must load");
        let body = payload(&serde_json::json!({
            "method": "POST",
            "uri": "/login",
            "body": "username=admin&password=x union select password from users",
        }));
        assert!(matches!(
            reactor.evaluate(&body).unwrap(),
            ReactorDecision::Block { status: 403, .. }
        ));
    }

    #[test]
    fn rejects_malformed_module() {
        let err = WasmReactor::from_wat("(module (func", ReactorLimits::default())
            .expect_err("malformed WAT must not load");
        assert!(matches!(err, ReactorError::Compile(_)));
    }

    #[test]
    fn rejects_module_without_required_exports() {
        let err = WasmReactor::from_wat(
            "(module (memory (export \"memory\") 1))",
            ReactorLimits::default(),
        )
        .expect_err("module without ABI exports must not load");
        assert!(matches!(err, ReactorError::MissingExport(_)));
    }

    #[test]
    fn reports_init_failure() {
        let wat = r#"
            (module
              (memory (export "memory") 1)
              (func (export "init") (result i32) i32.const 7)
              (func (export "eval") (param i32 i32) (result i32) i32.const 0)
              (func (export "free") (param i32 i32)))
        "#;
        let reactor =
            WasmReactor::from_wat(wat, ReactorLimits::default()).expect("module must load");
        assert!(matches!(
            reactor.evaluate(b"{}"),
            Err(ReactorError::Init(7))
        ));
    }

    #[test]
    fn reports_trap_as_error() {
        let wat = r#"
            (module
              (memory (export "memory") 1)
              (func (export "init") (result i32) i32.const 0)
              (func (export "eval") (param i32 i32) (result i32) unreachable)
              (func (export "free") (param i32 i32)))
        "#;
        let reactor =
            WasmReactor::from_wat(wat, ReactorLimits::default()).expect("module must load");
        assert!(matches!(
            reactor.evaluate(b"{}"),
            Err(ReactorError::Trap(_))
        ));
    }

    #[test]
    fn rejects_oversized_payload() {
        let limits = ReactorLimits {
            max_payload_bytes: 8,
            ..ReactorLimits::default()
        };
        let reactor = WasmReactor::from_wat(SPIKE_WAT, limits).expect("spike module must load");
        assert!(matches!(
            reactor.evaluate(b"0123456789"),
            Err(ReactorError::PayloadTooLarge { .. })
        ));
    }

    #[test]
    fn rule_maps_allow_and_block_decisions() {
        let rule = WasmReactorRule::spike().expect("spike module must load");

        assert_eq!(rule.name(), "wasm-reactor-spike");
        assert_eq!(
            rule.evaluate(&context("/index.html", None)),
            Decision::Allow
        );

        let decision = rule.evaluate(&context("/search", Some("<script>alert(1)</script>")));
        assert!(matches!(decision, Decision::Block { status: 403, .. }));

        let decision = rule.evaluate(&context("/login", Some("union select 1")));
        assert!(matches!(decision, Decision::Block { status: 403, .. }));
    }
}
