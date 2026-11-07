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
/// Multi-pattern Vectorscan candidate gate (non-default `hyperscan-eval`).
#[cfg(feature = "hyperscan-eval")]
pub mod candidates;
pub mod engine;
pub mod error;
pub mod gate;
pub mod ir;
pub mod operators;
#[cfg(feature = "parallel-args")]
pub mod parallel_args;
pub mod parser;
pub mod processors;
#[cfg(feature = "engine-profile")]
pub mod profile;
pub mod request;
pub mod response;
pub(crate) mod subsequence;
pub mod transforms;

pub use budget::{Budget, Limits};
pub use engine::{Outcome, RustEngine};
pub use error::{EngineError, LoadError, UnsupportedConstruct};
pub use gate::{GateMask, GateSet};
pub use ir::{CompiledRule, Phase, Program, ProgramItem, RuleGroup};
pub use parser::{parse_conf_path, parse_conf_str, CompilePolicy, ConstructUse, SupportReport};
pub use request::{
    expand_macros, Candidate, Collections, EngineRequest, RequestData, ResolvedValue, TxState,
};
pub use response::{EngineResponse, ResponseConfig};

use std::path::PathBuf;
use std::sync::Arc;

use crate::waf::{
    Decision, RequestContext, ResponseContext, ResponseEvaluator, ResponseInspectionOptions,
    WafRule,
};

/// Repository-relative path of the pinned CRS bundle used by the reactor.
pub const CRS_CONF_RELATIVE: &str = "wasm/coraza_reactor/rules/crs/crs.conf";

/// Returns the pinned CRS bundle path for this checkout or installation.
///
/// Resolution order:
/// 1. `WAF_CRS_CONF` (explicit override for custom bundles).
/// 2. The source-tree path (development builds and tests).
/// 3. `<exe>/../share/waf/rules/crs/crs.conf` (Nix package layout).
/// 4. `<exe>/share/waf/rules/crs/crs.conf` (release tarball layout).
/// 5. `<exe>/wasm/coraza_reactor/rules/crs/crs.conf` (legacy tarball layout).
/// 6. `/usr/share/waf/rules/crs/crs.conf` (container layout).
/// 7. `/usr/local/share/waf/rules/crs/crs.conf`.
///
/// The source-tree path is returned as the final fallback so a missing bundle
/// produces a clear strict-load error instead of an empty path.
pub fn default_crs_conf_path() -> PathBuf {
    if let Some(path) = std::env::var_os("WAF_CRS_CONF") {
        return PathBuf::from(path);
    }

    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(CRS_CONF_RELATIVE);
    if source.is_file() {
        return source;
    }

    if let Ok(exe) = std::env::current_exe() {
        if let Some(bin_dir) = exe.parent() {
            for relative in [
                "../share/waf/rules/crs/crs.conf",
                "share/waf/rules/crs/crs.conf",
                "wasm/coraza_reactor/rules/crs/crs.conf",
            ] {
                let candidate = bin_dir.join(relative);
                let candidate = candidate.canonicalize().unwrap_or(candidate);
                if candidate.is_file() {
                    return candidate;
                }
            }
        }
    }

    for path in [
        "/usr/share/waf/rules/crs/crs.conf",
        "/usr/local/share/waf/rules/crs/crs.conf",
    ] {
        let path = PathBuf::from(path);
        if path.is_file() {
            return path;
        }
    }

    source
}

/// [`WafRule`] adapter for the native engine.
///
/// The adapter is intentionally small: the live proxy still defaults to the
/// Coraza backend. It exists so the engine can be selected explicitly and so
/// integration tests exercise the same `WafRule` contract.
pub struct RustEngineRule {
    engine: Arc<RustEngine>,
    /// Optional explicit fallback (Coraza WASI reactor) used only when the
    /// native engine returns a runtime error. Load failures never reach here.
    fallback: Option<Box<dyn WafRule>>,
}

impl RustEngineRule {
    /// Wraps a compiled engine.
    pub fn new(engine: Arc<RustEngine>) -> Self {
        Self {
            engine,
            fallback: None,
        }
    }

    /// Attaches an explicit fallback used only for Rust-engine runtime errors.
    pub fn with_fallback(mut self, fallback: Box<dyn WafRule>) -> Self {
        self.fallback = Some(fallback);
        self
    }

    /// Returns the underlying engine.
    pub fn engine(&self) -> &RustEngine {
        &self.engine
    }

    /// Builds the gRPC field-content scanner backed by this engine.
    pub fn content_scanner(&self) -> Arc<dyn crate::waf::grpc::GrpcContentScanner> {
        Arc::new(RustEngineContentScanner {
            engine: Arc::clone(&self.engine),
        })
    }
}

/// Evaluates a request against the native engine.
///
/// The request head is borrowed from the `RequestContext`; only a URI that is
/// not in origin-form (absolute-form, with a scheme/authority) needs a
/// temporary `String`.
fn evaluate_request(engine: &RustEngine, ctx: &RequestContext) -> Result<Decision, EngineError> {
    let mut uri_buf = String::new();
    let uri: &str = match ctx.uri.path_and_query() {
        Some(path_and_query) if ctx.uri.scheme().is_none() && ctx.uri.authority().is_none() => {
            path_and_query.as_str()
        }
        _ => {
            uri_buf.push_str(&ctx.uri.to_string());
            &uri_buf
        }
    };
    engine
        .evaluate_detailed_borrowed(
            ctx.method.as_str(),
            uri,
            &ctx.http_version,
            &ctx.headers,
            ctx.body.as_deref(),
        )
        .map(|outcome| outcome.decision)
}

/// Response-phase evaluator backed by the native engine.
///
/// The proxy attaches this only for `waf.coraza.backend = "rust"`. It replays
/// the request phases and then runs response phases 3–5, so response rules see
/// the same request collections and `TX` state as the request path.
pub struct RustEngineResponseEvaluator {
    engine: Arc<RustEngine>,
}

impl RustEngineResponseEvaluator {
    /// Wraps a compiled engine.
    pub fn new(engine: Arc<RustEngine>) -> Self {
        Self { engine }
    }
}

impl ResponseEvaluator for RustEngineResponseEvaluator {
    fn evaluate_response(
        &self,
        ctx: &RequestContext,
        response: &ResponseContext,
        options: &ResponseInspectionOptions,
    ) -> Decision {
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
        let request = EngineRequest {
            method: ctx.method.as_str(),
            uri: &uri,
            http_version: &ctx.http_version,
            headers: &headers,
            body: ctx.body.as_deref(),
        };

        // Deterministic inspection prefix: never hand more than the configured
        // cap to the engine, even when the caller buffered a larger body.
        let body = response.body.as_deref().map(|body| {
            let end = body.len().min(options.max_body_bytes);
            &body[..end]
        });
        let engine_response = EngineResponse {
            status: response.status,
            protocol: &response.protocol,
            headers: &response.headers,
            body,
        };
        let config = ResponseConfig {
            inspect_body: options.inspect_body,
            max_body_bytes: options.max_body_bytes,
            ..ResponseConfig::default()
        };
        self.engine
            .evaluate_response(&request, &engine_response, &config)
    }
}

/// gRPC field-content scanner for the default Rust backend.
///
/// The gRPC inspector hands over the serialised Coraza payload for the
/// synthetic `f0=...&f1=...` form request. The WASI reactor parses that JSON
/// inside the guest; the native engine has no guest, so it decodes the same
/// payload here and evaluates the synthetic request directly. Wrapping the
/// JSON as a form body would inspect the serialised envelope instead of the
/// field values and could block benign content on the embedded method path.
pub struct RustEngineContentScanner {
    engine: Arc<RustEngine>,
}

#[derive(serde::Deserialize)]
struct ContentScanPayload {
    method: String,
    uri: String,
    http_version: String,
    headers: Vec<(String, String)>,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    body_encoding: Option<String>,
}

impl crate::waf::grpc::GrpcContentScanner for RustEngineContentScanner {
    fn scan(&self, payload: &[u8]) -> Result<Decision, String> {
        use base64::Engine as _;

        let payload: ContentScanPayload = serde_json::from_slice(payload)
            .map_err(|err| format!("failed to decode gRPC content-scan payload: {err}"))?;
        let body = match (payload.body, payload.body_encoding.as_deref()) {
            (Some(body), Some("base64")) => Some(
                base64::engine::general_purpose::STANDARD
                    .decode(body)
                    .map_err(|err| format!("failed to decode gRPC content-scan body: {err}"))?,
            ),
            (Some(body), _) => Some(body.into_bytes()),
            (None, _) => None,
        };

        let request = EngineRequest {
            method: &payload.method,
            uri: &payload.uri,
            http_version: &payload.http_version,
            headers: &payload.headers,
            body: body.as_deref(),
        };
        self.engine
            .evaluate_detailed(&request)
            .map(|outcome| outcome.decision)
            .map_err(|err| err.to_string())
    }
}

impl WafRule for RustEngineRule {
    fn name(&self) -> &str {
        "rust-engine"
    }

    fn cacheable(&self) -> bool {
        true
    }

    fn fast_allow_policy(&self) -> crate::waf::fast_allow::FastAllowPolicy {
        // Like the Coraza reactor: an explicitly allowlisted route opts out of
        // inspection.
        crate::waf::fast_allow::FastAllowPolicy::Skip
    }

    fn evaluate(&self, ctx: &RequestContext) -> Decision {
        match evaluate_request(&self.engine, ctx) {
            Ok(decision) => decision,
            Err(err) => match &self.fallback {
                Some(fallback) => {
                    tracing::warn!(
                        error = %err,
                        fallback = fallback.name(),
                        "Rust engine runtime error; re-evaluating with the explicit fallback"
                    );
                    fallback.evaluate(ctx)
                }
                None => Decision::Block {
                    status: 500,
                    reason: format!("Rust engine runtime error (fail-closed): {err}"),
                },
            },
        }
    }
}

#[cfg(test)]
mod adapter_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn context() -> RequestContext {
        RequestContext::new(
            "127.0.0.1".parse().unwrap(),
            hyper::Method::GET,
            "/?q=evil".parse().unwrap(),
            hyper::HeaderMap::new(),
            None,
        )
    }

    fn engine_with_zero_budget() -> RustEngine {
        RustEngine::from_conf_str(
            r#"SecRule ARGS "@rx evil" "id:1001,phase:1,deny,status:403""#,
            ".",
            CompilePolicy::Report,
        )
        .expect("test rule compiles")
        .with_limits(Limits {
            max_values_per_rule: 0,
            max_value_bytes: 0,
            max_total_bytes: 0,
            max_matches_per_rule: 0,
        })
    }

    struct RecordingFallback {
        decision: Decision,
        calls: AtomicUsize,
    }

    impl WafRule for RecordingFallback {
        fn name(&self) -> &str {
            "test-fallback"
        }

        fn evaluate(&self, _ctx: &RequestContext) -> Decision {
            self.calls.fetch_add(1, Ordering::Relaxed);
            self.decision.clone()
        }
    }

    #[test]
    fn runtime_error_without_fallback_fails_closed() {
        let rule = RustEngineRule::new(Arc::new(engine_with_zero_budget()));
        assert!(matches!(
            rule.evaluate(&context()),
            Decision::Block { status: 500, .. }
        ));
    }

    #[test]
    fn runtime_error_with_fallback_uses_the_fallback_decision() {
        let fallback = Arc::new(RecordingFallback {
            decision: Decision::Block {
                status: 403,
                reason: "fallback".to_string(),
            },
            calls: AtomicUsize::new(0),
        });
        struct SharedFallback(Arc<RecordingFallback>);
        impl WafRule for SharedFallback {
            fn name(&self) -> &str {
                "test-fallback"
            }
            fn evaluate(&self, ctx: &RequestContext) -> Decision {
                self.0.evaluate(ctx)
            }
        }
        let rule = RustEngineRule::new(Arc::new(engine_with_zero_budget()))
            .with_fallback(Box::new(SharedFallback(Arc::clone(&fallback))));
        assert!(matches!(
            rule.evaluate(&context()),
            Decision::Block { status: 403, .. }
        ));
        assert_eq!(fallback.calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn successful_evaluation_never_calls_the_fallback() {
        let fallback = Arc::new(RecordingFallback {
            decision: Decision::Allow,
            calls: AtomicUsize::new(0),
        });
        struct SharedFallback(Arc<RecordingFallback>);
        impl WafRule for SharedFallback {
            fn name(&self) -> &str {
                "test-fallback"
            }
            fn evaluate(&self, ctx: &RequestContext) -> Decision {
                self.0.evaluate(ctx)
            }
        }
        let engine = RustEngine::from_conf_str(
            r#"SecRule ARGS "@rx never-matches" "id:1001,phase:1,deny,status:403""#,
            ".",
            CompilePolicy::Report,
        )
        .expect("test rule compiles");
        let rule = RustEngineRule::new(Arc::new(engine))
            .with_fallback(Box::new(SharedFallback(Arc::clone(&fallback))));
        assert_eq!(rule.evaluate(&context()), Decision::Allow);
        assert_eq!(fallback.calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn content_scanner_decodes_the_serialised_payload() {
        let engine = RustEngine::from_conf_str(
            r#"SecRule ARGS "@rx attack" "id:1001,phase:2,deny,status:403""#,
            ".",
            CompilePolicy::Report,
        )
        .expect("test rule compiles");
        let scanner = RustEngineRule::new(Arc::new(engine)).content_scanner();

        let payload = |body: &str| {
            serde_json::to_vec(&serde_json::json!({
                "method": "POST",
                "uri": "/__grpc__/helloworld.Greeter/Sqli",
                "http_version": "HTTP/2.0",
                "headers": [["content-type", "application/x-www-form-urlencoded"]],
                "body_size": body.len(),
                "body_original_size": body.len(),
                "body_encoding": "utf8",
                "body": body,
            }))
            .unwrap()
        };

        assert!(matches!(
            scanner.scan(&payload("f0=attack")).unwrap(),
            Decision::Block { .. }
        ));
        assert_eq!(scanner.scan(&payload("f0=alice")).unwrap(), Decision::Allow);
    }
}
