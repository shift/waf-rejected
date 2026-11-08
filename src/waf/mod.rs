pub mod admission;
pub mod ai;
pub mod auth;
pub mod content_inspection;
pub mod coraza_corpus;
pub mod exporters;
pub mod fast_allow;
pub mod geoip;
pub mod grpc_allowlist;
pub mod io;
pub mod middleware;
#[path = "proxy_fixed.rs"]
pub mod proxy;
pub mod rate_limit;
pub mod rules;
pub mod security_events;
pub mod simd_ops;
pub mod storage;
pub mod tls_config;

/// Experimental request-in/decision-out WASM reactor ABI (non-default feature).
#[cfg(feature = "wasm-reactor")]
pub mod wasm_reactor;

/// Experimental content-addressed allow-verdict cache (non-default feature).
#[cfg(feature = "allow-cache")]
pub mod allow_cache;

/// Distributed security fabric client scaffold (non-default `distri-kv`
/// feature). See `docs/operations/distributed.md`.
#[cfg(feature = "distri-kv")]
pub mod distributed;

/// Shared, bounded, allocation-free transform pipeline used by the prefilter
/// and the native engine.
/// Compiled for unit tests even without the feature so parity tests always run.
#[cfg(any(
    feature = "crs-prefilter",
    feature = "fastpath",
    feature = "rust-engine",
    test
))]
pub mod transforms;

/// Experimental required-literal prefilter for CRS request bodies. Non-default:
/// it is an opt-in evaluation mode until the detection-parity corpus proves it.
#[cfg(any(feature = "crs-prefilter", feature = "fastpath"))]
pub mod prefilter;

/// Experimental native Rust evaluation kernel (prototype, non-default).
/// Demonstrates the execution model for a future Coraza replacement; it does
/// not replace the Coraza backends. See
/// `docs/suggestions_from_agents/engine-kernel.md`.
#[cfg(feature = "engine-kernel")]
pub mod engine_kernel;
/// Offline extractor that emits `rules/crs/prefilter.json`.
///
/// Always compiled: the default Rust engine reuses its conservative
/// required-literal analysis for the heuristic content-inspection rules.
pub mod prefilter_extract;

/// Experimental Vectorscan/Hyperscan multi-pattern scanner (non-default).
/// Requires the system `libhs` (nixpkgs `vectorscan`); see
/// `docs/suggestions_from_agents/hyperscan-evaluation.md`.
#[cfg(feature = "hyperscan-eval")]
pub mod hyperscan;

/// Experimental compiled request fast path (non-default `fastpath` feature).
#[cfg(feature = "fastpath")]
pub mod fastpath;

/// Native (Rust) ports of Coraza's `@detectSQLi` and `@detectXSS` operators.
/// Non-default: Coraza remains the request-path engine until a caller opts in.
#[cfg(feature = "native-detect")]
pub mod native_detect;

/// Native Rust replacement for the Coraza request engine (experimental,
/// non-default). See `docs/suggestions_from_agents/rust-engine.md`.
#[cfg(feature = "rust-engine")]
pub mod rust_engine;

/// Borrowed request view shared by the proxy and the WAF encoders.
pub mod request_view;

/// Shared JSON payload envelope for the wasm reactor and native sidecar.
/// Kept unconditional so gRPC envelope inspection also builds with
/// `--no-default-features`.
pub mod coraza_payload;
#[cfg(all(feature = "coraza-native", unix))]
pub mod coraza_wire;

/// Experimental native Go Coraza sidecar client (non-default feature).
#[cfg(all(feature = "coraza-native", unix))]
pub mod native_coraza;

/// Protocol-aware gRPC inspection (protobuf frames are not sent to CRS body
/// rules). The envelope/frame handling is independent of the WASM reactor, so
/// it stays available with `--no-default-features`.
pub mod grpc;

/// Protocol-aware GraphQL-over-HTTP inspection (raw JSON bodies can be
/// withheld from CRS body rules in `graphql-only` mode).
#[cfg(feature = "wasm-reactor")]
pub mod graphql;
/// Deterministic persisted-query allowlist generation and loading.
#[cfg(feature = "wasm-reactor")]
pub mod graphql_allowlist;
/// Minimal protobuf wire decoder used by gRPC field-level inspection.
pub mod protobuf;

use bytes::Bytes;
use hyper::{HeaderMap, Method, Uri};
use std::borrow::Cow;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::time::Instant;
use tracing::{debug, info, warn};

use self::admission::{AdmissionController, AdmissionGuard};
use self::content_inspection::ContentInspectionRuleFactory;
use self::geoip::{GeoBlockingRuleFactory, GeoIpService};
use self::rate_limit::{GlobalRateLimiter, RateLimiter};
use self::rules::{MethodRule, RequestSizeRule};
use self::security_events::SecurityEventLogger;
use crate::config::Config;

#[cfg(feature = "wasm-waf")]
use crate::wasm::{SecurityDecision as WasmDecision, WasmEngine, WasmRequestContext};

/// Maximum body size whose native Rust engine scan runs inline on the async
/// worker instead of the blocking pool. Above this the scan is offloaded so a
/// pathological request cannot park a runtime worker.
const INLINE_HEAVY_MAX_BYTES: usize = 64 * 1024;

/// Direct Coraza backend handle used for gRPC field-content scanning.
#[cfg(feature = "wasm-reactor")]
type GrpcContentScannerHandle = Arc<dyn grpc::GrpcContentScanner>;
#[cfg(not(feature = "wasm-reactor"))]
type GrpcContentScannerHandle = ();

/// Resident set size of the current process, when the platform exposes it.
///
/// Used only for start-up diagnostics (the Rust engine compile time and the
/// resulting footprint are logged once at startup).
#[cfg(feature = "rust-engine")]
pub(crate) fn rss_bytes() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let statm = std::fs::read_to_string("/proc/self/statm").ok()?;
        let pages: u64 = statm.split_whitespace().nth(1)?.parse().ok()?;
        Some(pages.saturating_mul(4096))
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// WAF decision on how to handle a request
#[derive(Debug, Clone, PartialEq)]
pub enum Decision {
    /// Allow the request to proceed
    Allow,
    /// Block the request with a specific status code and reason
    Block { status: u16, reason: String },
    /// Rate limit the request (429 Too Many Requests)
    RateLimit { reason: String },
}

/// WAF rule evaluation context containing request information
#[derive(Debug, Clone)]
pub struct RequestContext {
    pub client_ip: IpAddr,
    pub method: Method,
    pub uri: Uri,
    pub headers: HeaderMap,
    pub body_size: Option<usize>,
    pub body: Option<Bytes>,
    pub timestamp: Instant,
    /// HTTP version string. The proxy has a `&'static str` from the negotiated
    /// connection and stores it borrowed, so the hot path does not allocate
    /// one `String` per request.
    pub http_version: Cow<'static, str>,
}

impl RequestContext {
    pub fn new(
        client_ip: IpAddr,
        method: Method,
        uri: Uri,
        headers: HeaderMap,
        body_size: Option<usize>,
    ) -> Self {
        Self {
            client_ip,
            method,
            uri,
            headers,
            body_size,
            body: None,
            timestamp: Instant::now(),
            http_version: Cow::Borrowed("1.1"), // Default to HTTP/1.1
        }
    }

    /// Create RequestContext with explicit HTTP version
    pub fn with_http_version(
        client_ip: IpAddr,
        method: Method,
        uri: Uri,
        headers: HeaderMap,
        body_size: Option<usize>,
        http_version: impl Into<Cow<'static, str>>,
    ) -> Self {
        Self {
            client_ip,
            method,
            uri,
            headers,
            body_size,
            body: None,
            timestamp: Instant::now(),
            http_version: http_version.into(),
        }
    }

    pub fn with_body(mut self, body: Option<Bytes>) -> Self {
        self.body = body;
        self
    }
}

/// An upstream response as seen by the response-inspection path.
#[derive(Debug, Clone)]
pub struct ResponseContext {
    /// HTTP status code.
    pub status: u16,
    /// Protocol string, e.g. `HTTP/1.1` or `HTTP/2.0`.
    pub protocol: String,
    /// Response headers in wire order.
    pub headers: Vec<(String, String)>,
    /// Response body, when the caller captured it.
    pub body: Option<Bytes>,
}

/// Response-inspection options derived from
/// [`crate::config::ResponseInspectionConfig`].
#[derive(Debug, Clone, Copy)]
pub struct ResponseInspectionOptions {
    /// Inspect the response body in addition to headers.
    pub inspect_body: bool,
    /// Maximum body bytes handed to the engine.
    pub max_body_bytes: usize,
}

/// Backend that can evaluate response phases 3–5.
///
/// Only the native Rust engine implements this today. The Coraza WASI/native
/// backends have no response path, so they leave the evaluator unset.
pub trait ResponseEvaluator: Send + Sync {
    /// Evaluate the response and return a decision. Implementations must
    /// fail closed on internal errors.
    fn evaluate_response(
        &self,
        request: &RequestContext,
        response: &ResponseContext,
        options: &ResponseInspectionOptions,
    ) -> Decision;
}

/// WAF rule trait for implementing custom rules
pub trait WafRule: Send + Sync {
    fn name(&self) -> &str;
    fn evaluate(&self, ctx: &RequestContext) -> Decision;
    fn is_enabled(&self) -> bool {
        true
    }
    /// Whether this rule's verdict is a pure function of the canonical request
    /// content and may therefore be memoised by the experimental allow-verdict
    /// cache.
    ///
    /// The safe default is `false`: custom and stateful rules always run, even
    /// on a cache hit. Only the Coraza backend and the built-in content
    /// inspector opt in.
    fn cacheable(&self) -> bool {
        false
    }

    /// How the compiled bodyless fast path treats this rule.
    ///
    /// The default is [`fast_allow::FastAllowPolicy::FallThrough`], so a
    /// custom rule can never be silently skipped by an allowlisted route. A
    /// rule that is stateless inspection may opt into `Skip`; a stateful
    /// policy gate may opt into `Gate` and implement
    /// [`Self::fast_allow_gate`].
    fn fast_allow_policy(&self) -> fast_allow::FastAllowPolicy {
        fast_allow::FastAllowPolicy::FallThrough
    }

    /// Evaluate the always-on policy/state portion of a gate rule for a
    /// bodyless request. Only called when [`Self::fast_allow_policy`] returns
    /// [`fast_allow::FastAllowPolicy::Gate`].
    fn fast_allow_gate(&self, _ctx: &fast_allow::FastAllowContext<'_>) -> Decision {
        Decision::Block {
            status: 503,
            reason: "fast-allow gate is not implemented for this rule".to_string(),
        }
    }
}

/// Fail-closed placeholder used when a configured reactor cannot be loaded.
#[cfg(any(
    feature = "wasm-reactor",
    feature = "coraza-native",
    feature = "rust-engine"
))]
struct UnavailableCorazaRule {
    reason: String,
}

#[cfg(any(
    feature = "wasm-reactor",
    feature = "coraza-native",
    feature = "rust-engine"
))]
impl WafRule for UnavailableCorazaRule {
    fn name(&self) -> &str {
        "coraza-backend-unavailable"
    }

    fn evaluate(&self, _ctx: &RequestContext) -> Decision {
        Decision::Block {
            status: 503,
            reason: self.reason.clone(),
        }
    }
}

/// WAF engine for evaluating requests against rules
pub struct WafEngine {
    rules: Arc<RwLock<Vec<Box<dyn WafRule>>>>,
    event_logger: SecurityEventLogger,
    geoip_service: Arc<GeoIpService>,
    enabled: bool,
    fail_closed: bool,
    wasm_init_failed: bool,
    /// Start-up failure for a configured WAF component (currently the Coraza
    /// reactor or the gRPC allowlist artifact). This is fatal for
    /// [`WafProxyService::new`](crate::proxy::WafProxyService::new) rather
    /// than deferred to request time.
    #[cfg(any(
        feature = "wasm-reactor",
        feature = "coraza-native",
        feature = "rust-engine"
    ))]
    waf_init_error: Option<String>,
    /// Protocol-aware gRPC pre-check; runs before the Coraza reactor and
    /// withholds protobuf bodies from CRS body rules.
    #[cfg(feature = "wasm-reactor")]
    grpc_inspector: Option<grpc::GrpcInspector>,
    /// Protocol-aware GraphQL pre-check; runs before Coraza and can withhold
    /// the raw body from CRS body rules in `graphql-only` mode.
    #[cfg(feature = "wasm-reactor")]
    graphql_inspector: Option<graphql::GraphqlInspector>,
    #[cfg(feature = "wasm-waf")]
    wasm_engine: Option<Arc<WasmEngine>>,
    #[cfg(feature = "ai-threat-detection")]
    ai_detector: Option<Arc<ai::AiThreatDetector>>,
    /// Bounds concurrent heavy (CRS body) inspections so cheap traffic keeps
    /// at least one reactor worker.
    admission: AdmissionController,
    /// True when the configured inspection backend is the native Rust engine.
    /// Its body scans are sub-millisecond for normal request sizes, so running
    /// them inline avoids a `spawn_blocking` hop and a `RequestContext` clone;
    /// large bodies are still offloaded (see `INLINE_HEAVY_MAX_BYTES`).
    inline_heavy: bool,
    /// Shared runtime metrics, when the caller supplied them.
    metrics: Option<Arc<crate::metrics::Metrics>>,
    /// Distributed fabric handle (`distri-kv` feature). `None` unless
    /// `waf.distributed.enabled` is set, so current behaviour is unchanged.
    #[cfg(feature = "distri-kv")]
    distributed: Option<Arc<distributed::DistributedState>>,
    /// Experimental content-addressed allow-verdict cache (`allow-cache`).
    #[cfg(feature = "allow-cache")]
    allow_cache: Option<Arc<allow_cache::AllowCache>>,
    /// Compiled bodyless allowlist fast path.
    fast_allow: Arc<fast_allow::FastAllow>,
    /// Optional response-phase evaluator (native Rust engine only).
    response_evaluator: Option<Arc<dyn ResponseEvaluator>>,
}

/// Result of the synchronous inspection stages.
///
/// The stages never touch the async runtime: the audit event for `decision` is
/// emitted by the caller once the blocking work is done. That keeps the whole
/// stage sequence runnable inside `spawn_blocking` without nesting runtimes.
struct CoreOutcome {
    decision: Decision,
    triggered_rules: Vec<String>,
}

impl CoreOutcome {
    fn new(decision: Decision, triggered_rules: Vec<String>) -> Self {
        Self {
            decision,
            triggered_rules,
        }
    }
}

/// Outcome of the synchronous protocol pre-checks.
enum PrecheckOutcome {
    /// Continue evaluation. `Some` carries the context a pre-check produced
    /// (for example a body-stripped one); `None` means "use the original".
    Continue(Option<Box<RequestContext>>),
    /// Stop evaluation with this outcome.
    Reject(CoreOutcome),
}

/// Outcome of the gRPC protocol pre-check.
#[cfg(feature = "wasm-reactor")]
enum GrpcPrecheck {
    /// Continue evaluation with the supplied (possibly body-stripped) context.
    Continue(Box<RequestContext>),
    /// Return this decision immediately.
    Reject(CoreOutcome),
}

/// Outcome of the GraphQL protocol pre-check.
#[cfg(feature = "wasm-reactor")]
enum GraphqlPrecheck {
    /// Continue evaluation with the supplied (possibly body-stripped) context.
    Continue(Box<RequestContext>),
    /// Return this decision immediately.
    Reject(CoreOutcome),
}

impl Default for WafEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for WafEngine {
    fn clone(&self) -> Self {
        Self {
            rules: Arc::clone(&self.rules),
            event_logger: SecurityEventLogger::default_logger(),
            geoip_service: Arc::clone(&self.geoip_service),
            enabled: self.enabled,
            fail_closed: self.fail_closed,
            wasm_init_failed: self.wasm_init_failed,
            #[cfg(any(
                feature = "wasm-reactor",
                feature = "coraza-native",
                feature = "rust-engine"
            ))]
            waf_init_error: self.waf_init_error.clone(),
            #[cfg(feature = "wasm-reactor")]
            grpc_inspector: self.grpc_inspector.clone(),
            #[cfg(feature = "wasm-reactor")]
            graphql_inspector: self.graphql_inspector.clone(),
            #[cfg(feature = "wasm-waf")]
            wasm_engine: self.wasm_engine.clone(),
            #[cfg(feature = "ai-threat-detection")]
            ai_detector: self.ai_detector.clone(),
            admission: self.admission.clone(),
            inline_heavy: self.inline_heavy,
            metrics: self.metrics.clone(),
            #[cfg(feature = "distri-kv")]
            distributed: self.distributed.clone(),
            #[cfg(feature = "allow-cache")]
            allow_cache: self.allow_cache.clone(),
            fast_allow: Arc::clone(&self.fast_allow),
            response_evaluator: self.response_evaluator.clone(),
        }
    }
}

impl WafEngine {
    pub fn new() -> Self {
        Self {
            rules: Arc::new(RwLock::new(Vec::new())),
            event_logger: SecurityEventLogger::default_logger(),
            geoip_service: Arc::new(GeoIpService::new()),
            enabled: true,
            fail_closed: true,
            wasm_init_failed: false,
            #[cfg(any(
                feature = "wasm-reactor",
                feature = "coraza-native",
                feature = "rust-engine"
            ))]
            waf_init_error: None,
            #[cfg(feature = "wasm-reactor")]
            grpc_inspector: None,
            #[cfg(feature = "wasm-reactor")]
            graphql_inspector: None,
            #[cfg(feature = "wasm-waf")]
            wasm_engine: None,
            #[cfg(feature = "ai-threat-detection")]
            ai_detector: None,
            admission: AdmissionController::disabled(),
            inline_heavy: false,
            metrics: None,
            #[cfg(feature = "distri-kv")]
            distributed: None,
            #[cfg(feature = "allow-cache")]
            allow_cache: None,
            fast_allow: Arc::new(fast_allow::FastAllow::disabled()),
            response_evaluator: None,
        }
    }

    pub fn with_config(config: &Config) -> Self {
        Self::with_config_and_metrics(config, None)
    }

    /// Build an engine and attach the process metrics registry. Admission
    /// counters, reactor metrics and per-class in-flight gauges are then
    /// exposed through `/metrics`.
    pub fn with_config_and_metrics(
        config: &Config,
        metrics: Option<Arc<crate::metrics::Metrics>>,
    ) -> Self {
        #[cfg(feature = "wasm-waf")]
        let wasm_engine = Self::initialize_wasm_engine(config);
        #[cfg(feature = "wasm-waf")]
        let wasm_init_failed = config.waf.wasm.enabled && wasm_engine.is_none();
        #[cfg(not(feature = "wasm-waf"))]
        let wasm_init_failed = false;

        let fast_allow = match fast_allow::FastAllow::from_config(&config.waf.fast_allow) {
            Ok(fast) => Arc::new(fast),
            Err(err) => {
                warn!(
                    error = %err,
                    "waf.fast_allow configuration is invalid; the compiled allowlist is disabled"
                );
                Arc::new(fast_allow::FastAllow::disabled())
            }
        };

        #[cfg(feature = "distri-kv")]
        let distributed = config.waf.distributed.enabled.then(|| {
            Arc::new(distributed::DistributedState::from_config(
                &config.waf.distributed,
            ))
        });

        let mut engine = Self {
            rules: Arc::new(RwLock::new(Vec::new())),
            event_logger: SecurityEventLogger::new(config.waf.security_events.clone()),
            geoip_service: Self::initialize_geoip(config),
            enabled: config.waf.enabled,
            fail_closed: config.waf.fail_mode != "open",
            wasm_init_failed,
            #[cfg(any(
                feature = "wasm-reactor",
                feature = "coraza-native",
                feature = "rust-engine"
            ))]
            waf_init_error: None,
            #[cfg(feature = "wasm-reactor")]
            grpc_inspector: None,
            #[cfg(feature = "wasm-reactor")]
            graphql_inspector: None,
            #[cfg(feature = "wasm-waf")]
            wasm_engine,
            #[cfg(feature = "ai-threat-detection")]
            ai_detector: Self::initialize_ai_detector(config),
            admission: AdmissionController::from_config(
                &config.waf.admission,
                config.waf.coraza.resolved_pool_size(),
                metrics.clone(),
            ),
            inline_heavy: config.waf.coraza.enabled
                && config.waf.coraza.backend == crate::config::CorazaBackend::Rust,
            metrics,
            #[cfg(feature = "distri-kv")]
            distributed,
            #[cfg(feature = "allow-cache")]
            allow_cache: None,
            fast_allow,
            response_evaluator: None,
        };

        // gRPC is protocol-aware: validate the envelope before Coraza runs so
        // protobuf bytes never reach CRS body rules.
        #[cfg(feature = "wasm-reactor")]
        if config.waf.enabled && config.waf.coraza.enabled && config.waf.grpc.enabled {
            match grpc::GrpcInspector::try_from_config(&config.waf.grpc) {
                Ok(inspector) => {
                    let inspector = match &engine.metrics {
                        Some(metrics) => inspector.with_metrics(Arc::clone(metrics)),
                        None => inspector,
                    };
                    engine.grpc_inspector = Some(inspector);
                    info!("Enabled protocol-aware gRPC inspection");
                }
                Err(err) => {
                    warn!(error = %err, "failed to load the gRPC allowlist artifact");
                    engine.record_init_error(format!("gRPC allowlist failed to load: {err}"));
                }
            }
        }

        // GraphQL is protocol-aware too: validate the operation before Coraza
        // runs so `graphql-only` mode can withhold the raw JSON body.
        #[cfg(feature = "wasm-reactor")]
        if config.waf.enabled
            && config.waf.graphql.enabled
            && config.waf.graphql.scan_mode() != crate::config::WafGraphqlScanMode::Off
        {
            match graphql::GraphqlInspector::try_from_config(&config.waf.graphql) {
                Ok(inspector) => {
                    engine.graphql_inspector = Some(inspector);
                    info!(
                        mode = config.waf.graphql.scan_mode().as_str(),
                        "Enabled protocol-aware GraphQL inspection"
                    );
                }
                Err(err) => {
                    warn!(error = %err, "failed to load the GraphQL allowlist artifact");
                    engine.record_init_error(format!("GraphQL allowlist failed to load: {err}"));
                }
            }
        }

        // The Coraza reactor must run before the traditional heuristics.
        #[cfg(any(
            feature = "wasm-reactor",
            feature = "coraza-native",
            feature = "rust-engine"
        ))]
        let content_scanner = engine.add_coraza_rule(config);

        // gRPC field-content scanning reuses the same backend directly. It is
        // attached after the Coraza rule so no second reactor is compiled.
        // Only take the inspector when a scanner exists: taking it on a `None`
        // scanner would silently drop gRPC envelope inspection (the Rust
        // backend has no legacy reactor scanner of its own).
        #[cfg(feature = "wasm-reactor")]
        if let Some(scanner) = content_scanner {
            if let Some(inspector) = engine.grpc_inspector.take() {
                engine.grpc_inspector = Some(inspector.with_content_scanner(scanner));
            }
        }

        // Add default rules based on configuration
        engine.add_default_rules(config);

        #[cfg(feature = "allow-cache")]
        if config.waf.enabled && config.waf.allow_cache.enabled {
            let key = allow_cache::Key::random();
            let generation = {
                let rules = engine.rules.read().unwrap();
                allow_cache::policy_generation(
                    &key,
                    &config.waf,
                    rules.iter().map(|rule| (rule.name(), rule.is_enabled())),
                )
            };
            engine.allow_cache = Some(Arc::new(allow_cache::AllowCache::new(
                &config.waf.allow_cache,
                generation,
                key,
                engine.metrics.clone(),
            )));
            info!(
                ttl_secs = config.waf.allow_cache.ttl_secs,
                max_entries = config.waf.allow_cache.max_entries,
                max_body_bytes = config.waf.allow_cache.max_body_bytes,
                routes = ?config.waf.allow_cache.routes,
                "Enabled experimental allow-verdict cache"
            );
        }

        #[cfg(not(feature = "allow-cache"))]
        if config.waf.allow_cache.enabled {
            warn!(
                "waf.allow_cache.enabled is set but this build was compiled without \
                 the `allow-cache` feature; the cache stays disabled"
            );
        }

        engine
    }

    #[cfg(any(
        feature = "wasm-reactor",
        feature = "coraza-native",
        feature = "rust-engine"
    ))]
    fn add_coraza_rule(&mut self, config: &Config) -> Option<GrpcContentScannerHandle> {
        if !config.waf.enabled || !config.waf.coraza.enabled {
            return None;
        }

        if config.waf.coraza.oversize_action != crate::config::CorazaOversizeAction::InspectAll {
            warn!(
                action = ?config.waf.coraza.oversize_action,
                max_inspect_bytes = config.waf.coraza.max_inspect_bytes,
                max_payload_bytes = config.waf.coraza.max_payload_bytes,
                "Coraza body inspection policy is not inspect-all: bodies above \
                 max_inspect_bytes are not fully inspected by CRS"
            );
        }

        let backend = config.waf.coraza.backend;
        if backend != crate::config::CorazaBackend::Rust
            && config.waf.coraza.fallback == crate::config::CorazaFallback::Wasm
        {
            warn!(
                backend = ?backend,
                "waf.coraza.fallback = \"wasm\" only applies to the rust backend; ignoring it"
            );
        }
        let result = match backend {
            #[cfg(feature = "wasm-reactor")]
            crate::config::CorazaBackend::Wasm => {
                wasm_reactor::WasmReactorRule::from_config(&config.waf.coraza, self.fail_closed)
                    .map(|rule| {
                        let scanner: GrpcContentScannerHandle = rule.reactor();
                        let rule = match &self.metrics {
                            Some(metrics) => rule.with_metrics(Arc::clone(metrics)),
                            None => rule,
                        };
                        (Box::new(rule) as Box<dyn WafRule>, Some(scanner))
                    })
                    .map_err(|err| err.to_string())
            }
            #[cfg(not(feature = "wasm-reactor"))]
            crate::config::CorazaBackend::Wasm => Err(
                "waf.coraza.backend = \"wasm\" requires a build with the `wasm-reactor` feature"
                    .to_string(),
            ),
            #[cfg(all(feature = "coraza-native", unix))]
            crate::config::CorazaBackend::Native => {
                native_coraza::NativeCorazaRule::from_config(&config.waf.coraza, self.fail_closed)
                    .map(|rule| {
                        #[cfg(feature = "wasm-reactor")]
                        let scanner: GrpcContentScannerHandle = rule.client();
                        #[cfg(not(feature = "wasm-reactor"))]
                        let scanner: GrpcContentScannerHandle = ();
                        let rule = match &self.metrics {
                            Some(metrics) => rule.with_metrics(Arc::clone(metrics)),
                            None => rule,
                        };
                        (Box::new(rule) as Box<dyn WafRule>, Some(scanner))
                    })
                    .map_err(|err| err.to_string())
            }
            #[cfg(not(all(feature = "coraza-native", unix)))]
            crate::config::CorazaBackend::Native => Err(
                "waf.coraza.backend = \"native\" requires a Unix build with the `coraza-native` feature"
                    .to_string(),
            ),
            #[cfg(feature = "rust-engine")]
            crate::config::CorazaBackend::Rust => {
                let path = rust_engine::default_crs_conf_path();
                let started = Instant::now();
                rust_engine::RustEngine::from_conf_path(&path)
                    .map_err(|err| err.to_string())
                    .and_then(|engine| {
                        let load_ms = started.elapsed().as_secs_f64() * 1000.0;
                        let report = engine.support_report();
                        info!(
                            backend = "rust",
                            source = %path.display(),
                            startup_ms = load_ms,
                            rules_seen = report.rules_seen,
                            rules_compiled = report.rules_compiled,
                            rules_skipped = report.rules_skipped,
                            rule_groups = engine.rule_groups(),
                            pipelines = engine.pipeline_count(),
                            rss_bytes = rss_bytes().unwrap_or(0),
                            "Compiled the Rust engine rule IR at startup"
                        );
                        let engine = Arc::new(engine);
                        self.response_evaluator = Some(Arc::new(
                            rust_engine::RustEngineResponseEvaluator::new(Arc::clone(&engine)),
                        ));
                        let rule = rust_engine::RustEngineRule::new(engine);
                        #[cfg(feature = "wasm-reactor")]
                        let scanner: GrpcContentScannerHandle = rule.content_scanner();
                        #[cfg(not(feature = "wasm-reactor"))]
                        let scanner: GrpcContentScannerHandle = ();
                        let rule = match config.waf.coraza.fallback {
                            crate::config::CorazaFallback::None => rule,
                            crate::config::CorazaFallback::Wasm => {
                                let fallback = Self::wasm_fallback_rule(
                                    &config.waf.coraza,
                                    self.fail_closed,
                                    self.metrics.as_ref(),
                                )?;
                                info!(
                                    "Rust engine fallback is enabled: runtime errors re-evaluate \
                                     with the Coraza WASI reactor"
                                );
                                rule.with_fallback(fallback)
                            }
                        };
                        Ok((Box::new(rule) as Box<dyn WafRule>, Some(scanner)))
                    })
            }
            #[cfg(not(feature = "rust-engine"))]
            crate::config::CorazaBackend::Rust => Err(
                "waf.coraza.backend = \"rust\" requires a build with the `rust-engine` feature"
                    .to_string(),
            ),
        };

        match result {
            Ok((rule, scanner)) => {
                info!(backend = ?backend, "Added Coraza backend as the first WAF rule");
                self.add_rule_boxed(rule);
                return scanner;
            }
            Err(err) => {
                warn!(backend = ?backend, error = %err, "failed to initialise Coraza backend");
                let reason = match backend {
                    crate::config::CorazaBackend::Wasm => {
                        format!("Coraza WASI reactor failed to initialise: {err}")
                    }
                    crate::config::CorazaBackend::Native => {
                        format!("Coraza native sidecar failed to initialise: {err}")
                    }
                    crate::config::CorazaBackend::Rust => {
                        format!("Rust engine failed to initialise: {err}")
                    }
                };
                self.record_init_error(reason.clone());
                if self.fail_closed {
                    // Preserve request-time fail-closed behaviour for callers
                    // that build a WafEngine directly.
                    self.add_rule(UnavailableCorazaRule { reason });
                }
            }
        }
        None
    }

    /// Builds the explicit Rust-engine fallback (Coraza WASI reactor).
    #[cfg(feature = "rust-engine")]
    fn wasm_fallback_rule(
        config: &crate::config::WafCorazaConfig,
        fail_closed: bool,
        metrics: Option<&Arc<crate::metrics::Metrics>>,
    ) -> Result<Box<dyn WafRule>, String> {
        #[cfg(feature = "wasm-reactor")]
        {
            let rule = wasm_reactor::WasmReactorRule::from_config(config, fail_closed)
                .map_err(|err| format!("Coraza fallback reactor failed to initialise: {err}"))?;
            let rule = match metrics {
                Some(metrics) => rule.with_metrics(Arc::clone(metrics)),
                None => rule,
            };
            Ok(Box::new(rule))
        }
        #[cfg(not(feature = "wasm-reactor"))]
        {
            let _ = (config, fail_closed, metrics);
            Err(
                "waf.coraza.fallback = \"wasm\" requires a build with the `wasm-reactor` feature"
                    .to_string(),
            )
        }
    }

    /// Records a start-up failure, keeping earlier ones so the operator sees
    /// every misconfigured component.
    #[cfg(any(
        feature = "wasm-reactor",
        feature = "coraza-native",
        feature = "rust-engine"
    ))]
    fn record_init_error(&mut self, reason: String) {
        match &mut self.waf_init_error {
            Some(existing) => {
                existing.push_str("; ");
                existing.push_str(&reason);
            }
            None => self.waf_init_error = Some(reason),
        }
    }

    /// Returns the WAF start-up error, if a configured component (the Coraza
    /// reactor or the gRPC allowlist artifact) could not be loaded or
    /// initialised. Proxy start-up treats this as fatal so the process never
    /// serves traffic without its WAF engine.
    #[cfg(any(
        feature = "wasm-reactor",
        feature = "coraza-native",
        feature = "rust-engine"
    ))]
    pub fn waf_init_error(&self) -> Option<&str> {
        self.waf_init_error.as_deref()
    }

    fn initialize_geoip(config: &Config) -> Arc<GeoIpService> {
        let mut service = match &config.waf.geo_blocking.database_path {
            Some(path) => match GeoIpService::from_database(path) {
                Ok(service) => {
                    info!("GeoIP database loaded from {}", path);
                    service
                }
                Err(e) => {
                    warn!(
                        "Failed to load GeoIP database '{}': {}. Country blocking will only match built-in test data",
                        path, e
                    );
                    GeoIpService::new()
                }
            },
            None => GeoIpService::new(),
        };

        if let Some(path) = &config.waf.geo_blocking.anonymous_database_path {
            match service.load_anonymous_database(path) {
                Ok(()) => {
                    info!("GeoIP Anonymous IP database loaded from {}", path);
                }
                Err(e) => {
                    warn!(
                        "Failed to load GeoIP Anonymous IP database '{}': {}. Anonymous network detection will be unavailable",
                        path, e
                    );
                }
            }
        }

        Arc::new(service)
    }

    #[cfg(feature = "wasm-waf")]
    fn initialize_wasm_engine(config: &Config) -> Option<Arc<WasmEngine>> {
        if !config.waf.wasm.enabled {
            info!("WASM ModSecurity engine disabled in configuration");
            return None;
        }

        info!("Initializing WASM ModSecurity engine");

        let wasm_config = crate::wasm::WasmEngineConfig {
            module_path: config.waf.wasm.module_path.clone(),
            // Config stores bytes; the engine API expects megabytes.
            memory_limit_mb: (config.waf.wasm.memory_limit / (1024 * 1024)).max(1),
            timeout_ms: config.waf.wasm.timeout_ms,
            debug: config.waf.wasm.debug,
            instance_pool_size: config.waf.wasm.instance_pool_size,
            hot_reload: config.waf.wasm.hot_reload,
            enable_memory_mapping: true,
            enable_shared_memory: true,
        };

        match WasmEngine::new(wasm_config) {
            Ok(engine) => {
                info!("✅ WASM ModSecurity engine initialized successfully");
                Some(Arc::new(engine))
            }
            Err(e) => {
                warn!("❌ Failed to initialize WASM engine: {}", e);
                None
            }
        }
    }

    #[cfg(feature = "ai-threat-detection")]
    fn initialize_ai_detector(config: &Config) -> Option<Arc<ai::AiThreatDetector>> {
        if !config.security.ai.enabled {
            info!("AI threat detection disabled in configuration");
            return None;
        }

        info!("Initializing AI threat detection engine");

        match ai::AiThreatDetector::new(config.security.ai.clone()) {
            Ok(detector) => {
                info!("✅ AI threat detection engine initialized successfully");
                Some(Arc::new(detector))
            }
            Err(e) => {
                warn!("❌ Failed to initialize AI threat detection: {}", e);
                None
            }
        }
    }

    fn add_default_rules(&mut self, config: &Config) {
        // Add content inspection rules
        if config.waf.content_inspection.enabled {
            for pattern in &config.waf.content_inspection.threat_patterns {
                let rule = ContentInspectionRuleFactory::create_threat_rule(pattern)
                    .with_inspection(
                        config.waf.content_inspection.inspect_headers,
                        config.waf.content_inspection.inspect_body,
                    );
                self.add_rule(rule);
            }
        }

        // Reject oversized bodies and dangerous HTTP methods before any
        // payload inspection.
        self.add_rule(RequestSizeRule::new(
            "request_body_size",
            config.server.max_body_size,
        ));
        self.add_rule(MethodRule::new("dangerous_methods"));

        // Rate limiting must be part of the live rule chain, not just config.
        if config.waf.rate_limit.per_ip_enabled {
            let window = config.waf.rate_limit.per_ip_window_secs.max(1);
            let refill = (config.waf.rate_limit.per_ip_max_requests as f64 / window as f64)
                .ceil()
                .max(1.0) as u32;
            let limiter = RateLimiter::new(
                "per_ip_rate_limit",
                config.waf.rate_limit.per_ip_max_requests.max(1),
                refill,
                std::time::Duration::from_secs(window),
            )
            .with_limits(
                config.waf.rate_limit.max_tracked_ips,
                config.waf.rate_limit.capacity_policy,
            );
            #[cfg(feature = "distri-kv")]
            let limiter = match &self.distributed {
                Some(state) => limiter.with_distributed_state(Arc::clone(state)),
                None => limiter,
            };
            self.add_rule(limiter);
        }
        if config.waf.rate_limit.global_enabled {
            let window = config.waf.rate_limit.global_window_secs.max(1);
            let refill = (config.waf.rate_limit.global_max_requests as f64 / window as f64)
                .ceil()
                .max(1.0) as u32;
            self.add_rule(GlobalRateLimiter::new(
                "global_rate_limit",
                config.waf.rate_limit.global_max_requests.max(1),
                refill,
            ));
        }

        // Add geographic blocking rules
        if config.waf.geo_blocking.enabled {
            for country_code in &config.waf.geo_blocking.blocked_countries {
                let rule = GeoBlockingRuleFactory::create_country_rule(
                    country_code,
                    Arc::clone(&self.geoip_service),
                );
                self.add_rule(rule);
            }
            warn!(
                "Geographic blocking is enabled for {} countries, but no GeoIP database is loaded; unknown IPs will not be matched",
                config.waf.geo_blocking.blocked_countries.len()
            );
        }

        if config.waf.security_events.enabled
            && !matches!(
                config.waf.security_events.format.as_str(),
                "json" | "cef" | "plain"
            )
        {
            warn!(
                "Unknown security event format '{}'; falling back to json",
                config.waf.security_events.format
            );
        }

        info!("Added {} default WAF rules", self.rule_count());
    }

    /// Replace the admission controller. Primarily for embedding and tests.
    pub fn with_admission(mut self, admission: AdmissionController) -> Self {
        self.admission = admission;
        self
    }

    /// The admission controller used for heavy inspections.
    pub fn admission(&self) -> &AdmissionController {
        &self.admission
    }

    /// Whether the compiled bodyless allowlist is enabled.
    pub fn fast_allow_enabled(&self) -> bool {
        self.fast_allow.enabled()
    }

    /// Number of compiled fast-allow routes.
    pub fn fast_allow_route_count(&self) -> usize {
        self.fast_allow.route_count()
    }

    /// Look up a bodyless request in the compiled allowlist.
    ///
    /// `None` means "fall through to full evaluation": the route is not
    /// configured, the request is not bodyless (query, body framing, content
    /// encoding, upgrade or a gRPC/GraphQL content type), or a rule in the
    /// chain is not fast-allow safe. `Some(Allow)` is the precomputed route
    /// verdict after every always-on policy gate (size, method, rate limits,
    /// geographic blocking) allowed the request. A gate rejection is returned
    /// with the triggering rule so the caller can audit it.
    ///
    /// This method borrows the method/URI/headers: it never clones a
    /// `HeaderMap`, allocates a `RequestContext` or formats a string on the
    /// allow path.
    pub fn fast_allow(
        &self,
        method: &Method,
        uri: &Uri,
        headers: &HeaderMap,
        client_ip: IpAddr,
        body_size: Option<usize>,
        body_is_empty: bool,
    ) -> Option<fast_allow::FastAllowOutcome> {
        if !self.enabled || !self.fast_allow.enabled() {
            return None;
        }
        // Never fast-allow through a fail-closed initialisation failure.
        if self.wasm_init_failed && self.fail_closed {
            return None;
        }
        if !body_is_empty
            || !fast_allow::is_bodyless_headers(headers)
            || fast_allow::has_protocol_content_type(headers)
        {
            return None;
        }
        if !self.fast_allow.matches(method, uri) {
            return None;
        }

        let ctx = fast_allow::FastAllowContext {
            client_ip,
            method,
            uri,
            headers,
            body_size,
        };
        let rules = self.rules.read().unwrap();

        // Pass 1: only allow when every enabled rule is either inspection the
        // route opted out of, or a gate we can evaluate. Any custom/unknown
        // rule falls through before a gate consumes state.
        for rule in rules.iter() {
            if !rule.is_enabled() {
                continue;
            }
            if rule.fast_allow_policy() == fast_allow::FastAllowPolicy::FallThrough {
                drop(rules);
                self.record_fast_allow_fallthrough();
                return None;
            }
        }

        // Pass 2: evaluate always-on gates. No inspection rule runs here.
        for rule in rules.iter() {
            if !rule.is_enabled() || rule.fast_allow_policy() != fast_allow::FastAllowPolicy::Gate {
                continue;
            }
            let decision = rule.fast_allow_gate(&ctx);
            if decision != Decision::Allow {
                let triggered_rules = vec![rule.name().to_string()];
                drop(rules);
                self.record_fast_allow_block();
                return Some(fast_allow::FastAllowOutcome {
                    decision,
                    triggered_rules,
                });
            }
        }

        drop(rules);
        self.record_fast_allow_hit();
        Some(fast_allow::FastAllowOutcome {
            decision: Decision::Allow,
            triggered_rules: Vec::new(),
        })
    }

    fn record_fast_allow_hit(&self) {
        if let Some(metrics) = &self.metrics {
            metrics.record_fast_allow_hit();
        }
    }

    fn record_fast_allow_block(&self) {
        if let Some(metrics) = &self.metrics {
            metrics.record_fast_allow_block();
        }
    }

    fn record_fast_allow_fallthrough(&self) {
        if let Some(metrics) = &self.metrics {
            metrics.record_fast_allow_fallthrough();
        }
    }

    /// Emit the audit event for a fast-allow decision. Only called for blocks
    /// and for sampled allows, so the allow path normally pays nothing.
    #[allow(clippy::too_many_arguments)]
    pub async fn audit_fast_decision(
        &self,
        client_ip: IpAddr,
        method: &Method,
        uri: &Uri,
        headers: &HeaderMap,
        http_version: &str,
        decision: &Decision,
        triggered_rules: Vec<String>,
    ) {
        let ctx = RequestContext::with_http_version(
            client_ip,
            method.clone(),
            uri.clone(),
            headers.clone(),
            None,
            http_version.to_string(),
        );
        self.event_logger
            .log_event(&ctx, decision, triggered_rules)
            .await;
    }

    pub fn add_rule<R: WafRule + 'static>(&mut self, rule: R) {
        self.add_rule_boxed(Box::new(rule));
    }

    fn add_rule_boxed(&mut self, rule: Box<dyn WafRule>) {
        let mut rules = self.rules.write().unwrap();
        rules.push(rule);
        drop(rules);
        // A rule-set change is a policy change: never serve an entry produced
        // under the previous rule chain.
        #[cfg(feature = "allow-cache")]
        if let Some(cache) = &self.allow_cache {
            cache.invalidate();
        }
    }

    /// Builds a per-message inspector for the incremental streaming path.
    ///
    /// Returns an inspector only when protocol-aware gRPC inspection is
    /// enabled, so streaming relays keep working in builds without it. The
    /// returned inspector borrows the request headers/method policy but owns
    /// cloned state, so it can live inside the request body guard.
    #[cfg(feature = "wasm-reactor")]
    pub(crate) fn grpc_stream_frame_inspector(
        &self,
        request: &RequestContext,
    ) -> Option<grpc::GrpcStreamFrameInspector> {
        self.grpc_inspector.as_ref().map(|inspector| {
            grpc::GrpcStreamFrameInspector::new(
                inspector.clone(),
                request.clone(),
                self.fail_closed,
            )
        })
    }

    /// Builds a per-message inspector for the incremental streaming path.
    ///
    /// Protocol-aware gRPC inspection requires the reactor feature; in builds
    /// without it the streaming relay runs transport-only, matching the
    /// previous behaviour.
    #[cfg(not(feature = "wasm-reactor"))]
    pub(crate) fn grpc_stream_frame_inspector(
        &self,
        _request: &RequestContext,
    ) -> Option<grpc::GrpcStreamFrameInspector> {
        None
    }

    /// Outcome of the gRPC protocol pre-check.
    ///
    /// Synchronous by design: its Coraza field-content scan is one of the
    /// reasons the whole stage sequence is offloaded to a blocking thread.
    #[cfg(feature = "wasm-reactor")]
    fn grpc_precheck(&self, request: &RequestContext) -> Option<GrpcPrecheck> {
        let inspector = self.grpc_inspector.as_ref()?;
        if !inspector.matches(request) {
            return None;
        }

        match inspector.inspect(request) {
            Ok(grpc::GrpcVerdict::Allow {
                strip_body,
                monitored,
            }) => {
                if let Some(metrics) = &self.metrics {
                    metrics.record_grpc_allow();
                }
                if monitored {
                    debug!(
                        uri = %request.uri,
                        "gRPC method not in allowlist; monitor mode allows the request"
                    );
                }
                if strip_body {
                    Some(GrpcPrecheck::Continue(Box::new(grpc::strip_body(request))))
                } else {
                    None
                }
            }
            Ok(grpc::GrpcVerdict::Block { status, reason }) => {
                if let Some(metrics) = &self.metrics {
                    metrics.record_grpc_block();
                }
                Some(GrpcPrecheck::Reject(CoreOutcome::new(
                    Decision::Block { status, reason },
                    vec!["grpc-protocol-inspection".to_string()],
                )))
            }
            Err(err) => {
                if let Some(metrics) = &self.metrics {
                    metrics.record_grpc_error();
                }
                if self.fail_closed {
                    Some(GrpcPrecheck::Reject(CoreOutcome::new(
                        Decision::Block {
                            status: 503,
                            reason: format!("gRPC inspection unavailable: {err}"),
                        },
                        vec!["grpc-protocol-inspection".to_string()],
                    )))
                } else {
                    warn!(
                        error = %err,
                        "gRPC inspection failed; continuing because fail_mode is open"
                    );
                    // Never hand protobuf bytes to CRS body rules even when
                    // fail-open tolerates the inspection failure.
                    Some(GrpcPrecheck::Continue(Box::new(grpc::strip_body(request))))
                }
            }
        }
    }

    /// Outcome of the GraphQL protocol pre-check.
    ///
    /// Synchronous by design: the stage sequence runs inside a blocking task.
    #[cfg(feature = "wasm-reactor")]
    fn graphql_precheck(&self, request: &RequestContext) -> Option<GraphqlPrecheck> {
        let inspector = self.graphql_inspector.as_ref()?;
        if !inspector.matches(request) {
            return None;
        }

        match inspector.inspect(request) {
            Ok(graphql::GraphqlVerdict::Allow {
                strip_body,
                monitored,
                operation_type,
                operation_name,
                query_hash,
            }) => {
                if let Some(metrics) = &self.metrics {
                    metrics.record_graphql_allow();
                }
                debug!(
                    operation_type = operation_type.as_str(),
                    operation = operation_name.as_deref().unwrap_or("<anonymous>"),
                    hash = %query_hash,
                    monitored,
                    strip_body,
                    "GraphQL pre-check passed"
                );
                if strip_body {
                    Some(GraphqlPrecheck::Continue(Box::new(graphql::strip_body(
                        request,
                    ))))
                } else {
                    None
                }
            }
            Ok(graphql::GraphqlVerdict::Block { status, reason }) => {
                if let Some(metrics) = &self.metrics {
                    metrics.record_graphql_block();
                }
                Some(GraphqlPrecheck::Reject(CoreOutcome::new(
                    Decision::Block { status, reason },
                    vec![graphql::RULE_NAME.to_string()],
                )))
            }
            Err(err) => {
                if let Some(metrics) = &self.metrics {
                    metrics.record_graphql_error();
                }
                if self.fail_closed {
                    Some(GraphqlPrecheck::Reject(CoreOutcome::new(
                        Decision::Block {
                            status: 503,
                            reason: format!("GraphQL inspection unavailable: {err}"),
                        },
                        vec![graphql::RULE_NAME.to_string()],
                    )))
                } else {
                    warn!(
                        error = %err,
                        "GraphQL inspection failed; continuing because fail_mode is open"
                    );
                    // `graphql-only` promised to keep the raw body away from
                    // CRS; `crs` mode should keep scanning it.
                    if inspector.matches(request) && self.graphql_strips_body() {
                        Some(GraphqlPrecheck::Continue(Box::new(graphql::strip_body(
                            request,
                        ))))
                    } else {
                        None
                    }
                }
            }
        }
    }

    #[cfg(feature = "wasm-reactor")]
    fn graphql_strips_body(&self) -> bool {
        self.graphql_inspector
            .as_ref()
            .is_some_and(|inspector| inspector.strips_body())
    }

    /// Admission signals for the request as received, before any pre-check.
    ///
    /// Classification must not use the post-pre-check context: the gRPC
    /// pre-check withholds the protobuf body from CRS but may still run its own
    /// Coraza evaluation of decoded field values, which is as expensive as a
    /// CRS body scan.
    fn inspection_signals(&self, request: &RequestContext) -> admission::InspectionSignals {
        let body_present = request.body.as_ref().is_some_and(|body| !body.is_empty());
        #[cfg(feature = "wasm-reactor")]
        {
            let grpc = self.grpc_inspector.as_ref();
            let graphql = self.graphql_inspector.as_ref();
            admission::InspectionSignals {
                body_present,
                protocol_content_scan: grpc
                    .is_some_and(|inspector| inspector.scans_content(request)),
                body_withheld: grpc.is_some_and(|inspector| inspector.matches(request))
                    || graphql.is_some_and(|inspector| {
                        inspector.matches(request) && inspector.strips_body()
                    }),
            }
        }
        #[cfg(not(feature = "wasm-reactor"))]
        {
            admission::InspectionSignals {
                body_present,
                protocol_content_scan: false,
                body_withheld: false,
            }
        }
    }

    fn inspection_cost(&self, request: &RequestContext) -> admission::InspectionCost {
        admission::classify(self.inspection_signals(request))
    }

    /// Fail-closed response for a request rejected by admission control.
    async fn admission_rejected(
        &self,
        request: &RequestContext,
        rejection: admission::AdmissionRejection,
    ) -> Decision {
        let decision = Decision::Block {
            status: 503,
            reason: format!(
                "WAF admission control rejected heavy inspection: {rejection}; retry later"
            ),
        };
        warn!(
            client_ip = %request.client_ip,
            reason = %rejection,
            "heavy inspection rejected by admission control"
        );
        self.event_logger
            .log_event(request, &decision, vec!["admission-control".to_string()])
            .await;
        decision
    }

    /// Acquire admission for one evaluation.
    ///
    /// The wait happens on the async runtime, before any blocking stage, so a
    /// queued request never occupies an evaluation thread. Rejections are
    /// mapped to the fail-closed `503` decision here.
    async fn admit(&self, request: &RequestContext) -> Result<AdmissionGuard, Decision> {
        match self.admission.admit(self.inspection_cost(request)).await {
            Ok(guard) => Ok(guard),
            Err(rejection) => Err(self.admission_rejected(request, rejection).await),
        }
    }

    /// Emit the audit event for a completed evaluation.
    ///
    /// Exactly one event is emitted per evaluation, matching the inline path
    /// this replaced: blocks, rate limits and allows all produce one event.
    async fn finish(&self, request: &RequestContext, outcome: CoreOutcome) -> Decision {
        self.event_logger
            .log_event(request, &outcome.decision, outcome.triggered_rules)
            .await;
        outcome.decision
    }

    /// Complete a fast-allow lookup. Allows skip audit construction unless the
    /// configured sample rate selects them; blocks and rate limits are always
    /// audited.
    async fn complete_fast_allow(
        &self,
        request: &RequestContext,
        outcome: fast_allow::FastAllowOutcome,
    ) -> Decision {
        match outcome.decision {
            Decision::Allow => {
                if self.fast_allow.should_sample_allow() {
                    self.finish(request, CoreOutcome::new(Decision::Allow, Vec::new()))
                        .await;
                }
                Decision::Allow
            }
            decision => {
                self.finish(request, CoreOutcome::new(decision, outcome.triggered_rules))
                    .await
            }
        }
    }

    /// Synchronous protocol pre-checks: GraphQL, then gRPC.
    ///
    /// Both run a Coraza evaluation of decoded content (the gRPC field-content
    /// scan is a full body scan) and neither needs the async runtime, so the
    /// sequence is safe to run on a blocking thread.
    #[cfg_attr(not(feature = "wasm-reactor"), allow(unused_variables))]
    fn precheck_core(&self, request: &RequestContext) -> PrecheckOutcome {
        #[cfg(feature = "wasm-reactor")]
        {
            let graphql_stripped = match self.graphql_precheck(request) {
                Some(GraphqlPrecheck::Reject(outcome)) => return PrecheckOutcome::Reject(outcome),
                Some(GraphqlPrecheck::Continue(context)) => Some(context),
                None => None,
            };
            let request: &RequestContext = graphql_stripped.as_deref().unwrap_or(request);

            let grpc_stripped = match self.grpc_precheck(request) {
                Some(GrpcPrecheck::Reject(outcome)) => return PrecheckOutcome::Reject(outcome),
                Some(GrpcPrecheck::Continue(context)) => Some(context),
                None => None,
            };
            // The gRPC context is derived from the GraphQL one, so it already
            // carries the GraphQL body policy.
            PrecheckOutcome::Continue(grpc_stripped.or(graphql_stripped))
        }
        #[cfg(not(feature = "wasm-reactor"))]
        {
            PrecheckOutcome::Continue(None)
        }
    }

    /// Fail-closed decision when a configured WASM engine never initialised.
    fn init_failure(&self) -> Option<CoreOutcome> {
        if self.wasm_init_failed && self.fail_closed {
            Some(CoreOutcome::new(
                Decision::Block {
                    status: 503,
                    reason: "WAF engine failed to initialise (fail-closed)".to_string(),
                },
                vec!["wasm_init_failed".to_string()],
            ))
        } else {
            None
        }
    }

    /// Synchronous traditional rule chain.
    ///
    /// Returns the first blocking decision, or `Allow` when every rule passed.
    fn rules_core(&self, request: &RequestContext) -> CoreOutcome {
        self.rules_core_filtered(request, false)
    }

    /// Rule-chain pass used by an allow-cache hit: pure content rules are
    /// skipped because their `Allow` was memoised, while every stateful or
    /// IP-dependent rule still runs.
    #[cfg(feature = "allow-cache")]
    fn rules_core_cache_hit(&self, request: &RequestContext) -> CoreOutcome {
        self.rules_core_filtered(request, true)
    }

    fn rules_core_filtered(&self, request: &RequestContext, skip_cacheable: bool) -> CoreOutcome {
        let mut triggered_rules = Vec::new();
        {
            let rules = self.rules.read().unwrap();
            let rules_count = rules.len();

            debug!(
                "Evaluating {} traditional rules for request from {}",
                rules_count, request.client_ip
            );

            for rule in rules.iter() {
                if !rule.is_enabled() {
                    continue;
                }
                if skip_cacheable && rule.cacheable() {
                    continue;
                }

                let decision = rule.evaluate(request);
                match &decision {
                    Decision::Block { status, reason } => {
                        triggered_rules.push(rule.name().to_string());

                        warn!(
                            "Rule '{}' blocked request from {}: {} ({})",
                            rule.name(),
                            request.client_ip,
                            reason,
                            status
                        );

                        return CoreOutcome::new(decision, triggered_rules);
                    }
                    Decision::RateLimit { reason } => {
                        triggered_rules.push(rule.name().to_string());

                        warn!(
                            "Rule '{}' rate limited request from {}: {}",
                            rule.name(),
                            request.client_ip,
                            reason
                        );

                        return CoreOutcome::new(decision, triggered_rules);
                    }
                    Decision::Allow => {
                        debug!("Rule '{}' allowed request", rule.name());
                    }
                }
            }

            debug!(
                "All {} rules passed for request from {}",
                rules_count, request.client_ip
            );
        } // RwLockReadGuard is dropped here

        CoreOutcome::new(Decision::Allow, triggered_rules)
    }

    /// Rule chain with the experimental allow-verdict cache in front.
    ///
    /// The cache is consulted after the protocol pre-checks and admission (the
    /// callers acquire admission before this function), so a hit skips only
    /// the pure content rules. A miss evaluates the full chain and inserts
    /// only when the result is `Allow`; blocks and rate limits are never
    /// stored. When the feature or configuration is off this is exactly
    /// [`Self::rules_core`].
    fn rules_with_cache(&self, request: &RequestContext) -> CoreOutcome {
        #[cfg(feature = "allow-cache")]
        if let Some(cache) = &self.allow_cache {
            if cache.applies_to(&request.uri) {
                match cache.fingerprint(request) {
                    allow_cache::KeyBuild::Fingerprint(fingerprint) => {
                        // The body digest is verified inside `lookup`; the
                        // fingerprint alone never authorises an allow.
                        let body = request.body.as_deref().unwrap_or_default();
                        if cache.lookup(fingerprint, body) {
                            return self.rules_core_cache_hit(request);
                        }
                        let outcome = self.rules_core(request);
                        if outcome.decision == Decision::Allow {
                            cache.insert(fingerprint, body);
                        }
                        return outcome;
                    }
                    allow_cache::KeyBuild::NotCacheable(reason) => {
                        cache.record_skipped(reason);
                    }
                }
            }
        }
        self.rules_core(request)
    }

    /// The complete synchronous inspection: pre-checks, the initialisation
    /// gate and the rule chain.
    ///
    /// This is what [`Self::evaluate_shared`] hands to `spawn_blocking`. It is
    /// only defined for builds without the async WASM/AI stages; those builds
    /// keep the inline path (see [`Self::evaluate_shared`]).
    #[cfg(not(any(feature = "wasm-waf", feature = "ai-threat-detection")))]
    fn evaluate_core(&self, request: &RequestContext) -> CoreOutcome {
        // Protocol pre-checks always run, including on an allow-cache hit. The
        // cache only memoises the pure content-rule verdict; it must never skip
        // gRPC/GraphQL descriptor checks. Descriptor reloads invalidate the
        // cache through `reload_protocol_descriptors`.
        let stripped = match self.precheck_core(request) {
            PrecheckOutcome::Reject(outcome) => return outcome,
            PrecheckOutcome::Continue(stripped) => stripped,
        };
        let request: &RequestContext = stripped.as_deref().unwrap_or(request);

        if let Some(outcome) = self.init_failure() {
            return outcome;
        }

        self.rules_with_cache(request)
    }

    /// Fast evaluation for performance-critical paths.
    ///
    /// Runs the protocol pre-checks and the rule chain (which includes the
    /// Coraza reactor rule) but skips the WASM/AI stages and does not emit an
    /// audit event for allowed requests.
    pub async fn fast_evaluate(&self, request: &RequestContext) -> Decision {
        if !self.enabled {
            return Decision::Allow;
        }

        if let Some(outcome) = self.fast_allow(
            &request.method,
            &request.uri,
            &request.headers,
            request.client_ip,
            request.body_size,
            request.body.as_ref().is_none_or(|body| body.is_empty()),
        ) {
            return self.complete_fast_allow(request, outcome).await;
        }

        let guard = match self.admit(request).await {
            Ok(guard) => guard,
            Err(decision) => return decision,
        };

        // Protocol pre-checks always run, including on an allow-cache hit.
        let stripped = match self.precheck_core(request) {
            PrecheckOutcome::Reject(outcome) => {
                drop(guard);
                return self.finish(request, outcome).await;
            }
            PrecheckOutcome::Continue(stripped) => stripped,
        };
        let request: &RequestContext = stripped.as_deref().unwrap_or(request);

        #[cfg(feature = "wasm-waf")]
        if let Some(_wasm_engine) = &self.wasm_engine {
            debug!("Skipping WASM evaluation for fast path (performance optimization)");
        }

        let outcome = self.rules_with_cache(request);
        drop(guard);

        // Even the fast path must produce an audit event for blocks.
        if outcome.decision == Decision::Allow {
            return Decision::Allow;
        }
        self.finish(request, outcome).await
    }

    /// Evaluate all rules against the request context.
    ///
    /// Returns the first blocking decision or `Allow` if all rules pass. The
    /// synchronous stages run on the calling thread; async callers that hold
    /// the engine behind an [`Arc`] should prefer [`Self::evaluate_shared`],
    /// which offloads them.
    pub async fn evaluate(&self, request: &RequestContext) -> Decision {
        if !self.enabled {
            return Decision::Allow;
        }

        if let Some(outcome) = self.fast_allow(
            &request.method,
            &request.uri,
            &request.headers,
            request.client_ip,
            request.body_size,
            request.body.as_ref().is_none_or(|body| body.is_empty()),
        ) {
            return self.complete_fast_allow(request, outcome).await;
        }

        // Admission control covers the protocol pre-checks as well as the rule
        // chain: a gRPC field-content scan runs a Coraza evaluation before the
        // main evaluation. Classification uses the original request, because
        // the pre-checks strip the body that made the scan expensive.
        let guard = match self.admit(request).await {
            Ok(guard) => guard,
            Err(decision) => return decision,
        };

        #[cfg(not(any(feature = "wasm-waf", feature = "ai-threat-detection")))]
        let outcome = self.evaluate_core(request);

        #[cfg(any(feature = "wasm-waf", feature = "ai-threat-detection"))]
        let outcome = self.evaluate_with_async_stages(request).await;

        drop(guard);
        self.finish(request, outcome).await
    }

    /// Evaluate a request without blocking the calling Tokio worker.
    ///
    /// Identical in behaviour to [`Self::evaluate`], but a *heavy* inspection
    /// (a CRS body scan or a gRPC field-content scan) runs on a Tokio blocking
    /// thread instead of the calling worker. Those scans cost 39–706 ms on the
    /// reference host and used to park a worker for their whole duration, so a
    /// handful of them stalled unrelated connections even though the Coraza
    /// reactor has its own thread pool.
    ///
    /// Cheap evaluations (no body, or a body withheld from CRS) stay inline:
    /// they are a header/URI rule pass plus a short reactor round-trip, and
    /// offloading them measured worse for bodyless p95 without a throughput
    /// gain.
    ///
    /// Only the engine handle and the request are moved into the task, so no
    /// engine state is cloned per request and the body is shared through
    /// [`Bytes`]. Admission is still acquired asynchronously *before* the
    /// offload, and the permit moves into the blocking task so it is released
    /// when the inspection actually finishes rather than when the caller stops
    /// waiting.
    pub async fn evaluate_shared(self: &Arc<Self>, request: &RequestContext) -> Decision {
        // The WASM and AI stages are async and would need a nested `block_on`
        // inside the blocking task, so those builds keep the inline path
        // instead of nesting runtimes.
        #[cfg(any(feature = "wasm-waf", feature = "ai-threat-detection"))]
        {
            return self.evaluate(request).await;
        }

        #[cfg(not(any(feature = "wasm-waf", feature = "ai-threat-detection")))]
        {
            if !self.enabled {
                return Decision::Allow;
            }

            if let Some(outcome) = self.fast_allow(
                &request.method,
                &request.uri,
                &request.headers,
                request.client_ip,
                request.body_size,
                request.body.as_ref().is_none_or(|body| body.is_empty()),
            ) {
                return self.complete_fast_allow(request, outcome).await;
            }

            let cost = self.inspection_cost(request);
            let guard = match self.admission.admit(cost).await {
                Ok(guard) => guard,
                Err(rejection) => return self.admission_rejected(request, rejection).await,
            };

            // Cheap evaluations are a header/URI rule pass plus a short reactor
            // round-trip (no body scan). Running them inline keeps the reactor
            // queue shallow: offloading them too measured ~25% worse bodyless
            // p95 at concurrency 64 for no throughput gain, because the extra
            // thread hop and the deeper queue cost more than the parked worker
            // does at sub-millisecond inspection times.
            //
            // The native Rust engine is also cheap in absolute terms, so its
            // normal-size body scans stay inline as well: the `spawn_blocking`
            // hand-off plus the owned `RequestContext` clone otherwise cost
            // more than the scan itself. Large bodies keep the blocking-pool
            // path so a pathological payload cannot park a runtime worker.
            let inline_body = self.inline_heavy
                && request
                    .body
                    .as_ref()
                    .map_or(request.body_size.unwrap_or(0), |body| body.len())
                    <= INLINE_HEAVY_MAX_BYTES;
            if cost == admission::InspectionCost::Cheap || inline_body {
                let outcome = self.evaluate_core(request);
                drop(guard);
                return self.finish(request, outcome).await;
            }

            let engine = Arc::clone(self);
            let owned = request.clone();
            let joined = tokio::task::spawn_blocking(move || {
                // Keep the permit inside the task: dropping the caller's
                // future must not release admission while the scan still runs.
                let _guard = guard;
                engine.evaluate_core(&owned)
            })
            .await;

            match joined {
                Ok(outcome) => self.finish(request, outcome).await,
                Err(error) => {
                    // A panicking rule used to take down the request task. The
                    // offloaded path can only observe it as a `JoinError`; keep
                    // the configured fail mode instead of silently allowing.
                    tracing::error!(error = %error, "WAF evaluation task failed");
                    let decision = if self.fail_closed {
                        Decision::Block {
                            status: 503,
                            reason: "WAF evaluation failed (fail-closed)".to_string(),
                        }
                    } else {
                        Decision::Allow
                    };
                    self.finish(
                        request,
                        CoreOutcome::new(decision, vec!["evaluation-task-failed".to_string()]),
                    )
                    .await
                }
            }
        }
    }

    /// True when a response-phase evaluator is attached (native Rust engine).
    pub fn has_response_evaluator(&self) -> bool {
        self.response_evaluator.is_some()
    }

    /// Attach a response evaluator (used by proxy unit tests).
    #[cfg(test)]
    pub(crate) fn set_response_evaluator(&mut self, evaluator: Arc<dyn ResponseEvaluator>) {
        self.response_evaluator = Some(evaluator);
    }

    /// Evaluate an upstream response with the attached response evaluator.
    ///
    /// Returns `None` when response inspection is unavailable (WAF disabled or
    /// a backend without a response path). Engine errors and panics fail
    /// closed with a `500` block.
    pub async fn evaluate_response_shared(
        self: &Arc<Self>,
        request: &RequestContext,
        response: &ResponseContext,
        options: &ResponseInspectionOptions,
    ) -> Option<Decision> {
        if !self.enabled {
            return None;
        }
        let evaluator = self.response_evaluator.clone()?;
        let request = request.clone();
        let response = response.clone();
        let options = *options;
        match tokio::task::spawn_blocking(move || {
            evaluator.evaluate_response(&request, &response, &options)
        })
        .await
        {
            Ok(decision) => Some(decision),
            Err(error) => {
                tracing::error!(error = %error, "response inspection task failed");
                Some(Decision::Block {
                    status: 500,
                    reason: "response inspection failed (fail-closed)".to_string(),
                })
            }
        }
    }

    /// Evaluation for builds that carry the async WASM/AI stages.
    ///
    /// Same order as the offloaded path: pre-checks, initialisation gate, WASM,
    /// AI, then the rule chain.
    #[cfg(any(feature = "wasm-waf", feature = "ai-threat-detection"))]
    async fn evaluate_with_async_stages(&self, request: &RequestContext) -> CoreOutcome {
        let stripped = match self.precheck_core(request) {
            PrecheckOutcome::Reject(outcome) => return outcome,
            PrecheckOutcome::Continue(stripped) => stripped,
        };
        let request: &RequestContext = stripped.as_deref().unwrap_or(request);

        if let Some(outcome) = self.init_failure() {
            return outcome;
        }

        // PHASE 1: WASM ModSecurity evaluation (if enabled)
        #[cfg(feature = "wasm-waf")]
        if let Some(wasm_engine) = &self.wasm_engine {
            debug!("Evaluating request through WASM ModSecurity engine");

            // Convert RequestContext to WasmRequestContext
            let wasm_context = self.create_wasm_context(request);

            match wasm_engine.process_request(wasm_context).await {
                Ok(wasm_decision) => {
                    let decision = self.convert_wasm_decision(wasm_decision);
                    match &decision {
                        Decision::Block { .. } | Decision::RateLimit { .. } => {
                            info!("Request blocked by WASM ModSecurity engine");
                            return CoreOutcome::new(
                                decision,
                                vec!["WASM-ModSecurity".to_string()],
                            );
                        }
                        Decision::Allow => {
                            debug!("Request allowed by WASM ModSecurity engine, continuing with traditional rules");
                        }
                    }
                }
                Err(e) => {
                    warn!("WASM ModSecurity engine error: {}", e);
                    if self.fail_closed {
                        return CoreOutcome::new(
                            Decision::Block {
                                status: 503,
                                reason: "WAF engine unavailable (fail-closed)".to_string(),
                            },
                            Vec::new(),
                        );
                    }
                }
            }
        }

        // PHASE 2: AI Threat Detection (if enabled)
        #[cfg(feature = "ai-threat-detection")]
        if let Some(ai_detector) = &self.ai_detector {
            debug!("Evaluating request through AI threat detection");

            match ai_detector.analyze_request(request).await {
                Ok(ai_result) => {
                    if ai_result.should_block {
                        info!(
                            "Request blocked by AI threat detection (score: {:.3})",
                            ai_result.analysis.overall_risk_score
                        );
                        return CoreOutcome::new(
                            Decision::Block {
                                status: 403,
                                reason: format!(
                                    "AI detected threat (score: {:.3})",
                                    ai_result.analysis.overall_risk_score
                                ),
                            },
                            vec!["AI-Threat-Detection".to_string()],
                        );
                    } else {
                        debug!(
                            "AI analysis passed (score: {:.3})",
                            ai_result.analysis.overall_risk_score
                        );
                    }
                }
                Err(e) => {
                    warn!("AI analysis error: {}", e);
                    if self.fail_closed {
                        return CoreOutcome::new(
                            Decision::Block {
                                status: 503,
                                reason: "WAF AI engine unavailable (fail-closed)".to_string(),
                            },
                            Vec::new(),
                        );
                    }
                }
            }
        }

        // PHASE 3: Traditional rule evaluation
        self.rules_with_cache(request)
    }

    #[cfg(feature = "wasm-waf")]
    fn create_wasm_context(&self, request: &RequestContext) -> WasmRequestContext {
        // Convert headers to Vec<(&str, &str)>
        let headers: Vec<(&str, &str)> = request
            .headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.to_str().unwrap_or("")))
            .collect();

        // Get body bytes if available
        let body_bytes = request.body.as_ref().map(|b| b.to_vec());

        WasmRequestContext::from_http_request(
            request.method.as_str(),
            request
                .uri
                .path_and_query()
                .map(|pq| pq.as_str())
                .unwrap_or("/"),
            &headers,
            &request.client_ip.to_string(),
            body_bytes.as_deref(),
        )
    }

    #[cfg(feature = "wasm-waf")]
    fn convert_wasm_decision(&self, wasm_decision: WasmDecision) -> Decision {
        match wasm_decision {
            WasmDecision::Allow => Decision::Allow,
            WasmDecision::Block {
                rule_id, message, ..
            } => Decision::Block {
                status: 403,
                reason: format!("WASM Rule {}: {}", rule_id, message),
            },
            WasmDecision::Log {
                rule_id, message, ..
            } => {
                info!("WASM security log - Rule {}: {}", rule_id, message);
                Decision::Allow // Log rules don't block
            }
            WasmDecision::Challenge { message, .. } => Decision::RateLimit {
                reason: format!("WASM Challenge: {}", message),
            },
        }
    }

    pub fn rule_count(&self) -> usize {
        self.rules.read().unwrap().len()
    }

    /// Names of the configured rule chain, in evaluation order.
    pub fn rule_names(&self) -> Vec<String> {
        self.rules
            .read()
            .unwrap()
            .iter()
            .map(|rule| rule.name().to_string())
            .collect()
    }

    pub fn enabled_rule_count(&self) -> usize {
        self.rules
            .read()
            .unwrap()
            .iter()
            .filter(|r| r.is_enabled())
            .count()
    }

    /// The experimental allow-verdict cache, when the `allow-cache` feature is
    /// compiled in and `waf.allow_cache.enabled` is true.
    #[cfg(feature = "allow-cache")]
    pub fn allow_cache(&self) -> Option<&Arc<allow_cache::AllowCache>> {
        self.allow_cache.as_ref()
    }

    /// Invalidate every allow-cache entry and move to a new policy generation.
    #[cfg(feature = "allow-cache")]
    pub fn invalidate_allow_cache(&self) {
        if let Some(cache) = &self.allow_cache {
            cache.invalidate();
        }
    }

    /// The distributed fabric handle, when the `distri-kv` feature is compiled
    /// in and `waf.distributed.enabled` is true. `None` is the default and
    /// means the engine is entirely process-local.
    #[cfg(feature = "distri-kv")]
    pub fn distributed_state(&self) -> Option<&Arc<distributed::DistributedState>> {
        self.distributed.as_ref()
    }

    /// Reload gRPC/GraphQL descriptor-backed policy and invalidate the
    /// allow-verdict cache.
    ///
    /// A descriptor reload changes the inputs to the protocol pre-checks, so a
    /// cached `Allow` from the previous descriptor generation must never be
    /// served. This is the only supported reload entry point; callers must not
    /// replace the inspectors directly.
    #[cfg(feature = "wasm-reactor")]
    pub fn reload_protocol_descriptors(&mut self, config: &Config) -> Result<(), String> {
        let grpc_enabled =
            config.waf.enabled && config.waf.coraza.enabled && config.waf.grpc.enabled;
        if grpc_enabled {
            match self.grpc_inspector.as_mut() {
                Some(inspector) => inspector
                    .reload_from_config(&config.waf.grpc)
                    .map_err(|error| error.to_string())?,
                None => {
                    let mut inspector = grpc::GrpcInspector::try_from_config(&config.waf.grpc)
                        .map_err(|error| error.to_string())?;
                    if let Some(metrics) = &self.metrics {
                        inspector = inspector.with_metrics(Arc::clone(metrics));
                    }
                    self.grpc_inspector = Some(inspector);
                }
            }
        } else {
            self.grpc_inspector = None;
        }

        let graphql_enabled = config.waf.enabled
            && config.waf.graphql.enabled
            && config.waf.graphql.scan_mode() != crate::config::WafGraphqlScanMode::Off;
        if graphql_enabled {
            match self.graphql_inspector.as_mut() {
                Some(inspector) => inspector
                    .reload_from_config(&config.waf.graphql)
                    .map_err(|error| error.to_string())?,
                None => {
                    self.graphql_inspector = Some(graphql::GraphqlInspector::try_from_config(
                        &config.waf.graphql,
                    )?);
                }
            }
        } else {
            self.graphql_inspector = None;
        }

        #[cfg(feature = "allow-cache")]
        self.invalidate_allow_cache();

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[cfg(feature = "rust-engine")]
    #[test]
    fn default_config_selects_the_rust_engine() {
        let config = crate::config::Config::default();
        let engine = WafEngine::with_config(&config);
        assert!(
            engine.waf_init_error().is_none(),
            "startup failed: {:?}",
            engine.waf_init_error()
        );
        assert!(
            engine.rule_names().iter().any(|name| name == "rust-engine"),
            "rust backend was not installed: {:?}",
            engine.rule_names()
        );
    }

    #[cfg(all(feature = "rust-engine", feature = "wasm-reactor"))]
    #[test]
    fn explicit_wasm_selection_keeps_the_coraza_reactor() {
        let mut config = crate::config::Config::default();
        config.waf.coraza.backend = crate::config::CorazaBackend::Wasm;
        let engine = WafEngine::with_config(&config);
        assert!(engine.waf_init_error().is_none());
        let names = engine.rule_names();
        assert!(names.iter().any(|name| name.starts_with("coraza")));
        assert!(!names.iter().any(|name| name == "rust-engine"));
    }

    struct TestRule {
        name: String,
        decision: Decision,
        enabled: bool,
    }

    impl TestRule {
        fn new(name: &str, decision: Decision) -> Self {
            Self {
                name: name.to_string(),
                decision,
                enabled: true,
            }
        }

        fn disabled(mut self) -> Self {
            self.enabled = false;
            self
        }
    }

    impl WafRule for TestRule {
        fn name(&self) -> &str {
            &self.name
        }

        fn evaluate(&self, _ctx: &RequestContext) -> Decision {
            self.decision.clone()
        }

        fn is_enabled(&self) -> bool {
            self.enabled
        }
    }

    fn create_test_context() -> RequestContext {
        RequestContext::new(
            IpAddr::from_str("192.168.1.100").unwrap(),
            Method::GET,
            Uri::from_str("/test").unwrap(),
            HeaderMap::new(),
            None,
        )
    }

    #[tokio::test]
    async fn test_waf_disabled_allows_everything() {
        let mut config = crate::config::Config::default();
        config.waf.enabled = false;
        let engine = WafEngine::with_config(&config);

        let mut ctx = create_test_context();
        ctx.uri = Uri::from_str("/?id=1%20UNION%20SELECT%201").unwrap();
        assert_eq!(engine.evaluate(&ctx).await, Decision::Allow);
    }

    #[tokio::test]
    async fn test_waf_engine_empty() {
        let engine = WafEngine::new();
        let ctx = create_test_context();

        let decision = engine.evaluate(&ctx).await;
        assert_eq!(decision, Decision::Allow);
        assert_eq!(engine.rule_count(), 0);
        assert_eq!(engine.enabled_rule_count(), 0);
    }

    #[tokio::test]
    async fn test_waf_engine_allow_rule() {
        let mut engine = WafEngine::new();
        engine.add_rule(TestRule::new("allow_rule", Decision::Allow));

        let ctx = create_test_context();
        let decision = engine.evaluate(&ctx).await;
        assert_eq!(decision, Decision::Allow);
        assert_eq!(engine.rule_count(), 1);
        assert_eq!(engine.enabled_rule_count(), 1);
    }

    #[tokio::test]
    async fn test_waf_engine_block_rule() {
        let mut engine = WafEngine::new();
        engine.add_rule(TestRule::new(
            "block_rule",
            Decision::Block {
                status: 403,
                reason: "Test block".to_string(),
            },
        ));

        let ctx = create_test_context();
        let result = engine.evaluate(&ctx).await;

        match result {
            Decision::Block { status, reason } => {
                assert_eq!(status, 403);
                assert_eq!(reason, "Test block");
            }
            _ => panic!("Expected Block decision"),
        }
    }

    #[tokio::test]
    async fn test_waf_engine_first_block_wins() {
        let mut engine = WafEngine::new();
        engine.add_rule(TestRule::new("allow_rule", Decision::Allow));
        engine.add_rule(TestRule::new(
            "block_rule",
            Decision::Block {
                status: 403,
                reason: "First block".to_string(),
            },
        ));
        engine.add_rule(TestRule::new(
            "second_block_rule",
            Decision::Block {
                status: 404,
                reason: "Second block".to_string(),
            },
        ));

        let ctx = create_test_context();
        let result = engine.evaluate(&ctx).await;

        match result {
            Decision::Block { reason, .. } => {
                assert_eq!(reason, "First block");
            }
            _ => panic!("Expected Block decision"),
        }
    }

    #[tokio::test]
    async fn test_waf_engine_disabled_rule() {
        let mut engine = WafEngine::new();
        engine.add_rule(
            TestRule::new(
                "disabled_block_rule",
                Decision::Block {
                    status: 403,
                    reason: "Should not trigger".to_string(),
                },
            )
            .disabled(),
        );

        let ctx = create_test_context();
        let decision = engine.evaluate(&ctx).await;
        assert_eq!(decision, Decision::Allow);
        assert_eq!(engine.rule_count(), 1);
        assert_eq!(engine.enabled_rule_count(), 0);
    }

    #[tokio::test]
    async fn test_waf_engine_rate_limit() {
        let mut engine = WafEngine::new();
        engine.add_rule(TestRule::new(
            "rate_limit_rule",
            Decision::RateLimit {
                reason: "Too many requests".to_string(),
            },
        ));

        let ctx = create_test_context();
        let result = engine.evaluate(&ctx).await;

        match result {
            Decision::RateLimit { reason } => {
                assert_eq!(reason, "Too many requests");
            }
            _ => panic!("Expected RateLimit decision"),
        }
    }

    #[cfg(feature = "wasm-reactor")]
    fn reactor_only_config() -> crate::config::Config {
        let mut config = crate::config::Config::default();
        config.waf.content_inspection.enabled = false;
        config.waf.rate_limit.per_ip_enabled = false;
        config.waf.rate_limit.global_enabled = false;
        config.waf.geo_blocking.enabled = false;
        config.waf.coraza.backend = crate::config::CorazaBackend::Wasm;
        config.waf.coraza.enabled = true;
        config
    }

    #[cfg(feature = "wasm-reactor")]
    fn post_context(body: &str) -> RequestContext {
        let mut headers = HeaderMap::new();
        headers.insert(
            "content-type",
            "application/x-www-form-urlencoded".parse().unwrap(),
        );
        let mut ctx = RequestContext::new(
            IpAddr::from_str("192.168.1.100").unwrap(),
            Method::POST,
            Uri::from_str("/login").unwrap(),
            headers,
            Some(body.len()),
        );
        ctx = ctx.with_body(Some(Bytes::from(body.to_string())));
        ctx
    }

    #[cfg(feature = "wasm-reactor")]
    struct BodyProbeRule {
        seen: std::sync::Arc<std::sync::Mutex<Vec<Option<usize>>>>,
    }

    #[cfg(feature = "wasm-reactor")]
    impl WafRule for BodyProbeRule {
        fn name(&self) -> &str {
            "body-probe"
        }

        fn evaluate(&self, ctx: &RequestContext) -> Decision {
            self.seen
                .lock()
                .unwrap()
                .push(ctx.body.as_ref().map(|body| body.len()));
            Decision::Allow
        }
    }

    #[cfg(feature = "wasm-reactor")]
    fn grpc_body() -> Bytes {
        let payload = b"protobuf-bytes";
        let mut frame = Vec::with_capacity(5 + payload.len());
        frame.push(0u8);
        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        frame.extend_from_slice(payload);
        Bytes::from(frame)
    }

    #[cfg(all(feature = "wasm-reactor", feature = "rust-engine"))]
    #[test]
    fn rust_backend_keeps_the_grpc_inspector() {
        let engine = WafEngine::with_config(&crate::config::Config::default());
        assert!(
            engine.grpc_inspector.is_some(),
            "the default Rust backend must keep gRPC envelope inspection"
        );
    }

    #[cfg(feature = "wasm-reactor")]
    #[tokio::test]
    async fn grpc_body_is_withheld_from_downstream_rules() {
        let mut engine = WafEngine::new();
        engine.grpc_inspector = Some(crate::waf::grpc::GrpcInspector::from_config(
            &crate::config::WafGrpcConfig::default(),
        ));
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        engine.add_rule(BodyProbeRule {
            seen: std::sync::Arc::clone(&seen),
        });

        let mut headers = HeaderMap::new();
        headers.insert(
            hyper::header::CONTENT_TYPE,
            hyper::header::HeaderValue::from_static("application/grpc+proto"),
        );
        let grpc_request = RequestContext::new(
            IpAddr::from_str("192.168.1.100").unwrap(),
            Method::POST,
            Uri::from_str("/acme.Service/Method").unwrap(),
            headers.clone(),
            Some(grpc_body().len()),
        )
        .with_body(Some(grpc_body()));

        assert_eq!(engine.evaluate(&grpc_request).await, Decision::Allow);
        assert_eq!(seen.lock().unwrap().as_slice(), &[None]);

        // Non-gRPC bodies are still inspected.
        headers.insert(
            hyper::header::CONTENT_TYPE,
            hyper::header::HeaderValue::from_static("application/x-www-form-urlencoded"),
        );
        let form_request = RequestContext::new(
            IpAddr::from_str("192.168.1.100").unwrap(),
            Method::POST,
            Uri::from_str("/login").unwrap(),
            headers,
            Some(5),
        )
        .with_body(Some(Bytes::from_static(b"a=b&c")));

        assert_eq!(engine.evaluate(&form_request).await, Decision::Allow);
        assert_eq!(seen.lock().unwrap().as_slice(), &[None, Some(5)]);
    }

    #[cfg(feature = "wasm-reactor")]
    #[tokio::test]
    async fn grpc_precheck_blocks_unknown_method_before_rules() {
        let mut config = crate::config::WafGrpcConfig::default();
        config.method_allowlist = vec!["/acme.Service/Allowed".to_string()];
        let mut engine = WafEngine::new();
        engine.grpc_inspector = Some(crate::waf::grpc::GrpcInspector::from_config(&config));

        let mut headers = HeaderMap::new();
        headers.insert(
            hyper::header::CONTENT_TYPE,
            hyper::header::HeaderValue::from_static("application/grpc"),
        );
        let request = RequestContext::new(
            IpAddr::from_str("192.168.1.100").unwrap(),
            Method::POST,
            Uri::from_str("/acme.Service/Denied").unwrap(),
            headers,
            Some(grpc_body().len()),
        )
        .with_body(Some(grpc_body()));

        assert!(matches!(
            engine.evaluate(&request).await,
            Decision::Block { status: 403, .. }
        ));
    }

    #[cfg(feature = "wasm-reactor")]
    fn graphql_context(body: &str) -> RequestContext {
        let mut headers = HeaderMap::new();
        headers.insert(
            hyper::header::CONTENT_TYPE,
            hyper::header::HeaderValue::from_static("application/json"),
        );
        RequestContext::new(
            IpAddr::from_str("192.168.1.100").unwrap(),
            Method::POST,
            Uri::from_str("/graphql").unwrap(),
            headers,
            Some(body.len()),
        )
        .with_body(Some(Bytes::from(body.to_string())))
    }

    #[cfg(feature = "wasm-reactor")]
    fn graphql_config(mode: crate::config::WafGraphqlScanMode) -> crate::config::WafGraphqlConfig {
        let mut config = crate::config::WafGraphqlConfig::default();
        config.body_scan = mode.as_str().to_string();
        config.operation_allowlist = vec!["GetUser".to_string()];
        config
    }

    #[cfg(feature = "wasm-reactor")]
    #[tokio::test]
    async fn graphql_only_withholds_body_but_header_and_uri_rules_still_run() {
        let mut engine = WafEngine::new();
        engine.graphql_inspector = Some(crate::waf::graphql::GraphqlInspector::from_config(
            &graphql_config(crate::config::WafGraphqlScanMode::GraphqlOnly),
        ));
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        engine.add_rule(BodyProbeRule {
            seen: std::sync::Arc::clone(&seen),
        });
        let uri_seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        engine.add_rule(UriProbeRule {
            seen: std::sync::Arc::clone(&uri_seen),
        });

        let body = r#"{"query":"query GetUser { user { id } }","operationName":"GetUser"}"#;
        assert_eq!(
            engine.evaluate(&graphql_context(body)).await,
            Decision::Allow
        );
        assert_eq!(seen.lock().unwrap().as_slice(), &[None]);
        assert_eq!(
            uri_seen.lock().unwrap().as_slice(),
            &["/graphql".to_string()]
        );
    }

    #[cfg(feature = "wasm-reactor")]
    #[tokio::test]
    async fn graphql_crs_mode_keeps_the_body_visible_to_rules() {
        let mut engine = WafEngine::new();
        engine.graphql_inspector = Some(crate::waf::graphql::GraphqlInspector::from_config(
            &graphql_config(crate::config::WafGraphqlScanMode::Crs),
        ));
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        engine.add_rule(BodyProbeRule {
            seen: std::sync::Arc::clone(&seen),
        });

        let body = r#"{"query":"query GetUser { user { id } }","operationName":"GetUser"}"#;
        assert_eq!(
            engine.evaluate(&graphql_context(body)).await,
            Decision::Allow
        );
        assert_eq!(seen.lock().unwrap().as_slice(), &[Some(body.len())]);
    }

    #[cfg(feature = "wasm-reactor")]
    #[tokio::test]
    async fn graphql_malformed_body_fails_closed_only_in_graphql_only_mode() {
        let body = "{ this is not json";

        let mut crs_engine = WafEngine::new();
        crs_engine.graphql_inspector = Some(crate::waf::graphql::GraphqlInspector::from_config(
            &graphql_config(crate::config::WafGraphqlScanMode::Crs),
        ));
        assert_eq!(
            crs_engine.evaluate(&graphql_context(body)).await,
            Decision::Allow
        );

        let mut only_engine = WafEngine::new();
        only_engine.graphql_inspector = Some(crate::waf::graphql::GraphqlInspector::from_config(
            &graphql_config(crate::config::WafGraphqlScanMode::GraphqlOnly),
        ));
        assert!(matches!(
            only_engine.evaluate(&graphql_context(body)).await,
            Decision::Block { status: 503, .. }
        ));
    }

    #[cfg(feature = "wasm-reactor")]
    #[test]
    fn graphql_allowlist_init_failure_is_recorded_for_startup_abort() {
        let mut config = crate::config::Config::default();
        // Keep the reactor from loading so the failure under test is the
        // GraphQL allowlist artifact.
        config.waf.coraza.module_path = Some("/nonexistent/coraza-reactor.wasm".to_string());
        config.waf.graphql.allowlist_file = Some("/nonexistent/graphql/allowlist.json".to_string());

        let engine = WafEngine::with_config(&config);
        let error = engine
            .waf_init_error()
            .expect("an unreadable GraphQL allowlist must abort start-up");
        assert!(
            error.contains("GraphQL allowlist failed to load")
                && error.contains("/nonexistent/graphql/allowlist.json"),
            "unexpected error: {error}"
        );
    }

    #[cfg(feature = "wasm-reactor")]
    #[tokio::test]
    async fn graphql_allowlist_blocked_operation_is_rejected_before_rules() {
        let mut config = graphql_config(crate::config::WafGraphqlScanMode::GraphqlOnly);
        config.unknown_operation_action = Some("block".to_string());
        let mut engine = WafEngine::new();
        engine.graphql_inspector =
            Some(crate::waf::graphql::GraphqlInspector::from_config(&config));
        let body = r#"{"query":"query Other { user { id } }","operationName":"Other"}"#;
        assert!(matches!(
            engine.evaluate(&graphql_context(body)).await,
            Decision::Block { status: 403, .. }
        ));
    }

    #[cfg(feature = "wasm-reactor")]
    struct UriProbeRule {
        seen: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    }

    #[cfg(feature = "wasm-reactor")]
    impl WafRule for UriProbeRule {
        fn name(&self) -> &str {
            "uri-probe"
        }

        fn evaluate(&self, ctx: &RequestContext) -> Decision {
            self.seen.lock().unwrap().push(ctx.uri.path().to_string());
            Decision::Allow
        }
    }

    #[cfg(feature = "wasm-reactor")]
    #[test]
    fn test_coraza_disabled_does_not_add_rule() {
        let mut config = reactor_only_config();
        config.waf.coraza.enabled = false;
        let engine = WafEngine::with_config(&config);

        // Only the request-size and dangerous-method rules remain.
        assert_eq!(engine.rule_count(), 2);
    }

    #[cfg(feature = "wasm-reactor")]
    #[tokio::test]
    async fn test_coraza_init_failure_fails_closed() {
        let mut config = reactor_only_config();
        config.waf.fail_mode = "closed".to_string();
        config.waf.coraza.module_path = Some("/nonexistent/coraza-reactor.wasm".to_string());
        let engine = WafEngine::with_config(&config);

        let decision = engine.evaluate(&create_test_context()).await;
        assert!(
            matches!(decision, Decision::Block { status: 503, .. }),
            "expected fail-closed 503, got {decision:?}"
        );
    }

    #[cfg(feature = "wasm-reactor")]
    #[tokio::test]
    async fn test_coraza_init_failure_fails_open_when_configured() {
        let mut config = reactor_only_config();
        config.waf.fail_mode = "open".to_string();
        config.waf.coraza.module_path = Some("/nonexistent/coraza-reactor.wasm".to_string());
        let engine = WafEngine::with_config(&config);

        assert_eq!(engine.rule_count(), 2);
        assert_eq!(
            engine.evaluate(&create_test_context()).await,
            Decision::Allow
        );
    }

    struct SlowRule {
        started: Arc<std::sync::atomic::AtomicBool>,
        delay: std::time::Duration,
        heavy_only: bool,
    }

    impl WafRule for SlowRule {
        fn name(&self) -> &str {
            "slow-inspection"
        }

        fn evaluate(&self, ctx: &RequestContext) -> Decision {
            let heavy = ctx.body.as_ref().is_some_and(|body| !body.is_empty());
            if heavy || !self.heavy_only {
                self.started
                    .store(true, std::sync::atomic::Ordering::SeqCst);
                std::thread::sleep(self.delay);
            }
            Decision::Allow
        }
    }

    fn admission_context(body: &str) -> RequestContext {
        let mut headers = HeaderMap::new();
        headers.insert(
            "content-type",
            "application/x-www-form-urlencoded".parse().unwrap(),
        );
        RequestContext::new(
            IpAddr::from_str("192.168.1.100").unwrap(),
            Method::POST,
            Uri::from_str("/login").unwrap(),
            headers,
            Some(body.len()),
        )
        .with_body(Some(Bytes::from(body.to_string())))
    }

    async fn wait_for_slow_rule(started: &std::sync::atomic::AtomicBool) {
        for _ in 0..200 {
            if started.load(std::sync::atomic::Ordering::SeqCst) {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
        panic!("slow rule did not start");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn cheap_request_bypasses_saturated_heavy_admission() {
        use std::sync::atomic::AtomicBool;

        let started = Arc::new(AtomicBool::new(false));
        let admission = AdmissionController::with_permits(
            true,
            1,
            std::time::Duration::from_millis(50),
            4,
            None,
        );
        let mut engine = WafEngine::new().with_admission(admission);
        engine.add_rule(SlowRule {
            started: Arc::clone(&started),
            delay: std::time::Duration::from_millis(250),
            heavy_only: true,
        });

        let heavy_engine = engine.clone();
        let heavy =
            tokio::spawn(async move { heavy_engine.evaluate(&admission_context("a=1")).await });
        wait_for_slow_rule(&started).await;

        let cheap_started = std::time::Instant::now();
        let decision = engine.evaluate(&create_test_context()).await;
        assert_eq!(decision, Decision::Allow);
        assert!(
            cheap_started.elapsed() < std::time::Duration::from_millis(100),
            "cheap request waited behind heavy inspection: {:?}",
            cheap_started.elapsed()
        );

        assert_eq!(heavy.await.unwrap(), Decision::Allow);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn heavy_request_times_out_with_503_metrics_and_recovers() {
        use std::sync::atomic::AtomicBool;

        let metrics = Arc::new(crate::metrics::Metrics::new());
        let started = Arc::new(AtomicBool::new(false));
        let admission = AdmissionController::with_permits(
            true,
            1,
            std::time::Duration::from_millis(50),
            2,
            Some(Arc::clone(&metrics)),
        );
        let mut engine = WafEngine::new().with_admission(admission);
        engine.add_rule(SlowRule {
            started: Arc::clone(&started),
            delay: std::time::Duration::from_millis(250),
            heavy_only: true,
        });

        let heavy_engine = engine.clone();
        let heavy =
            tokio::spawn(async move { heavy_engine.evaluate(&admission_context("a=1")).await });
        wait_for_slow_rule(&started).await;

        let decision = engine.evaluate(&admission_context("b=2")).await;
        match &decision {
            Decision::Block { status, reason } => {
                assert_eq!(*status, 503);
                assert!(
                    reason.contains("admission control"),
                    "reason must name admission control: {reason}"
                );
            }
            other => panic!("admission rejection must never Allow: {other:?}"),
        }

        let rendered = metrics.render_prometheus();
        assert!(
            rendered.contains("waf_admission_queued_total 1"),
            "queued metric missing:\n{rendered}"
        );
        assert!(
            rendered.contains("waf_admission_rejected_total{reason=\"timeout\"} 1"),
            "rejection metric missing:\n{rendered}"
        );
        assert!(
            rendered.contains("waf_admission_queue_depth 0"),
            "queue depth must return to zero:\n{rendered}"
        );

        assert_eq!(heavy.await.unwrap(), Decision::Allow);
        assert_eq!(
            engine.evaluate(&admission_context("c=3")).await,
            Decision::Allow,
            "admission must recover after the permit is released"
        );
    }

    #[tokio::test]
    async fn disabled_admission_admits_heavy_requests_without_queueing() {
        let metrics = Arc::new(crate::metrics::Metrics::new());
        let started = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let admission = AdmissionController::with_permits(
            false,
            1,
            std::time::Duration::from_millis(1),
            0,
            Some(Arc::clone(&metrics)),
        );
        let mut engine = WafEngine::new().with_admission(admission);
        engine.add_rule(SlowRule {
            started,
            delay: std::time::Duration::from_millis(20),
            heavy_only: true,
        });

        assert_eq!(
            engine.evaluate(&admission_context("a=1")).await,
            Decision::Allow
        );
        let rendered = metrics.render_prometheus();
        assert!(rendered.contains("waf_admission_queued_total 0"));
        assert!(rendered.contains("waf_admission_rejected_total{reason=\"timeout\"} 0"));
        assert!(rendered.contains("waf_admission_rejected_total{reason=\"queue_full\"} 0"));
    }

    #[cfg(feature = "wasm-reactor")]
    struct ContentScanProbe {
        calls: Arc<std::sync::atomic::AtomicUsize>,
    }

    #[cfg(feature = "wasm-reactor")]
    impl crate::waf::grpc::GrpcContentScanner for ContentScanProbe {
        fn scan(&self, _payload: &[u8]) -> Result<Decision, String> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(Decision::Allow)
        }
    }

    #[cfg(feature = "wasm-reactor")]
    struct CountingRule {
        seen: Arc<std::sync::atomic::AtomicUsize>,
    }

    #[cfg(feature = "wasm-reactor")]
    impl WafRule for CountingRule {
        fn name(&self) -> &str {
            "counting-rule"
        }

        fn evaluate(&self, _ctx: &RequestContext) -> Decision {
            self.seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Decision::Allow
        }
    }

    /// Builds an engine whose gRPC artifact gives `/acme.Content/Scan` a
    /// descriptor-backed `string` field, so content scanning is possible.
    #[cfg(feature = "wasm-reactor")]
    fn grpc_content_scan_engine(
        content_scan: &str,
        scanner: Arc<ContentScanProbe>,
        admission: AdmissionController,
    ) -> WafEngine {
        use crate::waf::grpc_allowlist::{
            AllowlistSource, GrpcAllowlist, GrpcAllowlistMethod, GrpcMessage, GrpcMessageField,
            ALLOWLIST_IR_VERSION,
        };

        let allowlist = GrpcAllowlist {
            ir_version: ALLOWLIST_IR_VERSION,
            source: AllowlistSource {
                kind: "protobuf".to_string(),
                sha256: "d".repeat(64),
            },
            methods: vec![GrpcAllowlistMethod {
                path: "/acme.Content/Scan".to_string(),
                client_streaming: false,
                server_streaming: false,
                input: "acme.Request".to_string(),
                output: "acme.Response".to_string(),
                max_message_bytes: 64 * 1024,
            }],
            messages: vec![GrpcMessage {
                message: "acme.Request".to_string(),
                fields: vec![GrpcMessageField {
                    name: "name".to_string(),
                    number: 1,
                    field_type: "string".to_string(),
                    repeated: false,
                    required: false,
                    message_type: None,
                    enum_values: None,
                }],
            }],
            // Unknown methods keep the envelope-only behaviour used by the
            // existing gRPC tests and the load harness.
            unknown_method_action: "allow".to_string(),
        };
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("allowlist.json");
        std::fs::write(&path, allowlist.to_canonical_json().unwrap()).unwrap();

        let mut config = crate::config::WafGrpcConfig::default();
        config.allowlist_file = Some(path.display().to_string());
        config.content_scan = content_scan.to_string();
        let inspector = crate::waf::grpc::GrpcInspector::try_from_config(&config)
            .unwrap()
            .with_content_scanner(scanner);

        let mut engine = WafEngine::new().with_admission(admission);
        engine.grpc_inspector = Some(inspector);
        engine
    }

    #[cfg(feature = "wasm-reactor")]
    fn grpc_content_request() -> RequestContext {
        let value = "x".repeat(64);
        let mut payload = Vec::with_capacity(value.len() + 2);
        payload.push(0x0a); // field 1, length-delimited
        payload.push(value.len() as u8);
        payload.extend_from_slice(value.as_bytes());
        let mut body = Vec::with_capacity(5 + payload.len());
        body.push(0);
        body.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        body.extend_from_slice(&payload);

        let mut headers = HeaderMap::new();
        headers.insert(
            hyper::header::CONTENT_TYPE,
            hyper::header::HeaderValue::from_static("application/grpc+proto"),
        );
        headers.insert(
            "grpc-encoding",
            hyper::header::HeaderValue::from_static("identity"),
        );
        RequestContext::new(
            IpAddr::from_str("192.168.1.100").unwrap(),
            Method::POST,
            Uri::from_str("/acme.Content/Scan").unwrap(),
            headers,
            Some(body.len()),
        )
        .with_body(Some(Bytes::from(body)))
    }

    #[cfg(feature = "wasm-reactor")]
    #[test]
    fn admission_classification_uses_the_original_request() {
        let disabled = AdmissionController::disabled();
        let engine = grpc_content_scan_engine(
            "strings",
            Arc::new(ContentScanProbe {
                calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            }),
            disabled.clone(),
        );
        assert_eq!(
            engine.inspection_cost(&grpc_content_request()),
            admission::InspectionCost::Heavy,
            "gRPC content scanning triggers a Coraza evaluation"
        );

        let scan_off = grpc_content_scan_engine(
            "off",
            Arc::new(ContentScanProbe {
                calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            }),
            disabled.clone(),
        );
        assert_eq!(
            scan_off.inspection_cost(&grpc_content_request()),
            admission::InspectionCost::Cheap,
            "content_scan = off withholds the body without a Coraza evaluation"
        );

        assert_eq!(
            engine.inspection_cost(&admission_context("a=1")),
            admission::InspectionCost::Heavy,
            "plain bodies still reach CRS body rules"
        );
        assert_eq!(
            engine.inspection_cost(&create_test_context()),
            admission::InspectionCost::Cheap,
            "bodyless requests stay cheap"
        );
    }

    #[cfg(feature = "wasm-reactor")]
    #[test]
    fn graphql_only_stays_cheap_and_graphql_crs_stays_heavy() {
        let body = r#"{"query":"query GetUser { user { id } }","operationName":"GetUser"}"#;

        let mut only_engine = WafEngine::new();
        only_engine.graphql_inspector = Some(crate::waf::graphql::GraphqlInspector::from_config(
            &graphql_config(crate::config::WafGraphqlScanMode::GraphqlOnly),
        ));
        assert_eq!(
            only_engine.inspection_cost(&graphql_context(body)),
            admission::InspectionCost::Cheap,
            "graphql-only withholds the body and runs only cheap checks"
        );

        let mut crs_engine = WafEngine::new();
        crs_engine.graphql_inspector = Some(crate::waf::graphql::GraphqlInspector::from_config(
            &graphql_config(crate::config::WafGraphqlScanMode::Crs),
        ));
        assert_eq!(
            crs_engine.inspection_cost(&graphql_context(body)),
            admission::InspectionCost::Heavy,
            "graphql crs mode still scans the body"
        );
    }

    #[cfg(feature = "wasm-reactor")]
    #[tokio::test]
    async fn saturated_heavy_pool_rejects_grpc_content_scan_before_evaluation() {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let admission = AdmissionController::with_permits(
            true,
            1,
            std::time::Duration::from_millis(50),
            0,
            None,
        );
        let _held = admission
            .admit(admission::InspectionCost::Heavy)
            .await
            .unwrap();

        let mut engine = grpc_content_scan_engine(
            "strings",
            Arc::new(ContentScanProbe {
                calls: Arc::clone(&calls),
            }),
            admission.clone(),
        );
        let rule_runs = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        engine.add_rule(CountingRule {
            seen: Arc::clone(&rule_runs),
        });

        for decision in [
            engine.evaluate(&grpc_content_request()).await,
            engine.fast_evaluate(&grpc_content_request()).await,
        ] {
            match decision {
                Decision::Block { status, reason } => {
                    assert_eq!(status, 503);
                    assert!(
                        reason.contains("admission control"),
                        "reason must name admission control: {reason}"
                    );
                }
                other => panic!("gRPC content scan must not bypass admission: {other:?}"),
            }
        }

        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "the content-scan Coraza evaluation must not run"
        );
        assert_eq!(
            rule_runs.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "the rule chain must not run"
        );
    }

    #[cfg(feature = "wasm-reactor")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn grpc_content_scan_off_stays_cheap_under_a_saturated_heavy_pool() {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let admission = AdmissionController::with_permits(
            true,
            1,
            std::time::Duration::from_millis(200),
            0,
            None,
        );
        let _held = admission
            .admit(admission::InspectionCost::Heavy)
            .await
            .unwrap();

        let engine = grpc_content_scan_engine(
            "off",
            Arc::new(ContentScanProbe {
                calls: Arc::clone(&calls),
            }),
            admission,
        );

        let started = std::time::Instant::now();
        assert_eq!(
            engine.evaluate(&grpc_content_request()).await,
            Decision::Allow
        );
        assert!(
            started.elapsed() < std::time::Duration::from_millis(100),
            "cheap gRPC request waited behind heavy inspection: {:?}",
            started.elapsed()
        );
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[cfg(feature = "wasm-reactor")]
    #[tokio::test]
    async fn grpc_content_scan_holds_exactly_one_permit() {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let admission = AdmissionController::with_permits(
            true,
            1,
            std::time::Duration::from_millis(20),
            1,
            None,
        );
        let engine = grpc_content_scan_engine(
            "strings",
            Arc::new(ContentScanProbe {
                calls: Arc::clone(&calls),
            }),
            admission.clone(),
        );

        // With a single permit, a double acquire would time out and return 503.
        assert_eq!(
            engine.evaluate(&grpc_content_request()).await,
            Decision::Allow
        );
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(admission.available_permits(), 1);

        assert_eq!(
            engine.evaluate(&grpc_content_request()).await,
            Decision::Allow
        );
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
        assert_eq!(admission.available_permits(), 1);
    }

    /// Rule with a fixed decision, used for parity checks.
    struct FixedRule {
        name: &'static str,
        decision: Decision,
    }

    impl WafRule for FixedRule {
        fn name(&self) -> &str {
            self.name
        }

        fn evaluate(&self, _ctx: &RequestContext) -> Decision {
            self.decision.clone()
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn offloaded_evaluation_matches_inline_for_every_outcome() {
        let cases = [
            ("allow", Decision::Allow, WafEngine::new()),
            (
                "block",
                Decision::Block {
                    status: 403,
                    reason: "parity block".to_string(),
                },
                WafEngine::new(),
            ),
            (
                "rate-limit",
                Decision::RateLimit {
                    reason: "parity limit".to_string(),
                },
                WafEngine::new(),
            ),
        ];

        for (label, expected, mut engine) in cases {
            if expected != Decision::Allow {
                engine.add_rule(FixedRule {
                    name: label,
                    decision: expected.clone(),
                });
            }
            let engine = Arc::new(engine);

            for context in [create_test_context(), admission_context("a=1")] {
                assert_eq!(engine.evaluate(&context).await, expected, "{label} inline");
                assert_eq!(
                    engine.evaluate_shared(&context).await,
                    expected,
                    "{label} offloaded"
                );
            }
        }
    }

    #[cfg(feature = "wasm-reactor")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn offloaded_evaluation_preserves_protocol_precheck_semantics() {
        use std::sync::atomic::AtomicUsize;

        let calls = Arc::new(AtomicUsize::new(0));
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut engine = grpc_content_scan_engine(
            "strings",
            Arc::new(ContentScanProbe {
                calls: Arc::clone(&calls),
            }),
            AdmissionController::disabled(),
        );
        engine.add_rule(BodyProbeRule {
            seen: Arc::clone(&seen),
        });
        let engine = Arc::new(engine);

        assert_eq!(
            engine.evaluate(&grpc_content_request()).await,
            Decision::Allow
        );
        assert_eq!(
            engine.evaluate_shared(&grpc_content_request()).await,
            Decision::Allow
        );

        // The pre-check ran once per evaluation, and the rule chain saw no body
        // on either path: offloading must not reorder or drop the strip.
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
        assert_eq!(
            *seen.lock().unwrap(),
            vec![None, None],
            "protobuf bodies must stay withheld from the rule chain"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn offloaded_evaluation_keeps_admission_before_the_offload() {
        use std::sync::atomic::AtomicBool;

        let started = Arc::new(AtomicBool::new(false));
        let admission = AdmissionController::with_permits(
            true,
            1,
            std::time::Duration::from_millis(50),
            2,
            None,
        );
        let mut engine = WafEngine::new().with_admission(admission.clone());
        engine.add_rule(SlowRule {
            started: Arc::clone(&started),
            delay: std::time::Duration::from_millis(250),
            heavy_only: true,
        });
        let engine = Arc::new(engine);

        let first = {
            let engine = Arc::clone(&engine);
            tokio::spawn(async move { engine.evaluate_shared(&admission_context("a=1")).await })
        };
        wait_for_slow_rule(&started).await;

        // The single heavy permit is held by the running evaluation, so a
        // second heavy request is rejected instead of queued on the blocking
        // pool.
        match engine.evaluate_shared(&admission_context("b=2")).await {
            Decision::Block { status, reason } => {
                assert_eq!(status, 503);
                assert!(reason.contains("admission control"), "{reason}");
            }
            other => panic!("admission rejection must never Allow: {other:?}"),
        }

        assert_eq!(first.await.unwrap(), Decision::Allow);
        assert_eq!(
            admission.available_permits(),
            1,
            "the permit must return once the offloaded evaluation finishes"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn cancelled_offloaded_evaluation_holds_its_permit_until_it_finishes() {
        use std::sync::atomic::AtomicBool;

        let started = Arc::new(AtomicBool::new(false));
        let admission = AdmissionController::with_permits(
            true,
            1,
            std::time::Duration::from_millis(10),
            4,
            None,
        );
        let mut engine = WafEngine::new().with_admission(admission.clone());
        engine.add_rule(SlowRule {
            started: Arc::clone(&started),
            delay: std::time::Duration::from_millis(300),
            heavy_only: true,
        });
        let engine = Arc::new(engine);

        // Simulate a client disconnect: the caller stops awaiting the decision.
        let caller = {
            let engine = Arc::clone(&engine);
            tokio::spawn(async move { engine.evaluate_shared(&admission_context("a=1")).await })
        };
        wait_for_slow_rule(&started).await;
        caller.abort();
        let _ = caller.await;

        // The permit is still owned by the blocking task, so a competing heavy
        // request is rejected rather than over-admitting.
        assert_eq!(
            admission.available_permits(),
            0,
            "cancelling the caller must not release the inspection permit"
        );

        // Once the abandoned scan finishes the permit comes back and normal
        // admission resumes.
        for _ in 0..200 {
            if admission.available_permits() == 1 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert_eq!(admission.available_permits(), 1);
        assert_eq!(
            engine.evaluate_shared(&admission_context("c=3")).await,
            Decision::Allow
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn offloaded_evaluation_does_not_deadlock_under_concurrency() {
        use std::sync::atomic::AtomicUsize;

        let started = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut engine = WafEngine::new();
        engine.add_rule(SlowRule {
            started,
            delay: std::time::Duration::from_millis(20),
            heavy_only: false,
        });
        let engine = Arc::new(engine);
        let completed = Arc::new(AtomicUsize::new(0));

        let mut tasks = Vec::new();
        for index in 0..48 {
            let engine = Arc::clone(&engine);
            let completed = Arc::clone(&completed);
            tasks.push(tokio::spawn(async move {
                let context = if index % 2 == 0 {
                    create_test_context()
                } else {
                    admission_context("a=1")
                };
                assert_eq!(engine.evaluate_shared(&context).await, Decision::Allow);
                completed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }));
        }

        let all = futures::future::join_all(tasks);
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(30), all).await;
        assert!(
            outcome.is_ok(),
            "concurrent offloaded evaluation deadlocked"
        );
        for result in outcome.unwrap() {
            result.expect("evaluation task must not panic");
        }
        assert_eq!(completed.load(std::sync::atomic::Ordering::SeqCst), 48);
    }

    /// Measures how long an unrelated Tokio task waits while slow inspections
    /// run. Ignored by default because it is a timing measurement rather than a
    /// correctness gate; run it in release mode:
    ///
    /// `cargo test --release --lib --features wasm-reactor \
    ///   measure_runtime_responsiveness -- --ignored --nocapture`
    #[tokio::test(flavor = "multi_thread", worker_threads = 6)]
    #[ignore = "timing measurement; run in release mode with --nocapture"]
    async fn measure_runtime_responsiveness_during_slow_inspection() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::time::Duration;

        const SLOW_MS: u64 = 200;
        const CONCURRENCY: usize = 6;

        async fn worst_ticker_delay(offload: bool) -> Duration {
            let started = Arc::new(AtomicBool::new(false));
            let mut engine = WafEngine::new();
            engine.add_rule(SlowRule {
                started: Arc::clone(&started),
                delay: Duration::from_millis(SLOW_MS),
                heavy_only: true,
            });
            let engine = Arc::new(engine);

            let stop = Arc::new(AtomicBool::new(false));
            let ticker = {
                let stop = Arc::clone(&stop);
                tokio::spawn(async move {
                    let mut worst = Duration::ZERO;
                    while !stop.load(Ordering::SeqCst) {
                        let tick = std::time::Instant::now();
                        tokio::time::sleep(Duration::from_millis(1)).await;
                        worst = worst.max(tick.elapsed());
                    }
                    worst
                })
            };

            let mut tasks = Vec::new();
            for _ in 0..CONCURRENCY {
                let engine = Arc::clone(&engine);
                tasks.push(tokio::spawn(async move {
                    let context = admission_context("a=1");
                    if offload {
                        engine.evaluate_shared(&context).await
                    } else {
                        engine.evaluate(&context).await
                    }
                }));
            }
            wait_for_slow_rule(&started).await;
            tokio::time::sleep(Duration::from_millis(SLOW_MS)).await;
            for task in tasks {
                assert_eq!(task.await.unwrap(), Decision::Allow);
            }

            stop.store(true, Ordering::SeqCst);
            ticker.await.unwrap()
        }

        let inline = worst_ticker_delay(false).await;
        let offloaded = worst_ticker_delay(true).await;
        println!(
            "{CONCURRENCY} x {SLOW_MS} ms inspection: worst 1 ms ticker delay \
             inline {inline:?}, offloaded {offloaded:?}"
        );
        assert!(
            offloaded * 2 < inline,
            "offloaded inspection must not park workers: inline {inline:?}, offloaded {offloaded:?}"
        );
    }

    #[cfg(feature = "wasm-reactor")]
    #[test]
    #[ignore = "Go/WASI reactor is exercised in release mode"]
    fn test_coraza_reactor_engine_blocks_attacks_and_allows_benign() {
        std::thread::Builder::new()
            .stack_size(256 * 1024 * 1024)
            .spawn(|| {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("runtime");
                runtime.block_on(async {
                    let config = reactor_only_config();
                    let engine = WafEngine::with_config(&config);

                    assert_eq!(
                        engine.evaluate(&create_test_context()).await,
                        Decision::Allow,
                        "benign request must pass"
                    );

                    for body in [
                        "username=admin&password=x union select password from users",
                        "<script>alert(1)</script>",
                        "../../etc/passwd",
                    ] {
                        let decision = engine.evaluate(&post_context(body)).await;
                        assert!(
                            matches!(decision, Decision::Block { status: 403, .. }),
                            "expected Coraza to block {body:?}, got {decision:?}"
                        );
                    }
                });
            })
            .expect("spawn reactor thread")
            .join()
            .expect("reactor thread must not panic");
    }

    #[cfg(feature = "allow-cache")]
    mod allow_cache_integration {
        use super::*;
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

        struct CacheableContentRule {
            name: &'static str,
            evaluations: Arc<AtomicUsize>,
            block_marker: &'static str,
        }

        impl CacheableContentRule {
            fn new(
                name: &'static str,
                evaluations: Arc<AtomicUsize>,
                block_marker: &'static str,
            ) -> Self {
                Self {
                    name,
                    evaluations,
                    block_marker,
                }
            }
        }

        impl WafRule for CacheableContentRule {
            fn name(&self) -> &str {
                self.name
            }

            fn cacheable(&self) -> bool {
                true
            }

            fn evaluate(&self, ctx: &RequestContext) -> Decision {
                self.evaluations.fetch_add(1, Ordering::SeqCst);
                let body_hit = ctx
                    .body
                    .as_deref()
                    .is_some_and(|body| String::from_utf8_lossy(body).contains(self.block_marker));
                if body_hit || ctx.uri.to_string().contains(self.block_marker) {
                    Decision::Block {
                        status: 403,
                        reason: format!("marker {} found", self.block_marker),
                    }
                } else {
                    Decision::Allow
                }
            }
        }

        struct StatefulRule {
            name: &'static str,
            evaluations: Arc<AtomicUsize>,
            block: Arc<AtomicBool>,
        }

        impl StatefulRule {
            fn new(name: &'static str, evaluations: Arc<AtomicUsize>) -> Self {
                Self {
                    name,
                    evaluations,
                    block: Arc::new(AtomicBool::new(false)),
                }
            }
        }

        impl WafRule for StatefulRule {
            fn name(&self) -> &str {
                self.name
            }

            fn evaluate(&self, _ctx: &RequestContext) -> Decision {
                self.evaluations.fetch_add(1, Ordering::SeqCst);
                if self.block.load(Ordering::SeqCst) {
                    Decision::RateLimit {
                        reason: "stateful limit".to_string(),
                    }
                } else {
                    Decision::Allow
                }
            }
        }

        fn cache_engine(
            enabled: bool,
            ttl_secs: u64,
            routes: Vec<String>,
            max_body_bytes: usize,
        ) -> WafEngine {
            let mut config = crate::config::Config::default();
            config.waf.coraza.enabled = false;
            config.waf.content_inspection.enabled = false;
            config.waf.rate_limit.per_ip_enabled = false;
            config.waf.rate_limit.global_enabled = false;
            config.waf.geo_blocking.enabled = false;
            config.waf.allow_cache.enabled = enabled;
            config.waf.allow_cache.ttl_secs = ttl_secs;
            config.waf.allow_cache.max_entries = 64;
            config.waf.allow_cache.max_body_bytes = max_body_bytes;
            config.waf.allow_cache.routes = routes;
            WafEngine::with_config(&config)
        }

        fn post_context(body: &str) -> RequestContext {
            RequestContext::new(
                IpAddr::from_str("192.168.1.100").unwrap(),
                Method::POST,
                Uri::from_str("/submit").unwrap(),
                HeaderMap::new(),
                Some(body.len()),
            )
            .with_body(Some(Bytes::copy_from_slice(body.as_bytes())))
        }

        #[tokio::test]
        async fn hit_skips_cacheable_rules_but_runs_stateful_rules() {
            let mut engine = cache_engine(true, 30, Vec::new(), 1024);
            let cacheable = Arc::new(AtomicUsize::new(0));
            let stateful = Arc::new(AtomicUsize::new(0));
            engine.add_rule(CacheableContentRule::new(
                "cacheable-allow",
                Arc::clone(&cacheable),
                "never-present",
            ));
            engine.add_rule(StatefulRule::new("stateful", Arc::clone(&stateful)));

            let request = create_test_context();
            assert_eq!(engine.evaluate(&request).await, Decision::Allow);
            assert_eq!(cacheable.load(Ordering::SeqCst), 1);
            assert_eq!(stateful.load(Ordering::SeqCst), 1);

            assert_eq!(engine.evaluate(&request).await, Decision::Allow);
            assert_eq!(
                cacheable.load(Ordering::SeqCst),
                1,
                "cache hit must skip the pure content rule"
            );
            assert_eq!(
                stateful.load(Ordering::SeqCst),
                2,
                "stateful rules must run on every request"
            );
            assert_eq!(engine.allow_cache().unwrap().stats().hits, 1);
        }

        #[tokio::test]
        async fn cache_hit_cannot_bypass_a_stateful_block() {
            let mut engine = cache_engine(true, 30, Vec::new(), 1024);
            let cacheable = Arc::new(AtomicUsize::new(0));
            let stateful = Arc::new(AtomicUsize::new(0));
            engine.add_rule(CacheableContentRule::new(
                "cacheable-allow",
                Arc::clone(&cacheable),
                "never-present",
            ));
            let rule = StatefulRule::new("stateful", Arc::clone(&stateful));
            let block = Arc::clone(&rule.block);
            engine.add_rule(rule);

            let request = create_test_context();
            assert_eq!(engine.evaluate(&request).await, Decision::Allow);
            block.store(true, Ordering::SeqCst);
            assert!(matches!(
                engine.evaluate(&request).await,
                Decision::RateLimit { .. }
            ));
            assert_eq!(cacheable.load(Ordering::SeqCst), 1);
        }

        #[tokio::test]
        async fn same_metadata_different_body_is_not_allowed() {
            let mut engine = cache_engine(true, 30, Vec::new(), 1024);
            let cacheable = Arc::new(AtomicUsize::new(0));
            engine.add_rule(CacheableContentRule::new(
                "cacheable-content",
                Arc::clone(&cacheable),
                "attack",
            ));

            // Identical method, URI, headers and body length: only the body
            // bytes differ, so the two requests share one fingerprint.
            let benign = post_context("data=benign");
            let attack = post_context("data=attack");
            assert_eq!(
                benign.body.as_ref().unwrap().len(),
                attack.body.as_ref().unwrap().len()
            );

            assert_eq!(engine.evaluate(&benign).await, Decision::Allow);
            assert_eq!(engine.allow_cache().unwrap().stats().hits, 0);
            assert!(matches!(
                engine.evaluate(&attack).await,
                Decision::Block { status: 403, .. }
            ));
            assert_eq!(
                cacheable.load(Ordering::SeqCst),
                2,
                "a fingerprint match alone must never allow"
            );
        }

        #[tokio::test]
        async fn blocks_are_never_cached() {
            let mut engine = cache_engine(true, 30, Vec::new(), 1024);
            let cacheable = Arc::new(AtomicUsize::new(0));
            engine.add_rule(CacheableContentRule::new(
                "cacheable-block",
                Arc::clone(&cacheable),
                "attack",
            ));

            let request = post_context("data=attack");
            assert!(matches!(
                engine.evaluate(&request).await,
                Decision::Block { status: 403, .. }
            ));
            assert!(matches!(
                engine.evaluate(&request).await,
                Decision::Block { status: 403, .. }
            ));
            assert_eq!(
                cacheable.load(Ordering::SeqCst),
                2,
                "a block must never be memoised"
            );
            assert_eq!(engine.allow_cache().unwrap().stats().entries, 0);
        }

        #[tokio::test]
        async fn policy_invalidation_forces_re_evaluation() {
            let mut engine = cache_engine(true, 30, Vec::new(), 1024);
            let cacheable = Arc::new(AtomicUsize::new(0));
            engine.add_rule(CacheableContentRule::new(
                "cacheable-allow",
                Arc::clone(&cacheable),
                "never-present",
            ));

            let request = create_test_context();
            assert_eq!(engine.evaluate(&request).await, Decision::Allow);
            engine.invalidate_allow_cache();
            assert_eq!(engine.evaluate(&request).await, Decision::Allow);
            assert_eq!(cacheable.load(Ordering::SeqCst), 2);
        }

        #[cfg(feature = "wasm-reactor")]
        #[tokio::test]
        async fn cache_hit_still_runs_protocol_prechecks() {
            let metrics = Arc::new(crate::metrics::Metrics::new());
            let mut engine = cache_engine(true, 30, Vec::new(), 1024);
            engine.metrics = Some(Arc::clone(&metrics));
            engine.graphql_inspector = Some(crate::waf::graphql::GraphqlInspector::from_config(
                &super::graphql_config(crate::config::WafGraphqlScanMode::Crs),
            ));
            engine.add_rule(CacheableContentRule::new(
                "cacheable-allow",
                Arc::new(AtomicUsize::new(0)),
                "never-present",
            ));

            let request = super::graphql_context(
                r#"{"query":"query GetUser { user { id } }","operationName":"GetUser"}"#,
            );
            assert_eq!(engine.evaluate(&request).await, Decision::Allow);
            assert_eq!(engine.evaluate(&request).await, Decision::Allow);
            assert_eq!(engine.allow_cache().unwrap().stats().hits, 1);
            assert!(
                metrics
                    .render_prometheus()
                    .contains("waf_graphql_decisions_total{decision=\"allow\"} 2"),
                "a cache hit must still run the GraphQL pre-check"
            );
        }

        #[cfg(feature = "wasm-reactor")]
        #[tokio::test]
        async fn descriptor_reload_invalidates_the_allow_cache() {
            let mut engine = cache_engine(true, 30, Vec::new(), 1024);
            let cacheable = Arc::new(AtomicUsize::new(0));
            engine.add_rule(CacheableContentRule::new(
                "cacheable-allow",
                Arc::clone(&cacheable),
                "never-present",
            ));

            let request = create_test_context();
            assert_eq!(engine.evaluate(&request).await, Decision::Allow);
            assert_eq!(engine.evaluate(&request).await, Decision::Allow);
            assert_eq!(cacheable.load(Ordering::SeqCst), 1);
            assert_eq!(engine.allow_cache().unwrap().stats().hits, 1);

            let config = crate::config::Config::default();
            engine.reload_protocol_descriptors(&config).unwrap();
            assert_eq!(engine.allow_cache().unwrap().stats().entries, 0);

            assert_eq!(engine.evaluate(&request).await, Decision::Allow);
            assert_eq!(
                cacheable.load(Ordering::SeqCst),
                2,
                "a descriptor reload must force re-evaluation"
            );
        }

        #[tokio::test]
        async fn route_opt_in_leaves_other_paths_uncached() {
            let mut engine = cache_engine(true, 30, vec!["/api".to_string()], 1024);
            let cacheable = Arc::new(AtomicUsize::new(0));
            engine.add_rule(CacheableContentRule::new(
                "cacheable-allow",
                Arc::clone(&cacheable),
                "never-present",
            ));

            let outside = create_test_context();
            assert_eq!(engine.evaluate(&outside).await, Decision::Allow);
            assert_eq!(engine.evaluate(&outside).await, Decision::Allow);
            assert_eq!(cacheable.load(Ordering::SeqCst), 2);

            let mut inside = create_test_context();
            inside.uri = Uri::from_str("/api/items").unwrap();
            assert_eq!(engine.evaluate(&inside).await, Decision::Allow);
            assert_eq!(engine.evaluate(&inside).await, Decision::Allow);
            assert_eq!(cacheable.load(Ordering::SeqCst), 3);
        }

        #[tokio::test]
        async fn over_cap_bodies_are_evaluated_but_not_cached() {
            let mut engine = cache_engine(true, 30, Vec::new(), 4);
            let cacheable = Arc::new(AtomicUsize::new(0));
            engine.add_rule(CacheableContentRule::new(
                "cacheable-allow",
                Arc::clone(&cacheable),
                "never-present",
            ));

            let request = post_context("data=12345");
            assert_eq!(engine.evaluate(&request).await, Decision::Allow);
            assert_eq!(engine.evaluate(&request).await, Decision::Allow);
            assert_eq!(cacheable.load(Ordering::SeqCst), 2);
            let stats = engine.allow_cache().unwrap().stats();
            assert_eq!(stats.entries, 0);
            assert_eq!(stats.skipped, 2);
        }

        #[tokio::test]
        async fn decision_parity_with_the_uncached_engine() {
            let mut cached = cache_engine(true, 30, Vec::new(), 1024);
            let mut uncached = cache_engine(false, 30, Vec::new(), 1024);
            for engine in [&mut cached, &mut uncached] {
                engine.add_rule(CacheableContentRule::new(
                    "cacheable-content",
                    Arc::new(AtomicUsize::new(0)),
                    "attack",
                ));
                engine.add_rule(StatefulRule::new("stateful", Arc::new(AtomicUsize::new(0))));
            }

            let requests = vec![
                create_test_context(),
                post_context("data=benign"),
                post_context("data=attack"),
                post_context("data="),
            ];

            for request in &requests {
                for _ in 0..3 {
                    assert_eq!(
                        cached.evaluate(request).await,
                        uncached.evaluate(request).await,
                        "cached and fresh decisions diverged for {:?}",
                        request.uri
                    );
                }
            }
            assert!(
                cached.allow_cache().unwrap().stats().hits > 0,
                "the parity corpus must exercise at least one hit"
            );
        }

        #[tokio::test]
        async fn cache_metrics_are_exported() {
            let metrics = Arc::new(crate::metrics::Metrics::new());
            let mut config = crate::config::Config::default();
            config.waf.coraza.enabled = false;
            config.waf.content_inspection.enabled = false;
            config.waf.rate_limit.per_ip_enabled = false;
            config.waf.rate_limit.global_enabled = false;
            config.waf.allow_cache.enabled = true;
            config.waf.allow_cache.max_entries = 64;
            let mut engine =
                WafEngine::with_config_and_metrics(&config, Some(Arc::clone(&metrics)));
            engine.add_rule(CacheableContentRule::new(
                "cacheable-allow",
                Arc::new(AtomicUsize::new(0)),
                "never-present",
            ));

            let request = create_test_context();
            assert_eq!(engine.evaluate(&request).await, Decision::Allow);
            assert_eq!(engine.evaluate(&request).await, Decision::Allow);

            let rendered = metrics.render_prometheus();
            assert!(rendered.contains("waf_allow_cache_hits_total 1"));
            assert!(rendered.contains("waf_allow_cache_misses_total 1"));
            assert!(rendered.contains("waf_allow_cache_entries 1"));
        }
    }

    fn fast_allow_engine(routes: &[&str]) -> WafEngine {
        let mut config = crate::config::Config::default();
        // The unit test build must not spin up the reactor or protocol
        // inspectors; the fast path is decided before either would run.
        config.waf.coraza.enabled = false;
        config.waf.grpc.enabled = false;
        config.waf.graphql.enabled = false;
        config.waf.fast_allow.enabled = true;
        config.waf.fast_allow.routes = routes.iter().map(|route| route.to_string()).collect();
        WafEngine::with_config(&config)
    }

    fn health_context(uri: &'static str) -> RequestContext {
        RequestContext::new(
            IpAddr::from_str("192.168.1.100").unwrap(),
            Method::GET,
            Uri::from_static(uri),
            HeaderMap::new(),
            None,
        )
    }

    #[test]
    fn fast_allow_is_disabled_by_default_and_never_matches() {
        let mut config = crate::config::Config::default();
        assert!(!config.waf.fast_allow.enabled);
        // Keep the unit test from initialising the reactor.
        config.waf.coraza.enabled = false;
        config.waf.grpc.enabled = false;
        config.waf.graphql.enabled = false;
        let engine = WafEngine::with_config(&config);
        assert!(!engine.fast_allow_enabled());
        assert_eq!(engine.fast_allow_route_count(), 0);
        let ctx = health_context("/health");
        assert!(engine
            .fast_allow(
                &ctx.method,
                &ctx.uri,
                &ctx.headers,
                ctx.client_ip,
                ctx.body_size,
                true,
            )
            .is_none());
    }

    #[test]
    fn fast_allow_matches_exact_method_and_path() {
        let engine = fast_allow_engine(&["GET /health"]);
        assert!(engine.fast_allow_enabled());
        assert_eq!(engine.fast_allow_route_count(), 1);

        let hit = health_context("/health");
        let outcome = engine
            .fast_allow(
                &hit.method,
                &hit.uri,
                &hit.headers,
                hit.client_ip,
                hit.body_size,
                true,
            )
            .expect("configured route must match");
        assert_eq!(outcome.decision, Decision::Allow);

        for uri in ["/healthz", "/health/", "/other"] {
            let miss = health_context(uri);
            assert!(
                engine
                    .fast_allow(
                        &miss.method,
                        &miss.uri,
                        &miss.headers,
                        miss.client_ip,
                        miss.body_size,
                        true,
                    )
                    .is_none(),
                "{uri} must fall through"
            );
        }

        let mut post = health_context("/health");
        post.method = Method::POST;
        assert!(engine
            .fast_allow(
                &post.method,
                &post.uri,
                &post.headers,
                post.client_ip,
                post.body_size,
                true,
            )
            .is_none());
    }

    #[test]
    fn fast_allow_requires_a_bodyless_request() {
        let engine = fast_allow_engine(&["GET /health"]);

        let mut query = health_context("/health?probe=1");
        assert!(engine
            .fast_allow(
                &query.method,
                &query.uri,
                &query.headers,
                query.client_ip,
                query.body_size,
                true,
            )
            .is_none());
        query.uri = Uri::from_static("/health");

        // A non-empty body, a framing header or a content encoding must all
        // fall through so the body is inspected.
        assert!(engine
            .fast_allow(
                &query.method,
                &query.uri,
                &query.headers,
                query.client_ip,
                None,
                false,
            )
            .is_none());

        let mut framed = query.clone();
        framed
            .headers
            .insert("transfer-encoding", "chunked".parse().unwrap());
        assert!(engine
            .fast_allow(
                &framed.method,
                &framed.uri,
                &framed.headers,
                framed.client_ip,
                None,
                true,
            )
            .is_none());

        let mut encoded = query.clone();
        encoded
            .headers
            .insert("content-encoding", "gzip".parse().unwrap());
        assert!(engine
            .fast_allow(
                &encoded.method,
                &encoded.uri,
                &encoded.headers,
                encoded.client_ip,
                None,
                true,
            )
            .is_none());
    }

    #[tokio::test]
    async fn fast_allow_never_allows_an_engine_block_for_the_route() {
        let engine = fast_allow_engine(&["GET /health"]);
        let malicious = health_context("/health?q=1%20union%20select%20password%20from%20users");

        // The query is outside the fast-path domain, so the request falls
        // through and the engine's content inspection blocks it.
        assert!(engine
            .fast_allow(
                &malicious.method,
                &malicious.uri,
                &malicious.headers,
                malicious.client_ip,
                malicious.body_size,
                true,
            )
            .is_none());
        assert!(
            matches!(engine.evaluate(&malicious).await, Decision::Block { .. }),
            "the engine must still block the malicious query"
        );
    }

    #[tokio::test]
    async fn fast_allow_still_enforces_stateful_rate_limit_gates() {
        let mut config = crate::config::Config::default();
        config.waf.coraza.enabled = false;
        config.waf.grpc.enabled = false;
        config.waf.graphql.enabled = false;
        config.waf.rate_limit.per_ip_enabled = true;
        config.waf.rate_limit.per_ip_max_requests = 1;
        config.waf.rate_limit.per_ip_window_secs = 60;
        config.waf.rate_limit.global_enabled = false;
        config.waf.fast_allow.enabled = true;
        config.waf.fast_allow.routes = vec!["GET /health".to_string()];
        let engine = WafEngine::with_config(&config);

        let ctx = health_context("/health");
        let first = engine
            .fast_allow(
                &ctx.method,
                &ctx.uri,
                &ctx.headers,
                ctx.client_ip,
                ctx.body_size,
                true,
            )
            .expect("route matches");
        assert_eq!(first.decision, Decision::Allow);

        let second = engine
            .fast_allow(
                &ctx.method,
                &ctx.uri,
                &ctx.headers,
                ctx.client_ip,
                ctx.body_size,
                true,
            )
            .expect("route still matches");
        assert!(
            matches!(second.decision, Decision::RateLimit { .. }),
            "the fast path must not bypass the rate-limit gate: {:?}",
            second.decision
        );
    }

    #[test]
    fn fast_allow_falls_through_for_a_custom_rule() {
        struct CustomRule;

        impl WafRule for CustomRule {
            fn name(&self) -> &str {
                "custom"
            }

            fn evaluate(&self, _ctx: &RequestContext) -> Decision {
                Decision::Allow
            }
        }

        let mut engine = fast_allow_engine(&["GET /health"]);
        engine.add_rule(CustomRule);
        let ctx = health_context("/health");
        assert!(
            engine
                .fast_allow(
                    &ctx.method,
                    &ctx.uri,
                    &ctx.headers,
                    ctx.client_ip,
                    ctx.body_size,
                    true,
                )
                .is_none(),
            "an unknown custom rule must force full evaluation"
        );
    }
}
