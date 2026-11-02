pub mod admission;
pub mod ai;
pub mod auth;
pub mod content_inspection;
pub mod exporters;
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

/// Experimental required-literal prefilter for CRS request bodies. Non-default:
/// it is an opt-in evaluation mode until the detection-parity corpus proves it.
#[cfg(feature = "crs-prefilter")]
pub mod prefilter;
/// Offline extractor that emits `rules/crs/prefilter.json`.
#[cfg(feature = "crs-prefilter")]
pub mod prefilter_extract;

/// Shared JSON payload envelope for the wasm reactor and native sidecar.
#[cfg(any(feature = "wasm-reactor", feature = "coraza-native"))]
pub mod coraza_payload;
#[cfg(all(feature = "coraza-native", unix))]
pub mod coraza_wire;

/// Experimental native Go Coraza sidecar client (non-default feature).
#[cfg(all(feature = "coraza-native", unix))]
pub mod native_coraza;

/// Protocol-aware gRPC inspection (protobuf frames are not sent to CRS body
/// rules).
#[cfg(feature = "wasm-reactor")]
pub mod grpc;

/// Protocol-aware GraphQL-over-HTTP inspection (raw JSON bodies can be
/// withheld from CRS body rules in `graphql-only` mode).
#[cfg(feature = "wasm-reactor")]
pub mod graphql;
/// Deterministic persisted-query allowlist generation and loading.
#[cfg(feature = "wasm-reactor")]
pub mod graphql_allowlist;
/// Minimal protobuf wire decoder used by gRPC field-level inspection.
#[cfg(feature = "wasm-reactor")]
pub mod protobuf;

use bytes::Bytes;
use hyper::{HeaderMap, Method, Uri};
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::time::Instant;
use tracing::{debug, info, warn};

use self::admission::AdmissionController;
use self::content_inspection::ContentInspectionRuleFactory;
use self::geoip::{GeoBlockingRuleFactory, GeoIpService};
use self::rate_limit::{GlobalRateLimiter, RateLimiter};
use self::rules::{MethodRule, RequestSizeRule};
use self::security_events::SecurityEventLogger;
use crate::config::Config;

#[cfg(feature = "wasm-waf")]
use crate::wasm::{SecurityDecision as WasmDecision, WasmEngine, WasmRequestContext};

/// Direct Coraza backend handle used for gRPC field-content scanning.
#[cfg(feature = "wasm-reactor")]
type GrpcContentScannerHandle = Arc<dyn grpc::GrpcContentScanner>;
#[cfg(not(feature = "wasm-reactor"))]
type GrpcContentScannerHandle = ();

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
    pub http_version: String,
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
            http_version: "1.1".to_string(), // Default to HTTP/1.1
        }
    }

    /// Create RequestContext with explicit HTTP version
    pub fn with_http_version(
        client_ip: IpAddr,
        method: Method,
        uri: Uri,
        headers: HeaderMap,
        body_size: Option<usize>,
        http_version: String,
    ) -> Self {
        Self {
            client_ip,
            method,
            uri,
            headers,
            body_size,
            body: None,
            timestamp: Instant::now(),
            http_version,
        }
    }

    pub fn with_body(mut self, body: Option<Bytes>) -> Self {
        self.body = body;
        self
    }
}

/// WAF rule trait for implementing custom rules
pub trait WafRule: Send + Sync {
    fn name(&self) -> &str;
    fn evaluate(&self, ctx: &RequestContext) -> Decision;
    fn is_enabled(&self) -> bool {
        true
    }
}

/// Fail-closed placeholder used when a configured reactor cannot be loaded.
#[cfg(any(feature = "wasm-reactor", feature = "coraza-native"))]
struct UnavailableCorazaRule {
    reason: String,
}

#[cfg(any(feature = "wasm-reactor", feature = "coraza-native"))]
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
    #[cfg(feature = "wasm-reactor")]
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
    /// Shared runtime metrics, when the caller supplied them.
    metrics: Option<Arc<crate::metrics::Metrics>>,
}

/// Outcome of the gRPC protocol pre-check.
#[cfg(feature = "wasm-reactor")]
enum GrpcPrecheck {
    /// Continue evaluation with the supplied (possibly body-stripped) context.
    Continue(Box<RequestContext>),
    /// Return this decision immediately.
    Reject(Decision),
}

/// Outcome of the GraphQL protocol pre-check.
#[cfg(feature = "wasm-reactor")]
enum GraphqlPrecheck {
    /// Continue evaluation with the supplied (possibly body-stripped) context.
    Continue(Box<RequestContext>),
    /// Return this decision immediately.
    Reject(Decision),
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
            #[cfg(feature = "wasm-reactor")]
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
            metrics: self.metrics.clone(),
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
            #[cfg(feature = "wasm-reactor")]
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
            metrics: None,
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

        let mut engine = Self {
            rules: Arc::new(RwLock::new(Vec::new())),
            event_logger: SecurityEventLogger::new(config.waf.security_events.clone()),
            geoip_service: Self::initialize_geoip(config),
            enabled: config.waf.enabled,
            fail_closed: config.waf.fail_mode != "open",
            wasm_init_failed,
            #[cfg(feature = "wasm-reactor")]
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
            metrics,
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
        #[cfg(any(feature = "wasm-reactor", feature = "coraza-native"))]
        let content_scanner = engine.add_coraza_rule(config);

        // gRPC field-content scanning reuses the same backend directly. It is
        // attached after the Coraza rule so no second reactor is compiled.
        #[cfg(feature = "wasm-reactor")]
        if let (Some(inspector), Some(scanner)) = (engine.grpc_inspector.take(), content_scanner) {
            engine.grpc_inspector = Some(inspector.with_content_scanner(scanner));
        }

        // Add default rules based on configuration
        engine.add_default_rules(config);

        engine
    }

    #[cfg(any(feature = "wasm-reactor", feature = "coraza-native"))]
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

    /// Records a start-up failure, keeping earlier ones so the operator sees
    /// every misconfigured component.
    #[cfg(feature = "wasm-reactor")]
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
    #[cfg(feature = "wasm-reactor")]
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
            self.add_rule(RateLimiter::new(
                "per_ip_rate_limit",
                config.waf.rate_limit.per_ip_max_requests.max(1),
                refill,
                std::time::Duration::from_secs(window),
            ));
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

    pub fn add_rule<R: WafRule + 'static>(&mut self, rule: R) {
        self.add_rule_boxed(Box::new(rule));
    }

    fn add_rule_boxed(&mut self, rule: Box<dyn WafRule>) {
        let mut rules = self.rules.write().unwrap();
        rules.push(rule);
    }

    /// Outcome of the gRPC protocol pre-check.
    #[cfg(feature = "wasm-reactor")]
    async fn grpc_precheck(&self, request: &RequestContext) -> Option<GrpcPrecheck> {
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
                let decision = Decision::Block { status, reason };
                self.event_logger
                    .log_event(
                        request,
                        &decision,
                        vec!["grpc-protocol-inspection".to_string()],
                    )
                    .await;
                Some(GrpcPrecheck::Reject(decision))
            }
            Err(err) => {
                if let Some(metrics) = &self.metrics {
                    metrics.record_grpc_error();
                }
                if self.fail_closed {
                    let decision = Decision::Block {
                        status: 503,
                        reason: format!("gRPC inspection unavailable: {err}"),
                    };
                    self.event_logger
                        .log_event(
                            request,
                            &decision,
                            vec!["grpc-protocol-inspection".to_string()],
                        )
                        .await;
                    Some(GrpcPrecheck::Reject(decision))
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
    #[cfg(feature = "wasm-reactor")]
    async fn graphql_precheck(&self, request: &RequestContext) -> Option<GraphqlPrecheck> {
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
                let decision = Decision::Block { status, reason };
                self.event_logger
                    .log_event(request, &decision, vec![graphql::RULE_NAME.to_string()])
                    .await;
                Some(GraphqlPrecheck::Reject(decision))
            }
            Err(err) => {
                if let Some(metrics) = &self.metrics {
                    metrics.record_graphql_error();
                }
                if self.fail_closed {
                    let decision = Decision::Block {
                        status: 503,
                        reason: format!("GraphQL inspection unavailable: {err}"),
                    };
                    self.event_logger
                        .log_event(request, &decision, vec![graphql::RULE_NAME.to_string()])
                        .await;
                    Some(GraphqlPrecheck::Reject(decision))
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

    /// Fast evaluation for performance-critical paths (headers/URI only)
    /// Skips expensive operations like body inspection
    pub async fn fast_evaluate(&self, request: &RequestContext) -> Decision {
        if !self.enabled {
            return Decision::Allow;
        }

        // Admission control covers the protocol pre-checks too: a gRPC
        // field-content scan is a full Coraza evaluation even though the raw
        // body is withheld from the rule chain.
        let _admission_guard = match self.admission.admit(self.inspection_cost(request)).await {
            Ok(guard) => guard,
            Err(rejection) => return self.admission_rejected(request, rejection).await,
        };

        #[cfg(feature = "wasm-reactor")]
        let graphql_context;
        #[cfg(feature = "wasm-reactor")]
        let request: &RequestContext = match self.graphql_precheck(request).await {
            Some(GraphqlPrecheck::Reject(decision)) => return decision,
            Some(GraphqlPrecheck::Continue(context)) => {
                graphql_context = *context;
                &graphql_context
            }
            None => request,
        };
        #[cfg(feature = "wasm-reactor")]
        let grpc_context;
        #[cfg(feature = "wasm-reactor")]
        let request: &RequestContext = match self.grpc_precheck(request).await {
            Some(GrpcPrecheck::Reject(decision)) => return decision,
            Some(GrpcPrecheck::Continue(context)) => {
                grpc_context = *context;
                &grpc_context
            }
            None => request,
        };

        let mut triggered_rules = Vec::new();
        let mut blocking_decision = None;
        let rules_count;

        // PHASE 1: WASM ModSecurity evaluation (if enabled) - Skip for fast path
        #[cfg(feature = "wasm-waf")]
        if let Some(_wasm_engine) = &self.wasm_engine {
            debug!("Skipping WASM evaluation for fast path (performance optimization)");
        }

        // PHASE 2: Optimized traditional rule evaluation
        {
            let rules = self.rules.read().unwrap();
            rules_count = rules.len();

            debug!(
                "Fast evaluating {} traditional rules for request from {}",
                rules_count, request.client_ip
            );

            // Optimized rule evaluation - check only lightweight rules first
            for rule in rules.iter() {
                if !rule.is_enabled() {
                    continue;
                }

                let decision = rule.evaluate(request);
                match &decision {
                    Decision::Block { status, reason } => {
                        triggered_rules.push(rule.name().to_string());

                        debug!(
                            "Fast rule '{}' blocked request from {}: {} ({})",
                            rule.name(),
                            request.client_ip,
                            reason,
                            status
                        );

                        // Store the blocking decision and break early for performance
                        blocking_decision = Some(decision);
                        break;
                    }
                    Decision::RateLimit { reason } => {
                        triggered_rules.push(rule.name().to_string());

                        debug!(
                            "Fast rule '{}' rate limited request from {}: {}",
                            rule.name(),
                            request.client_ip,
                            reason
                        );

                        // Store the rate limit decision and break early
                        blocking_decision = Some(decision);
                        break;
                    }
                    Decision::Allow => {
                        // Continue evaluating other rules quickly
                    }
                }
            }
        } // RwLockReadGuard is dropped here

        // Now we can safely do async operations (if needed)
        if let Some(decision) = blocking_decision {
            // Even the fast path must produce an audit event for blocks.
            self.event_logger
                .log_event(request, &decision, triggered_rules)
                .await;
            return decision;
        }

        // If we get here, all rules passed
        debug!(
            "Fast evaluation: All {} rules passed for request from {}",
            rules_count, request.client_ip
        );

        Decision::Allow
    }

    /// Evaluate all rules against the request context
    /// Returns the first blocking decision or Allow if all rules pass
    pub async fn evaluate(&self, request: &RequestContext) -> Decision {
        if !self.enabled {
            return Decision::Allow;
        }

        // Admission control covers the protocol pre-checks as well as the rule
        // chain: a gRPC field-content scan runs a Coraza evaluation before the
        // main evaluation. Classification uses the original request, because
        // the pre-checks strip the body that made the scan expensive.
        let _admission_guard = match self.admission.admit(self.inspection_cost(request)).await {
            Ok(guard) => guard,
            Err(rejection) => return self.admission_rejected(request, rejection).await,
        };

        #[cfg(feature = "wasm-reactor")]
        let graphql_context;
        #[cfg(feature = "wasm-reactor")]
        let request: &RequestContext = match self.graphql_precheck(request).await {
            Some(GraphqlPrecheck::Reject(decision)) => return decision,
            Some(GraphqlPrecheck::Continue(context)) => {
                graphql_context = *context;
                &graphql_context
            }
            None => request,
        };
        #[cfg(feature = "wasm-reactor")]
        let grpc_context;
        #[cfg(feature = "wasm-reactor")]
        let request: &RequestContext = match self.grpc_precheck(request).await {
            Some(GrpcPrecheck::Reject(decision)) => return decision,
            Some(GrpcPrecheck::Continue(context)) => {
                grpc_context = *context;
                &grpc_context
            }
            None => request,
        };

        let mut triggered_rules = Vec::new();
        let mut blocking_decision = None;
        let rules_count;

        // A configured-but-unavailable WASM engine must not silently downgrade
        // to traditional rules when fail-closed is requested.
        if self.wasm_init_failed && self.fail_closed {
            let decision = Decision::Block {
                status: 503,
                reason: "WAF engine failed to initialise (fail-closed)".to_string(),
            };
            self.event_logger
                .log_event(request, &decision, vec!["wasm_init_failed".to_string()])
                .await;
            return decision;
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
                            triggered_rules.push("WASM-ModSecurity".to_string());

                            // Log security event and return immediately
                            self.event_logger
                                .log_event(request, &decision, triggered_rules)
                                .await;
                            return decision;
                        }
                        Decision::Allow => {
                            debug!("Request allowed by WASM ModSecurity engine, continuing with traditional rules");
                        }
                    }

                    // Re-export performance optimization modules
                }
                Err(e) => {
                    warn!("WASM ModSecurity engine error: {}", e);
                    if self.fail_closed {
                        let decision = Decision::Block {
                            status: 503,
                            reason: "WAF engine unavailable (fail-closed)".to_string(),
                        };
                        self.event_logger
                            .log_event(request, &decision, triggered_rules)
                            .await;
                        return decision;
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
                            ai_result.analysis.threat_score
                        );
                        triggered_rules.push("AI-Threat-Detection".to_string());

                        let decision = Decision::Block {
                            status: 403,
                            reason: format!(
                                "AI detected threat (score: {:.3})",
                                ai_result.analysis.threat_score
                            ),
                        };

                        self.event_logger
                            .log_event(request, &decision, triggered_rules)
                            .await;
                        return decision;
                    } else {
                        debug!(
                            "AI analysis passed (score: {:.3})",
                            ai_result.analysis.threat_score
                        );
                    }
                }
                Err(e) => {
                    warn!("AI analysis error: {}", e);
                    if self.fail_closed {
                        let decision = Decision::Block {
                            status: 503,
                            reason: "WAF AI engine unavailable (fail-closed)".to_string(),
                        };
                        self.event_logger
                            .log_event(request, &decision, triggered_rules)
                            .await;
                        return decision;
                    }
                }
            }
        }

        // PHASE 3: Traditional rule evaluation
        {
            let rules = self.rules.read().unwrap();
            rules_count = rules.len();

            debug!(
                "Evaluating {} traditional rules for request from {}",
                rules_count, request.client_ip
            );

            for rule in rules.iter() {
                if !rule.is_enabled() {
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

                        // Store the blocking decision and break
                        blocking_decision = Some(decision);
                        break;
                    }
                    Decision::RateLimit { reason } => {
                        triggered_rules.push(rule.name().to_string());

                        warn!(
                            "Rule '{}' rate limited request from {}: {}",
                            rule.name(),
                            request.client_ip,
                            reason
                        );

                        // Store the rate limit decision and break
                        blocking_decision = Some(decision);
                        break;
                    }
                    Decision::Allow => {
                        debug!("Rule '{}' allowed request", rule.name());
                        // Continue evaluating other rules
                    }
                }
            }
        } // RwLockReadGuard is dropped here

        // Now we can safely do async operations
        if let Some(decision) = blocking_decision {
            // Log security event with enhanced logging
            self.event_logger
                .log_event(request, &decision, triggered_rules)
                .await;
            return decision;
        }

        // If we get here, all rules passed
        debug!(
            "All {} rules passed for request from {}",
            rules_count, request.client_ip
        );

        // Log allowed request if configured to log low-threat events
        let allow_decision = Decision::Allow;
        self.event_logger
            .log_event(request, &allow_decision, triggered_rules)
            .await;

        allow_decision
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

    pub fn enabled_rule_count(&self) -> usize {
        self.rules
            .read()
            .unwrap()
            .iter()
            .filter(|r| r.is_enabled())
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

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
}
