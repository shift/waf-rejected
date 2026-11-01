pub mod ai;
pub mod auth;
pub mod content_inspection;
pub mod exporters;
pub mod geoip;
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

use bytes::Bytes;
use hyper::{HeaderMap, Method, Uri};
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::time::Instant;
use tracing::{debug, info, warn};

use self::content_inspection::ContentInspectionRuleFactory;
use self::geoip::{GeoBlockingRuleFactory, GeoIpService};
use self::rate_limit::{GlobalRateLimiter, RateLimiter};
use self::rules::{MethodRule, RequestSizeRule};
use self::security_events::SecurityEventLogger;
use crate::config::Config;

#[cfg(feature = "wasm-waf")]
use crate::wasm::{SecurityDecision as WasmDecision, WasmEngine, WasmRequestContext};

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
#[cfg(feature = "wasm-reactor")]
struct UnavailableCorazaRule {
    reason: String,
}

#[cfg(feature = "wasm-reactor")]
impl WafRule for UnavailableCorazaRule {
    fn name(&self) -> &str {
        "coraza-wasi-reactor-unavailable"
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
    /// Start-up failure for the Coraza reactor. This is fatal for
    /// [`WafProxyService::new`](crate::proxy::WafProxyService::new) rather
    /// than deferred to request time.
    #[cfg(feature = "wasm-reactor")]
    coraza_init_error: Option<String>,
    #[cfg(feature = "wasm-waf")]
    wasm_engine: Option<Arc<WasmEngine>>,
    #[cfg(feature = "ai-threat-detection")]
    ai_detector: Option<Arc<ai::AiThreatDetector>>,
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
            coraza_init_error: self.coraza_init_error.clone(),
            #[cfg(feature = "wasm-waf")]
            wasm_engine: self.wasm_engine.clone(),
            #[cfg(feature = "ai-threat-detection")]
            ai_detector: self.ai_detector.clone(),
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
            coraza_init_error: None,
            #[cfg(feature = "wasm-waf")]
            wasm_engine: None,
        }
    }

    pub fn with_config(config: &Config) -> Self {
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
            coraza_init_error: None,
            #[cfg(feature = "wasm-waf")]
            wasm_engine,
            #[cfg(feature = "ai-threat-detection")]
            ai_detector: Self::initialize_ai_detector(config),
        };

        // The Coraza reactor must run before the traditional heuristics.
        #[cfg(feature = "wasm-reactor")]
        engine.add_coraza_rule(config);

        // Add default rules based on configuration
        engine.add_default_rules(config);

        engine
    }

    #[cfg(feature = "wasm-reactor")]
    fn add_coraza_rule(&mut self, config: &Config) {
        if !config.waf.enabled || !config.waf.coraza.enabled {
            return;
        }

        match wasm_reactor::WasmReactorRule::from_config(&config.waf.coraza, self.fail_closed) {
            Ok(rule) => {
                info!("Added Coraza WASI reactor as the first WAF rule");
                self.add_rule(rule);
            }
            Err(err) => {
                warn!(error = %err, "failed to initialise Coraza WASI reactor");
                let reason = format!("Coraza WASI reactor failed to initialise: {err}");
                self.coraza_init_error = Some(reason.clone());
                if self.fail_closed {
                    // Preserve request-time fail-closed behaviour for callers
                    // that build a WafEngine directly.
                    self.add_rule(UnavailableCorazaRule { reason });
                }
            }
        }
    }

    /// Returns the Coraza start-up error, if the reactor was enabled but could
    /// not be compiled, validated or warmed. Proxy start-up treats this as
    /// fatal so the process never serves traffic without its WAF engine.
    #[cfg(feature = "wasm-reactor")]
    pub fn coraza_init_error(&self) -> Option<&str> {
        self.coraza_init_error.as_deref()
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

    pub fn add_rule<R: WafRule + 'static>(&mut self, rule: R) {
        let mut rules = self.rules.write().unwrap();
        rules.push(Box::new(rule));
    }

    /// Fast evaluation for performance-critical paths (headers/URI only)
    /// Skips expensive operations like body inspection
    pub async fn fast_evaluate(&self, request: &RequestContext) -> Decision {
        if !self.enabled {
            return Decision::Allow;
        }
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
