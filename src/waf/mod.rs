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

use bytes::Bytes;
use hyper::{HeaderMap, Method, Uri};
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::time::Instant;
use tracing::{debug, info, warn};

use self::content_inspection::ContentInspectionRuleFactory;
use self::geoip::{GeoBlockingRuleFactory, GeoIpService};
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
#[derive(Debug)]
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

/// WAF engine for evaluating requests against rules
pub struct WafEngine {
    rules: Arc<RwLock<Vec<Box<dyn WafRule>>>>,
    event_logger: SecurityEventLogger,
    geoip_service: Arc<GeoIpService>,
    #[cfg(feature = "wasm-waf")]
    wasm_engine: Option<Arc<WasmEngine>>,
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
            #[cfg(feature = "wasm-waf")]
            wasm_engine: self.wasm_engine.clone(),
        }
    }
}

impl WafEngine {
    pub fn new() -> Self {
        Self {
            rules: Arc::new(RwLock::new(Vec::new())),
            event_logger: SecurityEventLogger::default_logger(),
            geoip_service: Arc::new(GeoIpService::new()),
            #[cfg(feature = "wasm-waf")]
            wasm_engine: None,
        }
    }

    pub fn with_config(config: &Config) -> Self {
        let mut engine = Self {
            rules: Arc::new(RwLock::new(Vec::new())),
            event_logger: SecurityEventLogger::new(config.waf.security_events.clone()),
            geoip_service: Arc::new(GeoIpService::new()),
            #[cfg(feature = "wasm-waf")]
            wasm_engine: Self::initialize_wasm_engine(config),
        };

        // Add default rules based on configuration
        engine.add_default_rules(config);

        engine
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
            memory_limit_mb: config.waf.wasm.memory_limit,
            timeout_ms: config.waf.wasm.timeout_ms,
            debug: config.waf.wasm.debug,
            instance_pool_size: config.waf.wasm.instance_pool_size,
            hot_reload: config.waf.wasm.hot_reload,
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

    fn add_default_rules(&mut self, config: &Config) {
        // Add content inspection rules
        if config.waf.content_inspection.enabled {
            for pattern in &config.waf.content_inspection.threat_patterns {
                let rule = ContentInspectionRuleFactory::create_threat_rule(pattern);
                self.add_rule(rule);
            }
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
            // Skip expensive logging for performance in fast path
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
        let mut triggered_rules = Vec::new();
        let mut blocking_decision = None;
        let rules_count;

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
                    pub use simd_ops::{fast_pattern_search, contains_sql_injection_patterns, contains_xss_patterns};
                }
                Err(e) => {
                    warn!("WASM ModSecurity engine error: {}", e);
                    // Continue with traditional rules on WASM error (fail-open for WASM)
                }
            }
        }

        // PHASE 2: Traditional rule evaluation
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
}
