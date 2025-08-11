pub mod middleware;
pub mod rules;
pub mod rate_limit;
pub mod proxy;
pub mod security_events;
pub mod content_inspection;
pub mod geoip;
pub mod exporters;

use std::net::IpAddr;
use std::time::Instant;
use std::sync::{Arc, RwLock};
use hyper::{HeaderMap, Method, Uri};
use bytes::Bytes;
use tracing::{info, warn, debug};

use crate::config::Config;
use self::security_events::SecurityEventLogger;
use self::content_inspection::ContentInspectionRuleFactory;
use self::geoip::{GeoBlockingRuleFactory, GeoIpService};

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
    fn is_enabled(&self) -> bool { true }
}

/// WAF engine for evaluating requests against rules
pub struct WafEngine {
    rules: Arc<RwLock<Vec<Box<dyn WafRule>>>>,
    event_logger: SecurityEventLogger,
    geoip_service: Arc<GeoIpService>,
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
        }
    }
}

impl WafEngine {
    pub fn new() -> Self {
        Self { 
            rules: Arc::new(RwLock::new(Vec::new())),
            event_logger: SecurityEventLogger::default_logger(),
            geoip_service: Arc::new(GeoIpService::new()),
        }
    }

    pub fn with_config(config: &Config) -> Self {
        let mut engine = Self { 
            rules: Arc::new(RwLock::new(Vec::new())),
            event_logger: SecurityEventLogger::new(config.waf.security_events.clone()),
            geoip_service: Arc::new(GeoIpService::new()),
        };
        
        // Add default rules based on configuration
        engine.add_default_rules(config);
        
        engine
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

    /// Evaluate all rules against the request context
    /// Returns the first blocking decision or Allow if all rules pass
    pub async fn evaluate(&self, request: &RequestContext) -> Decision {
        let mut triggered_rules = Vec::new();
        let mut blocking_decision = None;
        let rules_count;
        
        // Scope the lock guard to avoid Send issues
        {
            let rules = self.rules.read().unwrap();
            rules_count = rules.len();
            
            debug!(
                "Evaluating {} rules for request from {}",
                rules_count,
                request.client_ip
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
                            rule.name(), request.client_ip, reason, status
                        );
                        
                        // Store the blocking decision and break
                        blocking_decision = Some(decision);
                        break;
                    }
                    Decision::RateLimit { reason } => {
                        triggered_rules.push(rule.name().to_string());
                        
                        warn!(
                            "Rule '{}' rate limited request from {}: {}",
                            rule.name(), request.client_ip, reason
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
            self.event_logger.log_event(request, &decision, triggered_rules).await;
            return decision;
        }
        
        // If we get here, all rules passed
        debug!("All {} rules passed for request from {}", rules_count, request.client_ip);
        
        // Log allowed request if configured to log low-threat events
        let allow_decision = Decision::Allow;
        self.event_logger.log_event(request, &allow_decision, triggered_rules).await;
        
        allow_decision
    }

    pub fn rule_count(&self) -> usize {
        self.rules.read().unwrap().len()
    }

    pub fn enabled_rule_count(&self) -> usize {
        self.rules.read().unwrap().iter().filter(|r| r.is_enabled()).count()
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
        
        assert_eq!(engine.evaluate(&ctx).await, Decision::Allow);
        assert_eq!(engine.rule_count(), 0);
        assert_eq!(engine.enabled_rule_count(), 0);
    }

    #[tokio::test]
    async fn test_waf_engine_allow_rule() {
        let mut engine = WafEngine::new();
        engine.add_rule(TestRule::new("allow_rule", Decision::Allow));
        
        let ctx = create_test_context();
        assert_eq!(engine.evaluate(&ctx).await, Decision::Allow);
        assert_eq!(engine.rule_count(), 1);
        assert_eq!(engine.enabled_rule_count(), 1);
    }

    #[tokio::test]
    async fn test_waf_engine_block_rule() {
        let mut engine = WafEngine::new();
        engine.add_rule(TestRule::new(
            "block_rule",
            Decision::Block { status: 403, reason: "Test block".to_string() }
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
            Decision::Block { status: 403, reason: "First block".to_string() }
        ));
        engine.add_rule(TestRule::new(
            "second_block_rule",
            Decision::Block { status: 404, reason: "Second block".to_string() }
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

    #[test]
    fn test_waf_engine_disabled_rule() {
        let mut engine = WafEngine::new();
        engine.add_rule(TestRule::new(
            "disabled_block_rule",
            Decision::Block { status: 403, reason: "Should not trigger".to_string() }
        ).disabled());
        
        let ctx = create_test_context();
        assert_eq!(engine.evaluate(&ctx), Decision::Allow);
        assert_eq!(engine.rule_count(), 1);
        assert_eq!(engine.enabled_rule_count(), 0);
    }

    #[test]
    fn test_waf_engine_rate_limit() {
        let mut engine = WafEngine::new();
        engine.add_rule(TestRule::new(
            "rate_limit_rule",
            Decision::RateLimit { reason: "Too many requests".to_string() }
        ));
        
        let ctx = create_test_context();
        let result = engine.evaluate(&ctx);
        
        match result {
            Decision::RateLimit { reason } => {
                assert_eq!(reason, "Too many requests");
            }
            _ => panic!("Expected RateLimit decision"),
        }
    }
}
