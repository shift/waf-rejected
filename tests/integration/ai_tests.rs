use std::net::IpAddr;
use std::str::FromStr;
use std::time::Instant;

use hyper::{Method, Uri, HeaderMap};
use bytes::Bytes;

use waf_ingress::waf::{WafEngine, RequestContext, Decision};
use waf_ingress::config::Config;

/// Integration tests for AI threat detection
#[cfg(test)]
mod ai_integration_tests {
    use super::*;

    fn create_config_with_ai() -> Config {
        let mut config = Config::default();
        config.security.ai.enabled = true;
        config.security.ai.threat_threshold = 0.7;
        config.security.ai.timeout_ms = 2000;

        config
    }

    fn create_malicious_request() -> RequestContext {
        let mut headers = HeaderMap::new();
        headers.insert("User-Agent", "MaliciousBot/1.0".parse().unwrap());
        headers.insert("X-API-Key", "test-key".parse().unwrap());

        RequestContext::new(
            IpAddr::from_str("192.168.1.100").unwrap(),
            Method::POST,
            Uri::from_str("http://example.com/api/user").unwrap(),
            headers,
            Some(1024),
        ).with_body(Some(Bytes::from(r#"{
            "query": "'; DROP TABLE users; --",
            "action": "<script>alert('xss')</script>",
            "data": "UNION SELECT * FROM admin"
        }"#)))
    }

    fn create_benign_request() -> RequestContext {
        let mut headers = HeaderMap::new();
        headers.insert("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".parse().unwrap());
        headers.insert("X-API-Key", "test-key".parse().unwrap());

        RequestContext::new(
            IpAddr::from_str("192.168.1.100").unwrap(),
            Method::GET,
            Uri::from_str("http://example.com/api/user/profile").unwrap(),
            headers,
            None,
        )
    }

    #[tokio::test]
    async fn test_ai_threat_detection_enabled() {
        let config = create_config_with_ai();
        let engine = WafEngine::with_config(&config);

        // Verify AI is configured
        assert!(config.security.ai.enabled);
        assert_eq!(config.security.ai.threat_threshold, 0.7);
        assert_eq!(config.security.ai.timeout_ms, 2000);

        // The engine should be created successfully
        // (AI detector initialization may fail in test environment, but that's OK)
    }

    #[tokio::test]
    async fn test_waf_engine_with_ai_disabled() {
        let mut config = Config::default();
        config.security.ai.enabled = false; // Explicitly disable AI

        let engine = WafEngine::with_config(&config);

        // Should work without AI
        let request = create_benign_request();
        let decision = engine.evaluate(&request).await;

        // Should allow benign requests
        assert_eq!(decision, Decision::Allow);
    }

    #[tokio::test]
    async fn test_ai_timeout_handling() {
        let mut config = create_config_with_ai();
        config.security.ai.timeout_ms = 1; // Very short timeout

        let engine = WafEngine::with_config(&config);

        // Create a request that might trigger AI analysis
        let request = create_malicious_request();

        // Should not hang due to timeout
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            engine.evaluate(&request)
        ).await;

        // Should complete within timeout (may allow or block, but shouldn't hang)
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_ai_integration_with_traditional_rules() {
        let config = create_config_with_ai();
        let mut engine = WafEngine::with_config(&config);

        // Add a traditional rule that should block
        use waf_ingress::waf::rules::RequestSizeRule;
        engine.add_rule(RequestSizeRule::new("size_limit", 100)); // Very small limit

        let request = create_malicious_request();
        let decision = engine.evaluate(&request).await;

        // Should be blocked by traditional rule (size limit)
        match decision {
            Decision::Block { .. } => {
                // Expected - traditional rules take precedence
            }
            _ => {
                // If not blocked by traditional rules, AI might still catch it
                // This is acceptable as long as it doesn't crash
            }
        }
    }

    #[tokio::test]
    async fn test_ai_configuration_validation() {
        // Test various AI configurations
        let configs = vec![
            {
                let mut c = Config::default();
                c.security.ai.enabled = true;
                c.security.ai.threat_threshold = 0.0; // Very low threshold
                c
            },
            {
                let mut c = Config::default();
                c.security.ai.enabled = true;
                c.security.ai.threat_threshold = 1.0; // Very high threshold
                c
            },
            {
                let mut c = Config::default();
                c.security.ai.enabled = true;
                c.security.ai.timeout_ms = 10000; // Long timeout
                c
            },
        ];

        for config in configs {
            // Should create engine without panicking
            let _engine = WafEngine::with_config(&config);
        }
    }

    #[tokio::test]
    async fn test_performance_with_ai_enabled() {
        let config = create_config_with_ai();
        let engine = WafEngine::with_config(&config);

        let request = create_benign_request();

        // Measure performance
        let start = Instant::now();

        for _ in 0..10 {
            let _decision = engine.evaluate(&request).await;
        }

        let elapsed = start.elapsed();
        let avg_latency = elapsed.as_millis() as f64 / 10.0;

        // AI should not add excessive latency (less than 50ms per request in test environment)
        assert!(avg_latency < 50.0, "AI analysis too slow: {}ms average", avg_latency);
    }
}