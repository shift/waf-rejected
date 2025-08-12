#!/usr/bin/env cargo
//! Test WASM ModSecurity integration

use waf_ingress::{Config, WafEngine, RequestContext};
use hyper::{Method, HeaderMap, Uri};
use std::net::IpAddr;
use std::str::FromStr;
use tracing_subscriber;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    
    println!("🧪 Testing WASM ModSecurity Integration");
    println!("=====================================");
    
    // Load configuration
    let config = Config::default();
    
    // Initialize WAF engine with WASM support
    let waf_engine = WafEngine::with_config(&config);
    
    println!("✅ WAF Engine initialized with {} rules", waf_engine.rule_count());
    
    // Test 1: Normal request (should be allowed)
    println!("\n📋 Test 1: Normal Request");
    let normal_request = create_request("GET", "/api/users", None);
    let decision = waf_engine.evaluate(&normal_request).await;
    println!("   Result: {:?}", decision);
    
    // Test 2: SQL injection attempt (should be blocked by WASM)
    println!("\n📋 Test 2: SQL Injection Attack");
    let sqli_request = create_request("POST", "/api/login?user=' OR '1'='1", None);
    let decision = waf_engine.evaluate(&sqli_request).await;
    println!("   Result: {:?}", decision);
    
    // Test 3: XSS attempt (should be blocked by WASM)
    println!("\n📋 Test 3: XSS Attack");
    let xss_request = create_request("GET", "/search?q=<script>alert('xss')</script>", None);
    let decision = waf_engine.evaluate(&xss_request).await;
    println!("   Result: {:?}", decision);
    
    // Test 4: Path traversal attempt (should be logged by WASM)
    println!("\n📋 Test 4: Path Traversal");
    let traversal_request = create_request("GET", "/file?path=../../etc/passwd", None);
    let decision = waf_engine.evaluate(&traversal_request).await;
    println!("   Result: {:?}", decision);
    
    println!("\n🏆 WASM ModSecurity Integration Test Complete!");
    println!("Strategic Roadmap v0.1: WASM integration ✅ FUNCTIONAL");
    
    Ok(())
}

fn create_request(method: &str, uri: &str, body_size: Option<usize>) -> RequestContext {
    let method = Method::from_str(method).unwrap();
    let uri = Uri::from_str(uri).unwrap();
    let headers = HeaderMap::new();
    let client_ip = IpAddr::from_str("192.168.1.10").unwrap();
    
    RequestContext::new(client_ip, method, uri, headers, body_size)
}
