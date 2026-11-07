#!/usr/bin/env cargo
//! Simple smoke test for WAF-Rejected core functionality
//!
//! This validates the core WAF engine can:
//! 1. Initialize successfully
//! 2. Load and evaluate rules
//! 3. Make basic security decisions
//!
//! Aligned with Strategic Roadmap v0.1: The Stable Core

use hyper::{HeaderMap, Method, Uri};
use std::net::IpAddr;
use std::str::FromStr;
use waf_ingress::waf::rules::{IpRule, MethodRule, RequestSizeRule};
use waf_ingress::waf::{Decision, RequestContext, WafEngine};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    println!("🚀 WAF-Rejected Core Functionality Smoke Test");
    println!("===============================================");

    // Test 1: WAF Engine Initialization
    println!("\n1. Testing WAF Engine initialization...");
    let mut engine = WafEngine::new();
    println!("   ✅ WAF Engine initialized successfully");

    // Test 2: Rule Loading
    println!("\n2. Testing Rule loading...");

    // Add a request size rule
    let size_rule = RequestSizeRule::new("max_request_size", 1024 * 1024); // 1MB
    engine.add_rule(size_rule);

    // Add a method rule
    let method_rule = MethodRule::new("blocked_methods")
        .block_method(Method::DELETE)
        .block_method(Method::PATCH);
    engine.add_rule(method_rule);

    // Add an IP rule
    let ip_rule = IpRule::new("blocked_ips").block_ip(IpAddr::from_str("192.168.1.100")?);
    engine.add_rule(ip_rule);

    println!("   ✅ {} rules loaded successfully", engine.rule_count());
    println!("   ✅ {} rules enabled", engine.enabled_rule_count());

    // Test 3: Request Context Creation
    println!("\n3. Testing Request Context creation...");
    let ctx = RequestContext::new(
        IpAddr::from_str("192.168.1.50")?,
        Method::GET,
        Uri::from_str("/api/test")?,
        HeaderMap::new(),
        Some(512), // body_size
    );
    println!("   ✅ Request context created successfully");

    // Test 4: WAF Evaluation - Normal Request (Should Allow)
    println!("\n4. Testing normal request evaluation...");
    let decision = engine.evaluate(&ctx).await;
    match decision {
        Decision::Allow => {
            println!("   ✅ Normal request allowed as expected");
        }
        other => {
            println!("   ❌ Expected Allow, got: {:?}", other);
            return Err("Normal request was not allowed".into());
        }
    }

    // Test 5: WAF Evaluation - Blocked Method (Should Block)
    println!("\n5. Testing blocked method detection...");
    let blocked_ctx = RequestContext::new(
        IpAddr::from_str("192.168.1.50")?,
        Method::DELETE,
        Uri::from_str("/api/test")?,
        HeaderMap::new(),
        Some(512),
    );

    let decision = engine.evaluate(&blocked_ctx).await;
    match decision {
        Decision::Block { status, reason } => {
            println!("   ✅ Blocked method detected: {} - {}", status, reason);
        }
        other => {
            println!("   ❌ Expected Block, got: {:?}", other);
            return Err("Blocked method was not detected".into());
        }
    }

    // Test 6: WAF Evaluation - Blocked IP (Should Block)
    println!("\n6. Testing blocked IP detection...");
    let blocked_ip_ctx = RequestContext::new(
        IpAddr::from_str("192.168.1.100")?,
        Method::GET,
        Uri::from_str("/api/test")?,
        HeaderMap::new(),
        Some(512),
    );

    let decision = engine.evaluate(&blocked_ip_ctx).await;
    match decision {
        Decision::Block { status, reason } => {
            println!("   ✅ Blocked IP detected: {} - {}", status, reason);
        }
        other => {
            println!("   ❌ Expected Block, got: {:?}", other);
            return Err("Blocked IP was not detected".into());
        }
    }

    // Test 7: Performance Baseline
    println!("\n7. Testing basic performance baseline...");
    let start = std::time::Instant::now();
    let iterations = 1000;

    for _ in 0..iterations {
        let _ = engine.evaluate(&ctx).await;
    }

    let duration = start.elapsed();
    let avg_micros = duration.as_micros() / iterations as u128;
    let rps_estimate = 1_000_000 / avg_micros; // Rough RPS estimate

    println!("   ✅ {} evaluations in {:?}", iterations, duration);
    println!("   ✅ Average: {} μs per evaluation", avg_micros);
    println!("   ✅ Estimated RPS capability: ~{}", rps_estimate);

    if avg_micros > 1000 {
        println!("   ⚠️  Performance warning: >1ms per evaluation");
    } else {
        println!("   ✅ Performance target achieved: <1ms per evaluation");
    }

    println!("\n🎉 WAF-Rejected Core Functionality Smoke Test PASSED");
    println!("==================================================");
    println!("✅ Core WAF engine operational");
    println!("✅ Rule loading and evaluation functional");
    println!("✅ Security decisions working correctly");
    println!("✅ Basic performance baseline established");
    println!("\n🚀 Ready for Phase 1 Day 3: Performance validation");

    Ok(())
}
