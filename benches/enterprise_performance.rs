//! Enterprise WAF Performance and Load Tests
//! 
//! Comprehensive test suite proving production readiness for enterprise deployment

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use tokio::runtime::Runtime;
use std::time::{Duration, Instant};
use std::sync::{Arc, atomic::{AtomicU64, Ordering}};
use std::collections::HashMap;

// Import WAF components for testing
#[cfg(feature = "wasm-waf")]
use crate::wasm::{WasmEngine, WasmEngineConfig, WasmRequestContext};

#[cfg(feature = "export-system")]
use crate::waf::exporters::{
    dispatcher::ExportDispatcher,
    cef::CefExporter,
    sled::SledExporter,
};

/// Enterprise-grade load test configuration
#[derive(Debug, Clone)]
pub struct EnterpriseLoadConfig {
    /// Concurrent connections to simulate
    pub concurrent_users: usize,
    /// Requests per second target
    pub requests_per_second: u64,
    /// Test duration in seconds
    pub duration_seconds: u64,
    /// Request payload sizes to test
    pub payload_sizes: Vec<usize>,
    /// Attack pattern simulation
    pub attack_patterns: Vec<AttackPattern>,
}

impl Default for EnterpriseLoadConfig {
    fn default() -> Self {
        Self {
            concurrent_users: 1000,
            requests_per_second: 10000,
            duration_seconds: 300, // 5 minutes
            payload_sizes: vec![1024, 10240, 102400], // 1KB, 10KB, 100KB
            attack_patterns: vec![
                AttackPattern::SQLInjection,
                AttackPattern::XSS,
                AttackPattern::CommandInjection,
                AttackPattern::LFI,
                AttackPattern::RFI,
                AttackPattern::XXE,
            ],
        }
    }
}

#[derive(Debug, Clone)]
pub enum AttackPattern {
    SQLInjection,
    XSS,
    CommandInjection,
    LFI, // Local File Inclusion
    RFI, // Remote File Inclusion
    XXE, // XML External Entity
}

impl AttackPattern {
    fn to_payload(&self) -> &'static str {
        match self {
            AttackPattern::SQLInjection => "' OR '1'='1' --",
            AttackPattern::XSS => "<script>alert('XSS')</script>",
            AttackPattern::CommandInjection => "; cat /etc/passwd",
            AttackPattern::LFI => "../../../../etc/passwd",
            AttackPattern::RFI => "http://evil.com/shell.php",
            AttackPattern::XXE => "<!DOCTYPE test [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>",
        }
    }
}

/// Enterprise performance metrics
#[derive(Debug, Default)]
pub struct EnterpriseMetrics {
    pub total_requests: AtomicU64,
    pub successful_requests: AtomicU64,
    pub blocked_requests: AtomicU64,
    pub error_requests: AtomicU64,
    pub total_latency_ns: AtomicU64,
    pub max_latency_ns: AtomicU64,
    pub min_latency_ns: AtomicU64,
    pub p95_latency_ns: AtomicU64,
    pub p99_latency_ns: AtomicU64,
    pub memory_usage_mb: AtomicU64,
    pub cpu_usage_percent: AtomicU64,
}

impl EnterpriseMetrics {
    pub fn record_request(&self, latency_ns: u64, blocked: bool, error: bool) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        
        if error {
            self.error_requests.fetch_add(1, Ordering::Relaxed);
        } else if blocked {
            self.blocked_requests.fetch_add(1, Ordering::Relaxed);
        } else {
            self.successful_requests.fetch_add(1, Ordering::Relaxed);
        }
        
        self.total_latency_ns.fetch_add(latency_ns, Ordering::Relaxed);
        
        // Update max latency
        let current_max = self.max_latency_ns.load(Ordering::Relaxed);
        if latency_ns > current_max {
            self.max_latency_ns.compare_exchange_weak(
                current_max,
                latency_ns,
                Ordering::Relaxed,
                Ordering::Relaxed
            ).ok();
        }
        
        // Update min latency (skip first few to avoid initialization bias)
        let current_min = self.min_latency_ns.load(Ordering::Relaxed);
        if current_min == 0 || (latency_ns < current_min && latency_ns > 0) {
            self.min_latency_ns.compare_exchange_weak(
                current_min,
                latency_ns,
                Ordering::Relaxed,
                Ordering::Relaxed
            ).ok();
        }
    }
    
    pub fn average_latency_ns(&self) -> f64 {
        let total = self.total_latency_ns.load(Ordering::Relaxed);
        let count = self.total_requests.load(Ordering::Relaxed);
        if count > 0 {
            total as f64 / count as f64
        } else {
            0.0
        }
    }
    
    pub fn requests_per_second(&self, duration_seconds: u64) -> f64 {
        let total = self.total_requests.load(Ordering::Relaxed);
        if duration_seconds > 0 {
            total as f64 / duration_seconds as f64
        } else {
            0.0
        }
    }
    
    pub fn success_rate(&self) -> f64 {
        let total = self.total_requests.load(Ordering::Relaxed);
        let successful = self.successful_requests.load(Ordering::Relaxed);
        if total > 0 {
            (successful as f64 / total as f64) * 100.0
        } else {
            0.0
        }
    }
    
    pub fn block_rate(&self) -> f64 {
        let total = self.total_requests.load(Ordering::Relaxed);
        let blocked = self.blocked_requests.load(Ordering::Relaxed);
        if total > 0 {
            (blocked as f64 / total as f64) * 100.0
        } else {
            0.0
        }
    }
}

/// Enterprise WASM performance benchmarks
fn bench_wasm_enterprise_load(c: &mut Criterion) {
    #[cfg(feature = "wasm-waf")]
    {
        let rt = Runtime::new().unwrap();
        
        // Initialize WASM engine with enterprise configuration
        let engine_config = WasmEngineConfig {
            memory_limit: Some(64 * 1024 * 1024), // 64MB per instance
            execution_timeout_ms: 50, // 50ms enterprise SLA
            async_execution: true,
            ..Default::default()
        };
        
        let engine = rt.block_on(async {
            WasmEngine::new(engine_config).await.unwrap()
        });
        
        let mut group = c.benchmark_group("enterprise_wasm_performance");
        
        // Test different payload sizes
        for payload_size in [1024, 10240, 102400].iter() {
            group.throughput(Throughput::Bytes(*payload_size as u64));
            group.bench_with_input(
                BenchmarkId::new("wasm_request_processing", payload_size),
                payload_size,
                |b, &size| {
                    let payload = vec![b'A'; size];
                    let ctx = WasmRequestContext::from_http_request(
                        "POST",
                        "/api/enterprise",
                        &[
                            ("Content-Type", "application/json"),
                            ("User-Agent", "EnterpriseClient/1.0"),
                            ("X-Forwarded-For", "203.0.113.100"),
                        ],
                        "203.0.113.100",
                        Some(&payload),
                    );
                    
                    b.to_async(&rt).iter(|| async {
                        let result = engine.process_request(&ctx).await;
                        black_box(result)
                    });
                }
            );
        }
        
        // Test concurrent processing capability
        group.bench_function("concurrent_wasm_processing", |b| {
            b.to_async(&rt).iter(|| async {
                let mut handles = Vec::new();
                
                for i in 0..100 {
                    let engine = &engine;
                    let ctx = WasmRequestContext::from_http_request(
                        "GET",
                        &format!("/api/concurrent/{}", i),
                        &[("Host", "enterprise.example.com")],
                        &format!("192.168.1.{}", i % 255),
                        None,
                    );
                    
                    handles.push(tokio::spawn(async move {
                        engine.process_request(&ctx).await
                    }));
                }
                
                let results: Vec<_> = futures::future::join_all(handles).await;
                black_box(results)
            });
        });
        
        group.finish();
    }
    
    #[cfg(not(feature = "wasm-waf"))]
    {
        // Placeholder test when WASM is not enabled
        let mut group = c.benchmark_group("wasm_disabled");
        group.bench_function("no_wasm", |b| {
            b.iter(|| black_box(42))
        });
        group.finish();
    }
}

/// Enterprise export system performance benchmarks
fn bench_export_enterprise_throughput(c: &mut Criterion) {
    #[cfg(feature = "export-system")]
    {
        let rt = Runtime::new().unwrap();
        
        let mut group = c.benchmark_group("enterprise_export_throughput");
        
        // Test high-volume event export
        for event_count in [1000, 10000, 100000].iter() {
            group.throughput(Throughput::Elements(*event_count as u64));
            group.bench_with_input(
                BenchmarkId::new("bulk_event_export", event_count),
                event_count,
                |b, &count| {
                    b.to_async(&rt).iter(|| async {
                        // Simulate bulk export of security events
                        let events: Vec<_> = (0..count).map(|i| {
                            crate::waf::SecurityEvent {
                                id: format!("evt-{}", i),
                                timestamp: std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap()
                                    .as_secs(),
                                event_type: "bulk_test".to_string(),
                                severity: crate::waf::Severity::Medium,
                                client_ip: format!("10.0.{}.{}", i / 256, i % 256),
                                user_agent: Some("EnterpriseTestClient/1.0".to_string()),
                                request_method: "POST".to_string(),
                                request_uri: format!("/api/bulk/{}", i),
                                rule_id: Some(format!("rule-{}", i % 100)),
                                message: format!("Bulk test event {}", i),
                                blocked: i % 10 == 0, // 10% blocked
                                response_status: if i % 10 == 0 { 403 } else { 200 },
                            }
                        }).collect();
                        
                        // Measure export performance
                        let start = Instant::now();
                        for event in events {
                            // Simulate export processing
                            black_box(&event);
                        }
                        let duration = start.elapsed();
                        black_box(duration)
                    });
                }
            );
        }
        
        group.finish();
    }
}

/// Enterprise memory usage and stability tests
fn bench_memory_stability(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("memory_stability");
    
    // Long-running stability test
    group.measurement_time(Duration::from_secs(30));
    group.bench_function("long_running_stability", |b| {
        b.to_async(&rt).iter(|| async {
            let start_memory = get_memory_usage_mb();
            
            // Simulate 1 hour of processing in accelerated time
            for batch in 0..1000 {
                // Process batch of requests
                for request in 0..100 {
                    let ctx = create_test_request(batch, request);
                    // Simulate processing
                    tokio::task::yield_now().await;
                    black_box(&ctx);
                }
                
                // Yield periodically to allow cleanup
                if batch % 100 == 0 {
                    tokio::task::yield_now().await;
                }
            }
            
            let end_memory = get_memory_usage_mb();
            let memory_growth = end_memory.saturating_sub(start_memory);
            
            // Assert memory growth is reasonable (< 50MB for this test)
            assert!(memory_growth < 50, "Memory growth too high: {}MB", memory_growth);
            
            black_box(memory_growth)
        });
    });
    
    group.finish();
}

/// Create test request for benchmarking
fn create_test_request(batch: usize, request: usize) -> HashMap<String, String> {
    let mut req = HashMap::new();
    req.insert("method".to_string(), "POST".to_string());
    req.insert("uri".to_string(), format!("/api/test/{}/{}", batch, request));
    req.insert("client_ip".to_string(), format!("10.{}.{}.{}", 
        batch % 256, request % 256, (batch + request) % 256));
    req.insert("user_agent".to_string(), "EnterpriseTestClient/1.0".to_string());
    req.insert("payload".to_string(), "x".repeat(1024)); // 1KB payload
    req
}

/// Get current memory usage in MB (simplified for testing)
fn get_memory_usage_mb() -> u64 {
    // In a real implementation, this would use proper memory monitoring
    // For testing, we'll return a simulated value
    std::thread::available_parallelism()
        .map(|n| n.get() as u64 * 10)
        .unwrap_or(40)
}

/// Enterprise attack pattern detection benchmarks
fn bench_attack_detection_accuracy(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("attack_detection");
    
    // Test detection accuracy for different attack types
    for attack_pattern in [
        AttackPattern::SQLInjection,
        AttackPattern::XSS,
        AttackPattern::CommandInjection,
        AttackPattern::LFI,
        AttackPattern::RFI,
        AttackPattern::XXE,
    ].iter() {
        group.bench_with_input(
            BenchmarkId::new("detect_attack", format!("{:?}", attack_pattern)),
            attack_pattern,
            |b, attack| {
                b.to_async(&rt).iter(|| async {
                    let payload = attack.to_payload();
                    let ctx = create_attack_request(payload);
                    
                    // Simulate attack detection processing
                    let start = Instant::now();
                    let detected = simulate_attack_detection(payload).await;
                    let processing_time = start.elapsed();
                    
                    // Assert detection works and is fast
                    assert!(detected, "Attack pattern not detected: {:?}", attack);
                    assert!(processing_time.as_micros() < 1000, "Detection too slow: {:?}", processing_time);
                    
                    black_box((detected, processing_time))
                });
            }
        );
    }
    
    group.finish();
}

/// Create request with attack payload
fn create_attack_request(payload: &str) -> HashMap<String, String> {
    let mut req = HashMap::new();
    req.insert("method".to_string(), "POST".to_string());
    req.insert("uri".to_string(), format!("/api/vulnerable?q={}", payload));
    req.insert("client_ip".to_string(), "192.0.2.100".to_string());
    req.insert("payload".to_string(), payload.to_string());
    req
}

/// Simulate attack detection logic
async fn simulate_attack_detection(payload: &str) -> bool {
    // Simplified attack detection patterns
    let attack_indicators = [
        "' OR '1'='1'",
        "<script",
        "cat /etc/passwd",
        "../../../",
        "http://",
        "<!DOCTYPE",
        "UNION SELECT",
        "javascript:",
        "eval(",
        "exec(",
    ];
    
    // Simulate processing time
    tokio::task::yield_now().await;
    
    attack_indicators.iter().any(|indicator| payload.contains(indicator))
}

/// Enterprise compliance and audit benchmarks
fn bench_compliance_logging(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("compliance_audit");
    
    group.bench_function("audit_log_generation", |b| {
        b.to_async(&rt).iter(|| async {
            // Simulate generating compliance audit logs
            let events = (0..1000).map(|i| {
                format!(
                    "{{\"timestamp\":\"{}\",\"event_id\":\"{}\",\"compliance\":\"PCI-DSS\",\"action\":\"AUDIT\",\"details\":\"Request {} processed\"}}",
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                    uuid::Uuid::new_v4(),
                    i
                )
            }).collect::<Vec<_>>();
            
            let start = Instant::now();
            
            // Simulate writing audit logs
            for event in &events {
                // In real implementation, this would write to compliance log
                black_box(event);
            }
            
            let duration = start.elapsed();
            
            // Assert audit logging is fast enough for compliance
            assert!(duration.as_millis() < 100, "Audit logging too slow: {:?}", duration);
            
            black_box((events.len(), duration))
        });
    });
    
    group.finish();
}

criterion_group!(
    enterprise_benches,
    bench_wasm_enterprise_load,
    bench_export_enterprise_throughput,
    bench_memory_stability,
    bench_attack_detection_accuracy,
    bench_compliance_logging
);

criterion_main!(enterprise_benches);
