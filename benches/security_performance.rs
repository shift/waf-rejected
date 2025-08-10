use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use std::sync::Arc;
use tokio::runtime::Runtime;
use std::time::Duration;
use chrono::Utc;

/// Mock security event for benchmarking
#[derive(Debug, Clone)]
pub struct SecurityEvent {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub threat_level: String,
    pub attack_type: String,
    pub source_ip: String,
    pub target_path: String,
    pub rule_id: String,
    pub details: String,
    pub blocked: bool,
}

/// Mock security event logger for benchmarking
pub struct SecurityEventLogger {
    events_processed: std::sync::atomic::AtomicU64,
}

impl SecurityEventLogger {
    pub fn new() -> Self {
        Self {
            events_processed: std::sync::atomic::AtomicU64::new(0),
        }
    }
    
    pub async fn log_event(&self, event: SecurityEvent) -> Result<(), String> {
        // Simulate event processing time
        tokio::task::yield_now().await;
        
        // Simulate serialization and logging
        let _serialized = format!("{:?}", event);
        
        self.events_processed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }
}

/// Mock content inspection rule for benchmarking
pub struct ContentInspectionRule {
    patterns: Vec<regex::Regex>,
}

impl ContentInspectionRule {
    pub fn new() -> Self {
        // Pre-compile common attack patterns
        let patterns = vec![
            regex::Regex::new(r"(?i)(?:union|select|insert|update|delete|drop|create|alter)\s").unwrap(),
            regex::Regex::new(r"(?i)<script[^>]*>.*?</script>").unwrap(),
            regex::Regex::new(r"(?i)javascript:").unwrap(),
            regex::Regex::new(r"(?i)(?:\.\./|\.\.\\){2,}").unwrap(),
            regex::Regex::new(r"(?i)(?:eval|system|exec|shell_exec)\s*\(").unwrap(),
        ];
        
        Self { patterns }
    }
    
    pub async fn inspect(&self, content: &str) -> bool {
        tokio::task::yield_now().await;
        
        // Check all patterns
        for pattern in &self.patterns {
            if pattern.is_match(content) {
                return true;
            }
        }
        false
    }
}

/// Mock geographic IP blocking for benchmarking
pub struct GeoBlockingRule {
    blocked_countries: std::collections::HashSet<String>,
}

impl GeoBlockingRule {
    pub fn new() -> Self {
        let mut blocked_countries = std::collections::HashSet::new();
        blocked_countries.insert("CN".to_string());
        blocked_countries.insert("RU".to_string());
        blocked_countries.insert("IR".to_string());
        
        Self { blocked_countries }
    }
    
    pub async fn check_ip(&self, ip: &str) -> bool {
        tokio::task::yield_now().await;
        
        // Mock geolocation lookup (in reality this would use MaxMind database)
        let country_code = match ip {
            ip if ip.starts_with("114.") => "CN", // Chinese IP range
            ip if ip.starts_with("77.") => "RU",  // Russian IP range  
            ip if ip.starts_with("5.") => "IR",   // Iranian IP range
            _ => "US", // Default to US
        };
        
        self.blocked_countries.contains(country_code)
    }
}

/// Performance benchmark for Security Event Logging System
fn bench_security_event_logging(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let logger = Arc::new(SecurityEventLogger::new());
    
    let mut group = c.benchmark_group("security_event_logging");
    group.measurement_time(Duration::from_secs(10));
    
    // Test event generation latency
    group.bench_function("event_generation", |b| {
        b.iter(|| {
            let event = SecurityEvent {
                timestamp: Utc::now(),
                threat_level: black_box("Medium".to_string()),
                attack_type: black_box("SQL_INJECTION".to_string()),
                source_ip: black_box("192.168.1.100".to_string()),
                target_path: black_box("/api/users".to_string()),
                rule_id: black_box("SQLI_001".to_string()),
                details: black_box("Detected SQL injection attempt in query parameter".to_string()),
                blocked: black_box(true),
            };
            black_box(event);
        })
    });
    
    // Test event logging throughput
    group.bench_function("event_logging", |b| {
        b.to_async(&rt).iter(|| async {
            let event = SecurityEvent {
                timestamp: Utc::now(),
                threat_level: "High".to_string(),
                attack_type: "XSS".to_string(),
                source_ip: "10.0.0.1".to_string(),
                target_path: "/search".to_string(),
                rule_id: "XSS_001".to_string(),
                details: "Cross-site scripting detected in search parameter".to_string(),
                blocked: true,
            };
            logger.log_event(black_box(event)).await.unwrap();
        })
    });
    
    // Test high-throughput logging (batch operations)
    for batch_size in [100, 1000].iter() {
        group.bench_with_input(
            BenchmarkId::new("batch_logging", batch_size),
            batch_size,
            |b, &size| {
                b.to_async(&rt).iter(|| async {
                    for i in 0..size {
                        let event = SecurityEvent {
                            timestamp: Utc::now(),
                            threat_level: "Low".to_string(),
                            attack_type: format!("TEST_ATTACK_{}", i),
                            source_ip: format!("192.168.1.{}", i % 255),
                            target_path: format!("/test/{}", i),
                            rule_id: format!("TEST_{:03}", i),
                            details: format!("Test event {}", i),
                            blocked: i % 2 == 0,
                        };
                        logger.log_event(black_box(event)).await.unwrap();
                    }
                })
            },
        );
    }
    
    group.finish();
}

/// Performance benchmark for Content Inspection Engine
fn bench_content_inspection(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    
    let mut group = c.benchmark_group("content_inspection");
    group.measurement_time(Duration::from_secs(10));
    
    // Create test payloads of different sizes
    let small_payload = "SELECT * FROM users WHERE id = 1";
    let medium_payload = format!("SELECT * FROM users WHERE name = '{}' AND active = 1", "x".repeat(1000));
    let large_payload = format!("SELECT * FROM users WHERE description = '{}' ORDER BY created_at", "x".repeat(100000));
    
    // Test SQL injection detection on different payload sizes
    for (name, payload) in [
        ("small", small_payload.as_ref()),
        ("medium", medium_payload.as_ref()), 
        ("large", large_payload.as_ref()),
    ].iter() {
        group.bench_with_input(
            BenchmarkId::new("sql_injection_detection", name),
            payload,
            |b, &content| {
                b.to_async(&rt).iter(|| async {
                    let rule = ContentInspectionRule::new();
                    let result = rule.inspect(content).await;
                    black_box(result);
                })
            },
        );
    }
    
    // Test XSS detection performance
    let xss_payloads = vec![
        "<script>alert('xss')</script>",
        "javascript:alert('xss')",
        "<img src=x onerror=alert('xss')>",
        "<svg onload=alert('xss')>",
    ];
    
    group.bench_function("xss_detection_multiple", |b| {
        b.to_async(&rt).iter(|| async {
            let rule = ContentInspectionRule::new();
            
            for payload in &xss_payloads {
                let result = rule.inspect(payload).await;
                black_box(result);
            }
        })
    });
    
    // Test pattern compilation performance
    group.bench_function("pattern_compilation", |b| {
        b.iter(|| {
            let rule = ContentInspectionRule::new();
            black_box(rule);
        })
    });
    
    group.finish();
}

/// Performance benchmark for Geographic IP Blocking
fn bench_geoip_blocking(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    
    let mut group = c.benchmark_group("geoip_blocking");
    group.measurement_time(Duration::from_secs(10));
    
    // Test IP lookup performance
    let test_ips = vec![
        "8.8.8.8",           // Google DNS (US)
        "1.1.1.1",           // Cloudflare (US)
        "77.88.8.8",         // Yandex (RU)
        "114.114.114.114",   // 114DNS (CN)
    ];
    
    group.bench_function("ip_lookup_single", |b| {
        b.to_async(&rt).iter(|| async {
            let rule = GeoBlockingRule::new();
            
            for ip in &test_ips {
                let result = rule.check_ip(ip).await;
                black_box(result);
            }
        })
    });
    
    // Test bulk IP lookup performance
    for batch_size in [100, 1000].iter() {
        group.bench_with_input(
            BenchmarkId::new("ip_lookup_batch", batch_size),
            batch_size,
            |b, &size| {
                b.to_async(&rt).iter(|| async {
                    let rule = GeoBlockingRule::new();
                    
                    for i in 0..size {
                        // Generate diverse IP addresses for testing
                        let ip = format!("{}.{}.{}.{}", 
                            (i % 223) + 1,
                            (i % 255),
                            (i % 255),
                            (i % 254) + 1
                        );
                        
                        let result = rule.check_ip(&ip).await;
                        black_box(result);
                    }
                })
            },
        );
    }
    
    group.finish();
}

/// Integrated performance test simulating realistic WAF processing
fn bench_integrated_waf_processing(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    
    let mut group = c.benchmark_group("integrated_waf");
    group.measurement_time(Duration::from_secs(15));
    
    // Test complete WAF pipeline with all security modules
    group.bench_function("full_pipeline", |b| {
        b.to_async(&rt).iter(|| async {
            // Initialize all components
            let event_logger = Arc::new(SecurityEventLogger::new());
            let content_rule = ContentInspectionRule::new();
            let geo_rule = GeoBlockingRule::new();
            
            // Simulate malicious request
            let source_ip = "114.114.114.114"; // Chinese IP
            let request_content = "q=<script>alert('xss')</script> AND 1=1";
            
            // Run all security checks
            let geo_blocked = geo_rule.check_ip(source_ip).await;
            let content_threat = content_rule.inspect(request_content).await;
            
            // Log security events
            if geo_blocked {
                let event = SecurityEvent {
                    timestamp: Utc::now(),
                    threat_level: "High".to_string(),
                    attack_type: "GEO_BLOCK".to_string(),
                    source_ip: source_ip.to_string(),
                    target_path: "/api/search".to_string(),
                    rule_id: "GEO_001".to_string(),
                    details: "Request from blocked country".to_string(),
                    blocked: true,
                };
                event_logger.log_event(event).await.unwrap();
            }
            
            if content_threat {
                let event = SecurityEvent {
                    timestamp: Utc::now(),
                    threat_level: "Critical".to_string(),
                    attack_type: "XSS".to_string(),
                    source_ip: source_ip.to_string(),
                    target_path: "/api/search".to_string(),
                    rule_id: "XSS_001".to_string(),
                    details: "Cross-site scripting attempt detected".to_string(),
                    blocked: true,
                };
                event_logger.log_event(event).await.unwrap();
            }
            
            black_box((geo_blocked, content_threat));
        })
    });
    
    group.finish();
}

criterion_group!(
    benches,
    bench_security_event_logging,
    bench_content_inspection,
    bench_geoip_blocking,
    bench_integrated_waf_processing
);

criterion_main!(benches);
