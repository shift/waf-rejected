use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use std::time::Duration;
use tokio::runtime::Runtime;
use waf_ingress::wasm::context::WasmRequestContext;
use waf_ingress::wasm::{WasmEngine, WasmEngineConfig};

/// Benchmark WASM ModSecurity engine performance
fn bench_wasm_engine_performance(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("wasm_modsecurity");
    group.measurement_time(Duration::from_secs(15));

    // Test with different pool sizes to show pooling benefit
    for pool_size in [1, 5, 10, 20].iter() {
        let config = WasmEngineConfig {
            module_path: "rules/coraza.wasm".to_string(),
            memory_limit_mb: 16,
            timeout_ms: 100,
            debug: false,
            instance_pool_size: *pool_size,
            hot_reload: false,
            enable_memory_mapping: false,
            enable_shared_memory: false,
        };

        group.bench_with_input(
            BenchmarkId::new("instance_pooling", pool_size),
            pool_size,
            |b, _pool_size| {
                b.to_async(&rt).iter(|| async {
                    // Create engine with pooling
                    let engine = WasmEngine::new(config.clone()).unwrap();

                    // Create test request context
                    let context = WasmRequestContext {
                        method: "GET".to_string(),
                        uri: "/test?param=value".to_string(),
                        headers: std::collections::HashMap::new(),
                        body: None,
                        client_ip: "192.168.1.100".to_string(),
                        http_version: "HTTP/1.1".to_string(),
                        geo_context: None,
                        security_metadata: Default::default(),
                    };

                    // Process request through WASM engine
                    let decision = engine.process_request(context).await;
                    black_box(decision);
                })
            },
        );
    }

    // Test different attack patterns for performance
    let attack_patterns = vec![
        ("clean_request", "/normal/path".to_string()),
        ("sql_injection", "/test?id=' OR '1'='1".to_string()),
        (
            "xss_attack",
            "/search?q=<script>alert('xss')</script>".to_string(),
        ),
        (
            "path_traversal",
            "/file?path=../../../etc/passwd".to_string(),
        ),
        (
            "large_request",
            format!("/data?payload={}", "A".repeat(10000)),
        ),
    ];

    for (name, uri) in attack_patterns {
        group.bench_function(name, |b| {
            b.to_async(&rt).iter(|| async {
                let config = WasmEngineConfig {
                    instance_pool_size: 10,
                    ..Default::default()
                };

                let engine = WasmEngine::new(config).unwrap();

                let context = WasmRequestContext {
                    method: "GET".to_string(),
                    uri: uri.to_string(),
                    headers: std::collections::HashMap::new(),
                    body: None,
                    client_ip: "192.168.1.100".to_string(),
                    http_version: "HTTP/1.1".to_string(),
                    geo_context: None,
                    security_metadata: Default::default(),
                };

                let decision = engine.process_request(context).await;
                black_box(decision);
            })
        });
    }

    group.finish();
}

/// Test concurrent processing performance
fn bench_wasm_concurrent_processing(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("wasm_concurrent");
    group.measurement_time(Duration::from_secs(20));

    // Test with different concurrency levels
    for concurrency in [1, 2, 4, 8, 16].iter() {
        group.bench_with_input(
            BenchmarkId::new("concurrent_requests", concurrency),
            concurrency,
            |b, &concurrency| {
                b.to_async(&rt).iter(|| async {
                    let config = WasmEngineConfig {
                        instance_pool_size: concurrency * 2, // Pool size larger than concurrency
                        ..Default::default()
                    };

                    let engine = std::sync::Arc::new(WasmEngine::new(config).unwrap());

                    // Create concurrent tasks
                    let mut handles = Vec::new();
                    for i in 0..concurrency {
                        let engine_clone = engine.clone();
                        let handle = tokio::spawn(async move {
                            let context = WasmRequestContext {
                                method: "GET".to_string(),
                                uri: format!("/test{}", i),
                                headers: std::collections::HashMap::new(),
                                body: None,
                                client_ip: "192.168.1.100".to_string(),
                                http_version: "HTTP/1.1".to_string(),
                                geo_context: None,
                                security_metadata: Default::default(),
                            };

                            engine_clone.process_request(context).await
                        });
                        handles.push(handle);
                    }

                    // Wait for all to complete
                    for handle in handles {
                        let decision = handle.await.unwrap();
                        black_box(decision);
                    }
                })
            },
        );
    }

    group.finish();
}

/// Test pool efficiency metrics
fn bench_pool_efficiency(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("pool_efficiency_metrics", |b| {
        b.to_async(&rt).iter(|| async {
            let config = WasmEngineConfig {
                instance_pool_size: 5,
                ..Default::default()
            };

            let engine = WasmEngine::new(config).unwrap();

            // Process multiple requests to test pooling
            for i in 0..20 {
                let context = WasmRequestContext {
                    method: "GET".to_string(),
                    uri: format!("/test{}", i),
                    headers: std::collections::HashMap::new(),
                    body: None,
                    client_ip: "192.168.1.100".to_string(),
                    http_version: "HTTP/1.1".to_string(),
                    geo_context: None,
                    security_metadata: Default::default(),
                };

                let decision = engine.process_request(context).await;
                black_box(decision);
            }

            // Check pool efficiency
            let stats = engine.get_stats();
            let pool_stats = engine.get_pool_stats();

            black_box((stats, pool_stats));
        })
    });
}

criterion_group!(
    benches,
    bench_wasm_engine_performance,
    bench_wasm_concurrent_processing,
    bench_pool_efficiency
);
criterion_main!(benches);
