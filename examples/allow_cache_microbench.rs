//! In-process, pinned micro-benchmark for the experimental allow-verdict cache.
//!
//! ```sh
//! taskset -c 3 cargo run --release --example allow_cache_microbench \
//!   --features wasm-reactor,allow-cache -- components
//! taskset -c 3 cargo run --release --example allow_cache_microbench \
//!   --features wasm-reactor,allow-cache -- load
//! ```
//!
//! `components` reports ns/op for each stage of a cache hit: canonical
//! fingerprint, body digest, thread-local L1 probe, shared shard probe, insert,
//! and the full `WafEngine::evaluate` hit path. `load` reports hit throughput at
//! c=1 and c=64.
//!
//! Pin the process (`taskset`) and keep other work off the host: the sub-µs
//! numbers are sensitive to SMT siblings and frequency scaling.

use std::hint::black_box;
use std::sync::{Arc, Barrier};
use std::time::Instant;

use bytes::Bytes;
use hyper::header::HeaderValue;
use hyper::{HeaderMap, Method};
use waf_ingress::config::{AllowCacheConfig, Config};
use waf_ingress::waf::allow_cache::{AllowCache, Fingerprint, Key, KeyBuild};
use waf_ingress::waf::{Decision, RequestContext, WafEngine};

const BODY_SIZES: [usize; 3] = [1024, 4096, 8192];

fn form_body(size: usize) -> Bytes {
    let mut body = Vec::with_capacity(size);
    body.extend_from_slice(b"data=");
    while body.len() < size {
        body.push(b'A');
    }
    Bytes::from(body)
}

fn headers_for(size: usize) -> HeaderMap {
    let mut map = HeaderMap::new();
    let pairs = [
        ("host", "benchmark.test".to_string()),
        (
            "content-type",
            "application/x-www-form-urlencoded".to_string(),
        ),
        ("content-length", size.to_string()),
        ("user-agent", "allow-cache-bench/1.0".to_string()),
        ("accept", "*/*".to_string()),
        ("accept-language", "en-US,en;q=0.9".to_string()),
        ("x-request-id", "replay".to_string()),
    ];
    for (name, value) in pairs {
        map.insert(name, HeaderValue::from_str(&value).unwrap());
    }
    map
}

fn context(uri: &str, body: &Bytes, headers: &HeaderMap) -> RequestContext {
    RequestContext::new(
        "127.0.0.1".parse().unwrap(),
        Method::POST,
        uri.parse().unwrap(),
        headers.clone(),
        Some(body.len()),
    )
    .with_body(Some(body.clone()))
}

fn cache(max_entries: usize) -> AllowCache {
    let config = AllowCacheConfig {
        enabled: true,
        ttl_secs: 300,
        max_entries,
        max_body_bytes: 64 * 1024,
        routes: Vec::new(),
    };
    AllowCache::new(&config, 1, Key::random(), None)
}

fn fingerprint(cache: &AllowCache, request: &RequestContext) -> Fingerprint {
    match cache.fingerprint(request) {
        KeyBuild::Fingerprint(fingerprint) => fingerprint,
        other => panic!("expected a fingerprint, got {other:?}"),
    }
}

fn percentile(sorted: &[f64], fraction: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let index = ((sorted.len() - 1) as f64 * fraction).round() as usize;
    sorted[index]
}

/// Time `rounds` batches of `batch` operations and report ns/op percentiles.
fn bench(mut op: impl FnMut(), batch: usize, rounds: usize) -> (f64, f64, f64) {
    for _ in 0..batch.min(10_000) {
        op();
    }
    let mut samples = Vec::with_capacity(rounds);
    for _ in 0..rounds {
        let started = Instant::now();
        for _ in 0..batch {
            op();
        }
        samples.push(started.elapsed().as_nanos() as f64 / batch as f64);
    }
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
    (
        percentile(&samples, 0.50),
        percentile(&samples, 0.95),
        percentile(&samples, 0.99),
    )
}

/// Async variant: one batch per measurement, no per-iteration timer.
fn bench_async(
    runtime: &tokio::runtime::Runtime,
    engine: &WafEngine,
    request: &RequestContext,
    batch: usize,
    rounds: usize,
) -> (f64, f64, f64) {
    let mut samples = Vec::with_capacity(rounds);
    for _ in 0..2 {
        runtime.block_on(async {
            for _ in 0..batch {
                black_box(engine.evaluate(request).await);
            }
        });
    }
    for _ in 0..rounds {
        let elapsed = runtime.block_on(async {
            let started = Instant::now();
            for _ in 0..batch {
                black_box(engine.evaluate(request).await);
            }
            started.elapsed()
        });
        samples.push(elapsed.as_nanos() as f64 / batch as f64);
    }
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
    (
        percentile(&samples, 0.50),
        percentile(&samples, 0.95),
        percentile(&samples, 0.99),
    )
}

fn bench_async_fast(
    runtime: &tokio::runtime::Runtime,
    engine: &WafEngine,
    request: &RequestContext,
    batch: usize,
    rounds: usize,
) -> (f64, f64, f64) {
    let mut samples = Vec::with_capacity(rounds);
    for _ in 0..2 {
        runtime.block_on(async {
            for _ in 0..batch {
                black_box(engine.fast_evaluate(request).await);
            }
        });
    }
    for _ in 0..rounds {
        let elapsed = runtime.block_on(async {
            let started = Instant::now();
            for _ in 0..batch {
                black_box(engine.fast_evaluate(request).await);
            }
            started.elapsed()
        });
        samples.push(elapsed.as_nanos() as f64 / batch as f64);
    }
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
    (
        percentile(&samples, 0.50),
        percentile(&samples, 0.95),
        percentile(&samples, 0.99),
    )
}

fn engine_config() -> Config {
    let mut config = Config::default();
    config.waf.coraza.enabled = false;
    config.waf.content_inspection.enabled = true;
    config.waf.rate_limit.per_ip_enabled = false;
    config.waf.rate_limit.global_enabled = false;
    config.waf.security_events.enabled = false;
    config.waf.admission.enabled = false;
    config.waf.allow_cache.enabled = true;
    config.waf.allow_cache.ttl_secs = 300;
    config.waf.allow_cache.max_entries = 4096;
    config.waf.allow_cache.max_body_bytes = 64 * 1024;
    config
}

fn fmt(ns: f64) -> String {
    if ns >= 1000.0 {
        format!("{:.2} us", ns / 1000.0)
    } else {
        format!("{ns:.0} ns")
    }
}

fn row(label: &str, stats: (f64, f64, f64)) {
    println!(
        "| {label} | {} | {} | {} |",
        fmt(stats.0),
        fmt(stats.1),
        fmt(stats.2)
    );
}

fn components() {
    println!(
        "pinned={} cores={}",
        std::env::var("ALLOW_CACHE_CPU").unwrap_or_else(|_| "unset".to_string()),
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(0)
    );
    println!();
    println!("| component | p50 | p95 | p99 |");
    println!("|---|---:|---:|---:|");

    for size in BODY_SIZES {
        let body = form_body(size);
        let headers = headers_for(size);
        let request = context("/api/v1/items/1?id=1&page=1&sort=asc", &body, &headers);
        let local = cache(4096);
        let key = fingerprint(&local, &request);

        row(
            &format!("fingerprint {size} B"),
            bench(
                || {
                    black_box(local.fingerprint(black_box(&request)));
                },
                2000,
                200,
            ),
        );
        let no_headers = context(
            "/api/v1/items/1?id=1&page=1&sort=asc",
            &body,
            &HeaderMap::new(),
        );
        row(
            &format!("fingerprint no headers {size} B"),
            bench(
                || {
                    black_box(local.fingerprint(black_box(&no_headers)));
                },
                2000,
                200,
            ),
        );
        row(
            &format!("header iteration {size} B"),
            bench(
                || {
                    let mut count = 0usize;
                    for (name, value) in request.headers.iter() {
                        count += name.as_str().len() + value.as_bytes().len();
                    }
                    black_box(count);
                },
                2000,
                200,
            ),
        );
        row(
            &format!("body digest {size} B"),
            bench(
                || {
                    black_box(local.body_digest_for_bench(black_box(&body)));
                },
                2000,
                200,
            ),
        );

        local.insert(key, &body);
        assert!(local.lookup(key, &body));
        row(
            &format!("lookup L1 hit {size} B"),
            bench(
                || {
                    black_box(local.lookup(black_box(key), black_box(&body)));
                },
                2000,
                200,
            ),
        );

        // L1-busting lookup: 4096 distinct fingerprints, all resident.
        let shared = cache(8192);
        let mut probes = Vec::with_capacity(4096);
        for index in 0..4096 {
            let uri = format!("/api/v1/items/{index}?id={index}");
            let request = context(&uri, &body, &headers);
            let key = fingerprint(&shared, &request);
            shared.insert(key, &body);
            probes.push(key);
        }
        let mut cursor = 0usize;
        row(
            &format!("lookup shared hit {size} B"),
            bench(
                || {
                    cursor = (cursor + 1) & 4095;
                    black_box(shared.lookup(probes[cursor], black_box(&body)));
                },
                2000,
                200,
            ),
        );

        let mut insert_cursor = 0usize;
        row(
            &format!("insert (miss path) {size} B"),
            bench(
                || {
                    insert_cursor = (insert_cursor + 1) & 4095;
                    shared.insert(probes[insert_cursor], black_box(&body));
                },
                1000,
                100,
            ),
        );

        // Fingerprint miss: no bucket, so no body digest is computed.
        let absent = fingerprint(&local, &context("/api/v1/absent/1", &body, &headers));
        row(
            &format!("lookup fingerprint miss {size} B"),
            bench(
                || {
                    black_box(local.lookup(black_box(absent), black_box(&body)));
                },
                2000,
                200,
            ),
        );
    }

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    for size in BODY_SIZES {
        let body = form_body(size);
        let headers = headers_for(size);
        let request = context("/api/v1/items/1?id=1&page=1&sort=asc", &body, &headers);
        let engine = WafEngine::with_config(&engine_config());
        assert!(engine.allow_cache().is_some());
        assert_eq!(
            runtime.block_on(engine.evaluate(&request)),
            Decision::Allow,
            "benchmark traffic must be benign"
        );
        assert_eq!(
            runtime.block_on(engine.evaluate(&request)),
            Decision::Allow,
            "benchmark traffic must be benign"
        );
        assert!(
            engine.allow_cache().unwrap().stats().hits >= 1,
            "the second evaluate must be a hit"
        );
        row(
            &format!("engine.evaluate hit {size} B"),
            bench_async(&runtime, &engine, &request, 500, 200),
        );
        row(
            &format!("engine.fast_evaluate hit {size} B"),
            bench_async_fast(&runtime, &engine, &request, 500, 200),
        );
        let mut lean = engine_config();
        lean.waf.grpc.enabled = false;
        lean.waf.graphql.enabled = false;
        let lean_engine = WafEngine::with_config(&lean);
        assert_eq!(
            runtime.block_on(lean_engine.evaluate(&request)),
            Decision::Allow
        );
        assert_eq!(
            runtime.block_on(lean_engine.evaluate(&request)),
            Decision::Allow
        );
        row(
            &format!("engine.evaluate hit, no proto {size} B"),
            bench_async(&runtime, &lean_engine, &request, 500, 200),
        );
    }
}

fn load() {
    println!("c=1 and c=64 hit throughput");
    println!();
    println!("| stage | threads | ops/s | ns/op |");
    println!("|---|---:|---:|---:|");
    for size in BODY_SIZES {
        let body = form_body(size);
        let headers = headers_for(size);
        let request = context("/api/v1/items/1?id=1&page=1&sort=asc", &body, &headers);
        let cache = Arc::new(cache(8192));
        let key = fingerprint(&cache, &request);
        cache.insert(key, &body);
        assert!(cache.lookup(key, &body));

        for threads in [1usize, 64] {
            let per_thread = 200_000 / threads;
            let barrier = Arc::new(Barrier::new(threads));
            let started = Instant::now();
            let handles: Vec<_> = (0..threads)
                .map(|_| {
                    let cache = Arc::clone(&cache);
                    let barrier = Arc::clone(&barrier);
                    let body = body.clone();
                    std::thread::spawn(move || {
                        barrier.wait();
                        for _ in 0..per_thread {
                            black_box(cache.lookup(black_box(key), black_box(&body)));
                        }
                    })
                })
                .collect();
            for handle in handles {
                handle.join().unwrap();
            }
            let elapsed = started.elapsed();
            let ops = (threads * per_thread) as f64 / elapsed.as_secs_f64();
            println!(
                "| lookup {size} B | {threads} | {:.0} | {:.0} |",
                ops,
                elapsed.as_nanos() as f64 / (threads * per_thread) as f64
            );
        }

        let engine = Arc::new(WafEngine::with_config(&engine_config()));
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(engine.evaluate(&request));
        let request = Arc::new(request);
        for threads in [1usize, 64] {
            let per_thread = 20_000 / threads;
            let barrier = Arc::new(Barrier::new(threads));
            let started = Instant::now();
            let handles: Vec<_> = (0..threads)
                .map(|_| {
                    let engine = Arc::clone(&engine);
                    let request = Arc::clone(&request);
                    let barrier = Arc::clone(&barrier);
                    std::thread::spawn(move || {
                        let runtime = tokio::runtime::Builder::new_current_thread()
                            .enable_all()
                            .build()
                            .unwrap();
                        barrier.wait();
                        runtime.block_on(async {
                            for _ in 0..per_thread {
                                black_box(engine.evaluate(&request).await);
                            }
                        });
                    })
                })
                .collect();
            for handle in handles {
                handle.join().unwrap();
            }
            let elapsed = started.elapsed();
            let ops = (threads * per_thread) as f64 / elapsed.as_secs_f64();
            println!(
                "| engine hit {size} B | {threads} | {:.0} | {:.0} |",
                ops,
                elapsed.as_nanos() as f64 / (threads * per_thread) as f64
            );
        }
    }
}

fn main() {
    let mode = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "components".to_string());
    match mode.as_str() {
        "components" => components(),
        "load" => load(),
        other => {
            eprintln!("unknown mode {other:?}; use `components` or `load`");
            std::process::exit(2);
        }
    }
}
