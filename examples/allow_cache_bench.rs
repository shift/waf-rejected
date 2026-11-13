//! Replay benchmark for the experimental allow-verdict cache.
//!
//! ```sh
//! cargo run --release --example allow_cache_bench \
//!   --features wasm-reactor,allow-cache
//! ```
//!
//! Environment:
//! - `WAF_BENCH_BACKEND` = `wasm` (default) or `native` (needs
//!   `--features coraza-native` and a running sidecar)
//! - `CORAZA_SOCKET` native sidecar socket (default
//!   `/tmp/coraza-native-bench.sock`)
//! - `ALLOW_CACHE_UNIQUE` unique requests per body size (default 16)
//! - `ALLOW_CACHE_REPEATS` header-order repeats per unique request (default 3)
//! - `ALLOW_CACHE_PERMS` query-parameter permutations per unique request
//!   (default 2)
//!
//! The trace is warmed once, then replayed twice and measured. Header-order
//! permutations hit (the key sorts headers), while query-parameter
//! permutations miss on the first replay pass and hit on the second because
//! query order is deliberately preserved.

use std::time::{Duration, Instant};

use bytes::Bytes;
use hyper::header::HeaderValue;
use hyper::{HeaderMap, Method};
use waf_ingress::config::{Config, CorazaBackend};
use waf_ingress::waf::{Decision, RequestContext, WafEngine};

const BODY_SIZES: [usize; 3] = [1024, 4096, 8192];

struct Trace {
    /// First request of each unique URI; used to warm the cache and reactor.
    unique: Vec<RequestContext>,
    /// Repeated traffic: header-order permutations and query permutations.
    replay: Vec<RequestContext>,
}

fn form_body(size: usize) -> Bytes {
    let mut body = Vec::with_capacity(size);
    body.extend_from_slice(b"data=");
    while body.len() < size {
        body.push(b'A');
    }
    Bytes::from(body)
}

fn headers_for(size: usize) -> Vec<(&'static str, String)> {
    vec![
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
    ]
}

fn context(uri: &str, body: &Bytes, headers: &[(&'static str, String)]) -> RequestContext {
    let mut map = HeaderMap::new();
    for (name, value) in headers {
        map.insert(
            *name,
            HeaderValue::from_str(value).expect("benchmark header value"),
        );
    }
    RequestContext::new(
        "127.0.0.1".parse().unwrap(),
        Method::POST,
        uri.parse().expect("benchmark URI"),
        map,
        Some(body.len()),
    )
    .with_body(Some(body.clone()))
}

fn trace(size: usize, unique_count: usize, repeats: usize, perms: usize) -> Trace {
    let body = form_body(size);
    let headers = headers_for(size);
    let mut reversed = headers.clone();
    reversed.reverse();

    let mut unique = Vec::with_capacity(unique_count);
    let mut replay = Vec::with_capacity(unique_count * (repeats + perms));

    for index in 0..unique_count {
        let uri = format!("/api/v1/items/{index}?id={index}&page=1&sort=asc");
        unique.push(context(&uri, &body, &headers));

        for _ in 0..repeats {
            replay.push(context(&uri, &body, &reversed));
        }
        for permutation in 0..perms {
            // Query order changes the canonical key by design.
            let permuted = if permutation % 2 == 0 {
                format!("/api/v1/items/{index}?sort=asc&page=1&id={index}")
            } else {
                format!("/api/v1/items/{index}?page=1&sort=asc&id={index}")
            };
            replay.push(context(&permuted, &body, &headers));
        }
    }

    Trace { unique, replay }
}

fn percentile(samples: &mut [Duration], fraction: f64) -> Duration {
    if samples.is_empty() {
        return Duration::ZERO;
    }
    samples.sort_unstable();
    let index = ((samples.len() - 1) as f64 * fraction).round() as usize;
    samples[index]
}

fn fmt(duration: Duration) -> String {
    let micros = duration.as_secs_f64() * 1_000_000.0;
    if micros >= 1000.0 {
        format!("{:.2} ms", micros / 1000.0)
    } else {
        format!("{micros:.1} us")
    }
}

async fn warm(engine: &WafEngine, trace: &Trace) {
    for request in &trace.unique {
        assert_eq!(
            engine.evaluate(request).await,
            Decision::Allow,
            "warm-up traffic must be benign"
        );
    }
}

async fn replay_cached(
    engine: &WafEngine,
    trace: &Trace,
    passes: usize,
) -> (Vec<Duration>, Vec<Duration>) {
    let cache = engine
        .allow_cache()
        .expect("allow-cache must be enabled for the cached engine");
    let mut hit = Vec::new();
    let mut miss = Vec::new();

    for _ in 0..passes {
        for request in &trace.replay {
            let before = cache.stats().hits;
            let started = Instant::now();
            let decision = engine.evaluate(request).await;
            let elapsed = started.elapsed();
            assert_eq!(
                decision,
                Decision::Allow,
                "benchmark traffic must be benign: {decision:?}"
            );
            if cache.stats().hits > before {
                hit.push(elapsed);
            } else {
                miss.push(elapsed);
            }
        }
    }

    (hit, miss)
}

async fn replay_uncached(engine: &WafEngine, trace: &Trace, passes: usize) -> Vec<Duration> {
    let mut samples = Vec::with_capacity(trace.replay.len() * passes);
    for _ in 0..passes {
        for request in &trace.replay {
            let started = Instant::now();
            let decision = engine.evaluate(request).await;
            samples.push(started.elapsed());
            assert_eq!(
                decision,
                Decision::Allow,
                "benchmark traffic must be benign: {decision:?}"
            );
        }
    }
    samples
}

fn engine_config(cache_enabled: bool, backend: CorazaBackend) -> Config {
    let mut config = Config::default();
    config.waf.coraza.enabled = true;
    config.waf.coraza.backend = backend;
    config.waf.coraza.pool_size = 1;
    config.waf.coraza.eval_timeout_ms = 30_000;
    if matches!(backend, CorazaBackend::Native) {
        config.waf.coraza.native_socket_path = Some(
            std::env::var("CORAZA_SOCKET")
                .unwrap_or_else(|_| "/tmp/coraza-native-bench.sock".to_string()),
        );
    }
    // Keep the benchmark focused on content inspection: rate limits would
    // eventually turn a long replay into 429s and audit logging would add
    // unrelated I/O.
    config.waf.rate_limit.per_ip_enabled = false;
    config.waf.rate_limit.global_enabled = false;
    config.waf.security_events.enabled = false;
    config.waf.admission.enabled = false;
    config.waf.allow_cache.enabled = cache_enabled;
    config.waf.allow_cache.ttl_secs = 300;
    config.waf.allow_cache.max_entries = 4096;
    config.waf.allow_cache.max_body_bytes = 16 * 1024;
    config
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

#[tokio::main]
async fn main() {
    let backend = match std::env::var("WAF_BENCH_BACKEND").as_deref() {
        Ok("native") => {
            #[cfg(feature = "coraza-native")]
            {
                CorazaBackend::Native
            }
            #[cfg(not(feature = "coraza-native"))]
            {
                eprintln!(
                    "WAF_BENCH_BACKEND=native needs --features coraza-native; \
                     falling back to wasm"
                );
                CorazaBackend::Wasm
            }
        }
        _ => CorazaBackend::Wasm,
    };
    let unique_count = env_usize("ALLOW_CACHE_UNIQUE", 16);
    let repeats = env_usize("ALLOW_CACHE_REPEATS", 3);
    let perms = env_usize("ALLOW_CACHE_PERMS", 2);
    let passes = 2;

    let cached = WafEngine::with_config(&engine_config(true, backend));
    let uncached = WafEngine::with_config(&engine_config(false, backend));
    if let Some(error) = cached.waf_init_error() {
        eprintln!("cached engine failed to initialise Coraza: {error}");
        std::process::exit(1);
    }
    if let Some(error) = uncached.waf_init_error() {
        eprintln!("uncached engine failed to initialise Coraza: {error}");
        std::process::exit(1);
    }

    println!(
        "backend={backend:?} unique={unique_count} repeats={repeats} query_perms={perms} \
         passes={passes} ttl=300s max_body=16KiB"
    );
    println!(
        "| body | hit rate | hit p50 | miss p50 | cached p50 | cached p95 | uncached p50 | uncached p95 | p50 speedup |"
    );
    println!("|---:|---:|---:|---:|---:|---:|---:|---:|---:|");

    for size in BODY_SIZES {
        let trace = trace(size, unique_count, repeats, perms);
        warm(&cached, &trace).await;
        warm(&uncached, &trace).await;

        let (mut hit, mut miss) = replay_cached(&cached, &trace, passes).await;
        let mut uncached_all = replay_uncached(&uncached, &trace, passes).await;

        let mut cached_all: Vec<Duration> = hit.iter().chain(miss.iter()).copied().collect();
        let hit_rate = if cached_all.is_empty() {
            0.0
        } else {
            hit.len() as f64 * 100.0 / cached_all.len() as f64
        };
        let cached_p50 = percentile(&mut cached_all, 0.50);
        let uncached_p50 = percentile(&mut uncached_all, 0.50);
        let speedup = if cached_p50.as_nanos() == 0 {
            0.0
        } else {
            uncached_p50.as_secs_f64() / cached_p50.as_secs_f64()
        };

        println!(
            "| {size} B | {hit_rate:.1}% | {} | {} | {} | {} | {} | {} | {speedup:.1}x |",
            fmt(percentile(&mut hit, 0.50)),
            fmt(percentile(&mut miss, 0.50)),
            fmt(cached_p50),
            fmt(percentile(&mut cached_all, 0.95)),
            fmt(uncached_p50),
            fmt(percentile(&mut uncached_all, 0.95)),
        );

        if let Some(cache) = cached.allow_cache() {
            let stats = cache.stats();
            eprintln!(
                "  cache: hits={} misses={} evictions={} entries={} generation={}",
                stats.hits, stats.misses, stats.evictions, stats.entries, stats.generation
            );
        }
    }
}
