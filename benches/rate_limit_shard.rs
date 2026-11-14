//! Rate-limiter contention and cardinality benchmark.
//!
//! Run both implementations in separate processes so RSS deltas are clean:
//!
//! ```text
//! cargo bench --bench rate_limit_shard -- baseline
//! cargo bench --bench rate_limit_shard -- sharded
//! cargo bench --bench rate_limit_shard -- baseline-concurrent
//! cargo bench --bench rate_limit_shard -- sharded-concurrent
//! ```
//!
//! `baseline` reproduces the pre-sharding design (one global `RwLock` over a
//! `HashMap`). `sharded` uses the production `RateLimiter` with 64 shards and
//! a 100 000-IP hard cap. The `*-concurrent` modes run eight threads to show
//! the contention behaviour that sharding targets.

use std::collections::HashMap;
use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::{Duration, Instant};

use hyper::{HeaderMap, Method, Uri};
use waf_ingress::waf::fast_allow::FastAllowContext;
use waf_ingress::waf::rate_limit::{CapacityPolicy, RateLimiter, TokenBucket};
use waf_ingress::waf::WafRule;

const UNIQUE_IPS: usize = 100_000;
const OPS: usize = 1_000_000;

struct Baseline {
    buckets: RwLock<HashMap<IpAddr, TokenBucket>>,
}

impl Baseline {
    fn new() -> Self {
        Self {
            buckets: RwLock::new(HashMap::new()),
        }
    }

    fn check(&self, ip: IpAddr) {
        let mut buckets = self.buckets.write().unwrap();
        let bucket = buckets
            .entry(ip)
            .or_insert_with(|| TokenBucket::new(u32::MAX, 1));
        black_box(bucket.try_consume(1));
    }
}

fn rss_kib() -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    status
        .lines()
        .find_map(|line| {
            line.strip_prefix("VmRSS:")
                .and_then(|rest| rest.split_whitespace().next())
                .and_then(|value| value.parse().ok())
        })
        .unwrap_or(0)
}

fn percentile(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let index = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[index]
}

fn report(label: &str, mut samples: Vec<u64>, elapsed: Duration) {
    samples.sort_unstable();
    let throughput = samples.len() as f64 / elapsed.as_secs_f64();
    println!(
        "{label}: p50={} ns p99={} ns throughput={:.0} ops/s",
        percentile(&samples, 0.50),
        percentile(&samples, 0.99),
        throughput
    );
}

fn run_baseline(ips: &[IpAddr]) {
    let before = rss_kib();
    let limiter = Baseline::new();
    let mut samples = Vec::with_capacity(OPS);
    let start = Instant::now();
    for index in 0..OPS {
        let ip = ips[index % ips.len()];
        let op = Instant::now();
        limiter.check(ip);
        samples.push(op.elapsed().as_nanos() as u64);
    }
    let elapsed = start.elapsed();
    let after = rss_kib();
    report("baseline high-cardinality", samples, elapsed);
    println!(
        "baseline memory at cap: {} KiB (delta {} KiB, {} tracked)",
        after,
        after.saturating_sub(before),
        limiter.buckets.read().unwrap().len()
    );

    let hot = ips[0];
    let mut samples = Vec::with_capacity(OPS);
    let start = Instant::now();
    for _ in 0..OPS {
        let op = Instant::now();
        limiter.check(hot);
        samples.push(op.elapsed().as_nanos() as u64);
    }
    let elapsed = start.elapsed();
    report("baseline hot-IP", samples, elapsed);
}

fn run_sharded(ips: &[IpAddr]) {
    let before = rss_kib();
    let limiter = RateLimiter::new("bench", u32::MAX, 1, Duration::from_secs(60))
        .with_limits(UNIQUE_IPS, CapacityPolicy::FailClosed);
    let method = Method::GET;
    let uri = Uri::from_static("/");
    let headers = HeaderMap::new();

    let mut samples = Vec::with_capacity(OPS);
    let start = Instant::now();
    for index in 0..OPS {
        let ip = ips[index % ips.len()];
        let ctx = FastAllowContext {
            client_ip: ip,
            method: &method,
            uri: &uri,
            headers: &headers,
            body_size: None,
        };
        let op = Instant::now();
        black_box(limiter.fast_allow_gate(&ctx));
        samples.push(op.elapsed().as_nanos() as u64);
    }
    let elapsed = start.elapsed();
    let after = rss_kib();
    report("sharded high-cardinality", samples, elapsed);
    println!(
        "sharded memory at cap: {} KiB (delta {} KiB, {} tracked)",
        after,
        after.saturating_sub(before),
        UNIQUE_IPS
    );

    let hot = ips[0];
    let mut samples = Vec::with_capacity(OPS);
    let start = Instant::now();
    for _ in 0..OPS {
        let ctx = FastAllowContext {
            client_ip: hot,
            method: &method,
            uri: &uri,
            headers: &headers,
            body_size: None,
        };
        let op = Instant::now();
        black_box(limiter.fast_allow_gate(&ctx));
        samples.push(op.elapsed().as_nanos() as u64);
    }
    let elapsed = start.elapsed();
    report("sharded hot-IP", samples, elapsed);
}

const THREADS: usize = 8;
const OPS_PER_THREAD: usize = 200_000;

fn run_baseline_concurrent(ips: &[IpAddr], hot: bool) {
    let before = rss_kib();
    let limiter = Arc::new(Baseline::new());
    let start = Instant::now();
    let mut handles = Vec::with_capacity(THREADS);
    for thread_id in 0..THREADS {
        let limiter = Arc::clone(&limiter);
        let ips = ips.to_vec();
        handles.push(thread::spawn(move || {
            let mut samples = Vec::with_capacity(OPS_PER_THREAD);
            for index in 0..OPS_PER_THREAD {
                let ip = if hot {
                    ips[0]
                } else {
                    ips[(thread_id * OPS_PER_THREAD + index) % ips.len()]
                };
                let op = Instant::now();
                limiter.check(ip);
                samples.push(op.elapsed().as_nanos() as u64);
            }
            samples
        }));
    }
    let mut samples = Vec::with_capacity(THREADS * OPS_PER_THREAD);
    for handle in handles {
        samples.extend(handle.join().unwrap());
    }
    let elapsed = start.elapsed();
    let after = rss_kib();
    let label = if hot {
        "baseline concurrent hot-IP"
    } else {
        "baseline concurrent high-cardinality"
    };
    report(label, samples, elapsed);
    println!(
        "baseline concurrent memory at cap: {} KiB (delta {} KiB, {} tracked)",
        after,
        after.saturating_sub(before),
        limiter.buckets.read().unwrap().len()
    );
}

fn run_sharded_concurrent(ips: &[IpAddr], hot: bool) {
    let before = rss_kib();
    let limiter = Arc::new(
        RateLimiter::new("bench", u32::MAX, 1, Duration::from_secs(60))
            .with_limits(UNIQUE_IPS, CapacityPolicy::FailClosed),
    );
    let method = Method::GET;
    let uri = Uri::from_static("/");
    let headers = HeaderMap::new();
    let start = Instant::now();
    let mut handles = Vec::with_capacity(THREADS);
    for thread_id in 0..THREADS {
        let limiter = Arc::clone(&limiter);
        let ips = ips.to_vec();
        let method = method.clone();
        let uri = uri.clone();
        let headers = headers.clone();
        handles.push(thread::spawn(move || {
            let mut samples = Vec::with_capacity(OPS_PER_THREAD);
            for index in 0..OPS_PER_THREAD {
                let ip = if hot {
                    ips[0]
                } else {
                    ips[(thread_id * OPS_PER_THREAD + index) % ips.len()]
                };
                let ctx = FastAllowContext {
                    client_ip: ip,
                    method: &method,
                    uri: &uri,
                    headers: &headers,
                    body_size: None,
                };
                let op = Instant::now();
                black_box(limiter.fast_allow_gate(&ctx));
                samples.push(op.elapsed().as_nanos() as u64);
            }
            samples
        }));
    }
    let mut samples = Vec::with_capacity(THREADS * OPS_PER_THREAD);
    for handle in handles {
        samples.extend(handle.join().unwrap());
    }
    let elapsed = start.elapsed();
    let after = rss_kib();
    let label = if hot {
        "sharded concurrent hot-IP"
    } else {
        "sharded concurrent high-cardinality"
    };
    report(label, samples, elapsed);
    println!(
        "sharded concurrent memory at cap: {} KiB (delta {} KiB, {} tracked)",
        after,
        after.saturating_sub(before),
        UNIQUE_IPS
    );
}

fn main() {
    let mode = std::env::args().nth(1).unwrap_or_else(|| "sharded".into());
    let ips: Vec<IpAddr> = (0..UNIQUE_IPS)
        .map(|value| IpAddr::V4(Ipv4Addr::from(value as u32)))
        .collect();

    match mode.as_str() {
        "baseline" => run_baseline(&ips),
        "sharded" => run_sharded(&ips),
        "baseline-concurrent" => {
            run_baseline_concurrent(&ips, false);
            run_baseline_concurrent(&ips, true);
        }
        "sharded-concurrent" => {
            run_sharded_concurrent(&ips, false);
            run_sharded_concurrent(&ips, true);
        }
        other => panic!(
            "unknown mode {other}; use baseline, sharded, baseline-concurrent or sharded-concurrent"
        ),
    }
}
