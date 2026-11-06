//! In-process benchmark for the bodyless WAF decision path.
//!
//! This measures the decision pipeline only (no sockets, no upstream): request
//! context construction, admission, protocol pre-checks, rule dispatch,
//! metrics, audit/event logging, the compiled fast-allow lookup and the
//! response decision.
//!
//! ```sh
//! cargo run --release --bin bodyless-bench -- --profile
//! cargo run --release --bin bodyless-bench -- --concurrency 1,16,64
//! ```
//!
//! The engine is built with the default heuristic rules (content inspection,
//! size/method checks and the two rate limiters) and Coraza disabled so the
//! numbers isolate the host-side decision path. Coraza is a separate,
//! byte-linear budget (`bench-subms`). Rate limits use a large capacity so the
//! sweep measures the gate cost without exhausting a bucket mid-run.

use std::hint::black_box;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::Parser;
use hyper::header::HeaderValue;
use hyper::{HeaderMap, Method, Uri};
use tokio::sync::Barrier;

use waf_ingress::config::Config;
use waf_ingress::metrics::Metrics;
use waf_ingress::waf::admission::InspectionCost;
use waf_ingress::waf::{Decision, RequestContext, WafEngine};

#[derive(Debug, Parser)]
#[command(
    name = "bodyless-bench",
    about = "In-process bodyless WAF decision-path benchmark (release)"
)]
struct Cli {
    /// Component profile (single-threaded nanoseconds).
    #[arg(long)]
    profile: bool,

    /// Concurrency levels for the latency/throughput sweep.
    #[arg(long, default_value = "1,16,64")]
    concurrency: String,

    /// Requests per worker for the sweep.
    #[arg(long, default_value_t = 20_000)]
    requests: usize,

    /// Warm-up iterations per cell (excluded from stats).
    #[arg(long, default_value_t = 2_000)]
    warmup: usize,

    /// Samples for the component profile.
    #[arg(long, default_value_t = 20_000)]
    samples: usize,
}

#[derive(Debug, Clone, Copy)]
struct Stats {
    p50: f64,
    p95: f64,
    p99: f64,
    mean: f64,
    min: f64,
}

impl Stats {
    fn from_samples(mut samples: Vec<Duration>) -> Self {
        samples.sort_unstable();
        let n = samples.len().max(1);
        let ns = |d: Duration| d.as_secs_f64() * 1e9;
        let sum: f64 = samples.iter().map(|d| ns(*d)).sum();
        Self {
            p50: ns(samples[(n - 1) * 50 / 100]),
            p95: ns(samples[(n - 1) * 95 / 100]),
            p99: ns(samples[(n - 1) * 99 / 100]),
            mean: sum / n as f64,
            min: ns(samples[0]),
        }
    }
}

fn bodyless_context() -> RequestContext {
    let mut headers = HeaderMap::new();
    headers.insert("host", HeaderValue::from_static("benchmark.test"));
    headers.insert(
        "user-agent",
        HeaderValue::from_static("Mozilla/5.0 (X11; Linux x86_64) Firefox/128.0"),
    );
    headers.insert(
        "accept",
        HeaderValue::from_static("text/html,application/xhtml+xml;q=0.9,*/*;q=0.8"),
    );
    headers.insert("accept-encoding", HeaderValue::from_static("gzip, deflate"));
    RequestContext::with_http_version(
        IpAddr::from([127, 0, 0, 1]),
        Method::GET,
        Uri::from_static("/health"),
        headers,
        None,
        "1.1".to_string(),
    )
}

fn bench_config(fast_allow: bool) -> Config {
    let mut config = Config::default();
    // Isolate the host-side decision path. Coraza body scanning has its own
    // layered benchmark (bench-subms) and is skipped by the fast allow path.
    config.waf.coraza.enabled = false;
    config.waf.grpc.enabled = false;
    config.waf.graphql.enabled = false;
    // Keep the gate cost but never exhaust a bucket during the sweep.
    config.waf.rate_limit.per_ip_max_requests = u32::MAX;
    config.waf.rate_limit.global_max_requests = u32::MAX;
    if fast_allow {
        config.waf.fast_allow.enabled = true;
        config.waf.fast_allow.routes = vec!["GET /health".to_string()];
    }
    config
}

fn measure<F: FnMut()>(mut operation: F, warmup: usize, samples: usize) -> Stats {
    for _ in 0..warmup {
        operation();
    }
    let mut values = Vec::with_capacity(samples);
    for _ in 0..samples {
        let started = Instant::now();
        operation();
        values.push(started.elapsed());
    }
    Stats::from_samples(values)
}

fn measure_async<F, Fut>(
    runtime: &tokio::runtime::Runtime,
    mut operation: F,
    warmup: usize,
    samples: usize,
) -> Stats
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    runtime.block_on(async {
        for _ in 0..warmup {
            operation().await;
        }
        let mut values = Vec::with_capacity(samples);
        for _ in 0..samples {
            let started = Instant::now();
            operation().await;
            values.push(started.elapsed());
        }
        Stats::from_samples(values)
    })
}

fn fmt_ns(value: f64) -> String {
    if value >= 1_000.0 {
        format!("{:.2} us", value / 1_000.0)
    } else {
        format!("{value:.0} ns")
    }
}

fn profile(
    base: &Arc<WafEngine>,
    fast: &Arc<WafEngine>,
    gates_off: &Arc<WafEngine>,
    samples: usize,
    warmup: usize,
) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let ctx = bodyless_context();
    let metrics = Metrics::new();

    println!("\n== component profile (single-threaded, ns) ==");
    println!(
        "{:<30} {:>10} {:>10} {:>10} {:>10}",
        "component", "p50", "p95", "p99", "mean"
    );

    let row = |name: &str, stats: Stats| {
        println!(
            "{:<30} {:>10} {:>10} {:>10} {:>10}",
            name,
            fmt_ns(stats.p50),
            fmt_ns(stats.p95),
            fmt_ns(stats.p99),
            fmt_ns(stats.mean)
        );
    };

    // Request canonicalisation: HeaderMap clone, URI/method clone and the
    // version string allocation that the full context needs.
    row(
        "context construction",
        measure(
            || {
                let built = RequestContext::with_http_version(
                    ctx.client_ip,
                    ctx.method.clone(),
                    ctx.uri.clone(),
                    ctx.headers.clone(),
                    ctx.body_size,
                    ctx.http_version.clone(),
                );
                black_box(built);
            },
            warmup,
            samples,
        ),
    );

    // Cheap admission (no semaphore, no wait).
    row(
        "admission (cheap)",
        measure_async(
            &rt,
            || async {
                let guard = base.admission().admit(InspectionCost::Cheap).await;
                black_box(guard.is_ok());
            },
            warmup,
            samples,
        ),
    );

    // Metrics only.
    row(
        "metrics (request+allow)",
        measure(
            || {
                metrics.record_request();
                metrics.record_allowed();
                black_box(());
            },
            warmup,
            samples,
        ),
    );

    // Pre-checks + rule dispatch + admission, but no audit on allow.
    row(
        "fast_evaluate (no audit)",
        measure_async(
            &rt,
            || async {
                let decision = base.fast_evaluate(&ctx).await;
                black_box(decision);
            },
            warmup,
            samples,
        ),
    );

    // Full path: admission + pre-checks + rule dispatch + audit event.
    row(
        "evaluate_shared (full)",
        measure_async(
            &rt,
            || async {
                let decision = base.evaluate_shared(&ctx).await;
                black_box(decision);
            },
            warmup,
            samples,
        ),
    );

    // Rule dispatch alone: an engine with no rules.
    let empty = Arc::new(WafEngine::new());
    row(
        "dispatch (0 rules)",
        measure_async(
            &rt,
            || async {
                let decision = empty.fast_evaluate(&ctx).await;
                black_box(decision);
            },
            warmup,
            samples,
        ),
    );

    // Compiled allowlist: exact method+path trie, bodyless checks and the
    // always-on gates. No context construction, admission, pre-check,
    // inspection or audit.
    row(
        "fast_allow (compiled route)",
        measure(
            || {
                let outcome = fast.fast_allow(
                    &ctx.method,
                    &ctx.uri,
                    &ctx.headers,
                    ctx.client_ip,
                    ctx.body_size,
                    true,
                );
                black_box(outcome.is_some());
            },
            warmup,
            samples,
        ),
    );

    // The same compiled lookup with the two rate-limit gates disabled, to
    // attribute the gate cost in the report.
    row(
        "fast_allow (no rate gates)",
        measure(
            || {
                let outcome = gates_off.fast_allow(
                    &ctx.method,
                    &ctx.uri,
                    &ctx.headers,
                    ctx.client_ip,
                    ctx.body_size,
                    true,
                );
                black_box(outcome.is_some());
            },
            warmup,
            samples,
        ),
    );

    // Audit construction is the delta between the full path and the
    // no-audit path; report it explicitly for the report table.
    let full = measure_async(
        &rt,
        || async {
            let decision = base.evaluate_shared(&ctx).await;
            black_box(decision);
        },
        warmup,
        samples,
    );
    let no_audit = measure_async(
        &rt,
        || async {
            let decision = base.fast_evaluate(&ctx).await;
            black_box(decision);
        },
        warmup,
        samples,
    );
    row(
        "audit (full - fast)",
        Stats {
            p50: (full.p50 - no_audit.p50).max(0.0),
            p95: (full.p95 - no_audit.p95).max(0.0),
            p99: (full.p99 - no_audit.p99).max(0.0),
            mean: (full.mean - no_audit.mean).max(0.0),
            min: (full.min - no_audit.min).max(0.0),
        },
    );
}

async fn run_worker(
    engine: Arc<WafEngine>,
    ctx: Arc<RequestContext>,
    barrier: Arc<Barrier>,
    requests: usize,
    mode: Mode,
) -> Vec<Duration> {
    barrier.wait().await;
    let mut samples = Vec::with_capacity(requests);
    for _ in 0..requests {
        let started = Instant::now();
        match mode {
            Mode::Full => {
                let decision = engine.evaluate_shared(&ctx).await;
                black_box(decision);
            }
            Mode::Fast => {
                let decision = engine.fast_evaluate(&ctx).await;
                black_box(decision);
            }
            Mode::Allow => {
                let outcome = engine.fast_allow(
                    &ctx.method,
                    &ctx.uri,
                    &ctx.headers,
                    ctx.client_ip,
                    ctx.body_size,
                    true,
                );
                debug_assert!(matches!(
                    outcome.as_ref().map(|outcome| &outcome.decision),
                    Some(Decision::Allow)
                ));
                black_box(outcome);
            }
        }
        samples.push(started.elapsed());
    }
    samples
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Full,
    Fast,
    Allow,
}

impl Mode {
    fn label(self) -> &'static str {
        match self {
            Self::Full => "evaluate_shared",
            Self::Fast => "fast_evaluate",
            Self::Allow => "fast_allow",
        }
    }
}

async fn sweep(
    base: Arc<WafEngine>,
    fast: Arc<WafEngine>,
    levels: &[usize],
    requests: usize,
    warmup: usize,
) {
    let ctx = Arc::new(bodyless_context());

    println!("\n== latency / throughput (per-request, in-process) ==");
    println!(
        "{:<18} {:>3} {:>10} {:>10} {:>10} {:>12}",
        "path", "c", "p50", "p95", "p99", "RPS"
    );

    for mode in [Mode::Full, Mode::Fast, Mode::Allow] {
        let engine = match mode {
            Mode::Full | Mode::Fast => Arc::clone(&base),
            Mode::Allow => Arc::clone(&fast),
        };
        for &concurrency in levels {
            // Warm the engine, rate-limit buckets and allocator on one worker.
            for _ in 0..warmup {
                match mode {
                    Mode::Full => {
                        black_box(engine.evaluate_shared(&ctx).await);
                    }
                    Mode::Fast => {
                        black_box(engine.fast_evaluate(&ctx).await);
                    }
                    Mode::Allow => {
                        black_box(engine.fast_allow(
                            &ctx.method,
                            &ctx.uri,
                            &ctx.headers,
                            ctx.client_ip,
                            ctx.body_size,
                            true,
                        ));
                    }
                }
            }

            let barrier = Arc::new(Barrier::new(concurrency));
            let started = Instant::now();
            let mut handles = Vec::with_capacity(concurrency);
            for _ in 0..concurrency {
                handles.push(tokio::spawn(run_worker(
                    Arc::clone(&engine),
                    Arc::clone(&ctx),
                    Arc::clone(&barrier),
                    requests,
                    mode,
                )));
            }
            let mut samples = Vec::with_capacity(concurrency * requests);
            for handle in handles {
                samples.extend(handle.await.expect("worker"));
            }
            let elapsed = started.elapsed();
            let stats = Stats::from_samples(samples);
            let total = (concurrency * requests) as f64;
            let rps = total / elapsed.as_secs_f64();
            println!(
                "{:<18} {:>3} {:>10} {:>10} {:>10} {:>12.0}",
                mode.label(),
                concurrency,
                fmt_ns(stats.p50),
                fmt_ns(stats.p95),
                fmt_ns(stats.p99),
                rps
            );
        }
    }
}

fn main() {
    let cli = Cli::parse();
    let base = Arc::new(WafEngine::with_config(&bench_config(false)));
    let fast = Arc::new(WafEngine::with_config(&bench_config(true)));
    let mut gates_off_config = bench_config(true);
    gates_off_config.waf.rate_limit.per_ip_enabled = false;
    gates_off_config.waf.rate_limit.global_enabled = false;
    let gates_off = Arc::new(WafEngine::with_config(&gates_off_config));

    if cli.profile {
        profile(
            &base,
            &fast,
            &gates_off,
            cli.samples,
            cli.warmup.min(cli.samples),
        );
    }

    let levels: Vec<usize> = cli
        .concurrency
        .split(',')
        .filter_map(|value| value.trim().parse().ok())
        .collect();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(sweep(
        base,
        fast,
        &levels,
        cli.requests.max(1),
        cli.warmup.min(cli.requests),
    ));
}
