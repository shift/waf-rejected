//! Layered sub-millisecond budget benchmark for the WAF ingress.
//!
//! The harness decomposes request cost into layers so a fast path can be
//! budgeted rather than guessed:
//!
//! * **L0** — `WafEngine::evaluate` with a synthetic context (no HTTP), plus
//!   the raw Coraza backend (WASI reactor or native sidecar round trip) and a
//!   heuristics-only engine (Coraza disabled).
//! * **L1** — payload construction only: header stringification, body
//!   selection, the JSON envelope (`coraza_payload`) and the binary v1 frame
//!   (`coraza_wire`).
//! * **L2** — the real proxy with the WAF disabled (`waf.enabled = false`):
//!   hyper request parse → framing/auth/body buffering → upstream forward →
//!   response. This is the proxy floor a fast path inherits.
//! * **L3** — the same proxy with the WAF enabled (wasm and, when a sidecar
//!   socket is supplied, native).
//! * **L4** — TLS/h2 overhead. Not implemented here; see the report. TLS
//!   record and handshake cost is transport, not WAF budget, and is measured
//!   by the load harness when a certificate is configured.
//!
//! Everything runs in one process over loopback: a mock upstream, the real
//! `WafProxyService` listener and a keep-alive hyper client. No external
//! network is used. Timings therefore include loopback TCP and the client;
//! the L2 row is the empirical proxy floor and L3−L2 is the WAF add-on.
//!
//! Run with:
//!
//! ```sh
//! cargo run --release --features wasm-reactor,coraza-native \
//!   --bin bench-subms -- --native-socket /tmp/opencode/coraza.sock
//! ```
//!
//! `scripts/bench-subms.sh` builds the sidecar, starts it and invokes this
//! binary. See `docs/operations/subms-budget.md`.

use std::alloc::{GlobalAlloc, Layout, System};
use std::convert::Infallible;
use std::hint::black_box;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use clap::Parser;
use http_body_util::{BodyExt, Full};
use hyper::header::{HeaderValue, ACCEPT, CONTENT_LENGTH, CONTENT_TYPE, HOST, USER_AGENT};
use hyper::{HeaderMap, Method, Request, Response, Uri};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde_json::json;
use tokio::net::TcpListener;

use waf_ingress::config::{Config, CorazaBackend};
use waf_ingress::proxy::WafProxyService;
use waf_ingress::waf::coraza_payload::{
    build_payload_with_policy, select_body, BodyInspectionPolicy,
};
use waf_ingress::waf::coraza_wire::encode_request;
use waf_ingress::waf::{Decision, RequestContext, WafEngine};

// ---------------------------------------------------------------------------
// Allocation accounting
// ---------------------------------------------------------------------------

struct CountingAlloc;

static ALLOC_ENABLED: AtomicBool = AtomicBool::new(false);
static ALLOC_BYTES: AtomicU64 = AtomicU64::new(0);
static ALLOC_CALLS: AtomicU64 = AtomicU64::new(0);

#[global_allocator]
static GLOBAL: CountingAlloc = CountingAlloc;

unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = System.alloc(layout);
        if !ptr.is_null() && ALLOC_ENABLED.load(Ordering::Relaxed) {
            ALLOC_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
            ALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = System.alloc_zeroed(layout);
        if !ptr.is_null() && ALLOC_ENABLED.load(Ordering::Relaxed) {
            ALLOC_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
            ALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new_ptr = System.realloc(ptr, layout, new_size);
        if !new_ptr.is_null() && ALLOC_ENABLED.load(Ordering::Relaxed) {
            ALLOC_BYTES.fetch_add(new_size as u64, Ordering::Relaxed);
            ALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
        }
        new_ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }
}

fn alloc_start() {
    ALLOC_BYTES.store(0, Ordering::Relaxed);
    ALLOC_CALLS.store(0, Ordering::Relaxed);
    ALLOC_ENABLED.store(true, Ordering::Relaxed);
}

fn alloc_stop(reps: usize) -> (f64, f64) {
    ALLOC_ENABLED.store(false, Ordering::Relaxed);
    let bytes = ALLOC_BYTES.load(Ordering::Relaxed) as f64 / reps as f64;
    let calls = ALLOC_CALLS.load(Ordering::Relaxed) as f64 / reps as f64;
    (bytes, calls)
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Debug, Parser)]
#[command(
    name = "bench-subms",
    about = "Layered sub-millisecond WAF budget benchmark (release, in-process)"
)]
struct Cli {
    /// Comma-separated layers to run: l0,l1,l2,l3 (default: all).
    #[arg(long, default_value = "l0,l1,l2,l3")]
    only: String,

    /// Samples per L0/L1 cell (L0 samples are single calls).
    #[arg(long, default_value_t = 100)]
    samples: usize,

    /// Sequential requests per L2/L3 cell.
    #[arg(long, default_value_t = 100)]
    requests: usize,

    /// Warm-up iterations per cell (excluded from stats).
    #[arg(long, default_value_t = 10)]
    warmup: usize,

    /// Closed-loop worker count for the throughput cell.
    #[arg(long, default_value_t = 8)]
    concurrency: usize,

    /// Requests per worker in the throughput cell.
    #[arg(long, default_value_t = 50)]
    per_worker: usize,

    /// Coraza evaluation budget. Raised by default above the shipped 5 s DoS
    /// bound so a host stall is measured, not reported as a WAF 503.
    #[arg(long, default_value_t = 120_000)]
    eval_timeout_ms: u64,

    /// Native Coraza sidecar socket. Native rows are skipped without it.
    #[arg(long)]
    native_socket: Option<PathBuf>,

    /// Write the measured rows and gates as JSON.
    #[arg(long)]
    json_out: Option<PathBuf>,
}

impl Cli {
    fn wants(&self, layer: &str) -> bool {
        self.only
            .split(',')
            .map(str::trim)
            .any(|value| value.eq_ignore_ascii_case(layer))
    }
}

// ---------------------------------------------------------------------------
// Sizes and statistics
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SizeClass {
    Bodyless,
    K1,
    K4,
    K8,
}

const SIZES: [SizeClass; 4] = [
    SizeClass::Bodyless,
    SizeClass::K1,
    SizeClass::K4,
    SizeClass::K8,
];

impl SizeClass {
    fn label(self) -> &'static str {
        match self {
            SizeClass::Bodyless => "bodyless",
            SizeClass::K1 => "1 KiB",
            SizeClass::K4 => "4 KiB",
            SizeClass::K8 => "8 KiB",
        }
    }

    fn bytes(self) -> usize {
        match self {
            SizeClass::Bodyless => 0,
            SizeClass::K1 => 1024,
            SizeClass::K4 => 4 * 1024,
            SizeClass::K8 => 8 * 1024,
        }
    }

    fn body(self) -> Option<Vec<u8>> {
        let len = self.bytes();
        if len == 0 {
            return None;
        }
        // A urlencoded form field keeps CRS happy: a bare text/plain body is
        // itself a protocol anomaly, and the row would measure a block.
        let prefix = b"data=";
        let mut body = Vec::with_capacity(len);
        body.extend_from_slice(prefix);
        body.resize(len, b'A');
        Some(body)
    }

    fn path(self) -> &'static str {
        if self.bytes() == 0 {
            "/hello?id=42"
        } else {
            "/upload"
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct Stats {
    n: usize,
    p50_ms: f64,
    p95_ms: f64,
    p99_ms: f64,
    mean_ms: f64,
    max_ms: f64,
}

fn summarize(mut samples: Vec<u64>) -> Stats {
    if samples.is_empty() {
        return Stats::default();
    }
    samples.sort_unstable();
    let n = samples.len();
    let pct = |p: f64| -> f64 {
        let index = ((p * n as f64).ceil() as usize)
            .saturating_sub(1)
            .min(n - 1);
        samples[index] as f64 / 1e6
    };
    let mean = samples.iter().map(|v| *v as f64).sum::<f64>() / n as f64 / 1e6;
    Stats {
        n,
        p50_ms: pct(0.50),
        p95_ms: pct(0.95),
        p99_ms: pct(0.99),
        mean_ms: mean,
        max_ms: *samples.last().unwrap() as f64 / 1e6,
    }
}

fn measure_sync<F: FnMut()>(samples: usize, warmup: usize, batch: usize, mut op: F) -> Stats {
    for _ in 0..warmup {
        op();
    }
    let batch = batch.max(1) as u64;
    let mut values = Vec::with_capacity(samples);
    for _ in 0..samples {
        let started = Instant::now();
        for _ in 0..batch {
            op();
        }
        values.push(started.elapsed().as_nanos() as u64 / batch);
    }
    summarize(values)
}

// ---------------------------------------------------------------------------
// Rows and reporting
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Row {
    layer: &'static str,
    backend: &'static str,
    size: &'static str,
    stats: Stats,
    alloc_bytes: Option<f64>,
    alloc_calls: Option<f64>,
    errors: usize,
    note: String,
}

impl Row {
    fn new(layer: &'static str, backend: &'static str, size: &'static str, stats: Stats) -> Self {
        Self {
            layer,
            backend,
            size,
            stats,
            alloc_bytes: None,
            alloc_calls: None,
            errors: 0,
            note: String::new(),
        }
    }

    fn with_alloc(mut self, bytes: f64, calls: f64) -> Self {
        self.alloc_bytes = Some(bytes);
        self.alloc_calls = Some(calls);
        self
    }

    fn with_errors(mut self, errors: usize) -> Self {
        self.errors = errors;
        self
    }

    fn with_note(mut self, note: impl Into<String>) -> Self {
        self.note = note.into();
        self
    }
}

fn print_rows(rows: &[Row]) {
    println!();
    println!(
        "| layer | backend | size | p50 ms | p95 ms | p99 ms | mean ms | alloc B/op | allocs/op | non-200 | note |"
    );
    println!("|---|---|---|---:|---:|---:|---:|---:|---:|---:|---|");
    for row in rows {
        let bytes = row
            .alloc_bytes
            .map(|value| format!("{value:.0}"))
            .unwrap_or_else(|| "-".to_string());
        let calls = row
            .alloc_calls
            .map(|value| format!("{value:.2}"))
            .unwrap_or_else(|| "-".to_string());
        println!(
            "| {} | {} | {} | {:.3} | {:.3} | {:.3} | {:.3} | {} | {} | {} | {} |",
            row.layer,
            row.backend,
            row.size,
            row.stats.p50_ms,
            row.stats.p95_ms,
            row.stats.p99_ms,
            row.stats.mean_ms,
            bytes,
            calls,
            row.errors,
            row.note
        );
    }
}

fn find<'a>(rows: &'a [Row], layer: &str, backend: &str, size: &str) -> Option<&'a Row> {
    rows.iter()
        .find(|row| row.layer == layer && row.backend == backend && row.size == size)
}

/// The throughput-cell row for a size (`note` starts with `c=`).
fn find_concurrent<'a>(rows: &'a [Row], layer: &str, backend: &str, size: &str) -> Option<&'a Row> {
    rows.iter().find(|row| {
        row.layer == layer
            && row.backend == backend
            && row.size == size
            && row.note.starts_with("c=")
    })
}

// ---------------------------------------------------------------------------
// Contexts and payloads
// ---------------------------------------------------------------------------

fn synthetic_context(size: SizeClass) -> RequestContext {
    let mut headers = HeaderMap::new();
    headers.insert(HOST, HeaderValue::from_static("bench.example"));
    headers.insert(
        USER_AGENT,
        HeaderValue::from_static("waf-rejected-subms-bench/1.0"),
    );
    headers.insert(ACCEPT, HeaderValue::from_static("*/*"));

    match size.body() {
        Some(body) => {
            headers.insert(
                CONTENT_TYPE,
                HeaderValue::from_static("application/x-www-form-urlencoded"),
            );
            headers.insert(
                CONTENT_LENGTH,
                HeaderValue::from_str(&body.len().to_string()).expect("content-length is ASCII"),
            );
            RequestContext::with_http_version(
                IpAddr::from([127, 0, 0, 1]),
                Method::POST,
                Uri::from_static("/upload"),
                headers,
                Some(body.len()),
                "1.1".to_string(),
            )
            .with_body(Some(Bytes::from(body)))
        }
        None => RequestContext::with_http_version(
            IpAddr::from([127, 0, 0, 1]),
            Method::GET,
            Uri::from_static("/hello?id=42"),
            headers,
            None,
            "1.1".to_string(),
        ),
    }
}

fn describe(decision: &Decision) -> String {
    match decision {
        Decision::Allow => "allow".to_string(),
        Decision::Block { status, reason } => format!("block {status}: {reason}"),
        Decision::RateLimit { reason } => format!("rate-limit: {reason}"),
    }
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

// Config has many nested defaults; assigning the benchmark overrides after
// `Config::default()` is clearer than spelling every field.
#[allow(clippy::field_reassign_with_default)]
fn base_config(upstream: SocketAddr, eval_timeout_ms: u64) -> Config {
    let mut config = Config::default();
    config.upstream_uri = format!("http://{upstream}");
    // The benchmark issues thousands of requests from one IP; the production
    // default (100 req/min/IP) would turn the rows into 429s. This is the same
    // exclusion the load harness makes.
    config.waf.rate_limit.per_ip_enabled = false;
    config.waf.rate_limit.global_enabled = false;
    // The shipped 5 s bound is a DoS guard. On a contended host a stall would
    // surface as a 503 and hide the real scan cost, so the harness raises it
    // and reports the wall time instead.
    config.waf.coraza.eval_timeout_ms = eval_timeout_ms;
    config
}

fn wasm_config(upstream: SocketAddr, pool_size: usize, eval_timeout_ms: u64) -> Config {
    let mut config = base_config(upstream, eval_timeout_ms);
    config.waf.coraza.backend = CorazaBackend::Wasm;
    config.waf.coraza.pool_size = pool_size;
    config
}

fn heuristics_config(upstream: SocketAddr) -> Config {
    let mut config = base_config(upstream, 5_000);
    config.waf.coraza.enabled = false;
    config
}

#[cfg(feature = "rust-engine")]
fn rust_config(upstream: SocketAddr, eval_timeout_ms: u64) -> Config {
    let mut config = base_config(upstream, eval_timeout_ms);
    config.waf.coraza.backend = CorazaBackend::Rust;
    config.waf.coraza.fallback = waf_ingress::config::CorazaFallback::None;
    config
}

#[cfg(all(feature = "coraza-native", unix))]
fn native_config(
    upstream: SocketAddr,
    socket: &std::path::Path,
    pool_size: usize,
    eval_timeout_ms: u64,
) -> Config {
    let mut config = base_config(upstream, eval_timeout_ms);
    config.waf.coraza.backend = CorazaBackend::Native;
    config.waf.coraza.native_socket_path = Some(socket.display().to_string());
    config.waf.coraza.pool_size = pool_size;
    config
}

// ---------------------------------------------------------------------------
// L0: engine and raw backend
// ---------------------------------------------------------------------------

fn measure_engine(
    runtime: &tokio::runtime::Runtime,
    engine: &WafEngine,
    ctx: &RequestContext,
    samples: usize,
    warmup: usize,
) -> (Stats, Decision) {
    runtime.block_on(async {
        let mut last = Decision::Allow;
        for _ in 0..warmup {
            last = engine.evaluate(ctx).await;
        }
        let mut values = Vec::with_capacity(samples);
        for _ in 0..samples {
            let started = Instant::now();
            last = engine.evaluate(ctx).await;
            values.push(started.elapsed().as_nanos() as u64);
        }
        (summarize(values), last)
    })
}

fn measure_engine_alloc(
    runtime: &tokio::runtime::Runtime,
    engine: &WafEngine,
    ctx: &RequestContext,
    reps: usize,
) -> (f64, f64) {
    runtime.block_on(async {
        for _ in 0..3 {
            black_box(engine.evaluate(ctx).await);
        }
        alloc_start();
        for _ in 0..reps {
            black_box(engine.evaluate(ctx).await);
        }
        alloc_stop(reps)
    })
}

fn run_l0(cli: &Cli, runtime: &tokio::runtime::Runtime) -> Result<Vec<Row>> {
    let mut rows = Vec::new();

    let heuristics = WafEngine::with_config_and_metrics(
        &heuristics_config("127.0.0.1:1".parse().expect("valid addr")),
        None,
    );

    for size in SIZES {
        let ctx = synthetic_context(size);
        let (stats, decision) = measure_engine(runtime, &heuristics, &ctx, cli.samples, cli.warmup);
        let (bytes, calls) = measure_engine_alloc(runtime, &heuristics, &ctx, cli.samples.min(50));
        rows.push(
            Row::new("L0-engine", "heuristics-only", size.label(), stats)
                .with_alloc(bytes, calls)
                .with_note(describe(&decision)),
        );
    }

    #[cfg(feature = "wasm-reactor")]
    {
        let module = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/wasm/coraza_reactor/coraza_reactor.wasm"
        ))
        .context("read the committed Coraza reactor module")?;
        let reactor = waf_ingress::waf::wasm_reactor::WasmReactor::from_bytes(
            &module,
            waf_ingress::waf::wasm_reactor::ReactorLimits::coraza(),
        )
        .context("load the Coraza reactor")?;

        let engine = WafEngine::with_config_and_metrics(
            &wasm_config(
                "127.0.0.1:1".parse().expect("valid addr"),
                1,
                cli.eval_timeout_ms,
            ),
            None,
        );
        if let Some(error) = engine.waf_init_error() {
            bail!("wasm WAF engine failed to initialise: {error}");
        }

        for size in SIZES {
            let ctx = synthetic_context(size);
            let payload = build_payload_with_policy(&ctx, &BodyInspectionPolicy::default())
                .context("build reactor payload")?;
            let payload = match payload {
                waf_ingress::waf::coraza_payload::PayloadBuild::Built { payload, .. } => payload,
                waf_ingress::waf::coraza_payload::PayloadBuild::Reject { .. } => {
                    bail!("default policy rejected the {} payload", size.label())
                }
            };

            let stats = measure_sync(cli.samples, cli.warmup, 1, || {
                let result = reactor.evaluate(black_box(&payload));
                black_box(&result);
            });
            let (bytes, calls) = {
                for _ in 0..3 {
                    let _ = black_box(reactor.evaluate(&payload));
                }
                alloc_start();
                for _ in 0..cli.samples.min(50) {
                    let _ = black_box(reactor.evaluate(&payload));
                }
                alloc_stop(cli.samples.min(50))
            };
            rows.push(
                Row::new("L0-reactor", "wasm", size.label(), stats)
                    .with_alloc(bytes, calls)
                    .with_note(format!("payload {} B", payload.len())),
            );

            let (stats, decision) = measure_engine(runtime, &engine, &ctx, cli.samples, cli.warmup);
            let (bytes, calls) = measure_engine_alloc(runtime, &engine, &ctx, cli.samples.min(50));
            rows.push(
                Row::new("L0-engine", "wasm", size.label(), stats)
                    .with_alloc(bytes, calls)
                    .with_note(describe(&decision)),
            );
        }
    }

    #[cfg(not(feature = "wasm-reactor"))]
    println!("L0 wasm rows skipped: build without the `wasm-reactor` feature");

    #[cfg(feature = "rust-engine")]
    {
        let engine = WafEngine::with_config_and_metrics(
            &rust_config("127.0.0.1:1".parse().expect("valid addr"), 5_000),
            None,
        );
        if let Some(error) = engine.waf_init_error() {
            bail!("rust WAF engine failed to initialise: {error}");
        }

        for size in SIZES {
            let ctx = synthetic_context(size);
            let (stats, decision) = measure_engine(runtime, &engine, &ctx, cli.samples, cli.warmup);
            let (bytes, calls) = measure_engine_alloc(runtime, &engine, &ctx, cli.samples.min(50));
            rows.push(
                Row::new("L0-engine", "rust", size.label(), stats)
                    .with_alloc(bytes, calls)
                    .with_note(describe(&decision)),
            );
        }
    }

    #[cfg(not(feature = "rust-engine"))]
    println!("L0 rust rows skipped: build without the `rust-engine` feature");

    #[cfg(all(feature = "coraza-native", unix))]
    if let Some(socket) = cli.native_socket.as_deref() {
        let client_config = waf_ingress::waf::native_coraza::ClientConfig {
            socket_path: socket.to_path_buf(),
            pool_size: 4,
            timeout: Duration::from_millis(cli.eval_timeout_ms),
            max_payload_bytes: 64 * 1024,
        };
        let client = waf_ingress::waf::native_coraza::NativeCorazaClient::new(&client_config)
            .with_context(|| format!("connect to the native sidecar at {}", socket.display()))?;
        let policy = BodyInspectionPolicy::default();

        let engine = WafEngine::with_config_and_metrics(
            &native_config(
                "127.0.0.1:1".parse().expect("valid addr"),
                socket,
                4,
                cli.eval_timeout_ms,
            ),
            None,
        );
        if let Some(error) = engine.waf_init_error() {
            bail!("native WAF engine failed to initialise: {error}");
        }

        for size in SIZES {
            let ctx = synthetic_context(size);
            let stats = measure_sync(cli.samples, cli.warmup, 1, || {
                let result = client.evaluate_context(black_box(&ctx), &policy);
                black_box(&result);
            });
            let (bytes, calls) = {
                for _ in 0..3 {
                    let _ = black_box(client.evaluate_context(&ctx, &policy));
                }
                alloc_start();
                for _ in 0..cli.samples.min(50) {
                    let _ = black_box(client.evaluate_context(&ctx, &policy));
                }
                alloc_stop(cli.samples.min(50))
            };
            rows.push(
                Row::new("L0-reactor", "native", size.label(), stats)
                    .with_alloc(bytes, calls)
                    .with_note("client round trip + sidecar"),
            );

            let (stats, decision) = measure_engine(runtime, &engine, &ctx, cli.samples, cli.warmup);
            let (bytes, calls) = measure_engine_alloc(runtime, &engine, &ctx, cli.samples.min(50));
            rows.push(
                Row::new("L0-engine", "native", size.label(), stats)
                    .with_alloc(bytes, calls)
                    .with_note(describe(&decision)),
            );
        }
    }

    #[cfg(not(all(feature = "coraza-native", unix)))]
    println!("L0 native rows skipped: build without the `coraza-native` feature");

    Ok(rows)
}

// ---------------------------------------------------------------------------
// L1: payload construction only
// ---------------------------------------------------------------------------

fn run_l1(cli: &Cli) -> Vec<Row> {
    let policy = BodyInspectionPolicy::default();
    let mut rows = Vec::new();

    for size in SIZES {
        let ctx = synthetic_context(size);

        let stats = measure_sync(cli.samples, cli.warmup, 200, || {
            let headers: Vec<(String, String)> = ctx
                .headers
                .iter()
                .map(|(name, value)| {
                    (
                        name.as_str().to_string(),
                        String::from_utf8_lossy(value.as_bytes()).into_owned(),
                    )
                })
                .collect();
            black_box(headers);
        });
        let (bytes, calls) = {
            for _ in 0..3 {
                let _: Vec<(String, String)> = ctx
                    .headers
                    .iter()
                    .map(|(name, value)| {
                        (
                            name.as_str().to_string(),
                            String::from_utf8_lossy(value.as_bytes()).into_owned(),
                        )
                    })
                    .collect();
            }
            alloc_start();
            for _ in 0..100 {
                let headers: Vec<(String, String)> = ctx
                    .headers
                    .iter()
                    .map(|(name, value)| {
                        (
                            name.as_str().to_string(),
                            String::from_utf8_lossy(value.as_bytes()).into_owned(),
                        )
                    })
                    .collect();
                black_box(headers);
            }
            alloc_stop(100)
        };
        rows.push(
            Row::new("L1-payload", "header-strings", size.label(), stats).with_alloc(bytes, calls),
        );

        let stats = measure_sync(cli.samples, cli.warmup, 500, || {
            black_box(select_body(&ctx, &policy));
        });
        rows.push(Row::new("L1-payload", "select-body", size.label(), stats));

        let stats = measure_sync(cli.samples, cli.warmup, 20, || {
            let built = build_payload_with_policy(&ctx, &policy).expect("payload builds");
            black_box(built);
        });
        let (bytes, calls) = {
            for _ in 0..3 {
                black_box(build_payload_with_policy(&ctx, &policy).expect("payload builds"));
            }
            alloc_start();
            for _ in 0..100 {
                black_box(build_payload_with_policy(&ctx, &policy).expect("payload builds"));
            }
            alloc_stop(100)
        };
        rows.push(Row::new("L1-payload", "json", size.label(), stats).with_alloc(bytes, calls));

        let stats = measure_sync(cli.samples, cli.warmup, 50, || {
            let built = encode_request(&ctx, &policy).expect("frame builds");
            black_box(built);
        });
        let (bytes, calls) = {
            for _ in 0..3 {
                black_box(encode_request(&ctx, &policy).expect("frame builds"));
            }
            alloc_start();
            for _ in 0..100 {
                black_box(encode_request(&ctx, &policy).expect("frame builds"));
            }
            alloc_stop(100)
        };
        rows.push(Row::new("L1-payload", "binary", size.label(), stats).with_alloc(bytes, calls));
    }

    rows
}

// ---------------------------------------------------------------------------
// L2/L3: real proxy over loopback
// ---------------------------------------------------------------------------

async fn spawn_upstream() -> Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .context("bind the mock upstream")?;
    let addr = listener.local_addr().context("mock upstream address")?;
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(value) => value,
                Err(_) => break,
            };
            tokio::spawn(async move {
                let service = hyper::service::service_fn(
                    |request: Request<hyper::body::Incoming>| async move {
                        let _ = request.into_body().collect().await;
                        Ok::<_, Infallible>(
                            Response::builder()
                                .status(200)
                                .body(Full::new(Bytes::from_static(b"upstream-ok")))
                                .expect("static response builds"),
                        )
                    },
                );
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    Ok(addr)
}

async fn spawn_proxy(config: Config) -> Result<(SocketAddr, Arc<WafProxyService>)> {
    let service = Arc::new(WafProxyService::new(config).context("build the proxy service")?);
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .context("bind the proxy listener")?;
    let addr = listener.local_addr().context("proxy address")?;
    let handle = Arc::clone(&service);
    tokio::spawn(async move {
        let _ = handle.start_with_listener(listener).await;
    });
    Ok((addr, service))
}

type BenchClient = Client<HttpConnector, Full<Bytes>>;

fn http_client() -> BenchClient {
    let mut connector = HttpConnector::new();
    connector.set_nodelay(true);
    connector.set_keepalive(Some(Duration::from_secs(30)));
    Client::builder(TokioExecutor::new()).build(connector)
}

fn proxy_request(base: &str, size: SizeClass) -> Request<Full<Bytes>> {
    let uri = format!("{base}{}", size.path());
    let builder = Request::builder()
        .method(if size.bytes() == 0 {
            Method::GET
        } else {
            Method::POST
        })
        .uri(uri)
        .header(HOST, "bench.example")
        .header(USER_AGENT, "waf-rejected-subms-bench/1.0")
        .header(ACCEPT, "*/*");

    match size.body() {
        Some(body) => builder
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(CONTENT_LENGTH, body.len().to_string())
            .body(Full::new(Bytes::from(body)))
            .expect("request builds"),
        None => builder
            .body(Full::new(Bytes::new()))
            .expect("request builds"),
    }
}

async fn one_request_raw(
    client: &BenchClient,
    base: &str,
    size: SizeClass,
) -> Result<(u64, hyper::StatusCode, Bytes)> {
    let request = proxy_request(base, size);
    let started = Instant::now();
    let response = client.request(request).await.context("send request")?;
    let status = response.status();
    let body = response
        .into_body()
        .collect()
        .await
        .context("read response body")?
        .to_bytes();
    Ok((started.elapsed().as_nanos() as u64, status, body))
}

async fn measure_requests(
    client: &BenchClient,
    base: &str,
    size: SizeClass,
    samples: usize,
    warmup: usize,
) -> Result<(Stats, usize)> {
    for _ in 0..warmup {
        black_box(one_request_raw(client, base, size).await?);
    }
    let mut values = Vec::with_capacity(samples);
    let mut errors = 0usize;
    for _ in 0..samples {
        let (elapsed, status, _) = one_request_raw(client, base, size).await?;
        values.push(elapsed);
        if status != 200 {
            errors += 1;
        }
    }
    Ok((summarize(values), errors))
}

async fn count_request_alloc(
    client: &BenchClient,
    base: &str,
    size: SizeClass,
    reps: usize,
) -> Result<(f64, f64)> {
    for _ in 0..10 {
        black_box(one_request_raw(client, base, size).await?);
    }
    alloc_start();
    for _ in 0..reps {
        black_box(one_request_raw(client, base, size).await?);
    }
    Ok(alloc_stop(reps))
}

async fn measure_concurrent(
    client: &BenchClient,
    base: &str,
    size: SizeClass,
    workers: usize,
    per_worker: usize,
) -> Result<(Stats, f64, usize)> {
    for _ in 0..10 {
        black_box(one_request_raw(client, base, size).await?);
    }
    let started = Instant::now();
    let mut handles = Vec::with_capacity(workers);
    for _ in 0..workers {
        let client = client.clone();
        let base = base.to_string();
        handles.push(tokio::spawn(async move {
            let mut values = Vec::with_capacity(per_worker);
            let mut errors = 0usize;
            for _ in 0..per_worker {
                let (elapsed, status, _) = one_request_raw(&client, &base, size).await?;
                values.push(elapsed);
                if status != 200 {
                    errors += 1;
                }
            }
            Ok::<_, anyhow::Error>((values, errors))
        }));
    }
    let mut all = Vec::with_capacity(workers * per_worker);
    let mut errors = 0usize;
    for handle in handles {
        let (values, worker_errors) = handle.await.context("worker task")??;
        all.extend(values);
        errors += worker_errors;
    }
    let elapsed = started.elapsed().as_secs_f64();
    let rps = all.len() as f64 / elapsed;
    Ok((summarize(all), rps, errors))
}

async fn run_proxy_layer(
    cli: &Cli,
    config: Config,
    layer: &'static str,
    backend: &'static str,
    alloc_reps: usize,
) -> Result<Vec<Row>> {
    let (proxy_addr, _service) = spawn_proxy(config).await?;
    let base = format!("http://{proxy_addr}");
    let client = http_client();
    let mut rows = Vec::new();

    for size in SIZES {
        let (stats, errors) =
            measure_requests(&client, &base, size, cli.requests, cli.warmup).await?;
        let (bytes, calls) = count_request_alloc(&client, &base, size, alloc_reps).await?;
        rows.push(
            Row::new(layer, backend, size.label(), stats)
                .with_alloc(bytes, calls)
                .with_errors(errors)
                .with_note("loopback client + proxy + upstream"),
        );
    }

    for size in [SizeClass::Bodyless, SizeClass::K1] {
        let (stats, rps, errors) =
            measure_concurrent(&client, &base, size, cli.concurrency, cli.per_worker).await?;
        rows.push(
            Row::new(layer, backend, size.label(), stats)
                .with_errors(errors)
                .with_note(format!(
                    "c={} throughput {:.0} req/s, non-200 {errors}",
                    cli.concurrency, rps
                )),
        );
    }

    Ok(rows)
}

// ---------------------------------------------------------------------------
// Gates and derived budget
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct GateResult {
    name: String,
    backend: String,
    size: String,
    limit: String,
    measured: String,
    passed: bool,
}

fn gate(rows: &[Row], backend: &str, size: &str, limit_ms: f64) -> GateResult {
    let row = find(rows, "L3-proxy", backend, size);
    match row {
        Some(row) => GateResult {
            name: format!("{size} p50 < {limit_ms} ms"),
            backend: backend.to_string(),
            size: size.to_string(),
            limit: format!("< {limit_ms} ms"),
            measured: format!("{:.3} ms, non-200 {}", row.stats.p50_ms, row.errors),
            passed: row.stats.p50_ms < limit_ms && row.errors == 0,
        },
        None => GateResult {
            name: format!("{size} p50 < {limit_ms} ms"),
            backend: backend.to_string(),
            size: size.to_string(),
            limit: format!("< {limit_ms} ms"),
            measured: "SKIP".to_string(),
            passed: false,
        },
    }
}

fn tail_gate(rows: &[Row], backend: &str, size: &str) -> GateResult {
    match find(rows, "L3-proxy", backend, size) {
        Some(row) => {
            let limit = row.stats.p50_ms * 2.0;
            GateResult {
                name: format!("{size} p99 <= 2x p50"),
                backend: backend.to_string(),
                size: size.to_string(),
                limit: format!("<= {limit:.3} ms"),
                measured: format!("{:.3} ms, non-200 {}", row.stats.p99_ms, row.errors),
                passed: row.stats.p99_ms <= limit && row.errors == 0,
            }
        }
        None => GateResult {
            name: format!("{size} p99 <= 2x p50"),
            backend: backend.to_string(),
            size: size.to_string(),
            limit: "<= 2x p50".to_string(),
            measured: "SKIP".to_string(),
            passed: false,
        },
    }
}

fn gate_results(rows: &[Row]) -> Vec<GateResult> {
    let mut gates = Vec::new();
    for backend in ["wasm", "native", "rust"] {
        for (size, limit) in [("bodyless", 0.5), ("1 KiB", 0.8), ("4 KiB", 1.5)] {
            gates.push(gate(rows, backend, size, limit));
        }
        for size in ["bodyless", "1 KiB", "4 KiB", "8 KiB"] {
            gates.push(tail_gate(rows, backend, size));
        }
    }
    gates
}

fn print_gates(gates: &[GateResult]) {
    println!();
    println!("## Sub-millisecond gates (full proxy, c=1)");
    println!();
    println!("| gate | backend | limit | measured | result |");
    println!("|---|---|---|---:|---|");
    for gate in gates {
        println!(
            "| {} | {} | {} | {} | {} |",
            gate.name,
            gate.backend,
            gate.limit,
            gate.measured,
            if gate.passed { "PASS" } else { "FAIL" }
        );
    }
}

fn print_budget(rows: &[Row]) {
    println!();
    println!("## Per-request overhead outside the rule engine");
    println!();
    println!(
        "| size | L0 engine wasm | L2 proxy no WAF | L3 proxy wasm | L3 - L0 (non-rule overhead) | L3 - L2 (WAF add-on) | fast-path budget (gate - L2) |"
    );
    println!("|---|---:|---:|---:|---:|---:|---:|");
    for size in SIZES {
        let label = size.label();
        let l0 = find(rows, "L0-engine", "wasm", label).map(|row| row.stats.p50_ms);
        let l2 = find(rows, "L2-proxy", "no-waf", label).map(|row| row.stats.p50_ms);
        let l3 = find(rows, "L3-proxy", "wasm", label).map(|row| row.stats.p50_ms);
        let gate = match size {
            SizeClass::Bodyless => Some(0.5),
            SizeClass::K1 => Some(0.8),
            SizeClass::K4 => Some(1.5),
            SizeClass::K8 => None,
        };
        let outside = match (l3, l0) {
            (Some(l3), Some(l0)) => format!("{:.3} ms", l3 - l0),
            _ => "-".to_string(),
        };
        let addon = match (l3, l2) {
            (Some(l3), Some(l2)) => format!("{:.3} ms", l3 - l2),
            _ => "-".to_string(),
        };
        let budget = match (gate, l2) {
            (Some(gate), Some(l2)) => {
                let value = gate - l2;
                if value >= 0.0 {
                    format!("{value:.3} ms")
                } else {
                    format!("{value:.3} ms (proxy alone over gate)")
                }
            }
            _ => "-".to_string(),
        };
        println!(
            "| {label} | {} | {} | {} | {} | {} | {} |",
            l0.map(|v| format!("{v:.3} ms"))
                .unwrap_or_else(|| "-".to_string()),
            l2.map(|v| format!("{v:.3} ms"))
                .unwrap_or_else(|| "-".to_string()),
            l3.map(|v| format!("{v:.3} ms"))
                .unwrap_or_else(|| "-".to_string()),
            outside,
            addon,
            budget
        );
    }

    println!();
    println!("### Budget against the concurrent proxy floor");
    println!();
    println!(
        "The c=1 L2 row includes client/server scheduling latency on a contended host. The c=N throughput cell keeps the runtime busy and is a better estimate of the intrinsic proxy floor."
    );
    println!();
    println!("| size | gate | L2 c=N p50 | budget (gate - L2 c=N) |");
    println!("|---|---:|---:|---:|");
    for size in [SizeClass::Bodyless, SizeClass::K1, SizeClass::K4] {
        let label = size.label();
        let gate = match size {
            SizeClass::Bodyless => 0.5,
            SizeClass::K1 => 0.8,
            SizeClass::K4 => 1.5,
            SizeClass::K8 => continue,
        };
        let floor = find_concurrent(rows, "L2-proxy", "no-waf", label).map(|row| row.stats.p50_ms);
        let budget = floor
            .map(|floor| format!("{:.3} ms", gate - floor))
            .unwrap_or_else(|| "-".to_string());
        println!(
            "| {label} | < {gate} ms | {} | {budget} |",
            floor
                .map(|v| format!("{v:.3} ms"))
                .unwrap_or_else(|| "-".to_string())
        );
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() -> Result<()> {
    let cli = Cli::parse();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("build the tokio runtime")?;

    println!("# WAF sub-millisecond budget benchmark");
    println!();
    println!("- samples per cell: {}", cli.samples);
    println!("- sequential requests per L2/L3 cell: {}", cli.requests);
    println!(
        "- throughput cell: {} workers x {} requests",
        cli.concurrency, cli.per_worker
    );
    println!("- layers: {}", cli.only);
    println!(
        "- native sidecar: {}",
        cli.native_socket
            .as_deref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "not supplied (native rows skipped)".to_string())
    );
    println!();

    let mut rows = Vec::new();

    if cli.wants("l0") {
        rows.extend(run_l0(&cli, &runtime)?);
    }
    if cli.wants("l1") {
        rows.extend(run_l1(&cli));
    }

    if cli.wants("l2") || cli.wants("l3") {
        let upstream = runtime.block_on(spawn_upstream())?;

        if cli.wants("l2") {
            let mut config = base_config(upstream, cli.eval_timeout_ms);
            config.waf.enabled = false;
            rows.extend(
                runtime
                    .block_on(run_proxy_layer(
                        &cli,
                        config,
                        "L2-proxy",
                        "no-waf",
                        cli.requests.min(50),
                    ))
                    .context("run L2 proxy layer")?,
            );
        }

        if cli.wants("l3") {
            let config = wasm_config(upstream, 4, cli.eval_timeout_ms);
            rows.extend(
                runtime
                    .block_on(run_proxy_layer(
                        &cli,
                        config,
                        "L3-proxy",
                        "wasm",
                        cli.requests.min(50),
                    ))
                    .context("run L3 wasm proxy layer")?,
            );

            #[cfg(all(feature = "coraza-native", unix))]
            if let Some(socket) = cli.native_socket.as_deref() {
                let config = native_config(upstream, socket, 4, cli.eval_timeout_ms);
                rows.extend(
                    runtime
                        .block_on(run_proxy_layer(
                            &cli,
                            config,
                            "L3-proxy",
                            "native",
                            cli.requests.min(50),
                        ))
                        .context("run L3 native proxy layer")?,
                );
            }

            #[cfg(feature = "rust-engine")]
            {
                let config = rust_config(upstream, cli.eval_timeout_ms);
                rows.extend(
                    runtime
                        .block_on(run_proxy_layer(
                            &cli,
                            config,
                            "L3-proxy",
                            "rust",
                            cli.requests.min(50),
                        ))
                        .context("run L3 rust proxy layer")?,
                );
            }
        }
    }

    print_rows(&rows);
    print_budget(&rows);
    let gates = gate_results(&rows);
    print_gates(&gates);

    if let Some(path) = cli.json_out.as_deref() {
        let payload = json!({
            "schema": 1,
            "samples": cli.samples,
            "requests": cli.requests,
            "rows": rows.iter().map(|row| json!({
                "layer": row.layer,
                "backend": row.backend,
                "size": row.size,
                "samples": row.stats.n,
                "p50_ms": row.stats.p50_ms,
                "p95_ms": row.stats.p95_ms,
                "p99_ms": row.stats.p99_ms,
                "mean_ms": row.stats.mean_ms,
                "max_ms": row.stats.max_ms,
                "alloc_bytes_per_op": row.alloc_bytes,
                "allocs_per_op": row.alloc_calls,
                "non_200": row.errors,
                "note": row.note,
            })).collect::<Vec<_>>(),
            "gates": gates.iter().map(|gate| json!({
                "name": gate.name,
                "backend": gate.backend,
                "size": gate.size,
                "limit": gate.limit,
                "measured": gate.measured,
                "passed": gate.passed,
            })).collect::<Vec<_>>(),
        });
        std::fs::write(path, serde_json::to_vec_pretty(&payload)?)
            .with_context(|| format!("write {}", path.display()))?;
        println!();
        println!("wrote {}", path.display());
    }

    Ok(())
}
