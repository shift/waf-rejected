//! Reproducible engine-level benchmark for the performance regression gate.
//!
//! Measures the three request engines behind the same synthetic request set:
//!
//! * `coraza` — the Coraza WASI reactor on wasmtime. The JSON payload is built
//!   once per case and only `WasmReactor::evaluate` is timed, matching the
//!   `L0-reactor` row in `bench-subms`. Payload construction is deliberately
//!   excluded so the row tracks the rule engine, not the envelope.
//! * `rust` — the native Rust CRS engine (`RustEngine::evaluate`).
//! * `kernel` — the experimental native evaluation kernel
//!   (`KernelEngine::evaluate`).
//!
//! Every row reports p50/p95/p99, mean, throughput, host allocations per
//! operation and the decision. Process RSS and the CPU affinity mask are
//! recorded in `meta`. Run one backend per process (`--only`) to keep RSS
//! attributable; `benchmarks/perf-gate/run.sh` does that and merges the rows.
//!
//! ```sh
//! nix develop -c cargo run --release \
//!   --features wasm-reactor,rust-engine,engine-kernel \
//!   --bin perf-gate-bench -- --only coraza --json-out /tmp/coraza.json
//! ```

use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

use anyhow::{Context, Result};
use bytes::Bytes;
use clap::{Parser, ValueEnum};
use hyper::header::HeaderValue;
use hyper::{HeaderMap, Method, Uri};
use serde_json::json;

use waf_ingress::waf::coraza_payload::{
    build_payload_with_policy, BodyInspectionPolicy, PayloadBuild,
};
use waf_ingress::waf::wasm_reactor::{ReactorLimits, WasmReactor};

#[repr(C)]
struct Timespec {
    tv_sec: i64,
    tv_nsec: i64,
}

extern "C" {
    fn clock_gettime(clock_id: i32, time: *mut Timespec) -> i32;
}

const CLOCK_PROCESS_CPUTIME_ID: i32 = 2;

/// Process CPU time. Wall-clock timings on the shared build host are dominated
/// by other agents; CPU time still shows the engine's own cost.
fn cpu_now_ns() -> u64 {
    let mut time = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `time` is a valid, writable `timespec`.
    unsafe {
        clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &mut time);
    }
    (time.tv_sec as u64) * 1_000_000_000 + time.tv_nsec as u64
}

#[cfg(feature = "rust-engine")]
use waf_ingress::waf::rust_engine::{
    default_crs_conf_path, CompilePolicy, EngineRequest, RustEngine,
};

#[cfg(feature = "engine-kernel")]
use waf_ingress::waf::engine_kernel::state::{Arena, RequestInput};
#[cfg(feature = "engine-kernel")]
use waf_ingress::waf::engine_kernel::KernelEngine;

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
// CLI and cases
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Backend {
    Coraza,
    Rust,
    Kernel,
}

#[derive(Debug, Parser)]
#[command(
    name = "perf-gate-bench",
    about = "Engine-level benchmark for the WAF performance regression gate"
)]
struct Cli {
    /// Backend to measure. Run one per process for attributable RSS.
    #[arg(long, value_enum, default_value_t = Backend::Coraza)]
    only: Backend,

    /// Timed samples per case.
    #[arg(long, default_value_t = 50)]
    samples: usize,

    /// Warm-up iterations per case (excluded from stats).
    #[arg(long, default_value_t = 5)]
    warmup: usize,

    /// Iterations used for the allocation counter.
    #[arg(long, default_value_t = 50)]
    alloc_reps: usize,

    /// Coraza reactor module. Defaults to the committed module.
    #[arg(long)]
    wasm: Option<PathBuf>,

    /// Write the report as JSON.
    #[arg(long)]
    json_out: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy)]
enum CaseKind {
    Bodyless,
    Allow4k,
    Sqli4k,
}

impl CaseKind {
    fn label(self) -> &'static str {
        match self {
            Self::Bodyless => "bodyless",
            Self::Allow4k => "4k-allow",
            Self::Sqli4k => "4k-sqli",
        }
    }
}

struct Case {
    kind: CaseKind,
    method: &'static str,
    uri: &'static str,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

fn form_body(payload: &[u8], size: usize) -> Vec<u8> {
    let mut body = Vec::with_capacity(size);
    body.extend_from_slice(b"data=");
    body.extend_from_slice(payload);
    while body.len() < size {
        body.push(b'A');
    }
    body
}

fn cases() -> Vec<Case> {
    let base_headers = |content_type: Option<&str>, body_len: usize| {
        let mut headers = vec![
            ("Host".to_string(), "benchmark.test".to_string()),
            ("User-Agent".to_string(), "Mozilla/5.0".to_string()),
            (
                "Accept".to_string(),
                "text/html,application/xhtml+xml".to_string(),
            ),
        ];
        if let Some(value) = content_type {
            headers.push(("Content-Type".to_string(), value.to_string()));
            headers.push(("Content-Length".to_string(), body_len.to_string()));
        }
        headers
    };

    vec![
        Case {
            kind: CaseKind::Bodyless,
            method: "GET",
            uri: "/index.html",
            headers: base_headers(None, 0),
            body: Vec::new(),
        },
        Case {
            kind: CaseKind::Allow4k,
            method: "POST",
            uri: "/submit",
            headers: base_headers(Some("application/x-www-form-urlencoded"), 4096),
            body: form_body(b"", 4096),
        },
        Case {
            kind: CaseKind::Sqli4k,
            method: "POST",
            uri: "/submit",
            headers: base_headers(Some("application/x-www-form-urlencoded"), 4096),
            body: form_body(b"1+union+select+password+from+users", 4096),
        },
    ]
}

// ---------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------

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

fn measure<F, T>(samples: usize, warmup: usize, mut op: F) -> (Stats, f64)
where
    F: FnMut() -> T,
{
    for _ in 0..warmup {
        black_box(op());
    }
    let mut values = Vec::with_capacity(samples);
    let started = Instant::now();
    for _ in 0..samples {
        let call_started = cpu_now_ns();
        black_box(op());
        values.push(cpu_now_ns().saturating_sub(call_started));
    }
    let elapsed = started.elapsed().as_secs_f64();
    let throughput = if elapsed > 0.0 {
        samples as f64 / elapsed
    } else {
        0.0
    };
    (summarize(values), throughput)
}

fn measure_alloc<F, T>(reps: usize, mut op: F) -> (f64, f64)
where
    F: FnMut() -> T,
{
    alloc_start();
    for _ in 0..reps {
        black_box(op());
    }
    alloc_stop(reps)
}

// ---------------------------------------------------------------------------
// Process metadata
// ---------------------------------------------------------------------------

fn proc_status_kb(key: &str) -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix(key) {
            let value = rest.trim().trim_end_matches(" kB").trim();
            return value.parse().ok();
        }
    }
    None
}

fn cpus_allowed() -> String {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Cpus_allowed_list:") {
            return rest.trim().to_string();
        }
    }
    "unknown".to_string()
}

// ---------------------------------------------------------------------------
// Backends
// ---------------------------------------------------------------------------

fn run_coraza(cli: &Cli) -> Result<Vec<serde_json::Value>> {
    let path = cli.wasm.clone().unwrap_or_else(|| {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("wasm/coraza_reactor/coraza_reactor.wasm")
    });
    let bytes = std::fs::read(&path)
        .with_context(|| format!("read Coraza reactor module {}", path.display()))?;
    let mut limits = ReactorLimits::coraza();
    limits.pool_size = 1;
    let reactor = WasmReactor::from_coraza_bytes_with_limits(&bytes, limits)
        .context("compile Coraza reactor")?;
    reactor.warm().context("warm Coraza reactor")?;

    let policy = BodyInspectionPolicy::default();
    let mut rows = Vec::new();
    for case in cases() {
        let mut headers = HeaderMap::new();
        for (name, value) in &case.headers {
            headers.insert(
                hyper::header::HeaderName::from_bytes(name.as_bytes())?,
                HeaderValue::from_str(value)?,
            );
        }
        let body = if case.body.is_empty() {
            None
        } else {
            Some(Bytes::from(case.body.clone()))
        };
        let ctx = waf_ingress::waf::RequestContext::new(
            "127.0.0.1".parse::<IpAddr>()?,
            Method::from_bytes(case.method.as_bytes())?,
            case.uri.parse::<Uri>()?,
            headers,
            body.as_ref().map(Bytes::len),
        )
        .with_body(body);
        let payload = match build_payload_with_policy(&ctx, &policy)? {
            PayloadBuild::Built { payload, .. } => payload,
            PayloadBuild::Reject { .. } => anyhow::bail!("body policy rejected the benchmark case"),
        };

        let (stats, throughput) = measure(cli.samples, cli.warmup, || reactor.evaluate(&payload));
        let (alloc_bytes, alloc_calls) =
            measure_alloc(cli.alloc_reps, || reactor.evaluate(&payload));
        let decision = match reactor.evaluate(&payload) {
            Ok(waf_ingress::waf::wasm_reactor::ReactorDecision::Allow) => "allow",
            Ok(waf_ingress::waf::wasm_reactor::ReactorDecision::Block { .. }) => "block",
            Err(_) => "error",
        };
        rows.push(row_json(
            "coraza",
            case.kind,
            stats,
            throughput,
            alloc_bytes,
            alloc_calls,
            decision,
        ));
    }
    Ok(rows)
}

#[cfg(feature = "rust-engine")]
fn run_rust(cli: &Cli) -> Result<Vec<serde_json::Value>> {
    let engine =
        RustEngine::from_conf_path_with_policy(default_crs_conf_path(), CompilePolicy::Report)
            .context("compile the Rust CRS engine")?;
    let mut rows = Vec::new();
    for case in cases() {
        let request = EngineRequest {
            method: case.method,
            uri: case.uri,
            http_version: "HTTP/1.1",
            headers: &case.headers,
            body: if case.body.is_empty() {
                None
            } else {
                Some(&case.body)
            },
        };
        let (stats, throughput) = measure(cli.samples, cli.warmup, || engine.evaluate(&request));
        let (alloc_bytes, alloc_calls) =
            measure_alloc(cli.alloc_reps, || engine.evaluate(&request));
        let decision = match engine.evaluate(&request) {
            waf_ingress::waf::Decision::Allow => "allow",
            waf_ingress::waf::Decision::Block { .. } => "block",
            waf_ingress::waf::Decision::RateLimit { .. } => "rate-limit",
        };
        rows.push(row_json(
            "rust",
            case.kind,
            stats,
            throughput,
            alloc_bytes,
            alloc_calls,
            decision,
        ));
    }
    Ok(rows)
}

#[cfg(not(feature = "rust-engine"))]
fn run_rust(_cli: &Cli) -> Result<Vec<serde_json::Value>> {
    anyhow::bail!("perf-gate-bench was built without the `rust-engine` feature")
}

#[cfg(feature = "engine-kernel")]
fn run_kernel(cli: &Cli) -> Result<Vec<serde_json::Value>> {
    let engine = KernelEngine::new().map_err(anyhow::Error::msg)?;
    let mut arena = Arena::new();
    let mut rows = Vec::new();
    for case in cases() {
        let headers: Vec<(&str, &str)> = case
            .headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect();
        let request = RequestInput::new(case.method, case.uri, "", &headers, &case.body);
        let (stats, throughput) = measure(cli.samples, cli.warmup, || {
            engine.evaluate(&request, &mut arena)
        });
        let (alloc_bytes, alloc_calls) =
            measure_alloc(cli.alloc_reps, || engine.evaluate(&request, &mut arena));
        let decision = if engine.evaluate(&request, &mut arena).is_block() {
            "block"
        } else {
            "allow"
        };
        rows.push(row_json(
            "kernel",
            case.kind,
            stats,
            throughput,
            alloc_bytes,
            alloc_calls,
            decision,
        ));
    }
    Ok(rows)
}

#[cfg(not(feature = "engine-kernel"))]
fn run_kernel(_cli: &Cli) -> Result<Vec<serde_json::Value>> {
    anyhow::bail!("perf-gate-bench was built without the `engine-kernel` feature")
}

fn row_json(
    backend: &str,
    kind: CaseKind,
    stats: Stats,
    throughput: f64,
    alloc_bytes: f64,
    alloc_calls: f64,
    decision: &str,
) -> serde_json::Value {
    json!({
        "backend": backend,
        "case": kind.label(),
        "samples": stats.n,
        "p50_ms": stats.p50_ms,
        "p95_ms": stats.p95_ms,
        "p99_ms": stats.p99_ms,
        "mean_ms": stats.mean_ms,
        "max_ms": stats.max_ms,
        "throughput_rps": throughput,
        "alloc_bytes_per_op": alloc_bytes,
        "allocs_per_op": alloc_calls,
        "decision": decision,
    })
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let rows = match cli.only {
        Backend::Coraza => run_coraza(&cli)?,
        Backend::Rust => run_rust(&cli)?,
        Backend::Kernel => run_kernel(&cli)?,
    };

    let report = json!({
        "schema": 1,
        "backend": format!("{:?}", cli.only).to_lowercase(),
        "samples": cli.samples,
        "warmup": cli.warmup,
        "alloc_reps": cli.alloc_reps,
        "meta": {
            "cpus_allowed": cpus_allowed(),
            "rss_kb": proc_status_kb("VmRSS:"),
            "rss_peak_kb": proc_status_kb("VmHWM:"),
            "target_os": std::env::consts::OS,
            "target_arch": std::env::consts::ARCH,
        },
        "rows": rows,
    });

    println!("{}", serde_json::to_string_pretty(&report)?);
    if let Some(path) = cli.json_out.as_deref() {
        std::fs::write(path, serde_json::to_vec_pretty(&report)?)
            .with_context(|| format!("write {}", path.display()))?;
    }
    Ok(())
}
