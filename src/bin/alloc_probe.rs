//! Allocation-attribution probe for the WAF request path.
//!
//! Runs the native engine directly and through `WafEngine` with a counting
//! global allocator that also keeps a size histogram. The histogram shows
//! whether body-proportional allocations are copies of the payload.
//!
//! ```sh
//! cargo run --release --features rust-engine,engine-profile \
//!   --bin alloc_probe -- --hist
//! # one cell under perf stat -p:
//! cargo run --release --features rust-engine,engine-profile \
//!   --bin alloc_probe -- --cell 4096 --mode waf --reps 3000 --sleep-ms 4000
//! ```

use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use hyper::header::{HeaderValue, ACCEPT, CONTENT_LENGTH, CONTENT_TYPE, HOST, USER_AGENT};
use hyper::{HeaderMap, Method, Uri};

use waf_ingress::config::{Config, CorazaBackend, CorazaFallback};
use waf_ingress::waf::rust_engine::{default_crs_conf_path, EngineRequest, RustEngine};
use waf_ingress::waf::{Decision, RequestContext, WafEngine};

const BUCKETS: [usize; 11] = [
    0,
    16,
    64,
    256,
    1024,
    4096,
    8192,
    16384,
    65536,
    1 << 20,
    usize::MAX,
];

struct Probe;

static ON: AtomicBool = AtomicBool::new(false);
static BYTES: AtomicU64 = AtomicU64::new(0);
static CALLS: AtomicU64 = AtomicU64::new(0);
static BUCKET_BYTES: [AtomicU64; 11] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];
static BUCKET_CALLS: [AtomicU64; 11] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];

fn bucket(size: usize) -> usize {
    BUCKETS
        .iter()
        .position(|limit| size <= *limit)
        .unwrap_or(BUCKETS.len() - 1)
}

unsafe impl GlobalAlloc for Probe {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = System.alloc(layout);
        if !ptr.is_null() && ON.load(Ordering::Relaxed) {
            record(layout.size());
        }
        ptr
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = System.alloc_zeroed(layout);
        if !ptr.is_null() && ON.load(Ordering::Relaxed) {
            record(layout.size());
        }
        ptr
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new_ptr = System.realloc(ptr, layout, new_size);
        if !new_ptr.is_null() && ON.load(Ordering::Relaxed) {
            record(new_size);
        }
        new_ptr
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }
}

fn record(size: usize) {
    BYTES.fetch_add(size as u64, Ordering::Relaxed);
    CALLS.fetch_add(1, Ordering::Relaxed);
    #[cfg(feature = "engine-profile")]
    waf_ingress::waf::rust_engine::profile::ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
    let index = bucket(size);
    BUCKET_BYTES[index].fetch_add(size as u64, Ordering::Relaxed);
    BUCKET_CALLS[index].fetch_add(1, Ordering::Relaxed);
}

#[global_allocator]
static GLOBAL: Probe = Probe;

fn start() {
    BYTES.store(0, Ordering::Relaxed);
    CALLS.store(0, Ordering::Relaxed);
    for counter in &BUCKET_BYTES {
        counter.store(0, Ordering::Relaxed);
    }
    for counter in &BUCKET_CALLS {
        counter.store(0, Ordering::Relaxed);
    }
    ON.store(true, Ordering::Relaxed);
}

fn stop(reps: usize) -> (f64, f64) {
    ON.store(false, Ordering::Relaxed);
    (
        BYTES.load(Ordering::Relaxed) as f64 / reps as f64,
        CALLS.load(Ordering::Relaxed) as f64 / reps as f64,
    )
}

fn print_histogram(reps: usize) {
    println!("    size bucket      allocs/op       bytes/op");
    for (index, limit) in BUCKETS.iter().enumerate() {
        let calls = BUCKET_CALLS[index].load(Ordering::Relaxed) as f64 / reps as f64;
        let bytes = BUCKET_BYTES[index].load(Ordering::Relaxed) as f64 / reps as f64;
        if calls > 0.0 {
            let low = if index == 0 {
                0
            } else {
                BUCKETS[index - 1] + 1
            };
            println!("    {low:>8}..{limit:<8} {calls:>10.1} {bytes:>14.0}");
        }
    }
}

fn body(size: usize) -> Vec<u8> {
    let mut body = Vec::with_capacity(size);
    body.extend_from_slice(b"data=");
    body.resize(size, b'A');
    body
}

fn headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(HOST, HeaderValue::from_static("bench.example"));
    headers.insert(
        USER_AGENT,
        HeaderValue::from_static("waf-rejected-subms-bench/1.0"),
    );
    headers.insert(ACCEPT, HeaderValue::from_static("*/*"));
    headers
}

fn ctx(size: usize) -> RequestContext {
    let mut headers = headers();
    let body = (size > 0).then(|| body(size));
    if let Some(body) = body.as_ref() {
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        );
        headers.insert(
            CONTENT_LENGTH,
            HeaderValue::from_str(&body.len().to_string()).expect("ascii"),
        );
    }
    RequestContext::with_http_version(
        IpAddr::from([127, 0, 0, 1]),
        if size == 0 { Method::GET } else { Method::POST },
        Uri::from_static(if size == 0 { "/hello?id=42" } else { "/upload" }),
        headers,
        body.as_ref().map(Vec::len),
        "1.1",
    )
    .with_body(body.map(Bytes::from))
}

fn engine_config() -> Config {
    let mut config = Config::default();
    config.waf.rate_limit.per_ip_enabled = false;
    config.waf.rate_limit.global_enabled = false;
    config.waf.coraza.backend = CorazaBackend::Rust;
    config.waf.coraza.fallback = CorazaFallback::None;
    config.waf.coraza.eval_timeout_ms = 120_000;
    config
}

fn engine_request(size: usize) -> (Vec<(String, String)>, Vec<u8>) {
    let request_body = (size > 0).then(|| body(size)).unwrap_or_default();
    let header_pairs: Vec<(String, String)> = headers()
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_string(),
                value.to_str().unwrap_or("").to_string(),
            )
        })
        .collect();
    (header_pairs, request_body)
}

fn arg(name: &str) -> Option<String> {
    let mut args = std::env::args();
    while let Some(value) = args.next() {
        if value == name {
            return args.next();
        }
    }
    None
}

fn flag(name: &str) -> bool {
    std::env::args().any(|value| value == name)
}

fn main() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");

    let engine = RustEngine::from_conf_path_with_policy(
        default_crs_conf_path(),
        waf_ingress::waf::rust_engine::CompilePolicy::Report,
    )
    .expect("compile rust engine");

    if let Some(cell) = arg("--cell") {
        let size: usize = cell.parse().expect("cell size");
        let reps: usize = arg("--reps")
            .unwrap_or_else(|| "200".into())
            .parse()
            .unwrap();
        let mode = arg("--mode").unwrap_or_else(|| "waf".into());
        let sleep_ms: u64 = arg("--sleep-ms")
            .unwrap_or_else(|| "0".into())
            .parse()
            .unwrap();
        let header_pairs = engine_request(size).0;
        let request_body = engine_request(size).1;
        let request = EngineRequest {
            method: if size == 0 { "GET" } else { "POST" },
            uri: if size == 0 { "/hello?id=42" } else { "/upload" },
            http_version: "HTTP/1.1",
            headers: &header_pairs,
            body: (size > 0).then_some(request_body.as_slice()),
        };
        let request_ctx = ctx(size);
        let waf = WafEngine::with_config_and_metrics(&engine_config(), None);
        if let Some(error) = waf.waf_init_error() {
            panic!("engine init: {error}");
        }
        let warmup = if size >= 1 << 20 { 1 } else { 5 };
        for _ in 0..warmup {
            if mode == "direct" {
                black_box(engine.evaluate(&request));
            } else {
                black_box(runtime.block_on(waf.evaluate(&request_ctx)));
            }
        }
        if sleep_ms > 0 {
            println!("READY pid={}", std::process::id());
            std::thread::sleep(Duration::from_millis(sleep_ms));
        }
        start();
        let mut blocked = 0usize;
        for _ in 0..reps {
            let decision = if mode == "direct" {
                engine.evaluate(&request)
            } else {
                runtime.block_on(waf.evaluate(&request_ctx))
            };
            if !matches!(decision, Decision::Allow) {
                blocked += 1;
            }
            black_box(decision);
        }
        let (bytes, calls) = stop(reps);
        println!(
            "cell={size} mode={mode} reps={reps} allocs={calls:.2} bytes={bytes:.0} blocked={blocked}"
        );
        return;
    }

    let sizes = [0usize, 1024, 4096, 8192, 10 * 1024 * 1024];
    let hist = flag("--hist");

    println!("== direct RustEngine::evaluate ==");
    for size in sizes {
        let (header_pairs, request_body) = engine_request(size);
        let request = EngineRequest {
            method: if size == 0 { "GET" } else { "POST" },
            uri: if size == 0 { "/hello?id=42" } else { "/upload" },
            http_version: "HTTP/1.1",
            headers: &header_pairs,
            body: (size > 0).then_some(request_body.as_slice()),
        };
        for _ in 0..3 {
            black_box(engine.evaluate(&request));
        }
        let reps = if size >= 1 << 20 { 2 } else { 20 };
        start();
        for _ in 0..reps {
            black_box(engine.evaluate(&request));
        }
        let (bytes, calls) = stop(reps);
        println!("  {size:>9} B: {calls:.1} allocs/op, {bytes:.0} B/op");
        #[cfg(feature = "engine-profile")]
        {
            start();
            let (_, report) = engine.evaluate_profiled(&request);
            ON.store(false, Ordering::Relaxed);
            println!(
                "    profile allocs: parse={} xform={} cand={} gate={} op={} score={} cap={} tx={} matched={} total={}",
                report.parse_allocs,
                report.transforms_allocs,
                report.candidates_allocs,
                report.gate_allocs,
                report.operators_allocs,
                report.scoring_allocs,
                report.captures_allocs,
                report.tx_allocs,
                report.matched_allocs,
                report.total_allocs
            );
        }
        if hist {
            print_histogram(reps);
        }
    }

    println!("== WafEngine::evaluate (rust backend) ==");
    for content_inspection in [true, false] {
        let mut config = engine_config();
        config.waf.content_inspection.enabled = content_inspection;
        let waf = WafEngine::with_config_and_metrics(&config, None);
        if let Some(error) = waf.waf_init_error() {
            panic!("engine init: {error}");
        }
        println!("-- content_inspection = {content_inspection}");
        for size in sizes {
            let request = ctx(size);
            for _ in 0..3 {
                black_box(runtime.block_on(waf.evaluate(&request)));
            }
            let reps = if size >= 1 << 20 { 2 } else { 20 };
            start();
            for _ in 0..reps {
                let decision = runtime.block_on(waf.evaluate(&request));
                if !matches!(decision, Decision::Allow) {
                    println!("    decision: {decision:?}");
                }
                black_box(decision);
            }
            let (bytes, calls) = stop(reps);
            println!("  {size:>9} B: {calls:.1} allocs/op, {bytes:.0} B/op");
            if hist {
                print_histogram(reps);
            }
        }
    }
}
