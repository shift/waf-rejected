//! Benchmark the experimental native engine kernel.
//!
//! ```sh
//! nix develop -c cargo run --release --no-default-features \
//!     --features engine-kernel --bin engine-kernel-bench
//! ```
//!
//! Reports p50/p95/p99, effective MB/s and allocations per request. Coraza
//! reference rows are the documented measurements from
//! `docs/suggestions_from_agents/crs-performance.md` (native) and
//! `docs/suggestions_from_agents/coraza-body-performance.md` (wasm). The native
//! sidecar is not built in this environment (no Go toolchain), so it is a
//! reference rather than a same-run comparison.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicU64, Ordering};

use waf_ingress::waf::engine_kernel::state::{Arena, RequestInput};
use waf_ingress::waf::engine_kernel::KernelEngine;

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
/// by other agents; CPU time still shows the kernel's own cost.
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

struct CountingAlloc;

static ALLOCATIONS: AtomicU64 = AtomicU64::new(0);
static ALLOCATED_BYTES: AtomicU64 = AtomicU64::new(0);

unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        ALLOCATED_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        System.alloc(layout)
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        System.dealloc(pointer, layout)
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        ALLOCATED_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        System.alloc_zeroed(layout)
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        ALLOCATED_BYTES.fetch_add(new_size as u64, Ordering::Relaxed);
        System.realloc(pointer, layout, new_size)
    }
}

#[global_allocator]
static GLOBAL: CountingAlloc = CountingAlloc;

struct Case {
    name: &'static str,
    method: &'static str,
    path: &'static str,
    headers: Vec<(&'static str, &'static str)>,
    body: Vec<u8>,
}

impl Case {
    fn request_bytes(&self) -> usize {
        self.method.len()
            + self.path.len()
            + self.body.len()
            + self
                .headers
                .iter()
                .map(|(name, value)| name.len() + value.len() + 4)
                .sum::<usize>()
    }

    fn evaluate(&self, engine: &KernelEngine, arena: &mut Arena) {
        let request = RequestInput::new(self.method, self.path, "", &self.headers, &self.body);
        let _ = engine.evaluate(&request, arena);
    }
}

fn form_body(bytes: usize) -> Vec<u8> {
    let mut body = Vec::with_capacity(bytes);
    body.extend_from_slice(b"data=");
    while body.len() < bytes {
        body.push(b'A');
    }
    body
}

fn cases() -> Vec<Case> {
    vec![
        Case {
            name: "bodyless GET",
            method: "GET",
            path: "/index.html",
            headers: vec![
                ("Host", "benchmark.test"),
                ("User-Agent", "Mozilla/5.0"),
                ("Accept", "text/html,application/xhtml+xml"),
            ],
            body: Vec::new(),
        },
        Case {
            name: "1 KiB form",
            method: "POST",
            path: "/submit",
            headers: vec![
                ("Host", "benchmark.test"),
                ("User-Agent", "Mozilla/5.0"),
                ("Content-Type", "application/x-www-form-urlencoded"),
            ],
            body: form_body(1024),
        },
        Case {
            name: "4 KiB form",
            method: "POST",
            path: "/submit",
            headers: vec![
                ("Host", "benchmark.test"),
                ("User-Agent", "Mozilla/5.0"),
                ("Content-Type", "application/x-www-form-urlencoded"),
            ],
            body: form_body(4096),
        },
        Case {
            name: "8 KiB form",
            method: "POST",
            path: "/submit",
            headers: vec![
                ("Host", "benchmark.test"),
                ("User-Agent", "Mozilla/5.0"),
                ("Content-Type", "application/x-www-form-urlencoded"),
            ],
            body: form_body(8192),
        },
    ]
}

struct Stats {
    p50_us: f64,
    p95_us: f64,
    p99_us: f64,
    mb_per_second: f64,
    allocations_per_request: f64,
}

fn measure(
    engine: &KernelEngine,
    arena: &mut Arena,
    case: &Case,
    warmup: usize,
    iterations: usize,
) -> Stats {
    for _ in 0..warmup {
        case.evaluate(engine, arena);
    }

    let mut samples = Vec::with_capacity(iterations);
    let started = cpu_now_ns();
    for _ in 0..iterations {
        let request_started = cpu_now_ns();
        case.evaluate(engine, arena);
        samples.push(cpu_now_ns().saturating_sub(request_started));
    }
    let elapsed = cpu_now_ns().saturating_sub(started) as f64 / 1_000_000_000.0;
    samples.sort_unstable();

    let before = ALLOCATIONS.load(Ordering::Relaxed);
    for _ in 0..iterations {
        case.evaluate(engine, arena);
    }
    let after = ALLOCATIONS.load(Ordering::Relaxed);

    Stats {
        p50_us: percentile(&samples, 50) as f64 / 1000.0,
        p95_us: percentile(&samples, 95) as f64 / 1000.0,
        p99_us: percentile(&samples, 99) as f64 / 1000.0,
        mb_per_second: (case.request_bytes() * iterations) as f64 / elapsed / 1_000_000.0,
        allocations_per_request: (after.saturating_sub(before)) as f64 / iterations as f64,
    }
}

fn percentile(sorted: &[u64], percentile: usize) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let index = (sorted.len() * percentile / 100).min(sorted.len() - 1);
    sorted[index]
}

fn main() {
    let engine = match KernelEngine::new() {
        Ok(engine) => engine,
        Err(error) => {
            eprintln!("failed to compile kernel: {error}");
            std::process::exit(1);
        }
    };
    println!(
        "kernel: {} rules, {} pipelines, {} gates",
        engine.rule_count(),
        engine.pipeline_count(),
        engine.gate_count()
    );
    println!();
    println!("| case | request bytes | p50 µs | p95 µs | p99 µs | MB/s (CPU) | alloc/req |");
    println!("|---|---:|---:|---:|---:|---:|---:|");

    let mut arena = Arena::new();
    let mut results = Vec::new();
    for case in cases() {
        let iterations = match case.body.len() {
            0 => 20_000,
            1..=1024 => 10_000,
            1025..=4096 => 5_000,
            _ => 2_000,
        };
        let stats = measure(&engine, &mut arena, &case, iterations / 10, iterations);
        println!(
            "| {} | {} | {:.2} | {:.2} | {:.2} | {:.1} | {:.2} |",
            case.name,
            case.request_bytes(),
            stats.p50_us,
            stats.p95_us,
            stats.p99_us,
            stats.mb_per_second,
            stats.allocations_per_request
        );
        results.push((case.name, stats));
    }

    println!();
    println!("## Coraza reference (documented measurements, not same-run)");
    println!();
    println!("| case | Coraza native p50 ms | Coraza wasm p50 ms | kernel p50 µs | vs native | vs wasm |");
    println!("|---|---:|---:|---:|---:|---:|");
    // Native: docs/suggestions_from_agents/crs-performance.md, p50 CPU.
    // Wasm: docs/suggestions_from_agents/coraza-body-performance.md; 4 KiB is
    // linearly interpolated between the 1 KiB and 8 KiB rows.
    let reference = [
        ("bodyless GET", 0.55, 2.65),
        ("1 KiB form", 7.92, 40.8),
        ("4 KiB form", 32.66, 165.6),
        ("8 KiB form", 60.94, 333.5),
    ];
    for ((name, native_ms, wasm_ms), (_, stats)) in reference.iter().zip(results.iter()) {
        println!(
            "| {name} | {native_ms:.2} | {wasm_ms:.1} | {:.2} | {:.0}× | {:.0}× |",
            stats.p50_us,
            native_ms * 1000.0 / stats.p50_us,
            wasm_ms * 1000.0 / stats.p50_us
        );
    }

    println!();
    println!("## Gap to sub-millisecond");
    println!();
    for (name, stats) in &results {
        let gap = if stats.p50_us < 1000.0 {
            format!("{:.0}× headroom", 1000.0 / stats.p50_us)
        } else {
            format!("{:.1}× over budget", stats.p50_us / 1000.0)
        };
        println!(
            "- {name}: p50 {:.2} µs, p99 {:.2} µs, {gap}",
            stats.p50_us, stats.p99_us
        );
    }
}
