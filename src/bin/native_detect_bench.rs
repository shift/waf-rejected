//! Latency and allocation benchmark for the native `detect_sqli` / `detect_xss`
//! operators.
//!
//! ```text
//! cargo run --release --features native-detect --bin native_detect_bench
//! ```
//!
//! Reports p50/p99 for 1, 4 and 8 KiB bodies (benign and attack), throughput in
//! MB/s, and the number of heap allocations performed per evaluation. The
//! allocation counter is the point of the exercise: these operators sit on the
//! sub-millisecond request path, so a single heap allocation per call would be
//! a regression.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use waf_ingress::waf::native_detect::{detect_sqli, detect_xss};

struct CountingAllocator;

static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

// SAFETY: delegates every operation to the system allocator and only adds a
// counter, which cannot affect pointer validity or layout.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        System.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

const BENIGN: &str =
    "The quick brown fox jumps over the lazy dog. name=alice&city=paris&page=2&sort=asc ";
const ATTACK: &str = "1' OR '1'='1 <script>alert(1)</script> <img src=x onerror=alert(1)> ";

fn body(pattern: &str, size: usize) -> String {
    let mut out = String::with_capacity(size + pattern.len());
    while out.len() < size {
        out.push_str(pattern);
    }
    out.truncate(size);
    // Keep the body valid UTF-8; the patterns are ASCII so truncation is safe.
    out
}

fn percentile(samples: &[Duration], p: f64) -> Duration {
    if samples.is_empty() {
        return Duration::ZERO;
    }
    let idx = ((samples.len() - 1) as f64 * p) as usize;
    samples[idx]
}

fn measure(body: &str) -> (Duration, Duration, f64, usize) {
    const WARMUP: usize = 200;
    const REPS: usize = 2000;

    for _ in 0..WARMUP {
        std::hint::black_box(detect_sqli(std::hint::black_box(body)));
        std::hint::black_box(detect_xss(std::hint::black_box(body)));
    }

    let mut samples = Vec::with_capacity(REPS);
    for _ in 0..REPS {
        let start = Instant::now();
        std::hint::black_box(detect_sqli(std::hint::black_box(body)));
        std::hint::black_box(detect_xss(std::hint::black_box(body)));
        samples.push(start.elapsed());
    }
    samples.sort_unstable();

    let before = ALLOCATIONS.load(Ordering::Relaxed);
    for _ in 0..REPS {
        std::hint::black_box(detect_sqli(std::hint::black_box(body)));
        std::hint::black_box(detect_xss(std::hint::black_box(body)));
    }
    let allocations = (ALLOCATIONS.load(Ordering::Relaxed) - before) / (REPS * 2);

    let p50 = percentile(&samples, 0.50);
    let p99 = percentile(&samples, 0.99);
    let mbps = body.len() as f64 / p50.as_secs_f64() / (1024.0 * 1024.0);
    (p50, p99, mbps, allocations)
}

fn main() {
    println!(
        "{:>6}  {:<8}  {:>10}  {:>10}  {:>10}  {:>8}  {:>6}",
        "body", "input", "p50", "p99", "MB/s", "alloc/op", "hit"
    );
    for size in [1024usize, 4096, 8192] {
        for (name, pattern) in [("benign", BENIGN), ("attack", ATTACK)] {
            let value = body(pattern, size);
            let (p50, p99, mbps, allocations) = measure(&value);
            let hit = detect_sqli(&value) || detect_xss(&value);
            println!(
                "{:>6}  {:<8}  {:>10.2?}  {:>10.2?}  {:>10.1}  {:>8}  {:>6}",
                size, name, p50, p99, mbps, allocations, hit
            );
        }
    }
}
