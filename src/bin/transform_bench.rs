//! Latency and allocation harness for the shared transform pipeline and the
//! CRS prefilter that uses it.
//!
//! ```text
//! nix develop -c cargo run --release --features crs-prefilter,coraza-native \
//!   --bin transform-bench
//! ```
//!
//! The harness measures the production entry points:
//!
//! * `evaluate_inputs` — the `Gated` mode scan (never exits early), and
//! * `evaluate_with_cache` — the body-withhold scan (exits on the first hit).
//!
//! For each body size it compares the embedded artifact ("all transforms")
//! with a copy of the same artifact whose rule transform chains were removed
//! ("no rule transforms"). The four body-processor extraction variants
//! (`identity`, `urlDecode`, `jsonUnescape`, `htmlEntityDecode`) are present in
//! both, so the delta is the transform chain cost.
//!
//! Allocations are counted with a global allocator over the measured loop;
//! warm-up calls are excluded so the per-thread arena has already grown.

use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::sync::atomic::{AtomicU64, Ordering};

use waf_ingress::waf::prefilter::{Prefilter, EMBEDDED_ARTIFACT};
use waf_ingress::waf::prefilter_extract::PrefilterArtifact;
use waf_ingress::waf::transforms::{Transform, TransformCache};

struct CountingAllocator;

static ALLOCATIONS: AtomicU64 = AtomicU64::new(0);

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

const SIZES: [usize; 3] = [1024, 4096, 8192];
const REPETITIONS: usize = 300;
const WARMUP: usize = 32;

#[derive(Clone, Copy)]
enum Variant {
    Plain,
    PercentEncoded,
    DoubleEncoded,
}

impl Variant {
    fn name(self) -> &'static str {
        match self {
            Self::Plain => "plain",
            Self::PercentEncoded => "percent",
            Self::DoubleEncoded => "double",
        }
    }

    fn body(self, size: usize) -> Vec<u8> {
        match self {
            Self::Plain => {
                let seed = b"name=alice&city=paris&note=the+quick+brown+fox";
                seed.iter().copied().cycle().take(size).collect()
            }
            Self::PercentEncoded => b"%41".iter().copied().cycle().take(size).collect(),
            Self::DoubleEncoded => b"%2541".iter().copied().cycle().take(size).collect(),
        }
    }
}

#[repr(C)]
struct Timespec {
    tv_sec: i64,
    tv_nsec: i64,
}

extern "C" {
    fn clock_gettime(clock_id: i32, time: *mut Timespec) -> i32;
}

const CLOCK_PROCESS_CPUTIME_ID: i32 = 2;

/// Process CPU time. The shared build host is heavily loaded, so wall-clock
/// p50s mix in scheduling delays; CPU time isolates the work under test.
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

fn percentile(sorted: &[u64], percentile: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let index = ((sorted.len() as f64 - 1.0) * percentile).round() as usize;
    sorted[index]
}

fn micros(ns: u64) -> f64 {
    ns as f64 / 1_000.0
}

fn main() {
    let embedded = Prefilter::embedded().expect("embedded prefilter artifact");

    let mut artifact: PrefilterArtifact =
        serde_json::from_str(EMBEDDED_ARTIFACT).expect("artifact parses");
    for rule in &mut artifact.rules {
        rule.transforms.clear();
        for group in &mut rule.literal_groups {
            group.transforms.clear();
        }
    }
    let no_transforms = Prefilter::from_artifact(artifact).expect("transform-free artifact");

    println!("# Transform pipeline / CRS prefilter benchmark");
    println!(
        "# automata: all transforms = {}, no rule transforms = {}",
        embedded.automaton_count(),
        no_transforms.automaton_count()
    );
    println!(
        "# chain prefixes: all transforms = {}, no rule transforms = {}",
        embedded.prefix_count(),
        no_transforms.prefix_count()
    );
    println!("# reps = {REPETITIONS}, warm-up = {WARMUP}, one input value per call");
    println!();
    println!(
        "{:<6} {:<8} {:<18} {:>10} {:>10} {:>10} {:>9} {:>6}",
        "size", "variant", "pipeline", "p50_us", "p99_us", "allocs", "scannedKiB", "hit"
    );

    let mut scratch = TransformCache::new();
    for size in SIZES {
        for variant in [
            Variant::Plain,
            Variant::PercentEncoded,
            Variant::DoubleEncoded,
        ] {
            let body = variant.body(size);
            for (label, prefilter) in [
                ("all-transforms", embedded),
                ("no-transforms", &no_transforms),
            ] {
                // Gated-mode scan: every group and input, no early exit.
                for _ in 0..WARMUP {
                    black_box(prefilter.evaluate_inputs(&[body.as_slice()]));
                }
                let before = ALLOCATIONS.load(Ordering::Relaxed);
                let mut samples = Vec::with_capacity(REPETITIONS);
                let mut hit = false;
                let mut scanned = 0usize;
                for _ in 0..REPETITIONS {
                    let started = cpu_now_ns();
                    let gate = black_box(prefilter.evaluate_inputs(&[black_box(body.as_slice())]));
                    samples.push(cpu_now_ns().saturating_sub(started));
                    hit |= !gate.matched_rules.is_empty();
                    scanned = gate.scanned_bytes;
                }
                let allocations = ALLOCATIONS.load(Ordering::Relaxed) - before;
                samples.sort_unstable();
                println!(
                    "{:<6} {:<8} {:<18} {:>10.2} {:>10.2} {:>10.2} {:>9.1} {:>6}",
                    format!("{}KiB", size / 1024),
                    variant.name(),
                    label,
                    micros(percentile(&samples, 0.50)),
                    micros(percentile(&samples, 0.99)),
                    allocations as f64 / REPETITIONS as f64,
                    scanned as f64 / 1024.0,
                    hit
                );
            }

            // Union-automaton cost on the raw body only (no transforms).
            for _ in 0..WARMUP {
                black_box(embedded.scan_bytes_for_bench(body.as_slice()));
            }
            let mut samples = Vec::with_capacity(REPETITIONS);
            for _ in 0..REPETITIONS {
                let started = cpu_now_ns();
                black_box(embedded.scan_bytes_for_bench(black_box(body.as_slice())));
                samples.push(cpu_now_ns().saturating_sub(started));
            }
            samples.sort_unstable();
            println!(
                "{:<6} {:<8} {:<18} {:>10.2} {:>10.2} {:>10.2} {:>9.1} {:>6}",
                format!("{}KiB", size / 1024),
                variant.name(),
                "scan-only",
                micros(percentile(&samples, 0.50)),
                micros(percentile(&samples, 0.99)),
                0.0,
                body.len() as f64 / 1024.0,
                ""
            );

            // Body-withhold scan: early exit on the first hit, reusable cache.
            for _ in 0..WARMUP {
                black_box(embedded.evaluate_with_cache(body.as_slice(), &mut scratch));
            }
            let before = ALLOCATIONS.load(Ordering::Relaxed);
            let mut samples = Vec::with_capacity(REPETITIONS);
            let mut scanned = 0usize;
            for _ in 0..REPETITIONS {
                let started = cpu_now_ns();
                let hit = black_box(
                    embedded.evaluate_with_cache(black_box(body.as_slice()), &mut scratch),
                );
                samples.push(cpu_now_ns().saturating_sub(started));
                scanned = hit.scanned_bytes;
            }
            let allocations = ALLOCATIONS.load(Ordering::Relaxed) - before;
            samples.sort_unstable();
            println!(
                "{:<6} {:<8} {:<18} {:>10.2} {:>10.2} {:>10.2} {:>9.1} {:>6}",
                format!("{}KiB", size / 1024),
                variant.name(),
                "body-withhold",
                micros(percentile(&samples, 0.50)),
                micros(percentile(&samples, 0.99)),
                allocations as f64 / REPETITIONS as f64,
                scanned as f64 / 1024.0,
                ""
            );
        }
    }

    // Per-transform cost on the 4 KiB plain body: isolates the expensive
    // byte loops from the arena, cache and automaton work.
    println!();
    println!("# Single transform on 4 KiB plain body");
    println!(
        "{:<6} {:<8} {:<18} {:>10} {:>10}",
        "size", "variant", "transform", "p50_us", "p99_us"
    );
    let body = Variant::Plain.body(4096);
    let amp_body: Vec<u8> = b"&city=paris".iter().copied().cycle().take(4096).collect();
    for (label, body) in [("plain", &body), ("amp", &amp_body)] {
        for step in [
            Transform::HtmlEntityDecode,
            Transform::UrlDecode,
            Transform::UrlDecodeUni,
            Transform::CompressWhitespace,
            Transform::RemoveWhitespace,
            Transform::Lowercase,
            Transform::CmdLine,
        ] {
            let mut output = Vec::new();
            for _ in 0..WARMUP {
                step.apply_into(body, &mut output);
            }
            let mut samples = Vec::with_capacity(REPETITIONS);
            for _ in 0..REPETITIONS {
                let started = cpu_now_ns();
                step.apply_into(black_box(body), &mut output);
                samples.push(cpu_now_ns().saturating_sub(started));
            }
            samples.sort_unstable();
            println!(
                "{:<6} {:<8} {:<18} {:>10.2} {:>10.2}",
                "4KiB",
                label,
                format!("{step:?}"),
                micros(percentile(&samples, 0.50)),
                micros(percentile(&samples, 0.99))
            );
        }
    }

    // Pipeline-only cost: one long CRS chain applied to one value. This
    // isolates the transform work from the automaton scans and shows the
    // no-op aliasing (unchanged steps share their parent's arena bytes).
    println!();
    println!(
        "# Pipeline-only: urlDecodeUni,htmlEntityDecode,jsDecode,cssDecode,removeNulls,lowercase"
    );
    let steps = [
        Transform::UrlDecodeUni,
        Transform::HtmlEntityDecode,
        Transform::JsDecode,
        Transform::CssDecode,
        Transform::RemoveNulls,
        Transform::Lowercase,
    ];
    let mut prefixes: Vec<Vec<Transform>> = vec![Vec::new()];
    let mut plan = Vec::new();
    for step in steps {
        let mut next = prefixes.last().expect("prefix").clone();
        next.push(step);
        prefixes.push(next);
        plan.push((prefixes.len() - 1) as u32);
    }
    println!(
        "{:<6} {:<8} {:<18} {:>10} {:>10} {:>10} {:>9} {:>6}",
        "size", "variant", "pipeline", "p50_us", "p99_us", "allocs", "outKiB", "changed"
    );
    for size in SIZES {
        for variant in [
            Variant::Plain,
            Variant::PercentEncoded,
            Variant::DoubleEncoded,
        ] {
            let body = variant.body(size);
            for _ in 0..WARMUP {
                scratch.begin_request(prefixes.len());
                let value = scratch.begin_value(&body).expect("fits");
                black_box(
                    scratch
                        .resolve(value, &body, &plan, &prefixes)
                        .expect("resolves"),
                );
            }
            let before = ALLOCATIONS.load(Ordering::Relaxed);
            let mut samples = Vec::with_capacity(REPETITIONS);
            let mut output_len = 0usize;
            for _ in 0..REPETITIONS {
                scratch.begin_request(prefixes.len());
                let value = scratch.begin_value(black_box(&body)).expect("fits");
                let started = cpu_now_ns();
                let range = scratch
                    .resolve(value, &body, &plan, &prefixes)
                    .expect("resolves");
                samples.push(cpu_now_ns().saturating_sub(started));
                output_len = scratch.bytes(range).len();
            }
            let allocations = ALLOCATIONS.load(Ordering::Relaxed) - before;
            samples.sort_unstable();
            println!(
                "{:<6} {:<8} {:<18} {:>10.2} {:>10.2} {:>10.2} {:>9.1} {:>6}",
                format!("{}KiB", size / 1024),
                variant.name(),
                "long-chain",
                micros(percentile(&samples, 0.50)),
                micros(percentile(&samples, 0.99)),
                allocations as f64 / REPETITIONS as f64,
                output_len as f64 / 1024.0,
                output_len != body.len()
            );
        }
    }
}
