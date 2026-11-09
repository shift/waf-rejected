//! Prototype benchmark: serial vs parallel ARGS candidate evaluation.
//!
//! ```text
//! nix develop -c cargo run --release \
//!   --features rust-engine,native-detect,parallel-args \
//!   --bin parallel-args-bench -- --samples 200
//! ```
//!
//! Reports p50/p99 wall latency and per-request process CPU time for
//! single-argument and multi-argument URLENCODED bodies at 1, 4 and 8 KiB.
//! The parallel path is the scoped-thread prototype from
//! `waf::rust_engine::parallel_args` (thread creation included), so the table
//! is a lower bound on the benefit of a persistent pool.

use std::hint::black_box;
use std::time::Instant;

use waf_ingress::waf::rust_engine::parallel_args::{default_threads, ArgsParallelConfig};
use waf_ingress::waf::rust_engine::{
    default_crs_conf_path, CompilePolicy, EngineRequest, RustEngine,
};

#[repr(C)]
struct Timespec {
    tv_sec: i64,
    tv_nsec: i64,
}

extern "C" {
    fn clock_gettime(clock_id: i32, time: *mut Timespec) -> i32;
}

const CLOCK_PROCESS_CPUTIME_ID: i32 = 2;

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

fn engine(threads: Option<usize>) -> RustEngine {
    let engine =
        RustEngine::from_conf_path_with_policy(default_crs_conf_path(), CompilePolicy::Report)
            .expect("pinned CRS bundle must compile in report mode");
    match threads {
        Some(threads) => engine.with_parallel_args(ArgsParallelConfig {
            threads,
            min_candidates: 2,
        }),
        None => engine,
    }
}

fn body(size: usize, args: usize, payload: &str) -> Vec<u8> {
    let mut body = Vec::with_capacity(size);
    let chunk = size / args;
    for index in 0..args {
        if index > 0 {
            body.push(b'&');
        }
        body.extend_from_slice(format!("a{index}=").as_bytes());
        let target = (index + 1) * chunk;
        while body.len() < target && body.len() < size {
            body.push(b'A');
        }
        if index == args / 2 {
            body.extend_from_slice(payload.as_bytes());
        }
    }
    body.truncate(size);
    body
}

fn headers(body_len: usize) -> Vec<(String, String)> {
    vec![
        ("Host".to_string(), "benchmark.test".to_string()),
        (
            "Content-Type".to_string(),
            "application/x-www-form-urlencoded".to_string(),
        ),
        ("Content-Length".to_string(), body_len.to_string()),
    ]
}

struct Stats {
    p50: f64,
    p99: f64,
    cpu_p50: f64,
    cpu_mean: f64,
}

fn stats(mut wall: Vec<u64>, mut cpu: Vec<u64>) -> Stats {
    wall.sort_unstable();
    cpu.sort_unstable();
    let pct = |values: &[u64], p: f64| {
        let index = ((p * values.len() as f64).ceil() as usize)
            .saturating_sub(1)
            .min(values.len() - 1);
        values[index] as f64 / 1e3
    };
    let cpu_mean = cpu.iter().map(|value| *value as f64).sum::<f64>() / cpu.len() as f64 / 1e3;
    Stats {
        p50: pct(&wall, 0.50),
        p99: pct(&wall, 0.99),
        cpu_p50: pct(&cpu, 0.50),
        cpu_mean,
    }
}

fn measure(engine: &RustEngine, request: &EngineRequest<'_>, samples: usize) -> Stats {
    for _ in 0..10 {
        black_box(engine.evaluate(request));
    }
    let mut wall = Vec::with_capacity(samples);
    let mut cpu = Vec::with_capacity(samples);
    for _ in 0..samples {
        let wall_started = Instant::now();
        let cpu_started = cpu_now_ns();
        black_box(engine.evaluate(black_box(request)));
        cpu.push(cpu_now_ns().saturating_sub(cpu_started));
        wall.push(wall_started.elapsed().as_nanos() as u64);
    }
    stats(wall, cpu)
}

fn spawn_overhead(threads: usize, samples: usize) -> f64 {
    let mut wall = Vec::with_capacity(samples);
    for _ in 0..samples {
        let started = Instant::now();
        std::thread::scope(|scope| {
            for _ in 1..threads {
                scope.spawn(|| black_box(0u8));
            }
        });
        wall.push(started.elapsed().as_nanos() as u64);
    }
    wall.sort_unstable();
    wall[wall.len() / 2] as f64 / 1e3
}

fn main() {
    let mut samples = 200usize;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--samples" {
            if let Some(value) = args.next() {
                samples = value.parse().unwrap_or(samples);
            }
        }
    }

    let thread_counts = [2usize, 3, 4, default_threads()];
    let serial = engine(None);
    let parallel: Vec<(usize, RustEngine)> = thread_counts
        .iter()
        .copied()
        .map(|threads| (threads, engine(Some(threads))))
        .collect();

    println!(
        "{:<16} {:<7} {:>9} {:>9} {:>8} {:>9} {:>9} {:>8}",
        "case", "threads", "p50_us", "p99_us", "cpu_p50", "cpu_mean", "spawn_us", "vs_ser"
    );

    for size in [1024usize, 4096, 8192] {
        for arg_count in [1usize, 16, 64] {
            let payload = "1+union+select+password+from+users";
            let body = body(size, arg_count, payload);
            let headers = headers(body.len());
            let request = EngineRequest {
                method: "POST",
                uri: "/submit",
                http_version: "HTTP/1.1",
                headers: &headers,
                body: Some(&body),
            };
            let label = format!(
                "{size}/{}",
                if arg_count == 1 {
                    "single".to_string()
                } else {
                    format!("multi{arg_count}")
                }
            );
            let base = measure(&serial, &request, samples);
            println!(
                "{:<16} {:<7} {:>9.1} {:>9.1} {:>8.1} {:>9.1} {:>9.1} {:>8.1}",
                label, "serial", base.p50, base.p99, base.cpu_p50, base.cpu_mean, 0.0, 1.0
            );
            for (threads, engine) in &parallel {
                let stats = measure(engine, &request, samples);
                let spawn = spawn_overhead(*threads, samples.min(50));
                println!(
                    "{:<16} {:<7} {:>9.1} {:>9.1} {:>8.1} {:>9.1} {:>9.1} {:>8.1}",
                    label,
                    threads,
                    stats.p50,
                    stats.p99,
                    stats.cpu_p50,
                    stats.cpu_mean,
                    spawn,
                    base.p50 / stats.p50
                );
            }
        }
    }

    println!(
        "notes: scoped workers are created per request; `spawn_us` is the measured \
         empty-scope cost; cpu_* is CLOCK_PROCESS_CPUTIME_ID per request (all threads)."
    );
}
