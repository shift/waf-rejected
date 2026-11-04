//! Coraza WASI reactor memory soak.
//!
//! Drives a warm reactor with a mixed body-size workload for a configurable
//! duration while sampling process RSS and the wasm linear-memory total. It
//! reports whether memory plateaus, and can enforce a ceiling as an
//! operational memory gate.
//!
//! Example:
//!   memory-soak --duration-secs 600 --pool-size 6 \
//!       --max-rss-mib 1280 --output /tmp/opencode/coraza-soak.csv

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufWriter, Write as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use clap::Parser;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde_json::json;

use waf_ingress::waf::wasm_reactor::{ReactorLimits, WasmReactor};

const MIB: f64 = 1024.0 * 1024.0;
const CLASSES: [&str; 4] = ["bodyless", "form-1k", "form-8k", "form-60k"];
const BUCKETS: usize = 2001;

#[derive(Debug, Parser)]
#[command(
    name = "memory-soak",
    about = "Soak a warm Coraza WASI reactor and report RSS/linear-memory growth"
)]
struct Cli {
    /// Module path; defaults to the reactor embedded in this binary.
    #[arg(long)]
    module: Option<PathBuf>,

    /// Warm reactor workers. 0 = auto (cores, capped at 8).
    #[arg(long, default_value_t = 6)]
    pool_size: usize,

    /// Total soak duration in seconds.
    #[arg(long, default_value_t = 300)]
    duration_secs: u64,

    /// Client threads issuing normal traffic (60 KiB is driven separately).
    #[arg(long, default_value_t = 8)]
    concurrency: usize,

    /// Seconds between periodic maximum-size (60 KiB) bodies. 0 disables them.
    #[arg(long, default_value_t = 20)]
    large_body_interval_secs: u64,

    /// RSS sampling interval.
    #[arg(long, default_value_t = 1)]
    sample_secs: u64,

    /// Per-evaluation guest timeout. Production default is 5 s; longer values
    /// keep a loaded experiment machine from turning CPU contention into a
    /// spurious memory-soak error.
    #[arg(long, default_value_t = 5)]
    eval_timeout_secs: u64,

    /// Hard RSS ceiling in MiB. 0 selects the documented pool ceiling
    /// `370 + 96 * pool_size` MiB.
    #[arg(long, default_value_t = 0)]
    max_rss_mib: u64,

    /// Allowed growth between the midpoint and the end of the run, in percent.
    #[arg(long, default_value_t = 10.0)]
    max_growth_pct: f64,

    /// Optional CSV sample output.
    #[arg(long)]
    output: Option<PathBuf>,

    #[arg(long, default_value_t = 42)]
    seed: u64,
}

struct Sample {
    elapsed_secs: f64,
    rss_mib: f64,
    hwm_mib: f64,
    linear_mib: f64,
}

struct ClassStats {
    /// Log-ish latency histogram: 100 µs buckets to 100 ms, then 10 ms buckets.
    buckets: [u64; BUCKETS],
    count: u64,
    errors: u64,
}

impl Default for ClassStats {
    fn default() -> Self {
        Self {
            buckets: [0; BUCKETS],
            count: 0,
            errors: 0,
        }
    }
}

impl ClassStats {
    fn record(&mut self, duration: Duration, error: bool) {
        if error {
            self.errors += 1;
            return;
        }
        let us = duration.as_micros().min(u128::from(u64::MAX)) as u64;
        let index = if us < 100_000 {
            (us / 100) as usize
        } else {
            (1000 + (us - 100_000) / 10_000).min((BUCKETS - 1) as u64) as usize
        };
        self.buckets[index] += 1;
        self.count += 1;
    }

    fn percentile_ms(&self, pct: f64) -> Option<f64> {
        if self.count == 0 {
            return None;
        }
        let target = ((self.count as f64) * pct / 100.0).ceil() as u64;
        let mut seen = 0u64;
        for (index, count) in self.buckets.iter().enumerate() {
            seen += count;
            if seen >= target {
                let us = if index < 1000 {
                    index as f64 * 100.0
                } else {
                    100_000.0 + (index - 1000) as f64 * 10_000.0
                };
                return Some(us / 1000.0);
            }
        }
        None
    }

    fn mean_ms(&self) -> Option<f64> {
        if self.count == 0 {
            return None;
        }
        let mut total_us = 0.0;
        for (index, count) in self.buckets.iter().enumerate() {
            if *count == 0 {
                continue;
            }
            let us = if index < 1000 {
                index as f64 * 100.0
            } else {
                100_000.0 + (index - 1000) as f64 * 10_000.0
            };
            total_us += us * *count as f64;
        }
        Some(total_us / self.count as f64 / 1000.0)
    }
}

fn fill(seed: u64, len: usize) -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = StdRng::seed_from_u64(seed);
    (0..len)
        .map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char)
        .collect()
}

fn form_body(seed: u64, total_len: usize) -> String {
    let prefix = "data=";
    let pad = total_len.saturating_sub(prefix.len());
    format!("{prefix}{}", fill(seed, pad))
}

fn payloads() -> [Vec<u8>; 4] {
    let bodyless = json!({
        "method": "GET",
        "uri": "/assets/app.js?v=3",
        "http_version": "1.1",
        "headers": [["host", "example.com"], ["accept", "*/*"]],
        "body": null,
    });
    let small = json!({
        "method": "POST",
        "uri": "/login",
        "http_version": "1.1",
        "headers": [
            ["host", "example.com"],
            ["content-type", "application/x-www-form-urlencoded"],
        ],
        "body": form_body(1, 1024),
        "body_size": 1024,
        "body_encoding": "utf8",
    });
    let medium = json!({
        "method": "POST",
        "uri": "/submit",
        "http_version": "1.1",
        "headers": [
            ["host", "example.com"],
            ["content-type", "application/x-www-form-urlencoded"],
        ],
        "body": form_body(2, 8192),
        "body_size": 8192,
        "body_encoding": "utf8",
    });
    let large = json!({
        "method": "POST",
        "uri": "/upload",
        "http_version": "1.1",
        "headers": [
            ["host", "example.com"],
            ["content-type", "application/x-www-form-urlencoded"],
        ],
        "body": form_body(3, 60_000),
        "body_size": 60_000,
        "body_encoding": "utf8",
    });
    [
        serde_json::to_vec(&bodyless).expect("bodyless payload"),
        serde_json::to_vec(&small).expect("1 KiB payload"),
        serde_json::to_vec(&medium).expect("8 KiB payload"),
        serde_json::to_vec(&large).expect("60 KiB payload"),
    ]
}

fn read_meminfo() -> (f64, f64) {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let mut rss = 0.0;
    let mut hwm = 0.0;
    for line in status.lines() {
        if let Some(value) = line.strip_prefix("VmRSS:") {
            rss = value
                .split_whitespace()
                .next()
                .and_then(|kb| kb.parse::<f64>().ok())
                .unwrap_or(0.0)
                / 1024.0;
        } else if let Some(value) = line.strip_prefix("VmHWM:") {
            hwm = value
                .split_whitespace()
                .next()
                .and_then(|kb| kb.parse::<f64>().ok())
                .unwrap_or(0.0)
                / 1024.0;
        }
    }
    (rss, hwm)
}

fn load_module(path: Option<&Path>, limits: ReactorLimits) -> Result<WasmReactor> {
    let bytes = match path {
        Some(path) => std::fs::read(path)
            .with_context(|| format!("reading reactor module {}", path.display()))?,
        None => waf_ingress::waf::wasm_reactor::EMBEDDED_CORAZA_REACTOR.to_vec(),
    };
    WasmReactor::from_coraza_bytes_with_limits(&bytes, limits).context("compiling reactor module")
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    if cli.duration_secs == 0 {
        bail!("--duration-secs must be positive");
    }
    let concurrency = cli.concurrency.max(1);

    let module_bytes = match cli.module.as_deref() {
        Some(path) => {
            std::fs::read(path).with_context(|| format!("reading module {}", path.display()))?
        }
        None => waf_ingress::waf::wasm_reactor::EMBEDDED_CORAZA_REACTOR.to_vec(),
    };
    let digest = sha256_hex(&module_bytes);

    let mut limits = ReactorLimits::coraza();
    limits.pool_size = cli.pool_size;
    limits.eval_timeout = Duration::from_secs(cli.eval_timeout_secs.max(1));
    let pool_size = limits.pool_size.clamp(1, 8);

    println!(
        "memory-soak: pool={} concurrency={} duration={}s large_body_every={}s module_sha256={}",
        pool_size, concurrency, cli.duration_secs, cli.large_body_interval_secs, digest
    );

    let warm_start = Instant::now();
    let reactor = Arc::new(load_module(cli.module.as_deref(), limits.clone())?);
    reactor.warm().context("warming reactor pool")?;
    println!(
        "warmed in {:.2}s, linear_memory={:.1} MiB",
        warm_start.elapsed().as_secs_f64(),
        reactor.linear_memory_bytes() as f64 / MIB
    );

    let payloads = Arc::new(payloads());
    for (class, payload) in CLASSES.iter().zip(payloads.iter()) {
        println!("payload {class}: {} bytes", payload.len());
    }

    let stop = Arc::new(AtomicBool::new(false));
    let normal_evals = Arc::new(AtomicU64::new(0));
    let large_evals = Arc::new(AtomicU64::new(0));

    let mut handles = Vec::new();
    for thread_id in 0..concurrency {
        let reactor = Arc::clone(&reactor);
        let payloads = Arc::clone(&payloads);
        let stop = Arc::clone(&stop);
        let counter = Arc::clone(&normal_evals);
        let seed = cli.seed.wrapping_add(thread_id as u64);
        handles.push(thread::spawn(move || {
            let mut rng = StdRng::seed_from_u64(seed);
            let mut stats = [
                ClassStats::default(),
                ClassStats::default(),
                ClassStats::default(),
            ];
            while !stop.load(Ordering::Relaxed) {
                // 55% bodyless, 25% 1 KiB, 20% 8 KiB.
                let roll = rng.gen_range(0..100u32);
                let class = if roll < 55 {
                    0
                } else if roll < 80 {
                    1
                } else {
                    2
                };
                let started = Instant::now();
                let result = reactor.evaluate(&payloads[class]);
                stats[class].record(started.elapsed(), result.is_err());
                counter.fetch_add(1, Ordering::Relaxed);
            }
            stats
        }));
    }

    let large_handle = if cli.large_body_interval_secs > 0 {
        let reactor = Arc::clone(&reactor);
        let payloads = Arc::clone(&payloads);
        let stop = Arc::clone(&stop);
        let counter = Arc::clone(&large_evals);
        let interval = Duration::from_secs(cli.large_body_interval_secs);
        Some(thread::spawn(move || {
            let mut stats = ClassStats::default();
            while !stop.load(Ordering::Relaxed) {
                thread::sleep(interval);
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                let started = Instant::now();
                let result = reactor.evaluate(&payloads[3]);
                stats.record(started.elapsed(), result.is_err());
                counter.fetch_add(1, Ordering::Relaxed);
            }
            stats
        }))
    } else {
        None
    };

    let mut samples = Vec::new();
    let mut csv = cli
        .output
        .as_deref()
        .map(|path| -> Result<BufWriter<File>> {
            let file =
                File::create(path).with_context(|| format!("creating {}", path.display()))?;
            let mut writer = BufWriter::new(file);
            writeln!(writer, "elapsed_secs,rss_mib,hwm_mib,linear_mib,evals")?;
            Ok(writer)
        })
        .transpose()?;

    let started = Instant::now();
    let deadline = Duration::from_secs(cli.duration_secs);
    while started.elapsed() < deadline {
        let (rss, hwm) = read_meminfo();
        let sample = Sample {
            elapsed_secs: started.elapsed().as_secs_f64(),
            rss_mib: rss,
            hwm_mib: hwm,
            linear_mib: reactor.linear_memory_bytes() as f64 / MIB,
        };
        if let Some(writer) = csv.as_mut() {
            writeln!(
                writer,
                "{:.0},{:.1},{:.1},{:.1},{}",
                sample.elapsed_secs,
                sample.rss_mib,
                sample.hwm_mib,
                sample.linear_mib,
                normal_evals.load(Ordering::Relaxed) + large_evals.load(Ordering::Relaxed)
            )?;
        }
        println!(
            "t={:>4.0}s rss={:>6.1} MiB hwm={:>6.1} MiB linear={:>6.1} MiB evals={}",
            sample.elapsed_secs,
            sample.rss_mib,
            sample.hwm_mib,
            sample.linear_mib,
            normal_evals.load(Ordering::Relaxed) + large_evals.load(Ordering::Relaxed)
        );
        samples.push(sample);
        thread::sleep(Duration::from_secs(cli.sample_secs.max(1)));
    }

    stop.store(true, Ordering::Relaxed);
    let mut stats: Vec<ClassStats> = Vec::new();
    for handle in handles {
        let local = handle.join().expect("client thread panicked");
        for (index, item) in local.into_iter().enumerate() {
            merge_stats(&mut stats, index, item);
        }
    }
    if let Some(handle) = large_handle {
        merge_stats(
            &mut stats,
            3,
            handle.join().expect("large-body thread panicked"),
        );
    }

    let (final_rss, final_hwm) = read_meminfo();
    let end = Sample {
        elapsed_secs: started.elapsed().as_secs_f64(),
        rss_mib: final_rss,
        hwm_mib: final_hwm.max(samples.last().map(|s| s.hwm_mib).unwrap_or(0.0)),
        linear_mib: reactor.linear_memory_bytes() as f64 / MIB,
    };
    samples.push(end);

    report(&cli, pool_size, &samples, &stats, &digest)
}

fn merge_stats(stats: &mut Vec<ClassStats>, index: usize, local: ClassStats) {
    while stats.len() <= index {
        stats.push(ClassStats::default());
    }
    let target = &mut stats[index];
    target.count += local.count;
    target.errors += local.errors;
    for (dst, src) in target.buckets.iter_mut().zip(local.buckets.iter()) {
        *dst += *src;
    }
}

fn report(
    cli: &Cli,
    pool_size: usize,
    samples: &[Sample],
    stats: &[ClassStats],
    digest: &str,
) -> Result<()> {
    let peak_rss = samples.iter().map(|s| s.rss_mib).fold(0.0, f64::max);
    let peak_linear = samples.iter().map(|s| s.linear_mib).fold(0.0, f64::max);
    let baseline = samples.first().map(|s| s.rss_mib).unwrap_or(0.0);
    let end = samples.last().map(|s| s.rss_mib).unwrap_or(0.0);
    let mid = samples
        .iter()
        .find(|s| s.elapsed_secs >= samples.last().map(|l| l.elapsed_secs / 2.0).unwrap_or(0.0))
        .map(|s| s.rss_mib)
        .unwrap_or(baseline);
    let end_linear = samples.last().map(|s| s.linear_mib).unwrap_or(0.0);
    let mid_linear = samples
        .iter()
        .find(|s| s.elapsed_secs >= samples.last().map(|l| l.elapsed_secs / 2.0).unwrap_or(0.0))
        .map(|s| s.linear_mib)
        .unwrap_or(0.0);
    let growth_pct = if mid > 0.0 {
        (end - mid) / mid * 100.0
    } else {
        0.0
    };

    println!();
    println!("=== memory soak summary ===");
    println!("module_sha256: {digest}");
    println!("pool_size: {pool_size}");
    println!("rss_mib: baseline={baseline:.1} mid={mid:.1} end={end:.1} peak={peak_rss:.1}");
    println!("linear_mib: mid={mid_linear:.1} end={end_linear:.1} peak={peak_linear:.1}");
    println!("growth_after_midpoint: {growth_pct:.1}%");

    let mut totals: BTreeMap<&str, (u64, u64)> = BTreeMap::new();
    for (index, class) in CLASSES.iter().enumerate() {
        let item = stats.get(index);
        let count = item.map(|s| s.count).unwrap_or(0);
        let errors = item.map(|s| s.errors).unwrap_or(0);
        totals.insert(class, (count, errors));
        let p50 = item.and_then(|s| s.percentile_ms(50.0));
        let p95 = item.and_then(|s| s.percentile_ms(95.0));
        let mean = item.and_then(ClassStats::mean_ms);
        println!(
            "{class}: n={count} errors={errors} p50={} p95={} mean={}",
            fmt_ms(p50),
            fmt_ms(p95),
            fmt_ms(mean)
        );
    }

    let total_errors: u64 = totals.values().map(|(_, errors)| *errors).sum();
    let rss_ceiling = if cli.max_rss_mib == 0 {
        370.0 + 96.0 * pool_size as f64
    } else {
        cli.max_rss_mib as f64
    };
    let rss_gate = peak_rss <= rss_ceiling;
    let growth_gate = growth_pct <= cli.max_growth_pct;
    let error_gate = total_errors == 0;
    println!(
        "gate rss<={rss_ceiling:.0}MiB: {} ({peak_rss:.1} MiB)",
        if rss_gate { "PASS" } else { "FAIL" }
    );
    println!(
        "gate growth<={:.1}%: {} ({growth_pct:.1}%)",
        cli.max_growth_pct,
        if growth_gate { "PASS" } else { "FAIL" }
    );
    println!(
        "gate zero_errors: {} ({total_errors})",
        if error_gate { "PASS" } else { "FAIL" }
    );

    if !(rss_gate && growth_gate && error_gate) {
        bail!("memory soak gate failed");
    }
    Ok(())
}

fn fmt_ms(value: Option<f64>) -> String {
    value
        .map(|ms| format!("{ms:.1}ms"))
        .unwrap_or_else(|| "n/a".to_string())
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}
