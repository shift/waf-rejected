//! Latency of the request-side distributed policy/reputation caches.
//!
//! The caches are the only distributed objects read by the request path. This
//! harness measures a fresh hit, a miss, a stale read and a generation bump on
//! the real `VersionedCache` types so the numbers can be compared with the
//! end-to-end rows in `scripts/bench-distributed.sh`.
//!
//! ```sh
//! cargo run --release --features distri-kv --bin distributed-cache-bench
//! ```

use std::hint::black_box;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use clap::Parser;
use serde_json::json;
use waf_ingress::waf::distributed::{PolicySnapshot, ReputationEntry, VersionedCache};

#[derive(Debug, Parser)]
#[command(
    name = "distributed-cache-bench",
    about = "Request-side policy/reputation cache microbenchmark"
)]
struct Cli {
    /// Iterations per timed sample.
    #[arg(long, default_value_t = 200_000)]
    iterations: usize,

    /// Timed samples per row.
    #[arg(long, default_value_t = 20)]
    samples: usize,

    /// Entries used for the generation-invalidation row.
    #[arg(long, default_value_t = 65_536)]
    invalidation_entries: usize,

    /// Write the measured rows as JSON.
    #[arg(long)]
    json_out: Option<std::path::PathBuf>,
}

#[derive(Debug, Clone, Copy)]
struct Row {
    operation: &'static str,
    ns_per_op: f64,
    p99_ns: f64,
}

fn summarize(operation: &'static str, mut values: Vec<f64>) -> Row {
    values.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = values.len();
    let p99 = values[((0.99 * n as f64).ceil() as usize)
        .saturating_sub(1)
        .min(n - 1)];
    Row {
        operation,
        ns_per_op: values[n / 2],
        p99_ns: p99,
    }
}

fn measure<F: FnMut()>(cli: &Cli, mut op: F) -> Row {
    for _ in 0..1_000 {
        op();
    }
    let mut samples = Vec::with_capacity(cli.samples);
    for _ in 0..cli.samples {
        let started = Instant::now();
        for _ in 0..cli.iterations {
            op();
        }
        samples.push(started.elapsed().as_nanos() as f64 / cli.iterations as f64);
    }
    summarize("", samples)
}

fn main() {
    let cli = Cli::parse();
    let policy: VersionedCache<String, PolicySnapshot> =
        VersionedCache::new(Duration::from_secs(300), Duration::from_secs(900), 64);
    let reputation: VersionedCache<IpAddr, ReputationEntry> =
        VersionedCache::new(Duration::from_secs(300), Duration::from_secs(900), 65_536);

    let policy_key = "active".to_string();
    policy.insert(policy_key.clone(), PolicySnapshot::local());
    let ip: IpAddr = "203.0.113.7".parse().expect("valid IP");
    reputation.insert(
        ip,
        ReputationEntry {
            ip,
            score: 0.93,
            confidence: 0.8,
            labels: vec!["scanner".to_string()],
            expires_at: None,
            version: 9,
        },
    );
    let missing_policy = "absent".to_string();
    let missing_ip: IpAddr = "198.51.100.9".parse().expect("valid IP");

    let mut rows = Vec::new();
    let mut row = measure(&cli, || {
        black_box(policy.get(black_box(&policy_key)));
    });
    row.operation = "policy fresh hit";
    rows.push(row);

    let mut row = measure(&cli, || {
        black_box(reputation.get(black_box(&ip)));
    });
    row.operation = "reputation fresh hit";
    rows.push(row);

    let mut row = measure(&cli, || {
        black_box(policy.get(black_box(&missing_policy)));
    });
    row.operation = "policy miss";
    rows.push(row);

    let mut row = measure(&cli, || {
        black_box(reputation.get(black_box(&missing_ip)));
    });
    row.operation = "reputation miss";
    rows.push(row);

    let mut samples = Vec::with_capacity(cli.samples);
    for generation in (policy.generation() + 1..).take(cli.samples) {
        let cache: VersionedCache<u64, u64> = VersionedCache::new(
            Duration::from_secs(300),
            Duration::from_secs(900),
            cli.invalidation_entries.max(1),
        );
        for key in 0..cli.invalidation_entries as u64 {
            cache.insert(key, key);
        }
        let started = Instant::now();
        cache.set_generation(generation);
        samples.push(started.elapsed().as_nanos() as f64);
    }
    let row = summarize("generation invalidation (ns, whole cache)", samples);
    rows.push(row);

    println!("# distributed request-side cache latency");
    println!();
    println!("- iterations/sample: {}", cli.iterations);
    println!("- samples: {}", cli.samples);
    println!();
    println!("| operation | median ns/op | p99 ns/op |");
    println!("|---|---:|---:|");
    for row in &rows {
        println!(
            "| {} | {:.1} | {:.1} |",
            row.operation, row.ns_per_op, row.p99_ns
        );
    }

    if let Some(path) = cli.json_out.as_deref() {
        let payload = json!({
            "schema": 1,
            "iterations": cli.iterations,
            "samples": cli.samples,
            "invalidation_entries": cli.invalidation_entries,
            "rows": rows.iter().map(|row| json!({
                "operation": row.operation,
                "ns_per_op": row.ns_per_op,
                "p99_ns": row.p99_ns,
            })).collect::<Vec<_>>(),
        });
        if let Err(error) = std::fs::write(path, serde_json::to_vec_pretty(&payload).unwrap()) {
            eprintln!("failed to write {}: {error}", path.display());
            std::process::exit(1);
        }
        println!();
        println!("wrote {}", path.display());
    }
}
