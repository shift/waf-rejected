//! Standalone wasm-vs-native Coraza backend benchmark.
//!
//! Run the native sidecar first, then:
//!
//! ```sh
//! cargo run --release --example coraza_backend_bench --features coraza-native
//! ```
//!
//! Environment:
//! - `CORAZA_SOCKET` (default `/tmp/coraza-native-bench.sock`)
//! - `CORAZA_REPS` scales every case (default 1.0)
//! - `CORAZA_ONLY` = `wasm` | `native` to skip one backend
//! - `CORAZA_MODULE` loads a specific reactor `.wasm` file instead of the
//!   embedded module (used to A/B `wasm-opt` output without rebuilding)
//! - `CORAZA_POOL_SIZE` overrides the wasm pool size (default 4)
//!
//! The measurement method mirrors `docs/suggestions_from_agents/coraza-body-performance.md`:
//! release build, warmed engine, whole `WafRule::evaluate` call (payload build +
//! backend round trip), p50/mean over repeated single-threaded requests.

use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use hyper::{HeaderMap, Method, Uri};
use waf_ingress::config::{CorazaBackend, WafCorazaConfig};
use waf_ingress::waf::{Decision, RequestContext, WafRule};

struct Case {
    name: &'static str,
    body: Option<Vec<u8>>,
    uri: &'static str,
    reps: usize,
}

impl Case {
    fn context(&self) -> RequestContext {
        let mut headers = HeaderMap::new();
        headers.insert("host", "benchmark.test".parse().unwrap());
        headers.insert(
            "content-type",
            "application/x-www-form-urlencoded".parse().unwrap(),
        );
        RequestContext::new(
            "127.0.0.1".parse().unwrap(),
            if self.body.is_some() {
                Method::POST
            } else {
                Method::GET
            },
            self.uri.parse::<Uri>().unwrap(),
            headers,
            self.body.as_ref().map(Vec::len),
        )
        .with_body(self.body.clone().map(Bytes::from))
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

fn cases(scale: f64) -> Vec<Case> {
    let rep = |n: usize| ((n as f64 * scale).round() as usize).max(1);
    let sqli = b"user=admin'%20OR%20'1'='1&password=x".to_vec();
    let xss = b"comment=%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E".to_vec();
    vec![
        Case {
            name: "1 KiB form",
            body: Some(form_body(1024)),
            uri: "/submit",
            reps: rep(15),
        },
        Case {
            name: "4 KiB form",
            body: Some(form_body(4096)),
            uri: "/submit",
            reps: rep(10),
        },
        Case {
            name: "8 KiB form",
            body: Some(form_body(8192)),
            uri: "/submit",
            reps: rep(8),
        },
        Case {
            name: "16 KiB form",
            body: Some(form_body(16384)),
            uri: "/submit",
            reps: rep(6),
        },
        Case {
            name: "60 KiB form",
            body: Some(form_body(60 * 1024)),
            uri: "/submit",
            reps: rep(4),
        },
        Case {
            name: "SQLi 44 B",
            body: Some(sqli),
            uri: "/login",
            reps: rep(15),
        },
        Case {
            name: "XSS 56 B",
            body: Some(xss),
            uri: "/comment",
            reps: rep(15),
        },
    ]
}

struct Stats {
    p50: Duration,
    p95: Duration,
    mean: Duration,
    decision: Decision,
}

fn measure(rule: &dyn WafRule, case: &Case) -> Stats {
    let ctx = case.context();
    let mut samples = Vec::with_capacity(case.reps);
    let mut decision = Decision::Allow;
    for _ in 0..case.reps {
        let started = Instant::now();
        decision = rule.evaluate(&ctx);
        samples.push(started.elapsed());
    }
    samples.sort_unstable();
    let p50 = samples[samples.len() / 2];
    let p95 = samples[(samples.len() * 95 / 100).min(samples.len() - 1)];
    let total: Duration = samples.iter().sum();
    Stats {
        p50,
        p95,
        mean: total / samples.len() as u32,
        decision,
    }
}

fn throughput(rule: &dyn WafRule, case: &Case, threads: usize, reps: usize) -> f64 {
    let barrier = Arc::new(std::sync::Barrier::new(threads));
    let started = Instant::now();
    std::thread::scope(|scope| {
        for _ in 0..threads {
            let barrier = Arc::clone(&barrier);
            scope.spawn(move || {
                let ctx = case.context();
                barrier.wait();
                for _ in 0..reps {
                    let _ = rule.evaluate(&ctx);
                }
            });
        }
    });
    let elapsed = started.elapsed().as_secs_f64();
    (threads * reps) as f64 / elapsed
}

fn fmt_ms(d: Duration) -> String {
    format!("{:.2}", d.as_secs_f64() * 1000.0)
}

/// Peak resident set size of this process in MiB, from `/proc/self/status`.
fn peak_rss_mib() -> f64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status.lines().find_map(|line| {
                let rest = line.strip_prefix("VmHWM:")?;
                let kib: f64 = rest.trim().trim_end_matches(" kB").trim().parse().ok()?;
                Some(kib / 1024.0)
            })
        })
        .unwrap_or(f64::NAN)
}

/// Throughput at several client concurrencies for the two pool-sizing cases.
fn throughput_matrix(rule: &dyn WafRule, pool_size: usize) {
    println!("\n## Throughput vs pool size (requests/second)\n");
    println!("| pool | case | concurrency | requests/s | peak RSS MiB |");
    println!("|---|---|---|---|---|");
    for (name, body) in [
        ("1 KiB form", form_body(1024)),
        ("8 KiB form", form_body(8192)),
    ] {
        for concurrency in [1usize, 4, 16] {
            let case = Case {
                name,
                body: Some(body.clone()),
                uri: "/submit",
                reps: 1,
            };
            // Keep total work roughly constant across concurrencies so a run
            // of the matrix takes about the same time per row.
            let reps = (16 / concurrency).max(1);
            let rps = throughput(rule, &case, concurrency, reps);
            println!(
                "| {pool_size} | {name} | {concurrency} | {rps:.1} | {:.1} |",
                peak_rss_mib()
            );
        }
    }
}

fn main() {
    let socket = std::env::var("CORAZA_SOCKET")
        .unwrap_or_else(|_| "/tmp/coraza-native-bench.sock".to_string());
    // The socket is only consumed by the native backend below; keep the
    // default build warning-free.
    #[cfg(not(feature = "coraza-native"))]
    let _ = &socket;
    let scale = std::env::var("CORAZA_REPS")
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(1.0);
    let only = std::env::var("CORAZA_ONLY").unwrap_or_default();

    let mut config = WafCorazaConfig {
        eval_timeout_ms: 30_000,
        pool_size: std::env::var("CORAZA_POOL_SIZE")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(4),
        module_path: std::env::var("CORAZA_MODULE").ok(),
        ..Default::default()
    };

    let mut backends: Vec<(&str, Box<dyn WafRule>)> = Vec::new();

    if only != "native" {
        config.backend = CorazaBackend::Wasm;
        let started = Instant::now();
        match waf_ingress::waf::wasm_reactor::WasmReactorRule::from_config(&config, true) {
            Ok(rule) => {
                eprintln!(
                    "wasm backend compiled and warmed in {:.2} s (pool {})",
                    started.elapsed().as_secs_f64(),
                    config.resolved_pool_size()
                );
                backends.push(("wasm", Box::new(rule)))
            }
            Err(err) => eprintln!("wasm backend unavailable: {err}"),
        }
    }

    if only != "wasm" {
        #[cfg(feature = "coraza-native")]
        {
            config.backend = CorazaBackend::Native;
            config.native_socket_path = Some(socket.clone());
            match waf_ingress::waf::native_coraza::NativeCorazaRule::from_config(&config, true) {
                Ok(rule) => backends.push(("native", Box::new(rule))),
                Err(err) => eprintln!("native backend unavailable ({socket}): {err}"),
            }
        }
        #[cfg(not(feature = "coraza-native"))]
        eprintln!("native backend skipped: build with --features coraza-native");
    }

    if backends.is_empty() {
        eprintln!("no backend available; is the sidecar running or wasm enabled?");
        std::process::exit(1);
    }

    // Warm each backend once per case so rule compilation and pool start-up
    // are excluded from steady-state numbers.
    let all_cases = cases(scale);
    for (_, rule) in &backends {
        for case in &all_cases {
            let ctx = case.context();
            let _ = rule.evaluate(&ctx);
        }
    }

    if std::env::var("CORAZA_SKIP_LATENCY").is_err() {
        println!("\n## Single-request latency (p50 / p95 / mean, ms)\n");
        print!("| case |");
        for (name, _) in &backends {
            print!(" {name} p50 | {name} p95 | {name} mean | {name} decision |");
        }
        println!();
        print!("|---|");
        for _ in &backends {
            print!("---|---|---|---|");
        }
        println!();
        for case in &all_cases {
            print!("| {} |", case.name);
            for (_, rule) in &backends {
                let stats = measure(rule.as_ref(), case);
                print!(
                    " {} | {} | {} | {:?} |",
                    fmt_ms(stats.p50),
                    fmt_ms(stats.p95),
                    fmt_ms(stats.mean),
                    stats.decision
                );
            }
            println!();
        }
    }

    if std::env::var("CORAZA_THROUGHPUT").is_ok() {
        for (_, rule) in &backends {
            throughput_matrix(rule.as_ref(), config.resolved_pool_size());
        }
        return;
    }

    let throughput_case = Case {
        name: "throughput 4 KiB",
        body: Some(form_body(4096)),
        uri: "/submit",
        reps: 1,
    };
    println!("\n## Throughput (requests/second)\n");
    println!("| backend | 1 connection | 4 concurrent |");
    println!("|---|---|---|");
    for (name, rule) in &backends {
        let reps = ((30.0 * scale).round() as usize).max(5);
        let single = throughput(rule.as_ref(), &throughput_case, 1, reps);
        let concurrent = throughput(rule.as_ref(), &throughput_case, 4, reps);
        println!("| {name} | {single:.1} | {concurrent:.1} |");
    }
    println!();
}
