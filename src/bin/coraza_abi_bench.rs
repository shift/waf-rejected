//! In-process ABI benchmark for the Coraza WASI reactor.
//!
//! Compares the compact binary request envelope against the legacy JSON
//! envelope, and pre-warmed pools against a cold pool.
//!
//! ```sh
//! cargo run --release --bin coraza_abi_bench --features wasm-reactor
//! CORAZA_BENCH_REPS=200 cargo run --release --bin coraza_abi_bench --features wasm-reactor
//! ```

use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use hyper::{HeaderMap, Method, Uri};
use waf_ingress::waf::wasm_reactor::{
    set_json_abi, ReactorLimits, WasmReactor, WasmReactorRule, EMBEDDED_CORAZA_REACTOR,
};
use waf_ingress::waf::{RequestContext, WafRule};

fn stats(mut samples: Vec<Duration>) -> (Duration, Duration) {
    samples.sort_unstable();
    let p50 = samples[samples.len() / 2];
    let p99 = samples[(samples.len() * 99 / 100).min(samples.len() - 1)];
    (p50, p99)
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1_000.0
}

fn context(method: &str, uri: &str, body: Option<Vec<u8>>) -> RequestContext {
    let mut headers = HeaderMap::new();
    headers.insert("host", "bench.test".parse().unwrap());
    headers.insert(
        "user-agent",
        "Mozilla/5.0 (X11; Linux x86_64) Firefox/128.0"
            .parse()
            .unwrap(),
    );
    headers.insert("accept", "*/*".parse().unwrap());
    if body.is_some() {
        headers.insert(
            "content-type",
            "application/x-www-form-urlencoded".parse().unwrap(),
        );
    }
    let body = body.map(Bytes::from);
    RequestContext::new(
        "127.0.0.1".parse().unwrap(),
        method.parse::<Method>().unwrap(),
        uri.parse::<Uri>().unwrap(),
        headers,
        body.as_ref().map(Bytes::len),
    )
    .with_body(body)
}

fn build_rule(warm: bool, workers: Option<usize>) -> WasmReactorRule {
    let limits = ReactorLimits::coraza();
    let reactor = WasmReactor::from_coraza_bytes_with_limits(EMBEDDED_CORAZA_REACTOR, limits)
        .expect("reactor");
    if warm {
        match workers {
            Some(n) => reactor.warm_workers(n).expect("warm"),
            None => reactor.warm().expect("warm"),
        }
    }
    WasmReactorRule::new("coraza-bench", Arc::new(reactor)).with_fail_closed(true)
}

fn measure(
    rule: &WasmReactorRule,
    ctx: &RequestContext,
    reps: usize,
) -> (Duration, Duration, Duration) {
    // One untimed call so a cold pool pays initialisation outside the sample.
    let first_start = Instant::now();
    let _ = rule.evaluate(ctx);
    let first = first_start.elapsed();
    let mut samples = Vec::with_capacity(reps);
    for _ in 0..reps {
        let start = Instant::now();
        let _ = std::hint::black_box(rule.evaluate(ctx));
        samples.push(start.elapsed());
    }
    let (p50, p99) = stats(samples);
    (first, p50, p99)
}

fn main() {
    let reps: usize = std::env::var("CORAZA_BENCH_REPS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(120);

    let allow = context("GET", "/", None);
    let sqli = context("GET", "/login?q=admin%27%20OR%20%271%27%3D%271", None);
    let body = context("POST", "/submit", Some(vec![b'A'; 4096]));
    let cases = [("allow", &allow), ("sqli", &sqli), ("4KiB body", &body)];

    println!("reps={reps} per case");
    println!(
        "{:<12} {:<8} {:>10} {:>10}",
        "case", "abi", "p50 (ms)", "p99 (ms)"
    );

    for (abi_name, json) in [("binary", false), ("json", true)] {
        set_json_abi(Some(json));
        for (warm_name, warm) in [("cold", false), ("warm", true)] {
            if let Ok(rule) = std::panic::catch_unwind(|| build_rule(warm, Some(2))) {
                for (case, ctx) in cases {
                    let case_reps = if case == "4KiB body" {
                        (reps / 10).max(5)
                    } else {
                        reps
                    };
                    let (first, p50, p99) = measure(&rule, ctx, case_reps);
                    println!(
                        "{:<12} {:<8} {:>10.2} {:>10.2}  first={:.1}ms",
                        case,
                        format!("{abi_name}/{warm_name}"),
                        ms(p50),
                        ms(p99),
                        ms(first)
                    );
                }
            }
        }
    }
    set_json_abi(None);
}
