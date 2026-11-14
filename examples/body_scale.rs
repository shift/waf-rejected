//! Body-size scaling harness for the native CRS engine.
//!
//! Measures the same URLENCODED body shape at a list of sizes so the growth
//! exponent is visible, and (with `engine-profile`) splits the cost into the
//! engine's hot-loop categories.
//!
//! ```text
//! cargo run --release --features rust-engine,engine-profile \
//!   --example body_scale -- --sizes 64KiB,1MiB,10MiB --reps 5
//! ```

use std::time::Instant;

use waf_ingress::waf::rust_engine::{
    default_crs_conf_path, CompilePolicy, EngineRequest, Limits, RustEngine,
};

fn parse_size(text: &str) -> Option<usize> {
    let text = text.trim();
    for (suffix, scale) in [
        ("KiB", 1usize << 10),
        ("MiB", 1usize << 20),
        ("Ki", 1usize << 10),
        ("Mi", 1usize << 20),
        ("K", 1usize << 10),
        ("M", 1usize << 20),
        ("B", 1usize),
    ] {
        if let Some(value) = text.strip_suffix(suffix) {
            return value.trim().parse::<usize>().ok().map(|n| n * scale);
        }
    }
    text.parse().ok()
}

fn body(size: usize) -> Vec<u8> {
    let mut body = format!("data={}", "A".repeat(size)).into_bytes();
    body.truncate(size.max(5));
    body
}

fn headers(len: usize) -> Vec<(String, String)> {
    vec![
        ("Host".to_string(), "localhost".to_string()),
        ("User-Agent".to_string(), "OWASP CRS test agent".to_string()),
        (
            "Accept".to_string(),
            "text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5".to_string(),
        ),
        (
            "Content-Type".to_string(),
            "application/x-www-form-urlencoded".to_string(),
        ),
        ("Content-Length".to_string(), len.to_string()),
    ]
}

fn percentile(sorted: &[u64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let index = ((p * sorted.len() as f64).ceil() as usize)
        .saturating_sub(1)
        .min(sorted.len() - 1);
    sorted[index] as f64 / 1e6
}

/// Thread CPU time. Unlike wall time this is unaffected by the concurrent
/// release-gate build sharing the host, so the curve shape stays visible.
fn cpu_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock_gettime only writes into the provided timespec.
    unsafe {
        libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut ts);
    }
    (ts.tv_sec as u64) * 1_000_000_000 + ts.tv_nsec as u64
}

fn main() {
    let mut args = std::env::args().skip(1);
    let mut sizes = vec![
        64 << 10,
        256 << 10,
        512 << 10,
        1 << 20,
        2 << 20,
        4 << 20,
        8 << 20,
        10 << 20,
    ];
    let mut reps = 7usize;
    let mut warmup = 2usize;
    let mut profile = false;
    let mut cap = None;
    let mut default_limits = false;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--sizes" => {
                let value = args.next().expect("--sizes needs a value");
                sizes = value
                    .split(',')
                    .map(|part| parse_size(part).expect("size must parse (e.g. 1MiB)"))
                    .collect();
            }
            "--reps" => {
                reps = args
                    .next()
                    .expect("--reps needs a value")
                    .parse()
                    .expect("reps")
            }
            "--warmup" => {
                warmup = args
                    .next()
                    .expect("--warmup needs a value")
                    .parse()
                    .expect("warmup")
            }
            "--profile" => profile = true,
            "--cap" => {
                cap = Some(parse_size(&args.next().expect("--cap needs a value")).expect("cap"))
            }
            "--default-limits" => default_limits = true,
            other => panic!("unknown argument {other}"),
        }
    }

    let cap = cap.unwrap_or_else(|| *sizes.iter().max().expect("at least one size"));
    let limits = if default_limits {
        Limits::default()
    } else {
        Limits::for_body_cap(cap)
    };
    let engine =
        RustEngine::from_conf_path_with_policy(default_crs_conf_path(), CompilePolicy::Report)
            .expect("pinned CRS bundle compiles")
            .with_limits(limits);
    eprintln!(
        "limits: value {} B, total {} B, gates {:?}",
        limits.max_value_bytes,
        limits.max_total_bytes,
        engine.gate_set().map(|g| format!("{g:?}"))
    );

    println!(
        "{:>10} {:>12} {:>10} {:>10} {:>10} {:>10} {:>12} {:>8}",
        "size", "bytes", "cpu min", "cpu p50", "p50 ms", "p95 ms", "cpu ms/MiB", "decision"
    );
    for size in sizes {
        let body = body(size);
        let headers = headers(body.len());
        let request = EngineRequest {
            method: "POST",
            uri: "/post",
            http_version: "HTTP/1.1",
            headers: &headers,
            body: Some(&body),
        };
        let mut decision = String::new();
        for _ in 0..warmup {
            let _ = std::hint::black_box(engine.evaluate(&request));
        }
        let mut samples = Vec::with_capacity(reps);
        let mut cpu_samples = Vec::with_capacity(reps);
        for _ in 0..reps {
            let cpu_start = cpu_ns();
            let start = Instant::now();
            let outcome = engine.evaluate(&request);
            samples.push(start.elapsed().as_nanos() as u64);
            cpu_samples.push(cpu_ns().saturating_sub(cpu_start));
            decision = format!("{outcome:?}");
            std::hint::black_box(outcome);
        }
        samples.sort_unstable();
        cpu_samples.sort_unstable();
        let cpu_min = cpu_samples[0] as f64 / 1e6;
        let cpu_p50 = percentile(&cpu_samples, 0.5);
        let p50 = percentile(&samples, 0.5);
        let p95 = percentile(&samples, 0.95);
        let mib = size as f64 / (1 << 20) as f64;
        println!(
            "{:>10} {:>12} {:>10.3} {:>10.3} {:>10.3} {:>10.3} {:>12.3} {:>8}",
            format!("{:.1}MiB", size as f64 / (1 << 20) as f64),
            size,
            cpu_min,
            cpu_p50,
            p50,
            p95,
            if mib > 0.0 { cpu_min / mib } else { 0.0 },
            &decision[..decision.len().min(8)]
        );
        eprintln!("  decision: {decision}");

        #[cfg(feature = "engine-profile")]
        if profile {
            let mut total = waf_ingress::waf::rust_engine::profile::Report::default();
            let profiled_reps = reps.min(3);
            for _ in 0..profiled_reps {
                let (_, report) = engine.evaluate_profiled(&request);
                total.parse_ns += report.parse_ns;
                total.transforms_ns += report.transforms_ns;
                total.candidates_ns += report.candidates_ns;
                total.gate_ns += report.gate_ns;
                total.operators_ns += report.operators_ns;
                total.scoring_ns += report.scoring_ns;
                total.captures_ns += report.captures_ns;
                total.tx_ns += report.tx_ns;
                total.matched_ns += report.matched_ns;
                total.regex_evaluations += report.regex_evaluations;
                total.regex_skipped += report.regex_skipped;
                for (id, ns) in report.rule_ns {
                    if let Some(entry) = total.rule_ns.iter_mut().find(|(rule, _)| *rule == id) {
                        entry.1 += ns;
                    } else {
                        total.rule_ns.push((id, ns));
                    }
                }
            }
            let n = profiled_reps as f64;
            let sum = (total.parse_ns
                + total.transforms_ns
                + total.candidates_ns
                + total.gate_ns
                + total.operators_ns
                + total.scoring_ns
                + total.captures_ns
                + total.tx_ns
                + total.matched_ns) as f64;
            println!(
                "  profile ms/req: parse {:.3} xform {:.3} cand {:.3} gate {:.3} ops {:.3} score {:.3} capture {:.3} tx {:.3} matched {:.3} | regex {:.0} skipped {:.0} | accounted {:.3}",
                total.parse_ns as f64 / n / 1e6,
                total.transforms_ns as f64 / n / 1e6,
                total.candidates_ns as f64 / n / 1e6,
                total.gate_ns as f64 / n / 1e6,
                total.operators_ns as f64 / n / 1e6,
                total.scoring_ns as f64 / n / 1e6,
                total.captures_ns as f64 / n / 1e6,
                total.tx_ns as f64 / n / 1e6,
                total.matched_ns as f64 / n / 1e6,
                total.regex_evaluations as f64 / n,
                total.regex_skipped as f64 / n,
                sum / n / 1e6
            );
            total.rule_ns.sort_unstable_by(|a, b| b.1.cmp(&a.1));
            let top: Vec<String> = total
                .rule_ns
                .iter()
                .take(15)
                .map(|(id, ns)| format!("{id}:{:.1}", *ns as f64 / n / 1e6))
                .collect();
            println!("  top rules ms/req: {}", top.join(" "));
        }
        #[cfg(not(feature = "engine-profile"))]
        if profile {
            eprintln!(
                "profile rows need the `engine-profile` feature: \
                 cargo run --release --features rust-engine,engine-profile \
                 --example body_scale -- --profile"
            );
        }
    }
}
