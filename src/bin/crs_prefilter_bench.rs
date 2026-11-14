//! Benchmark and detection-parity harness for the experimental CRS prefilter.
//!
//! ```text
//! cargo run --release --features crs-prefilter,coraza-native \
//!   --bin crs-prefilter-bench -- \
//!   --corpus tests/corpus/crs-prefilter-corpus.json \
//!   --socket /tmp/opencode/coraza.sock --reps 3
//! ```
//!
//! Without `--socket` only the prefilter itself is measured. With a running
//! native Coraza sidecar the harness also measures full-CRS latency and the
//! detection parity of the body-withholding path (which is *unsafe* on stock
//! CRS; the report labels it accordingly).

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use serde::Deserialize;
use waf_ingress::waf::prefilter::{Prefilter, EMBEDDED_ARTIFACT};

#[derive(Debug, Deserialize)]
struct Corpus {
    #[serde(default)]
    source: String,
    #[serde(default)]
    benign: Vec<Case>,
    #[serde(default)]
    attacks: Vec<Case>,
}

#[derive(Debug, Clone, Deserialize)]
struct Case {
    name: String,
    #[serde(default)]
    family: String,
    method: String,
    uri: String,
    #[serde(default)]
    content_type: String,
    #[serde(default)]
    body: String,
}

fn main() {
    let mut corpus_path = PathBuf::from("tests/corpus/crs-prefilter-corpus.json");
    let mut reps = 5usize;
    let mut socket: Option<PathBuf> = None;
    let mut json_out: Option<PathBuf> = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--corpus" => corpus_path = args.next().map(PathBuf::from).unwrap_or(corpus_path),
            "--reps" => {
                reps = args.next().and_then(|v| v.parse().ok()).unwrap_or(reps);
            }
            "--socket" => socket = args.next().map(PathBuf::from),
            "--json-out" => json_out = args.next().map(PathBuf::from),
            "-h" | "--help" => {
                println!("crs-prefilter-bench [--corpus <json>] [--reps N] [--socket <unix>] [--json-out <json>]");
                return;
            }
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(2);
            }
        }
    }

    let load_started = Instant::now();
    let prefilter = Prefilter::from_json(EMBEDDED_ARTIFACT).expect("embedded artifact parses");
    let load_elapsed = load_started.elapsed();
    let corpus: Corpus =
        serde_json::from_str(&std::fs::read_to_string(&corpus_path).expect("corpus readable"))
            .expect("corpus parses");

    println!("# CRS prefilter benchmark");
    println!();
    println!("- corpus: `{}` ({})", corpus_path.display(), corpus.source);
    println!(
        "- artifact: {} automata, {} gated rules, {} ungated body rules, all gated: {}",
        prefilter.automaton_count(),
        prefilter.gated_rule_ids().len(),
        prefilter.ungated_body_rule_ids().len(),
        prefilter.all_body_rules_gated()
    );
    println!(
        "- artifact load + automata build: {:.1} ms",
        load_elapsed.as_secs_f64() * 1e3
    );
    println!();

    // ---- prefilter latency by body size -----------------------------------
    let mut latency = BTreeMap::new();
    for kib in [1usize, 4, 8, 16, 60] {
        let body = synthetic_body(kib * 1024);
        let mut samples = Vec::with_capacity(reps);
        for _ in 0..reps {
            let started = Instant::now();
            let hit = prefilter.evaluate(&body);
            samples.push((started.elapsed(), hit));
        }
        let durations: Vec<Duration> = samples.iter().map(|(d, _)| *d).collect();
        let (p50, p95) = percentiles(&durations);
        let hit = samples.iter().filter(|(_, h)| h.hit).count();
        let reps_scanned = samples.first().map(|(_, h)| h.representations).unwrap_or(0);
        println!(
            "| {:>2} KiB | {:>8.1} µs | {:>8.1} µs | {:>6.2} µs/KiB | {} reps | {}/{} hits |",
            kib,
            micros(p50),
            micros(p95),
            micros(p50) / kib as f64,
            reps_scanned,
            hit,
            reps
        );
        latency.insert(kib, (p50, p95));
    }

    // ---- hit rate on benign corpus ----------------------------------------
    let benign_hits = corpus
        .benign
        .iter()
        .filter(|case| {
            let body = case.body.as_bytes();
            prefilter.evaluate(body).hit
        })
        .count();
    println!();
    println!(
        "Benign corpus hit rate: {}/{} ({:.1}%)",
        benign_hits,
        corpus.benign.len(),
        percent(benign_hits, corpus.benign.len())
    );
    for case in &corpus.benign {
        let hit = prefilter.evaluate(case.body.as_bytes());
        if hit.hit {
            println!(
                "  - hit: {} (rules {:?}{})",
                case.name,
                hit.matched_rules,
                hit.forced_reason
                    .map(|r| format!(", forced: {r}"))
                    .unwrap_or_default()
            );
        }
    }

    // ---- attack corpus: does the prefilter see every attack? --------------
    let attack_hits = corpus
        .attacks
        .iter()
        .filter(|case| prefilter.evaluate(case.body.as_bytes()).hit)
        .count();
    println!();
    println!(
        "Attack corpus prefilter hit rate: {}/{} ({:.1}%)",
        attack_hits,
        corpus.attacks.len(),
        percent(attack_hits, corpus.attacks.len())
    );
    let mut misses: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for case in &corpus.attacks {
        if !prefilter.evaluate(case.body.as_bytes()).hit {
            misses
                .entry(case.family.clone())
                .or_default()
                .push(case.name.clone());
        }
    }
    for (family, names) in &misses {
        println!("  - family {family}: {}", names.join(", "));
    }

    // ---- optional sidecar measurements ------------------------------------
    #[cfg(feature = "coraza-native")]
    if let Some(socket) = socket.as_deref() {
        run_sidecar(&prefilter, &corpus, socket, reps, &latency);
    }
    #[cfg(not(feature = "coraza-native"))]
    if socket.is_some() {
        eprintln!("--socket ignored: build with `--features coraza-native`");
    }

    if let Some(path) = json_out {
        let summary = serde_json::json!({
            "benign_hits": benign_hits,
            "benign_total": corpus.benign.len(),
            "attack_hits": attack_hits,
            "attack_total": corpus.attacks.len(),
            "all_body_rules_gated": prefilter.all_body_rules_gated(),
            "automata": prefilter.automaton_count(),
            "gated_rules": prefilter.gated_rule_ids().len(),
            "ungated_body_rules": prefilter.ungated_body_rule_ids().len(),
            "latency_us": latency.iter().map(|(k, (p50, p95))| {
                (k.to_string(), serde_json::json!({"p50": micros(*p50), "p95": micros(*p95)}))
            }).collect::<BTreeMap<_, _>>(),
        });
        std::fs::write(&path, serde_json::to_string_pretty(&summary).unwrap())
            .expect("write json summary");
        println!("\nwrote {}", path.display());
    }
}

fn synthetic_body(size: usize) -> Vec<u8> {
    let seed =
        b"data=The+quick+brown+fox+jumps+over+the+lazy+dog+and+keeps+running+through+the+meadow&";
    let mut body = Vec::with_capacity(size);
    while body.len() < size {
        body.extend_from_slice(seed);
    }
    body.truncate(size);
    body
}

fn percentiles(samples: &[Duration]) -> (Duration, Duration) {
    if samples.is_empty() {
        return (Duration::ZERO, Duration::ZERO);
    }
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let p50 = sorted[sorted.len() / 2];
    let p95 = sorted[(sorted.len() * 95 / 100).min(sorted.len() - 1)];
    (p50, p95)
}

fn micros(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1_000_000.0
}

fn percent(part: usize, total: usize) -> f64 {
    if total == 0 {
        0.0
    } else {
        part as f64 * 100.0 / total as f64
    }
}

#[cfg(feature = "coraza-native")]
fn run_sidecar(
    prefilter: &Prefilter,
    corpus: &Corpus,
    socket: &std::path::Path,
    reps: usize,
    _latency: &BTreeMap<usize, (Duration, Duration)>,
) {
    use std::time::Duration;

    use waf_ingress::waf::coraza_payload::BodyInspectionPolicy;
    use waf_ingress::waf::native_coraza::{ClientConfig, NativeCorazaClient};

    let config = ClientConfig {
        socket_path: socket.to_path_buf(),
        pool_size: 4,
        timeout: Duration::from_secs(30),
        max_payload_bytes: 1024 * 1024,
    };
    let client = match NativeCorazaClient::new(&config) {
        Ok(client) => client,
        Err(err) => {
            eprintln!("sidecar unavailable at {}: {err}", socket.display());
            return;
        }
    };
    let policy = BodyInspectionPolicy::default();

    println!();
    println!("## Sidecar measurements ({} reps)", reps);
    println!();

    // Full CRS (off) vs host-gated latency for synthetic benign bodies.
    println!("| body | off p50 | gated p50 | speedup | off p95 | gated p95 | rules removed |");
    println!("|---:|---:|---:|---:|---:|---:|---:|");
    for kib in [1usize, 4, 8, 16, 60] {
        let body = synthetic_body(kib * 1024);
        let mut full = Vec::with_capacity(reps);
        let mut gated = Vec::with_capacity(reps);
        let mut removed = 0usize;
        for _ in 0..reps {
            let ctx = context(
                "POST",
                "/bench",
                "application/x-www-form-urlencoded",
                Some(&body),
            );
            let started = Instant::now();
            let _ = client.evaluate_context(&ctx, &policy);
            full.push(started.elapsed());

            let gate = prefilter.evaluate_request(&ctx);
            removed = gate.removable_rule_ids.len();
            let started = Instant::now();
            let _ = client.evaluate_context_with_rules(&ctx, &policy, &gate.removable_rule_ids);
            gated.push(started.elapsed());
        }
        let (full_p50, full_p95) = percentiles(&full);
        let (gated_p50, gated_p95) = percentiles(&gated);
        let speedup = if gated_p50.is_zero() {
            0.0
        } else {
            full_p50.as_secs_f64() / gated_p50.as_secs_f64()
        };
        println!(
            "| {} KiB | {:.2} ms | {:.2} ms | {:.1}x | {:.2} ms | {:.2} ms | {} |",
            kib,
            full_p50.as_secs_f64() * 1e3,
            gated_p50.as_secs_f64() * 1e3,
            speedup,
            full_p95.as_secs_f64() * 1e3,
            gated_p95.as_secs_f64() * 1e3,
            removed,
        );
    }

    // Detection parity: full CRS vs host-gated removals.
    println!();
    println!("## Detection parity (off vs gated)");
    println!();
    println!("| case | full CRS | gated | removed | parity |");
    println!("|---|---|---|---|---|");
    let mut false_negatives = 0usize;
    let mut false_positives = 0usize;
    let mut benign_removed = 0usize;
    let mut benign_cases = 0usize;
    for case in corpus.attacks.iter().chain(corpus.benign.iter()) {
        let ctx = context(
            &case.method,
            &case.uri,
            &case.content_type,
            if case.body.is_empty() {
                None
            } else {
                Some(case.body.as_bytes())
            },
        );
        let gate = prefilter.evaluate_request(&ctx);
        let removed = gate.removable_rule_ids.len();
        let full = eval_decision(&client, &ctx, &policy);
        let gated_decision =
            eval_decision_with_rules(&client, &ctx, &policy, &gate.removable_rule_ids);
        let parity = if full == "block" && gated_decision != "block" {
            false_negatives += 1;
            "FALSE NEGATIVE".to_string()
        } else if full != "block" && gated_decision == "block" {
            false_positives += 1;
            "false positive".to_string()
        } else {
            "ok".to_string()
        };
        if corpus.benign.iter().any(|b| b.name == case.name) {
            benign_cases += 1;
            benign_removed += removed;
        }
        if parity != "ok" {
            println!(
                "| {} ({}) | {} | {} | {} | {} |",
                case.name, case.family, full, gated_decision, removed, parity
            );
        }
    }
    println!();
    println!(
        "Detection parity: {} false negatives, {} false positives over {} cases.",
        false_negatives,
        false_positives,
        corpus.attacks.len() + corpus.benign.len()
    );
    println!(
        "Rules removed on benign corpus: {} total over {} cases ({:.1} per request).",
        benign_removed,
        benign_cases,
        if benign_cases == 0 {
            0.0
        } else {
            benign_removed as f64 / benign_cases as f64
        }
    );
}

#[cfg(feature = "coraza-native")]
fn context(
    method: &str,
    uri: &str,
    content_type: &str,
    body: Option<&[u8]>,
) -> waf_ingress::waf::RequestContext {
    use std::net::{IpAddr, Ipv4Addr};

    use bytes::Bytes;
    use hyper::{HeaderMap, Method, Uri};
    use waf_ingress::waf::RequestContext;

    let method = Method::from_bytes(method.as_bytes()).unwrap_or(Method::GET);
    let uri: Uri = uri.parse().unwrap_or_else(|_| "/".parse().unwrap());
    let mut headers = HeaderMap::new();
    headers.insert("host", "bench.local".parse().unwrap());
    headers.insert("user-agent", "crs-prefilter-bench/1.0".parse().unwrap());
    if !content_type.is_empty() {
        headers.insert("content-type", content_type.parse().unwrap());
    }
    let mut ctx = RequestContext::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        method,
        uri,
        headers,
        body.map(<[u8]>::len),
    );
    if let Some(body) = body {
        ctx.body = Some(Bytes::copy_from_slice(body));
    }
    ctx
}

#[cfg(feature = "coraza-native")]
fn eval_decision(
    client: &waf_ingress::waf::native_coraza::NativeCorazaClient,
    ctx: &waf_ingress::waf::RequestContext,
    policy: &waf_ingress::waf::coraza_payload::BodyInspectionPolicy,
) -> &'static str {
    eval_decision_with_rules(client, ctx, policy, &[])
}

#[cfg(feature = "coraza-native")]
fn eval_decision_with_rules(
    client: &waf_ingress::waf::native_coraza::NativeCorazaClient,
    ctx: &waf_ingress::waf::RequestContext,
    policy: &waf_ingress::waf::coraza_payload::BodyInspectionPolicy,
    remove_rule_ids: &[u32],
) -> &'static str {
    use waf_ingress::waf::native_coraza::Evaluation;
    use waf_ingress::waf::Decision;

    match client.evaluate_context_with_rules(ctx, policy, remove_rule_ids) {
        Ok(Evaluation::Decided { decision, .. }) => match decision {
            Decision::Block { .. } => "block",
            Decision::Allow => "allow",
            Decision::RateLimit { .. } => "ratelimit",
        },
        Ok(Evaluation::BodyRejected { .. }) => "block",
        Err(_) => "error",
    }
}
