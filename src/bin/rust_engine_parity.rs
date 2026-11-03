//! Differential parity harness for the native Rust CRS engine.
//!
//! Runs the pinned OWASP CRS detection corpus through the native engine and
//! the existing Coraza WASI reactor, compares decisions, prints the support
//! matrix and (with `--bench`) a p50/p95 latency table.
//!
//! ```text
//! cargo run --features rust-engine --bin rust-engine-parity -- --report-only
//! cargo run --features rust-engine --bin rust-engine-parity -- --engine both
//! cargo run --features rust-engine --bin rust-engine-parity -- --bench
//! ```

use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use clap::{Parser, ValueEnum};
use serde::Serialize;

struct CountingAllocator;

static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

// SAFETY: delegates every operation to the system allocator and only adds a
// counter, which cannot affect pointer validity or layout.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        #[cfg(feature = "engine-profile")]
        waf_ingress::waf::rust_engine::profile::ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        System.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        #[cfg(feature = "engine-profile")]
        waf_ingress::waf::rust_engine::profile::ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

use waf_ingress::waf::coraza_corpus::{Corpus, CorpusCase, Expected, Observed};
use waf_ingress::waf::rust_engine::{
    default_crs_conf_path, CompilePolicy, EngineRequest, RustEngine, SupportReport,
};
use waf_ingress::waf::Decision;

#[cfg(feature = "wasm-reactor")]
use waf_ingress::waf::wasm_reactor::{ReactorDecision, WasmReactor, EMBEDDED_CORAZA_REACTOR};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum EngineChoice {
    Rust,
    Coraza,
    Both,
}

#[derive(Debug, Parser)]
#[command(
    name = "rust-engine-parity",
    about = "Native Rust CRS engine support matrix, parity and latency harness",
    version
)]
struct Args {
    /// Pinned CRS bundle.
    #[arg(long, default_value_os_t = default_crs_conf_path())]
    conf: PathBuf,

    /// Detection corpus.
    #[arg(long, default_value = "tests/corpus/crs/corpus.json")]
    corpus: PathBuf,

    /// Engine(s) to run.
    #[arg(long, value_enum, default_value_t = EngineChoice::Both)]
    engine: EngineChoice,

    /// Only run cases carrying at least one of these tags.
    #[arg(long, value_delimiter = ',')]
    filter: Vec<String>,

    /// Only run cases whose id contains one of these substrings.
    #[arg(long, value_delimiter = ',')]
    id: Vec<String>,

    /// Stop after this many cases.
    #[arg(long)]
    limit: Option<usize>,

    /// Print the support matrix and exit.
    #[arg(long)]
    report_only: bool,

    /// Abort the load on unsupported constructs instead of reporting them.
    #[arg(long)]
    strict: bool,

    /// Write the machine-readable report here.
    #[arg(long)]
    json: Option<PathBuf>,

    /// Print every disagreement (otherwise the first 50).
    #[arg(long)]
    verbose: bool,

    /// Run the latency benchmark instead of the corpus.
    #[arg(long)]
    bench: bool,

    /// Print the per-category hot-loop profile (requires `engine-profile`).
    #[arg(long)]
    profile: bool,

    /// Repetitions per latency row.
    #[arg(long, default_value_t = 100)]
    reps: usize,
}

fn main() -> ExitCode {
    let args = Args::parse();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::from(1)
        }
    }
}

fn run(args: &Args) -> Result<(), String> {
    let policy = if args.strict {
        CompilePolicy::Strict
    } else {
        CompilePolicy::Report
    };
    let engine = RustEngine::from_conf_path_with_policy(&args.conf, policy)
        .map_err(|err| format!("failed to load `{}`: {err}", args.conf.display()))?;

    print_support(engine.support_report());
    if args.report_only {
        return Ok(());
    }
    if args.profile {
        #[cfg(feature = "engine-profile")]
        {
            return profile(args, &engine);
        }
        #[cfg(not(feature = "engine-profile"))]
        {
            return Err("--profile requires the `engine-profile` feature".to_string());
        }
    }
    if args.bench {
        return bench(args, &engine);
    }

    let corpus = Corpus::from_path(&args.corpus)
        .map_err(|err| format!("failed to load corpus `{}`: {err}", args.corpus.display()))?;
    let mut cases = corpus.filter_by_tags(&args.filter);
    if !args.id.is_empty() {
        cases.retain(|case| args.id.iter().any(|id| case.id.contains(id)));
    }
    if let Some(limit) = args.limit {
        cases.truncate(limit);
    }
    if cases.is_empty() {
        return Err(format!("no corpus cases matched filter {:?}", args.filter));
    }

    let coraza = matches!(args.engine, EngineChoice::Coraza | EngineChoice::Both);
    let rust = matches!(args.engine, EngineChoice::Rust | EngineChoice::Both);

    #[cfg(feature = "wasm-reactor")]
    let reactor = if coraza {
        Some(
            WasmReactor::from_coraza_bytes(EMBEDDED_CORAZA_REACTOR)
                .map_err(|err| format!("failed to load Coraza reactor: {err}"))?,
        )
    } else {
        None
    };
    #[cfg(not(feature = "wasm-reactor"))]
    let reactor: Option<()> = None;
    #[cfg(not(feature = "wasm-reactor"))]
    if coraza {
        return Err("the Coraza comparison requires the `wasm-reactor` feature".to_string());
    }

    let mut report = Report {
        unsupported: engine.support_report().unsupported.len(),
        rules_compiled: engine.support_report().rules_compiled,
        rules_skipped: engine.support_report().rules_skipped,
        ..Report::default()
    };

    for case in &cases {
        let mut row = CaseRow {
            id: case.id.clone(),
            expected: case.expected,
            rust: None,
            coraza: None,
            rust_rules: Vec::new(),
            rust_error: None,
            coraza_error: None,
        };
        if rust {
            match evaluate_rust(&engine, case) {
                Ok((observed, matched)) => {
                    row.rust = Some(observed);
                    row.rust_rules = matched;
                    report.rust.record(observed);
                }
                Err(err) => {
                    row.rust_error = Some(err);
                    report.rust.errors += 1;
                }
            }
        }
        if coraza {
            #[cfg(feature = "wasm-reactor")]
            match evaluate_coraza(reactor.as_ref().expect("reactor"), case) {
                Ok(observed) => {
                    row.coraza = Some(observed);
                    report.coraza.record(observed);
                }
                Err(err) => {
                    row.coraza_error = Some(err);
                    report.coraza.errors += 1;
                }
            }
        }
        report.total += 1;
        report.cases.push(row.clone());
        if let (Some(rust), Some(coraza)) = (row.rust, row.coraza) {
            if rust == coraza {
                report.agree += 1;
            } else {
                report.disagree += 1;
                report.disagreements.push(row.clone());
            }
        }
        match (case.expected, row.rust) {
            (Expected::Block, Some(Observed::Allow)) => report.rust_false_negatives += 1,
            (Expected::Allow, Some(Observed::Block)) => report.rust_false_positives += 1,
            _ => {}
        }
        match (case.expected, row.coraza) {
            (Expected::Block, Some(Observed::Allow)) => report.coraza_false_negatives += 1,
            (Expected::Allow, Some(Observed::Block)) => report.coraza_false_positives += 1,
            _ => {}
        }
    }

    print_report(&report, args.verbose);
    if let Some(path) = &args.json {
        let json = serde_json::to_vec_pretty(&report)
            .map_err(|err| format!("failed to serialise report: {err}"))?;
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .map_err(|err| format!("failed to create `{}`: {err}", parent.display()))?;
            }
        }
        std::fs::write(path, json)
            .map_err(|err| format!("failed to write `{}`: {err}", path.display()))?;
        println!("report written to {}", path.display());
    }
    Ok(())
}

fn print_support(report: &SupportReport) {
    let supported = report
        .constructs
        .values()
        .filter(|entry| entry.supported)
        .count();
    let unsupported_constructs = report
        .constructs
        .values()
        .filter(|entry| !entry.supported)
        .count();
    println!(
        "support: {} directives, {} rules seen, {} compiled, {} skipped, {} unsupported constructs",
        report.directives,
        report.rules_seen,
        report.rules_compiled,
        report.rules_skipped,
        report.unsupported.len()
    );
    println!("constructs: {supported} supported, {unsupported_constructs} unsupported");
    if !report.unsupported.is_empty() {
        println!("unsupported rules:");
        for unsupported in &report.unsupported {
            println!("  - {unsupported}");
        }
    }
    let mut families: BTreeMap<String, usize> = BTreeMap::new();
    for construct in report.constructs.keys() {
        let family = construct.split(':').next().unwrap_or(construct);
        *families.entry(family.to_string()).or_default() += 1;
    }
    let summary: Vec<String> = families
        .iter()
        .map(|(family, count)| format!("{family}={count}"))
        .collect();
    println!("construct families: {}", summary.join(", "));
}

fn evaluate_rust(engine: &RustEngine, case: &CorpusCase) -> Result<(Observed, Vec<u32>), String> {
    let headers: Vec<(String, String)> = case
        .request
        .headers
        .iter()
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect();
    let body = case.request.body.as_ref().map(|body| body.as_bytes());
    let request = EngineRequest {
        method: &case.request.method,
        uri: &case.request.uri,
        http_version: &case.request.http_version,
        headers: &headers,
        body,
    };
    match engine.evaluate_detailed(&request) {
        Ok(outcome) => {
            let observed = match outcome.decision {
                Decision::Allow => Observed::Allow,
                Decision::Block { .. } | Decision::RateLimit { .. } => Observed::Block,
            };
            Ok((observed, outcome.matched_rules))
        }
        Err(err) => Err(err.to_string()),
    }
}

#[cfg(feature = "wasm-reactor")]
fn evaluate_coraza(reactor: &WasmReactor, case: &CorpusCase) -> Result<Observed, String> {
    let payload = case
        .request
        .to_payload()
        .map_err(|err| format!("payload encoding failed: {err}"))?;
    match reactor.evaluate(&payload) {
        Ok(ReactorDecision::Allow) => Ok(Observed::Allow),
        Ok(ReactorDecision::Block { .. }) => Ok(Observed::Block),
        Err(err) => Err(err.to_string()),
    }
}

#[derive(Debug, Default, Serialize)]
struct Report {
    total: usize,
    agree: usize,
    disagree: usize,
    rust_false_negatives: usize,
    rust_false_positives: usize,
    coraza_false_negatives: usize,
    coraza_false_positives: usize,
    unsupported: usize,
    rules_compiled: usize,
    rules_skipped: usize,
    rust: EngineCounts,
    coraza: EngineCounts,
    disagreements: Vec<CaseRow>,
    cases: Vec<CaseRow>,
}

#[derive(Debug, Default, Serialize)]
struct EngineCounts {
    allow: usize,
    block: usize,
    errors: usize,
}

impl EngineCounts {
    fn record(&mut self, observed: Observed) {
        match observed {
            Observed::Allow => self.allow += 1,
            Observed::Block => self.block += 1,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct CaseRow {
    id: String,
    expected: Expected,
    rust: Option<Observed>,
    coraza: Option<Observed>,
    rust_rules: Vec<u32>,
    rust_error: Option<String>,
    coraza_error: Option<String>,
}

fn print_report(report: &Report, verbose: bool) {
    println!(
        "corpus: {} cases, rust/coraza agree {}/{} ({:.2}%)",
        report.total,
        report.agree,
        report.total,
        percentage(report.agree, report.total)
    );
    println!(
        "rust:   allow {} block {} errors {} | vs expected: FN {} FP {}",
        report.rust.allow,
        report.rust.block,
        report.rust.errors,
        report.rust_false_negatives,
        report.rust_false_positives
    );
    println!(
        "coraza: allow {} block {} errors {} | vs expected: FN {} FP {}",
        report.coraza.allow,
        report.coraza.block,
        report.coraza.errors,
        report.coraza_false_negatives,
        report.coraza_false_positives
    );
    println!(
        "unsupported: {} constructs across {} skipped rules ({} compiled)",
        report.unsupported, report.rules_skipped, report.rules_compiled
    );
    if report.disagree > 0 {
        println!("disagreements:");
        let limit = if verbose {
            report.disagreements.len()
        } else {
            50
        };
        for row in report.disagreements.iter().take(limit) {
            println!(
                "  - {} expected={:?} rust={:?} coraza={:?} rust_rules={:?}",
                row.id, row.expected, row.rust, row.coraza, row.rust_rules
            );
        }
    }
    if verbose {
        println!("all cases:");
        for row in &report.cases {
            println!(
                "  - {} expected={:?} rust={:?} coraza={:?} rust_rules={:?}",
                row.id, row.expected, row.rust, row.coraza, row.rust_rules
            );
        }
    }
}

fn percentage(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 * 100.0 / denominator as f64
    }
}

#[cfg(feature = "engine-profile")]
fn profile(args: &Args, engine: &RustEngine) -> Result<(), String> {
    use waf_ingress::waf::rust_engine::profile::Report;

    let rows = [
        ("bodyless", 0usize),
        ("1KiB", 1024),
        ("4KiB", 4096),
        ("8KiB", 8192),
    ];
    println!(
        "{:<10} {:>9} {:>9} {:>9} {:>9} {:>9} {:>9} {:>9} {:>8} {:>8}",
        "body", "parse", "xform", "cand", "gate", "regex", "score", "capture", "rules", "skipped"
    );
    println!(
        "{:<10} {:>9} {:>9} {:>9} {:>9} {:>9} {:>9} {:>9} {:>8} {:>8}",
        "", "ns", "ns", "ns", "ns", "ns", "ns", "ns", "run", "gate"
    );
    for (label, size) in rows {
        let (headers, body) = bench_request(size);
        let request = EngineRequest {
            method: "POST",
            uri: "/post",
            http_version: "HTTP/1.1",
            headers: &headers,
            body: if size == 0 { None } else { Some(&body) },
        };
        for _ in 0..20 {
            let _ = engine.evaluate(&request);
        }
        let mut total = Report::default();
        for _ in 0..args.reps.max(1) {
            let (_, report) = engine.evaluate_profiled(&request);
            total.parse_ns += report.parse_ns;
            total.transforms_ns += report.transforms_ns;
            total.candidates_ns += report.candidates_ns;
            total.gate_ns += report.gate_ns;
            total.operators_ns += report.operators_ns;
            total.scoring_ns += report.scoring_ns;
            total.captures_ns += report.captures_ns;
            total.regex_evaluations += report.regex_evaluations;
            total.regex_skipped += report.regex_skipped;
        }
        let reps = args.reps.max(1) as f64;
        println!(
            "{:<10} {:>9.0} {:>9.0} {:>9.0} {:>9.0} {:>9.0} {:>9.0} {:>9.0} {:>8.1} {:>8.1}",
            label,
            total.parse_ns as f64 / reps,
            total.transforms_ns as f64 / reps,
            total.candidates_ns as f64 / reps,
            total.gate_ns as f64 / reps,
            total.operators_ns as f64 / reps,
            total.scoring_ns as f64 / reps,
            total.captures_ns as f64 / reps,
            total.regex_evaluations as f64 / reps,
            total.regex_skipped as f64 / reps,
        );
    }
    println!(
        "note: `xform` is transform cache misses + pipeline application; `regex` is\
         operator time; per-category allocation deltas are in the engine-profile report"
    );
    println!(
        "{:<10} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8}",
        "body",
        "parse",
        "xform",
        "cand",
        "gate",
        "regex",
        "score",
        "capture",
        "tx",
        "matched",
        "total",
        "unacct"
    );
    for (label, size) in rows {
        let (headers, body) = bench_request(size);
        let request = EngineRequest {
            method: "POST",
            uri: "/post",
            http_version: "HTTP/1.1",
            headers: &headers,
            body: if size == 0 { None } else { Some(&body) },
        };
        let mut all = Report::default();
        for _ in 0..args.reps.max(1) {
            let (_, report) = engine.evaluate_profiled(&request);
            all.parse_allocs += report.parse_allocs;
            all.transforms_allocs += report.transforms_allocs;
            all.candidates_allocs += report.candidates_allocs;
            all.gate_allocs += report.gate_allocs;
            all.operators_allocs += report.operators_allocs;
            all.scoring_allocs += report.scoring_allocs;
            all.captures_allocs += report.captures_allocs;
            all.tx_allocs += report.tx_allocs;
            all.matched_allocs += report.matched_allocs;
            all.total_allocs += report.total_allocs;
        }
        let reps = args.reps.max(1) as f64;
        let total = all.parse_allocs
            + all.transforms_allocs
            + all.candidates_allocs
            + all.gate_allocs
            + all.operators_allocs
            + all.scoring_allocs
            + all.captures_allocs
            + all.tx_allocs
            + all.matched_allocs;
        let unaccounted = all.total_allocs.saturating_sub(total);
        println!(
            "{:<10} {:>8.1} {:>8.1} {:>8.1} {:>8.1} {:>8.1} {:>8.1} {:>8.1} {:>8.1} {:>8.1} {:>8.1} {:>8.1}",
            label,
            all.parse_allocs as f64 / reps,
            all.transforms_allocs as f64 / reps,
            all.candidates_allocs as f64 / reps,
            all.gate_allocs as f64 / reps,
            all.operators_allocs as f64 / reps,
            all.scoring_allocs as f64 / reps,
            all.captures_allocs as f64 / reps,
            all.tx_allocs as f64 / reps,
            all.matched_allocs as f64 / reps,
            total as f64 / reps,
            unaccounted as f64 / reps,
        );
    }
    Ok(())
}

#[cfg(feature = "wasm-reactor")]
fn bench(args: &Args, engine: &RustEngine) -> Result<(), String> {
    let reactor = WasmReactor::from_coraza_bytes(EMBEDDED_CORAZA_REACTOR)
        .map_err(|err| format!("failed to load Coraza reactor: {err}"))?;
    let rows = [
        ("bodyless", 0usize),
        ("1KiB", 1024),
        ("4KiB", 4096),
        ("8KiB", 8192),
    ];
    println!(
        "{:<10} {:>11} {:>11} {:>11} {:>11} {:>11} {:>11} {:>10}",
        "body",
        "rust p50",
        "rust p99",
        "coraza p50",
        "coraza p99",
        "rust p95",
        "coraza p95",
        "alloc/req"
    );
    for (label, size) in rows {
        let (headers, body) = bench_request(size);
        let header_pairs: Vec<(String, String)> = headers.clone();
        let request = EngineRequest {
            method: "POST",
            uri: "/post",
            http_version: "HTTP/1.1",
            headers: &header_pairs,
            body: if size == 0 { None } else { Some(&body) },
        };
        ALLOCATIONS.store(0, Ordering::Relaxed);
        let rust_samples = measure(args.reps, || {
            let _ = engine.evaluate(&request);
        });
        let rust_allocs = ALLOCATIONS.load(Ordering::Relaxed) as f64 / args.reps as f64;
        let payload = bench_payload(&headers, if size == 0 { None } else { Some(&body) });
        let coraza_samples = measure(args.reps, || {
            let _ = reactor.evaluate(&payload);
        });
        println!(
            "{:<10} {:>9.2}µs {:>9.2}µs {:>9.2}µs {:>9.2}µs {:>9.2}µs {:>9.2}µs {:>10.1}",
            label,
            percentile(&rust_samples, 50.0),
            percentile(&rust_samples, 99.0),
            percentile(&coraza_samples, 50.0),
            percentile(&coraza_samples, 99.0),
            percentile(&rust_samples, 95.0),
            percentile(&coraza_samples, 95.0),
            rust_allocs
        );
    }
    Ok(())
}

#[cfg(not(feature = "wasm-reactor"))]
fn bench(args: &Args, engine: &RustEngine) -> Result<(), String> {
    let rows = [
        ("bodyless", 0usize),
        ("1KiB", 1024),
        ("4KiB", 4096),
        ("8KiB", 8192),
    ];
    println!(
        "{:<10} {:>11} {:>11} {:>11} {:>10}",
        "body", "rust p50", "rust p99", "rust p95", "alloc/req"
    );
    for (label, size) in rows {
        let (headers, body) = bench_request(size);
        let request = EngineRequest {
            method: "POST",
            uri: "/post",
            http_version: "HTTP/1.1",
            headers: &headers,
            body: if size == 0 { None } else { Some(&body) },
        };
        ALLOCATIONS.store(0, Ordering::Relaxed);
        let samples = measure(args.reps, || {
            let _ = engine.evaluate(&request);
        });
        let allocs = ALLOCATIONS.load(Ordering::Relaxed) as f64 / args.reps as f64;
        println!(
            "{:<10} {:>9.2}µs {:>9.2}µs {:>9.2}µs {:>10.1}",
            label,
            percentile(&samples, 50.0),
            percentile(&samples, 99.0),
            percentile(&samples, 95.0),
            allocs
        );
    }
    println!("coraza: rebuild with the `wasm-reactor` feature for the A/B table");
    Ok(())
}

fn bench_request(size: usize) -> (Vec<(String, String)>, Vec<u8>) {
    let body = if size == 0 {
        Vec::new()
    } else {
        format!("data={}", "A".repeat(size)).into_bytes()
    };
    let headers = vec![
        ("Host".to_string(), "localhost".to_string()),
        ("User-Agent".to_string(), "OWASP CRS test agent".to_string()),
        (
            "Accept".to_string(),
            "text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5"
                .to_string(),
        ),
        (
            "Content-Type".to_string(),
            "application/x-www-form-urlencoded".to_string(),
        ),
        ("Content-Length".to_string(), body.len().to_string()),
    ];
    (headers, body)
}

#[cfg(feature = "wasm-reactor")]
fn bench_payload(headers: &[(String, String)], body: Option<&[u8]>) -> Vec<u8> {
    let headers: Vec<(&str, &str)> = headers
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();
    serde_json::to_vec(&serde_json::json!({
        "method": "POST",
        "uri": "/post",
        "http_version": "HTTP/1.1",
        "headers": headers,
        "body_size": body.map(<[u8]>::len),
        "body_original_size": body.map(<[u8]>::len),
        "body_encoding": "utf8",
        "body": body.and_then(|body| std::str::from_utf8(body).ok()),
    }))
    .expect("payload")
}

fn measure(reps: usize, mut run: impl FnMut()) -> Vec<Duration> {
    let mut samples = Vec::with_capacity(reps);
    for _ in 0..reps {
        let start = Instant::now();
        run();
        samples.push(start.elapsed());
    }
    samples.sort();
    samples
}

fn percentile(samples: &[Duration], percentile: f64) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }
    let index = ((percentile / 100.0) * (samples.len() - 1) as f64).round() as usize;
    samples[index].as_secs_f64() * 1_000_000.0
}
