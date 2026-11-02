//! Runs the pinned OWASP CRS detection corpus through the Coraza backends.
//!
//! The harness is intentionally a thin driver: corpus parsing, validation,
//! filtering and decision mapping live in [`waf_ingress::waf::coraza_corpus`],
//! while this binary owns engine construction and reporting.
//!
//! ```text
//! cargo run --bin crs_corpus -- --engine wasm
//! cargo run --bin crs_corpus --features wasm-reactor,coraza-native \
//!     -- --engine both --json target/crs-corpus.json
//! ```
//!
//! Exit codes: `0` when the run completed (even with mismatches), `1` for a
//! fatal error, `2` for an invalid invocation/corpus, and `3` when
//! `--fail-on-mismatch` was set and at least one case failed or errored.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::ExitCode;

#[cfg(all(feature = "coraza-native", unix))]
use std::time::Duration;

use clap::{Parser, ValueEnum};
use serde::Serialize;
use waf_ingress::waf::coraza_corpus::{
    judge, CaseResult, Corpus, CorpusCase, Expected, Observed, DEFAULT_CORPUS_PATH,
};

#[cfg(feature = "wasm-reactor")]
use waf_ingress::waf::wasm_reactor::{ReactorDecision, WasmReactor, EMBEDDED_CORAZA_REACTOR};

#[cfg(feature = "fastpath")]
use waf_ingress::waf::fastpath::{FastPath, FastPathDecision, FastPathRequest};

#[cfg(all(feature = "coraza-native", unix))]
use waf_ingress::waf::native_coraza::{ClientConfig, NativeCorazaClient};

/// Engine selection for the harness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum EngineChoice {
    /// Run only the WASI reactor (requires `wasm-reactor`).
    Wasm,
    /// Run only the native Go sidecar (requires `coraza-native` and a socket).
    Native,
    /// Run both and compare their decisions.
    Both,
    /// Run only the experimental compiled Rust fast path (requires `fastpath`).
    Fastpath,
}

impl std::fmt::Display for EngineChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Wasm => f.write_str("wasm"),
            Self::Native => f.write_str("native"),
            Self::Both => f.write_str("both"),
            Self::Fastpath => f.write_str("fastpath"),
        }
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "crs_corpus",
    about = "Run the pinned OWASP CRS detection corpus through the Coraza backends",
    version
)]
struct Args {
    /// Corpus JSON file.
    #[arg(long, default_value = DEFAULT_CORPUS_PATH)]
    corpus: PathBuf,

    /// Engine(s) to run.
    #[arg(long, value_enum, default_value_t = EngineChoice::Wasm)]
    engine: EngineChoice,

    /// Only run cases carrying at least one of these tags (repeatable or comma-separated).
    #[arg(long, value_delimiter = ',')]
    filter: Vec<String>,

    /// Stop after this many filtered cases.
    #[arg(long)]
    limit: Option<usize>,

    /// Write the full machine-readable report here.
    #[arg(long)]
    json: Option<PathBuf>,

    /// Optional reactor module path. Defaults to the embedded module.
    #[arg(long)]
    module: Option<PathBuf>,

    /// Native sidecar Unix socket.
    #[arg(long, default_value = "/run/waf/coraza.sock")]
    native_socket: PathBuf,

    /// Per-evaluation timeout for the native client, in milliseconds.
    #[arg(long, default_value_t = 5000)]
    native_timeout_ms: u64,

    /// Print every case instead of only failures.
    #[arg(long)]
    verbose: bool,

    /// Return exit code 3 when any case fails or errors.
    #[arg(long)]
    fail_on_mismatch: bool,
}

fn main() -> ExitCode {
    let args = Args::parse();
    match run(&args) {
        Ok(code) => code,
        Err(FatalError::Usage(message)) => {
            eprintln!("error: {message}");
            ExitCode::from(2)
        }
        Err(FatalError::Fatal(message)) => {
            eprintln!("error: {message}");
            ExitCode::from(1)
        }
    }
}

enum FatalError {
    Usage(String),
    Fatal(String),
}

fn run(args: &Args) -> Result<ExitCode, FatalError> {
    let corpus =
        Corpus::from_path(&args.corpus).map_err(|err| FatalError::Usage(err.to_string()))?;
    let mut cases = corpus.filter_by_tags(&args.filter);
    if let Some(limit) = args.limit {
        cases.truncate(limit);
    }
    if cases.is_empty() {
        return Err(FatalError::Usage(format!(
            "no corpus cases matched filter {:?}",
            args.filter
        )));
    }

    println!(
        "CRS detection corpus v{}: {} cases ({} {} @ {})",
        corpus.format_version,
        cases.len(),
        corpus.source.project,
        corpus.source.version,
        short_commit(&corpus.source.commit)
    );
    println!("source sha256: {}", corpus.source.sha256);

    let mut report = Report {
        corpus: ReportCorpus {
            format_version: corpus.format_version,
            project: corpus.source.project.clone(),
            version: corpus.source.version.clone(),
            commit: corpus.source.commit.clone(),
            sha256: corpus.source.sha256.clone(),
            cases: cases.len(),
        },
        engines: BTreeMap::new(),
        parity: None,
        fastpath: None,
    };

    let run_wasm = matches!(args.engine, EngineChoice::Wasm | EngineChoice::Both);
    let run_native = matches!(args.engine, EngineChoice::Native | EngineChoice::Both);
    let run_fastpath = matches!(args.engine, EngineChoice::Fastpath);

    let mut wasm_report = None;
    if run_wasm {
        let engine_report = run_wasm_engine(&cases, args)?;
        print_engine_summary(&engine_report, args.verbose);
        if engine_report.available {
            wasm_report = Some(engine_report.clone());
        }
        report.engines.insert("wasm".to_string(), engine_report);
    }

    let mut native_report = None;
    if run_native {
        let engine_report = run_native_engine(&cases, args)?;
        print_engine_summary(&engine_report, args.verbose);
        if engine_report.available {
            native_report = Some(engine_report.clone());
        }
        report.engines.insert("native".to_string(), engine_report);
    }

    if let (Some(wasm), Some(native)) = (&wasm_report, &native_report) {
        if wasm.available && native.available {
            let parity = compare_engines(wasm, native);
            print_parity_summary(&parity);
            report.parity = Some(parity);
        }
    }

    if run_fastpath {
        let fastpath_report = run_fastpath_engine(&cases)?;
        print_fastpath_summary(&fastpath_report);
        report.fastpath = Some(fastpath_report);
    }

    if let Some(path) = &args.json {
        let json = serde_json::to_vec_pretty(&report)
            .map_err(|err| FatalError::Fatal(format!("failed to serialise report: {err}")))?;
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|err| {
                    FatalError::Fatal(format!(
                        "failed to create report directory `{}`: {err}",
                        parent.display()
                    ))
                })?;
            }
        }
        std::fs::write(path, json).map_err(|err| {
            FatalError::Fatal(format!("failed to write `{}`: {err}", path.display()))
        })?;
        println!("report written to {}", path.display());
    }

    let failed = report
        .engines
        .values()
        .any(|engine| engine.false_negatives + engine.false_positives + engine.errors > 0);
    let fastpath_failed = report.fastpath.as_ref().is_some_and(|fastpath| {
        fastpath
            .cases
            .iter()
            .any(|case| case.clean && case.expected == Expected::Block)
    });
    if args.fail_on_mismatch && (failed || fastpath_failed) {
        return Ok(ExitCode::from(3));
    }
    Ok(ExitCode::SUCCESS)
}

fn short_commit(commit: &str) -> &str {
    commit.get(..12).unwrap_or(commit)
}

#[derive(Serialize)]
struct Report {
    corpus: ReportCorpus,
    engines: BTreeMap<String, EngineReport>,
    parity: Option<ParityReport>,
    fastpath: Option<FastpathReport>,
}

#[derive(Debug, Clone, Serialize)]
struct FastpathReport {
    total: usize,
    clean: usize,
    fallback: usize,
    by_reason: BTreeMap<String, usize>,
    cases: Vec<FastpathCaseReport>,
}

#[derive(Debug, Clone, Serialize)]
struct FastpathCaseReport {
    id: String,
    expected: Expected,
    clean: bool,
    reason: Option<String>,
}

#[derive(Serialize)]
struct ReportCorpus {
    format_version: u32,
    project: String,
    version: String,
    commit: String,
    sha256: String,
    cases: usize,
}

#[derive(Debug, Clone, Serialize)]
struct EngineReport {
    engine: String,
    available: bool,
    skip_reason: Option<String>,
    total: usize,
    passed: usize,
    false_negatives: usize,
    false_positives: usize,
    errors: usize,
    positives: usize,
    detected: usize,
    detection_rate: Option<f64>,
    by_tag: BTreeMap<String, TagReport>,
    cases: Vec<CaseReport>,
}

#[cfg_attr(
    not(any(feature = "wasm-reactor", all(feature = "coraza-native", unix))),
    allow(dead_code)
)]
impl EngineReport {
    fn new(engine: &str) -> Self {
        Self {
            engine: engine.to_string(),
            available: true,
            skip_reason: None,
            total: 0,
            passed: 0,
            false_negatives: 0,
            false_positives: 0,
            errors: 0,
            positives: 0,
            detected: 0,
            detection_rate: None,
            by_tag: BTreeMap::new(),
            cases: Vec::new(),
        }
    }

    fn skipped(engine: &str, reason: impl Into<String>) -> Self {
        let mut report = Self::new(engine);
        report.available = false;
        report.skip_reason = Some(reason.into());
        report
    }

    fn record(&mut self, case: &CorpusCase, observed: Option<Observed>, error: Option<String>) {
        let result = match (case.expected, observed) {
            (_, Some(observed)) => Some(judge(case.expected, observed)),
            (_, None) => None,
        };

        self.total += 1;
        if case.expected == Expected::Block {
            self.positives += 1;
        }
        match result {
            Some(CaseResult::Pass) => {
                self.passed += 1;
                if case.expected == Expected::Block {
                    self.detected += 1;
                }
            }
            Some(CaseResult::FalseNegative) => self.false_negatives += 1,
            Some(CaseResult::FalsePositive) => self.false_positives += 1,
            None => self.errors += 1,
        }

        for tag in &case.tags {
            let entry = self.by_tag.entry(tag.clone()).or_default();
            entry.total += 1;
            if case.expected == Expected::Block {
                entry.positives += 1;
            }
            match result {
                Some(CaseResult::Pass) => {
                    entry.passed += 1;
                    if case.expected == Expected::Block {
                        entry.detected += 1;
                    }
                }
                Some(CaseResult::FalseNegative) => entry.false_negatives += 1,
                Some(CaseResult::FalsePositive) => entry.false_positives += 1,
                None => entry.errors += 1,
            }
        }

        self.cases.push(CaseReport {
            id: case.id.clone(),
            description: case.description.clone(),
            expected: case.expected,
            observed,
            result,
            error,
            tags: case.tags.clone(),
        });
    }

    fn finish(&mut self) {
        self.detection_rate = rate(self.detected, self.positives);
        for tag in self.by_tag.values_mut() {
            tag.detection_rate = rate(tag.detected, tag.positives);
        }
    }
}

#[derive(Debug, Clone, Default, Serialize)]
struct TagReport {
    total: usize,
    positives: usize,
    detected: usize,
    passed: usize,
    false_negatives: usize,
    false_positives: usize,
    errors: usize,
    detection_rate: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
struct CaseReport {
    id: String,
    description: String,
    expected: Expected,
    observed: Option<Observed>,
    result: Option<CaseResult>,
    error: Option<String>,
    tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct ParityReport {
    compared: usize,
    agree: usize,
    disagree: usize,
    disagreements: Vec<ParityDisagreement>,
}

#[derive(Debug, Clone, Serialize)]
struct ParityDisagreement {
    id: String,
    wasm: Option<Observed>,
    native: Option<Observed>,
    wasm_error: Option<String>,
    native_error: Option<String>,
}

fn rate(numerator: usize, denominator: usize) -> Option<f64> {
    if denominator == 0 {
        None
    } else {
        Some(numerator as f64 / denominator as f64)
    }
}

#[cfg(feature = "wasm-reactor")]
fn run_wasm_engine(cases: &[&CorpusCase], args: &Args) -> Result<EngineReport, FatalError> {
    let reactor = match &args.module {
        Some(path) => WasmReactor::from_coraza_file(path),
        None => WasmReactor::from_coraza_bytes(EMBEDDED_CORAZA_REACTOR),
    }
    .map_err(|err| FatalError::Fatal(format!("failed to load wasm reactor: {err}")))?;

    let mut report = EngineReport::new("wasm");
    for case in cases {
        let payload = match case.request.to_payload() {
            Ok(payload) => payload,
            Err(err) => {
                report.record(case, None, Some(format!("payload encoding failed: {err}")));
                continue;
            }
        };
        match reactor.evaluate(&payload) {
            Ok(ReactorDecision::Allow) => report.record(case, Some(Observed::Allow), None),
            Ok(ReactorDecision::Block { .. }) => report.record(case, Some(Observed::Block), None),
            Err(err) => report.record(case, None, Some(err.to_string())),
        }
    }
    report.finish();
    Ok(report)
}

#[cfg(not(feature = "wasm-reactor"))]
fn run_wasm_engine(_cases: &[&CorpusCase], _args: &Args) -> Result<EngineReport, FatalError> {
    Ok(EngineReport::skipped(
        "wasm",
        "built without the `wasm-reactor` feature",
    ))
}

#[cfg(all(feature = "coraza-native", unix))]
fn run_native_engine(cases: &[&CorpusCase], args: &Args) -> Result<EngineReport, FatalError> {
    let config = ClientConfig {
        socket_path: args.native_socket.clone(),
        pool_size: 2,
        timeout: Duration::from_millis(args.native_timeout_ms),
        max_payload_bytes: 64 * 1024,
    };
    let client = match NativeCorazaClient::new(&config) {
        Ok(client) => client,
        Err(err) => {
            return Ok(EngineReport::skipped("native", err.to_string()));
        }
    };

    let mut report = EngineReport::new("native");
    for case in cases {
        let payload = match case.request.to_payload() {
            Ok(payload) => payload,
            Err(err) => {
                report.record(case, None, Some(format!("payload encoding failed: {err}")));
                continue;
            }
        };
        match client.evaluate(&payload) {
            Ok(waf_ingress::waf::Decision::Allow) => {
                report.record(case, Some(Observed::Allow), None)
            }
            Ok(waf_ingress::waf::Decision::Block { .. })
            | Ok(waf_ingress::waf::Decision::RateLimit { .. }) => {
                report.record(case, Some(Observed::Block), None)
            }
            Err(err) => report.record(case, None, Some(err.to_string())),
        }
    }
    report.finish();
    Ok(report)
}

#[cfg(not(all(feature = "coraza-native", unix)))]
fn run_native_engine(_cases: &[&CorpusCase], _args: &Args) -> Result<EngineReport, FatalError> {
    Ok(EngineReport::skipped(
        "native",
        "built without the `coraza-native` feature (or not on Unix)",
    ))
}

#[cfg(feature = "fastpath")]
fn run_fastpath_engine(cases: &[&CorpusCase]) -> Result<FastpathReport, FatalError> {
    let fast_path = FastPath::embedded()
        .map_err(|err| FatalError::Fatal(format!("failed to build fast path: {err}")))?;
    let mut report = FastpathReport {
        total: cases.len(),
        clean: 0,
        fallback: 0,
        by_reason: BTreeMap::new(),
        cases: Vec::with_capacity(cases.len()),
    };

    for case in cases {
        let headers: Vec<(&str, &str)> = case
            .request
            .headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect();
        let request = FastPathRequest {
            method: &case.request.method,
            uri: &case.request.uri,
            http_version: &case.request.http_version,
            headers: &headers,
            body: case.request.body.as_deref().map(str::as_bytes),
        };
        match fast_path.evaluate(&request) {
            FastPathDecision::Clean { .. } => {
                report.clean += 1;
                report.cases.push(FastpathCaseReport {
                    id: case.id.clone(),
                    expected: case.expected,
                    clean: true,
                    reason: None,
                });
            }
            FastPathDecision::NeedsCoraza { reason } => {
                report.fallback += 1;
                *report.by_reason.entry(reason.to_string()).or_default() += 1;
                report.cases.push(FastpathCaseReport {
                    id: case.id.clone(),
                    expected: case.expected,
                    clean: false,
                    reason: Some(reason.to_string()),
                });
            }
        }
    }

    Ok(report)
}

#[cfg(not(feature = "fastpath"))]
fn run_fastpath_engine(_cases: &[&CorpusCase]) -> Result<FastpathReport, FatalError> {
    Err(FatalError::Usage(
        "built without the `fastpath` feature".to_string(),
    ))
}

fn print_fastpath_summary(report: &FastpathReport) {
    println!(
        "fastpath: clean {}/{} ({} fallback to Coraza)",
        report.clean, report.total, report.fallback
    );
    for (reason, count) in &report.by_reason {
        println!("  {reason}: {count}");
    }
}

fn print_engine_summary(report: &EngineReport, verbose: bool) {
    if !report.available {
        println!(
            "engine {}: SKIPPED ({})",
            report.engine,
            report.skip_reason.as_deref().unwrap_or("unavailable")
        );
        return;
    }

    println!(
        "engine {}: {}/{} passed, FN={}, FP={}, errors={}, detection={}",
        report.engine,
        report.passed,
        report.total,
        report.false_negatives,
        report.false_positives,
        report.errors,
        format_rate(report.detected, report.positives)
    );

    for (tag, entry) in &report.by_tag {
        println!(
            "  {tag}: {}/{} passed, detection={}, FN={}, FP={}, errors={}",
            entry.passed,
            entry.total,
            format_rate(entry.detected, entry.positives),
            entry.false_negatives,
            entry.false_positives,
            entry.errors
        );
    }

    let failures: Vec<&CaseReport> = report
        .cases
        .iter()
        .filter(|case| case.result != Some(CaseResult::Pass))
        .collect();
    if !failures.is_empty() {
        println!("  failures:");
        for case in failures.iter().take(if verbose { usize::MAX } else { 20 }) {
            match (&case.result, &case.error) {
                (Some(CaseResult::FalseNegative), _) => println!(
                    "    FALSE NEGATIVE {} expected block, observed {}",
                    case.id,
                    case.observed.map(Observed::as_str).unwrap_or("error")
                ),
                (Some(CaseResult::FalsePositive), _) => println!(
                    "    FALSE POSITIVE {} expected allow, observed block",
                    case.id
                ),
                (_, Some(error)) => println!("    ERROR {}: {}", case.id, error),
                _ => {}
            }
        }
        if !verbose && failures.len() > 20 {
            println!(
                "    ... {} more (use --json for the full list)",
                failures.len() - 20
            );
        }
    }
}

fn format_rate(numerator: usize, denominator: usize) -> String {
    match rate(numerator, denominator) {
        Some(value) => format!("{:.1}% ({}/{})", value * 100.0, numerator, denominator),
        None => "n/a (0 positives)".to_string(),
    }
}

fn compare_engines(wasm: &EngineReport, native: &EngineReport) -> ParityReport {
    let mut parity = ParityReport {
        compared: 0,
        agree: 0,
        disagree: 0,
        disagreements: Vec::new(),
    };
    for (wasm_case, native_case) in wasm.cases.iter().zip(native.cases.iter()) {
        if wasm_case.id != native_case.id {
            continue;
        }
        parity.compared += 1;
        if wasm_case.observed == native_case.observed
            && wasm_case.error.is_none()
            && native_case.error.is_none()
        {
            parity.agree += 1;
        } else {
            parity.disagree += 1;
            parity.disagreements.push(ParityDisagreement {
                id: wasm_case.id.clone(),
                wasm: wasm_case.observed,
                native: native_case.observed,
                wasm_error: wasm_case.error.clone(),
                native_error: native_case.error.clone(),
            });
        }
    }
    parity
}

fn print_parity_summary(parity: &ParityReport) {
    println!(
        "parity: {}/{} agree, {} disagree",
        parity.agree, parity.compared, parity.disagree
    );
    for disagreement in parity.disagreements.iter().take(20) {
        println!(
            "  DISAGREE {}: wasm={:?}, native={:?}, wasm_error={:?}, native_error={:?}",
            disagreement.id,
            disagreement.wasm,
            disagreement.native,
            disagreement.wasm_error,
            disagreement.native_error
        );
    }
    if parity.disagreements.len() > 20 {
        println!(
            "  ... {} more (use --json for the full list)",
            parity.disagreements.len() - 20
        );
    }
}
