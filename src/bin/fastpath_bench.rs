//! In-process benchmark for the experimental `fastpath` request engine.
//!
//! ```sh
//! cargo run --release --bin fastpath_bench --features fastpath
//! cargo run --release --bin fastpath_bench --features fastpath,wasm-reactor
//! ```
//!
//! Environment:
//! - `FASTPATH_REPS` scales the number of measured iterations (default 1.0).
//! - `FASTPATH_CORAZA=0` skips the in-process WASI Coraza comparison.

use std::hint::black_box;
use std::time::{Duration, Instant};

use waf_ingress::waf::fastpath::body::BodyInspector;
use waf_ingress::waf::fastpath::{FastPath, FastPathDecision, FastPathRequest};

#[cfg(feature = "wasm-reactor")]
use bytes::Bytes;
#[cfg(feature = "wasm-reactor")]
use hyper::{HeaderMap, Method, Uri};
#[cfg(feature = "wasm-reactor")]
use waf_ingress::config::WafCorazaConfig;
#[cfg(feature = "wasm-reactor")]
use waf_ingress::waf::wasm_reactor::WasmReactorRule;
#[cfg(feature = "wasm-reactor")]
use waf_ingress::waf::{RequestContext, WafRule};

const BODYLESS_HEADERS: &[(&str, &str)] = &[
    ("Host", "benchmark.test"),
    (
        "User-Agent",
        "Mozilla/5.0 (X11; Linux x86_64) Firefox/128.0",
    ),
    ("Accept", "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8"),
    ("Accept-Encoding", "gzip, deflate"),
];

struct Case {
    name: &'static str,
    method: &'static str,
    uri: &'static str,
    body: Option<Vec<u8>>,
    headers: Vec<(&'static str, &'static str)>,
}

impl Case {
    fn bodyless(name: &'static str, method: &'static str, uri: &'static str) -> Self {
        Self {
            name,
            method,
            uri,
            body: None,
            headers: BODYLESS_HEADERS.to_vec(),
        }
    }

    fn form(name: &'static str, bytes: usize) -> Self {
        let mut body = Vec::with_capacity(bytes);
        body.extend_from_slice(b"data=");
        while body.len() < bytes {
            body.push(b'A');
        }
        Self::post(name, body)
    }

    fn encoded_form(name: &'static str, bytes: usize) -> Self {
        let mut body = Vec::with_capacity(bytes);
        body.extend_from_slice(b"data=");
        while body.len() < bytes {
            body.extend_from_slice(b"%41");
        }
        body.truncate(bytes);
        Self::post(name, body)
    }

    fn post(name: &'static str, body: Vec<u8>) -> Self {
        let length = body.len().to_string();
        let mut headers = BODYLESS_HEADERS.to_vec();
        headers.push(("Content-Type", "application/x-www-form-urlencoded"));
        // Leak the length string so the case keeps `&'static str` headers.
        headers.push(("Content-Length", Box::leak(length.into_boxed_str())));
        Self {
            name,
            method: "POST",
            uri: "/submit",
            body: Some(body),
            headers,
        }
    }
}

struct Stats {
    p50: Duration,
    p95: Duration,
    p99: Duration,
    min: Duration,
}

fn measure<F: FnMut()>(mut operation: F, reps: usize) -> Stats {
    for _ in 0..reps.min(64).max(8) {
        operation();
    }
    let mut samples = Vec::with_capacity(reps);
    for _ in 0..reps {
        let started = Instant::now();
        operation();
        samples.push(started.elapsed());
    }
    samples.sort_unstable();
    Stats {
        p50: samples[reps / 2],
        p95: samples[reps * 95 / 100],
        p99: samples[reps * 99 / 100],
        min: samples[0],
    }
}

fn fmt_us(duration: Duration) -> String {
    format!("{:.2}", duration.as_secs_f64() * 1_000_000.0)
}

fn fmt_ms(duration: Duration) -> String {
    format!("{:.3}", duration.as_secs_f64() * 1_000.0)
}

fn main() {
    let scale = std::env::var("FASTPATH_REPS")
        .ok()
        .and_then(|value| value.parse::<f64>().ok())
        .unwrap_or(1.0);
    let reps = |base: usize| ((base as f64 * scale).round() as usize).max(1);
    let compare_coraza = std::env::var("FASTPATH_CORAZA")
        .map(|value| value != "0")
        .unwrap_or(true);

    let started = Instant::now();
    let fast = FastPath::embedded().expect("fast path");
    let startup = started.elapsed();
    let body_inspector = BodyInspector::embedded()
        .expect("body inspector")
        .with_max_body_bytes(8192);
    println!(
        "fastpath: {} prefilter automata, all body rules gated = {}, built in {:.1} ms",
        fast.automaton_count(),
        fast.all_body_rules_gated(),
        startup.as_secs_f64() * 1000.0
    );

    let cases = vec![
        Case::bodyless("bodyless GET", "GET", "/"),
        Case::bodyless("bodyless HEAD", "HEAD", "/"),
        Case::bodyless("bodyless OPTIONS *", "OPTIONS", "*"),
        Case::form("1 KiB form", 1024),
        Case::form("4 KiB form", 4096),
        Case::form("8 KiB form", 8192),
        Case::encoded_form("4 KiB encoded", 4096),
    ];

    #[cfg(feature = "wasm-reactor")]
    let coraza = if compare_coraza {
        let config = WafCorazaConfig::default();
        match WasmReactorRule::from_config(&config, true) {
            Ok(rule) => Some(rule),
            Err(err) => {
                eprintln!("wasm Coraza unavailable: {err}");
                None
            }
        }
    } else {
        None
    };

    println!();
    println!(
        "{:<20} {:>10} {:>10} {:>10} {:>10} {:>12}",
        "case", "fp p50", "fp p95", "fp p99", "fp min", "coraza p50"
    );
    println!(
        "{:<20} {:>10} {:>10} {:>10} {:>10} {:>12}",
        "", "(us)", "(us)", "(us)", "(us)", "(ms)"
    );

    for case in &cases {
        let request = FastPathRequest {
            method: case.method,
            uri: case.uri,
            http_version: "HTTP/1.1",
            headers: &case.headers,
            body: case.body.as_deref(),
        };
        let body_len = case.body.as_ref().map(Vec::len).unwrap_or(0);
        let case_reps = if body_len == 0 {
            reps(20_000)
        } else if case.name.contains("encoded") {
            reps(500)
        } else {
            reps(2_000)
        };

        // For body-bearing requests the conservative fast path returns
        // `BodyNotCovered` without scanning; measure the body prefilter
        // directly so the table shows the work the engine actually does.
        let stats = if body_len == 0 {
            measure(
                || {
                    let decision = fast.evaluate(black_box(&request));
                    black_box(decision);
                },
                case_reps,
            )
        } else {
            let content_type = Some("application/x-www-form-urlencoded");
            measure(
                || {
                    let scan =
                        body_inspector.scan(black_box(case.body.as_deref().unwrap()), content_type);
                    black_box(scan);
                },
                case_reps,
            )
        };

        #[cfg(feature = "wasm-reactor")]
        let coraza_p50 = coraza
            .as_ref()
            .map(|rule| {
                // WASI Coraza is orders of magnitude slower on bodies; keep
                // the sample count small so the comparison terminates.
                let coraza_reps = if body_len == 0 { reps(2_000) } else { reps(3) };
                fmt_ms(measure_coraza(rule, case, coraza_reps).p50)
            })
            .unwrap_or_else(|| "-".to_string());
        #[cfg(not(feature = "wasm-reactor"))]
        let coraza_p50 = "-".to_string();

        println!(
            "{:<20} {:>10} {:>10} {:>10} {:>10} {:>12}",
            case.name,
            fmt_us(stats.p50),
            fmt_us(stats.p95),
            fmt_us(stats.p99),
            fmt_us(stats.min),
            coraza_p50
        );
    }

    // Sanity-check the decision shape so the benchmark cannot silently drift
    // into measuring a fallback-only path for bodyless requests.
    let bodyless = FastPathRequest {
        method: "GET",
        uri: "/",
        http_version: "HTTP/1.1",
        headers: BODYLESS_HEADERS,
        body: None,
    };
    assert!(matches!(
        fast.evaluate(&bodyless),
        FastPathDecision::Clean { .. }
    ));
}

#[cfg(feature = "wasm-reactor")]
fn measure_coraza(rule: &WasmReactorRule, case: &Case, reps: usize) -> Stats {
    let mut headers = HeaderMap::new();
    for (name, value) in &case.headers {
        headers.insert(
            name.parse::<hyper::header::HeaderName>()
                .expect("header name"),
            value.parse().expect("header value"),
        );
    }
    let body = case.body.as_ref().map(|body| Bytes::from(body.clone()));
    let context = RequestContext::new(
        "127.0.0.1".parse().expect("ip"),
        case.method.parse::<Method>().expect("method"),
        case.uri
            .parse::<Uri>()
            .unwrap_or_else(|_| Uri::from_static("/")),
        headers,
        body.as_ref().map(Bytes::len),
    )
    .with_body(body);

    measure(
        || {
            let decision = rule.evaluate(black_box(&context));
            black_box(decision);
        },
        reps,
    )
}
