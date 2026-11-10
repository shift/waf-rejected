//! Differential test: serial ARGS evaluation vs the experimental parallel
//! candidate path.
//!
//! Enabled with the non-default `parallel-args` feature:
//!
//! ```text
//! nix develop -c cargo test --features rust-engine,native-detect,parallel-args \
//!     --test parallel_args_parity
//! ```
//!
//! Every case must produce the same decision, matched-rule order, anomaly
//! scores, early-blocking flag and diagnostics. The generated multi-argument
//! bodies cover the shape the parallel path is meant for (many decoded
//! arguments at 1, 4 and 8 KiB total).

#![cfg(feature = "parallel-args")]

use waf_ingress::waf::coraza_corpus::Corpus;
use waf_ingress::waf::rust_engine::parallel_args::ArgsParallelConfig;
use waf_ingress::waf::rust_engine::{
    default_crs_conf_path, CompilePolicy, EngineRequest, Outcome, RustEngine,
};

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

fn evaluate(engine: &RustEngine, request: &EngineRequest<'_>) -> Result<Outcome, String> {
    engine
        .evaluate_detailed(request)
        .map_err(|error| error.to_string())
}

fn assert_same(label: &str, serial: &Outcome, parallel: &Outcome) {
    assert_eq!(
        format!("{:?}", serial.decision),
        format!("{:?}", parallel.decision),
        "{label}: decision differs"
    );
    assert_eq!(
        serial.matched_rules, parallel.matched_rules,
        "{label}: matched rule order differs"
    );
    assert_eq!(
        serial.blocking_inbound_anomaly_score, parallel.blocking_inbound_anomaly_score,
        "{label}: blocking anomaly score differs"
    );
    assert_eq!(
        serial.inbound_anomaly_score_pl1, parallel.inbound_anomaly_score_pl1,
        "{label}: PL1 anomaly score differs"
    );
    assert_eq!(
        serial.early_blocking, parallel.early_blocking,
        "{label}: early blocking differs"
    );
    assert_eq!(
        serial.operator_evaluations, parallel.operator_evaluations,
        "{label}: operator evaluation count differs"
    );
    assert_eq!(
        serial.regex_evaluations_skipped, parallel.regex_evaluations_skipped,
        "{label}: gate skip count differs"
    );
}

#[test]
fn corpus_serial_and_parallel_agree() {
    let corpus = Corpus::from_path("tests/corpus/crs/corpus.json")
        .expect("pinned CRS detection corpus must load");
    let serial = engine(None);
    let parallel = engine(Some(4));
    let mut checked = 0usize;

    for case in &corpus.cases {
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
        let serial_outcome = evaluate(&serial, &request).expect("serial evaluation");
        let parallel_outcome = evaluate(&parallel, &request).expect("parallel evaluation");
        assert_same(&case.id, &serial_outcome, &parallel_outcome);
        checked += 1;
    }

    assert_eq!(checked, 2_112, "unexpected corpus size");
}

fn multi_arg_body(size: usize, arg_count: usize, payload: &str) -> Vec<u8> {
    let mut body = Vec::with_capacity(size);
    let chunk = size / arg_count;
    for index in 0..arg_count {
        if index > 0 {
            body.push(b'&');
        }
        body.extend_from_slice(format!("a{index}=").as_bytes());
        let target = (index + 1) * chunk;
        while body.len() < target && body.len() < size {
            body.push(b'A');
        }
        if index == arg_count / 2 {
            body.extend_from_slice(payload.as_bytes());
        }
    }
    body.truncate(size);
    body
}

#[test]
fn generated_multi_arg_bodies_agree() {
    let serial = engine(None);
    let parallel = engine(Some(4));
    let payloads = [
        "union+select+password+from+users",
        "<script>alert(1)</script>",
        "../../etc/passwd",
        "benign",
    ];

    for size in [1024usize, 4096, 8192] {
        for arg_count in [1usize, 2, 8, 32, 128] {
            for payload in payloads {
                let body = multi_arg_body(size, arg_count, payload);
                let headers = vec![
                    ("Host".to_string(), "benchmark.test".to_string()),
                    (
                        "Content-Type".to_string(),
                        "application/x-www-form-urlencoded".to_string(),
                    ),
                    ("Content-Length".to_string(), body.len().to_string()),
                ];
                let label = format!("size={size} args={arg_count} payload={payload}");
                let request = EngineRequest {
                    method: "POST",
                    uri: "/submit?q=1&r=2",
                    http_version: "HTTP/1.1",
                    headers: &headers,
                    body: Some(&body),
                };
                match (evaluate(&serial, &request), evaluate(&parallel, &request)) {
                    (Ok(serial_outcome), Ok(parallel_outcome)) => {
                        assert_same(&label, &serial_outcome, &parallel_outcome);
                    }
                    // Both paths must fail closed (the per-request budget can
                    // trip while resolving a 128-argument body).
                    (Err(_), Err(_)) => {}
                    (serial_result, parallel_result) => {
                        panic!("{label}: serial={serial_result:?} parallel={parallel_result:?}")
                    }
                }
            }
        }
    }
}
