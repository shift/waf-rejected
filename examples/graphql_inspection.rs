//! Engine-level GraphQL body-scan benchmark.
//!
//! ```sh
//! cargo run --release --features wasm-reactor --example graphql_inspection
//! ```
//!
//! Prints p50 wall time for 1/4/8 KiB GraphQL requests in `crs` and
//! `graphql-only` modes. The delta is the CRS JSON body-scan cost removed by
//! withholding the raw body. Uses the real Coraza/CRS reactor, so numbers
//! depend on the host and the embedded rule set.

use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::time::Instant;

use bytes::Bytes;
use hyper::{HeaderMap, Method, Uri};
use waf_ingress::config::{Config, WafGraphqlConfig, WafGraphqlScanMode};
use waf_ingress::waf::{Decision, RequestContext, WafEngine};

const SIZES: [usize; 3] = [1024, 4096, 8192];
const ITERATIONS: usize = 7;

fn body_of(target: usize) -> String {
    let mut fields = String::new();
    while fields.len() + 64 < target {
        fields.push_str("id ");
    }
    let query = format!("query GetUser {{ user {{ {fields}}} }}");
    serde_json::json!({
        "query": query,
        "operationName": "GetUser",
    })
    .to_string()
}

fn context(body: &str) -> RequestContext {
    let mut headers = HeaderMap::new();
    headers.insert(
        hyper::header::CONTENT_TYPE,
        hyper::header::HeaderValue::from_static("application/json"),
    );
    headers.insert(
        hyper::header::HOST,
        hyper::header::HeaderValue::from_static("bench.example"),
    );
    headers.insert(
        hyper::header::USER_AGENT,
        hyper::header::HeaderValue::from_static("waf-rejected-bench/1.0"),
    );
    headers.insert(
        hyper::header::ACCEPT,
        hyper::header::HeaderValue::from_static("*/*"),
    );
    RequestContext::new(
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
        Method::POST,
        Uri::from_str("/graphql").unwrap(),
        headers,
        Some(body.len()),
    )
    .with_body(Some(Bytes::from(body.to_string())))
}

fn engine(mode: WafGraphqlScanMode) -> WafEngine {
    let mut config = Config::default();
    config.waf.content_inspection.enabled = false;
    config.waf.rate_limit.per_ip_enabled = false;
    config.waf.rate_limit.global_enabled = false;
    config.waf.geo_blocking.enabled = false;
    config.waf.coraza.enabled = true;
    config.waf.graphql = WafGraphqlConfig {
        enabled: true,
        body_scan: mode.as_str().to_string(),
        operation_allowlist: vec!["GetUser".to_string()],
        ..WafGraphqlConfig::default()
    };
    WafEngine::with_config(&config)
}

fn p50(samples: &mut [u128]) -> u128 {
    samples.sort_unstable();
    samples[samples.len() / 2]
}

fn main() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let crs = engine(WafGraphqlScanMode::Crs);
        let only = engine(WafGraphqlScanMode::GraphqlOnly);

        for target in SIZES {
            let body = body_of(target);
            let ctx = context(&body);
            let mut rows = Vec::new();
            for (mode, engine) in [("crs", &crs), ("graphql-only", &only)] {
                let decision = engine.evaluate(&ctx).await;
                assert!(
                    matches!(decision, Decision::Allow),
                    "{mode} unexpectedly blocked: {decision:?}"
                );
                let mut samples = Vec::with_capacity(ITERATIONS);
                for _ in 0..ITERATIONS {
                    let started = Instant::now();
                    let decision = engine.evaluate(&ctx).await;
                    samples.push(started.elapsed().as_micros());
                    assert!(matches!(decision, Decision::Allow));
                }
                rows.push((mode, p50(&mut samples)));
            }
            let delta = rows[0].1.saturating_sub(rows[1].1);
            println!(
                "{:>5} B body ({:>5} B json): crs p50 {:>8.2} ms, graphql-only p50 {:>8.2} ms, delta {:>8.2} ms",
                target,
                body.len(),
                rows[0].1 as f64 / 1000.0,
                rows[1].1 as f64 / 1000.0,
                delta as f64 / 1000.0,
            );
        }
    });
}
