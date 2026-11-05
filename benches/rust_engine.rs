//! Native Rust CRS engine microbenchmarks.
//!
//! ```text
//! cargo bench --features rust-engine --bench rust_engine
//! ```
//!
//! The rows mirror the differential harness: bodyless, 1 KiB, 4 KiB and 8 KiB
//! URLENCODED bodies. Coraza comparison is produced by
//! `cargo run --features rust-engine --bin rust-engine-parity -- --bench`.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use waf_ingress::waf::rust_engine::{
    default_crs_conf_path, CompilePolicy, EngineRequest, RustEngine,
};

fn engine() -> RustEngine {
    RustEngine::from_conf_path_with_policy(default_crs_conf_path(), CompilePolicy::Report)
        .expect("pinned CRS bundle must compile in report mode")
}

fn request_body(size: usize) -> Vec<u8> {
    format!("data={}", "A".repeat(size)).into_bytes()
}

fn headers(size: usize) -> Vec<(String, String)> {
    vec![
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
        ("Content-Length".to_string(), size.to_string()),
    ]
}

fn bench(c: &mut Criterion) {
    let engine = engine();
    let mut group = c.benchmark_group("rust_engine");
    for (label, size) in [
        ("bodyless", 0usize),
        ("1KiB", 1024),
        ("4KiB", 4096),
        ("8KiB", 8192),
    ] {
        let headers = headers(size);
        let body = if size == 0 {
            Vec::new()
        } else {
            request_body(size)
        };
        let request = EngineRequest {
            method: "POST",
            uri: "/post",
            http_version: "HTTP/1.1",
            headers: &headers,
            body: if size == 0 { None } else { Some(&body) },
        };
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(label), &size, |bencher, _| {
            bencher.iter(|| black_box(engine.evaluate(black_box(&request))));
        });
    }
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
