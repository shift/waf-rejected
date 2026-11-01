//! Coraza WASI reactor benchmarks.
//!
//! Only built with `--features wasm-reactor`:
//!
//! ```sh
//! cargo bench --features wasm-reactor --bench coraza
//! ```
//!
//! The Go/WASI reactor needs a large native stack for Go runtime start-up, so
//! the whole Criterion run happens on a dedicated thread with a 256 MiB stack.

use std::sync::OnceLock;
use std::time::Duration;

use criterion::{black_box, BenchmarkId, Criterion, Throughput};
use waf_ingress::waf::wasm_reactor::{
    ReactorDecision, ReactorLimits, WasmReactor, CORAZA_MAX_PAYLOAD_BYTES,
};

const BODY_SIZES: [(&str, usize); 3] = [("1kb", 1024), ("16kb", 16 * 1024), ("64kb", 64 * 1024)];

static MODULE_BYTES: OnceLock<Vec<u8>> = OnceLock::new();

fn module_bytes() -> &'static [u8] {
    MODULE_BYTES.get_or_init(|| {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/wasm/coraza_reactor/coraza_reactor.wasm"
        );
        std::fs::read(path)
            .unwrap_or_else(|err| panic!("built Coraza reactor must exist at {path}: {err}"))
    })
}

fn reactor() -> WasmReactor {
    WasmReactor::from_bytes(module_bytes(), ReactorLimits::coraza())
        .expect("committed Coraza reactor must load")
}

/// Builds the host JSON payload for a POST with an ASCII `A` body.
fn post_payload(body_len: usize) -> Vec<u8> {
    let body = "A".repeat(body_len);
    serde_json::to_vec(&serde_json::json!({
        "method": "POST",
        "uri": "/upload",
        "http_version": "1.1",
        "headers": [["content-type", "text/plain"]],
        "body_size": body.len(),
        "body": body,
    }))
    .expect("payload must serialise")
}

fn attack_payload(body: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "method": "POST",
        "uri": "/login",
        "http_version": "1.1",
        "headers": [["content-type", "application/x-www-form-urlencoded"]],
        "body_size": body.len(),
        "body": body,
    }))
    .expect("payload must serialise")
}

/// Largest body that still fits the reactor's fixed 64 KiB payload buffer.
///
/// The ABI wraps the body in a JSON envelope, so a literal 64 KiB body cannot
/// fit; this trims only the envelope overhead and reports the representable
/// ceiling for the `64kb` row.
fn body_that_fits(target: usize) -> Vec<u8> {
    let mut body_len = target;
    loop {
        let payload = post_payload(body_len);
        if payload.len() <= CORAZA_MAX_PAYLOAD_BYTES {
            return payload;
        }
        body_len -= 1;
    }
}

fn bench_construction(c: &mut Criterion) {
    let mut group = c.benchmark_group("reactor_construction");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(30));

    group.bench_function("compile_module", |b| {
        b.iter(|| {
            WasmReactor::from_bytes(black_box(module_bytes()), ReactorLimits::coraza())
                .expect("reactor must compile")
        })
    });

    group.bench_function("compile_instantiate_and_init", |b| {
        b.iter(|| {
            let reactor = WasmReactor::from_bytes(module_bytes(), ReactorLimits::coraza())
                .expect("reactor must compile");
            reactor
                .evaluate(black_box(b"{}"))
                .expect("cold init must succeed")
        })
    });

    group.finish();
}

fn bench_decisions(c: &mut Criterion) {
    let reactor = reactor();
    let allow = attack_payload("username=admin&password=not-a-real-password");
    let sqli = attack_payload("username=admin&password=x+union+select+password+from+users");
    let xss = attack_payload("q=%3Cscript%3Ealert(1)%3C%2Fscript%3E");

    assert_eq!(
        reactor.evaluate(&allow).expect("allow payload"),
        ReactorDecision::Allow
    );
    for (name, payload) in [("sqli", &sqli), ("xss", &xss)] {
        assert!(
            matches!(
                reactor.evaluate(payload).expect("attack payload"),
                ReactorDecision::Block { status: 403, .. }
            ),
            "{name} payload must be blocked"
        );
    }

    let mut group = c.benchmark_group("reactor_decision");
    group.throughput(Throughput::Elements(1));
    group.measurement_time(Duration::from_secs(20));

    group.bench_function("allow", |b| b.iter(|| reactor.evaluate(black_box(&allow))));
    group.bench_function("block_sqli", |b| {
        b.iter(|| reactor.evaluate(black_box(&sqli)))
    });
    group.bench_function("block_xss", |b| {
        b.iter(|| reactor.evaluate(black_box(&xss)))
    });

    group.finish();
}

fn bench_body_sizes(c: &mut Criterion) {
    let reactor = reactor();
    let mut group = c.benchmark_group("reactor_body");
    group.measurement_time(Duration::from_secs(20));

    for (name, target) in BODY_SIZES {
        let payload = body_that_fits(target);
        assert_eq!(
            reactor.evaluate(&payload).expect("clean body payload"),
            ReactorDecision::Allow,
            "clean {name} body must be allowed"
        );
        group.throughput(Throughput::Bytes(payload.len() as u64));
        group.bench_with_input(
            BenchmarkId::new("allow_body", name),
            &payload,
            |b, payload| b.iter(|| reactor.evaluate(black_box(payload))),
        );
    }

    group.finish();
}

fn bench_main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_construction(&mut criterion);
    bench_decisions(&mut criterion);
    bench_body_sizes(&mut criterion);
    criterion.final_summary();
}

fn main() {
    std::thread::Builder::new()
        .name("coraza-bench".to_string())
        .stack_size(256 * 1024 * 1024)
        .spawn(bench_main)
        .expect("spawn benchmark thread")
        .join()
        .expect("benchmark thread must not panic");
}
