//! gRPC field-content scanning benchmarks.
//!
//! ```sh
//! cargo bench --features wasm-reactor --bench grpc_content
//! ```
//!
//! Measures the full `GrpcInspector::inspect` path for a declared string field
//! with `content_scan = "strings"` (one extra Coraza evaluation) and `"off"`
//! (structural checks only), for 1/4/16 KiB messages.

use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::sync::Arc;

use criterion::{black_box, BenchmarkId, Criterion, Throughput};
use hyper::{HeaderMap, Method, Uri};
use waf_ingress::config::WafGrpcConfig;
use waf_ingress::waf::grpc::GrpcInspector;
use waf_ingress::waf::grpc_allowlist::{
    AllowlistSource, GrpcAllowlist, GrpcAllowlistMethod, GrpcMessage, GrpcMessageField,
    ALLOWLIST_IR_VERSION,
};
use waf_ingress::waf::wasm_reactor::{ReactorLimits, WasmReactor};
use waf_ingress::waf::RequestContext;

const SIZES: [(&str, usize); 3] = [("1kb", 1024), ("4kb", 4 * 1024), ("16kb", 16 * 1024)];

fn reactor() -> WasmReactor {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/wasm/coraza_reactor/coraza_reactor.wasm"
    );
    let bytes = std::fs::read(path).expect("committed Coraza reactor must exist");
    let reactor = WasmReactor::from_bytes(&bytes, ReactorLimits::coraza())
        .expect("committed Coraza reactor must load");
    reactor.warm().expect("reactor must warm");
    reactor
}

fn allowlist_file() -> (tempfile::TempDir, String) {
    let allowlist = GrpcAllowlist {
        ir_version: ALLOWLIST_IR_VERSION,
        source: AllowlistSource {
            kind: "protobuf".to_string(),
            sha256: "d".repeat(64),
        },
        methods: vec![GrpcAllowlistMethod {
            path: "/acme.Service/Method".to_string(),
            client_streaming: false,
            server_streaming: false,
            input: "acme.Request".to_string(),
            output: "acme.Response".to_string(),
            max_message_bytes: 64 * 1024,
        }],
        messages: vec![GrpcMessage {
            message: "acme.Request".to_string(),
            fields: vec![GrpcMessageField {
                name: "name".to_string(),
                number: 1,
                field_type: "string".to_string(),
                repeated: false,
                required: false,
                message_type: None,
                enum_values: None,
            }],
        }],
        unknown_method_action: "block".to_string(),
    };
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("allowlist.json");
    std::fs::write(&path, allowlist.to_canonical_json().unwrap()).unwrap();
    (dir, path.display().to_string())
}

fn frame(value: &str) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(0x0a); // field 1, wire type 2
    let mut len = value.len() as u64;
    loop {
        let mut byte = (len & 0x7f) as u8;
        len >>= 7;
        if len != 0 {
            byte |= 0x80;
        }
        payload.push(byte);
        if len == 0 {
            break;
        }
    }
    payload.extend_from_slice(value.as_bytes());

    let mut body = Vec::with_capacity(5 + payload.len());
    body.push(0);
    body.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    body.extend_from_slice(&payload);
    body
}

fn context(body: Vec<u8>) -> RequestContext {
    let mut headers = HeaderMap::new();
    headers.insert(
        hyper::header::CONTENT_TYPE,
        "application/grpc+proto".parse().unwrap(),
    );
    headers.insert("grpc-encoding", "identity".parse().unwrap());
    let mut ctx = RequestContext::new(
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
        Method::POST,
        Uri::from_str("/acme.Service/Method").unwrap(),
        headers,
        None,
    );
    ctx.body = Some(bytes::Bytes::from(body));
    ctx
}

fn inspector(mode: &str, reactor: Arc<WasmReactor>) -> (tempfile::TempDir, GrpcInspector) {
    let (dir, path) = allowlist_file();
    let config = WafGrpcConfig {
        allowlist_file: Some(path),
        content_scan: mode.to_string(),
        ..WafGrpcConfig::default()
    };
    let inspector = GrpcInspector::try_from_config(&config)
        .unwrap()
        .with_content_scanner(reactor);
    (dir, inspector)
}

fn bench(c: &mut Criterion) {
    let reactor = Arc::new(reactor());
    let mut group = c.benchmark_group("grpc_content_scan");
    for (label, size) in SIZES {
        let body = frame(&"A".repeat(size));
        group.throughput(Throughput::Bytes(size as u64));
        for mode in ["strings", "off"] {
            let (_dir, inspector) = inspector(mode, Arc::clone(&reactor));
            group.bench_with_input(BenchmarkId::new(mode, label), &body, |bencher, body| {
                bencher.iter(|| {
                    let verdict = inspector.inspect(black_box(&context(body.clone())));
                    black_box(verdict.unwrap());
                });
            });
        }
    }
    group.finish();
}

fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench(&mut criterion);
    criterion.final_summary();
}
