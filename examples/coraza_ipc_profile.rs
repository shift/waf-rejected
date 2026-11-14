//! Splits the native Coraza sidecar request cost into client build, socket
//! round trip (no CRS) and full evaluation.
//!
//! ```sh
//! CORAZA_SOCKET=/tmp/coraza-native-bench.sock \
//!   cargo run --release --example coraza_ipc_profile --features coraza-native
//! ```
//!
//! A stub sidecar answers the same framing with an immediate allow, so the
//! difference between "stub" and "full" is Coraza plus server-side decode. The
//! server-side decode is measured separately by the Go benchmarks in
//! `native/coraza-sidecar/bench_test.go`.
//!
//! Environment:
//! - `CORAZA_SOCKET` real sidecar socket (optional; "full" rows are skipped if
//!   it is not reachable)
//! - `CORAZA_PROFILE_REPS` iterations per measurement (default 200)

use std::io::{Read, Write};
use std::net::IpAddr;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use hyper::{HeaderMap, Method, Uri};

use waf_ingress::waf::coraza_payload::{build_payload_with_policy, BodyInspectionPolicy};
use waf_ingress::waf::coraza_wire::encode_request;
use waf_ingress::waf::native_coraza::{ClientConfig, Evaluation, NativeCorazaClient};
use waf_ingress::waf::RequestContext;

static SOCKET_SEQ: AtomicU64 = AtomicU64::new(0);

fn form_body(bytes: usize) -> Vec<u8> {
    let mut body = Vec::with_capacity(bytes);
    body.extend_from_slice(b"data=");
    while body.len() < bytes {
        body.push(b'A');
    }
    body
}

fn context(size: usize) -> RequestContext {
    let body = form_body(size);
    let mut headers = HeaderMap::new();
    headers.insert("host", "profile.test".parse().unwrap());
    headers.insert(
        "content-type",
        "application/x-www-form-urlencoded".parse().unwrap(),
    );
    RequestContext::new(
        "127.0.0.1".parse::<IpAddr>().unwrap(),
        Method::POST,
        "/submit".parse::<Uri>().unwrap(),
        headers,
        Some(body.len()),
    )
    .with_body(Some(Bytes::from(body)))
}

fn write_framed(stream: &mut UnixStream, body: &[u8]) {
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(body);
    let _ = stream.write_all(&out);
}

fn serve_stub(mut stream: UnixStream, binary: bool) {
    loop {
        let mut header = [0u8; 4];
        if stream.read_exact(&mut header).is_err() {
            return;
        }
        let len = u32::from_be_bytes(header) as usize;
        let mut payload = vec![0u8; len];
        if stream.read_exact(&mut payload).is_err() {
            return;
        }
        if payload.first() == Some(&0xC1) {
            if binary {
                write_framed(&mut stream, &[0xC1, 1, 1]);
            } else {
                // Legacy sidecar: a JSON block in answer to the handshake.
                write_framed(
                    &mut stream,
                    br#"{"decision":"block","status":400,"reason":"malformed request payload"}"#,
                );
            }
            continue;
        }
        if binary {
            write_framed(&mut stream, &[0xC2, 1, 0, 0, 0, 0, 0, 0]);
        } else {
            write_framed(&mut stream, br#"{"decision":"allow"}"#);
        }
    }
}

fn spawn_stub(binary: bool) -> PathBuf {
    let seq = SOCKET_SEQ.fetch_add(1, Ordering::Relaxed);
    let path =
        std::env::temp_dir().join(format!("coraza-ipc-stub-{}-{seq}.sock", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).expect("bind stub socket");
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { break };
            std::thread::spawn(move || serve_stub(stream, binary));
        }
    });
    path
}

fn client(path: &Path) -> Option<NativeCorazaClient> {
    NativeCorazaClient::new(&ClientConfig {
        socket_path: path.to_path_buf(),
        pool_size: 1,
        timeout: Duration::from_secs(30),
        max_payload_bytes: 64 * 1024,
    })
    .ok()
}

fn measure(reps: usize, mut op: impl FnMut()) -> Duration {
    let started = Instant::now();
    for _ in 0..reps {
        op();
    }
    started.elapsed() / reps as u32
}

fn micros(duration: Duration) -> String {
    format!("{:.1}", duration.as_secs_f64() * 1_000_000.0)
}

fn main() {
    let reps = std::env::var("CORAZA_PROFILE_REPS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(200);
    let real_socket = std::env::var("CORAZA_SOCKET")
        .unwrap_or_else(|_| "/tmp/coraza-native-bench.sock".to_string());

    let binary_stub = client(&spawn_stub(true)).expect("binary stub client");
    let json_stub = client(&spawn_stub(false)).expect("json stub client");
    let real = client(Path::new(&real_socket));
    let policy = BodyInspectionPolicy::default();

    println!("\n## Native sidecar cost split (mean µs per request, {reps} reps)\n");
    println!("| body | build JSON | build binary | client+IPC JSON | client+IPC binary | full binary | CRS (full - IPC) |");
    println!("|---|---:|---:|---:|---:|---:|---:|");

    for kib in [1usize, 4, 8, 16] {
        let size = kib * 1024;
        let ctx = context(size);

        let build_json = measure(reps, || {
            let _ = build_payload_with_policy(&ctx, &policy).unwrap();
        });
        let build_binary = measure(reps, || {
            let _ = encode_request(&ctx, &policy).unwrap();
        });
        let ipc_json = measure(reps, || {
            let decision = json_stub.evaluate_context(&ctx, &policy).unwrap();
            assert!(matches!(decision, Evaluation::Decided { .. }));
        });
        let ipc_binary = measure(reps, || {
            let decision = binary_stub.evaluate_context(&ctx, &policy).unwrap();
            assert!(matches!(decision, Evaluation::Decided { .. }));
        });
        let full = real.as_ref().map(|client| {
            measure(reps, || {
                let decision = client.evaluate_context(&ctx, &policy).unwrap();
                assert!(matches!(decision, Evaluation::Decided { .. }));
            })
        });

        match full {
            Some(full) => println!(
                "| {kib} KiB | {} | {} | {} | {} | {} | {} |",
                micros(build_json),
                micros(build_binary),
                micros(ipc_json),
                micros(ipc_binary),
                micros(full),
                micros(full.saturating_sub(ipc_binary)),
            ),
            None => println!(
                "| {kib} KiB | {} | {} | {} | {} | n/a | n/a |",
                micros(build_json),
                micros(build_binary),
                micros(ipc_json),
                micros(ipc_binary),
            ),
        }
    }
    println!();
}
