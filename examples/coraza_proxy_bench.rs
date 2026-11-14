//! wasm-vs-native Coraza benchmark through the real proxy.
//!
//! Start the native sidecar first, then:
//!
//! ```sh
//! CORAZA_SOCKET=/tmp/coraza-native-bench.sock \
//!   cargo run --release --example coraza_proxy_bench --features coraza-native
//! ```
//!
//! Unlike `coraza_backend_bench`, this measures a full HTTP request through
//! `WafProxyService` (client -> proxy -> WAF -> mock upstream -> client), so it
//! includes proxy framing, body buffering and the WAF rule chain.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::Full;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use waf_ingress::config::CorazaBackend;
use waf_ingress::proxy::WafProxyService;
use waf_ingress::Config;

struct Case {
    name: &'static str,
    path: &'static str,
    body: Vec<u8>,
    content_type: &'static str,
    reps: usize,
}

fn form_body(bytes: usize) -> Vec<u8> {
    let mut body = Vec::with_capacity(bytes);
    body.extend_from_slice(b"data=");
    while body.len() < bytes {
        body.push(b'A');
    }
    body
}

fn cases() -> Vec<Case> {
    vec![
        Case {
            name: "1 KiB form",
            path: "/submit",
            body: form_body(1024),
            content_type: "application/x-www-form-urlencoded",
            reps: 15,
        },
        Case {
            name: "4 KiB form",
            path: "/submit",
            body: form_body(4096),
            content_type: "application/x-www-form-urlencoded",
            reps: 10,
        },
        Case {
            name: "8 KiB form",
            path: "/submit",
            body: form_body(8192),
            content_type: "application/x-www-form-urlencoded",
            reps: 8,
        },
        Case {
            name: "16 KiB form",
            path: "/submit",
            body: form_body(16384),
            content_type: "application/x-www-form-urlencoded",
            reps: 6,
        },
        Case {
            name: "60 KiB form",
            path: "/submit",
            body: form_body(60 * 1024),
            content_type: "application/x-www-form-urlencoded",
            reps: 4,
        },
        Case {
            name: "gRPC 1 KiB",
            path: "/helloworld.Greeter/SayHello",
            body: {
                let payload = form_body(1024);
                let mut body = Vec::with_capacity(5 + payload.len());
                body.push(0);
                body.extend_from_slice(&(payload.len() as u32).to_be_bytes());
                body.extend_from_slice(&payload);
                body
            },
            content_type: "application/grpc+proto",
            reps: 15,
        },
    ]
}

async fn spawn_upstream() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(
                        TokioIo::new(stream),
                        service_fn(|_req: Request<hyper::body::Incoming>| async {
                            Ok::<_, Infallible>(
                                Response::builder()
                                    .status(StatusCode::OK)
                                    .body(Full::new(Bytes::from_static(b"upstream-ok")))
                                    .unwrap(),
                            )
                        }),
                    )
                    .await;
            });
        }
    });
    addr
}

async fn spawn_proxy(upstream: SocketAddr, backend: CorazaBackend, socket: &str) -> SocketAddr {
    let mut config = Config {
        upstream_uri: format!("http://{upstream}"),
        ..Config::default()
    };
    config.server.max_body_size = 1024 * 1024;
    config.waf.rate_limit.per_ip_enabled = false;
    config.waf.rate_limit.global_enabled = false;
    config.waf.coraza.enabled = true;
    config.waf.coraza.backend = backend;
    config.waf.coraza.native_socket_path = Some(socket.to_string());
    config.waf.coraza.eval_timeout_ms = 30_000;
    config.waf.coraza.pool_size = 4;

    let service = Arc::new(WafProxyService::new(config).expect("proxy starts"));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = service.start_with_listener(listener).await;
    });
    addr
}

async fn measure(client: &reqwest::Client, proxy: SocketAddr, case: &Case) -> (Duration, Duration) {
    let url = format!("http://{proxy}{}", case.path);
    let mut samples = Vec::with_capacity(case.reps);
    for _ in 0..case.reps {
        let started = Instant::now();
        let mut request = client
            .post(&url)
            .header("content-type", case.content_type)
            .body(case.body.clone());
        if case.name.starts_with("gRPC") {
            request = request.header("te", "trailers");
        }
        let response = request.send().await.expect("proxy response");
        assert_eq!(response.status(), StatusCode::OK, "{}", case.name);
        let _ = response.bytes().await.expect("response body");
        samples.push(started.elapsed());
    }
    samples.sort_unstable();
    let p50 = samples[samples.len() / 2];
    let p95_index = ((samples.len() as f64 * 0.95).ceil() as usize)
        .saturating_sub(1)
        .min(samples.len() - 1);
    (p50, samples[p95_index])
}

fn fmt_ms(d: Duration) -> String {
    format!("{:.2}", d.as_secs_f64() * 1000.0)
}

#[tokio::main]
async fn main() {
    let socket = std::env::var("CORAZA_SOCKET")
        .unwrap_or_else(|_| "/tmp/coraza-native-bench.sock".to_string());
    let upstream = spawn_upstream().await;

    let mut backends: Vec<(&str, SocketAddr)> = Vec::new();
    #[cfg(feature = "wasm-reactor")]
    {
        backends.push((
            "wasm",
            spawn_proxy(upstream, CorazaBackend::Wasm, &socket).await,
        ));
    }
    #[cfg(feature = "coraza-native")]
    {
        backends.push((
            "native",
            spawn_proxy(upstream, CorazaBackend::Native, &socket).await,
        ));
    }
    if backends.is_empty() {
        eprintln!("no backend available; enable wasm-reactor or coraza-native");
        std::process::exit(1);
    }

    let client = reqwest::Client::builder()
        .pool_max_idle_per_host(4)
        .build()
        .unwrap();
    let all_cases = cases();

    // Warm each proxy and backend so rule compilation and pool start-up are
    // excluded from steady-state numbers.
    for (_, proxy) in &backends {
        for case in &all_cases {
            let _ = measure(&client, *proxy, case).await;
        }
    }

    println!("\n## Proxy end-to-end latency (p50 / p95, ms)\n");
    print!("| case |");
    for (name, _) in &backends {
        print!(" {name} p50 | {name} p95 |");
    }
    println!();
    print!("|---|");
    for _ in &backends {
        print!("---|---|");
    }
    println!();
    for case in &all_cases {
        print!("| {} |", case.name);
        for (_, proxy) in &backends {
            let (p50, p95) = measure(&client, *proxy, case).await;
            print!(" {} | {} |", fmt_ms(p50), fmt_ms(p95));
        }
        println!();
    }
}
