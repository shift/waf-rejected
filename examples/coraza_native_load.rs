//! Native Coraza sidecar load matrix through the real proxy.
//!
//! Start the sidecar first, then:
//!
//! ```sh
//! CORAZA_SOCKET=/tmp/coraza-native-bench.sock \
//!   cargo run --release --example coraza_native_load --features coraza-native
//! ```
//!
//! For each body size it runs closed-loop load at concurrency 1/4/16/64 and
//! reports throughput plus p50/p95/p99 end-to-end latency (client -> proxy ->
//! WAF -> sidecar -> mock upstream -> client).
//!
//! Environment:
//! - `CORAZA_SOCKET` (default `/tmp/coraza-native-bench.sock`)
//! - `CORAZA_LOAD_SECS` per cell (default 2)
//! - `CORAZA_LOAD_SIZES` comma list in KiB (default `1,4,8,16`)
//! - `CORAZA_LOAD_CONCURRENCY` comma list (default `1,4,16,64`)
//! - `CORAZA_LOAD_POOL` client pool size override (default 0 = config default)

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

fn form_body(bytes: usize) -> Vec<u8> {
    let mut body = Vec::with_capacity(bytes);
    body.extend_from_slice(b"data=");
    while body.len() < bytes {
        body.push(b'A');
    }
    body
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

async fn spawn_proxy(upstream: SocketAddr, socket: &str, pool: usize) -> SocketAddr {
    let mut config = Config::default();
    config.upstream_uri = format!("http://{upstream}");
    config.server.max_body_size = 1024 * 1024;
    config.waf.rate_limit.per_ip_enabled = false;
    config.waf.rate_limit.global_enabled = false;
    config.waf.coraza.enabled = true;
    config.waf.coraza.backend = CorazaBackend::Native;
    config.waf.coraza.native_socket_path = Some(socket.to_string());
    config.waf.coraza.eval_timeout_ms = 30_000;
    config.waf.coraza.pool_size = pool;
    // This harness measures the sidecar, not the admission limiter. Production
    // defaults bound heavy concurrency to about half the reactor pool.
    config.waf.admission.enabled = false;

    let service = Arc::new(WafProxyService::new(config).expect("proxy starts"));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = service.start_with_listener(listener).await;
    });
    addr
}

struct Cell {
    rps: f64,
    p50: Duration,
    p95: Duration,
    p99: Duration,
    completed: usize,
    errors: usize,
}

async fn load_cell(
    client: reqwest::Client,
    url: String,
    body: Vec<u8>,
    concurrency: usize,
    duration: Duration,
) -> Cell {
    // Warm the proxy, sidecar pool and client pool.
    for _ in 0..concurrency.max(1) {
        let response = client
            .post(&url)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(body.clone())
            .send()
            .await
            .expect("warmup response");
        assert_eq!(response.status(), StatusCode::OK);
        let _ = response.bytes().await;
    }

    let started = Instant::now();
    let deadline = started + duration;
    let mut handles = Vec::with_capacity(concurrency);
    for _ in 0..concurrency {
        let client = client.clone();
        let url = url.clone();
        let body = body.clone();
        handles.push(tokio::spawn(async move {
            let mut samples = Vec::new();
            let mut errors = 0usize;
            while Instant::now() < deadline {
                let request_started = Instant::now();
                let response = client
                    .post(&url)
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(body.clone())
                    .send()
                    .await
                    .expect("load response");
                if response.status() != StatusCode::OK {
                    // Fail-closed 503s under saturation are a real outcome;
                    // count them instead of hiding them.
                    errors += 1;
                    let _ = response.bytes().await;
                    continue;
                }
                let _ = response.bytes().await.expect("response body");
                samples.push(request_started.elapsed());
            }
            (samples, errors)
        }));
    }

    let mut samples = Vec::new();
    let mut errors = 0usize;
    for handle in handles {
        let (mut task_samples, task_errors) = handle.await.expect("load task");
        samples.append(&mut task_samples);
        errors += task_errors;
    }
    let elapsed = started.elapsed().as_secs_f64();
    samples.sort_unstable();
    let percentile = |p: f64| {
        if samples.is_empty() {
            return Duration::ZERO;
        }
        let index = ((samples.len() as f64 * p).ceil() as usize)
            .saturating_sub(1)
            .min(samples.len().saturating_sub(1));
        samples[index]
    };
    Cell {
        rps: samples.len() as f64 / elapsed,
        p50: percentile(0.50),
        p95: percentile(0.95),
        p99: percentile(0.99),
        completed: samples.len(),
        errors,
    }
}

fn fmt_ms(duration: Duration) -> String {
    format!("{:.2}", duration.as_secs_f64() * 1000.0)
}

fn env_list(name: &str, default: &str) -> Vec<usize> {
    std::env::var(name)
        .unwrap_or_else(|_| default.to_string())
        .split(',')
        .filter_map(|value| value.trim().parse::<usize>().ok())
        .collect()
}

#[tokio::main]
async fn main() {
    let socket = std::env::var("CORAZA_SOCKET")
        .unwrap_or_else(|_| "/tmp/coraza-native-bench.sock".to_string());
    let seconds = std::env::var("CORAZA_LOAD_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(2);
    let sizes = env_list("CORAZA_LOAD_SIZES", "1,4,8,16");
    let concurrency = env_list("CORAZA_LOAD_CONCURRENCY", "1,4,16,64");
    let pool = std::env::var("CORAZA_LOAD_POOL")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);

    let upstream = spawn_upstream().await;
    // `CORAZA_PROXY_URL` points the harness at an already running proxy (for
    // example a separate `waf-ingress` process) instead of spawning one in the
    // load-generator process.
    let base_url = match std::env::var("CORAZA_PROXY_URL") {
        Ok(url) => url,
        Err(_) => format!("http://{}", spawn_proxy(upstream, &socket, pool).await),
    };
    let max_concurrency = concurrency.iter().copied().max().unwrap_or(1);
    let client = reqwest::Client::builder()
        .pool_max_idle_per_host(max_concurrency)
        .build()
        .unwrap();

    println!(
        "\n## Native sidecar load matrix (through the proxy, {}s per cell)\n",
        seconds
    );
    println!("| body | concurrency | RPS | p50 ms | p95 ms | p99 ms | ok | 503 |");
    println!("|---|---:|---:|---:|---:|---:|---:|---:|");
    for kib in sizes {
        let body = form_body(kib * 1024);
        let url = format!("{base_url}/submit");
        for level in &concurrency {
            let cell = load_cell(
                client.clone(),
                url.clone(),
                body.clone(),
                *level,
                Duration::from_secs(seconds),
            )
            .await;
            println!(
                "| {kib} KiB | {level} | {:.1} | {} | {} | {} | {} | {} |",
                cell.rps,
                fmt_ms(cell.p50),
                fmt_ms(cell.p95),
                fmt_ms(cell.p99),
                cell.completed,
                cell.errors
            );
        }
    }
    println!();
}
