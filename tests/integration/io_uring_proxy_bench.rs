//! End-to-end proxy benchmark: TLS + HTTP/2 + WAF, tokio vs io_uring listener.
//!
//! Ignored by default because it binds ports, generates a certificate and runs
//! for a couple of minutes:
//!
//! ```sh
//! cargo test --release --test integration --features io-uring \
//!   io_uring_proxy_bench -- --ignored --nocapture
//! ```
//!
//! It reports req/s, p50/p99 latency and process CPU seconds for bodyless and
//! 1 KiB requests at concurrency 1/16/64. Every request traverses the real
//! proxy (TLS 1.3, ALPN h2, WAF/Coraza enabled) and a loopback upstream.

#![cfg(all(feature = "io-uring", target_os = "linux"))]

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::header::{CONTENT_LENGTH, CONTENT_TYPE, HOST};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpListener;

use waf_ingress::config::{Config, ListenerIoBackend};
use waf_ingress::proxy::WafProxyService;

const ROUNDS: usize = 400;
// 1 KiB bodies hit the Coraza heavy-inspection path (~tens of ms each),
// so use fewer samples to keep the sweep bounded.
const BODY_ROUNDS: usize = 80;
const WARMUP: usize = 30;

#[derive(Debug, Clone, Copy)]
struct Stats {
    rps: f64,
    p50_us: f64,
    p99_us: f64,
    cpu_s: f64,
}

async fn spawn_upstream(cert_path: &str, key_path: &str) -> SocketAddr {
    use tokio_rustls::rustls::pki_types::pem::PemObject;
    use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};

    let certs = CertificateDer::pem_file_iter(cert_path)
        .unwrap()
        .collect::<std::result::Result<Vec<_>, _>>()
        .unwrap();
    let key = PrivateKeyDer::from_pem_file(key_path).unwrap();
    let mut tls = tokio_rustls::rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    tls.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(value) => value,
                Err(_) => break,
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(stream) = acceptor.accept(stream).await else {
                    return;
                };
                let service = service_fn(|request: Request<hyper::body::Incoming>| async move {
                    let _ = request.into_body().collect().await;
                    Ok::<_, Infallible>(
                        Response::builder()
                            .status(StatusCode::OK)
                            .body(Full::new(Bytes::from_static(b"upstream-ok")))
                            .unwrap(),
                    )
                });
                // The proxy preserves the client's HTTP version, so an h2
                // ingress needs an h2 upstream.
                let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    addr
}

fn bench_config(
    upstream: SocketAddr,
    backend: ListenerIoBackend,
    cert_path: &str,
    key_path: &str,
) -> Config {
    let mut config = Config::default();
    config.upstream_uri = format!("https://{}", upstream);
    config.proxy.upstream_ca_path = Some(cert_path.to_string());
    config.server.io_backend = backend;
    config.server.max_connections = 4096;
    config.server.enable_http3 = false;
    config.server.tls.enabled = true;
    config.server.tls.cert_path = cert_path.to_string();
    config.server.tls.key_path = key_path.to_string();
    config.server.tls.min_version = "1.3".to_string();
    config.server.tls.max_version = "1.3".to_string();
    config.server.tls.alpn_protocols = vec!["h2".to_string()];
    // Keep the WAF (Coraza/CRS + built-in rules) enabled but remove rate
    // limiting so the sweep measures the steady-state path.
    config.waf.rate_limit.per_ip_enabled = false;
    config.waf.rate_limit.global_enabled = false;
    // A 1 KiB body is a "heavy" Coraza inspection. The shipped 250 ms queue
    // bound would turn a saturated permit pool into 503s; the benchmark wants
    // the steady-state scan cost instead.
    config.waf.admission.queue_timeout_ms = 30_000;
    config.waf.admission.max_queued = 4096;
    config
}

async fn spawn_proxy(config: Config) -> (SocketAddr, ListenerIoBackend) {
    let backend = config.server.io_backend;
    let service = Arc::new(WafProxyService::new(config).unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listener = waf_ingress::proxy::listener::ConnectionListener::from_tokio(listener, backend);
    let actual = listener.backend();
    let addr = listener.local_addr().unwrap();
    let handle = Arc::clone(&service);
    tokio::spawn(async move {
        let _ = handle.start_with_connection_listener(listener).await;
    });
    (addr, actual)
}

type BenchConnector =
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>;
type BenchClient = Client<BenchConnector, Full<Bytes>>;

fn tls_client(cert_pem: &[u8]) -> BenchClient {
    use hyper_rustls::HttpsConnectorBuilder;
    use tokio_rustls::rustls;
    use tokio_rustls::rustls::pki_types::pem::PemObject;
    use tokio_rustls::rustls::pki_types::CertificateDer;

    let mut roots = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(cert_pem) {
        roots.add(cert.unwrap()).unwrap();
    }
    let tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    let connector = HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_only()
        .enable_http2()
        .build();
    Client::builder(TokioExecutor::new()).build(connector)
}

async fn one_request(
    client: &BenchClient,
    addr: SocketAddr,
    path: &str,
    body: &[u8],
) -> std::result::Result<(), String> {
    let uri = format!("https://127.0.0.1:{}{}", addr.port(), path);
    let request = if body.is_empty() {
        Request::builder()
            .method(Method::GET)
            .uri(uri)
            .header(HOST, "bench.example")
            .body(Full::new(Bytes::new()))
            .map_err(|e| e.to_string())?
    } else {
        Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header(HOST, "bench.example")
            .header(CONTENT_TYPE, "application/json")
            .header(CONTENT_LENGTH, body.len().to_string())
            .body(Full::new(Bytes::from(body.to_vec())))
            .map_err(|e| e.to_string())?
    };
    let response = client.request(request).await.map_err(|e| e.to_string())?;
    let status = response.status();
    let body = response
        .into_body()
        .collect()
        .await
        .map_err(|e| e.to_string())?
        .to_bytes();
    if status != StatusCode::OK {
        return Err(format!(
            "status {} body {}",
            status,
            String::from_utf8_lossy(&body)
        ));
    }
    Ok(())
}

async fn run_case(
    client: &BenchClient,
    addr: SocketAddr,
    body_size: usize,
    concurrency: usize,
) -> Stats {
    // Neutral, valid-ish JSON padded with spaces. A wall of one repeated byte
    // trips CRS body rules and would measure the block path instead.
    let mut body = b"{\"message\":\"bench\"}".to_vec();
    body.resize(body_size.max(body.len()), b' ');
    let body = if body_size == 0 { Vec::new() } else { body };
    let path = "/bench";

    let rounds = if body_size == 0 { ROUNDS } else { BODY_ROUNDS };
    for _ in 0..WARMUP.min(rounds) {
        one_request(client, addr, path, &body).await.unwrap();
    }

    let cpu_before = cpu_seconds();
    let started = Instant::now();
    let mut workers = Vec::with_capacity(concurrency);
    for _ in 0..concurrency {
        let client = client.clone();
        let body = body.clone();
        workers.push(tokio::spawn(async move {
            let mut latencies = Vec::with_capacity(rounds);
            for _ in 0..rounds {
                let t = Instant::now();
                one_request(&client, addr, path, &body).await.unwrap();
                latencies.push(t.elapsed().as_micros() as u64);
            }
            latencies
        }));
    }

    let mut all = Vec::with_capacity(concurrency * rounds);
    for worker in workers {
        all.extend(worker.await.unwrap());
    }
    let elapsed = started.elapsed();
    let cpu = cpu_seconds() - cpu_before;

    all.sort_unstable();
    Stats {
        rps: (concurrency * rounds) as f64 / elapsed.as_secs_f64(),
        p50_us: percentile(&all, 0.50),
        p99_us: percentile(&all, 0.99),
        cpu_s: cpu,
    }
}

fn percentile(sorted: &[u64], q: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((sorted.len() - 1) as f64 * q).round() as usize;
    sorted[idx] as f64
}

fn cpu_seconds() -> f64 {
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };
    let user = usage.ru_utime.tv_sec as f64 + usage.ru_utime.tv_usec as f64 / 1_000_000.0;
    let sys = usage.ru_stime.tv_sec as f64 + usage.ru_stime.tv_usec as f64 / 1_000_000.0;
    user + sys
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "long-running end-to-end benchmark; run explicitly"]
async fn io_uring_proxy_bench() {
    // Pick the ring provider explicitly; the test process may otherwise fail
    // to auto-select one when several rustls features are compiled in.
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new("waf_ingress=warn"))
        .try_init();
    let dir = tempfile::tempdir().unwrap();
    let certified =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string(), "127.0.0.1".to_string()])
            .unwrap();
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    let cert_pem = certified.cert.pem();
    std::fs::write(&cert_path, &cert_pem).unwrap();
    std::fs::write(&key_path, certified.signing_key.serialize_pem()).unwrap();
    let cert_path = cert_path.to_string_lossy().into_owned();
    let key_path = key_path.to_string_lossy().into_owned();

    let upstream = spawn_upstream(&cert_path, &key_path).await;
    let client = tls_client(cert_pem.as_bytes());

    let tokio_proxy = spawn_proxy(bench_config(
        upstream,
        ListenerIoBackend::Tokio,
        &cert_path,
        &key_path,
    ))
    .await;

    let uring_proxy = spawn_proxy(bench_config(
        upstream,
        ListenerIoBackend::IoUring,
        &cert_path,
        &key_path,
    ))
    .await;
    if uring_proxy.1 != ListenerIoBackend::IoUring {
        eprintln!("io_uring unavailable; skipping the io_uring rows");
    }

    println!("backend body c rps p50_us p99_us cpu_s");
    for body in [0usize, 1024] {
        for concurrency in [1usize, 16, 64] {
            let tokio_stats = run_case(&client, tokio_proxy.0, body, concurrency).await;
            println!(
                "tokio {:>4} {:>2} {:>9.0} {:>7.1} {:>7.1} {:.2}",
                body,
                concurrency,
                tokio_stats.rps,
                tokio_stats.p50_us,
                tokio_stats.p99_us,
                tokio_stats.cpu_s
            );
            if uring_proxy.1 == ListenerIoBackend::IoUring {
                let uring_stats = run_case(&client, uring_proxy.0, body, concurrency).await;
                println!(
                    "io_uring {:>4} {:>2} {:>9.0} {:>7.1} {:>7.1} {:.2}",
                    body,
                    concurrency,
                    uring_stats.rps,
                    uring_stats.p50_us,
                    uring_stats.p99_us,
                    uring_stats.cpu_s
                );
            }
        }
    }
}
