//! Loopback throughput/latency benchmark for the opt-in HTTP/2 and upstream
//! pool tuning.
//!
//! ```sh
//! cargo bench --bench http2_tuning -- --tuned
//! cargo bench --bench http2_tuning -- --baseline
//! ```
//!
//! Each cell drives real TLS connections through the fully configured proxy
//! into a keep-alive HTTP/1.1 upstream and reports throughput, p50/p95/p99
//! and the upstream connection reuse ratio.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::net::TcpListener;
use tokio::sync::Barrier;
use tokio_rustls::TlsAcceptor;

use waf_ingress::proxy::WafProxyService;
use waf_ingress::Config;

#[derive(Clone, Copy, Debug)]
struct Cell {
    protocol: &'static str,
    body_len: usize,
    concurrency: usize,
}

#[derive(Debug)]
struct Stats {
    rps: f64,
    p50_ms: f64,
    p95_ms: f64,
    p99_ms: f64,
    reuse_pct: f64,
}

fn percentile(sorted: &[Duration], p: usize) -> f64 {
    let n = sorted.len().max(1);
    sorted[(n - 1) * p / 100].as_secs_f64() * 1e3
}

struct Upstream {
    addr: SocketAddr,
    connections: Arc<AtomicUsize>,
}

async fn spawn_upstream(body_len: usize, h2: bool, cert: &str, key: &str) -> Upstream {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let connections = Arc::new(AtomicUsize::new(0));
    let accepted = Arc::clone(&connections);
    let body: Arc<[u8]> = vec![b'x'; body_len].into();
    let tls = if h2 {
        let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cert)
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        let key = PrivateKeyDer::from_pem_file(key).unwrap();
        let mut config =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .unwrap();
        config.alpn_protocols = vec![b"h2".to_vec()];
        Some(TlsAcceptor::from(Arc::new(config)))
    } else {
        None
    };

    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(value) => value,
                Err(_) => break,
            };
            accepted.fetch_add(1, Ordering::Relaxed);
            let _ = stream.set_nodelay(true);
            let body = Arc::clone(&body);
            let tls = tls.clone();
            tokio::spawn(async move {
                let service = service_fn(move |_req: Request<hyper::body::Incoming>| {
                    let body = Arc::clone(&body);
                    async move {
                        Ok::<_, Infallible>(
                            Response::builder()
                                .status(StatusCode::OK)
                                .header("content-length", body.len().to_string())
                                .body(Full::new(Bytes::from(body.to_vec())))
                                .unwrap(),
                        )
                    }
                });
                match tls {
                    Some(acceptor) => {
                        let stream = acceptor.accept(stream).await.unwrap();
                        let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                            .serve_connection(TokioIo::new(stream), service)
                            .await;
                    }
                    None => {
                        let _ = hyper::server::conn::http1::Builder::new()
                            .serve_connection(TokioIo::new(stream), service)
                            .await;
                    }
                }
            });
        }
    });

    Upstream { addr, connections }
}

fn generate_certificates(dir: &Path) -> (CertificateDer<'static>, String, String, String) {
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "waf-h2-bench-ca");
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca_key = KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();

    let mut server_params = CertificateParams::new(vec!["127.0.0.1".to_string()]).unwrap();
    server_params.is_ca = IsCa::NoCa;
    server_params
        .distinguished_name
        .push(DnType::CommonName, "127.0.0.1");
    server_params.use_authority_key_identifier_extension = true;
    server_params
        .key_usages
        .push(KeyUsagePurpose::DigitalSignature);
    server_params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ServerAuth);
    let server_key = KeyPair::generate().unwrap();
    let issuer = Issuer::from_params(&ca_params, &ca_key);
    let server_cert = server_params.signed_by(&server_key, &issuer).unwrap();

    let ca_path = dir.join("ca.pem");
    let cert_path = dir.join("server.pem");
    let key_path = dir.join("server.key");
    std::fs::write(&ca_path, ca_cert.pem()).unwrap();
    std::fs::write(&cert_path, server_cert.pem()).unwrap();
    std::fs::write(&key_path, server_key.serialize_pem()).unwrap();
    (
        ca_cert.der().clone(),
        ca_path.to_string_lossy().into_owned(),
        cert_path.to_string_lossy().into_owned(),
        key_path.to_string_lossy().into_owned(),
    )
}

async fn spawn_proxy(
    upstream: SocketAddr,
    h2_upstream: bool,
    ca_path: &str,
    tuned: bool,
    cert: &str,
    key: &str,
) -> SocketAddr {
    let mut config = Config {
        upstream_uri: if h2_upstream {
            format!("https://{}", upstream)
        } else {
            format!("http://{}", upstream)
        },
        ..Config::default()
    };
    if h2_upstream {
        config.proxy.upstream_ca_path = Some(ca_path.to_string());
    }
    config.server.enable_http3 = false;
    config.server.tls.enabled = true;
    config.server.tls.cert_path = cert.to_string();
    config.server.tls.key_path = key.to_string();
    config.server.tls.alpn_protocols = vec!["h2".to_string(), "http/1.1".to_string()];
    config.server.tls.tcp_nodelay = true;
    config.waf.coraza.enabled = false;
    config.waf.rate_limit.per_ip_enabled = false;
    config.waf.rate_limit.global_enabled = false;

    if tuned {
        config.proxy.pool.enabled = true;
        config.proxy.pool.max_idle_per_host = 64;
        config.proxy.pool.idle_timeout_secs = 30;
        config.proxy.streaming.enabled = true;
        config.proxy.streaming.response_threshold_bytes = 4096;
        config.server.http2.enabled = true;
        config.server.http2.initial_stream_window_bytes = 1024 * 1024;
        config.server.http2.initial_connection_window_bytes = 16 * 1024 * 1024;
        config.server.http2.max_concurrent_streams = 256;
    }

    let service = Arc::new(WafProxyService::new(config).unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = service.start_with_listener(listener).await;
    });
    addr
}

fn client_for(ca: CertificateDer<'static>, h2: bool) -> BenchClient {
    let mut roots = RootCertStore::empty();
    roots.add(ca).unwrap();
    let tls =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();

    let builder = HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_only();
    let connector = if h2 {
        builder.enable_all_versions().build()
    } else {
        builder.enable_http1().build()
    };
    Client::builder(TokioExecutor::new()).build(connector)
}

type BenchClient = Client<
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
    Full<Bytes>,
>;

async fn run_cell(
    client: &BenchClient,
    proxy: SocketAddr,
    upstream_connections: &AtomicUsize,
    cell: Cell,
    total_requests: usize,
) -> Stats {
    let uri: hyper::Uri = format!("https://{}/", proxy).parse().unwrap();
    let workers = cell.concurrency.min(total_requests);
    let per_worker = total_requests / workers;
    let barrier = Arc::new(Barrier::new(workers + 1));
    let mut handles = Vec::with_capacity(workers);

    for _ in 0..workers {
        let client = client.clone();
        let uri = uri.clone();
        let barrier = Arc::clone(&barrier);
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            let mut samples = Vec::with_capacity(per_worker);
            for _ in 0..per_worker {
                let request = Request::builder()
                    .uri(uri.clone())
                    .body(Full::new(Bytes::new()))
                    .unwrap();
                let started = Instant::now();
                let response = client.request(request).await.unwrap();
                assert_eq!(response.status(), StatusCode::OK);
                let body = response.into_body().collect().await.unwrap().to_bytes();
                assert_eq!(body.len(), cell.body_len);
                samples.push(started.elapsed());
            }
            samples
        }));
    }

    barrier.wait().await;
    let started = Instant::now();
    let mut samples = Vec::with_capacity(total_requests);
    for handle in handles {
        samples.extend(handle.await.unwrap());
    }
    let elapsed = started.elapsed();
    let requests = samples.len();
    samples.sort_unstable();

    let connections = upstream_connections.load(Ordering::Relaxed);
    let reuse = (1.0 - connections as f64 / requests.max(1) as f64).max(0.0) * 100.0;

    Stats {
        rps: requests as f64 / elapsed.as_secs_f64(),
        p50_ms: percentile(&samples, 50),
        p95_ms: percentile(&samples, 95),
        p99_ms: percentile(&samples, 99),
        reuse_pct: reuse,
    }
}

#[tokio::main]
async fn main() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .try_init();
    let tuned = std::env::args().any(|arg| arg == "--tuned");
    let total_requests = std::env::var("BENCH_REQUESTS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(6_000);
    let cells = [
        Cell {
            protocol: "h2",
            body_len: 0,
            concurrency: 1,
        },
        Cell {
            protocol: "h2",
            body_len: 0,
            concurrency: 16,
        },
        Cell {
            protocol: "h2",
            body_len: 0,
            concurrency: 64,
        },
        Cell {
            protocol: "h2",
            body_len: 1024,
            concurrency: 1,
        },
        Cell {
            protocol: "h2",
            body_len: 1024,
            concurrency: 16,
        },
        Cell {
            protocol: "h2",
            body_len: 1024,
            concurrency: 64,
        },
        Cell {
            protocol: "h2",
            body_len: 8192,
            concurrency: 1,
        },
        Cell {
            protocol: "h2",
            body_len: 8192,
            concurrency: 16,
        },
        Cell {
            protocol: "h2",
            body_len: 8192,
            concurrency: 64,
        },
        Cell {
            protocol: "h1",
            body_len: 0,
            concurrency: 1,
        },
        Cell {
            protocol: "h1",
            body_len: 0,
            concurrency: 16,
        },
        Cell {
            protocol: "h1",
            body_len: 0,
            concurrency: 64,
        },
        Cell {
            protocol: "h1",
            body_len: 1024,
            concurrency: 1,
        },
        Cell {
            protocol: "h1",
            body_len: 1024,
            concurrency: 16,
        },
        Cell {
            protocol: "h1",
            body_len: 1024,
            concurrency: 64,
        },
        Cell {
            protocol: "h1",
            body_len: 8192,
            concurrency: 1,
        },
        Cell {
            protocol: "h1",
            body_len: 8192,
            concurrency: 16,
        },
        Cell {
            protocol: "h1",
            body_len: 8192,
            concurrency: 64,
        },
    ];

    let temp = tempfile::tempdir().unwrap();
    let (ca, ca_path, cert, key) = generate_certificates(temp.path());
    let h2_client = client_for(ca.clone(), true);
    let h1_client = client_for(ca, false);

    println!(
        "mode={} requests_per_cell={}",
        if tuned { "tuned" } else { "baseline" },
        total_requests
    );
    println!("proto\tbody\tconc\trps\tp50_ms\tp95_ms\tp99_ms\treuse_pct");

    let mut current_body = usize::MAX;
    let mut current_protocol = "";
    let mut upstream = None;
    let mut proxy = None;

    for cell in cells {
        if cell.body_len != current_body || cell.protocol != current_protocol {
            current_body = cell.body_len;
            current_protocol = cell.protocol;
            let started_upstream =
                spawn_upstream(cell.body_len, cell.protocol == "h2", &cert, &key).await;
            proxy = Some(
                spawn_proxy(
                    started_upstream.addr,
                    cell.protocol == "h2",
                    &ca_path,
                    tuned,
                    &cert,
                    &key,
                )
                .await,
            );
            upstream = Some(started_upstream);
        }
        let upstream = upstream.as_ref().unwrap();
        let proxy = proxy.unwrap();
        let client = if cell.protocol == "h2" {
            &h2_client
        } else {
            &h1_client
        };
        let stats = run_cell(client, proxy, &upstream.connections, cell, total_requests).await;
        println!(
            "{}\t{}\t{}\t{:.0}\t{:.3}\t{:.3}\t{:.3}\t{:.1}",
            cell.protocol,
            cell.body_len,
            cell.concurrency,
            stats.rps,
            stats.p50_ms,
            stats.p95_ms,
            stats.p99_ms,
            stats.reuse_pct
        );
    }
}
