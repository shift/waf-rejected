//! End-to-end tests for opt-in upstream pooling, HTTP/2 tuning and response
//! streaming. Defaults are covered by the existing proxy tests; every test
//! here explicitly enables the tuning it exercises.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use waf_ingress::proxy::WafProxyService;
use waf_ingress::Config;

const BODY_LEN: usize = 8 * 1024;

struct Upstream {
    addr: SocketAddr,
    connections: Arc<AtomicUsize>,
}

/// HTTP/1.1 upstream that keeps connections alive and returns a fixed body.
async fn spawn_upstream() -> Upstream {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let connections = Arc::new(AtomicUsize::new(0));
    let accepted = Arc::clone(&connections);

    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(value) => value,
                Err(_) => break,
            };
            accepted.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(
                        TokioIo::new(stream),
                        service_fn(|_req: Request<hyper::body::Incoming>| async move {
                            Ok::<_, Infallible>(
                                Response::builder()
                                    .status(StatusCode::OK)
                                    .header("content-length", BODY_LEN.to_string())
                                    .body(Full::new(Bytes::from(vec![b'x'; BODY_LEN])))
                                    .unwrap(),
                            )
                        }),
                    )
                    .await;
            });
        }
    });

    Upstream { addr, connections }
}

async fn spawn_proxy(upstream: SocketAddr, configure: impl FnOnce(&mut Config)) -> SocketAddr {
    let mut config = Config {
        upstream_uri: format!("http://{}", upstream),
        ..Config::default()
    };
    config.server.enable_http3 = false;
    config.waf.coraza.enabled = false;
    config.waf.rate_limit.per_ip_enabled = false;
    config.waf.rate_limit.global_enabled = false;
    configure(&mut config);

    let service = Arc::new(WafProxyService::new(config).unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = service.start_with_listener(listener).await;
    });
    addr
}

fn client() -> Client<hyper_util::client::legacy::connect::HttpConnector, Full<Bytes>> {
    Client::builder(TokioExecutor::new()).build_http()
}

async fn get(
    client: &Client<hyper_util::client::legacy::connect::HttpConnector, Full<Bytes>>,
    url: String,
) -> Vec<u8> {
    let response = client.get(url.parse().unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec()
}

#[tokio::test]
async fn enabled_pool_reuses_idle_upstream_connection() {
    let upstream = spawn_upstream().await;
    let proxy = spawn_proxy(upstream.addr, |config| {
        config.proxy.pool.enabled = true;
        config.proxy.pool.max_idle_per_host = 8;
        config.proxy.pool.idle_timeout_secs = 30;
    })
    .await;

    let client = client();
    for _ in 0..8 {
        let body = get(&client, format!("http://{}/", proxy)).await;
        assert_eq!(body.len(), BODY_LEN);
    }

    assert_eq!(
        upstream.connections.load(Ordering::SeqCst),
        1,
        "eight sequential requests must reuse one upstream connection"
    );
}

#[tokio::test]
async fn pool_evicts_connections_after_idle_timeout() {
    let upstream = spawn_upstream().await;
    let proxy = spawn_proxy(upstream.addr, |config| {
        config.proxy.pool.enabled = true;
        config.proxy.pool.idle_timeout_secs = 1;
    })
    .await;

    let client = client();
    let body = get(&client, format!("http://{}/", proxy)).await;
    assert_eq!(body.len(), BODY_LEN);

    tokio::time::sleep(Duration::from_millis(1500)).await;

    let body = get(&client, format!("http://{}/", proxy)).await;
    assert_eq!(body.len(), BODY_LEN);
    assert!(
        upstream.connections.load(Ordering::SeqCst) >= 2,
        "an idle connection past the timeout must not be reused"
    );
}

#[tokio::test]
async fn streamed_response_preserves_body_and_arrives_incrementally() {
    // Upstream sends headers, the first chunk, then pauses before the rest.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = vec![0u8; 4096];
        let _ = stream.read(&mut request).await;
        let _ = stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 11\r\n\r\nhello")
            .await;
        let _ = stream.flush().await;
        tokio::time::sleep(Duration::from_millis(400)).await;
        let _ = stream.write_all(b" world").await;
        let _ = stream.flush().await;
    });

    let proxy = spawn_proxy(upstream, |config| {
        config.proxy.streaming.enabled = true;
        config.proxy.streaming.response_threshold_bytes = 1;
    })
    .await;

    let client = client();
    let started = Instant::now();
    let response = client
        .get(format!("http://{}/", proxy).parse().unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let mut body = response.into_body();
    let first = body.frame().await.unwrap().unwrap();
    let first_at = started.elapsed();
    let mut received = first.into_data().unwrap().to_vec();
    while let Some(frame) = body.frame().await {
        if let Ok(data) = frame.unwrap().into_data() {
            received.extend_from_slice(&data);
        }
    }

    assert_eq!(received, b"hello world");
    assert!(
        first_at < Duration::from_millis(300),
        "first frame arrived after {first_at:?}; response was buffered instead of streamed"
    );
}

#[tokio::test]
async fn response_inspection_skips_streamed_body_and_passes_through() {
    let upstream = spawn_upstream().await;
    let proxy = spawn_proxy(upstream.addr, |config| {
        config.waf.response_inspection.enabled = true;
        config.waf.response_inspection.inspect_body = true;
        config.waf.response_inspection.max_body_bytes = 1024;
        config.proxy.streaming.enabled = true;
        config.proxy.streaming.response_threshold_bytes = 1;
    })
    .await;

    let client = client();
    let body = get(&client, format!("http://{}/", proxy)).await;
    assert_eq!(body.len(), BODY_LEN);
}

#[tokio::test]
async fn http1_keep_alive_reuses_client_connection() {
    let upstream = spawn_upstream().await;
    let proxy = spawn_proxy(upstream.addr, |_| {}).await;

    let stream = TcpStream::connect(proxy).await.unwrap();
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });

    for _ in 0..3 {
        let request = Request::builder()
            .uri("/")
            .header("host", "localhost")
            .body(Full::new(Bytes::new()))
            .unwrap();
        let response = sender.send_request(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let _ = response.into_body().collect().await.unwrap();
    }
}
