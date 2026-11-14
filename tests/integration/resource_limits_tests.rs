//! End-to-end resource-exhaustion limits: connections, headers, bodies,
//! upstream timeouts, keep-alive and WebSocket tunnels.

use std::convert::Infallible;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use http_body_util::Full;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::Message;

use waf_ingress::proxy::WafProxyService;
use waf_ingress::Config;

async fn spawn_upstream() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(
                        TokioIo::new(stream),
                        service_fn(|_req: Request<hyper::body::Incoming>| async {
                            Ok::<_, Infallible>(
                                Response::builder()
                                    .status(StatusCode::OK)
                                    .header("content-length", "11")
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

/// Upstream that counts how many requests reached it, so a test can prove a
/// rejected body was not forwarded.
async fn spawn_counting_upstream() -> (std::net::SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let forwarded = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&forwarded);

    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let counter = Arc::clone(&counter);
            tokio::spawn(async move {
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(
                        TokioIo::new(stream),
                        service_fn(move |_req: Request<hyper::body::Incoming>| {
                            let counter = Arc::clone(&counter);
                            async move {
                                counter.fetch_add(1, Ordering::Relaxed);
                                Ok::<_, Infallible>(
                                    Response::builder()
                                        .status(StatusCode::OK)
                                        .header("content-length", "11")
                                        .body(Full::new(Bytes::from_static(b"upstream-ok")))
                                        .unwrap(),
                                )
                            }
                        }),
                    )
                    .await;
            });
        }
    });

    (addr, forwarded)
}

async fn spawn_silent_upstream() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((_stream, _)) = listener.accept().await {
            // Accept and never answer.
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
    });
    addr
}

async fn spawn_ws_upstream() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
                while let Some(Ok(message)) = ws.next().await {
                    if ws.send(message).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    addr
}

fn base_config(upstream: std::net::SocketAddr) -> Config {
    let mut config = Config {
        upstream_uri: format!("http://{}", upstream),
        ..Config::default()
    };
    config.waf.rate_limit.per_ip_enabled = false;
    config.waf.rate_limit.global_enabled = false;
    config.waf.coraza.enabled = false;
    config
}

async fn spawn_proxy(config: Config) -> std::net::SocketAddr {
    let service = Arc::new(WafProxyService::new(config).unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = service.start_with_listener(listener).await;
    });
    addr
}

async fn read_until_headers_end(stream: &mut TcpStream) -> String {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        let n = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut chunk))
            .await
            .expect("response headers timed out")
            .expect("read failed");
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    String::from_utf8_lossy(&buf).into_owned()
}

#[tokio::test]
async fn connection_limit_rejects_an_extra_connection_with_503() {
    let upstream = spawn_upstream().await;
    let mut config = base_config(upstream);
    config.server.max_connections = 1;
    let proxy = spawn_proxy(config).await;

    // Complete one request on the first connection so it is provably admitted
    // and then kept alive, holding the only slot.
    let mut first = TcpStream::connect(proxy).await.unwrap();
    first
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    let first_response = read_until_headers_end(&mut first).await;
    assert!(
        first_response.starts_with("HTTP/1.1 200"),
        "the first connection must be admitted: {first_response:?}"
    );

    let mut second = TcpStream::connect(proxy).await.unwrap();
    second
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    let response = read_until_headers_end(&mut second).await;

    assert!(
        response.starts_with("HTTP/1.1 503"),
        "over-limit connection must receive 503, got: {response:?}"
    );
    assert!(
        response.to_ascii_lowercase().contains("retry-after:"),
        "503 must carry Retry-After: {response:?}"
    );
}

#[tokio::test]
async fn header_count_limit_returns_431() {
    let upstream = spawn_upstream().await;
    let mut config = base_config(upstream);
    config.server.max_header_count = 5;
    let proxy = spawn_proxy(config).await;

    let mut stream = TcpStream::connect(proxy).await.unwrap();
    let mut request = String::from("GET / HTTP/1.1\r\nHost: localhost\r\n");
    for index in 0..10 {
        request.push_str(&format!("x-test-{index}: value\r\n"));
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();
    let response = read_until_headers_end(&mut stream).await;

    assert!(
        response.starts_with("HTTP/1.1 431"),
        "header-count excess must return 431, got: {response:?}"
    );
}

#[tokio::test]
async fn header_byte_limit_returns_431() {
    let upstream = spawn_upstream().await;
    let mut config = base_config(upstream);
    config.server.max_header_bytes = 64;
    let proxy = spawn_proxy(config).await;

    let mut stream = TcpStream::connect(proxy).await.unwrap();
    let request = format!(
        "GET / HTTP/1.1\r\nHost: localhost\r\nx-big: {}\r\n\r\n",
        "A".repeat(256)
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let response = read_until_headers_end(&mut stream).await;

    assert!(
        response.starts_with("HTTP/1.1 431"),
        "header-byte excess must return 431, got: {response:?}"
    );
}

#[tokio::test]
async fn proxy_max_request_size_caps_the_body() {
    let upstream = spawn_upstream().await;
    let mut config = base_config(upstream);
    config.server.max_body_size = 4096;
    config.proxy.max_request_size = 128;
    let proxy = spawn_proxy(config).await;

    let response = reqwest::Client::new()
        .post(format!("http://{proxy}/upload"))
        .body("A".repeat(512))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn proxy_timeout_seconds_bounds_the_upstream_exchange() {
    let upstream = spawn_silent_upstream().await;
    let mut config = base_config(upstream);
    config.proxy.timeout_seconds = 1;
    let proxy = spawn_proxy(config).await;

    let started = std::time::Instant::now();
    let response = reqwest::Client::new()
        .get(format!("http://{proxy}/slow"))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "proxy.timeout_seconds = 1 must abort quickly, took {:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn keep_alive_timeout_closes_an_idle_connection() {
    let upstream = spawn_upstream().await;
    let mut config = base_config(upstream);
    config.server.keep_alive_timeout_secs = 1;
    let proxy = spawn_proxy(config).await;

    let mut stream = TcpStream::connect(proxy).await.unwrap();
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    let response = read_until_headers_end(&mut stream).await;
    assert!(response.starts_with("HTTP/1.1 200"), "{response:?}");

    // Drain the 11-byte body (some of it may have arrived with the headers),
    // then wait for the idle keep-alive close.
    let header_end = response.find("\r\n\r\n").expect("header terminator") + 4;
    let mut body = response.as_bytes()[header_end..].to_vec();
    while body.len() < 11 {
        let mut chunk = [0u8; 64];
        let n = stream.read(&mut chunk).await.unwrap();
        assert_ne!(n, 0, "connection closed before the response body");
        body.extend_from_slice(&chunk[..n]);
    }
    assert_eq!(&body[..11], b"upstream-ok");

    let mut byte = [0u8; 1];
    let closed = tokio::time::timeout(Duration::from_secs(4), stream.read(&mut byte)).await;
    assert!(
        matches!(closed, Ok(Ok(0)) | Ok(Err(_))),
        "idle keep-alive connection must be closed, got {closed:?}"
    );
}

#[tokio::test]
async fn websocket_concurrency_cap_rejects_a_second_tunnel() {
    let upstream = spawn_ws_upstream().await;
    let mut config = base_config(upstream);
    config.server.websocket.max_concurrent_tunnels = 1;
    let proxy = spawn_proxy(config).await;

    let (_first, _) = tokio_tungstenite::connect_async(format!("ws://{proxy}/ws"))
        .await
        .expect("first tunnel admitted");

    let second = tokio_tungstenite::connect_async(format!("ws://{proxy}/ws")).await;
    assert!(
        second.is_err(),
        "a second tunnel must be refused at max_concurrent_tunnels = 1"
    );
}

#[tokio::test]
async fn websocket_idle_timeout_closes_with_going_away() {
    let upstream = spawn_ws_upstream().await;
    let mut config = base_config(upstream);
    config.server.websocket.idle_timeout_secs = 1;
    config.server.websocket.max_lifetime_secs = 30;
    let proxy = spawn_proxy(config).await;

    let (mut client, _) = tokio_tungstenite::connect_async(format!("ws://{proxy}/ws"))
        .await
        .expect("tunnel established");

    let next = tokio::time::timeout(Duration::from_secs(4), client.next())
        .await
        .expect("idle timeout must close the tunnel");
    match next {
        Some(Ok(Message::Close(Some(frame)))) => {
            assert_eq!(frame.code, CloseCode::Away);
        }

        Some(Ok(Message::Close(None))) | Some(Err(_)) | None => {}
        Some(Ok(other)) => panic!("unexpected message after idle timeout: {other:?}"),
    }
}

#[tokio::test]
async fn websocket_lifetime_cap_closes_with_policy_violation() {
    let upstream = spawn_ws_upstream().await;
    let mut config = base_config(upstream);
    config.server.websocket.idle_timeout_secs = 0;
    config.server.websocket.max_lifetime_secs = 1;
    let proxy = spawn_proxy(config).await;

    let (mut client, _) = tokio_tungstenite::connect_async(format!("ws://{proxy}/ws"))
        .await
        .expect("tunnel established");

    let next = tokio::time::timeout(Duration::from_secs(4), client.next())
        .await
        .expect("lifetime cap must close the tunnel");
    match next {
        Some(Ok(Message::Close(Some(frame)))) => {
            assert_eq!(frame.code, CloseCode::Policy);
        }
        Some(Ok(Message::Close(None))) | Some(Err(_)) | None => {}
        Some(Ok(other)) => panic!("unexpected message after lifetime cap: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Body cap / engine inspection cap alignment
// ---------------------------------------------------------------------------

#[cfg(feature = "rust-engine")]
fn inspected_config(upstream: std::net::SocketAddr) -> Config {
    let mut config = base_config(upstream);
    config.waf.coraza.enabled = true;
    config.waf.coraza.backend = waf_ingress::config::CorazaBackend::Rust;
    config
}

#[cfg(feature = "rust-engine")]
fn large_body(len: usize) -> String {
    let mut body = String::with_capacity(len);
    body.push_str("data=");
    body.extend(std::iter::repeat('A').take(len - body.len()));
    body
}

#[cfg(feature = "rust-engine")]
#[tokio::test]
async fn default_256_kib_body_is_inspected() {
    let upstream = spawn_upstream().await;
    let config = inspected_config(upstream);
    assert_eq!(config.server.max_body_size, 256 << 10);
    let proxy = spawn_proxy(config).await;

    let response = reqwest::Client::new()
        .post(format!("http://{proxy}/upload"))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(large_body(256 << 10))
        .send()
        .await
        .unwrap();

    let status = response.status();
    let text = response.text().await.unwrap();
    assert_eq!(
        status,
        StatusCode::OK,
        "a 256 KiB body must be inspected, not fail closed: {text}"
    );
}

#[cfg(feature = "rust-engine")]
fn counting_warning_subscriber(count: Arc<AtomicUsize>) -> impl tracing::Subscriber + Send + Sync {
    struct WarningCounter(Arc<AtomicUsize>);

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for WarningCounter {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _context: tracing_subscriber::layer::Context<'_, S>,
        ) {
            if *event.metadata().level() == tracing::Level::WARN {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    use tracing_subscriber::layer::SubscriberExt;
    tracing_subscriber::registry().with(WarningCounter(count))
}

/// Load-validate a config while counting `warn` events. The subscriber is
/// scoped to this call, so concurrent tests are unaffected.
#[cfg(feature = "rust-engine")]
fn load_and_count_warnings(config: &Config) -> usize {
    let count = Arc::new(AtomicUsize::new(0));
    let subscriber = counting_warning_subscriber(Arc::clone(&count));
    tracing::subscriber::with_default(subscriber, || {
        config.validate().expect("configuration must load");
    });
    count.load(Ordering::SeqCst)
}

#[cfg(feature = "rust-engine")]
#[test]
fn the_default_body_cap_does_not_log_a_warning() {
    let config = Config::default();
    assert_eq!(config.server.max_body_size, 256 << 10);
    assert_eq!(load_and_count_warnings(&config), 0);
}

#[cfg(feature = "rust-engine")]
#[tokio::test]
async fn two_mib_opt_in_cap_warns_once_and_inspects_above_the_default() {
    let upstream = spawn_upstream().await;
    let mut config = inspected_config(upstream);
    config.server.max_body_size = 2 << 20;

    assert_eq!(
        load_and_count_warnings(&config),
        1,
        "a cap above 256 KiB must log exactly one start-up warning"
    );

    let proxy = spawn_proxy(config).await;
    let response = reqwest::Client::new()
        .post(format!("http://{proxy}/upload"))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(large_body(512 << 10))
        .send()
        .await
        .unwrap();

    let status = response.status();
    let text = response.text().await.unwrap();
    assert_eq!(
        status,
        StatusCode::OK,
        "an opted-in 2 MiB cap must inspect a body above 256 KiB, not fail closed: {text}"
    );
}

#[cfg(feature = "rust-engine")]
#[tokio::test]
async fn ten_mib_opt_in_cap_warns_once_and_inspects_above_the_default() {
    let upstream = spawn_upstream().await;
    let mut config = inspected_config(upstream);
    config.server.max_body_size = 10 << 20;

    assert_eq!(
        load_and_count_warnings(&config),
        1,
        "a cap above 256 KiB must log exactly one start-up warning"
    );

    let proxy = spawn_proxy(config).await;
    let response = reqwest::Client::new()
        .post(format!("http://{proxy}/upload"))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(large_body(3 << 20))
        .send()
        .await
        .unwrap();

    let status = response.status();
    let text = response.text().await.unwrap();
    assert_eq!(
        status,
        StatusCode::OK,
        "an opted-in cap must inspect a body above 256 KiB, not fail closed: {text}"
    );
}

#[cfg(feature = "rust-engine")]
#[test]
fn an_engine_value_cap_below_the_body_cap_fails_at_load() {
    let mut config = Config::default();
    config.waf.coraza.max_value_bytes = 128 << 10;
    let error = config
        .validate_with_source("file '/etc/waf/config.toml'")
        .expect_err("a smaller engine value cap must fail at load")
        .to_string();
    assert!(error.contains("waf.coraza.max_value_bytes"), "{error}");
    assert!(error.contains("server.max_body_size"), "{error}");
}

#[cfg(feature = "rust-engine")]
#[tokio::test]
async fn body_over_the_cap_returns_413_and_is_not_forwarded() {
    let (upstream, forwarded) = spawn_counting_upstream().await;
    let config = inspected_config(upstream);
    assert_eq!(config.server.max_body_size, 256 << 10);
    let proxy = spawn_proxy(config).await;

    let response = reqwest::Client::new()
        .post(format!("http://{proxy}/upload"))
        .body(vec![b'A'; (256 << 10) + 1])
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(
        forwarded.load(Ordering::Relaxed),
        0,
        "an over-cap body must not reach the upstream"
    );
}

#[cfg(feature = "rust-engine")]
#[tokio::test]
async fn a_rule_match_inside_a_256_kib_body_is_blocked() {
    let upstream = spawn_upstream().await;
    let config = inspected_config(upstream);
    let proxy = spawn_proxy(config).await;

    let suffix = "&q=%27+OR+%271%27%3D%271%27";
    let mut body = large_body((256 << 10) - suffix.len());
    body.push_str(suffix);
    let response = reqwest::Client::new()
        .post(format!("http://{proxy}/upload"))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await
        .unwrap();

    let status = response.status();
    let text = response.text().await.unwrap();
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a CRS match at 256 KiB must block: {text}"
    );
}
