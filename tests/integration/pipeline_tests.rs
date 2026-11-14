//! End-to-end pipeline tests: real proxy, real upstream, real HTTP client.

use std::convert::Infallible;
use std::io::Write;
use std::sync::Arc;

use bytes::Bytes;
use futures_util::stream;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::Frame;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use waf_ingress::config::ListenerIoBackend;
use waf_ingress::proxy::WafProxyService;
use waf_ingress::Config;

async fn spawn_upstream() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(value) => value,
                Err(_) => break,
            };
            tokio::spawn(async move {
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(
                        TokioIo::new(stream),
                        service_fn(|req: Request<hyper::body::Incoming>| async move {
                            let path = req.uri().path().to_string();
                            // Model an upstream that trusts client-controlled
                            // routing overrides: if either the override header
                            // or an /admin path arrives, it serves admin.
                            let routed_to_admin = req.headers().contains_key("x-original-url")
                                || path.starts_with("/admin");
                            let custom = req
                                .headers()
                                .get("x-custom-header")
                                .and_then(|value| value.to_str().ok())
                                .unwrap_or("")
                                .to_string();
                            let received = req
                                .into_body()
                                .collect()
                                .await
                                .map(|body| body.to_bytes())
                                .unwrap_or_default();
                            let body = if routed_to_admin {
                                Bytes::from_static(b"admin")
                            } else if path == "/large" {
                                Bytes::from("A".repeat(4096))
                            } else if path == "/echo" {
                                received
                            } else if path == "/routing-check" {
                                Bytes::from(format!("routing-check:{}", custom))
                            } else {
                                Bytes::from_static(b"upstream-ok")
                            };
                            Ok::<_, Infallible>(
                                Response::builder()
                                    .status(StatusCode::OK)
                                    .body(Full::new(body))
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

async fn spawn_proxy(upstream: std::net::SocketAddr) -> String {
    spawn_proxy_with_backend(upstream, ListenerIoBackend::Tokio).await
}

async fn spawn_proxy_with_backend(
    upstream: std::net::SocketAddr,
    backend: ListenerIoBackend,
) -> String {
    let config = test_config(upstream, backend);
    spawn_proxy_with_config(config).await
}

fn test_config(upstream: std::net::SocketAddr, backend: ListenerIoBackend) -> Config {
    let mut config = Config {
        upstream_uri: format!("http://{}", upstream),
        ..Config::default()
    };
    config.server.max_body_size = 512;
    config.server.io_backend = backend;
    config.waf.rate_limit.per_ip_enabled = false;
    config.waf.rate_limit.global_enabled = false;
    config.waf.coraza.enabled = false;
    config
}

async fn spawn_proxy_with_config(config: Config) -> String {
    let service = Arc::new(WafProxyService::new(config).unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let _ = service.start_with_listener(listener).await;
    });

    format!("http://{}", addr)
}

#[cfg(all(feature = "io-uring", target_os = "linux"))]
#[tokio::test]
async fn pipeline_works_with_io_uring_listener() {
    let upstream = spawn_upstream().await;
    let proxy = spawn_proxy_with_backend(upstream, ListenerIoBackend::IoUring).await;
    let client = reqwest::Client::new();

    for _ in 0..3 {
        let response = client.get(format!("{}/hello", proxy)).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.text().await.unwrap(), "upstream-ok");
    }
}

#[tokio::test]
async fn pipeline_allows_clean_requests() {
    let upstream = spawn_upstream().await;
    let proxy = spawn_proxy(upstream).await;
    let response = reqwest::get(format!("{}/hello?id=42", proxy))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.text().await.unwrap(), "upstream-ok");
}

#[tokio::test]
async fn pipeline_blocks_encoded_newline_payload_without_panicking_or_echoing_it() {
    let upstream = spawn_upstream().await;
    let proxy = spawn_proxy(upstream).await;
    let client = reqwest::Client::new();

    // `%0A` decodes to a newline inside the matched `UNION\nSELECT` payload.
    // The block reason therefore contains a control character; the response
    // must still be a clean 403 and must not echo the match.
    let response = client
        .get(format!(
            "{}/hello?q=1%20UNION%0ASELECT%20*%20FROM%20users",
            proxy
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(response.headers().get("x-waf-decision").unwrap(), "block");
    assert_eq!(
        response.headers().get("x-waf-rule-id").unwrap(),
        "sql-injection"
    );
    assert!(response.headers().get("x-waf-reason").is_none());
    let body = response.text().await.unwrap();
    assert!(!body.contains("UNION"), "payload echoed in body: {body}");
    assert!(!body.contains("SELECT"), "payload echoed in body: {body}");

    // The hostile request must not have aborted the process: the same proxy
    // still serves a clean request afterwards.
    let follow_up = client.get(format!("{}/hello", proxy)).send().await.unwrap();
    assert_eq!(follow_up.status(), StatusCode::OK);
    assert_eq!(follow_up.text().await.unwrap(), "upstream-ok");
}

#[tokio::test]
async fn pipeline_strips_routing_headers_so_upstream_executes_the_inspected_path() {
    let upstream = spawn_upstream().await;
    let proxy = spawn_proxy(upstream).await;
    let response = reqwest::Client::new()
        .get(format!("{}/routing-check", proxy))
        .header("x-original-url", "/admin")
        .header("x-rewrite-url", "/admin")
        .header("x-http-method-override", "DELETE")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    // The upstream model serves "admin" whenever X-Original-URL is present.
    // Receiving the routing-check body proves the forwarded path is the same
    // path the WAF inspected and that the override header was stripped.
    assert_eq!(response.text().await.unwrap(), "routing-check:");
}

#[tokio::test]
async fn pipeline_forwards_normal_custom_headers() {
    let upstream = spawn_upstream().await;
    let proxy = spawn_proxy(upstream).await;
    let response = reqwest::Client::new()
        .get(format!("{}/routing-check", proxy))
        .header("x-custom-header", "keep-me")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.text().await.unwrap(), "routing-check:keep-me");
}

#[tokio::test]
async fn pipeline_rejects_ambiguous_routing_headers_when_enabled() {
    let upstream = spawn_upstream().await;
    let mut config = test_config(upstream, ListenerIoBackend::Tokio);
    config.proxy.reject_ambiguous_routing = true;
    let proxy = spawn_proxy_with_config(config).await;

    let response = reqwest::Client::new()
        .get(format!("{}/routing-check", proxy))
        .header("x-original-url", "/admin")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // Trusted-proxy identity headers are still accepted in reject mode.
    let response = reqwest::Client::new()
        .get(format!("{}/routing-check", proxy))
        .header("x-forwarded-for", "203.0.113.9")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn pipeline_blocks_query_sqli() {
    let upstream = spawn_upstream().await;
    let proxy = spawn_proxy(upstream).await;
    let response = reqwest::get(format!(
        "{}/?id=1%20UNION%20SELECT%20*%20FROM%20users",
        proxy
    ))
    .await
    .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn pipeline_blocks_body_sqli() {
    let upstream = spawn_upstream().await;
    let proxy = spawn_proxy(upstream).await;
    let response = reqwest::Client::new()
        .post(format!("{}/login", proxy))
        .body("id=1 UNION SELECT * FROM users")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

#[tokio::test]
async fn pipeline_blocks_decompressed_gzip_sqli_body() {
    let upstream = spawn_upstream().await;
    let proxy = spawn_proxy(upstream).await;
    let response = reqwest::Client::new()
        .post(format!("{}/login", proxy))
        .header("content-encoding", "gzip")
        .body(gzip(b"id=1 UNION SELECT * FROM users"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn pipeline_forwards_decompressed_gzip_body() {
    let upstream = spawn_upstream().await;
    let proxy = spawn_proxy(upstream).await;
    let response = reqwest::Client::new()
        .post(format!("{}/echo", proxy))
        .header("content-encoding", "gzip")
        .body(gzip(b"clean request body"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.text().await.unwrap(), "clean request body");
}

#[tokio::test]
async fn pipeline_rejects_malformed_gzip_body() {
    let upstream = spawn_upstream().await;
    let proxy = spawn_proxy(upstream).await;
    let response = reqwest::Client::new()
        .post(format!("{}/upload", proxy))
        .header("content-encoding", "gzip")
        .body("not-really-gzip")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn pipeline_rejects_oversized_decompressed_body() {
    let upstream = spawn_upstream().await;
    let proxy = spawn_proxy(upstream).await;
    let response = reqwest::Client::new()
        .post(format!("{}/upload", proxy))
        .header("content-encoding", "gzip")
        .body(gzip(&vec![b'A'; 4096]))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn pipeline_rejects_unsupported_request_encoding() {
    let upstream = spawn_upstream().await;
    let proxy = spawn_proxy(upstream).await;
    let response = reqwest::Client::new()
        .post(format!("{}/upload", proxy))
        .header("content-encoding", "zstd")
        .body("encoded-body")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

#[tokio::test]
async fn pipeline_rejects_stacked_request_encoding() {
    let upstream = spawn_upstream().await;
    let proxy = spawn_proxy(upstream).await;
    let response = reqwest::Client::new()
        .post(format!("{}/upload", proxy))
        .header("content-encoding", "gzip, gzip")
        .body(gzip(b"clean request body"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

#[tokio::test]
async fn pipeline_rejects_oversized_upstream_response() {
    let upstream = spawn_upstream().await;
    let proxy = spawn_proxy(upstream).await;
    let response = reqwest::get(format!("{}/large", proxy)).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
}

#[tokio::test]
async fn pipeline_rejects_oversized_body() {
    let upstream = spawn_upstream().await;
    let proxy = spawn_proxy(upstream).await;
    let response = reqwest::Client::new()
        .post(format!("{}/upload", proxy))
        .body("A".repeat(4096))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn pipeline_accepts_chunked_body() {
    let upstream = spawn_upstream().await;
    let proxy = spawn_proxy(upstream).await;

    let chunks: Vec<Result<Frame<Bytes>, std::io::Error>> = vec![
        Ok(Frame::data(Bytes::from_static(b"chunk-one|"))),
        Ok(Frame::data(Bytes::from_static(b"chunk-two|"))),
        Ok(Frame::data(Bytes::from_static(b"chunk-three"))),
    ];
    let body = reqwest::Body::wrap(StreamBody::new(stream::iter(chunks)));
    let response = reqwest::Client::new()
        .post(format!("{}/echo", proxy))
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.text().await.unwrap(),
        "chunk-one|chunk-two|chunk-three"
    );
}

#[tokio::test]
async fn pipeline_rejects_content_length_mismatch() {
    let upstream = spawn_upstream().await;
    let proxy = spawn_proxy(upstream).await;
    let proxy_addr = proxy.strip_prefix("http://").unwrap();

    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
    // Advertise 16 bytes but send only 5, then close the write side.
    stream
        .write_all(b"POST /echo HTTP/1.1\r\nHost: localhost\r\nContent-Length: 16\r\n\r\nshort")
        .await
        .unwrap();
    stream.shutdown().await.unwrap();

    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    let response = String::from_utf8_lossy(&response);
    assert!(
        response.contains("400 Bad Request") || response.contains("431"),
        "unexpected response: {response}"
    );
}

#[tokio::test]
async fn pipeline_rejects_truncated_body() {
    let upstream = spawn_upstream().await;
    let proxy = spawn_proxy(upstream).await;
    let proxy_addr = proxy.strip_prefix("http://").unwrap();

    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
    stream
        .write_all(b"POST /echo HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1024\r\n\r\npartial")
        .await
        .unwrap();
    // Close without completing the advertised body.
    stream.shutdown().await.unwrap();

    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    let response = String::from_utf8_lossy(&response);
    assert!(
        response.contains("400 Bad Request") || response.contains("408"),
        "unexpected response: {response}"
    );
}

#[tokio::test]
async fn pipeline_keeps_connection_alive_for_reuse() {
    let upstream = spawn_upstream().await;
    let proxy = spawn_proxy(upstream).await;
    let client = reqwest::Client::new();

    for _ in 0..3 {
        let response = client.get(format!("{}/hello", proxy)).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.text().await.unwrap(), "upstream-ok");
    }
}
