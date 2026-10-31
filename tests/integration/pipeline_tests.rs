//! End-to-end pipeline tests: real proxy, real upstream, real HTTP client.

use std::convert::Infallible;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::Full;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

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
                            let body = if req.uri().path() == "/large" {
                                Bytes::from("A".repeat(4096))
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
    let mut config = Config::default();
    config.upstream_uri = format!("http://{}", upstream);
    config.server.max_body_size = 512;
    config.waf.rate_limit.per_ip_enabled = false;
    config.waf.rate_limit.global_enabled = false;

    let service = Arc::new(WafProxyService::new(config).unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let _ = service.start_with_listener(listener).await;
    });

    format!("http://{}", addr)
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

#[tokio::test]
async fn pipeline_rejects_compressed_request_body() {
    let upstream = spawn_upstream().await;
    let proxy = spawn_proxy(upstream).await;
    let response = reqwest::Client::new()
        .post(format!("{}/upload", proxy))
        .header("content-encoding", "gzip")
        .body("not-really-gzip")
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
