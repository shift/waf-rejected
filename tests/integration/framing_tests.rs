//! Wire-level request-framing tests.
//!
//! These send literal bytes over a TCP socket. A normal HTTP client would
//! normalise CL+TE and duplicate Content-Length before they reach the proxy,
//! which is exactly the ambiguity under test. The fixture origin records every
//! request it receives so the tests can prove a rejected request was not
//! forwarded.

use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use waf_ingress::proxy::WafProxyService;
use waf_ingress::Config;

#[derive(Clone, Debug)]
struct RecordedRequest {
    method: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

type Records = Arc<Mutex<Vec<RecordedRequest>>>;

async fn spawn_origin() -> (std::net::SocketAddr, Records) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let records: Records = Arc::new(Mutex::new(Vec::new()));
    let accepted = Arc::clone(&records);

    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(value) => value,
                Err(_) => break,
            };
            let records = Arc::clone(&accepted);
            tokio::spawn(async move {
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(
                        TokioIo::new(stream),
                        service_fn(move |req: Request<hyper::body::Incoming>| {
                            let records = Arc::clone(&records);
                            async move {
                                let method = req.method().to_string();
                                let headers = req
                                    .headers()
                                    .iter()
                                    .map(|(name, value)| {
                                        (
                                            name.as_str().to_string(),
                                            value.to_str().unwrap_or("").to_string(),
                                        )
                                    })
                                    .collect();
                                let body = req
                                    .into_body()
                                    .collect()
                                    .await
                                    .map(|body| body.to_bytes().to_vec())
                                    .unwrap_or_default();
                                records.lock().unwrap().push(RecordedRequest {
                                    method,
                                    headers,
                                    body,
                                });
                                Ok::<_, Infallible>(
                                    Response::builder()
                                        .status(StatusCode::OK)
                                        .body(Full::new(Bytes::from_static(b"origin-ok")))
                                        .unwrap(),
                                )
                            }
                        }),
                    )
                    .await;
            });
        }
    });

    (addr, records)
}

async fn spawn_proxy(origin: std::net::SocketAddr) -> String {
    let mut config = Config {
        upstream_uri: format!("http://{}", origin),
        ..Config::default()
    };
    config.waf.rate_limit.per_ip_enabled = false;
    config.waf.rate_limit.global_enabled = false;
    config.waf.coraza.enabled = false;

    let service = Arc::new(WafProxyService::new(config).unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = service.start_with_listener(listener).await;
    });
    format!("http://{}", addr)
}

async fn send_raw(proxy: &str, request: &[u8]) -> String {
    let addr = proxy.strip_prefix("http://").unwrap();
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream.write_all(request).await.unwrap();

    let mut response = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut response)).await;
    String::from_utf8_lossy(&response).into_owned()
}

fn status(response: &str) -> Option<u16> {
    response
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
}

async fn assert_rejected_without_forwarding(request: &[u8], expected_status: u16) {
    let (origin, records) = spawn_origin().await;
    let proxy = spawn_proxy(origin).await;

    let response = send_raw(&proxy, request).await;
    assert_eq!(
        status(&response),
        Some(expected_status),
        "request was not rejected as expected: {response:?}"
    );
    // Give any in-flight forwarding a chance to reach the fixture before
    // asserting the origin saw nothing.
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        records.lock().unwrap().is_empty(),
        "rejected request reached the origin: {:?}",
        records.lock().unwrap()
    );

    // The proxy is still serving after the rejection.
    let response = send_raw(
        &proxy,
        b"GET /alive HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(
        status(&response),
        Some(200),
        "proxy did not recover: {response:?}"
    );
}

#[tokio::test]
async fn cl_te_is_rejected_and_not_forwarded() {
    assert_rejected_without_forwarding(
        b"POST /smuggle HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        400,
    )
    .await;
}

#[tokio::test]
async fn te_cl_is_rejected_and_not_forwarded() {
    assert_rejected_without_forwarding(
        b"POST /smuggle HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n0\r\n\r\n",
        400,
    )
    .await;
}

#[tokio::test]
async fn identical_duplicate_content_length_is_rejected_and_not_forwarded() {
    assert_rejected_without_forwarding(
        b"POST /smuggle HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello",
        400,
    )
    .await;
}

#[tokio::test]
async fn conflicting_duplicate_content_length_is_rejected_and_not_forwarded() {
    assert_rejected_without_forwarding(
        b"POST /smuggle HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello",
        400,
    )
    .await;
}

#[tokio::test]
async fn non_chunked_transfer_encoding_is_rejected_and_not_forwarded() {
    for value in ["gzip", "chunked, gzip", "gzip, chunked", "chunked, chunked"] {
        let request = format!(
            "POST /smuggle HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: {value}\r\n\r\n0\r\n\r\n"
        );
        assert_rejected_without_forwarding(request.as_bytes(), 400).await;
    }
}

#[tokio::test]
async fn absolute_form_target_is_rejected_and_not_forwarded() {
    assert_rejected_without_forwarding(
        b"GET http://example.com/ HTTP/1.1\r\nHost: localhost\r\n\r\n",
        400,
    )
    .await;
}

#[tokio::test]
async fn whitespace_before_header_colon_is_rejected_and_not_forwarded() {
    assert_rejected_without_forwarding(
        b"POST /smuggle HTTP/1.1\r\nHost: localhost\r\nContent-Length : 5\r\n\r\nhello",
        400,
    )
    .await;
}

#[tokio::test]
async fn trace_and_connect_are_rejected_with_405_and_not_forwarded() {
    assert_rejected_without_forwarding(b"TRACE / HTTP/1.1\r\nHost: localhost\r\n\r\n", 405).await;
    assert_rejected_without_forwarding(
        b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
        405,
    )
    .await;
}

#[tokio::test]
async fn valid_chunked_request_is_forwarded_without_ambiguous_framing() {
    let (origin, records) = spawn_origin().await;
    let proxy = spawn_proxy(origin).await;

    let response = send_raw(
        &proxy,
        b"POST /echo HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
    )
    .await;
    assert_eq!(
        status(&response),
        Some(200),
        "unexpected response: {response:?}"
    );

    tokio::time::sleep(Duration::from_millis(50)).await;
    let records = records.lock().unwrap();
    assert_eq!(records.len(), 1, "valid request was not forwarded");
    let record = &records[0];
    assert_eq!(record.method, "POST");
    assert_eq!(record.body, b"hello");
    let has_cl = record
        .headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("content-length"));
    let has_te = record
        .headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("transfer-encoding"));
    assert!(
        !(has_cl && has_te),
        "upstream received both Content-Length and Transfer-Encoding: {:?}",
        record.headers
    );
    if has_te {
        let te = record
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("transfer-encoding"))
            .map(|(_, value)| value.as_str())
            .unwrap();
        assert_eq!(te.to_ascii_lowercase(), "chunked");
    }
}
