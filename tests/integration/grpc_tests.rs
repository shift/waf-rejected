//! gRPC transport tests: trailing headers (unary) and unbuffered streaming.

use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::{Body, Frame, Incoming};
use hyper::service::service_fn;
use hyper::{HeaderMap, Request, Response, StatusCode};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

use waf_ingress::proxy::WafProxyService;
use waf_ingress::Config;

/// Minimal body used by the mock upstream: optional data followed by optional
/// trailing headers.
struct TestBody {
    data: Option<Bytes>,
    trailers: Option<HeaderMap>,
}

impl TestBody {
    fn empty() -> Self {
        Self {
            data: None,
            trailers: None,
        }
    }

    fn with_trailers(trailers: HeaderMap) -> Self {
        Self {
            data: None,
            trailers: Some(trailers),
        }
    }
}

impl Body for TestBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let this = self.get_mut();
        if let Some(data) = this.data.take() {
            return Poll::Ready(Some(Ok(Frame::data(data))));
        }
        if let Some(trailers) = this.trailers.take() {
            return Poll::Ready(Some(Ok(Frame::trailers(trailers))));
        }
        Poll::Ready(None)
    }
}

/// Client body that sends one chunk, then waits for the upstream to observe it
/// before sending the rest. If the proxy buffered the request the upstream
/// would never see the first chunk and this body would stall forever.
struct GatedBody {
    first: Option<Bytes>,
    rest: Option<Bytes>,
    gate: Option<oneshot::Receiver<()>>,
}

impl Body for GatedBody {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let this = self.get_mut();
        if let Some(first) = this.first.take() {
            return Poll::Ready(Some(Ok(Frame::data(first))));
        }
        if let Some(mut gate) = this.gate.take() {
            match Pin::new(&mut gate).poll(cx) {
                Poll::Ready(_) => {}
                Poll::Pending => {
                    this.gate = Some(gate);
                    return Poll::Pending;
                }
            }
        }
        if let Some(rest) = this.rest.take() {
            return Poll::Ready(Some(Ok(Frame::data(rest))));
        }
        Poll::Ready(None)
    }
}

/// A body with no size hint, so hyper uses `transfer-encoding: chunked`
/// instead of `content-length`. This is the HTTP/1.1 shape that the old
/// classifier mistook for a streaming RPC.
struct NoLengthBody {
    data: Option<Bytes>,
}

impl Body for NoLengthBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let this = self.get_mut();
        match this.data.take() {
            Some(data) => Poll::Ready(Some(Ok(Frame::data(data)))),
            None => Poll::Ready(None),
        }
    }
}

async fn bind() -> (TcpListener, SocketAddr) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    (listener, addr)
}

async fn spawn_proxy(upstream: SocketAddr, configure: impl FnOnce(&mut Config)) -> SocketAddr {
    let mut config = Config {
        upstream_uri: format!("http://{}", upstream),
        ..Config::default()
    };
    config.waf.rate_limit.per_ip_enabled = false;
    config.waf.rate_limit.global_enabled = false;
    config.waf.coraza.enabled = false;
    configure(&mut config);

    let service = Arc::new(WafProxyService::new(config).unwrap());
    let (listener, addr) = bind().await;
    tokio::spawn(async move {
        let _ = service.start_with_listener(listener).await;
    });
    addr
}

async fn spawn_upstream<F, Fut>(handler: F) -> SocketAddr
where
    F: Fn(Request<Incoming>) -> Fut + Clone + Send + Sync + 'static,
    Fut: std::future::Future<Output = Response<TestBody>> + Send + 'static,
{
    let (listener, addr) = bind().await;
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(_) => break,
            };
            let handler = handler.clone();
            tokio::spawn(async move {
                let service = service_fn(move |req| {
                    let handler = handler.clone();
                    async move { Ok::<_, Infallible>(handler(req).await) }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    addr
}

fn client<B>() -> Client<HttpConnector, B>
where
    B: Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let mut connector = HttpConnector::new();
    connector.enforce_http(false);
    Client::builder(TokioExecutor::new()).build(connector)
}

/// Split a response body into its data and trailing headers.
async fn read_body<E>(body: impl Body<Data = Bytes, Error = E>) -> (Bytes, Option<HeaderMap>)
where
    E: std::error::Error + Send + Sync + 'static,
{
    let mut body = std::pin::pin!(body);
    let mut data = Vec::new();
    let mut trailers = None;
    while let Some(frame) = body.frame().await {
        let frame = frame.expect("response body frame");
        match frame.into_data() {
            Ok(chunk) => data.extend_from_slice(&chunk),
            Err(frame) => {
                if let Ok(block) = frame.into_trailers() {
                    trailers = Some(block);
                }
            }
        }
    }
    (Bytes::from(data), trailers)
}

fn grpc_status(status: &str) -> HeaderMap {
    let mut trailers = HeaderMap::new();
    trailers.insert("grpc-status", status.parse().unwrap());
    trailers
}

fn grpc_frame(payload: &[u8]) -> Bytes {
    let mut out = Vec::with_capacity(5 + payload.len());
    out.push(0);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    Bytes::from(out)
}
#[tokio::test]
async fn unary_grpc_keeps_status_trailers_with_empty_body() {
    let upstream = spawn_upstream(|req: Request<Incoming>| async move {
        assert_eq!(
            req.headers().get("content-type").unwrap(),
            "application/grpc+proto"
        );
        // gRPC over HTTP/1.1 requires TE: trailers towards the upstream.
        assert_eq!(req.headers().get("te").unwrap(), "trailers");
        // The unary request is buffered, so the upstream sees a content-length.
        assert_eq!(req.headers().get("content-length").unwrap(), "10");

        Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/grpc+proto")
            .header("trailer", "grpc-status, grpc-message")
            .body(TestBody::with_trailers(grpc_status("0")))
            .unwrap()
    })
    .await;

    let proxy = spawn_proxy(upstream, |_| {}).await;

    let request = Request::builder()
        .method("POST")
        .uri(format!("http://{}/helloworld.Greeter/SayHello", proxy))
        .header("content-type", "application/grpc+proto")
        .header("te", "trailers")
        // Full has an exact size hint, so hyper sets content-length: unary path.
        .body(Full::new(Bytes::from_static(b"\x00\x00\x00\x00\x05hello")))
        .unwrap();

    let response = client::<Full<Bytes>>()
        .request(request)
        .await
        .expect("proxy response");
    assert_eq!(response.status(), StatusCode::OK);
    let (data, trailers) = read_body(response.into_body()).await;
    assert!(data.is_empty());
    assert_eq!(
        trailers.expect("trailers").get("grpc-status").unwrap(),
        "0",
        "grpc-status must survive an empty body"
    );
}

#[tokio::test]
async fn streaming_grpc_request_forwards_trailers() {
    let seen = Arc::new(Mutex::new(None::<HeaderMap>));
    let seen_upstream = Arc::clone(&seen);

    let upstream = spawn_upstream(move |req: Request<Incoming>| {
        let seen = Arc::clone(&seen_upstream);
        async move {
            let (data, trailers) = read_body(req.into_body()).await;
            assert_eq!(data, Bytes::from_static(b"\x00\x00\x00\x00\x01x"));
            *seen.lock().unwrap() = trailers;

            Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/grpc+proto")
                .header("trailer", "grpc-status")
                .body(TestBody::with_trailers(grpc_status("0")))
                .unwrap()
        }
    })
    .await;

    let proxy = spawn_proxy(upstream, |_| {}).await;

    let request = Request::builder()
        .method("POST")
        .uri(format!("http://{}/svc/Method", proxy))
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .header("trailer", "grpc-request-note")
        .body(TestBody {
            data: Some(Bytes::from_static(b"\x00\x00\x00\x00\x01x")),
            trailers: Some({
                let mut map = HeaderMap::new();
                map.insert("grpc-request-note", "kept".parse().unwrap());
                map
            }),
        })
        .unwrap();

    let response = client::<TestBody>()
        .request(request)
        .await
        .expect("proxy response");
    assert_eq!(response.status(), StatusCode::OK);
    let (_, trailers) = read_body(response.into_body()).await;
    assert_eq!(trailers.unwrap().get("grpc-status").unwrap(), "0");

    let request_trailers = seen.lock().unwrap().clone().expect("request trailers");
    assert_eq!(request_trailers.get("grpc-request-note").unwrap(), "kept");
}

#[tokio::test]
async fn streaming_grpc_is_not_buffered_and_honours_the_byte_cap() {
    let (gate_tx, gate_rx) = oneshot::channel();
    let gate_tx = Arc::new(Mutex::new(Some(gate_tx)));

    let upstream = spawn_upstream(move |req: Request<Incoming>| {
        let gate_tx = Arc::clone(&gate_tx);
        async move {
            let mut body = req.into_body();
            while let Some(frame) = body.frame().await {
                let Ok(frame) = frame else { break };
                if frame.data_ref().is_some_and(|data| !data.is_empty()) {
                    if let Some(tx) = gate_tx.lock().unwrap().take() {
                        let _ = tx.send(());
                    }
                }
            }
            Response::builder()
                .status(StatusCode::OK)
                .body(TestBody::empty())
                .unwrap()
        }
    })
    .await;

    let proxy = spawn_proxy(upstream, |config| {
        config.server.grpc_max_stream_bytes = 32;
        config.server.grpc_max_stream_seconds = 10;
    })
    .await;

    let request = Request::builder()
        .method("POST")
        .uri(format!("http://{}/svc/Stream", proxy))
        .header("content-type", "application/grpc+proto")
        .body(GatedBody {
            first: Some(grpc_frame(b"first")),
            // Well beyond the 32 byte cap.
            rest: Some(Bytes::from(vec![b'a'; 256])),
            gate: Some(gate_rx),
        })
        .unwrap();

    // The upstream observes the first chunk before the client finishes, so the
    // proxy did not buffer the body. The oversized remainder then trips the cap.
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        client::<GatedBody>().request(request),
    )
    .await;

    match result {
        Ok(Ok(response)) => {
            assert!(
                response.status().is_server_error(),
                "byte cap violation should fail the exchange, got {}",
                response.status()
            );
        }
        Ok(Err(_)) => {}
        Err(_) => panic!("streaming body was buffered or the byte cap was not enforced"),
    }
}

#[tokio::test]
async fn normal_http1_requests_are_still_buffered_and_inspected() {
    let calls = Arc::new(AtomicUsize::new(0));
    let calls_upstream = Arc::clone(&calls);

    let upstream = spawn_upstream(move |req: Request<Incoming>| {
        let calls = Arc::clone(&calls_upstream);
        async move {
            calls.fetch_add(1, Ordering::SeqCst);
            let (data, _) = read_body(req.into_body()).await;
            assert_eq!(data, Bytes::from_static(b"name=value"));
            Response::builder()
                .status(StatusCode::OK)
                .body(TestBody {
                    data: Some(Bytes::from_static(b"ok")),
                    trailers: None,
                })
                .unwrap()
        }
    })
    .await;

    let proxy = spawn_proxy(upstream, |_| {}).await;

    let benign = Request::builder()
        .method("POST")
        .uri(format!("http://{}/normal", proxy))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Full::new(Bytes::from_static(b"name=value")))
        .unwrap();
    let response = client::<Full<Bytes>>()
        .request(benign)
        .await
        .expect("proxy response");
    assert_eq!(response.status(), StatusCode::OK);
    let (data, _) = read_body(response.into_body()).await;
    assert_eq!(data, Bytes::from_static(b"ok"));
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let attack = Request::builder()
        .method("POST")
        .uri(format!("http://{}/normal", proxy))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Full::new(Bytes::from_static(
            b"id=1 UNION SELECT * FROM users",
        )))
        .unwrap();
    let response = client::<Full<Bytes>>()
        .request(attack)
        .await
        .expect("proxy response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "blocked request must not reach the upstream"
    );
}

#[tokio::test]
async fn unary_grpc_over_http1_chunked_without_content_length_is_buffered() {
    let upstream = spawn_upstream(|req: Request<Incoming>| async move {
        // The unary path re-emits the request trailers captured while probing.
        assert_eq!(req.headers().get("te").unwrap(), "trailers");
        let (data, _) = read_body(req.into_body()).await;
        assert_eq!(data, Bytes::from_static(b"\x00\x00\x00\x00\x05hello"));

        Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/grpc+proto")
            .header("trailer", "grpc-status, grpc-message")
            .body(TestBody::with_trailers(grpc_status("0")))
            .unwrap()
    })
    .await;

    // If the missing content-length were still treated as "streaming", the
    // reject policy would block this unary RPC.
    let proxy = spawn_proxy(upstream, |config| {
        config.server.grpc_streaming_policy = waf_ingress::config::GrpcStreamingPolicy::Reject;
    })
    .await;

    let request = Request::builder()
        .method("POST")
        .uri(format!("http://{}/helloworld.Greeter/SayHello", proxy))
        .header("content-type", "application/grpc+proto")
        .header("te", "trailers")
        .body(NoLengthBody {
            data: Some(Bytes::from_static(b"\x00\x00\x00\x00\x05hello")),
        })
        .unwrap();

    let response = client::<NoLengthBody>()
        .request(request)
        .await
        .expect("proxy response");
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "a chunked unary RPC without content-length must still be buffered and forwarded"
    );
    let (data, trailers) = read_body(response.into_body()).await;
    assert!(data.is_empty());
    assert_eq!(
        trailers.expect("grpc trailers").get("grpc-status").unwrap(),
        "0"
    );
}

#[tokio::test]
async fn unknown_grpc_prefixed_media_types_take_the_http_path() {
    let calls = Arc::new(AtomicUsize::new(0));

    // Non-frame bytes would be rejected as a malformed gRPC frame if these
    // types were classified as gRPC. A 200 echo proves ordinary HTTP framing.
    let echo_calls = Arc::clone(&calls);
    let upstream = spawn_upstream(move |req: Request<Incoming>| {
        let calls = Arc::clone(&echo_calls);
        async move {
            assert!(
                req.headers().get("te").is_none(),
                "non-gRPC requests must not gain TE: trailers"
            );
            calls.fetch_add(1, Ordering::SeqCst);
            let (data, _) = read_body(req.into_body()).await;
            Response::builder()
                .status(StatusCode::OK)
                .body(TestBody {
                    data: Some(data),
                    trailers: None,
                })
                .unwrap()
        }
    })
    .await;

    let proxy = spawn_proxy(upstream, |_| {}).await;

    for content_type in ["application/grpcx", "application/grpc-malicious"] {
        let body = Bytes::from_static(b"plain bytes, not a gRPC frame");
        let request = Request::builder()
            .method("POST")
            .uri(format!("http://{}/normal", proxy))
            .header("content-type", content_type)
            .body(Full::new(body.clone()))
            .unwrap();
        let response = client::<Full<Bytes>>()
            .request(request)
            .await
            .expect("proxy response");
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "{content_type} must be handled as ordinary HTTP, not rejected as malformed gRPC"
        );
        let (data, _) = read_body(response.into_body()).await;
        assert_eq!(
            data, body,
            "{content_type} body must be forwarded unchanged"
        );
    }
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn unknown_grpc_prefixed_media_type_bodies_are_inspected() {
    let calls = Arc::new(AtomicUsize::new(0));
    let calls_upstream = Arc::clone(&calls);

    let upstream = spawn_upstream(move |_req: Request<Incoming>| {
        let calls = Arc::clone(&calls_upstream);
        async move {
            calls.fetch_add(1, Ordering::SeqCst);
            Response::builder()
                .status(StatusCode::OK)
                .body(TestBody::empty())
                .unwrap()
        }
    })
    .await;

    let proxy = spawn_proxy(upstream, |_| {}).await;

    for content_type in ["application/grpcx", "application/grpc-malicious"] {
        let request = Request::builder()
            .method("POST")
            .uri(format!("http://{}/normal", proxy))
            .header("content-type", content_type)
            .body(Full::new(Bytes::from_static(
                b"id=1 UNION SELECT * FROM users",
            )))
            .unwrap();
        let response = client::<Full<Bytes>>()
            .request(request)
            .await
            .expect("proxy response");
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "{content_type} must be body-inspected as ordinary HTTP"
        );
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "blocked unknown gRPC-prefixed requests must not reach the upstream"
    );
}
