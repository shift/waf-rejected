//! End-to-end gRPC over real HTTP/2 (TLS + ALPN h2) through the WAF proxy.
//!
//! These tests start a real HTTP/2 gRPC upstream, a TLS-enabled
//! `WafProxyService` with HTTP/2 enabled, and drive both with real HTTP/2
//! clients that negotiate ALPN `h2`. They are ignored by default because they
//! bind local ports and generate certificates:
//!
//! ```sh
//! cargo test --test integration grpc_h2_e2e -- --ignored --nocapture
//! ```
//!
//! The gRPC-Web case uses a real HTTP/1.1 client over TLS (ALPN `http/1.1`).

use std::convert::Infallible;
use std::error::Error as StdError;
use std::future::Future;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::{Body, Frame, Incoming};
use hyper::client::conn::{http1, http2};
use hyper::service::service_fn;
use hyper::{HeaderMap, Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio_rustls::rustls;
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use waf_ingress::proxy::WafProxyService;
use waf_ingress::waf::grpc_allowlist::{
    AllowlistSource, GrpcAllowlist, GrpcAllowlistMethod, GrpcMessage, GrpcMessageField,
    ALLOWLIST_IR_VERSION,
};
use waf_ingress::Config;

const SAY_HELLO: &str = "/helloworld.Greeter/SayHello";
const STREAM: &str = "/helloworld.Greeter/Stream";
const WEB: &str = "/helloworld.Greeter/Web";
const SQLI: &str = "/helloworld.Greeter/Sqli";
const UNKNOWN_FIELD: &str = "/helloworld.Greeter/UnknownField";
const BLOCKED: &str = "/helloworld.Greeter/Blocked";

/// A response body that can carry data followed by trailing headers.
struct TrailerBody {
    data: Option<Bytes>,
    trailers: Option<HeaderMap>,
}

impl TrailerBody {
    fn data_and_trailers(data: Bytes, trailers: HeaderMap) -> Self {
        Self {
            data: Some(data),
            trailers: Some(trailers),
        }
    }
}

impl Body for TrailerBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let this = self.get_mut();
        if let Some(data) = this.data.take() {
            if !data.is_empty() {
                return Poll::Ready(Some(Ok(Frame::data(data))));
            }
        }
        if let Some(trailers) = this.trailers.take() {
            return Poll::Ready(Some(Ok(Frame::trailers(trailers))));
        }
        Poll::Ready(None)
    }
}

/// Client body that sends one chunk, waits for the upstream to observe it, then
/// sends the rest and request trailers. If the proxy buffered the request the
/// upstream would never see the first chunk and this body would stall.
struct GatedBody {
    first: Option<Bytes>,
    rest: Option<Bytes>,
    trailers: Option<HeaderMap>,
    gate: Option<oneshot::Receiver<()>>,
}

impl Body for GatedBody {
    type Data = Bytes;
    type Error = Infallible;

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
        if let Some(trailers) = this.trailers.take() {
            return Poll::Ready(Some(Ok(Frame::trailers(trailers))));
        }
        Poll::Ready(None)
    }
}

#[derive(Default)]
struct UpstreamState {
    calls: AtomicUsize,
    gate: Mutex<Option<oneshot::Sender<()>>>,
    request_trailers: Mutex<Option<HeaderMap>>,
}

fn grpc_trailers(status: &str, message: Option<&str>) -> HeaderMap {
    let mut trailers = HeaderMap::new();
    trailers.insert("grpc-status", status.parse().unwrap());
    if let Some(message) = message {
        trailers.insert("grpc-message", message.parse().unwrap());
    }
    trailers
}

fn grpc_frame(payload: &[u8]) -> Bytes {
    let mut out = Vec::with_capacity(5 + payload.len());
    out.push(0);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    Bytes::from(out)
}

fn protobuf_string(field: u32, value: &str) -> Vec<u8> {
    let mut out = Vec::new();
    // tag: field number << 3 | wire type 2 (length-delimited)
    let mut tag = (u64::from(field) << 3) | 2;
    loop {
        let mut byte = (tag & 0x7f) as u8;
        tag >>= 7;
        if tag != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if tag == 0 {
            break;
        }
    }
    let mut len = value.len() as u64;
    loop {
        let mut byte = (len & 0x7f) as u8;
        len >>= 7;
        if len != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if len == 0 {
            break;
        }
    }
    out.extend_from_slice(value.as_bytes());
    out
}

fn grpc_web_trailer_frame() -> Bytes {
    let block = b"grpc-status: 0\r\n";
    let mut out = Vec::with_capacity(5 + block.len());
    out.push(0x80);
    out.extend_from_slice(&(block.len() as u32).to_be_bytes());
    out.extend_from_slice(block);
    Bytes::from(out)
}

async fn read_body<E>(body: impl Body<Data = Bytes, Error = E>) -> (Bytes, Option<HeaderMap>)
where
    E: StdError + Send + Sync + 'static,
{
    let mut body = std::pin::pin!(body);
    let mut data = Vec::new();
    let mut trailers = None;
    while let Some(frame) = body.frame().await {
        let frame = frame.expect("body frame");
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

async fn handle_upstream(
    req: Request<Incoming>,
    state: Arc<UpstreamState>,
) -> Response<TrailerBody> {
    state.calls.fetch_add(1, Ordering::SeqCst);
    let path = req.uri().path().to_string();
    let (_, body) = req.into_parts();

    let mut body = body;
    let mut data = Vec::new();
    let mut trailers = None;
    let mut signalled = false;
    while let Some(frame) = body.frame().await {
        let Ok(frame) = frame else { break };
        if let Some(chunk) = frame.data_ref() {
            if !chunk.is_empty() && !signalled {
                signalled = true;
                if let Some(tx) = state.gate.lock().unwrap().take() {
                    let _ = tx.send(());
                }
            }
            data.extend_from_slice(chunk);
        } else if let Ok(block) = frame.into_trailers() {
            trailers = Some(block);
        }
    }
    *state.request_trailers.lock().unwrap() = trailers;
    let data = Bytes::from(data);

    match path.as_str() {
        STREAM => Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/grpc+proto")
            .header("trailer", "grpc-status, grpc-message")
            .body(TrailerBody::data_and_trailers(
                data,
                grpc_trailers("0", Some("stream-ok")),
            ))
            .unwrap(),
        WEB => {
            let mut response = data.to_vec();
            response.extend_from_slice(&grpc_web_trailer_frame());
            Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/grpc-web+proto")
                .body(TrailerBody {
                    data: Some(Bytes::from(response)),
                    trailers: None,
                })
                .unwrap()
        }
        _ => Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/grpc+proto")
            .header("trailer", "grpc-status, grpc-message")
            .body(TrailerBody::data_and_trailers(
                data,
                grpc_trailers("0", Some("ok")),
            ))
            .unwrap(),
    }
}

async fn spawn_upstream(cert_path: &Path, key_path: &Path) -> (SocketAddr, Arc<UpstreamState>) {
    let cert_pem = std::fs::read(cert_path).unwrap();
    let certs = CertificateDer::pem_slice_iter(&cert_pem)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key_pem = std::fs::read(key_path).unwrap();
    let key = PrivateKeyDer::from_pem_slice(&key_pem).expect("server key");

    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .unwrap();
    config.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(config));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state = Arc::new(UpstreamState::default());
    let upstream_state = Arc::clone(&state);

    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(_) => break,
            };
            let acceptor = acceptor.clone();
            let state = Arc::clone(&upstream_state);
            tokio::spawn(async move {
                let tls = match acceptor.accept(stream).await {
                    Ok(tls) => tls,
                    Err(_) => return,
                };
                let service = service_fn(move |req| {
                    let state = Arc::clone(&state);
                    async move { Ok::<_, Infallible>(handle_upstream(req, state).await) }
                });
                let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(tls), service)
                    .await;
            });
        }
    });

    (addr, state)
}

/// Generate a test CA and a server certificate for 127.0.0.1.
/// Returns `(ca_path, server_cert_path, server_key_path)`.
fn generate_certificates(dir: &Path) -> (PathBuf, PathBuf, PathBuf) {
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "waf-grpc-h2-e2e-ca");
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
    (ca_path, cert_path, key_path)
}

fn write_allowlist(dir: &Path) -> PathBuf {
    let methods = [SAY_HELLO, STREAM, WEB, SQLI, UNKNOWN_FIELD]
        .iter()
        .map(|path| GrpcAllowlistMethod {
            path: (*path).to_string(),
            client_streaming: false,
            server_streaming: false,
            input: "helloworld.Request".to_string(),
            output: "helloworld.Response".to_string(),
            max_message_bytes: 4096,
        })
        .collect();

    let messages = vec![GrpcMessage {
        message: "helloworld.Request".to_string(),
        fields: vec![GrpcMessageField {
            name: "name".to_string(),
            number: 1,
            field_type: "string".to_string(),
            repeated: false,
            required: false,
            message_type: None,
            enum_values: None,
        }],
    }];

    let allowlist = GrpcAllowlist {
        ir_version: ALLOWLIST_IR_VERSION,
        source: AllowlistSource {
            kind: "protobuf".to_string(),
            sha256: "a".repeat(64),
        },
        methods,
        messages,
        unknown_method_action: "block".to_string(),
    };
    let path = dir.join("grpc-allowlist.json");
    std::fs::write(&path, allowlist.to_canonical_json().unwrap()).unwrap();
    path
}

async fn spawn_proxy(
    upstream: SocketAddr,
    ca_path: &Path,
    cert_path: &Path,
    key_path: &Path,
    allowlist_path: &Path,
    grpc_aware_rejections: bool,
) -> SocketAddr {
    let mut config = Config::default();
    config.upstream_uri = format!("https://127.0.0.1:{}", upstream.port());
    config.proxy.upstream_ca_path = Some(ca_path.to_string_lossy().into_owned());
    config.server.enable_http2 = true;
    config.server.enable_http3 = false;
    config.server.tls.enabled = true;
    config.server.tls.cert_path = cert_path.to_string_lossy().into_owned();
    config.server.tls.key_path = key_path.to_string_lossy().into_owned();
    config.server.tls.alpn_protocols = vec!["h2".to_string(), "http/1.1".to_string()];
    config.server.grpc_aware_rejections = grpc_aware_rejections;
    config.waf.rate_limit.per_ip_enabled = false;
    config.waf.rate_limit.global_enabled = false;
    config.waf.coraza.enabled = true;
    config.waf.grpc.enabled = true;
    config.waf.grpc.allowlist_file = Some(allowlist_path.to_string_lossy().into_owned());
    config.waf.grpc.reject_unknown_fields = true;
    config.waf.grpc.unknown_method_action = Some("block".to_string());

    let service = Arc::new(WafProxyService::new(config).unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = service.start_with_listener(listener).await;
    });
    addr
}

fn client_tls_config(ca_path: &Path, alpn: &[u8]) -> Arc<ClientConfig> {
    let ca_pem = std::fs::read(ca_path).unwrap();
    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(&ca_pem) {
        roots.add(cert.unwrap()).unwrap();
    }
    let mut config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
    config.alpn_protocols = vec![alpn.to_vec()];
    Arc::new(config)
}

async fn tls_connect(
    addr: SocketAddr,
    ca_path: &Path,
    alpn: &[u8],
) -> tokio_rustls::client::TlsStream<TcpStream> {
    let tcp = TcpStream::connect(addr).await.unwrap();
    let connector = TlsConnector::from(client_tls_config(ca_path, alpn));
    let server_name = ServerName::try_from("127.0.0.1").unwrap();
    let tls = connector.connect(server_name, tcp).await.unwrap();
    assert_eq!(
        tls.get_ref().1.alpn_protocol(),
        Some(alpn),
        "ALPN must negotiate the requested protocol"
    );
    tls
}

async fn h2_client<B>(addr: SocketAddr, ca_path: &Path) -> http2::SendRequest<B>
where
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn StdError + Send + Sync>>,
{
    let tls = tls_connect(addr, ca_path, b"h2").await;
    let (sender, connection) = http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
        .await
        .expect("HTTP/2 handshake");
    tokio::spawn(async move {
        let _ = connection.await;
    });
    sender
}

async fn http1_client<B>(addr: SocketAddr, ca_path: &Path) -> http1::SendRequest<B>
where
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn StdError + Send + Sync>>,
{
    let tls = tls_connect(addr, ca_path, b"http/1.1").await;
    let (sender, connection) = http1::handshake(TokioIo::new(tls))
        .await
        .expect("HTTP/1.1 handshake");
    tokio::spawn(async move {
        let _ = connection.await;
    });
    sender
}

fn grpc_request(addr: SocketAddr, path: &str, body: Bytes) -> Request<Full<Bytes>> {
    Request::builder()
        .method("POST")
        .uri(format!("https://127.0.0.1:{}{}", addr.port(), path))
        .header("content-type", "application/grpc+proto")
        .header("te", "trailers")
        .body(Full::new(body))
        .unwrap()
}

struct TestEnv {
    _dir: tempfile::TempDir,
    ca_path: PathBuf,
    cert_path: PathBuf,
    key_path: PathBuf,
    allowlist_path: PathBuf,
    upstream: SocketAddr,
    upstream_state: Arc<UpstreamState>,
}

async fn test_env() -> TestEnv {
    let dir = tempfile::tempdir().unwrap();
    let (ca_path, cert_path, key_path) = generate_certificates(dir.path());
    let allowlist_path = write_allowlist(dir.path());
    let (upstream, upstream_state) = spawn_upstream(&cert_path, &key_path).await;
    TestEnv {
        _dir: dir,
        ca_path,
        cert_path,
        key_path,
        allowlist_path,
        upstream,
        upstream_state,
    }
}

#[tokio::test]
#[ignore = "requires TLS, local ports and the wasm-reactor feature"]
async fn unary_grpc_over_h2_echoes_body_and_preserves_trailers() {
    let env = test_env().await;
    let proxy = spawn_proxy(
        env.upstream,
        &env.ca_path,
        &env.cert_path,
        &env.key_path,
        &env.allowlist_path,
        false,
    )
    .await;
    let mut sender = h2_client::<Full<Bytes>>(proxy, &env.ca_path).await;

    let payload = protobuf_string(1, "hello-h2");
    let frame = grpc_frame(&payload);
    let response = sender
        .send_request(grpc_request(proxy, SAY_HELLO, frame.clone()))
        .await
        .expect("unary response");
    let status = response.status();
    let (data, trailers) = read_body(response.into_body()).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "unexpected status; body={:?}",
        String::from_utf8_lossy(&data)
    );
    assert_eq!(data, frame, "unary body must be echoed unchanged");
    let trailers = trailers.expect("grpc trailers");
    assert_eq!(trailers.get("grpc-status").unwrap(), "0");
    assert_eq!(trailers.get("grpc-message").unwrap(), "ok");

    // Empty response body: trailers must still survive.
    let response = sender
        .send_request(grpc_request(proxy, SAY_HELLO, Bytes::new()))
        .await
        .expect("empty unary response");
    assert_eq!(response.status(), StatusCode::OK);
    let (data, trailers) = read_body(response.into_body()).await;
    assert!(data.is_empty());
    let trailers = trailers.expect("grpc trailers on empty body");
    assert_eq!(trailers.get("grpc-status").unwrap(), "0");
    assert_eq!(trailers.get("grpc-message").unwrap(), "ok");
}

#[tokio::test]
#[ignore = "requires TLS, local ports and the wasm-reactor feature"]
async fn streaming_grpc_over_h2_is_not_buffered_and_keeps_trailers() {
    let env = test_env().await;
    let proxy = spawn_proxy(
        env.upstream,
        &env.ca_path,
        &env.cert_path,
        &env.key_path,
        &env.allowlist_path,
        false,
    )
    .await;
    let mut sender = h2_client::<GatedBody>(proxy, &env.ca_path).await;

    let (gate_tx, gate_rx) = oneshot::channel();
    *env.upstream_state.gate.lock().unwrap() = Some(gate_tx);

    let first = grpc_frame(b"first");
    let rest = grpc_frame(b"second");
    let mut request_trailers = HeaderMap::new();
    request_trailers.insert("grpc-request-note", "kept".parse().unwrap());

    let request = Request::builder()
        .method("POST")
        .uri(format!("https://127.0.0.1:{}{}", proxy.port(), STREAM))
        .header("content-type", "application/grpc+proto")
        .header("te", "trailers")
        .header("trailer", "grpc-request-note")
        .body(GatedBody {
            first: Some(first.clone()),
            rest: Some(rest.clone()),
            trailers: Some(request_trailers),
            gate: Some(gate_rx),
        })
        .unwrap();

    let response = tokio::time::timeout(Duration::from_secs(10), sender.send_request(request))
        .await
        .expect("streaming request stalled: proxy buffered the body")
        .expect("streaming response");
    assert_eq!(response.status(), StatusCode::OK);
    let (data, trailers) = read_body(response.into_body()).await;
    let mut expected = first.to_vec();
    expected.extend_from_slice(&rest);
    assert_eq!(data, Bytes::from(expected));
    let trailers = trailers.expect("streaming response trailers");
    assert_eq!(trailers.get("grpc-status").unwrap(), "0");
    assert_eq!(trailers.get("grpc-message").unwrap(), "stream-ok");

    let seen = env
        .upstream_state
        .request_trailers
        .lock()
        .unwrap()
        .clone()
        .expect("upstream request trailers");
    assert_eq!(seen.get("grpc-request-note").unwrap(), "kept");
}

#[tokio::test]
#[ignore = "requires TLS, local ports and the wasm-reactor feature"]
async fn malformed_grpc_frame_is_rejected_before_upstream() {
    let env = test_env().await;
    let proxy = spawn_proxy(
        env.upstream,
        &env.ca_path,
        &env.cert_path,
        &env.key_path,
        &env.allowlist_path,
        false,
    )
    .await;
    let mut sender = h2_client::<Full<Bytes>>(proxy, &env.ca_path).await;

    let response = sender
        .send_request(grpc_request(
            proxy,
            SAY_HELLO,
            Bytes::from_static(&[0, 0, 0]),
        ))
        .await
        .expect("malformed response");
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "truncated frame prefix must map to 400"
    );
    assert_eq!(
        env.upstream_state.calls.load(Ordering::SeqCst),
        0,
        "malformed gRPC must not reach the upstream"
    );
}

#[tokio::test]
#[ignore = "requires TLS, local ports and the wasm-reactor feature"]
async fn sqli_in_declared_protobuf_field_is_not_content_inspected() {
    let env = test_env().await;
    let proxy = spawn_proxy(
        env.upstream,
        &env.ca_path,
        &env.cert_path,
        &env.key_path,
        &env.allowlist_path,
        false,
    )
    .await;
    let mut sender = h2_client::<Full<Bytes>>(proxy, &env.ca_path).await;

    let payload = protobuf_string(1, "' OR '1'='1' -- <script>alert(1)</script>");
    let frame = grpc_frame(&payload);
    let response = sender
        .send_request(grpc_request(proxy, SQLI, frame.clone()))
        .await
        .expect("sqli response");
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "descriptor field policy is structural: SQLi/XSS text in a declared string field is not content-inspected"
    );
    let (data, trailers) = read_body(response.into_body()).await;
    assert_eq!(data, frame);
    assert_eq!(trailers.unwrap().get("grpc-status").unwrap(), "0");
}

#[tokio::test]
#[ignore = "requires TLS, local ports and the wasm-reactor feature"]
async fn sqli_in_unknown_protobuf_field_is_blocked_by_descriptor_policy() {
    let env = test_env().await;
    let proxy = spawn_proxy(
        env.upstream,
        &env.ca_path,
        &env.cert_path,
        &env.key_path,
        &env.allowlist_path,
        false,
    )
    .await;
    let mut sender = h2_client::<Full<Bytes>>(proxy, &env.ca_path).await;

    let payload = protobuf_string(99, "' OR '1'='1' --");
    let response = sender
        .send_request(grpc_request(proxy, UNKNOWN_FIELD, grpc_frame(&payload)))
        .await
        .expect("unknown field response");
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "reject_unknown_fields must block an undeclared field"
    );
    assert_eq!(env.upstream_state.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
#[ignore = "requires TLS, local ports and the wasm-reactor feature"]
async fn grpc_web_over_http1_preserves_body_encoded_trailers() {
    let env = test_env().await;
    let proxy = spawn_proxy(
        env.upstream,
        &env.ca_path,
        &env.cert_path,
        &env.key_path,
        &env.allowlist_path,
        false,
    )
    .await;
    let mut sender = http1_client::<Full<Bytes>>(proxy, &env.ca_path).await;

    let frame = grpc_frame(&protobuf_string(1, "web-hello"));
    let request = Request::builder()
        .method("POST")
        .uri(format!("https://127.0.0.1:{}{}", proxy.port(), WEB))
        .header("content-type", "application/grpc-web+proto")
        .header("te", "trailers")
        .body(Full::new(frame.clone()))
        .unwrap();

    let response = sender
        .send_request(request)
        .await
        .expect("grpc-web response");
    assert_eq!(response.status(), StatusCode::OK);
    let (data, _) = read_body(response.into_body()).await;
    let mut expected = frame.to_vec();
    expected.extend_from_slice(&grpc_web_trailer_frame());
    assert_eq!(
        data,
        Bytes::from(expected),
        "gRPC-Web body-encoded trailers must be forwarded unchanged"
    );
    assert!(
        data.windows(b"grpc-status: 0".len())
            .any(|window| window == b"grpc-status: 0"),
        "gRPC-Web trailer frame must contain grpc-status"
    );
}

#[tokio::test]
#[ignore = "requires TLS, local ports and the wasm-reactor feature"]
async fn grpc_aware_rejection_is_opt_in_and_maps_status() {
    let env = test_env().await;
    let frame = grpc_frame(b"blocked");

    // Default: plain HTTP 403, preserving historical behaviour.
    let legacy = spawn_proxy(
        env.upstream,
        &env.ca_path,
        &env.cert_path,
        &env.key_path,
        &env.allowlist_path,
        false,
    )
    .await;
    let mut sender = h2_client::<Full<Bytes>>(legacy, &env.ca_path).await;
    let response = sender
        .send_request(grpc_request(legacy, BLOCKED, frame.clone()))
        .await
        .expect("legacy rejection");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("text/plain")
    );

    // Opt-in: HTTP 200 with grpc-status 7 (PERMISSION_DENIED) and grpc-message.
    let aware = spawn_proxy(
        env.upstream,
        &env.ca_path,
        &env.cert_path,
        &env.key_path,
        &env.allowlist_path,
        true,
    )
    .await;
    let mut sender = h2_client::<Full<Bytes>>(aware, &env.ca_path).await;
    let response = sender
        .send_request(grpc_request(aware, BLOCKED, frame))
        .await
        .expect("grpc-aware rejection");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("application/grpc")
    );
    let (data, trailers) = read_body(response.into_body()).await;
    assert!(data.is_empty());
    let trailers = trailers.expect("grpc-aware rejection trailers");
    assert_eq!(trailers.get("grpc-status").unwrap(), "7");
    assert!(trailers
        .get("grpc-message")
        .unwrap()
        .to_str()
        .unwrap()
        .contains("not in waf.grpc.method_allowlist"));
}
