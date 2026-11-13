use std::convert::Infallible;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::{Body, Frame, Incoming, SizeHint};
use hyper::header::{HeaderName, HeaderValue};
use hyper::service::service_fn;
use hyper::{HeaderMap, Request, Response, StatusCode, Uri};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::connect::{Connection, HttpConnector};
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioTimer};
use ipnetwork::IpNetwork;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_rustls::TlsConnector;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::{
    CloseFrame, Role, WebSocketConfig as WsCodecConfig,
};
use tokio_tungstenite::tungstenite::{Error as WsError, Message};
use tokio_tungstenite::WebSocketStream;
use tower::Service;
use tracing::{debug, error, info, warn};

use crate::config::{
    Config, CorazaBackend, GrpcStreamingPolicy, HeaderStripMode, ProxyConfig, DEFAULT_STRIP_HEADERS,
};
use crate::error::WafError;
use crate::health::{DependencyHealth, ReadinessProbe, ReadinessSnapshot};
use crate::metrics::Metrics;
use crate::proxy::buffer_pool::{BodyReadError, BufferPool};
use crate::proxy::decompression::{
    decompress_request_body, strip_encoding_headers, DecompressionError,
};
use crate::proxy::framing::{
    read_request_head, reconcile_content_length, reject_request_head,
    validate_request_framing_for_version, validate_request_head, validate_request_trailers,
    FramingVersion, Http1RequestGate,
};
use crate::proxy::grpc_body::{
    probe_grpc_body, GrpcBodyMode, GrpcProbeError, GrpcStreamError, GrpcStreamGuard, PrefixedBody,
};
use crate::proxy::telemetry::{RequestRejection, RequestTelemetry};
use crate::proxy::websocket::{WebSocketHandler, WebSocketTunnelLimiter};
use crate::waf::auth::{ApiKeyEntry, ApiKeyValidator, InMemoryKeyStore};
use crate::waf::security_events::EventDetails;
use crate::waf::tls_config::TlsManager;
use crate::waf::{Decision, RequestContext, ResponseContext, ResponseInspectionOptions, WafEngine};

/// Core WAF Proxy Service with multi-protocol support
///
/// This is the main HTTP proxy service that integrates the WAF engine
/// into the request/response pipeline. It follows the Strategic Roadmap
/// v0.1 requirements for establishing a stable core before WASM integration.
/// Supports HTTP/1.0-3, WebSocket, and WebTransport protocols.
pub struct WafProxyService {
    waf_engine: Arc<WafEngine>,
    upstream_client: UpstreamClient,
    upstream_uri: Uri,
    config: Arc<Config>,
    buffer_pool: Arc<BufferPool>,
    websocket_handler: WebSocketHandler,
    websocket_limiter: WebSocketTunnelLimiter,
    tls_manager: Option<Arc<TlsManager>>,
    auth_validator: Option<Arc<ApiKeyValidator>>,
    trusted_proxies: Vec<IpNetwork>,
    metrics: Arc<Metrics>,
}

/// Upstream byte stream, either plain TCP or TLS over TCP.
trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncStream for T {}

/// Error type shared by every proxied request and response body.
pub(crate) type ProxyBodyError = Box<dyn std::error::Error + Send + Sync>;

/// Upstream connector wrapper that counts newly established connections.
///
/// The hyper connection pool reuses idle connections transparently; this
/// wrapper only observes connector calls, which happen exactly once per new
/// TCP/TLS connection. Comparing this counter with
/// `waf_upstream_requests_total` yields the pool reuse ratio.
#[derive(Clone)]
pub(crate) struct UpstreamConnector<C> {
    inner: C,
    metrics: Arc<Metrics>,
}

impl<C> Service<Uri> for UpstreamConnector<C>
where
    C: Service<Uri> + Clone + Send + Sync + 'static,
    C::Future: Send + 'static,
    C::Response: hyper::rt::Read + hyper::rt::Write + Connection + Unpin + Send + 'static,
    C::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    type Response = C::Response;
    type Error = C::Error;
    type Future = Pin<Box<dyn Future<Output = Result<C::Response, C::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut TaskContext<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let metrics = Arc::clone(&self.metrics);
        let future = self.inner.call(uri);
        Box::pin(async move {
            let result = future.await;
            if result.is_ok() {
                metrics.record_upstream_connection();
            }
            result
        })
    }
}

/// Upstream HTTP client type, including the observing connector.
pub(crate) type UpstreamClient =
    Client<UpstreamConnector<HttpsConnector<HttpConnector>>, ProxyBody>;

/// gRPC request classification derived from the request headers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct RequestClassification {
    /// `content-type` is a gRPC or gRPC-Web media type.
    pub(crate) is_grpc: bool,
    /// The body uses the gRPC-Web HTTP/1.1 framing (trailers in the body).
    pub(crate) is_grpc_web: bool,
}

/// Media types that use the gRPC/gRPC-Web transport framing.
///
/// Deliberately an explicit allowlist, not a prefix match: `application/grpcx`
/// and `application/grpc-malicious` are unknown types and must not be handed
/// to the gRPC body framing parser.
const GRPC_MEDIA_TYPES: &[&str] = &[
    "application/grpc",
    "application/grpc+proto",
    "application/grpc+json",
    "application/grpc-web",
    "application/grpc-web+proto",
    "application/grpc-web+json",
    "application/grpc-web-text",
    "application/grpc-web-text+proto",
    "application/grpc-web-text+json",
];

/// The subset of [`GRPC_MEDIA_TYPES`] that uses gRPC-Web framing (trailers are
/// carried in the body).
const GRPC_WEB_MEDIA_TYPES: &[&str] = &[
    "application/grpc-web",
    "application/grpc-web+proto",
    "application/grpc-web+json",
    "application/grpc-web-text",
    "application/grpc-web-text+proto",
    "application/grpc-web-text+json",
];

/// Classify a request for gRPC transport handling.
///
/// Only the media types in [`GRPC_MEDIA_TYPES`] are gRPC. Matching is
/// case-insensitive and ignores parameters (`; charset=...`). Unknown types
/// that merely start with `application/grpc` (for example `application/grpcx`
/// or `application/grpc-malicious`) are treated as ordinary HTTP: they take
/// the normal body-inspection path and never reach the gRPC framing parser or
/// gRPC transport shortcuts.
pub(crate) fn classify_request(headers: &HeaderMap) -> RequestClassification {
    let content_type = headers
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.trim().to_ascii_lowercase());

    let media_type = content_type
        .as_deref()
        .map(|value| value.split(';').next().unwrap_or("").trim())
        .unwrap_or("");

    let is_grpc = GRPC_MEDIA_TYPES.contains(&media_type);
    let is_grpc_web = is_grpc && GRPC_WEB_MEDIA_TYPES.contains(&media_type);

    // Streaming is not inferred from HTTP framing. HTTP/2 does not require
    // `content-length`, so a unary RPC without one is still unary. The actual
    // frame sequence is classified by `grpc_body::probe_grpc_body`.
    RequestClassification {
        is_grpc,
        is_grpc_web,
    }
}

/// True when the request is a gRPC call (response bodies are framed/streamed).
fn is_grpc_request(request: &RequestContext) -> bool {
    classify_request(&request.headers).is_grpc
}

/// Connection-scoped header fields that must not be forwarded by a proxy.
///
/// `Trailer` is deliberately absent: it is an end-to-end field announcing
/// trailing headers and is required for gRPC over HTTP/1.1.
pub(crate) fn is_hop_by_hop_header(name: &str) -> bool {
    // Case-insensitive so callers can pass the wire name without allocating a
    // lowercase copy on the response hot path.
    name.eq_ignore_ascii_case("connection")
        || name.eq_ignore_ascii_case("proxy-connection")
        || name.eq_ignore_ascii_case("keep-alive")
        || name.eq_ignore_ascii_case("transfer-encoding")
        || name.eq_ignore_ascii_case("upgrade")
}

/// Collect the lower-case field names nominated by every `Connection` header.
///
/// RFC 9110 makes these hop-by-hop for the current connection, so they must
/// never be forwarded even when they are not in the fixed hop-by-hop set.
fn connection_nominated_headers(headers: &HeaderMap) -> Vec<String> {
    let mut nominated = Vec::new();
    for value in headers.get_all("connection") {
        if let Ok(value) = value.to_str() {
            for token in value.split(',') {
                let token = token.trim();
                if !token.is_empty() {
                    nominated.push(token.to_ascii_lowercase());
                }
            }
        }
    }
    nominated
}

/// Client-supplied headers the proxy removes before WAF inspection and before
/// forwarding to the upstream.
///
/// Matching is case-insensitive. A trailing `*` is a prefix match, so the
/// default `x-forwarded-*` pattern covers `X-Forwarded-For`, `-Host`, `-Port`,
/// `-Prefix`, `-Proto`, `-Server` and any future `X-Forwarded-*` header. The
/// proxy then emits its own trusted `X-Forwarded-*` values from the resolved
/// client address and inbound `Host`.
#[derive(Debug, Clone)]
pub(crate) struct HeaderStripPolicy {
    patterns: Vec<String>,
}

impl HeaderStripPolicy {
    pub(crate) fn from_config(config: &ProxyConfig) -> Self {
        let mut patterns = Vec::new();
        if config.strip_headers_mode == HeaderStripMode::Extend {
            patterns.extend(DEFAULT_STRIP_HEADERS.iter().map(|name| (*name).to_string()));
        }
        patterns.extend(
            config
                .strip_headers
                .iter()
                .map(|name| name.trim().to_ascii_lowercase())
                .filter(|name| !name.is_empty()),
        );
        patterns.sort_unstable();
        patterns.dedup();
        Self { patterns }
    }

    pub(crate) fn defaults() -> Self {
        Self::from_config(&ProxyConfig::default())
    }

    fn matches(&self, name: &str) -> bool {
        self.patterns.iter().any(|pattern| {
            if pattern == "*" {
                true
            } else if let Some(prefix) = pattern.strip_suffix('*') {
                name.starts_with(prefix)
            } else {
                name.eq_ignore_ascii_case(pattern)
            }
        })
    }

    pub(crate) fn should_strip(&self, name: &str) -> bool {
        self.matches(name)
    }

    /// Client identity headers must remain usable for trusted-proxy
    /// resolution and are rewritten by the proxy, so reject mode ignores them.
    fn is_client_identity_header(name: &str) -> bool {
        matches!(name, "x-forwarded-for" | "x-real-ip" | "x-forwarded-proto")
    }

    pub(crate) fn is_ambiguous_routing(&self, name: &str) -> bool {
        self.should_strip(name) && !Self::is_client_identity_header(name)
    }

    pub(crate) fn first_ambiguous<'a>(&self, headers: &'a HeaderMap) -> Option<&'a str> {
        headers
            .keys()
            .find(|name| self.is_ambiguous_routing(name.as_str()))
            .map(|name| name.as_str())
    }

    /// Remove every matching client header, logging each at debug level.
    pub(crate) fn strip(&self, headers: &mut HeaderMap, client_ip: IpAddr) {
        let matched: Vec<_> = headers
            .keys()
            .filter(|name| self.should_strip(name.as_str()))
            .cloned()
            .collect();
        for name in matched {
            headers.remove(&name);
            debug!(
                "Stripped client-supplied routing header '{}' from request from {}",
                name.as_str(),
                client_ip
            );
        }
    }
}

/// Requests and responses may be buffered, passed through from hyper, or
/// streamed under a size/duration guard.
///
/// Trailing headers are body frames in hyper 1.x, never request/response
/// parts, so every variant that can carry trailers yields them as a final
/// `Frame::trailers`. This is what keeps gRPC `grpc-status` / `grpc-message`
/// intact for both unary and streaming RPCs.
pub(crate) enum ProxyBody {
    /// A fully buffered body with no trailing headers.
    Full(Full<Bytes>),
    /// A buffered body plus optional trailing headers.
    Buffered {
        data: Option<Bytes>,
        trailers: Option<HeaderMap>,
    },
    /// An upstream body streamed incrementally (body frames and trailers).
    Incoming(Incoming),
    /// A streaming body bounded by a byte cap and an overall deadline.
    Guarded(GuardedBody<Incoming>),
    /// A type-erased body used for frame-aware gRPC streaming guards.
    Boxed(BoxBody<Bytes, ProxyBodyError>),
}

impl ProxyBody {
    pub(crate) fn full(data: impl Into<Bytes>) -> Self {
        Self::Full(Full::new(data.into()))
    }

    pub(crate) fn buffered(data: Bytes, trailers: Option<HeaderMap>) -> Self {
        Self::Buffered {
            data: Some(data),
            trailers,
        }
    }

    pub(crate) fn incoming(body: Incoming) -> Self {
        Self::Incoming(body)
    }

    /// Stream `body` unchanged while enforcing a byte cap and a deadline.
    pub(crate) fn guarded(body: Incoming, max_bytes: usize, max_duration: Duration) -> Self {
        Self::Guarded(GuardedBody::new(body, max_bytes, max_duration))
    }

    /// Trailer field names carried by an already-buffered body, formatted for a
    /// `Trailer` header. Hyper only encodes trailing fields that the message
    /// head announced, so this must be emitted before the body is polled.
    fn announced_trailer_fields(&self) -> Option<String> {
        match self {
            ProxyBody::Buffered {
                trailers: Some(trailers),
                ..
            } if !trailers.is_empty() => Some(
                trailers
                    .keys()
                    .map(|name| name.as_str())
                    .collect::<Vec<_>>()
                    .join(", "),
            ),
            _ => None,
        }
    }
}

fn map_body_poll<E>(
    poll: Poll<Option<Result<Frame<Bytes>, E>>>,
) -> Poll<Option<Result<Frame<Bytes>, ProxyBodyError>>>
where
    E: std::error::Error + Send + Sync + 'static,
{
    match poll {
        Poll::Ready(Some(Ok(frame))) => Poll::Ready(Some(Ok(frame))),
        Poll::Ready(Some(Err(error))) => Poll::Ready(Some(Err(Box::new(error) as ProxyBodyError))),
        Poll::Ready(None) => Poll::Ready(None),
        Poll::Pending => Poll::Pending,
    }
}

impl Body for ProxyBody {
    type Data = Bytes;
    type Error = ProxyBodyError;

    fn size_hint(&self) -> SizeHint {
        match self {
            ProxyBody::Full(body) => body.size_hint(),
            ProxyBody::Buffered { data, trailers } => {
                // A non-empty trailer block cannot be combined with an exact
                // Content-Length on HTTP/1.x. Report an unknown size so hyper
                // keeps chunked framing and emits the trailers instead of
                // silently dropping them.
                if trailers
                    .as_ref()
                    .is_some_and(|trailers| !trailers.is_empty())
                {
                    SizeHint::default()
                } else {
                    SizeHint::with_exact(data.as_ref().map_or(0, |data| data.len() as u64))
                }
            }
            ProxyBody::Incoming(body) => body.size_hint(),
            ProxyBody::Guarded(body) => body.size_hint(),
            ProxyBody::Boxed(body) => body.size_hint(),
        }
    }

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        match self.get_mut() {
            ProxyBody::Full(body) => map_body_poll(Pin::new(body).poll_frame(cx)),
            ProxyBody::Buffered { data, trailers } => {
                if let Some(data) = data.take() {
                    if !data.is_empty() {
                        return Poll::Ready(Some(Ok(Frame::data(data))));
                    }
                }
                if let Some(trailers) = trailers.take() {
                    return Poll::Ready(Some(Ok(Frame::trailers(trailers))));
                }
                Poll::Ready(None)
            }
            ProxyBody::Incoming(body) => map_body_poll(Pin::new(body).poll_frame(cx)),
            ProxyBody::Guarded(body) => Pin::new(body).poll_frame(cx),
            ProxyBody::Boxed(body) => Pin::new(body).poll_frame(cx),
        }
    }
}

/// Streaming-body limit violations surfaced to hyper as body errors.
#[derive(Debug)]
pub(crate) enum StreamLimitError {
    BytesExceeded { limit: usize },
    DurationExceeded { seconds: u64 },
}

impl std::fmt::Display for StreamLimitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StreamLimitError::BytesExceeded { limit } => {
                write!(f, "streaming body exceeds limit of {} bytes", limit)
            }
            StreamLimitError::DurationExceeded { seconds } => {
                write!(f, "streaming body exceeded its {} second deadline", seconds)
            }
        }
    }
}

impl std::error::Error for StreamLimitError {}

/// Body wrapper that relays frames unchanged while enforcing a total byte cap
/// and an overall deadline. No buffering is performed.
pub(crate) struct GuardedBody<B> {
    inner: B,
    remaining: usize,
    deadline: Pin<Box<tokio::time::Sleep>>,
    max_seconds: u64,
}

impl<B> GuardedBody<B> {
    fn new(inner: B, max_bytes: usize, max_duration: Duration) -> Self {
        Self {
            inner,
            remaining: max_bytes,
            deadline: Box::pin(tokio::time::sleep(max_duration)),
            max_seconds: max_duration.as_secs(),
        }
    }
}

impl<B> Body for GuardedBody<B>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    type Data = Bytes;
    type Error = ProxyBodyError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let this = self.get_mut();
        if std::future::Future::poll(this.deadline.as_mut(), cx).is_ready() {
            return Poll::Ready(Some(Err(Box::new(StreamLimitError::DurationExceeded {
                seconds: this.max_seconds,
            }))));
        }

        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    if data.len() > this.remaining {
                        return Poll::Ready(Some(Err(Box::new(StreamLimitError::BytesExceeded {
                            limit: this.remaining,
                        }))));
                    }
                    this.remaining -= data.len();
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(error))) => {
                Poll::Ready(Some(Err(Box::new(error) as ProxyBodyError)))
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Build the tungstenite codec limits from the server configuration.
///
/// The parser enforces these while reading, so an oversized frame or a
/// fragmented message that exceeds the message cap is rejected before the
/// complete message is assembled. `0` values inherit `server.max_body_size`.
fn websocket_codec_config(config: &crate::config::ServerConfig) -> WsCodecConfig {
    let max_frame = config
        .websocket
        .resolved_max_frame_bytes(config.max_body_size);
    let max_message = config
        .websocket
        .resolved_max_message_bytes(config.max_body_size);
    WsCodecConfig::default()
        .max_frame_size(Some(max_frame))
        .max_message_size(Some(max_message))
}

/// A WebSocket upgrade must not carry a request body. Any framing or content
/// coding header means the client is trying to smuggle bytes past the normal
/// body inspection path.
fn websocket_upgrade_has_body(headers: &HeaderMap) -> bool {
    if headers.contains_key(hyper::header::TRANSFER_ENCODING)
        || headers.contains_key(hyper::header::CONTENT_ENCODING)
    {
        return true;
    }
    match headers.get(hyper::header::CONTENT_LENGTH) {
        Some(value) => value
            .to_str()
            .ok()
            .and_then(|value| value.trim().parse::<u64>().ok())
            .map(|length| length != 0)
            .unwrap_or(true),
        None => false,
    }
}

/// Resolve a WebSocket upstream URI to `(use_tls, port)`.
fn websocket_upstream_transport(upstream: &Uri) -> Result<(bool, u16), ()> {
    match upstream.scheme_str() {
        Some("http") => Ok((false, upstream.port_u16().unwrap_or(80))),
        Some("https") => Ok((true, upstream.port_u16().unwrap_or(443))),
        _ => Err(()),
    }
}

/// IO wrapper that replays bytes already read from the upstream socket during
/// the HTTP upgrade handshake.
struct PrefixedIo<S> {
    prefix: Vec<u8>,
    offset: usize,
    inner: S,
}

impl<S> PrefixedIo<S> {
    fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self {
            prefix,
            offset: 0,
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedIo<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.offset < this.prefix.len() {
            let remaining = &this.prefix[this.offset..];
            let count = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..count]);
            this.offset += count;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedIo<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// HTTP/1.1 `Upgrade: webtransport` is not a WebTransport transport; it is
/// rejected with `501`. WebTransport is served over HTTP/3 on the dedicated
/// UDP listener.
#[cfg(feature = "webtransport")]
fn is_webtransport_upgrade(headers: &hyper::HeaderMap) -> bool {
    headers
        .get("upgrade")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("webtransport"))
}

/// Why a request head exceeded the configured header bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HeaderLimitViolation {
    Count { count: usize, limit: usize },
    Bytes { bytes: usize, limit: usize },
}

impl HeaderLimitViolation {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Count { .. } => "header_count",
            Self::Bytes { .. } => "header_bytes",
        }
    }
}

/// Enforce `server.max_header_count` and `server.max_header_bytes` before any
/// body handling. hyper's parser limits are configured above these values so
/// this check produces the generic `431` response instead of a connection
/// reset. Only aggregate counts are logged; header values never are.
pub(crate) fn enforce_header_bounds(
    headers: &HeaderMap,
    config: &crate::config::ServerConfig,
) -> Result<(), HeaderLimitViolation> {
    let count = headers.len();
    if count > config.max_header_count {
        return Err(HeaderLimitViolation::Count {
            count,
            limit: config.max_header_count,
        });
    }

    let mut bytes = 0usize;
    for (name, value) in headers {
        bytes = bytes
            .saturating_add(name.as_str().len())
            .saturating_add(value.as_bytes().len())
            .saturating_add(4);
        if bytes > config.max_header_bytes {
            return Err(HeaderLimitViolation::Bytes {
                bytes,
                limit: config.max_header_bytes,
            });
        }
    }
    Ok(())
}

/// Maximum number of bytes accepted across every value of one forwarding
/// header family. Larger chains are discarded rather than silently truncated.
pub(crate) const MAX_FORWARDED_HEADER_BYTES: usize = 8 * 1024;

/// Maximum number of hops accepted in one forwarding chain. Larger chains are
/// discarded rather than silently truncated.
pub(crate) const MAX_FORWARDED_CHAIN_HOPS: usize = 32;

/// Why a trusted peer's forwarding header was not used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClientIpFallback {
    MalformedXForwardedFor,
    MalformedForwarded,
    MalformedXRealIp,
    MalformedXClientIp,
    ForwardedHeaderTooLarge,
    ForwardedChainTooLong,
}

impl ClientIpFallback {
    fn as_str(self) -> &'static str {
        match self {
            Self::MalformedXForwardedFor => "malformed_x_forwarded_for",
            Self::MalformedForwarded => "malformed_forwarded",
            Self::MalformedXRealIp => "malformed_x_real_ip",
            Self::MalformedXClientIp => "malformed_x_client_ip",
            Self::ForwardedHeaderTooLarge => "forwarded_header_too_large",
            Self::ForwardedChainTooLong => "forwarded_chain_too_long",
        }
    }

    fn for_header(header: ForwardedHeader) -> Self {
        match header {
            ForwardedHeader::XForwardedFor => Self::MalformedXForwardedFor,
            ForwardedHeader::Forwarded => Self::MalformedForwarded,
            ForwardedHeader::XRealIp => Self::MalformedXRealIp,
            ForwardedHeader::XClientIp => Self::MalformedXClientIp,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ForwardedHeader {
    XForwardedFor,
    Forwarded,
    XRealIp,
    XClientIp,
}

impl ForwardedHeader {
    fn name(self) -> &'static str {
        match self {
            Self::XForwardedFor => "x-forwarded-for",
            Self::Forwarded => "forwarded",
            Self::XRealIp => "x-real-ip",
            Self::XClientIp => "x-client-ip",
        }
    }
}

/// Parse one forwarding-chain member. Bare addresses, IPv4 `addr:port`,
/// bracketed IPv6 `[addr]:port` and bare IPv6 are accepted.
fn parse_forwarded_ip(raw: &str) -> Option<IpAddr> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }

    if let Some(rest) = raw.strip_prefix('[') {
        let (inside, after) = rest.split_once(']')?;
        let ip = inside.parse::<IpAddr>().ok()?;
        if after.is_empty() {
            return Some(ip);
        }
        let port = after.strip_prefix(':')?;
        if port.is_empty() || port.parse::<u16>().is_err() {
            return None;
        }
        return Some(ip);
    }

    if let Ok(ip) = raw.parse::<IpAddr>() {
        return Some(ip);
    }

    raw.parse::<SocketAddr>().ok().map(|socket| socket.ip())
}

/// Split on `delimiter` while ignoring delimiters inside quoted strings.
/// Returns `None` when a quote is left unterminated.
fn split_quoted(value: &str, delimiter: char) -> Option<Vec<&str>> {
    let mut parts = Vec::new();
    let mut start = 0usize;
    let mut in_quotes = false;
    let mut escaped = false;

    for (index, ch) in value.char_indices() {
        if in_quotes {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_quotes = false;
            }
        } else if ch == '"' {
            in_quotes = true;
        } else if ch == delimiter {
            parts.push(&value[start..index]);
            start = index + ch.len_utf8();
        }
    }

    if in_quotes || escaped {
        return None;
    }
    parts.push(&value[start..]);
    Some(parts)
}

fn unquote_forwarded(value: &str) -> Option<String> {
    if let Some(inner) = value.strip_prefix('"') {
        let inner = inner.strip_suffix('"')?;
        let mut out = String::with_capacity(inner.len());
        let mut chars = inner.chars();
        while let Some(ch) = chars.next() {
            match ch {
                '\\' => out.push(chars.next()?),
                '"' => return None,
                _ => out.push(ch),
            }
        }
        Some(out)
    } else if value.contains('"') {
        None
    } else {
        Some(value.to_string())
    }
}

/// Extract the `for=` parameter from one RFC 7239 Forwarded element.
fn parse_forwarded_element(element: &str) -> Option<IpAddr> {
    let mut address = None;
    for parameter in split_quoted(element, ';')? {
        let (name, value) = parameter.split_once('=')?;
        if !name.trim().eq_ignore_ascii_case("for") {
            continue;
        }
        if address.is_some() {
            return None;
        }
        let value = unquote_forwarded(value.trim())?;
        address = Some(parse_forwarded_ip(&value)?);
    }
    address
}

/// Request-side context needed to evaluate an upstream response.
pub(crate) struct ResponseInspectionRequest<'a> {
    pub(crate) request: &'a RequestContext,
    pub(crate) config: &'a crate::config::ResponseInspectionConfig,
}

/// Per-connection state cloned into each hyper service invocation.
#[derive(Clone)]
pub(crate) struct ProxyState {
    pub(crate) waf_engine: Arc<WafEngine>,
    pub(crate) upstream_client: UpstreamClient,
    pub(crate) upstream_uri: Uri,
    pub(crate) config: Arc<Config>,
    pub(crate) buffer_pool: Arc<BufferPool>,
    pub(crate) auth_validator: Option<Arc<ApiKeyValidator>>,
    pub(crate) trusted_proxies: Arc<Vec<IpNetwork>>,
    pub(crate) strip_policy: Arc<HeaderStripPolicy>,
    pub(crate) websocket_limiter: WebSocketTunnelLimiter,
    pub(crate) metrics: Arc<Metrics>,
}

/// RAII slot for one admitted ingress connection. Holding it keeps the
/// configured `server.max_connections` permit and the active gauge accurate
/// even if the connection task panics.
struct ConnectionSlot {
    _permit: OwnedSemaphorePermit,
    metrics: Arc<Metrics>,
}

impl Drop for ConnectionSlot {
    fn drop(&mut self) {
        self.metrics.connection_finished();
    }
}

/// Write a minimal `503` with `Retry-After` for a plaintext connection that
/// exceeded `server.max_connections`, then close. TLS connections cannot be
/// answered before the handshake, so they are closed promptly instead.
async fn reject_connection_over_limit(mut stream: TcpStream) {
    use tokio::io::AsyncWriteExt;

    const BODY: &str = "Service Unavailable\n";
    let response = format!(
        "HTTP/1.1 503 Service Unavailable\r\n\
         Retry-After: 1\r\n\
         Content-Type: text/plain\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n{}",
        BODY.len(),
        BODY
    );
    let _ = tokio::time::timeout(
        Duration::from_secs(1),
        stream.write_all(response.as_bytes()),
    )
    .await;
    let _ = tokio::time::timeout(Duration::from_secs(1), stream.shutdown()).await;
}

/// Build the rustls client configuration used for HTTPS upstreams.
///
/// The WebPKI public roots are always trusted. When `proxy.upstream_ca_path`
/// is set, the certificates in that PEM bundle are trusted in addition to the
/// public roots, which allows private/self-signed upstream CAs.
///
/// When both `client_cert_path` and `client_key_path` are set, the PEM client
/// certificate chain and key are presented to the upstream for mutual TLS.
fn build_upstream_tls_config(
    ca_path: Option<&str>,
    client_cert_path: Option<&str>,
    client_key_path: Option<&str>,
) -> Result<ClientConfig, WafError> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    if let Some(ca_path) = ca_path {
        let ca_pem = std::fs::read(ca_path).map_err(|e| {
            WafError::internal(format!(
                "Failed to read upstream CA bundle '{}': {}",
                ca_path, e
            ))
        })?;

        let mut loaded = 0usize;
        for cert in CertificateDer::pem_slice_iter(&ca_pem) {
            let cert = cert.map_err(|e| {
                WafError::internal(format!(
                    "Failed to parse upstream CA bundle '{}': {}",
                    ca_path, e
                ))
            })?;
            roots.add(cert).map_err(|e| {
                WafError::internal(format!(
                    "Invalid certificate in upstream CA bundle '{}': {}",
                    ca_path, e
                ))
            })?;
            loaded += 1;
        }

        if loaded == 0 {
            return Err(WafError::internal(format!(
                "Upstream CA bundle '{}' contains no certificates",
                ca_path
            )));
        }
    }

    let builder =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|e| WafError::internal(format!("Failed to build upstream TLS config: {}", e)))?
            .with_root_certificates(roots);

    match (client_cert_path, client_key_path) {
        (None, None) => Ok(builder.with_no_client_auth()),
        (Some(cert_path), Some(key_path)) => {
            let cert_pem = std::fs::read(cert_path).map_err(|e| {
                WafError::internal(format!(
                    "Failed to read upstream client certificate '{}': {}",
                    cert_path, e
                ))
            })?;
            let certs = CertificateDer::pem_slice_iter(&cert_pem)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| {
                    WafError::internal(format!(
                        "Failed to parse upstream client certificate '{}': {}",
                        cert_path, e
                    ))
                })?;
            if certs.is_empty() {
                return Err(WafError::internal(format!(
                    "Upstream client certificate '{}' contains no certificates",
                    cert_path
                )));
            }

            let key_pem = std::fs::read(key_path).map_err(|e| {
                WafError::internal(format!(
                    "Failed to read upstream client key '{}': {}",
                    key_path, e
                ))
            })?;
            let key = PrivateKeyDer::from_pem_slice(&key_pem).map_err(|e| {
                WafError::internal(format!(
                    "Failed to parse upstream client key '{}': {}",
                    key_path, e
                ))
            })?;

            builder
                .with_client_auth_cert(certs, key)
                .map_err(|e| {
                    WafError::internal(format!(
                        "Failed to configure upstream mutual TLS from '{}' and '{}': {}",
                        cert_path, key_path, e
                    ))
                })
        }
        (Some(_), None) => Err(WafError::internal(
            "proxy.upstream_client_cert_path is set but proxy.upstream_client_key_path is missing; both are required for upstream mutual TLS",
        )),
        (None, Some(_)) => Err(WafError::internal(
            "proxy.upstream_client_key_path is set but proxy.upstream_client_cert_path is missing; both are required for upstream mutual TLS",
        )),
    }
}

/// Build the absolute URI probed by upstream health checks.
fn upstream_health_uri(base: &Uri, path: &str) -> Option<Uri> {
    let scheme = base.scheme_str()?;
    let authority = base.authority()?;
    Uri::builder()
        .scheme(scheme)
        .authority(authority.as_str())
        .path_and_query(path)
        .build()
        .ok()
}

/// Periodically probe the upstream so a dead idle connection is evicted before
/// a client request is routed onto it. Failures are counted, not fatal: the
/// proxy keeps serving and the hyper pool retries with a fresh connection.
async fn run_upstream_health_checks(
    client: UpstreamClient,
    health_uri: Uri,
    interval: Duration,
    metrics: Arc<Metrics>,
) {
    loop {
        tokio::time::sleep(interval).await;

        let request = match Request::builder()
            .method(hyper::Method::GET)
            .uri(health_uri.clone())
            .header(
                hyper::header::HOST,
                health_uri.authority().map(|a| a.as_str()).unwrap_or(""),
            )
            .body(ProxyBody::full(Bytes::new()))
        {
            Ok(request) => request,
            Err(error) => {
                warn!("Failed to build upstream health-check request: {}", error);
                metrics.record_upstream_health_check(false);
                continue;
            }
        };

        let ok = matches!(
            tokio::time::timeout(Duration::from_secs(5), client.request(request)).await,
            Ok(Ok(response)) if response.status().is_success()
        );
        metrics.record_upstream_request();
        metrics.record_upstream_health_check(ok);
        if !ok {
            warn!("Upstream health check {} failed", health_uri);
        }
    }
}

/// Readiness adapter over the live engine and event exporters.
pub(crate) struct ProxyReadinessProbe {
    engine: Arc<WafEngine>,
    backend: String,
}

#[async_trait]
impl ReadinessProbe for ProxyReadinessProbe {
    async fn snapshot(&self) -> ReadinessSnapshot {
        let engine_health = self.engine.event_exporter_health().await;
        let configured = self.engine.configured_exporters();
        let mut dependencies = Vec::new();

        // The persistent event store is a required dependency when enabled.
        // Probe the configured backend by name (redb is the default, sled is
        // the legacy backend); a hard-coded Sled probe made a healthy redb
        // deployment permanently report `event_store_unavailable:Sled`.
        let event_store = self.engine.event_store_name();
        if let Some(store_name) = event_store {
            let healthy = engine_health
                .iter()
                .any(|(name, healthy)| name == store_name && *healthy);
            dependencies.push(DependencyHealth {
                name: store_name.to_string(),
                status: if healthy { "healthy" } else { "down" }.to_string(),
                required: true,
                detail: Some(if healthy {
                    "event store open".to_string()
                } else {
                    "event store unavailable or not compiled in".to_string()
                }),
            });
        }

        for name in configured {
            if Some(name) == event_store {
                continue;
            }
            let healthy = engine_health
                .iter()
                .any(|(exporter, healthy)| exporter == name && *healthy);
            // Tracing export is best-effort; CEF/Sled are audit paths and are
            // required when configured.
            let required = name != "OpenTelemetry";
            dependencies.push(DependencyHealth {
                name: name.to_string(),
                status: if healthy { "healthy" } else { "down" }.to_string(),
                required,
                detail: if healthy {
                    None
                } else {
                    Some(format!("{name} exporter health check failed"))
                },
            });
        }

        ReadinessSnapshot {
            backend: self.backend.clone(),
            engine_ready: self.engine.is_ready(),
            engine_detail: self
                .engine
                .waf_init_error()
                .map(str::to_string)
                .or_else(|| {
                    Some(format!(
                        "{backend} inspection engine initialised",
                        backend = self.backend
                    ))
                }),
            dependencies,
        }
    }
}

impl WafProxyService {
    /// Create a new WAF proxy service with optimized connection pooling
    pub fn new(config: Config) -> Result<Self, WafError> {
        info!("Initializing WAF Proxy Service with performance optimizations");

        if config.server.grpc_streaming_policy == GrpcStreamingPolicy::TransportOnly {
            warn!(
                "server.grpc_streaming_policy = \"transport-only\": genuinely streaming gRPC \
                 RPCs are permitted; every complete message is inspected incrementally \
                 before forwarding. Set it to \"reject\" to refuse streaming RPCs."
            );
        }

        let metrics = Arc::new(Metrics::new());
        let waf_engine = Arc::new(WafEngine::with_config_and_metrics(
            &config,
            Some(Arc::clone(&metrics)),
        ));

        // The WAF engine is a configured security control: a start-up failure
        // (Coraza compile/validation/warm, the Rust engine strict load, or the
        // gRPC/GraphQL allowlist artifact) must stop start-up instead of
        // surfacing as a 503 per request. There is no silent fallback.
        #[cfg(any(
            feature = "wasm-reactor",
            feature = "coraza-native",
            feature = "rust-engine"
        ))]
        if let Some(err) = waf_engine.waf_init_error() {
            return Err(WafError::internal(format!(
                "WAF engine initialisation failed (fail-closed): {err}"
            )));
        }

        #[cfg(feature = "distri-kv")]
        if let Some(state) = waf_engine.distributed_state() {
            metrics.set_distributed_state(Arc::clone(state));
        }

        // Initialize high-performance buffer pool for zero-allocation HTTP processing
        let buffer_pool = BufferPool::new();
        info!(
            "Buffer pool initialized with {} total buffers",
            buffer_pool.stats().small_capacity
                + buffer_pool.stats().medium_capacity
                + buffer_pool.stats().large_capacity
        );

        // Create optimized HTTP client with multi-protocol support
        let mut connector = HttpConnector::new();
        connector.enforce_http(false);
        connector.set_keepalive(Some(Duration::from_secs(30)));
        connector.set_nodelay(true);
        connector.set_reuse_address(true);

        let tls_config = build_upstream_tls_config(
            config.proxy.upstream_ca_path.as_deref(),
            config.proxy.upstream_client_cert_path.as_deref(),
            config.proxy.upstream_client_key_path.as_deref(),
        )?;
        let connector = HttpsConnectorBuilder::new()
            .with_tls_config(tls_config)
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .wrap_connector(connector);
        let connector = UpstreamConnector {
            inner: connector,
            metrics: Arc::clone(&metrics),
        };

        let h2 = config.server.http2.clone();
        let pool = config.proxy.pool.clone();

        // Create HTTP client with optimized configuration for all protocols.
        // HTTP/2 tuning and bounded pool reuse are opt-in so the default
        // behaviour is unchanged.
        let mut client_builder = Client::builder(TokioExecutor::new());
        client_builder
            .http1_title_case_headers(true)
            .http1_preserve_header_case(true)
            .http2_only(false); // Support HTTP/1.x and HTTP/2

        if h2.enabled {
            client_builder
                .timer(TokioTimer::new())
                .http2_adaptive_window(h2.adaptive_window)
                .http2_initial_stream_window_size(h2.initial_stream_window_bytes)
                .http2_initial_connection_window_size(h2.initial_connection_window_bytes)
                .http2_initial_max_send_streams(h2.max_concurrent_streams as usize)
                .http2_keep_alive_timeout(Duration::from_secs(h2.keep_alive_timeout_secs.max(1)))
                .http2_keep_alive_while_idle(h2.keep_alive_while_idle);
            if h2.keep_alive_interval_secs > 0 {
                client_builder
                    .http2_keep_alive_interval(Duration::from_secs(h2.keep_alive_interval_secs));
            }
        }

        if pool.enabled {
            client_builder
                .pool_timer(TokioTimer::new())
                .pool_idle_timeout(Duration::from_secs(pool.idle_timeout_secs))
                .pool_max_idle_per_host(pool.max_idle_per_host);
            info!(
                "Upstream pool tuning enabled (max_idle_per_host={}, idle_timeout={}s, health_check={}s)",
                pool.max_idle_per_host, pool.idle_timeout_secs, pool.health_check_interval_secs
            );
        }

        let upstream_client = client_builder.build(connector);

        // Parse upstream URI from config using the helper method
        let upstream_uri = config
            .upstream_uri()
            .map_err(|e| WafError::internal(format!("Invalid upstream URL: {}", e)))?;

        let config_arc = Arc::new(config);

        // Initialize protocol handlers
        let websocket_handler =
            WebSocketHandler::new(Arc::clone(&waf_engine), Arc::clone(&config_arc));
        let websocket_limiter = WebSocketTunnelLimiter::new(
            config_arc.server.websocket.max_concurrent_tunnels,
            Arc::clone(&metrics),
        );

        let tls_manager = if config_arc.server.tls.enabled {
            let manager = TlsManager::new(config_arc.server.tls.clone())?;
            Some(Arc::new(manager))
        } else {
            None
        };

        let auth_validator = if config_arc.security.auth.enabled {
            let auth = &config_arc.security.auth;
            let mut entries: Vec<ApiKeyEntry> = auth
                .api_keys
                .iter()
                .map(|key| ApiKeyEntry {
                    key: key.clone(),
                    expires_at: None,
                })
                .collect();
            entries.extend(auth.api_key_entries.iter().cloned());
            let store = Arc::new(InMemoryKeyStore::from_entries(&entries));
            info!(
                "API key authentication enabled ({} key(s), header '{}', failure limit {})",
                entries.len(),
                auth.header_name,
                if auth.failure_limit.enabled {
                    "enabled"
                } else {
                    "disabled"
                }
            );
            Some(Arc::new(ApiKeyValidator::new(
                store,
                config_arc.security.auth.clone(),
            )))
        } else {
            None
        };

        let trusted_proxies = config_arc
            .server
            .trusted_proxies
            .iter()
            .filter_map(|cidr| match cidr.parse::<IpNetwork>() {
                Ok(network) => Some(network),
                Err(e) => {
                    warn!("Ignoring invalid trusted proxy '{}': {}", cidr, e);
                    None
                }
            })
            .collect();

        info!(
            "WAF Proxy Service initialized with {} rules",
            waf_engine.rule_count()
        );
        info!(
            "Upstream target: {} (HTTP/1.1 + HTTP/2, http/https)",
            upstream_uri
        );
        info!(
            "Protocol support: HTTP/1.0-3, WebSocket{}, TLS: {}",
            if cfg!(feature = "webtransport") {
                ", WebTransport"
            } else {
                ""
            },
            if tls_manager.is_some() {
                "enabled"
            } else {
                "disabled"
            }
        );

        Ok(Self {
            waf_engine,
            upstream_client,
            upstream_uri,
            config: config_arc,
            buffer_pool,
            websocket_handler,
            websocket_limiter,
            tls_manager,
            auth_validator,
            trusted_proxies,
            metrics,
        })
    }

    /// Shared runtime metrics, also served by the health service.
    pub fn metrics(&self) -> Arc<Metrics> {
        Arc::clone(&self.metrics)
    }

    /// Readiness adapter over the live engine and configured exporters.
    pub fn readiness_probe(&self) -> Arc<dyn ReadinessProbe> {
        let backend = if !self.config.waf.enabled {
            "disabled".to_string()
        } else {
            match self.config.waf.coraza.backend {
                CorazaBackend::Rust => "rust",
                CorazaBackend::Wasm => "wasm",
                CorazaBackend::Native => "native",
            }
            .to_string()
        };
        Arc::new(ProxyReadinessProbe {
            engine: Arc::clone(&self.waf_engine),
            backend,
        })
    }

    /// The engine's distributed fabric handle, when compiled and enabled.
    /// The server uses it to share one handle with the controller.
    #[cfg(feature = "distri-kv")]
    pub fn distributed_state(&self) -> Option<Arc<crate::waf::distributed::DistributedState>> {
        self.waf_engine.distributed_state().cloned()
    }

    /// Start the proxy server with optimized concurrency
    pub async fn start(&self, bind_addr: SocketAddr) -> Result<(), WafError> {
        info!(
            "Starting WAF Proxy Server on {} with high-performance configuration",
            bind_addr
        );

        let listener = TcpListener::bind(bind_addr)
            .await
            .map_err(|e| WafError::internal(format!("Failed to bind to {}: {}", bind_addr, e)))?;

        self.start_with_listener(listener).await
    }

    /// Serve on an already-bound listener (useful for tests and socket activation).
    pub async fn start_with_listener(&self, listener: TcpListener) -> Result<(), WafError> {
        let listener = crate::proxy::listener::ConnectionListener::from_tokio(
            listener,
            self.config.server.io_backend,
        );
        self.start_with_connection_listener(listener).await
    }

    /// Serve on a listener whose backend has already been selected (used by
    /// benchmarks and tests that need to observe the post-fallback backend).
    pub async fn start_with_connection_listener(
        &self,
        mut listener: crate::proxy::listener::ConnectionListener,
    ) -> Result<(), WafError> {
        let bind_addr = listener
            .local_addr()
            .map_err(|e| WafError::internal(format!("Failed to read listener address: {}", e)))?;
        info!("Listener backend: {:?}", listener.backend());

        info!("🚀 WAF Proxy Server started successfully on {}", bind_addr);
        info!("📊 Performance optimizations: connection pooling, async processing, rule caching");
        if self.tls_manager.is_some() {
            info!("🔒 TLS enabled - all connections require TLS 1.2+");
        } else {
            warn!(
                "⚠️  TLS disabled - connections are unencrypted (not recommended for production)"
            );
        }

        let state = ProxyState {
            waf_engine: Arc::clone(&self.waf_engine),
            upstream_client: self.upstream_client.clone(),
            upstream_uri: self.upstream_uri.clone(),
            config: Arc::clone(&self.config),
            buffer_pool: Arc::clone(&self.buffer_pool),
            auth_validator: self.auth_validator.clone(),
            trusted_proxies: Arc::new(self.trusted_proxies.clone()),
            strip_policy: Arc::new(HeaderStripPolicy::from_config(&self.config.proxy)),
            websocket_limiter: self.websocket_limiter.clone(),
            metrics: Arc::clone(&self.metrics),
        };

        if self.config.proxy.pool.enabled && self.config.proxy.pool.health_check_interval_secs > 0 {
            match upstream_health_uri(
                &self.upstream_uri,
                &self.config.proxy.pool.health_check_path,
            ) {
                Some(health_uri) => {
                    let client = self.upstream_client.clone();
                    let metrics = Arc::clone(&self.metrics);
                    let interval =
                        Duration::from_secs(self.config.proxy.pool.health_check_interval_secs);
                    tokio::spawn(async move {
                        run_upstream_health_checks(client, health_uri, interval, metrics).await;
                    });
                    info!(
                        "Upstream health checks enabled every {}s",
                        interval.as_secs()
                    );
                }
                None => warn!(
                    "Cannot build upstream health-check URI from '{}'",
                    self.upstream_uri
                ),
            }
        }

        #[cfg(feature = "http3")]
        if self.config.server.enable_http3 {
            if !self
                .config
                .server
                .supported_http_versions
                .iter()
                .any(|version| version == "3")
            {
                warn!(
                    "HTTP/3 enabled but \"3\" is not in server.supported_http_versions; not starting HTTP/3"
                );
            } else if let Some(tls_manager) = self.tls_manager.as_ref() {
                let h3_state = state.clone();
                let tls_manager = Arc::clone(tls_manager);
                tokio::spawn(async move {
                    if let Err(e) =
                        crate::proxy::http3::serve(tls_manager, h3_state, bind_addr).await
                    {
                        warn!("HTTP/3 listener not started: {}", e);
                    }
                });
            } else {
                warn!(
                    "HTTP/3 enabled but TLS is disabled; not starting HTTP/3 (QUIC requires TLS 1.3)"
                );
            }
        }

        #[cfg(not(feature = "http3"))]
        if self.config.server.enable_http3 {
            debug!("HTTP/3 requested but this binary was built without the `http3` feature");
        }

        #[cfg(feature = "webtransport")]
        if self.config.server.webtransport.enabled {
            if let Some(tls_manager) = self.tls_manager.as_ref() {
                let webtransport_state = state.clone();
                let tls_manager = Arc::clone(tls_manager);
                let webtransport_config = self.config.server.webtransport.clone();
                tokio::spawn(async move {
                    if let Err(e) = crate::proxy::webtransport::serve(
                        tls_manager,
                        webtransport_state,
                        webtransport_config,
                    )
                    .await
                    {
                        warn!("WebTransport listener not started: {}", e);
                    }
                });
            } else {
                warn!(
                    "WebTransport enabled but TLS is disabled; not starting WebTransport (QUIC requires TLS 1.3)"
                );
            }
        }

        #[cfg(not(feature = "webtransport"))]
        if self.config.server.webtransport.enabled {
            debug!("WebTransport requested but this binary was built without the `webtransport` feature");
        }

        // `server.max_connections` is enforced per listener. The process runs
        // one TCP listener, so this is effectively a process-wide TCP cap.
        let max_connections = self.config.server.max_connections.max(1);
        let connection_slots = Arc::new(Semaphore::new(max_connections));
        info!(
            "Ingress connection limit: {} concurrent TCP connections",
            max_connections
        );

        loop {
            let (tcp_stream, remote_addr) = match listener.accept().await {
                Ok(connection) => connection,
                Err(e) => {
                    // Accept errors are usually transient (EMFILE, aborted
                    // handshake). Log and keep serving instead of tearing down
                    // the listener.
                    warn!("Failed to accept connection: {}", e);
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    continue;
                }
            };

            let permit = match Arc::clone(&connection_slots).try_acquire_owned() {
                Ok(permit) => permit,
                Err(_) => {
                    // The connection was accepted (so it is not left in the
                    // backlog) but never admitted or counted as active.
                    self.metrics.record_connection_rejected();
                    warn!(
                        "Rejected connection from {}: server.max_connections ({}) reached",
                        remote_addr, max_connections
                    );
                    if self.tls_manager.is_none() {
                        tokio::spawn(reject_connection_over_limit(tcp_stream));
                    } else {
                        // A TLS peer cannot receive a meaningful HTTP response
                        // before the handshake; close promptly instead.
                        drop(tcp_stream);
                    }
                    continue;
                }
            };

            self.metrics.connection_started();
            let slot = ConnectionSlot {
                _permit: permit,
                metrics: Arc::clone(&self.metrics),
            };

            let tls_manager = self.tls_manager.clone();
            let state = state.clone();
            let peer_ip = remote_addr.ip();

            tokio::task::spawn(async move {
                let _slot = slot;
                if let Some(tls_mgr) = tls_manager {
                    match tls_mgr.accept(tcp_stream).await {
                        Ok(tls_stream) => {
                            // Only speak HTTP/2 when ALPN actually negotiated h2.
                            let negotiated_h2 =
                                tls_stream.get_ref().1.alpn_protocol() == Some(b"h2");
                            if let Err(e) = Self::handle_connection(
                                tls_stream,
                                state,
                                peer_ip,
                                true,
                                negotiated_h2,
                            )
                            .await
                            {
                                error!("TLS connection error from {}: {}", remote_addr, e);
                            }
                        }
                        Err(e) => {
                            error!("TLS handshake failed from {}: {}", remote_addr, e);
                        }
                    }
                } else if let Err(e) =
                    Self::handle_connection(tcp_stream, state, peer_ip, false, false).await
                {
                    error!("Connection error from {}: {}", remote_addr, e);
                }
            });
        }
    }

    async fn handle_connection<S>(
        mut stream: S,
        state: ProxyState,
        peer_ip: IpAddr,
        is_https: bool,
        negotiated_h2: bool,
    ) -> Result<(), WafError>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
    {
        // HTTP/2 over cleartext requires h2c negotiation/prior knowledge.
        // Plaintext listeners therefore speak HTTP/1.1; HTTP/2 is enabled only
        // when TLS ALPN negotiated h2.
        let enable_http2 = negotiated_h2 && state.config.server.enable_http2;
        let http2_tuning = state.config.server.http2.clone();
        let max_header_bytes = state.config.server.max_header_bytes;
        let max_header_count = state.config.server.max_header_count;
        // Bounds idle keep-alive: hyper starts this timer while waiting for
        // the next request head, so an idle client is closed rather than held
        // forever. It also bounds a slow request head.
        let keep_alive_timeout =
            Duration::from_secs(state.config.server.keep_alive_timeout_secs.max(1));
        let service =
            service_fn(move |req| Self::handle_request(req, state.clone(), peer_ip, is_https));

        if enable_http2 {
            let io = hyper_util::rt::TokioIo::new(stream);
            let tuning = &http2_tuning;
            let mut builder = hyper::server::conn::http2::Builder::new(TokioExecutor::new());
            builder.timer(TokioTimer::new());
            // Backstop above the explicit header-byte check so the pipeline
            // returns a generic 431 rather than an HPACK-level reset.
            let header_backstop = max_header_bytes
                .saturating_mul(2)
                .max(16 * 1024)
                .min(u32::MAX as usize) as u32;
            builder.max_header_list_size(header_backstop);
            if tuning.enabled {
                builder
                    .adaptive_window(tuning.adaptive_window)
                    .initial_stream_window_size(tuning.initial_stream_window_bytes)
                    .initial_connection_window_size(tuning.initial_connection_window_bytes)
                    .max_concurrent_streams(tuning.max_concurrent_streams)
                    .max_pending_accept_reset_streams(tuning.max_pending_accept_reset_streams)
                    .keep_alive_timeout(Duration::from_secs(tuning.keep_alive_timeout_secs.max(1)));
                builder.keep_alive_interval(if tuning.keep_alive_interval_secs > 0 {
                    Some(Duration::from_secs(tuning.keep_alive_interval_secs))
                } else {
                    None
                });
            } else {
                builder
                    .keep_alive_interval(Some(Duration::from_secs(30)))
                    .keep_alive_timeout(keep_alive_timeout);
            }
            builder
                .serve_connection(io, service)
                .await
                .map_err(|e| WafError::NetworkError(format!("HTTP/2 connection error: {}", e)))
        } else {
            // Validate the wire-level request head before hyper sees it. hyper
            // collapses duplicate identical Content-Length fields and removes
            // Content-Length when Transfer-Encoding is present, which makes
            // CL+TE and duplicate CL invisible to the service layer. The gate
            // rejects them (and absolute-form targets, whitespace before a
            // header colon, CONNECT/TRACE) with a fail-closed 400/405 before
            // any bytes are forwarded.
            let head = match read_request_head(
                &mut stream,
                max_header_bytes.saturating_add(8192).max(8192),
                keep_alive_timeout,
            )
            .await
            {
                Ok(head) => head,
                Err(error) => {
                    debug!("Rejected request head from {}: {}", peer_ip, error);
                    reject_request_head(&mut stream, error).await;
                    return Ok(());
                }
            };
            if let Err(error) = validate_request_head(&head) {
                warn!(
                    "Rejected wire-level request framing from {}: {}",
                    peer_ip, error
                );
                reject_request_head(&mut stream, error).await;
                return Ok(());
            }
            // Keep-alive stays on for every HTTP/1.x connection. The gate
            // validates each subsequent head on the wire (tracking the
            // validated body framing to find it), so a second pipelined or
            // keep-alive request cannot bypass the smuggling checks.
            let io = hyper_util::rt::TokioIo::new(
                match Http1RequestGate::new(
                    stream,
                    head,
                    max_header_bytes.saturating_add(8192).max(8192),
                ) {
                    Ok(gate) => gate,
                    Err(error) => {
                        warn!(
                            "Rejected wire-level request framing from {}: {}",
                            peer_ip, error
                        );
                        return Ok(());
                    }
                },
            );
            let mut builder = hyper::server::conn::http1::Builder::new();
            builder
                .keep_alive(true)
                .pipeline_flush(true)
                .timer(TokioTimer::new())
                .header_read_timeout(Some(keep_alive_timeout))
                // hyper backstops, deliberately looser than the explicit
                // pipeline checks so those return the generic 431.
                .max_headers(max_header_count.saturating_mul(2).max(100))
                .max_header_size(max_header_bytes.saturating_mul(2).max(8192))
                .max_buf_size(max_header_bytes.saturating_add(8192).max(8192));
            builder
                .serve_connection(io, service)
                .with_upgrades()
                .await
                .map_err(|e| WafError::NetworkError(format!("HTTP/1.1 connection error: {}", e)))
        }
    }

    /// Handle incoming HTTP requests with multi-protocol support
    async fn handle_request(
        mut req: Request<Incoming>,
        state: ProxyState,
        peer_ip: IpAddr,
        is_https: bool,
    ) -> Result<Response<ProxyBody>, Infallible> {
        let start_time = Instant::now();
        let telemetry = RequestTelemetry::begin(Arc::clone(&state.metrics));

        // Header bounds are the primary control; hyper's parser limits are a
        // backstop configured above these values. Details stay server-side.
        if let Err(violation) = enforce_header_bounds(req.headers(), &state.config.server) {
            warn!(
                "Rejected request head: {} limit exceeded ({:?})",
                violation.as_str(),
                violation
            );
            telemetry.reject(RequestRejection::HeaderLimit);
            state.metrics.record_blocked();
            return Ok(Self::create_error_response(
                StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
                "Request Header Fields Too Large",
            ));
        }

        // Detect HTTP protocol version
        let http_version = Self::detect_http_version(&req);
        debug!("Detected HTTP version: {}", http_version);

        // Check if HTTP version is supported
        if !Self::is_http_version_supported(http_version, &state.config) {
            warn!("Unsupported HTTP version: {}", http_version);
            telemetry.reject(RequestRejection::UnsupportedHttpVersion);
            state.metrics.record_blocked();
            return Ok(Self::create_error_response(
                StatusCode::HTTP_VERSION_NOT_SUPPORTED,
                &format!("HTTP version {} not supported", http_version),
            ));
        }

        let client_ip = Self::resolve_client_ip_with_metrics(
            peer_ip,
            req.headers(),
            &state.trusted_proxies,
            &state.metrics,
        );

        // Client-controlled routing/override headers are removed before the WAF
        // and the upstream see the request. Optional reject mode refuses them
        // outright instead. Identity headers used by trusted-proxy resolution
        // were consumed above and are rewritten by the proxy; they are never
        // rejected here.
        if state.config.proxy.reject_ambiguous_routing {
            if let Some(name) = state.strip_policy.first_ambiguous(req.headers()) {
                warn!(
                    "Rejected request from {} carrying ambiguous routing header '{}'",
                    client_ip, name
                );
                telemetry.reject(RequestRejection::AmbiguousRouting);
                state.metrics.record_blocked();
                return Ok(Self::create_error_response(
                    StatusCode::BAD_REQUEST,
                    "Ambiguous routing headers are not allowed",
                ));
            }
        }
        state.strip_policy.strip(req.headers_mut(), client_ip);

        // Reject ambiguous request framing before any body is read. HTTP/2 and
        // HTTP/3 additionally reject Transfer-Encoding and connection-specific
        // headers before the shared HTTP/1.x checks. Details are intentionally
        // not exposed to the client.
        let framing_version = FramingVersion::from_wire(http_version);
        if let Err(e) = validate_request_framing_for_version(req.headers(), framing_version) {
            warn!(
                "Rejected ambiguous request framing from {}: {}",
                client_ip, e
            );
            telemetry.reject(RequestRejection::InvalidFraming);
            state.metrics.record_blocked();
            return Ok(Self::create_error_response(
                StatusCode::BAD_REQUEST,
                "Bad Request",
            ));
        }

        // CONNECT is a tunnel request and TRACE reflects the request back at
        // the caller. Reject both before inspection so a rule-engine block
        // (which may use 403) cannot mask the documented 405, and so no
        // tunnel/upgrade path is ever considered for CONNECT.
        if req.method() == hyper::Method::CONNECT || req.method() == hyper::Method::TRACE {
            warn!(
                "Rejected unsupported method {} from {}",
                req.method(),
                client_ip
            );
            telemetry.reject(RequestRejection::MethodNotAllowed);
            state.metrics.record_blocked();
            return Ok(Self::create_error_response(
                StatusCode::METHOD_NOT_ALLOWED,
                "Method Not Allowed",
            ));
        }

        // Authentication is a first-class pipeline stage, not an unused module.
        if let Some(validator) = &state.auth_validator {
            match validator.validate_request_for_client(req.headers(), is_https, Some(client_ip)) {
                Ok(()) => {}
                Err(WafError::RateLimitError(e)) => {
                    warn!(
                        "Authentication rate limited request from {}: {}",
                        client_ip, e
                    );
                    telemetry.reject(RequestRejection::WafRateLimited);
                    state.metrics.record_auth_rate_limited();
                    state.metrics.record_rate_limited();
                    state.metrics.record_blocked();
                    return Ok(Self::create_rate_limit_response(&e));
                }
                Err(WafError::AuthFailureLimited(e)) => {
                    warn!(
                        "Authentication failure lockout for request from {}: {}",
                        client_ip, e
                    );
                    telemetry.reject(RequestRejection::WafRateLimited);
                    state.metrics.record_auth_failure_limited();
                    state.metrics.record_auth_failure();
                    state.metrics.record_rate_limited();
                    state.metrics.record_blocked();
                    return Ok(Self::create_rate_limit_response(&e));
                }
                Err(WafError::AuthExpiredKey) => {
                    warn!("Authentication rejected expired API key from {}", client_ip);
                    telemetry.reject(RequestRejection::Authentication);
                    state.metrics.record_auth_expired_key();
                    state.metrics.record_auth_failure();
                    state.metrics.record_blocked();
                    return Ok(Self::create_error_response(
                        StatusCode::UNAUTHORIZED,
                        "Unauthorized",
                    ));
                }
                Err(WafError::AuthMissingKey) => {
                    warn!(
                        "Authentication rejected request from {}: missing API key",
                        client_ip
                    );
                    telemetry.reject(RequestRejection::Authentication);
                    state.metrics.record_auth_missing_key();
                    state.metrics.record_auth_failure();
                    state.metrics.record_blocked();
                    return Ok(Self::create_error_response(
                        StatusCode::UNAUTHORIZED,
                        "Unauthorized",
                    ));
                }
                Err(WafError::AuthInvalidKey) => {
                    warn!("Authentication rejected invalid API key from {}", client_ip);
                    telemetry.reject(RequestRejection::Authentication);
                    state.metrics.record_auth_invalid_key();
                    state.metrics.record_auth_failure();
                    state.metrics.record_blocked();
                    return Ok(Self::create_error_response(
                        StatusCode::UNAUTHORIZED,
                        "Unauthorized",
                    ));
                }
                Err(e) => {
                    warn!("Authentication rejected request from {}: {}", client_ip, e);
                    telemetry.reject(RequestRejection::Authentication);
                    state.metrics.record_auth_failure();
                    state.metrics.record_blocked();
                    return Ok(Self::create_error_response(
                        StatusCode::UNAUTHORIZED,
                        "Unauthorized",
                    ));
                }
            }
        }

        // Proxy WebSocket upgrades end-to-end over a raw upstream connection.
        if WebSocketHandler::is_websocket_upgrade(req.headers()) {
            if req.version() != hyper::Version::HTTP_11 {
                telemetry.reject(RequestRejection::WebSocketVersion);
                state.metrics.record_blocked();
                return Ok(Self::create_error_response(
                    StatusCode::NOT_IMPLEMENTED,
                    "WebSocket upgrades require HTTP/1.1",
                ));
            }
            if req.method() != hyper::Method::GET {
                telemetry.reject(RequestRejection::WebSocketVersion);
                state.metrics.record_blocked();
                return Ok(Self::create_error_response(
                    StatusCode::BAD_REQUEST,
                    "WebSocket upgrades require GET",
                ));
            }
            if websocket_upgrade_has_body(req.headers()) {
                warn!(
                    "Rejected WebSocket upgrade from {} carrying a request body",
                    client_ip
                );
                telemetry.reject(RequestRejection::InvalidFraming);
                state.metrics.record_blocked();
                return Ok(Self::create_error_response(
                    StatusCode::BAD_REQUEST,
                    "WebSocket upgrades must not carry a body",
                ));
            }
            if let Err(reason) = WebSocketHandler::validate_websocket_handshake(req.headers()) {
                warn!(
                    "Rejected invalid WebSocket handshake from {}: {}",
                    client_ip, reason
                );
                telemetry.reject(RequestRejection::WebSocketVersion);
                state.metrics.record_blocked();
                return Ok(Self::create_error_response(StatusCode::BAD_REQUEST, reason));
            }

            // The upgrade request must pass the WAF before any tunneling.
            let upgrade_context = RequestContext::with_http_version(
                client_ip,
                req.method().clone(),
                req.uri().clone(),
                req.headers().clone(),
                None,
                http_version,
            );
            match state.waf_engine.evaluate_shared(&upgrade_context).await {
                Decision::Allow => {}
                Decision::Block { status, reason } => {
                    warn!(
                        "WAF blocked WebSocket upgrade from {}: {} (status: {})",
                        client_ip, reason, status
                    );
                    telemetry.reject(RequestRejection::WafBlocked);
                    state.metrics.record_blocked();
                    return Ok(Self::create_blocked_response(status, &reason));
                }
                Decision::RateLimit { reason } => {
                    warn!(
                        "WAF rate limited WebSocket upgrade from {}: {}",
                        client_ip, reason
                    );
                    telemetry.reject(RequestRejection::WafRateLimited);
                    state.metrics.record_rate_limited();
                    state.metrics.record_blocked();
                    return Ok(Self::create_rate_limit_response(&reason));
                }
            }

            let tunnel_guard = match state.websocket_limiter.try_acquire() {
                Some(guard) => guard,
                None => {
                    warn!(
                        "Rejected WebSocket upgrade from {}: server.websocket.max_concurrent_tunnels ({}) reached",
                        client_ip,
                        state.websocket_limiter.limit()
                    );
                    telemetry.reject(RequestRejection::WebSocketTunnelLimit);
                    state.metrics.record_websocket_tunnel_rejected();
                    state.metrics.record_blocked();
                    let mut response = Self::create_error_response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "WebSocket tunnel limit reached",
                    );
                    response
                        .headers_mut()
                        .insert("retry-after", HeaderValue::from_static("1"));
                    return Ok(response);
                }
            };

            return Ok(Self::proxy_websocket(req, &state, client_ip, tunnel_guard).await);
        }
        #[cfg(feature = "webtransport")]
        if is_webtransport_upgrade(req.headers()) {
            warn!("WebTransport request rejected: not implemented");
            telemetry.reject(RequestRejection::WebTransportUnsupported);
            state.metrics.record_blocked();
            return Ok(Self::create_error_response(
                StatusCode::NOT_IMPLEMENTED,
                "WebTransport is not implemented",
            ));
        }

        let classification = classify_request(req.headers());

        // Compiled bodyless allowlist. This runs before `into_parts` and before
        // any `RequestContext` is built, so an allowlisted route pays no
        // HeaderMap clone, version string, admission, pre-check, inspection,
        // rule dispatch or audit-event construction. A query, body, framing
        // header, content encoding, upgrade, gRPC/GraphQL content type or
        // streaming gRPC request never matches and falls through unchanged.
        if !classification.is_grpc {
            if let Some(outcome) = state.waf_engine.fast_allow(
                req.method(),
                req.uri(),
                req.headers(),
                client_ip,
                None,
                req.body().is_end_stream(),
            ) {
                match &outcome.decision {
                    Decision::Allow => {
                        let (parts, _body) = req.into_parts();
                        let fast_ctx = state.config.waf.response_inspection.enabled.then(|| {
                            RequestContext::with_http_version(
                                client_ip,
                                parts.method.clone(),
                                parts.uri.clone(),
                                parts.headers.clone(),
                                None,
                                http_version,
                            )
                        });
                        let response_inspection =
                            fast_ctx.as_ref().map(|request| ResponseInspectionRequest {
                                request,
                                config: &state.config.waf.response_inspection,
                            });
                        state.metrics.record_allowed();
                        return Self::forward_to_upstream_with_protocol(
                            parts,
                            ProxyBody::buffered(Bytes::new(), None),
                            state.upstream_client,
                            state.upstream_uri,
                            start_time,
                            http_version,
                            &state.waf_engine,
                            &state.metrics,
                            client_ip,
                            is_https,
                            Duration::from_secs(state.config.proxy.timeout_seconds.max(1)),
                            state.config.server.max_body_size,
                            state
                                .config
                                .proxy
                                .streaming
                                .enabled
                                .then_some(state.config.proxy.streaming.response_threshold_bytes),
                            &state.strip_policy,
                            response_inspection,
                        )
                        .await;
                    }
                    Decision::Block { status, reason } => {
                        state
                            .waf_engine
                            .audit_fast_decision(
                                client_ip,
                                req.method(),
                                req.uri(),
                                req.headers(),
                                http_version,
                                &outcome.decision,
                                outcome.triggered_rules,
                            )
                            .await;
                        warn!(
                            "WAF fast-allow gate blocked request from {}: {} (status: {})",
                            client_ip, reason, status
                        );
                        telemetry.reject(RequestRejection::FastAllowBlocked);
                        state.metrics.record_blocked();
                        return Ok(Self::create_blocked_response(*status, reason));
                    }
                    Decision::RateLimit { reason } => {
                        state
                            .waf_engine
                            .audit_fast_decision(
                                client_ip,
                                req.method(),
                                req.uri(),
                                req.headers(),
                                http_version,
                                &outcome.decision,
                                outcome.triggered_rules,
                            )
                            .await;
                        warn!(
                            "WAF fast-allow gate rate limited request from {}: {}",
                            client_ip, reason
                        );
                        telemetry.reject(RequestRejection::FastAllowRateLimited);
                        state.metrics.record_rate_limited();
                        state.metrics.record_blocked();
                        return Ok(Self::create_rate_limit_response(reason));
                    }
                }
            }
        }

        let (mut parts, body) = req.into_parts();
        let has_content_encoding = parts.headers.contains_key(hyper::header::CONTENT_ENCODING);
        let size_hint = parts
            .headers
            .get(hyper::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<usize>().ok());
        let max_body_size = state.config.effective_max_request_body();
        let mut body = Some(body);
        let mut pre_read: Option<(Bytes, Option<HeaderMap>)> = None;

        // gRPC is classified from its actual frame sequence, never from the
        // presence of `content-length`. HTTP/2 unary RPCs commonly omit it.
        // gRPC-Web keeps the buffered path because its text framing is base64.
        if classification.is_grpc && !classification.is_grpc_web {
            let mut incoming = body.take().expect("request body");

            // `transport-only` is an explicit opt-out from rejecting genuine
            // streams. It is not an opt-out from inspection: every complete
            // message is inspected incrementally before it is forwarded. The
            // default policy is `reject`, which classifies the body first.
            if state.config.server.grpc_streaming_policy == GrpcStreamingPolicy::TransportOnly {
                return Ok(Self::handle_grpc_stream(
                    parts,
                    incoming,
                    Bytes::new(),
                    &state,
                    start_time,
                    http_version,
                    client_ip,
                    is_https,
                    &telemetry,
                )
                .await);
            }

            match probe_grpc_body(&mut incoming, max_body_size).await {
                Ok(probe) => match probe.mode {
                    GrpcBodyMode::Unary => {
                        pre_read = Some((probe.prefix, probe.trailers));
                    }
                    GrpcBodyMode::Streaming => {
                        return Ok(Self::handle_grpc_stream(
                            parts,
                            incoming,
                            probe.prefix,
                            &state,
                            start_time,
                            http_version,
                            client_ip,
                            is_https,
                            &telemetry,
                        )
                        .await);
                    }
                },
                Err(error) => {
                    let status = match error {
                        GrpcProbeError::TooLarge { .. } => StatusCode::PAYLOAD_TOO_LARGE,
                        _ => StatusCode::BAD_REQUEST,
                    };
                    warn!(
                        "Rejecting malformed gRPC request from {}: {}",
                        client_ip, error
                    );
                    telemetry.reject(RequestRejection::InvalidFraming);
                    state.metrics.record_blocked();
                    state.metrics.record_request_duration(start_time.elapsed());
                    if state.config.server.grpc_aware_rejections {
                        return Ok(Self::create_grpc_blocked_response(
                            status.as_u16(),
                            &error.to_string(),
                        ));
                    }
                    return Ok(Self::create_error_response(status, &error.to_string()));
                }
            }
        }

        let (body_bytes, request_trailers) = if let Some(pre_read) = pre_read {
            pre_read
        } else {
            let incoming = body.take().expect("request body");
            match tokio::time::timeout(
                Duration::from_secs(state.config.server.request_timeout_secs.max(1)),
                state.buffer_pool.read_incoming_body_bytes(
                    incoming,
                    size_hint,
                    Some(max_body_size),
                ),
            )
            .await
            {
                Ok(Ok((bytes, trailers))) => (bytes, trailers),
                Ok(Err(BodyReadError::TooLarge { .. })) => {
                    warn!(
                        "Request body from {} exceeds limit {}",
                        client_ip, max_body_size
                    );
                    telemetry.reject(RequestRejection::BodyTooLarge);
                    state.metrics.record_blocked();
                    state.metrics.record_request_duration(start_time.elapsed());
                    return Ok(Self::create_error_response(
                        StatusCode::PAYLOAD_TOO_LARGE,
                        "Request body too large",
                    ));
                }
                Ok(Err(e)) => {
                    warn!("Failed to read request body from {}: {}", client_ip, e);
                    telemetry.reject(RequestRejection::BodyReadError);
                    state.metrics.record_blocked();
                    state.metrics.record_request_duration(start_time.elapsed());
                    return Ok(Self::create_error_response(
                        StatusCode::BAD_REQUEST,
                        "Failed to read request body",
                    ));
                }
                Err(_) => {
                    warn!("Request body read timed out for {}", client_ip);
                    telemetry.reject(RequestRejection::BodyTimeout);
                    state.metrics.record_blocked();
                    state.metrics.record_request_duration(start_time.elapsed());
                    return Ok(Self::create_error_response(
                        StatusCode::REQUEST_TIMEOUT,
                        "Request body timeout",
                    ));
                }
            }
        };

        // Trailers arrive after the body. Framing and connection metadata in a
        // trailer block is always illegal and is rejected before forwarding.
        if let Some(trailers) = request_trailers.as_ref() {
            if let Err(e) = validate_request_trailers(trailers) {
                warn!("Rejected request trailer from {}: {}", client_ip, e);
                telemetry.reject(RequestRejection::InvalidTrailerFraming);
                state.metrics.record_blocked();
                return Ok(Self::create_error_response(
                    StatusCode::BAD_REQUEST,
                    "Bad Request",
                ));
            }
        }

        // HTTP/2 and HTTP/3 do not enforce that DATA length matches the
        // declared Content-Length. Reconcile before decompression (the header
        // describes the encoded body) so the WAF and upstream see the same
        // bytes. An absent Content-Length is valid on both versions.
        if let Err(e) = reconcile_content_length(&parts.headers, body_bytes.len()) {
            warn!(
                "Rejected request from {} with mismatched Content-Length: {}",
                client_ip, e
            );
            telemetry.reject(RequestRejection::InvalidFraming);
            state.metrics.record_blocked();
            return Ok(Self::create_error_response(
                StatusCode::BAD_REQUEST,
                "Bad Request",
            ));
        }

        let body_bytes = if has_content_encoding {
            match decompress_request_body(&parts.headers, body_bytes, max_body_size) {
                Ok(decoded) => {
                    strip_encoding_headers(&mut parts.headers);
                    decoded
                }
                Err(DecompressionError::UnsupportedEncoding(encoding)) => {
                    warn!(
                        "Rejecting unsupported request encoding from {} (Content-Encoding: {})",
                        client_ip, encoding
                    );
                    telemetry.reject(RequestRejection::UnsupportedContentEncoding);
                    state.metrics.record_blocked();
                    return Ok(Self::create_error_response(
                        StatusCode::UNSUPPORTED_MEDIA_TYPE,
                        "Unsupported request Content-Encoding",
                    ));
                }
                Err(DecompressionError::TooLarge) => {
                    warn!(
                        "Decompressed request body from {} exceeds limit {}",
                        client_ip, max_body_size
                    );
                    telemetry.reject(RequestRejection::DecompressedTooLarge);
                    state.metrics.record_blocked();
                    return Ok(Self::create_error_response(
                        StatusCode::PAYLOAD_TOO_LARGE,
                        "Decompressed request body too large",
                    ));
                }
                Err(DecompressionError::Malformed) => {
                    warn!("Malformed compressed request body from {}", client_ip);
                    telemetry.reject(RequestRejection::MalformedCompression);
                    state.metrics.record_blocked();
                    return Ok(Self::create_error_response(
                        StatusCode::BAD_REQUEST,
                        "Malformed compressed request body",
                    ));
                }
            }
        } else {
            body_bytes
        };

        // Full evaluation includes body inspection, WASM/AI stages and audit
        // logging. The previous fast path silently skipped all of these.
        //
        // Move the request head into the context instead of cloning it, then
        // move it back for the upstream forward. This removes a `HeaderMap`
        // clone (and its per-header allocations) from every request.
        let method = std::mem::replace(&mut parts.method, hyper::Method::GET);
        let uri = std::mem::replace(&mut parts.uri, Uri::from_static("/"));
        let headers = std::mem::take(&mut parts.headers);
        let request_context = RequestContext::with_http_version(
            client_ip,
            method,
            uri,
            headers,
            Some(body_bytes.len()),
            http_version,
        )
        .with_body(Some(body_bytes.clone()));

        let audit_outcome = state
            .waf_engine
            .evaluate_shared_deferred(&request_context)
            .await;
        let inspection_ms = start_time.elapsed().as_millis() as u64;

        match audit_outcome.decision.clone() {
            Decision::Allow => {
                debug!(
                    "WAF allowed request from {}, forwarding with HTTP/{}",
                    client_ip, http_version
                );
                state.metrics.record_allowed();

                // Allowed events are filtered at the default `medium` level;
                // only clone the context when the record would actually be
                // written, after the final upstream status is known.
                let audit_context = state
                    .waf_engine
                    .logs_allowed_requests()
                    .then(|| request_context.clone());

                parts.method = request_context.method;
                parts.uri = request_context.uri;
                parts.headers = request_context.headers;

                let response_ctx = state.config.waf.response_inspection.enabled.then(|| {
                    RequestContext::with_http_version(
                        client_ip,
                        parts.method.clone(),
                        parts.uri.clone(),
                        parts.headers.clone(),
                        request_context.body_size,
                        http_version,
                    )
                });
                let response_inspection =
                    response_ctx
                        .as_ref()
                        .map(|request| ResponseInspectionRequest {
                            request,
                            config: &state.config.waf.response_inspection,
                        });
                let response = Self::forward_to_upstream_with_protocol(
                    parts,
                    ProxyBody::buffered(body_bytes, request_trailers),
                    state.upstream_client,
                    state.upstream_uri,
                    start_time,
                    http_version,
                    &state.waf_engine,
                    &state.metrics,
                    client_ip,
                    is_https,
                    Duration::from_secs(state.config.proxy.timeout_seconds.max(1)),
                    state.config.server.max_body_size,
                    state
                        .config
                        .proxy
                        .streaming
                        .enabled
                        .then_some(state.config.proxy.streaming.response_threshold_bytes),
                    &state.strip_policy,
                    response_inspection,
                )
                .await?;

                if let Some(context) = audit_context {
                    let total_ms = start_time.elapsed().as_millis() as u64;
                    state
                        .waf_engine
                        .audit_outcome(
                            &context,
                            &audit_outcome,
                            EventDetails {
                                response_status: Some(response.status().as_u16()),
                                inspection_duration_ms: Some(inspection_ms),
                                upstream_duration_ms: Some(total_ms.saturating_sub(inspection_ms)),
                                total_duration_ms: Some(total_ms),
                                ..EventDetails::default()
                            },
                        )
                        .await;
                }

                Ok(response)
            }
            Decision::Block { status, reason } => {
                warn!(
                    "WAF blocked request from {}: {} (status: {})",
                    client_ip, reason, status
                );
                telemetry.reject(RequestRejection::WafBlocked);
                state.metrics.record_blocked();
                let response =
                    if classification.is_grpc && state.config.server.grpc_aware_rejections {
                        Self::create_grpc_blocked_response(status, &reason)
                    } else {
                        Self::create_blocked_response(status, &reason)
                    };
                let total_ms = start_time.elapsed().as_millis() as u64;
                state
                    .waf_engine
                    .audit_outcome(
                        &request_context,
                        &audit_outcome,
                        EventDetails {
                            response_status: Some(response.status().as_u16()),
                            inspection_duration_ms: Some(inspection_ms),
                            total_duration_ms: Some(total_ms),
                            ..EventDetails::default()
                        },
                    )
                    .await;
                Ok(response)
            }
            Decision::RateLimit { reason } => {
                warn!("WAF rate limited request from {}: {}", client_ip, reason);
                telemetry.reject(RequestRejection::WafRateLimited);
                state.metrics.record_rate_limited();
                state.metrics.record_blocked();
                let response = Self::create_rate_limit_response(&reason);
                let total_ms = start_time.elapsed().as_millis() as u64;
                state
                    .waf_engine
                    .audit_outcome(
                        &request_context,
                        &audit_outcome,
                        EventDetails {
                            response_status: Some(response.status().as_u16()),
                            inspection_duration_ms: Some(inspection_ms),
                            total_duration_ms: Some(total_ms),
                            ..EventDetails::default()
                        },
                    )
                    .await;
                Ok(response)
            }
        }
    }

    /// Proxy a WebSocket upgrade to the configured upstream over a raw TCP
    /// connection, then splice the two upgraded byte streams together.
    async fn proxy_websocket(
        mut req: Request<Incoming>,
        state: &ProxyState,
        client_ip: IpAddr,
        tunnel_guard: crate::proxy::websocket::WebSocketTunnelGuard,
    ) -> Response<ProxyBody> {
        if state.config.waf.response_inspection.enabled {
            // WebSocket frames are not an HTTP response body; response
            // inspection does not apply to the upgraded tunnel.
            state.metrics.record_response_skipped_unsupported();
        }
        let upstream = &state.upstream_uri;
        let (use_tls, port) = match websocket_upstream_transport(upstream) {
            Ok(transport) => transport,
            Err(()) => {
                return Self::create_error_response(
                    StatusCode::BAD_GATEWAY,
                    "WebSocket upstream must use http:// or https://",
                )
            }
        };
        let host = match upstream.host() {
            Some(host) => host,
            None => {
                return Self::create_error_response(
                    StatusCode::BAD_GATEWAY,
                    "Invalid WebSocket upstream host",
                )
            }
        };
        let default_port = if use_tls { 443 } else { 80 };
        let path = req
            .uri()
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/");
        let client_host = req
            .headers()
            .get(hyper::header::HOST)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .to_string();
        let upstream_host = if port == default_port {
            host.to_string()
        } else {
            format!("{}:{}", host, port)
        };

        let connection_nominated = connection_nominated_headers(req.headers());
        let mut headers = String::new();
        for (name, value) in req.headers() {
            let lower = name.as_str().to_ascii_lowercase();
            if state.strip_policy.should_strip(lower.as_str()) {
                debug!(
                    "Stripped client-supplied routing header '{}' from WebSocket upgrade from {}",
                    lower, client_ip
                );
                continue;
            }
            if matches!(
                lower.as_str(),
                "host"
                    | "connection"
                    | "upgrade"
                    | "proxy-connection"
                    | "keep-alive"
                    | "transfer-encoding"
                    | "content-length"
                    | "content-encoding"
                    | "te"
                    | "trailer"
                    | "sec-websocket-accept"
                    | "sec-websocket-extensions"
                    | "x-forwarded-host"
                    | "x-forwarded-for"
                    | "x-real-ip"
                    | "x-forwarded-proto"
            ) || connection_nominated
                .iter()
                .any(|nominated| nominated == &lower)
            {
                continue;
            }
            if let Ok(value) = value.to_str() {
                headers.push_str(&format!("{}: {}\r\n", name.as_str(), value));
            }
        }

        let handshake = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nX-Forwarded-Host: {}\r\nX-Forwarded-For: {}\r\nX-Real-IP: {}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n{}\r\n",
            path, upstream_host, client_host, client_ip, client_ip, headers
        );

        const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
        let tcp_stream =
            match tokio::time::timeout(HANDSHAKE_TIMEOUT, TcpStream::connect((host, port))).await {
                Ok(Ok(stream)) => stream,
                Ok(Err(e)) => {
                    error!("WebSocket upstream connect failed: {}", e);
                    state.metrics.record_upstream_error();
                    return Self::create_error_response(
                        StatusCode::BAD_GATEWAY,
                        "WebSocket upstream unavailable",
                    );
                }
                Err(_) => {
                    state.metrics.record_upstream_error();
                    return Self::create_error_response(
                        StatusCode::GATEWAY_TIMEOUT,
                        "WebSocket upstream connect timed out",
                    );
                }
            };

        let mut upstream_stream: Box<dyn AsyncStream> = if use_tls {
            let mut roots = RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            if let Some(ca_path) = state.config.proxy.upstream_ca_path.as_deref() {
                let ca_pem = match tokio::fs::read(ca_path).await {
                    Ok(pem) => pem,
                    Err(e) => {
                        error!(
                            "Failed to read WebSocket upstream CA bundle '{}': {}",
                            ca_path, e
                        );
                        state.metrics.record_upstream_error();
                        return Self::create_error_response(
                            StatusCode::BAD_GATEWAY,
                            "WebSocket upstream CA bundle unavailable",
                        );
                    }
                };
                let mut loaded = 0usize;
                for cert in CertificateDer::pem_slice_iter(&ca_pem) {
                    match cert {
                        Ok(cert) => match roots.add(cert) {
                            Ok(()) => loaded += 1,
                            Err(e) => {
                                error!(
                                    "Invalid certificate in WebSocket upstream CA bundle '{}': {}",
                                    ca_path, e
                                );
                                state.metrics.record_upstream_error();
                                return Self::create_error_response(
                                    StatusCode::BAD_GATEWAY,
                                    "Invalid WebSocket upstream CA bundle",
                                );
                            }
                        },
                        Err(e) => {
                            error!(
                                "Failed to parse WebSocket upstream CA bundle '{}': {}",
                                ca_path, e
                            );
                            state.metrics.record_upstream_error();
                            return Self::create_error_response(
                                StatusCode::BAD_GATEWAY,
                                "Invalid WebSocket upstream CA bundle",
                            );
                        }
                    }
                }
                if loaded == 0 {
                    error!(
                        "WebSocket upstream CA bundle '{}' contains no certificates",
                        ca_path
                    );
                    state.metrics.record_upstream_error();
                    return Self::create_error_response(
                        StatusCode::BAD_GATEWAY,
                        "Invalid WebSocket upstream CA bundle",
                    );
                }
            }
            // Select the ring provider explicitly: both ring and aws-lc-rs are
            // enabled in this crate, so the implicit default is ambiguous.
            let config = ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .expect("ring provider supports the default TLS protocol versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
            let server_name = match ServerName::try_from(host.to_string()) {
                Ok(name) => name,
                Err(e) => {
                    error!("Invalid WebSocket upstream TLS server name: {}", e);
                    state.metrics.record_upstream_error();
                    return Self::create_error_response(
                        StatusCode::BAD_GATEWAY,
                        "Invalid WebSocket upstream host",
                    );
                }
            };
            let connector = TlsConnector::from(Arc::new(config));
            match tokio::time::timeout(
                HANDSHAKE_TIMEOUT,
                connector.connect(server_name, tcp_stream),
            )
            .await
            {
                Ok(Ok(stream)) => Box::new(stream),
                Ok(Err(e)) => {
                    error!("WebSocket upstream TLS handshake failed: {}", e);
                    state.metrics.record_upstream_error();
                    return Self::create_error_response(
                        StatusCode::BAD_GATEWAY,
                        "WebSocket upstream TLS handshake failed",
                    );
                }
                Err(_) => {
                    state.metrics.record_upstream_error();
                    return Self::create_error_response(
                        StatusCode::GATEWAY_TIMEOUT,
                        "WebSocket upstream TLS handshake timed out",
                    );
                }
            }
        } else {
            Box::new(tcp_stream)
        };

        if let Err(e) = upstream_stream.write_all(handshake.as_bytes()).await {
            error!("WebSocket upstream handshake write failed: {}", e);
            state.metrics.record_upstream_error();
            return Self::create_error_response(
                StatusCode::BAD_GATEWAY,
                "WebSocket upstream handshake failed",
            );
        }

        // Read the upstream handshake response headers only.
        let mut buffer = Vec::with_capacity(2048);
        let mut chunk = [0u8; 1024];
        let header_end = loop {
            if let Some(pos) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
                break pos + 4;
            }
            if buffer.len() > 16 * 1024 {
                return Self::create_error_response(
                    StatusCode::BAD_GATEWAY,
                    "WebSocket upstream handshake too large",
                );
            }
            match tokio::time::timeout(HANDSHAKE_TIMEOUT, upstream_stream.read(&mut chunk)).await {
                Ok(Ok(0)) => {
                    return Self::create_error_response(
                        StatusCode::BAD_GATEWAY,
                        "WebSocket upstream closed during handshake",
                    )
                }
                Ok(Ok(n)) => buffer.extend_from_slice(&chunk[..n]),
                Ok(Err(e)) => {
                    error!("WebSocket upstream handshake read failed: {}", e);
                    state.metrics.record_upstream_error();
                    return Self::create_error_response(
                        StatusCode::BAD_GATEWAY,
                        "WebSocket upstream handshake failed",
                    );
                }
                Err(_) => {
                    state.metrics.record_upstream_error();
                    return Self::create_error_response(
                        StatusCode::GATEWAY_TIMEOUT,
                        "WebSocket upstream handshake timed out",
                    );
                }
            }
        };

        let head = String::from_utf8_lossy(&buffer[..header_end]);
        let (status, upstream_headers) = match parse_websocket_handshake_head(&head) {
            Ok(parsed) => parsed,
            Err(e) => {
                warn!("Malformed WebSocket upstream handshake response: {}", e);
                state.metrics.record_upstream_error();
                return Self::create_error_response(
                    StatusCode::BAD_GATEWAY,
                    "WebSocket upstream handshake response was malformed",
                );
            }
        };
        if status != 101 {
            warn!("WebSocket upstream rejected upgrade with status {}", status);
            return Self::create_error_response(
                StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY),
                "WebSocket upstream rejected upgrade",
            );
        }

        let mut builder = Response::builder()
            .status(StatusCode::SWITCHING_PROTOCOLS)
            .version(hyper::Version::HTTP_11);
        for (name, value) in upstream_headers.iter() {
            // The proxy's tungstenite codec never negotiates extensions (no
            // permessage-deflate). Forwarding an origin acceptance would make
            // the client compress frames the proxy cannot decode, silently
            // disabling inspection. Strip it on the response direction too.
            if name
                .as_str()
                .eq_ignore_ascii_case("sec-websocket-extensions")
            {
                continue;
            }
            builder = builder.header(name.clone(), value.clone());
        }
        builder = builder
            .header("connection", "upgrade")
            .header("upgrade", "websocket");

        let on_upgrade = hyper::upgrade::on(&mut req);
        let metrics = Arc::clone(&state.metrics);
        let waf_engine = Arc::clone(&state.waf_engine);
        let base_context = RequestContext::with_http_version(
            client_ip,
            req.method().clone(),
            req.uri().clone(),
            req.headers().clone(),
            None,
            "1.1".to_string(),
        );
        let leftover = buffer[header_end..].to_vec();
        let max_message_bytes = state
            .config
            .server
            .websocket
            .resolved_max_message_bytes(state.config.server.max_body_size);
        let codec_config = websocket_codec_config(&state.config.server);
        let idle_timeout = (state.config.server.websocket.idle_timeout_secs > 0)
            .then(|| Duration::from_secs(state.config.server.websocket.idle_timeout_secs));
        let max_lifetime =
            Duration::from_secs(state.config.server.websocket.max_lifetime_secs.max(1));
        let inspect_responses = state.config.server.websocket.inspect_responses;
        tokio::spawn(async move {
            let _tunnel_guard = tunnel_guard;
            let upgraded = match on_upgrade.await {
                Ok(upgraded) => upgraded,
                Err(e) => {
                    metrics.record_upstream_error();
                    warn!("WebSocket client upgrade failed: {}", e);
                    return;
                }
            };

            let client_io = hyper_util::rt::TokioIo::new(upgraded);
            let client_ws =
                WebSocketStream::from_raw_socket(client_io, Role::Server, Some(codec_config)).await;
            let upstream_io = PrefixedIo::new(leftover, upstream_stream);
            let upstream_ws =
                WebSocketStream::from_raw_socket(upstream_io, Role::Client, Some(codec_config))
                    .await;

            Self::bridge_websocket(
                client_ws,
                upstream_ws,
                waf_engine,
                base_context,
                max_message_bytes,
                idle_timeout,
                max_lifetime,
                metrics,
                inspect_responses,
            )
            .await;
        });

        info!(
            "WebSocket tunnel established from {} to {}:{}",
            client_ip, host, port
        );
        builder
            .body(ProxyBody::full(Bytes::new()))
            .unwrap_or_else(|_| Self::create_error_response(StatusCode::BAD_GATEWAY, "Handshake"))
    }

    /// Bridge two WebSocket streams, evaluating data frames through the WAF
    /// before forwarding them. Control frames are validated against RFC 6455
    /// bounds before either side sees them. When `inspect_responses` is set,
    /// upstream-to-client data frames are inspected with the same bounded
    /// buffer and rate-limit budget as the request direction.
    #[allow(clippy::too_many_arguments)]
    async fn bridge_websocket<C, U>(
        mut client: WebSocketStream<C>,
        mut upstream: WebSocketStream<U>,
        waf_engine: Arc<WafEngine>,
        base_context: RequestContext,
        max_message_bytes: usize,
        idle_timeout: Option<Duration>,
        max_lifetime: Duration,
        metrics: Arc<Metrics>,
        inspect_responses: bool,
    ) where
        C: AsyncRead + AsyncWrite + Unpin,
        U: AsyncRead + AsyncWrite + Unpin,
    {
        let lifetime_deadline = tokio::time::Instant::now() + max_lifetime;
        let mut last_activity = tokio::time::Instant::now();

        loop {
            let idle_deadline = idle_timeout.map(|idle| last_activity + idle);
            let idle = async {
                match idle_deadline {
                    Some(deadline) => tokio::time::sleep_until(deadline).await,
                    None => std::future::pending::<()>().await,
                }
            };

            tokio::select! {
                _ = tokio::time::sleep_until(lifetime_deadline) => {
                    warn!(
                        "Closing WebSocket tunnel for {} at the {}s lifetime cap",
                        base_context.client_ip,
                        max_lifetime.as_secs()
                    );
                    metrics.record_websocket_tunnel_lifetime_closed();
                    let close = CloseFrame {
                        code: CloseCode::Policy,
                        reason: "WebSocket tunnel lifetime exceeded".into(),
                    };
                    let _ = client.send(Message::Close(Some(close.clone()))).await;
                    let _ = upstream.send(Message::Close(Some(close))).await;
                    break;
                }
                _ = idle => {
                    warn!(
                        "Closing idle WebSocket tunnel for {} after {}s",
                        base_context.client_ip,
                        idle_timeout.map(|d| d.as_secs()).unwrap_or_default()
                    );
                    metrics.record_websocket_tunnel_idle_closed();
                    let close = CloseFrame {
                        code: CloseCode::Away,
                        reason: "WebSocket tunnel idle timeout".into(),
                    };
                    let _ = client.send(Message::Close(Some(close.clone()))).await;
                    let _ = upstream.send(Message::Close(Some(close))).await;
                    break;
                }
                incoming = client.next() => {
                    last_activity = tokio::time::Instant::now();
                    match incoming {
                        Some(Ok(message)) => {
                            if let Some(close) = Self::websocket_control_violation(&message) {
                                warn!(
                                    "WebSocket protocol violation from {}",
                                    base_context.client_ip
                                );
                                let _ = client.send(Message::Close(Some(close.clone()))).await;
                                let _ = upstream.send(Message::Close(Some(close))).await;
                                break;
                            }
                            match &message {
                                Message::Ping(data) => {
                                    if client.send(Message::Pong(data.clone())).await.is_err() {
                                        break;
                                    }
                                    continue;
                                }
                                Message::Pong(_) => continue,
                                Message::Close(frame) => {
                                    let frame = frame.clone();
                                    let _ = upstream.send(Message::Close(frame.clone())).await;
                                    let _ = client.send(Message::Close(frame)).await;
                                    break;
                                }
                                Message::Frame(_) => continue,
                                _ => {}
                            }
                            if Self::websocket_message_blocked(
                                &waf_engine,
                                &base_context,
                                &message,
                                max_message_bytes,
                            )
                            .await
                            {
                                let _ = client.send(Message::Close(None)).await;
                                let _ = upstream.send(Message::Close(None)).await;
                                break;
                            }
                            if upstream.send(message).await.is_err() {
                                break;
                            }
                        }
                        Some(Err(e)) => {
                            // The parser rejects an oversized frame, a
                            // fragmented/oversized control frame, or a
                            // message that exceeds the cap before forwarding.
                            // Close both sides rather than forwarding.
                            if let Some(close) = Self::websocket_error_close(&e) {
                                warn!(
                                    "WebSocket client {} violated the protocol: {}",
                                    base_context.client_ip, e
                                );
                                let _ = client.send(Message::Close(Some(close.clone()))).await;
                                let _ = upstream.send(Message::Close(Some(close))).await;
                            } else {
                                debug!("WebSocket client stream error: {}", e);
                            }
                            break;
                        }
                        None => break,
                    }
                }
                incoming = upstream.next() => {
                    last_activity = tokio::time::Instant::now();
                    match incoming {
                        Some(Ok(message)) => {
                            if let Some(close) = Self::websocket_control_violation(&message) {
                                warn!(
                                    "WebSocket protocol violation from upstream for {}",
                                    base_context.client_ip
                                );
                                let _ = client.send(Message::Close(Some(close.clone()))).await;
                                let _ = upstream.send(Message::Close(Some(close))).await;
                                break;
                            }
                            match &message {
                                Message::Ping(data) => {
                                    if upstream.send(Message::Pong(data.clone())).await.is_err() {
                                        break;
                                    }
                                    continue;
                                }
                                Message::Pong(_) => continue,
                                Message::Close(frame) => {
                                    let frame = frame.clone();
                                    let _ = client.send(Message::Close(frame.clone())).await;
                                    let _ = upstream.send(Message::Close(frame)).await;
                                    break;
                                }
                                Message::Frame(_) => continue,
                                _ => {}
                            }
                            if inspect_responses
                                && Self::websocket_message_blocked(
                                    &waf_engine,
                                    &base_context,
                                    &message,
                                    max_message_bytes,
                                )
                                .await
                            {
                                warn!(
                                    "WAF blocked upstream WebSocket frame for {}",
                                    base_context.client_ip
                                );
                                let close = CloseFrame {
                                    code: CloseCode::Policy,
                                    reason: "WebSocket response blocked by WAF".into(),
                                };
                                let _ = client.send(Message::Close(Some(close.clone()))).await;
                                let _ = upstream.send(Message::Close(Some(close))).await;
                                break;
                            }
                            if client.send(message).await.is_err() {
                                break;
                            }
                        }
                        Some(Err(e)) => {
                            // An inspection/parse failure must close the
                            // tunnel, never forward the unverified message.
                            if let Some(close) = Self::websocket_error_close(&e) {
                                warn!(
                                    "WebSocket upstream stream error for {}: {}",
                                    base_context.client_ip, e
                                );
                                let _ = client.send(Message::Close(Some(close.clone()))).await;
                                let _ = upstream.send(Message::Close(Some(close))).await;
                            } else {
                                debug!("WebSocket upstream stream error: {}", e);
                            }
                            break;
                        }
                        None => break,
                    }
                }
            }
        }
    }

    /// Validate an assembled control message against RFC 6455. Control frames
    /// carry at most 125 payload bytes, are never fragmented (the parser
    /// rejects `FIN=0` before this point), and close codes must be legal.
    fn websocket_control_violation(message: &Message) -> Option<CloseFrame> {
        let reason = match message {
            Message::Ping(payload) | Message::Pong(payload) if payload.len() > 125 => {
                "control frame payload exceeds 125 bytes"
            }
            Message::Close(Some(frame)) if !frame.code.is_allowed() => "invalid close code",
            Message::Close(Some(frame)) if frame.reason.len() > 123 => {
                "close reason exceeds 123 bytes"
            }
            _ => return None,
        };
        Some(CloseFrame {
            code: CloseCode::Protocol,
            reason: reason.into(),
        })
    }

    /// Map stream errors to the close code sent to both peers.
    fn websocket_error_close(error: &WsError) -> Option<CloseFrame> {
        match error {
            WsError::Protocol(_) => Some(CloseFrame {
                code: CloseCode::Protocol,
                reason: "WebSocket protocol violation".into(),
            }),
            // Capacity covers oversized frames/messages; the parser rejects
            // them before assembly.
            WsError::Capacity(_) => Some(CloseFrame {
                code: CloseCode::Policy,
                reason: "WebSocket message exceeds configured limit".into(),
            }),
            _ => None,
        }
    }

    async fn websocket_message_blocked(
        waf_engine: &Arc<WafEngine>,
        base_context: &RequestContext,
        message: &Message,
        max_message_bytes: usize,
    ) -> bool {
        let payload = match message {
            Message::Text(text) => text.as_bytes().to_vec(),
            Message::Binary(data) => data.to_vec(),
            _ => return false,
        };
        if payload.is_empty() {
            return false;
        }
        // Defence in depth: the tungstenite parser already enforces
        // `server.websocket.max_message_bytes` before a message is assembled.
        if payload.len() > max_message_bytes {
            warn!(
                "WAF blocked oversized WebSocket message from {}: {} bytes exceeds {}",
                base_context.client_ip,
                payload.len(),
                max_message_bytes
            );
            return true;
        }

        let mut context = base_context.clone();
        context.body = Some(Bytes::from(payload.clone()));
        context.body_size = Some(payload.len());
        context.timestamp = Instant::now();

        match waf_engine.evaluate_shared(&context).await {
            Decision::Allow => false,
            Decision::Block { status, reason } => {
                warn!(
                    "WAF blocked WebSocket frame from {}: {} (status: {})",
                    context.client_ip, reason, status
                );
                true
            }
            Decision::RateLimit { reason } => {
                warn!(
                    "WAF rate limited WebSocket frame from {}: {}",
                    context.client_ip, reason
                );
                true
            }
        }
    }

    /// Resolve the client address without blindly trusting client headers.
    ///
    /// Forwarding headers are only honoured when the immediate peer is a
    /// configured trusted proxy; otherwise the socket address is
    /// authoritative. The precedence is `X-Forwarded-For`, `Forwarded`
    /// (`for=`), `X-Real-IP`, then `X-Client-IP`. Every family is read in wire
    /// order across repeated header lines and comma-separated members. A
    /// malformed, oversized or over-long chain is never silently trimmed: the
    /// selected header family is discarded, the immediate peer is used, and a
    /// warning names the fallback reason.
    pub(crate) fn resolve_client_ip(
        peer_ip: IpAddr,
        headers: &hyper::HeaderMap,
        trusted_proxies: &[IpNetwork],
    ) -> IpAddr {
        Self::resolve_client_ip_inner(peer_ip, headers, trusted_proxies, None)
    }

    /// Same as [`Self::resolve_client_ip`], but also records a rejection metric
    /// when a trusted peer's forwarding header is discarded.
    pub(crate) fn resolve_client_ip_with_metrics(
        peer_ip: IpAddr,
        headers: &hyper::HeaderMap,
        trusted_proxies: &[IpNetwork],
        metrics: &Metrics,
    ) -> IpAddr {
        Self::resolve_client_ip_inner(peer_ip, headers, trusted_proxies, Some(metrics))
    }

    fn resolve_client_ip_inner(
        peer_ip: IpAddr,
        headers: &hyper::HeaderMap,
        trusted_proxies: &[IpNetwork],
        metrics: Option<&Metrics>,
    ) -> IpAddr {
        let (ip, fallback) = Self::resolve_client_ip_detailed(peer_ip, headers, trusted_proxies);
        if let Some(reason) = fallback {
            if let Some(metrics) = metrics {
                metrics.record_forwarded_header_rejected();
            }
            warn!(
                peer = %peer_ip,
                reason = reason.as_str(),
                "Discarding forwarded header; using the immediate peer as the client address"
            );
        }
        ip
    }

    /// Detailed variant used by tests and the wrappers above.
    pub(crate) fn resolve_client_ip_detailed(
        peer_ip: IpAddr,
        headers: &hyper::HeaderMap,
        trusted_proxies: &[IpNetwork],
    ) -> (IpAddr, Option<ClientIpFallback>) {
        let trusted_peer = trusted_proxies
            .iter()
            .any(|network| network.contains(peer_ip));
        if !trusted_peer {
            return (peer_ip, None);
        }

        for header in [
            ForwardedHeader::XForwardedFor,
            ForwardedHeader::Forwarded,
            ForwardedHeader::XRealIp,
            ForwardedHeader::XClientIp,
        ] {
            if !headers.contains_key(header.name()) {
                continue;
            }

            let hops = match header {
                ForwardedHeader::Forwarded => Self::collect_forwarded_chain(headers),
                _ => Self::collect_forwarded_chain_for(headers, header),
            };

            match hops {
                Err(reason) => return (peer_ip, Some(reason)),
                Ok(hops) => {
                    // Walk from the nearest hop backwards, skipping addresses
                    // that are themselves trusted proxies. This prevents a
                    // client behind a trusted LB from spoofing its source by
                    // prepending an address or by using a separate header
                    // line.
                    for hop in hops.iter().rev() {
                        if !trusted_proxies.iter().any(|network| network.contains(*hop)) {
                            return (*hop, None);
                        }
                    }
                    // Every hop is a trusted proxy: there is no client address
                    // to report, so the immediate peer remains authoritative.
                    return (peer_ip, None);
                }
            }
        }

        (peer_ip, None)
    }

    fn collect_forwarded_chain_for(
        headers: &hyper::HeaderMap,
        header: ForwardedHeader,
    ) -> Result<Vec<IpAddr>, ClientIpFallback> {
        let malformed = ClientIpFallback::for_header(header);
        let mut hops = Vec::new();
        let mut bytes = 0usize;

        for value in headers.get_all(header.name()) {
            bytes = bytes.saturating_add(value.as_bytes().len());
            if bytes > MAX_FORWARDED_HEADER_BYTES {
                return Err(ClientIpFallback::ForwardedHeaderTooLarge);
            }
            let value = value.to_str().map_err(|_| malformed)?;
            for part in value.split(',') {
                let part = part.trim();
                if part.is_empty() {
                    return Err(malformed);
                }
                let ip = parse_forwarded_ip(part).ok_or(malformed)?;
                hops.push(ip);
                if hops.len() > MAX_FORWARDED_CHAIN_HOPS {
                    return Err(ClientIpFallback::ForwardedChainTooLong);
                }
            }
        }

        if hops.is_empty() {
            return Err(malformed);
        }
        Ok(hops)
    }

    fn collect_forwarded_chain(
        headers: &hyper::HeaderMap,
    ) -> Result<Vec<IpAddr>, ClientIpFallback> {
        let mut hops = Vec::new();
        let mut bytes = 0usize;

        for value in headers.get_all("forwarded") {
            bytes = bytes.saturating_add(value.as_bytes().len());
            if bytes > MAX_FORWARDED_HEADER_BYTES {
                return Err(ClientIpFallback::ForwardedHeaderTooLarge);
            }
            let value = value
                .to_str()
                .map_err(|_| ClientIpFallback::MalformedForwarded)?;
            let elements = split_quoted(value, ',').ok_or(ClientIpFallback::MalformedForwarded)?;
            for element in elements {
                let element = element.trim();
                if element.is_empty() {
                    return Err(ClientIpFallback::MalformedForwarded);
                }
                let ip =
                    parse_forwarded_element(element).ok_or(ClientIpFallback::MalformedForwarded)?;
                hops.push(ip);
                if hops.len() > MAX_FORWARDED_CHAIN_HOPS {
                    return Err(ClientIpFallback::ForwardedChainTooLong);
                }
            }
        }

        if hops.is_empty() {
            return Err(ClientIpFallback::MalformedForwarded);
        }
        Ok(hops)
    }

    /// Detect HTTP protocol version from request
    fn detect_http_version<T>(req: &Request<T>) -> &'static str {
        match req.version() {
            hyper::Version::HTTP_09 => "0.9",
            hyper::Version::HTTP_10 => "1.0",
            hyper::Version::HTTP_11 => "1.1",
            hyper::Version::HTTP_2 => "2",
            hyper::Version::HTTP_3 => "3",
            _ => "1.1", // Default fallback
        }
    }

    /// Check if the detected HTTP version is supported
    pub(crate) fn is_http_version_supported(version: &str, config: &Config) -> bool {
        config
            .server
            .supported_http_versions
            .iter()
            .any(|supported| supported.as_str() == version)
    }

    /// Build the upstream request, preserving the client's method, headers and
    /// protocol version while stripping hop-by-hop values and stamping the
    /// authoritative client identity.
    fn build_upstream_request(
        parts: hyper::http::request::Parts,
        body: ProxyBody,
        upstream_uri: &Uri,
        http_version: &str,
        client_ip: IpAddr,
        is_https: bool,
    ) -> Result<Request<ProxyBody>, Box<Response<ProxyBody>>> {
        Self::build_upstream_request_with_policy(
            parts,
            body,
            upstream_uri,
            http_version,
            client_ip,
            is_https,
            &HeaderStripPolicy::defaults(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn build_upstream_request_with_policy(
        mut parts: hyper::http::request::Parts,
        body: ProxyBody,
        upstream_uri: &Uri,
        http_version: &str,
        client_ip: IpAddr,
        is_https: bool,
        strip_policy: &HeaderStripPolicy,
    ) -> Result<Request<ProxyBody>, Box<Response<ProxyBody>>> {
        // Defence in depth: callers sanitise before WAF inspection, but the
        // upstream request must never contain a client routing header even if a
        // future call site forgets to do so.
        strip_policy.strip(&mut parts.headers, client_ip);

        let classification = classify_request(&parts.headers);
        // Downstream version negotiation is independent of the upstream
        // connection. Default to HTTP/1.1 (the capability every configured
        // origin supports); gRPC multiplexed over an h2/h3 ingress keeps
        // HTTP/2 because the gRPC transport requires it. Mirrored versions
        // caused `502 UserUnsupportedVersion` against HTTP/1.1-only origins.
        let upstream_version = if classification.is_grpc && matches!(http_version, "2" | "3") {
            hyper::Version::HTTP_2
        } else {
            hyper::Version::HTTP_11
        };

        let upstream_path_and_query = parts
            .uri
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/");

        let upstream_base = upstream_uri.to_string();
        let upstream_base = upstream_base.trim_end_matches('/');
        let path = if upstream_path_and_query.starts_with('/') {
            upstream_path_and_query.to_string()
        } else {
            format!("/{}", upstream_path_and_query)
        };

        let new_uri = match format!("{}{}", upstream_base, path).parse::<Uri>() {
            Ok(uri) => uri,
            Err(e) => {
                error!("Failed to construct upstream URI: {}", e);
                return Err(Box::new(Self::create_error_response(
                    StatusCode::BAD_GATEWAY,
                    "Invalid upstream URI",
                )));
            }
        };

        // Preserve the original virtual host for the upstream application.
        let original_host = parts.headers.get(hyper::header::HOST).cloned();

        // Hyper only writes trailing fields listed in a `Trailer` header. For a
        // buffered body the names are known now; for a streamed body the client
        // must have announced them (the header is forwarded below).
        let announced_trailers = body.announced_trailer_fields();
        let has_buffered_trailers = announced_trailers.is_some();
        // The body sent upstream is the body the WAF inspected and possibly
        // re-framed (decompressed), so its length is authoritative. It is
        // stamped explicitly below rather than inherited from the client.
        let body_length = body.size_hint().exact();
        let has_trailer_header = parts.headers.contains_key(hyper::header::TRAILER);

        let mut proxy_req = Request::builder()
            .method(parts.method)
            .uri(new_uri)
            .version(upstream_version);

        match http_version {
            "1.0" => {
                proxy_req = proxy_req.header("Connection", "close");
            }
            "1.1" => {
                proxy_req = proxy_req.header("Connection", "keep-alive");
            }
            "2" => {}
            "3" => {
                debug!("HTTP/3 request forwarded via HTTP/2 to upstream (protocol conversion)");
            }
            _ => {
                proxy_req = proxy_req.header("Connection", "keep-alive");
            }
        }

        // Copy headers, skipping hop-by-hop values that the upstream connection
        // must negotiate for itself. `Te` and `Trailer` are end-to-end header
        // fields for gRPC: dropping them silently breaks trailing status.
        let connection_nominated = connection_nominated_headers(&parts.headers);
        let mut has_te = false;
        // Hop-by-hop and proxy-owned headers are compared case-insensitively
        // without allocating a lowercase copy per forwarded header.
        let skip_header = |key: &hyper::header::HeaderName| {
            let name = key.as_str();
            const FIXED: [&str; 10] = [
                "host",
                "connection",
                "proxy-connection",
                "upgrade",
                "transfer-encoding",
                "content-length",
                "keep-alive",
                "x-forwarded-for",
                "x-real-ip",
                "x-forwarded-proto",
            ];
            FIXED
                .iter()
                .any(|candidate| name.eq_ignore_ascii_case(candidate))
                || connection_nominated
                    .iter()
                    .any(|nominated| name.eq_ignore_ascii_case(nominated))
        };
        for (key, value) in parts.headers {
            if let Some(key) = key {
                if skip_header(&key) {
                    continue;
                }
                if key.as_str().eq_ignore_ascii_case("te") {
                    // `TE` is connection-scoped; only gRPC's `trailers` value is
                    // meaningful end-to-end (and the only value HTTP/2 allows).
                    let trailer_te = value.to_str().ok().is_some_and(|value| {
                        value
                            .split(',')
                            .any(|token| token.trim().eq_ignore_ascii_case("trailers"))
                    });
                    if !classification.is_grpc || !trailer_te {
                        continue;
                    }
                    has_te = true;
                }
                proxy_req = proxy_req.header(key, value);
            }
        }

        // gRPC over HTTP/1.x uses chunked framing; `TE: trailers` tells the
        // upstream that trailing headers may be sent.
        if classification.is_grpc && !has_te && matches!(http_version, "1.0" | "1.1") {
            proxy_req = proxy_req.header("te", "trailers");
        }

        if !has_trailer_header && matches!(http_version, "1.0" | "1.1") {
            if let Some(names) = announced_trailers {
                proxy_req = proxy_req.header(hyper::header::TRAILER, names);
            }
        }

        // Egress normalisation: never forward the client's framing. The
        // inspected/forwarded body is length-delimited unless it is a genuinely
        // streaming body or carries HTTP/1.x trailers (which require chunked
        // framing and cannot be combined with an exact Content-Length).
        if let Some(length) = body_length {
            let streaming_trailers = has_buffered_trailers && matches!(http_version, "1.0" | "1.1");
            if !streaming_trailers {
                proxy_req = proxy_req.header(hyper::header::CONTENT_LENGTH, length.to_string());
            }
        }

        // The WAF is authoritative for client identity.
        let client_ip_header = HeaderValue::from_str(&client_ip.to_string())
            .unwrap_or(HeaderValue::from_static("unknown"));
        proxy_req = proxy_req
            .header("x-forwarded-for", client_ip_header.clone())
            .header("x-real-ip", client_ip_header)
            .header("x-forwarded-proto", if is_https { "https" } else { "http" })
            .header(
                "x-waf-proxy",
                concat!("waf-rejected/", env!("CARGO_PKG_VERSION")),
            );

        if let Some(host) = original_host {
            proxy_req = proxy_req
                .header("x-forwarded-host", host.clone())
                .header(hyper::header::HOST, host);
        }

        proxy_req.body(body).map_err(|e| {
            error!("Failed to build proxy request: {}", e);
            Box::new(Self::create_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to build proxy request",
            ))
        })
    }

    /// Evaluate an upstream response when response inspection is enabled.
    ///
    /// Returns `None` when inspection is disabled or unavailable. The body is
    /// truncated to `max_body_bytes` before it reaches the engine; the caller
    /// still relays the full body. Engine errors fail closed.
    async fn inspect_upstream_response(
        waf_engine: &Arc<WafEngine>,
        metrics: &Metrics,
        inspection: &ResponseInspectionRequest<'_>,
        status: u16,
        protocol: &str,
        headers: &[(String, String)],
        body: Option<&[u8]>,
    ) -> Option<Decision> {
        if !inspection.config.enabled {
            return None;
        }
        if !waf_engine.has_response_evaluator() {
            metrics.record_response_skipped_unsupported();
            return None;
        }

        let mut inspected_body = body;
        if let Some(bytes) = body {
            if bytes.len() > inspection.config.max_body_bytes {
                metrics.record_response_body_truncated();
                inspected_body = Some(&bytes[..inspection.config.max_body_bytes]);
            }
        }

        let response = ResponseContext {
            status,
            protocol: protocol.to_string(),
            headers: headers.to_vec(),
            body: inspected_body.map(Bytes::copy_from_slice),
        };
        let options = ResponseInspectionOptions {
            inspect_body: inspection.config.inspect_body,
            max_body_bytes: inspection.config.max_body_bytes,
        };
        metrics.record_response_inspection();
        let decision = waf_engine
            .evaluate_response_shared(inspection.request, &response, &options)
            .await;
        match &decision {
            Some(Decision::Block { .. } | Decision::RateLimit { .. }) => {
                metrics.record_response_block();
            }
            Some(Decision::Allow) => {}
            None => metrics.record_response_skipped_unsupported(),
        }
        decision
    }

    /// Safe client-facing block for a response rejected by response inspection.
    fn create_response_blocked_response(status_code: u16, is_grpc: bool) -> Response<ProxyBody> {
        if is_grpc {
            Self::create_grpc_blocked_response(status_code, "response blocked by WAF")
        } else {
            Self::create_blocked_response(status_code, "response inspection")
        }
    }

    /// Protocol-aware request forwarding with version preservation.
    ///
    /// The request body is already buffered (and inspected) by the caller. By
    /// default the upstream response is collected for inspection and its
    /// trailing headers are re-emitted unchanged so `grpc-status` survives even
    /// with an empty body. When `stream_response_threshold` is set and the
    /// upstream advertises a `content-length` at or above it, the body is
    /// relayed frame by frame under the same byte cap instead of being
    /// buffered.
    ///
    /// Response inspection is opt-in. Headers are evaluated on both buffered
    /// and streamed responses; body inspection requires buffering, so a
    /// streamed response is passed through and counted as skipped. gRPC
    /// responses are treated as streaming and are not body-inspected.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn forward_to_upstream_with_protocol(
        parts: hyper::http::request::Parts,
        body: ProxyBody,
        upstream_client: UpstreamClient,
        upstream_uri: Uri,
        start_time: Instant,
        http_version: &str,
        waf_engine: &Arc<WafEngine>,
        metrics: &Metrics,
        client_ip: IpAddr,
        is_https: bool,
        upstream_timeout: Duration,
        max_response_bytes: usize,
        stream_response_threshold: Option<usize>,
        strip_policy: &HeaderStripPolicy,
        response_inspection: Option<ResponseInspectionRequest<'_>>,
    ) -> Result<Response<ProxyBody>, Infallible> {
        let proxy_req = match Self::build_upstream_request_with_policy(
            parts,
            body,
            &upstream_uri,
            http_version,
            client_ip,
            is_https,
            strip_policy,
        ) {
            Ok(request) => request,
            Err(response) => return Ok(*response),
        };

        metrics.record_upstream_request();
        let upstream_deadline = Instant::now() + upstream_timeout;
        match tokio::time::timeout(upstream_timeout, upstream_client.request(proxy_req)).await {
            Ok(Ok(response)) => {
                let processing_time = start_time.elapsed();
                debug!("Request processed in {:?}", processing_time);

                let (parts, body) = response.into_parts();
                let inspection = response_inspection.filter(|inspection| inspection.config.enabled);
                let is_grpc = inspection
                    .as_ref()
                    .is_some_and(|inspection| is_grpc_request(inspection.request));
                let inspection_headers = inspection.as_ref().map(|_| {
                    parts
                        .headers
                        .iter()
                        .map(|(name, value)| {
                            (
                                name.as_str().to_string(),
                                String::from_utf8_lossy(value.as_bytes()).into_owned(),
                            )
                        })
                        .collect::<Vec<_>>()
                });
                let has_trailer_header = parts.headers.contains_key(hyper::header::TRAILER);
                let content_length = parts
                    .headers
                    .get(hyper::header::CONTENT_LENGTH)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.parse::<usize>().ok());
                if let Some(length) = content_length {
                    if length > max_response_bytes {
                        metrics.record_upstream_error();
                        return Ok(Self::create_error_response(
                            StatusCode::BAD_GATEWAY,
                            "Upstream response too large",
                        ));
                    }
                }

                if let Some(threshold) = stream_response_threshold {
                    if content_length.is_some_and(|length| length >= threshold) {
                        if let Some(inspection) = &inspection {
                            if inspection.config.inspect_body {
                                // Body inspection needs the whole body; a
                                // streamed response is passed through instead.
                                if is_grpc {
                                    metrics.record_response_skipped_unsupported();
                                } else {
                                    metrics.record_response_skipped_streaming();
                                }
                            } else if let Some(decision) = Self::inspect_upstream_response(
                                waf_engine,
                                metrics,
                                inspection,
                                parts.status.as_u16(),
                                &format!("{:?}", parts.version),
                                inspection_headers.as_deref().unwrap_or(&[]),
                                None,
                            )
                            .await
                            {
                                if matches!(
                                    decision,
                                    Decision::Block { .. } | Decision::RateLimit { .. }
                                ) {
                                    return Ok(Self::create_response_blocked_response(
                                        inspection.config.block_status,
                                        is_grpc,
                                    ));
                                }
                            }
                        }
                        let response_builder = Self::build_upstream_response_head(
                            parts.status,
                            parts.version,
                            parts.headers,
                            None,
                            processing_time,
                        );
                        return match response_builder.body(ProxyBody::guarded(
                            body,
                            max_response_bytes,
                            upstream_timeout,
                        )) {
                            Ok(response) => Ok(response),
                            Err(e) => {
                                error!("Failed to build streamed response: {}", e);
                                Ok(Self::create_error_response(
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    "Failed to build response",
                                ))
                            }
                        };
                    }
                }

                let mut collected = Vec::new();
                let mut trailers = None;
                let mut body = std::pin::pin!(body);
                loop {
                    let remaining = upstream_deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        metrics.record_upstream_error();
                        error!("Upstream response collection exceeded the configured timeout");
                        return Ok(Self::create_error_response(
                            StatusCode::GATEWAY_TIMEOUT,
                            "Upstream response timeout",
                        ));
                    }
                    let frame =
                        match tokio::time::timeout(remaining, BodyExt::frame(&mut body)).await {
                            Ok(Some(Ok(frame))) => frame,
                            Ok(Some(Err(e))) => {
                                metrics.record_upstream_error();
                                error!("Failed to collect upstream response body: {}", e);
                                return Ok(Self::create_error_response(
                                    StatusCode::BAD_GATEWAY,
                                    "Failed to read upstream response",
                                ));
                            }
                            Ok(None) => break,
                            Err(_) => {
                                metrics.record_upstream_error();
                                error!("Upstream response collection timed out");
                                return Ok(Self::create_error_response(
                                    StatusCode::GATEWAY_TIMEOUT,
                                    "Upstream response timeout",
                                ));
                            }
                        };

                    match frame.into_data() {
                        Ok(data) => {
                            if collected.len().saturating_add(data.len()) > max_response_bytes {
                                metrics.record_upstream_error();
                                return Ok(Self::create_error_response(
                                    StatusCode::BAD_GATEWAY,
                                    "Upstream response too large",
                                ));
                            }
                            collected.extend_from_slice(&data);
                        }
                        Err(frame) => {
                            if let Ok(block) = frame.into_trailers() {
                                trailers = Some(block);
                            }
                        }
                    }
                }

                let announced_trailers =
                    if !has_trailer_header && matches!(http_version, "1.0" | "1.1") {
                        trailers
                            .as_ref()
                            .filter(|fields| !fields.is_empty())
                            .map(|fields| {
                                fields
                                    .keys()
                                    .map(|name| name.as_str())
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            })
                    } else {
                        None
                    };

                if let Some(inspection) = &inspection {
                    if is_grpc {
                        // gRPC response bodies are framed/streamed; only the
                        // headers are safe to inspect here.
                        metrics.record_response_skipped_unsupported();
                    }
                    let body = if inspection.config.inspect_body && !is_grpc {
                        Some(collected.as_slice())
                    } else {
                        None
                    };
                    if let Some(decision) = Self::inspect_upstream_response(
                        waf_engine,
                        metrics,
                        inspection,
                        parts.status.as_u16(),
                        &format!("{:?}", parts.version),
                        inspection_headers.as_deref().unwrap_or(&[]),
                        body,
                    )
                    .await
                    {
                        if matches!(
                            decision,
                            Decision::Block { .. } | Decision::RateLimit { .. }
                        ) {
                            return Ok(Self::create_response_blocked_response(
                                inspection.config.block_status,
                                is_grpc,
                            ));
                        }
                    }
                }

                let response_builder = Self::build_upstream_response_head(
                    parts.status,
                    parts.version,
                    parts.headers,
                    announced_trailers,
                    processing_time,
                );

                match response_builder.body(ProxyBody::buffered(Bytes::from(collected), trailers)) {
                    Ok(response) => Ok(response),
                    Err(e) => {
                        error!("Failed to build response: {}", e);
                        Ok(Self::create_error_response(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "Failed to build response",
                        ))
                    }
                }
            }
            Ok(Err(e)) => {
                metrics.record_upstream_error();
                error!("Upstream request failed: {}", e);
                Ok(Self::create_error_response(
                    StatusCode::BAD_GATEWAY,
                    "Upstream server unavailable",
                ))
            }
            Err(_) => {
                metrics.record_upstream_error();
                error!("Upstream request timed out");
                Ok(Self::create_error_response(
                    StatusCode::GATEWAY_TIMEOUT,
                    "Upstream server timeout",
                ))
            }
        }
    }

    /// Build the client response head shared by the buffered and streamed
    /// upstream response paths.
    fn build_upstream_response_head(
        status: StatusCode,
        version: hyper::Version,
        headers: HeaderMap,
        announced_trailers: Option<String>,
        processing_time: Duration,
    ) -> hyper::http::response::Builder {
        let mut response_builder = Response::builder().status(status).version(version);

        // Copy response headers, dropping only connection-specific values.
        // `trailer` announces trailing fields and is preserved.
        for (key, value) in headers {
            if let Some(key) = key {
                if !is_hop_by_hop_header(key.as_str()) {
                    response_builder = response_builder.header(key, value);
                }
            }
        }

        if let Some(names) = announced_trailers {
            response_builder = response_builder.header(hyper::header::TRAILER, names);
        }

        response_builder
            .header(
                "x-waf-processing-time-ms",
                processing_time.as_millis().to_string(),
            )
            .header(
                "x-waf-version",
                concat!("waf-rejected/", env!("CARGO_PKG_VERSION")),
            )
            .header("x-content-type-options", "nosniff")
    }

    /// Prepare and relay a gRPC stream with incremental per-message inspection.
    ///
    /// Every complete length-prefixed message is inspected by the configured
    /// `GrpcInspector` (including its field-content scan) before that frame is
    /// forwarded. The first message is primed before the upstream request is
    /// sent, so a blocked/oversized/malformed first frame produces a WAF
    /// response instead of an upstream error. There is no timing-based
    /// classification: delaying `END_STREAM` cannot skip inspection.
    #[allow(clippy::too_many_arguments)]
    async fn handle_grpc_stream(
        parts: hyper::http::request::Parts,
        incoming: Incoming,
        prefix: Bytes,
        state: &ProxyState,
        start_time: Instant,
        http_version: &str,
        client_ip: IpAddr,
        is_https: bool,
        telemetry: &RequestTelemetry,
    ) -> Response<ProxyBody> {
        let request_context = RequestContext::with_http_version(
            client_ip,
            parts.method.clone(),
            parts.uri.clone(),
            parts.headers.clone(),
            None,
            http_version.to_string(),
        );

        // Header/URI rules (including method allowlist and rate limits) still
        // run before any body bytes are forwarded.
        match state.waf_engine.evaluate_shared(&request_context).await {
            Decision::Allow => {}
            Decision::Block { status, reason } => {
                warn!(
                    "WAF blocked streaming gRPC request from {}: {} (status: {})",
                    client_ip, reason, status
                );
                telemetry.reject(RequestRejection::WafBlocked);
                state.metrics.record_blocked();
                state.metrics.record_request_duration(start_time.elapsed());
                if state.config.server.grpc_aware_rejections {
                    return Self::create_grpc_blocked_response(status, &reason);
                }
                return Self::create_blocked_response(status, &reason);
            }
            Decision::RateLimit { reason } => {
                warn!(
                    "WAF rate limited streaming gRPC request from {}: {}",
                    client_ip, reason
                );
                telemetry.reject(RequestRejection::WafRateLimited);
                state.metrics.record_rate_limited();
                state.metrics.record_blocked();
                state.metrics.record_request_duration(start_time.elapsed());
                return Self::create_rate_limit_response(&reason);
            }
        }

        if state.config.server.grpc_streaming_policy == GrpcStreamingPolicy::Reject {
            let reason = "streaming gRPC rejected by server.grpc_streaming_policy = \"reject\"";
            warn!(
                "Rejecting streaming gRPC request from {}: {}",
                client_ip, reason
            );
            telemetry.reject(RequestRejection::WafBlocked);
            state.metrics.record_blocked();
            state.metrics.record_request_duration(start_time.elapsed());
            if state.config.server.grpc_aware_rejections {
                return Self::create_grpc_blocked_response(403, reason);
            }
            return Self::create_blocked_response(403, reason);
        }

        debug!(
            "Streaming gRPC request from {} inspected incrementally (transport-only)",
            client_ip
        );
        let encoding = parts
            .headers
            .get("grpc-encoding")
            .and_then(|value| value.to_str().ok());
        let max_duration = Duration::from_secs(state.config.server.grpc_max_stream_seconds);
        let mut guarded = match GrpcStreamGuard::new(
            PrefixedBody::new(prefix, incoming),
            encoding,
            state.config.server.grpc_max_stream_bytes,
            state.config.server.grpc_max_stream_messages,
            state.config.server.grpc_max_decompressed_bytes,
            max_duration,
        ) {
            Ok(guarded) => guarded,
            Err(error) => {
                warn!(
                    "Rejecting streaming gRPC request from {}: {}",
                    client_ip, error
                );
                telemetry.reject(RequestRejection::InvalidFraming);
                state.metrics.record_blocked();
                state.metrics.record_request_duration(start_time.elapsed());
                if state.config.server.grpc_aware_rejections {
                    return Self::create_grpc_blocked_response(400, &error.to_string());
                }
                return Self::create_error_response(StatusCode::BAD_REQUEST, &error.to_string());
            }
        };
        guarded = guarded.with_max_message_bytes(state.config.waf.grpc.max_message_bytes);
        if let Some(inspector) = state
            .waf_engine
            .grpc_stream_frame_inspector(&request_context)
        {
            guarded = guarded.with_inspector(Arc::new(inspector));
        }

        let prime_timeout = Duration::from_secs(state.config.server.request_timeout_secs.max(1));
        match tokio::time::timeout(prime_timeout, guarded.prime()).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                let (status, rejection) = match &error {
                    GrpcStreamError::InspectionBlocked { status, .. } => {
                        (*status, RequestRejection::WafBlocked)
                    }
                    GrpcStreamError::MessageTooLarge { .. }
                    | GrpcStreamError::BytesExceeded { .. }
                    | GrpcStreamError::DecompressedExceeded { .. } => (
                        StatusCode::PAYLOAD_TOO_LARGE.as_u16(),
                        RequestRejection::BodyTooLarge,
                    ),
                    GrpcStreamError::DurationExceeded { .. } => (
                        StatusCode::REQUEST_TIMEOUT.as_u16(),
                        RequestRejection::BodyTimeout,
                    ),
                    _ => (
                        StatusCode::BAD_REQUEST.as_u16(),
                        RequestRejection::InvalidFraming,
                    ),
                };
                warn!(
                    "Rejecting streaming gRPC request from {}: {}",
                    client_ip, error
                );
                telemetry.reject(rejection);
                state.metrics.record_blocked();
                state.metrics.record_request_duration(start_time.elapsed());
                if state.config.server.grpc_aware_rejections {
                    return Self::create_grpc_blocked_response(status, &error.to_string());
                }
                return Self::create_error_response(
                    StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_REQUEST),
                    &error.to_string(),
                );
            }
            Err(_) => {
                warn!("gRPC stream prime timed out for {}", client_ip);
                telemetry.reject(RequestRejection::BodyTimeout);
                state.metrics.record_blocked();
                state.metrics.record_request_duration(start_time.elapsed());
                return Self::create_error_response(
                    StatusCode::REQUEST_TIMEOUT,
                    "gRPC request body timeout",
                );
            }
        }

        state.metrics.record_allowed();
        let response = Self::forward_grpc_stream(
            parts,
            ProxyBody::Boxed(guarded.boxed()),
            state,
            start_time,
            http_version,
            client_ip,
            is_https,
        )
        .await;
        state.metrics.record_request_duration(start_time.elapsed());
        response
    }

    /// Relay a gRPC stream prepared by [`Self::handle_grpc_stream`].
    ///
    /// The request and response bodies are forwarded frame by frame (including
    /// trailing headers) under `server.grpc_max_stream_bytes` and
    /// `server.grpc_max_stream_seconds`.
    #[allow(clippy::too_many_arguments)]
    async fn forward_grpc_stream(
        parts: hyper::http::request::Parts,
        request_body: ProxyBody,
        state: &ProxyState,
        start_time: Instant,
        http_version: &str,
        client_ip: IpAddr,
        is_https: bool,
    ) -> Response<ProxyBody> {
        let max_bytes = state.config.server.grpc_max_stream_bytes;
        let max_seconds = state.config.server.grpc_max_stream_seconds;
        let max_duration = Duration::from_secs(max_seconds);

        let announce_grpc_trailers =
            classify_request(&parts.headers).is_grpc && matches!(http_version, "1.0" | "1.1");

        let proxy_req = match Self::build_upstream_request_with_policy(
            parts,
            request_body,
            &state.upstream_uri,
            http_version,
            client_ip,
            is_https,
            &state.strip_policy,
        ) {
            Ok(request) => request,
            Err(response) => return *response,
        };

        state.metrics.record_upstream_request();
        match tokio::time::timeout(max_duration, state.upstream_client.request(proxy_req)).await {
            Ok(Ok(response)) => {
                let processing_time = start_time.elapsed();
                let (parts, body) = response.into_parts();
                let has_trailer_header = parts.headers.contains_key(hyper::header::TRAILER);

                let mut response_builder = Response::builder()
                    .status(parts.status)
                    .version(parts.version);
                for (key, value) in parts.headers {
                    if let Some(key) = key {
                        let name = key.as_str().to_ascii_lowercase();
                        if !is_hop_by_hop_header(&name) {
                            response_builder = response_builder.header(key, value);
                        }
                    }
                }
                if announce_grpc_trailers && !has_trailer_header {
                    // Streaming trailers are unknown up front; announce the
                    // gRPC status fields so HTTP/1.x can encode them.
                    response_builder = response_builder
                        .header(hyper::header::TRAILER, "grpc-status, grpc-message");
                }
                response_builder = response_builder
                    .header(
                        "x-waf-processing-time-ms",
                        processing_time.as_millis().to_string(),
                    )
                    .header(
                        "x-waf-version",
                        concat!("waf-rejected/", env!("CARGO_PKG_VERSION")),
                    )
                    .header("x-content-type-options", "nosniff");

                match response_builder.body(ProxyBody::guarded(body, max_bytes, max_duration)) {
                    Ok(response) => response,
                    Err(e) => {
                        error!("Failed to build streaming gRPC response: {}", e);
                        Self::create_error_response(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "Failed to build response",
                        )
                    }
                }
            }
            Ok(Err(e)) => {
                state.metrics.record_upstream_error();
                error!("Streaming gRPC upstream request failed: {}", e);
                Self::create_error_response(StatusCode::BAD_GATEWAY, "Upstream server unavailable")
            }
            Err(_) => {
                state.metrics.record_upstream_error();
                error!("Streaming gRPC upstream request timed out");
                Self::create_error_response(StatusCode::GATEWAY_TIMEOUT, "Upstream server timeout")
            }
        }
    }

    /// Create blocked response with protocol information.
    ///
    /// The client only receives a generic body, the status and a fixed
    /// rule-id vocabulary. The full reason (including any matched excerpt) is
    /// retained by the security event log; it is never echoed to the client.
    pub(crate) fn create_blocked_response(status_code: u16, reason: &str) -> Response<ProxyBody> {
        let status = StatusCode::from_u16(status_code).unwrap_or(StatusCode::FORBIDDEN);
        let rule_id = rule_id_for_reason(reason);
        let body = format!(
            "Request blocked by WAF\nstatus: {}\nrule: {}\n",
            status.as_u16(),
            rule_id
        );

        let mut builder = Response::builder()
            .status(status)
            .header("content-type", "text/plain")
            .header("x-waf-decision", "block")
            .header("x-waf-rule-id", rule_id)
            .header(
                "x-waf-version",
                concat!("waf-rejected/", env!("CARGO_PKG_VERSION")),
            )
            .header(
                "x-waf-supported-protocols",
                "HTTP/1.0,HTTP/1.1,HTTP/2,HTTP/3",
            );
        // Admission rejection is transient: advertise a short retry hint.
        if status == StatusCode::SERVICE_UNAVAILABLE {
            builder = builder.header("retry-after", "1");
        }
        finish_response(builder, ProxyBody::full(body), StatusCode::FORBIDDEN)
    }

    /// Create a gRPC-native rejection response.
    ///
    /// gRPC clients expect HTTP 200 with the outcome in `grpc-status` /
    /// `grpc-message` trailers. `403` maps to `7` (PERMISSION_DENIED); every
    /// other WAF block status maps to `13` (INTERNAL). The body is empty, so
    /// the trailers are the only payload.
    pub(crate) fn create_grpc_blocked_response(
        status_code: u16,
        reason: &str,
    ) -> Response<ProxyBody> {
        let grpc_status = if status_code == 403 { "7" } else { "13" };
        let rule_id = rule_id_for_reason(reason);
        let mut trailers = HeaderMap::new();
        trailers.insert("grpc-status", HeaderValue::from_static(grpc_status));
        trailers.insert(
            "grpc-message",
            header_value_from_reason(&format!(
                "blocked by WAF (status: {status_code}, rule: {rule_id})"
            )),
        );

        let builder = Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/grpc")
            .header("trailer", "grpc-status, grpc-message")
            .header("x-waf-decision", "block")
            .header("x-waf-rule-id", rule_id)
            .header(
                "x-waf-version",
                concat!("waf-rejected/", env!("CARGO_PKG_VERSION")),
            )
            .header(
                "x-waf-supported-protocols",
                "HTTP/1.0,HTTP/1.1,HTTP/2,HTTP/3",
            );
        finish_response(
            builder,
            ProxyBody::buffered(Bytes::new(), Some(trailers)),
            StatusCode::FORBIDDEN,
        )
    }

    /// Create rate limit response with protocol information.
    ///
    /// Rate-limit reasons are not echoed: they can include the offending key
    /// or request detail, which is audit data rather than a client message.
    pub(crate) fn create_rate_limit_response(_reason: &str) -> Response<ProxyBody> {
        let body = "Rate limited by WAF\nstatus: 429\nrule: rate-limit\n";

        let builder = Response::builder()
            .status(StatusCode::TOO_MANY_REQUESTS)
            .header("content-type", "text/plain")
            .header("x-waf-decision", "rate-limit")
            .header("x-waf-rule-id", "rate-limit")
            .header(
                "x-waf-version",
                concat!("waf-rejected/", env!("CARGO_PKG_VERSION")),
            )
            .header(
                "x-waf-supported-protocols",
                "HTTP/1.0,HTTP/1.1,HTTP/2,HTTP/3",
            )
            .header("retry-after", "60"); // Suggest retry after 60 seconds
        finish_response(
            builder,
            ProxyBody::full(body),
            StatusCode::TOO_MANY_REQUESTS,
        )
    }

    /// Create generic error response with protocol information
    pub(crate) fn create_error_response(status: StatusCode, message: &str) -> Response<ProxyBody> {
        let builder = Response::builder()
            .status(status)
            .header("content-type", "text/plain")
            .header(
                "x-waf-version",
                concat!("waf-rejected/", env!("CARGO_PKG_VERSION")),
            )
            .header(
                "x-waf-supported-protocols",
                "HTTP/1.0,HTTP/1.1,HTTP/2,HTTP/3",
            );
        finish_response(
            builder,
            ProxyBody::full(message.to_string()),
            StatusCode::INTERNAL_SERVER_ERROR,
        )
    }
}

/// Maximum byte length of a sanitised reason. The value is intentionally
/// small: it bounds response work and prevents an attacker from padding a
/// header or log field.
const MAX_SANITISED_REASON_BYTES: usize = 160;

/// Render attacker-influenced text so it is safe in an HTTP header value and
/// in a `text/plain` body.
///
/// Visible ASCII (0x20..=0x7E) is preserved. Tabs and every other character,
/// including CR, LF, NUL, DEL and non-ASCII UTF-8, become spaces. Whitespace
/// runs collapse to one space, the result is trimmed, and it is truncated to
/// [`MAX_SANITISED_REASON_BYTES`]. The output is ASCII-only and therefore
/// always accepted by `HeaderValue::from_str`.
pub(crate) fn sanitize_reason(reason: &str) -> String {
    let mut out = String::with_capacity(reason.len().min(MAX_SANITISED_REASON_BYTES));
    let mut pending_space = false;

    for ch in reason.chars() {
        if out.len() >= MAX_SANITISED_REASON_BYTES {
            break;
        }
        let safe = match ch {
            '\t' => ' ',
            '\u{20}'..='\u{7e}' => ch,
            _ => ' ',
        };
        if safe == ' ' {
            pending_space = !out.is_empty();
            continue;
        }
        if pending_space && out.len() < MAX_SANITISED_REASON_BYTES {
            out.push(' ');
        }
        pending_space = false;
        if out.len() >= MAX_SANITISED_REASON_BYTES {
            break;
        }
        out.push(safe);
    }

    out.trim_end().to_string()
}

/// Header-safe rendering of attacker-influenced text.
///
/// [`sanitize_reason`] is already guaranteed to be valid; the fallback keeps
/// the function total even if that invariant is ever broken.
pub(crate) fn header_value_from_reason(reason: &str) -> HeaderValue {
    HeaderValue::from_str(&sanitize_reason(reason))
        .unwrap_or_else(|_| HeaderValue::from_static("blocked by WAF"))
}

/// Map a block reason to the fixed rule-id vocabulary exposed to clients.
///
/// The actual reason (rule name and matched excerpt) stays in the security
/// event log. Clients only need a stable category that cannot carry payload.
pub(crate) fn rule_id_for_reason(reason: &str) -> &'static str {
    let lower = reason.to_ascii_lowercase();
    let has = |needle: &str| lower.contains(needle);

    if has("rate limit") || has("rate-limit") || has("too many") {
        "rate-limit"
    } else if has("sql injection") || has("sql_injection") || has("sqli") {
        "sql-injection"
    } else if has("xss") || has("cross-site scripting") || has("cross site scripting") {
        "xss"
    } else if has("command injection") || has("command_injection") {
        "command-injection"
    } else if has("path traversal") || has("path_traversal") || has("traversal") {
        "path-traversal"
    } else if has("remote file inclusion") || has("local file inclusion") || has("file inclusion") {
        "file-inclusion"
    } else if has("xxe") || has("xml external entity") {
        "xxe"
    } else if has("ssrf") || has("server-side request forgery") {
        "ssrf"
    } else if has("graphql") {
        "graphql"
    } else if has("grpc") {
        "grpc"
    } else if has("wasm") {
        "wasm-rule"
    } else if has("ai detected") || has("ai threat") {
        "ai-threat"
    } else if has("geographic") || has("geo blocking") {
        "geographic-block"
    } else if has("admission") {
        "admission-control"
    } else if has("protocol")
        || has("framing")
        || has("smuggl")
        || has("handshake")
        || has("malformed")
        || has("ambiguous")
    {
        "protocol-violation"
    } else {
        "policy-violation"
    }
}

/// Finish a response builder without panicking.
///
/// A builder error means a dynamic header was rejected. The request must still
/// receive a valid response, so fall back to a minimal static response that
/// carries no dynamic headers instead of aborting the process.
fn finish_response(
    builder: hyper::http::response::Builder,
    body: ProxyBody,
    fallback_status: StatusCode,
) -> Response<ProxyBody> {
    match builder.body(body) {
        Ok(response) => response,
        Err(error) => {
            error!(
                "Failed to build WAF response, returning static fallback: {}",
                error
            );
            minimal_response(fallback_status)
        }
    }
}

/// Minimal response used when a response builder rejects its inputs.
fn minimal_response(status: StatusCode) -> Response<ProxyBody> {
    let mut response = Response::new(ProxyBody::full(Bytes::from_static(
        b"Request blocked by WAF\n",
    )));
    *response.status_mut() = status;
    response.headers_mut().insert(
        hyper::header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain"),
    );
    response
}

/// Parse the upstream WebSocket handshake response head without panicking.
///
/// `http::response::Builder::header` panics on an invalid name or value, so a
/// malformed upstream must be rejected here with a typed error before the
/// builder is touched. `Connection` and `Upgrade` are dropped because the
/// proxy writes its own values.
fn parse_websocket_handshake_head(head: &str) -> Result<(u16, HeaderMap), WafError> {
    let mut lines = head.lines();
    let status_line = lines
        .next()
        .ok_or_else(|| WafError::Upstream("empty WebSocket handshake response".to_string()))?;
    let mut status_parts = status_line.split_whitespace();
    let version = status_parts
        .next()
        .ok_or_else(|| WafError::Upstream("missing HTTP version".to_string()))?;
    if !version.starts_with("HTTP/") {
        return Err(WafError::Upstream(format!(
            "invalid WebSocket handshake status line '{status_line}'"
        )));
    }
    let status = status_parts
        .next()
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| WafError::Upstream("invalid WebSocket handshake status code".to_string()))?;

    let mut headers = HeaderMap::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line.split_once(':').ok_or_else(|| {
            WafError::Upstream(format!("malformed WebSocket handshake header '{line}'"))
        })?;
        let name = HeaderName::from_bytes(name.trim().as_bytes()).map_err(|e| {
            WafError::Upstream(format!("invalid WebSocket handshake header name: {e}"))
        })?;
        let value = HeaderValue::from_str(value.trim()).map_err(|e| {
            WafError::Upstream(format!("invalid WebSocket handshake header value: {e}"))
        })?;
        if name == hyper::header::CONNECTION || name == hyper::header::UPGRADE {
            continue;
        }
        headers.append(name, value);
    }

    Ok((status, headers))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ProxyConfig;
    use proptest::prelude::*;

    fn classify(content_type: &str) -> RequestClassification {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", content_type.parse().unwrap());
        classify_request(&headers)
    }

    #[test]
    fn header_count_and_byte_bounds_are_enforced() {
        let mut config = crate::config::ServerConfig::default();
        config.max_header_count = 2;
        config.max_header_bytes = 64;

        let mut headers = HeaderMap::new();
        headers.insert("a", "1".parse().unwrap());
        assert!(enforce_header_bounds(&headers, &config).is_ok());

        headers.insert("b", "2".parse().unwrap());
        headers.insert("c", "3".parse().unwrap());
        assert!(matches!(
            enforce_header_bounds(&headers, &config),
            Err(HeaderLimitViolation::Count { .. })
        ));

        let mut headers = HeaderMap::new();
        headers.insert("x-big", "A".repeat(128).parse().unwrap());
        assert!(matches!(
            enforce_header_bounds(&headers, &config),
            Err(HeaderLimitViolation::Bytes { .. })
        ));
    }

    #[tokio::test]
    async fn websocket_bridge_closes_an_idle_tunnel() {
        use tokio_tungstenite::tungstenite::protocol::Role;

        let (client_io, _client_peer) = tokio::io::duplex(1024);
        let (upstream_io, _upstream_peer) = tokio::io::duplex(1024);
        let client = WebSocketStream::from_raw_socket(client_io, Role::Server, None).await;
        let upstream = WebSocketStream::from_raw_socket(upstream_io, Role::Client, None).await;
        let context = RequestContext::new(
            "127.0.0.1".parse().unwrap(),
            hyper::Method::GET,
            "/ws".parse().unwrap(),
            HeaderMap::new(),
            None,
        );

        let started = Instant::now();
        tokio::time::timeout(
            Duration::from_secs(2),
            WafProxyService::bridge_websocket(
                client,
                upstream,
                Arc::new(WafEngine::new()),
                context,
                1024,
                Some(Duration::from_millis(100)),
                Duration::from_secs(30),
                Arc::new(Metrics::new()),
                false,
            ),
        )
        .await
        .expect("idle tunnel must close instead of hanging");
        assert!(started.elapsed() >= Duration::from_millis(80));
    }

    #[tokio::test]
    async fn websocket_bridge_enforces_the_absolute_lifetime() {
        use tokio_tungstenite::tungstenite::protocol::Role;

        let (client_io, _client_peer) = tokio::io::duplex(1024);
        let (upstream_io, _upstream_peer) = tokio::io::duplex(1024);
        let client = WebSocketStream::from_raw_socket(client_io, Role::Server, None).await;
        let upstream = WebSocketStream::from_raw_socket(upstream_io, Role::Client, None).await;
        let context = RequestContext::new(
            "127.0.0.1".parse().unwrap(),
            hyper::Method::GET,
            "/ws".parse().unwrap(),
            HeaderMap::new(),
            None,
        );

        tokio::time::timeout(
            Duration::from_secs(2),
            WafProxyService::bridge_websocket(
                client,
                upstream,
                Arc::new(WafEngine::new()),
                context,
                1024,
                None,
                Duration::from_millis(100),
                Arc::new(Metrics::new()),
                false,
            ),
        )
        .await
        .expect("lifetime cap must close the tunnel");
    }

    #[test]
    fn classifies_supported_grpc_media_types() {
        for content_type in [
            "application/grpc",
            "application/grpc+proto",
            "application/grpc+json",
            "application/grpc-web",
            "application/grpc-web+proto",
            "application/grpc-web+json",
            "application/grpc-web-text",
            "application/grpc-web-text+proto",
            "application/grpc-web-text+json",
        ] {
            let classification = classify(content_type);
            assert!(classification.is_grpc, "{content_type} must be gRPC");
        }

        for content_type in [
            "application/grpc-web",
            "application/grpc-web+proto",
            "application/grpc-web+json",
            "application/grpc-web-text",
            "application/grpc-web-text+proto",
            "application/grpc-web-text+json",
        ] {
            assert!(
                classify(content_type).is_grpc_web,
                "{content_type} must use gRPC-Web framing"
            );
        }

        for content_type in [
            "application/grpc",
            "application/grpc+proto",
            "application/grpc+json",
        ] {
            assert!(
                !classify(content_type).is_grpc_web,
                "{content_type} must use native gRPC framing"
            );
        }
    }

    #[test]
    fn grpc_classification_is_case_and_parameter_insensitive() {
        for content_type in [
            "Application/GRPC+Proto; charset=utf-8",
            "APPLICATION/GRPC;charset=UTF-8",
            "application/grpc-web+proto; charset=utf-8",
            "  application/grpc-web-text+json ; charset=utf-8  ",
        ] {
            let classification = classify(content_type);
            assert!(classification.is_grpc, "{content_type} must be gRPC");
        }

        assert!(classify("Application/GRPC-WEB+Proto; charset=utf-8").is_grpc_web);
        assert!(
            !classify("application/grpc+proto; charset=utf-8").is_grpc_web,
            "native gRPC must not use gRPC-Web framing"
        );
    }

    #[test]
    fn unknown_grpc_prefixed_media_types_are_not_grpc() {
        for content_type in [
            "application/grpcx",
            "application/grpc-malicious",
            "application/grpc+",
            "application/grpc/web",
            "application/grpc-webb",
            "application/grpc-web-textx",
            "application/grpcjson",
        ] {
            let classification = classify(content_type);
            assert!(
                !classification.is_grpc,
                "{content_type} must not take the gRPC path"
            );
            assert!(
                !classification.is_grpc_web,
                "{content_type} must not take the gRPC-Web path"
            );
        }

        let mut headers = HeaderMap::new();
        headers.insert("content-type", "application/grpc+proto".parse().unwrap());
        let without_length = classify_request(&headers);
        assert!(without_length.is_grpc);
        assert!(
            !without_length.is_grpc_web,
            "content-length must not influence gRPC classification"
        );

        headers.insert("content-length", "10".parse().unwrap());
        let unary = classify_request(&headers);
        assert!(unary.is_grpc);
        assert!(!unary.is_grpc_web);

        let mut headers = HeaderMap::new();
        headers.insert("content-type", "application/json".parse().unwrap());
        let plain = classify_request(&headers);
        assert!(!plain.is_grpc && !plain.is_grpc_web);
    }

    #[tokio::test]
    async fn guarded_body_enforces_byte_cap() {
        let body = GuardedBody::new(
            Full::new(Bytes::from_static(b"0123456789")),
            4,
            Duration::from_secs(30),
        );
        let mut body = std::pin::pin!(body);
        let error = loop {
            match body.frame().await {
                Some(Ok(_)) => continue,
                Some(Err(error)) => break error,
                None => panic!("byte cap was not enforced"),
            }
        };
        assert!(
            error.to_string().contains("exceeds limit"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn test_websocket_upstream_transport_schemes() {
        let http: Uri = "http://example.com/socket".parse().unwrap();
        assert_eq!(websocket_upstream_transport(&http), Ok((false, 80)));

        let https: Uri = "https://example.com/socket".parse().unwrap();
        assert_eq!(websocket_upstream_transport(&https), Ok((true, 443)));

        let https_port: Uri = "https://example.com:8443/socket".parse().unwrap();
        assert_eq!(websocket_upstream_transport(&https_port), Ok((true, 8443)));

        let unsupported: Uri = "ws://example.com/socket".parse().unwrap();
        assert_eq!(websocket_upstream_transport(&unsupported), Err(()));
    }

    #[test]
    fn test_proxy_service_creation() {
        let mut config = Config {
            proxy: ProxyConfig {
                timeout_seconds: 30,
                max_request_size: 10_485_760,
                upstream_ca_path: None,
                upstream_client_cert_path: None,
                upstream_client_key_path: None,
                ..ProxyConfig::default()
            },
            ..Default::default()
        };
        config.waf.coraza.enabled = false;

        let service = WafProxyService::new(config);
        assert!(service.is_ok());
    }

    #[cfg(feature = "wasm-reactor")]
    #[test]
    fn test_coraza_init_failure_is_fatal_at_startup() {
        let mut config = Config {
            proxy: ProxyConfig {
                timeout_seconds: 30,
                max_request_size: 10_485_760,
                upstream_ca_path: None,
                upstream_client_cert_path: None,
                upstream_client_key_path: None,
                ..ProxyConfig::default()
            },
            ..Default::default()
        };
        config.waf.coraza.backend = crate::config::CorazaBackend::Wasm;
        config.waf.coraza.module_path = Some("/nonexistent/coraza-reactor.wasm".to_string());

        let error = WafProxyService::new(config)
            .err()
            .expect("a configured reactor that cannot load must abort start-up")
            .to_string();
        assert!(
            error.contains("WAF engine initialisation failed")
                && error.contains("Coraza WASI reactor failed to initialise"),
            "unexpected error: {error}"
        );
    }

    #[cfg(feature = "wasm-reactor")]
    #[test]
    fn test_grpc_allowlist_init_failure_is_fatal_at_startup() {
        let mut config = Config {
            proxy: ProxyConfig {
                timeout_seconds: 30,
                max_request_size: 10_485_760,
                upstream_ca_path: None,
                upstream_client_cert_path: None,
                upstream_client_key_path: None,
                ..ProxyConfig::default()
            },
            ..Default::default()
        };
        // Keep the reactor from loading so the failure under test is the gRPC
        // allowlist artifact.
        config.waf.coraza.module_path = Some("/nonexistent/coraza-reactor.wasm".to_string());
        config.waf.grpc.allowlist_file = Some("/nonexistent/grpc/allowlist.json".to_string());

        let error = WafProxyService::new(config)
            .err()
            .expect("an unreadable gRPC allowlist must abort start-up")
            .to_string();
        assert!(
            error.contains("WAF engine initialisation failed")
                && error.contains("gRPC allowlist failed to load")
                && error.contains("/nonexistent/grpc/allowlist.json"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn test_client_ip_ignores_forwarded_header_from_untrusted_peer() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            "192.168.1.100, 10.0.0.1".parse().unwrap(),
        );

        let ip = WafProxyService::resolve_client_ip("203.0.113.10".parse().unwrap(), &headers, &[]);
        assert_eq!(ip, "203.0.113.10".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_client_ip_uses_forwarded_header_from_trusted_peer() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            "192.168.1.100, 10.0.0.1".parse().unwrap(),
        );

        let trusted: Vec<IpNetwork> = vec!["10.0.0.0/8".parse().unwrap()];
        let ip =
            WafProxyService::resolve_client_ip("10.0.0.5".parse().unwrap(), &headers, &trusted);
        assert_eq!(ip, "192.168.1.100".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_client_ip_walks_forwarded_chain_from_the_right() {
        let mut headers = hyper::HeaderMap::new();
        // A client-prepended spoofed value must not win over the hop appended
        // by the trusted proxy.
        headers.insert(
            "x-forwarded-for",
            "203.0.113.9, 198.51.100.7, 10.0.0.7".parse().unwrap(),
        );

        let trusted: Vec<IpNetwork> = vec!["10.0.0.0/8".parse().unwrap()];
        let ip =
            WafProxyService::resolve_client_ip("10.0.0.5".parse().unwrap(), &headers, &trusted);
        assert_eq!(ip, "198.51.100.7".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn multiple_forwarded_for_headers_are_read_in_wire_order() {
        // The audit's H2 regression: the first header is client-controlled and
        // the trusted proxy appended a second header. Reading only the first
        // value would return the spoofed address; the fixed code reads every
        // value in wire order and selects the right-most untrusted hop.
        let mut headers = hyper::HeaderMap::new();
        headers.append("x-forwarded-for", "203.0.113.9".parse().unwrap());
        headers.append("x-forwarded-for", "198.51.100.7".parse().unwrap());

        let trusted: Vec<IpNetwork> = vec!["10.0.0.0/8".parse().unwrap()];
        let (ip, fallback) = WafProxyService::resolve_client_ip_detailed(
            "10.0.0.5".parse().unwrap(),
            &headers,
            &trusted,
        );
        assert_eq!(ip, "198.51.100.7".parse::<IpAddr>().unwrap());
        assert_eq!(fallback, None);
    }

    #[test]
    fn multiple_forwarded_for_headers_skip_appended_trusted_hops() {
        let mut headers = hyper::HeaderMap::new();
        headers.append("x-forwarded-for", "203.0.113.9".parse().unwrap());
        headers.append("x-forwarded-for", "198.51.100.7, 10.0.0.7".parse().unwrap());

        let trusted: Vec<IpNetwork> = vec!["10.0.0.0/8".parse().unwrap()];
        let ip =
            WafProxyService::resolve_client_ip("10.0.0.5".parse().unwrap(), &headers, &trusted);
        assert_eq!(ip, "198.51.100.7".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn malformed_forwarded_chain_falls_back_to_peer() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            "198.51.100.7, not-an-ip, 10.0.0.7".parse().unwrap(),
        );
        headers.insert("x-real-ip", "203.0.113.99".parse().unwrap());

        let trusted: Vec<IpNetwork> = vec!["10.0.0.0/8".parse().unwrap()];
        let (ip, fallback) = WafProxyService::resolve_client_ip_detailed(
            "10.0.0.5".parse().unwrap(),
            &headers,
            &trusted,
        );
        assert_eq!(ip, "10.0.0.5".parse::<IpAddr>().unwrap());
        assert_eq!(fallback, Some(ClientIpFallback::MalformedXForwardedFor));
    }

    #[test]
    fn empty_forwarded_chain_falls_back_to_peer() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert("x-forwarded-for", "  ".parse().unwrap());

        let trusted: Vec<IpNetwork> = vec!["10.0.0.0/8".parse().unwrap()];
        let (ip, fallback) = WafProxyService::resolve_client_ip_detailed(
            "10.0.0.5".parse().unwrap(),
            &headers,
            &trusted,
        );
        assert_eq!(ip, "10.0.0.5".parse::<IpAddr>().unwrap());
        assert_eq!(fallback, Some(ClientIpFallback::MalformedXForwardedFor));
    }

    #[test]
    fn malformed_real_ip_falls_back_to_peer() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert("x-real-ip", "definitely-not-an-ip".parse().unwrap());

        let trusted: Vec<IpNetwork> = vec!["10.0.0.0/8".parse().unwrap()];
        let (ip, fallback) = WafProxyService::resolve_client_ip_detailed(
            "10.0.0.5".parse().unwrap(),
            &headers,
            &trusted,
        );
        assert_eq!(ip, "10.0.0.5".parse::<IpAddr>().unwrap());
        assert_eq!(fallback, Some(ClientIpFallback::MalformedXRealIp));
    }

    #[test]
    fn malformed_client_ip_falls_back_to_peer() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert("x-client-ip", "definitely-not-an-ip".parse().unwrap());

        let trusted: Vec<IpNetwork> = vec!["10.0.0.0/8".parse().unwrap()];
        let (ip, fallback) = WafProxyService::resolve_client_ip_detailed(
            "10.0.0.5".parse().unwrap(),
            &headers,
            &trusted,
        );
        assert_eq!(ip, "10.0.0.5".parse::<IpAddr>().unwrap());
        assert_eq!(fallback, Some(ClientIpFallback::MalformedXClientIp));
    }

    #[test]
    fn malformed_forwarded_rfc7239_falls_back_to_peer() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert("forwarded", "for=not-an-ip;proto=https".parse().unwrap());

        let trusted: Vec<IpNetwork> = vec!["10.0.0.0/8".parse().unwrap()];
        let (ip, fallback) = WafProxyService::resolve_client_ip_detailed(
            "10.0.0.5".parse().unwrap(),
            &headers,
            &trusted,
        );
        assert_eq!(ip, "10.0.0.5".parse::<IpAddr>().unwrap());
        assert_eq!(fallback, Some(ClientIpFallback::MalformedForwarded));
    }

    #[test]
    fn forwarded_rfc7239_chain_handles_quotes_ipv6_and_ports() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert(
            "forwarded",
            "for=192.0.2.60;proto=https, for=\"[2001:db8:cafe::17]:4711\""
                .parse()
                .unwrap(),
        );

        let trusted: Vec<IpNetwork> = vec!["10.0.0.0/8".parse().unwrap()];
        let ip =
            WafProxyService::resolve_client_ip("10.0.0.5".parse().unwrap(), &headers, &trusted);
        assert_eq!(ip, "2001:db8:cafe::17".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn forwarded_chain_accepts_ipv6_and_port_forms() {
        for value in [
            "2001:db8::1",
            "[2001:db8::1]",
            "[2001:db8::1]:8443",
            "198.51.100.7:443",
        ] {
            let mut headers = hyper::HeaderMap::new();
            headers.insert("x-forwarded-for", value.parse().unwrap());
            let trusted: Vec<IpNetwork> = vec!["10.0.0.0/8".parse().unwrap()];
            let ip =
                WafProxyService::resolve_client_ip("10.0.0.5".parse().unwrap(), &headers, &trusted);
            let expected: IpAddr = if value.starts_with("198.") {
                "198.51.100.7".parse().unwrap()
            } else {
                "2001:db8::1".parse().unwrap()
            };
            assert_eq!(ip, expected, "failed to parse forwarding value {value}");
        }
    }

    #[test]
    fn forwarding_header_precedence_is_documented_order() {
        let trusted: Vec<IpNetwork> = vec!["10.0.0.0/8".parse().unwrap()];
        let peer: IpAddr = "10.0.0.5".parse().unwrap();

        let mut headers = hyper::HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.5".parse().unwrap());
        headers.insert("forwarded", "for=198.51.100.1".parse().unwrap());
        headers.insert("x-real-ip", "192.0.2.1".parse().unwrap());
        headers.insert("x-client-ip", "192.0.2.2".parse().unwrap());
        assert_eq!(
            WafProxyService::resolve_client_ip(peer, &headers, &trusted),
            "203.0.113.5".parse::<IpAddr>().unwrap()
        );

        let mut headers = hyper::HeaderMap::new();
        headers.insert("forwarded", "for=198.51.100.1".parse().unwrap());
        headers.insert("x-real-ip", "192.0.2.1".parse().unwrap());
        headers.insert("x-client-ip", "192.0.2.2".parse().unwrap());
        assert_eq!(
            WafProxyService::resolve_client_ip(peer, &headers, &trusted),
            "198.51.100.1".parse::<IpAddr>().unwrap()
        );

        let mut headers = hyper::HeaderMap::new();
        headers.insert("x-real-ip", "192.0.2.1".parse().unwrap());
        headers.insert("x-client-ip", "192.0.2.2".parse().unwrap());
        assert_eq!(
            WafProxyService::resolve_client_ip(peer, &headers, &trusted),
            "192.0.2.1".parse::<IpAddr>().unwrap()
        );

        let mut headers = hyper::HeaderMap::new();
        headers.insert("x-client-ip", "192.0.2.2".parse().unwrap());
        assert_eq!(
            WafProxyService::resolve_client_ip(peer, &headers, &trusted),
            "192.0.2.2".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn untrusted_peer_ignores_every_forwarding_header() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.5".parse().unwrap());
        headers.insert("forwarded", "for=198.51.100.1".parse().unwrap());
        headers.insert("x-real-ip", "192.0.2.1".parse().unwrap());
        headers.insert("x-client-ip", "192.0.2.2".parse().unwrap());

        let peer: IpAddr = "203.0.113.10".parse().unwrap();
        let (ip, fallback) = WafProxyService::resolve_client_ip_detailed(peer, &headers, &[]);
        assert_eq!(ip, peer);
        assert_eq!(fallback, None);
    }

    #[test]
    fn fully_trusted_forwarded_chain_uses_peer() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert("x-forwarded-for", "10.0.0.9, 10.0.0.8".parse().unwrap());

        let trusted: Vec<IpNetwork> = vec!["10.0.0.0/8".parse().unwrap()];
        let (ip, fallback) = WafProxyService::resolve_client_ip_detailed(
            "10.0.0.5".parse().unwrap(),
            &headers,
            &trusted,
        );
        assert_eq!(ip, "10.0.0.5".parse::<IpAddr>().unwrap());
        assert_eq!(fallback, None);
    }

    #[test]
    fn over_long_forwarded_chain_falls_back_to_peer() {
        let value = vec!["203.0.113.9"; MAX_FORWARDED_CHAIN_HOPS + 1].join(",");
        let mut headers = hyper::HeaderMap::new();
        headers.insert("x-forwarded-for", value.parse().unwrap());

        let trusted: Vec<IpNetwork> = vec!["10.0.0.0/8".parse().unwrap()];
        let (ip, fallback) = WafProxyService::resolve_client_ip_detailed(
            "10.0.0.5".parse().unwrap(),
            &headers,
            &trusted,
        );
        assert_eq!(ip, "10.0.0.5".parse::<IpAddr>().unwrap());
        assert_eq!(fallback, Some(ClientIpFallback::ForwardedChainTooLong));
    }

    #[test]
    fn oversized_forwarded_header_falls_back_to_peer() {
        let value = "1".repeat(MAX_FORWARDED_HEADER_BYTES + 1);
        let mut headers = hyper::HeaderMap::new();
        headers.insert("x-forwarded-for", value.parse().unwrap());

        let trusted: Vec<IpNetwork> = vec!["10.0.0.0/8".parse().unwrap()];
        let (ip, fallback) = WafProxyService::resolve_client_ip_detailed(
            "10.0.0.5".parse().unwrap(),
            &headers,
            &trusted,
        );
        assert_eq!(ip, "10.0.0.5".parse::<IpAddr>().unwrap());
        assert_eq!(fallback, Some(ClientIpFallback::ForwardedHeaderTooLarge));
    }

    #[test]
    fn rejected_forwarded_header_is_counted() {
        let metrics = Metrics::new();
        let mut headers = hyper::HeaderMap::new();
        headers.insert("x-forwarded-for", "not-an-ip".parse().unwrap());

        let trusted: Vec<IpNetwork> = vec!["10.0.0.0/8".parse().unwrap()];
        let ip = WafProxyService::resolve_client_ip_with_metrics(
            "10.0.0.5".parse().unwrap(),
            &headers,
            &trusted,
            &metrics,
        );
        assert_eq!(ip, "10.0.0.5".parse::<IpAddr>().unwrap());
        assert!(metrics
            .render_prometheus()
            .contains("waf_forwarded_header_rejected_total 1"));
    }

    #[test]
    fn upstream_health_uri_preserves_scheme_and_authority() {
        let base: Uri = "https://upstream.internal:8443/base".parse().unwrap();
        let health = upstream_health_uri(&base, "/healthz").unwrap();
        assert_eq!(health.scheme_str(), Some("https"));
        assert_eq!(
            health.authority().unwrap().as_str(),
            "upstream.internal:8443"
        );
        assert_eq!(health.path(), "/healthz");
        assert!(upstream_health_uri(&Uri::from_static("/relative"), "/healthz").is_none());
    }

    #[test]
    fn tuning_defaults_are_opt_in() {
        let config = Config::default();
        assert!(!config.proxy.pool.enabled);
        assert!(!config.proxy.streaming.enabled);
        assert!(!config.server.http2.enabled);
        config.validate().unwrap();
    }

    fn build_upstream_for_test(request: Request<ProxyBody>) -> Request<ProxyBody> {
        build_upstream_for_test_with_policy(request, &HeaderStripPolicy::defaults())
    }

    fn build_upstream_for_test_with_policy(
        request: Request<ProxyBody>,
        policy: &HeaderStripPolicy,
    ) -> Request<ProxyBody> {
        let (parts, body) = request.into_parts();
        let upstream: Uri = "http://upstream.local".parse().unwrap();
        match WafProxyService::build_upstream_request_with_policy(
            parts,
            body,
            &upstream,
            "1.1",
            "127.0.0.1".parse().unwrap(),
            false,
            policy,
        ) {
            Ok(request) => request,
            Err(_) => panic!("upstream request construction failed"),
        }
    }

    fn build_upstream_for_version(
        version: hyper::Version,
        http_version: &str,
    ) -> Request<ProxyBody> {
        let (parts, body) = Request::builder()
            .method("GET")
            .uri("/")
            .version(version)
            .body(ProxyBody::full(Bytes::new()))
            .unwrap()
            .into_parts();
        let upstream: Uri = "http://upstream.local".parse().unwrap();
        WafProxyService::build_upstream_request_with_policy(
            parts,
            body,
            &upstream,
            http_version,
            "127.0.0.1".parse().unwrap(),
            false,
            &HeaderStripPolicy::defaults(),
        )
        .unwrap_or_else(|_| panic!("upstream request construction failed"))
    }

    #[test]
    fn h2_downstream_defaults_to_http1_upstream() {
        let built = build_upstream_for_version(hyper::Version::HTTP_2, "2");
        assert_eq!(
            built.version(),
            hyper::Version::HTTP_11,
            "h2 ingress must not require an h2 origin"
        );
    }

    #[test]
    fn http1_downstream_uses_http1_upstream() {
        let built = build_upstream_for_version(hyper::Version::HTTP_11, "1.1");
        assert_eq!(built.version(), hyper::Version::HTTP_11);
    }

    #[test]
    fn multiplexed_grpc_keeps_http2_upstream() {
        let (mut parts, body) = Request::builder()
            .method("POST")
            .uri("/svc/Method")
            .version(hyper::Version::HTTP_2)
            .header("content-type", "application/grpc")
            .body(ProxyBody::full(Bytes::new()))
            .unwrap()
            .into_parts();
        parts.version = hyper::Version::HTTP_2;
        let upstream: Uri = "http://upstream.local".parse().unwrap();
        let built = WafProxyService::build_upstream_request_with_policy(
            parts,
            body,
            &upstream,
            "2",
            "127.0.0.1".parse().unwrap(),
            false,
            &HeaderStripPolicy::defaults(),
        )
        .unwrap_or_else(|_| panic!("upstream request construction failed"));
        assert_eq!(built.version(), hyper::Version::HTTP_2);
    }

    async fn probe_for(config: &Config) -> ReadinessSnapshot {
        let engine = Arc::new(WafEngine::with_config(config));
        ProxyReadinessProbe {
            engine,
            backend: "rust".to_string(),
        }
        .snapshot()
        .await
    }

    #[cfg(feature = "export-redb")]
    #[tokio::test]
    async fn readiness_probes_the_configured_redb_store() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let mut config = Config::default();
        config.waf.coraza.enabled = false;
        config.storage.enabled = true;
        config.storage.backend = "redb".to_string();
        config.storage.path = directory.path().join("audit.redb").display().to_string();

        let snapshot = probe_for(&config).await;
        let store = snapshot
            .dependencies
            .iter()
            .find(|dependency| dependency.name == "Redb")
            .expect("redb dependency must be probed");
        assert_eq!(store.status, "healthy");
        assert!(store.required);
        assert!(
            !snapshot
                .dependencies
                .iter()
                .any(|dependency| dependency.name == "Sled"),
            "a redb deployment must not report a Sled dependency"
        );
    }

    #[tokio::test]
    async fn readiness_reports_memory_when_no_store_is_configured() {
        let mut config = Config::default();
        config.waf.coraza.enabled = false;
        config.storage.enabled = false;

        let snapshot = probe_for(&config).await;
        assert!(
            !snapshot
                .dependencies
                .iter()
                .any(|dependency| matches!(dependency.name.as_str(), "Redb" | "Sled")),
            "in-memory event handling must not require a persistent store"
        );
    }

    #[tokio::test]
    async fn readiness_reports_a_genuinely_unavailable_store() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let mut config = Config::default();
        config.waf.coraza.enabled = false;
        config.storage.enabled = true;
        config.storage.backend = "redb".to_string();
        // A directory cannot be opened as a redb database file.
        config.storage.path = directory.path().display().to_string();

        let snapshot = probe_for(&config).await;
        let store = snapshot
            .dependencies
            .iter()
            .find(|dependency| dependency.name == "Redb")
            .expect("configured redb dependency must still be reported");
        assert_eq!(store.status, "down");
        assert!(store.required);
    }

    #[cfg(feature = "export-sled")]
    #[tokio::test]
    async fn readiness_probes_the_configured_sled_store() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let mut config = Config::default();
        config.waf.coraza.enabled = false;
        config.storage.enabled = true;
        config.storage.backend = "sled".to_string();
        config.storage.path = directory.path().join("audit.sled").display().to_string();

        let snapshot = probe_for(&config).await;
        let store = snapshot
            .dependencies
            .iter()
            .find(|dependency| dependency.name == "Sled")
            .expect("sled dependency must be probed");
        assert_eq!(store.status, "healthy");
    }

    #[test]
    fn client_routing_and_override_headers_are_not_forwarded() {
        let request = Request::builder()
            .method("GET")
            .uri("/public")
            .header("x-original-url", "/admin")
            .header("x-rewrite-url", "/admin")
            .header("x-forwarded-prefix", "/admin")
            .header("x-forwarded-port", "8443")
            .header("x-forwarded-host", "admin.internal")
            .header("x-http-method-override", "DELETE")
            .header("x-method-override", "DELETE")
            .header("x-forwarded-server", "admin.internal")
            .header("x-host", "admin.internal")
            .header("forwarded", "for=203.0.113.9")
            .header("x-forwarded-custom", "attacker-controlled")
            .body(ProxyBody::full(Bytes::new()))
            .unwrap();

        let built = build_upstream_for_test(request);
        for name in [
            "x-original-url",
            "x-rewrite-url",
            "x-forwarded-prefix",
            "x-forwarded-port",
            "x-forwarded-host",
            "x-http-method-override",
            "x-method-override",
            "x-forwarded-server",
            "x-host",
            "forwarded",
            "x-forwarded-custom",
        ] {
            assert!(
                built.headers().get(name).is_none(),
                "client-controlled header {name} must not reach the upstream"
            );
        }
        assert_eq!(built.method(), hyper::Method::GET);
        assert_eq!(built.uri().path(), "/public");
    }

    #[test]
    fn connection_nominated_headers_are_stripped() {
        let request = Request::builder()
            .method("GET")
            .uri("/public")
            .header("connection", "X-Custom-Hop, Content-Length")
            .header("x-custom-hop", "secret")
            .header("content-length", "5")
            .header("x-keep", "yes")
            .body(ProxyBody::full(Bytes::from_static(b"abc")))
            .unwrap();

        let built = build_upstream_for_test(request);
        assert!(
            built.headers().get("x-custom-hop").is_none(),
            "Connection-nominated header must not reach the upstream"
        );
        assert_eq!(
            built
                .headers()
                .get("content-length")
                .and_then(|value| value.to_str().ok()),
            Some("3"),
            "the upstream must receive the WAF's exact body length, not the client's"
        );
        assert_eq!(
            built
                .headers()
                .get("x-keep")
                .and_then(|value| value.to_str().ok()),
            Some("yes")
        );
    }

    #[test]
    fn websocket_upgrade_body_headers_are_rejected() {
        assert!(!websocket_upgrade_has_body(&HeaderMap::new()));

        let mut headers = HeaderMap::new();
        headers.insert(hyper::header::CONTENT_LENGTH, "0".parse().unwrap());
        assert!(!websocket_upgrade_has_body(&headers));

        headers.insert(hyper::header::CONTENT_LENGTH, "5".parse().unwrap());
        assert!(websocket_upgrade_has_body(&headers));

        let mut headers = HeaderMap::new();
        headers.insert(hyper::header::TRANSFER_ENCODING, "chunked".parse().unwrap());
        assert!(websocket_upgrade_has_body(&headers));

        let mut headers = HeaderMap::new();
        headers.insert(hyper::header::CONTENT_ENCODING, "gzip".parse().unwrap());
        assert!(websocket_upgrade_has_body(&headers));
    }

    #[test]
    fn normal_custom_headers_are_still_forwarded() {
        let request = Request::builder()
            .method("GET")
            .uri("/public")
            .header("x-request-id", "abc-123")
            .header("x-custom-header", "keep-me")
            .body(ProxyBody::full(Bytes::new()))
            .unwrap();

        let built = build_upstream_for_test(request);
        assert_eq!(
            built
                .headers()
                .get("x-request-id")
                .and_then(|value| value.to_str().ok()),
            Some("abc-123")
        );
        assert_eq!(
            built
                .headers()
                .get("x-custom-header")
                .and_then(|value| value.to_str().ok()),
            Some("keep-me")
        );
    }

    #[test]
    fn config_strip_headers_extend_keeps_defaults_and_adds_names() {
        let mut config = ProxyConfig::default();
        config.strip_headers = vec!["x-custom-routing".to_string()];
        config.strip_headers_mode = HeaderStripMode::Extend;
        let policy = HeaderStripPolicy::from_config(&config);
        assert!(policy.should_strip("x-original-url"));
        assert!(policy.should_strip("x-forwarded-anything"));
        assert!(policy.should_strip("x-custom-routing"));
        assert!(!policy.should_strip("x-request-id"));
    }

    #[test]
    fn config_strip_headers_replace_uses_only_configured_names() {
        let mut config = ProxyConfig::default();
        config.strip_headers = vec!["x-custom-routing".to_string()];
        config.strip_headers_mode = HeaderStripMode::Replace;
        let policy = HeaderStripPolicy::from_config(&config);
        assert!(policy.should_strip("x-custom-routing"));
        assert!(!policy.should_strip("x-original-url"));
        assert!(!policy.should_strip("x-forwarded-host"));
        assert!(!policy.should_strip("x-forwarded-for"));
    }

    #[test]
    fn reject_mode_detects_routing_headers_but_not_identity_headers() {
        let config = ProxyConfig::default();
        let policy = HeaderStripPolicy::from_config(&config);
        let mut headers = HeaderMap::new();
        headers.insert("x-original-url", "/admin".parse().unwrap());
        assert_eq!(policy.first_ambiguous(&headers), Some("x-original-url"));

        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.9".parse().unwrap());
        headers.insert("x-real-ip", "203.0.113.9".parse().unwrap());
        headers.insert("x-forwarded-proto", "https".parse().unwrap());
        assert_eq!(policy.first_ambiguous(&headers), None);

        let mut headers = HeaderMap::new();
        headers.insert("x-request-id", "abc".parse().unwrap());
        assert_eq!(policy.first_ambiguous(&headers), None);
    }

    #[test]
    fn default_strip_headers_cover_forwarded_and_override_families() {
        let policy = HeaderStripPolicy::defaults();
        for name in [
            "x-original-url",
            "x-rewrite-url",
            "x-http-method-override",
            "x-method-override",
            "x-forwarded-prefix",
            "x-forwarded-host",
            "x-forwarded-server",
            "x-forwarded-port",
            "x-forwarded-for",
            "x-forwarded-proto",
            "x-real-ip",
            "forwarded",
            "x-host",
            "x-forwarded-future",
        ] {
            assert!(policy.should_strip(name), "{name} must be stripped");
        }
    }

    #[test]
    fn websocket_control_frame_validation_rejects_oversized_and_invalid_close() {
        let oversized = Message::Ping(vec![0u8; 126].into());
        let close = WafProxyService::websocket_control_violation(&oversized);
        assert_eq!(close.map(|frame| frame.code), Some(CloseCode::Protocol));

        let invalid_close = Message::Close(Some(CloseFrame {
            code: CloseCode::from(1005),
            reason: "status code must not be sent".into(),
        }));
        let close = WafProxyService::websocket_control_violation(&invalid_close);
        assert_eq!(close.map(|frame| frame.code), Some(CloseCode::Protocol));

        let valid = Message::Ping(vec![0u8; 125].into());
        assert!(WafProxyService::websocket_control_violation(&valid).is_none());
    }

    #[test]
    fn websocket_protocol_errors_map_to_protocol_close() {
        use tokio_tungstenite::tungstenite::error::ProtocolError;

        let close = WafProxyService::websocket_error_close(&WsError::Protocol(
            ProtocolError::FragmentedControlFrame,
        ))
        .expect("protocol error must close");
        assert_eq!(close.code, CloseCode::Protocol);

        let close = WafProxyService::websocket_error_close(&WsError::Protocol(
            ProtocolError::ControlFrameTooBig,
        ))
        .expect("protocol error must close");
        assert_eq!(close.code, CloseCode::Protocol);
    }

    #[test]
    fn websocket_handshake_parses_valid_response_headers() {
        let head = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: abc\r\n\r\n";
        let (status, headers) = parse_websocket_handshake_head(head).unwrap();
        assert_eq!(status, 101);
        assert_eq!(headers.get("sec-websocket-accept").unwrap(), "abc");
        assert!(!headers.contains_key("upgrade"));
        assert!(!headers.contains_key("connection"));
    }

    #[test]
    fn websocket_handshake_rejects_invalid_header_name() {
        let head = "HTTP/1.1 101 Switching Protocols\r\nBad Header: value\r\n\r\n";
        assert!(matches!(
            parse_websocket_handshake_head(head),
            Err(WafError::Upstream(_))
        ));
    }

    #[test]
    fn websocket_handshake_rejects_invalid_header_value() {
        let head = "HTTP/1.1 101 Switching Protocols\r\nX-Test: bad\u{7f}value\r\n\r\n";
        assert!(matches!(
            parse_websocket_handshake_head(head),
            Err(WafError::Upstream(_))
        ));
    }

    #[test]
    fn websocket_handshake_rejects_malformed_lines_and_status() {
        assert!(matches!(
            parse_websocket_handshake_head("HTTP/1.1 101 OK\r\nnot-a-header\r\n\r\n"),
            Err(WafError::Upstream(_))
        ));
        assert!(matches!(
            parse_websocket_handshake_head("not-http\r\n\r\n"),
            Err(WafError::Upstream(_))
        ));
        assert!(matches!(
            parse_websocket_handshake_head("HTTP/1.1 nope\r\n\r\n"),
            Err(WafError::Upstream(_))
        ));
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        /// Arbitrary (possibly malformed) forwarding headers must never panic,
        /// and an untrusted peer must never have its address overridden.
        #[test]
        fn resolve_client_ip_never_panics_for_arbitrary_headers(
            forwarded in any::<String>(),
            real_ip in any::<String>(),
            peer_last_octet in any::<u8>(),
            trust_peer in any::<bool>(),
        ) {
            let mut headers = hyper::HeaderMap::new();
            if let Ok(value) = forwarded.parse() {
                headers.insert("x-forwarded-for", value);
            }
            if let Ok(value) = real_ip.parse() {
                headers.insert("x-real-ip", value);
            }

            let peer = IpAddr::from([10, 0, 0, peer_last_octet]);
            let trusted: Vec<IpNetwork> = if trust_peer {
                vec!["10.0.0.0/8".parse().unwrap()]
            } else {
                Vec::new()
            };

            let resolved = WafProxyService::resolve_client_ip(peer, &headers, &trusted);

            if !trust_peer {
                prop_assert_eq!(resolved, peer);
            }
        }
    }

    struct FakeResponseEvaluator {
        decision: Decision,
        seen_body_len: std::sync::Mutex<Option<usize>>,
        panic: bool,
    }

    impl crate::waf::ResponseEvaluator for FakeResponseEvaluator {
        fn evaluate_response(
            &self,
            _request: &RequestContext,
            response: &ResponseContext,
            _options: &ResponseInspectionOptions,
        ) -> Decision {
            if self.panic {
                panic!("simulated response engine failure");
            }
            *self.seen_body_len.lock().unwrap() = response.body.as_ref().map(Bytes::len);
            self.decision.clone()
        }
    }

    fn response_test_context() -> RequestContext {
        RequestContext::new(
            "127.0.0.1".parse().unwrap(),
            hyper::Method::GET,
            "/".parse().unwrap(),
            HeaderMap::new(),
            None,
        )
    }

    fn response_test_config() -> crate::config::ResponseInspectionConfig {
        crate::config::ResponseInspectionConfig {
            enabled: true,
            inspect_body: true,
            max_body_bytes: 4,
            block_status: 403,
        }
    }

    #[tokio::test]
    async fn response_inspection_disabled_by_default() {
        let config = crate::config::ResponseInspectionConfig::default();
        assert!(!config.enabled);
        assert!(!config.inspect_body);
        let engine = Arc::new(WafEngine::new());
        let metrics = Metrics::new();
        let request = response_test_context();
        let inspection = ResponseInspectionRequest {
            request: &request,
            config: &config,
        };
        let decision = WafProxyService::inspect_upstream_response(
            &engine,
            &metrics,
            &inspection,
            200,
            "HTTP/1.1",
            &[],
            Some(b"evil"),
        )
        .await;
        assert!(decision.is_none());
    }

    #[tokio::test]
    async fn response_inspection_blocks_and_truncates_body() {
        let evaluator = Arc::new(FakeResponseEvaluator {
            decision: Decision::Block {
                status: 403,
                reason: "response rule".to_string(),
            },
            seen_body_len: std::sync::Mutex::new(None),
            panic: false,
        });
        let mut engine = WafEngine::new();
        engine.set_response_evaluator(evaluator.clone());
        let engine = Arc::new(engine);
        let metrics = Metrics::new();
        let request = response_test_context();
        let config = response_test_config();
        let inspection = ResponseInspectionRequest {
            request: &request,
            config: &config,
        };
        let decision = WafProxyService::inspect_upstream_response(
            &engine,
            &metrics,
            &inspection,
            200,
            "HTTP/1.1",
            &[],
            Some(b"0123456789"),
        )
        .await;
        assert!(matches!(decision, Some(Decision::Block { .. })));
        assert_eq!(*evaluator.seen_body_len.lock().unwrap(), Some(4));
    }

    #[tokio::test]
    async fn response_inspection_fails_closed_on_engine_panic() {
        let evaluator = Arc::new(FakeResponseEvaluator {
            decision: Decision::Allow,
            seen_body_len: std::sync::Mutex::new(None),
            panic: true,
        });
        let mut engine = WafEngine::new();
        engine.set_response_evaluator(evaluator);
        let engine = Arc::new(engine);
        let metrics = Metrics::new();
        let request = response_test_context();
        let config = response_test_config();
        let inspection = ResponseInspectionRequest {
            request: &request,
            config: &config,
        };
        let decision = WafProxyService::inspect_upstream_response(
            &engine,
            &metrics,
            &inspection,
            200,
            "HTTP/1.1",
            &[],
            Some(b"benign"),
        )
        .await;
        assert!(matches!(
            decision,
            Some(Decision::Block { status: 500, .. })
        ));
    }

    #[tokio::test]
    async fn response_inspection_without_evaluator_is_skipped() {
        let engine = Arc::new(WafEngine::new());
        let metrics = Metrics::new();
        let request = response_test_context();
        let config = response_test_config();
        let inspection = ResponseInspectionRequest {
            request: &request,
            config: &config,
        };
        let decision = WafProxyService::inspect_upstream_response(
            &engine,
            &metrics,
            &inspection,
            200,
            "HTTP/1.1",
            &[],
            Some(b"benign"),
        )
        .await;
        assert!(decision.is_none());
    }

    #[tokio::test]
    async fn response_inspection_runs_on_h2_upstream_response() {
        use http_body_util::Full;
        use hyper::service::service_fn;
        use hyper_util::rt::TokioIo;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (stream, _) = match listener.accept().await {
                    Ok(value) => value,
                    Err(_) => break,
                };
                tokio::spawn(async move {
                    let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                        .serve_connection(
                            TokioIo::new(stream),
                            service_fn(|_req: Request<Incoming>| async {
                                Ok::<_, Infallible>(
                                    Response::builder()
                                        .status(StatusCode::OK)
                                        .body(Full::new(Bytes::from_static(b"h2-benign")))
                                        .unwrap(),
                                )
                            }),
                        )
                        .await;
                });
            }
        });

        let tls = build_upstream_tls_config(None, None, None).unwrap();
        let connector = HttpsConnectorBuilder::new()
            .with_tls_config(tls)
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .wrap_connector(HttpConnector::new());
        let connector = UpstreamConnector {
            inner: connector,
            metrics: Arc::new(Metrics::new()),
        };
        let client = Client::builder(TokioExecutor::new())
            .http2_only(true)
            .build(connector);

        let evaluator = Arc::new(FakeResponseEvaluator {
            decision: Decision::Allow,
            seen_body_len: std::sync::Mutex::new(None),
            panic: false,
        });
        let mut engine = WafEngine::new();
        engine.set_response_evaluator(evaluator.clone());
        let engine = Arc::new(engine);
        let metrics = Metrics::new();
        let request = response_test_context();
        let config = response_test_config();
        let inspection = ResponseInspectionRequest {
            request: &request,
            config: &config,
        };

        let req = Request::builder().method("GET").uri("/").body(()).unwrap();
        let (parts, _) = req.into_parts();
        let response = WafProxyService::forward_to_upstream_with_protocol(
            parts,
            ProxyBody::buffered(Bytes::new(), None),
            client,
            format!("http://{upstream_addr}").parse().unwrap(),
            Instant::now(),
            "2",
            &engine,
            &metrics,
            "127.0.0.1".parse().unwrap(),
            false,
            Duration::from_secs(30),
            1024 * 1024,
            None,
            &HeaderStripPolicy::from_config(&ProxyConfig::default()),
            Some(inspection),
        )
        .await
        .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"h2-benign");
        // The inspection prefix is capped at `max_body_bytes` (4 in the test
        // config); the full body is still relayed.
        assert_eq!(*evaluator.seen_body_len.lock().unwrap(), Some(4));
    }

    #[tokio::test]
    async fn configured_upstream_timeout_aborts_the_exchange() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            // Accept but never answer, so only the configured timeout can end
            // the exchange.
            let (_stream, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(10)).await;
        });

        let tls = build_upstream_tls_config(None, None, None).unwrap();
        let connector = HttpsConnectorBuilder::new()
            .with_tls_config(tls)
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .wrap_connector(HttpConnector::new());
        let connector = UpstreamConnector {
            inner: connector,
            metrics: Arc::new(Metrics::new()),
        };
        let client = Client::builder(TokioExecutor::new()).build(connector);

        let request = Request::builder().method("GET").uri("/").body(()).unwrap();
        let (parts, _) = request.into_parts();
        let started = Instant::now();
        let response = WafProxyService::forward_to_upstream_with_protocol(
            parts,
            ProxyBody::buffered(Bytes::new(), None),
            client,
            format!("http://{upstream_addr}").parse().unwrap(),
            Instant::now(),
            "1.1",
            &Arc::new(WafEngine::new()),
            &Metrics::new(),
            "127.0.0.1".parse().unwrap(),
            false,
            Duration::from_millis(200),
            1024 * 1024,
            None,
            &HeaderStripPolicy::from_config(&ProxyConfig::default()),
            None,
        )
        .await
        .unwrap();

        assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "a 200ms upstream timeout must not wait for the hard-coded 30s"
        );
    }

    #[test]
    fn grpc_requests_are_detected_for_response_skip() {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", "application/grpc+proto".parse().unwrap());
        let request = RequestContext::new(
            "127.0.0.1".parse().unwrap(),
            hyper::Method::POST,
            "/svc/Method".parse().unwrap(),
            headers,
            None,
        );
        assert!(is_grpc_request(&request));
    }

    async fn collect_body(response: Response<ProxyBody>) -> String {
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    fn hostile_reasons() -> Vec<String> {
        vec![
            "Content inspection: SQL Injection - UNION SELECT detected in body: ' UNION\nSELECT SECRET_PAYLOAD".to_string(),
            "Content inspection: SQL Injection - UNION SELECT detected in body: ' UNION\r\nSELECT SECRET_PAYLOAD".to_string(),
            "Content inspection: XSS detected in body: <script>\0SECRET_PAYLOAD</script>".to_string(),
            "Content inspection: XSS detected in body: <script>\u{7f}SECRET_PAYLOAD</script>".to_string(),
            "Content inspection: XSS detected in body: <script>héllo→SECRET_PAYLOAD</script>".to_string(),
            format!(
                "Content inspection: SQL Injection - UNION SELECT detected in body: {}SECRET_PAYLOAD",
                "A".repeat(4096)
            ),
        ]
    }

    #[tokio::test]
    async fn blocked_response_sanitises_hostile_reasons_without_echoing_payload() {
        for reason in hostile_reasons() {
            let response = WafProxyService::create_blocked_response(403, &reason);
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
            assert_eq!(response.headers().get("x-waf-decision").unwrap(), "block");
            let rule_id = response
                .headers()
                .get("x-waf-rule-id")
                .expect("rule id header")
                .to_str()
                .unwrap()
                .to_string();
            assert!(
                HeaderValue::from_str(&rule_id).is_ok(),
                "rule id must be a valid header value"
            );
            assert!(response.headers().get("x-waf-reason").is_none());
            let body = collect_body(response).await;
            assert!(
                !body.contains("SECRET_PAYLOAD"),
                "client body must not echo the matched payload: {body}"
            );
            assert!(body.contains(&rule_id));
        }
    }

    #[tokio::test]
    async fn blocked_response_uses_fixed_rule_id_vocabulary() {
        let response = WafProxyService::create_blocked_response(
            403,
            "Content inspection: SQL Injection - UNION SELECT detected in query: 1 UNION SELECT SECRET",
        );
        assert_eq!(
            response.headers().get("x-waf-rule-id").unwrap(),
            "sql-injection"
        );
        let body = collect_body(response).await;
        assert!(body.contains("rule: sql-injection"));
        assert!(!body.contains("SECRET"));
        assert!(!body.contains("UNION SELECT"));
    }

    #[tokio::test]
    async fn rate_limit_response_sanitises_hostile_reason_without_echoing_it() {
        for reason in hostile_reasons() {
            let response = WafProxyService::create_rate_limit_response(&reason);
            assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
            assert_eq!(
                response.headers().get("x-waf-decision").unwrap(),
                "rate-limit"
            );
            assert_eq!(
                response.headers().get("x-waf-rule-id").unwrap(),
                "rate-limit"
            );
            assert!(response.headers().get("x-waf-reason").is_none());
            let body = collect_body(response).await;
            assert!(!body.contains("SECRET_PAYLOAD"));
        }
    }

    #[tokio::test]
    async fn grpc_blocked_response_sanitises_hostile_reason_without_echoing_it() {
        for reason in hostile_reasons() {
            let (parts, body) =
                WafProxyService::create_grpc_blocked_response(403, &reason).into_parts();
            assert_eq!(parts.status, StatusCode::OK);
            assert!(parts.headers.get("x-waf-reason").is_none());
            let rule_id = parts.headers.get("x-waf-rule-id").expect("rule id header");
            assert!(HeaderValue::from_str(rule_id.to_str().unwrap()).is_ok());

            let mut body = std::pin::pin!(body);
            let mut trailers = None;
            let mut data = Vec::new();
            while let Some(frame) = body.frame().await {
                let frame = frame.unwrap();
                match frame.into_data() {
                    Ok(bytes) => data.extend_from_slice(&bytes),
                    Err(frame) => {
                        if let Ok(block) = frame.into_trailers() {
                            trailers = Some(block);
                        }
                    }
                }
            }
            assert!(data.is_empty(), "gRPC rejection body must be empty");
            let trailers = trailers.expect("gRPC trailers must carry the status");
            assert_eq!(trailers.get("grpc-status").unwrap(), "7");
            let message = trailers
                .get("grpc-message")
                .expect("grpc-message must be present");
            assert!(HeaderValue::from_str(message.to_str().unwrap()).is_ok());
            assert!(!message.to_str().unwrap().contains("SECRET_PAYLOAD"));
        }
    }

    #[test]
    fn sanitiser_output_always_parses_as_header_value() {
        let long = "A".repeat(4096);
        let cases = [
            "\n",
            "\r\n",
            "\0",
            "\u{7f}",
            "héllo→world",
            long.as_str(),
            "\t\tmultiple\t\t\ttabs",
            "  leading and trailing  ",
        ];
        for reason in cases {
            let sanitized = sanitize_reason(reason);
            assert!(
                HeaderValue::from_str(&sanitized).is_ok(),
                "sanitiser produced an invalid header value for {reason:?}: {sanitized:?}"
            );
            assert!(sanitized.len() <= MAX_SANITISED_REASON_BYTES);
            assert!(
                sanitized
                    .chars()
                    .all(|c| c == '\t' || (' '..='~').contains(&c)),
                "sanitiser leaked a non-visible character: {sanitized:?}"
            );
            assert!(!sanitized.contains('\n') && !sanitized.contains('\r'));
        }
    }

    proptest! {
        #[test]
        fn sanitiser_is_total_for_arbitrary_strings(reason in any::<String>()) {
            let sanitized = sanitize_reason(&reason);
            prop_assert!(HeaderValue::from_str(&sanitized).is_ok());
            prop_assert!(sanitized.len() <= MAX_SANITISED_REASON_BYTES);
        }
    }
}
