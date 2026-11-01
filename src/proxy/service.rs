use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode, Uri};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use ipnetwork::IpNetwork;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;
use tokio_tungstenite::tungstenite::protocol::Role;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;
use tracing::{debug, error, info, warn};

use crate::config::Config;
use crate::error::WafError;
use crate::metrics::Metrics;
use crate::proxy::buffer_pool::{BodyReadError, BufferPool};
use crate::proxy::decompression::{
    decompress_request_body, strip_encoding_headers, DecompressionError,
};
use crate::proxy::framing::validate_request_framing;
use crate::proxy::websocket::WebSocketHandler;
use crate::waf::auth::{ApiKeyValidator, InMemoryKeyStore};
use crate::waf::tls_config::TlsManager;
use crate::waf::{Decision, RequestContext, WafEngine};

/// Core WAF Proxy Service with multi-protocol support
///
/// This is the main HTTP proxy service that integrates the WAF engine
/// into the request/response pipeline. It follows the Strategic Roadmap
/// v0.1 requirements for establishing a stable core before WASM integration.
/// Supports HTTP/1.0-3, WebSocket, and WebTransport protocols.
pub struct WafProxyService {
    waf_engine: Arc<WafEngine>,
    upstream_client: Client<HttpsConnector<HttpConnector>, Full<Bytes>>,
    upstream_uri: Uri,
    config: Arc<Config>,
    buffer_pool: Arc<BufferPool>,
    websocket_handler: WebSocketHandler,
    tls_manager: Option<Arc<TlsManager>>,
    auth_validator: Option<Arc<ApiKeyValidator>>,
    trusted_proxies: Vec<IpNetwork>,
    metrics: Arc<Metrics>,
}

/// Upstream byte stream, either plain TCP or TLS over TCP.
trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncStream for T {}

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

/// Per-connection state cloned into each hyper service invocation.
#[derive(Clone)]
pub(crate) struct ProxyState {
    pub(crate) waf_engine: Arc<WafEngine>,
    pub(crate) upstream_client: Client<HttpsConnector<HttpConnector>, Full<Bytes>>,
    pub(crate) upstream_uri: Uri,
    pub(crate) config: Arc<Config>,
    pub(crate) buffer_pool: Arc<BufferPool>,
    pub(crate) auth_validator: Option<Arc<ApiKeyValidator>>,
    pub(crate) trusted_proxies: Arc<Vec<IpNetwork>>,
    pub(crate) metrics: Arc<Metrics>,
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

impl WafProxyService {
    /// Create a new WAF proxy service with optimized connection pooling
    pub fn new(config: Config) -> Result<Self, WafError> {
        info!("Initializing WAF Proxy Service with performance optimizations");

        let waf_engine = Arc::new(WafEngine::with_config(&config));

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

        // Create HTTP client with optimized configuration for all protocols
        let upstream_client = Client::builder(TokioExecutor::new())
            .http1_title_case_headers(true)
            .http1_preserve_header_case(true)
            .http2_only(false) // Support HTTP/1.x and HTTP/2
            .build(connector);

        // Parse upstream URI from config using the helper method
        let upstream_uri = config
            .upstream_uri()
            .map_err(|e| WafError::internal(format!("Invalid upstream URL: {}", e)))?;

        let config_arc = Arc::new(config);

        // Initialize protocol handlers
        let websocket_handler =
            WebSocketHandler::new(Arc::clone(&waf_engine), Arc::clone(&config_arc));

        let tls_manager = if config_arc.server.tls.enabled {
            let manager = TlsManager::new(config_arc.server.tls.clone())?;
            Some(Arc::new(manager))
        } else {
            None
        };

        let auth_validator = if config_arc.security.auth.enabled {
            let store = Arc::new(InMemoryKeyStore::from_raw_keys(
                &config_arc.security.auth.api_keys,
            ));
            info!(
                "API key authentication enabled ({} key(s), header '{}')",
                config_arc.security.auth.api_keys.len(),
                config_arc.security.auth.header_name
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

        let metrics = Arc::new(Metrics::new());

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
        let bind_addr = listener
            .local_addr()
            .map_err(|e| WafError::internal(format!("Failed to read listener address: {}", e)))?;

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
            metrics: Arc::clone(&self.metrics),
        };

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

        loop {
            let (tcp_stream, remote_addr) = listener
                .accept()
                .await
                .map_err(|e| WafError::internal(format!("Failed to accept connection: {}", e)))?;

            let tls_manager = self.tls_manager.clone();
            let state = state.clone();
            let peer_ip = remote_addr.ip();

            tokio::task::spawn(async move {
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
        stream: S,
        state: ProxyState,
        peer_ip: IpAddr,
        is_https: bool,
        negotiated_h2: bool,
    ) -> Result<(), WafError>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
    {
        let io = hyper_util::rt::TokioIo::new(stream);
        // HTTP/2 over cleartext requires h2c negotiation/prior knowledge.
        // Plaintext listeners therefore speak HTTP/1.1; HTTP/2 is enabled only
        // when TLS ALPN negotiated h2.
        let enable_http2 = negotiated_h2 && state.config.server.enable_http2;
        let service =
            service_fn(move |req| Self::handle_request(req, state.clone(), peer_ip, is_https));

        if enable_http2 {
            hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                .keep_alive_interval(Some(Duration::from_secs(30)))
                .keep_alive_timeout(Duration::from_secs(10))
                .serve_connection(io, service)
                .await
                .map_err(|e| WafError::NetworkError(format!("HTTP/2 connection error: {}", e)))
        } else {
            let mut builder = hyper::server::conn::http1::Builder::new();
            builder.keep_alive(true).pipeline_flush(true);
            builder
                .serve_connection(io, service)
                .with_upgrades()
                .await
                .map_err(|e| WafError::NetworkError(format!("HTTP/1.1 connection error: {}", e)))
        }
    }

    /// Handle incoming HTTP requests with multi-protocol support
    async fn handle_request(
        req: Request<Incoming>,
        state: ProxyState,
        peer_ip: IpAddr,
        is_https: bool,
    ) -> Result<Response<Full<Bytes>>, Infallible> {
        let start_time = Instant::now();
        state.metrics.record_request();

        // Detect HTTP protocol version
        let http_version = Self::detect_http_version(&req);
        debug!("Detected HTTP version: {}", http_version);

        // Check if HTTP version is supported
        if !Self::is_http_version_supported(&http_version, &state.config) {
            warn!("Unsupported HTTP version: {}", http_version);
            return Ok(Self::create_error_response(
                StatusCode::HTTP_VERSION_NOT_SUPPORTED,
                &format!("HTTP version {} not supported", http_version),
            ));
        }

        let client_ip = Self::resolve_client_ip(peer_ip, req.headers(), &state.trusted_proxies);

        // Reject ambiguous request framing before any body is read. Details are
        // intentionally not exposed to the client.
        if let Err(e) = validate_request_framing(req.headers()) {
            warn!(
                "Rejected ambiguous request framing from {}: {}",
                client_ip, e
            );
            state.metrics.record_blocked();
            state.metrics.record_request_duration(start_time.elapsed());
            return Ok(Self::create_error_response(
                StatusCode::BAD_REQUEST,
                "Bad Request",
            ));
        }

        // Authentication is a first-class pipeline stage, not an unused module.
        if let Some(validator) = &state.auth_validator {
            if let Err(e) = validator.validate_request(req.headers(), is_https) {
                warn!("Authentication rejected request from {}: {}", client_ip, e);
                state.metrics.record_auth_failure();
                state.metrics.record_blocked();
                state.metrics.record_request_duration(start_time.elapsed());
                return Ok(Self::create_error_response(
                    StatusCode::UNAUTHORIZED,
                    "Unauthorized",
                ));
            }
        }

        // Proxy WebSocket upgrades end-to-end over a raw upstream connection.
        if WebSocketHandler::is_websocket_upgrade(req.headers()) {
            if req.version() != hyper::Version::HTTP_11 {
                state.metrics.record_blocked();
                state.metrics.record_request_duration(start_time.elapsed());
                return Ok(Self::create_error_response(
                    StatusCode::NOT_IMPLEMENTED,
                    "WebSocket upgrades require HTTP/1.1",
                ));
            }

            // The upgrade request must pass the WAF before any tunneling.
            let upgrade_context = RequestContext::with_http_version(
                client_ip,
                req.method().clone(),
                req.uri().clone(),
                req.headers().clone(),
                None,
                http_version.clone(),
            );
            match state.waf_engine.evaluate(&upgrade_context).await {
                Decision::Allow => {}
                Decision::Block { status, reason } => {
                    warn!(
                        "WAF blocked WebSocket upgrade from {}: {} (status: {})",
                        client_ip, reason, status
                    );
                    state.metrics.record_blocked();
                    state.metrics.record_request_duration(start_time.elapsed());
                    return Ok(Self::create_blocked_response(status, &reason));
                }
                Decision::RateLimit { reason } => {
                    warn!(
                        "WAF rate limited WebSocket upgrade from {}: {}",
                        client_ip, reason
                    );
                    state.metrics.record_rate_limited();
                    state.metrics.record_blocked();
                    state.metrics.record_request_duration(start_time.elapsed());
                    return Ok(Self::create_rate_limit_response(&reason));
                }
            }

            return Ok(Self::proxy_websocket(req, &state, client_ip).await);
        }
        #[cfg(feature = "webtransport")]
        if is_webtransport_upgrade(req.headers()) {
            warn!("WebTransport request rejected: not implemented");
            state.metrics.record_blocked();
            state.metrics.record_request_duration(start_time.elapsed());
            return Ok(Self::create_error_response(
                StatusCode::NOT_IMPLEMENTED,
                "WebTransport is not implemented",
            ));
        }

        let (mut parts, body) = req.into_parts();
        let has_content_encoding = parts.headers.contains_key(hyper::header::CONTENT_ENCODING);
        let size_hint = parts
            .headers
            .get(hyper::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<usize>().ok());
        let max_body_size = state.config.server.max_body_size;

        let body_bytes = match tokio::time::timeout(
            Duration::from_secs(state.config.server.request_timeout_secs.max(1)),
            state
                .buffer_pool
                .read_incoming_body(body, size_hint, Some(max_body_size)),
        )
        .await
        {
            Ok(Ok(buffer)) => buffer.to_bytes(),
            Ok(Err(BodyReadError::TooLarge { .. })) => {
                warn!(
                    "Request body from {} exceeds limit {}",
                    client_ip, max_body_size
                );
                state.metrics.record_blocked();
                state.metrics.record_request_duration(start_time.elapsed());
                return Ok(Self::create_error_response(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "Request body too large",
                ));
            }
            Ok(Err(e)) => {
                warn!("Failed to read request body from {}: {}", client_ip, e);
                return Ok(Self::create_error_response(
                    StatusCode::BAD_REQUEST,
                    "Failed to read request body",
                ));
            }
            Err(_) => {
                warn!("Request body read timed out for {}", client_ip);
                return Ok(Self::create_error_response(
                    StatusCode::REQUEST_TIMEOUT,
                    "Request body timeout",
                ));
            }
        };

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
                    state.metrics.record_blocked();
                    return Ok(Self::create_error_response(
                        StatusCode::PAYLOAD_TOO_LARGE,
                        "Decompressed request body too large",
                    ));
                }
                Err(DecompressionError::Malformed) => {
                    warn!("Malformed compressed request body from {}", client_ip);
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
        let request_context = RequestContext::with_http_version(
            client_ip,
            parts.method.clone(),
            parts.uri.clone(),
            parts.headers.clone(),
            Some(body_bytes.len()),
            http_version.clone(),
        )
        .with_body(Some(body_bytes.clone()));

        let decision = state.waf_engine.evaluate(&request_context).await;

        match decision {
            Decision::Allow => {
                debug!(
                    "WAF allowed request from {}, forwarding with HTTP/{}",
                    client_ip, http_version
                );
                state.metrics.record_allowed();
                let response = Self::forward_to_upstream_with_protocol(
                    parts,
                    body_bytes,
                    state.upstream_client,
                    state.upstream_uri,
                    start_time,
                    &http_version,
                    &state.metrics,
                    client_ip,
                    is_https,
                    state.config.server.max_body_size,
                )
                .await;
                state.metrics.record_request_duration(start_time.elapsed());
                response
            }
            Decision::Block { status, reason } => {
                warn!(
                    "WAF blocked request from {}: {} (status: {})",
                    client_ip, reason, status
                );
                state.metrics.record_blocked();
                state.metrics.record_request_duration(start_time.elapsed());
                Ok(Self::create_blocked_response(status, &reason))
            }
            Decision::RateLimit { reason } => {
                warn!("WAF rate limited request from {}: {}", client_ip, reason);
                state.metrics.record_rate_limited();
                state.metrics.record_blocked();
                state.metrics.record_request_duration(start_time.elapsed());
                Ok(Self::create_rate_limit_response(&reason))
            }
        }
    }

    /// Proxy a WebSocket upgrade to the configured upstream over a raw TCP
    /// connection, then splice the two upgraded byte streams together.
    async fn proxy_websocket(
        mut req: Request<Incoming>,
        state: &ProxyState,
        client_ip: IpAddr,
    ) -> Response<Full<Bytes>> {
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

        let mut headers = String::new();
        for (name, value) in req.headers() {
            let lower = name.as_str().to_ascii_lowercase();
            if matches!(
                lower.as_str(),
                "host"
                    | "connection"
                    | "upgrade"
                    | "proxy-connection"
                    | "x-forwarded-host"
                    | "x-forwarded-for"
                    | "x-real-ip"
                    | "x-forwarded-proto"
            ) {
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
        let mut lines = head.lines();
        let status = lines
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|code| code.parse::<u16>().ok())
            .unwrap_or(502);
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
        for line in lines {
            if let Some((name, value)) = line.split_once(':') {
                let lower = name.trim().to_ascii_lowercase();
                if lower == "connection" || lower == "upgrade" {
                    continue;
                }
                builder = builder.header(name.trim(), value.trim());
            }
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
        let max_frame_bytes = state.config.server.max_body_size;
        tokio::spawn(async move {
            let upgraded = match on_upgrade.await {
                Ok(upgraded) => upgraded,
                Err(e) => {
                    metrics.record_upstream_error();
                    warn!("WebSocket client upgrade failed: {}", e);
                    return;
                }
            };

            let client_io = hyper_util::rt::TokioIo::new(upgraded);
            let client_ws = WebSocketStream::from_raw_socket(client_io, Role::Server, None).await;
            let upstream_io = PrefixedIo::new(leftover, upstream_stream);
            let upstream_ws =
                WebSocketStream::from_raw_socket(upstream_io, Role::Client, None).await;

            Self::bridge_websocket(
                client_ws,
                upstream_ws,
                waf_engine,
                base_context,
                max_frame_bytes,
            )
            .await;
        });

        info!(
            "WebSocket tunnel established from {} to {}:{}",
            client_ip, host, port
        );
        builder
            .body(Full::new(Bytes::new()))
            .unwrap_or_else(|_| Self::create_error_response(StatusCode::BAD_GATEWAY, "Handshake"))
    }

    /// Bridge two WebSocket streams, evaluating client data frames through the
    /// WAF before forwarding them upstream.
    async fn bridge_websocket<C, U>(
        mut client: WebSocketStream<C>,
        mut upstream: WebSocketStream<U>,
        waf_engine: Arc<WafEngine>,
        base_context: RequestContext,
        max_frame_bytes: usize,
    ) where
        C: AsyncRead + AsyncWrite + Unpin,
        U: AsyncRead + AsyncWrite + Unpin,
    {
        loop {
            tokio::select! {
                incoming = client.next() => {
                    match incoming {
                        Some(Ok(message)) => {
                            if Self::websocket_message_blocked(
                                &waf_engine,
                                &base_context,
                                &message,
                                max_frame_bytes,
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
                            debug!("WebSocket client stream error: {}", e);
                            break;
                        }
                        None => break,
                    }
                }
                incoming = upstream.next() => {
                    match incoming {
                        Some(Ok(message)) => {
                            if client.send(message).await.is_err() {
                                break;
                            }
                        }
                        Some(Err(e)) => {
                            debug!("WebSocket upstream stream error: {}", e);
                            break;
                        }
                        None => break,
                    }
                }
            }
        }
    }

    async fn websocket_message_blocked(
        waf_engine: &WafEngine,
        base_context: &RequestContext,
        message: &Message,
        max_frame_bytes: usize,
    ) -> bool {
        let payload = match message {
            Message::Text(text) => text.as_bytes().to_vec(),
            Message::Binary(data) => data.to_vec(),
            _ => return false,
        };
        if payload.is_empty() {
            return false;
        }
        if payload.len() > max_frame_bytes {
            warn!(
                "WAF blocked oversized WebSocket frame from {}: {} bytes exceeds {}",
                base_context.client_ip,
                payload.len(),
                max_frame_bytes
            );
            return true;
        }

        let mut context = base_context.clone();
        context.body = Some(Bytes::from(payload.clone()));
        context.body_size = Some(payload.len());
        context.timestamp = Instant::now();

        match waf_engine.evaluate(&context).await {
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
    /// `X-Forwarded-For` / `X-Real-IP` are only honoured when the immediate
    /// peer is a configured trusted proxy; otherwise the socket address is
    /// authoritative.
    pub(crate) fn resolve_client_ip(
        peer_ip: IpAddr,
        headers: &hyper::HeaderMap,
        trusted_proxies: &[IpNetwork],
    ) -> IpAddr {
        let trusted_peer = trusted_proxies
            .iter()
            .any(|network| network.contains(peer_ip));
        if !trusted_peer {
            return peer_ip;
        }

        if let Some(value) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            let hops: Vec<IpAddr> = value
                .split(',')
                .map(str::trim)
                .filter_map(|part| part.parse::<IpAddr>().ok())
                .collect();

            // Walk from the nearest hop backwards, skipping addresses that are
            // themselves trusted proxies. This prevents a client behind a
            // trusted LB from spoofing its source by prepending an address.
            for hop in hops.iter().rev() {
                if !trusted_proxies.iter().any(|network| network.contains(*hop)) {
                    return *hop;
                }
            }
        }
        if let Some(ip) = headers
            .get("x-real-ip")
            .and_then(|v| v.to_str().ok())
            .and_then(|value| value.trim().parse::<IpAddr>().ok())
        {
            return ip;
        }
        peer_ip
    }

    /// Detect HTTP protocol version from request
    fn detect_http_version<T>(req: &Request<T>) -> String {
        match req.version() {
            hyper::Version::HTTP_09 => "0.9".to_string(),
            hyper::Version::HTTP_10 => "1.0".to_string(),
            hyper::Version::HTTP_11 => "1.1".to_string(),
            hyper::Version::HTTP_2 => "2".to_string(),
            hyper::Version::HTTP_3 => "3".to_string(),
            _ => "1.1".to_string(), // Default fallback
        }
    }

    /// Check if the detected HTTP version is supported
    pub(crate) fn is_http_version_supported(version: &str, config: &Config) -> bool {
        config
            .server
            .supported_http_versions
            .contains(&version.to_string())
    }

    /// Protocol-aware request forwarding with version preservation
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn forward_to_upstream_with_protocol(
        parts: hyper::http::request::Parts,
        body_bytes: Bytes,
        upstream_client: Client<HttpsConnector<HttpConnector>, Full<Bytes>>,
        upstream_uri: Uri,
        start_time: Instant,
        http_version: &str,
        metrics: &Metrics,
        client_ip: IpAddr,
        is_https: bool,
        max_response_bytes: usize,
    ) -> Result<Response<Full<Bytes>>, Infallible> {
        // Optimized URI rewriting with protocol version awareness
        let upstream_path_and_query = parts
            .uri
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/");

        // Efficient path concatenation
        let upstream_base = upstream_uri.to_string();
        let upstream_base = upstream_base.trim_end_matches('/');
        let path = if upstream_path_and_query.starts_with('/') {
            upstream_path_and_query
        } else {
            &format!("/{}", upstream_path_and_query)
        };

        let new_uri = format!("{}{}", upstream_base, path).parse::<Uri>();

        let new_uri = match new_uri {
            Ok(uri) => uri,
            Err(e) => {
                error!("Failed to construct upstream URI: {}", e);
                return Ok(Self::create_error_response(
                    StatusCode::BAD_GATEWAY,
                    "Invalid upstream URI",
                ));
            }
        };

        // Preserve the original virtual host for the upstream application.
        let original_host = parts.headers.get(hyper::header::HOST).cloned();

        // Build protocol-aware proxy request
        let mut proxy_req = Request::builder()
            .method(parts.method)
            .uri(new_uri)
            .version(parts.version); // Preserve HTTP version

        // Add protocol-specific headers
        match http_version {
            "1.0" => {
                // HTTP/1.0 specific handling
                proxy_req = proxy_req.header("Connection", "close");
            }
            "1.1" => {
                // HTTP/1.1 specific handling
                proxy_req = proxy_req.header("Connection", "keep-alive");
            }
            "2" => {
                // HTTP/2 specific handling - no Connection header needed
            }
            "3" => {
                // HTTP/3 specific handling - QUIC protocol
                debug!("HTTP/3 request forwarded via HTTP/2 to upstream (protocol conversion)");
            }
            _ => {
                // Default to HTTP/1.1 behavior
                proxy_req = proxy_req.header("Connection", "keep-alive");
            }
        }

        // Efficient header copying (skip hop-by-hop and untrusted forwarding headers)
        for (key, value) in parts.headers {
            if let Some(key) = key {
                let key_str = key.as_str().to_ascii_lowercase();
                if !matches!(
                    key_str.as_str(),
                    "host"
                        | "connection"
                        | "proxy-connection"
                        | "upgrade"
                        | "te"
                        | "trailer"
                        | "transfer-encoding"
                        | "keep-alive"
                        | "x-forwarded-for"
                        | "x-real-ip"
                        | "x-forwarded-proto"
                ) {
                    proxy_req = proxy_req.header(key, value);
                }
            }
        }

        // The WAF is authoritative for client identity.
        proxy_req = proxy_req
            .header("x-forwarded-for", client_ip.to_string())
            .header("x-real-ip", client_ip.to_string())
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

        let proxy_req = match proxy_req.body(Full::new(body_bytes)) {
            Ok(req) => req,
            Err(e) => {
                error!("Failed to build proxy request: {}", e);
                return Ok(Self::create_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to build proxy request",
                ));
            }
        };

        // Forward request with timeout
        match tokio::time::timeout(
            Duration::from_secs(30), // Reasonable timeout
            upstream_client.request(proxy_req),
        )
        .await
        {
            Ok(Ok(response)) => {
                let processing_time = start_time.elapsed();
                debug!("Request processed in {:?}", processing_time);

                // Optimized response handling
                let (parts, body) = response.into_parts();
                if let Some(length) = parts
                    .headers
                    .get(hyper::header::CONTENT_LENGTH)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.parse::<usize>().ok())
                {
                    if length > max_response_bytes {
                        metrics.record_upstream_error();
                        return Ok(Self::create_error_response(
                            StatusCode::BAD_GATEWAY,
                            "Upstream response too large",
                        ));
                    }
                }
                let limited = Limited::new(body, max_response_bytes);
                let body_bytes =
                    match tokio::time::timeout(Duration::from_secs(30), limited.collect()).await {
                        Ok(Ok(collected)) => collected.to_bytes(),
                        Ok(Err(e)) => {
                            metrics.record_upstream_error();
                            error!("Failed to collect upstream response body: {}", e);
                            return Ok(Self::create_error_response(
                                StatusCode::BAD_GATEWAY,
                                "Failed to read upstream response",
                            ));
                        }
                        Err(_) => {
                            error!("Upstream response collection timed out");
                            return Ok(Self::create_error_response(
                                StatusCode::GATEWAY_TIMEOUT,
                                "Upstream response timeout",
                            ));
                        }
                    };

                let mut response_builder = Response::builder()
                    .status(parts.status)
                    .version(parts.version);

                // Copy response headers, dropping hop-by-hop values that the
                // downstream connection must negotiate for itself.
                for (key, value) in parts.headers {
                    if let Some(key) = key {
                        let name = key.as_str().to_ascii_lowercase();
                        if !matches!(
                            name.as_str(),
                            "connection"
                                | "proxy-connection"
                                | "keep-alive"
                                | "transfer-encoding"
                                | "upgrade"
                                | "trailer"
                        ) {
                            response_builder = response_builder.header(key, value);
                        }
                    }
                }

                // Add performance-optimized WAF response headers
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

                match response_builder.body(Full::new(body_bytes)) {
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

    /// Create blocked response with protocol information
    pub(crate) fn create_blocked_response(status_code: u16, reason: &str) -> Response<Full<Bytes>> {
        let status = StatusCode::from_u16(status_code).unwrap_or(StatusCode::FORBIDDEN);
        let body = format!("Request blocked by WAF: {}", reason);

        Response::builder()
            .status(status)
            .header("content-type", "text/plain")
            .header("x-waf-decision", "block")
            .header("x-waf-reason", reason)
            .header(
                "x-waf-version",
                concat!("waf-rejected/", env!("CARGO_PKG_VERSION")),
            )
            .header(
                "x-waf-supported-protocols",
                "HTTP/1.0,HTTP/1.1,HTTP/2,HTTP/3",
            )
            .body(Full::new(Bytes::from(body)))
            .unwrap()
    }

    /// Create rate limit response with protocol information
    pub(crate) fn create_rate_limit_response(reason: &str) -> Response<Full<Bytes>> {
        let body = format!("Rate limited: {}", reason);

        Response::builder()
            .status(StatusCode::TOO_MANY_REQUESTS)
            .header("content-type", "text/plain")
            .header("x-waf-decision", "rate-limit")
            .header("x-waf-reason", reason)
            .header(
                "x-waf-version",
                concat!("waf-rejected/", env!("CARGO_PKG_VERSION")),
            )
            .header(
                "x-waf-supported-protocols",
                "HTTP/1.0,HTTP/1.1,HTTP/2,HTTP/3",
            )
            .header("retry-after", "60") // Suggest retry after 60 seconds
            .body(Full::new(Bytes::from(body)))
            .unwrap()
    }

    /// Create generic error response with protocol information
    pub(crate) fn create_error_response(
        status: StatusCode,
        message: &str,
    ) -> Response<Full<Bytes>> {
        Response::builder()
            .status(status)
            .header("content-type", "text/plain")
            .header(
                "x-waf-version",
                concat!("waf-rejected/", env!("CARGO_PKG_VERSION")),
            )
            .header(
                "x-waf-supported-protocols",
                "HTTP/1.0,HTTP/1.1,HTTP/2,HTTP/3",
            )
            .body(Full::new(Bytes::from(message.to_string())))
            .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ProxyConfig;
    use proptest::prelude::*;

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
        let config = Config {
            proxy: ProxyConfig {
                upstream_url: "http://localhost:8080".to_string(),
                bind_addr: "0.0.0.0:3000".to_string(),
                timeout_seconds: 30,
                max_request_size: 10_485_760,
                upstream_ca_path: None,
                upstream_client_cert_path: None,
                upstream_client_key_path: None,
            },
            ..Default::default()
        };

        let service = WafProxyService::new(config);
        assert!(service.is_ok());
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
}
