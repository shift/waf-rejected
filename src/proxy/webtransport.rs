//! WebTransport over HTTP/3 (QUIC) ingress.
//!
//! This module is compiled only with the `webtransport` feature. WebTransport
//! is a *terminating* endpoint, not an HTTP request/response proxy: there is no
//! upstream HTTP framing to reuse. Sessions are authenticated, validated, and
//! inspected locally; stream and datagram payloads never leave this process.
//! Bidirectional streams are echoed back (bounded by `max_stream_bytes`) so the
//! endpoint can be verified without an application-specific upstream bridge.
//!
//! Rejections happen before the session is established whenever the protocol
//! allows it: Origin/path/authentication/WAF failures reply with a `403`
//! CONNECT response. A missing or invalid API key is reported as a `401`
//! application close because WebTransport only defines `403`, `404`, and `429`
//! CONNECT responses.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use http::header::{CONTENT_TYPE, HOST, ORIGIN};
use http::{HeaderMap, HeaderValue, Method, Uri};
use parking_lot::Mutex;
use tokio::task::JoinSet;
use tracing::{debug, info, warn};
use wtransport::endpoint::SessionRequest;
use wtransport::quinn::VarInt as QuicVarInt;
use wtransport::{Connection, Endpoint, ServerConfig, VarInt};

use crate::config::WebTransportConfig;
use crate::error::WafError;
use crate::proxy::service::{ProxyState, WafProxyService};
use crate::waf::tls_config::TlsManager;
use crate::waf::{Decision, RequestContext};

const CLOSE_NORMAL: u32 = 0;
const CLOSE_BAD_REQUEST: u32 = 400;
const CLOSE_UNAUTHORIZED: u32 = 401;
const CLOSE_FORBIDDEN: u32 = 403;
const CLOSE_SESSION_TIMEOUT: u32 = 408;
const CLOSE_DUPLICATE_SESSION: u32 = 409;
const CLOSE_PAYLOAD_TOO_LARGE: u32 = 413;
const CLOSE_TOO_MANY_REQUESTS: u32 = 429;

const STREAM_CHUNK: usize = 8 * 1024;

/// Bind the WebTransport UDP listener and serve sessions.
///
/// Returns `Ok(())` without binding when QUIC/TLS cannot be configured, so a
/// misconfigured WebTransport listener never prevents the TCP listener from
/// running.
pub(crate) async fn serve(
    tls_manager: Arc<TlsManager>,
    state: ProxyState,
    config: WebTransportConfig,
) -> Result<(), WafError> {
    let tls_config = match tls_manager.quic_server_config() {
        Ok(config) => config,
        Err(e) => {
            warn!("WebTransport listener not started: {}", e);
            return Ok(());
        }
    };

    let idle_timeout = Duration::from_secs(config.idle_timeout_secs);
    let server_config = ServerConfig::builder()
        .with_bind_address(config.bind_addr)
        .with_custom_tls((*tls_config).clone())
        .allow_migration(false)
        .max_idle_timeout(Some(idle_timeout))
        .map_err(|_| WafError::Configuration("Invalid WebTransport idle timeout".to_string()))?
        .build();

    let mut server_config = server_config;
    let mut transport = wtransport::quinn::TransportConfig::default();
    transport
        .max_concurrent_bidi_streams(QuicVarInt::from_u32(config.max_bidi_streams))
        .max_concurrent_uni_streams(QuicVarInt::from_u32(config.max_uni_streams));
    server_config
        .quic_config_mut()
        .transport_config(Arc::new(transport));

    let endpoint = Endpoint::server(server_config).map_err(|e| {
        WafError::internal(format!(
            "Failed to bind WebTransport UDP listener to {}: {}",
            config.bind_addr, e
        ))
    })?;

    info!(
        "WebTransport (HTTP/3) listener started on udp://{}",
        endpoint.local_addr().unwrap_or(config.bind_addr)
    );

    let config = Arc::new(config);
    let registry = Arc::new(SessionRegistry::default());

    loop {
        let incoming = endpoint.accept().await;

        // Cheap global admission check before paying for a QUIC handshake.
        if registry.active() >= config.max_sessions {
            debug!("WebTransport session rejected: global session cap reached");
            state.metrics.record_webtransport_blocked();
            incoming.refuse();
            continue;
        }

        let state = state.clone();
        let config = Arc::clone(&config);
        let registry = Arc::clone(&registry);
        tokio::spawn(async move {
            let request = match incoming.await {
                Ok(request) => request,
                Err(e) => {
                    debug!("WebTransport handshake failed: {}", e);
                    return;
                }
            };
            if let Err(e) = handle_session(request, state, config, registry).await {
                debug!("WebTransport session closed: {}", e);
            }
        });
    }
}

async fn handle_session(
    request: SessionRequest,
    state: ProxyState,
    config: Arc<WebTransportConfig>,
    registry: Arc<SessionRegistry>,
) -> Result<(), WafError> {
    let peer_ip = request.remote_address().ip();
    let headers = request_headers(&request);
    // The QUIC peer address is authoritative; forwarded headers are only
    // honoured when that peer is a configured trusted proxy.
    let client_ip = WafProxyService::resolve_client_ip(peer_ip, &headers, &state.trusted_proxies);
    let path = request.path().to_string();
    let origin = request.origin().map(str::to_string);
    let authority = request.authority().to_string();

    if !config.is_origin_allowed(origin.as_deref()) {
        warn!(
            "WebTransport origin rejected from {}: {:?}",
            client_ip, origin
        );
        state.metrics.record_webtransport_blocked();
        reject(request, CLOSE_FORBIDDEN, "Origin not allowed").await;
        return Ok(());
    }

    if !config.is_path_allowed(&path) {
        warn!("WebTransport path rejected from {}: {}", client_ip, path);
        state.metrics.record_webtransport_blocked();
        reject(request, CLOSE_FORBIDDEN, "Path not allowed").await;
        return Ok(());
    }

    if let Some(validator) = &state.auth_validator {
        if let Err(e) = validator.validate_request(&headers, true) {
            warn!(
                "Authentication rejected WebTransport session from {}: {}",
                client_ip, e
            );
            state.metrics.record_webtransport_blocked();
            reject(request, CLOSE_UNAUTHORIZED, "Unauthorized").await;
            return Ok(());
        }
    }

    let mut guard = match registry.acquire(client_ip, &config) {
        Some(guard) => guard,
        None => {
            warn!(
                "WebTransport session cap reached for {} (per-IP limit {})",
                client_ip, config.max_sessions_per_ip
            );
            state.metrics.record_webtransport_blocked();
            reject(request, CLOSE_TOO_MANY_REQUESTS, "Too many sessions").await;
            return Ok(());
        }
    };

    let context = connect_context(
        client_ip,
        &authority,
        &path,
        origin.as_deref(),
        headers.clone(),
    );
    match state.waf_engine.evaluate(&context).await {
        Decision::Allow => {}
        Decision::Block { status, reason } => {
            warn!(
                "WAF blocked WebTransport CONNECT from {}: {} (status: {})",
                client_ip, reason, status
            );
            state.metrics.record_webtransport_blocked();
            reject(request, CLOSE_FORBIDDEN, &reason).await;
            return Ok(());
        }
        Decision::RateLimit { reason } => {
            warn!(
                "WAF rate limited WebTransport CONNECT from {}: {}",
                client_ip, reason
            );
            state.metrics.record_webtransport_blocked();
            reject(request, CLOSE_TOO_MANY_REQUESTS, &reason).await;
            return Ok(());
        }
    }

    let connection = request.accept().await.map_err(|e| {
        WafError::NetworkError(format!("WebTransport session accept failed: {}", e))
    })?;

    if !guard.register_identity(
        connection.stable_id(),
        Duration::from_secs(config.max_session_secs),
    ) {
        warn!(
            "Duplicate WebTransport session rejected from {} (stable id {})",
            client_ip,
            connection.stable_id()
        );
        state.metrics.record_webtransport_blocked();
        connection.close(
            VarInt::from_u32(CLOSE_DUPLICATE_SESSION),
            b"duplicate session",
        );
        return Ok(());
    }

    state.metrics.record_webtransport_session();
    state.metrics.record_webtransport_allowed();
    debug!(
        "WebTransport session accepted from {} on {} (origin {:?})",
        client_ip, path, origin
    );

    let outcome = tokio::time::timeout(
        Duration::from_secs(config.max_session_secs),
        run_session(
            &connection,
            &state,
            &config,
            client_ip,
            &authority,
            &path,
            origin,
        ),
    )
    .await;

    let (code, reason): (u32, &[u8]) = match outcome {
        Ok(Ok(())) => (CLOSE_NORMAL, b"session closed"),
        Ok(Err(SessionEnd::Blocked)) => (CLOSE_FORBIDDEN, b"blocked by WAF"),
        Ok(Err(SessionEnd::TooLarge)) => (CLOSE_PAYLOAD_TOO_LARGE, b"payload too large"),
        Ok(Err(SessionEnd::Closed)) => (CLOSE_NORMAL, b"session closed"),
        Err(_) => {
            warn!(
                "WebTransport session from {} exceeded {}s lifetime",
                client_ip, config.max_session_secs
            );
            (CLOSE_SESSION_TIMEOUT, b"session timeout")
        }
    };
    connection.close(VarInt::from_u32(code), reason);

    drop(guard);
    Ok(())
}

enum SessionEnd {
    Blocked,
    TooLarge,
    Closed,
}

async fn run_session(
    connection: &Connection,
    state: &ProxyState,
    config: &WebTransportConfig,
    client_ip: IpAddr,
    authority: &str,
    path: &str,
    origin: Option<String>,
) -> Result<(), SessionEnd> {
    let mut tasks: JoinSet<()> = JoinSet::new();
    let stream_cap = config
        .max_stream_bytes
        .min(state.config.server.max_body_size);

    let outcome = loop {
        tokio::select! {
            datagram = connection.receive_datagram() => {
                match datagram {
                    Ok(datagram) => {
                        state.metrics.record_webtransport_datagram();
                        let payload = datagram.payload();
                        if payload.len() > config.max_datagram_bytes {
                            warn!(
                                "WebTransport datagram from {} exceeds {} bytes",
                                client_ip, config.max_datagram_bytes
                            );
                            state.metrics.record_webtransport_blocked();
                            break Err(SessionEnd::TooLarge);
                        }
                        if config.inspect_datagrams {
                            let decision = evaluate_payload(
                                state,
                                client_ip,
                                authority,
                                path,
                                origin.as_deref(),
                                "datagram",
                                payload.clone(),
                            )
                            .await;
                            if blocked(decision, state, client_ip, "datagram") {
                                break Err(SessionEnd::Blocked);
                            }
                        }
                    }
                    Err(_) => break Ok(()),
                }
            }
            uni = connection.accept_uni() => {
                match uni {
                    Ok(stream) => {
                        state.metrics.record_webtransport_stream();
                        let state = state.clone();
                        let config = config.clone();
                        let connection = connection.clone();
                        let authority = authority.to_string();
                        let path = path.to_string();
                        let origin = origin.clone();
                        tasks.spawn(async move {
                            let _ = inspect_stream(
                                stream,
                                None,
                                state,
                                config,
                                connection,
                                client_ip,
                                authority,
                                path,
                                origin,
                                stream_cap,
                            )
                            .await;
                        });
                    }
                    Err(_) => break Ok(()),
                }
            }
            bi = connection.accept_bi() => {
                match bi {
                    Ok((send, recv)) => {
                        state.metrics.record_webtransport_stream();
                        let state = state.clone();
                        let config = config.clone();
                        let connection = connection.clone();
                        let authority = authority.to_string();
                        let path = path.to_string();
                        let origin = origin.clone();
                        tasks.spawn(async move {
                            let _ = inspect_stream(
                                recv,
                                Some(send),
                                state,
                                config,
                                connection,
                                client_ip,
                                authority,
                                path,
                                origin,
                                stream_cap,
                            )
                            .await;
                        });
                    }
                    Err(_) => break Ok(()),
                }
            }
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
        }
    };

    tasks.abort_all();
    outcome
}

#[allow(clippy::too_many_arguments)]
async fn inspect_stream(
    mut recv: wtransport::RecvStream,
    send: Option<wtransport::SendStream>,
    state: ProxyState,
    config: WebTransportConfig,
    connection: Connection,
    client_ip: IpAddr,
    authority: String,
    path: String,
    origin: Option<String>,
    stream_cap: usize,
) -> Result<(), SessionEnd> {
    let mut body = BytesMut::new();
    let mut buffer = [0u8; STREAM_CHUNK];
    let read_timeout = Duration::from_secs(config.idle_timeout_secs);

    loop {
        match tokio::time::timeout(read_timeout, recv.read(&mut buffer)).await {
            Ok(Ok(Some(read))) => {
                if body.len().saturating_add(read) > stream_cap {
                    warn!(
                        "WebTransport stream from {} exceeds {} bytes",
                        client_ip, stream_cap
                    );
                    state.metrics.record_webtransport_blocked();
                    connection.close(
                        VarInt::from_u32(CLOSE_PAYLOAD_TOO_LARGE),
                        b"payload too large",
                    );
                    return Err(SessionEnd::TooLarge);
                }
                body.extend_from_slice(&buffer[..read]);
            }
            Ok(Ok(None)) => break,
            Ok(Err(_)) => break,
            Err(_) => {
                warn!("WebTransport stream from {} timed out", client_ip);
                connection.close(VarInt::from_u32(CLOSE_SESSION_TIMEOUT), b"stream timeout");
                return Err(SessionEnd::Closed);
            }
        }
    }

    let body = body.freeze();
    if config.inspect_streams {
        let decision = evaluate_payload(
            &state,
            client_ip,
            &authority,
            &path,
            origin.as_deref(),
            "stream",
            body.clone(),
        )
        .await;
        if blocked(decision, &state, client_ip, "stream") {
            connection.close(VarInt::from_u32(CLOSE_FORBIDDEN), b"blocked by WAF");
            return Err(SessionEnd::Blocked);
        }
    }

    // Minimal local echo so the terminating endpoint is testable. There is no
    // application-specific upstream bridge.
    if let Some(mut send) = send {
        let _ = send.write_all(&body).await;
        let _ = send.finish().await;
    }

    Ok(())
}

fn blocked(decision: Decision, state: &ProxyState, client_ip: IpAddr, kind: &str) -> bool {
    match decision {
        Decision::Allow => false,
        Decision::Block { status, reason } => {
            warn!(
                "WAF blocked WebTransport {} from {}: {} (status: {})",
                kind, client_ip, reason, status
            );
            state.metrics.record_webtransport_blocked();
            true
        }
        Decision::RateLimit { reason } => {
            warn!(
                "WAF rate limited WebTransport {} from {}: {}",
                kind, client_ip, reason
            );
            state.metrics.record_webtransport_blocked();
            true
        }
    }
}

async fn evaluate_payload(
    state: &ProxyState,
    client_ip: IpAddr,
    authority: &str,
    path: &str,
    origin: Option<&str>,
    kind: &str,
    body: Bytes,
) -> Decision {
    let mut headers = HeaderMap::new();
    if let Ok(value) = HeaderValue::from_str(authority) {
        headers.insert(HOST, value);
    }
    if let Some(origin) = origin.and_then(|origin| HeaderValue::from_str(origin).ok()) {
        headers.insert(ORIGIN, origin);
    }
    headers.insert("x-waf-protocol", HeaderValue::from_static("webtransport"));
    headers.insert(
        "x-waf-webtransport-payload",
        HeaderValue::from_str(kind).unwrap_or_else(|_| HeaderValue::from_static("stream")),
    );
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );

    let uri = session_uri(authority, path);
    let context = RequestContext::with_http_version(
        client_ip,
        Method::POST,
        uri,
        headers,
        Some(body.len()),
        "3".to_string(),
    )
    .with_body(Some(body));

    state.waf_engine.evaluate(&context).await
}

fn connect_context(
    client_ip: IpAddr,
    authority: &str,
    path: &str,
    origin: Option<&str>,
    mut headers: HeaderMap,
) -> RequestContext {
    if !headers.contains_key(HOST) {
        if let Ok(value) = HeaderValue::from_str(authority) {
            headers.insert(HOST, value);
        }
    }
    if let Some(origin) = origin.and_then(|origin| HeaderValue::from_str(origin).ok()) {
        headers.insert(ORIGIN, origin);
    }
    headers.insert("x-waf-protocol", HeaderValue::from_static("webtransport"));
    // WebTransport's CONNECT establishes a session; it is not an HTTP tunnel.
    // The default `dangerous_methods` rule blocks every CONNECT, so the
    // synthetic request is evaluated as a body-less POST and the original
    // method is preserved for custom rules.
    headers.insert("x-waf-method", HeaderValue::from_static("CONNECT"));

    RequestContext::with_http_version(
        client_ip,
        Method::POST,
        session_uri(authority, path),
        headers,
        None,
        "3".to_string(),
    )
}

fn session_uri(authority: &str, path: &str) -> Uri {
    let path = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{}", path)
    };
    format!("https://{}{}", authority, path)
        .parse()
        .unwrap_or_else(|_| path.parse().unwrap_or_else(|_| Uri::from_static("/")))
}

fn request_headers(request: &SessionRequest) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (name, value) in request.headers() {
        if let (Ok(name), Ok(value)) = (
            name.parse::<http::header::HeaderName>(),
            HeaderValue::from_str(value),
        ) {
            headers.append(name, value);
        }
    }
    if !headers.contains_key(HOST) {
        if let Ok(value) = HeaderValue::from_str(request.authority()) {
            headers.insert(HOST, value);
        }
    }
    if let Some(origin) = request
        .origin()
        .and_then(|origin| HeaderValue::from_str(origin).ok())
    {
        headers.insert(ORIGIN, origin);
    }
    headers
}

/// Reject a session request.
///
/// WebTransport only defines `403`, `404`, and `429` CONNECT responses, so a
/// `401` is expressed by accepting and immediately closing with the `401`
/// application code. Every rejection happens before any stream is forwarded.
async fn reject(request: SessionRequest, status: u32, reason: &str) {
    match status {
        CLOSE_TOO_MANY_REQUESTS => request.too_many_requests().await,
        CLOSE_FORBIDDEN => request.forbidden().await,
        CLOSE_UNAUTHORIZED => {
            if let Ok(connection) = request.accept().await {
                connection.close(VarInt::from_u32(CLOSE_UNAUTHORIZED), reason.as_bytes());
            }
        }
        _ => request.forbidden().await,
    }
}

/// Session admission and duplicate-session tracking.
#[derive(Default)]
struct SessionRegistry {
    active: AtomicUsize,
    per_ip: Mutex<HashMap<IpAddr, usize>>,
    identities: Mutex<HashMap<(IpAddr, usize), Instant>>,
}

impl SessionRegistry {
    fn active(&self) -> usize {
        self.active.load(Ordering::Relaxed)
    }

    fn acquire(&self, client_ip: IpAddr, config: &WebTransportConfig) -> Option<SessionGuard<'_>> {
        if self.active() >= config.max_sessions {
            return None;
        }

        let mut per_ip = self.per_ip.lock();
        let count = per_ip.entry(client_ip).or_insert(0);
        if *count >= config.max_sessions_per_ip {
            return None;
        }
        *count += 1;
        drop(per_ip);
        self.active.fetch_add(1, Ordering::Relaxed);

        Some(SessionGuard {
            registry: self,
            client_ip,
            identity: None,
        })
    }

    fn register_identity(&self, client_ip: IpAddr, stable_id: usize, ttl: Duration) -> bool {
        let now = Instant::now();
        let mut identities = self.identities.lock();
        identities.retain(|_, expires| *expires > now);
        if identities.contains_key(&(client_ip, stable_id)) {
            return false;
        }
        identities.insert((client_ip, stable_id), now + ttl);
        true
    }

    fn release(&self, client_ip: IpAddr, identity: Option<(IpAddr, usize)>) {
        if let Some(identity) = identity {
            self.identities.lock().remove(&identity);
        }
        let mut per_ip = self.per_ip.lock();
        if let Some(count) = per_ip.get_mut(&client_ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                per_ip.remove(&client_ip);
            }
        }
        self.active.fetch_sub(1, Ordering::Relaxed);
    }
}

struct SessionGuard<'a> {
    registry: &'a SessionRegistry,
    client_ip: IpAddr,
    identity: Option<(IpAddr, usize)>,
}

impl SessionGuard<'_> {
    fn register_identity(&mut self, stable_id: usize, ttl: Duration) -> bool {
        if self
            .registry
            .register_identity(self.client_ip, stable_id, ttl)
        {
            self.identity = Some((self.client_ip, stable_id));
            true
        } else {
            false
        }
    }
}

impl Drop for SessionGuard<'_> {
    fn drop(&mut self) {
        self.registry.release(self.client_ip, self.identity);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_uri_falls_back_to_relative_path() {
        assert_eq!(
            session_uri("example.test:443", "/echo").to_string(),
            "https://example.test:443/echo"
        );
        assert_eq!(session_uri("", "/echo?x=1").to_string(), "/echo?x=1");
    }

    #[test]
    fn session_registry_enforces_global_and_per_ip_caps() {
        let registry = SessionRegistry::default();
        let config = WebTransportConfig {
            max_sessions: 2,
            max_sessions_per_ip: 1,
            ..WebTransportConfig::default()
        };
        let first = IpAddr::from([192, 0, 2, 1]);
        let second = IpAddr::from([192, 0, 2, 2]);

        let guard = registry.acquire(first, &config).unwrap();
        assert!(registry.acquire(first, &config).is_none());
        let _second = registry.acquire(second, &config).unwrap();
        assert!(registry.acquire(second, &config).is_none());
        assert_eq!(registry.active(), 2);

        drop(guard);
        assert_eq!(registry.active(), 1);
        assert!(registry.acquire(first, &config).is_some());
    }

    #[test]
    fn session_registry_rejects_duplicate_identities_until_expiry() {
        let registry = SessionRegistry::default();
        let config = WebTransportConfig::default();
        let ip = IpAddr::from([192, 0, 2, 10]);

        let mut guard = registry.acquire(ip, &config).unwrap();
        assert!(guard.register_identity(7, Duration::from_secs(60)));

        let mut duplicate = registry.acquire(ip, &config).unwrap();
        assert!(!duplicate.register_identity(7, Duration::from_secs(60)));

        drop(duplicate);
        drop(guard);

        let mut reused = registry.acquire(ip, &config).unwrap();
        assert!(reused.register_identity(7, Duration::from_secs(60)));
    }
}
