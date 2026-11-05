//! HTTP/3 (QUIC) ingress.
//!
//! This module is compiled only with the `http3` feature. It terminates QUIC
//! on a UDP socket that shares the TCP listener's address, then runs each
//! request through the same authentication and WAF pipeline as the HTTP/1.1
//! and HTTP/2 listeners before forwarding it to the upstream HTTP client.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::{Buf, Bytes, BytesMut};
use http::header::HOST;
use http::uri::Scheme;
use http::{HeaderMap, HeaderValue, Request, Response, StatusCode, Uri};
use http_body_util::BodyExt;
use quinn::crypto::rustls::QuicServerConfig;
use tracing::{debug, info, warn};

use crate::error::WafError;
use crate::proxy::decompression::{
    decompress_request_body, strip_encoding_headers, DecompressionError,
};
use crate::proxy::framing::{
    validate_request_framing_for_version, validate_request_trailers, FramingVersion,
};
use crate::proxy::h3_admission::{H3Admission, H3AdmissionRejection};
use crate::proxy::service::{ProxyState, WafProxyService};
use crate::proxy::telemetry::{RequestRejection, RequestTelemetry};
use crate::waf::tls_config::TlsManager;
use crate::waf::{Decision, RequestContext};

type H3Stream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

/// Bind the UDP listener and serve HTTP/3 connections.
///
/// Returns `Ok(())` without binding when QUIC/TLS cannot be configured, so a
/// misconfigured HTTP/3 listener never prevents the TCP listener from running.
pub(crate) async fn serve(
    tls_manager: Arc<TlsManager>,
    state: ProxyState,
    bind_addr: SocketAddr,
) -> Result<(), WafError> {
    let rustls_config = match tls_manager.quic_server_config() {
        Ok(config) => config,
        Err(e) => {
            warn!("HTTP/3 listener not started: {}", e);
            return Ok(());
        }
    };

    let crypto = QuicServerConfig::try_from(rustls_config).map_err(|e| {
        WafError::Configuration(format!("Failed to build QUIC TLS configuration: {}", e))
    })?;
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));

    let endpoint = quinn::Endpoint::server(server_config, bind_addr).map_err(|e| {
        WafError::internal(format!(
            "Failed to bind HTTP/3 UDP listener to {}: {}",
            bind_addr, e
        ))
    })?;

    info!(
        "HTTP/3 (QUIC) listener started on udp://{}",
        endpoint.local_addr().unwrap_or(bind_addr)
    );

    let admission = H3Admission::new(
        state.config.server.h3_max_inflight_requests,
        state.config.server.h3_max_inflight_per_client,
        Duration::from_millis(state.config.server.h3_admission_timeout_ms.max(1)),
        state.metrics.clone(),
    );

    while let Some(incoming) = endpoint.accept().await {
        let state = state.clone();
        let admission = admission.clone();
        tokio::spawn(async move {
            match incoming.await {
                Ok(connection) => {
                    let peer_ip = connection.remote_address().ip();
                    if let Err(e) = handle_connection(connection, state, peer_ip, admission).await {
                        debug!("HTTP/3 connection from {} closed: {}", peer_ip, e);
                    }
                }
                Err(e) => debug!("HTTP/3 handshake failed: {}", e),
            }
        });
    }

    // Listener shutdown: fail any waiters and let admitted requests release
    // their permits as they finish.
    admission.shutdown();

    Ok(())
}

async fn handle_connection(
    connection: quinn::Connection,
    state: ProxyState,
    peer_ip: IpAddr,
    admission: H3Admission,
) -> Result<(), WafError> {
    let mut connection = h3::server::Connection::<h3_quinn::Connection, Bytes>::new(
        h3_quinn::Connection::new(connection),
    )
    .await
    .map_err(|e| WafError::NetworkError(format!("HTTP/3 connection setup failed: {}", e)))?;

    loop {
        match connection.accept().await {
            Ok(Some(resolver)) => {
                // Admission is acquired before `resolve_request`, so a
                // saturated listener never spawns a handler or reads a body
                // for excess work. Waiting here provides per-connection
                // backpressure and the global semaphore bounds all tasks.
                let permit = match admission.acquire(peer_ip).await {
                    Ok(permit) => permit,
                    Err(rejection) => {
                        warn!(
                            "Rejected HTTP/3 request from {} before body read: {}",
                            peer_ip, rejection
                        );
                        state.metrics.record_request();
                        let started = Instant::now();
                        let response = admission_rejection_response(rejection);
                        let rejected = tokio::time::timeout(
                            Duration::from_secs(
                                state.config.server.request_timeout_secs.max(1),
                            ),
                            async {
                                match resolver.resolve_request().await {
                                    Ok((_request, mut stream)) => {
                                        send_response(&mut stream, response).await
                                    }
                                    Err(e) => {
                                        debug!(
                                            "HTTP/3 admission rejection could not resolve headers from {}: {}",
                                            peer_ip, e
                                        );
                                        Ok(())
                                    }
                                }
                            },
                        )
                        .await;
                        if rejected.is_err() {
                            debug!(
                                "Timed out sending HTTP/3 admission rejection to {}",
                                peer_ip
                            );
                        }
                        state.metrics.record_request_duration(started.elapsed());
                        continue;
                    }
                };

                let state = state.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    match resolver.resolve_request().await {
                        Ok((request, stream)) => {
                            if let Err(e) = handle_request(request, stream, state, peer_ip).await {
                                debug!("HTTP/3 request from {} failed: {}", peer_ip, e);
                            }
                        }
                        Err(e) => {
                            debug!("HTTP/3 request headers from {} rejected: {}", peer_ip, e)
                        }
                    }
                });
            }
            Ok(None) => break,
            Err(e) => {
                debug!("HTTP/3 connection from {} ended: {}", peer_ip, e);
                break;
            }
        }
    }

    Ok(())
}

async fn handle_request(
    request: Request<()>,
    mut stream: H3Stream,
    state: ProxyState,
    peer_ip: IpAddr,
) -> Result<(), WafError> {
    let start_time = Instant::now();
    let telemetry = RequestTelemetry::begin(Arc::clone(&state.metrics));

    let (mut parts, ()) = request.into_parts();
    let has_content_encoding = parts.headers.contains_key(http::header::CONTENT_ENCODING);
    parts.uri = reconstruct_uri(&parts.uri, &parts.headers);
    ensure_host_header(&mut parts.headers, &parts.uri);

    // HTTP/3 terminates here. The shared upstream client speaks HTTP/1.1 or
    // HTTP/2, so the outbound request must not claim HTTP/3.
    parts.version = http::Version::HTTP_11;

    let http_version = "3".to_string();
    if !WafProxyService::is_http_version_supported(&http_version, &state.config) {
        warn!("Unsupported HTTP version 3 request from {}", peer_ip);
        telemetry.reject(RequestRejection::UnsupportedHttpVersion);
        state.metrics.record_blocked();
        return send_response(
            &mut stream,
            WafProxyService::create_error_response(
                StatusCode::HTTP_VERSION_NOT_SUPPORTED,
                "HTTP version 3 not supported",
            ),
        )
        .await;
    }

    // The QUIC peer address is authoritative; forwarded headers are only
    // honoured when that peer is a configured trusted proxy.
    let client_ip =
        WafProxyService::resolve_client_ip(peer_ip, &parts.headers, &state.trusted_proxies);

    // Reject ambiguous request framing before any body is read. Details are
    // intentionally not exposed to the client.
    if let Err(e) = validate_request_framing_for_version(&parts.headers, FramingVersion::Http3) {
        warn!(
            "Rejected ambiguous HTTP/3 request framing from {}: {}",
            client_ip, e
        );
        telemetry.reject(RequestRejection::InvalidFraming);
        state.metrics.record_blocked();
        return send_response(
            &mut stream,
            WafProxyService::create_error_response(StatusCode::BAD_REQUEST, "Bad Request"),
        )
        .await;
    }

    if let Some(validator) = &state.auth_validator {
        if let Err(e) = validator.validate_request(&parts.headers, true) {
            warn!(
                "Authentication rejected HTTP/3 request from {}: {}",
                client_ip, e
            );
            telemetry.reject(RequestRejection::Authentication);
            state.metrics.record_auth_failure();
            state.metrics.record_blocked();
            return send_response(
                &mut stream,
                WafProxyService::create_error_response(StatusCode::UNAUTHORIZED, "Unauthorized"),
            )
            .await;
        }
    }

    let max_body_size = state.config.server.max_body_size;
    let (body_bytes, request_trailers) = match tokio::time::timeout(
        Duration::from_secs(state.config.server.request_timeout_secs.max(1)),
        read_body(&mut stream, max_body_size),
    )
    .await
    {
        Ok(Ok(body)) => body,
        Ok(Err(BodyReadError::TooLarge)) => {
            warn!(
                "HTTP/3 request body from {} exceeds limit {}",
                client_ip, max_body_size
            );
            telemetry.reject(RequestRejection::BodyTooLarge);
            state.metrics.record_blocked();
            return send_response(
                &mut stream,
                WafProxyService::create_error_response(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "Request body too large",
                ),
            )
            .await;
        }
        Ok(Err(BodyReadError::Stream(e))) => {
            warn!(
                "Failed to read HTTP/3 request body from {}: {}",
                client_ip, e
            );
            telemetry.reject(RequestRejection::BodyReadError);
            state.metrics.record_blocked();
            return send_response(
                &mut stream,
                WafProxyService::create_error_response(
                    StatusCode::BAD_REQUEST,
                    "Failed to read request body",
                ),
            )
            .await;
        }
        Err(_) => {
            warn!("HTTP/3 request body read timed out for {}", client_ip);
            telemetry.reject(RequestRejection::BodyTimeout);
            state.metrics.record_blocked();
            return send_response(
                &mut stream,
                WafProxyService::create_error_response(
                    StatusCode::REQUEST_TIMEOUT,
                    "Request body timeout",
                ),
            )
            .await;
        }
    };

    if let Some(trailers) = request_trailers.as_ref() {
        if let Err(e) = validate_request_trailers(trailers) {
            warn!("Rejected HTTP/3 request trailer from {}: {}", client_ip, e);
            telemetry.reject(RequestRejection::InvalidTrailerFraming);
            state.metrics.record_blocked();
            return send_response(
                &mut stream,
                WafProxyService::create_error_response(StatusCode::BAD_REQUEST, "Bad Request"),
            )
            .await;
        }
    }

    let body_bytes = if has_content_encoding {
        match decompress_request_body(&parts.headers, body_bytes, max_body_size) {
            Ok(decoded) => {
                strip_encoding_headers(&mut parts.headers);
                decoded
            }
            Err(DecompressionError::UnsupportedEncoding(encoding)) => {
                warn!(
                    "Rejecting unsupported HTTP/3 request encoding from {} (Content-Encoding: {})",
                    client_ip, encoding
                );
                telemetry.reject(RequestRejection::UnsupportedContentEncoding);
                state.metrics.record_blocked();
                return send_response(
                    &mut stream,
                    WafProxyService::create_error_response(
                        StatusCode::UNSUPPORTED_MEDIA_TYPE,
                        "Unsupported request Content-Encoding",
                    ),
                )
                .await;
            }
            Err(DecompressionError::TooLarge) => {
                warn!(
                    "Decompressed HTTP/3 request body from {} exceeds limit {}",
                    client_ip, max_body_size
                );
                telemetry.reject(RequestRejection::DecompressedTooLarge);
                state.metrics.record_blocked();
                return send_response(
                    &mut stream,
                    WafProxyService::create_error_response(
                        StatusCode::PAYLOAD_TOO_LARGE,
                        "Decompressed request body too large",
                    ),
                )
                .await;
            }
            Err(DecompressionError::Malformed) => {
                warn!(
                    "Malformed compressed HTTP/3 request body from {}",
                    client_ip
                );
                telemetry.reject(RequestRejection::MalformedCompression);
                state.metrics.record_blocked();
                return send_response(
                    &mut stream,
                    WafProxyService::create_error_response(
                        StatusCode::BAD_REQUEST,
                        "Malformed compressed request body",
                    ),
                )
                .await;
            }
        }
    } else {
        body_bytes
    };

    let request_context = RequestContext::with_http_version(
        client_ip,
        parts.method.clone(),
        parts.uri.clone(),
        parts.headers.clone(),
        Some(body_bytes.len()),
        http_version.clone(),
    )
    .with_body(Some(body_bytes.clone()));

    match state.waf_engine.evaluate_shared(&request_context).await {
        Decision::Allow => {
            debug!(
                "WAF allowed HTTP/3 request from {}, forwarding upstream",
                client_ip
            );
            state.metrics.record_allowed();
            let response = WafProxyService::forward_to_upstream_with_protocol(
                parts,
                crate::proxy::service::ProxyBody::buffered(body_bytes, request_trailers),
                state.upstream_client.clone(),
                state.upstream_uri.clone(),
                start_time,
                &http_version,
                &state.metrics,
                client_ip,
                true,
                max_body_size,
                state
                    .config
                    .proxy
                    .streaming
                    .enabled
                    .then_some(state.config.proxy.streaming.response_threshold_bytes),
            )
            .await;
            let response = match response {
                Ok(response) => response,
                Err(never) => match never {},
            };
            send_response(&mut stream, response).await
        }
        Decision::Block { status, reason } => {
            warn!(
                "WAF blocked HTTP/3 request from {}: {} (status: {})",
                client_ip, reason, status
            );
            telemetry.reject(RequestRejection::WafBlocked);
            state.metrics.record_blocked();
            send_response(
                &mut stream,
                WafProxyService::create_blocked_response(status, &reason),
            )
            .await
        }
        Decision::RateLimit { reason } => {
            warn!(
                "WAF rate limited HTTP/3 request from {}: {}",
                client_ip, reason
            );
            telemetry.reject(RequestRejection::WafRateLimited);
            state.metrics.record_rate_limited();
            state.metrics.record_blocked();
            send_response(
                &mut stream,
                WafProxyService::create_rate_limit_response(&reason),
            )
            .await
        }
    }
}

/// Map an admission rejection to a clear, retryable HTTP/3 response.
fn admission_rejection_response(
    rejection: H3AdmissionRejection,
) -> Response<crate::proxy::service::ProxyBody> {
    let (status, message) = match rejection {
        H3AdmissionRejection::ClientLimit { .. } => {
            (StatusCode::TOO_MANY_REQUESTS, "Too Many Requests")
        }
        H3AdmissionRejection::Timeout { .. } => {
            (StatusCode::SERVICE_UNAVAILABLE, "Service Unavailable")
        }
    };
    let mut response = WafProxyService::create_error_response(status, message);
    response
        .headers_mut()
        .insert(http::header::RETRY_AFTER, HeaderValue::from_static("1"));
    response
}

enum BodyReadError {
    TooLarge,
    Stream(String),
}

async fn read_body(
    stream: &mut H3Stream,
    max_body_size: usize,
) -> Result<(Bytes, Option<HeaderMap>), BodyReadError> {
    let mut body = BytesMut::new();
    while let Some(mut chunk) = stream
        .recv_data()
        .await
        .map_err(|e| BodyReadError::Stream(e.to_string()))?
    {
        let len = chunk.remaining();
        if body.len().saturating_add(len) > max_body_size {
            return Err(BodyReadError::TooLarge);
        }
        body.extend_from_slice(&chunk.copy_to_bytes(len));
    }
    let trailers = stream
        .recv_trailers()
        .await
        .map_err(|e| BodyReadError::Stream(e.to_string()))?;
    Ok((body.freeze(), trailers))
}

async fn send_response(
    stream: &mut H3Stream,
    response: Response<crate::proxy::service::ProxyBody>,
) -> Result<(), WafError> {
    let (parts, body) = response.into_parts();

    // Collect frames so the header block is sent before any body data. Trailing
    // headers (gRPC `grpc-status`) are forwarded as HTTP/3 trailers.
    let mut body_bytes = BytesMut::new();
    let mut trailers = None;
    let mut body = std::pin::pin!(body);
    while let Some(frame) = body.frame().await {
        let frame = frame
            .map_err(|e| WafError::internal(format!("Failed to read response body: {}", e)))?;
        match frame.into_data() {
            Ok(data) => body_bytes.extend_from_slice(&data),
            Err(frame) => {
                if let Ok(block) = frame.into_trailers() {
                    trailers = Some(block);
                }
            }
        }
    }

    let mut builder = Response::builder().status(parts.status);
    for (name, value) in parts.headers.iter() {
        // Connection-specific headers are forbidden in HTTP/3.
        let name_str = name.as_str().to_ascii_lowercase();
        if crate::proxy::service::is_hop_by_hop_header(&name_str) {
            continue;
        }
        builder = builder.header(name, value);
    }
    let response = builder
        .body(())
        .map_err(|e| WafError::internal(format!("Failed to build HTTP/3 response: {}", e)))?;

    stream
        .send_response(response)
        .await
        .map_err(|e| WafError::NetworkError(format!("Failed to send HTTP/3 response: {}", e)))?;
    if !body_bytes.is_empty() {
        stream
            .send_data(body_bytes.freeze())
            .await
            .map_err(|e| WafError::NetworkError(format!("Failed to send HTTP/3 body: {}", e)))?;
    }
    match trailers {
        Some(trailers) => stream.send_trailers(trailers).await.map_err(|e| {
            WafError::NetworkError(format!("Failed to send HTTP/3 trailers: {}", e))
        })?,
        None => stream.finish().await.map_err(|e| {
            WafError::NetworkError(format!("Failed to finish HTTP/3 stream: {}", e))
        })?,
    }

    Ok(())
}

/// Rebuild a full URI from the pseudo-header-derived URI, falling back to the
/// `Host` header for authority and to `https` for the scheme.
fn reconstruct_uri(uri: &Uri, headers: &HeaderMap) -> Uri {
    let scheme = uri.scheme().cloned().unwrap_or(Scheme::HTTPS);
    let authority = uri.authority().cloned().or_else(|| {
        headers
            .get(HOST)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse().ok())
    });
    let path_and_query = uri
        .path_and_query()
        .map(|value| value.as_str())
        .filter(|value| !value.is_empty())
        .unwrap_or("/");

    let mut builder = Uri::builder().scheme(scheme).path_and_query(path_and_query);
    if let Some(authority) = authority {
        builder = builder.authority(authority);
    }
    builder.build().unwrap_or_else(|_| uri.clone())
}

/// HTTP/3 carries the authority in `:authority`; downstream/upstream code also
/// expects a `Host` header, so derive one when the client omitted it.
fn ensure_host_header(headers: &mut HeaderMap, uri: &Uri) {
    if headers.contains_key(HOST) {
        return;
    }
    if let Some(authority) = uri.authority() {
        if let Ok(value) = HeaderValue::from_str(authority.as_str()) {
            headers.insert(HOST, value);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::Full;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use rustls::pki_types::CertificateDer;
    use rustls::RootCertStore;
    use tokio::net::TcpListener;

    #[test]
    fn reconstructs_scheme_authority_and_path_from_host_header() {
        let uri: Uri = "/hello?x=1".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(HOST, "example.test:8443".parse().unwrap());

        let uri = reconstruct_uri(&uri, &headers);
        assert_eq!(uri.scheme_str(), Some("https"));
        assert_eq!(uri.authority().unwrap().as_str(), "example.test:8443");
        assert_eq!(uri.path_and_query().unwrap().as_str(), "/hello?x=1");

        ensure_host_header(&mut headers, &uri);
        assert_eq!(headers.get(HOST).unwrap(), "example.test:8443");
    }

    #[test]
    fn preserves_pseudo_header_uri_and_derives_host() {
        let uri: Uri = "https://api.example.test:443/v1/items?id=7"
            .parse()
            .unwrap();
        let mut headers = HeaderMap::new();

        let uri = reconstruct_uri(&uri, &headers);
        assert_eq!(uri.scheme_str(), Some("https"));
        assert_eq!(uri.authority().unwrap().as_str(), "api.example.test:443");
        assert_eq!(uri.path(), "/v1/items");
        assert_eq!(uri.query(), Some("id=7"));

        ensure_host_header(&mut headers, &uri);
        assert_eq!(headers.get(HOST).unwrap(), "api.example.test:443");
    }

    #[test]
    fn defaults_empty_path_to_root() {
        let uri: Uri = "https://example.test".parse().unwrap();
        let headers = HeaderMap::new();
        let uri = reconstruct_uri(&uri, &headers);
        assert_eq!(uri.path(), "/");
    }

    #[test]
    fn keeps_existing_host_header() {
        let uri: Uri = "https://authority.example.test/path".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(HOST, "public.example.test".parse().unwrap());

        ensure_host_header(&mut headers, &uri);
        assert_eq!(headers.get(HOST).unwrap(), "public.example.test");
    }

    // Test-only CA and leaf certificate for `localhost` (SAN=DNS:localhost,
    // IP:127.0.0.1). Never use these keys outside tests.
    const TEST_CA_PEM: &str = "\
-----BEGIN CERTIFICATE-----
MIIDDTCCAfWgAwIBAgIUdpWGwjW9XcYQKyEK/4hjC+D9zjMwDQYJKoZIhvcNAQEL
BQAwFjEUMBIGA1UEAwwLV0FGIFRlc3QgQ0EwHhcNMjYxMDMxMTk1MTUyWhcNMzYx
MDI4MTk1MTUyWjAWMRQwEgYDVQQDDAtXQUYgVGVzdCBDQTCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBALZjvFF5Lg6HGSK+6xOpm6o5qbtv52Z1wnb7Lqg5
uC57t+v2gch1hpr00caPRrHDoEC7kLpelr1Wy5AXQzCVgYpD9eJSgE1xXUmGDvfq
lKpGYDkkNxrhBINfYCJkRVqfeJtJoESMNSo9bHA94QDo2yiWPb527gLjzpHhwzYL
HOwxtbSxKK0rAK9Xqsgza6+cCaaDhRnIuTTN83uFUaRZIqEqGstXySJ/RykM2gQ7
cFAje8j2DWGtp9FR6B1dpF4Zf6TDl+7nnaety/deobLOivF5grjBDp/NJfpOCSpg
XCqPSx7dIjlZeSglbAfjvYYy6MEDKj5HNXRHgRR+HmE2WZMCAwEAAaNTMFEwHQYD
VR0OBBYEFNIzNYsCQmi+UdWU+jzkOmP0HY6oMB8GA1UdIwQYMBaAFNIzNYsCQmi+
UdWU+jzkOmP0HY6oMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEB
ALM5+1wV2ns1vIdUWv6gExmtkH9WyflLlPaN5POH3FzTmIcPlJDJ7J2BPcavRLJA
QsjhBa+9DBWVhOwTUyR9JIv5z22indzKxYyHFFVQ1FdUtfOH+rxhiK1VM93t/Enl
1jN852P/vYEEHWPm//optknj3vy11cGIsMYZC71c2jDXSz26HYZrddUAgz0/BWLn
+rP3t1oqPccvw99FC9eoX0acJr5WMxr6tzgG94p1uypiDKjq0j71qWrg/chJgzrS
njyYCxhim65UFPKp3UCqps56ZJ5eX1b04iH7v4xeNiwAxauSluBns4JiWLCY+nHr
ydDY32aRkmantnyFiWx8G5k=
-----END CERTIFICATE-----
";

    const TEST_CERT_PEM: &str = "\
-----BEGIN CERTIFICATE-----
MIIDSzCCAjOgAwIBAgIUSNUNDQlhqR6gTDLaj5Soj36TndkwDQYJKoZIhvcNAQEL
BQAwFjEUMBIGA1UEAwwLV0FGIFRlc3QgQ0EwHhcNMjYxMDMxMTk1MTUyWhcNMzYx
MDI4MTk1MTUyWjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQDdWbqwNDzo3Cnn8BIR3pSoyW+NiSE2N28dB36ZuFYV
oUZziOFR4wlKJ2r9ftDrAEmZad6IKcgbKvjSctq+5Dv/HZqNI/+K0rBATcx5o9j5
bmJLPYvuloIV621S0jePmZd/+2RFYZIYSWPtZWPSxhhGERSXco6cb4yEArznuh4f
9cxtRfbUZTiScxbo2xoRjppBbwkVWCpwidciSqHnVX1z/WiiQV7t5ejvkFvI5YzC
mYcntbmYFLKa/z5lQqM3RECFEb9t/S1PP8bQn7EUmfEzkvkAtP8qDFAURa3CslzY
H8upU2cLpSrY8vN4WQMaKsk7/+Z1tWezsv3X14aSKAqZAgMBAAGjgZIwgY8wGgYD
VR0RBBMwEYIJbG9jYWxob3N0hwR/AAABMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/
BAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMBMB0GA1UdDgQWBBRpkEcIStyqVu6S
ywVIrQqScVII1jAfBgNVHSMEGDAWgBTSMzWLAkJovlHVlPo85Dpj9B2OqDANBgkq
hkiG9w0BAQsFAAOCAQEAVLZc7SHlCCfVV38qxEQcO256O2k4j3K/neCWLkg/rKdc
yhmUDHE1WNpxmi/1q/l4o1EhqbDZvczSmGrzNn5IHi0n8tNMrp2gHhdz1mgVRjBB
c/4g7B4/ll9VAnijWhW1B5i+oygaDTx3v86EQQ71dxbRRZ3rKn1iiryQhizxih7R
RqT+0TI636cAZCi+bU3GsSnJIWvhKCIX1UhZHDvqXcHonW88C4JaRBRHnxDO/jdM
iYUcT6iwFa3uK6tYJJX5D3UZ/N/4BO43ZBweRcY7LwtM+ihmIC6RGLaYMKz5AAkE
rwPb1MDIlQiK7v4XSTxKCVCx8YSacdzABniMzX3e1g==
-----END CERTIFICATE-----
";

    const TEST_KEY_PEM: &str = "\
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDdWbqwNDzo3Cnn
8BIR3pSoyW+NiSE2N28dB36ZuFYVoUZziOFR4wlKJ2r9ftDrAEmZad6IKcgbKvjS
ctq+5Dv/HZqNI/+K0rBATcx5o9j5bmJLPYvuloIV621S0jePmZd/+2RFYZIYSWPt
ZWPSxhhGERSXco6cb4yEArznuh4f9cxtRfbUZTiScxbo2xoRjppBbwkVWCpwidci
SqHnVX1z/WiiQV7t5ejvkFvI5YzCmYcntbmYFLKa/z5lQqM3RECFEb9t/S1PP8bQ
n7EUmfEzkvkAtP8qDFAURa3CslzYH8upU2cLpSrY8vN4WQMaKsk7/+Z1tWezsv3X
14aSKAqZAgMBAAECggEASelJ3Md8pTbK6W8w4XWkxx2IGcc151AoUpWrkPHMEOnq
x+5nanv4oKG76Ix9f1L3wHno/CeTcXruXftLDp3QaNX+Qu3HyRekEbzIr79l1pgk
y0HwZUktg9s6hIK8Wb9sJqiPaVl0upZa/yyxYfKSrWbLrOxsMVFQJs5xPKFZqMrA
Hnljw+pd6aClF28dLmPJmvNxhlsXuSEYdIRp2dYUc2nedvFqa8qydufpNrhKvBha
F7P6au1JjFA47G9+HV9TzZvipYf8Rp+mYO0R3+P9owHlSTRXpnA36+nfb3WopURv
UMp+b6ForqXCzI2/WhHU99rFkNZeaf6hlnzO0INP1wKBgQD1LdBfXsWFj7y+6Wn3
wjeOppKMa8H6pYk1S2A4/bgd6YJ7xZdBkXvlp17RGrL97/1WJMTQdiFGoLyzn6Wq
ObNmWHLGTQ954Sp0rKcA1bs8s28rIe7Y7U7iaKFbhIkgP1wfO/Z+BLgVCuoIwZ53
OYoZV4/wUEmUW2wW+Q6yJU+ENwKBgQDnHq+5PZlcXHwE7Vwa3qgJ5Ok4iihkKem5
1Ni6t0cYROCYwNjqVhz5+AzCxbeFfR+qpN/Fb7OIIN32i++FaymB3s62ArLTV3um
3VluExWxUxDd9cb5zcV0gDDfVQ82a7+RA/Ihmr9vSNgorpGOfoGFt727mcd6mOFf
CK7nHYYfrwKBgGXNXBP9ee53PFvY91MUpZTpvTfpFmZIjaw/W/jOAMEK0E8sQB3N
lrBIyqnweBnQqFQ4eDBGnJKC81dyFouT4dXBLAcCwEZPJB3GAqHqHRCbQLGcKVyR
TIvd/gHOClIFfO7LKxIwS28RVRPFsVK35YuYPAAAlkyvmTYAvAVkUJwJAoGBAIe3
SVDpjyjhViI+j5tnrB1DQoBlAJrw0cLB7hKWlTT3HTwV4kqZDqLqufOVztKgSvwV
nSF/GlmRk0W3nosmBlWw1ImkxAW+lWnDCUTOCCr8sCbmsFT4ND7ZF9nNRQWb9/3b
5088Y7WhfO1GtUqLlttCrjN/ddfT9mOr4ajteVkZAoGANc5vpgdbAE0Yzwwn8LYb
QWGCPL0OlAvpG0fxSfU/ACaPzfOCphPB7Wym3qMSsoijbyYIbxU0rKarO5euJoOd
C4to928sojvm4JgYrCKvtWJs1pDB32NUk1ss7c9rNXnDJq5+PYRXUAlAqXbEoQKF
F4s3IuSi44rR0CGaogZ+O/I=
-----END PRIVATE KEY-----
";

    async fn spawn_upstream() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(
                            TokioIo::new(stream),
                            service_fn(|_req: Request<hyper::body::Incoming>| async {
                                Ok::<_, std::convert::Infallible>(
                                    Response::builder()
                                        .status(StatusCode::OK)
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

    fn write_test_tls_files(dir: &std::path::Path) -> (String, String) {
        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");
        std::fs::write(&cert_path, TEST_CERT_PEM).unwrap();
        std::fs::write(&key_path, TEST_KEY_PEM).unwrap();
        (
            cert_path.to_string_lossy().into_owned(),
            key_path.to_string_lossy().into_owned(),
        )
    }

    fn h3_client_endpoint() -> quinn::Endpoint {
        let certs = rustls_pemfile::certs(&mut std::io::BufReader::new(std::io::Cursor::new(
            TEST_CA_PEM.as_bytes(),
        )))
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()
        .unwrap();
        let mut roots = RootCertStore::empty();
        for cert in certs {
            roots.add(cert).unwrap();
        }
        let mut client_tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        client_tls.alpn_protocols = vec![b"h3".to_vec()];

        let quic_client = quinn::crypto::rustls::QuicClientConfig::try_from(client_tls).unwrap();
        let client_config = quinn::ClientConfig::new(Arc::new(quic_client));

        let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(client_config);
        endpoint
    }

    async fn start_h3_proxy(
        dir: &std::path::Path,
        configure: impl FnOnce(&mut crate::config::Config),
    ) -> (SocketAddr, quinn::Endpoint) {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let upstream = spawn_upstream().await;
        let (cert_path, key_path) = write_test_tls_files(dir);

        let mut config = crate::config::Config::default();
        config.upstream_uri = format!("http://{}", upstream);
        config.server.max_body_size = 4096;
        config.server.enable_http3 = true;
        config.server.tls.enabled = true;
        config.server.tls.cert_path = cert_path;
        config.server.tls.key_path = key_path;
        config.waf.rate_limit.per_ip_enabled = false;
        config.waf.rate_limit.global_enabled = false;
        // Protocol tests exercise HTTP/3, not the Coraza reactor; keep them
        // from compiling and warming the 20 MiB module.
        config.waf.coraza.enabled = false;
        configure(&mut config);

        let service = Arc::new(WafProxyService::new(config).unwrap());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = service.start_with_listener(listener).await;
        });

        (proxy_addr, h3_client_endpoint())
    }

    async fn connect_h3(endpoint: &quinn::Endpoint, proxy_addr: SocketAddr) -> quinn::Connection {
        // The UDP listener is started asynchronously by `start_with_listener`,
        // so retry the handshake briefly instead of racing it.
        let mut last_error = String::new();
        for _ in 0..40 {
            match endpoint.connect(proxy_addr, "localhost") {
                Ok(connecting) => {
                    match tokio::time::timeout(Duration::from_millis(250), connecting).await {
                        Ok(Ok(connection)) => return connection,
                        Ok(Err(e)) => last_error = e.to_string(),
                        Err(_) => last_error = "connect timed out".to_string(),
                    }
                }
                Err(e) => last_error = e.to_string(),
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("HTTP/3 connect failed: {}", last_error)
    }

    async fn send_h3_request(
        endpoint: &quinn::Endpoint,
        proxy_addr: SocketAddr,
        request: Request<()>,
        body: Option<Bytes>,
    ) -> (StatusCode, Bytes) {
        let connection = connect_h3(endpoint, proxy_addr).await;
        let (mut driver, mut send_request) = h3::client::new(h3_quinn::Connection::new(connection))
            .await
            .unwrap();
        tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });

        let mut stream = send_request.send_request(request).await.unwrap();
        if let Some(body) = body {
            stream.send_data(body).await.unwrap();
        }
        stream.finish().await.unwrap();

        let response = stream.recv_response().await.unwrap();
        let status = response.status();

        let mut response_body = BytesMut::new();
        while let Some(mut chunk) = stream.recv_data().await.unwrap() {
            let len = chunk.remaining();
            response_body.extend_from_slice(&chunk.copy_to_bytes(len));
        }
        (status, response_body.freeze())
    }

    #[tokio::test]
    async fn loopback_h3_request_is_proxied() {
        let dir = tempfile::tempdir().unwrap();
        let (proxy_addr, endpoint) = start_h3_proxy(dir.path(), |_| {}).await;

        let request = Request::get(format!("https://localhost:{}/h3-test", proxy_addr.port()))
            .body(())
            .unwrap();
        let (status, body) = send_h3_request(&endpoint, proxy_addr, request, None).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(&body[..], b"upstream-ok");
    }

    #[tokio::test]
    async fn blocks_sqli_in_query_over_h3() {
        let dir = tempfile::tempdir().unwrap();
        let (proxy_addr, endpoint) = start_h3_proxy(dir.path(), |_| {}).await;

        let request = Request::get(format!(
            "https://localhost:{}/?id=1%20UNION%20SELECT%20*%20FROM%20users",
            proxy_addr.port()
        ))
        .body(())
        .unwrap();
        let (status, _) = send_h3_request(&endpoint, proxy_addr, request, None).await;

        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn blocks_sqli_in_body_over_h3() {
        let dir = tempfile::tempdir().unwrap();
        let (proxy_addr, endpoint) = start_h3_proxy(dir.path(), |_| {}).await;

        let request = Request::post(format!("https://localhost:{}/login", proxy_addr.port()))
            .body(())
            .unwrap();
        let (status, _) = send_h3_request(
            &endpoint,
            proxy_addr,
            request,
            Some(Bytes::from_static(b"id=1 UNION SELECT * FROM users")),
        )
        .await;

        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn blocks_xss_in_body_over_h3() {
        let dir = tempfile::tempdir().unwrap();
        let (proxy_addr, endpoint) = start_h3_proxy(dir.path(), |_| {}).await;

        let request = Request::post(format!("https://localhost:{}/comment", proxy_addr.port()))
            .body(())
            .unwrap();
        let (status, _) = send_h3_request(
            &endpoint,
            proxy_addr,
            request,
            Some(Bytes::from_static(b"<script>alert(1)</script>")),
        )
        .await;

        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn rejects_oversized_body_over_h3() {
        let dir = tempfile::tempdir().unwrap();
        let (proxy_addr, endpoint) =
            start_h3_proxy(dir.path(), |config| config.server.max_body_size = 512).await;

        let request = Request::post(format!("https://localhost:{}/upload", proxy_addr.port()))
            .body(())
            .unwrap();
        let (status, _) = send_h3_request(
            &endpoint,
            proxy_addr,
            request,
            Some(Bytes::from(vec![b'A'; 4096])),
        )
        .await;

        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn admission_saturation_rejects_before_body_and_releases_permit() {
        let dir = tempfile::tempdir().unwrap();
        let (proxy_addr, endpoint) = start_h3_proxy(dir.path(), |config| {
            config.server.h3_max_inflight_requests = 1;
            config.server.h3_admission_timeout_ms = 50;
        })
        .await;

        let connection = connect_h3(&endpoint, proxy_addr).await;
        let (mut driver, mut send_request) = h3::client::new(h3_quinn::Connection::new(connection))
            .await
            .unwrap();
        tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });

        // Hold the only permit by leaving the first request body open.
        let request = Request::post(format!("https://localhost:{}/hold", proxy_addr.port()))
            .body(())
            .unwrap();
        let mut first = send_request.send_request(request).await.unwrap();
        first
            .send_data(Bytes::from_static(b"partial"))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        // A second request is rejected with 503 before its body is read.
        let request = Request::get(format!("https://localhost:{}/second", proxy_addr.port()))
            .body(())
            .unwrap();
        let mut second = send_request.send_request(request).await.unwrap();
        second.finish().await.unwrap();
        let response = second.recv_response().await.unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        while second.recv_data().await.unwrap().is_some() {}

        // Completing the first request releases the permit.
        first.finish().await.unwrap();
        let response = first.recv_response().await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        while first.recv_data().await.unwrap().is_some() {}
        tokio::time::sleep(Duration::from_millis(100)).await;

        let request = Request::get(format!(
            "https://localhost:{}/after-release",
            proxy_addr.port()
        ))
        .body(())
        .unwrap();
        let (status, body) = send_h3_request(&endpoint, proxy_addr, request, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(&body[..], b"upstream-ok");
    }

    #[tokio::test]
    async fn missing_api_key_is_rejected_over_h3() {
        let dir = tempfile::tempdir().unwrap();
        let (proxy_addr, endpoint) = start_h3_proxy(dir.path(), |config| {
            config.security.auth.enabled = true;
            config.security.auth.api_keys = vec!["test-api-key-123".to_string()];
            config.security.auth.header_name = "X-API-Key".to_string();
            config.security.auth.require_https = false;
        })
        .await;

        let request = Request::get(format!("https://localhost:{}/h3-test", proxy_addr.port()))
            .body(())
            .unwrap();
        let (status, _) = send_h3_request(&endpoint, proxy_addr, request, None).await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
}
