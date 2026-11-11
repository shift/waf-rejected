use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
#[cfg(feature = "websocket")]
use futures_util::{SinkExt, StreamExt};
use http_body_util::Full;
use hyper::body::Incoming;
#[cfg(feature = "websocket")]
use hyper::upgrade::Upgraded;
use hyper::{HeaderMap, Request, Response, StatusCode};
#[cfg(feature = "websocket")]
use hyper_util::rt::TokioIo;
use tracing::{error, info, warn};

#[cfg(feature = "websocket")]
use tokio_tungstenite::{tungstenite::Message, WebSocketStream};

use crate::config::Config;
use crate::error::WafError;
use crate::waf::{Decision, RequestContext, WafEngine};

/// WebSocket Protocol Upgrade Handler
///
/// Handles WebSocket connection upgrades with WAF integration for
/// WebSocket frame inspection and real-time threat detection.
pub struct WebSocketHandler {
    waf_engine: Arc<WafEngine>,
    config: Arc<Config>,
}

impl WebSocketHandler {
    pub fn new(waf_engine: Arc<WafEngine>, config: Arc<Config>) -> Self {
        Self { waf_engine, config }
    }

    /// Check if request is a WebSocket upgrade request
    pub fn is_websocket_upgrade(headers: &HeaderMap) -> bool {
        let has_upgrade = headers
            .get("upgrade")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.eq_ignore_ascii_case("websocket"))
            .unwrap_or(false);
        let connection_has_upgrade = headers
            .get("connection")
            .and_then(|v| v.to_str().ok())
            .map(|value| {
                value
                    .split(',')
                    .map(str::trim)
                    .any(|token| token.eq_ignore_ascii_case("upgrade"))
            })
            .unwrap_or(false);
        let version_ok = headers
            .get("sec-websocket-version")
            .and_then(|v| v.to_str().ok())
            .map(|value| value.trim() == "13")
            .unwrap_or(false);
        let key_present = headers
            .get("sec-websocket-key")
            .and_then(|v| v.to_str().ok())
            .map(|value| !value.trim().is_empty())
            .unwrap_or(false);

        has_upgrade && connection_has_upgrade && version_ok && key_present
    }

    /// Validate the client handshake fields before any upstream connection is
    /// opened. `is_websocket_upgrade` already checks the upgrade tokens and
    /// version; this additionally requires a well-formed 16-byte key.
    pub fn validate_websocket_handshake(headers: &HeaderMap) -> Result<(), &'static str> {
        if !Self::is_websocket_upgrade(headers) {
            return Err("invalid WebSocket upgrade headers");
        }
        let key = headers
            .get("sec-websocket-key")
            .and_then(|value| value.to_str().ok())
            .ok_or("missing Sec-WebSocket-Key")?;
        use base64::Engine;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(key.trim())
            .map_err(|_| "invalid Sec-WebSocket-Key")?;
        if decoded.len() != 16 {
            return Err("invalid Sec-WebSocket-Key length");
        }
        Ok(())
    }

    /// Handle WebSocket upgrade with WAF validation
    pub async fn handle_websocket_upgrade(
        &self,
        req: Request<Incoming>,
        client_ip: Option<std::net::IpAddr>,
    ) -> std::result::Result<Response<Full<Bytes>>, hyper::Error> {
        let start_time = Instant::now();

        // Validate WebSocket upgrade request with WAF
        match self.validate_websocket_request(&req, client_ip).await {
            Ok(Decision::Allow) => {
                info!("WebSocket upgrade allowed by WAF");
            }
            Ok(Decision::Block { status, reason }) => {
                warn!("WebSocket upgrade blocked: {} (status: {})", reason, status);
                return Ok(self.create_blocked_response(status, &reason));
            }
            Ok(Decision::RateLimit { reason }) => {
                warn!("WebSocket upgrade rate limited: {}", reason);
                return Ok(self.create_rate_limit_response(&reason));
            }
            Err(e) => {
                error!("WAF evaluation error for WebSocket upgrade: {}", e);
                return Ok(self.create_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "WAF evaluation failed",
                ));
            }
        }

        // Perform WebSocket handshake
        match self.perform_websocket_handshake(req).await {
            Ok(response) => {
                let duration = start_time.elapsed();
                info!("WebSocket upgrade completed in {:?}", duration);
                Ok(response)
            }
            Err(e) => {
                error!("WebSocket handshake failed: {}", e);
                Ok(self
                    .create_error_response(StatusCode::BAD_REQUEST, "WebSocket handshake failed"))
            }
        }
    }

    /// Validate WebSocket upgrade request through WAF (Optimized)
    async fn validate_websocket_request(
        &self,
        req: &Request<Incoming>,
        client_ip: Option<std::net::IpAddr>,
    ) -> crate::error::Result<Decision> {
        // Pre-allocate headers capacity for better performance
        let mut extended_headers = HeaderMap::with_capacity(req.headers().len() + 2);
        extended_headers.extend(req.headers().iter().map(|(k, v)| (k.clone(), v.clone())));

        // Add WebSocket protocol information for WAF analysis (optimized)
        if let Some(protocols) = req.headers().get("sec-websocket-protocol") {
            extended_headers.insert("x-waf-websocket-protocols", protocols.clone());
        }

        if let Some(extensions) = req.headers().get("sec-websocket-extensions") {
            extended_headers.insert("x-waf-websocket-extensions", extensions.clone());
        }

        // Use static IP for better performance when client_ip is None
        static DEFAULT_IP: std::sync::OnceLock<std::net::IpAddr> = std::sync::OnceLock::new();
        let client_ip =
            client_ip.unwrap_or_else(|| *DEFAULT_IP.get_or_init(|| "127.0.0.1".parse().unwrap()));

        // Create optimized WAF request context for WebSocket upgrade
        let request_context = RequestContext::new(
            client_ip,
            req.method().clone(),
            req.uri().clone(),
            extended_headers,
            None, // WebSocket upgrades don't have initial body
        );

        // Use the full shared inspection path so the upgrade cannot bypass
        // protocol pre-checks or the async WAF stages.
        Ok(self.waf_engine.evaluate_shared(&request_context).await)
    }

    /// Perform WebSocket handshake
    async fn perform_websocket_handshake(
        &self,
        req: Request<Incoming>,
    ) -> crate::error::Result<Response<Full<Bytes>>> {
        // Validate required WebSocket headers
        let headers = req.headers();

        let websocket_key = headers
            .get("sec-websocket-key")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| WafError::http("Missing Sec-WebSocket-Key header".to_string()))?;

        let websocket_version = headers
            .get("sec-websocket-version")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("13");

        if websocket_version != "13" {
            return Err(WafError::http("Unsupported WebSocket version".to_string()));
        }

        // Generate WebSocket accept key
        let accept_key = self.generate_websocket_accept_key(websocket_key)?;

        // Create WebSocket upgrade response
        let mut response = Response::builder()
            .status(StatusCode::SWITCHING_PROTOCOLS)
            .header("upgrade", "websocket")
            .header("connection", "upgrade")
            .header("sec-websocket-accept", accept_key);

        // Handle WebSocket subprotocols
        if let Some(protocols) = headers.get("sec-websocket-protocol") {
            if let Ok(protocol_str) = protocols.to_str() {
                // Select first supported protocol (simple selection)
                let selected_protocol = protocol_str.split(',').next().unwrap_or("").trim();

                if !selected_protocol.is_empty() {
                    response = response.header("sec-websocket-protocol", selected_protocol);
                }
            }
        }

        // Build response
        let response = response.body(Full::new(Bytes::new())).map_err(|e| {
            WafError::internal(format!("Failed to build WebSocket response: {}", e))
        })?;

        Ok(response)
    }

    /// Generate WebSocket accept key from client key
    fn generate_websocket_accept_key(&self, client_key: &str) -> crate::error::Result<String> {
        use base64::Engine;
        use sha1::{Digest, Sha1};

        const WEBSOCKET_MAGIC_STRING: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

        let mut hasher = Sha1::new();
        hasher.update(client_key.as_bytes());
        hasher.update(WEBSOCKET_MAGIC_STRING.as_bytes());
        let hash = hasher.finalize();

        Ok(base64::engine::general_purpose::STANDARD.encode(&hash))
    }

    /// Handle WebSocket connection after upgrade (High-Performance)
    #[cfg(feature = "websocket")]
    pub async fn handle_websocket_connection(
        &self,
        websocket: WebSocketStream<TokioIo<Upgraded>>,
        client_ip: Option<std::net::IpAddr>,
    ) -> crate::error::Result<()> {
        info!(
            "High-performance WebSocket connection established for {:?}",
            client_ip
        );

        // Use fully-qualified split to ensure correct trait resolution
        let (mut ws_sender, mut ws_receiver) = futures_util::StreamExt::split(websocket);

        // High-performance message batching
        let mut message_batch = Vec::with_capacity(16);
        let mut last_batch_time = std::time::Instant::now();
        const BATCH_SIZE: usize = 16;
        const BATCH_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(10);

        // Pre-allocated reusable contexts for performance
        let mut reusable_headers = HeaderMap::with_capacity(8);

        while let Some(msg) = ws_receiver.next().await {
            match msg {
                Ok(Message::Text(text)) => {
                    message_batch.push(Message::Text(text));
                }
                Ok(Message::Binary(data)) => {
                    message_batch.push(Message::Binary(data));
                }
                Ok(Message::Ping(data)) => {
                    if ws_sender.send(Message::Pong(data)).await.is_err() {
                        break;
                    }
                    continue;
                }
                Ok(Message::Pong(_)) => {
                    continue;
                }
                Ok(Message::Close(close_frame)) => {
                    let _ = ws_sender.send(Message::Close(close_frame)).await;
                    break;
                }
                Ok(Message::Frame(_)) => {
                    // Low-level frames are allowed immediately and not echoed
                    continue;
                }
                Err(e) => {
                    warn!("WebSocket message error: {}", e);
                    break;
                }
            }

            let should_flush =
                message_batch.len() >= BATCH_SIZE || last_batch_time.elapsed() >= BATCH_TIMEOUT;

            if should_flush && !message_batch.is_empty() {
                let processed_messages = self
                    .process_message_batch(&message_batch, client_ip, &mut reusable_headers)
                    .await?;

                for response_msg in processed_messages {
                    if let Some(msg) = response_msg {
                        if ws_sender.send(msg).await.is_err() {
                            return Ok(());
                        }
                    }
                }

                message_batch.clear();
                last_batch_time = std::time::Instant::now();
            }
        }

        if !message_batch.is_empty() {
            let processed_messages = self
                .process_message_batch(&message_batch, client_ip, &mut reusable_headers)
                .await?;

            for response_msg in processed_messages {
                if let Some(msg) = response_msg {
                    let _ = ws_sender.send(msg).await;
                }
            }
        }

        info!("WebSocket connection closed for {:?}", client_ip);
        Ok(())
    }

    /// Process a batch of WebSocket messages for high performance
    #[cfg(feature = "websocket")]
    async fn process_message_batch(
        &self,
        messages: &[Message],
        client_ip: Option<std::net::IpAddr>,
        reusable_headers: &mut HeaderMap,
    ) -> crate::error::Result<Vec<Option<Message>>> {
        let mut results = Vec::with_capacity(messages.len());

        for message in messages {
            reusable_headers.clear();

            let result = match message {
                Message::Text(text) => {
                    match self.inspect_websocket_message(message, client_ip).await {
                        Ok(Decision::Allow) => Some(Message::Text(text.clone())),
                        Ok(Decision::Block { .. }) => {
                            warn!("WebSocket text message blocked for {:?}", client_ip);
                            None
                        }
                        Ok(Decision::RateLimit { .. }) => {
                            warn!("WebSocket text message rate-limited for {:?}", client_ip);
                            None
                        }
                        Err(e) => {
                            warn!("WebSocket inspection error: {}", e);
                            None
                        }
                    }
                }
                Message::Binary(data) => {
                    match self.inspect_websocket_message(message, client_ip).await {
                        Ok(Decision::Allow) => Some(Message::Binary(data.clone())),
                        Ok(Decision::Block { .. }) => {
                            warn!("WebSocket binary message blocked for {:?}", client_ip);
                            None
                        }
                        Ok(Decision::RateLimit { .. }) => {
                            warn!("WebSocket binary message rate-limited for {:?}", client_ip);
                            None
                        }
                        Err(e) => {
                            warn!("WebSocket inspection error: {}", e);
                            None
                        }
                    }
                }
                _ => Some(message.clone()),
            };

            results.push(result);
        }

        Ok(results)
    }

    /// Inspect WebSocket message through WAF (High-Performance)
    #[cfg(feature = "websocket")]
    async fn inspect_websocket_message(
        &self,
        message: &Message,
        client_ip: Option<std::net::IpAddr>,
    ) -> crate::error::Result<Decision> {
        use http::{Method, Uri};

        // Pre-compiled static URIs for better performance
        static TEXT_URI: std::sync::OnceLock<Uri> = std::sync::OnceLock::new();
        static BINARY_URI: std::sync::OnceLock<Uri> = std::sync::OnceLock::new();
        static DEFAULT_IP: std::sync::OnceLock<std::net::IpAddr> = std::sync::OnceLock::new();

        let client_ip =
            client_ip.unwrap_or_else(|| *DEFAULT_IP.get_or_init(|| "127.0.0.1".parse().unwrap()));

        match message {
            Message::Text(text) => {
                // Pre-allocated headers for text messages
                let mut headers = HeaderMap::with_capacity(2);
                headers.insert("content-type", "text/plain".parse().unwrap());
                headers.insert("x-websocket-message-type", "text".parse().unwrap());

                let uri = TEXT_URI.get_or_init(|| Uri::from_static("/websocket/message"));

                let request_context = RequestContext::new(
                    client_ip,
                    Method::POST, // Treat as POST for content inspection
                    uri.clone(),
                    headers,
                    Some(text.len()),
                )
                .with_body(Some(Bytes::copy_from_slice(text.as_bytes())));

                // Always run the full inspection path. The old small-message
                // fast path allowed text under 1 KiB without WAF evaluation.
                Ok(self.waf_engine.evaluate_shared(&request_context).await)
            }
            Message::Binary(data) => {
                // Pre-allocated headers for binary messages
                let mut headers = HeaderMap::with_capacity(2);
                headers.insert("content-type", "application/octet-stream".parse().unwrap());
                headers.insert("x-websocket-message-type", "binary".parse().unwrap());

                let uri = BINARY_URI.get_or_init(|| Uri::from_static("/websocket/binary"));

                let request_context = RequestContext::new(
                    client_ip,
                    Method::POST,
                    uri.clone(),
                    headers,
                    Some(data.len()),
                )
                .with_body(Some(Bytes::copy_from_slice(data)));

                // Always run the full inspection path. The old small-message
                // fast path allowed binary under 512 bytes without evaluation.
                Ok(self.waf_engine.evaluate_shared(&request_context).await)
            }
            Message::Close(_) | Message::Ping(_) | Message::Pong(_) => {
                // Control frames - allow immediately for performance
                Ok(Decision::Allow)
            }
            _ => {
                // Other message types - allow by default
                Ok(Decision::Allow)
            }
        }
    }

    /// Create blocked response.
    ///
    /// The client receives a generic body and the fixed rule-id category; the
    /// matched payload stays in the security event log.
    fn create_blocked_response(&self, status: u16, reason: &str) -> Response<Full<Bytes>> {
        let status_code = StatusCode::from_u16(status).unwrap_or(StatusCode::FORBIDDEN);
        let rule_id = crate::proxy::service::rule_id_for_reason(reason);
        let body = format!(
            "WebSocket blocked by WAF\nstatus: {}\nrule: {}\n",
            status_code.as_u16(),
            rule_id
        );

        finish_websocket_response(
            Response::builder()
                .status(status_code)
                .header("content-type", "text/plain")
                .header("x-waf-decision", "block")
                .header("x-waf-rule-id", rule_id),
            Full::new(Bytes::from(body)),
            StatusCode::FORBIDDEN,
        )
    }

    /// Create rate limit response. The reason is audit data, not client text.
    fn create_rate_limit_response(&self, _reason: &str) -> Response<Full<Bytes>> {
        finish_websocket_response(
            Response::builder()
                .status(StatusCode::TOO_MANY_REQUESTS)
                .header("content-type", "text/plain")
                .header("x-waf-decision", "rate-limit")
                .header("x-waf-rule-id", "rate-limit")
                .header("retry-after", "60"),
            Full::new(Bytes::from_static(
                b"WebSocket rate limited by WAF\nstatus: 429\nrule: rate-limit\n",
            )),
            StatusCode::TOO_MANY_REQUESTS,
        )
    }

    /// Create error response
    fn create_error_response(&self, status: StatusCode, message: &str) -> Response<Full<Bytes>> {
        finish_websocket_response(
            Response::builder()
                .status(status)
                .header("content-type", "text/plain"),
            Full::new(Bytes::from(message.to_string())),
            StatusCode::INTERNAL_SERVER_ERROR,
        )
    }
}

/// Finish a WebSocket response builder without panicking.
fn finish_websocket_response(
    builder: hyper::http::response::Builder,
    body: Full<Bytes>,
    fallback_status: StatusCode,
) -> Response<Full<Bytes>> {
    match builder.body(body) {
        Ok(response) => response,
        Err(error) => {
            error!(
                "Failed to build WebSocket WAF response, returning static fallback: {}",
                error
            );
            let mut response =
                Response::new(Full::new(Bytes::from_static(b"WebSocket blocked by WAF\n")));
            *response.status_mut() = fallback_status;
            response.headers_mut().insert(
                hyper::header::CONTENT_TYPE,
                hyper::header::HeaderValue::from_static("text/plain"),
            );
            response
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn upgrade_headers(connection: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("upgrade", "websocket".parse().unwrap());
        headers.insert("connection", connection.parse().unwrap());
        headers.insert("sec-websocket-version", "13".parse().unwrap());
        headers.insert(
            "sec-websocket-key",
            "dGhlIHNhbXBsZSBub25jZQ==".parse().unwrap(),
        );
        headers
    }

    #[test]
    fn accepts_exact_upgrade_connection_token() {
        assert!(WebSocketHandler::is_websocket_upgrade(&upgrade_headers(
            "keep-alive, Upgrade"
        )));
    }

    #[test]
    fn rejects_substring_connection_tokens() {
        assert!(!WebSocketHandler::is_websocket_upgrade(&upgrade_headers(
            "notupgrade"
        )));
    }

    #[test]
    fn rejects_missing_version_or_key() {
        let mut headers = upgrade_headers("Upgrade");
        headers.remove("sec-websocket-version");
        assert!(!WebSocketHandler::is_websocket_upgrade(&headers));
    }

    #[test]
    fn validates_websocket_handshake_key() {
        assert_eq!(
            WebSocketHandler::validate_websocket_handshake(&upgrade_headers("Upgrade")),
            Ok(())
        );

        let mut headers = upgrade_headers("Upgrade");
        headers.insert("sec-websocket-key", "not-base64!!".parse().unwrap());
        assert!(WebSocketHandler::validate_websocket_handshake(&headers).is_err());

        let mut headers = upgrade_headers("Upgrade");
        headers.insert("sec-websocket-key", "c2hvcnQ=".parse().unwrap());
        assert!(WebSocketHandler::validate_websocket_handshake(&headers).is_err());
    }

    #[cfg(feature = "websocket")]
    struct BlockMarkerRule;

    #[cfg(feature = "websocket")]
    impl crate::waf::WafRule for BlockMarkerRule {
        fn name(&self) -> &str {
            "block-marker"
        }

        fn evaluate(&self, ctx: &RequestContext) -> Decision {
            if ctx
                .body
                .as_deref()
                .is_some_and(|body| body.windows(6).any(|window| window == b"attack"))
            {
                Decision::Block {
                    status: 403,
                    reason: "marker".to_string(),
                }
            } else {
                Decision::Allow
            }
        }
    }

    #[cfg(feature = "websocket")]
    #[tokio::test]
    async fn small_text_message_is_not_allowed_by_a_fast_path() {
        let mut engine = WafEngine::new();
        engine.add_rule(BlockMarkerRule);
        let handler = WebSocketHandler::new(Arc::new(engine), Arc::new(Config::default()));

        let decision = handler
            .inspect_websocket_message(&Message::Text("attack".into()), None)
            .await
            .unwrap();
        assert!(matches!(decision, Decision::Block { status: 403, .. }));
    }
}
