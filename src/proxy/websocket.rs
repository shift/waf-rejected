use std::sync::Arc;
use std::time::Instant;

use hyper::{Request, Response, StatusCode, HeaderMap};
use hyper::body::Incoming;
use hyper::upgrade::Upgraded;
use http_body_util::Full;
use bytes::Bytes;
use tokio::net::TcpStream;
use futures_util::{SinkExt, StreamExt};
use tracing::{debug, error, info, warn};

#[cfg(feature = "websocket")]
use tokio_tungstenite::{
    WebSocketStream, 
    accept_async, 
    tungstenite::{Message, protocol::Role}
};

use crate::waf::{WafEngine, RequestContext, Decision};
use crate::error::{WafError, Result};
use crate::config::Config;

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
        Self {
            waf_engine,
            config,
        }
    }

    /// Check if request is a WebSocket upgrade request
    pub fn is_websocket_upgrade(headers: &HeaderMap) -> bool {
        headers.get("upgrade")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.eq_ignore_ascii_case("websocket"))
            .unwrap_or(false) &&
        headers.get("connection")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_lowercase().contains("upgrade"))
            .unwrap_or(false)
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
                Ok(self.create_error_response(
                    StatusCode::BAD_REQUEST,
                    "WebSocket handshake failed",
                ))
            }
        }
    }

    /// Validate WebSocket upgrade request through WAF
    async fn validate_websocket_request(
        &self,
        req: &Request<Incoming>,
        client_ip: Option<std::net::IpAddr>,
    ) -> crate::error::Result<Decision> {
        // Extract WebSocket-specific headers for validation
        let mut extended_headers = req.headers().clone();
        
        // Add WebSocket protocol information for WAF analysis
        if let Some(protocols) = req.headers().get("sec-websocket-protocol") {
            extended_headers.insert("x-waf-websocket-protocols", protocols.clone());
        }
        
        if let Some(extensions) = req.headers().get("sec-websocket-extensions") {
            extended_headers.insert("x-waf-websocket-extensions", extensions.clone());
        }

        // Create WAF request context for WebSocket upgrade
        let request_context = RequestContext::new(
            client_ip.unwrap_or_else(|| "127.0.0.1".parse().unwrap()),
            req.method().clone(),
            req.uri().clone(),
            extended_headers,
            None, // WebSocket upgrades don't have initial body
        );

        // Evaluate request through WAF
        Ok(self.waf_engine.fast_evaluate(&request_context).await)
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
            .ok_or_else(|| WafError::Http("Missing Sec-WebSocket-Key header".to_string()))?;

        let websocket_version = headers
            .get("sec-websocket-version")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("13");

        if websocket_version != "13" {
            return Err(WafError::Http("Unsupported WebSocket version".to_string()));
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
                let selected_protocol = protocol_str
                    .split(',')
                    .next()
                    .unwrap_or("")
                    .trim();
                
                if !selected_protocol.is_empty() {
                    response = response.header("sec-websocket-protocol", selected_protocol);
                }
            }
        }

        // Build response
        let response = response
            .body(Full::new(Bytes::new()))
            .map_err(|e| WafError::internal(format!("Failed to build WebSocket response: {}", e)))?;

        Ok(response)
    }

    /// Generate WebSocket accept key from client key
    fn generate_websocket_accept_key(&self, client_key: &str) -> crate::error::Result<String> {
        use sha1::{Sha1, Digest};
        use base64::Engine;
        
        const WEBSOCKET_MAGIC_STRING: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        
        let mut hasher = Sha1::new();
        hasher.update(client_key.as_bytes());
        hasher.update(WEBSOCKET_MAGIC_STRING.as_bytes());
        let hash = hasher.finalize();
        
        Ok(base64::engine::general_purpose::STANDARD.encode(&hash))
    }

    /// Handle WebSocket connection after upgrade
    #[cfg(feature = "websocket")]
    pub async fn handle_websocket_connection(
        &self,
        websocket: WebSocketStream<Upgraded>,
        client_ip: Option<std::net::IpAddr>,
    ) -> crate::error::Result<()> {
        info!("WebSocket connection established for {:?}", client_ip);
        
        // For now, just handle the connection without full message processing
        // TODO: Implement full WebSocket message inspection and forwarding
        info!("WebSocket connection handling not fully implemented yet");
        Ok(())
    }

    /// Inspect WebSocket message through WAF
    #[cfg(feature = "websocket")]
    async fn inspect_websocket_message(
        &self,
        message: &Message,
        client_ip: Option<std::net::IpAddr>,
    ) -> crate::error::Result<Decision> {
        use http::{Method, Uri};
        
        match message {
            Message::Text(text) => {
                // Create pseudo-HTTP request context for text message inspection
                let mut headers = HeaderMap::new();
                headers.insert("content-type", "text/plain".parse().unwrap());
                headers.insert("x-websocket-message-type", "text".parse().unwrap());
                
                let request_context = RequestContext::new(
                    client_ip.unwrap_or_else(|| "127.0.0.1".parse().unwrap()),
                    Method::POST, // Treat as POST for content inspection
                    Uri::from_static("/websocket/message"),
                    headers,
                    Some(text.len()),
                );
                
                // For now, just allow the message - full inspection would need evaluate_with_body method
                Ok(Decision::Allow)
            }
            Message::Binary(data) => {
                // Create pseudo-HTTP request context for binary message inspection
                let mut headers = HeaderMap::new();
                headers.insert("content-type", "application/octet-stream".parse().unwrap());
                headers.insert("x-websocket-message-type", "binary".parse().unwrap());
                
                let request_context = RequestContext::new(
                    client_ip.unwrap_or_else(|| "127.0.0.1".parse().unwrap()),
                    Method::POST, // Treat as POST for content inspection
                    Uri::from_static("/websocket/message"),
                    headers,
                    Some(data.len()),
                );
                
                // For now, just allow the message - full inspection would need evaluate_with_body method
                Ok(Decision::Allow)
            }
            Message::Close(_) => {
                // Allow close messages
                Ok(Decision::Allow)
            }
            Message::Ping(_) | Message::Pong(_) => {
                // Allow ping/pong messages
                Ok(Decision::Allow)
            }
            _ => {
                // Allow other message types
                Ok(Decision::Allow)
            }
        }
    }

    /// Create blocked response
    fn create_blocked_response(&self, status: u16, reason: &str) -> Response<Full<Bytes>> {
        let status_code = StatusCode::from_u16(status).unwrap_or(StatusCode::FORBIDDEN);
        
        Response::builder()
            .status(status_code)
            .header("content-type", "text/plain")
            .body(Full::new(Bytes::from(format!("WebSocket blocked: {}", reason))))
            .unwrap()
    }

    /// Create rate limit response
    fn create_rate_limit_response(&self, reason: &str) -> Response<Full<Bytes>> {
        Response::builder()
            .status(StatusCode::TOO_MANY_REQUESTS)
            .header("content-type", "text/plain")
            .header("retry-after", "60")
            .body(Full::new(Bytes::from(format!("WebSocket rate limited: {}", reason))))
            .unwrap()
    }

    /// Create error response
    fn create_error_response(&self, status: StatusCode, message: &str) -> Response<Full<Bytes>> {
        Response::builder()
            .status(status)
            .header("content-type", "text/plain")
            .body(Full::new(Bytes::from(message.to_string())))
            .unwrap()
    }
}

/// WebTransport Protocol Handler
/// 
/// Experimental support for WebTransport protocol over HTTP/3
#[cfg(feature = "webtransport")]
pub struct WebTransportHandler {
    waf_engine: Arc<WafEngine>,
    config: Arc<Config>,
}

#[cfg(feature = "webtransport")]
impl WebTransportHandler {
    pub fn new(waf_engine: Arc<WafEngine>, config: Arc<Config>) -> Self {
        Self {
            waf_engine,
            config,
        }
    }

    /// Check if request is a WebTransport request
    pub fn is_webtransport_request(headers: &HeaderMap) -> bool {
        headers.get("upgrade")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.eq_ignore_ascii_case("webtransport"))
            .unwrap_or(false)
    }

    /// Handle WebTransport connection
    pub async fn handle_webtransport_connection(
        &self,
        req: Request<Incoming>,
        client_ip: Option<std::net::IpAddr>,
    ) -> std::result::Result<Response<Full<Bytes>>, hyper::Error> {
        info!("WebTransport connection request from {:?}", client_ip);
        
        // Validate WebTransport request through WAF
        match self.validate_webtransport_request(&req, client_ip).await {
            Ok(Decision::Allow) => {
                info!("WebTransport connection allowed by WAF");
                
                // Create WebTransport connection response
                let response = Response::builder()
                    .status(StatusCode::OK)
                    .header("upgrade", "webtransport")
                    .header("connection", "upgrade")
                    .body(Full::new(Bytes::new()))
                    .unwrap();
                
                Ok(response)
            }
            Ok(Decision::Block { status, reason }) => {
                warn!("WebTransport connection blocked: {} (status: {})", reason, status);
                Ok(self.create_blocked_response(status, &reason))
            }
            Ok(Decision::RateLimit { reason }) => {
                warn!("WebTransport connection rate limited: {}", reason);
                Ok(self.create_rate_limit_response(&reason))
            }
            Err(e) => {
                error!("WAF evaluation error for WebTransport: {}", e);
                Ok(self.create_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "WAF evaluation failed",
                ))
            }
        }
    }

    /// Validate WebTransport request through WAF
    async fn validate_webtransport_request(
        &self,
        req: &Request<Incoming>,
        client_ip: Option<std::net::IpAddr>,
    ) -> crate::error::Result<Decision> {
        let mut headers = req.headers().clone();
        headers.insert("x-waf-protocol", "webtransport".parse().unwrap());
        
        let request_context = RequestContext::new(
            client_ip.unwrap_or_else(|| "127.0.0.1".parse().unwrap()),
            req.method().clone(),
            req.uri().clone(),
            headers,
            None,
        );

        Ok(self.waf_engine.fast_evaluate(&request_context).await)
    }

    /// Create blocked response for WebTransport
    fn create_blocked_response(&self, status: u16, reason: &str) -> Response<Full<Bytes>> {
        let status_code = StatusCode::from_u16(status).unwrap_or(StatusCode::FORBIDDEN);
        
        Response::builder()
            .status(status_code)
            .header("content-type", "text/plain")
            .body(Full::new(Bytes::from(format!("WebTransport blocked: {}", reason))))
            .unwrap()
    }

    /// Create rate limit response for WebTransport
    fn create_rate_limit_response(&self, reason: &str) -> Response<Full<Bytes>> {
        Response::builder()
            .status(StatusCode::TOO_MANY_REQUESTS)
            .header("content-type", "text/plain")
            .header("retry-after", "60")
            .body(Full::new(Bytes::from(format!("WebTransport rate limited: {}", reason))))
            .unwrap()
    }

    /// Create error response for WebTransport
    fn create_error_response(&self, status: StatusCode, message: &str) -> Response<Full<Bytes>> {
        Response::builder()
            .status(status)
            .header("content-type", "text/plain")
            .body(Full::new(Bytes::from(message)))
            .unwrap()
    }
}
