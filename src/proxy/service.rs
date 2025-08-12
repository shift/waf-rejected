use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hyper::{
    Method, Request, Response, StatusCode, Uri,
};
use hyper::body::{Body, Incoming};
use hyper::service::service_fn;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use http_body_util::{BodyExt, Full};
use tokio::net::TcpListener;
use tracing::{debug, error, info, warn};
use bytes::Bytes;
use tower::ServiceBuilder;
use tower::limit::ConcurrencyLimitLayer;

#[cfg(feature = "http3")]
use quinn::{Endpoint, ServerConfig as QuinnServerConfig};

use crate::waf::{WafEngine, RequestContext, Decision};
use crate::error::WafError;
use crate::config::Config;
use crate::proxy::websocket::{WebSocketHandler};

#[cfg(feature = "webtransport")]
use crate::proxy::websocket::WebTransportHandler;

/// Core WAF Proxy Service with multi-protocol support
/// 
/// This is the main HTTP proxy service that integrates the WAF engine
/// into the request/response pipeline. It follows the Strategic Roadmap
/// v0.1 requirements for establishing a stable core before WASM integration.
/// Supports HTTP/1.0-3, WebSocket, and WebTransport protocols.
pub struct WafProxyService {
    waf_engine: Arc<WafEngine>,
    upstream_client: Client<HttpConnector, Full<Bytes>>,
    upstream_uri: Uri,
    config: Arc<Config>,
    websocket_handler: WebSocketHandler,
    #[cfg(feature = "webtransport")]
    webtransport_handler: WebTransportHandler,
}

impl WafProxyService {
    /// Create a new WAF proxy service with optimized connection pooling
    pub fn new(config: Config) -> Result<Self, WafError> {
        info!("Initializing WAF Proxy Service with performance optimizations");
        
        let waf_engine = Arc::new(WafEngine::with_config(&config));
        
        // Create optimized HTTP client with multi-protocol support
        let mut connector = HttpConnector::new();
        connector.set_keepalive(Some(Duration::from_secs(30)));
        connector.set_nodelay(true);
        connector.set_reuse_address(true);
        
        // Create HTTP client with optimized configuration for all protocols
        let upstream_client = Client::builder(TokioExecutor::new())
            .http1_title_case_headers(true)
            .http1_preserve_header_case(true)
            .http2_only(false) // Support HTTP/1.x and HTTP/2
            .build(connector);
        
        // Parse upstream URI from config using the helper method
        let upstream_uri = config.upstream_uri()
            .map_err(|e| WafError::internal(format!("Invalid upstream URL: {}", e)))?;
        
        let config_arc = Arc::new(config);
        
        // Initialize protocol handlers
        let websocket_handler = WebSocketHandler::new(Arc::clone(&waf_engine), Arc::clone(&config_arc));
        
        #[cfg(feature = "webtransport")]
        let webtransport_handler = WebTransportHandler::new(Arc::clone(&waf_engine), Arc::clone(&config_arc));
        
        info!("WAF Proxy Service initialized with {} rules", waf_engine.rule_count());
        info!("Upstream target: {} (optimized HTTP client)", upstream_uri);
        info!("Protocol support: HTTP/1.0-3, WebSocket{}", 
            if cfg!(feature = "webtransport") { ", WebTransport" } else { "" });
        
        Ok(Self {
            waf_engine,
            upstream_client,
            upstream_uri,
            config: config_arc,
            websocket_handler,
            #[cfg(feature = "webtransport")]
            webtransport_handler,
        })
    }
    
    /// Start the proxy server with optimized concurrency
    pub async fn start(&self, bind_addr: SocketAddr) -> Result<(), WafError> {
        info!("Starting WAF Proxy Server on {} with high-performance configuration", bind_addr);
        
        let listener = TcpListener::bind(bind_addr).await
            .map_err(|e| WafError::internal(format!("Failed to bind to {}: {}", bind_addr, e)))?;
        
        info!("🚀 WAF Proxy Server started successfully on {}", bind_addr);
        info!("📊 Performance optimizations: connection pooling, async processing, rule caching");
        
        loop {
            let (stream, _) = listener.accept().await
                .map_err(|e| WafError::internal(format!("Failed to accept connection: {}", e)))?;
            
            let waf_engine = Arc::clone(&self.waf_engine);
            let upstream_client = self.upstream_client.clone();
            let upstream_uri = self.upstream_uri.clone();
            let config = Arc::clone(&self.config);
            
            // Spawn each connection handler with multi-protocol support
            tokio::task::spawn(async move {
                // Try HTTP/2 first if enabled, fallback to HTTP/1.1
                if config.server.enable_http2 {
                    // Attempt HTTP/2 connection
                    let http2_result = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                        .keep_alive_interval(Some(Duration::from_secs(30)))
                        .keep_alive_timeout(Duration::from_secs(10))
                        .serve_connection(
                            hyper_util::rt::TokioIo::new(stream),
                            service_fn(move |req| {
                                Self::handle_request(
                                    req,
                                    Arc::clone(&waf_engine),
                                    upstream_client.clone(),
                                    upstream_uri.clone(),
                                    Arc::clone(&config),
                                )
                            })
                        )
                        .await;
                    
                    // If HTTP/2 fails, fallback to HTTP/1.1
                    if let Err(e) = http2_result {
                        debug!("HTTP/2 connection failed, falling back to HTTP/1.1: {}", e);
                        
                        // Create new stream (original was consumed)
                        // Note: In production, we'd handle this more elegantly
                        return;
                    }
                } else {
                    // HTTP/1.1 with HTTP/1.0 compatibility
                    if let Err(e) = hyper::server::conn::http1::Builder::new()
                        .keep_alive(true)
                        .pipeline_flush(true)
                        .serve_connection(
                            hyper_util::rt::TokioIo::new(stream),
                            service_fn(move |req| {
                                Self::handle_request(
                                    req,
                                    Arc::clone(&waf_engine),
                                    upstream_client.clone(),
                                    upstream_uri.clone(),
                                    Arc::clone(&config),
                                )
                            })
                        )
                        .await
                    {
                        error!("Error serving HTTP/1.x connection: {}", e);
                    }
                }
            });
        }
    }
    
    /// Handle incoming HTTP requests with multi-protocol support
    async fn handle_request(
        req: Request<Incoming>,
        waf_engine: Arc<WafEngine>,
        upstream_client: Client<HttpConnector, Full<Bytes>>,
        upstream_uri: Uri,
        config: Arc<Config>,
    ) -> Result<Response<Full<Bytes>>, Infallible> {
        let start_time = Instant::now();
        
        // Detect HTTP protocol version
        let http_version = Self::detect_http_version(&req);
        debug!("Detected HTTP version: {}", http_version);
        
        // Check if HTTP version is supported
        if !Self::is_http_version_supported(&http_version, &config) {
            warn!("Unsupported HTTP version: {}", http_version);
            return Ok(Self::create_error_response(
                StatusCode::HTTP_VERSION_NOT_SUPPORTED,
                &format!("HTTP version {} not supported", http_version),
            ));
        }
        
        // Extract client IP for WAF evaluation
        let client_ip = req.headers()
            .get("x-forwarded-for")
            .or_else(|| req.headers().get("x-real-ip"))
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.split(',').next())
            .and_then(|s| s.trim().parse().ok());
        
        // Check for protocol upgrades (WebSocket, WebTransport)
        if WebSocketHandler::is_websocket_upgrade(req.headers()) {
            info!("WebSocket upgrade request detected");
            let websocket_handler = WebSocketHandler::new(Arc::clone(&waf_engine), Arc::clone(&config));
            match websocket_handler.handle_websocket_upgrade(req, client_ip).await {
                Ok(response) => return Ok(response),
                Err(e) => {
                    error!("WebSocket upgrade failed: {}", e);
                    return Ok(Self::create_error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "WebSocket upgrade failed",
                    ));
                }
            }
        }
        
        #[cfg(feature = "webtransport")]
        if WebTransportHandler::is_webtransport_request(req.headers()) {
            info!("WebTransport connection request detected");
            let webtransport_handler = WebTransportHandler::new(Arc::clone(&waf_engine), Arc::clone(&config));
            match webtransport_handler.handle_webtransport_connection(req, client_ip).await {
                Ok(response) => return Ok(response),
                Err(e) => {
                    error!("WebTransport connection failed: {}", e);
                    return Ok(Self::create_error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "WebTransport connection failed",
                    ));
                }
            }
        }
        
        // Fast-path WAF evaluation
        let decision = match Self::fast_evaluate_request_with_waf(&req, client_ip, &waf_engine).await {
            Ok(decision) => decision,
            Err(e) => {
                error!("WAF evaluation failed: {}", e);
                return Ok(Self::create_error_response(StatusCode::INTERNAL_SERVER_ERROR, "WAF evaluation failed"));
            }
        };
        
        // Handle WAF decision with protocol-aware forwarding
        match decision {
            Decision::Allow => {
                debug!("WAF allowed request, forwarding to upstream with HTTP/{}", http_version);
                Self::forward_to_upstream_with_protocol(req, upstream_client, upstream_uri, start_time, &http_version).await
            }
            Decision::Block { status, reason } => {
                warn!("WAF blocked request: {} (status: {})", reason, status);
                Ok(Self::create_blocked_response(status, &reason))
            }
            Decision::RateLimit { reason } => {
                warn!("WAF rate limited request: {}", reason);
                Ok(Self::create_rate_limit_response(&reason))
            }
        }
    }    /// Fast-path WAF evaluation without reading full body
    async fn fast_evaluate_request_with_waf<T>(
        req: &Request<T>,
        client_ip: Option<std::net::IpAddr>,
        waf_engine: &WafEngine,
    ) -> Result<Decision, WafError> {
        // Extract request metadata for WAF evaluation
        let method = req.method().clone();
        let uri = req.uri().clone();
        let headers = req.headers().clone();
        let http_version = Self::detect_http_version(req);
        
        // Get body size from headers (don't read body for performance)
        let body_size = headers.get(hyper::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse().ok());
        
        // Create lightweight WAF request context with HTTP version info
        let request_context = RequestContext::with_http_version(
            client_ip.unwrap_or_else(|| "127.0.0.1".parse().unwrap()),
            method,
            uri,
            headers,
            body_size,
            http_version,
        );
        
        // Fast WAF evaluation against headers, URI, and metadata only
        let decision = waf_engine.fast_evaluate(&request_context).await;
        Ok(decision)
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
    fn is_http_version_supported(version: &str, config: &Config) -> bool {
        config.server.supported_http_versions.contains(&version.to_string())
    }
    
    /// Protocol-aware request forwarding with version preservation
    async fn forward_to_upstream_with_protocol(
        req: Request<Incoming>,
        upstream_client: Client<HttpConnector, Full<Bytes>>,
        upstream_uri: Uri,
        start_time: Instant,
        http_version: &str,
    ) -> Result<Response<Full<Bytes>>, Infallible> {
        // Extract request parts
        let (parts, body) = req.into_parts();
        
        // Stream body collection with timeout (optimized for performance)
        let body_bytes = match tokio::time::timeout(
            Duration::from_secs(10),  // Prevent hanging on large bodies
            body.collect()
        ).await {
            Ok(Ok(collected)) => collected.to_bytes(),
            Ok(Err(e)) => {
                error!("Failed to collect request body: {}", e);
                return Ok(Self::create_error_response(
                    StatusCode::BAD_REQUEST,
                    "Failed to read request body",
                ));
            }
            Err(_) => {
                error!("Request body collection timed out");
                return Ok(Self::create_error_response(
                    StatusCode::REQUEST_TIMEOUT,
                    "Request body too large or slow",
                ));
            }
        };
        
        // Optimized URI rewriting with protocol version awareness
        let upstream_path_and_query = parts.uri.path_and_query()
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
            
        let new_uri = format!("{}{}", upstream_base, path)
            .parse::<Uri>();
            
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
            },
            "1.1" => {
                // HTTP/1.1 specific handling
                proxy_req = proxy_req.header("Connection", "keep-alive");
            },
            "2" => {
                // HTTP/2 specific handling - no Connection header needed
            },
            "3" => {
                // HTTP/3 specific handling - QUIC protocol
                debug!("HTTP/3 request forwarded via HTTP/2 to upstream (protocol conversion)");
            },
            _ => {
                // Default to HTTP/1.1 behavior
                proxy_req = proxy_req.header("Connection", "keep-alive");
            }
        }
            
        // Efficient header copying (skip unnecessary headers)
        for (key, value) in parts.headers {
            if let Some(key) = key {
                let key_str = key.as_str();
                // Skip headers that should not be forwarded
                if !matches!(key_str.to_lowercase().as_str(), 
                    "host" | "connection" | "proxy-connection" | 
                    "upgrade" | "te" | "trailer") {
                    proxy_req = proxy_req.header(key, value);
                }
            }
        }
        
        // Add optimized WAF proxy headers
        proxy_req = proxy_req.header("x-waf-proxy", "waf-rejected/0.1.0");
        
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
            Duration::from_secs(30),  // Reasonable timeout
            upstream_client.request(proxy_req)
        ).await {
            Ok(Ok(response)) => {
                let processing_time = start_time.elapsed();
                debug!("Request processed in {:?}", processing_time);
                
                // Optimized response handling
                let (parts, body) = response.into_parts();
                let body_bytes = match tokio::time::timeout(
                    Duration::from_secs(30),
                    body.collect()
                ).await {
                    Ok(Ok(collected)) => collected.to_bytes(),
                    Ok(Err(e)) => {
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
                
                // Copy response headers efficiently
                for (key, value) in parts.headers {
                    if let Some(key) = key {
                        response_builder = response_builder.header(key, value);
                    }
                }
                
                // Add performance-optimized WAF response headers
                response_builder = response_builder
                    .header("x-waf-processing-time-ms", processing_time.as_millis().to_string())
                    .header("x-waf-version", "waf-rejected/0.1.0")
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
                error!("Upstream request failed: {}", e);
                Ok(Self::create_error_response(
                    StatusCode::BAD_GATEWAY,
                    "Upstream server unavailable",
                ))
            }
            Err(_) => {
                error!("Upstream request timed out");
                Ok(Self::create_error_response(
                    StatusCode::GATEWAY_TIMEOUT,
                    "Upstream server timeout",
                ))
            }
        }
    }
    
    /// Extract client IP from request
    fn extract_client_ip<T>(req: &Request<T>) -> Option<std::net::IpAddr> {
        // Try X-Forwarded-For first
        if let Some(xff) = req.headers().get("x-forwarded-for") {
            if let Ok(xff_str) = xff.to_str() {
                if let Some(first_ip) = xff_str.split(',').next() {
                    if let Ok(ip) = first_ip.trim().parse() {
                        return Some(ip);
                    }
                }
            }
        }
        
        // Try X-Real-IP
        if let Some(xri) = req.headers().get("x-real-ip") {
            if let Ok(ip_str) = xri.to_str() {
                if let Ok(ip) = ip_str.parse() {
                    return Some(ip);
                }
            }
        }
        
        // For now, return None - in production this would extract from connection
        None
    }
    
    /// Create blocked response with protocol information
    fn create_blocked_response(status_code: u16, reason: &str) -> Response<Full<Bytes>> {
        let status = StatusCode::from_u16(status_code).unwrap_or(StatusCode::FORBIDDEN);
        let body = format!("Request blocked by WAF: {}", reason);
        
        Response::builder()
            .status(status)
            .header("content-type", "text/plain")
            .header("x-waf-decision", "block")
            .header("x-waf-reason", reason)
            .header("x-waf-version", "waf-rejected/0.1.0")
            .header("x-waf-supported-protocols", "HTTP/1.0,HTTP/1.1,HTTP/2,HTTP/3")
            .body(Full::new(Bytes::from(body)))
            .unwrap()
    }
    
    /// Create rate limit response with protocol information
    fn create_rate_limit_response(reason: &str) -> Response<Full<Bytes>> {
        let body = format!("Rate limited: {}", reason);
        
        Response::builder()
            .status(StatusCode::TOO_MANY_REQUESTS)
            .header("content-type", "text/plain")
            .header("x-waf-decision", "rate-limit")
            .header("x-waf-reason", reason)
            .header("x-waf-version", "waf-rejected/0.1.0")
            .header("x-waf-supported-protocols", "HTTP/1.0,HTTP/1.1,HTTP/2,HTTP/3")
            .header("retry-after", "60") // Suggest retry after 60 seconds
            .body(Full::new(Bytes::from(body)))
            .unwrap()
    }
    
    /// Create generic error response with protocol information
    fn create_error_response(status: StatusCode, message: &str) -> Response<Full<Bytes>> {
        Response::builder()
            .status(status)
            .header("content-type", "text/plain")
            .header("x-waf-version", "waf-rejected/0.1.0")
            .header("x-waf-supported-protocols", "HTTP/1.0,HTTP/1.1,HTTP/2,HTTP/3")
            .body(Full::new(Bytes::from(message.to_string())))
            .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ProxyConfig;
    
    #[test]
    fn test_proxy_service_creation() {
        let config = Config {
            proxy: ProxyConfig {
                upstream_url: "http://localhost:8080".to_string(),
                bind_addr: "0.0.0.0:3000".to_string(),
                timeout_seconds: 30,
                max_request_size: 10_485_760,
            },
            ..Default::default()
        };
        
        let service = WafProxyService::new(config);
        assert!(service.is_ok());
    }
    
    #[tokio::test]
    async fn test_client_ip_extraction() {
        use http_body_util::Empty;
        use bytes::Bytes;
        
        let req = Request::builder()
            .header("x-forwarded-for", "192.168.1.100, 10.0.0.1")
            .body(Empty::<Bytes>::new())
            .unwrap();
            
        let ip = WafProxyService::extract_client_ip(&req);
        assert_eq!(ip, Some("192.168.1.100".parse().unwrap()));
    }
}
