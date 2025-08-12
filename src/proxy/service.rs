use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

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

use crate::waf::{WafEngine, RequestContext, Decision};
use crate::error::WafError;
use crate::config::Config;

/// Core WAF Proxy Service
/// 
/// This is the main HTTP proxy service that integrates the WAF engine
/// into the request/response pipeline. It follows the Strategic Roadmap
/// v0.1 requirements for establishing a stable core before WASM integration.
pub struct WafProxyService {
    waf_engine: Arc<WafEngine>,
    upstream_client: Client<HttpConnector, Full<Bytes>>,
    upstream_uri: Uri,
    config: Arc<Config>,
}

impl WafProxyService {
    /// Create a new WAF proxy service
    pub fn new(config: Config) -> Result<Self, WafError> {
        info!("Initializing WAF Proxy Service");
        
        let waf_engine = Arc::new(WafEngine::with_config(&config));
        let upstream_client = Client::builder(TokioExecutor::new()).build_http();
        
        // Parse upstream URI from config using the helper method
        let upstream_uri = config.upstream_uri()
            .map_err(|e| WafError::internal(format!("Invalid upstream URL: {}", e)))?;
        
        info!("WAF Proxy Service initialized with {} rules", waf_engine.rule_count());
        info!("Upstream target: {}", upstream_uri);
        
        Ok(Self {
            waf_engine,
            upstream_client,
            upstream_uri,
            config: Arc::new(config),
        })
    }
    
    /// Start the proxy server
    pub async fn start(&self, bind_addr: SocketAddr) -> Result<(), WafError> {
        info!("Starting WAF Proxy Server on {}", bind_addr);
        
        let listener = TcpListener::bind(bind_addr).await
            .map_err(|e| WafError::internal(format!("Failed to bind to {}: {}", bind_addr, e)))?;
        
        info!("🚀 WAF Proxy Server started successfully on {}", bind_addr);
        
        loop {
            let (stream, _) = listener.accept().await
                .map_err(|e| WafError::internal(format!("Failed to accept connection: {}", e)))?;
            
            let waf_engine = Arc::clone(&self.waf_engine);
            let upstream_client = self.upstream_client.clone();
            let upstream_uri = self.upstream_uri.clone();
            let config = Arc::clone(&self.config);
            
            tokio::task::spawn(async move {
                if let Err(e) = hyper::server::conn::http1::Builder::new()
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
                    error!("Error serving connection: {}", e);
                }
            });
        }
    }
    
    /// Handle incoming HTTP request through WAF pipeline
    async fn handle_request(
        req: Request<Incoming>,
        waf_engine: Arc<WafEngine>,
        upstream_client: Client<HttpConnector, Full<Bytes>>,
        upstream_uri: Uri,
        config: Arc<Config>,
    ) -> Result<Response<Full<Bytes>>, Infallible> {
        let start_time = Instant::now();
        let client_ip = Self::extract_client_ip(&req);
        let method = req.method().clone();
        let uri = req.uri().clone();
        
        debug!("Processing request: {} {} from {:?}", method, uri, client_ip);
        
        // Phase 1: WAF Evaluation
        let waf_decision = match Self::evaluate_request_with_waf(
            &req,
            client_ip,
            &waf_engine,
        ).await {
            Ok(decision) => decision,
            Err(e) => {
                error!("WAF evaluation failed: {}", e);
                return Ok(Self::create_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "WAF evaluation failed",
                ));
            }
        };
        
        // Phase 2: Decision Processing
        match waf_decision {
            Decision::Allow => {
                debug!("WAF allowed request, forwarding to upstream");
                Self::forward_to_upstream(req, upstream_client, upstream_uri, start_time).await
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
    }
    
    /// Evaluate request against WAF engine
    async fn evaluate_request_with_waf<T>(
        req: &Request<T>,
        client_ip: Option<std::net::IpAddr>,
        waf_engine: &WafEngine,
    ) -> Result<Decision, WafError> {
        // Extract request metadata for WAF evaluation
        let method = req.method().clone();
        let uri = req.uri().clone();
        let headers = req.headers().clone();
        
        // Estimate body size (in production, this would be more accurate)
        let body_size = headers.get(hyper::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse().ok());
        
        // Create WAF request context
        let request_context = RequestContext::new(
            client_ip.unwrap_or_else(|| "127.0.0.1".parse().unwrap()),
            method,
            uri,
            headers,
            body_size,
        );
        
        // Evaluate against WAF rules
        let decision = waf_engine.evaluate(&request_context).await;
        Ok(decision)
    }
    
    /// Forward allowed request to upstream server
    async fn forward_to_upstream(
        req: Request<Incoming>,
        upstream_client: Client<HttpConnector, Full<Bytes>>,
        upstream_uri: Uri,
        start_time: Instant,
    ) -> Result<Response<Full<Bytes>>, Infallible> {
        // Extract request parts
        let (parts, body) = req.into_parts();
        
        // Collect body bytes
        let body_bytes = match body.collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(e) => {
                error!("Failed to collect request body: {}", e);
                return Ok(Self::create_error_response(
                    StatusCode::BAD_REQUEST,
                    "Failed to read request body",
                ));
            }
        };
        
        // Rewrite request URI to point to upstream
        let upstream_path_and_query = parts.uri.path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/");
        
        // Properly handle path concatenation to avoid double slashes
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
        
        // Build new request
        let mut proxy_req = Request::builder()
            .method(parts.method)
            .uri(new_uri)
            .version(parts.version);
            
        // Copy headers and add proxy headers
        for (key, value) in parts.headers {
            if let Some(key) = key {
                if key.as_str().to_lowercase() != "host" {
                    proxy_req = proxy_req.header(key, value);
                }
            }
        }
        
        // Add WAF proxy headers
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
        
        // Forward request to upstream
        match upstream_client.request(proxy_req).await {
            Ok(response) => {
                let processing_time = start_time.elapsed();
                debug!("Request processed in {:?}", processing_time);
                
                // Convert response
                let (parts, body) = response.into_parts();
                let body_bytes = match body.collect().await {
                    Ok(collected) => collected.to_bytes(),
                    Err(e) => {
                        error!("Failed to collect upstream response body: {}", e);
                        return Ok(Self::create_error_response(
                            StatusCode::BAD_GATEWAY,
                            "Failed to read upstream response",
                        ));
                    }
                };
                
                let mut response_builder = Response::builder()
                    .status(parts.status)
                    .version(parts.version);
                
                // Copy response headers and add WAF headers
                for (key, value) in parts.headers {
                    if let Some(key) = key {
                        response_builder = response_builder.header(key, value);
                    }
                }
                
                // Add WAF response headers
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
            Err(e) => {
                error!("Upstream request failed: {}", e);
                Ok(Self::create_error_response(
                    StatusCode::BAD_GATEWAY,
                    "Upstream server unavailable",
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
    
    /// Create blocked response
    fn create_blocked_response(status_code: u16, reason: &str) -> Response<Full<Bytes>> {
        let status = StatusCode::from_u16(status_code).unwrap_or(StatusCode::FORBIDDEN);
        let body = format!("Request blocked by WAF: {}", reason);
        
        Response::builder()
            .status(status)
            .header("content-type", "text/plain")
            .header("x-waf-decision", "block")
            .header("x-waf-reason", reason)
            .header("x-waf-version", "waf-rejected/0.1.0")
            .body(Full::new(Bytes::from(body)))
            .unwrap()
    }
    
    /// Create rate limit response
    fn create_rate_limit_response(reason: &str) -> Response<Full<Bytes>> {
        let body = format!("Rate limited: {}", reason);
        
        Response::builder()
            .status(StatusCode::TOO_MANY_REQUESTS)
            .header("content-type", "text/plain")
            .header("x-waf-decision", "rate-limit")
            .header("x-waf-reason", reason)
            .header("x-waf-version", "waf-rejected/0.1.0")
            .header("retry-after", "60") // Suggest retry after 60 seconds
            .body(Full::new(Bytes::from(body)))
            .unwrap()
    }
    
    /// Create generic error response
    fn create_error_response(status: StatusCode, message: &str) -> Response<Full<Bytes>> {
        Response::builder()
            .status(status)
            .header("content-type", "text/plain")
            .header("x-waf-version", "waf-rejected/0.1.0")
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
