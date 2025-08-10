use std::task::{Context, Poll};
use std::net::SocketAddr;
use hyper::{Request, Response, StatusCode};
use hyper::body::Incoming;
use http_body_util::{Full, BodyExt};
use bytes::Bytes;
use tower::{Layer, Service, ServiceBuilder};
use tower::util::ServiceExt;
use futures::future::BoxFuture;
use crate::waf::{WafEngine, RequestContext, Decision};
use crate::error::{WafError, Result};

/// WAF middleware layer for Tower
#[derive(Clone)]
pub struct WafLayer {
    engine: WafEngine,
}

impl WafLayer {
    pub fn new(engine: WafEngine) -> Self {
        Self { engine }
    }
}

impl<S> Layer<S> for WafLayer {
    type Service = WafMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        WafMiddleware {
            inner,
            engine: self.engine.clone(),
        }
    }
}

/// WAF middleware service
#[derive(Clone)]
pub struct WafMiddleware<S> {
    inner: S,
    engine: WafEngine,
}

impl<S> WafMiddleware<S> {
    fn extract_client_ip(&self, req: &Request<Incoming>) -> Option<std::net::IpAddr> {
        // Try to get client IP from various sources
        
        // 1. Check X-Forwarded-For header (for reverse proxies)
        if let Some(forwarded_for) = req.headers().get("x-forwarded-for") {
            if let Ok(header_value) = forwarded_for.to_str() {
                // Take the first IP in the chain
                if let Some(first_ip) = header_value.split(',').next() {
                    if let Ok(ip) = first_ip.trim().parse() {
                        return Some(ip);
                    }
                }
            }
        }

        // 2. Check X-Real-IP header (for nginx)
        if let Some(real_ip) = req.headers().get("x-real-ip") {
            if let Ok(header_value) = real_ip.to_str() {
                if let Ok(ip) = header_value.parse() {
                    return Some(ip);
                }
            }
        }

        // 3. Extract from connection info (if available in extensions)
        if let Some(connect_info) = req.extensions().get::<SocketAddr>() {
            return Some(connect_info.ip());
        }

        // Fallback: localhost for testing
        None
    }

    fn create_error_response(status: StatusCode, message: &str) -> Result<Response<Full<Bytes>>> {
        let body = serde_json::json!({
            "error": {
                "status": status.as_u16(),
                "message": message,
                "timestamp": chrono::Utc::now().to_rfc3339(),
            }
        });

        Response::builder()
            .status(status)
            .header("content-type", "application/json")
            .header("x-waf-blocked", "true")
            .body(Full::new(Bytes::from(body.to_string())))
            .map_err(|e| WafError::internal(format!("Failed to build error response: {}", e)))
    }
}

impl<S> Service<Request<Incoming>> for WafMiddleware<S>
where
    S: Service<Request<Incoming>, Response = Response<Full<Bytes>>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Into<WafError> + Send,
{
    type Response = Response<Full<Bytes>>;
    type Error = WafError;
    type Future = BoxFuture<'static, std::result::Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<std::result::Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(|e| e.into())
    }

    fn call(&mut self, req: Request<Incoming>) -> Self::Future {
        let engine = self.engine.clone();
        let mut inner = self.inner.clone();

        Box::pin(async move {
            // Extract client IP
            let client_ip = match extract_client_ip_from_request(&req) {
                Some(ip) => ip,
                None => {
                    tracing::warn!("Could not determine client IP, using localhost");
                    std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
                }
            };

            // Get content length for body size checking
            let body_size = req.headers()
                .get("content-length")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<usize>().ok());

            // Create request context for WAF evaluation
            let ctx = RequestContext::new(
                client_ip,
                req.method().clone(),
                req.uri().clone(),
                req.headers().clone(),
                body_size,
            );

            // Evaluate WAF rules
            match engine.evaluate(&ctx).await {
                Decision::Allow => {
                    // Request is allowed, forward to inner service
                    inner.call(req).await.map_err(|e| e.into())
                }
                Decision::Block { status, reason } => {
                    tracing::info!(
                        client_ip = %client_ip,
                        method = %req.method(),
                        uri = %req.uri(),
                        status = status,
                        reason = %reason,
                        "WAF blocked request"
                    );

                    let status_code = StatusCode::from_u16(status)
                        .unwrap_or(StatusCode::FORBIDDEN);
                    Self::create_error_response(status_code, &reason)
                }
                Decision::RateLimit { reason } => {
                    tracing::info!(
                        client_ip = %client_ip,
                        method = %req.method(),
                        uri = %req.uri(),
                        reason = %reason,
                        "WAF rate limited request"
                    );

                    Self::create_error_response(StatusCode::TOO_MANY_REQUESTS, &reason)
                }
            }
        })
    }
}

// Helper function to extract client IP from request
fn extract_client_ip_from_request(req: &Request<Incoming>) -> Option<std::net::IpAddr> {
    // Try to get client IP from various sources
    
    // 1. Check X-Forwarded-For header (for reverse proxies)
    if let Some(forwarded_for) = req.headers().get("x-forwarded-for") {
        if let Ok(header_value) = forwarded_for.to_str() {
            // Take the first IP in the chain
            if let Some(first_ip) = header_value.split(',').next() {
                if let Ok(ip) = first_ip.trim().parse() {
                    return Some(ip);
                }
            }
        }
    }

    // 2. Check X-Real-IP header (for nginx)
    if let Some(real_ip) = req.headers().get("x-real-ip") {
        if let Ok(header_value) = real_ip.to_str() {
            if let Ok(ip) = header_value.parse() {
                return Some(ip);
            }
        }
    }

    // 3. Extract from connection info (if available in extensions)
    if let Some(connect_info) = req.extensions().get::<SocketAddr>() {
        return Some(connect_info.ip());
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::Infallible;
    use std::str::FromStr;
    use tower::ServiceExt;
    use hyper::{Method, Uri};
    use http_body_util::Empty;
    use crate::waf::{WafEngine, rules::IpRule};

    // Mock service for testing
    #[derive(Clone)]
    struct MockService;

    impl Service<Request<Incoming>> for MockService {
        type Response = Response<Full<Bytes>>;
        type Error = Infallible;
        type Future = BoxFuture<'static, std::result::Result<Self::Response, Self::Error>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<std::result::Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _req: Request<Incoming>) -> Self::Future {
            Box::pin(async {
                Ok(Response::new(Full::new(Bytes::from("mock response"))))
            })
        }
    }

    fn create_test_request(method: Method, uri: &str, client_ip: Option<&str>) -> Request<Incoming> {
        let body = Empty::<Bytes>::new().map_err(|never| match never {}).boxed();
        let mut req = Request::builder()
            .method(method)
            .uri(uri)
            .body(body)
            .unwrap();

        if let Some(ip) = client_ip {
            req.headers_mut().insert("x-forwarded-for", ip.parse().unwrap());
        }

        // Convert to the expected Incoming body type  
        // For testing, create an empty body that matches Incoming
        use hyper::body::Incoming;
        use http_body_util::Empty;
        
        let empty_body = Empty::<Bytes>::new();
        // We need to work around the type system here for testing
        let body: Incoming = unsafe { std::mem::transmute(empty_body) };
        
        let mut incoming_req = Request::builder()
            .method(method)
            .uri(uri)
            .body(body)
            .unwrap();
            
        if let Some(ip) = client_ip {
            incoming_req.headers_mut().insert("x-forwarded-for", ip.parse().unwrap());
        }

        incoming_req
    }

    #[tokio::test]
    async fn test_waf_middleware_allow() {
        let engine = WafEngine::new();
        let layer = WafLayer::new(engine);
        let mut service = layer.layer(MockService);

        let req = create_test_request(Method::GET, "/test", Some("192.168.1.100"));
        let response = service.ready().await.unwrap().call(req).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_waf_middleware_block() {
        let mut engine = WafEngine::new();
        engine.add_rule(
            IpRule::new("test_block_rule")
                .block_ip_str("192.168.1.100").unwrap()
        );

        let layer = WafLayer::new(engine);
        let mut service = layer.layer(MockService);

        let req = create_test_request(Method::GET, "/test", Some("192.168.1.100"));
        let response = service.ready().await.unwrap().call(req).await.unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(response.headers().contains_key("x-waf-blocked"));
    }

    #[tokio::test]
    async fn test_client_ip_extraction_forwarded_for() {
        let req = create_test_request(Method::GET, "/test", Some("203.0.113.1"));
        let ip = extract_client_ip_from_request(&req);
        
        assert_eq!(ip, Some(std::net::IpAddr::from_str("203.0.113.1").unwrap()));
    }

    #[tokio::test]
    async fn test_client_ip_extraction_forwarded_for_chain() {
        let mut req = create_test_request(Method::GET, "/test", None);
        req.headers_mut().insert("x-forwarded-for", "203.0.113.1, 192.168.1.1, 10.0.0.1".parse().unwrap());
        
        let ip = extract_client_ip_from_request(&req);
        assert_eq!(ip, Some(std::net::IpAddr::from_str("203.0.113.1").unwrap()));
    }

    #[tokio::test]
    async fn test_client_ip_extraction_real_ip() {
        let mut req = create_test_request(Method::GET, "/test", None);
        req.headers_mut().insert("x-real-ip", "203.0.113.5".parse().unwrap());
        
        let ip = extract_client_ip_from_request(&req);
        assert_eq!(ip, Some(std::net::IpAddr::from_str("203.0.113.5").unwrap()));
    }

    #[tokio::test]
    async fn test_client_ip_extraction_no_headers() {
        let req = create_test_request(Method::GET, "/test", None);
        let ip = extract_client_ip_from_request(&req);
        
        assert_eq!(ip, None);
    }
}
