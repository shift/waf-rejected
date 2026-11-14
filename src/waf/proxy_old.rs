use hyper::{Request, Response};
use hyper::body::Incoming;
use http_body_util::{Full, BodyExt};
use bytes::Bytes;
use tower::{Service, ServiceBuilder};
use tower::util::{BoxService, ServiceExt};
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use std::convert::Infallible;
use crate::config::Config;
use crate::error::{Result, WafError};
use crate::waf::{WafEngine, middleware::WafLayer, rules::*, rate_limit::*, 
               content_inspection::ContentInspectionRuleFactory,
               geoip::GeoBlockingRuleFactory};

/// WAF-enabled proxy service factory
pub struct WafProxyService;

impl WafProxyService {
    /// Create a WAF-enabled proxy service with middleware stack
    pub fn create(config: &Config) -> BoxService<Request<Incoming>, Response<Full<Bytes>>, WafError> {
        // Create base proxy service
        let base_service = BaseProxyService::new(config);
        
        // If WAF is disabled, return base service wrapped to match the error type
        if !config.waf.enabled {
            return ServiceBuilder::new()
                .service(base_service)
                .boxed();
        }

        // Create WAF engine with configured rules
        let mut engine = WafEngine::new();
        
        // Add request size rule
        engine.add_rule(
            RequestSizeRule::new("max_body_size", config.server.max_body_size)
        );
        
        // Add method blocking rules (block dangerous methods)
        let method_rule = MethodRule::new("blocked_methods")
            .block_method(hyper::Method::TRACE)
            .block_method(hyper::Method::CONNECT);
        engine.add_rule(method_rule);
        
        // Add per-IP rate limiting if enabled
        if config.waf.rate_limit.per_ip_enabled {
            engine.add_rule(
                RateLimiter::new(
                    "per_ip_rate_limit",
                    config.waf.rate_limit.per_ip_max_requests,
                    (config.waf.rate_limit.per_ip_max_requests as u64 / config.waf.rate_limit.per_ip_window_secs) as u32, // refill rate
                    std::time::Duration::from_secs(config.waf.rate_limit.per_ip_window_secs)
                )
            );
        }
        
        // Add global rate limiting if enabled  
        if config.waf.rate_limit.global_enabled {
            engine.add_rule(
                GlobalRateLimiter::new(
                    "global_rate_limit",
                    config.waf.rate_limit.global_max_requests,
                    (config.waf.rate_limit.global_max_requests as u64 / config.waf.rate_limit.global_window_secs) as u32 // refill rate
                )
            );
        }
        
        // Add basic header validation
        engine.add_rule(
            HeaderRule::new("security_headers")
                .forbid_header("x-forwarded-for")  // Example forbidden header
        );
        
        // Build service with WAF middleware
        ServiceBuilder::new()
            .layer(WafLayer::new(engine))
            .service(base_service)
            .boxed()
    }
}

/// Base proxy service without WAF (internal use)
#[derive(Clone)]
struct BaseProxyService {
    client: Client<HttpConnector, Full<Bytes>>,
    upstream_uri: String,
}

impl BaseProxyService {
    fn new(config: &Config) -> Self {
        let client = Client::builder(hyper_util::rt::TokioExecutor::new()).build_http();
        
        Self {
            client,
            upstream_uri: config.upstream_uri.clone(),
        }
    }
}

impl Service<Request<Incoming>> for BaseProxyService {
    type Response = Response<Full<Bytes>>;
    type Error = WafError;
    type Future = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self::Response>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<Incoming>) -> Self::Future {
        let client = self.client.clone();
        let upstream_uri = self.upstream_uri.clone();
        
        Box::pin(async move {
            tracing::debug!("Forwarding request to upstream: {} {}", req.method(), req.uri());
            
            // Convert the request to forward to upstream
            let (parts, body) = req.into_parts();
            
            // Collect the body
            let body_bytes = match body.collect().await {
                Ok(collected) => collected.to_bytes(),
                Err(e) => return Err(WafError::internal(format!("Failed to read request body: {}", e))),
            };
            
            // Build upstream request URI
            let upstream_path = parts.uri.path_and_query()
                .map(|pq| pq.as_str())
                .unwrap_or("/");
            let full_upstream_uri = format!("{}{}", upstream_uri, upstream_path);

            // Build upstream request
            let mut upstream_req = Request::builder()
                .method(parts.method)
                .uri(full_upstream_uri)
                .body(Full::new(body_bytes))
                .map_err(|e| WafError::http(e.to_string()))?;
            
            // Copy headers (but skip host header to avoid conflicts)
            *upstream_req.headers_mut() = parts.headers;
            upstream_req.headers_mut().remove("host");

            // Forward request to upstream
            let upstream_response = client.request(upstream_req).await
                .map_err(|e| WafError::upstream_connection(format!("Upstream request failed: {}", e)))?;

            tracing::debug!("Upstream response: {}", upstream_response.status());

            // Convert upstream response body
            let (parts, body) = upstream_response.into_parts();
            let body_bytes = body.collect().await
                .map_err(|e| WafError::internal(format!("Failed to read upstream response: {}", e)))?
                .to_bytes();

            let response = Response::from_parts(parts, Full::new(body_bytes));
            Ok(response)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tower::ServiceExt;
    use hyper::{Method, StatusCode};
    use http_body_util::Empty;
    use hyper::body::Incoming;

    fn create_test_config() -> Config {
        let mut config = Config::default();
        config.waf.enabled = true;
        config
    }

    fn create_test_request(method: Method, uri: &str) -> Request<Incoming> {
        use hyper::body::Incoming;
        use http_body_util::{Empty};
        
        // Create an empty body for testing
        let empty_body = Empty::<Bytes>::new();
        
        let req = Request::builder()
            .method(method)
            .uri(uri)
            .header("user-agent", "test-agent")
            .body(empty_body)
            .unwrap();
            
        // Create a new request with the proper body type for testing
        let req = Request::builder()
            .method(req.method())
            .uri(req.uri())
            .version(req.version())
            .body(hyper::body::Incoming::default())
            .unwrap();
        
        req
    }

    #[tokio::test]
    async fn test_waf_service_creation() {
        let config = create_test_config();
        let _service = WafProxyService::create(&config);
        // Just test that service creation succeeds
    }

    #[tokio::test]
    async fn test_waf_disabled() {
        let mut config = create_test_config();
        config.waf.enabled = false;
        
        let mut service = WafProxyService::create(&config);
        let req = create_test_request(Method::GET, "/test");
        
        // Should attempt to proxy (will fail due to no upstream, but WAF should be bypassed)
        let result = service.ready().await.unwrap().call(req).await;
        
        // Expect upstream error, not WAF block
        assert!(result.is_err());
        match result.unwrap_err() {
            WafError::Upstream(_) => {}, // Expected
            _ => panic!("Expected upstream error when WAF disabled"),
        }
    }

    #[tokio::test]
    async fn test_method_blocking() {
        let config = create_test_config();
        let mut service = WafProxyService::create(&config);
        
        // TRACE method should be blocked
        let req = create_test_request(Method::TRACE, "/test");
        let response = service.ready().await.unwrap().call(req).await.unwrap();
        
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert!(response.headers().contains_key("x-waf-blocked"));
    }

    #[tokio::test]
    async fn test_empty_user_agent_blocking() {
        let config = create_test_config();
        let mut service = WafProxyService::create(&config);
        
        use hyper::body::Incoming;
        use http_body_util::{Empty};
        
        // Create an empty body for testing
        let empty_body = Empty::<Bytes>::new();
        
        let req = Request::builder()
            .method(Method::GET)
            .uri("/test")
            .header("user-agent", "")  // Empty user-agent should be blocked
            .body(empty_body)
            .unwrap();
            
        // Create a new request with the proper body type for testing
        let req = Request::builder()
            .method(req.method())
            .uri(req.uri())
            .version(req.version())
            .body(hyper::body::Incoming::default())
            .unwrap();
        
        let response = service.ready().await.unwrap().call(req).await.unwrap();
        
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(response.headers().contains_key("x-waf-blocked"));
    }
}
