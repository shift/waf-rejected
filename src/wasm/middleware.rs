//! WASM Middleware Integration
//! 
//! Tower middleware that integrates the WASM ModSecurity engine
//! into the HTTP request processing pipeline.

use std::sync::Arc;
use std::task::{Context, Poll};
use std::pin::Pin;
use std::future::Future;
use std::collections::HashMap;

use tower::{Layer, Service};
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use bytes::Bytes;
use tracing::{debug, error, warn};
use uuid::Uuid;

use crate::wasm::{WasmEngine, WasmRequestContext, SecurityMetadata, SecurityDecision};
use crate::wasm::context::RateLimitContext;

/// WASM middleware layer
#[derive(Clone)]
pub struct WasmLayer {
    wasm_engine: Arc<WasmEngine>,
}

impl WasmLayer {
    /// Create a new WASM layer
    pub fn new(wasm_engine: Arc<WasmEngine>) -> Self {
        Self { wasm_engine }
    }
}

impl<S> Layer<S> for WasmLayer {
    type Service = WasmMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        WasmMiddleware {
            inner,
            wasm_engine: self.wasm_engine.clone(),
        }
    }
}

/// WASM middleware service
#[derive(Clone)]
pub struct WasmMiddleware<S> {
    inner: S,
    wasm_engine: Arc<WasmEngine>,
}

// Simplified implementation for MVP - handles common body types
impl<S> Service<Request<hyper::body::Incoming>> for WasmMiddleware<S>
where
    S: Service<Request<Full<Bytes>>, Response = Response<Full<Bytes>>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    type Response = Response<Full<Bytes>>;
    type Error = Box<dyn std::error::Error + Send + Sync>;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, req: Request<hyper::body::Incoming>) -> Self::Future {
        let mut inner = self.inner.clone();
        let wasm_engine = self.wasm_engine.clone();

        Box::pin(async move {
            let (parts, body) = req.into_parts();

            // Collect body bytes for WASM analysis
            let body_bytes = match body.collect().await {
                Ok(collected) => collected.to_bytes().to_vec(),
                Err(e) => {
                    error!("Error collecting request body: {}", e);
                    vec![]
                }
            };

            // Convert headers to HashMap<String, String>
            let mut headers_map = HashMap::new();
            for (key, value) in parts.headers.iter() {
                if let Ok(value_str) = value.to_str() {
                    headers_map.insert(key.to_string(), value_str.to_string());
                }
            }

            // Extract client IP (simplified - in production would handle X-Forwarded-For, etc.)
            let client_ip = parts.headers
                .get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("127.0.0.1")
                .to_string();

            // Create WASM request context
            let wasm_ctx = WasmRequestContext {
                method: parts.method.to_string(),
                uri: parts.uri.to_string(),
                http_version: format!("{:?}", parts.version),
                headers: headers_map,
                client_ip: client_ip.clone(),
                body: Some(body_bytes.clone()),
                geo_context: None,
                security_metadata: SecurityMetadata {
                    timestamp: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                    request_id: Uuid::new_v4().to_string(),
                    violation_history: 0,
                    rate_limit_context: RateLimitContext {
                        current_count: 0,
                        window_size: 60,
                        max_requests: 1000,
                        reset_time: 0,
                    },
                    session_info: None,
                },
            };

            // Evaluate with WASM engine
            let decision = match wasm_engine.process_request(wasm_ctx).await {
                Ok(decision) => decision,
                Err(e) => {
                    warn!("WASM evaluation failed: {}, allowing request", e);
                    SecurityDecision::Allow
                }
            };

            debug!("WASM security decision: {:?}", decision);

            // Handle blocked requests
            match &decision {
                SecurityDecision::Block { message, .. } => {
                    let response = Response::builder()
                        .status(StatusCode::FORBIDDEN)
                        .header("Content-Type", "text/plain")
                        .body(Full::new(Bytes::from(format!("Request blocked by WAF: {}", message))))
                        .unwrap();
                    return Ok(response);
                }
                SecurityDecision::Log { rule_id, message, .. } => {
                    warn!("WAF Rule {} triggered: {}", rule_id, message);
                    // Log but allow - continue processing
                }
                SecurityDecision::Challenge { message, .. } => {
                    let response = Response::builder()
                        .status(StatusCode::TOO_MANY_REQUESTS)
                        .header("Content-Type", "text/plain")
                        .body(Full::new(Bytes::from(format!("Rate limited: {}", message))))
                        .unwrap();
                    return Ok(response);
                }
                SecurityDecision::Allow => {
                    // Continue processing
                }
            }

            // For allowed requests, reconstruct with Full<Bytes> body
            let new_body = Full::new(Bytes::from(body_bytes));
            let new_request = Request::from_parts(parts, new_body);

            match inner.call(new_request).await {
                Ok(response) => Ok(response),
                Err(e) => Err(e.into())
            }
        })
    }
}
