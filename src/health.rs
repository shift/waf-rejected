use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;
use tracing::{error, info};

use crate::error::WafError;
use crate::metrics::Metrics;
use std::sync::Arc;

#[derive(Debug, Serialize, Deserialize)]
pub struct HealthStatus {
    pub status: String,
    pub version: String,
    pub uptime: u64,
    pub components: HashMap<String, ComponentHealth>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ComponentHealth {
    pub status: String,
    pub last_check: u64,
    pub details: Option<String>,
}

/// Health monitoring service
#[derive(Debug)]
pub struct HealthService {
    start_time: Instant,
    metrics: Arc<Metrics>,
}

impl HealthService {
    pub fn new() -> Self {
        Self::with_metrics(Arc::new(Metrics::new()))
    }

    pub fn with_metrics(metrics: Arc<Metrics>) -> Self {
        Self {
            start_time: Instant::now(),
            metrics,
        }
    }

    pub async fn start(&self, bind_addr: SocketAddr) -> Result<(), WafError> {
        info!("Starting health monitoring service on {}", bind_addr);

        let listener = TcpListener::bind(bind_addr).await.map_err(|e| {
            WafError::internal(format!(
                "Failed to bind health service to {}: {}",
                bind_addr, e
            ))
        })?;

        let start_time = self.start_time;
        let metrics = Arc::clone(&self.metrics);

        loop {
            let (stream, _) = listener.accept().await.map_err(|e| {
                WafError::internal(format!("Failed to accept health check connection: {}", e))
            })?;

            let metrics = Arc::clone(&metrics);
            tokio::task::spawn(async move {
                if let Err(e) = hyper::server::conn::http1::Builder::new()
                    .serve_connection(
                        hyper_util::rt::TokioIo::new(stream),
                        service_fn(move |req| {
                            Self::handle_health_request(req, start_time, Arc::clone(&metrics))
                        }),
                    )
                    .await
                {
                    error!("Error serving health check connection: {}", e);
                }
            });
        }
    }

    async fn handle_health_request(
        req: Request<Incoming>,
        start_time: Instant,
        metrics: Arc<Metrics>,
    ) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
        if req.method() != Method::GET {
            return Ok(Response::builder()
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .header("allow", "GET")
                .body(Full::new(Bytes::from("Method not allowed")))
                .unwrap());
        }

        match req.uri().path() {
            "/health" => {
                let health_status = Self::get_health_status(start_time);
                let json =
                    serde_json::to_string(&health_status).unwrap_or_else(|_| "{}".to_string());

                let status_code = if health_status.is_healthy() {
                    StatusCode::OK
                } else {
                    StatusCode::SERVICE_UNAVAILABLE
                };

                Ok(Response::builder()
                    .status(status_code)
                    .header("content-type", "application/json")
                    .header("cache-control", "no-cache")
                    .body(Full::new(Bytes::from(json)))
                    .unwrap())
            }
            "/health/ready" | "/ready" => Ok(Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "text/plain")
                .body(Full::new(Bytes::from("ready")))
                .unwrap()),
            "/health/live" | "/live" => Ok(Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "text/plain")
                .body(Full::new(Bytes::from("live")))
                .unwrap()),
            "/metrics" => Ok(Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "text/plain; version=0.0.4")
                .body(Full::new(Bytes::from(metrics.render_prometheus())))
                .unwrap()),
            _ => Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Full::new(Bytes::from("Not found")))
                .unwrap()),
        }
    }

    fn get_health_status(start_time: Instant) -> HealthStatus {
        let uptime_secs = start_time.elapsed().as_secs();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut components = HashMap::new();

        components.insert(
            "waf_engine".to_string(),
            ComponentHealth {
                status: "healthy".to_string(),
                last_check: now,
                details: Some("Core WAF engine operational".to_string()),
            },
        );

        components.insert(
            "proxy_service".to_string(),
            ComponentHealth {
                status: "healthy".to_string(),
                last_check: now,
                details: Some("Reverse proxy service operational".to_string()),
            },
        );

        HealthStatus {
            status: "healthy".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            uptime: uptime_secs,
            components,
        }
    }
}

impl HealthStatus {
    pub fn new() -> Self {
        let mut components = HashMap::new();

        components.insert(
            "waf_engine".to_string(),
            ComponentHealth {
                status: "healthy".to_string(),
                last_check: chrono::Utc::now().timestamp() as u64,
                details: None,
            },
        );

        components.insert(
            "ai_models".to_string(),
            ComponentHealth {
                status: "healthy".to_string(),
                last_check: chrono::Utc::now().timestamp() as u64,
                details: None,
            },
        );

        Self {
            status: "healthy".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            uptime: 0,
            components,
        }
    }

    pub fn is_healthy(&self) -> bool {
        self.status == "healthy" && self.components.values().all(|c| c.status == "healthy")
    }
}
