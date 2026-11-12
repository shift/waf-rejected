use async_trait::async_trait;
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

/// One dependency probed by readiness.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyHealth {
    /// Machine-readable dependency name, e.g. `inspection_engine` or `CEF`.
    pub name: String,
    /// `healthy`, `degraded` or `down`.
    pub status: String,
    /// Whether a failure makes the process not ready.
    pub required: bool,
    pub detail: Option<String>,
}

/// A consistent snapshot of the process dependencies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadinessSnapshot {
    /// Selected inspection backend (`rust`, `wasm`, `native`, or `disabled`).
    pub backend: String,
    /// True when the configured engine initialised and is warm.
    pub engine_ready: bool,
    pub engine_detail: Option<String>,
    /// Event store and exporter checks.
    pub dependencies: Vec<DependencyHealth>,
}

/// Readiness probe implemented by the proxy (engine + event exporters).
#[async_trait]
pub trait ReadinessProbe: Send + Sync {
    async fn snapshot(&self) -> ReadinessSnapshot;
}

/// Machine-readable readiness response served by `/health/ready` and `/ready`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadinessReport {
    /// `ready`, `degraded` or `not_ready`.
    pub status: String,
    /// True only for `ready`.
    pub ready: bool,
    /// Stable machine-readable reason when not ready (for example
    /// `engine_not_ready`, `event_store_unavailable` or
    /// `exporter_unavailable:CEF`).
    pub reason: Option<String>,
    pub backend: String,
    pub version: String,
    pub uptime: u64,
    pub dependencies: Vec<DependencyHealth>,
}

/// Health monitoring service
pub struct HealthService {
    start_time: Instant,
    metrics: Arc<Metrics>,
    probe: Option<Arc<dyn ReadinessProbe>>,
    dependency_checks: bool,
}

impl std::fmt::Debug for HealthService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HealthService")
            .field("start_time", &self.start_time)
            .field("dependency_checks", &self.dependency_checks)
            .field("has_probe", &self.probe.is_some())
            .finish()
    }
}

impl HealthService {
    pub fn new() -> Self {
        Self::with_metrics(Arc::new(Metrics::new()))
    }

    pub fn with_metrics(metrics: Arc<Metrics>) -> Self {
        Self {
            start_time: Instant::now(),
            metrics,
            probe: None,
            dependency_checks: false,
        }
    }

    /// Build a readiness service that probes real dependencies.
    ///
    /// `dependency_checks = false` keeps `/health/ready` as a liveness alias
    /// for operators that only want a process check.
    pub fn with_readiness(
        metrics: Arc<Metrics>,
        probe: Arc<dyn ReadinessProbe>,
        dependency_checks: bool,
    ) -> Self {
        Self {
            start_time: Instant::now(),
            metrics,
            probe: Some(probe),
            dependency_checks,
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
        let probe = self.probe.clone();
        let dependency_checks = self.dependency_checks;

        loop {
            let (stream, _) = listener.accept().await.map_err(|e| {
                WafError::internal(format!("Failed to accept health check connection: {}", e))
            })?;

            let metrics = Arc::clone(&metrics);
            let probe = probe.clone();
            tokio::task::spawn(async move {
                if let Err(e) = hyper::server::conn::http1::Builder::new()
                    .serve_connection(
                        hyper_util::rt::TokioIo::new(stream),
                        service_fn(move |req| {
                            Self::handle_health_request(
                                req,
                                start_time,
                                Arc::clone(&metrics),
                                probe.clone(),
                                dependency_checks,
                            )
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
        probe: Option<Arc<dyn ReadinessProbe>>,
        dependency_checks: bool,
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
                let health_status = Self::get_health_status(start_time, probe.as_deref()).await;
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
            "/health/ready" | "/ready" => {
                let report = Self::readiness(start_time, probe.as_deref(), dependency_checks).await;
                let json = serde_json::to_string(&report).unwrap_or_else(|_| "{}".to_string());
                let status_code = if report.ready {
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

    async fn readiness(
        start_time: Instant,
        probe: Option<&dyn ReadinessProbe>,
        dependency_checks: bool,
    ) -> ReadinessReport {
        let uptime = start_time.elapsed().as_secs();
        let version = env!("CARGO_PKG_VERSION").to_string();

        if !dependency_checks {
            return ReadinessReport {
                status: "ready".to_string(),
                ready: true,
                reason: None,
                backend: "unchecked".to_string(),
                version,
                uptime,
                dependencies: Vec::new(),
            };
        }

        let Some(probe) = probe else {
            // No probe attached: the service itself is the only dependency.
            return ReadinessReport {
                status: "ready".to_string(),
                ready: true,
                reason: None,
                backend: "unknown".to_string(),
                version,
                uptime,
                dependencies: Vec::new(),
            };
        };

        let snapshot = probe.snapshot().await;
        let mut dependencies = Vec::new();
        let mut reason = None;
        let mut status = "ready";

        dependencies.push(DependencyHealth {
            name: "inspection_engine".to_string(),
            status: if snapshot.engine_ready {
                "healthy".to_string()
            } else {
                "down".to_string()
            },
            required: true,
            detail: snapshot.engine_detail.clone(),
        });
        if !snapshot.engine_ready {
            status = "not_ready";
            reason = Some("engine_not_ready".to_string());
        }

        for dependency in &snapshot.dependencies {
            if dependency.status != "healthy" {
                if dependency.required {
                    status = "not_ready";
                    reason = Some(format!(
                        "{}_unavailable:{}",
                        dependency_kind(dependency),
                        dependency.name
                    ));
                } else if status == "ready" {
                    status = "degraded";
                    reason = Some(format!(
                        "{}_degraded:{}",
                        dependency_kind(dependency),
                        dependency.name
                    ));
                }
            }
            dependencies.push(dependency.clone());
        }

        ReadinessReport {
            status: status.to_string(),
            ready: status == "ready",
            reason,
            backend: snapshot.backend,
            version,
            uptime,
            dependencies,
        }
    }

    async fn get_health_status(
        start_time: Instant,
        probe: Option<&dyn ReadinessProbe>,
    ) -> HealthStatus {
        let uptime_secs = start_time.elapsed().as_secs();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut components = HashMap::new();

        match probe {
            Some(probe) => {
                let snapshot = probe.snapshot().await;
                components.insert(
                    "waf_engine".to_string(),
                    ComponentHealth {
                        status: if snapshot.engine_ready {
                            "healthy".to_string()
                        } else {
                            "unhealthy".to_string()
                        },
                        last_check: now,
                        details: Some(
                            snapshot
                                .engine_detail
                                .clone()
                                .unwrap_or_else(|| format!("backend={}", snapshot.backend)),
                        ),
                    },
                );
                for dependency in snapshot.dependencies {
                    components.insert(
                        dependency.name,
                        ComponentHealth {
                            status: if dependency.status == "healthy" {
                                "healthy".to_string()
                            } else {
                                "unhealthy".to_string()
                            },
                            last_check: now,
                            details: dependency.detail,
                        },
                    );
                }
            }
            None => {
                components.insert(
                    "waf_engine".to_string(),
                    ComponentHealth {
                        status: "healthy".to_string(),
                        last_check: now,
                        details: Some("Readiness probe not attached".to_string()),
                    },
                );
            }
        }

        components.insert(
            "proxy_service".to_string(),
            ComponentHealth {
                status: "healthy".to_string(),
                last_check: now,
                details: Some("Reverse proxy service operational".to_string()),
            },
        );

        let healthy = components.values().all(|c| c.status == "healthy");

        HealthStatus {
            status: if healthy { "healthy" } else { "unhealthy" }.to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            uptime: uptime_secs,
            components,
        }
    }
}

fn dependency_kind(dependency: &DependencyHealth) -> &'static str {
    match dependency.name.as_str() {
        "Sled" => "event_store",
        _ => "exporter",
    }
}

impl Default for HealthService {
    fn default() -> Self {
        Self::new()
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

#[cfg(test)]
mod tests {
    use super::*;

    struct StubProbe(ReadinessSnapshot);

    #[async_trait]
    impl ReadinessProbe for StubProbe {
        async fn snapshot(&self) -> ReadinessSnapshot {
            self.0.clone()
        }
    }

    fn snapshot(engine_ready: bool, dependencies: Vec<DependencyHealth>) -> ReadinessSnapshot {
        ReadinessSnapshot {
            backend: "rust".to_string(),
            engine_ready,
            engine_detail: Some("rust engine compiled and warm".to_string()),
            dependencies,
        }
    }

    #[tokio::test]
    async fn readiness_is_healthy_when_all_dependencies_pass() {
        let probe = StubProbe(snapshot(
            true,
            vec![DependencyHealth {
                name: "Sled".to_string(),
                status: "healthy".to_string(),
                required: true,
                detail: None,
            }],
        ));
        let report = HealthService::readiness(Instant::now(), Some(&probe), true).await;
        assert!(report.ready);
        assert_eq!(report.status, "ready");
        assert_eq!(report.reason, None);
        assert_eq!(report.backend, "rust");
    }

    #[tokio::test]
    async fn readiness_is_degraded_when_an_optional_dependency_is_down() {
        let probe = StubProbe(snapshot(
            true,
            vec![DependencyHealth {
                name: "OpenTelemetry".to_string(),
                status: "unhealthy".to_string(),
                required: false,
                detail: Some("collector unreachable".to_string()),
            }],
        ));
        let report = HealthService::readiness(Instant::now(), Some(&probe), true).await;
        assert!(!report.ready);
        assert_eq!(report.status, "degraded");
        assert_eq!(
            report.reason.as_deref(),
            Some("exporter_degraded:OpenTelemetry")
        );
    }

    #[tokio::test]
    async fn readiness_is_down_when_engine_or_required_dependency_fails() {
        let engine = StubProbe(snapshot(false, Vec::new()));
        let report = HealthService::readiness(Instant::now(), Some(&engine), true).await;
        assert!(!report.ready);
        assert_eq!(report.status, "not_ready");
        assert_eq!(report.reason.as_deref(), Some("engine_not_ready"));

        let store = StubProbe(snapshot(
            true,
            vec![DependencyHealth {
                name: "Sled".to_string(),
                status: "unhealthy".to_string(),
                required: true,
                detail: Some("event store closed".to_string()),
            }],
        ));
        let report = HealthService::readiness(Instant::now(), Some(&store), true).await;
        assert!(!report.ready);
        assert_eq!(report.status, "not_ready");
        assert_eq!(
            report.reason.as_deref(),
            Some("event_store_unavailable:Sled")
        );
    }

    #[tokio::test]
    async fn readiness_can_be_disabled_for_simple_liveness() {
        let report = HealthService::readiness(Instant::now(), None, false).await;
        assert!(report.ready);
        assert_eq!(report.status, "ready");
    }
}
