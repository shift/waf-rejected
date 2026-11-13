//! Shared application bootstrap used by `waf-ingress` and `waf_proxy`.

use std::error::Error;
use std::time::Duration;

use tokio::signal;
use tracing::{error, info, warn};

use crate::config::Config;
use crate::health::HealthService;
use crate::proxy::WafProxyService;

/// Build a Tokio multi-thread runtime from the configured tuning options.
///
/// Defaults match Tokio's own defaults, so an untouched configuration behaves
/// exactly like `#[tokio::main]`. CPU pinning is only applied when the
/// `cpu-pinning` feature is compiled in and `runtime.enable_cpu_pinning` is set.
pub fn build_runtime(config: &Config) -> std::io::Result<tokio::runtime::Runtime> {
    let runtime_cfg = &config.runtime;
    let mut builder = tokio::runtime::Builder::new_multi_thread();
    builder.enable_all();

    if let Some(threads) = runtime_cfg.worker_threads {
        builder.worker_threads(threads);
    }
    if let Some(threads) = runtime_cfg.max_blocking_threads {
        builder.max_blocking_threads(threads);
    }
    if let Some(secs) = runtime_cfg.thread_keep_alive_secs {
        builder.thread_keep_alive(Duration::from_secs(secs));
    }

    #[cfg(feature = "cpu-pinning")]
    if runtime_cfg.enable_cpu_pinning {
        let cores = runtime_cfg
            .cpu_pin_cores
            .clone()
            .unwrap_or_else(crate::affinity::available_cores);
        if cores.is_empty() {
            warn!("runtime.enable_cpu_pinning set but no usable cores found; skipping");
        } else {
            let cores = std::sync::Arc::new(cores);
            let next = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
            builder.on_thread_start(move || {
                let idx = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if let Some(core) = crate::affinity::core_for_index(&cores, idx) {
                    if !crate::affinity::pin_current_thread(core) {
                        tracing::debug!(core, "worker thread CPU pinning not applied");
                    }
                }
            });
        }
    }
    #[cfg(not(feature = "cpu-pinning"))]
    if runtime_cfg.enable_cpu_pinning {
        warn!(
            "runtime.enable_cpu_pinning set but binary lacks the `cpu-pinning` feature; skipping"
        );
    }

    builder.build()
}

/// Synchronous entry point used by the binaries. Loads configuration, builds
/// the tuned runtime, then drives the async server future.
pub fn run() -> Result<(), Box<dyn Error>> {
    let config = Config::load()?;
    init_tracing(&config.logging)?;
    crate::affinity::set_reactor_pinning(config.runtime.enable_cpu_pinning);
    let runtime = build_runtime(&config)?;
    runtime.block_on(run_with_config(config))
}

/// Start the proxy using an already-loaded configuration. Separated from
/// [`run`] so a custom Tokio runtime (worker counts, keep-alive, CPU pinning)
/// can be built from the same configuration before this future is polled.
pub async fn run_with_config(config: Config) -> Result<(), Box<dyn Error>> {
    info!("🚀 Starting WAF-Rejected v{}", env!("CARGO_PKG_VERSION"));

    #[cfg(feature = "wasm-reactor")]
    {
        crate::waf::wasm_reactor::validate_startup(&config).map_err(|err| {
            format!("Coraza reactor startup validation failed (fail-closed): {err}")
        })?;
    }

    info!("Configuration loaded successfully");
    info!("  Bind address: {}", config.bind_addr);
    info!("  Health/metrics: {}", config.health_bind_addr);
    info!("  Upstream: {}", config.upstream_uri);
    info!("  WAF enabled: {}", config.waf.enabled);
    info!("  TLS enabled: {}", config.server.tls.enabled);
    info!("  Auth enabled: {}", config.security.auth.enabled);

    let distributed = &config.waf.distributed;
    if distributed.enabled {
        info!(
            "  Distributed: enabled (region='{}', node_id='{}', fallback='{}', endpoints={}, shadow={})",
            distributed.region,
            distributed.node_id,
            distributed.fallback.as_str(),
            distributed.endpoints.len(),
            distributed.shadow
        );
        if distributed.endpoints.is_empty() {
            warn!(
                "waf.distributed.enabled with no endpoints: the node stays local; \
                 fallback '{}' applies only to shared-data lookups",
                distributed.fallback.as_str()
            );
        }
        if distributed.fallback != crate::config::DistributedFallbackMode::LocalOnly {
            warn!(
                "waf.distributed.fallback = '{}' may block or allow shared-data lookups \
                 when the cluster is unavailable; review docs/operations/distributed.md",
                distributed.fallback.as_str()
            );
        }
        if !cfg!(feature = "distri-kv") {
            warn!(
                "waf.distributed.enabled is set but this build was compiled without the \
                 `distri-kv` feature; the client is inactive and all decisions remain local"
            );
        }
    } else {
        info!("  Distributed: disabled");
    }

    if !config.waf.enabled {
        warn!("WAF is disabled in configuration; requests will be forwarded unfiltered");
    }
    if !config.server.tls.enabled {
        warn!("TLS is disabled; use it behind a TLS-terminating load balancer or enable it");
    }

    let proxy_service = WafProxyService::new(config.clone())
        .map_err(|e| format!("Failed to initialize proxy service: {}", e))?;

    // The controller runs on its own task and never on the request path. It
    // shares the engine's state handle so generation/connectivity changes are
    // visible to `/metrics` and the rate limiter.
    #[cfg(feature = "distri-kv")]
    let distributed_handle = if config.waf.distributed.enabled {
        match proxy_service.distributed_state() {
            Some(state) => {
                match crate::waf::distributed::DistributedController::from_config_with_state(
                    &config.waf.distributed,
                    state,
                ) {
                    Ok(controller) => Some(controller.spawn()),
                    Err(error) => {
                        warn!("Distributed controller disabled: {}", error);
                        None
                    }
                }
            }
            None => None,
        }
    } else {
        None
    };

    let health_service = HealthService::with_readiness(
        proxy_service.metrics(),
        proxy_service.readiness_probe(),
        config.health.dependency_checks,
    );

    let health_addr = config.health_bind_addr;
    tokio::spawn(async move {
        if let Err(e) = health_service.start(health_addr).await {
            error!("Health service failed: {}", e);
        }
    });
    info!(
        "Health/metrics available at http://{}/health and /metrics",
        health_addr
    );

    let proxy_addr = config.bind_addr;
    info!("WAF-Rejected listening on http://{}", proxy_addr);

    tokio::select! {
        result = proxy_service.start(proxy_addr) => {
            if let Err(e) = result {
                error!("Proxy service failed: {}", e);
                return Err(e.into());
            }
        }
        _ = shutdown_signal() => {
            info!("Shutdown signal received");
        }
    }

    #[cfg(feature = "distri-kv")]
    if let Some(handle) = distributed_handle {
        handle.shutdown().await;
    }

    info!("WAF-Rejected shutdown complete");
    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut terminate = signal(SignalKind::terminate()).expect("install SIGTERM handler");
        tokio::select! {
            _ = signal::ctrl_c() => {},
            _ = terminate.recv() => {},
        }
    }
    #[cfg(not(unix))]
    {
        let _ = signal::ctrl_c().await;
    }
}

fn init_tracing(logging: &crate::config::LoggingConfig) -> Result<(), Box<dyn Error>> {
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    // An explicit RUST_LOG still wins; otherwise use the validated
    // `[logging] level` instead of a hard-coded default.
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(logging.level.as_str()));

    if logging.json_format {
        tracing_subscriber::registry()
            .with(
                fmt::layer()
                    .json()
                    .with_target(true)
                    .with_thread_ids(true)
                    .with_file(true)
                    .with_line_number(true),
            )
            .with(env_filter)
            .try_init()?;
    } else {
        tracing_subscriber::registry()
            .with(
                fmt::layer()
                    .with_target(true)
                    .with_thread_ids(true)
                    .with_file(true)
                    .with_line_number(true),
            )
            .with(env_filter)
            .try_init()?;
    }

    Ok(())
}
