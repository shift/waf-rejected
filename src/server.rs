//! Shared application bootstrap used by `waf-ingress` and `waf_proxy`.

use std::error::Error;

use tokio::signal;
use tracing::{error, info, warn};

use crate::config::Config;
use crate::health::HealthService;
use crate::proxy::WafProxyService;

/// Load configuration, start the proxy and health services, and wait for
/// shutdown.
pub async fn run() -> Result<(), Box<dyn Error>> {
    init_tracing()?;

    info!("🚀 Starting WAF-Rejected v{}", env!("CARGO_PKG_VERSION"));

    // Configuration errors must be fatal: silently running on defaults hides
    // mistakes such as disabled authentication or an upstream typo.
    let config = Config::load()?;

    #[cfg(feature = "wasm-reactor")]
    {
        crate::waf::wasm_reactor::validate_startup().map_err(|err| {
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

    if !config.waf.enabled {
        warn!("WAF is disabled in configuration; requests will be forwarded unfiltered");
    }
    if !config.server.tls.enabled {
        warn!("TLS is disabled; use it behind a TLS-terminating load balancer or enable it");
    }

    let proxy_service = WafProxyService::new(config.clone())
        .map_err(|e| format!("Failed to initialize proxy service: {}", e))?;
    let health_service = HealthService::with_metrics(proxy_service.metrics());

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

fn init_tracing() -> Result<(), Box<dyn Error>> {
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

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

    Ok(())
}
