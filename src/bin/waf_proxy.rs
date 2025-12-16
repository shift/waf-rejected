#!/usr/bin/env cargo
//! # WAF-Rejected Main Application
//!
//! Enterprise Web Application Firewall with integrated reverse proxy.
//! Strategic Roadmap v0.1 "The Stable Core" implementation.
//!
//! ## Features
//! - High-performance reverse proxy with integrated WAF
//! - Comprehensive request filtering and security analysis
//! - Rate limiting and DDoS protection
//! - Health monitoring and metrics
//! - Production-ready error handling and logging
//!
//! ## Architecture
//! ```text
//!                    ┌─────────────────────┐
//!                    │   Client Request    │
//!                    └──────────┬──────────┘
//!                               │
//!                    ┌──────────▼──────────┐
//!                    │   WAF Proxy Server  │
//!                    │  (This Application) │
//!                    └──────────┬──────────┘
//!                               │
//!                    ┌──────────▼──────────┐
//!                    │    WAF Engine       │
//!                    │  Security Analysis  │
//!                    └──────────┬──────────┘
//!                               │
//!               ┌───────────────┴───────────────┐
//!               │                               │
//!    ┌──────────▼──────────┐         ┌─────────▼─────────┐
//!    │      ALLOW          │         │      BLOCK        │
//!    │  Forward Upstream   │         │  Security Response│
//!    └─────────────────────┘         └───────────────────┘
//! ```

use waf_ingress::config::Config;
use waf_ingress::error::WafError;
use waf_ingress::health::HealthService;
use waf_ingress::proxy::WafProxyService;

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::signal;
use tracing::{error, info, warn};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    init_tracing()?;

    info!("🚀 Starting WAF-Rejected v0.1.0-preview");
    info!("========================================");

    // Load configuration
    let config = Config::load().unwrap_or_else(|e| {
        warn!("Failed to load config, using defaults: {}", e);
        Config::default()
    });

    info!("Configuration loaded successfully");
    info!("  Bind Address: {}", config.bind_addr);
    info!("  Upstream: {}", config.upstream_uri);
    info!("  WAF Enabled: {}", config.waf.enabled);

    // Initialize services
    let proxy_service = WafProxyService::new(config.clone())
        .map_err(|e| format!("Failed to initialize proxy service: {}", e))?;

    let health_service = HealthService::new();

    // Start health monitoring on separate port
    let health_addr: SocketAddr = "0.0.0.0:8081".parse()?;
    tokio::spawn(async move {
        if let Err(e) = health_service.start(health_addr).await {
            error!("Health service failed: {}", e);
        }
    });

    info!(
        "Health monitoring available at http://{}/health",
        health_addr
    );

    // Start main proxy service
    let proxy_addr = config.bind_addr;

    // Create graceful shutdown handler
    let shutdown_signal = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install CTRL+C signal handler");
    };

    info!("🌟 WAF-Rejected started successfully");
    info!("   Main service: http://{}", proxy_addr);
    info!("   Health check: http://{}/health", health_addr);
    info!("   Press Ctrl+C to shutdown gracefully");

    // Run the proxy service with graceful shutdown
    tokio::select! {
        result = proxy_service.start(proxy_addr) => {
            match result {
                Ok(_) => {
                    info!("Proxy service completed successfully");
                }
                Err(e) => {
                    error!("Proxy service failed: {}", e);
                    return Err(e.into());
                }
            }
        }
        _ = shutdown_signal => {
            info!("🛑 Shutdown signal received, stopping services...");
        }
    }

    info!("👋 WAF-Rejected shutdown complete");
    Ok(())
}

/// Initialize tracing/logging based on configuration
fn init_tracing() -> Result<(), Box<dyn std::error::Error>> {
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    // Set default log level from environment or use info
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
        .init();

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_main_app_initialization() {
        // Test that we can create the basic components
        let config = Config::default();
        let proxy_service = WafProxyService::new(config);
        assert!(proxy_service.is_ok());

        let health_service = HealthService::new();
        // Basic construction test
        assert!(format!("{:?}", health_service).contains("HealthService"));
    }
}
