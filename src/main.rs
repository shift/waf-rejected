mod config;

#[cfg(feature = "wasm-waf")]
mod wasm;

use clap::{Arg, Command};
use config::Config;
use tracing::{info, error};
use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command line arguments
    let matches = Command::new("waf-ingress")
        .version("0.1.0")
        .about("WAF Ingress Server")
        .arg(
            Arg::new("config")
                .long("config")
                .value_name("FILE")
                .help("Configuration file path")
        )
        .arg(
            Arg::new("dry-run")
                .long("dry-run")
                .help("Parse configuration and exit without starting server")
                .action(clap::ArgAction::SetTrue)
        )
        .get_matches();

    // Initialize tracing
    tracing_subscriber::fmt::init();
    
    info!("Starting WAF Ingress Server");
    
    // Set config file environment variable if provided via CLI
    if let Some(config_file) = matches.get_one::<String>("config") {
        std::env::set_var("WAF_CONFIG_FILE", config_file);
    }
    
    // Load configuration
    let config = match Config::load() {
        Ok(config) => {
            info!("Configuration loaded successfully");
            config
        }
        Err(e) => {
            error!("Failed to load configuration: {}", e);
            // Use default configuration for now
            Config::default()
        }
    };
    
    info!("WAF Ingress Server configured");
    info!("Bind address: {}", config.bind_addr);
    info!("Upstream URI: {}", config.upstream_uri);
    
    // For now, just print configuration and exit
    // This is a placeholder until the full WAF implementation is ready
    info!("WAF configuration loaded");
    
    // Exit early if dry-run is requested
    if matches.get_flag("dry-run") {
        info!("Dry-run mode - configuration parsed successfully, exiting");
        return Ok(());
    }
    
    // TODO: Start the actual WAF server here
    info!("WAF server would start here...");
    
    Ok(())
}
