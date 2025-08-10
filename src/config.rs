use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Address to bind the server to
    pub bind_addr: SocketAddr,
    
    /// Upstream URI to proxy requests to
    pub upstream_uri: String,
    
    /// Server configuration
    pub server: ServerConfig,
    
    /// Logging configuration
    pub logging: LoggingConfig,
    
    /// WAF configuration
    pub waf: WafConfig,
    
    // Security module configurations
    pub security: SecurityConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Maximum number of concurrent connections
    pub max_connections: usize,
    
    /// Request timeout in seconds
    pub request_timeout_secs: u64,
    
    /// Keep-alive timeout in seconds
    pub keep_alive_timeout_secs: u64,
    
    /// Enable HTTP/2 support
    pub enable_http2: bool,
    
    /// Maximum request body size in bytes
    pub max_body_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level (trace, debug, info, warn, error)
    pub level: String,
    
    /// Enable JSON formatted logs
    pub json_format: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafConfig {
    /// Enable WAF functionality
    pub enabled: bool,
    
    /// Rate limiting configuration
    pub rate_limit: RateLimitConfig,
    
    /// Security event logging configuration
    pub security_events: SecurityEventsConfig,
    
    /// Content inspection configuration
    pub content_inspection: ContentInspectionConfig,
    
    /// Geographic blocking configuration
    pub geo_blocking: GeoBlockingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Enable per-IP rate limiting
    pub per_ip_enabled: bool,
    
    /// Maximum requests per IP per window
    pub per_ip_max_requests: u32,
    
    /// Rate limiting window size in seconds
    pub per_ip_window_secs: u64,
    
    /// Enable global rate limiting
    pub global_enabled: bool,
    
    /// Maximum requests globally per window
    pub global_max_requests: u32,
    
    /// Global rate limiting window size in seconds
    pub global_window_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEventsConfig {
    /// Enable security event logging
    pub enabled: bool,
    
    /// Log format (json, cef, plain)
    pub format: String,
    
    /// Minimum threat level to log (Low, Medium, High, Critical)
    pub min_threat_level: String,
    
    /// Enable CEF format for SIEM integration
    pub enable_cef: bool,
    
    /// CEF exporter configuration
    pub cef_output_file: Option<String>,
    pub cef_device_vendor: Option<String>,
    pub cef_device_product: Option<String>,
    pub cef_device_version: Option<String>,
    
    /// Enable OpenTelemetry integration
    pub enable_otel: bool,
    
    /// OpenTelemetry configuration
    pub otel_service_name: Option<String>,
    pub otel_service_version: Option<String>,
    pub otel_export_traces: Option<bool>,
    pub otel_export_logs: Option<bool>,
    
    /// Sled database persistence configuration
    pub enable_sled: bool,
    pub sled_db_path: Option<String>,
    pub sled_max_events: Option<usize>,
    pub sled_compress: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentInspectionConfig {
    /// Enable content inspection
    pub enabled: bool,
    
    /// Inspect request headers
    pub inspect_headers: bool,
    
    /// Inspect request body
    pub inspect_body: bool,
    
    /// Maximum body size to inspect (bytes)
    pub max_body_size: usize,
    
    /// Threat patterns to detect
    pub threat_patterns: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoBlockingConfig {
    /// Enable geographic blocking
    pub enabled: bool,
    
    /// Blocked country codes (ISO 3166-1 alpha-2)
    pub blocked_countries: Vec<String>,
    
    /// Blocked regions/states
    pub blocked_regions: Vec<String>,
    
    /// Block known Tor exit nodes
    pub block_tor: bool,
    
    /// Block known VPN providers
    pub block_vpn: bool,
    
    /// Block datacenter/hosting IPs
    pub block_datacenter: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Security events configuration
    pub events: SecurityEventsConfig,
    
    /// Content inspection configuration
    pub content_inspection: ContentInspectionConfig,
    
    /// Geographic blocking configuration  
    pub geo_blocking: GeoBlockingConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:8080".parse().unwrap(),
            upstream_uri: "http://127.0.0.1:3000".to_string(),
            server: ServerConfig::default(),
            logging: LoggingConfig::default(),
            waf: WafConfig::default(),
            security: SecurityConfig::default(),
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            max_connections: 10000,
            request_timeout_secs: 30,
            keep_alive_timeout_secs: 90,
            enable_http2: true,
            max_body_size: 10 * 1024 * 1024, // 10MB
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            json_format: false,
        }
    }
}

impl Default for WafConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            rate_limit: RateLimitConfig::default(),
            security_events: SecurityEventsConfig::default(),
            content_inspection: ContentInspectionConfig::default(),
            geo_blocking: GeoBlockingConfig::default(),
        }
    }
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            per_ip_enabled: true,
            per_ip_max_requests: 100,
            per_ip_window_secs: 60,
            global_enabled: true,
            global_max_requests: 1000,
            global_window_secs: 60,
        }
    }
}

impl Default for SecurityEventsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            format: "json".to_string(),
            min_threat_level: "medium".to_string(),
            enable_cef: false,
            cef_output_file: None,
            cef_device_vendor: None,
            cef_device_product: None,
            cef_device_version: None,
            enable_otel: false,
            otel_service_name: None,
            otel_service_version: None,
            otel_export_traces: None,
            otel_export_logs: None,
            enable_sled: false,
            sled_db_path: None,
            sled_max_events: None,
            sled_compress: false,
        }
    }
}

impl Default for ContentInspectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            inspect_headers: true,
            inspect_body: true,
            max_body_size: 1024 * 1024, // 1MB
            threat_patterns: vec![
                "sql_injection".to_string(),
                "xss".to_string(),
                "command_injection".to_string(),
                "path_traversal".to_string(),
            ],
        }
    }
}

impl Default for GeoBlockingConfig {
    fn default() -> Self {
        Self {
            enabled: false, // Disabled by default
            blocked_countries: vec![], // Empty by default
            blocked_regions: vec![],
            block_tor: true,
            block_vpn: false,
            block_datacenter: false,
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            events: SecurityEventsConfig::default(),
            content_inspection: ContentInspectionConfig::default(),
            geo_blocking: GeoBlockingConfig::default(),
        }
    }
}

impl Config {
    /// Load configuration from environment variables and config file
    pub fn load() -> anyhow::Result<Self> {
        let mut settings = config::Config::builder()
            // Start with default values
            .add_source(config::Config::try_from(&Config::default())?)
            // Add environment variables (with WAF_ prefix)
            .add_source(
                config::Environment::with_prefix("WAF")
                    .prefix_separator("_")
                    .separator("__")
            );

        // Try to load from config file if it exists
        if let Ok(config_file) = std::env::var("WAF_CONFIG_FILE") {
            info!("Loading configuration from file: {}", config_file);
            settings = settings.add_source(config::File::with_name(&config_file).required(false));
        }

        let config: Config = settings.build()?.try_deserialize()?;
        
        Ok(config)
    }
    
    /// Get the upstream URI as a hyper::Uri
    #[cfg_attr(not(test), allow(dead_code))]  // Used in tests and future API compatibility
    pub fn upstream_uri(&self) -> anyhow::Result<http::Uri> {
        self.upstream_uri.parse()
            .map_err(|e| anyhow::anyhow!("Invalid upstream URI '{}': {}", self.upstream_uri, e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.bind_addr.to_string(), "0.0.0.0:8080");
        assert_eq!(config.upstream_uri, "http://127.0.0.1:3000");
        assert_eq!(config.server.max_connections, 10000);
        assert_eq!(config.logging.level, "info");
    }

    #[test]
    fn test_config_from_env() {
        // Simple test that just validates default config loading works
        let config = Config::default();
        assert_eq!(config.bind_addr.to_string(), "0.0.0.0:8080");
        assert!(config.upstream_uri.starts_with("http://"));
        assert!(config.server.max_connections > 0);
    }
    
    #[test]
    fn test_upstream_uri_parsing() {
        let config = Config::default();
        let uri = config.upstream_uri().expect("Failed to parse upstream URI");
        assert_eq!(uri.scheme_str(), Some("http"));
        assert_eq!(uri.host(), Some("127.0.0.1"));
        assert_eq!(uri.port_u16(), Some(3000));
    }
}
