use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::time::Duration;
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Address to bind the server to
    pub bind_addr: SocketAddr,

    /// Upstream URI to proxy requests to
    pub upstream_uri: String,

    /// Proxy configuration
    pub proxy: ProxyConfig,

    /// Server configuration
    pub server: ServerConfig,

    /// Logging configuration
    pub logging: LoggingConfig,

    /// WAF configuration
    pub waf: WafConfig,

    /// Storage configuration
    pub storage: StorageConfig,
    // Security module configurations
    pub security: SecurityConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    /// Upstream server URL
    pub upstream_url: String,

    /// Proxy bind address
    pub bind_addr: String,

    /// Request timeout in seconds
    pub timeout_seconds: u64,

    /// Maximum request size in bytes
    pub max_request_size: usize,
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

    /// Enable HTTP/3 support (QUIC)
    pub enable_http3: bool,

    /// Supported HTTP versions (1.0, 1.1, 2, 3)
    pub supported_http_versions: Vec<String>,

    /// Maximum request body size in bytes
    pub max_body_size: usize,

    /// TLS configuration
    pub tls: TlsConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Enable TLS/SSL
    pub enabled: bool,

    /// Path to TLS certificate file (PEM format)
    pub cert_path: String,

    /// Path to TLS private key file (PEM format)
    pub key_path: String,

    /// Minimum TLS version (1.2 or 1.3)
    pub min_version: String,

    /// Maximum TLS version (1.2 or 1.3)
    pub max_version: String,

    /// ALPN protocols (e.g., ["h2", "http/1.1"])
    pub alpn_protocols: Vec<String>,

    /// Require client certificate authentication
    pub require_client_cert: bool,

    /// Path to client CA certificate file (PEM format)
    pub client_ca_path: Option<String>,
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

    /// Fail mode: "closed" (block on errors) or "open" (allow on errors)
    pub fail_mode: String,

    /// Connection timeout for upstream in milliseconds
    pub upstream_timeout_ms: u64,

    /// Rate limiting configuration
    pub rate_limit: RateLimitConfig,

    /// Security event logging configuration
    pub security_events: SecurityEventsConfig,

    /// Content inspection configuration
    pub content_inspection: ContentInspectionConfig,

    /// Geographic blocking configuration
    pub geo_blocking: GeoBlockingConfig,

    /// WASM ModSecurity configuration
    #[cfg(feature = "wasm-waf")]
    pub wasm: WasmConfig,
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

/// WASM ModSecurity configuration
#[cfg(feature = "wasm-waf")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmConfig {
    /// Enable WASM ModSecurity engine
    pub enabled: bool,

    /// Path to the WASM module file
    pub module_path: String,

    /// Memory limit for WASM instances (bytes)
    pub memory_limit: usize,

    /// Execution timeout (milliseconds)
    pub timeout_ms: u64,

    /// Enable debug mode
    pub debug: bool,

    /// Number of WASM instances to pool
    pub instance_pool_size: usize,

    /// Enable hot reloading of WASM modules
    pub hot_reload: bool,

    /// Rules configuration file
    pub rules_config: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiConfig {
    /// Enable AI threat detection
    pub enabled: bool,

    /// Threat score threshold (0.0-1.0)
    pub threat_threshold: f64,

    /// Processing timeout in milliseconds
    pub timeout_ms: u64,

    /// Model configuration
    pub model: AiModelConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiModelConfig {
    /// Path to ML model file
    pub model_path: Option<String>,

    /// Enable anomaly detection
    pub anomaly_detection: bool,

    /// Enable advanced classification
    pub advanced_classification: bool,
}

impl Default for AiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            threat_threshold: 0.8,
            timeout_ms: 5000,
            model: AiModelConfig {
                model_path: None,
                anomaly_detection: true,
                advanced_classification: false,
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceConfig {
    /// Enable compliance features
    pub enabled: bool,

    /// Audit trail configuration
    pub audit: AuditConfig,

    /// Regulatory compliance settings
    pub regulatory: RegulatoryConfig,

    /// Data retention policies
    pub retention: RetentionConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    /// Enable tamper-evident audit logging
    pub tamper_evident: bool,

    /// Audit log retention period in days
    pub retention_days: u32,

    /// Integrity check interval in hours
    pub integrity_check_hours: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegulatoryConfig {
    /// Enable GDPR compliance features
    pub gdpr: bool,

    /// Enable HIPAA compliance features
    pub hipaa: bool,

    /// Enable PCI-DSS compliance features
    pub pci_dss: bool,

    /// Data residency requirements
    pub data_residency: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionConfig {
    /// Security event retention in days
    pub security_events_days: u32,

    /// Audit log retention in days
    pub audit_logs_days: u32,

    /// Automatic deletion of expired data
    pub auto_delete: bool,
}

impl Default for ComplianceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            audit: AuditConfig {
                tamper_evident: true,
                retention_days: 2555, // 7 years
                integrity_check_hours: 24,
            },
            regulatory: RegulatoryConfig {
                gdpr: false,
                hipaa: false,
                pci_dss: false,
                data_residency: None,
            },
            retention: RetentionConfig {
                security_events_days: 90,
                audit_logs_days: 2555, // 7 years
                auto_delete: true,
            },
        }
    }
}

pub struct SecurityConfig {
    /// Security events configuration
    pub events: SecurityEventsConfig,

    /// Content inspection configuration
    pub content_inspection: ContentInspectionConfig,

    /// Geographic blocking configuration
    pub geo_blocking: GeoBlockingConfig,

    /// Authentication configuration
    pub auth: crate::waf::auth::AuthConfig,
    /// AI threat detection configuration
    pub ai: AiConfig,

    /// Enterprise compliance configuration
    pub compliance: ComplianceConfig,
}
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:8080".parse().unwrap(),
            upstream_uri: "http://127.0.0.1:3000".to_string(),
            proxy: ProxyConfig::default(),
            server: ServerConfig::default(),
            logging: LoggingConfig::default(),
            waf: WafConfig::default(),
            storage: StorageConfig::default(),
            security: SecurityConfig::default(),
        }
    }
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            upstream_url: "http://127.0.0.1:3000".to_string(),
            bind_addr: "0.0.0.0:8080".to_string(),
            timeout_seconds: 30,
            max_request_size: 10 * 1024 * 1024, // 10MB
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
            enable_http3: true,
            supported_http_versions: vec![
                "1.0".to_string(),
                "1.1".to_string(),
                "2".to_string(),
                "3".to_string(),
            ],
            max_body_size: 10 * 1024 * 1024, // 10MB
            tls: TlsConfig::default(),
        }
    }
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            cert_path: "/etc/waf/certs/server.crt".to_string(),
            key_path: "/etc/waf/certs/server.key".to_string(),
            min_version: "1.2".to_string(),
            max_version: "1.3".to_string(),
            alpn_protocols: vec!["h2".to_string(), "http/1.1".to_string()],
            require_client_cert: false,
            client_ca_path: None,
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
            fail_mode: "closed".to_string(), // Default to fail-closed (secure)
            upstream_timeout_ms: 5000,       // 5 second timeout
            rate_limit: RateLimitConfig::default(),
            security_events: SecurityEventsConfig::default(),
            content_inspection: ContentInspectionConfig::default(),
            geo_blocking: GeoBlockingConfig::default(),
            #[cfg(feature = "wasm-waf")]
            wasm: WasmConfig::default(),
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
            enabled: false,            // Disabled by default
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
            auth: crate::waf::auth::AuthConfig::default(),
            ai: AiConfig::default(),
            compliance: ComplianceConfig::default(),
        }
    }
}

#[cfg(feature = "wasm-waf")]
impl Default for WasmConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            module_path: "rules/coraza.wasm".to_string(),
            memory_limit: 16 * 1024 * 1024, // 16MB
            timeout_ms: 100,
            debug: false,
            instance_pool_size: 10,
            hot_reload: true,
            rules_config: "rules/coraza.conf".to_string(),
        }
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            backend: "redb".to_string(),
            path: "./data/waf.redb".to_string(),
            enable_follower_reads: true,
            ttl_cleanup_interval_secs: 60,
            enable_compression: false,
            cache_size: Some(16 * 1024 * 1024), // 16MB default cache
            max_memory_entries: None,
        }
    }
}

impl StorageConfig {
    /// Convert to waf storage configuration
    pub fn to_waf_storage_config(&self) -> crate::waf::storage::StorageConfig {
        let backend = match self.backend.as_str() {
            "sled" => crate::waf::storage::StorageBackend::Sled {
                path: self.path.clone(),
                temporary: false,
            },
            "redb" => crate::waf::storage::StorageBackend::Redb {
                path: self.path.clone(),
                cache_size: self.cache_size,
            },
            "memory" => crate::waf::storage::StorageBackend::Memory {
                max_size: self.max_memory_entries,
            },
            _ => crate::waf::storage::StorageBackend::default(),
        };

        crate::waf::storage::StorageConfig {
            backend,
            enable_follower_reads: self.enable_follower_reads,
            ttl_cleanup_interval: Duration::from_secs(self.ttl_cleanup_interval_secs),
            enable_compression: self.enable_compression,
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
                    .separator("__"),
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
    #[cfg_attr(not(test), allow(dead_code))] // Used in tests and future API compatibility
    pub fn upstream_uri(&self) -> anyhow::Result<http::Uri> {
        self.upstream_uri
            .parse()
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
