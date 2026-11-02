use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::time::Duration;
use tracing::info;

use crate::waf::storage::StorageConfig as WafStorageConfig;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Address to bind the server to
    pub bind_addr: SocketAddr,

    /// Address to bind the health/metrics service to
    pub health_bind_addr: SocketAddr,

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
#[serde(default)]
pub struct StorageConfig {
    pub backend: String,
    pub path: String,
    pub enable_follower_reads: bool,
    pub ttl_cleanup_interval: Duration,
    pub enable_compression: bool,
    pub cache_size: Option<usize>,
    pub max_memory_entries: Option<usize>,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            backend: "redb".to_string(),
            path: "./data/waf.redb".to_string(),
            enable_follower_reads: true,
            ttl_cleanup_interval: Duration::from_secs(60),
            enable_compression: false,
            cache_size: Some(16 * 1024 * 1024), // 16MB default cache
            max_memory_entries: None,
        }
    }
}

impl StorageConfig {
    /// Convert to waf storage configuration
    pub fn to_waf_storage_config(&self) -> WafStorageConfig {
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

        WafStorageConfig {
            backend,
            enable_follower_reads: self.enable_follower_reads,
            ttl_cleanup_interval: self.ttl_cleanup_interval,
            enable_compression: self.enable_compression,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ProxyConfig {
    /// Upstream server URL
    pub upstream_url: String,

    /// Proxy bind address
    pub bind_addr: String,

    /// Request timeout in seconds
    pub timeout_seconds: u64,

    /// Maximum request size in bytes
    pub max_request_size: usize,

    /// Optional PEM CA bundle used to verify TLS upstreams.
    ///
    /// Applies to HTTPS upstreams and to TLS WebSocket upstreams. When unset,
    /// upstream certificates are verified against `webpki-roots`. When set, the
    /// certificates in the bundle are trusted in addition to the built-in
    /// roots. This is intended for private/self-signed upstream CAs.
    pub upstream_ca_path: Option<String>,

    /// Optional PEM client certificate chain presented to HTTPS upstreams.
    ///
    /// Must be set together with `upstream_client_key_path` to enable upstream
    /// mutual TLS. Setting only one of the pair is a startup error.
    pub upstream_client_cert_path: Option<String>,

    /// Optional PEM private key for the upstream client certificate.
    ///
    /// Must be set together with `upstream_client_cert_path`.
    pub upstream_client_key_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    /// Maximum number of concurrent connections
    pub max_connections: usize,

    /// CIDRs of reverse proxies/LBs whose X-Forwarded-For header is trusted.
    /// Empty means the peer socket address is always used (header ignored).
    pub trusted_proxies: Vec<String>,

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

    /// Maximum number of bytes forwarded for one streaming gRPC exchange.
    ///
    /// Streaming gRPC bodies (no `content-length`) are not buffered and never
    /// reach the WAF body inspector, so this cap bounds the bytes the proxy
    /// will relay in either direction.
    pub grpc_max_stream_bytes: usize,

    /// Maximum duration in seconds of one streaming gRPC exchange.
    pub grpc_max_stream_seconds: u64,

    /// TLS configuration
    pub tls: TlsConfig,

    /// WebTransport over HTTP/3 configuration
    pub webtransport: WebTransportConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
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

/// WebTransport over HTTP/3 (QUIC) listener configuration.
///
/// WebTransport is a terminating endpoint: sessions are inspected locally and
/// never proxied to the upstream. An empty `allowed_origins` or `allowed_paths`
/// list denies every session (secure by default).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WebTransportConfig {
    /// Enable the WebTransport UDP listener
    pub enabled: bool,

    /// UDP address for the WebTransport listener. Must not collide with the
    /// HTTP/3 UDP port.
    pub bind_addr: SocketAddr,

    /// Reject requests that do not carry an `Origin` header
    pub require_origin: bool,

    /// Exact allowlist of `https://host[:port]` origins. Empty denies all.
    pub allowed_origins: Vec<String>,

    /// Allowlist of `:path` values. A trailing `/*` matches a path prefix.
    /// Empty denies all.
    pub allowed_paths: Vec<String>,

    /// Maximum concurrent WebTransport sessions across all clients
    pub max_sessions: usize,

    /// Maximum concurrent WebTransport sessions per client IP
    pub max_sessions_per_ip: usize,

    /// Maximum concurrent bidirectional streams per session
    pub max_bidi_streams: u32,

    /// Maximum concurrent unidirectional streams per session
    pub max_uni_streams: u32,

    /// Maximum accepted datagram payload size in bytes
    pub max_datagram_bytes: usize,

    /// Maximum bytes read (and inspected) from a single stream
    pub max_stream_bytes: usize,

    /// QUIC idle timeout in seconds
    pub idle_timeout_secs: u64,

    /// Maximum total session lifetime in seconds
    pub max_session_secs: u64,

    /// Inspect stream payloads through the WAF
    pub inspect_streams: bool,

    /// Inspect datagram payloads through the WAF
    pub inspect_datagrams: bool,
}

impl Default for WebTransportConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind_addr: "0.0.0.0:4434".parse().unwrap(),
            require_origin: true,
            allowed_origins: Vec::new(),
            allowed_paths: Vec::new(),
            max_sessions: 1024,
            max_sessions_per_ip: 32,
            max_bidi_streams: 16,
            max_uni_streams: 16,
            max_datagram_bytes: 1200,
            max_stream_bytes: 1024 * 1024,
            idle_timeout_secs: 30,
            max_session_secs: 300,
            inspect_streams: true,
            inspect_datagrams: true,
        }
    }
}

impl WebTransportConfig {
    /// Returns true when the request origin passes the exact allowlist.
    ///
    /// A missing `Origin` is accepted only when `require_origin` is false. An
    /// empty allowlist always denies.
    pub fn is_origin_allowed(&self, origin: Option<&str>) -> bool {
        let origin = match origin {
            Some(origin) => origin,
            None => return !self.require_origin,
        };
        if self.allowed_origins.is_empty() {
            return false;
        }
        let normalized = match normalize_origin(origin) {
            Some(origin) => origin,
            None => return false,
        };
        self.allowed_origins
            .iter()
            .filter_map(|allowed| normalize_origin(allowed))
            .any(|allowed| allowed == normalized)
    }

    /// Returns true when the request `:path` passes the allowlist.
    ///
    /// An empty allowlist always denies. Patterns ending in `/*` match by
    /// prefix; every other pattern is an exact match. Query strings are
    /// ignored.
    pub fn is_path_allowed(&self, path: &str) -> bool {
        if self.allowed_paths.is_empty() {
            return false;
        }
        let path = path.split(['?', '#']).next().unwrap_or(path);
        if !path.starts_with('/') {
            return false;
        }
        self.allowed_paths.iter().any(|allowed| {
            if let Some(prefix) = allowed.strip_suffix("/*") {
                path == prefix || path.starts_with(&format!("{}/", prefix))
            } else {
                path == allowed
            }
        })
    }

    /// Validate WebTransport-specific limits and allowlist entries.
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.max_sessions == 0 {
            anyhow::bail!("server.webtransport.max_sessions must be greater than zero");
        }
        if self.max_sessions_per_ip == 0 {
            anyhow::bail!("server.webtransport.max_sessions_per_ip must be greater than zero");
        }
        if self.max_bidi_streams == 0 {
            anyhow::bail!("server.webtransport.max_bidi_streams must be greater than zero");
        }
        if self.max_uni_streams == 0 {
            anyhow::bail!("server.webtransport.max_uni_streams must be greater than zero");
        }
        if self.max_datagram_bytes == 0 {
            anyhow::bail!("server.webtransport.max_datagram_bytes must be greater than zero");
        }
        if self.max_stream_bytes == 0 {
            anyhow::bail!("server.webtransport.max_stream_bytes must be greater than zero");
        }
        if self.idle_timeout_secs == 0 {
            anyhow::bail!("server.webtransport.idle_timeout_secs must be greater than zero");
        }
        if self.max_session_secs == 0 {
            anyhow::bail!("server.webtransport.max_session_secs must be greater than zero");
        }

        for origin in &self.allowed_origins {
            let normalized = normalize_origin(origin).ok_or_else(|| {
                anyhow::anyhow!(
                    "invalid server.webtransport.allowed_origins entry '{}': expected https://host[:port]",
                    origin
                )
            })?;
            if !normalized.starts_with("https://") {
                anyhow::bail!(
                    "server.webtransport.allowed_origins entry '{}' must use the https scheme",
                    origin
                );
            }
        }

        for path in &self.allowed_paths {
            let candidate = path.strip_suffix("/*").unwrap_or(path);
            if !candidate.starts_with('/') || path.contains(['?', '#']) {
                anyhow::bail!(
                    "invalid server.webtransport.allowed_paths entry '{}': expected a /path or /prefix/*",
                    path
                );
            }
        }

        Ok(())
    }
}

/// Normalize an origin to `scheme://host[:port]` for exact comparison.
///
/// Default ports are removed, scheme and host are lowercased, and paths,
/// queries, fragments, and userinfo are rejected.
fn normalize_origin(value: &str) -> Option<String> {
    let uri: http::Uri = value.trim().parse().ok()?;
    let scheme = uri.scheme_str()?.to_ascii_lowercase();
    if scheme != "https" && scheme != "http" {
        return None;
    }
    if uri.path_and_query().is_some_and(|path| {
        path.query().is_some() || (path.path() != "/" && !path.path().is_empty())
    }) {
        return None;
    }
    let authority = uri.authority()?;
    if authority.as_str().contains('@') {
        return None;
    }
    let host = authority.host().to_ascii_lowercase();
    if host.is_empty() {
        return None;
    }
    let host = if host.contains(':') && !host.starts_with('[') {
        format!("[{}]", host)
    } else {
        host
    };
    let port = match authority.port_u16() {
        Some(443) if scheme == "https" => None,
        Some(80) if scheme == "http" => None,
        port => port,
    };
    Some(match port {
        Some(port) => format!("{}://{}:{}", scheme, host, port),
        None => format!("{}://{}", scheme, host),
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LoggingConfig {
    /// Log level (trace, debug, info, warn, error)
    pub level: String,

    /// Enable JSON formatted logs
    pub json_format: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
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

    /// Real Coraza WASI reactor configuration (`wasm-reactor` feature).
    pub coraza: WafCorazaConfig,

    /// Protocol-aware gRPC inspection (`wasm-reactor` feature).
    pub grpc: WafGrpcConfig,

    /// Protocol-aware GraphQL-over-HTTP inspection (`wasm-reactor` feature).
    pub graphql: WafGraphqlConfig,

    /// Admission control for expensive (CRS body) inspections.
    pub admission: WafAdmissionConfig,
}

/// Admission control for expensive inspections.
///
/// Cheap requests (no body, or a body withheld from CRS by the gRPC/GraphQL
/// pre-checks) bypass the heavy queue entirely. Heavy requests need one of
/// `heavy_permits` slots, wait at most `queue_timeout_ms` when saturated, and
/// are rejected with `503 + Retry-After` when the queue is full or the wait
/// expires. Admission never skips or reduces inspection.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WafAdmissionConfig {
    /// Enable heavy-inspection admission control. Enabling this does not
    /// weaken inspection: heavy requests are still fully evaluated or
    /// rejected, never allowed.
    pub enabled: bool,

    /// Number of concurrent heavy evaluations allowed. `0` selects about half
    /// the reactor pool, capped at `pool_size - 1` (at least 1), reserving
    /// reactor workers for cheap requests.
    pub heavy_permits: usize,

    /// Maximum time a heavy request may wait for a permit before a `503`.
    pub queue_timeout_ms: u64,

    /// Maximum number of heavy requests waiting for a permit. `0` disables
    /// queueing: a saturated pool rejects immediately.
    pub max_queued: usize,
}

impl Default for WafAdmissionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            heavy_permits: 0,
            queue_timeout_ms: 250,
            max_queued: 64,
        }
    }
}

impl WafAdmissionConfig {
    /// Resolve `heavy_permits = 0` against the reactor pool size, keeping at
    /// least one worker free for cheap requests when the pool has more than
    /// one worker. Reserving about half the pool keeps cheap traffic useful
    /// under sustained heavy load while still admitting large-body scans.
    pub fn resolved_heavy_permits(&self, pool_size: usize) -> usize {
        let pool_size = pool_size.max(1);
        if self.heavy_permits == 0 {
            let half = (pool_size / 2).max(1);
            half.min(pool_size.saturating_sub(1).max(1))
        } else {
            self.heavy_permits.min(pool_size)
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
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
#[serde(default)]
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
#[serde(default)]
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
#[serde(default)]
pub struct GeoBlockingConfig {
    /// Enable geographic blocking
    pub enabled: bool,

    /// Path to a MaxMind GeoLite2/GeoIP2 City database (`.mmdb`).
    pub database_path: Option<String>,

    /// Path to a MaxMind GeoIP2 Anonymous IP database (`.mmdb`).
    pub anonymous_database_path: Option<String>,

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
#[serde(default)]
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

/// Real Coraza WASI reactor configuration.
///
/// Disabled by default. When enabled, the reactor is registered as the first
/// rule in the live WAF chain (requires the non-default `wasm-reactor`
/// feature). `module_path = None` uses the Coraza module embedded in the
/// binary; otherwise the path is read at start-up.
/// Selects which Coraza backend evaluates requests.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CorazaBackend {
    /// In-process WASI reactor hosted by wasmtime (default).
    #[default]
    Wasm,
    /// Native Go sidecar over a Unix domain socket (`coraza-native` feature).
    Native,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WafCorazaConfig {
    /// Enable the real Coraza WASI reactor.
    pub enabled: bool,

    /// Evaluation backend: `wasm` (default) or `native`.
    pub backend: CorazaBackend,

    /// Unix domain socket for the native sidecar. Ignored by the wasm backend.
    pub native_socket_path: Option<String>,

    /// Optional path to a reactor `.wasm` file. `None` uses the embedded module.
    pub module_path: Option<String>,

    /// Maximum request payload handed to the reactor.
    pub max_payload_bytes: usize,

    /// Maximum linear memory the reactor may grow to.
    pub memory_limit_bytes: usize,

    /// Wall-clock budget for one reactor `eval`, in milliseconds. Enforced by
    /// wasmtime epoch interruption; this is a denial-of-service bound, not a
    /// latency target.
    pub eval_timeout_ms: u64,

    /// Number of pre-warmed reactor instances, one dedicated OS thread each.
    /// `0` selects the number of available cores clamped to `1..=8`.
    pub pool_size: usize,
}

impl WafCorazaConfig {
    /// Resolve `pool_size = 0` to one worker per available core, clamped to
    /// `1..=8`.
    pub fn resolved_pool_size(&self) -> usize {
        if self.pool_size == 0 {
            std::thread::available_parallelism()
                .map(std::num::NonZeroUsize::get)
                .unwrap_or(1)
                .clamp(1, 8)
        } else {
            self.pool_size
        }
    }
}

impl Default for WafCorazaConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            backend: CorazaBackend::Wasm,
            native_socket_path: None,
            module_path: None,
            max_payload_bytes: 64 * 1024,
            memory_limit_bytes: 256 * 1024 * 1024,
            // Generous DoS bound: CRS body inspection is byte-linear and a
            // 60 KiB body can legitimately take seconds on modest hardware.
            eval_timeout_ms: 5000,
            // Auto: one pre-warmed reactor per available core (clamped).
            pool_size: 0,
        }
    }
}

/// Protocol-aware gRPC inspection policy (`wasm-reactor` feature).
///
/// gRPC request bodies are protobuf frames. Running CRS body rules over those
/// bytes is meaningless and expensive, so gRPC requests are validated at the
/// protocol level before Coraza runs and their bodies are withheld from CRS
/// body rules (header and URI rules still apply).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WafGrpcConfig {
    /// Enable gRPC protocol-aware inspection. Effective only when the WAF and
    /// the Coraza reactor are enabled as well.
    pub enabled: bool,

    /// Fully-qualified methods (`/package.Service/Method`) that may be
    /// called. Empty means monitor-only: methods are logged, never blocked.
    /// The list can be generated from a protobuf `FileDescriptorSet`.
    pub method_allowlist: Vec<String>,

    /// Path to a generated allowlist artifact (JSON, see
    /// [`crate::waf::grpc_allowlist`]). When set, the artifact's methods are
    /// merged with `method_allowlist`, its per-method `max_message_bytes`
    /// values take precedence over the global limit, and its
    /// `unknown_method_action` is used unless this section sets one
    /// explicitly.
    pub allowlist_file: Option<String>,

    /// Maximum decoded size of a single gRPC message, in bytes.
    pub max_message_bytes: usize,

    /// Maximum number of length-prefixed messages in one request body.
    pub max_frames: usize,

    /// What to do with a method that is not in a non-empty allowlist:
    /// `allow` (monitor) or `block`. When unset, it defaults to `block` for a
    /// non-empty allowlist and `allow` for an empty one.
    pub unknown_method_action: Option<String>,

    /// Maximum length of one decoded `string` field value.
    pub max_string_bytes: usize,

    /// Maximum length of one decoded `bytes` field value.
    pub max_bytes_len: usize,

    /// Maximum number of values for one repeated field.
    pub max_repeated: usize,

    /// Maximum nested message depth during field decoding.
    pub max_depth: usize,

    /// Maximum total number of wire fields decoded per request message.
    pub max_decoded_fields: usize,

    /// Reject field numbers absent from the descriptor metadata.
    pub reject_unknown_fields: bool,

    /// Validate string values (UTF-8, NUL and control characters).
    pub validate_strings: bool,
}

impl Default for WafGrpcConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            method_allowlist: Vec::new(),
            allowlist_file: None,
            max_message_bytes: 4 * 1024 * 1024,
            max_frames: 64,
            unknown_method_action: None,
            max_string_bytes: 1024 * 1024,
            max_bytes_len: 1024 * 1024,
            max_repeated: 1024,
            max_depth: 32,
            max_decoded_fields: 100_000,
            reject_unknown_fields: false,
            validate_strings: true,
        }
    }
}

impl WafGrpcConfig {
    /// Resolved unknown-method policy. An empty allowlist is monitor-only.
    pub fn unknown_method_action(&self) -> &str {
        match self.unknown_method_action.as_deref() {
            Some(action) => action,
            None if self.method_allowlist.is_empty() => "allow",
            None => "block",
        }
    }

    /// Validates the gRPC inspection policy.
    ///
    /// Allowlist entries must be fully-qualified gRPC paths of the form
    /// `/package.Service/Method`; the same structural rules are applied by
    /// [`crate::waf::grpc::parse_method_path`] at request time.
    /// `allowlist_file`, when set, must be non-empty and load as a valid
    /// generated artifact.
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.max_message_bytes == 0 {
            anyhow::bail!("waf.grpc.max_message_bytes must be greater than zero");
        }
        if self.max_frames == 0 {
            anyhow::bail!("waf.grpc.max_frames must be greater than zero");
        }
        if self.max_string_bytes == 0 {
            anyhow::bail!("waf.grpc.max_string_bytes must be greater than zero");
        }
        if self.max_bytes_len == 0 {
            anyhow::bail!("waf.grpc.max_bytes_len must be greater than zero");
        }
        if self.max_repeated == 0 {
            anyhow::bail!("waf.grpc.max_repeated must be greater than zero");
        }
        if self.max_depth == 0 {
            anyhow::bail!("waf.grpc.max_depth must be greater than zero");
        }
        if self.max_decoded_fields == 0 {
            anyhow::bail!("waf.grpc.max_decoded_fields must be greater than zero");
        }
        if let Some(action) = self.unknown_method_action.as_deref() {
            if action != "allow" && action != "block" {
                anyhow::bail!(
                    "waf.grpc.unknown_method_action must be 'allow' or 'block', got '{action}'"
                );
            }
        }
        for method in &self.method_allowlist {
            if !is_valid_grpc_method_path(method) {
                anyhow::bail!(
                    "waf.grpc.method_allowlist entry '{method}' must be a fully-qualified gRPC method path like '/package.Service/Method'"
                );
            }
        }
        if let Some(path) = self.allowlist_file.as_deref() {
            if path.trim().is_empty() {
                anyhow::bail!("waf.grpc.allowlist_file must not be empty when set");
            }
            crate::waf::grpc_allowlist::load_allowlist(path).map_err(|error| {
                anyhow::anyhow!("waf.grpc.allowlist_file '{path}' could not be loaded: {error}")
            })?;
        }
        Ok(())
    }
}

/// Structural gRPC method-path check shared with request-time parsing.
fn is_valid_grpc_method_path(path: &str) -> bool {
    let Some(rest) = path.strip_prefix('/') else {
        return false;
    };
    let mut parts = rest.split('/');
    let (Some(service), Some(method), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    !service.is_empty()
        && !method.is_empty()
        && service
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
        && method
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// How much of the raw GraphQL body is exposed to CRS body rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WafGraphqlScanMode {
    /// Full CRS JSON body scan (default; no security change).
    Crs,
    /// GraphQL checks only; the raw body is withheld from CRS body rules.
    GraphqlOnly,
    /// Disable GraphQL-specific checks; CRS still scans the body.
    Off,
}

impl WafGraphqlScanMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Crs => "crs",
            Self::GraphqlOnly => "graphql-only",
            Self::Off => "off",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "crs" => Some(Self::Crs),
            "graphql-only" => Some(Self::GraphqlOnly),
            "off" => Some(Self::Off),
            _ => None,
        }
    }
}

/// Protocol-aware GraphQL-over-HTTP inspection policy (`wasm-reactor` feature).
///
/// GraphQL bodies are JSON envelopes around a query. CRS JSON body rules are
/// byte-linear and can cost hundreds of milliseconds on a few kilobytes, so
/// the request can instead be validated at the GraphQL level and its raw body
/// withheld from CRS. That trade-off is opt-in through `body_scan`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WafGraphqlConfig {
    /// Enable GraphQL-aware inspection. Effective only when the WAF is
    /// enabled and `body_scan` is not `off`.
    pub enabled: bool,

    /// `crs` (default), `graphql-only` or `off`.
    pub body_scan: String,

    /// Operation names (GraphQL names) or SHA-256 query hashes (64 hex
    /// characters) that may execute. Empty means monitor-only, except in
    /// `graphql-only` mode where a non-empty allowlist is required.
    pub operation_allowlist: Vec<String>,

    /// Path to a persisted-query allowlist artifact (JSON list of
    /// `{ "name", "sha256" }`). Merged with `operation_allowlist`.
    pub allowlist_file: Option<String>,

    /// Unknown-operation policy: `monitor` or `block`. Unset defaults to
    /// `block` when the effective allowlist is non-empty and `monitor`
    /// otherwise.
    pub unknown_operation_action: Option<String>,

    /// Maximum raw request body size.
    pub max_body_bytes: usize,
    /// Maximum GraphQL query size.
    pub max_query_bytes: usize,
    /// Maximum serialised `variables` size.
    pub max_variables_bytes: usize,
    /// Maximum number of top-level `variables` entries.
    pub max_variables: usize,
    /// Maximum approximate selection-set depth.
    pub max_depth: usize,
    /// Maximum approximate alias count.
    pub max_aliases: usize,
    /// Maximum approximate field count.
    pub max_fields: usize,

    /// Allow mutation operations.
    pub allow_mutations: bool,
    /// Allow subscription operations.
    pub allow_subscriptions: bool,
}

impl Default for WafGraphqlConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            body_scan: "crs".to_string(),
            operation_allowlist: Vec::new(),
            allowlist_file: None,
            unknown_operation_action: None,
            // Deliberately generous so the default `crs` mode does not change
            // behaviour for ordinary GraphQL requests.
            max_body_bytes: 8 * 1024 * 1024,
            max_query_bytes: 1024 * 1024,
            max_variables_bytes: 1024 * 1024,
            max_variables: 128,
            max_depth: 128,
            max_aliases: 1024,
            max_fields: 8192,
            allow_mutations: true,
            allow_subscriptions: true,
        }
    }
}

impl WafGraphqlConfig {
    /// Resolved scan mode. An invalid value falls back to the safe default;
    /// validation rejects it at config load.
    pub fn scan_mode(&self) -> WafGraphqlScanMode {
        WafGraphqlScanMode::parse(&self.body_scan).unwrap_or(WafGraphqlScanMode::Crs)
    }

    /// Validates the GraphQL inspection policy.
    pub fn validate(&self) -> anyhow::Result<()> {
        if WafGraphqlScanMode::parse(&self.body_scan).is_none() {
            anyhow::bail!(
                "waf.graphql.body_scan must be 'crs', 'graphql-only' or 'off', got '{}'",
                self.body_scan
            );
        }
        for (name, value) in [
            ("max_body_bytes", self.max_body_bytes),
            ("max_query_bytes", self.max_query_bytes),
            ("max_variables_bytes", self.max_variables_bytes),
            ("max_variables", self.max_variables),
            ("max_depth", self.max_depth),
        ] {
            if value == 0 {
                anyhow::bail!("waf.graphql.{name} must be greater than zero");
            }
        }
        if let Some(action) = self.unknown_operation_action.as_deref() {
            if action != "monitor" && action != "block" {
                anyhow::bail!(
                    "waf.graphql.unknown_operation_action must be 'monitor' or 'block', got '{action}'"
                );
            }
        }
        for entry in &self.operation_allowlist {
            let entry = entry.trim();
            if entry.is_empty() {
                anyhow::bail!("waf.graphql.operation_allowlist entries must not be empty");
            }
            if !is_sha256_hex(entry) && !is_valid_graphql_name(entry) {
                anyhow::bail!(
                    "waf.graphql.operation_allowlist entry '{entry}' must be a GraphQL operation name or a 64-character SHA-256 hex digest"
                );
            }
        }

        let mut artifact_entries = 0usize;
        if let Some(path) = self.allowlist_file.as_deref() {
            if path.trim().is_empty() {
                anyhow::bail!("waf.graphql.allowlist_file must not be empty when set");
            }
            #[cfg(feature = "wasm-reactor")]
            {
                let allowlist =
                    crate::waf::graphql_allowlist::load_allowlist(path).map_err(|error| {
                        anyhow::anyhow!(
                            "waf.graphql.allowlist_file '{path}' could not be loaded: {error}"
                        )
                    })?;
                artifact_entries = allowlist.operations.len();
            }
            #[cfg(not(feature = "wasm-reactor"))]
            {
                if !std::path::Path::new(path).is_file() {
                    anyhow::bail!(
                        "waf.graphql.allowlist_file '{path}' could not be read: file does not exist"
                    );
                }
            }
        }

        if self.scan_mode() == WafGraphqlScanMode::GraphqlOnly
            && self.operation_allowlist.is_empty()
            && artifact_entries == 0
        {
            anyhow::bail!(
                "waf.graphql.body_scan = 'graphql-only' requires a non-empty operation_allowlist or allowlist_file"
            );
        }
        Ok(())
    }
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_valid_graphql_name(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == '_')
        && chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
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
#[serde(default)]
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
#[serde(default)]
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
#[serde(default)]
pub struct AuditConfig {
    /// Enable tamper-evident audit logging
    pub tamper_evident: bool,

    /// Audit log retention period in days
    pub retention_days: u32,

    /// Integrity check interval in hours
    pub integrity_check_hours: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RegulatoryConfig {
    /// Enable GDPR compliance features
    pub gdpr: bool,

    /// Enable HIPAA compliance features
    pub hipaa: bool,

    /// Enable PCI-DSS compliance features
    pub pci_dss: bool,

    /// Generate EU AI Act evidence (Regulation (EU) 2024/1689 as amended by
    /// Regulation (EU) 2026/1744). This is evidence, not a conformity assessment.
    pub ai_act: bool,

    /// Generate NIS2 incident-reporting evidence (Directive (EU) 2022/2555).
    /// National transposition and competent-authority rules still apply.
    pub nis2: bool,

    /// Generate Cyber Resilience Act reporting evidence (Regulation (EU)
    /// 2024/2847, Article 14). Submission to ENISA/CSIRT remains manual.
    pub cra: bool,

    /// Data residency requirements
    pub data_residency: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RetentionConfig {
    /// Security event retention in days
    pub security_events_days: u32,

    /// Audit log retention in days
    pub audit_logs_days: u32,

    /// Automatic deletion of expired data
    pub auto_delete: bool,
}

impl Default for AiModelConfig {
    fn default() -> Self {
        Self {
            model_path: None,
            anomaly_detection: true,
            advanced_classification: false,
        }
    }
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            tamper_evident: true,
            retention_days: 2555,
            integrity_check_hours: 24,
        }
    }
}

impl Default for RegulatoryConfig {
    fn default() -> Self {
        Self {
            gdpr: false,
            hipaa: false,
            pci_dss: false,
            ai_act: false,
            nis2: false,
            cra: false,
            data_residency: None,
        }
    }
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            security_events_days: 90,
            audit_logs_days: 2555,
            auto_delete: true,
        }
    }
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
                ai_act: false,
                nis2: false,
                cra: false,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SecurityConfig {
    /// Authentication configuration
    pub auth: crate::waf::auth::AuthConfig,
    /// AI threat detection configuration
    pub ai: AiConfig,

    /// Enterprise compliance configuration
    pub compliance: ComplianceConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:8080".parse().unwrap(),
            health_bind_addr: "0.0.0.0:8081".parse().unwrap(),
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
            upstream_ca_path: None,
            upstream_client_cert_path: None,
            upstream_client_key_path: None,
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            max_connections: 10000,
            trusted_proxies: vec![],
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
            max_body_size: 10 * 1024 * 1024,        // 10MB
            grpc_max_stream_bytes: 4 * 1024 * 1024, // 4MiB
            grpc_max_stream_seconds: 300,
            tls: TlsConfig::default(),
            webtransport: WebTransportConfig::default(),
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
            coraza: WafCorazaConfig::default(),
            grpc: WafGrpcConfig::default(),
            graphql: WafGraphqlConfig::default(),
            admission: WafAdmissionConfig::default(),
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
            database_path: None,
            anonymous_database_path: None,
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
            // The WASM component ABI is not wired up yet. Enabling this runs the
            // built-in heuristic fallback, not the real Coraza module.
            enabled: false,
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

impl Config {
    /// Load configuration from environment variables and config file
    pub fn load() -> anyhow::Result<Self> {
        let mut settings =
            config::Config::builder().add_source(config::Config::try_from(&Config::default())?);

        // Load the file before the environment so WAF_* variables can override
        // file values (important for containers and Kubernetes deployments).
        let config_file = std::env::var("WAF_CONFIG_FILE")
            .or_else(|_| std::env::var("CONFIG_PATH"))
            .ok();
        if let Some(config_file) = config_file {
            info!("Loading configuration from file: {}", config_file);
            settings = settings.add_source(config::File::with_name(&config_file).required(true));
        }

        settings = settings.add_source(
            config::Environment::with_prefix("WAF")
                .prefix_separator("_")
                .separator("__"),
        );

        let config: Config = settings.build()?.try_deserialize()?;
        config.validate()?;

        Ok(config)
    }

    /// Reject configurations that would make the proxy unsafe or unusable.
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.server.max_body_size == 0 {
            anyhow::bail!("server.max_body_size must be greater than zero");
        }
        if self.server.grpc_max_stream_bytes == 0 {
            anyhow::bail!("server.grpc_max_stream_bytes must be greater than zero");
        }
        if self.server.grpc_max_stream_seconds == 0 {
            anyhow::bail!("server.grpc_max_stream_seconds must be greater than zero");
        }
        if self.proxy.timeout_seconds == 0 || self.server.request_timeout_secs == 0 {
            anyhow::bail!("request timeouts must be greater than zero");
        }
        if self.waf.rate_limit.per_ip_window_secs == 0 && self.waf.rate_limit.per_ip_enabled {
            anyhow::bail!("waf.rate_limit.per_ip_window_secs must be greater than zero");
        }
        if self.waf.rate_limit.global_window_secs == 0 && self.waf.rate_limit.global_enabled {
            anyhow::bail!("waf.rate_limit.global_window_secs must be greater than zero");
        }
        if self.waf.coraza.max_payload_bytes == 0 {
            anyhow::bail!("waf.coraza.max_payload_bytes must be greater than zero");
        }
        if self.waf.coraza.memory_limit_bytes < 64 * 1024 {
            anyhow::bail!("waf.coraza.memory_limit_bytes must be at least 65536");
        }
        if self.waf.coraza.max_payload_bytes > self.waf.coraza.memory_limit_bytes {
            anyhow::bail!(
                "waf.coraza.max_payload_bytes must not exceed waf.coraza.memory_limit_bytes"
            );
        }
        if self.waf.coraza.eval_timeout_ms == 0 {
            anyhow::bail!("waf.coraza.eval_timeout_ms must be greater than zero");
        }
        // Each pre-warmed reactor owns a Go runtime and its own OS thread.
        if self.waf.coraza.pool_size > 8 {
            anyhow::bail!("waf.coraza.pool_size must be between 0 (auto) and 8");
        }
        if self
            .waf
            .coraza
            .module_path
            .as_deref()
            .is_some_and(str::is_empty)
        {
            anyhow::bail!("waf.coraza.module_path must not be empty when set");
        }
        if self.waf.coraza.backend == CorazaBackend::Native
            && self
                .waf
                .coraza
                .native_socket_path
                .as_deref()
                .is_none_or(str::is_empty)
        {
            anyhow::bail!(
                "waf.coraza.native_socket_path is required when waf.coraza.backend = \"native\""
            );
        }
        if self.waf.admission.enabled && self.waf.admission.queue_timeout_ms == 0 {
            anyhow::bail!("waf.admission.queue_timeout_ms must be greater than zero");
        }
        if self.waf.admission.heavy_permits > 8 {
            anyhow::bail!("waf.admission.heavy_permits must be between 0 (auto) and 8");
        }
        self.waf.grpc.validate()?;
        self.waf.graphql.validate()?;
        if self.security.auth.enabled && self.security.auth.api_keys.is_empty() {
            anyhow::bail!("security.auth.enabled is true but security.auth.api_keys is empty");
        }
        for cidr in &self.server.trusted_proxies {
            cidr.parse::<ipnetwork::IpNetwork>().map_err(|e| {
                anyhow::anyhow!("invalid server.trusted_proxies entry '{}': {}", cidr, e)
            })?;
        }

        if self.server.webtransport.enabled {
            self.server.webtransport.validate()?;

            if !self.server.tls.enabled {
                anyhow::bail!(
                    "server.webtransport.enabled requires TLS, but server.tls.enabled is false"
                );
            }
            if crate::waf::tls_config::tls_rank(&self.server.tls.max_version)? < 3 {
                anyhow::bail!(
                    "server.webtransport.enabled requires TLS 1.3, but server.tls.max_version is {}",
                    self.server.tls.max_version
                );
            }

            if self.server.enable_http3 {
                let webtransport = self.server.webtransport.bind_addr;
                let http3 = self.bind_addr;
                let shares_socket = webtransport.port() == http3.port()
                    && (webtransport.ip().is_unspecified()
                        || http3.ip().is_unspecified()
                        || webtransport.ip() == http3.ip());
                if shares_socket {
                    anyhow::bail!(
                        "server.webtransport.bind_addr ({}) must not collide with the HTTP/3 UDP port {}",
                        webtransport,
                        http3
                    );
                }
            }
        }

        Ok(())
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
    fn test_shipped_configs_deserialize() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let files = [
            "config.toml",
            "config-test.toml",
            "config-test-fail-open.toml",
            "config-with-exports.toml",
            "test_config.toml",
            "config/development-production.toml",
            "config/enterprise.toml",
        ];

        for file in files {
            let path = root.join(file);
            let contents = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("failed to read {}: {}", path.display(), e));
            let settings = config::Config::builder()
                .add_source(config::Config::try_from(&Config::default()).unwrap())
                .add_source(config::File::from_str(&contents, config::FileFormat::Toml))
                .build()
                .unwrap_or_else(|e| panic!("failed to build {}: {}", file, e));
            let parsed: Config = settings
                .try_deserialize()
                .unwrap_or_else(|e| panic!("failed to deserialize {}: {}", file, e));
            parsed
                .validate()
                .unwrap_or_else(|e| panic!("{} failed validation: {}", file, e));
        }
    }

    #[test]
    fn test_geo_blocking_anonymous_database_path_deserializes() {
        let contents = r#"
[waf.geo_blocking]
enabled = true
database_path = "/tmp/GeoLite2-City.mmdb"
anonymous_database_path = "/tmp/GeoIP2-Anonymous-IP.mmdb"
"#;
        let settings = config::Config::builder()
            .add_source(config::Config::try_from(&Config::default()).unwrap())
            .add_source(config::File::from_str(contents, config::FileFormat::Toml))
            .build()
            .unwrap();
        let parsed: Config = settings.try_deserialize().unwrap();

        assert_eq!(
            parsed.waf.geo_blocking.database_path.as_deref(),
            Some("/tmp/GeoLite2-City.mmdb")
        );
        assert_eq!(
            parsed.waf.geo_blocking.anonymous_database_path.as_deref(),
            Some("/tmp/GeoIP2-Anonymous-IP.mmdb")
        );
    }

    #[test]
    fn test_upstream_uri_parsing() {
        let config = Config::default();
        let uri = config.upstream_uri().expect("Failed to parse upstream URI");
        assert_eq!(uri.scheme_str(), Some("http"));
        assert_eq!(uri.host(), Some("127.0.0.1"));
        assert_eq!(uri.port_u16(), Some(3000));
    }

    #[test]
    fn webtransport_defaults_are_disabled_and_secure() {
        let config = WebTransportConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.bind_addr.to_string(), "0.0.0.0:4434");
        assert!(config.require_origin);
        assert!(config.allowed_origins.is_empty());
        assert!(config.allowed_paths.is_empty());
        assert!(config.inspect_streams);
        assert!(config.inspect_datagrams);
    }

    #[test]
    fn webtransport_origin_matching_is_exact_and_normalized() {
        let mut config = WebTransportConfig::default();
        config.allowed_origins = vec!["https://App.Example.com:443".to_string()];

        assert!(config.is_origin_allowed(Some("https://app.example.com")));
        assert!(config.is_origin_allowed(Some("https://APP.example.com/")));
        assert!(!config.is_origin_allowed(Some("https://app.example.com:8443")));
        assert!(!config.is_origin_allowed(Some("https://evil.example.com")));
        assert!(!config.is_origin_allowed(Some("https://app.example.com.evil.test")));
        assert!(!config.is_origin_allowed(None));
    }

    #[test]
    fn webtransport_origin_requires_header_when_configured() {
        let mut config = WebTransportConfig::default();
        config.allowed_origins = vec!["https://app.example.com".to_string()];

        assert!(!config.is_origin_allowed(None));

        config.require_origin = false;
        assert!(config.is_origin_allowed(None));
    }

    #[test]
    fn webtransport_empty_origin_allowlist_denies_all() {
        let config = WebTransportConfig::default();
        assert!(!config.is_origin_allowed(Some("https://app.example.com")));

        let mut permissive = config.clone();
        permissive.require_origin = false;
        assert!(!permissive.is_origin_allowed(Some("https://app.example.com")));
    }

    #[test]
    fn webtransport_rejects_non_https_origins() {
        let mut config = WebTransportConfig::default();
        config.allowed_origins = vec!["http://app.example.com".to_string()];
        assert!(config.validate().is_err());

        config.allowed_origins = vec!["https://app.example.com/path".to_string()];
        assert!(config.validate().is_err());

        config.allowed_origins = vec!["https://app.example.com?x=1".to_string()];
        assert!(config.validate().is_err());

        config.allowed_origins = vec!["https://app.example.com".to_string()];
        assert!(config.validate().is_ok());
    }

    #[test]
    fn webtransport_path_matching_supports_exact_and_prefix() {
        let mut config = WebTransportConfig::default();
        config.allowed_paths = vec!["/echo".to_string(), "/api/*".to_string()];

        assert!(config.is_path_allowed("/echo"));
        assert!(config.is_path_allowed("/echo?x=1"));
        assert!(!config.is_path_allowed("/echo/extra"));
        assert!(config.is_path_allowed("/api"));
        assert!(config.is_path_allowed("/api/v1/session"));
        assert!(!config.is_path_allowed("/apiv1"));
        assert!(!config.is_path_allowed("echo"));
        assert!(!config.is_path_allowed("/other"));
    }

    #[test]
    fn webtransport_empty_path_allowlist_denies_all() {
        let config = WebTransportConfig::default();
        assert!(!config.is_path_allowed("/echo"));
    }

    #[test]
    fn webtransport_limits_must_be_positive() {
        let mut config = WebTransportConfig::default();
        config.allowed_origins = vec!["https://app.example.com".to_string()];
        config.allowed_paths = vec!["/echo".to_string()];
        assert!(config.validate().is_ok());

        config.max_sessions = 0;
        assert!(config.validate().is_err());

        let mut config = WebTransportConfig::default();
        config.max_datagram_bytes = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn webtransport_config_requires_tls_13_and_distinct_udp_port() {
        let mut config = Config::default();
        config.server.webtransport.enabled = true;
        config.server.webtransport.allowed_origins = vec!["https://app.example.com".to_string()];
        config.server.webtransport.allowed_paths = vec!["/echo".to_string()];

        assert!(config.validate().is_err(), "TLS must be required");

        config.server.tls.enabled = true;
        config.server.tls.max_version = "1.2".to_string();
        assert!(config.validate().is_err(), "TLS 1.3 must be required");

        config.server.tls.max_version = "1.3".to_string();
        assert!(config.validate().is_ok());

        let http3_bind_addr = config.bind_addr;
        config.server.webtransport.bind_addr = http3_bind_addr;
        assert!(config.validate().is_err(), "UDP port collision must fail");

        config.server.enable_http3 = false;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn coraza_limits_are_validated() {
        let mut config = Config::default();
        assert!(config.validate().is_ok());
        assert!(config.waf.coraza.enabled);

        config.waf.coraza.max_payload_bytes = 0;
        assert!(config.validate().is_err());

        let mut config = Config::default();
        config.waf.coraza.memory_limit_bytes = 1024;
        assert!(config.validate().is_err());

        let mut config = Config::default();
        config.waf.coraza.max_payload_bytes = config.waf.coraza.memory_limit_bytes + 1;
        assert!(config.validate().is_err());

        let mut config = Config::default();
        config.waf.coraza.eval_timeout_ms = 0;
        assert!(config.validate().is_err());

        let mut config = Config::default();
        config.waf.coraza.module_path = Some(String::new());
        assert!(config.validate().is_err());

        let mut config = Config::default();
        config.waf.coraza.pool_size = 9;
        assert!(config.validate().is_err());
        config.waf.coraza.pool_size = 4;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn native_coraza_backend_requires_a_socket() {
        let mut config = Config::default();
        assert_eq!(config.waf.coraza.backend, CorazaBackend::Wasm);
        assert!(config.validate().is_ok());

        config.waf.coraza.backend = CorazaBackend::Native;
        assert!(config.validate().is_err());

        config.waf.coraza.native_socket_path = Some(String::new());
        assert!(config.validate().is_err());

        config.waf.coraza.native_socket_path = Some("/run/waf/coraza.sock".to_string());
        assert!(config.validate().is_ok());
    }

    #[test]
    fn grpc_config_is_validated() {
        let mut config = Config::default();
        assert!(config.waf.grpc.enabled);
        assert_eq!(config.waf.grpc.max_message_bytes, 4 * 1024 * 1024);
        assert_eq!(config.waf.grpc.max_frames, 64);
        assert_eq!(config.waf.grpc.max_string_bytes, 1024 * 1024);
        assert_eq!(config.waf.grpc.max_bytes_len, 1024 * 1024);
        assert_eq!(config.waf.grpc.max_repeated, 1024);
        assert_eq!(config.waf.grpc.max_depth, 32);
        assert_eq!(config.waf.grpc.max_decoded_fields, 100_000);
        assert!(!config.waf.grpc.reject_unknown_fields);
        assert!(config.waf.grpc.validate_strings);
        assert_eq!(config.waf.grpc.unknown_method_action(), "allow");
        assert!(config.validate().is_ok());

        config.waf.grpc.max_message_bytes = 0;
        assert!(config.validate().is_err());

        let mut config = Config::default();
        config.waf.grpc.max_frames = 0;
        assert!(config.validate().is_err());

        let zeroers: [fn(&mut WafGrpcConfig); 5] = [
            |grpc| grpc.max_string_bytes = 0,
            |grpc| grpc.max_bytes_len = 0,
            |grpc| grpc.max_repeated = 0,
            |grpc| grpc.max_depth = 0,
            |grpc| grpc.max_decoded_fields = 0,
        ];
        for zero in zeroers {
            let mut config = Config::default();
            zero(&mut config.waf.grpc);
            assert!(config.validate().is_err());
        }

        let mut config = Config::default();
        config.waf.grpc.unknown_method_action = Some("maybe".to_string());
        assert!(config.validate().is_err());

        let mut config = Config::default();
        config.waf.grpc.method_allowlist = vec!["acme.Service/Method".to_string()];
        assert!(config.validate().is_err());

        config.waf.grpc.method_allowlist = vec!["/acme.Service/Method".to_string()];
        assert!(config.validate().is_ok());
        assert_eq!(config.waf.grpc.unknown_method_action(), "block");
    }

    fn write_grpc_allowlist(
        dir: &std::path::Path,
        methods: &[(&str, usize)],
    ) -> std::path::PathBuf {
        use crate::waf::grpc_allowlist::{
            AllowlistSource, GrpcAllowlist, GrpcAllowlistMethod, ALLOWLIST_IR_VERSION,
        };

        let allowlist = GrpcAllowlist {
            ir_version: ALLOWLIST_IR_VERSION,
            source: AllowlistSource {
                kind: "protobuf".to_string(),
                sha256: "a".repeat(64),
            },
            methods: methods
                .iter()
                .map(|(path, limit)| GrpcAllowlistMethod {
                    path: (*path).to_string(),
                    client_streaming: false,
                    server_streaming: false,
                    input: "acme.Request".to_string(),
                    output: "acme.Response".to_string(),
                    max_message_bytes: *limit,
                })
                .collect(),
            messages: Vec::new(),
            unknown_method_action: "block".to_string(),
        };
        let path = dir.join("allowlist.json");
        std::fs::write(&path, allowlist.to_canonical_json().unwrap()).unwrap();
        path
    }

    #[test]
    fn grpc_allowlist_file_is_validated() {
        let mut config = Config::default();
        config.waf.grpc.allowlist_file = Some(String::new());
        let error = config.validate().unwrap_err().to_string();
        assert!(
            error.contains("waf.grpc.allowlist_file must not be empty"),
            "unexpected error: {error}"
        );

        let missing = "/nonexistent/grpc/allowlist.json";
        let mut config = Config::default();
        config.waf.grpc.allowlist_file = Some(missing.to_string());
        let error = config.validate().unwrap_err().to_string();
        assert!(
            error.contains(missing) && error.contains("could not be loaded"),
            "unexpected error: {error}"
        );

        let dir = tempfile::tempdir().unwrap();
        let artifact = write_grpc_allowlist(dir.path(), &[("/acme.Service/Method", 1024)]);
        let mut config = Config::default();
        config.waf.grpc.allowlist_file = Some(artifact.display().to_string());
        assert!(config.validate().is_ok());

        let malformed = dir.path().join("malformed.json");
        std::fs::write(&malformed, b"{not json").unwrap();
        config.waf.grpc.allowlist_file = Some(malformed.display().to_string());
        let error = config.validate().unwrap_err().to_string();
        assert!(
            error.contains("malformed.json") && error.contains("could not be loaded"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn graphql_config_is_validated() {
        let mut config = Config::default();
        assert!(config.waf.graphql.enabled);
        assert_eq!(config.waf.graphql.scan_mode(), WafGraphqlScanMode::Crs);
        assert!(config.validate().is_ok());

        config.waf.graphql.body_scan = "everything".to_string();
        assert!(config.validate().is_err());

        let mut config = Config::default();
        config.waf.graphql.max_depth = 0;
        assert!(config.validate().is_err());

        let mut config = Config::default();
        config.waf.graphql.unknown_operation_action = Some("deny".to_string());
        assert!(config.validate().is_err());

        let mut config = Config::default();
        config.waf.graphql.operation_allowlist = vec!["not a name".to_string()];
        assert!(config.validate().is_err());

        config.waf.graphql.operation_allowlist = vec!["GetUser".to_string()];
        assert!(config.validate().is_ok());

        let mut config = Config::default();
        config.waf.graphql.body_scan = "graphql-only".to_string();
        assert!(config.validate().is_err());
        config.waf.graphql.operation_allowlist = vec!["GetUser".to_string()];
        assert!(config.validate().is_ok());
    }

    #[test]
    fn graphql_allowlist_file_is_validated() {
        let mut config = Config::default();
        config.waf.graphql.allowlist_file = Some(String::new());
        let error = config.validate().unwrap_err().to_string();
        assert!(
            error.contains("waf.graphql.allowlist_file must not be empty"),
            "unexpected error: {error}"
        );

        let missing = "/nonexistent/graphql/allowlist.json";
        let mut config = Config::default();
        config.waf.graphql.allowlist_file = Some(missing.to_string());
        let error = config.validate().unwrap_err().to_string();
        assert!(
            error.contains(missing) && error.contains("could not be loaded"),
            "unexpected error: {error}"
        );

        let dir = tempfile::tempdir().unwrap();
        let artifact = dir.path().join("allowlist.json");
        std::fs::write(
            &artifact,
            serde_json::to_vec(&vec![serde_json::json!({
                "name": "GetUser",
                "sha256": "b".repeat(64),
            })])
            .unwrap(),
        )
        .unwrap();
        let mut config = Config::default();
        config.waf.graphql.allowlist_file = Some(artifact.display().to_string());
        config.waf.graphql.body_scan = "graphql-only".to_string();
        assert!(config.validate().is_ok());

        std::fs::write(&artifact, b"{not json").unwrap();
        let error = config.validate().unwrap_err().to_string();
        assert!(
            error.contains("allowlist.json") && error.contains("could not be loaded"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn environment_overrides_file_values() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("config.toml");
        std::fs::write(&file, "upstream_uri = \"http://127.0.0.1:12345\"\n").unwrap();

        std::env::set_var("WAF_CONFIG_FILE", &file);
        std::env::set_var("WAF_UPSTREAM_URI", "http://127.0.0.1:54321");

        let config = Config::load().unwrap();
        assert_eq!(config.upstream_uri, "http://127.0.0.1:54321");

        std::env::remove_var("WAF_UPSTREAM_URI");
        std::env::remove_var("WAF_CONFIG_FILE");
    }
}
