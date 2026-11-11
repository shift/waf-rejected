use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tracing::info;

use crate::waf::rate_limit::CapacityPolicy;
use crate::waf::storage::StorageConfig as WafStorageConfig;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
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
    /// Runtime / scheduling configuration (Tokio tuning and CPU pinning).
    pub runtime: RuntimeConfig,
}

/// Tokio runtime and CPU-affinity tuning. All fields are optional and default
/// to the previous behaviour (Tokio defaults, no pinning) so existing
/// deployments are unaffected.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RuntimeConfig {
    /// Number of Tokio worker threads. `None` uses Tokio's default
    /// (number of logical CPUs).
    pub worker_threads: Option<usize>,
    /// Maximum number of Tokio blocking-pool threads. `None` uses Tokio's
    /// default (512).
    pub max_blocking_threads: Option<usize>,
    /// Keep-alive for idle worker threads in seconds. `None` uses Tokio's
    /// default (10s).
    pub thread_keep_alive_secs: Option<u64>,
    /// Enable CPU affinity/pinning for proxy worker threads. Requires the
    /// non-default `cpu-pinning` build feature; silently falls back when the
    /// platform does not support it.
    pub enable_cpu_pinning: bool,
    /// Explicit core IDs to pin worker threads to. When empty/`None`, all
    /// available cores are used in round-robin order.
    pub cpu_pin_cores: Option<Vec<usize>>,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            worker_threads: None,
            max_blocking_threads: None,
            thread_keep_alive_secs: None,
            enable_cpu_pinning: false,
            cpu_pin_cores: None,
        }
    }
}

impl RuntimeConfig {
    /// Validate scheduling settings. Pinning is optional and never fatal:
    /// requesting it without the build feature or host support logs a warning
    /// and the caller falls back to unpinned scheduling.
    pub fn validate(&self) -> anyhow::Result<()> {
        if let Some(threads) = self.worker_threads {
            if threads == 0 {
                anyhow::bail!("runtime.worker_threads must be greater than zero when set");
            }
            if threads > 1024 {
                anyhow::bail!("runtime.worker_threads must be at most 1024");
            }
        }
        if let Some(threads) = self.max_blocking_threads {
            if threads == 0 {
                anyhow::bail!("runtime.max_blocking_threads must be greater than zero when set");
            }
        }
        if self.enable_cpu_pinning && !cfg!(feature = "cpu-pinning") {
            tracing::warn!(
                "runtime.enable_cpu_pinning = true but binary was built without the \
                 `cpu-pinning` feature; worker threads will not be pinned"
            );
        }
        if let Some(cores) = &self.cpu_pin_cores {
            if cores.is_empty() {
                anyhow::bail!("runtime.cpu_pin_cores must not be empty when set");
            }
            let mut sorted = cores.clone();
            sorted.sort_unstable();
            sorted.dedup();
            if sorted.len() != cores.len() {
                anyhow::bail!("runtime.cpu_pin_cores must not contain duplicates");
            }
            let logical = num_cpus::get();
            if sorted.last().copied().unwrap_or(0) >= logical {
                anyhow::bail!(
                    "runtime.cpu_pin_cores entries must be below the logical CPU count ({logical})"
                );
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
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
#[serde(default, deny_unknown_fields)]
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

    /// Opt-in upstream connection-pool tuning.
    pub pool: UpstreamPoolConfig,

    /// Opt-in streaming policy for large upstream responses.
    pub streaming: StreamingConfig,

    /// Additional client headers removed before WAF inspection and upstream
    /// forwarding. Names are case-insensitive; a trailing `*` is a prefix
    /// match (`x-forwarded-*`). Defaults are in
    /// [`DEFAULT_STRIP_HEADERS`]. With the default `extend` mode these entries
    /// are added to the built-in defaults; `replace` mode uses only this list.
    pub strip_headers: Vec<String>,

    /// How `strip_headers` combines with the built-in routing-header defaults.
    pub strip_headers_mode: HeaderStripMode,

    /// Reject requests that carry a client-supplied routing/override header
    /// with `400 Bad Request` instead of stripping it. Client identity headers
    /// (`X-Forwarded-For`, `X-Real-IP`, `X-Forwarded-Proto`) are never
    /// rejected. Disabled by default.
    pub reject_ambiguous_routing: bool,
}

/// How [`ProxyConfig::strip_headers`] combines with the built-in defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HeaderStripMode {
    /// Add configured names to [`DEFAULT_STRIP_HEADERS`] (default).
    #[default]
    Extend,
    /// Use only the configured names; the built-in defaults are not applied.
    Replace,
}

/// Routing/override headers a client must never control on the upstream leg.
///
/// These headers commonly change upstream path or method selection. The proxy
/// removes them before WAF inspection and before forwarding, then sets its own
/// forwarding headers from trusted state (`Host`, `X-Forwarded-For`,
/// `X-Forwarded-Proto`, `X-Forwarded-Host`).
pub const DEFAULT_STRIP_HEADERS: &[&str] = &[
    "x-original-url",
    "x-rewrite-url",
    "x-http-method-override",
    "x-method-override",
    "x-forwarded-prefix",
    "x-forwarded-host",
    "x-forwarded-server",
    "x-forwarded-port",
    "x-forwarded-*",
    "forwarded",
    "x-host",
    "x-real-ip",
];

/// Opt-in upstream connection-pool policy.
///
/// Disabled by default: when `enabled` is `false` the hyper connection pool
/// keeps its built-in behaviour (unbounded idle connections, its default idle
/// timeout, no out-of-band health probes).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct UpstreamPoolConfig {
    /// Enable bounded idle reuse and (optionally) upstream health checks.
    pub enabled: bool,

    /// Maximum idle upstream connections kept per host. Must be greater than
    /// zero when the pool is enabled.
    pub max_idle_per_host: usize,

    /// Idle connections older than this are closed instead of reused.
    pub idle_timeout_secs: u64,

    /// Interval between out-of-band upstream health probes. `0` disables them.
    pub health_check_interval_secs: u64,

    /// Path probed by the health check (for example `/healthz`).
    pub health_check_path: String,
}

/// Opt-in streaming policy for large upstream responses.
///
/// Disabled by default: every upstream response body is buffered so the
/// existing size cap applies before anything is written to the client.
/// When enabled, responses that advertise a `content-length` at or above
/// `response_threshold_bytes` are relayed frame by frame under the same byte
/// cap and a deadline, instead of being collected in memory first.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StreamingConfig {
    /// Enable streaming of large upstream response bodies.
    pub enabled: bool,

    /// Minimum advertised `content-length` that is streamed.
    pub response_threshold_bytes: usize,
}

/// Opt-in HTTP/2 tuning for ingress connections and upstream client connections.
///
/// Disabled by default: when `enabled` is `false` the existing hard-coded
/// keep-alive policy (30s interval / 10s timeout) and hyper's HTTP/2 defaults
/// are left untouched.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Http2TuningConfig {
    /// Apply this tuning block to ingress and upstream HTTP/2 connections.
    pub enabled: bool,

    /// Per-stream flow-control window in bytes.
    pub initial_stream_window_bytes: u32,

    /// Per-connection flow-control window in bytes.
    pub initial_connection_window_bytes: u32,

    /// Maximum concurrent streams per ingress connection. Bounds how many
    /// requests a single h2 connection can pin to the reactor pool.
    pub max_concurrent_streams: u32,

    /// Maximum pending accept-reset streams per ingress connection.
    pub max_pending_accept_reset_streams: usize,

    /// HTTP/2 PING interval in seconds; `0` disables PING keep-alive.
    pub keep_alive_interval_secs: u64,

    /// Time to wait for a PING acknowledgement before closing the connection.
    pub keep_alive_timeout_secs: u64,

    /// Send keep-alive PINGs while the connection is idle.
    pub keep_alive_while_idle: bool,

    /// Let the h2 stack size flow-control windows adaptively (overrides the
    /// explicit window sizes).
    pub adaptive_window: bool,
}

/// WebSocket codec limits.
///
/// The tungstenite parser enforces these limits while reading, so a single
/// oversized frame, or a fragmented message whose reassembled size exceeds the
/// message cap, is rejected before the full message is assembled. The WAF then
/// re-checks the assembled message as defence in depth.
///
/// `0` means "inherit `server.max_body_size`" for both values, preserving the
/// pre-existing behaviour where the transport cap also bounded WebSocket
/// messages.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WebSocketConfig {
    /// Maximum size of a single WebSocket frame in bytes (`0` = inherit).
    pub max_frame_bytes: usize,

    /// Maximum size of a reassembled WebSocket message in bytes
    /// (`0` = inherit `server.max_body_size`).
    pub max_message_bytes: usize,

    /// Maximum number of concurrent WebSocket tunnels.
    ///
    /// The permit is taken during the upgrade handshake, before the upstream
    /// connection is opened, and held until the tunnel closes. Excess upgrades
    /// receive `503` with `Retry-After`.
    pub max_concurrent_tunnels: usize,

    /// Close an established tunnel after this many seconds without traffic in
    /// either direction. `0` disables the idle timeout.
    pub idle_timeout_secs: u64,

    /// Absolute maximum tunnel lifetime in seconds, regardless of activity.
    pub max_lifetime_secs: u64,

    /// Inspect upstream-to-client `Text`/`Binary` frames with the same bounded
    /// buffers and rate-limit budgets as the client-to-upstream direction.
    /// Defaults to `false`; enabling it roughly doubles per-frame inspection
    /// cost on a tunnel and can reject previously forwarded origin frames.
    pub inspect_responses: bool,
}

impl WebSocketConfig {
    /// Resolve the frame cap against `server.max_body_size`.
    pub fn resolved_max_frame_bytes(&self, max_body_size: usize) -> usize {
        if self.max_frame_bytes == 0 {
            max_body_size
        } else {
            self.max_frame_bytes
        }
    }

    /// Resolve the message cap against `server.max_body_size`.
    pub fn resolved_max_message_bytes(&self, max_body_size: usize) -> usize {
        if self.max_message_bytes == 0 {
            max_body_size
        } else {
            self.max_message_bytes
        }
    }
}

impl Default for WebSocketConfig {
    fn default() -> Self {
        Self {
            max_frame_bytes: 0,
            max_message_bytes: 0,
            max_concurrent_tunnels: 1024,
            idle_timeout_secs: 300,
            max_lifetime_secs: 3600,
            inspect_responses: false,
        }
    }
}

/// Policy for genuinely streaming gRPC RPCs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GrpcStreamingPolicy {
    /// Explicit opt-out from rejecting genuine streams.
    ///
    /// Every complete gRPC message is still inspected incrementally before it
    /// is forwarded; the policy only permits the stream to continue. It logs a
    /// start-up warning because streaming remains a larger attack surface than
    /// buffered unary inspection.
    TransportOnly,
    /// Reject genuine streaming RPCs with a clear 4xx / gRPC status.
    ///
    /// This is the default: a body must end after exactly one complete
    /// message to be accepted as unary. Delaying `END_STREAM` cannot force the
    /// request onto the streaming path.
    #[default]
    Reject,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
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

    /// Maximum number of header fields accepted in one request head.
    ///
    /// Enforced in the request pipeline before any body handling, returning
    /// `431` when exceeded. hyper's own parser limit remains a backstop and is
    /// configured above this value so the explicit check is authoritative.
    pub max_header_count: usize,

    /// Maximum combined size of the header names and values in one request
    /// head, in bytes. Enforced before body handling, returning `431`.
    pub max_header_bytes: usize,

    /// Maximum number of concurrent QUIC/HTTP3 connections.
    ///
    /// Applied per UDP listener at accept time. Connections over the limit are
    /// refused before QUIC connection state is created.
    pub h3_max_connections: usize,

    /// Maximum concurrent bidirectional streams per HTTP/3 connection.
    ///
    /// Advertised in the QUIC transport parameters, so a peer cannot open more
    /// streams than this and excess stream attempts fail closed at the
    /// transport layer.
    pub h3_max_concurrent_bidi_streams: u64,

    /// Require stateless address validation (QUIC `retry`) before accepting a
    /// new HTTP/3 connection. Enabled by default so an unauthenticated peer
    /// cannot cheaply allocate connection state.
    pub h3_stateless_retry: bool,

    /// Close an idle QUIC connection after this many seconds.
    pub h3_idle_timeout_secs: u64,

    /// Maximum number of concurrent HTTP/3 request handlers.
    ///
    /// Accepted requests acquire one permit before their request body is
    /// read. When the limit is saturated, new requests wait up to
    /// `h3_admission_timeout_ms` and are then rejected with `503`. Bounds the
    /// Tokio tasks (and body buffers) an HTTP/3 client can create.
    pub h3_max_inflight_requests: usize,

    /// Maximum concurrent HTTP/3 requests from one client IP.
    ///
    /// `0` disables the per-client limit. When set, excess requests from that
    /// client are rejected with `429` before their body is read.
    pub h3_max_inflight_per_client: usize,

    /// Maximum time an HTTP/3 request waits for an admission permit before
    /// being rejected with `503`.
    pub h3_admission_timeout_ms: u64,

    /// WebSocket frame/message limits enforced by the tungstenite parser.
    pub websocket: WebSocketConfig,

    /// Maximum number of bytes forwarded for one streaming gRPC exchange.
    ///
    /// Streaming gRPC bodies (no `content-length`) are not buffered and never
    /// reach the WAF body inspector, so this cap bounds the bytes the proxy
    /// will relay in either direction.
    pub grpc_max_stream_bytes: usize,

    /// Maximum duration in seconds of one streaming gRPC exchange.
    pub grpc_max_stream_seconds: u64,

    /// Maximum number of length-prefixed messages in one streaming gRPC
    /// exchange. Applies to the request stream.
    pub grpc_max_stream_messages: usize,

    /// Maximum decompressed bytes across one streaming gRPC exchange when
    /// `grpc-encoding: gzip` is used. The compressed bytes are still bounded
    /// by `grpc_max_stream_bytes`.
    pub grpc_max_decompressed_bytes: usize,

    /// Policy for genuinely streaming gRPC RPCs (more than one request
    /// message, or additional bytes after the first complete message).
    ///
    /// `reject` (default) refuses the RPC with a clear 4xx / gRPC status.
    /// `transport-only` is an explicit opt-out that permits the stream, but
    /// every complete message is still inspected incrementally before it is
    /// forwarded. Unary RPCs are always buffered and inspected.
    pub grpc_streaming_policy: GrpcStreamingPolicy,

    /// Return gRPC-native rejection responses for blocked gRPC requests.
    ///
    /// When `false` (the default), a WAF block is a plain HTTP response with
    /// the configured status (for example `403 text/plain`). When `true`, a
    /// blocked gRPC request receives HTTP 200 with `grpc-status` and
    /// `grpc-message` trailers: `7` (PERMISSION_DENIED) for `403` and `13`
    /// (INTERNAL) for other block statuses. Non-gRPC traffic is unaffected.
    pub grpc_aware_rejections: bool,

    /// TLS configuration
    pub tls: TlsConfig,

    /// Opt-in HTTP/2 flow-control, multiplexing and keep-alive tuning.
    pub http2: Http2TuningConfig,

    /// WebTransport over HTTP/3 configuration
    pub webtransport: WebTransportConfig,

    /// Listener I/O backend.
    ///
    /// `"tokio"` (default) uses the portable epoll/tokio accept path.
    /// `"io_uring"` uses the Linux io_uring multishot-accept path when the
    /// binary was built with the `io-uring` feature; setup failure falls back
    /// to the tokio path with a warning.
    pub io_backend: ListenerIoBackend,
}

/// Listener I/O backend selection (`server.io_backend`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ListenerIoBackend {
    /// Portable epoll/tokio listener (default).
    #[default]
    Tokio,
    /// Linux io_uring multishot-accept listener (requires `io-uring` feature).
    IoUring,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
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

    /// Enable TLS session resumption (TLS 1.2 session cache and TLS 1.3
    /// tickets). Disabled by default to preserve existing behaviour.
    pub session_resumption: bool,

    /// Number of cached TLS 1.2 sessions when `session_resumption` is enabled.
    pub session_cache_size: usize,

    /// Number of TLS 1.3 tickets issued per connection when resumption is
    /// enabled. `0` disables ticket issuance (stateful cache only).
    pub tls13_tickets: usize,

    /// Set `TCP_NODELAY` on accepted TLS connections to remove Nagle latency.
    pub tcp_nodelay: bool,

    /// TCP keep-alive idle time in seconds for accepted TLS connections.
    /// `0` leaves the operating-system default in place.
    pub tcp_keepalive_secs: u64,

    /// TCP keep-alive probe interval in seconds. `0` leaves the OS default.
    pub tcp_keepalive_interval_secs: u64,

    /// Request TCP Fast Open on the listening socket where the platform
    /// supports it. Best effort; unsupported platforms ignore the flag.
    pub tcp_fast_open: bool,
}

/// WebTransport over HTTP/3 (QUIC) listener configuration.
///
/// WebTransport is a terminating endpoint: sessions are inspected locally and
/// never proxied to the upstream. An empty `allowed_origins` or `allowed_paths`
/// list denies every session (secure by default).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
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
#[serde(default, deny_unknown_fields)]
pub struct LoggingConfig {
    /// Log level (trace, debug, info, warn, error)
    pub level: String,

    /// Enable JSON formatted logs
    pub json_format: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
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

    /// Opt-in upstream response inspection (phases 3–5).
    pub response_inspection: ResponseInspectionConfig,

    /// Geographic blocking configuration
    pub geo_blocking: GeoBlockingConfig,

    /// Legacy component-ABI WASM ModSecurity configuration.
    ///
    /// Parsed in every build so the shipped configs remain valid; it is only
    /// applied when the `wasm-waf` feature is compiled in.
    pub wasm: WasmConfig,

    /// Real Coraza WASI reactor configuration (`wasm-reactor` feature).
    pub coraza: WafCorazaConfig,

    /// Protocol-aware gRPC inspection (`wasm-reactor` feature).
    pub grpc: WafGrpcConfig,

    /// Protocol-aware GraphQL-over-HTTP inspection (`wasm-reactor` feature).
    pub graphql: WafGraphqlConfig,

    /// Admission control for expensive (CRS body) inspections.
    pub admission: WafAdmissionConfig,

    /// Experimental content-addressed allow-verdict cache (`allow-cache`
    /// feature). Disabled by default; see
    /// `docs/suggestions_from_agents/allow-cache.md`.
    pub allow_cache: AllowCacheConfig,

    /// Compiled bodyless allowlist fast path. Disabled by default; when
    /// enabled, only the explicitly listed `"METHOD /path"` routes skip
    /// per-request inspection.
    pub fast_allow: WafFastAllowConfig,

    /// Distributed security fabric client (`distri-kv` build feature).
    /// Disabled by default; see `docs/operations/distributed.md`.
    pub distributed: DistributedConfig,
}

/// Opt-in allow-verdict cache.
///
/// The cache only memoises the verdict of pure content rules (the Coraza
/// backend and the built-in content inspector) for requests that produced an
/// `Allow`. Stateful and IP-dependent rules (rate limits, GeoIP, method and
/// size checks) are always evaluated, including on a hit. Blocks are never
/// cached.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AllowCacheConfig {
    /// Enable the cache. Off by default; this is a research prototype.
    pub enabled: bool,

    /// Entry lifetime in seconds. Short by design so a policy or threat-feed
    /// change is picked up quickly even without an explicit invalidation.
    pub ttl_secs: u64,

    /// Maximum number of cached verdicts across all shards.
    pub max_entries: usize,

    /// Bodies larger than this are evaluated but never cached, which bounds
    /// key-construction cost.
    pub max_body_bytes: usize,

    /// Optional path prefixes the cache applies to. Empty means every route
    /// when `enabled = true`. A prefix matches on a `/` boundary, so `/api`
    /// matches `/api` and `/api/x` but not `/apix`.
    pub routes: Vec<String>,
}

impl Default for AllowCacheConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            ttl_secs: 30,
            max_entries: 8192,
            max_body_bytes: 64 * 1024,
            routes: Vec::new(),
        }
    }
}

/// Availability/security trade-off when the regional distri-kv cluster is
/// unreachable. This is independent of `waf.fail_mode`, which governs WAF
/// engine errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DistributedFallbackMode {
    /// Keep using process-local state. The cluster is never on the decision
    /// path, so an outage never changes a request decision. Default.
    #[default]
    LocalOnly,
    /// Allow shared-data lookups that cannot be answered (availability-first).
    FailOpen,
    /// Block shared-data lookups that cannot be answered (security-first).
    FailClosed,
}

impl DistributedFallbackMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LocalOnly => "local_only",
            Self::FailOpen => "fail_open",
            Self::FailClosed => "fail_closed",
        }
    }
}

/// Distributed security fabric client (`[waf.distributed]`).
///
/// Off by default. Enabling this section only has an effect in a build that
/// compiles the non-default `distri-kv` feature; without it the configuration
/// is still parsed and validated so shipped configs remain forward
/// compatible, and startup logs a warning. An enabled section without a
/// reachable cluster is valid: the default `fallback = "local_only"` keeps
/// every decision process-local.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DistributedConfig {
    /// Master switch. `false` (default) is byte-for-byte local behaviour.
    pub enabled: bool,

    /// Stable node identity. Empty lets the operator or a future client
    /// generate and persist one; it never gates request processing.
    pub node_id: String,

    /// Failure/consistency domain, for example `eu-west-1`.
    pub region: String,

    /// Policy scope requested from the cluster (`GetPolicy`). Empty selects
    /// `default`.
    pub policy_scope: String,

    /// Regional bootstrap endpoints (for example
    /// `https://dkv-eu.example:7443`). Empty is valid in `local_only` mode.
    pub endpoints: Vec<String>,

    /// Optional bearer token sent as `authorization: Bearer <token>` on every
    /// DistriWaf RPC. Required when the cluster's DistriWaf service uses
    /// bearer-token auth (for example behind a TLS-terminating sidecar).
    /// Empty means no credential is attached. Treat this value as a secret.
    pub auth_token: String,

    /// SPIFFE workload identity asserted in request metadata
    /// (`x-spiffe-id` by default). Empty disables identity metadata. This is
    /// an assertion consumed only after mTLS; it is never trusted on its own.
    pub spiffe_id: String,

    /// Metadata key used to carry `spiffe_id`. Must be a lowercase HTTP/2
    /// metadata name. Defaults to `x-spiffe-id`.
    pub spiffe_metadata_key: String,

    /// Optional SPIFFE JWT-SVID (or deployment-issued JWT) attached as
    /// `authorization: Bearer <token>` when `auth_token` is empty. Treat it as
    /// a secret; it is never logged.
    pub spiffe_jwt: String,

    /// PEM CA bundle used to verify the distri-kv server certificate for
    /// `https://` endpoints. Empty uses the system/webpki roots.
    pub tls_ca_cert_path: String,

    /// PEM client certificate for mutual TLS. Requires `tls_client_key_path`.
    pub tls_client_cert_path: String,

    /// PEM private key for `tls_client_cert_path`.
    pub tls_client_key_path: String,

    /// Override the TLS SNI/verification name when the endpoint host does not
    /// match the server certificate.
    pub tls_server_name: String,

    /// Explicitly permit `http://` endpoints (for a local TLS-terminating
    /// sidecar only). Off by default: plaintext control-plane transport is
    /// never implied by an `http://` URL.
    pub allow_insecure_transport: bool,

    /// Verify the Ed25519 signature, content hash and hash chain of every
    /// fetched policy bundle. Off is rejected unless explicitly set, because
    /// unsigned policy must never be applied by accident.
    pub require_policy_signature: bool,

    /// Ed25519 public key for policy bundles, hex or base64 encoded (32 raw
    /// bytes). Required when `require_policy_signature` is on.
    pub policy_signing_public_key: String,

    /// Expected policy signing key id. Empty accepts any verified key.
    pub policy_signing_key_id: String,

    /// Optional prerequisite policy hash for the first accepted bundle. Empty
    /// accepts an empty `previous_hash` on first use; later bundles must chain.
    pub policy_initial_hash: String,

    /// Enable shared rate-limit leases. The local token bucket always remains
    /// authoritative for local-only traffic.
    pub leases_enabled: bool,

    /// Requested lease TTL in milliseconds.
    pub lease_ttl_ms: u64,

    /// Maximum number of lease requests drained per background batch.
    pub lease_batch_max: usize,

    /// Bounded lease-request queue capacity. Overflow drops, never blocks.
    pub lease_queue_capacity: usize,

    /// This node's gRPC ingest endpoint advertised in `Register`
    /// (`NodeMetadata.endpoint`). The contract requires a non-empty value;
    /// when this is empty the first control-plane endpoint is advertised.
    pub advertise_endpoint: String,

    /// Behaviour when the cluster is unavailable. Default `local_only`.
    pub fallback: DistributedFallbackMode,

    /// Lifetime of a cached policy/allowlist generation, in seconds.
    pub policy_cache_ttl_secs: u64,

    /// Lifetime of a cached reputation entry, in seconds.
    pub reputation_cache_ttl_secs: u64,

    /// How long a stale entry may still be served before it is treated as a
    /// miss. `0` disables stale serving.
    pub max_stale_secs: u64,

    /// Controller heartbeat interval, in seconds.
    pub heartbeat_interval_secs: u64,

    /// Background RPC timeout. Never applied on the request path.
    pub request_timeout_ms: u64,

    /// Bounded security-event queue capacity. Overflow drops, never blocks.
    pub event_queue_capacity: usize,

    /// Bounded rate-limit counter-delta queue capacity. Overflow drops,
    /// never blocks.
    pub counter_queue_capacity: usize,

    /// Initial reconnect backoff, in milliseconds.
    pub reconnect_initial_backoff_ms: u64,

    /// Maximum reconnect backoff, in milliseconds.
    pub reconnect_max_backoff_ms: u64,

    /// Canary safety net: connect, observe and log, but never enforce derived
    /// actions. Default `true`.
    pub shadow: bool,
}

impl Default for DistributedConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            node_id: String::new(),
            region: String::new(),
            policy_scope: "default".to_string(),
            endpoints: Vec::new(),
            auth_token: String::new(),
            spiffe_id: String::new(),
            spiffe_metadata_key: "x-spiffe-id".to_string(),
            spiffe_jwt: String::new(),
            tls_ca_cert_path: String::new(),
            tls_client_cert_path: String::new(),
            tls_client_key_path: String::new(),
            tls_server_name: String::new(),
            allow_insecure_transport: false,
            require_policy_signature: true,
            policy_signing_public_key: String::new(),
            policy_signing_key_id: String::new(),
            policy_initial_hash: String::new(),
            leases_enabled: false,
            lease_ttl_ms: 5_000,
            lease_batch_max: 64,
            lease_queue_capacity: 4096,
            advertise_endpoint: String::new(),
            fallback: DistributedFallbackMode::LocalOnly,
            policy_cache_ttl_secs: 300,
            reputation_cache_ttl_secs: 300,
            max_stale_secs: 900,
            heartbeat_interval_secs: 10,
            request_timeout_ms: 2000,
            event_queue_capacity: 8192,
            counter_queue_capacity: 4096,
            reconnect_initial_backoff_ms: 100,
            reconnect_max_backoff_ms: 30_000,
            shadow: true,
        }
    }
}

impl DistributedConfig {
    /// Validate the distributed block. `enabled = false` performs no checks
    /// beyond the types, so existing configs are unaffected.
    pub fn validate(&self) -> anyhow::Result<()> {
        if !self.enabled {
            return Ok(());
        }
        if self.node_id.len() > 128 {
            anyhow::bail!("waf.distributed.node_id must be at most 128 characters");
        }
        if self.node_id.chars().any(char::is_whitespace) {
            anyhow::bail!("waf.distributed.node_id must not contain whitespace");
        }
        if self.region.len() > 64 {
            anyhow::bail!("waf.distributed.region must be at most 64 characters");
        }
        if self.policy_scope.len() > 128 {
            anyhow::bail!("waf.distributed.policy_scope must be at most 128 characters");
        }
        if self.auth_token.len() > 4096 {
            anyhow::bail!("waf.distributed.auth_token must be at most 4096 characters");
        }
        if !self.auth_token.is_empty()
            && !self
                .auth_token
                .bytes()
                .all(|byte| (0x21..=0x7e).contains(&byte))
        {
            anyhow::bail!(
                "waf.distributed.auth_token must contain only printable ASCII without spaces"
            );
        }
        if !self.auth_token.is_empty() && self.endpoints.is_empty() {
            anyhow::bail!(
                "waf.distributed.auth_token requires at least one waf.distributed.endpoints entry"
            );
        }
        if !self.spiffe_id.is_empty() {
            if !self.spiffe_id.starts_with("spiffe://") || self.spiffe_id.len() > 2048 {
                anyhow::bail!(
                    "waf.distributed.spiffe_id must be a spiffe:// URI of at most 2048 characters"
                );
            }
            if self.endpoints.is_empty() {
                anyhow::bail!(
                    "waf.distributed.spiffe_id requires at least one waf.distributed.endpoints entry"
                );
            }
        }
        if self.spiffe_metadata_key.is_empty()
            || !self
                .spiffe_metadata_key
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            anyhow::bail!(
                "waf.distributed.spiffe_metadata_key must be a lowercase HTTP/2 metadata name"
            );
        }
        for (name, value) in [
            ("spiffe_jwt", &self.spiffe_jwt),
            ("tls_ca_cert_path", &self.tls_ca_cert_path),
            ("tls_client_cert_path", &self.tls_client_cert_path),
            ("tls_client_key_path", &self.tls_client_key_path),
            ("tls_server_name", &self.tls_server_name),
            ("policy_signing_public_key", &self.policy_signing_public_key),
            ("policy_signing_key_id", &self.policy_signing_key_id),
            ("policy_initial_hash", &self.policy_initial_hash),
        ] {
            if value.len() > 8192 {
                anyhow::bail!("waf.distributed.{name} must be at most 8192 characters");
            }
        }
        if self.tls_client_cert_path.is_empty() != self.tls_client_key_path.is_empty() {
            anyhow::bail!(
                "waf.distributed.tls_client_cert_path and tls_client_key_path must be set together"
            );
        }
        if (!self.tls_client_cert_path.is_empty() || !self.tls_ca_cert_path.is_empty())
            && self
                .endpoints
                .iter()
                .any(|endpoint| endpoint.starts_with("http://"))
        {
            anyhow::bail!(
                "waf.distributed TLS client material cannot be used with an http:// endpoint"
            );
        }
        if !self.allow_insecure_transport
            && self
                .endpoints
                .iter()
                .any(|endpoint| endpoint.starts_with("http://"))
        {
            anyhow::bail!(
                "waf.distributed.endpoints uses http:// but allow_insecure_transport is false; \
                 use https:// or explicitly set allow_insecure_transport = true for a local sidecar"
            );
        }
        if self.leases_enabled {
            if self.lease_ttl_ms == 0 {
                anyhow::bail!("waf.distributed.lease_ttl_ms must be greater than zero");
            }
            if self.lease_batch_max == 0 {
                anyhow::bail!("waf.distributed.lease_batch_max must be greater than zero");
            }
            if self.lease_queue_capacity == 0 {
                anyhow::bail!("waf.distributed.lease_queue_capacity must be greater than zero");
            }
        }
        if !self.advertise_endpoint.trim().is_empty() {
            let uri = self
                .advertise_endpoint
                .parse::<http::Uri>()
                .map_err(|error| {
                    anyhow::anyhow!(
                        "invalid waf.distributed.advertise_endpoint '{}': {error}",
                        self.advertise_endpoint
                    )
                })?;
            if !matches!(uri.scheme_str(), Some("https") | Some("http"))
                || uri.authority().is_none()
            {
                anyhow::bail!(
                    "waf.distributed.advertise_endpoint '{}' must be an absolute http(s) URL",
                    self.advertise_endpoint
                );
            }
        }
        if !self.endpoints.is_empty() && self.node_id.trim().is_empty() {
            anyhow::bail!(
                "waf.distributed.node_id must be set when waf.distributed.endpoints is not empty"
            );
        }
        if !self.endpoints.is_empty() && self.region.trim().is_empty() {
            anyhow::bail!(
                "waf.distributed.region must be set when waf.distributed.endpoints is not empty"
            );
        }
        if self.endpoints.len() > 32 {
            anyhow::bail!("waf.distributed.endpoints must contain at most 32 entries");
        }
        for endpoint in &self.endpoints {
            let uri = endpoint.parse::<http::Uri>().map_err(|error| {
                anyhow::anyhow!("invalid waf.distributed.endpoints entry '{endpoint}': {error}")
            })?;
            if !matches!(uri.scheme_str(), Some("https") | Some("http"))
                || uri.authority().is_none()
            {
                anyhow::bail!(
                    "waf.distributed.endpoints entry '{endpoint}' must be an absolute http(s) URL"
                );
            }
        }
        if self.endpoints.is_empty() && self.fallback != DistributedFallbackMode::LocalOnly {
            anyhow::bail!(
                "waf.distributed.fallback = \"{}\" requires at least one \
                 waf.distributed.endpoints entry",
                self.fallback.as_str()
            );
        }
        if self.policy_cache_ttl_secs == 0 {
            anyhow::bail!("waf.distributed.policy_cache_ttl_secs must be greater than zero");
        }
        if self.reputation_cache_ttl_secs == 0 {
            anyhow::bail!("waf.distributed.reputation_cache_ttl_secs must be greater than zero");
        }
        if self.heartbeat_interval_secs == 0 {
            anyhow::bail!("waf.distributed.heartbeat_interval_secs must be greater than zero");
        }
        if self.request_timeout_ms == 0 {
            anyhow::bail!("waf.distributed.request_timeout_ms must be greater than zero");
        }
        for (name, capacity) in [
            ("event_queue_capacity", self.event_queue_capacity),
            ("counter_queue_capacity", self.counter_queue_capacity),
            ("lease_queue_capacity", self.lease_queue_capacity),
        ] {
            if capacity == 0 {
                anyhow::bail!("waf.distributed.{name} must be greater than zero");
            }
            if capacity > 1_048_576 {
                anyhow::bail!("waf.distributed.{name} must be at most 1048576");
            }
        }
        if self.reconnect_initial_backoff_ms == 0 {
            anyhow::bail!("waf.distributed.reconnect_initial_backoff_ms must be greater than zero");
        }
        if self.reconnect_max_backoff_ms < self.reconnect_initial_backoff_ms {
            anyhow::bail!(
                "waf.distributed.reconnect_max_backoff_ms must not be smaller than \
                 reconnect_initial_backoff_ms"
            );
        }
        Ok(())
    }
}

/// Compiled bodyless allowlist fast path.
///
/// A route listed here is an explicit, operator-approved WAF exclusion for
/// bodyless requests with no query string: the route's inspection rules are
/// skipped and the precomputed `Allow` verdict is returned. Always-on policy
/// gates (request size, method, rate limits and geographic blocking) still
/// run, so a fast-allowed route cannot bypass those controls.
///
/// This is **off by default** and never weakens inspection for any route that
/// is not listed. A request with a query string, a body, a body framing
/// header, a content encoding or an upgrade is never fast-allowed.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WafFastAllowConfig {
    /// Enable the compiled allowlist. Requires at least one route.
    pub enabled: bool,

    /// Exact routes as `"METHOD /path"` (for example `"GET /health"`).
    /// Matching is exact: no prefix, query, wildcard or trailing-slash
    /// folding. Methods are the standard uppercase HTTP methods.
    pub routes: Vec<String>,

    /// Fraction of fast-allowed requests that still emit an allow audit
    /// event. `0.0` (the default) skips allow-event construction entirely;
    /// blocks are always audited.
    pub allow_audit_sample_rate: f64,
}

impl Default for WafFastAllowConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            routes: Vec::new(),
            allow_audit_sample_rate: 0.0,
        }
    }
}

impl WafFastAllowConfig {
    /// Validate the compiled allowlist before it reaches the request path.
    pub fn validate(&self) -> anyhow::Result<()> {
        if !self.enabled {
            return Ok(());
        }
        if self.routes.is_empty() {
            anyhow::bail!("waf.fast_allow.enabled is true but waf.fast_allow.routes is empty");
        }
        if !(0.0..=1.0).contains(&self.allow_audit_sample_rate) {
            anyhow::bail!("waf.fast_allow.allow_audit_sample_rate must be between 0.0 and 1.0");
        }
        if self.routes.len() > 4096 {
            anyhow::bail!("waf.fast_allow.routes must contain at most 4096 entries");
        }
        let mut seen = std::collections::HashSet::with_capacity(self.routes.len());
        for route in &self.routes {
            let parsed = crate::waf::fast_allow::parse_route_spec(route)
                .map_err(|err| anyhow::anyhow!("waf.fast_allow.routes entry '{route}': {err}"))?;
            if !seen.insert((parsed.method.as_str().to_string(), parsed.path.to_string())) {
                anyhow::bail!("waf.fast_allow.routes contains duplicate route '{route}'");
            }
        }
        Ok(())
    }
}

/// Admission control for expensive inspections.
///
/// Cheap requests (no body, or a body withheld from CRS by the gRPC/GraphQL
/// pre-checks) bypass the heavy queue entirely. Heavy requests need one of
/// `heavy_permits` slots, wait at most `queue_timeout_ms` when saturated, and
/// are rejected with `503 + Retry-After` when the queue is full or the wait
/// expires. Admission never skips or reduces inspection.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
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
#[serde(default, deny_unknown_fields)]
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

    /// Hard cap on the number of client IPs tracked by the per-IP limiter.
    /// Once reached, `capacity_policy` decides what happens to new IPs.
    pub max_tracked_ips: usize,

    /// Behaviour when `max_tracked_ips` is reached. `fail_closed` (default)
    /// rejects new IPs; `evict_oldest` evicts the least-recently-seen bucket
    /// from a shard, starting at the cleanup cursor.
    pub capacity_policy: CapacityPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
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
#[serde(default, deny_unknown_fields)]
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

/// Opt-in upstream response inspection (Coraza phases 3–5).
///
/// Disabled by default. When enabled, the proxy evaluates the upstream
/// response headers (and, with `inspect_body`, the response body) with the
/// native Rust engine. Enabling body inspection buffers responses up to
/// `max_body_bytes` for inspection; the full response is still relayed unless
/// it exceeds `server.max_body_size`. Only the first `max_body_bytes` are
/// inspected, deterministically, so a large body cannot exhaust the engine
/// budget. The Coraza WASI/native backends do not implement response
/// inspection; enabling this with those backends records an unsupported
/// metric and leaves responses uninspected.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ResponseInspectionConfig {
    /// Enable response inspection. Defaults to `false`.
    pub enabled: bool,

    /// Inspect the response body in addition to headers. Defaults to `false`.
    /// Enabling this buffers the response (up to the configured caps).
    pub inspect_body: bool,

    /// Maximum number of response body bytes handed to the engine. The
    /// inspection prefix is deterministic; bytes beyond this cap are not
    /// inspected. Defaults to 1 MiB.
    pub max_body_bytes: usize,

    /// Status returned to the client when a response rule blocks. Defaults to
    /// `403`. The body is a generic WAF message; upstream content is never
    /// echoed.
    pub block_status: u16,
}

impl Default for ResponseInspectionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            inspect_body: false,
            max_body_bytes: 1024 * 1024,
            block_status: 403,
        }
    }
}

impl ResponseInspectionConfig {
    /// Validate the response-inspection settings.
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.max_body_bytes == 0 {
            anyhow::bail!("waf.response_inspection.max_body_bytes must be greater than zero");
        }
        if !(400..=599).contains(&self.block_status) {
            anyhow::bail!(
                "waf.response_inspection.block_status must be a 4xx or 5xx status (got {})",
                self.block_status
            );
        }
        if self.inspect_body && !self.enabled {
            anyhow::bail!(
                "waf.response_inspection.inspect_body requires waf.response_inspection.enabled = true"
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
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

/// Legacy component-ABI WASM ModSecurity configuration.
///
/// Parsed unconditionally; only used by builds with the `wasm-waf` feature.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
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
    /// In-process WASI reactor hosted by wasmtime. This is the reference
    /// implementation and the default when `rust-engine` is not compiled in.
    #[default]
    Wasm,
    /// Native Go sidecar over a Unix domain socket (`coraza-native` feature).
    Native,
    /// In-process native Rust CRS engine (`rust-engine` feature). This is the
    /// default when the feature is compiled in.
    Rust,
}

impl CorazaBackend {
    /// The backend selected when `waf.coraza.backend` is not configured.
    ///
    /// The Rust engine is the default whenever it is compiled in; builds
    /// without `rust-engine` keep the Coraza WASI reactor as the default.
    pub const fn compiled_default() -> Self {
        if cfg!(feature = "rust-engine") {
            Self::Rust
        } else {
            Self::Wasm
        }
    }
}

/// Fallback behaviour when the Rust engine fails at request time
/// (`waf.coraza.fallback`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CorazaFallback {
    /// No fallback: a Rust-engine runtime error is a fail-closed block
    /// (default).
    #[default]
    None,
    /// Re-evaluate the request with the Coraza WASI reactor after a Rust-engine
    /// runtime error. The Coraza decision is used, and a Coraza error is
    /// fail-closed. Requires the `wasm-reactor` feature.
    Wasm,
}

/// What the reactor does when a request body is larger than
/// [`WafCorazaConfig::max_inspect_bytes`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CorazaOversizeAction {
    /// Inspect the whole body (up to `max_payload_bytes`). This is the default
    /// and preserves the historical behaviour.
    #[default]
    InspectAll,
    /// Inspect only the first `max_inspect_bytes` bytes and forward the rest
    /// of the body without CRS body inspection. Header and URI rules still
    /// run. This is an explicit inspection gap.
    ForwardUninspected,
    /// Reject the request with `413 Payload Too Large` before evaluation.
    Reject,
}

/// Host-side CRS required-literal gating mode (`waf.coraza.prefilter`).
///
/// `off` (the default) evaluates every rule. `dry-run` measures the prefilter
/// verdict without changing the payload. `gated` removes only the gated rules
/// whose mandatory literals are provably absent from the request; ungated rules
/// always run, so no rule coverage is lost.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CorazaPrefilterMode {
    /// Evaluate every CRS rule (default).
    #[default]
    Off,
    /// Run the prefilter and record metrics, but send no removals.
    DryRun,
    /// Remove gated rules whose required literals are absent.
    Gated,
}

impl CorazaPrefilterMode {
    /// True when the prefilter should run at all.
    pub fn is_enabled(self) -> bool {
        self != Self::Off
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WafCorazaConfig {
    /// Enable the real Coraza WASI reactor.
    pub enabled: bool,

    /// Evaluation backend: `rust` (default when compiled with `rust-engine`),
    /// `wasm` (Coraza reference implementation) or `native`.
    pub backend: CorazaBackend,

    /// Fallback when the Rust engine fails at request time. `none` (default)
    /// fails closed; `wasm` re-evaluates with the Coraza reactor.
    pub fallback: CorazaFallback,

    /// Unix domain socket for the native sidecar. Ignored by the wasm backend.
    pub native_socket_path: Option<String>,

    /// Optional path to a reactor `.wasm` file. `None` uses the embedded module.
    pub module_path: Option<String>,

    /// Maximum request payload handed to the reactor.
    pub max_payload_bytes: usize,

    /// Maximum number of request-body bytes inspected by CRS. `0` (the
    /// default) inspects the whole body, preserving historical behaviour.
    /// Must not exceed `max_payload_bytes` when non-zero.
    pub max_inspect_bytes: usize,

    /// Policy applied when the body exceeds `max_inspect_bytes`.
    pub oversize_action: CorazaOversizeAction,

    /// Maximum linear memory the reactor may grow to.
    pub memory_limit_bytes: usize,

    /// Wall-clock budget for one reactor `eval`, in milliseconds. Enforced by
    /// wasmtime epoch interruption; this is a denial-of-service bound, not a
    /// latency target.
    pub eval_timeout_ms: u64,

    /// Number of pre-warmed reactor instances, one dedicated OS thread each.
    /// `0` selects the number of available cores clamped to `1..=8`.
    pub pool_size: usize,

    /// Host-side CRS required-literal gating. `off` (default) evaluates every
    /// rule; `gated` removes only the rules whose proven mandatory literals are
    /// absent from the request. Requires the non-default `crs-prefilter`
    /// feature.
    pub prefilter: CorazaPrefilterMode,
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
            backend: CorazaBackend::compiled_default(),
            fallback: CorazaFallback::None,
            native_socket_path: None,
            module_path: None,
            max_payload_bytes: 64 * 1024,
            // 0 = inspect the whole body (historical behaviour).
            max_inspect_bytes: 0,
            oversize_action: CorazaOversizeAction::InspectAll,
            memory_limit_bytes: 256 * 1024 * 1024,
            // Generous DoS bound: CRS body inspection is byte-linear and a
            // 60 KiB body can legitimately take seconds on modest hardware.
            eval_timeout_ms: 5000,
            // Auto: one pre-warmed reactor per available core (clamped).
            pool_size: 0,
            prefilter: CorazaPrefilterMode::Off,
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
#[serde(default, deny_unknown_fields)]
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

    /// Maximum decompressed bytes across all gzip-compressed frames in one
    /// request body. Bounds a gzip bomb before field decoding.
    pub max_decompressed_bytes: usize,

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

    /// Content scanning of decoded string/bytes fields: `off` or `strings`.
    /// `strings` (the default) sends the decoded field values to the Coraza
    /// backend as a synthetic form payload; `off` keeps the structural-only
    /// behaviour.
    pub content_scan: String,

    /// Maximum number of decoded field bytes included in one synthetic
    /// content-scan payload. Values beyond the cap are truncated
    /// deterministically.
    pub max_content_scan_bytes: usize,
}

impl Default for WafGrpcConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            method_allowlist: Vec::new(),
            allowlist_file: None,
            max_message_bytes: 4 * 1024 * 1024,
            max_frames: 64,
            max_decompressed_bytes: 10 * 1024 * 1024,
            unknown_method_action: None,
            max_string_bytes: 1024 * 1024,
            max_bytes_len: 1024 * 1024,
            max_repeated: 1024,
            max_depth: 32,
            max_decoded_fields: 100_000,
            reject_unknown_fields: false,
            validate_strings: true,
            content_scan: "strings".to_string(),
            max_content_scan_bytes: 64 * 1024,
        }
    }
}

impl WafGrpcConfig {
    /// Whether decoded field content is scanned by the Coraza backend.
    pub fn content_scan_enabled(&self) -> bool {
        self.content_scan == "strings"
    }

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
        if self.max_decompressed_bytes == 0 {
            anyhow::bail!("waf.grpc.max_decompressed_bytes must be greater than zero");
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
        if self.content_scan != "off" && self.content_scan != "strings" {
            anyhow::bail!(
                "waf.grpc.content_scan must be 'off' or 'strings', got '{}'",
                self.content_scan
            );
        }
        if self.max_content_scan_bytes == 0 {
            anyhow::bail!("waf.grpc.max_content_scan_bytes must be greater than zero");
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
#[serde(default, deny_unknown_fields)]
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

        #[allow(unused_mut)]
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
#[serde(default, deny_unknown_fields)]
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
#[serde(default, deny_unknown_fields)]
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
#[serde(default, deny_unknown_fields)]
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
#[serde(default, deny_unknown_fields)]
pub struct AuditConfig {
    /// Enable tamper-evident audit logging
    pub tamper_evident: bool,

    /// Audit log retention period in days
    pub retention_days: u32,

    /// Integrity check interval in hours
    pub integrity_check_hours: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
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
#[serde(default, deny_unknown_fields)]
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
#[serde(default, deny_unknown_fields)]
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
            runtime: RuntimeConfig::default(),
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
            pool: UpstreamPoolConfig::default(),
            streaming: StreamingConfig::default(),
            strip_headers: DEFAULT_STRIP_HEADERS
                .iter()
                .map(|name| (*name).to_string())
                .collect(),
            strip_headers_mode: HeaderStripMode::default(),
            reject_ambiguous_routing: false,
        }
    }
}

impl Default for UpstreamPoolConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_idle_per_host: 32,
            idle_timeout_secs: 90,
            health_check_interval_secs: 0,
            health_check_path: "/healthz".to_string(),
        }
    }
}

impl Default for StreamingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            response_threshold_bytes: 1024 * 1024,
        }
    }
}

impl Default for Http2TuningConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            initial_stream_window_bytes: 1024 * 1024,
            initial_connection_window_bytes: 16 * 1024 * 1024,
            max_concurrent_streams: 256,
            max_pending_accept_reset_streams: 1024,
            keep_alive_interval_secs: 30,
            keep_alive_timeout_secs: 10,
            keep_alive_while_idle: false,
            adaptive_window: false,
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
            max_body_size: 10 * 1024 * 1024, // 10MB
            max_header_count: 128,
            max_header_bytes: 64 * 1024,
            h3_max_connections: 1024,
            h3_max_concurrent_bidi_streams: 100,
            h3_stateless_retry: true,
            h3_idle_timeout_secs: 30,
            h3_max_inflight_requests: 256,
            h3_max_inflight_per_client: 0,
            h3_admission_timeout_ms: 250,
            websocket: WebSocketConfig::default(),
            grpc_max_stream_bytes: 4 * 1024 * 1024, // 4MiB
            grpc_max_stream_seconds: 300,
            grpc_max_stream_messages: 1024,
            grpc_max_decompressed_bytes: 10 * 1024 * 1024, // 10MiB
            grpc_streaming_policy: GrpcStreamingPolicy::Reject,
            grpc_aware_rejections: false,
            tls: TlsConfig::default(),
            http2: Http2TuningConfig::default(),
            webtransport: WebTransportConfig::default(),
            io_backend: ListenerIoBackend::default(),
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
            session_resumption: false,
            session_cache_size: 256,
            tls13_tickets: 2,
            tcp_nodelay: false,
            tcp_keepalive_secs: 0,
            tcp_keepalive_interval_secs: 0,
            tcp_fast_open: false,
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
            response_inspection: ResponseInspectionConfig::default(),
            geo_blocking: GeoBlockingConfig::default(),
            wasm: WasmConfig::default(),
            coraza: WafCorazaConfig::default(),
            grpc: WafGrpcConfig::default(),
            graphql: WafGraphqlConfig::default(),
            admission: WafAdmissionConfig::default(),
            allow_cache: AllowCacheConfig::default(),
            fast_allow: WafFastAllowConfig::default(),
            distributed: DistributedConfig::default(),
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
            max_tracked_ips: crate::waf::rate_limit::DEFAULT_MAX_TRACKED_IPS,
            capacity_policy: CapacityPolicy::FailClosed,
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

/// Resolve the TOML file that `config::File::with_name` will load.
///
/// `WAF_CONFIG_FILE` may omit the `.toml` extension, in which case the config
/// crate searches for a supported format. Strict pre-validation only applies to
/// files we can identify as TOML.
fn resolve_toml_path(config_file: &str) -> Option<PathBuf> {
    let path = PathBuf::from(config_file);
    match path.extension().and_then(|extension| extension.to_str()) {
        Some(extension) if extension.eq_ignore_ascii_case("toml") => path.is_file().then_some(path),
        Some(_) => None,
        None if path.is_file() => Some(path),
        None => {
            let candidate = path.with_extension("toml");
            candidate.is_file().then_some(candidate)
        }
    }
}

/// Parse the TOML file with the real config schema so unknown keys are fatal.
fn validate_toml_file(path: &Path) -> anyhow::Result<()> {
    let contents = std::fs::read_to_string(path).map_err(|error| {
        anyhow::anyhow!(
            "failed to read configuration file '{}': {error}",
            path.display()
        )
    })?;

    toml::from_str::<Config>(&contents)
        .map(|_| ())
        .map_err(|error| anyhow::anyhow!("{}", format_config_error(path, &contents, &error)))
}

/// Human-readable strict-config error with file, section, key and location.
fn format_config_error(path: &Path, contents: &str, error: &toml::de::Error) -> String {
    let (line, column) = error
        .span()
        .map(|span| position_in_source(contents, span.start))
        .unwrap_or((1, 1));
    let message = error.message();
    let key = unknown_field_name(message)
        .map(str::to_string)
        .or_else(|| key_on_line(contents, line));
    let section = section_at_line(contents, line);

    let key_path = match (section.as_deref(), key.as_deref()) {
        (Some(section), Some(key)) => format!("{section}.{key}"),
        (Some(section), None) => section.to_string(),
        (None, Some(key)) => format!("top-level.{key}"),
        (None, None) => "unknown".to_string(),
    };
    let kind = if message.starts_with("unknown field")
        || message.starts_with("unknown variant")
        || message.starts_with("duplicate field")
    {
        "unknown key"
    } else {
        "invalid key value"
    };

    format!(
        "configuration file '{}' is invalid: {kind} '{key_path}' (line {line}, column {column}): {message}",
        path.display()
    )
}

fn position_in_source(contents: &str, offset: usize) -> (usize, usize) {
    let before = contents.get(..offset).unwrap_or(contents);
    let line = before.bytes().filter(|byte| *byte == b'\n').count() + 1;
    let column = before
        .rsplit('\n')
        .next()
        .map(|line| line.chars().count() + 1)
        .unwrap_or(1);
    (line, column)
}

fn section_at_line(contents: &str, line: usize) -> Option<String> {
    let mut section = None;
    for (index, text) in contents.lines().enumerate() {
        if index + 1 >= line {
            break;
        }
        if let Some(header) = table_header(text) {
            section = Some(header);
        }
    }
    section
}

fn table_header(line: &str) -> Option<String> {
    let trimmed = line.trim_start();
    let inner = trimmed.strip_prefix('[')?;
    let inner = inner.strip_prefix('[').unwrap_or(inner);
    let end = inner.find(']')?;
    let header = inner[..end].trim();
    (!header.is_empty()).then(|| header.to_string())
}

fn unknown_field_name(message: &str) -> Option<&str> {
    let message = message
        .strip_prefix("unknown field `")
        .or_else(|| message.strip_prefix("duplicate field `"))
        .or_else(|| message.strip_prefix("unknown field '"))
        .or_else(|| message.strip_prefix("duplicate field '"))?;
    let end = message.find(['`', '\''])?;
    Some(&message[..end])
}

fn key_on_line(contents: &str, line: usize) -> Option<String> {
    let text = contents.lines().nth(line.saturating_sub(1))?.trim();
    if text.starts_with('[') {
        return None;
    }
    let (key, _) = text.split_once('=')?;
    let key = key.trim().trim_matches(['"', '\'']);
    (!key.is_empty()).then(|| key.to_string())
}

/// Build the `WAF_*` environment source used for overrides.
///
/// The prefix itself is stripped here rather than by `config::Environment` so
/// the selector variables (`WAF_CONFIG_FILE`, `WAF_CONFIG_PATH`) never become
/// configuration keys. Unknown `WAF_*` variables are still rejected by the
/// strict deserializer below.
fn environment_source() -> config::Environment {
    let variables: config::Map<String, String> = std::env::vars()
        .filter_map(|(key, value)| {
            let key = key.to_ascii_lowercase();
            let key = key.strip_prefix("waf_")?;
            if key.is_empty() || key == "config_file" || key == "config_path" {
                return None;
            }
            Some((key.to_string(), value))
        })
        .collect();

    config::Environment::default()
        .separator("__")
        .source(Some(variables))
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
        if let Some(config_file) = config_file.as_deref() {
            info!("Loading configuration from file: {}", config_file);
            // Validate the file with a strict TOML parse first so unknown keys
            // are reported with the file path, section and key location. The
            // config crate below still applies environment overrides.
            if let Some(path) = resolve_toml_path(config_file) {
                validate_toml_file(&path)?;
            }
            settings = settings.add_source(config::File::with_name(config_file).required(true));
        }

        settings = settings.add_source(environment_source());

        let source_context = match config_file.as_deref() {
            Some(file) => format!("file '{file}' and WAF_* environment overrides"),
            None => "WAF_* environment overrides".to_string(),
        };
        let config: Config = settings
            .build()
            .map_err(|error| {
                anyhow::anyhow!("failed to build configuration from {source_context}: {error}")
            })?
            .try_deserialize()
            .map_err(|error| {
                anyhow::anyhow!("invalid configuration from {source_context}: {error}")
            })?;
        config.validate()?;

        Ok(config)
    }

    /// Reject configurations that would make the proxy unsafe or unusable.
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.waf.wasm.enabled && !cfg!(feature = "wasm-waf") {
            tracing::warn!(
                "waf.wasm is the legacy component-ABI integration and is ignored by this \
                 build; rebuild with the `wasm-waf` feature or use [waf.coraza]"
            );
        }
        if self.server.max_body_size == 0 {
            anyhow::bail!("server.max_body_size must be greater than zero");
        }
        if self.server.max_connections == 0 {
            anyhow::bail!("server.max_connections must be greater than zero");
        }
        if self.server.max_header_count == 0 {
            anyhow::bail!("server.max_header_count must be greater than zero");
        }
        if self.server.max_header_bytes == 0 {
            anyhow::bail!("server.max_header_bytes must be greater than zero");
        }
        if self.server.h3_max_connections == 0 {
            anyhow::bail!("server.h3_max_connections must be greater than zero");
        }
        if self.server.h3_max_concurrent_bidi_streams == 0 {
            anyhow::bail!("server.h3_max_concurrent_bidi_streams must be greater than zero");
        }
        if self.server.h3_idle_timeout_secs == 0 {
            anyhow::bail!("server.h3_idle_timeout_secs must be greater than zero");
        }
        if self.server.websocket.max_concurrent_tunnels == 0 {
            anyhow::bail!("server.websocket.max_concurrent_tunnels must be greater than zero");
        }
        if self.server.websocket.max_lifetime_secs == 0 {
            anyhow::bail!("server.websocket.max_lifetime_secs must be greater than zero");
        }
        if self.server.websocket.idle_timeout_secs > self.server.websocket.max_lifetime_secs {
            anyhow::bail!(
                "server.websocket.idle_timeout_secs ({}) must not exceed \
                 server.websocket.max_lifetime_secs ({})",
                self.server.websocket.idle_timeout_secs,
                self.server.websocket.max_lifetime_secs
            );
        }
        if self.proxy.max_request_size == 0 {
            anyhow::bail!("proxy.max_request_size must be greater than zero");
        }
        if self.server.h3_max_inflight_requests == 0 {
            anyhow::bail!("server.h3_max_inflight_requests must be greater than zero");
        }
        if self.server.h3_admission_timeout_ms == 0 {
            anyhow::bail!("server.h3_admission_timeout_ms must be greater than zero");
        }
        if self.server.h3_max_inflight_per_client > 0
            && self.server.h3_max_inflight_per_client > self.server.h3_max_inflight_requests
        {
            anyhow::bail!(
                "server.h3_max_inflight_per_client ({}) must not exceed \
                 server.h3_max_inflight_requests ({})",
                self.server.h3_max_inflight_per_client,
                self.server.h3_max_inflight_requests
            );
        }
        let ws_frame = self
            .server
            .websocket
            .resolved_max_frame_bytes(self.server.max_body_size);
        let ws_message = self
            .server
            .websocket
            .resolved_max_message_bytes(self.server.max_body_size);
        if ws_frame == 0 || ws_message == 0 {
            anyhow::bail!(
                "server.websocket.max_frame_bytes and max_message_bytes must resolve to \
                 greater than zero"
            );
        }
        if ws_frame > ws_message {
            anyhow::bail!(
                "server.websocket.max_frame_bytes ({}) must not exceed \
                 server.websocket.max_message_bytes ({})",
                ws_frame,
                ws_message
            );
        }
        if self.server.grpc_max_stream_bytes == 0 {
            anyhow::bail!("server.grpc_max_stream_bytes must be greater than zero");
        }
        if self.server.grpc_max_stream_seconds == 0 {
            anyhow::bail!("server.grpc_max_stream_seconds must be greater than zero");
        }
        if self.server.grpc_max_stream_messages == 0 {
            anyhow::bail!("server.grpc_max_stream_messages must be greater than zero");
        }
        if self.server.grpc_max_decompressed_bytes == 0 {
            anyhow::bail!("server.grpc_max_decompressed_bytes must be greater than zero");
        }
        if self.proxy.timeout_seconds == 0 || self.server.request_timeout_secs == 0 {
            anyhow::bail!("request timeouts must be greater than zero");
        }
        if self.proxy.pool.enabled {
            if self.proxy.pool.max_idle_per_host == 0 {
                anyhow::bail!("proxy.pool.max_idle_per_host must be greater than zero");
            }
            if self.proxy.pool.idle_timeout_secs == 0 {
                anyhow::bail!("proxy.pool.idle_timeout_secs must be greater than zero");
            }
            if !self.proxy.pool.health_check_path.starts_with('/') {
                anyhow::bail!("proxy.pool.health_check_path must start with '/'");
            }
        }
        if self.proxy.streaming.enabled && self.proxy.streaming.response_threshold_bytes == 0 {
            anyhow::bail!("proxy.streaming.response_threshold_bytes must be greater than zero");
        }
        for name in &self.proxy.strip_headers {
            let trimmed = name.trim();
            if trimmed.is_empty() {
                anyhow::bail!("proxy.strip_headers entries must not be empty");
            }
            if trimmed
                .chars()
                .any(|c| c.is_whitespace() || c == ':' || c.is_control())
            {
                anyhow::bail!(
                    "proxy.strip_headers entry '{trimmed}' must be a header name or a trailing-* pattern"
                );
            }
            if trimmed.trim_end_matches('*').contains('*')
                || (trimmed.contains('*') && !trimmed.ends_with('*'))
            {
                anyhow::bail!(
                    "proxy.strip_headers entry '{trimmed}' may only use '*' as a trailing prefix match"
                );
            }
        }
        if self.server.http2.enabled {
            if self.server.http2.initial_stream_window_bytes == 0
                || self.server.http2.initial_connection_window_bytes == 0
            {
                anyhow::bail!("server.http2 flow-control windows must be greater than zero");
            }
            if self.server.http2.max_concurrent_streams == 0
                || self.server.http2.max_pending_accept_reset_streams == 0
            {
                anyhow::bail!("server.http2 multiplexing limits must be greater than zero");
            }
        }
        if self.waf.rate_limit.per_ip_window_secs == 0 && self.waf.rate_limit.per_ip_enabled {
            anyhow::bail!("waf.rate_limit.per_ip_window_secs must be greater than zero");
        }
        if self.waf.rate_limit.global_window_secs == 0 && self.waf.rate_limit.global_enabled {
            anyhow::bail!("waf.rate_limit.global_window_secs must be greater than zero");
        }
        if self.waf.rate_limit.max_tracked_ips == 0 {
            anyhow::bail!("waf.rate_limit.max_tracked_ips must be greater than zero");
        }
        if self.waf.coraza.max_payload_bytes == 0 {
            anyhow::bail!("waf.coraza.max_payload_bytes must be greater than zero");
        }
        if self.waf.coraza.max_inspect_bytes > 0
            && self.waf.coraza.max_inspect_bytes > self.waf.coraza.max_payload_bytes
        {
            anyhow::bail!(
                "waf.coraza.max_inspect_bytes must not exceed waf.coraza.max_payload_bytes"
            );
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
        if self.waf.coraza.prefilter.is_enabled() && !cfg!(feature = "crs-prefilter") {
            anyhow::bail!(
                "waf.coraza.prefilter = \"{}\" requires a build with the `crs-prefilter` feature",
                match self.waf.coraza.prefilter {
                    CorazaPrefilterMode::Off => "off",
                    CorazaPrefilterMode::DryRun => "dry-run",
                    CorazaPrefilterMode::Gated => "gated",
                }
            );
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
        if self.waf.coraza.backend == CorazaBackend::Rust && !cfg!(feature = "rust-engine") {
            anyhow::bail!(
                "waf.coraza.backend = \"rust\" requires a build with the `rust-engine` feature"
            );
        }
        if self.waf.coraza.fallback == CorazaFallback::Wasm && !cfg!(feature = "wasm-reactor") {
            anyhow::bail!(
                "waf.coraza.fallback = \"wasm\" requires a build with the `wasm-reactor` feature"
            );
        }
        if self.waf.admission.enabled && self.waf.admission.queue_timeout_ms == 0 {
            anyhow::bail!("waf.admission.queue_timeout_ms must be greater than zero");
        }
        if self.waf.admission.heavy_permits > 8 {
            anyhow::bail!("waf.admission.heavy_permits must be between 0 (auto) and 8");
        }
        if self.waf.allow_cache.enabled {
            if self.waf.allow_cache.ttl_secs == 0 {
                anyhow::bail!("waf.allow_cache.ttl_secs must be greater than zero");
            }
            if self.waf.allow_cache.max_entries == 0 {
                anyhow::bail!("waf.allow_cache.max_entries must be greater than zero");
            }
            if self.waf.allow_cache.max_body_bytes == 0 {
                anyhow::bail!("waf.allow_cache.max_body_bytes must be greater than zero");
            }
            for route in &self.waf.allow_cache.routes {
                if !route.starts_with('/') {
                    anyhow::bail!(
                        "waf.allow_cache.routes entry '{route}' must be an absolute path prefix"
                    );
                }
            }
        }
        self.waf.fast_allow.validate()?;
        self.waf.response_inspection.validate()?;
        self.waf.grpc.validate()?;
        self.waf.graphql.validate()?;
        self.waf.distributed.validate()?;
        if self.security.auth.enabled
            && self.security.auth.api_keys.is_empty()
            && self.security.auth.api_key_entries.is_empty()
        {
            anyhow::bail!(
                "security.auth.enabled is true but security.auth.api_keys and api_key_entries are empty"
            );
        }
        self.security.auth.validate()?;
        for cidr in &self.server.trusted_proxies {
            cidr.parse::<ipnetwork::IpNetwork>().map_err(|e| {
                anyhow::anyhow!("invalid server.trusted_proxies entry '{}': {}", cidr, e)
            })?;
        }

        if self.server.tls.enabled {
            for protocol in &self.server.tls.alpn_protocols {
                if protocol.is_empty() || protocol.len() > 255 || protocol.contains('\0') {
                    anyhow::bail!(
                        "server.tls.alpn_protocols entry '{protocol}' is not a valid ALPN token"
                    );
                }
            }
            let mut seen = std::collections::HashSet::new();
            for protocol in &self.server.tls.alpn_protocols {
                if !seen.insert(protocol.as_str()) {
                    anyhow::bail!(
                        "server.tls.alpn_protocols contains duplicate entry '{protocol}'"
                    );
                }
            }
            if !self.server.enable_http2
                && self
                    .server
                    .tls
                    .alpn_protocols
                    .iter()
                    .any(|protocol| protocol == "h2")
            {
                anyhow::bail!(
                    "server.tls.alpn_protocols advertises 'h2' but server.enable_http2 is false"
                );
            }
            if self.server.tls.tls13_tickets > 10 {
                anyhow::bail!("server.tls.tls13_tickets must be between 0 and 10");
            }
            if self.server.tls.session_resumption && self.server.tls.session_cache_size > 1_000_000
            {
                anyhow::bail!("server.tls.session_cache_size must not exceed 1000000");
            }
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

        self.runtime.validate()?;

        Ok(())
    }

    /// Effective cap for a request body.
    ///
    /// `proxy.max_request_size` is a transport cap that can only tighten
    /// `server.max_body_size`; it never widens it. This keeps existing configs
    /// safe when the proxy value is larger than the server value.
    pub fn effective_max_request_body(&self) -> usize {
        self.proxy.max_request_size.min(self.server.max_body_size)
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
    fn resource_limit_defaults_are_safe_and_valid() {
        let config = Config::default();
        assert_eq!(config.server.max_connections, 10000);
        assert!(config.server.max_header_count > 0);
        assert!(config.server.max_header_bytes > 0);
        assert!(config.server.h3_max_connections > 0);
        assert!(config.server.h3_max_concurrent_bidi_streams > 0);
        assert!(config.server.h3_stateless_retry);
        assert!(config.server.websocket.max_concurrent_tunnels > 0);
        assert!(config.server.websocket.idle_timeout_secs > 0);
        assert!(config.server.websocket.max_lifetime_secs > 0);
        config.validate().expect("defaults must validate");
    }

    #[test]
    fn proxy_max_request_size_can_only_tighten_the_body_cap() {
        let mut config = Config::default();
        config.server.max_body_size = 1024;
        config.proxy.max_request_size = 256;
        assert_eq!(config.effective_max_request_body(), 256);

        config.proxy.max_request_size = 4096;
        assert_eq!(config.effective_max_request_body(), 1024);
    }

    #[test]
    fn new_resource_limits_parse_and_are_validated() {
        let parsed: Config = toml::from_str(
            "[server]\n\
             max_connections = 7\n\
             max_header_count = 9\n\
             max_header_bytes = 4096\n\
             h3_max_connections = 3\n\
             h3_max_concurrent_bidi_streams = 4\n\
             h3_stateless_retry = false\n\
             h3_idle_timeout_secs = 12\n\
             [server.websocket]\n\
             max_concurrent_tunnels = 2\n\
             idle_timeout_secs = 30\n\
             max_lifetime_secs = 60\n",
        )
        .expect("resource limit keys parse");
        assert_eq!(parsed.server.max_connections, 7);
        assert_eq!(parsed.server.max_header_count, 9);
        assert_eq!(parsed.server.h3_max_concurrent_bidi_streams, 4);
        assert!(!parsed.server.h3_stateless_retry);
        assert_eq!(parsed.server.websocket.max_concurrent_tunnels, 2);
        parsed.validate().expect("parsed limits validate");

        let bad = toml::from_str::<Config>("[server]\nmax_connections = 0\n").unwrap();
        assert!(bad.validate().is_err());

        let bad_ws = toml::from_str::<Config>(
            "[server.websocket]\nidle_timeout_secs = 120\nmax_lifetime_secs = 60\n",
        )
        .unwrap();
        assert!(bad_ws.validate().is_err());
    }

    #[test]
    fn listener_io_backend_defaults_to_tokio_and_parses_io_uring() {
        let default: Config = toml::from_str("").expect("empty config parses");
        assert_eq!(default.server.io_backend, ListenerIoBackend::Tokio);

        let uring: Config =
            toml::from_str("[server]\nio_backend = \"io_uring\"\n").expect("io_uring parses");
        assert_eq!(uring.server.io_backend, ListenerIoBackend::IoUring);

        assert!(toml::from_str::<Config>("[server]\nio_backend = \"epoll\"\n").is_err());
    }

    #[test]
    fn unknown_top_level_and_nested_keys_are_rejected() {
        let top_level = toml::from_str::<Config>("bind_addr_typo = \"0.0.0.0:8080\"\n")
            .expect_err("unknown top-level key must be rejected");
        assert!(top_level.message().contains("unknown field"));

        let nested = toml::from_str::<Config>("[waf.coraza]\nbackedn = \"wasm\"\n")
            .expect_err("unknown nested key must be rejected");
        assert!(nested.message().contains("backedn"));
    }

    #[test]
    fn strict_config_error_names_file_section_and_key() {
        let contents = "[waf.coraza]\nbackedn = \"wasm\"\n";
        let error = toml::from_str::<Config>(contents).expect_err("typo must be rejected");
        let message = format_config_error(Path::new("config/bad.toml"), contents, &error);

        assert!(message.contains("config/bad.toml"), "{message}");
        assert!(message.contains("waf.coraza.backedn"), "{message}");
        assert!(message.contains("unknown key"), "{message}");
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
    fn test_runtime_config_defaults_are_off() {
        let runtime = RuntimeConfig::default();
        assert_eq!(runtime.worker_threads, None);
        assert_eq!(runtime.max_blocking_threads, None);
        assert_eq!(runtime.thread_keep_alive_secs, None);
        assert!(!runtime.enable_cpu_pinning);
        assert_eq!(runtime.cpu_pin_cores, None);
        runtime.validate().expect("defaults must validate");
    }

    #[test]
    fn test_runtime_config_rejects_zero_worker_threads() {
        let runtime = RuntimeConfig {
            worker_threads: Some(0),
            ..RuntimeConfig::default()
        };
        assert!(runtime.validate().is_err());
    }

    #[test]
    fn test_runtime_config_rejects_excessive_worker_threads() {
        let runtime = RuntimeConfig {
            worker_threads: Some(2048),
            ..RuntimeConfig::default()
        };
        assert!(runtime.validate().is_err());
    }

    #[test]
    fn test_runtime_config_rejects_duplicate_pin_cores() {
        let runtime = RuntimeConfig {
            cpu_pin_cores: Some(vec![0, 1, 1]),
            ..RuntimeConfig::default()
        };
        assert!(runtime.validate().is_err());
    }

    #[test]
    fn test_runtime_config_rejects_out_of_range_pin_cores() {
        let runtime = RuntimeConfig {
            cpu_pin_cores: Some(vec![num_cpus::get() + 1]),
            ..RuntimeConfig::default()
        };
        assert!(runtime.validate().is_err());
    }

    #[test]
    fn test_runtime_config_pinning_fallback_is_not_fatal() {
        // Requesting pinning without the build feature must warn, not fail.
        let runtime = RuntimeConfig {
            enable_cpu_pinning: true,
            ..RuntimeConfig::default()
        };
        runtime
            .validate()
            .expect("pinning fallback must not be fatal");
    }

    #[test]
    fn test_runtime_config_accepts_valid_pin_cores() {
        let runtime = RuntimeConfig {
            cpu_pin_cores: Some(vec![0]),
            ..RuntimeConfig::default()
        };
        runtime.validate().expect("valid pin cores must pass");
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
            "config/performance-native.toml",
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
    fn coraza_prefilter_defaults_off_and_parses_modes() {
        #[derive(serde::Deserialize)]
        struct Wrapper {
            prefilter: CorazaPrefilterMode,
        }

        let config = Config::default();
        assert_eq!(config.waf.coraza.prefilter, CorazaPrefilterMode::Off);
        assert!(!config.waf.coraza.prefilter.is_enabled());
        let parsed: Wrapper = toml::from_str("prefilter = \"gated\"").expect("gated parses");
        assert_eq!(parsed.prefilter, CorazaPrefilterMode::Gated);
        let parsed: Wrapper = toml::from_str("prefilter = \"dry-run\"").expect("dry-run parses");
        assert_eq!(parsed.prefilter, CorazaPrefilterMode::DryRun);
        let parsed: Wrapper = toml::from_str("prefilter = \"off\"").expect("off parses");
        assert_eq!(parsed.prefilter, CorazaPrefilterMode::Off);
    }

    #[test]
    fn coraza_body_inspection_policy_is_validated() {
        let mut config = Config::default();
        assert_eq!(config.waf.coraza.max_inspect_bytes, 0);
        assert_eq!(
            config.waf.coraza.oversize_action,
            CorazaOversizeAction::InspectAll
        );
        assert!(config.validate().is_ok());

        config.waf.coraza.max_inspect_bytes = config.waf.coraza.max_payload_bytes + 1;
        assert!(config.validate().is_err());

        config.waf.coraza.max_inspect_bytes = config.waf.coraza.max_payload_bytes;
        assert!(config.validate().is_ok());

        config.waf.coraza.max_inspect_bytes = 1024;
        config.waf.coraza.oversize_action = CorazaOversizeAction::ForwardUninspected;
        assert!(config.validate().is_ok());
        config.waf.coraza.oversize_action = CorazaOversizeAction::Reject;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn coraza_oversize_action_rejects_unknown_values() {
        let err = toml::from_str::<WafCorazaConfig>(
            "max_inspect_bytes = 1024\noversize_action = \"drop\"\n",
        )
        .expect_err("unknown oversize_action must be rejected");
        assert!(err.to_string().contains("unknown variant"), "{err}");

        let parsed: WafCorazaConfig =
            toml::from_str("max_inspect_bytes = 1024\noversize_action = \"forward-uninspected\"\n")
                .expect("documented action must parse");
        assert_eq!(
            parsed.oversize_action,
            CorazaOversizeAction::ForwardUninspected
        );
    }

    #[test]
    fn native_coraza_backend_requires_a_socket() {
        let mut config = Config::default();
        assert_eq!(config.waf.coraza.backend, CorazaBackend::compiled_default());
        assert_eq!(config.waf.coraza.fallback, CorazaFallback::None);
        assert!(config.validate().is_ok());

        config.waf.coraza.backend = CorazaBackend::Native;
        assert!(config.validate().is_err());

        config.waf.coraza.native_socket_path = Some(String::new());
        assert!(config.validate().is_err());

        config.waf.coraza.native_socket_path = Some("/run/waf/coraza.sock".to_string());
        assert!(config.validate().is_ok());
    }

    #[cfg(feature = "rust-engine")]
    #[test]
    fn rust_coraza_backend_does_not_require_a_socket() {
        let mut config = Config::default();
        config.waf.coraza.backend = CorazaBackend::Rust;
        assert!(config.validate().is_ok());
        assert_eq!(
            serde_json::to_string(&CorazaBackend::Rust).expect("serialize"),
            "\"rust\""
        );
    }

    #[test]
    fn backend_default_tracks_the_compiled_engine() {
        let config = Config::default();
        #[cfg(feature = "rust-engine")]
        assert_eq!(config.waf.coraza.backend, CorazaBackend::Rust);
        #[cfg(not(feature = "rust-engine"))]
        assert_eq!(config.waf.coraza.backend, CorazaBackend::Wasm);
    }

    #[test]
    fn backend_parsing_accepts_all_selectable_values() {
        for (text, expected) in [
            ("wasm", CorazaBackend::Wasm),
            ("rust", CorazaBackend::Rust),
            ("native", CorazaBackend::Native),
        ] {
            let backend: CorazaBackend =
                serde_json::from_str(&format!("\"{text}\"")).expect("backend parses");
            assert_eq!(backend, expected);
        }
        assert!(serde_json::from_str::<CorazaBackend>("\"bogus\"").is_err());
    }

    #[test]
    fn fallback_parsing_accepts_none_and_wasm_only() {
        assert_eq!(
            serde_json::from_str::<CorazaFallback>("\"none\"").expect("none"),
            CorazaFallback::None
        );
        assert_eq!(
            serde_json::from_str::<CorazaFallback>("\"wasm\"").expect("wasm"),
            CorazaFallback::Wasm
        );
        assert!(serde_json::from_str::<CorazaFallback>("\"rust\"").is_err());
    }

    #[cfg(not(feature = "rust-engine"))]
    #[test]
    fn rust_backend_without_the_feature_is_rejected_at_validation() {
        let mut config = Config::default();
        config.waf.coraza.backend = CorazaBackend::Rust;
        let error = config.validate().expect_err("must reject");
        assert!(error.to_string().contains("rust-engine"));
    }

    #[cfg(not(feature = "wasm-reactor"))]
    #[test]
    fn wasm_fallback_without_the_feature_is_rejected_at_validation() {
        let mut config = Config::default();
        config.waf.coraza.fallback = CorazaFallback::Wasm;
        let error = config.validate().expect_err("must reject");
        assert!(error.to_string().contains("wasm-reactor"));
    }

    #[test]
    fn rate_limit_capacity_config_is_validated() {
        let mut config = Config::default();
        assert_eq!(
            config.waf.rate_limit.max_tracked_ips,
            crate::waf::rate_limit::DEFAULT_MAX_TRACKED_IPS
        );
        assert_eq!(
            config.waf.rate_limit.capacity_policy,
            CapacityPolicy::FailClosed
        );
        assert!(config.validate().is_ok());

        config.waf.rate_limit.max_tracked_ips = 0;
        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("max_tracked_ips"));

        let mut config = Config::default();
        config.waf.rate_limit.capacity_policy = CapacityPolicy::EvictOldest;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn h3_and_websocket_limits_are_validated() {
        let mut config = Config::default();
        assert_eq!(config.server.h3_max_inflight_requests, 256);
        assert_eq!(config.server.h3_max_inflight_per_client, 0);
        assert_eq!(config.server.h3_admission_timeout_ms, 250);
        assert!(!config.server.websocket.inspect_responses);
        assert!(!config.security.auth.failure_limit.enabled);
        assert_eq!(
            config
                .server
                .websocket
                .resolved_max_frame_bytes(config.server.max_body_size),
            config.server.max_body_size
        );
        assert!(config.validate().is_ok());

        config.server.h3_max_inflight_requests = 0;
        assert!(config.validate().is_err());

        let mut config = Config::default();
        config.server.h3_admission_timeout_ms = 0;
        assert!(config.validate().is_err());

        let mut config = Config::default();
        config.server.h3_max_inflight_requests = 4;
        config.server.h3_max_inflight_per_client = 5;
        assert!(config.validate().is_err());

        let mut config = Config::default();
        config.server.websocket.max_frame_bytes = 2048;
        config.server.websocket.max_message_bytes = 1024;
        assert!(config.validate().is_err());

        let mut config = Config::default();
        config.server.websocket.max_frame_bytes = 1024;
        config.server.websocket.max_message_bytes = 2048;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn grpc_streaming_policy_defaults_to_reject() {
        let config = Config::default();
        assert_eq!(
            config.server.grpc_streaming_policy,
            GrpcStreamingPolicy::Reject,
            "streaming gRPC must be rejected unless the operator explicitly opts into transport-only"
        );
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
        assert_eq!(config.waf.grpc.content_scan, "strings");
        assert_eq!(config.waf.grpc.max_content_scan_bytes, 64 * 1024);
        assert!(config.waf.grpc.content_scan_enabled());
        assert_eq!(config.waf.grpc.unknown_method_action(), "allow");
        assert!(config.validate().is_ok());

        config.waf.grpc.content_scan = "off".to_string();
        assert!(!config.waf.grpc.content_scan_enabled());
        assert!(config.validate().is_ok());

        config.waf.grpc.content_scan = "everything".to_string();
        assert!(config.validate().is_err());

        let mut config = Config::default();
        config.waf.grpc.max_content_scan_bytes = 0;
        assert!(config.validate().is_err());

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
        // With the reactor feature the artifact is parsed; without it the
        // loader is not compiled and validation only checks readability.
        assert!(
            error.contains(missing)
                && (error.contains("could not be loaded") || error.contains("could not be read")),
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

        // Without the reactor feature the artifact cannot be parsed, so the
        // `graphql-only` mode requirement fails rather than succeeding.
        #[cfg(feature = "wasm-reactor")]
        {
            assert!(config.validate().is_ok());

            std::fs::write(&artifact, b"{not json").unwrap();
            let error = config.validate().unwrap_err().to_string();
            assert!(
                error.contains("allowlist.json") && error.contains("could not be loaded"),
                "unexpected error: {error}"
            );
        }
        #[cfg(not(feature = "wasm-reactor"))]
        {
            let error = config.validate().unwrap_err().to_string();
            assert!(
                error.contains("requires a non-empty"),
                "unexpected error: {error}"
            );
        }
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

    #[test]
    fn fast_allow_is_disabled_by_default() {
        let config = Config::default();
        assert!(!config.waf.fast_allow.enabled);
        assert!(config.waf.fast_allow.routes.is_empty());
        assert_eq!(config.waf.fast_allow.allow_audit_sample_rate, 0.0);
        config.validate().unwrap();
    }

    #[test]
    fn fast_allow_requires_routes_when_enabled() {
        let mut config = Config::default();
        config.waf.fast_allow.enabled = true;
        let error = config.validate().unwrap_err().to_string();
        assert!(
            error.contains("waf.fast_allow.routes is empty"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn fast_allow_rejects_invalid_and_duplicate_routes() {
        for (route, expected) in [
            ("GET", "expected \"METHOD /path\""),
            ("GET health", "path must start with '/'"),
            ("get /health", "not supported"),
            ("GET /health?x=1", "query or fragment"),
            ("GET /health/../admin", "'..'"),
        ] {
            let mut config = Config::default();
            config.waf.fast_allow.enabled = true;
            config.waf.fast_allow.routes = vec![route.to_string()];
            let error = config.validate().unwrap_err().to_string();
            assert!(
                error.contains(expected),
                "route {route:?}: expected {expected:?}, got {error}"
            );
        }

        let mut config = Config::default();
        config.waf.fast_allow.enabled = true;
        config.waf.fast_allow.routes = vec!["GET /health".to_string(), "GET /health".to_string()];
        let error = config.validate().unwrap_err().to_string();
        assert!(
            error.contains("duplicate route"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn fast_allow_rejects_out_of_range_sample_rate() {
        let mut config = Config::default();
        config.waf.fast_allow.enabled = true;
        config.waf.fast_allow.routes = vec!["GET /health".to_string()];
        config.waf.fast_allow.allow_audit_sample_rate = 1.5;
        let error = config.validate().unwrap_err().to_string();
        assert!(
            error.contains("allow_audit_sample_rate"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn response_inspection_is_disabled_by_default() {
        let config = Config::default();
        assert!(!config.waf.response_inspection.enabled);
        assert!(!config.waf.response_inspection.inspect_body);
        assert_eq!(config.waf.response_inspection.max_body_bytes, 1024 * 1024);
        assert_eq!(config.waf.response_inspection.block_status, 403);
        config.validate().unwrap();
    }

    #[test]
    fn response_inspection_validation_rejects_bad_limits() {
        let mut config = Config::default();
        config.waf.response_inspection.max_body_bytes = 0;
        let error = config.validate().unwrap_err().to_string();
        assert!(
            error.contains("max_body_bytes"),
            "unexpected error: {error}"
        );

        let mut config = Config::default();
        config.waf.response_inspection.block_status = 200;
        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("block_status"), "unexpected error: {error}");

        let mut config = Config::default();
        config.waf.response_inspection.inspect_body = true;
        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("inspect_body"), "unexpected error: {error}");
    }

    #[test]
    fn tls_alpn_validation_rejects_duplicates_and_invalid_tokens() {
        let mut config = Config::default();
        config.server.tls.enabled = true;
        config.server.tls.alpn_protocols =
            vec!["h2".to_string(), "http/1.1".to_string(), "h2".to_string()];
        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("duplicate"), "unexpected error: {error}");

        config.server.tls.alpn_protocols = vec!["".to_string()];
        let error = config.validate().unwrap_err().to_string();
        assert!(
            error.contains("valid ALPN token"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn tls_alpn_validation_rejects_h2_when_http2_disabled() {
        let mut config = Config::default();
        config.server.tls.enabled = true;
        config.server.enable_http2 = false;
        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("enable_http2"), "unexpected error: {error}");

        config.server.tls.alpn_protocols = vec!["http/1.1".to_string()];
        assert!(config.validate().is_ok());
    }

    #[test]
    fn tls_tuning_validation_bounds_ticket_count() {
        let mut config = Config::default();
        config.server.tls.enabled = true;
        config.server.tls.tls13_tickets = 11;
        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("tls13_tickets"), "unexpected error: {error}");
    }

    #[test]
    fn distributed_defaults_are_off_and_local_only() {
        let config = Config::default();
        assert!(!config.waf.distributed.enabled);
        assert_eq!(
            config.waf.distributed.fallback,
            DistributedFallbackMode::LocalOnly
        );
        assert_eq!(config.waf.distributed.heartbeat_interval_secs, 10);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn distributed_section_parses_and_validates() {
        let config: Config = toml::from_str(
            "[waf.distributed]\n\
             enabled = true\n\
             node_id = \"node-a\"\n\
             region = \"eu-west-1\"\n\
             endpoints = [\"https://dkv-eu.example:7443\"]\n\
             fallback = \"local_only\"\n\
             policy_cache_ttl_secs = 60\n\
             reputation_cache_ttl_secs = 120\n\
             heartbeat_interval_secs = 5\n\
             request_timeout_ms = 500\n\
             event_queue_capacity = 128\n\
             counter_queue_capacity = 64\n",
        )
        .expect("distributed section parses");
        assert!(config.waf.distributed.enabled);
        assert_eq!(config.waf.distributed.endpoints.len(), 1);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn distributed_unknown_keys_are_rejected() {
        let error = toml::from_str::<Config>("[waf.distributed]\nfallbak = \"local_only\"\n")
            .expect_err("unknown key must be rejected");
        assert!(error.message().contains("fallbak"));
    }

    #[test]
    fn distributed_rejects_non_local_fallback_without_endpoints() {
        let mut config = Config::default();
        config.waf.distributed.enabled = true;
        config.waf.distributed.fallback = DistributedFallbackMode::FailClosed;
        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("endpoints"), "unexpected error: {error}");

        config.waf.distributed.fallback = DistributedFallbackMode::LocalOnly;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn distributed_rejects_bad_endpoint_and_zero_bounds() {
        let mut config = Config::default();
        config.waf.distributed.enabled = true;
        config.waf.distributed.node_id = "node-a".to_string();
        config.waf.distributed.region = "eu-west-1".to_string();
        config.waf.distributed.endpoints = vec!["dkv-eu.example:7443".to_string()];
        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("absolute http"), "unexpected error: {error}");

        config.waf.distributed.node_id = String::new();
        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("node_id"), "unexpected error: {error}");
        config.waf.distributed.node_id = "node-a".to_string();

        config.waf.distributed.region = String::new();
        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("region"), "unexpected error: {error}");
        config.waf.distributed.region = "eu-west-1".to_string();

        config.waf.distributed.endpoints = Vec::new();
        config.waf.distributed.heartbeat_interval_secs = 0;
        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("heartbeat_interval_secs"));

        config.waf.distributed.heartbeat_interval_secs = 10;
        config.waf.distributed.event_queue_capacity = 0;
        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("event_queue_capacity"));

        config.waf.distributed.event_queue_capacity = 8192;
        config.waf.distributed.reconnect_initial_backoff_ms = 1000;
        config.waf.distributed.reconnect_max_backoff_ms = 500;
        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("reconnect_max_backoff_ms"));
    }
}
