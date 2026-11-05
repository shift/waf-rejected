# Configuration Reference

WAF-Rejected reads one TOML file. Values not present use the compiled defaults,
so a minimal file only needs the listener and upstream addresses. The complete
annotated file is [`config.toml`](../../config.toml); the container variant is
[`config.docker.toml`](../../config.docker.toml). Focused, validated examples
live in [`config/examples/`](../../config/examples/).

## Loading and precedence

1. Compiled defaults.
2. The TOML file named by `WAF_CONFIG_FILE` (or `CONFIG_PATH`).
3. `WAF_*` environment variables, using `__` for nesting:
   `WAF_SERVER__MAX_BODY_SIZE=10485760`,
   `WAF_WAF__CORAZA__BACKEND=wasm`.

A configured file that is missing or malformed is fatal, as is any value that
fails validation. The server never silently runs with defaults when a file was
requested.

Configuration is **strict**. Unknown keys in the file or in a `WAF_*`
environment override are a hard error. This includes misspelled security
settings: a typo such as `[waf.coraza] backedn = "wasm"` stops start-up before
any listener is bound instead of silently continuing with the default backend.
The error names the file, the section/key path and the line/column, for example:

```text
configuration file 'config/config.toml' is invalid: unknown key
'waf.coraza.backedn' (line 214, column 1): unknown field `backedn`, expected ...
```

Validate edits with:

```bash
./scripts/validate-configs.sh
```

The script loads every shipped config through the real loader and fails on
unknown keys, malformed TOML, wrong types, invalid enum values, cross-field
limit violations and unreadable allowlist artifacts.

### Migrating from permissive configs

Historical keys from the pre-1.0 schema are **not** accepted or allowlisted.
Remove or migrate them; the loader will reject them until you do. Common
migrations:

| Obsolete key | Current key |
| --- | --- |
| `[server] host` / `port` | top-level `bind_addr` |
| `[server] workers` | `[runtime] worker_threads` |
| `[proxy] upstream` | top-level `upstream_uri` (and `[proxy] upstream_url`) |
| `[proxy] retry_attempts` | no equivalent; remove (retries are not configurable) |
| `[security] max_request_size` | `[server] max_body_size` |
| `[security] rate_limit_requests` | `[waf.rate_limit] per_ip_max_requests` |
| `[logging] format` | `[logging] json_format` |
| `[health]`, `[metrics]` | use `health_bind_addr`; health/metrics are always served there |
| `[export]` | `[waf.security_events]` exporter keys |
| top-level `[rate_limit]` | `[waf.rate_limit]` |

The legacy `[waf.wasm]` section is still parsed on every build so shipped
configs remain loadable; it only has an effect in `wasm-waf` builds. Prefer
`[waf.coraza]` for request inspection.

## Top level

```toml
bind_addr = "0.0.0.0:8080"
health_bind_addr = "0.0.0.0:8081"
upstream_uri = "http://127.0.0.1:3000"
```

`bind_addr` is the proxy listener; `health_bind_addr` serves `/health`,
`/health/ready` and `/metrics`. Keep the health listener private.

## `[proxy]`

```toml
[proxy]
upstream_url = "http://127.0.0.1:3000"
bind_addr = "0.0.0.0:8080"
timeout_seconds = 30
max_request_size = 10485760
# upstream_ca_path = "/etc/waf/certs/upstream-ca.pem"
# upstream_client_cert_path = "/etc/waf/certs/client.crt"
# upstream_client_key_path = "/etc/waf/certs/client.key"
```

- `upstream_ca_path` adds a private CA bundle for HTTPS and TLS WebSocket
  upstreams.
- Upstream mTLS requires **both** client cert and key; setting one is a startup
  error.
- `max_request_size` and `server.max_body_size` are transport caps. They do not
  change CRS inspection depth (`waf.coraza.max_inspect_bytes` does).

### `[proxy.pool]` — opt-in

Disabled by default, leaving hyper's built-in connection pool unchanged.

```toml
[proxy.pool]
enabled = true
max_idle_per_host = 64
idle_timeout_secs = 90
health_check_interval_secs = 0   # 0 disables probes
health_check_path = "/healthz"
```

When enabled, `max_idle_per_host` and `idle_timeout_secs` must be greater than
zero and the health path must start with `/`.

### `[proxy.streaming]` — opt-in

Disabled by default: responses are buffered under the byte cap before anything
is written. When enabled, responses advertising at least
`response_threshold_bytes` are relayed frame by frame under the same cap and a
deadline.

```toml
[proxy.streaming]
enabled = true
response_threshold_bytes = 1048576
```

## `[server]`

```toml
[server]
max_connections = 1000
trusted_proxies = []
request_timeout_secs = 30
keep_alive_timeout_secs = 90
enable_http2 = true
enable_http3 = false
supported_http_versions = ["1.0", "1.1", "2"]
max_body_size = 10485760
grpc_max_stream_bytes = 4194304
grpc_max_stream_seconds = 300
grpc_aware_rejections = false
io_backend = "tokio"
```

- `trusted_proxies` is a CIDR list. `X-Forwarded-For` is ignored unless the peer
  matches; an invalid CIDR aborts start-up.
- `supported_http_versions` must match the listener features: HTTP/3 requires a
  `http3` build and `enable_http3 = true`; it is feature-gated, not default.
- Streaming gRPC bodies (no `content-length`) are relayed but never buffered or
  sent to CRS body rules. `grpc_max_stream_bytes` and
  `grpc_max_stream_seconds` bound each exchange.
- `grpc_aware_rejections = true` returns HTTP 200 with `grpc-status: 7`
  (PERMISSION_DENIED) for blocked gRPC calls instead of a plain HTTP error.
- `io_backend` is `"tokio"` (default) or `"io_uring"` (requires the
  non-default `io-uring` feature; unsupported hosts fall back to tokio with a
  warning).

### `[server.tls]`

```toml
[server.tls]
enabled = true
cert_path = "/etc/waf-rejected/certs/server.crt"
key_path = "/etc/waf-rejected/certs/server.key"
min_version = "1.2"
max_version = "1.3"
alpn_protocols = ["h2", "http/1.1"]
require_client_cert = false
# client_ca_path = "/etc/waf-rejected/certs/client-ca.pem"
session_resumption = false
session_cache_size = 256
tls13_tickets = 2
tcp_nodelay = false
tcp_keepalive_secs = 0
tcp_keepalive_interval_secs = 0
tcp_fast_open = false
```

ALPN values must be unique and, if `h2` is advertised, `enable_http2` must be
true. Session resumption, socket tuning and Fast Open are opt-in; `0` leaves the
OS defaults for keep-alive.

### `[server.http2]` — opt-in

```toml
[server.http2]
enabled = true
initial_stream_window_bytes = 1048576
initial_connection_window_bytes = 16777216
max_concurrent_streams = 256
max_pending_accept_reset_streams = 1024
keep_alive_interval_secs = 30
keep_alive_timeout_secs = 10
keep_alive_while_idle = false
adaptive_window = false
```

When enabled, flow-control windows and multiplexing limits must be greater than
zero. Disabled uses hyper's defaults and the historical 30s/10s keep-alive.

### `[server.webtransport]` — opt-in, terminating

Requires a `webtransport` build, TLS 1.3, a non-colliding UDP address and
non-empty allowlists. Empty `allowed_origins` or `allowed_paths` denies every
session. WebTransport is inspected locally and **not** proxied upstream.

```toml
[server.webtransport]
enabled = true
bind_addr = "0.0.0.0:4434"
require_origin = true
allowed_origins = ["https://app.example.com"]
allowed_paths = ["/wt", "/media/*"]
max_sessions = 1024
max_sessions_per_ip = 32
inspect_streams = true
inspect_datagrams = true
```

## `[logging]`

```toml
[logging]
level = "info"      # trace, debug, info, warn, error
json_format = true
```

## `[waf]`

```toml
[waf]
enabled = true
fail_mode = "closed"       # "open" forwards on inspection failure
upstream_timeout_ms = 30000
```

Keep `fail_mode = "closed"`. It controls the WAF layer's response to inspection
errors; the engine-level fallback is separate.

### `[waf.rate_limit]`

```toml
[waf.rate_limit]
per_ip_enabled = true
per_ip_max_requests = 100
per_ip_window_secs = 60
global_enabled = true
global_max_requests = 10000
global_window_secs = 60
max_tracked_ips = 100000
capacity_policy = "fail_closed"   # or "evict_oldest"
```

Windows must be greater than zero when the corresponding limit is enabled.
`max_tracked_ips` must be greater than zero. It is a hard cap on the number of
client IPs tracked by the per-IP limiter. At the cap, `capacity_policy`
controls new IPs:

- `fail_closed` (default) rejects new IPs with a 429 rate-limit decision.
  Existing tracked IPs keep their buckets. This prevents source-address
  spraying from evicting legitimate clients or bypassing the limiter.
- `evict_oldest` evicts the least-recently-seen bucket from a shard (starting
  at the cleanup cursor) to admit the new IP. Bounded, but an attacker with
  many source addresses can churn the table.

The limiter uses 64 independently locked shards selected by a stable hash of
the IP, so unrelated clients do not serialize. Cleanup is incremental
(one shard per 100 evaluations) and never takes a global lock. See
[rate-limiter.md](../developer-guide/rate-limiter.md).

### `[waf.security_events]`

```toml
[waf.security_events]
enabled = true
format = "json"
min_threat_level = "medium"
enable_cef = true
cef_output_file = "./logs/security_events.cef"
cef_device_vendor = "WAF-Rejected"
cef_device_product = "Security WAF"
cef_device_version = "0.1.0-beta.13"
enable_otel = false
# otel_service_name = "waf-rejected"
# otel_export_traces = false
# otel_export_logs = false
enable_sled = true
sled_db_path = "./data/waf_security_events.sled"
sled_max_events = 100000
sled_compress = false
```

### `[waf.content_inspection]`

Built-in heuristic inspection for URIs, headers and request bodies. This runs in
addition to the CRS backend.

```toml
[waf.content_inspection]
enabled = true
inspect_headers = true
inspect_body = true
max_body_size = 10485760
threat_patterns = ["sql_injection", "xss", "command_injection", "path_traversal"]
```

### `[waf.geo_blocking]`

```toml
[waf.geo_blocking]
enabled = false
# database_path = "/etc/waf/GeoLite2-City.mmdb"
# anonymous_database_path = "/etc/waf/GeoIP2-Anonymous-IP.mmdb"
blocked_countries = ["RU"]
blocked_regions = []
block_tor = false
block_vpn = false
block_datacenter = false
```

Tor/VPN/datacenter detection needs the Anonymous IP database; without it those
flags stay false. Licensed `.mmdb` files are never bundled.

### `[waf.admission]`

Bounds concurrent heavy (CRS body) inspections. Cheap requests — no body, or a
gRPC/GraphQL body withheld from CRS — bypass the queue. Saturation or timeout
returns `503 + Retry-After`; inspection is **never** skipped or reduced.

```toml
[waf.admission]
enabled = true
heavy_permits = 0        # 0 = auto (about half the pool, at least 1)
queue_timeout_ms = 250
max_queued = 64          # 0 rejects immediately when saturated
```

### `[waf.coraza]` — inspection backend and body policy

```toml
[waf.coraza]
enabled = true
backend = "rust"           # default when compiled with `rust-engine`
fallback = "none"          # "none" (fail closed) or "wasm"
# native_socket_path = "/run/waf/coraza.sock"   # required for backend = "native"
# module_path = "/usr/share/waf/wasm/coraza_reactor.wasm"
max_payload_bytes = 65536  # wasm contract
max_inspect_bytes = 0      # 0 = whole body (default)
oversize_action = "inspect-all"
memory_limit_bytes = 268435456
eval_timeout_ms = 5000
pool_size = 0              # 0 = cores, clamped to 1..=8
prefilter = "off"          # "dry-run"/"gated" need `crs-prefilter`
```

- `backend`: `"rust"` (default in default builds), `"wasm"` (Coraza reference),
  `"native"` (sidecar). See [engine selection](engine-selection.md).
- `fallback = "wasm"` re-evaluates a request with Coraza after a Rust-engine
  runtime error; a Coraza error is still a fail-closed block.
- `max_inspect_bytes` must not exceed `max_payload_bytes`. Policies:
  - `inspect-all` — scan up to the payload cap; above it fail closed.
  - `reject` — return `413` above `max_inspect_bytes`.
  - `forward-uninspected` — scan the prefix and forward the uninspected tail.
    This is an explicit inspection gap; document it.
- `prefilter = "gated"` requires the non-default `crs-prefilter` feature.
- `module_path` selects an alternate reactor module; the embedded module is used
  when unset.

### `[waf.grpc]`

Protobuf frames are validated structurally and withheld from CRS body rules;
URI and header rules still run. Streaming gRPC bodies remain envelope-only.

```toml
[waf.grpc]
enabled = true
method_allowlist = ["/demo.Echo/Say"]
# allowlist_file = "/etc/waf/grpc/allowlist.json"
max_message_bytes = 4194304
max_frames = 64
unknown_method_action = "block"   # unset => block for non-empty allowlist
max_string_bytes = 1048576
max_bytes_len = 1048576
max_repeated = 1024
max_depth = 32
max_decoded_fields = 100000
reject_unknown_fields = false
validate_strings = true
content_scan = "strings"          # "off" = envelope only
max_content_scan_bytes = 65536
```

A generated `allowlist_file` is merged with `method_allowlist`; its per-method
`max_message_bytes` wins. A configured file that cannot be loaded aborts
start-up. See [`grpc-inspection.md`](../grpc-inspection.md) and the
[`grpc-allowlist` example](../../config/examples/grpc-allowlist.toml).

### `[waf.graphql]`

```toml
[waf.graphql]
enabled = true
body_scan = "crs"          # "crs" | "graphql-only" | "off"
operation_allowlist = []
# allowlist_file = "/etc/waf/graphql/allowlist.json"
unknown_operation_action = "block"
max_body_bytes = 8388608
max_query_bytes = 1048576
max_variables_bytes = 1048576
max_variables = 128
max_depth = 128
max_aliases = 1024
max_fields = 8192
allow_mutations = true
allow_subscriptions = true
```

- `crs` keeps the full CRS JSON body scan; no security change.
- `graphql-only` runs GraphQL checks and withholds the raw body from CRS body
  rules. It requires a non-empty allowlist and gives up CRS body-rule coverage
  for those requests.
- `off` disables GraphQL-specific checks; CRS still scans.

See [`graphql-inspection.md`](../graphql-inspection.md) and the
[persisted-query example](../../config/examples/graphql-persisted.toml).

### `[waf.allow_cache]` — opt-in

Requires the non-default `allow-cache` feature. Memoises only pure-content
`Allow` verdicts for a short TTL. Blocks are never cached; rate limits, GeoIP,
method and size checks still run on every hit.

```toml
[waf.allow_cache]
enabled = true
ttl_secs = 30
max_entries = 8192
max_body_bytes = 65536
routes = ["/api"]        # empty = every route
```

Route entries must be absolute path prefixes and match on a `/` boundary.

### `[waf.fast_allow]` — opt-in

Compiled allowlist for **bodyless, query-free** requests on exact routes. The
listed route skips per-request inspection; request-size, method, rate-limit and
geographic gates still run. A request with a query, body, framing header,
content encoding or upgrade is never fast-allowed.

```toml
[waf.fast_allow]
enabled = true
routes = ["GET /assets/app.css", "GET /favicon.ico"]
allow_audit_sample_rate = 0.0    # 0 skips allow-event construction
```

The health and metrics endpoints are served on `health_bind_addr`, not the
proxy listener, so they do not need a fast-allow entry.

Requires at least one route; duplicate or malformed routes abort start-up.

### `[waf.wasm]` — legacy, feature-gated

Parsed on every build for compatibility, but only effective in builds with the
non-default `wasm-waf` feature. The component ABI is not wired up; enabling this
uses the built-in heuristic fallback, not the Coraza module. Use `[waf.coraza]`
instead.

## `[security]`

```toml
[security.auth]
enabled = false
api_keys = []
header_name = "X-API-Key"
require_https = false
# Optional per-key limits:
# [security.auth.rate_limit]
# per_ip_enabled = true
# per_ip_max_requests = 100
# per_ip_window_secs = 60
```

Enabling auth with an empty `api_keys` list aborts start-up. Prefer injecting
keys from a secret.

```toml
[security.ai]
enabled = false
threat_threshold = 0.8
timeout_ms = 5000

[security.ai.model]
# model_path = "/etc/waf/model.onnx"
anomaly_detection = true
advanced_classification = false
```

The AI/threat-intelligence modules are experimental and not on the request path
by default.

```toml
[security.compliance]
enabled = false

[security.compliance.regulatory]
gdpr = false
hipaa = false
pci_dss = false
ai_act = false
nis2 = false
cra = false

[security.compliance.audit]
tamper_evident = true
retention_days = 2555
integrity_check_hours = 24

[security.compliance.retention]
security_events_days = 90
audit_logs_days = 2555
auto_delete = true
```

Compliance outputs are evidence packs, not certifications. See
[`eu-regulatory-status.md`](../compliance/eu-regulatory-status.md).

## `[storage]`

```toml
[storage]
backend = "redb"           # "redb" | "sled" | "memory"
path = "./data/waf.redb"
enable_follower_reads = true
ttl_cleanup_interval = { secs = 60, nanos = 0 }
enable_compression = false
cache_size = 16777216
# max_memory_entries = 100000   # backend = "memory"
```

The container image uses `/var/lib/waf/data`; mount it read-write for the event
store.

## `[runtime]`

```toml
[runtime]
# worker_threads = 8             # unset = logical CPUs
# max_blocking_threads = 512     # unset = 512
# thread_keep_alive_secs = 10
enable_cpu_pinning = false
# cpu_pin_cores = [0, 1, 2, 3]
```

CPU pinning requires the non-default `cpu-pinning` build feature. Requesting it
without the feature or host support logs a warning and continues unpinned.

## Performance honesty

Sub-millisecond numbers apply to bodyless requests, cache/prefilter fast paths
and the Rust engine request path. End-to-end proxy p50 at 4 KiB and 8 KiB is
about 1.1 ms and 1.6 ms on the reference host. Response inspection is not
proxy-wired yet, and Hyperscan/io_uring/allow-cache/fast-allow are opt-in. See
the [support matrix](../operations/support-matrix.md) before making capacity
claims.

## Ready-to-run examples

| File | Purpose |
| --- | --- |
| [`minimal.toml`](../../config/examples/minimal.toml) | Rust engine default, smallest useful config |
| [`coraza-reference.toml`](../../config/examples/coraza-reference.toml) | Switch back to the Coraza wasm reactor |
| [`native-sidecar.toml`](../../config/examples/native-sidecar.toml) | Native sidecar backend and socket |
| [`grpc-allowlist.toml`](../../config/examples/grpc-allowlist.toml) | gRPC method allowlist and content scan |
| [`graphql-persisted.toml`](../../config/examples/graphql-persisted.toml) | GraphQL-only scan with a persisted allowlist |
| [`high-throughput.toml`](../../config/examples/high-throughput.toml) | Fast-allow, allow cache, admission and pool tuning |
