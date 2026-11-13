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
| `[proxy] upstream` / `upstream_url` | top-level `upstream_uri` |
| `[proxy] retry_attempts` | no equivalent; remove (retries are not configurable) |
| `[security] max_request_size` | `[server] max_body_size` |
| `[security] rate_limit_requests` | `[waf.rate_limit] per_ip_max_requests` |
| `[logging] format` | `[logging] json_format` |
| `[health]`, `[metrics]` | use `health_bind_addr`; health/metrics are always served there. `[health] dependency_checks` is the only health option |
| `[export]` | `[waf.security_events]` exporter keys |
| top-level `[rate_limit]` | `[waf.rate_limit]` |
| `[proxy] upstream_url` / `bind_addr` | top-level `upstream_uri` / `bind_addr` |
| `[waf] upstream_timeout_ms` | `[proxy] timeout_seconds` |
| `[waf.security_events] format` / `sled_compress` | remove (no runtime switch) |
| `[waf.security_events] store_*` / `enable_sled` | `[storage]` (legacy keys still accepted while `[storage] enabled = false`) |
| `[storage] enable_follower_reads` / `enable_compression` / `max_memory_entries` | remove (no runtime behaviour) |
| `[security.ai.model]` | remove (model selection was not wired) |
| `[security.compliance]` | remove (library-only API; no proxy runtime wiring) |
| `[waf.wasm] rules_config` | remove (the WASM engine has no rules-file input) |

The legacy `[waf.wasm]` section is still parsed on every build so shipped
configs remain loadable; it only has an effect in `wasm-waf` builds. Prefer
`[waf.coraza]` for request inspection.

## Top level

```toml
bind_addr = "0.0.0.0:8080"
health_bind_addr = "0.0.0.0:8081"
upstream_uri = "http://127.0.0.1:3000"
```

`bind_addr` is the proxy listener; `health_bind_addr` serves `/health`
(aggregate component status), `/health/ready` (readiness), `/health/live`
(process liveness) and `/metrics`. Keep the health listener private.

Readiness checks real dependencies by default and returns `503` with a
machine-readable `reason` when one is down. Set the option below only if the
process itself is all the orchestrator should probe:

```toml
[health]
# false = /health/ready is a liveness alias (no engine/store/exporter probes)
dependency_checks = true
```

## `[proxy]`

```toml
[proxy]
timeout_seconds = 30
max_request_size = 10485760
# upstream_ca_path = "/etc/waf/certs/upstream-ca.pem"
# upstream_client_cert_path = "/etc/waf/certs/client.crt"
# upstream_client_key_path = "/etc/waf/certs/client.key"
# Client routing/override headers stripped before WAF inspection and forwarding.
strip_headers = ["x-original-url", "x-rewrite-url", "x-http-method-override",
  "x-method-override", "x-forwarded-*", "forwarded", "x-host", "x-real-ip"]
strip_headers_mode = "extend"   # "extend" (default) or "replace"
reject_ambiguous_routing = false
```

The listener address and upstream URI are top-level keys (`bind_addr`,
`upstream_uri`); the old `[proxy] bind_addr` / `upstream_url` duplicates are
rejected so there is one source of truth.

- `strip_headers` removes client-controlled routing and method/path override
  headers before the WAF evaluates the request and before it is forwarded.
  Matching is case-insensitive; a trailing `*` is a prefix match, so
  `x-forwarded-*` covers every `X-Forwarded-*` header. The built-in defaults are
  `x-original-url`, `x-rewrite-url`, `x-http-method-override`,
  `x-method-override`, `x-forwarded-prefix`, `x-forwarded-host`,
  `x-forwarded-server`, `x-forwarded-port`, `x-forwarded-*`, `forwarded`,
  `x-host` and `x-real-ip`.
- `strip_headers_mode = "extend"` (default) adds configured names to the
  built-in defaults. `"replace"` uses only the configured list, which is
  explicit and therefore must include every family the deployment needs.
  Stripped headers are logged at debug level.
- `reject_ambiguous_routing = true` returns `400 Bad Request` instead of
  stripping whenever a configured routing/override header is present. Client
  identity headers (`X-Forwarded-For`, `X-Real-IP`, `X-Forwarded-Proto`) are
  exempt so trusted-proxy operation is unchanged; the proxy still rewrites
  those from the resolved client address. Default is `false` (strip and log).
- `upstream_ca_path` adds a private CA bundle for HTTPS and TLS WebSocket
  upstreams.
- Upstream mTLS requires **both** client cert and key; setting one is a startup
  error.
- `max_request_size` and `server.max_body_size` are transport caps. The
  effective request-body cap is `min(proxy.max_request_size,
  server.max_body_size)`, so the proxy key can tighten the server cap but never
  widen it. They do not change CRS inspection depth
  (`waf.coraza.max_inspect_bytes` does).
- `timeout_seconds` bounds the whole upstream exchange (connect, response
  headers and response-body collection). A timeout returns `504`.
- `keep_alive_timeout_secs` is under `[server]` and bounds idle keep-alive and
  request-head reads; see below.

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
max_header_count = 128
max_header_bytes = 65536
h3_max_connections = 1024
h3_max_concurrent_bidi_streams = 100
h3_stateless_retry = true
h3_idle_timeout_secs = 30
h3_max_inflight_requests = 256
h3_max_inflight_per_client = 0
h3_admission_timeout_ms = 250
grpc_max_stream_bytes = 4194304
grpc_max_stream_seconds = 300
grpc_max_stream_messages = 1024
grpc_max_decompressed_bytes = 10485760
grpc_streaming_policy = "reject"
grpc_aware_rejections = false
io_backend = "tokio"
```

- `max_connections` caps concurrent ingress TCP connections for the listener.
  The process runs one TCP listener, so it is effectively process-wide for
  TCP. A plaintext connection over the limit receives `503` with
  `Retry-After`; a TLS connection is closed promptly before the handshake.
  `waf_connections_active` and `waf_connections_rejected_total` expose the
  gauge and rejection counter. Must be greater than zero.
- `max_header_count` and `max_header_bytes` bound the request head before any
  body is read. Exceeding either returns a generic `431`; the count/byte
  details are logged server-side only. hyper's parser limits are configured
  above these values as a backstop, not as the primary control.
- `keep_alive_timeout_secs` bounds idle keep-alive and request-head reads. A
  connection that sends no next request within this window is closed.
- `max_body_size` is the accepted request-body size (10 MiB by default) and
  the effective cap is `min(proxy.max_request_size, server.max_body_size)`.
  Bodies above it are rejected with `413` before inspection and are never
  forwarded. The Rust engine derives its per-value inspection cap from this
  value, so every accepted body is inspectable; see
  [body inspection memory](../operations/body-inspection-memory.md) for the
  per-request memory bound. Raising this value raises the worst-case memory of
  one in-flight request, not the cost per rule.
- `h3_max_connections`, `h3_max_concurrent_bidi_streams`,
  `h3_stateless_retry` and `h3_idle_timeout_secs` apply only to HTTP/3.
  Stateless retry challenges an unvalidated QUIC peer before connection state
  is allocated; excess connections are refused and excess stream attempts fail
  closed at the transport layer.
- `trusted_proxies` is a CIDR list. All forwarding headers are ignored unless
  the immediate peer matches; an invalid CIDR aborts start-up. For a trusted
  peer the forwarding sources are considered in this order:
  `X-Forwarded-For`, `Forwarded` (`for=`), `X-Real-IP`, then `X-Client-IP`.
  Every value of the selected header family is read in wire order (repeated
  header lines and comma-separated members included), then the combined chain
  is walked right-to-left, skipping other trusted proxies, so multiple proxies
  can be listed. IPv6, `addr:port` and `[addr]:port` forms are accepted. A
  malformed, non-UTF-8, oversized (over 8 KiB) or over-long (over 32 hops)
  chain is discarded as a whole, the immediate peer is used, a warning is
  logged, and `waf_forwarded_header_rejected_total` is incremented. See
  `docs/developer-guide/request-framing-and-telemetry.md`.
- `supported_http_versions` must match the listener features: HTTP/3 requires a
  `http3` build and `enable_http3 = true`; it is feature-gated, not default.
- Unary gRPC is classified from its frame sequence, not `content-length` and
  not a timeout. Unary RPCs without `content-length` (normal over HTTP/2) are
  buffered up to `max_body_size` and inspected, even when the client delays
  `END_STREAM`.
- `grpc_streaming_policy` controls genuinely streaming RPCs: `"reject"`
  (default) refuses them with a clear 4xx / gRPC status; `"transport-only"` is
  an explicit opt-out that permits the stream but still inspects every complete
  message incrementally before forwarding. `grpc_max_stream_bytes`,
  `grpc_max_stream_seconds`, `grpc_max_stream_messages` and
  `grpc_max_decompressed_bytes` bound each exchange, and
  `waf.grpc.max_message_bytes` bounds one message. `grpc-encoding` accepts
  `identity` and `gzip`; other encodings are rejected.
- `grpc_aware_rejections = true` returns HTTP 200 with `grpc-status: 7`
  (PERMISSION_DENIED) for blocked gRPC calls instead of a plain HTTP error.
- `io_backend` is `"tokio"` (default) or `"io_uring"` (requires the
  non-default `io-uring` feature; unsupported hosts fall back to tokio with a
  warning).
- `h3_max_inflight_requests` (default `256`) bounds concurrent HTTP/3 request
  handlers. A permit is acquired before the request body is read; excess
  requests wait up to `h3_admission_timeout_ms` (default `250`) and then
  receive `503` with `Retry-After`. `h3_max_inflight_per_client` (default `0`,
  disabled) additionally caps one client IP and rejects excess requests with
  `429`. Both limits are enforced only by `http3` builds with
  `enable_http3 = true`.

### `[server.websocket]`

```toml
[server.websocket]
max_frame_bytes = 0
max_message_bytes = 0
max_concurrent_tunnels = 1024
idle_timeout_secs = 300
max_lifetime_secs = 3600
inspect_responses = false
```

- The tungstenite parser enforces these limits while reading, so an oversized
  frame or a fragmented message whose reassembled size exceeds
  `max_message_bytes` is rejected before the full message is allocated. The
  proxy closes both sides with a policy violation (`1008`).
- `0` inherits `server.max_body_size` for both values, preserving the previous
  behaviour. `max_frame_bytes` must not exceed `max_message_bytes`.
- The assembled message is still re-checked by the WAF as defence in depth.
- `max_concurrent_tunnels` is checked during the upgrade handshake, before the
  upstream connection is opened, and the permit is held for the tunnel's
  lifetime. Excess upgrades receive `503` with `Retry-After`. Must be greater
  than zero.
- `idle_timeout_secs` closes a tunnel with `1001` after this long without
  traffic in either direction; `0` disables the idle close. `max_lifetime_secs`
  closes it with `1008` regardless of activity. `idle_timeout_secs` must not
  exceed `max_lifetime_secs`; `max_lifetime_secs` must be greater than zero.
- Metrics: `waf_websocket_tunnels_active`,
  `waf_websocket_tunnels_rejected_total` and
  `waf_websocket_tunnels_closed_total{reason="idle|max_lifetime"}`.
- `inspect_responses` (default `false`) inspects upstream-to-client `Text` and
  `Binary` frames through the same WAF path and bounded message buffer as the
  request direction. Enabling it roughly doubles per-frame inspection cost on a
  busy tunnel and can reject origin frames that were previously forwarded, so
  it is opt-in. Inspection errors and blocks close both sides with `1008`.
- `Sec-WebSocket-Extensions` is always stripped on both handshake directions
  because the proxy's codec does not negotiate extensions. There is no key for
  this; forwarding it would let an origin compress frames the proxy cannot
  inspect.

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

`level` and `json_format` configure the process tracing subscriber. An explicit
`RUST_LOG` environment filter still wins over `level`.

## `[waf]`

```toml
[waf]
enabled = true
fail_mode = "closed"       # "open" forwards on inspection failure
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
min_threat_level = "medium"
enable_cef = true
cef_output_file = "./logs/security_events.cef"
cef_device_vendor = "WAF-Rejected"
cef_device_product = "Security WAF"
cef_device_version = "0.1.0-beta.16"
enable_otel = false
# otel_service_name = "waf-rejected"
# otel_export_traces = false
# otel_export_logs = false
```

This section controls event filtering and the stdout/CEF/OpenTelemetry
exporters. The persistent audit store is configured in [`[storage]`](#storage).

`enable_otel` requires a build with `--features export-otel`. The exporter
creates spans through the global OpenTelemetry tracer, so the embedding
application must install a matching `opentelemetry_sdk` 0.33 `TracerProvider`
before constructing the WAF. The SDK is intentionally not a dependency of
WAF-Rejected; with the default provider the exporter is a no-op.

### Legacy store keys

`[waf.security_events]` still accepts the pre-`[storage]` keys
(`store_backend`, `store_path`, `store_max_events`, `enable_sled`,
`sled_db_path`, `sled_max_events`) so existing files keep loading. They are
used only while `[storage] enabled = false`. Setting `[storage] enabled = true`
together with any of those keys is rejected as ambiguous; configure the store
in one place.

To move an existing sled store to redb, follow
[the migration runbook](../operations/migrating-event-store.md). Downgrading to
sled requires the reverse migration (`waf-storage-migrate --reverse`) or
restoring a pre-migration backup; the two formats are not interchangeable.

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

### `[waf.response_inspection]` — opt-in

Evaluates upstream responses with the native Rust engine's phases 3–5. Disabled
by default. Only `waf.coraza.backend = "rust"` implements response inspection;
the Coraza WASI/native backends record `waf_response_skipped_unsupported_total`
and leave responses uninspected.

```toml
[waf.response_inspection]
enabled = false
inspect_body = false
max_body_bytes = 1048576
block_status = 403
```

Enabling `inspect_body` buffers the response so the body can be inspected. The
proxy inspects at most the first `max_body_bytes` deterministically; the full
response is still relayed unless it exceeds `server.max_body_size`. A response
that is streamed under `[proxy.streaming]` is passed through without body
inspection and counted in `waf_response_skipped_streaming_total`; headers are
still inspected when `inspect_body = false`. gRPC response bodies are treated as
streaming and are not body-inspected. A block returns `block_status` with a
generic WAF body; upstream content is never echoed. Engine errors fail closed.

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
max_value_bytes = 0        # 0 = derive from server.max_body_size (default)
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
- `max_value_bytes` is the native Rust engine's per-value budget cap (`0`
  derives it from `server.max_body_size`). An explicit value smaller than
  `server.max_body_size` fails at load, naming both keys and the config file,
  because the proxy would otherwise accept a body the engine cannot inspect.
  Raise it to at least the body cap, or leave it at `0`.
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

### `[waf.distributed]` — opt-in, non-default build feature

Client for the distri-kv security fabric. Requires a build with the
non-default `distri-kv` feature. Defaults are off and `local_only`, so an
existing config and an existing build behave exactly as before. The client
implements the `waf.distri.v1.DistriWaf` contract; `LocalOnly` sources are used
when no endpoint is configured. See
[distributed operations](../operations/distributed.md).

```toml
[waf.distributed]
enabled = false                  # master switch
transport = "grpc"               # grpc (default) | quiccrunch (feature-gated)
node_id = ""                     # required when endpoints are set
region = "eu-west-1"             # required when endpoints are set
policy_scope = "default"         # GetPolicy scope
endpoints = []                   # e.g. ["https://dkv-eu.example:7443"]
fallback = "local_only"          # local_only | fail_open | fail_closed
policy_cache_ttl_secs = 300
reputation_cache_ttl_secs = 300
max_stale_secs = 900
heartbeat_interval_secs = 10
request_timeout_ms = 2000        # gRPC deadline and connect timeout
event_queue_capacity = 8192
counter_queue_capacity = 4096
reconnect_initial_backoff_ms = 100
reconnect_max_backoff_ms = 30000
shadow = true                    # observe/log derived actions, never enforce

# Only read when transport = "quiccrunch". Requires a build with the
# non-default `quiccrunch-transport` feature; all fields are required and
# there is no insecure mode.
[waf.distributed.quiccrunch]
endpoint = ""                    # e.g. "quic://dkv-eu.example:7443"
server_name = ""                 # certificate verification name / SNI
ca_cert_path = ""                # PEM CA bundle
client_cert_path = ""            # PEM client certificate
client_key_path = ""             # PEM client private key
```

`transport = "quiccrunch"` without the build feature fails at config load with
an actionable error; it never silently falls back to gRPC. See
[quiccrunch-transport](../operations/quiccrunch-transport.md). Both transports
share the same controller, caches, leases and `local_only` fallback.

`fail_open` and `fail_closed` are rejected without at least one endpoint.
Endpoints must be absolute `http(s)` URLs; `node_id` and `region` must be
non-empty once any endpoint is configured. Unknown keys are rejected. The
`fallback` setting only governs shared-data lookups; it is independent of
`waf.fail_mode`, which governs WAF engine errors.

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
# Optional per-key expiry and dual-key rotation. `api_keys` entries have no
# expiry; both forms may be combined during rotation.
# api_key_entries = [
#   { key = "old-key", expires_at = "2026-12-31T00:00:00Z" },
#   { key = "new-key" },
# ]
header_name = "X-API-Key"
require_https = false
# Optional auth-stage success limits:
# [security.auth.rate_limit]
# requests_per_minute = 60      # per API key
# per_ip_enabled = true
# per_ip_max_requests = 100
# per_ip_window_secs = 60
# global_enabled = true
# global_max_requests = 1000
# global_window_secs = 60
# Optional pre-validation failure budget (brute-force lockout). Disabled by
# default; when enabled, failed keys consume the budget and a correct key from
# a locked-out source is still rejected until the lockout expires.
# [security.auth.failure_limit]
# enabled = true
# max_failures = 10
# window_secs = 60
# lockout_secs = 300
```

Enabling auth with no `api_keys` and no `api_key_entries` aborts start-up.
Prefer injecting keys from a secret. `expires_at` must be RFC 3339; an expired
key is rejected with `401`. No presented key is logged.

```toml
[security.ai]
enabled = false
threat_threshold = 0.8
timeout_ms = 5000
```

The AI/threat-intelligence modules are experimental and not on the request path
by default.

`[security.compliance]` was parsed but never connected to the proxy. The
compliance managers remain a feature-gated library API (`compliance` /
`enterprise-proto` builds) constructed with `AuditConfig`, `RegulatoryConfig`
and `RetentionConfig` directly; there are no TOML keys for them. Compliance
outputs are evidence packs, not certifications. See
[`eu-regulatory-status.md`](../compliance/eu-regulatory-status.md).

## `[storage]`

The single place that selects and configures the persistent audit-trail store.

```toml
[storage]
# false (default) = no persistent store. Legacy [waf.security_events] store
# keys still work while this is false.
enabled = true
backend = "redb"                       # "redb" (default) or "sled" (legacy)
path = "./data/waf_security_events.redb"
max_events = 100000                    # omit to keep every event
ttl_cleanup_interval = { secs = 60, nanos = 0 }  # 0 = cleanup every write
cache_size = 16777216                  # redb page cache; omit for default
```

| Key | Behaviour |
|---|---|
| `enabled` | Opens the store at start-up. The default (`false`) preserves the historical no-store behaviour. |
| `backend` | `redb` writes with `Durability::Immediate` (one fsync per committed transaction). `sled` is the legacy directory store and flushes after every write. Unknown values are rejected at startup. |
| `path` | Single redb file or sled directory. The container image uses `/var/lib/waf/data`; mount it read-write. |
| `max_events` | Retention cap; the oldest events are deleted first. |
| `ttl_cleanup_interval` | Minimum time between retention passes. `0` (the default) runs the pass after every write. Audit events do not expire by age, so this is a cleanup schedule, not a per-event TTL. |
| `cache_size` | redb page cache in bytes. Ignored by sled. |

The `[storage]` section used to declare `enable_follower_reads`,
`enable_compression` and `max_memory_entries`. Those keys never had a runtime
effect in this deployment (there are no follower reads, the event exporters do
not compress, and the runtime has no memory-backed audit store), so they are
rejected now. Unknown or removed keys are hard errors naming the file and key.

See [migrating the event store](../operations/migrating-event-store.md).

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
about 1.1 ms and 1.6 ms on the reference host. Response inspection is opt-in
(`waf.response_inspection.enabled = true`) and wired for the native Rust
engine, and Hyperscan/io_uring/allow-cache/fast-allow are opt-in. See
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
