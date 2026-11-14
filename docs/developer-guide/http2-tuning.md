# HTTP/2 and upstream connection tuning

These controls are **opt-in**. With every block disabled the proxy keeps its
previous behaviour: hyper's default HTTP/2 flow-control windows, the hard-coded
30 s / 10 s ingress keep-alive policy, unbounded idle reuse in the hyper pool,
and full buffering of upstream responses.

## Upstream connection pool

```toml
[proxy.pool]
enabled = true
max_idle_per_host = 32
idle_timeout_secs = 90
health_check_interval_secs = 0   # 0 disables the probe
health_check_path = "/healthz"
```

When enabled:

- `max_idle_per_host` bounds idle connections kept per upstream authority.
- `idle_timeout_secs` evicts connections that have been idle longer than the
  limit instead of reusing a stale socket.
- `health_check_interval_secs > 0` starts an out-of-band `GET` probe on
  `health_check_path` (5 s timeout). Probe results are counted; failures are
  logged and never fail client requests.

Reuse is observable through Prometheus:

```
waf_upstream_requests_total
waf_upstream_connections_total
waf_upstream_health_checks_total
waf_upstream_health_check_failures_total
```

`1 - connections / requests` is the pool reuse ratio.

## HTTP/2 flow control, multiplexing and keep-alive

```toml
[server.http2]
enabled = true
initial_stream_window_bytes = 1048576       # 1 MiB per stream
initial_connection_window_bytes = 16777216  # 16 MiB per connection
max_concurrent_streams = 256
max_pending_accept_reset_streams = 1024
keep_alive_interval_secs = 30               # 0 disables PING keep-alive
keep_alive_timeout_secs = 10
keep_alive_while_idle = false
adaptive_window = false
```

The block applies to both ingress HTTP/2 connections and upstream HTTP/2
client connections. `max_concurrent_streams` bounds how many requests one
ingress connection can pin to the reactor pool; excess streams are queued by
the h2 stack rather than spawning unbounded work. `max_pending_accept_reset_streams`
bounds the pending reset-stream queue.

`adaptive_window = true` lets the h2 stack grow the windows itself and
overrides the two explicit window values.

## Response streaming

```toml
[proxy.streaming]
enabled = true
response_threshold_bytes = 1048576
```

When enabled, an upstream response that advertises a `content-length` at or
above the threshold is relayed frame by frame instead of being collected in
memory first. The response still passes through the same `max_body_size` byte
cap and a 30 s deadline, and trailing headers are preserved. Responses without
a `content-length`, and responses below the threshold, use the buffered path.

Response bodies are not WAF-inspected in either mode; request bodies are still
fully inspected before forwarding. Streaming gRPC is rejected by default and,
when explicitly set to `transport-only`, is inspected per message before each
frame is forwarded.

## Benchmark

`benches/http2_tuning.rs` drives real TLS ingress traffic into a keep-alive
upstream and reports throughput, p50/p95/p99 and the upstream reuse ratio for
bodyless, 1 KiB and 8 KiB responses at concurrency 1, 16 and 64:

```sh
cargo bench --bench http2_tuning -- --baseline
cargo bench --bench http2_tuning -- --tuned
```

The tuned run enables the pool, 1 MiB/16 MiB h2 windows, 256 concurrent
streams and response streaming above 4 KiB. Results are workload- and
host-dependent; the checked-in harness exists so the comparison is
reproducible rather than aspirational.
