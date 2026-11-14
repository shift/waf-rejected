# TLS and connection fast path

**Status:** implemented behind opt-in config, **defaults unchanged**.
**Branch:** `perf/tls-fastpath`, based on `main` @ `efb56b5`.
**Scope:** TLS handshake, session resumption, ALPN, socket tuning, and HTTP/2
settings. The WAF engine is disabled for every measurement so the numbers
isolate transport cost.

## TL;DR

On loopback with the WAF disabled, a reused HTTP/2 connection costs
**0.28 ms p50 / 3.46 ms p99** per request, a reused HTTP/1.1 keep-alive
connection **1.95 ms p50 / 9.32 ms p99**, and a fresh TLS connection
(handshake + request) **7.92 ms p50 / 13.03 ms p99**. Raw handshake
throughput is ~1.4k new connections/s and ~1.1k resumed connections/s on the
benchmark host. The proxy process used 10–60 ms of CPU for 50 requests,
depending on scenario.

The wins are opt-in: `session_resumption`, `tcp_nodelay`, and the keep-alive
fields default to their previous values, so existing deployments behave
exactly as before.

## 1. Measurement

`scripts/bench-tls.sh` starts a loopback keep-alive backend, starts
`waf-ingress` with TLS enabled and `waf.enabled = false`, then measures:

| Scenario | p50 | p99 | CPU (50 req) |
| --- | ---: | ---: | ---: |
| Fresh TLS connection + request | 7.92 ms | 13.03 ms | 60 ms |
| HTTP/2 reused connection | 0.28 ms | 3.46 ms | 10 ms |
| HTTP/1.1 keep-alive | 1.95 ms | 9.32 ms | 10 ms |

Raw handshake throughput (`openssl s_time`, 5 s):

| Handshake | Connections | Connections/s |
| --- | ---: | ---: |
| Full | 1986 | 1471 |
| Resumed | 1904 | 1133 |

Notes:

* The fresh-connection row includes TCP connect, TLS handshake, request, and
  response, so it is not directly comparable to the reused rows.
* The loopback backend is a small `socat` keep-alive responder; it is not a
  production upstream. Treat the absolute numbers as a relative baseline.
* `openssl s_time` does not send ALPN, so the handshake rows measure the TLS
  layer only.
* Run with `nix develop -c ./scripts/bench-tls.sh --requests 200`. The script
  builds the release binary unless `--skip-build` is passed.

## 2. Wins implemented

All new fields live under `[server.tls]` and are `serde(default)`, so old
config files keep working.

```toml
[server.tls]
enabled = true
# ... existing cert/key/version/ALPN fields ...

# Opt-in fast path (defaults shown).
session_resumption = false      # TLS 1.2 session cache + TLS 1.3 tickets
session_cache_size = 256        # cached TLS 1.2 sessions
tls13_tickets = 2               # tickets per connection (0 disables)
tcp_nodelay = false             # remove Nagle latency on accepted TLS sockets
tcp_keepalive_secs = 0          # 0 = OS default
tcp_keepalive_interval_secs = 0 # 0 = OS default
tcp_fast_open = false           # best effort; see blockers
```

* **Session resumption.** When `session_resumption = true`,
  `TlsManager::new` installs a `ServerSessionMemoryCache` and a ring
  `Ticketer`, and sets `send_tls13_tickets`. TLS 1.2 uses the stateful cache;
  TLS 1.3 uses stateless tickets. When disabled, rustls' previous defaults are
  left untouched.
* **ALPN correctness.** The configured list is deduplicated while preserving
  server preference order. Config validation rejects empty/over-long tokens,
  duplicate entries, and advertising `h2` while `server.enable_http2 = false`
  (which would negotiate h2 and then serve it with the HTTP/1.1 builder).
* **TCP tuning.** `TlsManager::accept` applies `TCP_NODELAY` and
  `TCP_KEEPALIVE` (idle + interval via `socket2`) to the accepted socket
  before the handshake. Failures are logged at debug level and never fail the
  connection.
* **Certificate/key loading.** Certificates and keys are parsed once in
  `TlsManager::new`; the resulting `Arc<ServerConfig>` is shared by every
  connection. No per-connection file I/O or key parsing is performed.
* **TCP Fast Open.** The config flag and `TlsManager::tcp_fast_open()` accessor
  are in place, but the listener is owned by `src/proxy/service.rs`, which is
  out of scope for this change. See blockers.

## 3. HTTP/2 settings evaluation

The HTTP/2 builder lives in `src/proxy/service.rs` (owned by another agent), so
this change does not alter it. Recommended values for a WAF ingress:

| Setting | Current | Recommendation | Why |
| --- | --- | --- | --- |
| `initial_window_size` | hyper default (64 KiB) | 1 MiB | WAF bodies are often 10 KiB–1 MiB; a larger stream window avoids a round trip per window update on high-BDP links. |
| `initial_connection_window_size` | hyper default | 4 MiB | Keeps many concurrent streams from serialising on the connection window. |
| `max_concurrent_streams` | hyper default | 128–256 | Matches typical browser/grpc client fan-out without unbounded per-stream memory. |
| `keep_alive_interval` | 30 s | 30 s | Already reasonable; lower values add PING traffic, higher values delay dead-peer detection. |
| `keep_alive_timeout` | 10 s | 10 s | Keep. |
| `max_frame_size` | 16 KiB | 16 KiB | Leave at the protocol default; larger frames increase head-of-line blocking. |

These are recommendations only; wiring them requires a follow-up in
`src/proxy/service.rs`.

## 4. Tests

* `waf::tls_config::tests::session_resumption_is_off_by_default`
* `waf::tls_config::tests::session_resumption_enables_cache_and_tickets`
* `waf::tls_config::tests::alpn_is_deduplicated_and_preserves_server_order`
* `waf::tls_config::tests::alpn_defaults_advertise_h2_then_http1`
* `config::tests::tls_alpn_validation_rejects_duplicates_and_invalid_tokens`
* `config::tests::tls_alpn_validation_rejects_h2_when_http2_disabled`
* `config::tests::tls_tuning_validation_bounds_ticket_count`

Existing HTTP/1.1, HTTP/2, WebSocket, and mTLS integration tests are unchanged
and continue to exercise the default (resumption-off) path.

## 5. Blockers / follow-ups

* **TCP Fast Open listener wiring** needs `src/proxy/service.rs` (out of
  scope). The flag and accessor are ready; the listener must call
  `setsockopt(TCP_FASTOPEN)` before `listen()`.
* **HTTP/2 builder tuning** also needs `src/proxy/service.rs`; the table above
  is the recommended configuration.
* **Release build disk pressure.** The host root filesystem was full, so the
  release build required `TMPDIR` on the data volume:
  `nix develop -c env TMPDIR=$PWD/target/tmp cargo build --release --bin waf-ingress`.
* **Pre-existing flaky test.**
  `waf::wasm_reactor::tests::evaluation_timeout_discards_instance_and_next_evaluation_recovers`
  failed once under full-suite load and passed in isolation; it is unrelated
  to this change.
