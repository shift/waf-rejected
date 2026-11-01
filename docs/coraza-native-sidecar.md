# Native Coraza sidecar (experimental)

**Status:** prototype, non-default backend. `wasm-reactor` remains the default
and `waf.coraza.enabled` / existing wasm behaviour are unchanged.
**Feature:** `coraza-native` (not in `default`).
**Branch:** `feat/native-coraza-sidecar`.
**Related research:** `docs/suggestions_from_agents/coraza-body-performance.md`.

## Why

The research report attributes 69 % of wasm body-inspection latency to the
Go-compiled-to-wasm execution penalty: a constant ~5.2× on top of native Go for
CRS operator scanning. Moving Coraza out of wasm removes that dominant cost
without reducing inspection depth or the inspected body size.

This prototype runs the **same vendored Coraza 3.3.3 and OWASP CRS 4.14.0
bundle** used by the WASI reactor as a native Go process and talks to it over a
Unix domain socket. The request envelope is the same JSON payload as the wasm
ABI, so decisions and configuration can be compared directly.

## Architecture

```
proxy process (Rust)                              sidecar process (Go)
┌─────────────────────────────┐                  ┌──────────────────────────────┐
│ WafEngine                    │                  │ coraza-sidecar               │
│  └ NativeCorazaRule          │                  │  ├ coraza.WAF (CRS)          │
│     ├ JSON payload builder   │  Unix socket     │  ├ one NewTransaction/request│
│     ├ bounded connection pool├─────────────────▶│  ├ ProcessURI/Headers/Body   │
│     └ dedicated Tokio thread │  4-byte BE len   │  └ allow/block + status      │
└─────────────────────────────┘  + JSON frames   └──────────────────────────────┘
```

- **Rules are not duplicated.** `native/coraza-sidecar/go.mod` uses the same
  dependency versions; `vendor/` is a symlink to
  `wasm/coraza_reactor/vendor`; the sidecar loads
  `wasm/coraza_reactor/rules/crs/crs.conf` (or `--rules <path>`).
- **Framing:** each direction is a 4-byte big-endian length followed by a JSON
  payload. Request fields mirror the host ABI: `method`, `uri`,
  `http_version`, `headers`, `body_size`, `body` + `body_encoding` (or
  `body_b64`). Response: `{"decision":"allow|block","status":403,"reason":"…"}`.
- **Limits:** `--max-body`, `--max-headers`, `--max-header-bytes`, `--timeout`
  and `--grace` are enforced in the sidecar. The client enforces
  `waf.coraza.max_payload_bytes`, `waf.coraza.eval_timeout_ms` and the bounded
  pool. Malformed/oversized payloads are blocked (`400`/`413`), never allowed.
- **No proxy-worker blocking:** `WafRule::evaluate` is synchronous, so the
  client hands jobs to a dedicated multi-thread Tokio runtime. All socket I/O,
  connect retries and timeouts happen there; the proxy's async workers only
  wait on a bounded channel with a timeout.

## Configuration

Default (unchanged):

```toml
[waf.coraza]
enabled = true
backend = "wasm"          # default
# module_path = "/usr/share/waf/wasm/coraza_reactor.wasm"
```

Native backend:

```toml
[waf.coraza]
enabled = true
backend = "native"
native_socket_path = "/run/waf/coraza.sock"
max_payload_bytes = 65536  # JSON envelope cap
eval_timeout_ms = 5000     # client budget per request
pool_size = 0              # 0 = 8 connections for the native backend
```

Validation rejects `backend = "native"` without a non-empty
`native_socket_path`. If the socket is not accepting connections at start-up,
the WAF aborts with a clear `Coraza native sidecar failed to initialise:
native Coraza sidecar socket ... is unavailable` error (fail-closed). At
request time, queue-full, timeout, protocol and I/O errors map to `503` when
fail mode is closed and are logged/allowed when fail mode is open, matching
`WasmReactorRule`.

## Build and run

Nix shell provides Go; the development shell exports `GOOS=js GOARCH=wasm` for
the reactor, so the sidecar must be built explicitly for the host.

```sh
nix develop -c just build-coraza-sidecar
nix develop -c just test-coraza-sidecar

# terminal 1
./target/native/coraza-sidecar \
  --socket /tmp/coraza-native.sock \
  --rules wasm/coraza_reactor/rules/crs/crs.conf \
  --max-body 65536 --timeout 5s

# terminal 2 (WAF built with the feature)
nix develop -c cargo run --release --features coraza-native -- \
  # ... with config.toml containing backend = "native"
```

A Nix package is available as `nix build .#coraza-native-sidecar`; it installs
the binary to `$out/bin/coraza-sidecar` and the ruleset to
`$out/share/waf/coraza/crs/`.

### systemd

The sidecar is foreground-only and logs to stderr.

```ini
[Unit]
Description=WAF-Rejected native Coraza sidecar
After=network.target

[Service]
ExecStart=/usr/local/bin/coraza-sidecar \
  --socket /run/waf/coraza.sock \
  --rules /usr/share/waf/coraza/crs/crs.conf \
  --max-body 65536 --timeout 5s
RuntimeDirectory=waf
Restart=on-failure
RestartSec=2
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

`RuntimeDirectory=waf` creates `/run/waf`; the socket is chmod `0660`, so the
WAF user must share the service group. The client reconnects after a sidecar
restart; the first request during the restart window fails closed (`503`).

## Measured numbers

Machine: Intel i5-8400T (6 cores, 1.7/3.3 GHz), Linux, release builds, pinned to
one core (`taskset -c 2`), warmed engines, same method as the research report
(whole `WafRule::evaluate` call: payload build + backend round trip). Run on
2026-11-01. Values are p50, ms.

| body | wasm p50 | native p50 | speed-up |
|---|---:|---:|---:|
| 1 KiB form | 41.07 | 7.89 | 5.2× |
| 4 KiB form | 172.54 | 29.76 | 5.8× |
| 8 KiB form | 357.95 | 61.23 | 5.8× |
| 16 KiB form | 744.46 | 122.01 | 6.1× |
| 60 KiB form | 2778.99 | 457.12 | 6.1× |
| SQLi (44 B body) | 5.29 | 1.21 | 4.4× |
| XSS (56 B body) | 5.81 | 1.34 | 4.3× |

Throughput, 4 KiB benign form body, one core:

| backend | 1 connection | 4 concurrent |
|---|---:|---:|
| wasm | 5.8 req/s | 5.7 req/s |
| native | 33.7 req/s | 46.2 req/s |

Repeat run gave the same p50 profile (8 KiB: 357.6 / 60.1 ms; 60 KiB:
2876 / 450 ms), with native throughput 29.1–61.7 req/s depending on scheduler
noise.

**Interpretation:** the native backend removes the 5–6× wasm tax. The residual
native cost is still ~7.5 µs per inspected body byte (61 ms at 8 KiB), i.e. the
CRS operator scanning itself, not IPC. A 60 KiB request still occupies a
sidecar transaction for ~0.45 s; body-size caps and per-request timeouts remain
necessary. This confirms the research report's recommendation F3: wasm was the
dominant removable cost, but the rule set is intrinsically expensive.

## Tests

- Go: `native/coraza-sidecar/main_test.go` — decision parity for benign, SQLi
  (body and URI), XSS (body and URI), path traversal (URI and body), plus
  malformed JSON/base64/encoding/size mismatch, oversized body and too many
  headers. `body_b64` alias covered.
- Rust (`src/waf/native_coraza.rs`): allow/block mapping, malformed response,
  timeout, reconnect/retry after a closed pooled connection, missing socket
  start-up error and payload limit.
- Existing `WasmReactorRule` tests still pass; the shared payload builder is
  tested by both feature sets.

## Limitations

- **IPC boundary.** One extra process to deploy, monitor and secure. Unix
  socket permissions are the trust boundary; there is no authentication beyond
  filesystem access. The sidecar must not be exposed on TCP.
- **Process isolation is coarser than wasmtime.** Memory/fuel limits are
  replaced by Go GC settings, `--max-body`/header limits and a wall-clock
  observation deadline. Coraza has no cancellation API, so a request that
  exceeds `--timeout` is logged but the goroutine still finishes; the client
  times out independently and fails closed. A production version should add a
  hard per-request context/cancellation or a supervised worker pool.
- **Two configurations.** The sidecar's `--max-body` must be at least the WAF's
  `max_payload_bytes` minus JSON overhead; the default 64 KiB body limit matches
  the reactor's payload cap. Validate this at deployment time.
- **Restart window.** WAF start-up requires a live socket. A sidecar restart
  causes brief fail-closed `503`s until reconnect.
- **Not measured here:** no-body/header-only latency, sustained soak under GC,
  multi-core scaling, or cross-host deployment (Unix socket is local only).
- **Not production-wired as a default.** The benchmark/client is exercised by
  the feature and unit tests, but no long-running proxy integration test starts
  the real sidecar; that remains for production hardening.
