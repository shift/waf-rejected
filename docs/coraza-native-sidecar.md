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

## Deployment

The sidecar is foreground-only, logs to stderr and owns no persistent state.
The only shared resource is the Unix socket. Deploy it on the same host (or in
the same pod) as the proxy; it must never listen on TCP.

### systemd

A hardened unit is provided at `deploy/systemd/coraza-sidecar.service`:

```ini
[Unit]
Description=WAF-Rejected native Coraza sidecar
After=network.target
Before=waf-ingress.service
PartOf=waf-ingress.service

[Service]
Type=simple
User=waf
Group=waf
RuntimeDirectory=waf
RuntimeDirectoryMode=0750
UMask=0077
ExecStart=/usr/local/bin/coraza-sidecar \
  --socket /run/waf/coraza.sock \
  --rules /usr/share/waf/coraza/crs/crs.conf \
  --max-body 65536 --max-headers 100 --max-header-bytes 65536 \
  --timeout 5s --grace 10s
Restart=on-failure
RestartSec=2s
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_UNIX
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallFilter=@system-service
CapabilityBoundingSet=
ReadOnlyPaths=/usr/share/waf/coraza
LimitNOFILE=8192
MemoryMax=512M

[Install]
WantedBy=multi-user.target
```

`RuntimeDirectory=waf` creates `/run/waf` owned by `waf:waf` with mode `0750`.
The sidecar chmods the socket to `0660`, so the proxy process must run as the
same user or in the same group. Do not widen the socket to `0666`: filesystem
access is the only authentication on this boundary.

### Container

`deploy/container/Dockerfile.coraza-sidecar` builds a multi-stage image from
the repository root. The runtime stage is distroless, runs as `nonroot`, and
contains only the binary plus the read-only CRS bundle:

```sh
docker build -f deploy/container/Dockerfile.coraza-sidecar -t waf-coraza-sidecar .
```

Mount a writable directory at `/run/waf` for the socket and keep the rules
read-only. The image has no shell, so health is observed through the proxy's
`/metrics` and the sidecar's stderr logs.

### Compose example

`deploy/compose/coraza-native.yaml` runs the proxy, sidecar and a mock upstream
on a shared socket volume:

```sh
docker compose -f deploy/compose/coraza-native.yaml up --build
```

The example runs both containers as uid `1000` so the `0660` socket is usable
by both, makes the sidecar filesystem read-only, drops all capabilities and
uses `no-new-privileges`. `deploy/compose/config.native.toml` selects
`backend = "native"` and points at `/run/waf/coraza.sock`.

### Socket permissions

| Path | Owner | Mode | Notes |
|---|---|---|---|
| `/run/waf` | `waf:waf` | `0750` | systemd `RuntimeDirectory` |
| `/run/waf/coraza.sock` | `waf:waf` | `0660` | set by the sidecar after bind |
| `/usr/share/waf/coraza` | root | `0755` | rules, read-only |

The proxy and sidecar must share a uid or gid. In containers, set the same
numeric uid on both services or use a shared group.

### Upgrade and restart behaviour

- **Sidecar restart:** the proxy keeps running. The client retries once on a
  fresh connection; requests during the gap fail closed (`503`) when
  `fail_mode = "closed"` and are allowed when `fail_mode = "open"`. The next
  request after the socket returns succeeds without restarting the proxy.
- **Proxy restart:** start the sidecar first. `WafProxyService::new` performs a
  preflight connect and aborts start-up if the socket is unavailable, so a
  missing sidecar cannot silently degrade to per-request 503s.
- **Rules upgrade:** replace the CRS bundle and restart the sidecar. The
  sidecar loads rules once at start-up; there is no hot reload. Keep the proxy
  and sidecar on the same CRS version so wasm/native decisions stay comparable.
- **Graceful shutdown:** `SIGTERM` stops accepting, closes idle pooled
  connections and drains in-flight requests for `--grace` (default 10 s).
  systemd's `TimeoutStopSec` should exceed `--grace`.

### Capacity guidance

- One sidecar transaction is CPU-bound CRS scanning. Size `pool_size` to the
  number of proxy worker threads that may evaluate concurrently, capped at 8
  by configuration validation.
- Budget roughly 7–8 µs of sidecar CPU per inspected body byte on the
  reference machine (about 0.45 s for 60 KiB). Keep `max_body_size` and
  `waf.coraza.max_payload_bytes` aligned; the sidecar's `--max-body` must be at
  least the decoded body size the proxy can send.
- `--timeout` is the sidecar's own observation budget; `eval_timeout_ms` is the
  client deadline. Set the client deadline slightly above the sidecar budget
  so the sidecar can report a decision first. The client deadline is enforced
  by closing the socket, which releases the connection and lets the sidecar
  goroutine exit after its current Coraza call returns.
- Leave headroom for GC: the sidecar sets `GOGC=600` and a 192 MiB soft memory
  limit. `MemoryMax=512M` in the unit bounds the process; a 60 KiB request
  needs roughly 8–12 MiB of transient allocation.
- Run at least two sidecar replicas behind separate sockets only if the proxy
  supports multiple sockets; the current client uses one socket and a bounded
  pool, so scale vertically first.

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

### Through the proxy (end-to-end)

`examples/coraza_proxy_bench.rs` measures a full HTTP request through
`WafProxyService` (client → proxy → WAF → mock upstream → client), including
proxy framing, body buffering and the built-in rule chain. Same machine and
release build, sequential requests, warmed proxies. Run on 2026-11-02.

| case | wasm p50 | wasm p95 | native p50 | native p95 | p50 speed-up |
|---|---:|---:|---:|---:|---:|
| 1 KiB form | 38.77 | 39.77 | 7.62 | 7.79 | 5.1× |
| 4 KiB form | 163.56 | 168.10 | 27.81 | 28.24 | 5.9× |
| 8 KiB form | 340.98 | 341.75 | 56.51 | 57.22 | 6.0× |
| 16 KiB form | 700.06 | 711.05 | 113.11 | 113.97 | 6.2× |
| 60 KiB form | 2617.24 | 2626.29 | 421.56 | 423.07 | 6.2× |
| gRPC 1 KiB | 3.06 | 3.40 | 1.05 | 1.41 | 2.9× |

The proxy adds a small constant overhead to both backends; the wasm/native
ratio is unchanged from the direct-rule benchmark. gRPC is cheaper because the
1 KiB payload is a single framed message and the proxy does not buffer a
streaming body.

## Tests

- Go: `native/coraza-sidecar/main_test.go` — decision parity for benign, SQLi
  (body and URI), XSS (body and URI), path traversal (URI and body), plus
  malformed JSON/base64/encoding/size mismatch, oversized body and too many
  headers. `body_b64` alias covered. `TestConnectionCleanup` opens and closes
  50 connections and asserts the handler goroutines and connection map drain.
- Rust (`src/waf/native_coraza.rs`): allow/block mapping, malformed response,
  timeout, reconnect/retry after a closed pooled connection, missing socket
  start-up error, payload limit, client-deadline socket close, and Coraza
  metrics parity (evaluations/blocks/errors/duration).
- End-to-end (`tests/integration/native_coraza_tests.rs`, ignored by default):
  starts the real sidecar and two real proxies (native and wasm), verifies
  benign allow, SQLi/XSS/path-traversal blocks, gRPC allow, native/wasm
  decision parity, metrics counters, fail-closed `503` after the sidecar is
  killed, fail-open allow, and recovery after restart. Run with
  `CORAZA_SIDECAR_BIN=... cargo test --test integration --features
  wasm-reactor,coraza-native native_coraza -- --ignored`.
- Existing `WasmReactorRule` tests still pass; the shared payload builder is
  tested by both feature sets.

## Limitations

- **IPC boundary.** One extra process to deploy, monitor and secure. Unix
  socket permissions are the trust boundary; there is no authentication beyond
  filesystem access. The sidecar must not be exposed on TCP.
- **Process isolation is coarser than wasmtime.** Memory/fuel limits are
  replaced by Go GC settings, `--max-body`/header limits and a wall-clock
  observation deadline. Coraza has no cancellation API, so an in-flight
  evaluation cannot be cancelled inside the sidecar. The client enforces
  `eval_timeout_ms` by closing the socket and returning a fail-closed decision;
  the sidecar goroutine exits after its current Coraza call returns. The
  sidecar must therefore bound its own work with `--timeout`, `--max-body` and
  header limits. A production version should add a hard per-request
  context/cancellation or a supervised worker pool.
- **Two configurations.** The sidecar's `--max-body` must be at least the WAF's
  `max_payload_bytes` minus JSON overhead; the default 64 KiB body limit matches
  the reactor's payload cap. Validate this at deployment time.
- **Restart window.** WAF start-up requires a live socket. A sidecar restart
  causes brief fail-closed `503`s until reconnect.
- **Not measured here:** no-body/header-only latency, sustained soak under GC,
  multi-core scaling, or cross-host deployment (Unix socket is local only).
- **Not production-wired as a default.** The real-process end-to-end test is
  ignored by default because it needs the separately built sidecar binary; CI
  must opt in with `CORAZA_SIDECAR_BIN` or `nix build .#coraza-native-sidecar`.
