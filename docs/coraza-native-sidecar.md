# Native Coraza sidecar

**Status:** supported, opt-in backend. The default request-inspection backend is
the native Rust CRS engine (`waf.coraza.backend = "rust"`); the Coraza WASI
reactor remains the reference implementation and explicit switch-back
(`backend = "wasm"`). `waf.coraza.enabled` / existing wasm behaviour are
unchanged. For the curated, tested high-throughput deployment (Compose,
Kubernetes, measured capacity and operational requirements), see
[`docs/operations/native-performance-profile.md`](operations/native-performance-profile.md).
**Feature:** `coraza-native` (not in `default`).
**Wire protocol:** binary v1 with a negotiated JSON fallback (see
[Architecture](#architecture)).
**Related research:** `docs/design/coraza-body-performance.md`.

## Why

The research report attributes 69 % of wasm body-inspection latency to the
Go-compiled-to-wasm execution penalty: a constant ~5.2× on top of native Go for
CRS operator scanning. Moving Coraza out of wasm removes that dominant cost
without reducing inspection depth or the inspected body size.

This backend runs the **same vendored Coraza 3.8.1 and OWASP CRS 4.14.0
bundle** used by the WASI reactor as a native Go process and talks to it over a
Unix domain socket. The request envelope is the same JSON payload as the wasm
ABI, so decisions and configuration can be compared directly.

## Architecture

```
proxy process (Rust)                              sidecar process (Go)
┌─────────────────────────────┐                  ┌──────────────────────────────┐
│ WafEngine                    │                  │ coraza-sidecar               │
│  └ NativeCorazaRule          │                  │  ├ coraza.WAF (CRS)          │
│     └ NativeCorazaClient     │  Unix socket     │  ├ one NewTransaction/request│
│        ├ binary v1 encoder   │─────────────────▶│  ├ ProcessURI/Headers/Body   │
│        └ bounded sync pool   │  4-byte BE len   │  ├ bounded conn admission    │
└─────────────────────────────┘  + frame         └──────────────────────────────┘
```

- **Rules are not duplicated.** `native/coraza-sidecar/go.mod` uses the same
  dependency versions; `vendor/` is a symlink to
  `wasm/coraza_reactor/vendor`; the sidecar loads
  `wasm/coraza_reactor/rules/crs/crs.conf` (or `--rules <path>`).
- **Framing:** each direction is a 4-byte big-endian length followed by a
  payload. The first payload byte selects the encoding:
  `{` = legacy JSON envelope, `0xC2` = binary v1, `0xC1` = handshake.
  Binary v1 is a fixed 28-byte request header (flags, method/URI/version
  lengths, header count, body length, declared and original body size, header
  block length), the request line, the header block (`u16 name len`, `u16 value
  len`, bytes per header) and the **raw body bytes** — no JSON escaping and no
  base64. Responses are an 8-byte header (decision, status, reason length) plus
  the reason, so the allow path is 8 bytes. The JSON envelope is unchanged and
  still accepted, which is what the WASI reactor uses.
- **Negotiation:** a new client sends a handshake frame when it opens a
  connection. A sidecar that understands binary v1 answers with an ack; a
  legacy sidecar answers with a JSON `400` block, which the client reads as
  "JSON only" and remembers for the process lifetime. New client + old sidecar
  and old client + new sidecar both work.
- **No per-request copies:** the client builds the frame head into a fresh
  `Vec`, keeps the body as refcounted `Bytes` and writes head + body with a
  single `writev`; the server reads into a per-connection buffer and hands
  Coraza a sub-slice of the frame. The allow response allocates nothing on
  either side.
- **Limits:** `--max-body`, `--max-headers`, `--max-header-bytes`, `--timeout`,
  `--max-conns`, `--early-blocking` and `--grace` are enforced in the sidecar.
  The client enforces `waf.coraza.max_payload_bytes`,
  `waf.coraza.eval_timeout_ms` and the bounded pool. Malformed/oversized
  payloads are blocked (`400`/`413`), never allowed.
- **Blocking is contained:** `WafRule::evaluate` is synchronous, so the client
  checks a connection out of a bounded pool, writes the frame, reads the
  decision and returns it. Socket send/receive timeouts plus a post-read
  deadline check enforce `eval_timeout_ms`; a connection that times out or
  errors is dropped, never reused. A caller that finds the pool exhausted waits
  on a condvar until a connection is returned or its deadline expires, instead
  of failing fast.

## Configuration

Default build (native Rust engine):

```toml
[waf.coraza]
enabled = true
# backend = "rust"        # compiled default in default builds
# module_path = "/usr/share/waf/wasm/coraza_reactor.wasm"
```

Reference wasm switch-back:

```toml
[waf.coraza]
enabled = true
backend = "wasm"
```

Native backend:

```toml
[waf.coraza]
enabled = true
backend = "native"
native_socket_path = "/run/waf/coraza.sock"
max_payload_bytes = 65536  # cap on the inspected body per request
eval_timeout_ms = 5000     # client budget per request
pool_size = 0              # 0 = 8 connections for the native backend
prefilter = "off"          # "off" | "dry-run" | "gated" (requires crs-prefilter)
```

### Per-rule CRS gating

With `prefilter = "gated"` the host removes the gated CRS rules whose proven
mandatory literals are absent from the request (URI, query, headers, cookies,
body) and sends the bounded list (`<= 256` ids) in the request payload. The
sidecar applies `tx.RemoveRuleByID` before `ProcessURI`, so the rules never
evaluate; the removal is per transaction and never mutates the shared WAF.
Ungated rules always run.

The sidecar validates the list against `prefilter.json` before applying it.
By default it reads `prefilter.json` next to `--rules`; override with
`--prefilter <path>`. If the artifact is missing or invalid the sidecar logs a
warning and disables removals, which is slower but always sound. The JSON
envelope carries `remove_rule_ids`; binary v1 carries an optional ids section
negotiated through the handshake capability bits, so an older client or
sidecar simply evaluates every rule.

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
`$out/share/waf/coraza/crs/`. The release tarball also contains the binary and
rules under `native/`, and a standalone sidecar tarball is published.

For container and Kubernetes probes, the sidecar has a probe mode that works
in the distroless image (no shell required):

```sh
coraza-sidecar --probe --socket /run/waf/coraza.sock   # exit 0 when ready
```

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
  --max-conns 128 --timeout 5s --grace 10s
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
  Protocol negotiation is re-run on the first new connection after a restart.
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

See [Capacity and deployment shape](#capacity-and-deployment-shape) under [Performance](#performance)
for the measured per-byte cost, pool sizing and the recommended deployment
shape.

## Performance

All numbers below are from the reference machine (Intel i5-8400T, 6 cores,
1.7/3.3 GHz), release builds, warmed engines, CRS 4.14.0, run on 2026-11-02.
The machine is shared, so treat absolute values as indicative and compare
ratios rather than single runs. Reproduction commands are in
[Measuring](#measuring).

### Where the time goes

`examples/coraza_ipc_profile.rs` splits one `WafRule::evaluate` call into client
serialisation, socket round trip and Coraza. "Client+IPC" is the whole client
path (encode, `writev`, socket round trip, response parse) against a stub
sidecar that answers `allow` immediately, so it contains no CRS work. Values are
mean µs per request over 200 iterations.

| body | build JSON | build binary | client+IPC JSON | client+IPC binary | full (binary) | CRS share |
|---|---:|---:|---:|---:|---:|---:|
| 1 KiB | 3.0 | 0.2 | 18.3 | 13.1 | 7 096 | 99.8 % |
| 4 KiB | 5.4 | 0.2 | 25.0 | 15.6 | 27 747 | 99.94 % |
| 8 KiB | 8.5 | 0.2 | 28.0 | 16.6 | 56 486 | 99.97 % |
| 16 KiB | 14.8 | 0.2 | 35.6 | 18.4 | 114 399 | 99.98 % |

The same split from the sidecar side (`go test -run '^$' -bench .`, ns/op and
allocations/op):

| stage | 1 KiB | 4 KiB | 8 KiB | 16 KiB |
|---|---:|---:|---:|---:|
| decode legacy JSON | 26.5 µs / 27 allocs | 59.3 µs / 27 | 116 µs / 27 | 112 µs / 27 |
| decode binary v1 | 0.29 µs / 9 allocs | 0.29 µs / 9 | 0.35 µs / 9 | 0.28 µs / 9 |
| CRS `ProcessRequestBody` | 7.61 ms | 29.3 ms | 57.8 ms | 117.5 ms |
| encode response JSON | 265 ns / 2 allocs (allow), 406 ns / 2 (block) | | | |
| encode response binary | 13 ns / 0 allocs (allow), 15 ns / 0 (block) | | | |

**Conclusion: the IPC boundary is not the bottleneck.** Removing JSON framing
and base64 takes the client path from 18–36 µs to 13–18 µs and the server
decode from 27 µs–112 µs (27 allocations) to 0.3 µs (9 allocations), but CRS
operator scanning is 99.8 %+ of the latency at every size. The remaining lever
is concurrency and body size, not the socket. This is why the earlier wasm
speed-up (5–6×) was real: it removed execution overhead from the dominant
component, whereas protocol work can only trim a rounding error.

### Early blocking (phase-1 anomaly evaluation)

The sidecar enables CRS rule 900120 (`tx.early_blocking=1`) by default. When a
request's phase-1 anomaly score already reaches the blocking threshold (scanner
User-Agent, protocol/header/cookie attack rules), CRS denies in phase 1 and the
request body is never scanned. The block decision is identical; only phase-2
alerts for an already-blocked request are skipped, which is the documented CRS
tradeoff for this mode. Disable with `--early-blocking=false` to restore the
phase-2 evaluation and its telemetry.

Benign traffic is unaffected (no phase-1 score → phase 2 runs normally). The
win is on requests that are blocked anyway, which is also a CPU-amplification
vector: a scanner User-Agent plus a large body used to force a full body scan
before the phase-2 deny.

| body | phase-2 only | early blocking | speedup |
|---:|---:|---:|---:|
| 1 KiB | 7.87 ms | 0.26 ms | 30× |
| 4 KiB | 29.76 ms | 0.26 ms | 115× |
| 8 KiB | 60.83 ms | 0.28 ms | 217× |
| 16 KiB | 119.87 ms | 0.29 ms | 413× |
| 60 KiB | 493.15 ms | 0.26 ms | 1 897× |

Numbers are process CPU time on the reference machine, pinned core, median of
6–9 evaluations; the full profile and the ranked remaining options are in
[`design/crs-performance.md`](design/crs-performance.md).

### Through the proxy

`examples/coraza_native_load.rs` drives a full HTTP request through
`WafProxyService` (client → proxy → WAF → sidecar → mock upstream → client).
Closed-loop load, 3 s per cell, native backend, admission control disabled so
the sidecar rather than the limiter is measured. One process hosts the client
and the proxy, so throughput is bounded by the six shared cores.

| body | c=1 | c=4 | c=16 | c=64 |
|---|---:|---:|---:|---:|
| 1 KiB RPS | 132 | 456 | 564 | 594 |
| 1 KiB p50 / p95 / p99 ms | 7.5 / 7.7 / 8.1 | 7.8 / 12.7 / 21.5 | 25.7 / 51.0 / 82.7 | 102 / 162 / 209 |
| 4 KiB RPS | 36 | 134 | 162 | 161 |
| 4 KiB p50 / p95 / p99 ms | 28.1 / 28.3 / 28.4 | 29.3 / 32.6 / 39.7 | 93.2 / 149 / 200 | 383 / 586 / 656 |
| 8 KiB RPS | 17.5 | 66 | 81 | 78 |
| 8 KiB p50 / p95 / p99 ms | 57.0 / 57.3 / 57.7 | 59.9 / 63.9 / 74.6 | 190 / 293 / 343 | 841 / 1300 / 1576 |
| 16 KiB RPS | 8.7 | 32.8 | 40.0 | 39.5 |
| 16 KiB p50 / p95 / p99 ms | 115 / 116 / 116 | 120 / 133 / 140 | 383 / 598 / 636 | 1587 / 2739 / 3212 |

Throughput is flat per byte: ~130 KiB of inspected body per second per core at
every size (1 KiB × 594 ≈ 580 KiB/s, 16 KiB × 39.5 ≈ 632 KiB/s). Concurrency
helps until the sidecar owns every core; past that it only adds queueing (c=64
has ~1.4× the p50 of c=16 and no extra RPS). p99 stays within ~1.6× of p50 up
to saturation.

### Before and after the protocol/concurrency work

The same harnesses were run against the previous JSON-only client (dedicated
2-worker Tokio runtime, job channel, JSON payload build) and the new binary
client on the same machine, interleaved:

| 4 KiB, direct rule | before | after |
|---|---:|---:|
| 1 caller (req/s) | 35.8 | 36.0 |
| 4 callers (req/s) | 133.3 | 134.7 |

| through the proxy (quiet window) | before p50 ms | after p50 ms |
|---|---:|---:|
| 1 KiB c=1 | 7.84 | 7.53 |
| 4 KiB c=1 | 28.39 | 28.07 |
| 8 KiB c=1 | 57.96 | 56.99 |
| 16 KiB c=1 | 115.6 | 115.4 |

p50 and steady-state RPS are unchanged within run-to-run noise, which is what
the split predicts: 13 µs of IPC cannot be seen in a 7–115 ms CRS-bound
request. The changes that do matter operationally are:

- **Per-request cost:** server decode+encode drops from ~27 µs to ~1 µs at
  1 KiB (and from ~112 µs to ~0.3 µs at 16 KiB), with 27 → 9 allocations; the
  client build drops from 3–15 µs to 0.2 µs. That is CPU returned to CRS under
  saturation, not latency.
- **No fail-fast queue:** the old client rejected with `QueueFull` as soon as
  `2 × pool_size` callers were in flight. The pool now waits for a connection
  until the deadline, so a burst is queued rather than failed closed.
- **Smaller failure surface:** no dedicated runtime thread, no per-request task
  or channel; a timed-out connection is dropped and replaced on the next
  request. Goroutine/connection counts stay flat under load (covered by tests).
- **Tails under contention:** with the machine oversubscribed by an unrelated
  build, the old client's 2-worker runtime produced 4 KiB c=1 p50 65 ms / p95
  144 ms and 8 KiB c=64 p50 3.0 s; the new client held 28 ms / 841 ms in the
  same window. This is noisy evidence, not a benchmark, but it is the failure
  mode the pool rework targets.

### Why not `SOCK_SEQPACKET`, `io_uring`, batching or pipelining

- **`SOCK_SEQPACKET`** would give message boundaries the 4-byte prefix already
  provides, and it caps message size at the socket buffer. It cannot improve a
  13 µs round trip and would complicate partial-read handling, so it is not
  used.
- **`io_uring`** targets syscall overhead. The measured syscall cost is inside
  the 13–18 µs client+IPC path, i.e. 0.2 % of a 1 KiB request and 0.02 % of a
  16 KiB request. It would add an async runtime to a synchronous `WafRule`
  trait for no measurable gain.
- **Batching** is rejected because responses must not be delayed: the socket
  round trip is 13–18 µs, so coalescing N requests saves at most (N−1) × ~5 µs
  while adding up to a full CRS evaluation of latency.
- **Pipelining** is supported on the wire (the sidecar reads the next frame
  after answering, covered by `TestPipelinedBinaryFrames`) but not used by the
  client. CRS saturates the CPU, so one connection evaluating serially already
  keeps a core busy; multiplexing would add head-of-line bookkeeping without
  adding throughput. The pool gives concurrency across connections instead,
  sized to the proxy's worker count.

### Capacity and deployment shape

- One sidecar transaction is CPU-bound CRS scanning: budget **~7–8 µs of
  sidecar CPU per inspected body byte**, or ~130 KiB/s per core. A 60 KiB body
  still occupies a core for ~0.45 s.
- Size `pool_size` to the number of proxy worker threads that may evaluate
  concurrently, capped at 8 by configuration validation. More connections than
  cores only adds queueing; fewer leaves cores idle.
- Bound the work instead of buying cores: `waf.coraza.max_inspect_bytes` with
  `oversize_action = "reject"` (or the documented `"forward-uninspected"`
  trade-off) turns a linear cost into a cap. Keep `--max-body` at least as
  large as the inspected body the proxy can send.
- `--timeout` is the sidecar's observation budget; `eval_timeout_ms` is the
  client deadline. Set the client deadline slightly above the sidecar budget so
  the sidecar can report a decision first. On expiry the client closes the
  socket, which releases the connection and lets the sidecar goroutine exit
  after its current Coraza call returns.
- `--max-conns` (default 128) bounds concurrent evaluations and applies
  backpressure through the listen backlog; keep it well above `pool_size` so a
  restarted proxy can reconnect immediately.
- Leave GC headroom: the sidecar sets `GOGC=600` and a 192 MiB soft memory
  limit. `MemoryMax=512M` in the unit bounds the process; a 60 KiB request
  needs roughly 8–12 MiB of transient allocation.
- One sidecar per proxy host/pod, on the same Unix socket, is the recommended
  shape. The client uses one socket and a bounded pool, so scale vertically
  first; a second sidecar replica needs a second proxy or a second socket.

### Measuring

```sh
nix develop -c just build-coraza-sidecar
nix develop -c just run-coraza-sidecar   # /tmp/coraza-native.sock

# cost split (client build, IPC, CRS)
CORAZA_SOCKET=/tmp/coraza-native.sock CORAZA_PROFILE_REPS=200 \
  cargo run --release --example coraza_ipc_profile --features coraza-native

# concurrency / tail matrix through the proxy
CORAZA_SOCKET=/tmp/coraza-native.sock CORAZA_LOAD_SECS=3 \
  cargo run --release --example coraza_native_load --features coraza-native

# sidecar-side split
cd native/coraza-sidecar && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
  GOFLAGS=-mod=vendor go test -run '^$' -bench . -benchmem
```

## Tests

- Go: `native/coraza-sidecar/main_test.go` — decision parity for benign, SQLi
  (body and URI), XSS (body and URI), path traversal (URI and body), plus
  malformed JSON/base64/encoding/size mismatch, oversized body and too many
  headers. `body_b64` alias covered. `TestConnectionCleanup` opens and closes
  50 connections and asserts the handler goroutines and connection map drain.
- Go protocol: `native/coraza-sidecar/protocol_test.go` — binary request and
  response round-trips (including invalid-UTF-8 bodies), binary/JSON decision
  parity, empty bodies, truncation flags, malformed frames (short header, bad
  version, lying lengths, body-flag mismatch, trailing bytes), oversized
  frames, partial reads one byte at a time, pipelined frames on one connection,
  handshake negotiation, legacy JSON still accepted, and per-connection buffer
  reuse. `bench_test.go` holds the decode/evaluate/encode benchmarks used for
  the split above.
- Rust (`src/waf/coraza_wire.rs`): encoder/decoder round-trip, JSON-equivalent
  semantics (body bytes, sizes, headers), truncation, empty body, oversized
  field rejection, malformed and unknown-decision responses, handshake.
- Rust (`src/waf/native_coraza.rs`): allow/block mapping over binary v1,
  legacy-JSON fallback for a pre-binary sidecar, binary/JSON decision parity,
  partial response reassembly, malformed response fail-closed, timeout,
  reconnect/retry after a closed pooled connection, missing socket start-up
  error, payload limit, pool saturation (8 callers on 2 connections), pool
  recovery after timeouts, client-deadline socket close, and Coraza metrics
  parity (evaluations/blocks/errors/duration).
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
  replaced by Go GC settings, `--max-body`/header limits, `--max-conns` and a
  wall-clock observation deadline. Coraza has no cancellation API, so an
  in-flight evaluation cannot be cancelled inside the sidecar. The client
  enforces `eval_timeout_ms` by closing the socket and returning a fail-closed
  decision; the sidecar goroutine exits after its current Coraza call returns.
  The sidecar must therefore bound its own work with `--timeout`, `--max-body`,
  `--max-conns` and header limits. A hard per-request context/cancellation
  would need a Coraza API that does not exist today.
- **Two configurations.** The sidecar's `--max-body` must be at least the WAF's
  `max_payload_bytes` (plus the request line and headers); the default 64 KiB
  body limit matches the reactor's payload cap. Validate this at deployment
  time.
- **Protocol negotiation is one-way today.** The client negotiates binary v1
  and falls back to JSON; the WASI reactor still uses the JSON envelope. A
  sidecar that is older than the proxy works, at JSON speed, and logs the
  fallback once per process.
- **Restart window.** WAF start-up requires a live socket. A sidecar restart
  causes brief fail-closed `503`s until reconnect.
- **Not measured here:** no-body/header-only latency, sustained soak under GC,
  or cross-host deployment (Unix socket is local only). Concurrency numbers
  come from a shared six-core machine with the load generator in the same
  process as the proxy.
- **Not production-wired as a default.** The real-process end-to-end test is
  ignored by default because it needs the separately built sidecar binary; CI
  must opt in with `CORAZA_SIDECAR_BIN` or `nix build .#coraza-native-sidecar`.
