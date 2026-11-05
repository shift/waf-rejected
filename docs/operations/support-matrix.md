# Support Matrix

**Release line:** `0.1.0-beta.13`  
**Default engine:** native Rust CRS engine (`rust-engine`, 505/505 rules)  
**Reference engine / explicit switch-back:** Coraza 3.3.3 + OWASP CRS 4.14.0 in the WASI reactor (`backend = "wasm"`)  
**Toolchain:** Rust 1.99.1, wasmtime 49

This document states what the beta release supports, which paths are on by
default, and what latency and coverage to expect from each one. It is the
long-form companion to the release summary in `CHANGELOG.md`.

For the operational choice between the three backends, including switch-back
and fail-closed/fallback semantics, see
[engine selection](../user-guide/engine-selection.md). Ready-to-run
configurations are in [`config/examples/`](../../config/examples/).

> **Headline caveat.** The sub-millisecond claims apply to **bodyless
> requests, early-blocked requests, allow-cache hits and prefilter fast paths**,
> and to the Rust engine's request path. They do **not** apply to a request that
> receives a full OWASP CRS body scan on the Coraza reference backend. The
> native Rust engine is the default request-inspection backend; Coraza remains
> the reference implementation and the explicit `wasm` backend. Response
> inspection is plumbed in the engine but is not proxy-wired yet.

## Workload matrix

Measured p50 unless stated otherwise. `native` = native Rust engine
(`backend = "rust"`), `wasm` = Coraza WASI reactor.

| Workload | Default path | Status | Typical measured cost | Notes |
| --- | --- | --- | --- | --- |
| Bodyless (`GET`/`HEAD`, no body, no query) | Rust engine + early blocking | Supported | native end-to-end 0.414 ms (engine request path ~0.11 ms); wasm ~4.5 ms | Sub-millisecond also covers allow-cache hits (0.56–0.96 µs) and fast-allow (0.38 µs). |
| Small bodies (≤ 4 KiB) | Full CRS body scan | Supported | native end-to-end 0.642 ms at 1 KiB, 1.091 ms at 4 KiB (engine request path ~566–591 µs at 4 KiB); wasm 40.13 ms and 169.56 ms | CRS evaluation dominates. The Rust engine is two orders of magnitude faster than the wasm reactor at these sizes. |
| Medium bodies (8 KiB) | Full CRS body scan | Supported | native end-to-end 1.614 ms (engine request path ~992 µs); wasm 354.09 ms | Byte-linear cost; admission control protects bodyless traffic from starvation. |
| Large bodies (32–64 KiB) | Full CRS body scan up to the wasm payload contract | Supported with policy | native ~737 ms p50 for 60 KiB at c=1; wasm seconds | The wasm reactor payload contract is 64 KiB. Above that, default behaviour fails closed unless `max_inspect_bytes` and `oversize_action` are configured explicitly. |
| Bodies above the policy limit | `reject` or `forward-uninspected` | Policy-dependent | Rejection is immediate; forwarding does not inspect the tail | `reject` returns `413` (or `503` on the wasm payload cap). `forward-uninspected` forwards a partially inspected body. Both are opt-in. |
| gRPC | Protocol-aware envelope + optional descriptor content scan | Supported | native 1 KiB envelope p50 ~3 ms, ~478 RPS at c=4 (zero 503) | Unary RPCs are classified from the frame sequence (not `content-length`) and fully inspected, including unary bodies without `content-length`. `content_scan = "strings"` adds a bounded content scan using a descriptor artifact. Genuinely streaming RPCs follow `server.grpc_streaming_policy`: `reject` (default) refuses them; explicit `transport-only` permits them but inspects every complete message incrementally before forwarding. Whole-stream bytes/messages/duration, per-message size and gzip expansion are bounded. |
| GraphQL | CRS JSON body scan (`body_scan = "crs"`) | Supported | CRS body cost for the JSON payload | `graphql-only` removes the CRS JSON scan at the cost of CRS body-rule coverage and requires a non-empty operation allowlist. `off` disables GraphQL-specific checks but keeps CRS scanning. |
| Native Coraza sidecar | `waf.coraza.backend = "native"` | Opt-in | ~6× faster body inspection than wasm | Extra process, Unix socket, shared uid/gid and separate upgrade lifecycle. See `native-performance-profile.md`. |
| Native Rust engine | `waf.coraza.backend = "rust"` | **Default** (compiled with `rust-engine`) | End-to-end proxy p50 0.414 / 0.642 / 1.091 / 1.614 ms for bodyless / 1 / 4 / 8 KiB; start-up 276 ms, ~30 MiB RSS | 505/505 rules, 2,110/2,112 corpus parity, 0 native-only FNs. Coraza remains the reference oracle. Runtime errors fail closed unless `waf.coraza.fallback = "wasm"`. |
| Coraza WASI reactor | `waf.coraza.backend = "wasm"` | Reference / explicit switch-back | End-to-end proxy p50 4.47 / 40.13 / 169.56 / 354.09 ms for bodyless / 1 / 4 / 8 KiB; start-up ~4.9 s, ~801 MiB RSS | Full reference implementation and differential oracle. Available in default builds; slower than the Rust engine. |
| Response inspection | engine phases 3–5 | Plumbed, not proxy-wired | Not on the proxy path | Response header/body collections and outbound scoring exist, but the proxy does not yet feed responses through them. |

Measured numbers are from the reference 6-core laptop described in
`performance-validation.md` and `subms-budget.md`. They are **capacity floors**
on a shared host, not ceilings, and should be re-measured on target hardware.

## Security controls and limits

The authoritative control-by-control status (code, test and introduced-in
release) is the matrix in
[`docs/architecture/security-model.md`](../architecture/security-model.md#2-control-status-matrix).
This table is the operator-facing summary.

| Control | Status | Default / limit | Notes |
| --- | --- | --- | --- |
| Request framing validation | Supported | On | Rejects CL+TE, duplicate/conflicting `Content-Length`, invalid lengths and non-`chunked` `Transfer-Encoding` with a generic `400` before any body read, on HTTP/1.1, HTTP/2 and HTTP/3. |
| Request decompression | Supported | On; `gzip`, `deflate`, `br`, `identity` | One coding per request; expanded output capped at `server.max_body_size` (`413`), malformed `400`, unsupported/stacked `415`. The upstream receives inspected identity bytes. |
| Trusted-proxy client IP | Supported | `server.trusted_proxies = []` | Forwarding headers are ignored unless the peer is listed; the chain is walked right-to-left. Never use `0.0.0.0/0`. |
| Per-IP rate limiting | Supported | `max_tracked_ips = 100000`, `capacity_policy = "fail_closed"` | 64 shards, incremental cleanup, hard cap. `evict_oldest` is available but weaker. |
| Global rate limiting | Supported | Configurable | One process-wide bucket; not shared across replicas. |
| Heavy-inspection admission | Supported | `waf.admission.enabled = true`, `queue_timeout_ms = 250`, `max_queued = 64` | Saturation returns `503 + Retry-After`; inspection is never skipped. |
| WebSocket per-message inspection | Supported | `server.max_body_size` per message | Client text/binary messages are inspected; control frames and upstream-to-client traffic are not. No idle timeout or concurrent-tunnel cap. |
| HTTP/3 admission | Supported (feature-gated) | `http3` feature + `enable_http3` + `"3"` in `supported_http_versions` + TLS 1.3 | No cap on concurrent QUIC connections/streams; no stateless retry. |
| WebTransport | Supported (feature-gated, terminating) | `webtransport` feature + `server.webtransport` | Origin/path/auth checks, session/stream/datagram caps, local inspection and bounded echo. **No upstream proxying.** |
| Response inspection | Not implemented | — | Engine phases 3–5 exist but the proxy does not call them. Response bodies are size-capped only. |
| Header-size / header-count / connection caps | Not implemented | hyper defaults | `server.max_connections` is parsed but not enforced. |

## Body inspection policy

The wasm reactor has a hard 64 KiB payload contract (`waf.coraza.max_payload_bytes`).
The default `max_inspect_bytes = 0` with `oversize_action = "inspect-all"`
means every body that fits is fully scanned. Choose one of the explicit
policies for larger bodies:

| Policy | Behaviour | Security trade-off |
| --- | --- | --- |
| `inspect-all` (default) | Scan up to `max_payload_bytes`; above the payload cap fail closed | No inspection gap inside the cap; large bodies cost seconds |
| `reject` + `max_inspect_bytes = N` | Return `413` for bodies above N before scanning | Bounds scan CPU and latency; clients sending larger bodies are refused |
| `forward-uninspected` + `max_inspect_bytes = N` | Scan the first N bytes and forward the rest | Bounds cost but leaves the body tail uninspected; document the gap |

The proxy-level `server.max_body_size` (1 MiB in the native profile) is a
separate transport cap and does not change WAF inspection depth.

## Opt-in fast paths

### Allow cache (`allow-cache`)

- **Build:** non-default Cargo feature `allow-cache`.
- **Config:** `waf.allow_cache.enabled = true`.
- **What it does:** memoises the verdict of pure content rules for requests
  that produced an `Allow`, for a short TTL. Blocks and rate limits are never
  cached, and stateful or IP-dependent rules still run on every hit.
- **When it helps:** repeated identical requests to content-inspected routes.
- **Limits:** bounded entries, TTL expiry and explicit invalidation; a cache
  hit is not a general bypass.

### Fast-allow

- **Config:** `waf.fast_allow.enabled = true` plus an explicit
  `waf.fast_allow.routes` list (`"METHOD /path"`).
- **What it does:** skips inspection for **bodyless, query-free** requests on
  the listed routes.
- **When it helps:** static endpoints and other exact, bodyless, query-free
  routes on the proxy listener.
- **Limits:** only exact configured routes; request-size, method, rate-limit
  and geographic gates still run. It cannot allow a request with a body or a
  query string.

### Prefilter and Hyperscan

- **Build:** `crs-prefilter` (pure Rust) or `hyperscan-eval` (links Vectorscan).
- **What it does:** required-literal gating skips rule groups and individual
  regex evaluations that cannot match a representation (137 skipped on a
  4 KiB body in this release). The opt-in Vectorscan candidate pass adds one
  block-mode multi-pattern scan per `(value, transform pipeline)` and skips
  per-rule regexes whose pattern did not hit.
- **Limits:** non-default evaluation modes. Vectorscan is x86-64/AVX2 only,
  bounded (256 rules, 16 MiB per group, 64 MiB total, 5 s compile), and falls
  back to the pure Rust automata when unavailable or when a scan fails.

## Native profile

Use `config/performance-native.toml` and a build with
`--features wasm-reactor,coraza-native`. The sidecar must be reachable on
`waf.coraza.native_socket_path` and share a uid or gid with the proxy (socket
mode `0660`).

| Item | Guidance |
| --- | --- |
| Pool size | One pooled connection per concurrent evaluation; `8` is the validation ceiling. Use `cores - 1` on small hosts. |
| Sidecar body cap | `--max-body` must be at least `max_payload_bytes` plus request line and headers. |
| Admission | `heavy_permits = 4` reserves half the pool for cheap requests; saturation returns `503 + Retry-After` and never skips inspection. |
| Failure mode | Keep `fail_mode = "closed"`; a sidecar outage returns `503`, never a silent allow. |
| Scaling | One sidecar per proxy pod/host. Unix sockets are local-only. |

## Rust engine (default)

- **Build:** default Cargo feature `rust-engine` (also listed explicitly in
  `flake.nix` and the `Dockerfile`). Builds without it default to `wasm`.
- **Config:** `waf.coraza.backend = "rust"` is the compiled default; set
  `backend = "wasm"` to switch back to the Coraza reference implementation at
  any time, or `backend = "native"` for the sidecar.
- **Startup:** the pinned CRS bundle is parsed and compiled into the IR once at
  start-up (505/505 rules, ~210 ms); there is no per-request rule parsing. The
  compile time, rule counts and process RSS are logged, and startup is aborted
  (fail closed) if strict loading fails. The bundle is shipped in the package
  (`share/waf/rules/crs`) and resolved by the binary; `WAF_CRS_CONF` overrides
  the path.
- **Fallback:** `waf.coraza.fallback = "none"` (default) turns a runtime engine
  error into a fail-closed block. `fallback = "wasm"` re-evaluates that request
  with the Coraza reactor; if both fail the request is still blocked. The
  fallback costs re-inspection, so enable it only when availability outweighs
  latency and you accept two engines in memory.
- **Status:** 505/505 rules and 2,110/2,112 corpus agreement with Coraza; the
  two differences are documented and match the corpus labels. Coraza remains
  the reference oracle.

## Memory sizing

### Native Rust engine (default)

The engine holds the compiled CRS IR and request state in-process. Measured
start-up is ~276 ms with ~30 MiB RSS for the 505-rule bundle; sizing scales
with concurrency and request/body buffers rather than a per-worker wasm pool.
The Coraza reactor is not instantiated when `backend = "rust"` and
`fallback = "none"` (the default), so its ~801 MiB steady-state footprint does
not apply.

### WASI reactor (reference / `backend = "wasm"`)

Host-side limits: 256 MiB wasm linear-memory trap ceiling, 8 MiB wasm stack,
5 s evaluation timeout, and `pool_size` pre-warmed workers (auto = cores
clamped to `1..=8`).

```text
budget MiB ≈ 370 (host: wasmtime engine, module, 32 MiB stacks, channels)
           + pool_size × 80 (guest linear memory per worker at the 64 MiB GC bound)
```

A conservative planning rule is one worker per 96 MiB of available memory after
reserving ~384 MiB for the host:

```text
pool_size ≈ (available_MiB - 384) / 96, clamped to 1..=8
```

| Available memory | Suggested pool |
| --- | ---: |
| 512 MiB | 1 |
| 1 GiB | 6 |
| 2 GiB+ | 8 (cap) |

Measured with `memory-soak` at 6 workers and the shipped GC 600 % / 64 MiB
soft limit: **837.6 MiB peak RSS / 480 MiB linear memory**, with 0.0 % growth
after the midpoint over 10 minutes and 24,112 evaluations. Do not size from
the 256 MiB trap ceiling; wasm memory only grows and is not returned to the OS.

### Native sidecar

Budget sidecar CPU, not only memory: CRS body inspection costs roughly
**7–8 µs of sidecar CPU per inspected body byte**, or about **130 KiB of body
per second per core**. A 6-core host can sustain roughly 800 RPS of 1 KiB
bodies, 100 RPS of 8 KiB bodies, or 13 RPS of 60 KiB bodies **if the sidecar
owns every core**. Leave at least one core for the proxy, TLS and networking.

## Known limitations

- Sub-millisecond latency is a **path** property: bodyless, allow-cache,
  fast-allow/prefilter and the Rust engine request path. Engine cost is
  ~566–591 µs at 4 KiB and ~992 µs at 8 KiB; the end-to-end proxy adds
  forwarding and I/O.
- The native Rust engine is the default, but corpus agreement is 2,110/2,112,
  not 100 %; the two differences are documented and match the corpus labels.
  Coraza remains available but slower (`backend = "wasm"`).
- Response inspection is plumbed but **not proxy-wired**; phases 3–5 do not
  run on proxied responses yet.
- WebTransport is a **terminating** endpoint: it authenticates, inspects and
  echoes sessions locally. Application-specific upstream proxying is **not
  implemented**, and HTTP/1.1 `Upgrade: webtransport` remains `501`.
- Request framing validation and bounded decompression are on by default, but
  header-size/header-count limits and `server.max_connections` are not
  enforced; hyper defaults and the OS/container limits apply.
- io_uring and Hyperscan/Vectorscan are **opt-in** and fall back to portable
  implementations.
- gRPC streaming bodies are not sent to CRS; descriptor content scanning is
  opt-in and bounded.
- `graphql-only` intentionally gives up CRS body-rule coverage for GraphQL
  requests.
- The wasm reactor pays a one-off ~4.5–5.6 s compile/warm-up before readiness.
- The native profile adds a process, socket and deployment lifecycle.
- Beta releases have best-effort support only; see `support-policy.md`.
