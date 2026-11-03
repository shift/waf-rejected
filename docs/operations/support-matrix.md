# Support Matrix

**Release line:** `0.1.0-beta.12`  
**Default engine:** Coraza 3.3.3 + OWASP CRS 4.14.0 in the WASI reactor  
**Toolchain:** Rust 1.99.1, wasmtime 49

This document states what the beta release supports, which paths are on by
default, and what latency and coverage to expect from each one. It is the
long-form companion to the release summary in `CHANGELOG.md`.

> **Headline caveat.** The sub-millisecond claims apply to **bodyless
> requests, early-blocked requests, allow-cache hits and prefilter fast paths**.
> They do **not** apply to a request that receives a full OWASP CRS body scan.
> The native Rust engine is **opt-in**, not the default.

## Workload matrix

| Workload | Default path | Status | Typical measured cost | Notes |
| --- | --- | --- | --- | --- |
| Bodyless (`GET`/`HEAD`, no body, no query) | Coraza reactor + early blocking | Supported | wasm p50 ~4.5 ms; native p50 ~0.9 ms end-to-end | Sub-millisecond is reachable only with fast-allow and/or allow-cache, or when an early-block rule fires before CRS body work. |
| Small bodies (≤ 4 KiB) | Full CRS body scan | Supported | wasm ~66 ms at 1 KiB, ~172 ms at 4 KiB; native ~8 ms at 1 KiB, ~29 ms at 4 KiB | CRS evaluation is ~99 % of the cost. This is the main supported inspection path. Native is ~6× faster but still CRS-bound. |
| Medium bodies (8–16 KiB) | Full CRS body scan | Supported | wasm ~354 ms at 8 KiB proxy p50; native ~58 ms at 8 KiB | Byte-linear cost; admission control protects bodyless traffic from starvation. |
| Large bodies (32–64 KiB) | Full CRS body scan up to the wasm payload contract | Supported with policy | native ~737 ms p50 for 60 KiB at c=1; wasm seconds | The wasm reactor payload contract is 64 KiB. Above that, default behaviour fails closed unless `max_inspect_bytes` and `oversize_action` are configured explicitly. |
| Bodies above the policy limit | `reject` or `forward-uninspected` | Policy-dependent | Rejection is immediate; forwarding does not inspect the tail | `reject` returns `413` (or `503` on the wasm payload cap). `forward-uninspected` forwards a partially inspected body. Both are opt-in. |
| gRPC | Protocol-aware envelope + optional descriptor content scan | Supported | native 1 KiB envelope p50 ~3 ms, ~478 RPS at c=4 (zero 503) | Protobuf frames are validated structurally and withheld from CRS body rules. `content_scan = "strings"` adds a bounded content scan using a descriptor artifact. Streaming bodies remain envelope-only. |
| GraphQL | CRS JSON body scan (`body_scan = "crs"`) | Supported | CRS body cost for the JSON payload | `graphql-only` removes the CRS JSON scan at the cost of CRS body-rule coverage and requires a non-empty operation allowlist. `off` disables GraphQL-specific checks but keeps CRS scanning. |
| Native Coraza sidecar | `waf.coraza.backend = "native"` | Opt-in | ~6× faster body inspection than wasm | Extra process, Unix socket, shared uid/gid and separate upgrade lifecycle. See `native-performance-profile.md`. |
| Native Rust engine | `waf.coraza.backend = "rust"` | Opt-in / experimental | Not a default SLA | 505/505 rules executed, 2,110/2,112 corpus parity. Not a drop-in replacement today. |

Measured numbers are from the reference 6-core laptop described in
`performance-validation.md` and `subms-budget.md`. They are **capacity floors**
on a shared host, not ceilings, and should be re-measured on target hardware.

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
- **When it helps:** health/readiness and static endpoints.
- **Limits:** only exact configured routes; request-size, method, rate-limit
  and geographic gates still run. It cannot allow a request with a body or a
  query string.

### Prefilter and Hyperscan

- **Build:** `crs-prefilter` (pure Rust) or `hyperscan-eval` (links Vectorscan).
- **What it does:** required-literal gating and multi-pattern prefilters skip
  rule groups that cannot match a representation.
- **Limits:** non-default evaluation modes. Hyperscan falls back to the pure
  Rust automata when unavailable or when a scan fails.

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

## Rust engine

- **Build:** non-default Cargo feature `rust-engine`.
- **Config:** `waf.coraza.backend = "rust"`.
- **Status:** experimental. It executes 505/505 rules and matches 2,110/2,112
  corpus cases; the remaining two are documented parity gaps.
- **Do not** treat it as a supported default replacement for Coraza in this
  beta.

## Memory sizing

### WASI reactor (default)

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

- Sub-millisecond latency is a **fast-path** property, not a full CRS body
  inspection property.
- The native Rust engine is opt-in and not fully parity-tested.
- gRPC streaming bodies are not sent to CRS; descriptor content scanning is
  opt-in and bounded.
- `graphql-only` intentionally gives up CRS body-rule coverage for GraphQL
  requests.
- The wasm reactor pays a one-off ~4.5–5.6 s compile/warm-up before readiness.
- The native profile adds a process, socket and deployment lifecycle.
- Beta releases have best-effort support only; see `support-policy.md`.
