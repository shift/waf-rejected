# Changelog

All notable changes to WAF-Rejected are documented here.

## [Unreleased]

### Added

- **Native Rust engine body processors and response phases:** Coraza-compatible
  JSON (`gjson`-style `json.` flattening into `ARGS_POST`) and XML
  (`XML:/*`/`XML://@*`, no external DTD/entity access) request body processors,
  `ctl:requestBodyProcessor` selection parity, Go-compatible `REQUEST_URI`
  normalisation/percent-decoding, and opt-in phases 3–5 with response
  headers/body collections and outbound anomaly scoring. XPath selectors other
  than `XML:/*` and `XML://@*` fail the strict load explicitly. Non-default
  (`rust-engine`); defaults and the Coraza path are unchanged. See
  `docs/suggestions_from_agents/rust-engine.md`.
- **Experimental (non-default) `parallel-args` feature:** a deterministic
  candidate-level parallel model for the native Rust CRS engine, with a
  serial-vs-parallel differential test over the 2,112-case corpus and generated
  multi-argument bodies. The prototype is **not enabled** because it misses the
  performance gate (best 8 KiB gain ~2.6%, 4 KiB ~1.3%, multi-argument bodies
  regress); see `docs/suggestions_from_agents/parallel-args.md`. Defaults,
  rules and the Coraza path are unchanged.
- Config-gated io_uring listener (`server.io_backend = "tokio" | "io_uring"`,
  default `tokio`) with automatic fallback to the tokio accept path when the
  ring cannot be created. See `docs/developer-guide/io-uring-listener.md`.
- End-to-end TLS/HTTP2/WAF proxy benchmark for the listener backends.

### Changed

- Native Rust CRS engine (`rust-engine`, non-default) rule-loop work: an
  empty-target gate skips rules whose positive collections are absent,
  `multiMatch`/`capture`/`MATCHED_VARS` flags are precomputed, `skipAfter`
  targets are resolved at load time, `MATCHED_VARS` uses recycled byte arenas,
  and macro/capture/selector paths no longer allocate per match. Corpus parity
  is unchanged (2,110/2,112, 0 native-only FNs); allocations fall from ~143 to
  33-42/request. Latency improves (bodyless 158→110 µs, 1 KiB 316→271 µs,
  4 KiB 636→596 µs, 8 KiB 1.05→1.02 ms); the 4/8 KiB targets are still missed.
  See `docs/suggestions_from_agents/engine-ruleloop.md`.
- io_uring ring thread now batches submissions, keeps multiple operations in
  flight, recycles read buffers, and slices a single `Bytes` copy for partial
  writes. SQPOLL remains opt-in (`WAF_IO_URING_SQPOLL=1`).
- Multishot accept uses a pollable CQ ring with bounded shutdown instead of
  blocking indefinitely in `io_uring_enter`.
- Accept errors no longer tear down the proxy listener; they are logged and
  retried.

## [0.1.0-beta.12] - 2026-11-03

### Release summary

Beta 12 packages the work merged since beta 11. Coraza 3.3.3 with OWASP CRS
4.14.0 remains the default request engine (WASI reactor, wasmtime 49, Rust
1.99.1). The native Go Coraza sidecar and the native Rust CRS engine remain
**opt-in** and are not selected by a plain `config.toml`.

Highlights:

- **gRPC:** HTTP/2/HTTP/1.1 transport, frame and header validation,
  descriptor-driven protobuf field decoding, and optional Coraza content scan.
  Raw protobuf is never sent to CRS body rules; streaming RPCs stay
  envelope-only by design.
- **GraphQL:** operation parsing, allowlists, persisted-query hashes, limits
  and mutation/subscription policy, with `crs` (default), `graphql-only` and
  `off` body-scan modes.
- **Native Coraza sidecar:** opt-in native Go Coraza/CRS backend over a Unix
  socket, corpus-verified against the wasm reactor, plus admission control,
  body-size policy and parser hardening.
- **Detection corpus:** 2,112 corpus cases, with 7,320/7,320 transform parity
  and 2,110/2,112 rule parity for the opt-in Rust engine.
- **Performance:** early blocking, sound gating, sub-microsecond allow cache,
  bodyless fast-allow, zero-allocation transforms, Hyperscan/prefilter,
  Coraza binary ABI, start-up pre-warm, HTTP/2 tuning, and optional
  allocator/TLS/io_uring paths.
- **Observability:** admission, Coraza, early-block and cache metrics, plus a
  documented feature matrix.

### Support matrix

This table summarises what the release actually guarantees. The full detail,
including measured numbers and sizing guidance, is in
[`docs/operations/support-matrix.md`](docs/operations/support-matrix.md).

| Workload / path | Default | Status | Latency and coverage notes |
| --- | --- | --- | --- |
| Bodyless, no query | yes | Supported | Early blocking and optional fast-allow/allow-cache can reach sub-millisecond. Without those opt-ins the measured wasm p50 is ~4.5 ms and native ~0.9 ms. |
| Small bodies (≤ 4 KiB) | yes | Supported | Full CRS body inspection. CRS-dominated: ~42 ms at 1 KiB and ~173 ms at 4 KiB on wasm; ~8 ms and ~29 ms on native. **Not sub-millisecond.** |
| gRPC | yes | Supported | Protocol-aware envelope, frame and optional descriptor/field checks. Bodies are withheld from CRS by default; `content_scan = "strings"` adds a bounded content scan. |
| GraphQL | yes | Supported | `body_scan = "crs"` keeps the full JSON body scan (default). `graphql-only` is cheaper but gives up CRS body-rule coverage for those requests. |
| Large bodies (> 64 KiB) | yes | Supported with policy | The wasm payload contract is 64 KiB. Bodies above the configured policy fail closed unless `max_inspect_bytes` + an explicit oversize action are set. Full 60 KiB CRS inspection is seconds, not milliseconds. |
| Native Coraza sidecar | no | Opt-in | ~6× faster body inspection than the wasm reactor; costs an extra process, socket and supervisor. |
| Native Rust engine | no | Opt-in / experimental | 505/505 rules executed, 2,110/2,112 corpus parity; not yet a default replacement for Coraza. |
| Allow cache | no | Opt-in | Memoises pure content-rule `Allow` verdicts for a short TTL; never caches blocks or bypasses stateful gates. |
| Fast-allow | no | Opt-in | Bodyless, query-free routes only; rate/size/geo gates still run. |
| Memory | — | Documented | Plan roughly `370 + 96 × pool_size` MiB for the wasm reactor (6 workers plateau ~838 MiB RSS at the 64 MiB guest GC bound); see the sizing table. |

### Known limitations

- **Sub-millisecond is not a full-inspection claim.** It applies to bodyless
  requests, early-blocked requests, allow-cache hits and prefilter fast paths.
  A request that receives a full OWASP CRS body scan costs milliseconds to
  hundreds of milliseconds depending on body size and backend.
- The native Rust engine is **opt-in and experimental**. It is not selected by
  default and its corpus parity is 2,110/2,112, not 100 %.
- gRPC streaming bodies are not scanned by CRS. Descriptor-backed field and
  content scanning only applies when a descriptor artifact and
  `content_scan = "strings"` are configured.
- `graphql-only` intentionally withholds the raw GraphQL body from CRS body
  rules and requires a non-empty operation allowlist; use it only when that
  coverage gap is acceptable.
- The native sidecar adds a process, a Unix socket, a shared uid/gid boundary
  and a separate upgrade lifecycle. There is no cross-host sidecar.
- The wasm reactor pays a one-off ~4.5–5.6 s compile/warm-up before readiness,
  and wasm linear memory only grows; size the pool from the plateau table, not
  from the 256 MiB trap ceiling.
- Beta releases are supported on a best-effort basis only. See
  [`docs/operations/support-policy.md`](docs/operations/support-policy.md).

### Performance

- Harden the engine performance gate against shared-host clock/GC drift. The
  reported 4 KiB SQLi regression is not reproducible on a quiet pinned host:
  swapping the baseline (`efb56b5`) and current (`06c38ec`) Coraza guest modules
  under the same binary gives the same p50/p95 (164/373 ms) and allocation
  counts (6 852 B / 5.04 per op). `compare.sh` now also enforces the same-run
  `4k-sqli / 4k-allow` ratio (baseline 1.48) alongside absolute p50, so a real
  attack-path regression is still caught when every row scales together; the
  self-test covers a doubled ratio with unchanged absolute rows. No rule,
  inspection or WAF default changes. See
  `docs/operations/performance-verification.md` §3.4.1.

- Native Rust CRS engine hot-loop optimisation (`rust-engine`, non-default):
  zero-allocation transform pipelines and cache, per-rule mandatory-literal
  gates from `rules/crs/prefilter.json` (50 gated rules, 55 % of regex
  evaluations skipped on a 4 KiB body), borrowed TX/MATCHED_VARS evaluation,
  reused operator macro/capture buffers, and `MATCHED_VAR*` bookkeeping only
  for groups that read it. Allocations fall from 1,251–1,785 to ~143 per
  request; p50 on the shared host drops from 327 µs/869 µs/2.15 ms/3.88 ms
  (bodyless/1/4/8 KiB) to 145 µs/426 µs/1.13 ms/2.07 ms. The 4 KiB and 8 KiB
  latency targets are not met; see
  `docs/suggestions_from_agents/engine-hotloop.md`. Adds the non-default
  `engine-profile` feature and a `--profile` mode to `rust-engine-parity`.

### Added

- Opt-in HTTP/2 and upstream connection tuning. `[proxy.pool]` bounds idle
  upstream reuse (`max_idle_per_host`, `idle_timeout_secs`) with optional
  out-of-band health probes; `[server.http2]` controls ingress/upstream
  flow-control windows, concurrent-stream and pending-reset limits, and the
  PING keep-alive policy; `[proxy.streaming]` relays large upstream responses
  frame by frame under the existing byte cap instead of buffering them.
  Defaults are unchanged (every block is disabled). Adds upstream request /
  connection / health-check Prometheus counters, a reproducible
  `benches/http2_tuning.rs` throughput and percentile harness, and
  `docs/developer-guide/http2-tuning.md`.

- Compact binary request envelope for the Coraza WASI reactor (default), with
  the legacy JSON envelope kept behind `WAF_CORAZA_JSON_ABI=1`. The host writes
  the length-prefixed struct directly into the guest's static input buffer and
  reads the decision from a fixed `decision_base` header, removing JSON parsing
  and base64 from the per-request path. Adds `WasmReactor::warm_workers(n)` for
  fail-closed start-up pre-warming and a `coraza_abi_bench` binary. Measured
  p50 is unchanged because CRS evaluation dominates; the 4 KiB body p99 drops
  from 546 ms to 502 ms, and pre-warming removes the ~1.3–1.7 s first-request
  Go/CRS initialisation. See `docs/coraza-wasi-reactor.md`.

- Engine-level performance regression gate (`benchmarks/perf-gate/`). A
  reproducible runner measures the Coraza WASI reactor, the native Rust CRS
  engine and the experimental kernel behind the same bodyless, 4 KiB allow and
  4 KiB SQLi requests; it records p50/p95/p99, throughput, RSS, allocations and
  the hardware/kernel/toolchain environment, with CPU affinity pinned by
  default. A checked-in JSON baseline and `compare.sh` report p50 regressions
  beyond a configurable threshold; enforcement is opt-in (`--enforce`) so shared
  CI runners stay green. Includes a synthetic self-test and a documented
  comparison against ModSecurity/CRS and public cloud WAF latency claims. See
  `docs/suggestions_from_agents/perf-gate.md`.

- Production-grade CRS prefilter backend (`hyperscan-eval`, non-default).
  The Hyperscan database set is compiled once per process and shared through
  the cached `Prefilter`, with an `Arc`-shared immutable database and a bounded
  scratch pool so concurrent workers do not serialise on the matcher. Extraction
  runs once per representation instead of per group, provably-identity
  transforms are skipped, and each rule group carries a required-byte gate that
  skips groups whose literals cannot occur in the scanned view. When Hyperscan
  is unavailable, unsupported on the CPU, or a scan fails, evaluation falls back
  to the pure-Rust Aho-Corasick automata; defaults are unchanged. Adds
  `scripts/bench-prefilter.sh` and
  `docs/suggestions_from_agents/simd-prefilter.md`. After rebasing onto the
  union-automaton/transform-cache work, the pure-Rust path is faster for the
  all-extraction scan; Hyperscan remains a win for content-type-aware and
  first-hit attack scans.

- Experimental native Rust evaluation kernel (`engine-kernel`, non-default).
  Standalone prototype of a Coraza replacement: zero-copy request spans, a
  per-value transform-pipeline cache, a compiled DAG of cheap predicates,
  shared Aho-Corasick literal automata and precompiled regex DFAs, sound
  literal gating from `rules/crs/prefilter.json`, and anomaly scoring with
  phase-1/phase-2 early exit. Includes a benchmark binary and a pinned-corpus
  soundness harness; the covered 1,077-case subset has zero false negatives.
  Coraza remains the default backend and no production defaults changed. See
  `docs/suggestions_from_agents/engine-kernel.md`.

- Native (Rust) ports of Coraza's `@detectSQLi` and `@detectXSS` operators
  (`native-detect`, non-default). `detect_sqli`/`detect_xss` are allocation-free,
  single-pass, and byte-for-byte ports of `libinjection-go` v0.2.2 — the library
  Coraza v3.3.3 calls for those operators — so decisions match Coraza exactly.
  A pinned oracle (`tests/corpus/native-detect/oracle.json`, 11,039 values from
  the CRS corpus plus generated variants) pins parity at 0 false negatives and
  0 false positives. `NativeOperator::from_coraza_name` exposes them to the
  native engine and prefilter; Coraza remains the default request path. See
  `docs/suggestions_from_agents/native-detect.md`.

- Compiled bodyless fast-allow path (`[waf.fast_allow]`, default **off**).
  An exact `(method, path)` byte trie returns a precomputed `Allow` for
  explicitly listed routes, before the proxy builds a `RequestContext`, clones
  a `HeaderMap`, acquires admission, runs the gRPC/GraphQL pre-checks,
  dispatches inspection rules or constructs an audit event. Only bodyless,
  query-free requests match; always-on gates (request size, method, per-IP/
  global/adaptive/burst rate limits and geographic blocking) still run, and any
  custom rule forces a fall-through. `Config::validate` rejects empty,
  malformed, duplicate or unsupported routes. New metrics
  `waf_fast_allow_{hits,blocks,fallthrough}_total`, and an in-process harness
  (`bodyless-bench`). Audit event construction now checks the threat level
  before allocating, so default `min_threat_level = "medium"` allow events are
  no longer built and discarded. See
  `docs/suggestions_from_agents/fastpath-engine.md`.

- Per-rule CRS gating (`waf.coraza.prefilter = "gated"`, default `off`). The
  host scans the URI, query, headers, cookies and body with the required-literal
  prefilter and removes only the gated CRS rules whose proven mandatory literals
  are absent, keeping every ungated rule. The bounded `remove_rule_ids` list
  (`<= 256`) travels in the JSON ABI and in binary sidecar v1 (negotiated
  through handshake capabilities); both guests validate it against their own
  `prefilter.json` copy and call `tx.RemoveRuleByID` before phase 1, so a
  forged payload cannot disable an ungated or unknown rule and removal is per
  transaction. The vendored Coraza `types.Transaction` interface now exposes
  `RemoveRuleByID` via `patches/coraza-v3.3.3-remove-rule-by-id.patch`, applied
  by both Go build paths. Measured on the native sidecar: 1.3-1.6x p50
  improvement on benign 1-60 KiB bodies, 57-58 of 61 gated rules removed, and
  0 false negatives / 0 false positives on the 51-case corpus. Requires the
  non-default `crs-prefilter` feature; builds without it reject the config.

- Experimental content-addressed allow-verdict cache (`allow-cache`,
  non-default, opt-in via `[waf.allow_cache]`). It memoises only the `Allow`
  verdict of pure content rules (the Coraza backend and the built-in content
  inspector) for a short TTL; blocks and rate limits are never cached, and
  stateful/IP-dependent rules (rate limits, GeoIP, size/method checks, custom
  rules) still run on every hit. Keys are a length-prefixed canonical encoding
  of method, exact URI, HTTP version, the complete sorted header multimap,
  exact body bytes (capped), declared body size and a ruleset/policy generation
  hash, hashed with keyed SipHash-2-4 (128-bit) under a process-lifetime
  secret. Bounded sharded map with TTL, hit/miss/eviction/entry metrics, and
  immediate invalidation on policy change. `WafRule::cacheable()` defaults to
  `false`, so custom rules are never memoised. Design, injectivity argument,
  threat model, measured replay results and disable conditions:
  `docs/suggestions_from_agents/allow-cache.md`.

- Experimental CRS required-literal prefilter (`crs-prefilter`, non-default).
  The offline `crs-prefilter-extract` tool parses the vendored CRS 4.14 rules
  and emits `rules/crs/prefilter.json` plus a coverage summary; the Rust
  runtime scans the request body with Aho-Corasick over the proven literal
  sets and the transform pipelines it can reproduce exactly. The native
  sidecar backend gains `PrefilterMode::{DryRun, BodyWithhold}` (default
  `Off`) and three metrics. Stock CRS has ungated body-relevant rules
  (`@detectSQLi`, `@detectXSS`, argument/file size checks, the
  obfuscation-tolerant 932 regexes), so `BodyWithhold` never fires on the
  stock bundle; the mode is an experimental measurement path until per-rule
  gating lands. See `docs/suggestions_from_agents/crs-prefilter.md`.

- Cross-feature CI matrix. `scripts/ci-feature-matrix.sh` (also
  `just ci-feature-matrix`) and `.github/workflows/feature-matrix.yml` compile
  and test the default, `wasm-reactor`, `wasm-reactor,coraza-native`,
  `--no-default-features`, `--no-default-features,wasm-reactor`,
  `http3,webtransport,wasm-reactor` and allowlist-binary combinations, so
  feature-gated test imports fail locally instead of only in an optional
  build. See `docs/developer-guide/feature-matrix.md`.

- gRPC field-content scanning. Decoded `string` and UTF-8 `bytes` values are
  evaluated by the configured Coraza backend as a synthetic
  `application/x-www-form-urlencoded` request (URI
  `/__grpc__/package.Service/Method`), so SQLi/XSS text inside a structurally
  valid field is blocked without sending raw protobuf to CRS. Bounded by
  `waf.grpc.max_content_scan_bytes` (default 64 KiB) and controlled by
  `waf.grpc.content_scan = "off" | "strings"` (default `strings`). Blocks
  include the field path in the reason and honour
  `server.grpc_aware_rejections`. New metrics
  `waf_grpc_content_scans_total` and `waf_grpc_content_blocks_total`. See
  `docs/grpc-inspection.md`.

- Production observability for the Coraza, admission, gRPC and GraphQL
  subsystems. New Grafana dashboard
  `infrastructure/monitoring/dashboards/waf-overview.json`, expanded
  `infrastructure/monitoring/alert_rules.yml` with runbook links, per-alert
  triage in `docs/operations/runbook.md`, and
  `scripts/check-dashboards.sh` to validate dashboard JSON and metric
  references against the Rust source. Adds bounded-cardinality
  `waf_grpc_decisions_total{decision}` and
  `waf_graphql_decisions_total{decision}` counters (three series each).
  Reactor pool/worker and RSS metrics remain unexported and are documented as
  a gap.

- Opt-in Coraza body-inspection size policy (`[waf.coraza]`).
  `max_inspect_bytes` (default `0` = inspect the whole body) and
  `oversize_action` (`"inspect-all"` default, `"forward-uninspected"`,
  `"reject"`) let operators bound the byte-linear CRS body cost. The default
  is unchanged. `forward-uninspected` sends only the first N bytes to CRS and
  forwards the rest uninspected (an explicit, documented gap); `reject`
  returns `413` before evaluation. New metrics
  `waf_coraza_body_truncated_total`, `waf_coraza_body_rejected_total` and the
  `waf_coraza_body_inspected_bytes` histogram, plus a start-up warning for
  non-default policies. See `docs/coraza-wasi-reactor.md`.

- Deterministic GraphQL persisted-query allowlist generation and loading.
  `graphql-allowlist` (`src/bin/graphql-allowlist.rs`,
  `scripts/graphql-allowlist.sh`) builds a sorted, byte-identical artifact
  from a JSON manifest of `{name, query}` / `{name, sha256}` entries and/or a
  directory of `.graphql` files. Queries are normalised (comments removed,
  commas and whitespace collapsed outside strings) before hashing, and the
  artifact records `ir_version`, input provenance (`source.kind`,
  `source.sha256`), operation `type`, and `unknown_operation_action`.
  `src/waf/graphql_allowlist.rs` provides strict `load_allowlist`,
  `allows_name` / `allows_hash`, and the `waf.graphql.allowlist_file` hook;
  file operations merge with the inline `operation_allowlist`, an explicit
  config `unknown_operation_action` wins over the artifact, and an unreadable
  file aborts start-up through `waf_init_error`. See
  `docs/graphql-inspection.md`.

- Property and fuzz hardening for the security-critical parsers. `proptest`
  suites now cover the protobuf wire decoder, gRPC frame/path/content-type
  parsing, GraphQL body/query parsing and counters, allowlist/descriptor
  loading, and admission classification. New isolated `cargo-fuzz` targets
  (`protobuf`, `grpc_frames`, `graphql_body`, `allowlist_json`) with seed
  corpora and `scripts/fuzz-smoke.sh` provide bounded local smoke runs. Fixed
  unbounded recursion in GraphQL selection-set parsing and binary descriptor
  parsing, and hardened gRPC frame arithmetic. See
  `docs/developer-guide/parser-hardening.md`.

- Heavy-inspection admission control (`[waf.admission]`). Each evaluation is
  classified as cheap (no body, or a gRPC/GraphQL body withheld from CRS) or
  heavy (CRS body scan) from the context the protocol pre-checks already
  produce. Heavy requests need one of `heavy_permits` slots (auto reserves
  about half the pool, capped at `pool_size - 1`, keeping reactor workers for
  cheap traffic), wait
  asynchronously up to `queue_timeout_ms` in a bounded `max_queued` queue, and
  fail closed with `503 + Retry-After` on saturation or timeout. Cheap requests
  bypass the queue. New metrics (`waf_admission_*`) and Prometheus alerts cover
  queue depth, admissions, rejections, wait duration and per-class in-flight.
  Inspection is never skipped or reduced. See `docs/coraza-wasi-reactor.md`.

- `memory-soak` (`src/bin/memory_soak.rs`), a direct Coraza reactor memory
  gate with a configurable mixed body workload, RSS/linear-memory sampling,
  and ceilings on peak RSS and post-midpoint growth. The reactor now publishes
  its aggregate wasm linear-memory size (`WasmReactor::linear_memory_bytes`)
  so guest growth is separable from host RSS. Measured 6-worker plateau is
  838 MiB RSS / 480 MiB linear memory over 10 minutes; see
  `docs/coraza-wasi-reactor.md` and
  `docs/operations/performance-validation.md`.

- Descriptor-driven gRPC field-level inspection. The generated allowlist
  artifact now carries an `ir_version` 2 `messages` section with request
  message field metadata (reachable nested messages and enum values, bounded
  to depth 16). A dependency-free protobuf wire decoder in
  `src/waf/protobuf.rs` enforces `[waf.grpc]` field limits
  (`max_string_bytes`, `max_bytes_len`, `max_repeated`, `max_depth`,
  `max_decoded_fields`), optional unknown-field rejection
  (`reject_unknown_fields`), enum membership and basic string sanity checks,
  reporting the fully-qualified field path in the decision reason. Version 1
  artifacts and methods without metadata keep envelope-only behaviour; raw
  protobuf is still never sent to CRS. See `docs/grpc-inspection.md`.

- Experimental native Go Coraza sidecar (`native/coraza-sidecar/`) and Rust
  client (`src/waf/native_coraza.rs`) behind the non-default `coraza-native`
  feature. Selected with `waf.coraza.backend = "native"` and
  `waf.coraza.native_socket_path`; the default remains `wasm`. The sidecar
  reuses the vendored Coraza/OWASP CRS bundle from `wasm/coraza_reactor/` and
  speaks length-prefixed JSON over a Unix domain socket. Removes the ~5–6×
  Go-to-wasm body-inspection penalty (8 KiB p50 358 → 61 ms, 60 KiB 2779 →
  457 ms on the research laptop). See `docs/coraza-native-sidecar.md`.


- Protocol-aware GraphQL-over-HTTP inspection (`src/waf/graphql.rs`,
  `wasm-reactor` feature). Detects `POST` JSON/GraphQL and `GET ?query=`
  requests, parses `query`/`operationName`/`variables`, extracts the operation
  type and a SHA-256 of the normalised query, and enforces operation allowlists
  (name or persisted-query hash, monitor/block), byte/variable/depth/alias/field
  limits, and mutation/subscription policy before Coraza runs. New
  `[waf.graphql]` configuration is validated at load; persisted-query
  allowlists use a documented JSON list of `{name, sha256}` and are loaded once
  at start-up. `waf.graphql.body_scan` selects `crs` (default, full CRS JSON
  body scan), `graphql-only` (wraps the GraphQL checks and withholds the raw
  body from CRS body rules, requires a non-empty allowlist), or `off`.
  `graphql-only` removes ~0.2–1.4 s of JSON body scanning per request at the
  cost of CRS body-rule coverage; header and URI rules still run. Security
  events are emitted for blocks and inspection failures. See
  `docs/graphql-inspection.md`.

- Reproducible end-to-end load-validation harness: `load-validate`
  (`src/bin/load_validate.rs`) starts a mock upstream and a throwaway
  `waf-ingress`, replays a seeded matrix of bodyless, form, gRPC, GraphQL and
  attack traffic at concurrency 1/4/16/64, records p50/p95/p99/RPS/errors/503s/
  RSS, checks decision correctness, and evaluates explicit acceptance gates.
  `scripts/load-validate.sh` builds release, generates the throwaway config and
  writes JSON plus a markdown summary under `/tmp/opencode/load-validation`.
  Measured capacity and gate results are documented in
  `docs/operations/performance-validation.md`.

- Real HTTP/2 gRPC end-to-end coverage. `tests/integration/grpc_h2_e2e.rs`
  starts a TLS HTTP/2 gRPC upstream and a TLS/HTTP2 proxy, then drives unary,
  streaming, malformed-frame, descriptor-policy and gRPC-Web cases with real
  ALPN `h2` / `http/1.1` clients. `scripts/test-grpc-e2e.sh` runs the ignored
  suite. See `docs/architecture/grpc-transport.md`.

- Opt-in gRPC-native WAF rejections via
  `server.grpc_aware_rejections` (default `false`). When enabled, blocked gRPC
  requests receive HTTP 200 with `grpc-status: 7` (PERMISSION_DENIED) for a
  `403` block or `13` (INTERNAL) for other block statuses, plus
  `grpc-message`. The default keeps the historical plain HTTP response.

- Binary wire protocol v1 for the experimental native Coraza sidecar
  (`coraza-native`, still not the default backend). Frames keep the 4-byte
  length prefix and add a fixed 28-byte request header (flags, request-line and
  header lengths, body length, declared and original body size) followed by the
  request line, the header block and the **raw body bytes**, so there is no
  JSON escaping and no base64 for protobuf/binary bodies. Responses are an
  8-byte header plus reason. A `0xC1` handshake negotiates binary v1 and falls
  back to the unchanged JSON envelope for older sidecars, so both directions
  stay compatible. Client and sidecar now allocate less per request (server
  decode 27 → 9 allocations, response encode 2 → 0) and write head + body with
  one `writev`.
- Native sidecar concurrency rework. The Rust client replaces its dedicated
  Tokio runtime, job channel and per-request task with a bounded pool of
  blocking connections (mutex + condvar, socket timeouts plus a post-read
  deadline check). Callers above `pool_size` now wait for a connection until
  `eval_timeout_ms` instead of failing immediately with `QueueFull`; a timed-out
  or failed connection is dropped and replaced. The Go sidecar gains
  `--max-conns` (default 128) admission control, a per-connection reusable
  read buffer, zero-copy body slices and a single-syscall response write.
- `examples/coraza_ipc_profile.rs` (client build / IPC / CRS split) and
  `examples/coraza_native_load.rs` (concurrency 1/4/16/64 × 1/4/8/16 KiB with
  p50/p95/p99 and RPS), plus Go decode/evaluate/encode benchmarks in
  `native/coraza-sidecar/bench_test.go`. `docs/coraza-native-sidecar.md` has a
  new Performance section with the split, the load matrix, capacity guidance
  and the reasoning for not using `SOCK_SEQPACKET`, `io_uring`, batching or
  client-side pipelining.

### Changed

- The WASI Coraza reactor enables CRS phase-1 early blocking
  (`tx.early_blocking=1`, the default of rule 901115) to match the native
  sidecar. Requests whose phase-1 anomaly score already reaches the blocking
  threshold are denied before the request body is scanned: a scanner
  User-Agent with a 60 KiB body drops from 3.2–7.6 s to ~3.8 ms p50 on the
  WASI reactor, and a 60 KiB body can no longer hit the 5 s `eval_timeout_ms`.
  Allow/block decisions are unchanged: all 2 112 cases of the CRS detection
  corpus produce identical decisions before and after, and the release
  `--ignored` reactor and gRPC h2 suites pass. The documented CRS tradeoff is
  that phase-2 alerts for an already-blocked request are not emitted.
  `scripts/vendor-coraza-crs.sh` re-applies the patch and
  `wasm/coraza_reactor/rules/crs/PROVENANCE.md` records the deviation. See
  `docs/coraza-wasi-reactor.md`.
- The native Coraza sidecar enables CRS phase-1 early blocking
  (`tx.early_blocking=1`, rule 900120) by default (`--early-blocking`, opt-out).
  Requests whose phase-1 anomaly score already exceeds the blocking threshold
  are denied before the request body is scanned: a scanner User-Agent with an
  8 KiB body drops from ~61 ms to ~0.3 ms of CPU, and a 60 KiB body from
  ~493 ms to ~0.3 ms. Allow/block decisions are unchanged (verified against the
  SQLi/XSS/LFI/RCE corpus in both query and body form); the documented CRS
  tradeoff is that phase-2 alerts for an already-blocked request are not
  generated. Benign traffic is unaffected. See
  `docs/suggestions_from_agents/crs-performance.md` for the full CRS profile and
  the ranked remaining options.
- The native Coraza sidecar's per-request cost is now protocol-independent: CRS
  scanning is 99.8 %+ of latency at every body size (measured split: 13–18 µs
  client+IPC vs 7.1–114 ms total), so p50 is unchanged and throughput is
  bounded by cores at ~130 KiB of inspected body per second per core. The
  earlier prototype claim of ~46 req/s at 4 KiB was a single-core measurement;
  the same harness reports ~134 req/s at four callers on six cores.

### Performance

- Zero-copy request path between the proxy and the WAF. The proxy now returns
  a single-frame hyper body as its own refcounted `Bytes` instead of copying it
  into a pooled buffer and then copying it again with `to_bytes`; multi-frame
  bodies are coalesced once. The parsed method, URI and header map are moved
  into `RequestContext` and back instead of cloned. A borrowed `RequestView`
  is shared by the encoders, and the native binary v1 encoder writes the URI
  directly into the frame (no `uri.to_string()`) and slices the body from the
  request `Bytes`. The WASI reactor still uses the JSON guest ABI, which is the
  remaining copy on that backend. See `docs/developer-guide/zero-copy-http.md`.

- Coraza WASI reactor tuning pass, with a reusable A/B harness. The
  `coraza_backend_bench` example now reports p95, accepts `CORAZA_MODULE` and
  `CORAZA_POOL_SIZE`, prints compile/warm time and can run a pool-size
  throughput matrix; the Criterion bench covers the documented
  1/4/8/16 KiB body rows. Measurements (documented in
  `docs/coraza-wasi-reactor.md`) found **no steady-state win** from
  `wasm-opt -O3`/`-Oz`, `memory_may_move(false)`, `native_unwind_info(false)`,
  `pooling_allocator` or stack sizing — CRS body cost is inherent Go→wasm
  scanning (a `SinglePass` regalloc control is 1.17–1.85× slower, so the
  method does detect codegen changes). Guest backtraces are now disabled on
  the reactor engine so the fail-closed timeout path does not walk frames or
  retain debug info. Precompiled-module caching was measured at ~5.6 s → ~1.3 s
  start-up but is not shipped (host-specific 40 MB artifact, `unsafe`
  deserialize). Peak RSS is ~65 MiB per pre-warmed worker; the default pool
  size is unchanged. No inspection coverage or default policy changed.

### Fixed

- gRPC field-content scans no longer bypass heavy-inspection admission control.
  Classification now runs **before** the gRPC pre-check on the original request:
  `application/grpc*` with content scanning enabled and decodable descriptor
  metadata is heavy, `content_scan = "off"` and `graphql-only` stay cheap, and
  plain bodies stay heavy. Previously `admission::classify` saw the
  body-stripped context, so every gRPC request was cheap and a 39–705 ms Coraza
  evaluation could occupy reactor workers outside the semaphore. The permit now
  covers the pre-check and the main evaluation, one permit per request, and a
  saturated pool rejects with `503 + Retry-After` before any reactor
  evaluation. Load validation: 4 KiB scans at c=64 went from 2.78 s to 0.40 s
  p95 with excess work rejected, and bodyless p95 under 10% gRPC-scan load
  improved from 491 ms to 52 ms. See
  `docs/operations/performance-validation.md`.
- HTTP/2 ingress with keep-alive enabled now installs a `TokioTimer`; without
  it hyper panicked with "You must supply a timer" on the first HTTP/2
  connection.
- Malformed and oversized gRPC frames now return the frame's own `400`/`413`
  status instead of falling through the fail-closed inspection-error path and
  returning `503`.

## [0.1.0-beta.11] - 2026-11-01

### Added

- gRPC-correct proxy transport. gRPC requests (`application/grpc*`, including
  gRPC-Web) are classified explicitly; unary requests keep trailing headers
  (`grpc-status`, `grpc-message`) across request/response forwarding, including
  empty bodies, and `TE: trailers` / `Trailer` are forwarded instead of being
  stripped. Streaming RPCs (gRPC content type without `content-length`) are
  relayed incrementally without buffering and without WAF body inspection,
  bounded by the new `server.grpc_max_stream_bytes` (default 4 MiB) and
  `server.grpc_max_stream_seconds` (default 300). See
  `docs/architecture/grpc-transport.md`.
- Protocol-aware gRPC inspection (`src/waf/grpc.rs`, `wasm-reactor` feature,
  enabled when Coraza is enabled). gRPC requests are validated before the
  Coraza reactor runs: `content-type` family detection, HTTP/2 `:path`
  (`/package.Service/Method`) against `waf.grpc.method_allowlist`, 5-byte frame
  prefix validation (compressed flag, big-endian length, truncation, message
  size, frame count), `grpc-encoding` (`identity` only), and base64 syntax for
  binary `-bin` metadata (excluded from text scanning). Protobuf bodies are
  withheld from CRS body rules, so large messages no longer hit the 64 KiB
  reactor payload cap; header and URI rules still run. `waf.grpc` is validated
  at config load. Field-level protobuf inspection is not implemented yet (see
  `docs/grpc-inspection.md`).
- Generated gRPC allowlists are now wired into runtime configuration:
  `waf.grpc.allowlist_file` points at the artifact produced by
  `grpc-allowlist`. The artifact's methods are merged with
  `method_allowlist`, its per-method `max_message_bytes` values take
  precedence over the global limit, and its `unknown_method_action` applies
  unless `waf.grpc.unknown_method_action` is set explicitly. The file is
  loaded once at start-up; an unreadable or invalid artifact makes
  `Config::validate` and `WafProxyService::new` fail with the file path and
  reason instead of starting with an empty allowlist. The start-up failure
  message is now the neutral `WAF engine initialisation failed` (covers both
  the Coraza reactor and the gRPC allowlist).
- The real Coraza v3.3.3 WASI reactor, built with Go 1.24 and running on
  wasmtime 49 (pinned Rust 1.99.1), replaces the non-functional reactor spike.
  The reactor is now enabled by default: `wasm-reactor` is part of the default
  Cargo features and `WafCorazaConfig::default().enabled` is `true`. Opt out
  with `waf.coraza.enabled = false` or `--no-default-features`. Start-up module
  or warm-up failures are fatal to `WafProxyService::new` (request-time
  failures remain fail-closed per `waf.fail_mode`), and `validate_startup`
  takes the loaded config without building a second reactor/pool. The
  `WAF_CORAZA_REACTOR_ENABLED` and `WAF_CORAZA_REACTOR_PATH` environment
  escape hatches are removed in favour of `waf.coraza.enabled` and
  `waf.coraza.module_path`.
- OWASP Core Rule Set (CRS) 4.14.0 (commit
  `b5b788b5bc50e68836e17995b191f72e848fed75`) embedded in the Coraza WASI
  reactor, replacing the four starter rules. Coverage is the complete
  request-side CRS: protocol enforcement, LFI/RFI, RCE, PHP/Java/generic
  injection, XSS, SQLi, session fixation and anomaly-score blocking at
  paranoia level 1. Response rules are excluded because response bodies are not
  available over the host ABI; deployment-specific exclusion files, plugins and
  the upstream regression corpus are also excluded. See
  `wasm/coraza_reactor/rules/crs/PROVENANCE.md` and
  `docs/coraza-wasi-reactor.md`.
- Deterministic pre-warmed reactor pool. `WasmReactor::warm()` creates a fixed
  pool of dedicated OS threads (available parallelism clamped to `1..=8`,
  configurable through `waf.coraza.pool_size`; `0` = auto) and blocks until
  every worker has completed Go `_initialize` + Coraza `init`. `evaluate`
  dispatches each payload to an idle worker over a channel, so the first
  production request no longer pays ~0.5 s of initialisation; measured
  first-evaluation latency after warm-up is ~3 ms versus ~2.7 ms steady state,
  with ~15 µs of pool dispatch overhead. Traps discard the worker's instance
  for the next job; a panicking or wedged worker is detected via channel
  disconnect or a reply timeout, returns an error instead of hanging, and is
  replaced. Rule construction warms the pool, so it is the only place that
  pays initialisation.
- Coraza reactor observability behind the `wasm-reactor` feature:
  `waf_coraza_evaluations_total`, `waf_coraza_blocks_total`,
  `waf_coraza_errors_total` and the
  `waf_coraza_evaluation_duration_seconds` histogram. `WasmReactorRule`
  records them through an optional shared metrics registry (`with_metrics`).
- Prometheus alerts for Coraza evaluation error rate and block spikes, using
  only the emitted Coraza metrics.
- Feature-gated Criterion benchmarks for the Coraza WASI reactor
  (`cargo bench --features wasm-reactor --bench coraza`), covering module
  construction and init, allow/SQLi/XSS decisions, and 1 KiB/16 KiB/64 KiB
  request bodies. `scripts/bench-coraza.sh` builds the release library and runs
  them.
- Reactor failures honour `waf.fail_mode`: `503` when closed, log-and-continue
  when open. Start-up failures use the same policy.
- Binary-safe request bodies in the Coraza WASI reactor ABI. The JSON payload
  gains `body_encoding` (`utf8` or `base64`); UTF-8 bodies keep the existing
  fast path and non-UTF-8 bodies (protobuf/gRPC, msgpack, compressed payloads)
  are base64-encoded so invalid bytes are no longer replaced with U+FFFD
  before inspection. `body_size` remains the raw byte length. Payloads that
  omit `body_encoding` are treated as `utf8`. The guest rejects malformed
  base64, unknown encodings and `body_size` mismatches with `eval` code `-5`,
  surfaced as `ReactorError::InvalidBodyEncoding`; the `64 KiB` payload limit
  (and `ReactorError::PayloadTooLarge`) is unchanged, which leaves roughly
  48 KiB of binary body per payload after base64 and JSON overhead.
- Unit coverage for attack blocking (SQLi, XSS, path traversal, command
  injection), benign traffic, disabled configuration, fail-closed/fail-open
  behaviour, reused-instance isolation and concurrent threads.
- `FileDescriptorSet`-driven gRPC allowlist generation:
  `grpc-allowlist` (`src/bin/grpc-allowlist.rs`,
  `scripts/grpc-allowlist.sh`) reads a binary or JSON descriptor set and emits
  a deterministic JSON artifact with paths, streaming flags, input/output
  types, per-message size limits and the descriptor's SHA-256. Supports a
  global `--max-message-bytes` and per-method overrides from a TOML file, and
  fails on malformed descriptors, missing fields, duplicate methods or
  unresolved types. The self-contained loader `waf::grpc_allowlist::load_allowlist`
  validates the artifact for the planned `waf.grpc.allowlist_file` hook; user
  and CI workflow documented in `docs/grpc-inspection.md`.

### Changed

- Heavy WAF evaluation no longer runs on Tokio worker threads.
  `WafEngine::evaluate` is async but its rule chain — including the Coraza
  reactor round-trip, which costs 39–706 ms for a 1–16 KiB body and ~3 s for
  60 KiB — executed inline, so a handful of slow inspections parked every worker
  and stalled unrelated connections. The proxy now calls
  `WafEngine::evaluate_shared`, which acquires admission asynchronously and
  then runs the synchronous stages (protocol pre-checks plus the rule chain) on
  `tokio::task::spawn_blocking` for heavy inspections only. Only an
  `Arc<WafEngine>` and a cloned `RequestContext` (body shared through `Bytes`)
  move into the task, so no engine state is copied per request; the admission
  permit travels into the task and is released when the inspection finishes,
  including after a client disconnect. Inspection order, decisions, metrics and
  audit events are unchanged; `evaluate` remains available for non-`Arc`
  callers and tests.
  `block_in_place` was rejected: it converts the calling worker into a blocking
  thread, cannot observe cancellation while the scan runs, and panics on
  current-thread runtimes. Cheap (no-body) evaluations stay inline — offloading
  them too measured worse for cheap p95 at c=64 with no throughput gain. Load
  validation: end-to-end throughput and latency are unchanged within this
  host's variance (the Coraza reactor, not the worker count, is the binding
  constraint), while an unrelated 1 ms Tokio task's worst delay during six
  concurrent 200 ms inspections drops from 200.4 ms to 4.0 ms. See
  `docs/operations/performance-validation.md`.

- Replaced wasmtime fuel metering in the Coraza WASI reactor with epoch
  interruption and a wall-clock timeout. `waf.coraza.fuel` is removed and
  replaced by `waf.coraza.eval_timeout_ms` (default 5000 ms, validated as
  non-zero). A per-reactor ticker advances the engine epoch every 10 ms; each
  `eval` gets a deadline of `eval_timeout_ms` and `_initialize`/`init` get a
  fixed 60 s budget. A deadline trap surfaces as `ReactorError::Timeout`,
  discards the worker instance, and follows the existing `fail_mode` path. The
  host reply wait is now `eval_timeout_ms + 5 s` instead of a fixed 60 s.
  Removing fuel instrumentation also removes its ~14 % per-block cost.
- Tuned the Go guest's garbage collector at startup with
  `debug.SetGCPercent(600)` and `debug.SetMemoryLimit(64 MiB)`. CRS workload
  allocates about 0.5–1 MiB per 8 KiB body, and the default GC target made
  collections land mid-evaluation (observed 8 KiB p50 ~830 ms versus ~347 ms
  steady state); the larger growth target removes that tail. The soft limit
  was reduced from 192 MiB to 64 MiB after soak testing showed wasm linear
  memory cannot shrink: a 6-worker pool went from >1.4 GiB and still rising to
  a stable ~838 MiB RSS / 480 MiB linear memory plateau, with no measurable
  p50 regression.
- Replaced the `wasmi` interpreter with wasmtime 49 (`wasmtime` +
  `wasmtime-wasi`) for the Coraza WASI reactor. `Engine`/`Module` compile once,
  the preview1 imports come from wasmtime-wasi, and each worker thread keeps a
  cached `Store`/instance/memory with a 256 MiB memory limit. wasmtime-wasi's
  sync preview1 adapters cannot be called inside the proxy's Tokio workers, so
  the stdio/path imports are shadowed with the previous authority-free shims;
  the clock and entropy calls remain wasmtime-wasi's.
- Raised the pinned Rust toolchain to 1.99.1 (rust-overlay updated) because
  wasmtime 49 requires Rust >= 1.96.
- The Coraza reactor module grows to about 20 MiB (from 18 MiB) because it now
  contains the CRS rules and `@pmFromFile` data.

### Performance and limitations

- Measured on the reference machine: bodyless/small-body evaluations cost
  ~2–6 ms, an 8 KiB body ~350 ms and a 60 KiB body ~2.6 s. The ABI payload
  ceiling is 64 KiB.
- Each pre-warmed worker holds roughly 127 MiB RSS, so the default pool (cores
  clamped to `1..=8`) is not free; size `waf.coraza.pool_size` accordingly.
- CRS evaluation through the WASI reactor is **not sub-millisecond**. The
  wasm boundary and Go/CRS work dominate; wasmtime's compiled execution did not
  remove that cost. The traditional Rust heuristic rules remain the cheap
  first line of defence.
- Response bodies are not inspected: the host ABI exposes request data only.

### Release packaging

- Coraza WASI reactor is now a first-class release artifact. The Nix package
  and release container install `coraza_reactor.wasm`, `LICENSE-CRS`,
  `PROVENANCE.md` and `SHA256SUMS` at `/usr/share/waf/wasm/`; the binary
  tarball includes the same files under `wasm/`, and tagged releases attach
  the module, licence and provenance as standalone assets with checksums.
- The CycloneDX SBOM now records the reactor as a `file` component with its
  SHA-256 digest and Apache-2.0 licence note, because `cargo-cyclonedx` only
  inventories Rust crates.
- Startup validation for `wasm-reactor` builds: a missing, malformed,
  oversized or export-incomplete module, failed `_initialize`/`init`, or
  failed pool warm-up aborts startup with a fail-closed error.
  `waf.coraza.module_path` selects the module and `waf.coraza.enabled = false`
  is the documented switch that skips validation and warm-up.
- A 32 MiB module size budget is enforced by the host loader, Nix package,
  container build, release workflow and
  `scripts/check-coraza-reactor-size.sh`. The current module is about 20 MiB;
  the tradeoff is documented in `docs/coraza-wasi-reactor.md`.
- `scripts/vendor-coraza-crs.sh` reproduces the pinned CRS vendoring and
  directive flattening.

### Documentation

- Added `docs/coraza-wasi-reactor.md` covering live wiring, the
  `[waf.coraza]` configuration, failure policy, start-up and per-request
  latency, hardware, benchmark commands and the 64 KiB ABI payload ceiling;
  updated the README security limitations.
- Documented Coraza metrics, alert rules and recording overhead in
  `docs/operations/monitoring.md` and `docs/coraza-wasi-reactor.md`.
- Updated the release checklist, container guide and SBOM notes with the
  stable reactor path, startup validation and size budget.

## [0.1.0-beta.10] - 2026-11-01

### Added

- Request-framing validation on HTTP/1.1, HTTP/2 and HTTP/3 that rejects
  ambiguous or malformed framing before a body is read: `Content-Length` with
  `Transfer-Encoding`, multiple `Content-Length` fields, conflicting
  comma-separated lengths, invalid lengths, and any `Transfer-Encoding` other
  than a single `chunked` token. Rejections return a generic `400`.
- Unit coverage for each request-framing rejection case.
- HTTPS upstream support: the proxy now uses a rustls-backed connector for both
  `http://` and `https://` upstreams over HTTP/1.1 and HTTP/2. HTTPS upstreams
  are verified against the public WebPKI roots, and `proxy.upstream_ca_path`
  adds a private CA bundle as an additional trust root (shared with TLS
  WebSocket upstreams).
- Integration tests for forwarding to a self-signed TLS upstream using
  `proxy.upstream_ca_path`, plus a plain HTTP regression test.
- HTTPS upstream mutual TLS: setting both `proxy.upstream_client_cert_path`
  and `proxy.upstream_client_key_path` presents a PEM client certificate chain
  and key to upstreams. Startup fails with a clear error when only one of the
  pair is configured or when the files are invalid. An integration test covers
  a client-auth-requiring upstream (success with the client certificate, `502`
  without it).
- Bounded `gzip`, `deflate` (zlib-wrapped) and `br` request-body
  decompression before WAF inspection on HTTP/1.1, HTTP/2 and HTTP/3.
  Decompressed output is capped at `server.max_body_size` (`413` when
  exceeded); malformed compressed data returns `400`, unsupported or stacked
  encodings return `415`.
- Integration coverage for decompressed SQLi blocking, clean gzip forwarding,
  malformed gzip, decompression bombs and unsupported/stacked encodings.
- Runtime metrics for API-key authentication failures
  (`waf_auth_failures_total`), rate-limit decisions
  (`waf_rate_limited_total`) and end-to-end request duration
  (`waf_request_duration_seconds` histogram) across HTTP/1.1, HTTP/2 and
  HTTP/3 request paths, with matching Prometheus alert rules and monitoring
  documentation.
- Trivy filesystem and release-image vulnerability scans in the release
  workflow, emitting SARIF and blocking releases on `HIGH`/`CRITICAL` findings.
- Optional `TRIVY=1` filesystem scan stage in `scripts/ci-local.sh`, skipped
  with a warning when Trivy is not installed.

### Changed

- Allowed compressed request bodies are forwarded upstream in their
  decompressed `identity` form. `Content-Encoding` is dropped and
  `Content-Length` is recomputed for the decompressed body.

### Documentation

- Documented the Trivy scan policy, failure thresholds and local reproduction
  commands in `docs/operations/supply-chain.md`, with links from `README.md`
  and `SECURITY.md`.

## [0.1.0-beta.9] - 2026-10-31

### Added

- Feature-gated WebTransport over HTTP/3 terminating endpoint with Origin/path
  allowlists, API-key auth, WAF inspection, session/stream/datagram limits,
  duplicate-session guard, timeouts and metrics.
- Added an isolated `fuzz/` cargo-fuzz workspace with `content_inspection`,
  `websocket_frame` and `config_toml` targets, seed corpora for SQLi/XSS/
  encoded payloads and valid/invalid configurations, and usage/CI guidance in
  `fuzz/README.md`.

### Documentation

- Added the audited WebTransport implementation plan
  (`docs/webtransport-plan.md`).
- Documented release build provenance: tagged releases now publish GitHub
  attestations (`actions/attest-build-provenance`) for the binary tarball, the
  container image tarball and the CycloneDX SBOM, verifiable with
  `gh attestation verify <file> --repo shift/waf-rejected`.
- Added a "verify provenance" section to `SECURITY.md`,
  `docs/operations/release-checklist.md` and `docs/operations/container.md`.
- Added `docs/architecture/security-model.md`: trust boundaries, request
  lifecycle and enforcement points, bypass classes, explicit non-goals,
  deployment assumptions, hardening checklist and audit-evidence sources for
  the current Beta.
- Added environment-gated MaxMind GeoIP integration tests and
  `docs/operations/maxmind-testing.md`, covering database licensing, local
  placement, test environment variables and failure handling. Database files
  are never committed.

## [0.1.0-beta.8] - 2026-10-31

### Added

- Optional custom CA bundle for TLS WebSocket upstreams via
  `proxy.upstream_ca_path`. The PEM bundle is trusted in addition to
  `webpki-roots`; hostname and certificate verification remain enforced.
- Integration test covering a `ws://` client tunnelled to an `https://`
  WebSocket upstream whose certificate is signed by a generated test CA.

## [0.1.0-beta.7] - 2026-10-31

### Added

- Feature-gated HTTP/3 (QUIC) ingress reusing the WAF/auth/rate-limit pipeline.
- TLS 1.3-only QUIC configuration with ALPN `h3` and explicit ring provider.
- Loopback HTTP/3 request test.

### Documentation

- Added `SECURITY.md` with coordinated vulnerability disclosure, supported
  versions, CRA Article 14 reporting timelines and NIS2 incident awareness.
- Added `docs/operations/support-policy.md` covering the support period, patch
  targets, end-of-life and the mapping to CRA manufacturer expectations.
- Added `docs/operations/container.md` covering image tarball loading, digest
  pinning, health/metrics ports, upgrade and rollback.
- Documented that the project is not certified and that compliance reports are
  evidence, not conformity.
- `docs/operations/release-checklist.md` and `docs/operations/container.md`
  now document the automatically attached image tarball and `.sha256`
  checksum assets, including `sha256sum --check` verification steps.

### Added

- Release workflow now generates a CycloneDX SBOM with `cargo cyclonedx`,
  attaches it to the GitHub release and includes it in the binary tarball.
- Release workflow now also exports the pushed container image with
  `docker save` as `waf-rejected-<version>-image.tar.gz`, attaches it to the
  GitHub release and publishes a `.sha256` checksum for the binary tarball,
  the image tarball and the SBOM. GHCR push behaviour is unchanged.

## [0.1.0-beta.6] - 2026-10-31

### Added

- HTTPS/WSS WebSocket upstream support using rustls with `webpki-roots`.
  Plaintext `http://` upstreams continue to work, and unsupported schemes are
  rejected with `502`.

### Fixed

- WebSocket text/binary frames larger than `server.max_body_size` are blocked.

### Documentation

- Documented that the bundled `rules/coraza.wasm` is a Go-JS demo, not a
  Coraza/CRS engine, in `docs/wasm-integration-status.md`.
- Beta.6 release now includes a prebuilt container image tarball.

## [0.1.0-beta.5] - 2026-10-31

### Added

- Per-frame WAF inspection of WebSocket text and binary messages.
- WebSocket frame-block integration test.
- Optional MaxMind GeoIP2 Anonymous IP database loading via
  `waf.geo_blocking.anonymous_database_path` for Tor exit, VPN/proxy and
  datacenter/hosting detection.

## [0.1.0-beta.4] - 2026-10-31

### Added

- MaxMind GeoLite2/GeoIP2 City database loading for real country blocking.
- `waf.geo_blocking.database_path` configuration.

## [0.1.0-beta.3] - 2026-10-31

### Added

- HTTP/1.1 WebSocket upgrade proxying with a raw bidirectional tunnel.
- End-to-end WebSocket integration test.

## [0.1.0-beta.2] - 2026-10-31

### Added

- EU AI Act, NIS2 and CRA evidence-report generators (evidence only, not
  certification).
- `docs/compliance/eu-regulatory-status.md` with the 2026-10-31 validated status
  of Regulation (EU) 2026/1744, NIS2 transposition/amendments and CRA Article 14.
- Container-specific configuration and writable runtime data/log paths.
- Helm PVC for Sled persistence.

### Changed

- PCI report status is now `EVIDENCE GENERATED - ASSESSMENT REQUIRED` instead of
  the misleading `COMPLIANT`.
- `WAF_*` environment variables now override configuration-file values.
- Header inspection is enabled for SQLi/XSS/command/path patterns.
- Alert rules now use metrics the service actually emits.

### Fixed

- UTF-8 boundary panic when truncating matched attack text.
- Over-length URI/query strings are rejected instead of skipping inspection.
- Full accepted request body is inspected, not only the first 1 MiB.
- HTTP/2 is selected from negotiated ALPN, not just `enable_http2`.
- `X-Forwarded-For` is resolved right-to-left across trusted proxies.
- Upstream responses are capped before buffering.
- A configured but unavailable WASM engine fails closed.
- Helm auth default, chart dependencies, GHCR image paths, HTTPS target port and
  Kubernetes persistence wiring corrected.
- Dependency audit cleaned: removed the unused WASM runtime, HTTP/3/QUIC and
  WebTransport stacks and updated live-path crates; `cargo audit` reports
  0 vulnerabilities.

## [0.1.0-beta.1] - 2026-10-31

### Added

- End-to-end request pipeline: URI, query, header and request-body inspection.
- API-key authentication with `X-API-Key` and optional HTTPS enforcement.
- Per-IP and global token-bucket rate limiting.
- Trusted-proxy aware `X-Forwarded-For` / `X-Real-IP` handling.
- Health, readiness and Prometheus metrics endpoints on port 8081.
- Graceful shutdown on `SIGTERM` and `Ctrl+C`.
- Dockerfile, Helm templates and corrected Kubernetes/Prometheus manifests.
- Discoverable integration test target.
- `README.md` and this changelog.

### Changed

- `waf-ingress` now runs the real proxy server (previously a launcher stub).
- Configuration loading is fail-fast and rejects invalid/unsafe settings.
- TLS `min_version`, `max_version` and optional mutual TLS are now enforced.
- `fail_mode = "closed"` now blocks when the WASM/AI stages fail.
- SQLi/XSS detection inspects percent-decoded payloads.
- `max_body_size` is enforced while streaming request bodies.

### Fixed

- Startup panic caused by WASM memory units being treated as megabytes.
- SQLi/XSS detection false negatives caused by the SIMD prefilter.
- Empty arrays being dropped during configuration deserialization.
- Security events not being emitted from the live proxy path.
- WebSocket upgrades returning a fake `101` without a backend tunnel.

### Known limitations

- Coraza/ModSecurity WASM component execution is not implemented; the built-in
  heuristic fallback is used only when `[waf.wasm] enabled = true`.
- WebSocket/WebTransport tunneling is not implemented (returns `501`).
- GeoIP country blocking requires a MaxMind database loader.
- HTTP/3 is not implemented.
