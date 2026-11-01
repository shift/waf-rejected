# Changelog

All notable changes to WAF-Rejected are documented here.

## [Unreleased]

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
- The Coraza WASI reactor is now enabled by default: `wasm-reactor` is part of
  the default Cargo features and `WafCorazaConfig::default().enabled` is
  `true`. Default start-up compiles the ~20 MiB module once (~4.5 s) and warms
  the reactor pool (~1.1 s) before readiness; measured steady-state cost is
  ~8–10 ms p50 per request with the full CRS. Opt out with
  `waf.coraza.enabled = false` or `--no-default-features`. Start-up module or
  warm-up failures are now fatal to `WafProxyService::new` (request-time
  failures remain fail-closed per `waf.fail_mode`), and `validate_startup`
  takes the loaded config without building a second reactor/pool. The
  `WAF_CORAZA_REACTOR_ENABLED` and `WAF_CORAZA_REACTOR_PATH` environment
  escape hatches are removed in favour of `waf.coraza.enabled` and
  `waf.coraza.module_path`.
- Coraza reactor observability behind the `wasm-reactor` feature:
  `waf_coraza_evaluations_total`, `waf_coraza_blocks_total`,
  `waf_coraza_errors_total` and the
  `waf_coraza_evaluation_duration_seconds` histogram. `WasmReactorRule`
  records them through an optional shared metrics registry
  (`with_metrics`).
- Prometheus alerts for Coraza evaluation error rate and block spikes, using
  only the emitted Coraza metrics.
- Feature-gated Criterion benchmarks for the Coraza WASI reactor
  (`cargo bench --features wasm-reactor --bench coraza`), covering module
  construction and init, allow/SQLi/XSS decisions, and 1 KiB/16 KiB/64 KiB
  request bodies. `scripts/bench-coraza.sh` builds the release library and runs
  them.
- Live integration of the real Coraza WASI reactor, default-on when the
  `wasm-reactor` feature is compiled (the default). `waf.coraza.enabled`
  registers the reactor before the traditional heuristic rules; `module_path`
  selects a module file and `None` uses the embedded reactor. Payload, memory
  and fuel limits are validated at config load.
- Reactor failures honour `waf.fail_mode`: `503` when closed, log-and-continue
  when open. Start-up failures use the same policy.
- Unit coverage for attack blocking (SQLi, XSS, path traversal), benign
  traffic, disabled configuration, and fail-closed/fail-open behaviour.
  Release-mode latency measurement reported in `docs/coraza-wasi-reactor.md`.

### Changed

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
  `debug.SetGCPercent(600)` and `debug.SetMemoryLimit(192 MiB)`. CRS workload
  allocates about 0.5–1 MiB per 8 KiB body, and the default GC target made
  collections land mid-evaluation (observed 8 KiB p50 ~830 ms versus ~347 ms
  steady state); the larger growth target and a soft limit below the 256 MiB
  store cap remove the tail without raising 60 KiB steady-state cost.
- Coraza WASI reactor instances are reused instead of being created per
  request, and start-up is now deterministic. `WasmReactor::warm()` creates a
  fixed pool of dedicated OS threads (available parallelism clamped to `1..=8`,
  configurable through `waf.coraza.pool_size`; `0` = auto) and blocks until
  every worker has completed Go `_initialize` + Coraza `init`. `evaluate`
  dispatches each payload to an idle worker over a channel, so the first
  production request no longer pays ~0.5 s of initialisation; measured
  first-evaluation latency after warm-up is ~3 ms versus ~2.7 ms steady state,
  with ~15 µs of pool dispatch overhead. Traps/fuel exhaustion discard the
  worker's instance for the next job; a panicking or wedged worker is detected
  via channel disconnect or a 60 s reply timeout, returns an error instead of
  hanging, and is replaced. Rule construction (engine start-up) warms the
  pool, so it is the only place that pays initialisation; `validate_startup()`
  only checks the module source and size budget without a second compile.
  `clear_thread_cache()` is removed because instances are pool-owned. Criterion
  p50 for allow/SQLi/XSS drops from ~61–63 ms to ~2.1–3.0 ms on the reference
  machine.
- Replaced the `wasmi` interpreter with wasmtime 49 (`wasmtime` +
  `wasmtime-wasi`) for the Coraza WASI reactor. `Engine`/`Module` compile once,
  the preview1 imports come from wasmtime-wasi, and each worker thread keeps a
  cached `Store`/instance/memory with fuel and 256 MiB memory limits.
  wasmtime-wasi's sync preview1 adapters cannot be called inside the proxy's
  Tokio workers, so the stdio/path imports are shadowed with the previous
  authority-free shims; the clock and entropy calls remain wasmtime-wasi's.
- Raised the pinned Rust toolchain to 1.99.1 (rust-overlay updated) because
  wasmtime 49 requires Rust >= 1.96.
- Added reused-instance and per-thread isolation tests for the reactor,
  covering interleaved allow/block decisions and three concurrent threads.

### Documentation

- Documented Coraza metrics, alert rules and recording overhead in
  `docs/operations/monitoring.md` and `docs/coraza-wasi-reactor.md`.
- Added measured p50/mean latency and throughput for the Coraza WASI reactor to
  `docs/coraza-wasi-reactor.md`, including hardware, command and the 64 KiB ABI
  payload ceiling.
- Documented the live wiring, `[waf.coraza]` configuration, failure policy and
  observed reactor latency in `docs/coraza-wasi-reactor.md`; updated the README
  security limitations. The reactor is enabled by default and documents the
  measured start-up and per-request cost.
- Embedded OWASP Core Rule Set (CRS) 4.14.0 (commit
  `b5b788b5bc50e68836e17995b191f72e848fed75`) in the Coraza WASI reactor,
  replacing the four starter rules. Coverage is the complete request-side CRS:
  protocol enforcement, LFI/RFI, RCE, PHP/Java/generic injection, XSS, SQLi,
  session fixation and anomaly-score blocking at paranoia level 1. Response
  rules are excluded because response bodies are not available over the host
  ABI; deployment-specific exclusion files, plugins and the upstream regression
  corpus are also excluded. See `wasm/coraza_reactor/rules/crs/PROVENANCE.md`
  and `docs/coraza-wasi-reactor.md`.
- `scripts/vendor-coraza-crs.sh` reproduces the pinned CRS vendoring and
  directive flattening.
- Reactor tests now cover SQLi, XSS, path traversal, command injection and two
  benign false-positive cases.

### Changed

- The Coraza reactor module grows to about 20 MiB (from 18 MiB) because it now
  contains the CRS rules and `@pmFromFile` data. The reactor fuel budget and
  wasmi recursion depth are raised to 200 billion and 1024 respectively so the
  larger rule bundle can initialise and evaluate.

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
  `scripts/check-coraza-reactor-size.sh`. The current module is about 18 MiB;
  the tradeoff is documented in `docs/coraza-wasi-reactor.md`.

### Documentation

- Updated `docs/coraza-wasi-reactor.md`, the release checklist, container guide
  and SBOM notes with the stable reactor path, startup validation and size
  budget.

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
