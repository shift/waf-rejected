# Changelog

All notable changes to WAF-Rejected are documented here.

## [Unreleased]

### Added

- HTTPS upstream support: the proxy now uses a rustls-backed connector for both
  `http://` and `https://` upstreams over HTTP/1.1 and HTTP/2. HTTPS upstreams
  are verified against the public WebPKI roots, and `proxy.upstream_ca_path`
  adds a private CA bundle as an additional trust root (shared with TLS
  WebSocket upstreams).
- Integration tests for forwarding to a self-signed TLS upstream using
  `proxy.upstream_ca_path`, plus a plain HTTP regression test.
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

### Changed

- Allowed compressed request bodies are forwarded upstream in their
  decompressed `identity` form. `Content-Encoding` is dropped and
  `Content-Length` is recomputed for the decompressed body.

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
