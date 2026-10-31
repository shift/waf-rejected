# Changelog

All notable changes to WAF-Rejected are documented here.

## [0.1.0-beta.3] - 2026-10-31

### Added

- HTTP/1.1 WebSocket upgrade proxying with a raw bidirectional tunnel.
- End-to-end WebSocket integration test.
- MaxMind GeoLite2/GeoIP2 City database loading for real country blocking.
- `waf.geo_blocking.database_path` configuration.

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
