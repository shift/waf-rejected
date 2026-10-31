# Changelog

All notable changes to WAF-Rejected are documented here.

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
