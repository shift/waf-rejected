# Copilot Instructions for this Repository

We don't use docker-compose, docker or podman, any OCI images are build via Nix.

We develop on NixOS and all commands need to be provided via nix, eg. nix develop -c <commnad>, maintain the flake.nix to allow the build envrionment to work.

This repository is a high-performance Rust WAF ingress supporting HTTP/1.1, HTTP/2, HTTP/3, WebSocket, and experimental WebTransport.

Follow these guidelines when generating code, tests, docs, or refactors.

## Project context
- Language: Rust 2021
- Runtime: tokio
- HTTP stack: hyper (1.x), hyper-util, http-body-util
- HTTP/3/QUIC: h3, h3-quinn, quinn (feature: `http3`)
- TLS: rustls, tokio-rustls (prefer rustls over OpenSSL)
- WebSocket: tokio-tungstenite + tungstenite (feature: `websocket`)
- WAF engine: `WafEngine` with `fast_evaluate(RequestContext)` returning `Decision`
- Important modules: `src/proxy`, `src/waf`, `src/modsecurity`

## Performance priorities
- Hot paths must minimize allocations and copies.
  - Pre-allocate with `HeaderMap::with_capacity(...)` and `Vec::with_capacity(...)`.
  - Cache static values using `OnceLock`.
- Prefer early-return fast paths for small/safe inputs.
- Avoid blocking calls; use async I/O and backpressure-friendly sinks.
- Batch where it helps throughput (e.g., WebSocket message batches of ~16).
- Reuse buffers/contexts across loops; clear instead of reallocating.

## Security and correctness
- Always run requests/messages through the WAF where applicable.
  - Use `WafEngine::fast_evaluate(&RequestContext)`.
  - Construct `RequestContext` with client IP, method, URI, headers, and optional body length.
- Respect `Decision`:
  - `Allow` → continue (echo/forward)
  - `Block { status, reason }` → return blocked response with reason
  - `RateLimit { reason }` → return 429 with `retry-after`
- WebSocket control frames (`Close`, `Ping`, `Pong`) should be allowed immediately.
- Do not log sensitive data; use structured `tracing` (info/warn/error) sparingly in hot paths.

## Protocol-specific guidance
- HTTP
  - Use hyper 1.x types and `http-body-util` for bodies.
  - Keep compatibility with features: `http3` optional.
- TLS
  - Prefer rustls; avoid introducing OpenSSL-based deps when possible.
- WebSocket
  - Use `tokio_tungstenite` streams; split into sender/receiver.
  - Fast path: small text (<1KB) without suspicious characters → allow.
  - Small binary (<512B) → allow.
  - Batch processing with short timeout (e.g., 10ms) for throughput.

## Coding conventions
- Error handling: `anyhow` in binaries/ops; `thiserror` for library errors.
- Logging: `tracing` + `tracing-subscriber`; avoid string formatting on cold paths.
- Config: respect `Config` where provided; avoid hard-coded ports/paths.
- Features:
  - Keep optional features guarded (`wasm-waf`, `http3`, `websocket`, `export-system`).
  - Don’t break default feature set in `Cargo.toml`.
- Style: idiomatic Rust, small focused functions, early returns, no unwraps in hot paths.

## Testing & benchmarks
- Use async tests with `tokio::test` where applicable.
- Provide integration tests under `tests/` mirroring existing layout.
- Prefer deterministic tests; avoid network flakiness when possible.
- For perf tests/benches, ensure they compile under `--release` and don’t require external services.

## Repository hygiene
- Keep public APIs documented; use rustdoc comments for key types.
- Prefer small PR-sized changes; include rationale in comments when adding low-level optimizations.
- Don’t introduce new top-level binaries unless they’re clearly useful (tests/benchmarks are okay).

## When in doubt
- Favor performance and safety.
- Reuse existing helpers: `RequestContext`, `Decision`, response builders in `websocket.rs`.
- Mirror existing patterns (e.g., header extension, fast_evaluate usage, batching).

## Examples to emulate
- Pre-allocating headers:
  - `let mut headers = HeaderMap::with_capacity(2);`
- Static caching:
  - `static DEFAULT_IP: OnceLock<IpAddr> = OnceLock::new();`
- Fast path for WebSocket text:
  - `if text.len() < 1024 && !text.contains(&['<','>','\'', '"',';','&'][..]) { return Ok(Decision::Allow); }`

Adhere to these instructions to keep contributions consistent, fast, and secure.
