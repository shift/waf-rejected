# WebTransport Implementation Plan

**Status:** not implemented. HTTP/1.1 `Upgrade: webtransport` remains `501`.

## Dependencies and feature

```toml
wtransport = { version = "0.7.2", optional = true, default-features = false, features = ["ring", "quinn"] }
webtransport = ["dep:wtransport"]
```

The release build should add `--features webtransport` alongside `http3`.
`TlsManager::quic_server_config` must be available for `any(http3, webtransport)`
and use ALPN `h3`.

## Configuration

Add `ServerConfig.webtransport`:

- `enabled = false`
- `bind_addr` (default `0.0.0.0:4434`, must differ from the HTTP/3 UDP port)
- `require_origin = true`
- `allowed_origins` (empty means deny all)
- `allowed_paths`
- `max_sessions`, `max_sessions_per_ip`
- `max_bidi_streams`, `max_uni_streams`
- `max_datagram_bytes`, `max_stream_bytes`
- `idle_timeout_secs`, `max_session_secs`
- `inspect_streams`, `inspect_datagrams`

## Integration

- New `src/proxy/webtransport.rs`, feature-gated, spawned from
  `WafProxyService::start_with_listener` like `http3::serve`.
- Use `wtransport::Endpoint::server` + `accept()` / `SessionRequest`.
- Before `accept()`: exact Origin allowlist (reject missing Origin when
  required), path allowlist, API-key auth, trusted-proxy peer resolution,
  session caps, WAF evaluation of CONNECT headers.
- After accept: cap bidi/uni streams, stream bytes, datagram size, idle time and
  total session duration; inspect the first N bytes of streams/datagrams up to
  `max_body_size`; on WAF block, `close(403)` and never forward.
- Disable migration and 0-RTT. Reject duplicate authenticated sessions keyed on
  `(client_ip, stable_id/session_id)` with a TTL guard.
- Add session/stream/datagram counters to `metrics.rs`.

## Important design decision

WebTransport is a **terminating** endpoint, not an HTTP request/response proxy.
There is no upstream HTTP framing to reuse. The first implementation should
terminate and inspect sessions locally, document that clearly, and only then
consider application-specific upstream bridging.

## Tests

- Unit: origin/path validation, config rejects colliding UDP ports, TLS 1.3/ALPN
  enforcement, limits.
- Integration (feature-gated, `wtransport` client + self-signed identity):
  allowed session, bad Origin 403, missing API key 401, oversized datagram/stream
  blocked, per-IP session cap 429.
- Run existing WebSocket and HTTP/3 suites with `--features webtransport`.

## Scope and risks

~1,000–1,400 LOC (2–3 days). Main risks:

1. `wtransport`/quinn/rustls provider and ALPN compatibility.
2. No natural upstream mapping; WAF body semantics must be defined.
3. UDP port collision with HTTP/3 and unauthenticated QUIC handshake floods.
