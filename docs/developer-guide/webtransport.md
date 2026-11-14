# WebTransport (HTTP/3) Ingress

**Status:** implemented behind the non-default `webtransport` feature.

WebTransport is a *terminating* endpoint. Sessions are authenticated, validated,
and inspected locally; stream and datagram payloads are never forwarded to an
upstream. Bidirectional streams are echoed back, bounded by `max_stream_bytes`,
so the listener can be verified without an application-specific upstream
bridge. HTTP/1.1 `Upgrade: webtransport` is still rejected with `501`.

## Build

```sh
nix develop -c cargo build --release --features http3,webtransport
```

The `webtransport` feature pulls in `wtransport = "0.7.2"` (ring provider,
quinn re-export). It is not part of the default features.

## Configuration

```toml
[server.webtransport]
enabled = true
bind_addr = "0.0.0.0:4434"          # must not collide with the HTTP/3 UDP port
require_origin = true
allowed_origins = ["https://app.example.com"]  # empty denies all
allowed_paths = ["/echo", "/api/*"]            # empty denies all
max_sessions = 1024
max_sessions_per_ip = 32
max_bidi_streams = 16
max_uni_streams = 16
max_datagram_bytes = 1200
max_stream_bytes = 1048576
idle_timeout_secs = 30
max_session_secs = 300
inspect_streams = true
inspect_datagrams = true
```

`server.webtransport.enabled` requires `server.tls.enabled = true` and
`server.tls.max_version = "1.3"`. Validation also rejects a UDP port collision
with the HTTP/3 listener.

## Request pipeline

1. QUIC handshake completes; global session cap is checked before the handshake
   is awaited, and the raw peer address is used for early admission.
2. `Origin` must exactly match an `allowed_origins` entry when
   `require_origin = true` (normalized scheme/host/default port; empty allowlist
   denies all).
3. `:path` must match `allowed_paths` (exact, or prefix with a trailing `/*`).
4. API-key authentication runs against the CONNECT headers.
5. The client IP is the QUIC peer address unless that peer is a configured
   trusted proxy, in which case `X-Forwarded-For` is honoured.
6. The WAF evaluates a synthetic `https://<authority><path>` request with
   `x-waf-protocol: webtransport` and `x-waf-method: CONNECT`. It is submitted
   as a body-less `POST` because the default `dangerous_methods` rule blocks
   every HTTP `CONNECT`; WebTransport's CONNECT establishes a session and is
   not an HTTP tunnel.
7. Global and per-IP session caps, then duplicate `(client_ip, stable_id)`
   detection with a TTL guard.

Rejections before acceptance use the WebTransport CONNECT response: `403` for
Origin/path/WAF failures and `429` for session caps. WebTransport has no `401`
CONNECT response, so an authentication failure accepts the session and closes
it with application code `401` before any stream is read.

After acceptance:

- QUIC migration is disabled (`allow_migration(false)`). 0-RTT is not enabled by
  quinn/wtransport on the server side.
- Concurrent bidirectional/unicast streams are capped in the QUIC transport
  config; datagrams and streams larger than their configured limits close the
  session with `413`.
- Stream and datagram payloads are inspected through the WAF when the `inspect_*`
  flags are set; a block closes the session with `403`.
- Reads are bounded by `idle_timeout_secs`; the whole session is bounded by
  `max_session_secs` (`408` close).
- Metrics: `waf_webtransport_sessions_total`, `waf_webtransport_allowed_total`,
  `waf_webtransport_blocked_total`, `waf_webtransport_streams_total`,
  `waf_webtransport_datagrams_total`.

## Tests

- Unit tests cover Origin/path normalization and allowlists, limit validation,
  TLS 1.3/ALPN `h3`, UDP port collision, and session registry caps.
- Feature-gated integration tests (`tests/integration/webtransport_tests.rs`)
  start a real listener with a self-signed identity and verify the bounded echo
  and Origin rejection.

```sh
nix develop -c cargo test --lib --features webtransport
nix develop -c cargo test --test integration --features webtransport
```

## Manual verification

```sh
# Terminal 1: run the WAF with a WebTransport-enabled config
nix develop -c cargo run --features http3,webtransport --bin waf-ingress

# Terminal 2: connect with a wtransport client (self-signed cert)
#   Endpoint::client(ClientConfig::builder()
#       .with_bind_default(0)
#       .with_no_cert_validation()
#       .build())
#   .connect(ConnectOptions::builder("https://127.0.0.1:4434/echo")
#       .add_header("origin", "https://app.example.com")
#       .build())
# Open a bidirectional stream, write bytes, and confirm the echo.
# Repeat with a disallowed Origin and confirm the 403 CONNECT rejection.
```

## Known limitations

- No upstream bridging: application-specific WebTransport protocols are not
  proxied. Only the bounded echo behavior is provided for verification.
- A missing/invalid API key is reported as a `401` application close rather than
  a CONNECT response because WebTransport only defines `403`/`404`/`429`.
- Datagram inspection is limited to datagrams that fit in a QUIC datagram
  (typically <= 1200 bytes).
