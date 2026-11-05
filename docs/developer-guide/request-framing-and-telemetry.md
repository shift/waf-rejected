# Request framing, decompression and completion telemetry

This page documents the ingress hardening that runs before WAF body inspection:
protocol-specific framing checks, gzip member handling, trusted-proxy client IP
resolution, and the single request-completion path.

## Framing rules by protocol

| Input | HTTP/1.0 and HTTP/1.1 | HTTP/2 | HTTP/3 |
| --- | --- | --- | --- |
| `Content-Length` | One unambiguous value; repeated identical values accepted | Same | Same |
| Conflicting `Content-Length` values | Rejected (`400`) | Rejected (`400`) | Rejected (`400`) |
| `Transfer-Encoding: chunked` | Accepted | Rejected | Rejected |
| `Content-Length` + `Transfer-Encoding` | Rejected | Rejected | Rejected |
| `Connection`, `Keep-Alive`, `Proxy-Connection`, `Upgrade` | Allowed (HTTP/1.1 semantics) | Rejected | Rejected |
| Framing fields in trailers | Rejected | Rejected | Rejected |

`Content-Length` is parsed as a decimal `u64`. Empty, negative, fractional,
hexadecimal and comma-list values with an empty member are rejected. Repeated
header fields and comma-separated list members are accepted only when every
value is identical; any disagreement is treated as a smuggling attempt.

HTTP/2 and HTTP/3 use DATA-frame lengths, so `Transfer-Encoding` is never
valid there. The protocol-specific check runs before the shared HTTP/1.x
validator. Trailer blocks are checked after the body is read: `Content-Length`,
`Transfer-Encoding`, `Trailer`, `Connection`, `Keep-Alive`,
`Proxy-Connection` and `Upgrade` are rejected. End-to-end trailers such as
`grpc-status` and `grpc-message` are still forwarded.

## Gzip decompression

`Content-Encoding: gzip` is decoded with `flate2::read::MultiGzDecoder`:

- every concatenated gzip member is decoded and inspected;
- trailing bytes that are not another valid gzip member are rejected as
  malformed (`400`);
- a stream that fails late (truncated trailer, bad CRC, corrupt deflate data)
  is rejected, not partially accepted;
- the decompressed output remains capped at `server.max_body_size`.

`deflate` (zlib) and `br` keep their existing single-stream decoders. Stacked
codings such as `gzip, gzip` are rejected rather than decoded recursively.

## Client IP through trusted proxies

`server.trusted_proxies` is the only way to make `X-Forwarded-For` or
`X-Real-IP` authoritative. The immediate socket peer is used for every other
connection.

For a trusted peer, `X-Forwarded-For` is parsed as a comma-separated chain and
walked from right to left. Hops that are themselves trusted proxies are
skipped, so the first untrusted address is the client. This supports multiple
proxies in front of the WAF:

```text
client, edge-proxy, regional-proxy  ->  WAF peer
        ^ first untrusted hop from the right is the client
```

If every hop is a trusted proxy, there is no client address in the chain and
the immediate peer is used. If any entry is malformed (non-IP, empty member or
non-UTF-8 value), the whole `X-Forwarded-For` header is discarded, the
immediate peer is used, and a warning is logged with
`reason="malformed_x_forwarded_for"`. A malformed `X-Real-IP` behaves the same
with `reason="malformed_x_real_ip"`. The proxy never silently drops only the
bad entry and continues with a partially trusted chain.

Deployment example:

```toml
[server]
trusted_proxies = ["10.0.0.0/8", "192.168.0.0/16"]
```

List only the exact load-balancer/proxy CIDRs. Do not add client networks: a
client that can reach the WAF directly could then spoof its own address.

## Request-completion telemetry

`RequestTelemetry` is created once at the start of every HTTP/1.x, HTTP/2 and
HTTP/3 request. It records `waf_requests_total` immediately and records exactly
one `waf_request_duration_seconds` observation when the request future returns,
including early rejections, body-read errors, body timeouts and WebSocket
tunnels. New early returns cannot skip the duration histogram.

Rejections also carry a stable reason in the structured completion log
(`unsupported_http_version`, `invalid_framing`, `invalid_trailer_framing`,
`authentication`, `body_too_large`, `body_read_error`, `body_timeout`,
`unsupported_content_encoding`, `decompressed_too_large`,
`malformed_compression`, `waf_blocked`, `waf_rate_limited`, and the fast-allow
variants). Aggregate counters remain `waf_blocked_total`,
`waf_auth_failures_total` and `waf_rate_limited_total`.
