# gRPC transport

The proxy treats gRPC as a first-class HTTP transport. `classify_request()` in
`src/proxy/service.rs` recognises an explicit allowlist of media types:

| Media type |
| --- |
| `application/grpc` |
| `application/grpc+proto` |
| `application/grpc+json` |
| `application/grpc-web` |
| `application/grpc-web+proto` |
| `application/grpc-web+json` |
| `application/grpc-web-text` |
| `application/grpc-web-text+proto` |
| `application/grpc-web-text+json` |

Matching is case-insensitive and parameters such as `; charset=utf-8` are
ignored. The list is deliberately exhaustive rather than a prefix match: an
unknown type that merely starts with `application/grpc` (for example
`application/grpcx` or `application/grpc-malicious`) is **not** gRPC. It is
treated as ordinary HTTP, takes the normal body-inspection path, and never
reaches the gRPC framing parser or gRPC transport shortcuts (no `TE: trailers`
injection, no gRPC-Web framing). This prevents smuggling unknown types into the
gRPC code path while keeping them subject to WAF inspection.

## Unary RPCs

Unary vs streaming is classified from the **actual gRPC frame sequence**, not
from HTTP framing. HTTP/2 does not require `content-length`, so a unary RPC
without one is still unary. `probe_grpc_body()` reads the first length-prefixed
message and checks whether the stream ends (or carries trailers) after it:

* exactly one complete message, then end-of-stream or trailers: **unary**;
* a second message, or a complete first message with the stream still open:
  **streaming**.

A unary body is buffered (subject to `server.max_body_size`), inspected by the
WAF, and forwarded. This includes unary gRPC over HTTP/2 with no
`content-length`; it is never silently forwarded uninspected.

Trailing headers are HTTP body frames (`Frame::trailers`) in hyper 1.x, not
request/response parts. The unary path therefore:

* captures any request trailers while buffering and re-emits them on the
  upstream request,
* captures upstream response trailers while collecting the response body and
  re-emits them after the (possibly empty) data frame.

`grpc-status` and `grpc-message` are preserved even when the response body is
empty, which is the normal unary response shape.

## Streaming RPCs

A genuinely streaming RPC (more than one request message, or a first message
followed by an open stream) is controlled by
`server.grpc_streaming_policy`:

| Value | Behaviour |
| --- | --- |
| `transport-only` (default) | Relay the stream frame by frame without body inspection. Header/URI rules still run. A start-up warning is logged. |
| `reject` | Refuse the RPC with `403` (or a gRPC-aware rejection with `grpc-status: 7` when `server.grpc_aware_rejections = true`). |

`transport-only` is a compatibility default, not a silent bypass: it is
explicitly configured, logged at start-up, and documented here. Streaming
bodies are never passed to the WAF body inspector.

Streaming bodies are relayed through a frame-aware guard that enforces limits
across the **whole** exchange, not per message:

| Key | Default | Meaning |
| --- | --- | --- |
| `server.grpc_max_stream_bytes` | 4 MiB | Maximum raw bytes relayed per streaming exchange |
| `server.grpc_max_stream_seconds` | 300 | Overall deadline for a streaming exchange |
| `server.grpc_max_stream_messages` | 1024 | Maximum request messages in one stream |
| `server.grpc_max_decompressed_bytes` | 10 MiB | Maximum decompressed bytes when `grpc-encoding: gzip` |

All must be greater than zero; `Config::validate()` rejects zero values.
`grpc-encoding` accepts `identity` and `gzip`; any other encoding is rejected
with `400`. Gzip frames are decompressed only to validate the bound; the
original compressed bytes are forwarded unchanged. A gzip bomb is rejected as
soon as the decompressed total exceeds the cap.

The response body is still bounded by `grpc_max_stream_bytes` and
`grpc_max_stream_seconds`.

## HTTP/2 and ALPN

HTTP/2 is used only when TLS ALPN negotiates `h2`; cleartext listeners speak
HTTP/1.1 (no h2c prior knowledge). The HTTP/2 server builder installs a
`TokioTimer` because keep-alive intervals require one. Upstream HTTPS
connections negotiate `h2` through the same ALPN list, so a gRPC request can
arrive over HTTP/2 and be forwarded to an HTTP/2 upstream without protocol
downgrade.

## Verified transport matrix

`tests/integration/grpc_h2_e2e.rs` starts a real TLS HTTP/2 gRPC upstream, a
TLS/HTTP2 `WafProxyService`, and real ALPN `h2` / `http/1.1` clients. Run it
with `./scripts/test-grpc-e2e.sh` (the tests are `#[ignore]`d by default
because they bind local ports and generate certificates).

| Case | Client | Result |
| --- | --- | --- |
| Unary echo, `te: trailers` | HTTP/2 + ALPN h2 | Body echoed; `grpc-status: 0` / `grpc-message` trailers preserved |
| Unary with empty response body | HTTP/2 + ALPN h2 | `grpc-status` / `grpc-message` trailers preserved |
| Unary without `content-length` | HTTP/2 + ALPN h2 | Buffered and inspected; SQLi/XSS in a declared field is blocked |
| Streaming request (two messages) | HTTP/2 + ALPN h2 | Relayed frame by frame; request and response trailers preserved |
| Streaming with `grpc_streaming_policy = "reject"` | HTTP/2 + ALPN h2 | `403`, or `grpc-status: 7` with gRPC-aware rejections; upstream not called |
| Gzip-compressed frame | HTTP/2 + ALPN h2 | Decompressed for inspection under `max_decompressed_bytes`; original bytes forwarded |
| Gzip bomb | HTTP/2 + ALPN h2 | `413` before the upstream is called |
| Malformed frame (truncated prefix) | HTTP/2 + ALPN h2 | `400` before the upstream is called |
| Oversized frame | HTTP/2 + ALPN h2 | `413` before the upstream is called |
| SQLi/XSS text in a declared protobuf string field | HTTP/2 + ALPN h2 | `403` (or gRPC-aware rejection): decoded field content is scanned by Coraza via a synthetic form payload |
| Benign text in a declared protobuf string field | HTTP/2 + ALPN h2 | Allowed; `grpc-status: 0` |
| SQLi text with `waf.grpc.content_scan = "off"` | HTTP/2 + ALPN h2 | Allowed: structural-only behaviour preserved |
| SQLi text in an undeclared field with `reject_unknown_fields` | HTTP/2 + ALPN h2 | `400` by descriptor policy |
| gRPC-Web binary framing | HTTP/1.1 + ALPN http/1.1 | Body-encoded trailer frame forwarded unchanged |

Malformed and oversized frames are client errors: the gRPC inspector maps
`FrameError::status()` (`400`/`413`) directly instead of taking the fail-closed
`503` inspection-error path.

## Field-content scanning

After structural protobuf validation, the inspector collects decoded `string`
and UTF-8 `bytes` values (bounded by `waf.grpc.max_content_scan_bytes`, default
64 KiB) and evaluates them through the same Coraza backend as a synthetic
`application/x-www-form-urlencoded` request with URI
`/__grpc__/package.Service/Method`. The raw protobuf body is never sent to CRS.
The direct backend call bypasses the gRPC pre-check, so there is no recursion.
A block is returned as `403` (or a gRPC-aware rejection when
`server.grpc_aware_rejections = true`) with the field paths in the reason.
`waf.grpc.content_scan = "off"` disables the extra evaluation. See
[gRPC inspection](../grpc-inspection.md#field-content-scanning).

## gRPC-aware rejections

By default a WAF block is a plain HTTP response (`403 text/plain` for a policy
block). Set `server.grpc_aware_rejections = true` to return a gRPC-native
rejection for blocked gRPC requests instead:

* HTTP `200` with `content-type: application/grpc`,
* `grpc-status: 7` (PERMISSION_DENIED) for a `403` block,
* `grpc-status: 13` (INTERNAL) for any other block status,
* `grpc-message` carrying the WAF reason,
* an empty body with the status fields as trailers.

The flag defaults to `false`, so existing deployments keep the historical
plain-HTTP behaviour. Non-gRPC traffic is unaffected.

## HTTP/1.1 framing

HTTP/2 carries trailers natively. HTTP/1.x requires chunked framing plus two
headers that hyper honours:

* `TE: trailers` on the request signals that the peer accepts trailing fields.
  It is forwarded for gRPC requests and added when the client omitted it.
* `Trailer: <field names>` announces which trailing fields will follow. It is
  forwarded unchanged. For buffered bodies the proxy derives it from the
  actual trailer names; for streaming responses it announces
  `grpc-status, grpc-message`.

`Trailer` and `TE` are end-to-end fields for gRPC and are deliberately not
treated as hop-by-hop headers. Because hyper's HTTP/1.1 server only writes
trailing fields that the downstream request advertised via `TE: trailers`,
clients must send that header (real gRPC clients do).

gRPC-Web also carries trailers inside the response body frame encoding; those
bytes are opaque to the proxy and are forwarded unchanged.

## Non-gRPC traffic

HTTP/1.0, HTTP/1.1, HTTP/2, HTTP/3, WebSocket upgrades and WebTransport
handling are unchanged. HTTP/3 responses keep streaming trailers via
`send_trailers`.
