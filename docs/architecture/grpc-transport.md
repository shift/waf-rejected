# gRPC transport

The proxy treats gRPC as a first-class HTTP transport. Requests whose
`content-type` starts with `application/grpc` (including `+proto`, `+json`,
`application/grpc-web` and `application/grpc-web-text`) are classified as gRPC
by `classify_request()` in `src/proxy/service.rs`.

## Unary RPCs

A gRPC request that carries a `content-length` is assumed to be a single,
complete unary message. It follows the normal pipeline: the body is buffered
(subject to `server.max_body_size`), inspected by the WAF, and forwarded.

Trailing headers are HTTP body frames (`Frame::trailers`) in hyper 1.x, not
request/response parts. The unary path therefore:

* captures any request trailers while buffering and re-emits them on the
  upstream request,
* captures upstream response trailers while collecting the response body and
  re-emits them after the (possibly empty) data frame.

`grpc-status` and `grpc-message` are preserved even when the response body is
empty, which is the normal unary response shape.

## Streaming RPCs

A gRPC request without `content-length` is treated as a streaming RPC. Its body
is **not** buffered and is passed through frame by frame in both directions,
including trailers. Streaming RPCs are **transport-only**: the WAF still
evaluates request headers and the request URI, but there is no body inspection
for the stream. This is documented behaviour, not a silent bypass — a streaming
request can never reach the body-inspection stage.

Two limits bound a streaming exchange, applied to both the request and the
response body:

| Key | Default | Meaning |
| --- | --- | --- |
| `server.grpc_max_stream_bytes` | 4 MiB | Maximum bytes relayed per streaming exchange |
| `server.grpc_max_stream_seconds` | 300 | Overall deadline for a streaming exchange |

Both must be greater than zero; `Config::validate()` rejects zero values.

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
| Streaming request (no `content-length`) | HTTP/2 + ALPN h2 | Relayed frame by frame; request and response trailers preserved |
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
