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
