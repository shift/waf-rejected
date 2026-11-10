# Zero-copy request path (proxy → WAF)

This document maps the request path from hyper to the Coraza backend and records
where bytes used to be copied. It covers the changes on `feat/zero-copy-http`.

## Request path

1. **hyper ingress** — `WafProxyService::handle` receives `Request<Incoming>`.
   The first body frame is already a refcounted `bytes::Bytes`.
2. **body buffering** — `BufferPool::read_incoming_body_bytes` streams the body
   and enforces `server.max_body_size` while reading. A single-frame body (the
   common case for ≤ 64 KiB) is returned as the frame's own `Bytes`; a
   multi-frame body is coalesced once into a `BytesMut` and frozen. The old path
   copied every chunk into a pooled buffer and then copied the whole body again
   with `PooledBuffer::to_bytes`.
3. **request context** — the proxy moves the parsed method, URI and header map
   into `RequestContext` (no `HeaderMap` clone) and moves them back after
   evaluation for the upstream forward.
4. **WAF rule chain** — `RequestContext::view()` produces a borrowed
   `RequestView` (method/URI/headers/body) that the encoders share.
5. **Coraza encoding**
   - *Native sidecar (binary v1)*: `coraza_wire::encode_request_view` writes the
     fixed header, method, URI, headers and removal list directly into one
     head buffer, then writes the body with a single `writev`. The body is
     `Bytes::slice_ref`'d from the request, and the URI is written straight into
     the frame instead of `uri.to_string()`. No JSON is produced.
   - *WASI reactor*: the guest ABI is still the JSON envelope
     (`coraza_payload::build_payload_with_policy_and_rules`). This is the
     blocking dependency for a fully copy-free wasm path: the guest decodes a
     JSON string and base64 for non-UTF-8 bodies. Changing it requires a guest
     ABI change in `wasm/coraza_reactor`, which is outside this change.

## Buffering and inspection caps

- `server.max_body_size` is enforced while streaming; an over-limit body is
  rejected with `413` before it is fully buffered.
- `waf.coraza.max_inspect_bytes` / `oversize_action` keep their existing
  semantics: `forward-uninspected` hands only the configured prefix to CRS,
  `reject` returns `413`, and `inspect-all` (default) inspects the whole buffered
  body. `waf.coraza.max_payload_bytes` is still checked by the native client and
  the reactor before evaluation.
- The proxy still buffers the full body up to `server.max_body_size` before
  evaluation. Streaming the remainder past the CRS prefix is deliberately not
  done: non-Coraza rules (content inspection, gRPC/GraphQL field scans) may need
  the whole body, so truncating the buffer would create an inspection gap that
  the configuration did not ask for. The explicit cap is `max_body_size`; the
  CRS prefix cap is `max_inspect_bytes`.

## Allocations and copies (before → after)

| body | before | after |
|---|---|---|
| bodyless | pooled read + copy, header clone | one `Bytes` (empty), no header clone |
| 1 KiB | 2 body copies + header clone | single-frame `Bytes` shared |
| 4 KiB | 2 body copies + header clone | single-frame `Bytes` shared |

The 4 KiB body is usually one hyper frame on a keep-alive connection, so the
proxy and the WAF see the same allocation. Multi-frame/chunked bodies still pay
one coalescing copy, which is required for a contiguous inspection slice.

## Remaining copies (follow-up)

- `WafEngine::evaluate_shared` clones the `RequestContext` (including the
  header map) before moving it into `spawn_blocking` for a heavy body scan.
  The proxy-level clone is gone; this engine-level clone is the next win and
  needs the blocking task to take an `Arc<RequestContext>` (or a cheaply
  cloneable header representation).
- The WASI reactor's JSON guest ABI still serialises the head and body into a
  JSON string and base64-encodes non-UTF-8 bodies.

## Measuring

`cargo run --release --features wasm-reactor,coraza-native --bin bench-subms`
reports p50/p95/p99 and `alloc B/op` / `allocs/op` for L2 (proxy, no WAF) and
L3 (proxy + WAF) at bodyless/1 KiB/4 KiB/8 KiB. See
`docs/operations/subms-budget.md`.

## Measured allocation change

Both binaries were built from the same base (`5608cf0`) and run back-to-back on
the same host with `--only l1` and `--only l2,l3 --samples 5 --requests 5
--warmup 2`. The allocation columns are load-independent.

| layer | size | before B/op | after B/op | before allocs/op | after allocs/op |
|---|---|---:|---:|---:|---:|
| L1 binary payload | bodyless | 150 | 126 | 3.00 | 1.00 |
| L1 binary payload | 4 KiB | 201 | 193 | 2.00 | 1.00 |
| L2 proxy (no WAF) | bodyless | 48 664 | 48 320 | 85.00 | 83.00 |
| L2 proxy (no WAF) | 4 KiB | 57 783 | 53 239 | 97.00 | 94.00 |
| L3 proxy (wasm) | bodyless | 52 992 | 52 642 | 123.20 | 121.00 |
| L3 proxy (wasm) | 4 KiB | 88 483 | 83 934 | 157.00 | 153.80 |

The 4 KiB L3 row saves ~4.5 KiB and ~3.2 allocations per request; the bodyless
row saves ~0.35 KiB and ~2.2 allocations. The L1 binary encoder drops from 3 to
1 allocation for a bodyless request and from 2 to 1 for a body, because the URI
is no longer formatted into a temporary `String`.

## Measured latency change

Same run, L3 proxy with the wasm reactor (p50 / p99, ms):

| size | before | after |
|---|---:|---:|
| bodyless | 3.906 / 3.924 | 3.433 / 3.622 |
| 4 KiB | 391.806 / 393.265 | 384.039 / 385.375 |

The CRS body scan dominates the 4 KiB row, so the proxy copy savings are only
~2 % of end-to-end latency there. The bodyless row improves ~12 % p50 because
the removed header/URI work is a larger share of a short request.
