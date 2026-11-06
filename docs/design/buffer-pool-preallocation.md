# Suggestion: relax or remove `BufferPool` preallocation

## Observation

`WafProxyService::new` builds a `BufferPool` that eagerly allocates:

- 1 000 × 4 KiB = 3.9 MiB
- 200 × 64 KiB = 12.5 MiB
- 50 × 1 MiB = 50 MiB

≈ 66 MiB per proxy instance, before any request is served.

After the zero-copy request path (`feat/zero-copy-http`), request bodies no
longer use `BufferPool::read_incoming_body`; the proxy returns hyper's own
`Bytes` or a single `BytesMut` coalescing. The only remaining users are the
performance-validation tests and `create_response_body`, which is not called by
the request hot path. The preallocation is therefore mostly unused on the
default path.

## Suggestion (not implemented)

1. Make preallocation lazy (fill on first `get_buffer`) or shrink the eager
   counts. This is a memory-footprint change, so it is left for the architecture
   team to decide.
2. If the pool is kept for responses, measure whether `create_response_body`
   should actually use it; today responses use `Full<Bytes>` directly.
3. Re-check the `POOL_SIZE_*` constants against realistic concurrent request
   counts per worker.

No defaults were changed by this suggestion.
