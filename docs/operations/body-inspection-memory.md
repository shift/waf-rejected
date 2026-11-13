# Body inspection memory budget

The proxy accepts request bodies up to `server.max_body_size` (2 MiB by
default). The native Rust engine's per-value budget is derived from the same
value at engine construction, so a body the proxy accepts can always be charged
to the engine budget and inspected. Status semantics:

- a body above `min(proxy.max_request_size, server.max_body_size)` is rejected
  with `413 Payload Too Large` before inspection and is never forwarded;
- an inspection budget breach inside the engine is a policy outcome, not an
  internal error: it is also a fail-closed `413`, never an allow and never an
  uninspected forward;
- only genuine internal invariant failures remain `500`.

An explicit `waf.coraza.max_value_bytes` below `server.max_body_size` is
rejected at load, because it would recreate the gap where a body is accepted
but cannot be inspected. `0` (the default) derives the cap from the body cap.

A resolved cap above 2 MiB is supported but is an explicit opt-in: start-up
logs one `warn` line naming `server.max_body_size`, its value, and the measured
per-request cost. At the default no warning is emitted.

## Worst case for one in-flight request

At the 2 MiB default the engine uses a 2 MiB per-value cap and a 64 MiB
request-wide budget. The request-wide multiplier is 32×: CRS applies many
distinct transform pipelines to `REQUEST_BODY`, and each pipeline's output is
real materialised bytes that the budget must admit.

| component | bound | notes |
|---|---:|---|
| transport body buffer | 2 MiB | read once; the engine borrows this slice |
| request-wide engine budget | 64 MiB | 32 × the per-value cap; accounting for body, decoded values and transform output |
| body-processor decoded values | 2 MiB | at most one value at the per-value cap (JSON/XML/form) |
| transform cache arena | 128 MiB | hard stop at 2 × the request-wide budget |
| **hard ceiling** | **≈132 MiB** | plus fixed per-request scratch and headers |

The hard ceiling is deliberately conservative: it is the point at which the
engine fails closed, not a number the shipped CRS bundle reaches. At the 10 MiB
cap the measured CRS path materialises roughly 210 MiB of transform output, so
a real in-flight request is about 230 MiB including the body and one processor
copy. The transform cache is the dominant term, and it is populated lazily:
only pipelines that rules actually execute allocate output. A bodyless or
header-only request never allocates body-proportional memory.

## Choosing a body cap

Inspection cost scales with the number of bytes accepted, because the whole
body is buffered and inspected in full. Measurements on the reference host
(CRS bundle, native Rust engine):

| `server.max_body_size` | p50 inspection | transient memory per in-flight request |
|---:|---:|---:|
| 1 MiB | ≈ 0.28 ms | ≈ 23 MiB |
| 2 MiB (default) | ≈ 0.6 ms | ≈ 46 MiB |
| 10 MiB | 1.43 s | ≈ 230 MiB |

The memory column scales roughly linearly with the cap and is dominated by
materialised transform output. The 10 MiB figures are measured; smaller rows
are interpolated from the same linear model, not separately benchmarked.

A handful of concurrent 10 MiB uploads can therefore consume gigabytes and pin
worker threads for seconds. Keep the 2 MiB default unless a specific workload
needs larger bodies, and then size process memory and concurrency for the cost
above. Raising the cap requires setting `server.max_body_size` explicitly and
accepts that cost; the process logs a start-up warning to make the trade-off
visible.

## Why the body is not copied per rule

The body buffer is read once by the proxy and passed to the engine as a
borrowed slice. Rule candidates reference that slice (`Cow::Borrowed`), and the
borrowed representation is not charged again when another rule resolves it. The
transform cache stores one output per `(value, pipeline)` and assigns the
request body a stable cache identity, so two rules that use the same transform
share the same bytes. All charges go through a single per-request `Budget`.
Adding rules therefore adds rule state, not another body copy; the dominant
memory term scales with `server.max_body_size` and the transform pipelines that
run, not with the number of rules.

Rules that record a match copy the matched value into `MATCHED_VAR`; that copy
is charged to the same request budget, so a large body that matches many rules
fails closed instead of multiplying memory without limit.

Raising `server.max_body_size` raises this per-request bound linearly. Size it
against the expected number of concurrent large uploads and the process memory
limit; the transport rejection still keeps anything above the cap out of
inspection entirely.