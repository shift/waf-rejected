# Sub-millisecond WAF overhead budget

**Status:** measurement harness and gates. Nothing in this document changes
production behaviour; it defines what a sub-millisecond fast path has to hit
and where the current engines spend their time.

The target is **p50 < 1 ms** for bodyless and ≤ 4 KiB requests at high
throughput. The current WAF-only cost is 2–6 ms bodyless, ~39 ms at 1 KiB and
~166 ms at 4 KiB on the wasm backend; the native sidecar is roughly 5–6×
faster, and CRS is ~99.8 % of the native cost. This harness decomposes those
numbers into layers so the remaining budget can be assigned rather than
guessed.

## Layer model

`bench-subms` (`src/bin/bench_subms.rs`) measures five layers in one release
process:

| layer | what runs | what it answers |
|---|---|---|
| **L0-reactor** | raw Coraza backend: `WasmReactor::evaluate(payload)` or `NativeCorazaClient::evaluate_context(ctx)` | how much of the cost is the rule engine itself |
| **L0-engine** | `WafEngine::evaluate` with a synthetic `RequestContext` (no HTTP), plus a heuristics-only engine with Coraza disabled | engine, admission, heuristic rules and audit-event path |
| **L1-payload** | `coraza_payload` header stringification, `select_body`, the JSON envelope and the binary v1 frame | serialisation, copies and allocations outside the engine |
| **L2-proxy** | the real `WafProxyService` with `waf.enabled = false`: hyper parse → framing/auth/body buffering → upstream forward → response | the proxy floor a fast path inherits |
| **L3-proxy** | the same proxy with the WAF enabled (wasm and, when a sidecar socket is supplied, native) | the end-to-end request cost |
| **L4** | TLS/h2 connection overhead | *not implemented*: see [L4](#l4-tls--http2) |

L2 is measured with the real proxy over loopback and a real keep-alive hyper
client; the mock upstream is also in-process. That includes loopback TCP and
the client, so **L2 is an upper bound on the proxy floor**, and L3−L2 is the
WAF add-on. The client and upstream cost is identical in L2 and L3, so the
difference cancels it.

L0 uses a synthetic context with `Host`, `User-Agent`, `Accept` and, for
bodies, `Content-Type: application/x-www-form-urlencoded` plus a matching
`Content-Length`. Bodies are `data=AAAA…`; a bare `text/plain` body is itself
a CRS protocol anomaly and would measure a block instead of a scan. The engine
rows are built with `pool_size = 1` so one call is attributed to one reactor
worker; L3 uses `pool_size = 4` so the throughput cell is not artificially
serialised.

## Running it

```sh
# Build the release benchmark, start the native sidecar and run every layer.
nix develop -c ./scripts/bench-subms.sh

# Quick iteration: wasm only, fewer samples, no sidecar.
nix develop -c ./scripts/bench-subms.sh --no-native -- \
  --samples 30 --requests 30 --warmup 5

# Pin the sidecar and benchmark to four cores on a quiet host.
nix develop -c ./scripts/bench-subms.sh --pin 2-5
```

The script writes `target/bench-subms/report.json` with every row and gate.
Benchmark options after `--` include `--samples`, `--requests`, `--warmup`,
`--concurrency`, `--per-worker`, `--only l0,l1,l2,l3` and `--native-socket`.
The sidecar socket defaults to `/tmp/opencode/bench-subms/coraza.sock`.

Direct invocation (for example under `perf`):

```sh
cargo build --release --features wasm-reactor,coraza-native --bin bench-subms
./target/release/bench-subms --only l0,l1 --samples 100
```

## Measurement method

* Release build (`--release`), default features plus `coraza-native`.
* Percentiles are nearest-rank over per-call nanosecond samples:
  `p50`, `p95`, `p99`, mean and max. Warm-up iterations are discarded.
* L0/L1 are single-threaded; L0 reactor calls are synchronous and L0 engine
  calls run inside one `tokio` runtime without a per-call `block_on`.
* L2/L3 latency rows are **c=1** closed loop over a persistent connection.
  The throughput cell is c=8 (configurable) and reports completed req/s and
  the number of non-200 responses (admission `503`s are counted, not hidden).
  A non-200 anywhere in a row fails its gate; the harness never retries it.
* The harness raises `waf.coraza.eval_timeout_ms` to 120 s by default. The
  shipped 5 s bound is a DoS guard; on a contended host a scheduler stall
  would otherwise surface as a `503` and hide the scan cost. The script also
  starts the benchmark sidecar with `--timeout 120s` for the same reason; the
  production sidecar unit keeps its 5 s budget. The measured wall time is
  reported either way, so a stall still fails the gates.
* Allocation accounting is a counting global allocator. It is enabled only
  around the measured loop, so timing runs do not pay for it. L0/L1 values
  are exact for the calling thread; L0 wasm includes the reactor pool worker
  in the same process. Native sidecar allocations happen in another process
  and are **not** included. L2/L3 values include the client and mock upstream
  and are therefore an upper bound on proxy allocations.

## Measured results

> **Host caveat.** The reference host is shared and throttles between roughly
> 1.7 and 3.3 GHz. The run below was taken in a quieter window (load average
> 4–6 on 6 logical CPUs) with the benchmark pinned to CPUs 2–5, but the
> `powersave` governor was still active. These are credible floors for this
> host, not ceilings; use the [quiet-host runbook](#quiet-host-runbook) before
> setting an SLO or comparing commits. The numbers match the baseline figures
> in the task (2–6 ms bodyless, ~39 ms 1 KiB, ~166 ms 4 KiB), which is the
> strongest evidence that the harness is measuring the intended path.

**Run:** 2026-11-02, release, `wasm-reactor,coraza-native`, 20 samples per
L0/L1 cell, 20 sequential requests per L2/L3 cell, 5 warm-up iterations,
c=8 throughput cell (20 requests per worker), native sidecar with
`--timeout 120s`, `taskset -c 2-5`. The allocation columns are not affected
by load and are the most transferable result.

```sh
taskset -c 2-5 ./target/release/bench-subms \
  --samples 20 --requests 20 --warmup 5 \
  --concurrency 8 --per-worker 20 --eval-timeout-ms 120000 \
  --native-socket /tmp/opencode/bench-subms/coraza.sock \
  --json-out target/bench-subms/report.json
```

### L0/L1: reactor, engine and payload construction

| layer | backend | size | p50 ms | p95 ms | p99 ms | mean ms | alloc B/op | allocs/op | non-200 |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|
| L0-engine | heuristics-only | bodyless | 0.003 | 0.003 | 0.003 | 0.003 | 69 | 6.00 | 0 |
| L0-engine | heuristics-only | 1 KiB | 0.018 | 0.018 | 0.018 | 0.018 | 119 | 7.00 | 0 |
| L0-engine | heuristics-only | 4 KiB | 0.057 | 0.058 | 0.084 | 0.059 | 119 | 7.00 | 0 |
| L0-engine | heuristics-only | 8 KiB | 0.112 | 0.150 | 0.153 | 0.117 | 119 | 7.00 | 0 |
| L0-reactor | wasm | bodyless | 3.309 | 3.398 | 3.466 | 3.306 | 2 663 | 4.05 | 0 |
| L0-engine | wasm | bodyless | 3.351 | 3.429 | 3.433 | 3.350 | 4 474 | 44.05 | 0 |
| L0-reactor | wasm | 1 KiB | 41.858 | 42.501 | 43.429 | 41.992 | 3 760 | 4.05 | 0 |
| L0-engine | wasm | 1 KiB | 42.428 | 43.657 | 44.233 | 42.368 | 11 005 | 60.05 | 0 |
| L0-reactor | wasm | 4 KiB | 174.189 | 217.742 | 331.590 | 185.197 | 6 757 | 4.00 | 0 |
| L0-engine | wasm | 4 KiB | 172.955 | 183.631 | 192.873 | 174.957 | 29 362 | 60.00 | 0 |
| L0-reactor | wasm | 8 KiB | 357.303 | 506.855 | 524.750 | 374.893 | 10 928 | 4.05 | 0 |
| L0-engine | wasm | 8 KiB | 372.217 | 426.641 | 486.726 | 380.335 | 54 013 | 60.05 | 0 |
| L0-reactor | native | bodyless | 1.430 | 4.111 | 4.202 | 1.679 | 150 | 3.00 | 0 |
| L0-engine | native | bodyless | 0.847 | 1.137 | 1.729 | 0.912 | 219 | 9.00 | 0 |
| L0-reactor | native | 1 KiB | 8.203 | 11.825 | 14.939 | 8.877 | 201 | 2.00 | 0 |
| L0-engine | native | 1 KiB | 8.111 | 8.324 | 8.349 | 8.145 | 419 | 12.00 | 0 |
| L0-reactor | native | 4 KiB | 30.594 | 74.379 | 95.100 | 40.383 | 201 | 2.00 | 0 |
| L0-engine | native | 4 KiB | 29.855 | 38.320 | 41.396 | 31.252 | 419 | 12.00 | 0 |
| L0-reactor | native | 8 KiB | 62.045 | 70.275 | 121.031 | 66.321 | 201 | 2.00 | 0 |
| L0-engine | native | 8 KiB | 158.365 | 273.279 | 273.643 | 153.360 | 419 | 12.00 | 0 |
| L1-payload | header-strings | bodyless | 0.000 | 0.000 | 0.000 | 0.000 | 256 | 7.00 | 0 |
| L1-payload | select-body | bodyless | 0.000 | 0.000 | 0.000 | 0.000 | - | - | 0 |
| L1-payload | json | bodyless | 0.002 | 0.003 | 0.004 | 0.002 | 1 742 | 34.00 | 0 |
| L1-payload | binary | bodyless | 0.000 | 0.000 | 0.000 | 0.000 | 150 | 3.00 | 0 |
| L1-payload | header-strings | 1 KiB | 0.000 | 0.001 | 0.001 | 0.001 | 415 | 11.00 | 0 |
| L1-payload | select-body | 1 KiB | 0.000 | 0.000 | 0.000 | 0.000 | - | - | 0 |
| L1-payload | json | 1 KiB | 0.004 | 0.004 | 0.006 | 0.004 | 7 027 | 46.00 | 0 |
| L1-payload | binary | 1 KiB | 0.000 | 0.001 | 0.001 | 0.000 | 201 | 2.00 | 0 |
| L1-payload | header-strings | 4 KiB | 0.000 | 0.001 | 0.001 | 0.000 | 415 | 11.00 | 0 |
| L1-payload | select-body | 4 KiB | 0.000 | 0.000 | 0.000 | 0.000 | - | - | 0 |
| L1-payload | json | 4 KiB | 0.007 | 0.009 | 0.009 | 0.008 | 22 387 | 46.00 | 0 |
| L1-payload | binary | 4 KiB | 0.000 | 0.000 | 0.000 | 0.000 | 201 | 2.00 | 0 |
| L1-payload | header-strings | 8 KiB | 0.000 | 0.001 | 0.001 | 0.000 | 415 | 11.00 | 0 |
| L1-payload | select-body | 8 KiB | 0.000 | 0.000 | 0.000 | 0.000 | - | - | 0 |
| L1-payload | json | 8 KiB | 0.013 | 0.014 | 0.015 | 0.013 | 42 867 | 46.00 | 0 |
| L1-payload | binary | 8 KiB | 0.000 | 0.000 | 0.000 | 0.000 | 201 | 2.00 | 0 |

L1 latency is sub-microsecond and dominated by the timer resolution at this
sample count; the allocation columns are the meaningful part. The JSON
envelope allocates **1.7 KiB bodyless, 7.0 KiB at 1 KiB, 22.4 KiB at 4 KiB
and 42.9 KiB at 8 KiB** (34–46 allocations), i.e. roughly 5–7× the body size.
The binary v1 frame allocates **150–201 B in 2–3 allocations** regardless of
body size, because the body is a `Bytes::slice_ref` and only the header block
is built.

### L2/L3: proxy with and without the WAF

| layer | backend | size | p50 ms | p95 ms | p99 ms | mean ms | alloc B/op | allocs/op | non-200 |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|
| L2-proxy | no-waf | bodyless | 0.154 | 0.307 | 0.337 | 0.176 | 48 444 | 86.50 | 0 |
| L2-proxy | no-waf | 1 KiB | 0.134 | 0.159 | 0.195 | 0.140 | 51 943 | 99.15 | 0 |
| L2-proxy | no-waf | 4 KiB | 0.135 | 0.166 | 0.168 | 0.137 | 57 617 | 98.75 | 0 |
| L2-proxy | no-waf | 8 KiB | 0.148 | 0.171 | 0.174 | 0.150 | 82 539 | 98.15 | 0 |
| L3-proxy | wasm | bodyless | 4.514 | 9.742 | 14.742 | 5.380 | 53 254 | 130.35 | 0 |
| L3-proxy | wasm | 1 KiB | 65.973 | 148.372 | 160.795 | 81.767 | 63 638 | 163.35 | 0 |
| L3-proxy | wasm | 4 KiB | 172.207 | 187.842 | 194.239 | 174.198 | 88 020 | 162.50 | 0 |
| L3-proxy | wasm | 8 KiB | 354.334 | 471.450 | 508.747 | 376.040 | 137 182 | 162.85 | 0 |
| L3-proxy | native | bodyless | 0.913 | 1.036 | 1.067 | 0.913 | 48 889 | 96.00 | 0 |
| L3-proxy | native | 1 KiB | 8.438 | 25.531 | 86.916 | 13.354 | 53 131 | 115.00 | 0 |
| L3-proxy | native | 4 KiB | 29.266 | 55.809 | 57.832 | 33.824 | 59 280 | 115.15 | 0 |
| L3-proxy | native | 8 KiB | 57.607 | 58.218 | 65.582 | 58.046 | 83 856 | 115.15 | 0 |

L2/L3 allocation includes the keep-alive hyper client and the in-process mock
upstream. The **L3 wasm − L2** difference at 4 KiB is ~30 KiB/request, which
matches the JSON envelope (22.4 KiB) plus header strings and the engine. The
**L3 native − L2** difference at 4 KiB is ~1.5 KiB, because the binary frame
is zero-copy and the sidecar allocates in its own process. The proxy floor
alone allocates ~48–82 KiB/request in this harness (client + upstream
included), which is the first thing a fast path must reduce.

### Derived per-request overhead

Wasm backend:

| size | L0 engine | L2 proxy (c=1) | L2 proxy (c=8) | L3 proxy | L3−L0 (non-rule) | L3−L2 (WAF add-on) |
|---|---:|---:|---:|---:|---:|---:|
| bodyless | 3.351 ms | 0.154 ms | 0.492 ms | 4.514 ms | +1.163 ms | 4.360 ms |
| 1 KiB | 42.428 ms | 0.134 ms | 0.549 ms | 65.973 ms | +23.545 ms | 65.839 ms |
| 4 KiB | 172.955 ms | 0.135 ms | — | 172.207 ms | −0.748 ms | 172.072 ms |
| 8 KiB | 372.217 ms | 0.148 ms | — | 354.334 ms | −17.883 ms | 354.186 ms |

L3−L0 is positive and close to the proxy floor at bodyless and 1 KiB. At
4 KiB and 8 KiB it is slightly negative because L0 and L3 are separate phases
and the reactor timing moved by a few percent between them; treat small
negatives as noise. The useful, same-phase number is **L3−L2**, the WAF
add-on over the proxy floor. At 1 KiB the wasm add-on is 65.8 ms while the
rule engine alone is 42.4 ms, so roughly 23 ms is payload construction,
transport and scheduling on top of the scan.

Native backend:

| size | L0 engine | L3 proxy | L3−L0 (non-rule) | L3−L2 (WAF add-on) |
|---|---:|---:|---:|---:|
| bodyless | 0.847 ms | 0.913 ms | +0.066 ms | 0.759 ms |
| 1 KiB | 8.111 ms | 8.438 ms | +0.327 ms | 8.304 ms |
| 4 KiB | 29.855 ms | 29.266 ms | −0.589 ms | 29.131 ms |
| 8 KiB | 158.365 ms | 57.607 ms | −100.758 ms | 57.459 ms |

Native L3−L0 is small and positive at bodyless and 1 KiB: the proxy plus the
Unix-socket round trip adds 0.07–0.33 ms on top of the engine. The 4 KiB and
8 KiB L0 engine rows are noisy (the 8 KiB engine p50 of 158 ms is higher than
its own raw reactor row of 62 ms), so L3−L0 is not meaningful there; use
L3−L2. The native WAF add-on is **0.76 ms bodyless, 8.3 ms at 1 KiB and
29.1 ms at 4 KiB** — still CRS-dominated.

## Allocation and copy findings

The clean UTF-8 request path still copies the body several times and allocates
a fresh JSON envelope per request. The measured allocation columns in the
table above quantify this; the static path is:

| step | copy / allocation | size at 4 KiB |
|---|---|---:|
| hyper body frame → pooled `BytesMut` (`extend_from_slice`) | copy | 4 KiB |
| pooled buffer → `Bytes` (`PooledBuffer::to_bytes` → `copy_from_slice`) | copy | 4 KiB |
| `parts.headers.clone()` into `RequestContext` | allocation (HeaderMap) | ~5 headers |
| `coraza_payload` header strings (`Vec<(String, String)>`) | 2 allocations + strings per header | ~10 allocs |
| `coraza_payload` body `text.to_string()` | copy | 4 KiB |
| `serde_json::json!` intermediate `Value` (map, header `Vec`, growth) | allocation | ~13 KiB |
| `serde_json::to_vec` envelope | allocation + escaping copy | ~4.4 KiB |
| `Bytes` clone into the context | refcount only | 0 |
| binary v1 frame (`coraza_wire`) | head `Vec`, body is `Bytes::slice_ref` | ~0 body copy |
| base64 (non-UTF-8 bodies only) | 4/3 expansion + buffer | n/a on clean path |

Consequences:

* The wasm path pays **two body copies before the reactor** plus a third into
  the JSON string and a fourth into the serialised envelope. At 4 KiB that is
  roughly 16 KiB of copying per request before Coraza sees a byte.
* The native binary-v1 path already avoids the body copies (`Bytes::slice_ref`)
  and the JSON envelope. Its remaining cost is the Unix-socket round trip and
  the Go/CRS scan.
* `HeaderMap` cloning and the `Vec<(String, String)>` header conversion are
  small in bytes but not free; they are the dominant L1 cost for bodyless
  requests.
* A sub-millisecond fast path cannot keep the JSON envelope. It must pass a
  borrowed request (method, URI, headers, body slice) to the rule engine and
  either use the binary frame or an in-process backend. It must also avoid the
  `to_bytes` copy by freezing the pooled buffer or reading into a `BytesMut`
  that becomes `Bytes` without a second copy.
* `Bytes::clone` is cheap and is **not** the problem; `PooledBuffer::to_bytes`
  is.

## Sub-millisecond gates

Gates apply to the **full proxy** (L3) at c=1. They are deliberately not
weakened after a run: a failure is a finding, not a reason to move the line.

| gate | requirement |
|---|---|
| `bodyless-p50` | bodyless p50 < **0.5 ms** |
| `1k-p50` | 1 KiB p50 < **0.8 ms** |
| `4k-p50` | 4 KiB p50 < **1.5 ms** |
| `tail-ratio` | p99 ≤ **2× p50** for bodyless, 1 KiB, 4 KiB and 8 KiB |

`8 KiB` has no p50 gate because the stated target is bodyless and ≤ 4 KiB; it
still has a tail gate so a fast path cannot hide a long tail there.

Throughput is reported separately (it is a capacity target, not a per-request
latency gate): bodyless ≥ 1 000 req/s and 1 KiB ≥ 100 req/s at c=8, with zero
non-200 responses. The harness prints the cell and the non-200 count; the
current run is assessed below.

**Result: all three p50 gates fail on both backends.** The wasm tail fails at
bodyless and 1 KiB and passes at 4 KiB and 8 KiB; the native tail passes at
bodyless, 4 KiB and 8 KiB and fails at 1 KiB on a single 86.9 ms outlier.
Native bodyless is the closest result: **0.913 ms p50**, 1.8× over the 0.5 ms
gate.

| gate | backend | limit | measured | result |
|---|---|---|---:|---|
| bodyless p50 | wasm | < 0.5 ms | 4.514 ms | **FAIL** |
| 1 KiB p50 | wasm | < 0.8 ms | 65.973 ms | **FAIL** |
| 4 KiB p50 | wasm | < 1.5 ms | 172.207 ms | **FAIL** |
| bodyless p99 ≤ 2× p50 | wasm | ≤ 9.028 ms | 14.742 ms | **FAIL** |
| 1 KiB p99 ≤ 2× p50 | wasm | ≤ 131.946 ms | 160.795 ms | **FAIL** |
| 4 KiB p99 ≤ 2× p50 | wasm | ≤ 344.414 ms | 194.239 ms | PASS |
| 8 KiB p99 ≤ 2× p50 | wasm | ≤ 708.669 ms | 508.747 ms | PASS |
| bodyless p50 | native | < 0.5 ms | 0.913 ms | **FAIL** |
| 1 KiB p50 | native | < 0.8 ms | 8.438 ms | **FAIL** |
| 4 KiB p50 | native | < 1.5 ms | 29.266 ms | **FAIL** |
| bodyless p99 ≤ 2× p50 | native | ≤ 1.825 ms | 1.067 ms | PASS |
| 1 KiB p99 ≤ 2× p50 | native | ≤ 16.876 ms | 86.916 ms | **FAIL** |
| 4 KiB p99 ≤ 2× p50 | native | ≤ 58.531 ms | 57.832 ms | PASS |
| 8 KiB p99 ≤ 2× p50 | native | ≤ 115.215 ms | 65.582 ms | PASS |

The native 1 KiB tail failure is a scheduling outlier, not a rule-engine
tail: p50 is 8.4 ms and p95 is 25.5 ms, but one sample reached 86.9 ms. It is
reported as a failure because the gate is not allowed to ignore outliers.

Throughput, assessed from the same c=8 cells: wasm bodyless 995 req/s, wasm
1 KiB 48 req/s, native bodyless 3 577 req/s, native 1 KiB 226 req/s. The wasm
bodyless cell misses the ≥ 1 000 req/s target by 5 req/s; the wasm 1 KiB cell
misses ≥ 100 req/s; both native cells pass. The wasm bodyless number is
within run-to-run noise of the target.

## Implied fast-path budget

The budget for work *other than* the proxy is `gate − L2 p50`. If L2 alone is
already above the gate, no rule-engine optimisation can reach the target; the
proxy path has to get cheaper first.

Measured on this contended host:

| size | gate | L2 c=1 p50 | budget vs c=1 | L2 c=8 p50 | budget vs c=8 |
|---|---:|---:|---:|---:|---:|
| bodyless | 0.5 ms | 0.154 ms | **+0.346 ms** | 0.492 ms | **+0.008 ms** |
| 1 KiB | 0.8 ms | 0.134 ms | **+0.666 ms** | 0.549 ms | **+0.251 ms** |
| 4 KiB | 1.5 ms | 0.135 ms | **+1.365 ms** | — | — |

The c=1 L2 row is the cleanest proxy floor: **0.13–0.15 ms** for every body
size. The proxy therefore can support sub-millisecond requests; the budget
that remains for WAF work is **0.35 ms bodyless, 0.67 ms at 1 KiB and
1.37 ms at 4 KiB**. The c=8 cell is a saturated throughput measurement, not a
latency floor: its p50 includes queueing, so its budget is much tighter and
should not be used to size the fast path.

The native WAF add-on (L3−L2) is 0.76 ms bodyless, 8.3 ms at 1 KiB and
29.1 ms at 4 KiB. The bodyless budget is 0.35 ms, so native is **2.2× over
budget** even at bodyless; at 1 KiB it is 12× over. The wasm add-on is 4.4 ms
bodyless (13× over) and 65.8 ms at 1 KiB (98× over).

For planning, use a small margin over the measured floor:

| size | gate | planning floor `F` | implied WAF budget |
|---|---:|---:|---:|
| bodyless | 0.5 ms | 0.20 ms | **0.30 ms** |
| 1 KiB | 0.8 ms | 0.20 ms | **0.60 ms** |
| 4 KiB | 1.5 ms | 0.25 ms | **1.25 ms** |

`F = 0.20/0.25 ms` is a 35–85 % margin over the measured 0.13–0.15 ms floor,
not a new measurement. The runbook exists to confirm it on a quiet host. The
gates themselves do not move.

A fast path that meets the gates therefore has to:

1. keep the body in one buffer from hyper frame to rule engine (no
   `to_bytes`, no JSON string);
2. borrow headers and URI instead of cloning them into a new context;
3. avoid the JSON envelope and base64 on the clean UTF-8 path;
4. keep the rule engine out of the request-critical path for bodyless and
   small requests, or replace CRS body scanning with a bounded prefilter that
   is proven on the detection corpus (see
   [`../design/crs-prefilter.md`](../design/crs-prefilter.md));
5. keep admission and audit-event work off the allow path (the event logger
   already returns early when disabled, but the engine still pays the call).

The CRS scan is ~99.8 % of native cost, so a fast path that still runs full
CRS cannot meet 1 KiB < 0.8 ms on this hardware: native is 8.44 ms at 1 KiB
and 29.27 ms at 4 KiB, 10–20× over the gate. Even bodyless native is 0.913 ms
against a 0.5 ms gate, so the bodyless fast path must also remove the JSON
envelope, the header clone and most of the sidecar round trip. The realistic
sub-millisecond target is bodyless and header/URI-only inspection, with a
separately budgeted bounded body check.

## L4: TLS / HTTP/2

Not implemented in this harness. TLS record protection, the handshake and h2
framing are transport costs, not WAF budget, and the handshake is amortised
over a keep-alive connection. Measure them with the existing load harness
(`scripts/load-validate.sh`) when a certificate is configured, and compare
the same profile with and without TLS. Do not add TLS cost to the WAF gates.

## Quiet-host runbook

The host is shared. Before recording numbers that will be compared or used to
set an SLO:

1. **Wait for other work to stop.** Check `uptime`; the 1-minute load average
   should be below the number of physical cores (6 here), ideally below 1.
   Check `ps aux --sort=-%cpu | head` for benchmark/build processes.
2. **Pin the benchmark.** Use `--pin 2-5` (or another otherwise-idle set).
   The script applies `taskset` to both the sidecar and the benchmark.
3. **Set the governor.** If permitted:
   ```sh
   cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor
   sudo sh -c 'echo performance > /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor'
   ```
4. **Disable turbo (optional, Intel).** Record the setting first; restore it
   afterwards:
   ```sh
   cat /sys/devices/system/cpu/intel_pstate/no_turbo
   echo 1 | sudo tee /sys/devices/system/cpu/intel_pstate/no_turbo
   ```
5. **Record the frequency.** `grep -m1 'cpu MHz' /proc/cpuinfo` before and
   after the run, and `lscpu | grep MHz`. This host throttles between roughly
   1.7 and 3.3 GHz; a 2× latency difference between runs is usually frequency
   or contention, not a code change.
6. **Run at least three times.** Discard the first run (page cache, reactor
   warm-up) and compare the median of p50 and p99. Keep the JSON reports.
7. **Record the environment** in the commit or report: kernel, CPU model,
   governor, turbo state, load average, sidecar/wasm commit, and the exact
   command line.

A useful one-liner to capture the environment:

```sh
{ uname -srm; lscpu | grep -E 'Model name|CPU\(s\)|MHz';
  cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null;
  cat /sys/devices/system/cpu/intel_pstate/no_turbo 2>/dev/null;
  uptime; } | tee target/bench-subms/environment.txt
```

## Limitations

* Loopback client and upstream are included in L2/L3; absolute values are
  higher than a kernel-bypass or in-process handler call. The L3−L2 delta is
  the useful WAF number.
* The native sidecar runs as a separate process, so its allocations and CPU
  are not in the L0/L3 allocation columns. Its wall-clock round trip is.
* Admission control is enabled with the production defaults. The throughput
  cell can legitimately produce `503`s at c=8 for heavy bodies; those are
  reported as `non-200`, not retried or hidden.
* The benchmark does not exercise TLS/h2 (L4), WebSocket, gRPC or GraphQL.
  Those have their own harnesses and budgets.
