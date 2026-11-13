# Performance verification (post-merge baseline)

**Status:** measurement report and reproduction procedure. No engine, proxy or
configuration default is changed by this document. The numbers are a snapshot
of `main` at the commit below on one shared host; absolute values are only
comparable to another run from `scripts/verify-performance.sh` on the same host
class with the same governor and turbo state.

**Commit:** `aca35db` (`perf(waf): batch transform prefixes and share
literal-gate bitsets (#143)`), with the post-optimization remeasurement in
§3.6. Sections §3.1–§3.5 are the earlier `fdb3ca7` snapshot and are kept for
history; §3.6 supersedes them for current numbers.

## 1. Question

The merged performance work changed the request path in several places at
once: the Coraza WASI binary ABI and worker pre-warming (`#133`), the shared
Hyperscan prefilter (`#134`), the io_uring network backend (`#135`) and the
zero-copy proxy/engine path (`#136`). Most earlier measurements were taken on
a contended host, so this report answers three questions with one harness:

1. What is the layered latency and allocation cost of each backend at
   bodyless, 1 KiB, 4 KiB and 8 KiB?
2. Did the merged work preserve CRS detection and decision parity?
3. Which costs still dominate, and what would it take to claim a sub-millisecond
   end-to-end p50?

## 2. Method

### 2.1 Harness layers

| layer | harness | what it measures |
|---|---|---|
| `L0-reactor` | `bench-subms` | raw backend: `WasmReactor::evaluate` (wasm) or `NativeCorazaClient` round trip (native sidecar) |
| `L0-engine` | `bench-subms` | `WafEngine::evaluate` with a synthetic `RequestContext` |
| `L1-payload` | `bench-subms` | header stringification, body selection, JSON envelope and binary v1 frame |
| `L2-proxy` | `bench-subms` | real proxy over loopback with `waf.enabled = false` (client + mock upstream included) |
| `L3-proxy` | `bench-subms` | the same proxy with the WAF enabled (add-on = L3 − L2) |
| engine gate | `perf-gate-bench` | Coraza reactor, native Rust engine and experimental kernel on identical requests; process CPU time, throughput, allocations and RSS |
| component profile | `bodyless-bench --profile` | single-threaded request-path components (context, admission, metrics, fast-allow, audit) |
| corpus | `crs_corpus`, `rust-engine-parity` | full 2,112-case OWASP CRS 4.14 detection corpus and parity |

Latency rows are nearest-rank percentiles over per-call samples after warm-up.
`bench-subms` reports wall time; `perf-gate` reports process CPU time
(`CLOCK_PROCESS_CPUTIME_ID`), which is the more transferable number on a shared
host. Throughput is wall-based and therefore a lower bound. Allocation counts
come from a counting global allocator enabled only around the measured loop.
The native sidecar allocates in a separate process and is excluded from the
client-side allocation columns; its RSS is recorded separately. Proxy rows
include the keep-alive client and the in-process mock upstream, so they are an
upper bound on the proxy floor.

### 2.2 Host and controls

| item | value |
|---|---|
| host | Linux 6.18.36 x86_64 |
| CPU | Intel Core i5-8400T (6 logical, 1.7 GHz base) |
| affinity | `taskset -c 2-5` for every measured process |
| governor | `performance` on all CPUs |
| turbo | enabled (`/sys/.../no_turbo = 0`) |
| observed frequency | 3.0 GHz at start (`scaling_cur_freq`); drops toward base under sustained all-core load |
| rustc / cargo | 1.99.1 |
| load average at start | 9.85 / 9.20 / 9.16 |

The reference host is shared. During this run, sibling agent builds were moved
to CPUs 0–1 with `taskset` so the measured processes had CPUs 2–5 to
themselves; earlier attempts on the same host were dominated by other `cargo`
builds (load average 14–18, 1.7–2.4× inflated latencies). The load average
column in the report therefore **overstates** pressure on the measured cores.
Tail percentiles (p99) remain sensitive to the 1.7 GHz base-clock drop and are
reported, not hidden. Treat p50 and the allocation columns as the primary
comparison; treat c=8 proxy throughput as a lower bound.

### 2.3 What was run

```sh
# Build release binaries and the native sidecar (one-time).
nix develop -c cargo build --release --locked \
  --features wasm-reactor,coraza-native --bin bench-subms --bin bodyless-bench
nix develop -c cargo build --release --locked \
  --features wasm-reactor,coraza-native,native-engine,rust-engine,engine-kernel,fastpath \
  --bin crs_corpus --bin rust-engine-parity --bin perf-gate-bench
nix develop -c ./scripts/build-coraza-sidecar.sh

# Full verification (writes JSON + Markdown under target/perf-verify/<run>).
nix develop -c ./scripts/verify-performance.sh --skip-build \
  --out target/perf-verify/run-20261103 --cpus 2-5 \
  --samples 30 --requests 10 --warmup 5 --reps 50
```

`scripts/verify-performance.sh` performs the build, starts the sidecar, runs
all of the above, and writes `environment.json`, `bench-subms.json`,
`perf-gate.json`, the corpus reports, `bench-subms.txt`, `bodyless-bench.txt`,
`rust-engine-bench.txt`, `summary.json` and `summary.md`.

## 3. Results

### 3.1 Backend latency, p50 ms

Same synthetic requests as `bench-subms` (bodyless `GET /hello?id=42`,
`application/x-www-form-urlencoded` bodies). Rust-engine rows are from
`rust-engine-parity --bench`; kernel rows are from `perf-gate` (`4k-allow`
for 4 KiB; it has no 1 KiB/8 KiB case).

| backend | bodyless | 1 KiB | 4 KiB | 8 KiB | source |
|---|---:|---:|---:|---:|---|
| Coraza WASI reactor | 4.938 | 74.122 | 179.934 | 374.669 | `bench-subms` L0-reactor |
| Coraza native sidecar | 1.178 | 8.078 | 28.752 | 58.246 | `bench-subms` L0-reactor |
| Native Rust engine | 0.158 | 0.477 | 1.241 | 2.266 | `rust-engine-parity` |
| Native kernel | 0.0099 | — | 0.676 | — | `perf-gate` |
| Fast-allow (compiled route) | 0.00035 | — | — | — | `bodyless-bench` |
| Fast-allow (no rate gates) | 0.00020 | — | — | — | `bodyless-bench` |

Percentiles and allocation detail:

| backend | size | p50 ms | p95 ms | p99 ms | allocs/op | alloc B/op |
|---|---|---:|---:|---:|---:|---:|
| wasm reactor | bodyless | 4.938 | 5.405 | 6.342 | 4.03 | 2 638 |
| wasm reactor | 1 KiB | 74.122 | 79.419 | 79.844 | 4.03 | 3 735 |
| wasm reactor | 4 KiB | 179.934 | 408.944 | 410.948 | 4.03 | 6 807 |
| wasm reactor | 8 KiB | 374.669 | 644.536 | 897.539 | 4.03 | 10 903 |
| native sidecar | bodyless | 1.178 | 1.952 | 2.669 | 1.00 | 126 |
| native sidecar | 1 KiB | 8.078 | 8.543 | 8.574 | 1.00 | 193 |
| native sidecar | 4 KiB | 28.752 | 47.302 | 84.032 | 1.00 | 193 |
| native sidecar | 8 KiB | 58.246 | 60.000 | 62.079 | 1.00 | 193 |
| Rust engine | bodyless | 0.158 | 0.163 | 0.164 | 1 150 | 29 325 |
| Rust engine | 1 KiB | 0.477 | 0.488 | — | 1 785 | — |
| Rust engine | 4 KiB | 1.241 | 1.303 | 1.313 | 1 772 | 646 468 |
| Rust engine | 8 KiB | 2.266 | 2.398 | 2.487 | 1 785 | — |

`bench-subms` engine rows add the WAF host path around the reactor:
bodyless 4.67 ms, 1 KiB 75.77 ms, 4 KiB 181.27 ms, 8 KiB 383.92 ms for wasm;
1.10 / 7.46 / 28.46 / 58.54 ms for native. The envelope therefore adds
0.1–0.7 ms and 4–8 extra allocations; the rule engine is the cost.

The 1 KiB wasm row is **not** linear with 4 KiB: 74 ms at 1 KiB versus 180 ms
at 4 KiB, i.e. 41 % of the 4 KiB cost for 25 % of the bytes. The two bodies
have the same form shape but different argument content, so this is a distinct
hot spot rather than a smaller 4 KiB one; attributing it needs a per-rule
profile of the 1 KiB argument path.

### 3.2 Payload construction (L1)

| representation | size | p50 ms | alloc B/op | allocs/op |
|---|---|---:|---:|---:|
| JSON envelope | bodyless | 0.0018 | 1 742 | 34 |
| JSON envelope | 1 KiB | 0.0036 | 7 027 | 46 |
| JSON envelope | 4 KiB | 0.0076 | 22 387 | 46 |
| JSON envelope | 8 KiB | 0.0124 | 42 867 | 46 |
| binary v1 frame | bodyless | 0.00016 | 126 | 1 |
| binary v1 frame | 1 KiB | 0.00025 | 193 | 1 |
| binary v1 frame | 4 KiB | 0.00026 | 193 | 1 |
| binary v1 frame | 8 KiB | 0.00025 | 193 | 1 |

The binary frame is ~30× cheaper at 4 KiB and is constant in body size. The
wasm L3 rows above still show JSON-sized allocations at 4 KiB (73.8 KiB
total), so the proxy path is not using the binary frame end-to-end.

### 3.3 Full proxy: floor and WAF add-on

c=1 closed loop over a persistent connection; client and mock upstream
included, so L2 is an upper bound on the proxy floor.

| layer | backend | size | p50 ms | p95 ms | p99 ms | alloc B/op | allocs/op | non-200 |
|---|---|---|---:|---:|---:|---:|---:|---:|
| L2-proxy | no-waf | bodyless | 0.131 | 0.656 | 0.656 | 50 426 | 83 | 0 |
| L2-proxy | no-waf | 1 KiB | 0.143 | 0.361 | 0.361 | 49 879 | 93 | 0 |
| L2-proxy | no-waf | 4 KiB | 0.124 | 0.146 | 0.146 | 52 951 | 93 | 0 |
| L2-proxy | no-waf | 8 KiB | 0.141 | 0.157 | 0.157 | 73 431 | 93 | 0 |
| L3-proxy | wasm | bodyless | 3.975 | 5.028 | 5.028 | 53 383 | 91 | 0 |
| L3-proxy | wasm | 1 KiB | 75.715 | 303.723 | 303.723 | 58 600 | 110 | 0 |
| L3-proxy | wasm | 4 KiB | 179.089 | 321.274 | 321.274 | 73 817 | 110 | 0 |
| L3-proxy | wasm | 8 KiB | 376.881 | 861.261 | 861.261 | 110 430 | 111 | 0 |
| L3-proxy | native | bodyless | 1.676 | 2.217 | 2.217 | 50 552 | 84 | 0 |
| L3-proxy | native | 1 KiB | 9.908 | 41.365 | 41.365 | 51 592 | 104 | 0 |
| L3-proxy | native | 4 KiB | 31.465 | 33.665 | 33.665 | 54 665 | 104 | 0 |
| L3-proxy | native | 8 KiB | 60.495 | 64.240 | 64.240 | 75 161 | 105 | 0 |

WAF add-on (L3 − L2) is 3.8 / 75.6 / 179.0 / 376.7 ms for wasm and
1.5 / 9.8 / 31.3 / 60.4 ms for native. The proxy floor is 0.12–0.14 ms and
0.12–0.16 ms at p50, i.e. **the proxy overhead is not the sub-millisecond
blocker**.

The c=8 throughput cells on this host were contaminated by sibling builds and
by oversubscribing four measured CPUs with eight workers. They are recorded
for completeness but must not be read as capacity:

| backend | size | p50 ms | p99 ms | throughput | non-200 |
|---|---|---:|---:|---:|---:|
| wasm | bodyless | 32.058 | 75.541 | 242 req/s | 0 |
| wasm | 1 KiB | 251.400 | 431.784 | 31 req/s | 65 |
| native | bodyless | 80.487 | 366.864 | 85 req/s | 0 |
| native | 1 KiB | 48.835 | 404.115 | 95 req/s | 18 |

The non-200s are admission `503`s (eval timeout / pool saturation), not retries.
They are a real signal that the wasm pool and the native sidecar saturate
before the proxy does; the absolute numbers need a dedicated host.

### 3.4 Engine regression gate

`perf-gate` on the same commit, compared with the committed baseline
(`benchmarks/perf-gate/baseline.json`, taken at `efb56b5`):

| backend | case | baseline p50 ms | current p50 ms | delta | gate |
|---|---|---:|---:|---:|---|
| coraza | bodyless | 3.653 | 3.373 | −7.7 % | ok |
| coraza | 4k-allow | 177.662 | 179.347 | +0.9 % | ok |
| coraza | 4k-sqli | 263.332 | 401.725 | +52.5 % | not reproduced (§3.4.1) |
| rust | bodyless | 0.202 | 0.158 | −21.5 % | ok |
| rust | 4k-allow | 1.919 | 1.231 | −35.9 % | ok |
| rust | 4k-sqli | 1.862 | 1.256 | −32.5 % | ok |
| kernel | bodyless | 0.0093 | 0.0099 | +6.2 % | ok |
| kernel | 4k-allow | 0.570 | 0.676 | +18.6 % | ok |
| kernel | 4k-sqli | 0.318 | 0.350 | +10.1 % | ok |

Allocation side of the same rows: the Rust engine dropped from 2.02 MB /
4 789 allocs to 646 KB / 1 772 allocs at 4 KiB allow, which explains most of
its 36 % p50 improvement. Coraza and kernel allocations are unchanged. The
4k-sqli delta is therefore not allocation growth (6 852 → 6 842 B/op,
5.04 → 5.03 allocs/op) and not envelope growth. A follow-up bisect (§3.4.1)
showed it is not a rule-path change either: the row reflects a guest GC/clock
bimodality.

The regression was re-measured twice more in separate processes on the same
host (`coraza-recheck-1.json`, `coraza-recheck-2.json`):

| run | bodyless p50 | 4k-allow p50 | 4k-sqli p50 |
|---|---:|---:|---:|
| baseline (`efb56b5`) | 3.653 | 177.662 | 263.332 |
| verification run | 3.373 | 179.347 | 401.725 |
| recheck 1 | 3.218 | 170.726 | 377.479 |
| recheck 2 | 3.034 | 170.048 | 388.516 |

Allow and bodyless track the baseline; SQLi is reported 43–53 % slower in
those runs.

### 3.4.1 Follow-up: the 4 KiB SQLi row was not reproducible

A later bisect on the same host, with the sibling builds stopped and the
process pinned first to CPU 5 and then to CPUs 2–5, could not reproduce the
regression in either direction. The Coraza row is **bimodal**: a request either
finishes in ~164 ms or pays a Go guest GC cycle and finishes in ~373 ms. The p50
therefore lands on whichever side of 50 % the GC hits fall in a particular run.
The report above caught a run where most samples were in the slow mode; a
quiet run puts the p50 in the fast mode.

| run (pinned, quiet) | bodyless p50 | 4k-allow p50/p95 | 4k-sqli p50/p95 | sqli/allow |
|---|---:|---:|---:|---:|
| current module (`06c38ec`) | 3.25 | 164.73 / 373.00 | 164.06 / 375.93 | 1.00 |
| baseline module (`efb56b5`) | 3.28 | 164.78 / 371.78 | 164.49 / 374.29 | 1.00 |
| pre-`3a86896` 192 MiB guest | 2.39 | 164.03 / 168.07 | 163.61 / 167.73 | 1.00 |

Evidence that this is not a rule-path commit in `efb56b5..ddc8547`:

* Only `06c38ec` changes the committed guest module. Swapping the `efb56b5`
  and `06c38ec` modules under the same host binary leaves p50/p95 and the
  block decision identical (table above).
* `perf-gate` builds the legacy JSON envelope, so the binary-ABI branch added
  by `06c38ec` is not exercised by this row. The host-side reactor diff adds
  only the optional `decision_base` read; allocations stay at 6 851.84 B /
  5.04 per op, matching the baseline.
* The 164/373 ms split tracks the guest `GOMEMLIMIT`/GC state, not the rules.
  Raising the guest soft limit to 192 MiB removes the GC hit from these short
  runs, but that limit was deliberately lowered to 64 MiB by `3a86896` to bound
  a six-worker pool's RSS, so it is not a free fix.

The actionable defect is therefore the gate, not the engine: an absolute p50
comparison cannot distinguish a slower CPU/GC phase from an attack-path
regression when every row scales together. `compare.sh` now also checks the
same-run `4k-sqli / 4k-allow` ratio, which cancels clock and GC-mode changes.
The committed baseline ratio is 1.48; the quiet runs above are 1.00, and the
ratio gate fails a doubled ratio even when absolute p50 rows are unchanged
(`selftest.sh` covers this case).

PERF-GATE RSS: coraza peak 422 716 KiB, Rust engine 21 732 KiB, kernel
14 700 KiB. `bench-subms` peak RSS (wasm pools + proxy + client + upstream) was
805 560 KiB; the native sidecar peaked at 159 456 KiB.

### 3.5 Request-path components (bodyless)

| component | p50 | p95 | p99 |
|---|---:|---:|---:|
| context construction | 165 ns | 168 ns | 178 ns |
| admission (cheap) | 32 ns | 36 ns | 36 ns |
| metrics (request + allow) | 32 ns | 34 ns | 35 ns |
| `fast_evaluate` (no audit) | 3.17 µs | 3.46 µs | 3.84 µs |
| `evaluate_shared` (full) | 3.20 µs | 3.45 µs | 3.77 µs |
| dispatch (0 rules) | 77 ns | 80 ns | 92 ns |
| fast-allow (compiled route) | 350 ns | 388 ns | 456 ns |
| fast-allow (no rate gates) | 199 ns | 203 ns | 258 ns |
| audit (full − fast) | 49 ns | 54 ns | ≤ 54 ns |

The host-side decision path is already sub-microsecond. Everything above it is
rule-engine work, proxy I/O, or queueing.

### 3.6 Post-optimization remeasurement (`aca35db`)

The transform/gate merge (`#143`) was re-measured on the same host class with
the governor at `performance`, turbo enabled, and every measured process
pinned with `taskset -c 2-5`. Three independent engine-gate runs were taken
(load average 0.86–7.24 at start); the cleanest run (0.86) is shown, with the
other runs in the variance column. All engine/prefilter latencies are process
CPU time.

**Important scope finding.** `#143` changes the *shared* modules
`src/waf/transforms.rs` and `src/waf/prefilter.rs`, but the Rust engine
(`src/waf/rust_engine`) and the experimental kernel (`src/waf/engine_kernel`)
do **not** import them: each has its own `TransformCache`, gate and prefilter.
`git diff 5fae75d..aca35db -- src/waf/rust_engine src/waf/engine_kernel` is
empty. The engine therefore did not get faster because of `#143`; its gain
against the committed baseline is the earlier hot-loop work (`#137`, `#132`).
The `#143` win is visible in the standalone shared prefilter and in its
consumers (fastpath, native sidecar body-wither, optional wasm gate).

#### Rust engine, `rust-engine-parity --bench` (run 2, `--reps 200`)

| body | p50 | p95 | p99 | allocs/req | p50 run 1 |
|---|---:|---:|---:|---:|---:|
| bodyless | 146.04 µs | 161.86 µs | 191.95 µs | 144.0 | 150.68 µs |
| 1 KiB | 468.26 µs | 478.18 µs | 542.78 µs | 148.2 | 451.17 µs |
| 4 KiB | 1 224.43 µs | 1 321.53 µs | 1 417.60 µs | 143.4 | 1 264.57 µs |
| 8 KiB | 2 251.50 µs | 2 332.26 µs | 2 388.64 µs | 143.4 | 2 354.74 µs |

Run-to-run p50 spread is ≤ 4 % at every size. Allocations are steady at
128–157/request (the 4 KiB gate row is 143), versus 4 789/request in the
committed baseline.

#### Shared prefilter, `transform-bench` (two runs)

| size | variant | p50 | p99 | allocs/call | p50 run 2 |
|---|---|---:|---:|---:|---:|
| 1 KiB | plain | 42.57 µs | 44.41 µs | 2.0 | 42.52 µs |
| 1 KiB | percent | 15.69 µs | 16.66 µs | 2.0 | 15.72 µs |
| 1 KiB | double | 19.15 µs | 20.08 µs | 2.0 | 19.18 µs |
| 4 KiB | plain | 150.96 µs | 152.86 µs | 2.0 | 151.58 µs |
| 4 KiB | percent | 47.76 µs | 48.82 µs | 2.0 | 47.76 µs |
| 4 KiB | double | 61.53 µs | 62.58 µs | 2.0 | 61.51 µs |
| 8 KiB | plain | 291.75 µs | 331.94 µs | 2.0 | 294.49 µs |
| 8 KiB | percent | 90.45 µs | 91.60 µs | 2.0 | 90.46 µs |
| 8 KiB | double | 117.70 µs | 153.12 µs | 2.0 | 117.77 µs |

Against the pre-`#143` 4 KiB numbers (604 / 184 / 214 µs) this is −75 % plain,
−74 % percent and −71 % double, and the two post-merge runs agree within 2 %.
The plain row is still above the < 120 µs target; the residual is the 19.2 KiB
of genuinely distinct representations scanned, as documented in
`docs/suggestions_from_agents/transform-hot.md`.

#### Allow-cache hit, `allow_cache_microbench components`

| body | p50 | p95 | p99 |
|---|---:|---:|---:|
| 1 KiB | 536 ns | 545 ns | 625 ns |
| 4 KiB | 699 ns | 756 ns | 783 ns |
| 8 KiB | 927 ns | 1.02 µs | 1.18 µs |

This reproduces the earlier 560 / 730 / 960 ns claim within noise; the body
digest (68 / 229 / 457 ns) and thread-local lookup (101 / 266 / 487 ns) still
dominate the hit path.

#### Fast-allow, `bodyless-bench --profile`

| path | p50 | p95 | p99 |
|---|---:|---:|---:|
| fast-allow (compiled route) | 342 ns | 350 ns | 389 ns |
| fast-allow (no rate gates) | 188 ns | 193 ns | 196 ns |

Run 1 measured 375/385/423 ns and 208/215/222 ns, so the claimed ~0.38 µs and
~0.20 µs paths hold on both runs.

#### Coraza reactor (`bench-subms` L0; clean wasm run, native run 1)

| backend | size | p50 | p95 | p99 | allocs/op | alloc B/op |
|---|---|---:|---:|---:|---:|---:|
| wasm | bodyless | 4.270 µs | 4.719 µs | 6.466 µs | 4.04 | 2 648 |
| wasm | 1 KiB | 39.471 µs | 70.013 µs | 71.500 µs | 4.04 | 3 745 |
| wasm | 4 KiB | 166.055 µs | 374.407 µs | 378.759 µs | 4.02 | 6 787 |
| wasm | 8 KiB | 346.980 µs | 829.515 µs | 834.948 µs | 4.04 | 10 913 |
| native | bodyless | 0.629 µs | 0.734 µs | 1.066 µs | 1.00 | 126 |
| native | 1 KiB | 7.587 µs | 7.917 µs | 8.090 µs | 1.00 | 193 |
| native | 4 KiB | 29.026 µs | 31.754 µs | 35.467 µs | 1.00 | 193 |
| native | 8 KiB | 58.299 µs | 59.828 µs | 60.387 µs | 1.00 | 193 |

The wasm p95/p99 remain bimodal at the ~373 ms guest-GC mode; p50 alone is the
comparable column.

#### Engine gate versus the committed baseline (`baseline.json`, `efb56b5`)

| backend | case | baseline | run 1 | run 2 | run 3 | Δ run 3 |
|---|---|---:|---:|---:|---:|---:|
| coraza | bodyless | 3.6528 | 3.4594 | 3.2620 | 3.2805 | −10.2 % |
| coraza | 4k-allow | 177.6622 | 174.6417 | 164.9296 | 165.3082 | −6.9 % |
| coraza | 4k-sqli | 263.3323 | 173.9483 | 168.4344 | 167.0350 | −36.6 % |
| rust | bodyless | 0.2016 | 0.1255 | 0.1206 | 0.1243 | −38.3 % |
| rust | 4k-allow | 1.9191 | 1.1765 | 1.1136 | 1.1129 | −42.0 % |
| rust | 4k-sqli | 1.8617 | 1.1672 | 1.1256 | 1.1299 | −39.3 % |
| kernel | bodyless | 0.00930 | 0.00955 | 0.00928 | 0.00930 | +0.1 % |
| kernel | 4k-allow | 0.5702 | 0.6441 | 0.6223 | 0.6233 | +9.3 % |
| kernel | 4k-sqli | 0.3180 | 0.3391 | 0.3255 | 0.3262 | +2.6 % |

The Rust rows are reproducible to ≤ 6 % and are the only rows updated in the
committed baseline. The Coraza SQLi row is again in its fast GC mode (~167 ms,
sqli/allow ratio 1.01) and is not a rule-path improvement. The kernel source is
unchanged since the baseline; its longer allow row is consistent with a
host/clock difference (bodyless is unchanged and the attack/allow ratio moved
−6 %), so the kernel baseline rows were deliberately left untouched.

#### Corpus

Re-running the full 2,112-case corpus at `aca35db` reproduces the §4 counts
exactly: wasm and native 2,016/2,112 (5 false negatives, 91 false positives,
2,112/2,112 agreement); Rust 2,016/2,112 with 3 false negatives and the same
91 false positives, agreeing with Coraza on 2,110/2,112 (the two former oracle
differences). A fresh `rust-engine-parity --engine both` run on 2026-11-11 at
`563541b` now agrees on 2,112/2,112: the two differences are resolved. Detection
and parity are otherwise unchanged.

## 4. CRS detection corpus

Pinned corpus: OWASP CRS 4.14.0, commit `b5b788b`, 2,112 cases (1,700 positive
/ 412 negative), source SHA-256 `c970605a…02123`.

| engine | total | passed | false negatives | false positives | detection rate |
|---|---:|---:|---:|---:|---:|
| Coraza WASI reactor | 2 112 | 2 016 | 5 | 91 | 1 695 / 1 700 = 99.71 % |
| Coraza native sidecar | 2 112 | 2 016 | 5 | 91 | 1 695 / 1 700 = 99.71 % |
| Native Rust engine (`waf::rust_engine`) | 2 112 | 2 016 | 3 | 91 | 1 697 / 1 700 = 99.82 % |

Parity:

| comparison | agree | disagree | detail |
|---|---:|---:|---|
| wasm vs native sidecar | 2 112 | 0 | **full decision parity** |
| Rust engine vs Coraza wasm | 2 110 | 2 | `crs-921250-1`, `crs-921250-2`: Rust blocks, Coraza allows; both are corpus-expected blocks, so these are Coraza false negatives |

Wasm/native false negatives: `crs-921250-1`, `crs-921250-2`, `crs-944150-12`,
`crs-944150-13`, `crs-944150-14`. Rust fixes the two `921250` cases. Both
Coraza backends share the same 91 false positives, dominated by `negative`
(91) and protocol/RCE negatives; they are aliasing/paranoia artefacts of the
deployed rule set, not a backend difference.

The `crs_corpus --engine rust` path could not run: `engine::NativeRustEngine`
is the guarantee-layer scaffold and `is_available()` returns `false` on `main`
(`src/engine/backend.rs`). The Rust-engine rows above come from
`rust-engine-parity`, which exercises the real `waf::rust_engine::RustEngine`
against the same corpus. This is a tooling gap, not a detection failure: the
scaffold deliberately refuses to run until the engine workstream links it.

## 5. Feature matrix and release tests

| check | result | wall time |
|---|---|---:|
| `cargo fmt -- --check` | PASS | 5 s |
| `cargo clippy --lib` (default) | PASS | 206 s |
| `cargo test --lib` (default) | PASS | 365 s |
| `cargo test --lib --features wasm-reactor` | PASS | 6 s |
| `cargo test --lib --features wasm-reactor,coraza-native` | PASS | 38 s |
| `cargo test --lib --no-default-features` | PASS | 48 s |
| `cargo test --lib --no-default-features --features wasm-reactor` | PASS | 151 s |
| `cargo check --bin graphql-allowlist --features wasm-reactor` | PASS | 13 s |
| `cargo check --bin grpc-allowlist --features wasm-reactor` | PASS | 1 s |
| `scripts/ci-feature-matrix.sh --quick` | **PASS** (9 passed, 2 skipped, 0 failed) | 833 s |

The two skipped stages are the slow `cargo check --all-targets` combinations,
which `--quick` deliberately omits; they are not failures. The full matrix
without `--quick` is the CI configuration.

### 5.1 Release tests

Release-profile tests were run after the matrix on the same host:

| command | result | wall time |
|---|---|---:|
| `cargo test --release --lib --features wasm-reactor,coraza-native` | **PASS** — 458 passed, 0 failed, 9 ignored | 919 s (includes the release test build) |
| `cargo test --release --test integration --features wasm-reactor,coraza-native` | **PASS** — 47 passed, 0 failed, 10 ignored | 810 s (includes the release test build) |

The release build is LTO + `codegen-units = 1`, so most of the wall time is the
one-off test-harness link, not the tests (the 458 tests themselves run in
1.4 s). These checks do not affect the latency tables above.

## 6. Remaining hot spots

Ranked by share of the measured budget:

1. **Coraza WASI rule evaluation is 99 % of the wasm budget.**
   The `fdb3ca7` reactor p50 was 4.94 ms bodyless, 74 ms at 1 KiB, 180 ms at
   4 KiB and 375 ms at 8 KiB; the `aca35db` clean remeasurement is 4.27 / 39.5
   / 166.1 / 347.0 ms. L3 − L2 matches the reactor within noise. Payload
   construction is 7.3 µs at 4 KiB, i.e. 0.004 % of the request. No proxy or
   serialisation optimisation can move this.

2. **The reported 4 KiB SQLi regression was a measurement artefact.**
   The row is bimodal at ~164 ms (no guest GC) and ~373 ms (GC cycle); a run
   whose samples are mostly in the slow mode reports p50 ≈ 400 ms. Swapping the
   baseline and current guest modules under the same binary gives identical
   p50/p95 and allocation counts, and no commit in `efb56b5..ddc8547` changes
   the JSON rule path. The gate now compares the same-run
   `4k-sqli / 4k-allow` ratio in addition to absolute p50 so clock and GC-mode
   shifts cannot masquerade as an attack-path regression (§3.4.1).

3. **The native sidecar is still CRS-bound.** Reactor 1.18 / 8.08 / 28.75 /
   58.25 ms and engine 1.10 / 7.46 / 28.46 / 58.54 ms: the socket round trip
   adds only ~70 µs bodyless. Sidecar RSS peaks at 159 MB. The native path is
   ~5–6× the wasm path, not a sub-millisecond path at any body size.

4. **The Rust engine is now allocation-light, but still CPU-bound.** At
   `aca35db` it is 1.11–1.22 ms and 143 allocs at 4 KiB, down from 1.92 ms and
   4 789 allocs in the committed baseline. Its remaining cost is transform,
   literal-gate and regex CPU (§6.1), not allocation.

5. **Queueing, not rule cost, dominates concurrency.** L3 c=8 wasm was 32 ms
   bodyless (vs 4.0 ms at c=1) and 251 ms at 1 KiB with 65/400 non-200
   admission failures; native c=8 was 80 ms bodyless. The pool (4 workers) and
   the sidecar connection pool saturate before the proxy.

6. **Tail latency is unstable on this host.** wasm 8 KiB p99 898 ms (2.4× p50),
   coraza 4 KiB p99 418 ms, and an earlier run of the Rust/Coraza table saw
   multi-second p99 from scheduler stalls. The 1.7 GHz base clock under
   sustained load explains part of it; a dedicated host is required before
   quoting p99 or throughput.

The allow-cache hit path is now measured: 536 / 699 / 927 ns p50 at
1 / 4 / 8 KiB (§3.6), reproducing the earlier 560 / 730 / 960 ns claim. It
remains a non-default feature and applies only to repeat requests.

### 6.1 Post-optimization top three (`aca35db`, Rust engine at 4 KiB)

The engine source is unchanged since the hot-loop merge, so its last profile
still describes the 1.11–1.22 ms 4 KiB row:

| rank | hot spot | cost at 4 KiB | share | why it remains |
|---:|---|---:|---:|---|
| 1 | Rust-engine transform pipeline | ~400 µs | ~36 % | private `TransformCache` + per-step transform, not the batched shared pipeline that `#143` improved |
| 2 | Regex / operator evaluation | ~374 µs | ~33 % | 181 operator evaluations at 4 KiB; literal gates skip 99 of them, the rest still run `regex` |
| 3 | Rust-engine literal gate | ~360 µs | ~32 % | private gate: per-value transform + AC scan without the shared case-insensitive union / rule-bitset attribution |

Candidate resolution, scoring, parse and captures together are under 6 %. For
the wasm backend the dominant cost is still Coraza rule evaluation, with the
~373 ms guest-GC tail as the largest p95/p99 risk.

## 7. Next five optimisations

Ranked by expected gain / effort / risk. None is implemented by this report.

| # | change | expected gain | effort | risk |
|---|---|---|---|---|
| 1 | **Stabilise the Coraza guest GC tail** (the 164/373 ms bimodality, §3.4.1). The rule path and binary ABI are not the cause; the guest `GOMEMLIMIT`/GC phase is. | p95 373 → ~168 ms and p50 no longer crosses into the slow mode; needs an RSS/soak tradeoff | M | M |
| 2 | **Use the binary v1 frame on the proxy → wasm path.** L1 measures 0.26 µs / 193 B / 1 alloc at 4 KiB versus 7.6 µs / 22.4 KB / 46 allocs for JSON. L3 wasm still shows JSON-sized allocations. | ~7.6 ms and ~22 KB / 46 allocs per 4 KiB request (≈4 % of p50); larger relative gain at 8 KiB | M | L–M (versioned ABI) |
| 3 | **Remove Rust-engine allocations.** 646 KB / 1 772 allocs at 4 KiB versus kernel 33 B / 1. Reuse an arena/scratch across evaluation and borrow request strings. | 20–40 % of the 1.24 ms 4 KiB row; brings Rust engine near the kernel's 0.68 ms | M–H | M (aliasing/lifetime correctness, differential corpus required) |
| 4 | **Prove a body prefilter and skip Coraza for clean bodies.** Hyperscan/literal prefilter or the compiled fast path currently covers only a small clean subset (44/2,112 in the prototype). | 2–3× on allow paths if parity holds; enables sub-ms at 1–4 KiB without changing the rule engine | H | H (false negatives, corpus proof, fallback correctness) |
| 5 | **Cut the proxy floor and batch the sidecar transport.** L2 allocates 50–73 KB / 83–93 allocs per request; native bodyless spends ~70 µs on the round trip and 0.85 ms in CRS. Batch/pipeline native evaluations and lazy-init the buffer pool. | 50–80 µs bodyless proxy; ~0.1–0.2 ms native bodyless; more under c=8 | M | L (proxy) / M (protocol) |

### 7.1 Post-optimization next steps (`aca35db`)

| # | change | expected gain | effort | risk |
|---|---|---|---|---|
| 1 | **Unify the Rust engine with the shared transform pipeline and gate.** It has a private `TransformCache`/gate, so the `#143` batching, identity aliasing, entity index, case-insensitive union and rule bitsets never reach it. Port them or refactor the engine onto `src/waf/transforms.rs` + `src/waf/prefilter.rs`. | 30–40 % off the 4 KiB row (≈1.11 → 0.7–0.8 ms) and a similar share at 8 KiB, based on the shared prefilter going 604 → 151 µs | M–H | M (byte-for-byte corpus parity required) |
| 2 | **Attack the remaining regex/operator cost.** After (1), regex evaluation is the largest bucket: compile gate-selected rule sets to dense `regex-automata` DFAs with a bounded per-group build budget, or add a per-group literal prefilter. | 15–25 % off the 4 KiB row; larger at 8 KiB | H | M (DFA size/startup, parity) |
| 3 | **Stabilise the Coraza guest GC tail.** The 164/373 ms bimodality is still the wasm p95 root cause; p50 166 ms is unchanged in the fast mode. | p95 373 → ~168 ms | M | M (RSS/soak tradeoff) |

The shared prefilter itself is now fast enough (47.8 µs percent, 151 µs plain
at 4 KiB) that the next meaningful gain is integrating it into the engine
rather than optimising it further. The plain-input < 120 µs target still needs
content-type-aware extraction or a whitespace/case-aware matcher, as recorded
in `docs/suggestions_from_agents/transform-hot.md`.

An allow-cache hit path (if the feature is adopted) is the only mechanism that
turns a 4.9 ms wasm bodyless request into a sub-microsecond one, but it applies
only to repeat requests and must remain opt-in until its TTL/correctness proof
is part of the corpus gate.

## 8. What would it take to claim sub-millisecond end-to-end?

The measured end-to-end p50 is `L2 proxy floor + engine + transport`. The proxy
floor is **0.12–0.16 ms** at c=1, so a sub-ms claim requires the engine and
transport to stay under roughly **0.85 ms**.

| backend | bodyless | 1 KiB | 4 KiB | 8 KiB | sub-ms today? |
|---|---:|---:|---:|---:|---|
| Coraza wasm | 4.27 ms | 39.5 ms | 166.1 ms | 347.0 ms | no, by 4–400× |
| Coraza native | 0.63 ms | 7.59 ms | 29.0 ms | 58.3 ms | no, by 1.5–60× |
| Rust engine (L0 only) | 0.124 ms | 0.468 ms | 1.113 ms | 2.252 ms | bodyless and 1 KiB yes *if* wired into the proxy; 4 KiB no |
| Kernel (covered subset) | 0.0093 ms | — | 0.623 ms | — | bodyless and 4 KiB yes on the covered rule subset |

To make the claim honestly, all of the following are needed:

1. **An engine row at or below ~0.85 ms for the claimed body size.** Today that
   is the Rust engine at bodyless/1 KiB and the kernel at 4 KiB; Coraza in
   either backend cannot meet it.
2. **A measured L3 row for that engine.** The Rust engine has no end-to-end
   proxy row on `main`; `bench-subms` only wires the wasm and native Coraza
   backends. The 0.29 ms bodyless sum above is a projection, not a measurement.
3. **The proxy floor left alone.** It is already 0.12–0.16 ms, so the remaining
   budget is in the engine. Further proxy work buys tens of microseconds, not
   milliseconds.
4. **p99 ≤ 2× p50 at c=1 and a stated c=8 throughput without non-200s.** On this
   host the wasm p99 is 2.4× p50 at 8 KiB and the c=8 cells admit 503s. A
   single-run p50 is not enough for an SLO claim.
5. **Detection proof.** Any engine that replaces Coraza must reproduce the
   corpus parity table in §4 (currently wasm/native 2 112/2 112; Rust 2 110/2 112
   with two Coraza false negatives) and keep the fail-closed/accounting gates.
6. **A stable clock.** Record the governor, turbo state and observed frequency
   with every claim. The same binary moved 1.7–3.0× between runs on this host
   when those changed.

In short: **sub-millisecond end-to-end is not a property of the merged Coraza
path at any size.** It is reachable at bodyless (and narrowly at 1 KiB) with
the Rust engine once that engine is wired into the proxy and measured at L3,
and at 4 KiB only with the kernel or a proven prefilter. Claiming it for the
shipped Coraza backend would require a 4–450× engine improvement, which is a
replacement, not a tuning change.

## 9. Reproduction

On a quiet host of the same class:

```sh
# 1. Quiet the host and record the controls.
sudo cpupower frequency-set -g performance      # or write scaling_governor
cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor
cat /sys/devices/system/cpu/intel_pstate/no_turbo
uptime

# 2. Full suite (build once, then re-use with --skip-build).
nix develop -c ./scripts/verify-performance.sh --cpus 2-5

# 3. Optional feature matrix and release tests.
nix develop -c ./scripts/verify-performance.sh --skip-build --with-matrix

# 4. Re-run only the gate against the committed baseline.
nix develop -c ./benchmarks/perf-gate/compare.sh \
  target/perf-verify/<run>/perf-gate.json
```

The script always writes raw artefacts; `summary.md` is a convenience view, not
the source of truth. Compare only runs with the same `environment.json`
(cpu_model, governor, turbo, frequency) and the same `--samples`/`--reps`.

## 10. Caveats and blockers

- The host is shared; sibling builds were moved to CPUs 0–1 for this run. The
  load-average field is not a measure of pressure on CPUs 2–5.
- Turbo/frequency varies with sustained load; p99 and c=8 throughput are not
  stable enough for an SLO.
- `allow-cache` has no harness on `main`; its hit-path claim is unverified.
- `crs_corpus --engine rust` cannot run because `engine::NativeRustEngine` is
  an unavailable scaffold; the real Rust engine is measured by
  `rust-engine-parity`.
- The 4 KiB SQLi "regression" is not reproducible on a quiet pinned host; it is
  a GC/clock bimodality (§3.4.1). The absolute p50 gate is now complemented by a
  same-run `4k-sqli / 4k-allow` ratio check so a real attack-path regression is
  still caught.
- The underlying guest GC tail (p95 ~373 ms versus p50 ~164 ms on a 4 KiB
  attack body) remains. Fixing it needs a GC/memory-limit tradeoff and a soak
  measurement; it is listed in §7 rather than changed in this report.

## 11. Request-path allocation removal (`perf/request-path-allocs`)

**Branch:** `perf/request-path-allocs`, base `6868a11`. Six alternating
before/after `bench-subms --only l0` runs, 20 samples per cell; medians are
reported. Host load average was 3.5–4.4 at the start of each run (shared host).

### 11.1 The 646 KB/4 KiB baseline is historical

The 646 468 B/op and 1 772 allocs/op at 4 KiB in §3.1/§6 were measured at
`aca35db`. They are **not reproducible on `6868a11`**: the same Rust engine
cell measures 5 445 B/op and 82 allocs/op, and the allocation-size histogram has
no bucket above 1 KiB. The body is already borrowed end to end (the transform
cache copies it once into a reused arena, and the rules see slices); the
zero-copy work landed before this branch. This section therefore measures the
*remaining* owned copies, not a 160× amplification.

### 11.2 What was copied and why

- `RequestData::resolve_into` cloned single-value collections for every rule
  that targeted them: `REQUEST_LINE` (an owned `Cow`), `REQUEST_URI`,
  `REQUEST_FILENAME`, `REQUEST_BASENAME`, `REQUEST_PROTOCOL`, `QUERY_STRING` and
  `REQBODY_PROCESSOR`. Each clone allocated once per targeting rule. They are
  now borrowed with the `'r` lifetime of the request data.
- GET argument parsing always materialised owned `Entry` keys and values even
  when `parse_query` returned borrowed slices. `build()` now matches
  `Cow::Borrowed(query)` and keeps the zero-copy entries; the normalised
  (owned) query case still owns, as it must.
- Response single-value collections (`RESPONSE_STATUS`, `RESPONSE_PROTOCOL`,
  `RESPONSE_BODY`, content type/length) follow the same borrow.
- TX and MATCHED_VARS candidates still own their bytes. `setvar` and
  `record_match` mutate those arenas while the candidate list is being
  evaluated, so borrowing would alias a mutable buffer. Their values are small
  (scores and names); making them borrowed needs the arena-backed IR change
  described in §6.1, not a one-line lifetime change.
- Content inspection still uses `String::from_utf8_lossy` and
  `urlencoding::decode` because its patterns are `regex::Regex` over `&str`.
  Valid-UTF-8 bodies borrow (no copy). Bodies that are not valid UTF-8, or that
  contain `%`/`+`, get **one** owned representation for the decoded/UTF-8 view.
  That is the only body-proportional copy left in the inspection path (≤1× the
  body, only when the decoded view is needed). Switching the patterns to
  `regex::bytes` would change operator semantics and was not done.
- The proxy forwards the inspected body by moving the same `Bytes` handle into
  `ProxyBody::buffered`; `RequestContext` holds a refcount clone. The egress
  normalisation is unchanged (client `Transfer-Encoding` stripped, exact
  `Content-Length` stamped).

### 11.3 Before/after (L0-engine rust, `bench-subms`)

Medians of six alternating runs:

| size | before p50 ms | after p50 ms | before allocs/op | after allocs/op | before B/op | after B/op |
|---|---:|---:|---:|---:|---:|---:|
| bodyless | 0.1266 | 0.1224 | 75 | **28** | 3 103 | **2 774** |
| 1 KiB | 0.2810 | 0.2770 | 82 | **35** | 5 445 | **5 075** |
| 4 KiB | 0.5797 | 0.5918 | 82 | **35** | 5 445 | **5 075** |
| 8 KiB | 1.0070 | 1.0082 | 82 | **35** | 5 445 | **5 075** |

Allocation counts are deterministic. The 4 KiB p50 moved +2.1 % and the 8 KiB
p50 +0.1 %; the per-run distributions overlap (4 KiB before 0.571–0.612 ms,
after 0.580–0.673 ms) and the after runs were taken at slightly higher load, so
this is unchanged within noise. Bodyless and 1 KiB p50 improved 3.3 % and 1.4 %
respectively. Per-request allocation count fell 57 % at every body size.

### 11.4 Full proxy (L3-proxy rust, loopback)

One run, 30 sequential requests per cell. This row includes the keep-alive
client and the in-process mock upstream, so its body copies are dominated by
the harness; the WAF add-on is the L3−L2 delta.

| size | before p50 ms | after p50 ms | before allocs/op | after allocs/op | before B/op | after B/op |
|---|---:|---:|---:|---:|---:|---:|
| bodyless | 0.428 | 0.424 | 156 | **109** | 68 082 | 67 753 |
| 1 KiB | 0.664 | **0.579** | 226 | **179** | 121 372 | 121 011 |
| 4 KiB | 0.966 | **0.931** | 174 | **127** | 83 710 | 83 340 |
| 8 KiB | 1.381 | 1.387 | 178 | **131** | 136 686 | 136 308 |

### 11.5 Remaining allocation profile (4 KiB)

`engine-profile`, one profiled request after warm-up (allocation events):

| category | before | after |
|---|---:|---:|
| candidate resolution | 56 | **10** |
| TX values | 13 | 13 |
| parse / request build | 10 | 10 |
| operators | 4 | 4 |
| scoring | 3 | 3 |
| transforms | 0 | 0 |
| **total** | **92** | **46** |

After the change the 4 KiB histogram is 15 allocations ≤16 B, 9 at 17–64 B,
7 at 65–256 B and 4 at 257–1024 B; there is no allocation above 1 KiB. The top
remaining sites are TX value clones (13), candidate resolution of mixed/owned
single-value collections and `MATCHED_VARS` (10), request build (10), operator
captures (4) and first-use TX scoring slots (3).

The single-value body above understates the multi-field case, which is the
largest allocation site left: a 4 KiB urlencoded body with 64 distinct fields
allocates **52 529 B / 210 allocations** (before this branch: 55 477 B / 225)
against 4 979 B / 36 for a one-argument body of the same size — ≈740 B and
≈2.7 allocations per distinct argument. That is the transform cache's
per-`(value, pipeline)` output plus the per-argument candidates: each transformed
value is a distinct byte sequence the rules must see, so it cannot be borrowed.
`parse_query` now also sizes its `Vec` from the separator count, so a
many-field body stops growing through log2(N) reallocations (one pass over the
body, no copy of the payload).

### 11.6 10 MiB cap stress cell

`bench-subms --stress-10m` adds the default `server.max_body_size` cell. At
10 MiB the Rust engine returns

```text
Block { status: 500, reason: "Rust engine runtime error (fail-closed):
transform output exceeded the per-request byte cap" }
```

because `Collections::process_body_bytes` charges the whole body through
`Budget::bytes`, whose per-value cap is `Limits::max_value_bytes` (1 MiB;
`max_total_bytes` is 8 MiB). The body is therefore refused **before phase 2**:
there is no body-proportional allocation to remove, but a configured 10 MiB
body is not inspectable. This is a blocker. Raising the cap would change
verdicts (from a blanket 500 to content-based allow/block) and needs an
architecture decision; it was not changed here. The stress cell records 209 →
201 allocs/op and 17 002 → 16 958 B/op at the fail-closed point (the small
reduction is the same candidate-borrow change).

A second pre-existing fail-closed path was found by the same harness: a 4 KiB
urlencoded body with **64 fields** returns

```text
Block { status: 500, reason: "Rust engine runtime error (fail-closed):
per-request budget exceeded: too many variable values" }
```

`Limits::max_values_per_rule` (4 096) is charged through one `Budget` for the
whole request, not per rule, so a form with enough fields exhausts it and the
request is refused. Like the 10 MiB case this changes decisions if fixed
(truncation or a per-rule budget), so it is recorded here and not changed.

### 11.7 Cache behaviour: the copy-pressure story does not hold

`perf` 7.1.1 from the Nix store; `kernel.perf_event_paranoid = 2`, uid 1000,
`CapEff 0`. At that level **`perf stat -p <pid>` is refused** (every event comes
back `<not counted>`), so counters can only be taken from a process perf itself
starts. That process also compiles the 505-rule CRS bundle (~2.5 G instructions
and ~0.8 M last-level misses) before it runs a single measured request, and the
compile's miss count varies with allocator/hash layout. Repeats of the *same*
binary, loop counters divided by the completed requests, gave 45, 75 and 122
LLC-load-misses per request at 4 KiB — a ±50 % spread. The per-request hardware
figures in the first version of this section (69.28 → 57.91) were within that
spread: the 16.4 % "improvement" was the compile prologue, not the request path.

The conclusion therefore uses Cachegrind (`--cache-sim=yes`, 8 MiB unified last
level), where both the prologue and the loop are deterministic: the loop's cost
is the exact difference between a 0-repeat and a *N*-repeat run of the same
binary, so the prologue cancels.

| cell | LLd misses/req before | after | D1 misses/req before | after | instructions/req before | after |
|---|---:|---:|---:|---:|---:|---:|
| 4 KiB | 3.6 | 27.4 * | 13 212 | 13 079 (−1.0 %) | 4 052 831 | 4 065 700 (+0.3 %) |
| 10 MiB | 0.03 | −0.1 * | 3 865 | 3 828 (−1.0 %) | 370 679 | 369 565 (−0.3 %) |

\* At the noise floor: two builds of the same harness differ by ~5 000 LLd
misses in the prologue, which is ±25 misses/request at the 200-request sample
used here. The value is also not stable in sign, so it is not an effect.

**Falsification condition: held.** Last-level misses per request are ~4 at
4 KiB (0.001 per body byte) before *and* after and do not fall when the copies
are removed, because a warmed request already lives in an 8 MiB LLC: the
removed allocations were ~466 B in ≤64 B size classes (tcache hits, no LLC
traffic). What moves is the L1 data-miss count (−1.0 %), matching a handful of
small allocations per request, and nothing else.

The explanation for the latency slope is therefore *instruction-bound rule
scanning*, not cache pressure: p50 is 0.27 / 0.56 / 0.96 ms at 1 / 4 / 8 KiB,
i.e. ≈0.12 ms and ≈0.7 M instructions per KiB of body, while per-request
allocated bytes are constant (4 979 B) from 1 KiB to 8 KiB.

### 11.8 Allocation gate

`perf-gate-bench` now enforces bytes/op and allocs/op for the Rust backend
(counts are deterministic and do not move with host load). Limits are the
measured after values plus headroom:

| case | measured B/op | limit | measured allocs/op | limit |
|---|---:|---:|---:|---:|
| bodyless | 2 610 | 4 000 | 28 | 45 |
| 4k-allow | 4 942 | 7 000 | 31 | 50 |
| 4k-sqli | 9 130 | 13 000 | 37 | 60 |

A row above either limit prints the table and exits non-zero; use
`--no-alloc-gate` for a measurement-only run.

`perf-gate-bench --only waf` covers the full request path (admission,
protocol pre-checks, content inspection and the rule chain) at bodyless,
1 KiB, 4 KiB, 8 KiB, 10 MiB, a 64-field 4 KiB form and 4 KiB SQLi. Limits are
the measured after values plus ~15 % headroom:

| case | measured B/op | limit | measured allocs/op | limit |
|---|---:|---:|---:|---:|
| bodyless | 2 658 | 3 200 | 29 | 40 |
| 1 KiB / 4 KiB / 8 KiB | 4 979 | 5 888 | 36 | 48 |
| 10 MiB | 16 941 | 19 968 | 201 | 224 |
| 4 KiB form, 64 fields | 52 529 | 61 440 | 210 | 240 |
| 4 KiB SQLi | 9 745 | 11 520 | 54 | 64 |

The 10 MiB and 64-field rows record their fail-closed decisions (§11.6) rather
than pretending the body was inspected. Every row also carries
`block_status`/`block_reason` in the JSON so a decision change shows up next to
the allocation numbers.

### 11.9 Verification

- `rust-engine-parity --engine both`: **2 112/2 112** agree, rust/coraza both
  1 788 block / 324 allow, 0 errors, rust FN 3 = coraza FN 3, i.e. **0
  native-only false negatives**.
- `cargo fmt -- --check`: clean.
- `cargo clippy --lib -- --deny warnings` and `cargo clippy --release
  --features wasm-reactor,rust-engine,engine-kernel --bin perf-gate-bench -- --deny warnings`:
  clean.
- `cargo test --lib`: 692 passed, 0 failed, 11 ignored.
- `cargo test --test integration`: 87 passed, 0 failed, 14 ignored.
- `nix build .#waf-ingress`: exit 0
  (`/nix/store/npdkbdsiyifpim2n3fsgm6rwgw1vyhd2-waf-ingress-0.1.0-beta.16`).
- `perf-gate-bench --only waf` with the gate enabled: all seven cases pass
  their allocation ceilings.
