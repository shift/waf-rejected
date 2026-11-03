# Performance verification (post-merge baseline)

**Status:** measurement report and reproduction procedure. No engine, proxy or
configuration default is changed by this document. The numbers are a snapshot
of `main` at the commit below on one shared host; absolute values are only
comparable to another run from `scripts/verify-performance.sh` on the same host
class with the same governor and turbo state.

**Commit:** `fdb3ca7` (`perf(proxy): zero-copy request path between proxy and
engine (#136)`), the tip after the performance branch merge window.

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
| coraza | 4k-sqli | 263.332 | 401.725 | **+52.5 %** | **REGRESSION** |
| rust | bodyless | 0.202 | 0.158 | −21.5 % | ok |
| rust | 4k-allow | 1.919 | 1.231 | −35.9 % | ok |
| rust | 4k-sqli | 1.862 | 1.256 | −32.5 % | ok |
| kernel | bodyless | 0.0093 | 0.0099 | +6.2 % | ok |
| kernel | 4k-allow | 0.570 | 0.676 | +18.6 % | ok |
| kernel | 4k-sqli | 0.318 | 0.350 | +10.1 % | ok |

Allocation side of the same rows: the Rust engine dropped from 2.02 MB /
4 789 allocs to 646 KB / 1 772 allocs at 4 KiB allow, which explains most of
its 36 % p50 improvement. Coraza and kernel allocations are unchanged. The
4k-sqli regression is therefore not allocation growth (6 852 → 6 842 B/op,
5.04 → 5.03 allocs/op) and not envelope growth; it is in the rule evaluation
or anomaly-scoring path for the attack body.

The regression was re-measured twice more in separate processes on the same
host (`coraza-recheck-1.json`, `coraza-recheck-2.json`):

| run | bodyless p50 | 4k-allow p50 | 4k-sqli p50 |
|---|---:|---:|---:|
| baseline (`efb56b5`) | 3.653 | 177.662 | 263.332 |
| verification run | 3.373 | 179.347 | 401.725 |
| recheck 1 | 3.218 | 170.726 | 377.479 |
| recheck 2 | 3.034 | 170.048 | 388.516 |

Allow and bodyless track the baseline; SQLi is consistently 43–53 % slower.
This is a reproducible regression, not a one-off scheduler artefact.

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
   Reactor p50 is 4.94 ms bodyless, 74 ms at 1 KiB, 180 ms at 4 KiB and 375 ms
   at 8 KiB; L3 − L2 matches the reactor within noise. Payload construction is
   7.6 µs at 4 KiB, i.e. 0.004 % of the request. No proxy or serialisation
   optimisation can move this.

2. **The 4 KiB SQLi path regressed 52 % against the committed gate**
   (263 → 402 ms p50) while 4 KiB allow is unchanged (+0.9 %) and bodyless
   improved (−7.7 %). Allocation counters are identical. This is the only
   gate failure and is specific to the attack body, which points at rule
   evaluation / anomaly scoring rather than the envelope or frequency alone.

3. **The native sidecar is still CRS-bound.** Reactor 1.18 / 8.08 / 28.75 /
   58.25 ms and engine 1.10 / 7.46 / 28.46 / 58.54 ms: the socket round trip
   adds only ~70 µs bodyless. Sidecar RSS peaks at 159 MB. The native path is
   ~5–6× the wasm path, not a sub-millisecond path at any body size.

4. **The Rust engine trades CPU for allocations.** 1.24 ms and 646 KB / 1 772
   allocs at 4 KiB, versus the kernel's 0.68 ms and 33 B / 1 alloc. It improved
   36 % over baseline but still allocates ~500× more bytes than the kernel for
   the same decision class.

5. **Queueing, not rule cost, dominates concurrency.** L3 c=8 wasm was 32 ms
   bodyless (vs 4.0 ms at c=1) and 251 ms at 1 KiB with 65/400 non-200
   admission failures; native c=8 was 80 ms bodyless. The pool (4 workers) and
   the sidecar connection pool saturate before the proxy.

6. **Tail latency is unstable on this host.** wasm 8 KiB p99 898 ms (2.4× p50),
   coraza 4 KiB p99 418 ms, and an earlier run of the Rust/Coraza table saw
   multi-second p99 from scheduler stalls. The 1.7 GHz base clock under
   sustained load explains part of it; a dedicated host is required before
   quoting p99 or throughput.

The allow-cache hit path (0.56–0.96 µs claimed in earlier work) is **not
reproduced here**: `allow-cache` is a non-default feature and `main` has no
benchmark binary for it. It should be measured before it is quoted as a
backend row.

## 7. Next five optimisations

Ranked by expected gain / effort / risk. None is implemented by this report.

| # | change | expected gain | effort | risk |
|---|---|---|---|---|
| 1 | **Bisect and fix the 4 KiB SQLi regression** (`perf-gate` coraza 4k-sqli +52 %). Start from the merged commits `#132`–`#136`; the unchanged allow row and allocation counters narrow it to the attack/scoring path. | 139 ms p50 back on attack requests (402 → 263 ms); no detection change if it is pure overhead | M | L |
| 2 | **Use the binary v1 frame on the proxy → wasm path.** L1 measures 0.26 µs / 193 B / 1 alloc at 4 KiB versus 7.6 µs / 22.4 KB / 46 allocs for JSON. L3 wasm still shows JSON-sized allocations. | ~7.6 ms and ~22 KB / 46 allocs per 4 KiB request (≈4 % of p50); larger relative gain at 8 KiB | M | L–M (versioned ABI) |
| 3 | **Remove Rust-engine allocations.** 646 KB / 1 772 allocs at 4 KiB versus kernel 33 B / 1. Reuse an arena/scratch across evaluation and borrow request strings. | 20–40 % of the 1.24 ms 4 KiB row; brings Rust engine near the kernel's 0.68 ms | M–H | M (aliasing/lifetime correctness, differential corpus required) |
| 4 | **Prove a body prefilter and skip Coraza for clean bodies.** Hyperscan/literal prefilter or the compiled fast path currently covers only a small clean subset (44/2,112 in the prototype). | 2–3× on allow paths if parity holds; enables sub-ms at 1–4 KiB without changing the rule engine | H | H (false negatives, corpus proof, fallback correctness) |
| 5 | **Cut the proxy floor and batch the sidecar transport.** L2 allocates 50–73 KB / 83–93 allocs per request; native bodyless spends ~70 µs on the round trip and 0.85 ms in CRS. Batch/pipeline native evaluations and lazy-init the buffer pool. | 50–80 µs bodyless proxy; ~0.1–0.2 ms native bodyless; more under c=8 | M | L (proxy) / M (protocol) |

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
| Coraza wasm | 3.98 ms | 75.7 ms | 179.1 ms | 376.9 ms | no, by 4–450× |
| Coraza native | 1.68 ms | 9.91 ms | 31.5 ms | 60.5 ms | no, by 1.7–60× |
| Rust engine (L0 only) | 0.158 ms | 0.477 ms | 1.241 ms | 2.266 ms | bodyless and 1 KiB yes *if* wired into the proxy; 4 KiB no |
| Kernel (covered subset) | 0.0099 ms | — | 0.676 ms | — | bodyless and 4 KiB yes on the covered rule subset |

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
- The 4 KiB SQLi regression is reproducible in this run (one gate failure) but
  needs a second confirmation and a bisect before it is attributed to a merged
  commit.
