# Performance regression gate and competitive baseline

**Status:** benchmark harness, committed baseline and opt-in comparison gate.
No production default, engine implementation or budget gate is changed by this
document.

The layered sub-millisecond budget is tracked by
[`../operations/subms-budget.md`](../operations/subms-budget.md). That harness
answers *where the time goes* for the full proxy. This gate answers a narrower,
repeatable question: **did the request engine itself get slower than the
committed baseline?** It measures the three engines behind the same synthetic
requests and compares p50 against a checked-in JSON baseline.

## What is measured

`src/bin/perf_gate_bench.rs` runs one backend per process:

| id | engine | measured call | what is excluded |
|---|---|---|---|
| `coraza` | Coraza WASI reactor on wasmtime, committed `wasm/coraza_reactor/coraza_reactor.wasm`, pool size 1 | `WasmReactor::evaluate(prebuilt payload)` | JSON payload construction, HTTP, TLS, proxy |
| `rust` | native Rust CRS engine (`rust-engine`) | `RustEngine::evaluate(EngineRequest)` | HTTP, TLS, proxy |
| `kernel` | experimental native kernel (`engine-kernel`) | `KernelEngine::evaluate(RequestInput, Arena)` | HTTP, TLS, proxy |

Cases are identical for every backend:

* `bodyless` — `GET /index.html` with Host, User-Agent and Accept.
* `4k-allow` — `POST /submit`, URLENCODED `data=` body padded to 4 KiB.
* `4k-sqli` — the same shape with `1+union+select+password+from+users` in the
  `data` argument.

Per row the harness records nearest-rank p50/p95/p99, mean and max of **process
CPU time** (`CLOCK_PROCESS_CPUTIME_ID`), wall throughput (samples / wall
second), host allocation bytes and calls per operation, and the decision.
Process `VmRSS`/`VmHWM` and the CPU affinity mask are recorded in `meta`. A
counting global allocator is enabled only around the allocation loop. CPU time
is used for the latency percentiles because the reference host is shared and
wall time is dominated by other agents; throughput remains wall-based and is
therefore a lower bound under contention.

The Coraza row deliberately measures the reactor, not `coraza_payload`; it is
therefore a lower bound on the full Coraza backend and tracks rule-engine
regressions rather than serde/envelope changes. Guest linear memory is not
counted by the host allocator; it shows up in RSS instead. The native engine
and kernel rows include their request parsing and evaluation.

## Running it

All commands go through the Nix development shell:

```sh
# Build, pin to CPUs 2-5, run all three backends, write a timestamped report.
nix develop -c ./benchmarks/perf-gate/run.sh

# Compare a fresh report with the committed baseline.
nix develop -c ./benchmarks/perf-gate/compare.sh benchmarks/perf-gate/results/<file>.json

# Verify the gate itself on synthetic pass/fail input.
nix develop -c ./benchmarks/perf-gate/selftest.sh
```

Useful options:

```sh
./benchmarks/perf-gate/run.sh --samples 100 --warmup 20 --alloc-reps 100
PERF_GATE_CPUS=0-3 ./benchmarks/perf-gate/run.sh
PERF_GATE_CPUS=all ./benchmarks/perf-gate/run.sh      # unpinned, for debugging
./benchmarks/perf-gate/run.sh --out benchmarks/perf-gate/results/latest.json
```

`run.sh` records the host, kernel, CPU model and count, affinity mask, scaling
governor, turbo state, load average at start, `rustc`, `cargo`, Nix and git
commit in the report. It refuses to run unpinned unless
`PERF_GATE_CPUS=all` is set explicitly.

### Quiet-host checklist

Absolute values are only comparable on the same class of host. Before recording
a baseline:

1. wait for other builds/tests to finish (`uptime`; 1-minute load should be
   below the physical core count, ideally near 0);
2. use a fixed affinity mask (`PERF_GATE_CPUS`), ideally cores unused by the
   rest of the system;
3. set the `performance` governor and disable turbo where permitted, and record
   the settings (`run.sh` does this automatically when readable);
4. discard the first post-build run (page cache, reactor warm-up);
5. run at least three times and use the median p50 per row;
6. keep the JSON reports and the exact command line in the review/commit.

## Baseline and regression gate

`benchmarks/perf-gate/baseline.json` is a complete report produced by
`run.sh`. Rows are keyed by `(backend, case)`; the gate compares p50 only.

```sh
# Report only. Always exits 0, so shared CI cannot fail by accident.
./benchmarks/perf-gate/compare.sh results.json

# Explicit enforcement. Non-zero if any row regresses by more than 20% p50.
./benchmarks/perf-gate/compare.sh --enforce --threshold 0.20 results.json
```

The default threshold is +20% p50. `--threshold` accepts any fraction, and
`--baseline` selects a different reference report. Without `--enforce` the gate
prints `WOULD FAIL` and exits 0; this is deliberate because the reference host
is shared and noisy. CI may run the report-only form everywhere and the
`--enforce` form only on a dedicated benchmark runner.

Baseline update policy:

* update **only** for an intentional, reviewed engine change, in the same PR as
  the change, with the old and new numbers in the description;
* never raise a baseline to make an unrelated PR pass;
* if the new number is a regression that is accepted for a security or
  correctness reason, document why in the PR and in this file;
* keep the old report in `benchmarks/perf-gate/results/` for audit.

### Current baseline

Run 2026-11-02, release build, 50 samples per case, 5 warm-up iterations,
`taskset -c 2-5`, Intel i5-8400T (6 logical), Linux 6.18.36, `powersave`
governor, turbo enabled, load average 2.70 at start. Latency is process CPU
time; throughput is wall-based and therefore a lower bound under contention.

| backend | case | p50 ms | p95 ms | p99 ms | throughput req/s | alloc B/op | allocs/op | decision |
|---|---|---:|---:|---:|---:|---:|---:|---|
| coraza | bodyless | 3.653 | 4.083 | 4.132 | 276 | 2 659 | 4.04 | allow |
| coraza | 4k-allow | 177.662 | 404.732 | 486.690 | 4.5 | 6 799 | 4.02 | allow |
| coraza | 4k-sqli | 263.332 | 599.848 | 717.985 | 1.8 | 6 852 | 5.04 | block |
| rust | bodyless | 0.202 | 0.239 | 0.241 | 4 807 | 125 379 | 2 666 | allow |
| rust | 4k-allow | 1.919 | 2.048 | 2.090 | 515 | 2 024 667 | 4 789 | allow |
| rust | 4k-sqli | 1.862 | 2.005 | 2.276 | 527 | 2 029 145 | 4 865 | block |
| kernel | bodyless | 0.009 | 0.009 | 0.011 | 97 913 | 0 | 0 | allow |
| kernel | 4k-allow | 0.570 | 0.626 | 0.638 | 1 716 | 33 | 1.0 | allow |
| kernel | 4k-sqli | 0.318 | 0.354 | 0.465 | 3 035 | 33 | 1.0 | block |

Process RSS after each backend (one process per backend):

| backend | VmRSS | VmHWM |
|---|---:|---:|
| coraza | 415 MiB | 435 MiB |
| rust | 20.7 MiB | 20.8 MiB |
| kernel | 11.8 MiB | 13.9 MiB |

The Coraza RSS includes the wasmtime host, the Go guest linear memory and the
reactor pool. The numbers above are from the committed baseline run. The
environment block in `baseline.json` is part of the record; a run on different
hardware is expected to differ in absolute terms and should be judged by ratio,
not by matching the table.

## Comparison with ModSecurity/CRS

ModSecurity + OWASP CRS is the reference for rule semantics, not a same-run
competitor in this repository. The Coraza backend runs the same pinned OWASP CRS
4.14.0 request rules at paranoia level 1, and the native Rust engine is a
from-scratch port of the request-rule subset.

Measured **native Coraza/CRS** CPU-time medians from
[`crs-performance.md`](crs-performance.md) (Intel i5-8400T, shared host, Go
1.24.5, pure CPU time, no HTTP/TLS):

| request | native Coraza/CRS p50 | wasm Coraza/CRS p50 |
|---|---:|---:|
| bodyless | 0.55 ms | 2.65 ms |
| 1 KiB form | 7.92 ms | 40.8 ms |
| 4 KiB form | 32.66 ms | 165.6 ms |
| 8 KiB form | 60.94 ms | 333.5 ms |

Those are the closest defensible ModSecurity-family numbers we have: ModSecurity
and Coraza execute the same CRS rule set, so the per-rule work is comparable,
but this is **not** a measurement of ModSecurity's own C engine. A real
ModSecurity comparison needs the same host, the same CRS version/paranoia
level, the same request corpus and the same measurement boundary (CPU time,
engine call only, no HTTP). It is not implied by the table above.

The Rust engine and kernel rows in the baseline are the meaningful comparisons
for this project: they are measured in the same process, same cases and same
run as the Coraza row.

## Comparison with public cloud WAF latency claims

Cloud WAF vendors publish edge/point-of-presence latency figures, not engine
cost. The following are **vendor marketing or vendor-published claims**, not
independent measurements, and they are **not** directly comparable with the
numbers in this repository:

| vendor / product | published claim (marketing) | what it does not state |
|---|---|---|
| AWS WAF | "adds less than 1 millisecond" to request latency (AWS documentation) | which rule set/body inspection, region, request size, percentile, or whether the client RTT is included |
| Cloudflare WAF | "no added latency" / sub-millisecond edge inspection claims | edge PoP placement, cache hit ratio, managed-rule subset, body inspection limits |
| Azure WAF / Front Door | sub-millisecond to low-millisecond WAF overhead claims | tier, rule set, body size, percentile, connection reuse |
| Fastly Next-Gen WAF | sub-millisecond / "negligible" latency claims | deployment mode (edge vs origin), sampling, rule set |
| Imperva Cloud WAF | low-millisecond inspection claims | PoP, rule set, request mix, percentile |

Why they cannot be placed in the same table:

1. **Different boundary.** Vendor claims usually describe added latency at the
   edge, after TLS termination and connection reuse, often without a full CRS
   body scan. The rows here are engine calls on a synthetic request, before
   HTTP/TLS/proxy cost.
2. **Different rule depth.** A managed cloud WAF may run a tuned subset, sample,
   cache verdicts or cap inspected body bytes. The Coraza rows run the full
   pinned CRS 4.14 PL1 body scan.
3. **Different hardware and isolation.** Cloud claims are backed by fleet-scale
   hardware and anycast placement; the baseline here is a shared 6-core desktop
   CPU (Intel i5-8400T class) with a throttling governor unless the quiet-host
   checklist is followed.
4. **Different percentile and workload.** "Less than 1 ms" is rarely qualified
   with p50/p95/p99, request size, or attack/benign mix. A p50 on bodyless
   traffic can be sub-millisecond while a 4 KiB body scan is tens of
   milliseconds.
5. **Marketing incentive.** The claims are not peer-reviewed benchmarks and
   change with product positioning. Treat them as order-of-magnitude context
   only.

A defensible competitive statement is therefore narrow: **on this host, with
full OWASP CRS 4.14 PL1 request inspection, the native Rust engine and kernel
are substantially cheaper than the Coraza WASI reactor for the same synthetic
requests.** Do not claim parity with a cloud WAF's published latency without a
same-host, same-corpus, same-boundary measurement.

## Gate behaviour and CI

* `selftest.sh` proves four cases: baseline copy passes, a +50% p50 row fails
  under `--enforce`, the same row does not fail without `--enforce`, and a
  doubled `4k-sqli / 4k-allow` ratio fails even when absolute p50 rows pass.
* The gate also compares the same-run `4k-sqli / 4k-allow` ratio per backend.
  A CPU-frequency, host-load or guest-GC-mode shift scales both rows together
  and cancels in the ratio, while a real attack-path regression raises it. Keep
  the ratio threshold aligned with the p50 threshold.
* The comparison uses exact `(backend, case)` keys. A new case with no baseline
  row is reported as `NO-BASELINE` and does not fail the gate; add it to the
  baseline in the same change that adds it to the harness.
* A missing row in the current report is not treated as a pass; update the
  harness/report and re-run. The gate does not infer a verdict from absence.
* Default report-only mode is safe for shared CI. `--enforce` is the explicit
  opt-in for a dedicated runner.

## Limitations and blockers

* The reference host is shared and throttles. `run.sh` records load average and
  governor so a noisy run is visible, but it cannot make the host quiet.
* Coraza guest allocations are invisible to the host allocator; use RSS and the
  existing `bench-subms` allocation columns for the guest side.
* RSS is process-level. Run one backend per process (as `run.sh` does) before
  attributing it to an engine.
* Throughput is derived from the timed sample loop, not a concurrent load
  generator. It is a regression signal, not a capacity claim.
* The harness does not measure HTTP, TLS, HTTP/2, WebSocket, gRPC or the proxy.
  Those remain covered by `subms-budget.md` and the load harnesses.
* There is no dedicated isolated CI benchmark runner in this repository yet.
  Until one exists, keep CI in report-only mode and use `--enforce` manually on
  a quiet host.
