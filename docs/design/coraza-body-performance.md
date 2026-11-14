# Coraza WASI reactor: request-body performance root cause

**Status:** research report, no production defaults changed.
**Branch:** `research/coraza-body-perf` (worktree `.worktrees/coraza-perf-research`), based on `main` @ `45d5a4a`.
**Date:** 2026-11-01
**Machine:** Intel i5-8400T (6 cores, 1.7 GHz base / 3.3 GHz turbo), Linux, release builds.

## TL;DR

The body slowdown is **not** the JSON ABI, body parsing, libinjection, fuel metering,
or catastrophic regex backtracking. It is the aggregate cost of **OWASP CRS
operators (regexp scans) applied byte-for-byte to the whole body**, multiplied by
the **Go-compiled-to-wasm execution penalty**, with **fuel instrumentation** and
**episodic GC** on top:

| Factor | Effect on 8 KiB body, per request | Share of 333 ms |
|---|---|---|
| CRS operator work (native baseline) | 55 ms (6.9 µs/byte) | 16.5 % |
| Go→wasm execution penalty | ×5.2 (55 → 286 ms) | 69.4 % |
| wasmtime fuel instrumentation | ×1.16 (286 → 333 ms) | 14.1 % |
| Guest ABI (JSON decode, headers, body parse) | ~1.8 ms | 0.5 % |
| GC (intermittent, heap-state dependent) | +0…160 % of p50 | tail only |

`333 ms` is the steady-state (min / GC-quiet) figure. Observed p50 of ~0.9 s in
production is that same work plus a GC cycle landing mid-request (measured below).
Cost is **linear in inspected body bytes** (~40 µs/byte wasm with fuel, ~35 µs/byte
without, ~6.9 µs/byte native) and independent of content type and of how the body
is split into arguments.

**Recommended fix:** replace fuel with epoch interruption/timeout (−14 %, safe),
cap the *inspected* body at 1–4 KiB with `SecRequestBodyLimitAction Reject` for
larger bodies (2–8×, with an explicit inspection tradeoff), and plan to move Coraza
out of wasm to native Go (5.2–6×, the only change that removes the dominant cost
without giving up inspection depth). Excluding the four most expensive rule
families from body targets buys a further ~2× but loses real detection.

---

## Method

Production code was **not** modified. All experiments used two out-of-tree probes:

1. `src/bin/coraza_perf_probe.rs` (new, uncommitted; registered with an extra
   `[[bin]]` entry in `Cargo.toml`) — a direct wasmtime driver that mirrors
   `src/waf/wasm_reactor.rs` instantiation (WASI p1, Cranelift `OptLevel::Speed`,
   8 MiB stacks, 256 MiB store limit, per-eval fuel 200e9) but *exposes* the knobs
   (fuel on/off, opt level, case selection) that production hides. It calls the
   same `_initialize` / `init` / `eval` exports and measures wall time around the
   memory write + `eval` call, plus guest-reported phase timings.
2. `/tmp/opencode/coraza-probe` — a **copy** of `wasm/coraza_reactor` with
   research-only additions: phase timings, `stats_base`, `set_gc`, a
   `disabledGroups` build knob for CRS subsets, a `bodyMode` knob and a
   `gcPercent` knob. Built with the repo's own
   `scripts/build-coraza-reactor.sh` flags (`CGO_ENABLED=0 GOOS=wasip1
   GOARCH=wasm -buildmode=c-shared -tags no_fs_access -trimpath -ldflags="-s -w
   -buildid="`). The committed `.wasm` is untouched.
3. `/tmp/opencode/coraza-native` — the same CRS bundle compiled for
   `linux/amd64` with the same vendor tree, driving
   `ProcessURI`/`ProcessRequestBody` directly (no JSON envelope), plus a patched
   **copy** of the vendored Coraza (`Rule.Evaluate` timing, `transformArg` vs
   `executeOperator`) to attribute cost per rule and per phase.

Commands used for the main tables:

```sh
nix develop -c cargo build --release --bin coraza_perf_probe
taskset -c 2 ./target/release/coraza_perf_probe <module.wasm> <fuel:0|1> <reps> speed [case,case,...]

# native
nix develop -c bash -c 'cd /tmp/opencode/coraza-native && CGO_ENABLED=0 GOOS=linux \
  GOARCH=amd64 GOFLAGS=-mod=vendor go build -trimpath -o /tmp/opencode/native-group .'
taskset -c 2 env DISABLED=<groups> KIND=form LABEL=full /tmp/opencode/native-group
```

All timings are p50 unless labelled min/mean. Because this laptop throttles
between 1.7 and 3.3 GHz, the same binary can report 333 ms or 865 ms for the same
workload in different runs (2.6× spread, **not** GC). All A/B comparisons below
were therefore run pinned (`taskset -c 2`), back-to-back, and repeated twice; the
`gcab` experiment toggles GC inside a single process to remove frequency drift.
Reported "steady-state" figures are the min across repetitions.

---

## Evidence trail

### E1 — Reproduce the scaling (committed-style full CRS, fuel on)

`coraza_perf_probe /tmp/opencode/full.wasm 1 8 speed`, pinned, GC off (steady
state), instrumented reactor:

| case | bytes | total p50 | rules phase | json | headers | write |
|---|---|---|---|---|---|---|
| no body | 173 | 2.65 ms | 1.37 ms | 0.04 ms | 1.20 ms | 0.00 ms |
| 1 KiB `data=AAA…` | 1 283 | 40.8 ms | 38.9 ms | 0.09 ms | 1.37 ms | 0.00 ms |
| 8 KiB single field | 8 451 | 333.5 ms | 331.8 ms | 0.29 ms | 1.45 ms | 0.01 ms |
| 16 KiB single field | 16 645 | 676.7 ms | 674.7 ms | 0.52 ms | 1.43 ms | 0.01 ms |
| 32 KiB single field | 33 029 | 1 353.0 ms | 1 350.3 ms | 1.01 ms | 1.47 ms | 0.03 ms |
| 60 KiB single field | 61 701 | 2 527.8 ms | 2 524.3 ms | 1.75 ms | 1.46 ms | 0.05 ms |
| 8 KiB / 16 args | 8 467 | 307.9 ms | 306.1 ms | 0.29 ms | 1.44 ms | 0.01 ms |
| 32 KiB / 64 args | 33 141 | 1 228.2 ms | 1 225.6 ms | 0.97 ms | 1.51 ms | 0.03 ms |
| 8 KiB JSON | 8 433 | 333.4 ms | 331.5 ms | 0.34 ms | 1.52 ms | 0.01 ms |
| 8 KiB text/plain | 8 423 | 348.4 ms | 331.5 ms | 0.33 ms | 1.50 ms | 0.01 ms |

Isolates: the whole cost is `ProcessRequestBody` (CRS phase 2). JSON decode is
≤0.5 % even at 60 KiB. Header processing is a constant ~1.4 ms. `WriteRequestBody`
(body parsing) is essentially free. The guest-reported sum matches host wall time
within 0.1 %, so the host JSON encode/copy path is irrelevant
(`host_build_payload_8k_us` = 8.5 µs measured in-probe).

Scaling is **linear**: (2527.8−333.5)/(61701−8451) = **40.7 µs/byte** with fuel;
8 KiB split over 16 args costs the same as one 8 KiB arg, and 32 KiB over 64 args
costs 4× a single 8 KiB field. This rules out catastrophic/quadratic backtracking
and shows the cost tracks *total inspected body bytes*, not argument structure.

### E2 — Fuel instrumentation (`consume_fuel(true)`, hypothesis 1)

Same module, same everything, only `config.consume_fuel(false)`:

| case | fuel on | fuel off | fuel share |
|---|---|---|---|
| 8 KiB single | 333.5 ms | 286.4 ms | 14.1 % |
| 16 KiB single | 676.7 ms | 583.6 ms | 13.8 % |
| 32 KiB single | 1 353.0 ms | 1 164.6 ms | 13.9 % |
| 60 KiB single | 2 527.8 ms | 2 182.1 ms | 13.7 % |
| 8 KiB / 16 args | 307.9 ms | 255.6 ms | 17.0 % |
| no body | 2.65 ms | 2.30 ms | 13.4 % |

Fuel is a real but **secondary** cost (~1.16×, ~14 %). It is nowhere near the
10–50× that would explain the regression. `OptLevel::SpeedAndSize` and
`wasm-opt -O3` on the module gave no improvement (338 ms vs 333 ms, within noise).

### E3 — Native Go Coraza baseline (hypothesis 4)

Same CRS bundle, same vendor tree, `linux/amd64`, `GOOS=linux`, no wasm:

| case | native p50 | wasm fuel-off steady | wasm/native |
|---|---|---|---|
| no body | 0.21 ms | 2.30 ms | 11× (fixed ABI + phase-1 cost) |
| 1 KiB | 6.8 ms | 33.5 ms | 4.9× |
| 8 KiB | 55.3 ms | 286.4 ms | 5.2× |
| 16 KiB | 112.2 ms | 583.6 ms | 5.2× |
| 32 KiB | 225.2 ms | 1 164.6 ms | 5.2× |
| 60 KiB | 421.3 ms | 2 182.1 ms | 5.2× |

The wasm multiplier is a constant **~5.2×** on top of native for body inspection
(6.0× with fuel). Critically, **native is already 55 ms for 8 KiB** — the
"~1 ms native expectation" in the task brief does not hold for *this* workload on
this hardware. The rule set is intrinsically expensive per body byte; wasm makes
it 5–6× worse. At 60 KiB, one request occupies a pool worker for ~0.42 s natively
and ~2.5 s in wasm.

### E4 — CRS rule-family attribution (hypothesis 2)

Native engine, one family removed at a time (whole `REQUEST-9XX` section filtered
out of the concatenated `crs.conf`), 8 KiB single field, pinned, two rounds:

| removed family | p50 | saved vs full | share |
|---|---|---|---|
| — (full) | 55.6 ms | — | 100 % |
| 932 RCE | 39.4 ms | 16.2 ms | **29 %** |
| 942 SQLi | 44.1 ms | 11.5 ms | **21 %** |
| 934 generic | 49.2 ms | 6.4 ms | 11.5 % |
| 921 protocol attack | 50.0 ms | 5.6 ms | 10 % |
| 941 XSS | 50.4 ms | 5.2 ms | 9 % |
| 933 PHP | 51.9 ms | 3.7 ms | 6.6 % |
| 944 Java | 52.2 ms | 3.4 ms | 6 % |
| 931 RFI | 53.8 ms | 1.8 ms | 3 % |
| 930 LFI | 53.8 ms | 1.8 ms | 3 % |
| 920 protocol enforcement | 55.2 ms | 0.4 ms | 1 % |
| 943 session fixation | 55.4 ms | 0.2 ms | ~0 % |
| 949 blocking evaluation | 55.6 ms | 0.0 ms | 0 % |
| *all body families off* (901/905/911/913 only) | 0.03 ms | 55.6 ms | 100 % |

The same ordering reproduced in wasm (932 −28 %, 942 −21 %, 921/934/941 ≈ −9…−10 %
each). Contributions are nearly additive; no single family dominates, and the
"core" CRS skeleton (initialisation, method/scanner checks) costs 0.03 ms.

### E5 — Rule-level attribution and libinjection (hypothesis 3)

Per-rule nanosecond accounting (patched **copy** of vendored Coraza, cumulative
over 7 requests, 8 KiB form body, 260 rules hit):

| rule | family | time (7 req) | per request | share |
|---|---|---|---|---|
| 934100 Node.js injection | 934 | 38.5 ms | 5.5 ms | 9.9 % |
| 921110 request smuggling | 921 | 32.6 ms | 4.7 ms | 8.3 % |
| 932250 unix command | 932 | 25.4 ms | 3.6 ms | 6.5 % |
| 932260 unix command | 932 | 25.4 ms | 3.6 ms | 6.5 % |
| 932230 unix command | 932 | 20.7 ms | 3.0 ms | 5.3 % |
| 932235 unix command | 932 | 20.7 ms | 3.0 ms | 5.3 % |
| 944120 Java injection | 944 | 15.6 ms | 2.2 ms | 4.0 % |
| 931110 RFI | 931 | 11.4 ms | 1.6 ms | 2.9 % |
| 942320 SQLi | 942 | 10.5 ms | 1.5 ms | 2.7 % |
| 942550 SQLi | 942 | 9.8 ms | 1.4 ms | 2.5 % |

The top 25 rules account for ~72 % of rule time; the largest single rule is
~10 %. **`@detectSQLi` (rule 942100) is 0.20 ms over 7 requests = 0.1 %** —
libinjection is not a factor. This is aggregate scanning cost spread across
hundreds of `@rx` operators, not one pathological expression.

Transformations are not the cause: instrumentation around `transformArg` vs
`executeOperator` gives **5.2 ms transforms vs 381 ms operators** over 7 requests
(1.3 % vs 97.5 %), consistent for form, text/plain and octet-stream bodies.

### E6 — Content type and parse shape (hypothesis 7)

Native, 8 KiB body, only `Content-Type` and encoding change:

| body shape | p50 |
|---|---|
| `application/x-www-form-urlencoded`, one 8 KiB arg | 55.5 ms |
| form-urlencoded, 16 × 512 B args | 52.7 ms |
| `application/json`, one 8 KiB string | 56.4 ms |
| `text/plain`, 8 KiB | 58.6 ms |
| `application/octet-stream`, 8 KiB | 58.8 ms |
| no body | 0.20 ms |

Content type is irrelevant: rules scan the raw `REQUEST_BODY` (and/or `ARGS`)
identically. Only *omitting the body* removes the cost. This means "send a
content type the parser ignores" is not a mitigation.

### E7 — GC and allocator (hypothesis 8)

`TotalAlloc` grows by ~0.5–1 MB per 8 KiB request and ~4 MB per 32 KiB/64-arg
request; NumGC 7–9 over a 12-request run. `MemStats.PauseTotalNs` is not populated
on wasip1, so GC was toggled inside one process via an experimental `set_gc`
export (`debug.SetGCPercent`), alternating GC-on/GC-off on the same pinned core:

```
8k_single  round0 gc100  min=337ms p50=863ms     <- GC cycle mid-request
8k_single  round0 gc-1   min=334ms p50=335ms
8k_single  round1 gc100  min=334ms p50=335ms     <- heap already primed
8k_single  round1 gc-1   min=334ms p50=335ms
32k_64args round0 gc100  min=1244ms p50=1468ms
32k_64args round0 gc-1   min=1245ms p50=1248ms
32k_64args round1 gc100  min=1250ms p50=1348ms
32k_64args round1 gc-1   min=1247ms p50=1250ms
```

GC does **not** change the steady-state (min) cost, but a collection landing
mid-evaluation inflates that request by up to **2.6×** (333 → 863 ms). This is the
difference between the ~333 ms floor and the ~0.9 s p50 reported in production:
the pool is pre-warmed, but the heap is not "GC-primed", so early requests pay it.
Separate builds with `GOGC=off` or `GOGC=200/400` reproduced the effect
(`GOGC=off` kept p50 == min), but **`GOGC=400` regressed 32 KiB/64-arg from 1.23 s
to 2.50 s** because the heap target grows linear memory; GC tuning is a real lever
for the tail but must be paired with a memory limit and measured per workload.

### E8 — Capping the inspected body (hypothesis 6)

Because cost is linear, the cap is a direct linear multiplier (steady state,
fuel on):

| inspected bytes | wasm p50 | native p50 |
|---|---|---|
| 0 | 2.65 ms | 0.21 ms |
| 1 KiB | 40.8 ms | 6.8 ms |
| 8 KiB (current default) | 333.5 ms | 55.3 ms |
| 16 KiB | 676.7 ms | 112 ms |
| 32 KiB | 1 353 ms | 225 ms |
| 60 KiB | 2 528 ms | 421 ms |

Capping *does* work, but linearly: 1 KiB still costs ~41 ms in wasm. There is no
cap above ~256 B that makes wasm body inspection cheap; 8 KiB (today's default)
is one of the worst settings latency-wise.

---

## Ranked root-cause attribution (8 KiB body, 333 ms steady-state)

1. **CRS operator scanning is byte-linear and expensive even natively — 100 % of
   the base work, 16.5 % of observed wasm time.** 55 ms / 8 KiB = 6.9 µs/byte,
   spread over ~260 rules. Family split: 932 29 %, 942 21 %, 934 11.5 %, 921 10 %,
   941 9 %, 933 6.6 %, 944 6 %, 931 3 %, 930 3 %, 920 1 %. No rule above 10 %.
   Transformations 1.3 %, libinjection 0.1 %.
2. **Go→wasm execution penalty — ×5.2, 69.4 % of observed time.** Constant across
   body sizes; not fuel, not ABI.
3. **wasmtime fuel instrumentation — ×1.16, 14.1 %.** `consume_fuel(true)`
   instruments every basic block; Go code is hit heavily.
4. **GC tail latency — up to ×2.6 on affected requests (episodic, not steady).**
   Explains the gap between the 333 ms floor and the observed ~0.9 s p50.
5. **Host/guest ABI — ≤0.5 %.** JSON encode 8.5 µs host-side; guest JSON decode
   0.29 ms; header phase 1.4 ms; body parse <0.05 ms. Not a problem.

Blocker/implication: **a 60 KiB request currently burns ~2.5 s of a pool worker.**
With the default auto pool (≤8 workers) that caps throughput at roughly 3 such
requests/second per process and is a cheap remote DoS vector.

---

## Recommended fixes (minimal first)

**F1. Replace fuel with epoch interruption + wall-clock timeout (safe, do first).**
`Config::epoch_interruption(true)`, a watchdog thread calling
`engine.increment_epoch()` every ~1 ms, `Store::set_epoch_deadline(N)` per eval.
Same fail-closed semantics (`ReactorError::Trap` → 503), no per-block
instrumentation. Expected **−14 %** on every body request (8 KiB 333 → 286 ms),
plus cheaper small requests. Cost: timeout granularity instead of an exact
instruction budget; keep a generous wall-clock budget (current 60 s is far too
large for a 64 KiB body — recommend ~100–250 ms and fail closed).

**F2. Cap the inspected body at 1–4 KiB and *reject* (not silently process) above
the cap.** `SecRequestBodyLimit` + `SecRequestBodyLimitAction Reject` (or a
host-side `max_payload_bytes` split into "inspect" and "forward" limits). Cost is
linear, so 8 KiB → 4 KiB ≈ 2×, → 1 KiB ≈ 8× (8 KiB 333 → ~170 ms / ~41 ms
steady). Security tradeoff is explicit: bytes past the cap are not inspected, so
this must be paired with a documented request-body size policy and a 413 for
oversized bodies rather than wave-through. This is the only config-only
containment that materially helps.

**F3. Move Coraza evaluation out of wasm (native Go), the only dominant-cost
removal that keeps full inspection.** `×5.2–6` for all body sizes: 8 KiB
333 → 55 ms, 60 KiB 2.5 s → 0.42 s. Options: cgo/dynamic library, a local
Unix-socket sidecar, or a native Go microservice. Tradeoff: loses wasmtime's
memory/fuel sandbox and the single-binary embedding; needs its own timeout,
memory cap and crash isolation. This is the recommended strategic fix.

**F4. GC tail control.** Prime the heap and tune `GOGC`/`GOMEMLIMIT` (e.g.
`debug.SetGCPercent` at reactor init, memory limit comfortably below the 256 MiB
store cap) so collection does not land mid-evaluation. Measured: GC off makes
p50 == min (8 KiB 863 → 334 ms), but `GOGC=400` regressed 32 KiB/64-arg 2× via
linear-memory growth — so tune and soak-test rather than setting a large constant.

**F5. Optional rule-family relief for large args.** Excluding 932/934/944/931
targets from `REQUEST_BODY`/`ARGS` above a size threshold buys ~1.9× (those
families are ~50 % of rule time) but removes RCE/JAVA/generic/RFI detection on
large bodies. Only acceptable as a documented, size-gated tradeoff.

**Combined expectation:** F1+F2(4 KiB) ≈ 2.3× p50; F1+F3 ≈ 5.5× with no detection
loss. F1+F2(1 KiB)+F4 ≈ 8× but inspects only 1 KiB. Confidence **high** on the
attribution (reproduced natively and in wasm, group and rule level); **medium** on
absolute numbers for other hardware (this is one throttling laptop).

## Confidence, caveats, blockers

- Attribution is triangulated three ways (wasm group filtering, native group
  filtering, per-rule and per-phase instrumentation) and is internally
  consistent to a few percent.
- The host CPU throttles 1.7↔3.3 GHz; the same run can differ 2.6×. All headline
  numbers are pinned to one core and repeated; budgets should be re-measured on
  the target server class before being turned into SLOs.
- `MemStats.PauseTotalNs` is unavailable on wasip1, so GC was characterised by
  toggling `SetGCPercent` inside one process rather than by pause counters.
- No production default was changed. Nothing here is committed except this
  report. The probe binary, the temporary `[[bin]]` entry in `Cargo.toml` and the
  `/tmp` Go/vendor instrumentation are experiment-only and are **not** committed.
- Exact research patch surface (all outside the repo, or uncommitted in the
  worktree):
  - new `src/bin/coraza_perf_probe.rs` (uncommitted) and one uncommitted
    `[[bin]] coraza_perf_probe` block appended to `Cargo.toml`;
  - `/tmp/opencode/coraza-probe/main.go`: added `stats_base`, `set_gc`, per-phase
    timings, `disabledGroups`/`bodyMode`/`gcPercent` build knobs;
  - `/tmp/opencode/coraza-probe/vendor/.../internal/corazawaf/rule.go`: added
    `time.Now()` accounting around `Rule.Evaluate`, `transformArg` and
    `executeOperator` (plus `timing.go`); research copy only.
