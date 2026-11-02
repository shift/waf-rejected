# Performance Validation (Beta Load Harness)

This document defines how the beta is load-validated end to end, the acceptance
gates a build must meet, and the measured capacity of the reference laptop.
The numbers below are **capacity floors**, not ceilings: the load generator,
the WAF and the mock upstream all share one 6-core laptop.

## What is measured

`load-validate` (`src/bin/load_validate.rs`) is a single release binary that:

1. starts a tiny in-process HTTP/1.1 mock upstream;
2. optionally spawns one `waf-ingress` child with a throwaway config, waits
   for its health port, and stops it with `SIGTERM` after the matrix;
3. replays closed-loop, persistent-connection requests at concurrency
   **1, 4, 16 and 64** (2 s warm-up + 8 s measurement by default);
4. records p50/p95/p99/max latency, RPS, transport errors, HTTP 503s, false
   allows (attack returned 2xx), false blocks (clean returned 403), status
   distributions and per-request-class results;
5. samples the WAF process RSS and CPU clock from `/proc` once a second;
6. evaluates explicit acceptance gates and writes deterministic, seeded JSON
   (`results.json`), a compact fixture (`fixture.json`) and `summary.md`.

Requests are generated from a `--seed` so body padding and per-worker class
selection are reproducible. Timings are obviously not bit-reproducible.

### Profiles

| profile | request |
|---|---|
| `bodyless` | `GET /` |
| `form-1k` | 1 KiB `application/x-www-form-urlencoded` POST |
| `form-8k` | 8 KiB form POST |
| `form-16k` | 16 KiB form POST |
| `form-60k` | 60 000-byte form POST (CRS scan; DoS probe) |
| `grpc-1k` | valid unary gRPC frame, 1 KiB message, no content-length (stream path) |
| `grpc-256k` | valid unary gRPC frame, 256 KiB message |
| `grpc-content-4k` | descriptor-backed gRPC string field, 4 KiB (Coraza content scan) |
| `grpc-content-16k` | descriptor-backed gRPC string field, 16 KiB (Coraza content scan) |
| `graphql-2k` | 2 KiB GraphQL JSON POST |
| `graphql-8k` | 8 KiB GraphQL JSON POST |
| `sqli` | SQL-injection form probe; must be 403 |
| `xss` | XSS query probe; must be 403 |
| `mixed` | 60% bodyless, 20% form-1k, 10% SQLi, 10% XSS |
| `mixed-dos` | 90% bodyless, 10% 60 KiB form (pool starvation probe) |
| `mixed-grpc-dos` | 90% bodyless, 10% gRPC 4 KiB content scan (admission isolation probe) |

gRPC uses HTTP/1.1 because plaintext ingress only speaks HTTP/1.1. The frame
envelope is valid and the request deliberately omits `Content-Length`, matching
real gRPC over HTTP/2; the WAF classifies it as a stream, forwards the body
incrementally and withholds it from CRS. `TE: trailers` is sent as gRPC-over-
HTTP/1.1 requires. The `grpc-content-*` profiles are the exception: they send
`Content-Length` so the body is buffered and the descriptor-backed gRPC
pre-check runs its Coraza content scan. The throwaway config points
`waf.grpc.allowlist_file` at a minimal IR v2 artifact that declares only
`/acme.Content/Scan`, so the other gRPC profiles keep the envelope-only path.

The throwaway config disables per-IP/global rate limiting and security-event
export so the matrix measures inspection capacity rather than the default
100 req/min/IP limiter or sled I/O. WAF defaults (64 KiB payload cap, 5 s
`eval_timeout_ms`, fail-closed, auto pool = cores clamped to 8) are unchanged.

## Body-inspection policy and the capacity table

The capacity table above assumes the default `waf.coraza` policy:
`max_inspect_bytes = 0` and `oversize_action = "inspect-all"`, so every body up
to the 64 KiB payload cap is fully scanned. The opt-in policy changes which
rows are meaningful:

| policy | effect on the capacity table |
| --- | --- |
| `inspect-all` (default) | Unchanged. `form-8k`, `form-16k` and `form-60k` measure full CRS body cost; bodies above 64 KiB still fail closed with `503`. |
| `forward-uninspected` with `max_inspect_bytes = N` | Bodies above N are scanned only for their first N bytes. The `form-8k`/`form-16k`/`form-60k` cells then measure the cost of N bytes, not the full body, and the `form-60k-admitted-c1` gate no longer proves full-body inspection. Re-run the matrix with the production policy and record N; do not compare those cells to the default table. |
| `reject` with `max_inspect_bytes = N` | Bodies above N return `413` before evaluation. Heavy-body cells become rejection-throughput cells, and the `form-60k-*` gates are not applicable. |

The `mixed-dos` isolation gate is the one to watch when choosing a policy: a
small prefix or `reject` removes the 60 KiB CRS cost that starves bodyless
traffic, but `forward-uninspected` still forwards the full body upstream and
still pays the transport cost. Any capacity claim must state the policy and
`max_inspect_bytes` used for the run.

## Acceptance gates

Gates are evaluated by the harness and reported PASS/FAIL/SKIP. They are not
weakened after a run; a failure is a release finding.

| gate | requirement |
|---|---|
| `bodyless-p95-c64` | bodyless p95 < 20 ms at c=64, zero errors/false blocks |
| `grpc-1k-p95-c64` | gRPC 1 KiB p95 < 25 ms at c=64, zero errors/false blocks |
| `grpc-256k-p95-c64` | gRPC 256 KiB p95 < 30 ms at c=64, zero errors/false blocks |
| `form-1k-p95-c64` | 1 KiB form p95 < 250 ms at c=64, zero errors |
| `form-8k-p95-c64` | 8 KiB form p95 < 1000 ms at c=64, zero errors |
| `form-16k-p95-c16` | 16 KiB form p95 < 2000 ms at c=16, zero errors |
| `form-60k-admitted-c1` | 60 KiB form inspected at c=1: no 503/error, p95 < 5 s |
| `form-60k-p95-c1` | 60 KiB form p95 < 5000 ms at c=1 |
| `grpc-content-4k-admission-bounded` | gRPC 4 KiB content scan p95 < 1000 ms at c=64, no non-503 errors |
| `zero-503-above-20rps` | every non-admission-bounded cell offered >= 20 RPS has zero 503s |
| `light-availability-c16` | light profiles have zero errors/503s at c <= 16 |
| `attack-block-rate` | SQLi/XSS: 100% 403, zero false allows |
| `mixed-decision-correctness` | mixed traffic: zero attack false allows and zero clean false blocks |
| `clean-no-false-blocks` | clean profiles never return 403 |
| `dos-isolation-bodyless-c64` | with 10% 60 KiB bodies at c=64, bodyless p95 < 100 ms |
| `rss-peak` | WAF peak RSS < 1536 MiB |
| `rss-growth` | WAF RSS growth over the matrix < 25% of baseline |

The 60 KiB isolation gate is deliberately strict: an untrusted client that can
send a handful of maximum-size bodies should not be able to add seconds to
every bodyless request. A failure here is a beta-readiness blocker for
untrusted-traffic deployments even when throughput gates pass.

## Commands

```bash
# Full matrix (builds release with the pinned Nix toolchain)
nix develop -c ./scripts/load-validate.sh

# Short smoke run
nix develop -c ./scripts/load-validate.sh \
  --warmup-secs 1 --duration-secs 3 --concurrency 1,4 \
  --profiles bodyless,form-1k,grpc-1k,sqli,xss

# Reuse already-built binaries (no rebuild)
SKIP_BUILD=1 ./scripts/load-validate.sh

# List profiles
./target/release/load-validate --list-profiles
```

Results default to `/tmp/opencode/load-validation/`:
`results.json`, `fixture.json`, `summary.md`, `waf-ingress.log`,
`config.toml`. Raw result files are intentionally not committed; the doc and
`docs/operations/load-validation-fixture.json` carry the evidence.

Override ports with `WAF_PORT`, `HEALTH_PORT`, `UPSTREAM_PORT` when 39080/39081/
39000 are occupied.

## Reference hardware and caveats

- Host: Intel Core i5-8400T, 6 logical CPUs, 15 862 MiB RAM, kernel 6.18.
- The CPU is a 1.7 GHz base laptop/desktop part that boosts to ~3.3 GHz.
  `/proc/cpuinfo` and sampled `scaling_cur_freq` values are recorded in the
  JSON. Other builds running on the host move the observed clock across that
  range, so absolute RPS varies by tens of percent between runs.
- The load generator, WAF and upstream share the same cores. Do not add
  generator CPU to WAF CPU when sizing; rerun on target hardware with a
  separate load generator.
- Reactor pool is auto (`pool_size = 0`), i.e. `min(cores, 8)`. This host runs
  6 pre-warmed reactor workers. Memory therefore scales with pool size plus
  per-request buffers.
- Plaintext ingress is HTTP/1.1 only; HTTP/2 requires TLS ALPN. gRPC numbers
  are the HTTP/1.1 path, which uses the same Coraza withholding path as HTTP/2
  gRPC. `grpc-content-*` buffers the body (Content-Length) so the
  descriptor-backed content scan runs; real HTTP/2 unary gRPC with a
  `Content-Length` equivalent behaves the same, while streaming RPCs remain
  uninspected by design.
- 60 KiB cells at high concurrency complete few requests, so their p95 has a
  small sample. Treat it as directional evidence of saturation, not a precise
  percentile.

## Reproducing on target hardware

1. Build the release binary with the target toolchain:
   `nix develop -c cargo build --release --bin waf-ingress --bin load-validate`.
2. Put the load generator on a separate host if possible. Point
   `--target http://WAF:PORT` at a running proxy with its own upstream and use
   `--no-upstream`; pass `--waf-pid` (or run on the same host) for RSS.
3. Keep rate limits disabled for capacity runs, then run a second pass with the
   production rate limits to validate the 429/limit path separately.
4. Record CPU model, sustained clock, pool size and kernel in the report. A
   capacity claim without them is not comparable.
5. Use at least 30 s measurement for heavy-body profiles if you need stable
   p99, and run the matrix three times; report the median run.

## Results

### Measured run (reference laptop)

- Date: 2026-11-01
- Source commit: `f20fa946d565` (`test/load-validation`); the WAF binary is
  `waf-ingress 0.1.0-beta.11` built from `93c56c9` with the harness branch's
  test-only changes. `git_dirty_tracked` is `true` in the JSON because this
  documentation and CHANGELOG were being written after the measured build;
  no WAF source or configuration changed after the build.
- Binary sha256: `949d86f46d6ed7a6ecd84829d58643bf24047ff36f5f6e58b710903fcf9b1c61`
- Warm-up 2 s + measurement 8 s, seed 42, pool auto = 6.
- Full matrix, gate table and per-cell statuses:
  [`load-validation-summary.md`](load-validation-summary.md).
- Compact machine-readable fixture:
  [`load-validation-fixture.json`](load-validation-fixture.json).

The host was **not idle** during the run: the highest sampled 1-minute load
was **7.37** on 6 logical CPUs, and the sampled clock fell to ~1.0 GHz. The
numbers are therefore conservative floors; some latency gates may pass on an
idle target. They are reported as failures here rather than excused or
weakened. Two full runs were made; bodyless p95 at c=64 was 88.5 ms in the
first and 51.1 ms in the second, and 8 KiB form p95 at c=64 was 11.1 s and
6.8 s. This variance is larger than the run-to-run stability needed for tight
SLA claims.

### Acceptance result: 7 passed, 9 failed, 0 skipped

| gate | result | observed |
|---|---|---|
| bodyless p95 at c=64 | **FAIL** | 51.14 ms (limit 20 ms) |
| gRPC 1 KiB p95 at c=64 | **FAIL** | 68.18 ms (limit 25 ms) |
| gRPC 256 KiB p95 at c=64 | **FAIL** | 70.97 ms (limit 30 ms) |
| 1 KiB form p95 at c=64 | **FAIL** | 1185.37 ms (limit 250 ms) |
| 8 KiB form p95 at c=64 | **FAIL** | 6764.18 ms (limit 1000 ms) |
| 16 KiB form p95 at c=16 | **FAIL** | 5992.90 ms (limit 2000 ms) |
| 60 KiB admitted at c=1 | PASS | p95 2998 ms, 0 503s |
| 60 KiB p95 at c=1 | PASS | 2998 ms (limit 5000 ms) |
| zero 503s whenever offered >= 20 RPS | PASS | 31 cells, zero 503s |
| light-profile availability at c<=16 | PASS | 21 cells, zero errors/503s |
| SQLi/XSS block rate | PASS | 40 064/40 064 blocked |
| mixed decision correctness | PASS | 1 774/1 774 attacks blocked, zero false allows/blocks |
| clean traffic never 403 | PASS | 112 256 clean requests |
| 60 KiB isolation at c=64 | **FAIL** | bodyless p95 6 492 ms with 10% 60 KiB traffic |
| peak RSS < 1536 MiB | **FAIL** | 1803.2 MiB |
| RSS growth < 25% | **FAIL** | 95.8% |

**Verdict:** beta-ready for bodyless and gRPC traffic up to roughly 16
concurrent connections / ~1.5 kRPS on this host. **Not beta-ready** for
untrusted 8–60 KiB bodies at c=64, for 16 KiB bodies at c=16, or for any
deployment where a client can send 60 KiB bodies alongside latency-sensitive
traffic. Correctness gates all pass: no false allows and no false blocks were
observed.

### Per-profile capacity (closed-loop, no rate limits)

"Max sustained" is the highest observed RPS where p95 met the target and
there were zero errors/503s/false blocks. It is not a guarantee; it is the
best cell in this matrix.

| workload | safe envelope on this host | max sustained RPS | p95 there | constraint |
|---|---|---:|---:|---|
| bodyless GET | c<=16 | 1 747 | 14.29 ms | c=64 p95 51.1 ms |
| gRPC 1 KiB unary | c<=16 | 1 480 | 15.39 ms | c=64 p95 68.2 ms |
| gRPC 256 KiB unary | c<=16 | 1 404 | 15.95 ms | body withheld from CRS; c=64 p95 71.0 ms |
| 1 KiB form | c<=4 | 60.8 | 92.08 ms | c=16 p95 314 ms; c=64 1.19 s |
| 8 KiB form | c=1 | 2.5 | 401.5 ms | c=4 p95 1.02 s (over 1 s) |
| 16 KiB form | c=1 | 1.2 | 819.9 ms | c=4 p95 2.12 s |
| 60 KiB form | c=1 only | 0.3 | 3.00 s | c=64 p95 39.8 s + 4x503 |
| GraphQL 2 KiB | c<=16 | 50.9 | 498.7 ms | target 500 ms; c=64 p95 2.08 s |
| GraphQL 8 KiB | c<=4 | 8.2 | 728.0 ms | c=16 p95 1.77 s |
| mixed 60/20/10/10 | c<=16 | 334.2 | 127.9 ms | c=64 p95 299 ms (over 250 ms) |
| mixed-dos (10% 60 KiB) | none | 0 | 2.98 s | bodyless starves to 6.49 s at c=64 |

GraphQL is CPU-heavy because the JSON body is sent through CRS body rules.
It is not in the same capacity class as form bodies but degrades at c=64.

### 60 KiB bodies are a single-request DoS amplifier

A 60 KiB body costs ~3.0 s of reactor time on this host. With `pool_size = 6`
(auto = 6 cores), **six concurrent 60 KiB requests occupy every reactor**;
every bodyless request queues behind them. The harness demonstrates this
directly:

| case | observed |
|---|---|
| 1x 60 KiB at c=1 | 3.00 s p50, 0.33 RPS, 0 503s |
| 64x 60 KiB at c=64 | 39.02 s p50, 39.79 s p95, 1.65 RPS, **4x503 (5.8%)** |
| 90% bodyless + 10% 60 KiB at c=64 | bodyless p95 **6.49 s** vs 51.1 ms baseline |
| 60 KiB at c=16 | p95 13.82 s |

This is the most important beta finding. Heavy-inspection admission control is
implemented in `feat/coraza-admission` (see below). A lower body-size limit for
untrusted routes or an async/streaming inspection path remain possible future
mitigations; changing defaults or security policy is out of scope.

### Admission control: 60 KiB isolation after the fix

`[waf.admission]` classifies evaluations as cheap (no body, a gRPC body
withheld from CRS without a content scan, or a `graphql-only` body) or heavy
(CRS body scan, or a gRPC field-content scan). Classification runs before the
protocol pre-checks on the original request, so a gRPC content scan cannot
bypass the heavy pool. Heavy evaluations are capped at `heavy_permits`; auto
reserves about half the reactor pool, capped at `pool_size - 1`. Cheap requests
bypass the heavy queue. A saturated heavy queue rejects with
`503 + Retry-After`, never `Allow`.

Measured on 2026-11-01 from the `feat/coraza-admission` working tree, release
build, warm-up 1 s + measurement 5 s for the heavy matrix and 1 s + 3 s for the
light cells, seed 42, pool auto = 6 (heavy permits = 3). The host was **not
idle**: 1-minute load average was **9.03** on 6 logical CPUs during the light
run and ~8.2 during the heavy matrix, versus 7.37 in the baseline. Absolute
light latencies are therefore not directly comparable; the isolation ratio is.

| case | before | after |
|---|---|---|
| 90% bodyless + 10% 60 KiB, c=64: bodyless p95 | **6 492 ms** | **240.8 ms** |
| 90% bodyless + 10% 60 KiB, c=64: bodyless errors/503 | 0 / 0 | 0 / 0 |
| bodyless only, c=64: p95 | 51.1 ms | 83.7 ms (load 9.03) |
| gRPC 1 KiB only, c=64: p95 | 68.2 ms | 114.0 ms (load 9.03) |
| gRPC 256 KiB only, c=64: p95 | 71.0 ms | 156.6 ms (load 9.03) |
| form-60k, c=6 | six workers occupied; bodyless starves | admitted p95 ~5.0 s, excess heavy requests 503 after 250 ms |

The mixed-DoS bodyless tail improves by ~27x with zero bodyless errors or
503s and zero false allows/blocks. `dos-isolation-bodyless-c64` still fails its
100 ms gate on this host under sustained 10% 60 KiB load, because the reserved
cheap capacity is finite; it is no longer a multi-second starvation. Heavy
requests above the permit count are deliberately rejected rather than queued
indefinitely, which is why heavy-only cells now show 503s. Operators who value
heavy throughput over cheap latency can raise `heavy_permits` explicitly.

### gRPC content-scan admission A/B

gRPC field-content scanning (`waf.grpc.content_scan = "strings"`) runs an extra
Coraza evaluation of decoded field values, costing ~39 ms / ~165 ms / ~705 ms
for 1/4/16 KiB on the benchmark host. Before this fix that evaluation ran
before admission classification, so it bypassed the heavy semaphore entirely.
`scripts/load-validate.sh` now accepts `ADMISSION_ENABLED=false` to reproduce
the pre-fix behaviour on the same binary for a controlled A/B.

Measured on 2026-11-02 from `fix/admission-grpc-content`, release build,
warm-up 1 s + measurement 3 s, seed 42, pool auto = 6 (heavy permits = 3),
`grpc-content-4k` (4 KiB decoded string, one content scan per request):

| case | admission bypassed (`false`) | admission enabled (`true`) |
|---|---|---|
| gRPC content scan only, c=64: p95 | 2 778 ms (max 4 006 ms) | **398 ms (max 450 ms)** |
| gRPC content scan only, c=64: 503s | 0 | 696 of 744 (excess rejected) |
| gRPC content scan only, c=64: RPS | 28 | **232** |
| 90% bodyless + 10% content scan, c=64: bodyless p95 | 491 ms | **52 ms** |
| 90% bodyless + 10% content scan, c=64: overall RPS | 218 | **969** |
| 90% bodyless + 10% content scan, c=8: bodyless p95 | 48 ms | **5.7 ms** |

Content scans are now bounded by `heavy_permits` plus the 250 ms queue timeout;
excess scans are rejected with `503 + Retry-After` instead of queueing for
seconds. Cheap bodyless traffic under gRPC-heavy load improves by ~9x at c=64
and ~8x at c=8. The `grpc-content-4k-admission-bounded` gate enforces p95 <
1 s with no non-503 errors. Absolute values are host- and load-dependent; the
before/after ratio is the signal.

### Memory

| metric | value |
|---|---:|
| baseline after pool warm-up | 764.1 MiB |
| end of matrix | 1 496.4 MiB |
| peak | 1 803.2 MiB |
| growth | +95.8% |

The baseline is consistent with ~127 MiB per pre-warmed worker (6 workers).
The growth is dominated by the heavy-body cells: concurrent 16/60 KiB bodies
and their buffers, plus allocator retention. This run is not a leak test, but
the 1536 MiB peak gate fails and the 25% growth gate fails. A dedicated soak
(no heavy bodies, 1–4 h) is still required to separate high-water retention
from a leak. Capacity planning should budget >1.8 GiB per process for this
workload mix, not the ~0.8 GiB warm baseline.

### Reproducibility notes

- Seed 42 determines body padding and per-worker mixed-profile selection.
  Two runs produced the same decision outcomes (all attacks blocked, no false
  blocks) but materially different heavy-tail latencies under host
  contention.
- The harness exits `2` when any gate fails so CI can consume it. A failing
  run still writes both JSON files and the markdown summary.
- Rate limiting was disabled. A separate pass with production limits is
  required before claiming the 429 path is validated.

