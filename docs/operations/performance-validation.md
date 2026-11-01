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
| `graphql-2k` | 2 KiB GraphQL JSON POST |
| `graphql-8k` | 8 KiB GraphQL JSON POST |
| `sqli` | SQL-injection form probe; must be 403 |
| `xss` | XSS query probe; must be 403 |
| `mixed` | 60% bodyless, 20% form-1k, 10% SQLi, 10% XSS |
| `mixed-dos` | 90% bodyless, 10% 60 KiB form (pool starvation probe) |

gRPC uses HTTP/1.1 because plaintext ingress only speaks HTTP/1.1. The frame
envelope is valid and the request deliberately omits `Content-Length`, matching
real gRPC over HTTP/2; the WAF classifies it as a stream, forwards the body
incrementally and withholds it from CRS. `TE: trailers` is sent as gRPC-over-
HTTP/1.1 requires.

The throwaway config disables per-IP/global rate limiting and security-event
export so the matrix measures inspection capacity rather than the default
100 req/min/IP limiter or sled I/O. WAF defaults (64 KiB payload cap, 5 s
`eval_timeout_ms`, fail-closed, auto pool = cores clamped to 8) are unchanged.

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
| `zero-503-above-20rps` | every cell offered >= 20 RPS has zero 503s |
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
  are the HTTP/1.1 stream path, which is the same Coraza withholding path used
  by HTTP/2 gRPC.
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

This is the most important beta finding. Mitigations would include a lower
body-size limit for untrusted routes, a separate reactor pool/queue for large
bodies, admission control on concurrent large scans, or an async/streaming
inspection path. None of these are implemented here; changing defaults or
security policy is out of scope for this task.

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

