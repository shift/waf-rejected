# Fixed proxy + WAF-wrapper floor

**Branch:** `perf/wrapper-floor` (worktree `.worktrees/wrapper-perf`, base
`main` = `e05d918`)
**Scope:** the fixed cost around the compiled rule engine: `RequestContext`
construction, engine request materialisation, the heuristic
content-inspection header scan, and the per-request proxy allocations.

## Method

- `bodyless-bench --profile --rust` (new `--rust` mode) builds four engines from
  the default configuration and evaluates the same bodyless request on one
  core: wrapper only (`coraza.enabled = false`, content inspection off),
  `+content inspection`, `+rust engine`, and the full default chain. The deltas
  attribute wrapper, heuristic scans and engine.
- `rust-engine-parity --bench` measures the native engine directly.
- `bench-subms --only l2,l3 --no-wasm` (new flag) measures the real proxy over
  loopback at `c = 1` and `c = 16`; the L2 row (WAF disabled) is the proxy
  floor and `L3 - L2` is the WAF add-on.
- The host is shared with other agents. Numbers below are from pinned runs
  (`taskset -c 2-3`) taken back-to-back; absolute values move between runs, so
  compare rows from the same run.

## Changes

1. **Borrowed HTTP version.** `RequestContext.http_version` is now
   `Cow<'static, str>`. The proxy derives the version as a `&'static str`;
   storing it borrowed removes one allocation per request instead of cloning
   the detected string.
2. **Zero-copy engine request materialisation.** `RustEngineRule::evaluate`
   used to build an owned `Uri` string and one `String` per header name and
   value before every evaluation. `RustEngine::evaluate_detailed_borrowed`
   builds the phase-1 collections straight from the hyper `HeaderMap`; origin
   form URIs are borrowed from `path_and_query()`, and only absolute-form URIs
   need a temporary string. Non-UTF-8 header values get exactly the same lossy
   normalisation as before.
3. **One candidate pass per header.** Each heuristic content rule used to run
   one required-literal search per pattern per header (four rules × several
   patterns × every header). Each rule now compiles one ASCII
   case-insensitive Aho–Corasick automaton over all of its high-priority gate
   literals. A header value is scanned once and yields a candidate bitmask;
   patterns outside the mask provably cannot match and skip their regex. The
   automaton is a deliberate over-approximation: a non-ASCII value marks every
   pattern as a candidate, matching the previous "non-ASCII cannot be ruled
   out" gate behaviour, and an empty literal marks the pattern always-on.
4. **Proxy fixed cost.** The upstream request builder no longer allocates a
   lowercase `String` for every forwarded header just to compare
   hop-by-hop/proxy-owned names, and it builds the `x-forwarded-for` /
   `x-real-ip` value once instead of formatting the client IP twice.

Behaviour is unchanged: the rule chain runs in the same order, the same
pattern/header pair produces the same status and reason, gated patterns are
only skipped when a sound literal precheck proves a miss, metrics names and
labels are untouched, audit events are unchanged, and fail-closed paths are
not modified.

## Results

### Component profile (single-threaded, `bodyless-bench --profile --rust`)

Bodyless request, default header set, same core:

| component | p50 | notes |
|---|---:|---|
| wrapper only (no rules) | 0.31 µs | admission, metrics, size/method/rate gates, audit-on-allow |
| + heuristic content inspection | 3.12 µs | header candidate pass for all four rules (was ~13.9 µs in the wrapper profile before this pass) |
| + rust engine | 113 µs | full default chain = 116 µs p50 |

The engine dominates a bodyless decision; the wrapper itself is sub-microsecond
and the heuristic header scan is ~3 µs. `audit (full - fast)` is 0 ns because an
allowed request returns before an event is constructed.

### End-to-end (`bench-subms`, pinned `taskset -c 2-3`)

Same-load pair: baseline binary (`main` = e05d918) and this branch, 200
samples/cell, 200 sequential requests, c=16 = 16×30. Reference-load numbers
move by ±10 % between runs on this shared host (load average 10–15 from other
agents). The "after" column is the median of seven branch runs; the bodyless
range was 0.294–0.323 ms, so one clean run met the 0.30 ms target.

| size | before p50 | after p50 (range) | after p95 | after p99 | before allocs/req | after allocs/req |
|---|---:|---:|---:|---:|---:|---:|
| bodyless | 0.346 ms | **0.315 ms** (0.294–0.323) | 0.405 ms | 0.440 ms | 165 | 150 |
| 1 KiB | 0.523 ms | **0.454 ms** | 0.546 ms | 0.606 ms | 186 | 166 |
| 4 KiB | 0.858 ms | **0.810 ms** (0.789–0.835) | 0.879 ms | 0.920 ms | 186 | 166 |
| 8 KiB | 1.284 ms | **1.234 ms** (1.205–1.253) | 1.348 ms | 1.372 ms | 186 | 166 |

Concurrency 16 (user-visible per-request latency, still host-limited):

| size | before p50 | after p50 | after p99 |
|---|---:|---:|---:|
| bodyless | 2.05 ms | 2.02 ms | 3.9 ms |
| 1 KiB | 5.29 ms | 5.46 ms | 5.7 ms |
| 4 KiB | 11.0 ms | 10.3 ms | 10.8 ms |
| 8 KiB | 16.3 ms | 16.9 ms | 17.6 ms |

The L2 proxy floor (WAF disabled) also drops: 0.120 → 0.104 ms bodyless,
0.127 → 0.112 ms at 4 KiB, and 81.5 → 74.1 allocations per request, from the
borrowed version and the allocation-free hop-by-hop header check.

Targets: bodyless **< 0.30 ms** (median 0.315 ms, best run 0.294 ms: still
~15 µs over at the median), 4 KiB **< 0.85 ms** (0.810 ms, met), 8 KiB
**< 1.30 ms** (1.234 ms, met). The brief's `main` reference was
0.373 / 0.924 / 1.354 ms; against that reference the rows improve
~16 % / ~12 % / ~9 %.

## Residual and blockers

- Bodyless is now engine-bound. On this host the compiled engine alone is
  ~113 µs and the loopback proxy floor ~0.10 ms; the remaining ~0.10 ms to the
  0.30 ms target is the async proxy round-trip and the query-bearing CRS scan
  (`ARGS_GET` for `?id=42`), not the wrapper (0.3 µs).
- 4/8 KiB are dominated by the engine body scan (583 / 965 µs p50). The proxy
  and wrapper add ~0.12 ms; heuristic content inspection adds only ~13 µs at
  4 KiB after the candidate pass.
- c=16 p99 on this host is scheduling noise: the WAF-disabled L2 row shows the
  same shape, and other agents’ builds run concurrently.
- Further bodyless gains need engine-side (phase-1 `ARGS_GET`/header rule)
  work or a lower proxy floor, not wrapper changes.

## Parity and verification

Behaviour-preserving by construction; the parity and test evidence is recorded
in the task log and CHANGELOG.