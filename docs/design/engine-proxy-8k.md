# 4/8 KiB end-to-end: engine and proxy hot-path work

**Branch:** `perf/8k` (worktree `.worktrees/perf-8k`, base `main` = `20afbaf`)
**Scope:** default Rust CRS engine + `WafProxyService`. gRPC, GraphQL and
security policy were not touched.

## Method

`bench-subms` was extended to run every size at `c = 1` and `c = 16` and to
report a second Rust row with the heuristic content-inspection rules disabled
(`--no-content-inspection`), so the engine cost can be separated from the
legacy heuristics. The real proxy and a mock upstream run in one process over
loopback; the L2 (WAF disabled) row is the proxy floor. Engine phases come from
`rust-engine-parity --profile` (`engine-profile`), which reports per-category
time and now the top rules per body size.

The measurement host is shared with other agents, so absolute numbers move
between runs. The tables below compare rows taken in the same run; the
`main` reference is the brief's baseline.

## Changes

1. **One transform/gate identity per argument.** `ARGS` / `ARGS_NAMES`
   concatenate the GET and POST collections, but previously gave the same
   bytes a third cache id. They now reuse `ARGS_GET[+POST]` /
   `ARGS_POST` ids (`entry_cache_id_split`), so a rule set that targets both
   `ARGS` and `ARGS_POST` transforms and literal-gates an argument once.
2. **Borrow identity pipelines.** A candidate whose rule has an empty
   transform chain is used directly instead of being copied into the transform
   arena (a full body-sized copy per phase). Gate groups with an empty plan do
   the same.
3. **Cross-phase transform cache.** The cache is now reset once per
   transaction, not per phase. Header values inspected in phase 1 are commonly
   re-read by phase 2 rules and cannot change; TX/`MATCHED_VARS` still use the
   uncached path because they do change.
4. **Per-phase gate pruning.** Every literal/subsequence gate group records the
   phases of the rules that reference its gates; `gate_mask` skips groups no
   rule in the current phase needs.
5. **Inline native-engine body scans.** The configured backend is now part of
   `WafEngine`. Rust-engine body scans up to 64 KiB run inline instead of
   `spawn_blocking` + an owned `RequestContext` clone; larger bodies and the
   Coraza backends keep the blocking-pool path.
6. **Content-inspection literal gates.** The four heuristic content rules
   scanned every 4/8 KiB body with several large regexes. Each pattern now
   carries a sound disjunctive required-literal set produced by the same
   conservative extractor as the CRS artifact (`prefilter_extract::
   required_literals`). A missing literal proves the regex cannot match, so
   the scan is skipped; non-ASCII haystacks and mixed case-folding patterns are
   never gated.
7. **Proxy response headers.** The hop-by-hop check is case-insensitive
   without allocating a lowercase `String` for every response header.

## Results

`bench-subms`, 300 sequential requests per cell, 16×50 for the throughput cell,
shared host (load ≈ 1.4–2.0). `rust-nocheck` disables the heuristic content
rules. Rows are the final build.

| layer | size | p50 | p99 | c=16 p50 | c=16 p99 |
|---|---|---:|---:|---:|---:|
| L2 proxy (no WAF) | bodyless | 0.144 ms | 0.249 ms | 0.276 ms | 0.954 ms |
| L2 proxy (no WAF) | 1 KiB | 0.136 ms | 0.281 ms | 0.281 ms | 0.573 ms |
| L2 proxy (no WAF) | 4 KiB | 0.126 ms | 0.259 ms | 0.282 ms | 0.551 ms |
| L2 proxy (no WAF) | 8 KiB | 0.153 ms | 0.274 ms | 0.299 ms | 0.731 ms |
| L3 rust | bodyless | 0.373 ms | 0.468 ms | 0.854 ms | 3.132 ms |
| L3 rust | 1 KiB | 0.603 ms | 0.679 ms | 2.100 ms | 4.382 ms |
| L3 rust | 4 KiB | 0.924 ms | 1.013 ms | 3.663 ms | 6.594 ms |
| L3 rust | 8 KiB | 1.354 ms | 1.439 ms | 5.887 ms | 8.213 ms |
| L3 rust-nocheck | bodyless | 0.351 ms | 0.430 ms | — | — |
| L3 rust-nocheck | 4 KiB | 0.891 ms | 0.979 ms | — | — |
| L3 rust-nocheck | 8 KiB | 1.286 ms | 1.369 ms | — | — |

Targets: 4 KiB < 0.9 ms (**0.924 ms, missed by 24 µs**), 8 KiB < 1.3 ms
(**1.354 ms, missed by 54 µs**), bodyless < 0.3 ms (**0.373 ms, missed**).
On this host the `main` reference was 1.09 / 1.61 ms; the pass is ~15 % lower
at both 4 and 8 KiB. The content-inspection gates alone are worth ~33 µs at
4 KiB and ~68 µs at 8 KiB; before them the same rows were 0.953 / 1.408 ms.

The engine alone (`rust-engine-parity --bench`, 500 reps, same host):

| body | engine p50 | engine p99 | allocs/req |
|---|---:|---:|---:|
| bodyless | 115 µs | 158 µs | 76 |
| 1 KiB | 281 µs | 335 µs | 79 |
| 4 KiB | 556 µs | 616 µs | 78 |
| 8 KiB | 941 µs | 1 159 µs | 78 |

## Residual breakdown and blockers

- At 4/8 KiB the engine is ~60 % of the end-to-end time and the proxy floor is
  ~0.13–0.15 ms. Within the engine the dominant residual is ungated per-rule
  `@rx` evaluation (`rust-engine-parity --profile`: regex/operator is the
  largest category, literal gate transform + Aho-Corasick the second,
  transform pipelines third; candidate resolution, scoring and body parsing
  are tens of microseconds together).
- The regex share is the known blocker: the residual rules have no provable
  mandatory literal, so each large `@rx` (for example the path-traversal and
  PHP patterns) still scans the whole 4/8 KiB value. The earlier union-DFA,
  Vectorscan and RCE-subsequence experiments are the existing attempts to
  reduce that count; none is part of the default build. This pass does not
  weaken detection to remove scans.
- Bodyless misses by ~70 µs. The engine is 115 µs and the proxy floor 144 µs;
  the rest is the `WafEngine` wrapper (rule-chain iteration, the `RequestContext`
  and header/URI materialisation for the engine adapter, admission checks and
  audit bookkeeping). Trimming it is the next bodyless lever.
- `p99` at `c = 16` is dominated by scheduling on the shared host, not by the
  WAF: the L2 floor shows the same shape.

## Parity

Decision parity is unchanged: **2,112/2,112** corpus agreement between the
native engine and Coraza (100 %), with 0 native-only false negatives, and the
transform fixture remains **7,320/7,320**. The content-inspection gates are
disjunctive required-literal checks, so a skipped pattern provably cannot
match; non-ASCII haystacks and mixed case-folding patterns are never gated.
