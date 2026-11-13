# Native engine: shared batched transform pipeline

> **Historical research report.** This records the state of the branch/commit
> below. `rust-engine` is now in the default feature set and selected by
> default; "non-default" below is the research baseline only. For current
> behaviour see [engine selection](../user-guide/engine-selection.md).

**Branch:** `perf/engine-transforms` (worktree `.worktrees/engine-transforms`)
**Base:** `22de3e9`
**Modules:** `src/waf/rust_engine/{transforms,engine,ir,error,budget}.rs`,
`src/waf/transforms.rs`, `src/waf/mod.rs`
**Feature:** non-default `rust-engine` (no defaults changed)

## Problem

The native engine carried a private `TransformCache` keyed by
`(value id, pipeline id)` that stored owned bytes per rule chain. It removed
duplicate work across rules that shared a chain, but every *distinct* chain
re-ran its steps from the raw value. CRS has many chains that share a prefix
(`urlDecodeUni`, `lowercase`, `urlDecodeUni → lowercase`, ...), so the same
percent-decoding and case folding ran several times per value.

Post-optimization verification ranked this path as the #1 hot spot:
**~400 µs / 36 % of a 4 KiB request** (`transform pipeline` in the
`engine-profile` build; the mandatory-literal gate pays the same cost once more
through its own pipelines).

## What changed

1. **One transform implementation.** `src/waf/rust_engine/transforms.rs` no
   longer contains byte codecs. The engine's `Transform` enum maps 1:1 onto the
   shared, Coraza-parity `waf::transforms::Transform`; the shared module gained
   the four transforms the engine needed but the prefilter did not
   (`sha1`, `hexEncode`, `removeCommentsChar`, `length`) plus a real
   `utf8ToUnicode`. `waf::transforms` is now compiled for `rust-engine` too.
2. **Shared prefix DAG.** `Program::intern_pipelines` also builds a
   `PrefixTable` over every interned chain: one entry per distinct chain prefix,
   parent-before-child. Each pipeline resolves through a plan of prefix ids.
3. **Shared request cache.** The engine uses `waf::transforms::TransformCache`
   directly (generic over the `Step` trait) instead of its private table:
   * a value is registered once per phase; a changed value id (TX storage reuse)
     is re-registered rather than served stale bytes,
   * an already-computed prefix is reused across rules, gate groups and
     extraction variants,
   * identity steps (`upper` on a lowercase value, `htmlEntityDecode` with no
     `&`, ...) alias their parent with no copy,
   * equal outputs alias one arena entry (one automaton scan),
   * the arena, slot table and scratch buffer keep their capacity across
     requests, so steady state allocates nothing.
4. **Budget preserved.** The shared cache enforces the engine's
   `max_value_bytes` per output and a bounded arena. Its `transform_bytes()`
   counter is charged as a delta through `Budget::materialised`, so aliased or
   memoised representations are not double charged and the request-wide byte
   cap is unchanged.
5. **Gate path.** `gate_mask` now resolves each gate pipeline through the same
   cache, so a representation shared by a rule chain and a gate group is
   computed once.

The prefilter entry points are untouched: it still uses the same cache with the
same defaults (sampled dedup hash, identity aliasing, `3 * input` expansion
guard). The only shared-internal change that affects it is that the per-request
step memo is cleared per value (it is per-value state anyway), which bounds it
to the prefix count.

## Semantics

Chains, order and outputs are unchanged in the corpus. The engine previously
had byte-level divergences from the vendored Coraza transforms (for example its
`jsDecode` implemented standard JS octal escapes while Coraza reproduces the
upstream octal quirk, and its `utf8ToUnicode` copied invalid bytes instead of
emitting U+FFFD). Using the shared Coraza-parity codecs removes those
divergences; corpus decisions are unchanged (see below). The transform fixture
(`tests/fixtures/transform_parity.json`, 7,320 assertions) is unchanged and
still passes byte-for-byte.

## Results

Shared host, `rust-engine-parity` release build, `taskset -c 3`, process wall
clock p50/p99, 500–600 reps per row. The host load average was ~1.1–1.6.

### Before / after

| Body | Before p50 | After p50 | Before p99 | After p99 | Target |
|---|---:|---:|---:|---:|---:|
| bodyless | 162.0 µs | **158.1 µs** | 172.0 µs | 192.6 µs | < 150 µs (missed, −2 %) |
| 1 KiB | 453.6 µs | **315.9 µs** | 483.8 µs | 361.8 µs | — |
| 4 KiB | 1,164.5 µs | **635.8 µs** | 1,258.1 µs | 701.8 µs | < 800 µs (met, −45 %) |
| 8 KiB | 2,110.6 µs | **1,053.2 µs** | 2,268.8 µs | 1,133.8 µs | < 1,500 µs (met, −50 %) |

Three consecutive after-runs: 4 KiB p50 634.0 / 635.8 / 636.3 µs,
8 KiB p50 1,052.9 / 1,053.2 / 1,053.9 µs. Bodyless stayed at 157.7–162.3 µs,
which is the pre-change range; the transform work at bodyless is only ~34 µs
and the remainder is the non-transform rule loop, so the < 150 µs row is not
reachable from the transform path alone.

### Per-phase (`engine-profile`, ns per request)

| Body | xform before | xform after | gate before | gate after | regex after |
|---|---:|---:|---:|---:|---:|
| bodyless | 11,857 | 15,859 | 24,003 | 18,496 | 22,520 |
| 1 KiB | 109,868 | 42,344 | 108,504 | 45,586 | 106,891 |
| 4 KiB | 373,512 | **89,858** | 338,541 | **102,019** | 316,107 |
| 8 KiB | 718,886 | **152,398** | 639,946 | **175,985** | 592,022 |

Transform work fell 76 % at 4 KiB and 79 % at 8 KiB; the mandatory-literal gate
fell 70–73 % because it shares the same prefix representations. The tiny
bodyless regression in `xform` (+4 µs) is the shared cache's per-resolution
bookkeeping on very small header values; it is more than offset in `gate` and
is invisible in the end-to-end p50.

### Allocations

141.1 (bodyless), 144.5 (1 KiB), 143.0 (4 KiB, 8 KiB) per request — unchanged
from the 142.7 / 146.4 / 143.3 baseline. The transform category itself reports
**0 allocations** at every size; the remaining allocations are candidate
resolution, scoring and captures, as documented in `engine-hotloop.md`.

## Verification

- `cargo fmt -- --check` — clean.
- `cargo clippy --lib --features rust-engine,native-detect,engine-kernel,crs-prefilter -- --deny warnings` — clean.
- `cargo test --lib --features rust-engine,native-detect,engine-kernel,crs-prefilter` — **538 passed**, 0 failed, 10 ignored. This includes
  `waf::transforms::tests::coraza_parity` (7,320/7,320 fixture assertions) and
  the new extended-transform/prefix-table tests.
- CRS corpus (`rust-engine-parity --engine both`, wasm Coraza oracle):
  **2,110 / 2,112** agree, rust vs expected FN 3 / FP 91, Coraza vs expected
  FN 5 / FP 91. The two disagreements are the known `921250` cases where the
  corpus expects Block, the native engine Blocks and Coraza Allows — i.e. **0
  native-only false negatives**.
- Prefilter regression: `transform-bench` 4 KiB plain 145.6 µs / percent
  46.1 µs raw pipeline, matching the pre-change 145 / 48 µs results; the
  prefilter entry points were not modified.

## Remaining

- Bodyless p50 is 158 µs against a < 150 µs target. The transform and gate
  phases at bodyless are ~34 µs total; the rest is rule-loop scaffolding that
  is outside this task's scope and unchanged by it.
- `waf::transforms::is_noop_name` still treats `utf8ToUnicode` as an identity
  for the prefilter (pre-existing behaviour, left untouched to keep the
  prefilter path stable). The engine maps it to the real Coraza transform.
