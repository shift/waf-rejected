# Native engine rule loop: profile, empty-target gating and allocation cut

> **Historical research report.** This records the state of the branch/commit
> below. `rust-engine` is now in the default feature set and selected by
> default; "non-default" below is the research baseline only. For current
> behaviour see [engine selection](../user-guide/engine-selection.md).

**Branch:** `perf/engine-ruleloop`
**Engine:** `src/waf/rust_engine` (non-default `rust-engine` feature)
**Baseline:** `ad7e7ea`

## Summary

This pass profiled the rule loop at bodyless/1/4/8 KiB, removed the remaining
per-request allocations, and added an empty-target gate that skips rules whose
positive collections are absent. Latency improved (bodyless −30 %, 1 KiB
−14 %), but the headline targets are **not all met**; see
[Results](#results). The mandated transform pipeline, literal prefilter and
proxy/Coraza code were not modified.

## Changes

1. **Empty-target rule gate.** Every rule precomputes a bitmask of the dynamic
   collections it positively targets (keyed values, body, TX, `MATCHED_VARS`)
   plus `has_static_positive` / `may_count`. At evaluation time
   `RequestData::dynamic_present` produces the present mask; a rule whose mask
   cannot intersect it is skipped before candidate resolution and regex work.
   This mostly removes ARGS/body/XML rules on requests that do not carry them.
2. **Precomputed flags.** `multi_match`, `captures`, and per-group
   `records_matches` are resolved at load time instead of rescanning action
   vectors per request. `clear_captures`/`clear_matches` only run for rules and
   groups that need them, and the removed-rule fast path short-circuits when no
   `ctl` removal is active.
3. **Allocation-free macro names.** `expand_macro_name` no longer calls
   `to_ascii_lowercase` unconditionally; it borrows lowercase names. Regex
   selector matching reuses `lower_name` instead of allocating a lowercase
   `String` for every TX entry.
4. **Pre-resolved `skipAfter`.** Marker indices are resolved once at load time
   into `CompiledRule::skip_after`; a matching rule no longer clones the marker
   `String` into `GroupFlow` on every request.
5. **Arena-backed `MATCHED_VARS`.** Match records store name/value ranges into
   reused byte arenas. `record_match` no longer allocates a `String` name and a
   `Vec<u8>` value per match.
6. **Capture buffers are reused.** Regex and phrase operators clear and extend
   the per-rule capture slots instead of replacing them with fresh `Vec`s, so
   `TX:0..9` capture copies allocate only while the buffers grow.
7. **Profile extensions.** `engine-profile` now reports `tx`, `matched` and
   `TOTAL`/`unaccounted` allocation columns in `--profile`, plus an allocation
   checkpoint helper used during the investigation.

## Profile at 4 KiB (instrumented release, 100 reps)

| Category | ns | allocs/req |
|---|---:|---:|
| transform cache misses + pipeline | 100,970 | 0 |
| mandatory-literal gate (transform + AC) | 101,797 | 0 |
| regex / operator | 316,531 | 1 |
| candidate resolution | 21,416 | 18 |
| scoring (`setvar`/anomaly) | 16,165 | 3 |
| parse / body processing | 5,799 | 6 |
| TX rule fast path | (profile column) | 1 |
| captures | 0 | 0 |
| **total** | — | **33** |

Bodyless top costs are the fixed rule-dispatch scaffolding (about 30 µs) and
the gate/regex work over the five headers. The 4 KiB body is still dominated by
per-rule regex scans after the gate (`183` operator runs, `99` gate skips).

## Results

In-process parity harness, release build without `engine-profile`, shared host
(reps = 100). Targets are from the task brief.

| Request | p50 before | p50 after | p99 after | target | met |
|---|---:|---:|---:|---:|:--:|
| bodyless | 158 µs | **110 µs** | 230 µs | < 100 µs | no (10 %) |
| 1 KiB | 316 µs | **271 µs** | 356 µs | < 200 µs | no |
| 4 KiB | 636 µs | **596 µs** | 718 µs | < 450 µs | no |
| 8 KiB | 1.05 ms | **1.02 ms** | 1.18 ms | < 800 µs | no |

Allocations fell from ~143/request to **33-42/request** (target < 50 met;
target < 30 narrowly missed at 4/8 KiB, met by the instrumented 29/request
profile).

## Rejected experiment: per-(phase, pipeline) union DFAs

A union matcher was implemented and measured, first with `regex::RegexSet`,
then with eager multi-pattern dense DFAs and finally the lazy `meta` engine,
with reusable `PatternSet`/`Cache` scratch. Groups were split recursively to
fit a 2-16 MiB DFA budget and annotated up to 208 rules / 45 groups.

Measured 4 KiB p50 was 725-958 µs versus 596 µs without unions, because CRS
patterns determinise poorly (individual groups exceeded 64 MiB) and the
resulting groups re-scan the 4 KiB value often enough to outweigh the skipped
rule regexes. On bodyless the union added scans over headers/TX-only rules and
was also slower. The code was removed rather than shipped behind a flag; the
experiment is recorded here so it is not repeated blindly. A future attempt
should use a per-target literal prefilter (or a much smaller curated pattern
set) rather than unioning arbitrary CRS regexes.

## Parity

- Corpus: **2,110 / 2,112** native/Coraza agreement (unchanged).
- Native false negatives: **3**; Coraza false negatives: **5**; therefore
  **0 native-only false negatives**.
- Transform parity fixture: **7,320 / 7,320**.

## Verification

```text
cargo fmt -- --check
cargo test --lib --features rust-engine,native-detect,engine-kernel,crs-prefilter
cargo clippy --features rust-engine,native-detect,engine-kernel,crs-prefilter -- --deny warnings
rust-engine-parity --engine both --conf wasm/coraza_reactor/rules/crs/crs.conf
```

## Follow-ups

- The 4/8 KiB gap is still regex scan time over the single large ARGS value.
  The safe next lever is reducing the number of scans (curated per-target
  unions, or a better required-literal artifact), not parallelising rule order.
- Allocation target < 30 needs borrowed single-value candidates and an
  interned TX-name table (key hashing and first-use slots account for most of
  the residual 33).