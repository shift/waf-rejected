# Shared transform pipeline: semantics, parity and measurements

**Status:** implemented behind the non-default `crs-prefilter` feature; also
compiled when the `fastpath` feature is enabled. Unit tests run without either
feature so `cargo test --lib` always exercises the Coraza parity suite.
**Branch:** `perf/transform-pipeline` (worktree `.worktrees/transforms`).
**Date:** 2026-11-02.
**Engine:** Coraza `v3.3.3` / OWASP CRS `4.14.0` (vendored at
`wasm/coraza_reactor/vendor`).
**Artifact:** `rules/crs/prefilter.json` (schema v1).

## TL;DR

* `src/waf/transforms.rs` is a bounded, allocation-free transform pipeline. A
  request-scoped arena stores every intermediate value; after the first request
  on a thread the arena, slot table and scratch buffers are reused, so the
  pipeline performs **0 allocations per request**.
* Chains are memoised at every prefix. Two additional levels of sharing make
  the cost proportional to the number of *distinct* representations rather than
  the number of rules:
  * step memoisation keyed by `(parent bytes, step)`,
  * content deduplication of equal intermediate values.
* The prefilter now scans each distinct representation **once** with a union
  Aho-Corasick automaton per case sensitivity, instead of running one automaton
  per `(extract, chain, case)` group (84 passes before).
* Differential parity against the vendored Go transforms: **7,320 / 7,320 cases
  match byte-for-byte** (20 transforms × 366 generated inputs).
* Measured on the shared `i5-8400T` host at load average ~4.3 (other agents were
  running): 4 KiB percent-encoded prefiltering is **176 µs p50 / 255 µs p99**;
  4 KiB double-encoded is **204 µs p50**. The transform pipeline alone costs
  **14 µs p50** for the longest CRS chain on 4 KiB percent input.
* Remaining gap: plain (not encoded) bodies are dominated by
  `removeWhitespace`/`cmdLine` work and stay above 200 µs at 4 KiB (590 µs p50);
  8 KiB encoded is ~350–400 µs. See §6.

## 1. API

```rust
pub enum Transform { Identity, Lowercase, Uppercase, UrlDecode, UrlDecodeUni,
    RemoveNulls, ReplaceNulls, CompressWhitespace, RemoveWhitespace, Trim,
    TrimLeft, TrimRight, NormalizePath, NormalizePathWin, EscapeSeqDecode,
    ReplaceComments, JsDecode, CssDecode, HtmlEntityDecode, CmdLine,
    Base64Decode, JsonUnescape }

impl Transform {
    pub fn from_rule_name(name: &str) -> Option<Self>;
    pub fn is_noop_name(name: &str) -> bool;   // "none" | "utf8tounicode"
    pub fn is_identity_on(self, input: &[u8]) -> bool;
    pub fn apply_into(self, input: &[u8], output: &mut Vec<u8>);
}

pub struct TransformCache { /* arena, slots, entries, scratch */ }
impl TransformCache {
    pub fn begin_request(&mut self, prefix_count: usize);
    pub fn begin_value(&mut self, value: &[u8]) -> Result<ValueId, TransformError>;
    pub fn resolve(&mut self, value: ValueId, input: &[u8],
                   plan: &[u32], prefixes: &[Vec<Transform>])
        -> Result<Range<usize>, TransformError>;
    pub fn bytes(&self, range: Range<usize>) -> &[u8];
}
```

`plan` is the list of registered prefix ids for a group's chain. Prefix 0 is the
raw value; prefix *i* is the chain truncated after *i* steps. The prefilter
assigns ids at load time, so two rules that share a prefix share its cache slot
automatically.

### 1.1 Bounds and fail-closed behaviour

| bound | value | on violation |
|---|---|---|
| one intermediate value | `MAX_VALUE_BYTES = 256 KiB` (also `3 × input + 64`) | `TransformError::OutputOverflow` |
| per-request arena | `MAX_ARENA_BYTES = 8 MiB` | `TransformError::ArenaOverflow` |

`Prefilter::evaluate` converts either error into `PrefilterHit::forced(...)`
(full CRS evaluation). `Prefilter::evaluate_inputs` returns a `RuleGate` with
`forced_reason = Some("transform pipeline exceeded its bound")` and **no**
removable rules. No partial transform result is ever used.

### 1.2 Zero-allocation design

* `begin_request` only calls `clear()`/`fill(0)`; capacities are retained.
* Outputs are written into a reusable `scratch: Vec<u8>` and appended to the
  arena; `Vec::extend_from_slice` does not allocate once the arena has reached
  its high-water mark.
* Slot lookup is a flat `Vec<u32>` indexed by
  `value_index * prefix_count + prefix_id`, so there is no hash allocation.
* `is_identity_on` skips the transform entirely for values it cannot change.
* Unchanged outputs alias their parent's range (no copy).
* Equal outputs from different chains are deduplicated by a fast 64-bit hash
  plus a byte comparison (the hash is only a filter; correctness comes from the
  comparison).

`evaluate_inputs` still allocates **one** `Vec` per request for the returned
removal list (bounded to 256 ids). That list is owned by the caller and is
outside the pipeline; the body-withhold path (`evaluate_with_cache`) and the
pipeline itself allocate zero.

## 2. Transform semantics

All semantics are ports of the vendored Coraza code. The fixture
(`tests/fixtures/transform_parity.json`) is generated by running the **actual
vendored Go functions**, not a re-implementation.

| transform | notes |
|---|---|
| `urlDecode`, `urlDecodeUni` | `+` → space; `%XX` only when both digits are hex; invalid `%` is copied literally and the following bytes are re-examined; `%uXXXX` in `urlDecodeUni` uses the low byte and adds `0x20` for full-width `FF01..FF5E`. |
| `lowercase`, `uppercase` | Go `strings.ToLower`/`ToUpper`: **simple, context-free** mappings. Rust's `char::to_lowercase` uses full mappings (e.g. `U+0130` → `i̇`), so the tables are generated from Go's `unicode` tables. Invalid UTF-8 bytes become one `U+FFFD` per byte, exactly like ranging over a Go string. |
| `removeNulls`, `replaceNulls` | `0x00` removed / replaced by space. |
| `compressWhitespace` | Latin-1 space set `\t \n \v \f \r space 0x85 0xA0` collapses to one ASCII space. |
| `removeWhitespace` | Go `unicode.IsSpace` (White_Space plus the ASCII controls); invalid UTF-8 → `U+FFFD`. |
| `trim*` | cutset `" \t\n\r\f\v"` (byte-safe: cutset bytes never occur in UTF-8 continuation positions). |
| `normalizePath` | Go `filepath.Clean` on Unix, then Coraza's quirks: empty → empty, clean `"."` → empty, and a trailing `/` is re-appended (`"/"` → `"//"`, `"a//b/./c/"` → `"a/b/c/"`). |
| `normalizePathWin` | Replace `\` with `/`, then `normalizePath` (the trailing-slash test uses the replaced string). |
| `escapeSeqDecode` | Octal escapes saturate at 255 (`\400` → `0xFF`), matching `strconv.ParseUint(..., 8, 8)`. |
| `replaceComments` | `/* ... */` removed; the closing token becomes a space; an unterminated comment appends a space. |
| `jsDecode` | Byte-for-byte port, **including Coraza's octal bug**: the first parsed digit is the backslash, so `\101` decodes to NUL plus the remaining bytes, not `A`. Reproducing the bug is required for soundness; a "correct" decoder would scan values Coraza never produces and could hide a literal. |
| `cssDecode` | 1–6 hex digits after `\`; last two bytes are used; full-width `FF01..FF5E` adds `0x20`; one whitespace after the escape is skipped. |
| `htmlEntityDecode` | Full `golang.org/x/net/html.UnescapeString` semantics: numeric references (Windows-1252 replacements for `0x80..0x9F`, invalid/surrogate/out-of-range → `U+FFFD`, wrapping `int32` accumulation), the complete 2,231-entry HTML5 named-entity table, and the legacy no-semicolon prefix rule (longest prefix ≤ 6). The table lives in `src/waf/transforms/entities.rs`. |
| `cmdLine` | Removes `" ' \ ^`, collapses space/comma/semicolon/tab/CR/LF to one space, removes a space before `/` or `(`, ASCII-lowercases. |
| `base64Decode` | Coraza's partial decoder: padding optional, `\r`/`\n` ignored, decoding stops at the first invalid byte (`=`, space, >127, or a 127 table entry), leftover 2/3 characters produce 1/2 bytes. |
| `jsonUnescape` | Extraction variant for JSON bodies (not a Coraza transform name). |

`utf8toUnicode` is treated as a no-op: the extractor only accepts it when every
literal is ASCII, where it is the identity. `none` is a no-op.

## 3. Differential parity

`scripts/gen-transform-fixture.sh` copies the vendored Coraza transform sources
into `target/transformgen`, renames their package, and runs
`scripts/transformgen/main.go` with `GOOS=linux GOARCH=amd64` (the dev shell
exports `GOOS=js GOARCH=wasm` for the reactor). The generator:

* emits `tests/fixtures/transform_parity.json` (366 inputs × 20 transforms,
  hex encoded),
* emits `src/waf/transforms/entities.rs` from
  `golang.org/x/net/html/entity.go`,
* emits `src/waf/transforms/case_tables.rs` from Go's `unicode.ToLower/ToUpper`.

Inputs cover valid/invalid/double percent encodings, `+`, `%uXXXX`, UTF-8 and
invalid UTF-8, truncated sequences, NULs, mixed case, HTML entities (named,
numeric, legacy no-semicolon, Windows-1252, invalid), path forms, whitespace,
command lines, escape sequences, comments, base64, and 200 deterministic random
byte strings.

Result: **7,320 / 7,320 byte-for-byte matches**, no documented mismatches.
The only deliberate non-parity is defensive: Coraza's `base64Decode` table has
128 entries, so bytes `123..=127` map to "invalid" (127) and stop decoding; the
Rust table reproduces that. Nothing panics.

Regenerate with:

```sh
nix develop -c scripts/gen-transform-fixture.sh
nix develop -c cargo fmt     # generated Rust is not pre-formatted
```

## 4. Prefilter integration

The prefilter changed in three places:

1. **Plans.** A group key is now the full step list (`extract` + rule
   transforms). A load-time registry assigns an id to every unique prefix.
2. **One scan per distinct representation.** For each input, every group's plan
   is resolved through `TransformCache`, producing `(start, end, group)`. Ranges
   are sorted and each distinct range is scanned once. A union Aho-Corasick
   automaton (one per case sensitivity) contains every literal; each pattern
   maps to `(group, rule ids)`, and a match is attributed only to groups that
   own the current representation. This is equivalent to the previous
   per-group automata but turns 84 passes into one pass per unique
   representation. `find_overlapping_iter` is used (after a fast `is_match`
   guard) so a shorter literal is never skipped because a longer literal
   overlaps it.
3. **Per-thread caches.** `evaluate`/`evaluate_inputs` use thread-local
   `TransformCache` and `ScanScratch`. Public `*_with_cache` variants take an
   explicit cache for benchmarks and callers that own one.

Detection policy is unchanged: the same groups, literals and case sensitivity
are evaluated; only the evaluation strategy changed. `automaton_count()` still
reports the logical group count (84 for stock CRS); `union_automaton_count()`
reports the two physical automata.

## 5. Measurements

Command:

```sh
nix develop -c cargo run --release --features crs-prefilter \
  --bin transform-bench
```

Host: Intel i5-8400T, 6 cores, shared with other agents (load average 4.3 during
the run below; earlier runs at load 6–14 were 2–3× slower). `taskset -c 5` was
used to reduce migration. p50/p99 over 300 repetitions after 32 warm-up calls.
"all-transforms" is the embedded artifact; "no-transforms" is the same artifact
with every rule transform chain cleared (the four extraction variants remain).

| size | variant | pipeline | p50 µs | p99 µs | allocs/req | scanned KiB |
|---:|---|---|---:|---:|---:|---:|
| 1 KiB | plain | all-transforms | 157.7 | 232.3 | 1 | 4.8 |
| 1 KiB | percent | all-transforms | 53.5 | 74.8 | 1 | 1.7 |
| 1 KiB | double | all-transforms | 54.4 | 69.2 | 1 | 2.0 |
| 4 KiB | plain | all-transforms | 590.0 | 664.9 | 1 | 19.2 |
| 4 KiB | percent | all-transforms | **175.9** | 255.4 | 1 | 6.7 |
| 4 KiB | double | all-transforms | **203.7** | 288.2 | 1 | 8.0 |
| 8 KiB | plain | all-transforms | 1151.5 | 1270.1 | 1 | 38.4 |
| 8 KiB | percent | all-transforms | 348.2 | 406.6 | 1 | 13.3 |
| 8 KiB | double | all-transforms | 399.6 | 448.9 | 1 | 16.0 |
| 4 KiB | percent | no-transforms | 61.5 | 136.9 | 1 | 5.3 |
| 4 KiB | percent | body-withhold | 168.1 | 269.4 | **0** | 6.7 |

Pipeline-only (longest CRS chain:
`urlDecodeUni,htmlEntityDecode,jsDecode,cssDecode,removeNulls,lowercase`):

| size | variant | p50 µs | p99 µs | allocs/req | output KiB |
|---:|---|---:|---:|---:|---:|
| 4 KiB | plain | 74.7 | 112.8 | **0** | 3.8 |
| 4 KiB | percent | 13.9 | 32.9 | **0** | 1.3 |
| 4 KiB | double | 12.6 | 16.5 | **0** | 2.4 |
| 8 KiB | percent | 27.5 | 41.2 | **0** | 2.7 |

Before this change, the same 4 KiB percent case measured **2.31 ms** (and the
old per-group pipeline recomputed each chain per group). The new path is ~13×
faster on the encoded case and removes all per-request transform allocations.
The `scanned KiB` column shows why the union automaton matters: 4 KiB percent
scans 6.7 KiB instead of the 176 KiB that 84 per-group automata scanned.

## 6. Remaining gaps

* **Plain bodies are still above 200 µs at 4 KiB** (590 µs p50). The cost is
  real transform work, not scanning: `removeWhitespace` and `cmdLine` change
  nearly every chain, so content dedup cannot collapse them. A future pass
  could fuse the common `removeWhitespace → lowercase` tail or add a
  vectorised whitespace remover.
* **8 KiB encoded is 350–400 µs**, sub-millisecond but not ≤200 µs. The target
  was specified for 4 KiB; 8 KiB doubles the transform input.
* **p99 is noisy on this host** (other agents share all 6 cores). The p50 is the
  stable signal; the p99 column includes scheduler interference.
* **Thread-local caches are per OS thread** and keep their high-water mark
  (arena ≤ 8 MiB, slots/entries proportional to groups × inputs). For a runtime
  with many short-lived threads this could be worth pooling; the ingress worker
  model reuses threads, so it is not a current problem.
* **Fast path integration is indirect**: `main`'s `fastpath` body inspector
  already calls `Prefilter::evaluate`, so it benefits from this pipeline
  automatically. The prefilter is compiled under either `crs-prefilter` or
  `fastpath`. The pipeline API (`TransformChain`, `extract_view`) is standalone
  for the Vectorscan/Hyperscan evaluation target.
* **`base64Decode` is implemented and parity-tested but the stock CRS artifact
  does not gate any rule with it.** It is available for future artifacts.
* **Generated tables are large** (~145 KiB of Rust source for entities and case
  mappings). They are static sorted arrays with binary search, so there is no
  startup parsing or allocation.
