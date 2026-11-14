# Transform cache and literal-gate hot path

**Branch:** `perf/transform-hot` (worktree `.worktrees/transform-hot`)
**Base:** `0d5d509` (`0.1.0-beta.12`)
**Modules:** `src/waf/transforms.rs`, `src/waf/prefilter.rs`,
`src/bin/transform_bench.rs`
**Feature:** non-default `crs-prefilter` (no defaults changed)

## Why plain input was slower than percent-encoded input

Plain form bodies contain many `&` separators (`&city=`, `&note=`, ...).
Each `&` drove `HtmlEntityDecode`, which walked the entity name and then ran
several binary searches over the 2,231-entry HTML5 table. A 4 KiB plain body
has roughly 190 `&` characters, so one `HtmlEntityDecode` pass cost ~45 µs;
the transform DAG applies it to several chains. Percent-encoded bodies contain
no `&`, so `HtmlEntityDecode` is the identity, aliases its parent, and several
chains collapse onto the same representation.

Two cache problems amplified this:

* `TransformCache::resolve` was called once per rule group and re-walked the
  whole group plan. A linear `(parent, step)` memo scan made the cost grow
  quadratically with the number of intermediate values.
* Every changed step copied its output and then re-hashed/re-compared several
  KiB for content deduplication.

## What changed

### Transform cache (`src/waf/transforms.rs`)

* **One pass per value.** `resolve_all` walks the registered prefix DAG in
  parent-before-child order, so groups read their final prefix instead of
  re-walking their plan. The O(n²) step memo is gone; a compact
  `(parent slot, step) -> slot` memo preserves cross-chain sharing.
* **Identity/unchanged values alias their parent.** No per-value `Vec`, no
  arena copy when a step is the identity or produces the same bytes.
* **Sampled dedup hash.** Content dedup still aliases equal large values (this
  is worth roughly 19 KiB of duplicate scans on the plain fixture) but hashes
  only a fixed sample per value instead of the whole buffer.
* **Transform fast paths:**
  * ASCII lower/upper case uses `extend_from_slice` +
    `make_ascii_lowercase`/`uppercase`.
  * `removeWhitespace` and `compressWhitespace` copy spans between spaces
    instead of branching per byte; their identity checks use `memchr`.
  * `cmdLine` folds case in place when the value only needs case folding.
  * `HtmlEntityDecode` uses an open-addressed entity index and, for
    no-semicolon references (`&key=value`), a ~100-entry legacy table instead
    of searching the full HTML5 table. This is the single largest win.

### Literal gate (`src/waf/prefilter.rs`)

* One **case-insensitive union automaton** covers both case classes; scanning
  a case-sensitive literal case-insensitively can only add hits, never remove
  a rule. This halves automaton passes.
* Pattern attribution is now a flat **group/rule bitset** per pattern. Each
  automaton match is a couple of word AND/OR operations instead of walking a
  `(group, rules)` list and doing linear `Vec::contains`.
* The accumulated **rule-hit bitset is shared across every input and group**
  and converted to the bounded rule-id list once per request.
* Distinct representations are still resolved and scanned once each. All four
  body-processor extraction variants are still scanned: a miss remains a
  proof, so gating stays one-sided and ungated rules always run.

### Benchmark

`transform-bench` now reports **process CPU time** (like
`engine-kernel-bench`). The shared host runs at load ~6 on 6 cores; wall-clock
p50 mixes in scheduling delays. It also reports union-scan-only and
single-transform rows so the cache and matcher costs stay separable.

## Results (4 KiB, process CPU time p50, `taskset -c 2`)

| phase / row | before | after |
|---|---:|---:|
| prefilter, plain | ~604 µs | **~145 µs** |
| prefilter, percent | ~184 µs | **~48 µs** |
| prefilter, double-encoded | ~214 µs | **~50 µs** |
| plain, no rule transforms | ~175 µs | ~39 µs |
| union scan only (4 KiB) | n/a | ~9 µs |
| long chain (6 transforms) | ~79 µs | ~12 µs |
| allocations per call | 1–2 | 2 |
| transform allocations | 0 | 0 |

Percent-encoded input beats the <120 µs target by ~2.5×. Plain input improved
~4.2× but is still **~145 µs, above the <120 µs target**; see the blocker.

## Parity and soundness

* Transform fixture: **7,320 / 7,320** byte-for-byte cases match the vendored
  Coraza transforms (`waf::transforms::tests::coraza_parity`).
* `cargo test --lib --features wasm-reactor,crs-prefilter,rust-engine`:
  **507 passed, 0 failed** (10 ignored).
* Prefilter tests (including clean-request removal, mixed-case literals,
  DTD forcing and ungated rules) all pass.
* A gate miss is still a proof over every extraction variant and transform
  prefix; the changes only add hits. `matched_rules` can now contain a few
  extra case-fold matches, which only keeps rules running.

## Remaining blocker

Plain input still pays ~19 KiB of representation scans because the four
extraction variants and the rule transform chains genuinely produce distinct
4 KiB representations (`&not` entity decoding, `+`→space, whitespace removal).
The safe "scan the parent instead of a lowercased child" shortcut cannot be
used unconditionally: an ASCII input can decode to non-ASCII bytes, and
Unicode simple case folding can then produce ASCII letters (e.g. `U+212A` →
`k`), which an ASCII-case-insensitive automaton would miss on the parent.
Restricting the shortcut to ASCII parents removed the win on this fixture.
Reaching <120 µs for plain text therefore needs a matcher that can express
"literal with removable whitespace/case folding" directly, or a
content-type-aware extraction path (body processor known), not another
transform micro-optimisation.
