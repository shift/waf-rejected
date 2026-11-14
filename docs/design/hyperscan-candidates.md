# Vectorscan multi-pattern candidate pass for the residual regex subset

**Status:** experimental, non-default (`hyperscan-eval`), not enabled by default.
**Branch:** `perf/hyperscan-candidates`.
**Engine:** native Rust CRS engine, OWASP CRS 4.14.0, PL1.
**Library:** Vectorscan 5.4.12 (`nixpkgs#vectorscan`, `libhs`).

## Why

At the time of writing the Rust engine spends roughly half of a body request in
per-rule `@rx` evaluation. The mandatory-literal prefilter
(`docs/suggestions_from_agents/crs-prefilter.md`, `src/waf/rust_engine/gate.rs`)
already skips rules whose required literals are absent, but only for rules where
the offline extractor could prove a literal set. The remaining positive `@rx`
rules run their own `regex` automaton for every candidate value.

This pass compiles the residual subset into Vectorscan block-mode databases and
uses one multi-pattern scan as a *candidate* filter: a rule is skipped only when
its own pattern did not hit; a hit still runs the full operator so captures,
`MATCHED_VARS`, transformations and anomaly scoring are unchanged.

## Design

* **Grouping.** Eligible rules are positive, non-negated `@rx` operators with no
  literal gate, no `multiMatch`, and a representable pattern. They are grouped
  by transform pipeline (`Program::pipelines`), with the rule's target set
  providing eligibility at runtime: a rule is only gated for a candidate the
  engine would have evaluated it against. One database per pipeline means one
  scan serves every residual rule that targets the same transformed value.
* **Pattern ids.** `hs_compile_multi` pattern ids index a per-group
  `pattern_rules` table; each entry is a set of rule ids. At scan time the
  callbacks OR the matching rules into the value's candidate bitmask.
* **Per-value cache.** The engine caches `(value id, pipeline) -> hit bitmask`
  for the phase, next to the literal gate cache. A value is scanned at most
  once per pipeline. Values shorter than 2 KiB keep the per-rule path: regex
  evaluation is already cheap there, and the benchmark showed the scan/setup
  overhead dominated for header-sized values.
* **Load bounds.**
  * at most 256 covered rules (the mask is a 4-word bitset);
  * at most 16 MiB per database and 64 MiB total;
  * a 5 s soft wall-clock compile ceiling, checked between groups (an
    in-flight Vectorscan compile is not interruptible); when exceeded,
    remaining rules stay ungated;
  * compiled sets are cached process-wide (up to 8 distinct rule/pipeline
    mappings), keyed by a hash of the mapping, so repeated engine loads in one
    process reuse the databases.
* **Exact mode.** Patterns are compiled without `HS_FLAG_PREFILTER`, with
  `DOTALL`/`MULTILINE` to mirror the parser's `(?sm)` prefix. The parser's
  normalised pattern is used, and plain `CString` semantics apply.

## Soundness

The contract is one-sided and the fallback is always the existing per-rule
regex:

1. Patterns with constructs whose byte semantics could differ from the Rust
   regex are rejected before compilation: non-ASCII text, Unicode properties,
   `\x{...}`/`\u{...}`, backreferences, `\C`/`\R`/`\X`/`\K`, lookaround,
   atomic/conditional/named groups, recursion, embedded end anchors
   (`$` not last, `\z`/`\Z` not last), and NUL bytes.
2. If a group still fails to compile, the whole group stays on the per-rule
   path.
3. A Vectorscan runtime error is reported as “unknown”, never as “no match”:
   `hs_gate_hit` returns `None` and the regex runs.
4. A rule is annotated with a gate id only when its own expression compiled in
   its own pipeline group.
5. Negated operators are never gated: a miss would flip the rule to a match.
6. The candidate path is disabled for `multiMatch` and for the `TX` fast path
   and the optional `parallel-args` path; those keep their original semantics.

`src/waf/rust_engine/candidates.rs` contains unit tests for the construct
filter, the CRS coverage, and the miss-gates/hit-confirms behaviour. The
2,112-case corpus is the end-to-end gate (see below).

## Platform and fallback

* The accelerated path requires x86-64 with SSSE3/AVX2. `hs_valid_platform()`
  is checked before compiling; on unsupported CPUs (or non-x86 hosts without a
  Vectorscan build) compilation fails and every rule keeps the per-rule path.
* `hyperscan-eval` links `libhs` only when enabled (`build.rs`); default builds
  do not need the library.
* AArch64 Vectorscan exists upstream but is not built by this feature.
* Serialised databases are CPU-feature specific; this implementation compiles
  at startup instead of shipping a cache file.

## Measurements

Host: Intel i5-8400T (6 cores, AVX2), shared with other agents; absolute
numbers move with host load. Release build, 200 reps, `rust-engine-parity
--bench`, `POST /post` with an `application/x-www-form-urlencoded` body of
`data=` followed by `A`s.

| body | rust p50 before | rust p50 after | rust p99 before | rust p99 after |
|---:|---:|---:|---:|---:|
| bodyless | 109.5 µs | 107.6 µs | 162.5 µs | 151.8 µs |
| 1 KiB | 274.2 µs | 269.8 µs | 315.5 µs | 316.1 µs |
| 4 KiB | 632.7 µs | 570.2 µs | 672.5 µs | 632.7 µs |
| 8 KiB | 1046.1 µs | 955.5 µs | 1128.8 µs | 1055.8 µs |

(Before: `main` at `b69ecc2`, same host/run conditions; after: this branch with
`hyperscan-eval`. Re-measure on an idle host before quoting absolute numbers.)

* **Database:** 23 groups, 130 covered rules, 120 deduplicated patterns,
  6 062 KiB total, compile 4.04 s (bounded at 5 s). The first engine load pays
  this; subsequent loads in the same process reuse the cached set.
* **Per request (4 KiB benchmark shape):** 11 database scans (one per
  `(value, pipeline)` pair above the 2 KiB size floor), 29 regex evaluations
  skipped by this pass, 128 skips including literal gates.
* **Raw scan cost:** the existing `hyperscan-bench` reports a 4 KiB block scan
  at ~0.5 µs on this host, so 11 scans are ~5–10 µs of the request; the gain
  comes from the 29 avoided regex evaluations.
* **Targets.** 4 KiB < 400 µs and 8 KiB < 800 µs are **not met** (570 µs and
  956 µs). The pass trims ~10 % at 4 KiB and ~9 % at 8 KiB. The dominant
  residual patterns (large RCE alternations) contain embedded end anchors that
  Vectorscan rejects, and the remaining per-rule cost is candidate resolution
  and transforms, which this pass does not replace. Sub-400 µs would require
  gating those patterns or removing per-candidate work, not a faster matcher.

## Reproduce

```text
nix develop -c cargo test --lib --features rust-engine,native-detect,engine-kernel,hyperscan-eval
nix develop -c cargo run --release --features hyperscan-eval --bin rust-engine-parity -- --bench --reps 200
nix develop -c cargo run --release --features hyperscan-eval --bin rust-engine-parity -- --engine rust
```

`WAF_HS_DEBUG=1` prints per-group compile time, failures and the covered rule
count at load time.
