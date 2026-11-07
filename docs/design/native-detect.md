# Native `@detectSQLi` / `@detectXSS`: parity, cost and integration

> **Historical research report.** This records the state of the branch/commit
> below. `native-detect` is now pulled in by the default `rust-engine` feature;
> statements about Coraza staying the default request path describe the
> research baseline. For current behaviour see
> [engine selection](../user-guide/engine-selection.md).

**Status:** experimental implementation, **not enabled by default**.
**Branch:** `feat/native-detect` (worktree `.worktrees/native-detect`), based on
`main` @ `8b6a4ec`.
**Date:** 2026-11-02
**Engine:** Coraza `v3.3.3` / `libinjection-go v0.2.2`, OWASP CRS `4.14.0`, PL1.
**Feature:** `native-detect` (non-default, no new dependencies).

## TL;DR

`@detectSQLi` and `@detectXSS` are the two body-relevant CRS operators that the
required-literal prefilter can **never** gate: libinjection has no mandatory
literal, so every request body has to be shipped to Coraza. This change removes
that dependency with a pure-Rust port of the exact library Coraza calls.

* `detect_sqli` / `detect_xss` are byte-oriented, allocation-free, single-pass
  ports of `libinjection-go` v0.2.2. Because Coraza implements `@detectSQLi` as
  `libinjection.IsSQLi` and `@detectXSS` as `libinjection.IsXSS`, parity is by
  construction rather than by approximation.
* Parity is pinned by a committed oracle: **11,039 values** (every request value
  from the 2,112-case CRS corpus, plus generated encodings/whitespace/comment/
  case/Unicode variants and deterministic mutants), **0 false negatives and
  0 false positives** for both operators.
* p50 for both operators together on an 8 KiB body is **163 µs** (48 MB/s) for
  benign text and **2.4 µs** for an attack body that hits early — roughly
  200-1000× below a Coraza round trip (35-78 ms on the native sidecar,
  ~333 ms on the wasm reactor for 8 KiB), with **zero heap allocations**.
* Coraza stays the default request path. The operators are exposed through
  `NativeOperator` / `evaluate_operator` for the native engine and prefilter.

## 1. Why these two operators

`rules/crs/PREFILTER_SUMMARY.md` reports 51 of 113 body-relevant CRS entries as
ungated at PL1. The dominant ungated members are:

| operator | entries | can be gated? |
|---|---:|---|
| `@rx` | 44 | partly — short/alternation-only patterns (932 obfuscation rules) |
| `@detectSQLi` | 1 | never: no required literal |
| `@gt` / `@eq` | 4 | never: numeric/validation |
| `@validateByteRange` / `@validateUtf8Encoding` | 2 | never |

Because the prefilter's body-withholding mode requires *all* body-relevant rules
to be gated, those entries disable the fast path for the whole rule set. 942100
(`@detectSQLi`) alone forces every body through Coraza. A native implementation
of the two libinjection operators removes the largest single blocker; the 932
regex family and the size/validation operators are separate work.

## 2. Implementation choice

**Pure Rust port of `libinjection-go` v0.2.2, not a C binding.**

* `libinjection` (C) is not vendored in this repository and the build sandbox
  has no network access, so a `cc`-built binding could not be made
  reproducible here. Adding a C toolchain dependency would also break the
  `wasm32-wasip1` target and the "every command starts with nix" workflow.
* Coraza v3.3.3 does **not** use the C library: it depends on
  `github.com/corazawaf/libinjection-go v0.2.2` (already vendored under
  `native/coraza-sidecar/vendor/`). Porting that Go source is both simpler and
  more accurate than binding the C original, because it is byte-for-byte what
  Coraza executes — including the Go port's quirks.
* No `unsafe`, no build script, no new crate dependency. The tables are static
  sorted arrays searched with `binary_search_by`, so lookups do not allocate and
  do not need a `HashMap`.

Layout:

```
src/waf/native_detect/
├── mod.rs                     public API + oracle replay test
├── sqli.rs                    tokenizer, folding, fingerprint blacklist/whitelist
├── sqli_data.rs               generated: 985 keywords, 8,367 fingerprints
├── xss.rs                     HTML5 tokenizer + black lists
├── xss_data.rs                generated: black tags, event names, attributes
└── LICENSE.libinjection.txt   retained BSD-3-Clause notice
```

Hot-path properties:

* SQLi: at most four tokenizer passes (as-is, MySQL reparse, single-quote and
  double-quote modes), a fixed 8-token vector, 32-byte inline token values,
  binary search over the static tables, **zero heap allocations**.
* XSS: five HTML5 tokenizer passes (one per initial state), fixed-size stack
  state, entity decoding for URL attributes streams through a 16-byte ring
  buffer, **zero heap allocations**.
* Work is linear in the value length and the loops all advance by at least one
  byte. The only super-linear path is upstream's quote-escape check, which
  searches for a repeated suffix (quadratic only for adversarial inputs made of
  a repeating quoted tail). The engine's body-size limit bounds it.

### API

```rust
use waf_ingress::waf::native_detect::{detect_sqli, detect_xss, NativeOperator};

assert!(detect_sqli("1' OR '1'='1"));
assert!(detect_xss("<script>alert(1)</script>"));

// Coraza operator names map directly; unknown operators return None so the
// caller can fall back to Coraza.
let op = NativeOperator::from_coraza_name("detectSQLi").unwrap();
assert!(op.evaluate("1 UNION SELECT 1"));
assert_eq!(NativeOperator::from_coraza_name("rx"), None);
```

`detect_sqli_fingerprint` returns the token-category fingerprint Coraza captures
on a hit (useful for `capture`/logging parity).

## 3. Parity validation

### Method

`native/coraza-sidecar/cmd/libinjection-oracle` is a Go tool in the existing
sidecar module (vendored dependencies, no network). It:

1. loads `tests/corpus/crs/corpus.json` and emits every request value (method,
   URI, header names and values, body) — i.e. all 2,112 cases;
2. generates variants of SQLi, XSS and benign seeds: upper/lower/alternating
   case, tab and double-space whitespace, `/**/` comment injection, URL
   encoding, HTML entity encoding, full-width Unicode, zero-width space,
   doubled and backslash-escaped quotes, NUL substitution, JSON/form wrapping,
   truncation;
3. generates deterministic byte mutants (seeded RNG: replace/insert/delete/
   duplicate over an operator-rich alphabet) to exercise tokenizer edges;
4. records `libinjection.IsSQLi` and `libinjection.IsXSS` for every unique
   value and writes `tests/corpus/native-detect/oracle.json`.

The Rust test `native_detect::tests::parity_with_coraza_on_pinned_oracle`
replays that file. The oracle is committed, so the check needs no Go toolchain.

### Result

| corpus slice | values | SQLi positives | XSS positives | SQLi FN/FP | XSS FN/FP |
|---|---:|---:|---:|---:|---:|
| CRS corpus (all 2,112 cases' request values) | 2,183 | 14 | 183 | 0 / 0 | 0 / 0 |
| generated variants (encodings, case, whitespace, comments, Unicode) | 2,688 | 672 | 412 | 0 / 0 | 0 / 0 |
| deterministic mutants (byte edits) | 6,168 | 859 | 952 | 0 / 0 | 0 / 0 |
| **total** | **11,039** | **1,545** | **1,547** | **0 / 0** | **0 / 0** |

Both directions are checked: a value Coraza flags must be flagged here (false
negative) and a value Coraza allows must not be flagged (false positive). The
replay takes 0.65 s in a debug build.

### Corpus harness (whole-request decisions)

The repository's `crs_corpus` harness was run through the native Coraza sidecar
on all 2,112 cases to confirm the change is additive (Coraza is untouched):

```
sqli:     255/262 passed, detection=100.0% (219/219), FN=0, FP=7
xss:      137/147 passed, detection=100.0% (132/132), FN=0, FP=10
upstream: 2016/2112 passed, detection=99.7% (1695/1700), FN=5, FP=91
```

The `sqli`/`xss` families have **0 false negatives**; the false positives are
expected-allow edge cases (920 protocol/encoding cases) from the pre-existing
sidecar baseline, not this change. The 5 `upstream` false negatives are likewise
pre-existing whole-rule gaps.

### What this does and does not prove

* It proves **operator-level** parity: for the same input string, our
  `detect_sqli`/`detect_xss` return the same boolean as Coraza's
  `@detectSQLi`/`@detectXSS`.
* It does not prove whole-rule parity for the 942/941 families: CRS also applies
  transforms before the operator and chains rules. Those transforms stay in
  Coraza; when the native engine calls the operator it must feed it the same
  transformed value Coraza would.
* The CRS corpus values are mostly already URL-decoded by the time an operator
  sees them; encoded variants in the generated set cover the operator's
  behaviour on raw encoded text, not the transform pipeline.

## 4. Performance

Machine: Intel i5-8400T (6 cores), Linux, release build, `native_detect_bench`.
`benign` is prose/form text, `attack` repeats
`1' OR '1'='1 <script>alert(1)</script> ...` so both detectors hit early.
Each row evaluates **both** operators on the whole body.

| body | input | p50 | p99 | throughput | alloc/op |
|---:|---|---:|---:|---:|---:|
| 1 KiB | benign | 18.11 µs | 2.95 ms | 53.9 MB/s | 0 |
| 1 KiB | attack | 1.90 µs | 2.65 µs | 514 MB/s | 0 |
| 4 KiB | benign | 66.08 µs | 8.11 ms | 59.1 MB/s | 0 |
| 4 KiB | attack | 2.01 µs | 2.61 µs | 1,944 MB/s | 0 |
| 8 KiB | benign | 162.94 µs | 6.41 ms | 47.9 MB/s | 0 |
| 8 KiB | attack | 2.44 µs | 8.53 µs | 3,199 MB/s | 0 |

The p99 figures are dominated by CPU contention on the benchmark host (other
builds were running); p50 is stable across runs. The benign path is linear and
dominated by keyword binary search in the SQLi tokenizer; the attack path stops
after five folded tokens.

For reference, the same bodies through `libinjection-go` (i.e. the code Coraza
executes for these operators), measured with the oracle's `-bench` mode on the
same machine:

| body | input | p50 (Go) | p50 (native) | speedup |
|---:|---|---:|---:|---:|
| 1 KiB | benign | 53.3 µs | 18.11 µs | 2.9× |
| 4 KiB | benign | 206.3 µs | 66.08 µs | 3.1× |
| 8 KiB | benign | 488.0 µs | 162.94 µs | 3.0× |
| 8 KiB | attack | 2.1 µs | 2.44 µs | ~1× |

The Go numbers include per-word `strings.ToUpper` allocations and GC, which the
Rust port avoids (0 allocations per evaluation).

Reference points for "invoking Coraza" from existing measurements in this
repository (same machine class):

| path | body | p50 |
|---|---:|---:|
| native sidecar, full CRS PL1 | 1 KiB | 35.11 ms |
| native sidecar, full CRS PL1 | 4 KiB | 39.43 ms |
| native sidecar, full CRS PL1 | 8 KiB | 78.37 ms |
| wasm reactor, full CRS PL1 | 8 KiB | ~333 ms (GC-quiet) |

The operator is not the dominant cost of a Coraza request; the point is that it
can now be evaluated **without** a Coraza request at all, which is what unblocks
gating for 942100 and the 941 family.

## 5. Licensing and build

* Logic and tables derive from `libinjection-go` v0.2.2 (BSD-3-Clause,
  Copyright (c) 2022-Present, Coraza), itself a port of libinjection
  (BSD-3-Clause, Nick Galbreath). The notice is retained verbatim in
  `src/waf/native_detect/LICENSE.libinjection.txt` and referenced from the
  module headers; BSD-3-Clause requires retaining the copyright notice and
  disclaimer for source redistribution, which this satisfies.
* `sqli_data.rs` and `xss_data.rs` are generated data. Regenerate both with
  `scripts/gen-native-detect-data.sh`, which reads only the vendored Go source,
  so the result is reproducible offline.
* No new dependencies, no `build.rs`, no C toolchain, no `unsafe`. The feature
  is additive: `cargo build` without `native-detect` is unchanged.

## 6. Residual gaps and semantic differences

1. **Unicode case folding in keyword lookup.** Upstream uses Go's
   `strings.ToUpper` (Unicode aware); the port folds ASCII only. Every table key
   is ASCII, so this can only differ for a non-ASCII code point that Unicode
   maps onto an ASCII letter (e.g. `ſ` → `S`). No corpus or variant case hits
   it; fixing it would require Unicode tables and allocation on the hot path.
2. **Panics become decisions.** A few upstream index expressions can panic on
   truncated input (e.g. the `not_whitelist` two-token branch reads
   `input[len+1]`, and the `%` bogus-comment path can produce a token longer
   than the remainder). The port clamps/returns instead of panicking, so it can
   return a decision where Coraza would abort the transaction. This is a
   robustness improvement, not a detection change on non-crashing inputs.
3. **Token values are copied, not borrowed.** `merge` needs a temporary `"A B"`
   string, so token values live in a 32-byte inline buffer. Semantics are
   identical (values are already truncated to 31 bytes upstream).
4. **`detectSQLi`/`detectXSS` only.** The 44 ungated `@rx` entries (mostly the
   932 obfuscation family) and the size/validation operators still require
   Coraza; the prefilter fast path stays unavailable until they are covered too.
5. **No transform pipeline.** The operator expects the value Coraza would feed
   it. If the native engine applies its own transforms, they must match the CRS
   chain exactly or decisions will diverge.
6. **Oracle provenance.** The oracle pins `libinjection-go v0.2.2`. A Coraza
   upgrade that bumps libinjection requires regenerating the oracle and
   re-running the test; the Rust tables must be regenerated from the new Go
   source as well.

## 7. Reproduce

```bash
# 1. Regenerate the data tables from the vendored Go source, then format them.
./scripts/gen-native-detect-data.sh
nix develop -c cargo fmt

# 2. Regenerate the parity oracle (needs the Go toolchain from the devshell).
cd native/coraza-sidecar
nix develop -c env GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
    go run -mod=vendor ./cmd/libinjection-oracle \
    -corpus ../../tests/corpus/crs/corpus.json \
    -out ../../tests/corpus/native-detect/oracle.json
cd ../..

# 3. Replay parity and unit tests.
nix develop -c cargo test --features native-detect --lib native_detect

# 4. Latency and allocation measurement (no default features: the operators do
#    not need the wasm reactor).
nix develop -c cargo run --release --no-default-features --features native-detect \
    --bin native_detect_bench

# 5. Coraza operator cost for comparison.
cd native/coraza-sidecar
nix develop -c env GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
    go run -mod=vendor ./cmd/libinjection-oracle -bench
```

## 8. Next steps (not implemented here)

1. Teach the prefilter that 942100/941100-family entries are *natively
   evaluable*, remove them from the ungated set, and evaluate them in the host
   instead of sending the body to Coraza.
2. Cover the 932 `@rx` family with a linear-time automaton so the body fast path
   can actually open on stock CRS.
3. Run the full 2,112-case harness end-to-end with the operators wired into the
   native engine and compare whole-request decisions, not just operator values.
