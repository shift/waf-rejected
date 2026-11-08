# Vectorscan/Hyperscan evaluation for CRS body scanning

**Status:** experimental evaluation, **not enabled by default**.
**Branch:** `research/hyperscan` (worktree `.worktrees/hyperscan`).
**Commit:** `research/hyperscan` head (see `git log`).
**Date:** 2026-11-02.
**Engine:** Coraza `v3.3.3`, OWASP CRS `4.14.0` (vendored bundle), PL1.
**Artifact:** `rules/crs/prefilter.json` (schema v1), unchanged.
**Library:** Vectorscan `5.4.12` from `nixpkgs#vectorscan` (`libhs`).

## TL;DR

* The multi-pattern scanner itself is very fast: **4.7-11.2 GB/s**
  (0.2-5.5 µs) on the full 3 247-pattern CRS literal set, at 1-64 KiB.
* A sound, content-type-aware prefilter decision costs **32 µs at 1 KiB,
  120 µs at 4 KiB, 238 µs at 8 KiB, 486 µs at 16 KiB, 1.89 ms at 64 KiB**
  (p50). That is **sub-millisecond through 16 KiB**, and **4-27× faster than
  the existing Aho-Corasick prefilter**.
* Without content-type dispatch (all four body representations, the same
  over-approximation the current prefilter uses), the floor is **126 µs /
  473 µs / 951 µs / 1.87 ms / 7.43 ms** — sub-millisecond through 8 KiB.
* The hardware matcher is **not** the bottleneck. The Rust extraction /
  transform layer is: a single raw scan is 0.2-5.5 µs, while the sound
  prefilter is 32 µs-1.9 ms. Reusing one extracted view when every transform
  is provably a no-op is what makes the sub-millisecond result possible.
* Only **62 of 113** body-relevant CRS entries (54.9 %) have a sound literal
  gate. The other 51 must stay in Coraza. Removing the gated rules from the
  native sidecar only saves **~1.5×** (52.7 ms vs 74.6 ms at 8 KiB), because
  the ungated rules dominate body cost. The prefilter-only floor is therefore
  **not** a drop-in replacement for Coraza.
* **Verdict:** Vectorscan is a good fit for a non-default prefilter, and it
  meets the sub-millisecond target for typical bodies. It cannot replace
  Coraza/CRS without a plan for the 51 ungated entries. Keep Coraza and the
  Aho-Corasick prefilter as defaults.

## 1. What was built

Two non-default pieces:

* `src/waf/hyperscan.rs` — a small hand-written FFI surface over `libhs`
  (block mode, `HS_FLAG_SINGLEMATCH`, per-pattern `HS_FLAG_CASELESS`,
  first-match termination). Literals are regex-escaped before compilation.
* `src/bin/hyperscan_bench.rs` — loads `rules/crs/prefilter.json`, compiles
  one database per transform chain, and measures the scanner, the sound
  prefilter, the existing Aho-Corasick prefilter, and a corpus parity check.

Feature: `hyperscan-eval` (non-default, implies `crs-prefilter`).
Nix package: `.#hyperscan-bench` (adds `vectorscan` to `buildInputs`).
The dev shell now contains `vectorscan`, so local runs work with
`nix develop -c cargo run ...`.

### 1.1 Build integration options

| Option | Result |
|---|---|
| `hyperscan` / `vectorscan-rs` crates.io binding | **Not used.** The crates were not in the local cargo cache and crates.io is unreachable from this sandbox (`403`). Vendoring a crate was unnecessary: the block-mode C API is small. |
| Hand-written FFI + `build.rs` | **Chosen.** `build.rs` emits `cargo:rustc-link-lib=hs` only when `hyperscan-eval` is enabled, and probes `pkg-config libhs` / `HS_LIB_DIR` as a fallback. Default builds do not need the library. |
| Nix package | **Works.** `nix build .#hyperscan-bench` produces a binary that links `libhs.so.5` from the pinned `vectorscan-5.4.12` store path. |
| Static/vendored build | Not needed here. If a self-contained artifact is required later, `vectorscan` can be built statically or the DBs can be serialized; see risks. |

### 1.2 Licensing and platform

* Vectorscan/Hyperscan is **BSD-3-Clause**. The Nix package metadata records
  `bsd3`; distributions that ship the linked binary must include the license
  notice. No GPL/AGPL obligation is introduced.
* The accelerated path is **x86-64 with SSSE3/AVX2**. This host is an
  i5-8400T (AVX2). `hs_valid_platform()` is checked before compiling; the
  integration must fall back to the Aho-Corasick prefilter on unsupported
  CPUs. AArch64 Vectorscan exists upstream but was not evaluated here.
* Serialized Hyperscan databases are **platform/feature-set specific**. A
  shipped cache must be keyed by CPU features, or the database must be
  compiled at startup (the prototype does the latter).

## 2. Prototype shape and soundness

The artifact supplies, for each gated rule, a disjunctive **required-literal
set**. The soundness contract is one-sided and unchanged:

* If no literal from any gated rule occurs in any representation the rule can
  see, no gated rule can match the body. The body can skip those rules.
* A hit only means "run Coraza"; it is not a detection.

The Hyperscan prototype reproduces the existing prefilter's groups exactly:
the same four extraction variants (`identity`, URL-decode, JSON-unescape,
HTML-entity-decode), the same transform chains, and per-literal case
sensitivity. Two implementation choices make it fast without changing the
contract:

1. **Extract once per representation.** The existing Aho-Corasick path calls
   `apply_pipeline` per group (84 times). The prototype applies the extraction
   once, then reuses the view for every group.
2. **Skip transforms that are provably the identity.** A conservative
   `Transform::is_identity_for` predicate checks trigger bytes (for example
   `%`/`+` for URL decode, `&` for HTML entities, `\` for JS/CSS/escape
   decode, uppercase for `lowercase`, `/*` for `replaceComments`). If a
   transform cannot change the input, the previous buffer is reused. A false
   negative only means the transform runs, which is always safe.

The predicate is tested against the naive transform path on adversarial
samples (`transform_identity_predicate_is_conservative`,
`transform_chain_skip_matches_naive`), and the full scanner is compared with
the existing prefilter on the 51-case corpus: **36/36 hits, zero
Aho-Corasick-hit/Hyperscan-miss, zero Hyperscan-only hits**.

### 2.1 Artifact shape

| metric | value |
|---|---:|
| distinct literals | 3 145 |
| literal patterns compiled (after per-chain dedupe) | 3 247 |
| transform chains | 18 |
| compiled databases | 18 |
| database size | 1 250 KiB |
| compile time (uncontended) | ~235 ms |
| compile time (loaded host) | 1.6 s |
| Aho-Corasick load/build | 55 ms (84 automata) |

Compile time is a startup cost, not a per-request cost. It should be paid
once at boot or hidden behind a lazy first-use path.

## 3. Measurements

Host: Intel i5-8400T (6 cores, 1.7/3.3 GHz), shared with other agents. The
run below had a load average around 10; absolute numbers move with host load,
ratios are the useful part. Release build, 50 reps, 5 warmups, clean
synthetic body (`zq` repeated, no literal hit) so every group must scan.

### 3.1 Clean body, p50 / p95

| body | hs-raw MB/s | hs-raw p50 | hs-fast MB/s | hs-fast p50 | hs-fast p95 | hs-naive MB/s | hs-naive p50 | hs-all MB/s | hs-all p50 | AC MB/s | AC p50 |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 KiB | 4 741 | 0.2 µs | 30.6 | 31.8 µs | 32.5 µs | 6.0 | 157.5 µs | 7.7 | 126.2 µs | 1.1 | 847.0 µs |
| 4 KiB | 8 294 | 0.5 µs | 32.3 | 120.5 µs | 124.1 µs | 6.3 | 611.2 µs | 8.1 | 473.0 µs | 1.2 | 3 308.1 µs |
| 8 KiB | 9 778 | 0.8 µs | 32.2 | 238.3 µs | 274.6 µs | 6.4 | 1 204.6 µs | 8.1 | 950.8 µs | 1.2 | 6 622.3 µs |
| 16 KiB | 10 565 | 1.5 µs | 31.5 | 486.3 µs | 525.7 µs | 6.4 | 2 401.7 µs | 8.3 | 1 870.8 µs | 1.2 | 13 110.7 µs |
| 64 KiB | 11 223 | 5.5 µs | 32.8 | 1 885.3 µs | 2 020.3 µs | 6.5 | 9 553.3 µs | 8.4 | 7 426.9 µs | 1.2 | 52 120.2 µs |

Definitions:

* `hs-raw`: all literals in one database, one scan of the raw body. This is
  the hardware floor, **not** a sound prefilter (it ignores transforms and
  extraction variants).
* `hs-fast`: sound prefilter, content-type-aware extraction (one of four),
  shared extraction, no-op transform skip. This is the achievable floor when
  the body processor is known.
* `hs-naive`: same content-type extraction, but extraction and transforms are
  re-run per group, matching the existing Aho-Corasick structure. It isolates
  the matcher difference from the pipeline optimisation.
* `hs-all`: fast mode over all four extraction variants. This is the sound
  over-approximation when the content type is unknown, and is directly
  comparable to the current prefilter.
* `AC`: the existing Aho-Corasick prefilter (84 automata, four extractions).

The AC p50 here (847 µs at 1 KiB, 6.6 ms at 8 KiB) is higher than the
`crs-prefilter.md` numbers because that report ran on a less loaded host; the
AC/Hyperscan ratio is stable at roughly **4-27×**.

### 3.2 Attack body, first-hit path

| body | hs-fast p50 | hs-all p50 | AC p50 |
|---:|---:|---:|---:|
| 1 KiB | 1.6 µs | 0.2 µs | 7.0 µs |
| 4 KiB | 5.7 µs | 0.2 µs | 27.1 µs |
| 8 KiB | 11.1 µs | 0.2 µs | 53.6 µs |
| 16 KiB | 22.0 µs | 0.3 µs | 108.7 µs |
| 64 KiB | 86.6 µs | 1.1 µs | 427.2 µs |

Attack bodies terminate on the first matching pattern. This is the common
case in production and is already far below a millisecond.

### 3.3 End-to-end prefilter-only decision floor

The p50 above **is** scan + boolean decision, excluding Coraza. At 8 KiB the
sound content-type-aware decision is **238 µs**, versus a measured full-CRS
sidecar p50 of **74.6 ms** (≈313×). At 16 KiB it is **486 µs** versus
**149.2 ms** (≈307×). That is the prize, but see §4: it is only valid for the
gated rules.

## 4. Rule coverage and what must remain in Coraza

Artifact coverage at PL1 (unchanged from `crs-prefilter.md`):

| family | body-relevant entries | gated | ungated |
|---|---:|---:|---:|
| 920 protocol enforcement | 8 | 1 | 7 |
| 921 protocol attack | 6 | 3 | 3 |
| 922 multipart attack | 4 | 2 | 2 |
| 930 LFI | 3 | 1 | 2 |
| 931 RFI | 3 | 3 | 0 |
| 932 RCE | 16 | 3 | 13 |
| 933 PHP | 12 | 7 | 5 |
| 934 generic | 6 | 4 | 2 |
| 941 XSS | 25 | 19 | 6 |
| 942 SQLi | 20 | 10 | 10 |
| 943 session fixation | 3 | 3 | 0 |
| 944 Java | 7 | 6 | 1 |
| **total** | **113** | **62 (54.9 %)** | **51** |

`all_body_rules_gated` is **false**, so the body-withholding fast path is not
available on stock CRS. The 51 ungated entries are dominated by:

* `@detectSQLi` (942100) and `@detectXSS` (941100): libinjection-style
  operators with no literal requirement;
* the generated obfuscation-tolerant 932 regexes
  (932250/932260/932230/932235), where every command letter is followed by
  optional junk and no contiguous literal is guaranteed;
* 942 alternations with 2-character SQL keywords/functions
  (942151/942170/942190/942230/942290/942320/942500/942540/942550);
* short tag/attribute XSS branches (941160/941170/941210/941220/941310/941360);
* size/validation operators (920360/920370/920380 `@gt`, 920250/920270
  UTF-8/byte-range validation, 922100/922130);
* `t:base64Decode` chains (934100/934160) and 930 traversal regexes made of
  character classes (930100/930110).

This matters for the business case. The native sidecar can remove the gated
rules from a transaction; measured on this host, that saves only **~1.5×**
(1 KiB: 6.78 ms vs 10.10 ms; 8 KiB: 52.71 ms vs 74.57 ms; 60 KiB: 352.55 ms
vs 571.38 ms) because the ungated rules carry most of the body cost. A
prefilter-only decision reaches 238 µs at 8 KiB, but it is not sound unless
the 51 ungated entries are handled elsewhere.

## 5. Risks and open questions

1. **Platform.** x86-64/AVX2 only for this evaluation. Runtime
   `hs_valid_platform()` check and an Aho-Corasick fallback are mandatory.
2. **Startup cost.** 18 databases / 3 247 patterns / 1.25 MiB / ~235 ms
   compile. Serialize databases per CPU feature set, or compile lazily, before
   enabling this on a latency-sensitive boot path. The prototype does not
   implement serialization yet.
3. **Memory.** One scratch region per database (18). Scratch size was not
   measured; pool or share carefully under concurrency. `hs_scan` with a
   single scratch is not thread-safe.
4. **Transform fidelity.** The prefilter's soundness depends on the Rust
   transforms matching Coraza. The new no-op predicate was added in this
   branch; it is conservative and tested, but every future transform change
   must keep the identity test conservative.
5. **Build/licensing.** BSD-3-Clause notice must ship. The Nix build is
   reproducible via `flake.lock`; the raw FFI avoids a crates.io dependency
   but is an ABI surface we own.
6. **Detection parity.** The 51-case corpus shows 36/36 hits and no
   Aho-Corasick/Hyperscan disagreement. It is not a proof of parity on the
   full regression corpus; the existing `crs-prefilter-bench` parity harness
   should be extended to the Hyperscan path before any non-default enablement.

## 6. Recommendation

* **Do not replace Coraza and do not change WAF defaults.** Keep
  `crs-prefilter` and the Aho-Corasick prefilter as they are.
* Adopt Vectorscan as the matcher for a **future non-default prefilter**:
  * content-type-aware extraction (one representation) + shared extraction +
    conservative no-op transform skip gets sub-millisecond through 16 KiB;
  * all-four-representation mode is the safe fallback when the body processor
    is unknown, and is sub-millisecond through 8 KiB.
* The next measurement should be **per-rule removal** (`RemoveRuleByID`) with
  the Hyperscan gated set, not body withholding. The sidecar already exposes
  the removal path; the 1.5× result is the current upper bound for a sound
  integration.
* To move beyond 1.5×, port the cheap ungated rules to Rust (size/validation,
  UTF-8/byte-range) and evaluate direct Hyperscan compilation of the 932
  generated regexes. Keep `@detectSQLi`/`@detectXSS` in Coraza: they are not
  literal-gated and are not Hyperscan patterns.
* Keep the Aho-Corasick prefilter as the portable fallback for non-x86 hosts
  and as the reference implementation for parity tests.

## 7. Reproduce

```sh
# Local build and run (Nix dev shell provides libhs):
nix develop -c cargo run --release --no-default-features \
  --features hyperscan-eval --bin hyperscan-bench -- --reps 50

# Reproducible package:
nix build .#hyperscan-bench
./result/bin/hyperscan-bench --reps 50 --json-out /tmp/hyperscan.json

# Checks used for this branch:
nix develop -c cargo fmt -- --check
nix develop -c cargo clippy --release --no-default-features \
  --features hyperscan-eval --bin hyperscan-bench -- -D warnings \
  -A unused-imports -A unused-mut
nix develop -c cargo test --release --no-default-features \
  --features crs-prefilter --lib waf::prefilter::tests::transform_
```
