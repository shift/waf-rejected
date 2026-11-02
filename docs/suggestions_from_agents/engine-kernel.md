# Native Rust engine kernel: execution model and prototype measurements

**Status:** experimental prototype, non-default feature `engine-kernel`.
**Branch:** `perf/engine-kernel` (worktree `.worktrees/engine-kernel`).
**Scope:** demonstrate the execution model for a future Coraza replacement.
Coraza remains the default backend; no production defaults, rules or policy
were changed.

## Why this prototype exists

The native Coraza sidecar is byte-linear at roughly **7.5 µs per inspected
byte** (1 KiB 7.9 ms, 4 KiB 32.7 ms, 8 KiB 61 ms), and the WASI reactor adds a
~5.2× execution penalty. The dominant cost is hundreds of CRS regex operators
applied to every argument and to the raw body. The kernel prototype tests a
different execution model: parse once, decode once per value, and evaluate a
compiled DAG of cheap predicates, shared literal automata and precompiled DFAs.

## Execution model

### 1. Parse once into compact, zero-copy spans

`state::RequestInput` borrows the method, path, query, headers and body. The
arena parses them once into `ValueRef` records (`Source`, offset, length, kind,
header kind). No value is copied unless a parser must decode it:

- query and `application/x-www-form-urlencoded` arguments are URL-decoded once
  into the arena (ModSecurity decodes ARGS before rule transforms);
- cookies are URL-decoded once;
- JSON string tokens are JS-unescaped into the arena;
- XML attribute values and text nodes are entity-decoded into the arena, while
  element names are deliberately excluded (Coraza's `XML:/*` does not expose
  them and the corpus has negative cases that depend on that);
- the raw path is kept for `REQUEST_URI_RAW`, and a decoded copy is kept for
  `REQUEST_FILENAME`.

### 2. Transform cache per value, not per rule

Every distinct transform pipeline in the rule set gets an id. The arena caches
`(value, pipeline) -> bytes` using a generation counter, so a cache reset is
O(1) and repeated requests do not allocate. Two rules that need
`urlDecodeUni + lowercase` share one decode. The cache is backed by reusable
`Vec<u8>` buffers (`buf`, `decoded`, two transform scratch buffers), which is
why the steady-state allocation count is zero.

### 3. Compiled matcher DAG

Rules are compiled once into four ordered layers per phase:

1. **Request predicates** — method enum, content-type enum, header presence.
2. **Value predicates** — length, prefix/suffix, byte-range/charset, enum,
   contains-byte. These are direct comparisons.
3. **Literal groups** — one Aho-Corasick automaton per
   `(phase, target mask, pipeline, case)`, over the CRS data files
   (`scanners-user-agents.data`, `unix-shell.data`, `java-classes.data`).
4. **Regex groups** — one precompiled `regex-automata` dense DFA per
   `(phase, target mask, pipeline)`. Patterns too large for a 4 MiB DFA fall
   back to a `regex::bytes` linear automaton per pattern. No regex is compiled
   at request time.

Groups are sorted by `(phase, target mask, pipeline, first rule id)`, so the
evaluation order is deterministic. Cheap disqualifiers always run before
literal and regex scans.

### 4. Sound literal prefilter

`rules/crs/prefilter.json` is embedded and filtered to the rules this kernel
implements. For gated regex rules, the kernel scans every parsed value with the
prefilter's Aho-Corasick automata and records a 64-bit gate mask. A regex group
is skipped when every rule in it is gated and no gate hit occurred. This is the
same one-sided proof used by the `crs-prefilter` feature: a miss means no
literal of the rule is present in any representation, so the regex cannot
match.

### 5. Anomaly scoring and early exit

Each match adds its CRS score (critical = 5) to a running total. Phase 1 runs
first; if the threshold is reached the kernel returns immediately and phase 2
is skipped. Phase 2 does the same. `Decision::Block` carries the rule id, phase
and score and never allocates a reason string.

## Rule subset

The prototype implements 21 CRS 4.14.0 rules:

| Family | Rules |
| --- | --- |
| Protocol / method | 911100, 920270, 920420 |
| Scanner | 913100 |
| LFI | 930100, 930110 |
| RCE (shell / Windows / PHP / Node) | 932140, 932160, 933160, 933180, 934100, 934160 |
| XSS | 941110, 941130 |
| SQLi | 942140, 942190, 942360, 942550 |
| Java | 944100, 944120, 944130 |

Deliberately absent: `@detectSQLi`, `@detectXSS`, libinjection, multipart and
full XML body processors, response-phase rules, and the long tail of CRS
operators. The kernel is therefore a **subset prototype**, not a drop-in
replacement.

## Corpus soundness

The harness runs the pinned `tests/corpus/crs/corpus.json` (2,112 cases) through
the kernel. A case is in the **covered subset** when every expected rule id is
implemented, the case is not multipart, and the case is a positive or negative
test for at least one implemented rule.

| Metric | Value |
| --- | ---: |
| Corpus cases | 2,112 |
| Covered | 1,077 (51.0%) |
| Covered block cases | 1,002 |
| Covered allow cases | 75 |
| Passed | 1,075 |
| **False negatives** | **0** |
| False positives | 2 |
| Uncovered | 1,035 |

Covered cases by rule: 944130 418, 932140 152, 944120 88, 942190 43, 933160
36, 942550 36, 933180 35, 934160 31, 934100 29, 942360 22, 941130 19, 920420
17, 942140 17, 944100 14, 932160 12, 941110 9, 930110 6, 913100 5, 920270 5,
911100 4, 930100 4.

The two false positives are covered **negative** cases where a different
implemented rule fires: `crs-933160-31` (blocked by 934100) and
`crs-942360-31` (blocked by 942190). This is the same class of ambiguity the
existing corpus report documents: the corpus records the target rule, not the
complete set of rules that fire, and the Coraza baseline itself has 91 such
false positives on negative cases. The acceptance gate for this prototype is
**zero false negatives on the covered subset**, which holds.

Reference: the existing Coraza corpus harness recorded 2,016/2,112 passed,
1,695/1,700 positives detected (5 known false negatives, all in 921250/944150),
and 2,112/2,112 wasm/native parity. The kernel's covered subset contains none
of those five known Coraza misses.

## Benchmark

Measured with the `engine-kernel-bench` binary on the same host class used by
the Coraza reports (Intel i5-8400T, Linux, release build). The host is shared
with other agents, so absolute numbers move; the ratio to the documented
Coraza baselines is the useful figure.

| case | request bytes | p50 µs | p95 µs | p99 µs | MB/s (CPU) | alloc/req |
|---|---:|---:|---:|---:|---:|---:|
| bodyless GET | 102 | 12.36 | 42.24 | 56.98 | 4.8 | 0.00 |
| 1 KiB form | 1,131 | 189.69 | 693.77 | 718.95 | 3.8 | 1.00 |
| 4 KiB form | 4,203 | 741.28 | 2,463.14 | 2,495.87 | 3.6 | 1.00 |
| 8 KiB form | 8,299 | 1,740.08 | 4,820.37 | 4,851.57 | 3.4 | 1.00 |

The release binary was built with `CARGO_PROFILE_RELEASE_LTO=false` to keep
the shared-host build bounded; the default release profile enables LTO, so
these numbers are conservative. These are **process CPU-time** samples, not
wall-clock: the host was at load average 38 with CPU 2 throttled to 1.2 GHz
while other agents compiled, so wall-clock numbers were unusable. CPU time still includes cache/frequency
effects, but not scheduler wait. The 4 KiB target (<1 ms p50) is met at
**741 µs**; the bodyless target (<0.2 ms p50) is met at **12 µs**. The 8 KiB
case is outside the stated target and is 1.7× over the 1 ms line on this
throttled host.

Coraza comparison from the same table:

| case | Coraza native p50 | Coraza wasm p50 | kernel p50 | vs native | vs wasm |
|---|---:|---:|---:|---:|---:|
| bodyless GET | 0.55 ms | 2.65 ms | 12.36 µs | 44× | 214× |
| 1 KiB form | 7.92 ms | 40.8 ms | 189.69 µs | 42× | 215× |
| 4 KiB form | 32.66 ms | 165.6 ms (interp.) | 741.28 µs | 44× | 223× |
| 8 KiB form | 60.94 ms | 333.5 ms | 1,740.08 µs | 35× | 192× |

Coraza reference rows are the documented p50 CPU numbers from
`docs/suggestions_from_agents/crs-performance.md` (native) and
`docs/suggestions_from_agents/coraza-body-performance.md` (wasm; 4 KiB is
linearly interpolated between 1 KiB and 8 KiB). The native sidecar is not built
in this environment (no Go toolchain in the sandbox), so it is a reference, not
a same-run comparison.

A same-run wasm measurement with the existing `coraza_backend_bench` binary
under the same saturated host reported 642 ms (1 KiB), 2,005 ms (4 KiB) and
5,278 ms (8 KiB) p50. Those are not comparable to the documented steady-state
numbers, but they confirm that the wasm path remains orders of magnitude
slower even under identical contention.

### Allocation profile

- Steady state: **0 allocations per bodyless request** and **1 allocation per
  body request** after warm-up. The arena reuses `values`, `cache`, `decoded`,
  `buf` and the transform scratch buffers; the generation counter avoids
  clearing the cache. The single body-case allocation does not scale with the
  number of rules or literals; it is arena capacity bookkeeping, not a
  per-rule allocation.
- First request: arena vectors grow to the request's value/pipeline count.
- Engine construction: compiles all literal automata, DFAs and the prefilter
  once. This is outside the request path.

### Gap to sub-millisecond

- Bodyless: p50 12.4 µs, p99 57 µs — **81× headroom** under 1 ms, **16×**
  under the 0.2 ms bodyless target.
- 1 KiB: p50 190 µs, p99 719 µs — **5.3× headroom**.
- 4 KiB: p50 741 µs, p99 2.50 ms — **1.35× headroom** at p50; p99 is over
  budget because of host contention and the two large regex families still
  scanning the body.
- 8 KiB: p50 1.74 ms — 1.7× over the 1 ms line (outside the stated target).

## What the full engine must add

1. **SecLang front end** — parse/compile `SecRule`, chains, variables,
   operators, transforms, `setvar`, `skipAfter`, `ctl`, includes and
   paranoia-level gating. The prototype's rule table is hand-written.
2. **Full operator set** — libinjection (`@detectSQLi`, `@detectXSS`),
   `@pmFromFile`, `@validateByteRange`, `@within`, `@eq`, `@gt`, `@rx`
   with PCRE-compatible semantics, `@unconditionalMatch`, and the rest.
3. **Full body processors** — multipart (including file parts), JSON with
   nested paths, XML with namespaces/attributes/text, gRPC/protobuf and
   GraphQL-aware withholding, plus decompression and encoding limits.
4. **Response phase and audit logging** — response headers/body rules,
   anomaly score variables, matched-variable capture, deterministic audit
   records, and the existing security-event exporters.
5. **Rule lifecycle** — configuration reload without dropping requests,
   compiled-artifact caching, deterministic ids, and the per-rule gating ABI
   already used by the sidecar/reactor.
6. **Parity harness** — run the full pinned corpus and a randomized
   differential test against both Coraza backends, with matched rule ids, not
   just block/allow.
7. **Performance hardening** — serialize/precompile DFAs at build time,
   multi-pattern regex grouping across pipelines, SIMD literal scans for the
   hot `ARGS` path, per-worker arenas with bounded memory, and backpressure
   when the arena would exceed a configured cap.
8. **Security review** — the prototype changes transform/target semantics in a
   few places to avoid known double-decoding gaps (documented in the rule
   table). Those deviations must be reviewed and proven before any production
   use.

## Reproduce

```sh
# Corpus soundness (exit 1 on a covered false negative)
nix develop -c cargo run --no-default-features --features engine-kernel \
    --bin engine-kernel-corpus

# Benchmark
nix develop -c cargo run --release --no-default-features \
    --features engine-kernel --bin engine-kernel-bench

# Verification
nix develop -c cargo fmt -- --check
nix develop -c cargo test --lib --features engine-kernel
nix develop -c cargo clippy --lib --features engine-kernel -- --deny warnings
```
