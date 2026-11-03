# Native engine hot loop: profile, gates and allocation budget

**Branch:** `perf/engine-hotloop`
**Engine:** `src/waf/rust_engine` (non-default `rust-engine` feature)
**Baseline:** `fdb3ca7`
**Status:** profiling and allocation work landed; the 4 KiB/8 KiB latency
targets are **not met** (see [Results](#results) and [Blockers](#blockers)).

## What changed

1. **Per-rule mandatory-literal gates.** `rules/crs/prefilter.json` is compiled
   once at load time into Aho-Corasick groups keyed by
   `(transform pipeline, case sensitivity)`. A candidate value is transformed
   once per group, cached by value id, and scanned before the rule's own
   transform pipeline runs. A rule whose required literals are absent is
   skipped without transforming or running the regex. Ungated rules (negated
   operators, libinjection, patterns without a required literal) are never
   gated. See `src/waf/rust_engine/gate.rs`.
2. **Zero-allocation transforms.** `Transform::apply_into` writes into a
   caller-owned buffer; the engine ping-pongs two reused buffers per pipeline.
   The transform cache is an open-addressed generational table, so steady-state
   transform work performs no allocation.
3. **Borrowed TX / MATCHED_VARS evaluation.** Single-target `TX:name` and
   `MATCHED_VARS` rules are evaluated in place instead of cloning each value
   into a `Candidate`. TX storage recycles `(name, value)` slots across
   requests through the thread-local scratch, and static TX names are
   lowercased at parse time.
4. **Operator macro buffers.** `%{...}` expansion for `@contains`,
   `@beginsWith`, numeric comparisons and friends writes into one reused
   buffer. Regex captures reuse one `CaptureLocations` sized from the largest
   pattern instead of allocating per evaluation.
5. **Match bookkeeping gating.** `MATCHED_VAR*` bookkeeping only runs for
   groups that actually read it, removing the per-match `String`/`Vec` copies
   for the other 90 % of rules.
6. **Correct per-collection cache ids.** Name collections previously shared a
   cache-id base, which could alias a header name and an argument name with the
   same index. Each keyed collection now has a distinct base.

No defaults changed: `rust-engine`, `engine-profile`, and every optimisation
path remain opt-in.

## Profile method

The non-default `engine-profile` feature (`RustEngine::evaluate_profiled`)
records per-category wall time and allocation events. The parity harness grows
a `--profile` mode that prints the breakdown and a counting allocator in the
binary feeds the library counter:

```sh
cargo run --release --no-default-features \
  --features rust-engine,native-detect,engine-kernel,engine-profile \
  --bin rust-engine-parity -- --profile --reps 100
```

The production path contains no timers; the feature is compiled out.

## Results

Measured on the shared host at load average ≈1.9, `--reps 300`. The host was
much noisier during the baseline run (load ≈17), so treat the absolute
before/after as directional and the allocation counts as exact.

| Body | Before p50 | After p50 | After p99 | Before alloc/req | After alloc/req |
|---|---:|---:|---:|---:|---:|
| bodyless | 327 µs | **145 µs** | 217 µs | 1,251 | **143** |
| 1 KiB | 869 µs | **426 µs** | 476 µs | 1,757 | **146** |
| 4 KiB | 2,151 µs | **1,132 µs** | 1,243 µs | 1,774 | **143** |
| 8 KiB | 3,879 µs | **2,069 µs** | 2,266 µs | 1,785 | **143** |

Targets: bodyless < 150 µs (met, 145 µs), 4 KiB < 800 µs (missed, 1.13 ms),
8 KiB < 1.5 ms (missed, 2.07 ms). Allocation target < 100/request (missed,
143; down 88–92 % from baseline).

### Per-category cost at 4 KiB (final instrumented build)

| Category | ns | allocs |
|---|---:|---:|
| transform pipeline | 399,854 | 0 |
| literal gate (transform + AC) | 360,168 | 0 |
| regex/operator | 373,821 | 8 |
| candidate resolution | 35,891 | 18 |
| scoring (`setvar`/anomaly) | 19,227 | 18 |
| captures | 959 | 0 |
| parse/body | 8,230 | 6 |

Top costs in order: transform pipeline, literal gate, regex, candidate
resolution, scoring, parse, captures. At 8 KiB the first three scale linearly
(747 µs / 657 µs / 617 µs).

### Gates

- 50 rules carry a compiled gate.
- A 4 KiB `data=AAAA…` request runs 181 operator evaluations and **skips 99
  regex evaluations (55 %)**; the bodyless request skips 18 of 95.
- Corpus decisions are **byte-for-byte identical** to the pre-change baseline
  for all 2,112 cases (same allow/block per case), preserving the baseline
  Coraza parity of 2,110/2,112 with **0 native-only false negatives**.
- Transform parity fixture (`tests/fixtures/transform_parity.json`, 7,320
  assertions) is untouched; `rust_engine` transform semantics are covered by
  the same 2,112-case decision corpus.

## Remaining allocation sources (143/request)

- 18 candidate-resolution allocations: mixed-target rules and owned
  single-value collections (`REQUEST_LINE`, `REQBODY_PROCESSOR`, sizes).
- 18 scoring allocations: first-use TX slot insertion and `ctl` clones.
- 8 operator allocations: capture-group copies on match.
- ~90 outside the profiled categories: `MATCHED_VARS` recording for the groups
  that need it, `matched_rules` growth, and generic mixed-target candidates.

## Blockers / follow-ups

- **4 KiB / 8 KiB latency targets.** The remaining cost is inherent
  single-threaded transform + gate + regex work over a 4–8 KiB argument. The
  benchmark has a single `ARGS` value, so the scoped ARGS thread pool in the
  task cannot help; parallelising rule order would change anomaly/skipAfter
  semantics. The next lever is prefix-sharing transform results across
  pipelines and compiling the gate literal sets to dense `regex-automata` DFAs
  (evaluated, not landed: DFA build size/time for 3,145 literals needs a
  bounded per-group budget).
- **< 100 allocations.** The remaining bookkeeping is required for
  `MATCHED_VARS` chains and mixed-target rules; removing it needs an interned
  TX-name table and an arena-backed `MATCHED_VARS`, which is a larger IR
  change than this task allowed.
- Coraza A/B could not be rebuilt in this worktree (the `wasm-reactor` build
  takes ~10 minutes and the host was shared); parity is asserted against the
  recorded baseline corpus decisions instead.
