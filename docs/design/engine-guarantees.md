# Engine guarantees for the native Rust replacement

This document describes the enforceable guarantees around replacing Coraza with
a native Rust engine. Each guarantee has a mechanism that fails the build or the
harness; none of them is a claim in prose.

The guarantee layer lives in `src/engine/` and is independent of the engine
implementation. The engine workstream plugs into `src/engine/backend.rs` behind
the non-default `native-engine` feature. The accounting parser, generator,
determinism runner, resource budget and fail-closed mapping are usable before
that branch is merged.

## 1. No silent rule loss

**Guarantee.** Every rule-bearing directive in the pinned CRS bundle is present
in a deterministic manifest. The native engine build calls
`engine::accounting::verify_complete(&manifest, &support)` and fails if any rule
id, directive, operator, transform, action or structural construct is not
accounted for.

**Mechanism.**

- `src/bin/rule_accounting.rs` parses
  `wasm/coraza_reactor/rules/crs/crs.conf` (OWASP CRS 4.14.0, pinned commit in
  the corpus provenance) into `rules/crs/rule-manifest.json`.
- The manifest records every entry's directive, rule id, line, phase, chain
  position, targets, operator, transforms, action names and constructs. It also
  records aggregate coverage and the SHA-256 of the parsed bundle.
- `rule_accounting --check` fails (exit 3) when the committed manifest drifts
  from the bundle, and reports added/removed rule ids and changed operator,
  transform, action and construct sets.
- Rule-mutating directives the parser does not model
  (`SecRuleUpdateTargetById`, `SecRuleRemoveById`, ...) are a hard parse error,
  as are unknown active `Sec*` directives. They are never ignored.
- `EngineSupport` is an explicit declaration: absent sets mean unsupported, not
  "probably fine". `EngineSupport::from_manifest` emits a full-support template
  the engine workstream trims. Metadata actions may be declared in
  `ignored_actions`, which is an explicit, reviewable decision.
- `verify_complete` returns every gap at once in a `GapReport`, so a failing
  build shows the full missing surface.

**Command.**

```bash
nix develop -c cargo run --bin rule_accounting -- --check
nix develop -c cargo run --bin rule_accounting -- --support rules/crs/engine-support.json
```

## 2. Decision equivalence with Coraza

**Guarantee.** On the pinned CRS corpus and on generated requests, the native
engine's `Allow`/`Block` decision must equal Coraza's. Any disagreement or
engine error fails the run and persists a minimized counterexample.

**Mechanism.**

- The existing `crs_corpus` harness gains `--engine rust`; it runs the pinned
  corpus through the native engine and reports false negatives, false positives
  and errors exactly like the Coraza backends.
- `--generated N` generates deterministic requests from a seed. The generator
  cycles SQLi/XSS/LFI/RCE tokens and benign variants, seven encoding
  permutations (identity, URL, double URL, HTML entity, mixed case, NUL byte,
  backslash) and eight placements (query, URI path, User-Agent, Referer,
  Cookie, form body, JSON body, multipart body).
- `engine::differential::compare` runs both engines. A candidate error is a
  mismatch even when the fail-closed decision happens to be `Block`, because
  the engine must not error on valid rules.
- Disagreements are minimized with greedy delta debugging over headers, URI and
  body, then merged into `tests/corpus/engine/counterexamples.json` keyed by
  request bytes. Existing regressions are preserved.

**Command.**

```bash
nix develop -c cargo run --bin crs_corpus --features wasm-reactor,native-engine -- \
  --engine rust --require-engine --generated 500 --generated-seed 2654435761 \
  --fail-on-mismatch
```

## 3. Determinism

**Guarantee.** Repeated evaluation of the same request returns the same
decision, regardless of order or concurrency.

**Mechanism.**

- `engine::determinism::run` evaluates a baseline pass, then runs `iterations`
  shuffled passes across `threads` workers. Each worker owns its engine instance
  through a factory, so engines that are not `Sync` are still exercised.
- Any difference from the baseline decision is a mismatch. A baseline error is
  reported as an error and fails the run, so an engine cannot hide
  nondeterminism behind an error.
- The harness exposes `--determinism`, `--determinism-threads` and
  `--determinism-limit`; the CI script runs 100 shuffled iterations on four
  threads against the Coraza baseline and against the Rust engine when enabled.
- Shuffled order and multiple threads expose accidental dependence on iteration
  order, shared mutable state, thread identity, wall-clock time and unseeded
  randomness.

**Command.**

```bash
nix develop -c cargo run --bin crs_corpus --features wasm-reactor -- \
  --engine wasm --determinism 100 --determinism-threads 4 --fail-on-mismatch
```

## 4. Bounded resources

**Guarantee.** A single request cannot consume unbounded arena bytes,
allocations, rule evaluations or transforms. Exhausting a budget blocks the
request.

**Mechanism.**

- `engine::budget::ResourceLimits` defines hard per-request limits and
  `RequestBudget` tracks arena usage, allocation count, rule evaluations and
  transform applications.
- Every charge returns `BudgetError`; `EngineError::BudgetExhausted` is mapped
  by `engine::failclosed::decide` to `Decision::Block` with status 503.
- Unit and regression tests cover arena overflow, allocation-count exhaustion,
  rule-evaluation exhaustion and transform exhaustion, and assert that each
  failure is a `Block`.

**Default limits.** 8 MiB arena, 65,536 allocations, 1,000,000 rule
evaluations, 1,000,000 transforms. The engine workstream may tighten them; the
guarantee is that a limit exists and exhaustion is fail-closed.

## 5. Fail closed

**Guarantee.** Every internal engine error produces `Block`, never `Allow`.

**Mechanism.**

- `engine::failclosed::decide` is the only mapping from `Result<EngineOutcome,
  EngineError>` to a WAF decision. Errors return
  `Decision::Block { status: 503 }`.
- Tests inject an unsupported operator at runtime, arena overflow and malformed
  rule IR, and assert `Block` for each.
- `validate_rule_ir` rejects empty rule sets, zero ids, empty operators,
  missing/empty targets, empty transforms and duplicate ids. An empty compiled
  rule set is an internal error, not "allow everything".
- `EngineError::Unavailable` (the current scaffold state) also blocks, so a
  missing backend cannot silently pass traffic.

## CI wiring

`scripts/check-engine-guarantees.sh` always enforces:

1. `cargo fmt -- --check`
2. `rule_accounting --check`
3. `cargo test --lib engine::`
4. `cargo check --features native-engine`
5. Coraza determinism baseline (100 iterations, shuffled, four threads)

With `ENGINE_FEATURE=1` it additionally runs the blocking Rust differential and
determinism target with `--require-engine --fail-on-mismatch`.

The `Feature Matrix` workflow has a `workflow_dispatch` job `Engine guarantees
(optional)` with `run_engine_guarantees` and `engine_feature` inputs. The job is
not `continue-on-error`: failures block the dispatched run. Enabling
`engine_feature` makes the Rust target blocking; leaving it off still blocks on
accounting and the Coraza determinism baseline while reporting the Rust target
as skipped.

## Residual risks

- **Upstream ruleset drift.** The manifest is pinned to CRS 4.14.0. A newer CRS
  can add operators, transforms, actions or directives. `--check` fails on the
  drift, but the fix requires human review of the new constructs and an engine
  implementation or an explicit `ignored_actions` decision.
- **PCRE feature gaps.** The accounting manifest records operator names, not
  the regex dialect. A native regex engine can accept `@rx` yet differ on
  lookarounds, backreferences, possessive quantifiers, `\C`, Unicode classes or
  case-folding. Differential testing catches observed differences on the
  corpus and generated inputs, but cannot prove regex equivalence for every
  pattern. This remains the largest equivalence risk.
- **Coraza version drift.** The reference decisions come from the pinned
  Coraza/CRS bundle. A different Coraza build, rule tuning or body limit changes
  the reference. The harness records provenance, but the reference is not an
  external oracle.
- **Generated-corpus coverage.** The generator covers the requested token
  families and encoding/placement permutations, not every CRS rule or every
  parser edge case. Counterexamples are minimized for review, not guaranteed to
  be globally minimal or semantically minimal.
- **Determinism sampling.** Shuffled multi-threaded repetition is strong
  evidence but not a proof. A dependency that only triggers on a specific clock
  value or rare seed may survive. The engine must still avoid time and random
  sources by construction.
- **Budget values.** The limits are a policy choice. Too-tight limits cause
  false blocks; too-loose limits weaken the bound. Exhaustion is fail-closed in
  either case, but operators must review the configured values.
- **Scaffold state.** `src/engine/backend.rs` currently reports unavailable. The
  Rust differential and determinism targets skip unless the engine workstream
  links a backend and sets `is_available()` to true; `--require-engine` turns
  that skip into a failure.
- **Fail-closed status.** Internal engine failures return HTTP 503 rather than
  403. This is a deliberate distinction between a detection and an engine
  fault; clients and monitoring must treat both as blocks.
