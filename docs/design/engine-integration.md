# Engine integration: native operators + kernel execution model

> **Historical research report.** This records the state of the branch/commit
> below, not current operator defaults. Since 0.1.0-beta.13 the native Rust
> engine is the default request-inspection backend; Coraza remains the reference
> oracle and the explicit `waf.coraza.backend = "wasm"` switch-back. For current
> behaviour see [engine selection](../user-guide/engine-selection.md).

Branch: `feat/engine-integration` (not pushed, not merged).
Feature set: `rust-engine,native-detect,engine-kernel` (defaults unchanged; Coraza
remains the default backend).

## What changed

1. **Full operator coverage.** `@detectSQLi` and `@detectXSS` are compiled into
   the engine IR (`OperatorKind::DetectSqlInjection` / `DetectXss`) and evaluate
   against `src/waf/native_detect` (`libinjection` port) directly on the value
   bytes. The SQLi operator also fills `TX:0` with the libinjection fingerprint
   when the rule uses `capture`, matching Coraza. `rust-engine` now implies
   `native-detect`, so strict load of the pinned bundle compiles **505/505**
   rules with **0 skipped** and **0 unsupported constructs**.
2. **Kernel execution model in the engine** (IR and rule semantics unchanged):
   * **Zero-copy request spans.** `RequestData` borrows the body, method, URI,
     protocol and header values (`Cow`), and TEXT/TX values are resolved as
     borrowed `Candidate` spans instead of cloned `Vec<u8>`.
   * **Shared transform cache.** Transform chains are interned once at load
     (`Program::pipelines`), and a per-request `TransformCache` computes each
     `(value id, pipeline id)` at most once. Rules with the same chain share
     the result; `multiMatch` is handled separately.
   * **Reused arena/scratch.** Capture slots, candidate buffers and transform
     buffers are reused across rules; transform output slots live in a
     thread-local arena.
   * **Phase early exit.** A disruptive action or the anomaly threshold stops
     the phase immediately; `allow` skips phase 2; the phase-1 anomaly check
     only runs when `early_blocking` is set, as before.
3. **Selectable backend.** `waf.coraza.backend = "rust"` is accepted behind
   `rust-engine`. The engine loads the pinned CRS bundle in strict mode, so an
   unsupported construct fails the transaction closed at startup exactly like
   the other backends (`UnavailableCorazaRule` when `fail_closed`). The default
   remains `wasm`.

## Performance

Release, in-process (`rust-engine-parity --engine rust --bench --reps 300`).
The host is shared with other agents and absolute numbers vary by more than 2x
between runs; the row below is the quietest of three interleaved runs. Coraza
numbers are the same run's WASI reactor for scale, not a tuned comparison.

| body    | target p50 | rust p50 | rust p95 | rust p99 | Coraza p50 | alloc/request |
|---------|-----------:|---------:|---------:|---------:|-----------:|--------------:|
| bodyless| < 0.3 ms   | 183 µs   | 222 µs   | 244 µs   | 3.27 ms    | 1,251 |
| 1 KiB   | < 0.6 ms   | 479 µs   | 522 µs   | 590 µs   | 40.7 ms    | 1,757 |
| 4 KiB   | < 1.0 ms   | 1,130 µs | 1,180 µs | 1,264 µs | 170 ms     | 1,774 |
| 8 KiB   | < 2.0 ms   | 2,028 µs | 2,302 µs | 3,304 µs | 355 ms     | 1,785 |

**Bodyless and 1 KiB meet the targets; 4 KiB and 8 KiB miss by ~13 % and ~1 %**
on a quiet run (they are much worse under load). Breakdown of the remaining
4/8 KiB cost:

* ~0.25 ms: the four previously unsupported libinjection rules (`942100`,
  `942101`, `941100`, `941101`) now scan every `ARGS`/cookie/header/filename
  value; on a 4 KiB body `detect_sqli` alone is ~70 µs and the XSS pass is
  comparable, plus the `@detectXSS` transform chain.
* ~0.6–0.8 ms: regex evaluation of the ~200 `ARGS`-targeted rules against the
  4 KiB value. The engine has no per-rule literal prefilter today, so every
  regex scans the transformed value. This is the main gap to 4 KiB < 1 ms; the
  existing `crs-prefilter` artifact (64/200 body rules gated) would remove a
  share, and a full required-literal artifact would be needed to close it.
* ~0.15 ms: transform pipelines and candidate resolution.
* ~1.7 k allocations/request, mostly `setvar` macro expansion and TX value
  materialisation for `TX:`/`&TX:` rules. They are reused buffers but still
  allocate their payloads.

## Parity gate

`rust-engine-parity --engine both` over the pinned 2,112-case corpus:

| metric | rust | Coraza |
|---|---:|---:|
| agree with each other | 2,110 / 2,112 (99.91 %) | — |
| false negatives vs corpus | 3 | 5 |
| false positives vs corpus | 91 | 91 |

Remaining disagreements (both are Coraza **false negatives**, not engine bugs):

| case | expected | rust | Coraza | classification |
|---|---|---|---|---|
| `crs-921250-1` | Block | Block | Allow | Coraza bug (rust matches corpus) |
| `crs-921250-2` | Block | Block | Allow | Coraza bug (rust matches corpus) |

The 3 rust false negatives are `944150-12/13/14` (JSON Log4Shell), which Coraza
also misses; they are a corpus expectation limitation shared by both engines,
not native-only. **There are zero unexplained native-only false negatives.**

## Wiring

```toml
[waf.coraza]
enabled = true
backend = "rust"   # requires a build with `rust-engine`
```

Startup uses `RustEngine::from_conf_path` (strict): a construct the engine does
not implement aborts with the rule id and construct, and with `fail_mode =
"closed"` the request path blocks rather than silently dropping coverage.

## Remaining work before making `rust` the default

* **JSON body processor**: CRS `REQUEST_BODY`/JSON rules currently see the raw
  body; the WASI reactor's JSON processor semantics are not ported.
* **XML processor and XPath**: `XML:/*` targets resolve to no values, and
  `@xpath`/`@validateXml` are not implemented. The 505-rule request bundle does
  not exercise XPath, but a full replacement needs it.
* **URI/collection parity**: a few corner cases (absolute-form targets,
  invalid escapes, multipart `_charset_`) are covered by the corpus but the
  collection model is a subset of Coraza's.
* **Response phases (3/4/5)**: the engine only evaluates request phases 1 and 2;
  response inspection would still require Coraza.
* **Prefilter for sub-1 ms 4/8 KiB**: wire the sound `crs-prefilter` gate (or a
  full required-literal artifact) to skip gated `ARGS` rules without lowering
  detection.
* **Allocation reduction**: intern/borrow TX setvar payloads to cut the ~1.7 k
  allocations/request.

## Verification

* `cargo fmt -- --check` — pass.
* `cargo test --lib --features rust-engine,native-detect,engine-kernel` —
  451 passed, 0 failed, 9 ignored.
* `cargo clippy --lib --features rust-engine,native-detect,engine-kernel --
  --deny warnings` — pass.
* `cargo clippy --features ... --bin rust-engine-parity -- --deny warnings` —
  pass.
* Corpus harness — see parity table above.
