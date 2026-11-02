# Native Rust CRS engine: core vertical slice

**Status:** experimental, feature-gated behind `rust-engine`, **not enabled by
default**.
**Branch:** `feat/rust-engine`
**Bundle:** OWASP CRS 4.14.0 (`wasm/coraza_reactor/rules/crs/crs.conf`), PL1.
**Oracle:** the existing Coraza WASI reactor (`wasm-reactor`).

## TL;DR

This slice replaces the Coraza *request* engine with a native Rust parser,
compiled IR and evaluator. It compiles **501 of 505** `SecRule`/`SecAction`
directives from the pinned bundle. The only unsupported rules are the four
libinjection operators (`941100`, `941101`, `942100`, `942101`); strict loading
aborts with the rule id and construct rather than dropping them.

On the 2,112-case pinned CRS corpus the native engine agrees with the Coraza
oracle on **2,099 / 2,112 (99.38 %)** cases. The remaining oracle differences
are the four libinjection rules (8 cases) plus 5 cases where the native decision
matches the corpus and Coraza does not. See [Parity](#differential-parity).

The decision path is deterministic (no wall clock, randomness or GC) and
fail-closed (any internal error or budget overflow returns `Block`).

## Design rules

1. **No silent rule loss.** The parser returns `Unsupported` with the rule id,
   source line and construct. `CompilePolicy::Strict` (the default loader)
   aborts the whole load; `CompilePolicy::Report` is the offline tooling mode
   that records the full support matrix and skips only the affected rule.
2. **Deterministic.** Collections iterate in insertion order or `BTreeMap`
   order; there is no time, randomness or GC in `evaluate`.
3. **Fail-closed.** `RustEngine::evaluate` converts every `EngineError` into
   `Decision::Block { status: 500, .. }`. A budget overflow never allows.
4. **Bounded.** Every request gets a `Budget` (`Limits::default()`: 4,096
   values/rule, 1 MiB/value, 8 MiB/request, 4,096 matches/rule).
5. **Feature-gated.** `rust-engine` is non-default; Coraza remains the default
   backend and the differential oracle.

## Architecture

```
crs.conf ──► parser (SecLang) ──► IR ──► Program (phase 1 / phase 2)
                                     │
                    ┌────────────────┴────────────────┐
                    │                                 │
             transforms (CRS set)              operators (CRS set)
                    │                                 │
                    └──────────────┬──────────────────┘
                                   ▼
                     Collections + TX anomaly scores
                     (URLENCODED / MULTIPART bodies)
                                   ▼
                        Decision + Outcome diagnostics
```

| Module | Responsibility |
|---|---|
| `src/waf/rust_engine/parser.rs` | SecLang logical-line/token parser, actions, variables, strict/report compilation, support matrix |
| `src/waf/rust_engine/ir.rs` | Compiled rules, operators, selectors, actions, phases, program |
| `src/waf/rust_engine/engine.rs` | Phase ordering, chains, `skipAfter`, `setvar`, `ctl`, anomaly checks, fail-closed wrapper |
| `src/waf/rust_engine/request.rs` | Coraza-compatible collections, URI parsing, URLENCODED/MULTIPART processors, macros |
| `src/waf/rust_engine/transforms.rs` | CRS transform implementations |
| `src/waf/rust_engine/operators.rs` | Operator implementations and phrase/regex compilation |
| `src/waf/rust_engine/budget.rs` | Fixed per-request accounting |

The regex compiler normalises PCRE spellings that Rust's `regex` crate rejects
(`\x{XX}` byte escapes, literal `{.*}` braces, escapes of non-metacharacters
such as `\!`) before compiling. PCRE lookarounds/backreferences are absent from
the pinned request rules; if they appear, the load fails as unsupported.

## Supported matrix

Counts are from the pinned bundle in `CompilePolicy::Report` mode.

| Category | Supported |
|---|---|
| Directives | `SecRule`, `SecAction`, `SecDefaultAction`, `SecMarker`, `SecComponentSignature`, `Include` |
| Operators | `@rx`, `@pm`, `@pmFromFile`, `@contains`, `@beginsWith`, `@endsWith`, `@within`, `@streq`, `@eq`, `@lt`, `@gt`, `@ge`, `@le`, `@validateByteRange`, `@validateUrlEncoding`, `@validateUtf8Encoding`, `@unconditionalMatch`, `@ipMatch` |
| Transforms | `none`, `lowercase`, `uppercase`, `urlDecode`, `urlDecodeUni`, `htmlEntityDecode`, `jsDecode`, `cssDecode`, `cmdLine`, `replaceComments`, `escapeSeqDecode`, `removeWhitespace`, `normalizePath`, `normalizePathWin`, `compressWhitespace`, `removeNulls`, `base64Decode`, `sha1`, `hexEncode`, `removeCommentsChar`, `length`, `utf8toUnicode`, `trim`, `trimLeft`, `trimRight` |
| Actions | `id`, `phase`, `block`, `pass`, `deny`, `drop`, `allow`, `status`, `chain`, `capture`, `multiMatch`, `setvar`, `ctl`, `skipAfter`, `initcol`, `msg`, `tag`, `logdata`, `severity`, `rev`, `ver`, `log`, `nolog`, `auditlog`, `noauditlog`, `t:` |
| Collections | `ARGS`, `ARGS_GET`, `ARGS_POST`, `ARGS_NAMES`, `ARGS_GET_NAMES`, `ARGS_POST_NAMES`, `ARGS_COMBINED_SIZE`, `REQUEST_HEADERS`, `REQUEST_HEADERS_NAMES`, `REQUEST_COOKIES`, `REQUEST_COOKIES_NAMES`, `REQUEST_URI`, `REQUEST_URI_RAW`, `REQUEST_METHOD`, `REQUEST_BODY`, `REQUEST_BODY_LENGTH`, `REQUEST_FILENAME`, `REQUEST_BASENAME`, `REQUEST_LINE`, `REQUEST_PROTOCOL`, `QUERY_STRING`, `TX`, `MATCHED_VARS`, `MATCHED_VARS_NAMES`, `XML`, `FILES`, `FILES_NAMES`, `FILES_SIZES`, `FILES_COMBINED_SIZE`, `MULTIPART_PART_HEADERS`, `REQBODY_PROCESSOR`, `REMOTE_ADDR`, `UNIQUE_ID`, `RULE`, `GLOBAL`, `IP` |

### Unsupported in this slice

| Rule | Construct | Why |
|---:|---|---|
| 941100 | `@detectXSS` | libinjection XSS port not started |
| 941101 | `@detectXSS` | libinjection XSS port not started |
| 942100 | `@detectSQLi` | libinjection SQLi port not started |
| 942101 | `@detectSQLi` | libinjection SQLi port not started |

Strict mode aborts on the first of these with the rule id and construct. Report
mode records them and skips only those rules, which is why the parity harness
can still measure the rest of the bundle.

The `XML` collection is accepted and empty: the WASI reactor never enables the
XML body processor, so `XML:/*` is empty for every corpus request. The
`REMOTE_ADDR` and `UNIQUE_ID` singles are empty for the same reason
(`ProcessConnection` is not called by the reactor).

## Differential parity

Harness:

```sh
cargo run --features rust-engine --bin rust-engine-parity -- \
  --engine both --json target/rust-engine-parity.json
```

`tests/corpus/crs/corpus.json`: 2,112 cases (1,700 expected block, 412 expected
allow), pinned CRS 4.14.0, PL1.

| Comparison | Result |
|---|---|
| Native vs Coraza | **2,099 / 2,112 agree (99.38 %)** |
| Native vs expected | 11 false negatives, 88 false positives |
| Coraza vs expected | 5 false negatives, 91 false positives |

The corpus itself contains 91 cases where the full CRS blocks a request the
upstream regression test marks `allow`; those are corpus/oracle false positives,
not native-engine regressions. The native engine has three fewer false
positives than the oracle on this corpus (88 vs 91).

Remaining native-vs-oracle differences:

* **8 cases** exercise the four libinjection rules (`941100`, `942100`), which
  this slice reports as unsupported.
* **2 cases** (`crs-921250-1/2`) are old-cookie `$Version` detection where the
  native engine matches the corpus and Coraza does not.
* **3 cases** (`crs-934160-1`, `crs-942151-13/14`) are oracle false positives;
  the native engine correctly allows them.

Both engines also miss **3 cases** (`crs-944150-12/13/14`) that the corpus
expects to block: a JSON Log4Shell body whose raw representation is not exposed
by the reactor's URLENCODED projection. JSON body processing is shared
follow-up work, not a native-vs-oracle difference.

## Performance

Run:

```sh
cargo run --release --features rust-engine --bin rust-engine-parity -- --bench
```

The table is filled from the release build on the development host. Rows are a
`POST /post` with `Content-Type: application/x-www-form-urlencoded` and a
`data=AAAA...` body; the Coraza column is the committed WASI reactor.

| Body | Native p50 | Native p95 | Coraza p50 | Coraza p95 |
|---|---:|---:|---:|---:|
| bodyless | 0.93 ms | 1.08 ms | 3.55 ms | 6.93 ms |
| 1 KiB | 1.08 ms | 3.52 ms | 57.1 ms | 136.2 ms |
| 4 KiB | 2.70 ms | 9.53 ms | 414.2 ms | 841.5 ms |
| 8 KiB | 5.02 ms | 17.67 ms | 599.8 ms | 2,564.1 ms |

Measured on the shared development host with `--reps 200`, a release build and
the committed WASI reactor. The host was under heavy parallel build load for
the whole session, so absolute values are inflated and vary between runs; the
ratio is the useful signal. The native binary was built with LTO disabled to
keep the build tractable; the shipped `release` profile enables LTO and should
be slightly faster. Coraza's own reference numbers for the same bodies on an
idle host are ~2.3 ms / 39 ms / 168 ms / 351 ms (bodyless / 1 / 4 / 8 KiB).

## Remaining work to full replacement

1. **Port libinjection** (`@detectSQLi`, `@detectXSS`) or vendor a Rust
   implementation, then compile rules 941100/941101/942100/942101. This is the
   only strict-load blocker.
2. **JSON and XML body processors.** The reactor only selects URLENCODED and
   MULTIPART today; full replacement needs the JSON/XML processors, XPath
   (`XML:/*`, `XML://@*`) and the corresponding `ctl:requestBodyProcessor`.
3. **URI `String()` encoding.** Coraza exposes `REQUEST_URI` as Go's
   `url.URL.String()`, which percent-encodes spaces/backslashes. The slice keeps
   the raw form; `REQUEST_URI_RAW` is exact.
4. **Selector and macro edge cases.** Regex selectors are lowercased for
   case-insensitive collections like Coraza; more work is needed for XPath
   selectors, `@pmFromDataset`, and dynamic collections.
5. **Response phases.** Only request phases 1 and 2 are implemented. Phases
   3–5, response body processors and outbound anomaly scoring are out of scope.
6. **Coraza feature parity.** `@geoLookup`, `@rbl`, `@inspectFile`,
   `@validateNid`, `SecRuleUpdateActionById`, `SecRuleRemoveById` and the
   response-side directives still need implementations or explicit unsupported
   reporting.
7. **Wire the engine into the proxy.** `RustEngineRule` implements `WafRule`,
   but the default backend remains Coraza until parity is proven on the
   deployment corpus and the remaining items above are closed.

## Verification

```sh
nix develop -c cargo fmt -- --check
nix develop -c cargo test --lib --features rust-engine
nix develop -c cargo clippy --lib --features rust-engine -- --deny warnings
nix develop -c cargo run --features rust-engine --bin rust-engine-parity -- --report-only
nix develop -c cargo run --features rust-engine --bin rust-engine-parity -- --engine both
```
