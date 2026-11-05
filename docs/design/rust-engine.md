# Native Rust CRS engine: core vertical slice

**Status:** default request-inspection backend (`rust-engine`); Coraza remains
the reference implementation and the explicit `wasm` fallback.
**Branch:** `feat/engine-default`
**Bundle:** OWASP CRS 4.14.0 (`wasm/coraza_reactor/rules/crs/crs.conf`), PL1.
**Oracle:** the existing Coraza WASI reactor (`wasm-reactor`).

## Default selection

When `rust-engine` is compiled (it is in the default feature set), a plain
configuration selects `waf.coraza.backend = "rust"`. Builds without the feature
keep `"wasm"` as the default, and `"wasm"` / `"native"` remain explicitly
selectable. The rule bundle is parsed and compiled **once at startup** in strict
mode; a load failure aborts startup (`WafProxyService::new`) instead of falling
back to a weaker engine. On the reference host start-up takes ~276 ms end to
end (~210 ms in the IR compiler) and the process RSS is ~30 MiB, versus ~4.9 s
and ~800 MiB for the wasm reactor pool.

`waf.coraza.fallback` controls runtime errors:

| Value | Behaviour | Trade-off |
| --- | --- | --- |
| `none` (default) | A Rust-engine runtime error returns a fail-closed `500` block | Lowest memory; a bug or budget overflow rejects the request |
| `wasm` | The request is re-evaluated by the Coraza reactor; if Coraza also fails the request is blocked | Availability during engine bugs, at the cost of two engines in memory and re-inspection latency |

Load failures never use the fallback: they are configuration errors and stop
startup. The fallback is only for request-time `EngineError` (budget overflow,
transform overflow, internal invariant).

The package ships the pinned bundle under `share/waf/rules/crs` (Nix and
container images). At startup the resolver checks `WAF_CRS_CONF`, then the
source-tree path, then `<exe>/../share/waf/rules/crs`, then
`/usr/share/waf/rules/crs`; there is no download or runtime rule fetching.

## TL;DR

This slice replaces the Coraza *request and response* engine with a native Rust
parser, compiled IR and evaluator. It compiles **505 of 505**
`SecRule`/`SecAction` directives from the pinned bundle; with the non-default
`native-detect` feature the four libinjection operators are provided by the
native detector and strict loading succeeds. Without that feature those four
rules are reported as unsupported and strict loading aborts with the rule id and
construct rather than dropping them.

On the 2,112-case pinned CRS corpus the native engine agrees with the Coraza
oracle on **2,110 / 2,112 (99.91 %)** cases. Both remaining differences are
`crs-921250-1/2`, where the native engine blocks and Coraza allows (the native
decision matches the corpus); see [Parity](#differential-parity).

The decision path is deterministic (no wall clock, randomness or GC) and
fail-closed (any internal error or budget overflow returns `Block`).
Request body processors now cover URLENCODED, MULTIPART, JSON and XML, and
phases 3–5 (response headers/body/logging) are implemented behind an explicit
opt-in response API.

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
5. **Default with an explicit reference.** `rust-engine` is compiled by
   default and selected by `CorazaBackend::compiled_default()`. Coraza stays
   the reference oracle and can be selected with
   `waf.coraza.backend = "wasm"`; a missing feature, strict-load failure or
   runtime error never silently degrades to an uninspected request.

## Architecture

```
crs.conf ──► parser (SecLang) ──► IR ──► Program (phases 1–5)
                                     │
                    ┌────────────────┴────────────────┐
                    │                                 │
             transforms (CRS set)              operators (CRS set)
                    │                                 │
                    └──────────────┬──────────────────┘
                                   ▼
                     Collections + TX anomaly scores
        (URLENCODED / MULTIPART / JSON / XML request bodies,
         response headers/body for opt-in phases 3–5)
                                   ▼
                        Decision + Outcome diagnostics
```

| Module | Responsibility |
|---|---|
| `src/waf/rust_engine/parser.rs` | SecLang logical-line/token parser, actions, variables, strict/report compilation, support matrix |
| `src/waf/rust_engine/ir.rs` | Compiled rules, operators, selectors, actions, phases, program |
| `src/waf/rust_engine/engine.rs` | Phase ordering, chains, `skipAfter`, `setvar`, `ctl`, anomaly checks, fail-closed wrapper |
| `src/waf/rust_engine/request.rs` | Coraza-compatible collections, Go-compatible URI parsing, URLENCODED/MULTIPART processors, macros |
| `src/waf/rust_engine/processors/json.rs` | Coraza/gjson-compatible JSON flattening into `ARGS_POST` |
| `src/waf/rust_engine/processors/xml.rs` | Non-validating XML scanner for `XML:/*` and `XML://@*` (no external DTD/entity access) |
| `src/waf/rust_engine/response.rs` | `EngineResponse`/`ResponseConfig` and the opt-in response body-processor hooks |
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
| Phases | `phase:1`–`phase:5` (request headers/body, response headers/body, logging) |
| Body processors | `URLENCODED`, `MULTIPART`, `JSON` (gjson-compatible), `XML` (`/*` and `//@*`) — JSON/XML are only selected by `ctl:requestBodyProcessor`, exactly like Coraza |
| XPath | `XML:/*` and `XML://@*`. Any other `XML:<xpath>` selector is an explicit unsupported construct at load time (strict load aborts; report mode records it) |
| Operators | `@rx`, `@pm`, `@pmFromFile`, `@contains`, `@beginsWith`, `@endsWith`, `@within`, `@streq`, `@eq`, `@lt`, `@gt`, `@ge`, `@le`, `@validateByteRange`, `@validateUrlEncoding`, `@validateUtf8Encoding`, `@unconditionalMatch`, `@ipMatch` |
| Transforms | `none`, `lowercase`, `uppercase`, `urlDecode`, `urlDecodeUni`, `htmlEntityDecode`, `jsDecode`, `cssDecode`, `cmdLine`, `replaceComments`, `escapeSeqDecode`, `removeWhitespace`, `normalizePath`, `normalizePathWin`, `compressWhitespace`, `removeNulls`, `base64Decode`, `sha1`, `hexEncode`, `removeCommentsChar`, `length`, `utf8toUnicode`, `trim`, `trimLeft`, `trimRight` |
| Actions | `id`, `phase`, `block`, `pass`, `deny`, `drop`, `allow`, `status`, `chain`, `capture`, `multiMatch`, `setvar`, `ctl`, `skipAfter`, `initcol`, `msg`, `tag`, `logdata`, `severity`, `rev`, `ver`, `log`, `nolog`, `auditlog`, `noauditlog`, `t:` |
| Collections | `ARGS`, `ARGS_GET`, `ARGS_POST`, `ARGS_NAMES`, `ARGS_GET_NAMES`, `ARGS_POST_NAMES`, `ARGS_COMBINED_SIZE`, `REQUEST_HEADERS`, `REQUEST_HEADERS_NAMES`, `REQUEST_COOKIES`, `REQUEST_COOKIES_NAMES`, `REQUEST_URI`, `REQUEST_URI_RAW`, `REQUEST_METHOD`, `REQUEST_BODY`, `REQUEST_BODY_LENGTH`, `REQUEST_FILENAME`, `REQUEST_BASENAME`, `REQUEST_LINE`, `REQUEST_PROTOCOL`, `QUERY_STRING`, `TX`, `MATCHED_VARS`, `MATCHED_VARS_NAMES`, `XML`, `FILES`, `FILES_NAMES`, `FILES_SIZES`, `FILES_COMBINED_SIZE`, `MULTIPART_PART_HEADERS`, `REQBODY_PROCESSOR`, `REMOTE_ADDR`, `UNIQUE_ID`, `RULE`, `GLOBAL`, `IP`, `RESPONSE_STATUS`, `RESPONSE_PROTOCOL`, `RESPONSE_HEADERS`, `RESPONSE_HEADERS_NAMES`, `RESPONSE_BODY`, `RESPONSE_BODY_LENGTH`, `RESPONSE_CONTENT_TYPE`, `RESPONSE_CONTENT_LENGTH`, `RESPONSE_ARGS`, `RESPONSE_XML`, `OUTBOUND_DATA_ERROR` |

### Body processors and URI parity

* **JSON** follows `internal/bodyprocessors/json.go`: keys are flattened with a
  `json.` prefix, array indices are numeric, an array also writes its length at
  the array path, `null` becomes `""`, numbers/booleans keep their raw spelling,
  duplicate keys are last-wins and malformed input yields no arguments. The
  native parser adds a depth/value bound (`ProcessorLimits`, 64 levels /
  16,384 values) that Coraza's `TODO add some anti DOS protection` does not
  have; overflow leaves the collection empty.
* **XML** follows `internal/bodyprocessors/xml.go`: attribute values populate
  `XML://@*`, trimmed character data (including CDATA) populates `XML:/*`.
  Declarations (including `DOCTYPE`) are skipped and **no external DTD,
  network or entity resolution is ever attempted**. Deviations from Go's
  decoder are documented in `processors/xml.rs`: only predefined/numeric and a
  small HTML entity subset are decoded (unknown entities are preserved),
  mismatched/unclosed tags are processor errors (XML stays empty), and the
  HTML auto-close rules are a compact subset.
* **URI** now mirrors Go `net/url.ParseRequestURI` + `URL.String()`:
  `REQUEST_URI` re-encodes a raw space/backslash/non-ASCII path with uppercase
  `%XX` while preserving an already valid `RawPath`; `REQUEST_FILENAME` is the
  percent-decoded path; opaque/authority-only URIs (`www.coreruleset.org:80`,
  `http://localhost`) and `//host/path` follow Go. `REQUEST_URI_RAW` remains the
  untouched wire value.

### Unsupported in this slice

Without the non-default `native-detect` feature, strict loading still aborts on
the four libinjection rules:

| Rule | Construct | Why |
|---:|---|---|
| 941100 | `@detectXSS` | libinjection XSS port not started |
| 941101 | `@detectXSS` | libinjection XSS port not started |
| 942100 | `@detectSQLi` | libinjection SQLi port not started |
| 942101 | `@detectSQLi` | libinjection SQLi port not started |

With `native-detect` these four rules compile and the pinned bundle is 505/505.
Report mode records any unsupported construct and skips only those rules, which
is why the parity harness can still measure the rest of the bundle.

Unsupported beyond the pinned request bundle: arbitrary XPath selectors,
`SecRuleUpdateActionById`, `SecRuleRemoveById` directives, `@geoLookup`, `@rbl`,
`@inspectFile`, `@validateNid`, and response-side `ctl:responseBodyAccess` /
`ctl:responseBodyProcessor` (response inspection is configured through
`ResponseConfig` instead). `REMOTE_ADDR` and `UNIQUE_ID` remain empty because
the WASI reactor never calls `ProcessConnection`.

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
| Native vs Coraza | **2,110 / 2,112 agree (99.91 %)** |
| Native vs expected | 3 false negatives, 91 false positives |
| Coraza vs expected | 5 false negatives, 91 false positives |

The corpus itself contains 91 cases where the full CRS blocks a request the
upstream regression test marks `allow`; those are corpus/oracle false positives,
not native-engine regressions.

Remaining native-vs-oracle differences:

* **2 cases** (`crs-921250-1/2`) are old-cookie `$Version` detection where the
  native engine matches the corpus and Coraza does not.

Both engines miss **3 cases** (`crs-944150-12/13/14`) that the corpus expects to
block: a JSON Log4Shell body. Coraza never selects the JSON processor from
`Content-Type` (JSON/XML require `ctl:requestBodyProcessor`), so its
`ARGS_POST` is empty and the reactor's `REQUEST_BODY` projection misses the
body. The native JSON processor is available, but enabling it automatically
would diverge from Coraza; these three remain shared false negatives of the
pinned request rules.

Per-category differential status:

| Category | Result |
|---|---|
| CRS request corpus (2,112) | 2,110/2,112 agree; 2 known oracle differences |
| JSON `Content-Type` selection | 6/6 differential cases agree with the reactor (`engine::tests::json_and_xml_content_type_selection_matches_coraza_reactor`) |
| XML `Content-Type` selection | same 6/6 differential cases |
| `ctl`-forced JSON flattening | unit vectors copied from `internal/bodyprocessors/json.go` (nested objects, arrays/length, duplicates, raw scalars, malformed) |
| `ctl`-forced XML collections | unit vectors for attributes, character data, CDATA, entities, DOCTYPE, malformed input |
| Response phases 3–5 | no live oracle: the WASI reactor never calls `ProcessResponseHeaders`/`ProcessResponseBody`. Verified with native unit tests for status/headers/body gating and outbound anomaly scoring |

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

### Default-backend verification (feat/engine-default)

Release `bench-subms` full proxy (loopback client + upstream), c=1, 60
requests/cell, default configuration selecting the backend explicitly:

| Body | Coraza `wasm` p50 | Rust default p50 | Rust p99 |
|---|---:|---:|---:|
| bodyless | 4.471 ms | **0.414 ms** | 0.485 ms |
| 1 KiB | 40.131 ms | **0.642 ms** | 0.770 ms |
| 4 KiB | 169.561 ms | **1.091 ms** | 1.187 ms |
| 8 KiB | 354.089 ms | **1.614 ms** | 1.676 ms |
| gRPC 1 KiB frame (HTTP/1.1, both blocked by 949110) | 4.913 ms | **1.050 ms** | — |

Corpus through `rust-engine-parity --engine both` with the default feature set:
2,112 cases, 0 errors, 2,110/2,112 agreement with Coraza. Startup: ~276 ms end
to end (IR compile ~211 ms) and ~30 MiB RSS, versus ~4.9 s and ~800 MiB for the
wasm reactor pool at `pool_size = 0` (auto). `cargo build --release` for the
main binary took ~7m46s on the shared host including dependencies; the release
`waf-ingress` binary is ~40 MiB.

gRPC and GraphQL pre-checks run before the Coraza/Rust rule in the chain, so
both protocols use the selected engine; protobuf/GraphQL bodies withheld by a
pre-check are not inspected a second time.

## Remaining work to full replacement

1. **Port libinjection** (`@detectSQLi`, `@detectXSS`) or vendor a Rust
   implementation with the same detection quality as the `native-detect`
   feature. `native-detect` closes the strict-load blocker behind a non-default
   feature; the default build still reports these four rules as unsupported.
2. **XPath coverage.** Only `XML:/*` and `XML://@*` are implemented. Broader
   XPath is reported as an unsupported construct; no rule is silently skipped.
3. **XML fidelity.** The non-validating scanner intentionally omits Go's full
   `HTMLEntity` table and complete HTML auto-close map. Add them only if a
   deployment rule depends on those entities; external DTD/entity resolution
   will stay disabled by design.
4. **Response wiring.** Phases 3–5 compile and evaluate, and `ResponseConfig`
   gates body inspection, but the proxy does not call
   `RustEngine::evaluate_response` yet and `ctl:responseBodyAccess` /
   `ctl:responseBodyProcessor` are unsupported. Wire response capture and the
   outbound blocking rules before enabling outbound CRS rules by default.
5. **Coraza feature parity.** `@geoLookup`, `@rbl`, `@inspectFile`,
   `@validateNid`, `@pmFromDataset`, `SecRuleUpdateActionById`,
   `SecRuleRemoveById` and dynamic collections still need implementations or
   explicit unsupported reporting.
6. **Wire the engine into the proxy.** `RustEngineRule` implements `WafRule`,
   but the default backend remains Coraza until parity is proven on the
   deployment corpus and the remaining items above are closed.

## Verification

```sh
nix develop -c cargo fmt -- --check
nix develop -c cargo test --lib --features rust-engine,native-detect,engine-kernel
nix develop -c cargo clippy --lib --features rust-engine,native-detect,engine-kernel -- --deny warnings
nix develop -c cargo run --features rust-engine --bin rust-engine-parity -- --report-only
nix develop -c cargo run --features rust-engine,wasm-reactor --bin rust-engine-parity -- --engine both
nix develop -c cargo test --lib --features rust-engine,native-detect,engine-kernel,wasm-reactor \
  json_and_xml_content_type_selection
```
