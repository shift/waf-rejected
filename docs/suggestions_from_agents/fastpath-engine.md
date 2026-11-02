# Native Rust fast path: architecture, soundness and measured gap to sub-millisecond

**Status:** research prototype, **non-default feature `fastpath`**.
**Branch:** `research/fastpath` (worktree `.worktrees/fastpath`), based on
`main` @ `24388c5`.
**Date:** 2026-11-02
**Engine:** Coraza `v3.3.3`, OWASP CRS `4.14.0` (vendored bundle), PL1.
**Artifact:** `rules/crs/prefilter.json` (schema v1), reused unchanged.

## TL;DR

A compiled Rust request fast path decides **bodyless** requests in
**2.7–2.8 µs p50** (p99 ≈ 3.2 µs), comfortably below 1 ms. It cannot yet
decide **body-bearing** requests below 1 ms without weakening detection: the
literal prefilter alone is byte-linear, costs **2.3 ms p50 at 4 KiB** for
transform-heavy (encoded) bodies, and stock CRS leaves 51 body-relevant rules
ungated (`@detectSQLi`, `@detectXSS`, several obfuscation-tolerant 932/941/942
regexes). Transform-free bodies are much cheaper (10 µs at 1 KiB, 40 µs at
4 KiB, 79 µs at 8 KiB) thanks to a single-automaton shortcut, but a clean
literal scan is still not a proof on stock CRS. The implementation therefore
ships **soundness mode (a)**: it returns `Clean` only when every covered rule
is provably unable to match, and returns `NeedsCoraza` for everything else.
Coraza remains the decision maker.

On the pinned 2,112-case corpus, the prototype proved **44 requests clean**,
all 44 were allowed by the WASI Coraza baseline, and there were **0 false
negatives**. The other 2,068 cases fell back to Coraza. Mode (b) — replacing a
documented rule subset — is defensible only for the non-body subset that the
prototype already checks exactly; it is not defensible for the body until
per-rule gating and the remaining ungated operators are modelled.

## 1. Architecture

```
FastPath::evaluate(FastPathRequest)
  ├─ MethodMatcher          exact method allowlist (CRS 911100)
  ├─ PathAllowlist          exact set + byte trie (fast-path eligibility)
  ├─ URI validator          origin-form subset, no query/fragment,
  │                         no dot segments/restricted extensions,
  │                         OS-file / PHP-function / signature matchers
  ├─ HeaderPolicy           Host, scanner UA, Accept, Content-Type,
  │                         Content-Length/Transfer-Encoding, protocol
  ├─ RegexSignatures        conservative SQLi/XSS/LFI/RCE/Java prefilters
  └─ BodyInspector          required-literal prefilter + exact body checks
       ├─ FastLiteralMatcher  one Aho-Corasick pass for transform-free bodies
       └─ Prefilter           84 per-group automata for transform-heavy bodies
```

The feature is declared in `Cargo.toml`:

```toml
fastpath = ["dep:aho-corasick"]
```

It enables `src/waf/fastpath/` and reuses `src/waf/prefilter.rs`; it does not
change defaults, remove Coraza, or alter the existing prefilter artifact.

### 1.1 Compiled matchers

* **Method**: exact `HashSet` lookup with the CRS default
  `GET HEAD POST OPTIONS`.
* **Path**: exact `HashSet` plus a byte trie. An empty allowlist means "all
  paths eligible"; a non-empty allowlist restricts *eligibility*, it never
  bypasses the safety checks.
* **Scanner UA**: Aho-Corasick over the vendored
  `scanners-user-agents.data`, matching CRS 913100.
* **OS files / restricted files / PHP functions**: Aho-Corasick over the
  vendored `lfi-os-files.data`, `restricted-files.data` and
  `php-function-names-933150/933151.data`.
* **Signatures**: a precompiled `regex::bytes::RegexSet` for SQLi, XSS, LFI,
  RCE and Java deserialization prefilters. A hit means "run Coraza"; a miss
  is not a proof on its own.
* **Body**: `rules/crs/prefilter.json` is loaded through the existing
  `Prefilter`. For bodies that contain no byte any CRS transform pipeline
  rewrites, a single case-insensitive Aho-Corasick pass over every gated
  literal replaces the 84 per-group automata. A miss is still a proof because
  the raw body is a superset representation for those bodies.

### 1.2 Header and protocol checks

`HeaderPolicy` implements the exact/superset checks for the non-body protocol
rules: method enforcement (911100), request-line form (920100), numeric
Content-Length (920160), body on GET/HEAD (920170), POST without
Content-Length (920180), Connection abuse (920210), Host presence/emptiness
(920280/920290), empty UA (920330), numeric Host (920350), allowed
Content-Type (920420), allowed HTTP version (920430), restricted extensions
(920440), restricted header names (920450), Content-Type syntax/charset
(920470/920480/920530), Accept grammar (920600), URI fragment (920610),
header injection (921140), multipart/Content-Type anomalies (921421/922100),
and scanner user agents (913100).

The policy is deliberately stricter than CRS: unknown headers, `Cookie`,
`Referer`, `Range`, `Request-Range`, encoded bytes (`%`), template syntax
(`${...}`), and ambiguous framing headers all force a Coraza fallback.

### 1.3 Body checks

`BodyInspector::scan` runs:

1. the signature set (SQLi/XSS/LFI/RCE/Java),
2. the required-literal prefilter (single AC for transform-free bodies,
   84 automata otherwise),
3. exact checks for `@validateUtf8Encoding` (920250), byte range (920270),
   form/JSON argument limits (920360-920390), multipart (922100/922130),
4. `all_body_rules_gated()`.

Stock CRS fails step 4, so the result is `BodyRuleUngated`; this is the
correct conservative outcome.

## 2. Soundness model (mode a)

`FastPathDecision::Clean` means: **every rule the fast path replaces is
provably unable to match this request**. The covered set is documented in
`src/waf/fastpath/mod.rs`. The argument has four parts:

1. **Structural domain.** The fast path only considers origin-form URIs
   without query/fragment, an allowed method, an allowed HTTP version, a valid
   Host, a non-scanner UA, a valid Accept header, allowed Content-Type, no
   ambiguous framing, and only known-safe headers. Anything outside this
   domain returns `NeedsCoraza`.
2. **Exact/superset checks.** Each covered non-body rule is implemented by a
   check that is at least as strict as the CRS rule (for example, the URI
   byte set is narrower than 920100's allowed request line, and the Accept
   grammar is narrower than 920600's). A passing check therefore proves the
   corresponding rule cannot match.
3. **Literal proof.** For the body, a miss in the required-literal prefilter
   proves no gated rule can match any derived value. The single-AC shortcut is
   only used when no transform-triggering byte is present, so every transform
   pipeline is identity modulo case; case-insensitive matching is a superset.
4. **No silent gaps.** `all_body_rules_gated()` is false on stock CRS, so
   body-bearing requests never return `Clean` by default. Unknown headers,
   query strings, cookies, `Referer`, `Range`, multipart bodies and bodies
   over the configured cap also return `NeedsCoraza`.

The fast path never blocks. Its only decisions are `Clean` (skip Coraza) and
`NeedsCoraza` (run Coraza). A bug in a check can therefore cause a false
negative only if it makes the check *more permissive* than CRS; the corpus and
the exact/superset construction are the guard against that.

## 3. Corpus validation

Command:

```sh
cargo run --bin crs_corpus --features fastpath -- \
    --engine fastpath --json target/crs-fastpath.json
```

Baseline: the same 2,112 cases through the WASI reactor (`--engine wasm`),
which matches the recorded baseline of 2,016/2,112 (FN=5, FP=91).

| metric | value |
|---|---:|
| corpus cases | 2,112 |
| fastpath `Clean` | 44 |
| fastpath `NeedsCoraza` | 2,068 |
| clean cases also allowed by WASI Coraza | 44 / 44 |
| **false negatives vs Coraza baseline** | **0** |
| clean cases expected to block | 0 |
| clean coverage of all cases | 2.1 % |
| clean coverage of allow cases | 10.7 % |

Fallback reasons (top): query/fragment not covered (617), body not covered
(962), unknown header (191), content-type not allowed (74), invalid header
value (44), unsafe path byte (37), missing Accept (22), charset not allowed
(20), obfuscated path (15), invalid Accept (13), method not allowed (10),
body headers on GET/HEAD (9), scanner UA (5).

The zero-false-negative result is on the **covered subset** (the 44 clean
cases). It is not a claim that the fast path can replace Coraza for the other
2,068 cases; those explicitly fall back. The stronger corpus statement is:
**no case that the WASI baseline blocked, and no case the corpus expected to
block, was returned `Clean`.** The harness enforces that condition with
`--fail-on-mismatch`.

Reproduce with:

```sh
scripts/run-fastpath-corpus.sh
```

It runs both engines and prints `false_negatives_vs_coraza`,
`false_negative_ids`, and `clean_expected_block`.

## 4. Benchmarks

Method: in-process, release build, single thread, warmed engine, whole
`FastPath::evaluate` for bodyless requests and `BodyInspector::scan` for body
requests. Coraza comparison uses the embedded WASI reactor in the same
process. Host: the shared development machine used for the other WAF
performance reports; absolute numbers move with host load, so treat the
ratios as the stable result.

| case | fastpath p50 | p95 | p99 | Coraza native p50 | Coraza wasm p50 |
|---|---:|---:|---:|---:|---:|
| bodyless GET | **2.79 µs** | 2.98 µs | 3.20 µs | 0.55 ms | 3.96 ms |
| bodyless HEAD | 2.77 µs | 2.98 µs | 3.22 µs | — | 4.71 ms |
| bodyless `OPTIONS *` | 2.72 µs | 2.91 µs | 3.12 µs | — | 4.32 ms |
| 1 KiB form (transform-free) | **10.01 µs** | 10.40 µs | 24.08 µs | 7.92 ms | 102.48 ms |
| 4 KiB form (transform-free) | **39.55 µs** | 43.02 µs | 65.18 µs | 32.66 ms | 432.99 ms |
| 8 KiB form (transform-free) | **79.07 µs** | 83.45 µs | 116.30 µs | 60.94 ms | 988.24 ms |
| 4 KiB form (`%41` encoded) | 2.31 ms | 4.85 ms | 8.98 ms | 32.66 ms | 166.90 ms |

Notes:

* Fastpath body rows measure `BodyInspector::scan` (the prefilter + exact
  checks), not a full decision. The conservative engine still returns
  `NeedsCoraza` for bodies because stock CRS has ungated rules, so the
  end-to-end body decision is Coraza's number plus this scan.
* The transform-free rows use the single-AC shortcut. The `%41` row forces
  the full 84-automaton prefilter and is the relevant worst case for encoded
  bodies.
* Native Coraza numbers are the pinned baseline from
  `docs/suggestions_from_agents/crs-performance.md` (same host class). WASI
  Coraza numbers are from this run; the host is shared, so the wasm p50 moved
  by 2–3× between runs. The ratio, not the absolute wasm number, is the
  result.

Interpretation:

* Bodyless decisions are dominated by header/URI validation and the signature
  set; they are far below 1 ms.
* The 1 KiB/4 KiB/8 KiB rows measure the **body prefilter**, not a full
  decision. The conservative engine still returns `NeedsCoraza` because stock
  CRS has ungated body rules, so the end-to-end decision adds Coraza's
  byte-linear cost on top.
* The single-AC shortcut is the difference between the earlier
  `crs-prefilter` numbers (1.4–2.0 ms/KiB) and the transform-free rows in the
  table.

## 5. Is mode (b) defensible?

**For a defined non-body subset, yes.** The prototype already implements
exact/superset checks for method, protocol, Host, scanner UA, Content-Type,
restricted extensions, OS files and PHP functions. A rule-subset mode could
skip Coraza for requests whose applicable rules are all in that subset, with
the same zero-FN gate on the corpus. This would raise clean coverage for
bodyless traffic and is the natural next step.

**For the body, not yet.** Stock CRS has 51 ungated body-relevant entries,
including `@detectSQLi` (942100), `@detectXSS` (941100), the
obfuscation-tolerant 932 regexes and the 934 transform chains. A clean literal
scan is necessary but not sufficient. Mode (b) becomes defensible only when
one of these holds:

1. every ungated operator is modelled exactly (libinjection-compatible
   `@detectSQLi`/`@detectXSS`, full transform chains, 934 base64/JS decode),
2. per-rule gating removes the gated rules and Coraza still runs the ungated
   ones (`RemoveRuleByID` for the sidecar, an equivalent wasm ABI), or
3. the deployment explicitly accepts a documented rule subset and its
   coverage trade-off.

Until then, skipping Coraza for bodies would be a coverage regression.

## 6. Gap to sub-millisecond and production work

**Verdict:** sub-millisecond p50 is achieved for bodyless requests. It is not
achieved for body-bearing requests with stock CRS detection. The gap is not
the Rust plumbing; it is the detection work (ungated body rules and the
byte-linear literal scan) and the absence of per-rule gating.

Work needed for production:

* **Per-rule gating** so gated rules can be removed while Coraza still runs
  `@detectSQLi`/`@detectXSS` and the other ungated rules. This is the single
  highest-value change.
* **A generated, versioned fast-path artifact** containing exact matchers for
  the non-body rules, not just the body literals. The current checks are
  hand-written and must be reviewed whenever CRS changes.
* **Transform-aware body fast path** (single automaton over transform classes,
  or a precomputed DFA) to keep 4–8 KiB scans below 1 ms for encoded bodies.
* **Configuration surface** for method/path/content-type allowlists, body cap,
  and fallback metrics. The prototype hard-codes CRS defaults.
* **Metrics** for clean/fallback counts and reasons, plus an audit event when
  Coraza is skipped.
* **Fuzzing/property tests** for the parser boundaries (URI, Host, Accept,
  Content-Type, header names) and a differential corpus that includes the
  upstream cases currently excluded from the pinned corpus.
* **Startup budget**: loading the embedded prefilter and building 84 automata
  plus the single AC takes measurable startup time; it should be warmed once
  at process start, never per request.
* **Fail-closed integration**: only `Clean` may skip Coraza; any error in the
  fast path must fall back to Coraza.

## 7. Limitations and risks

* The fast path is hand-written against CRS 4.14. A CRS upgrade requires a
  review of every check; the literal artifact alone is not enough.
* `Clean` coverage is intentionally narrow: no query strings, no cookies, no
  `Referer`/`Range`, no unknown headers, no multipart, and no body by default.
  This is a deliberate safety/coverage trade-off, not an oversight.
* The header/URI parsers are a security boundary. They need fuzzing and
  differential tests against Coraza before any production use.
* The single-AC body shortcut assumes that the listed bytes are the only
  transform triggers. Adding a new CRS transform requires updating that list.
* The prototype does not integrate with the proxy pipeline; it is an
  in-process engine and harness only. Integration must keep Coraza as the
  fallback and emit an audit event when Coraza is skipped.

## 8. Verification

```sh
cargo fmt -- --check
cargo test --lib --features fastpath
cargo clippy --lib --features fastpath -- --deny warnings
cargo run --bin crs_corpus --features fastpath -- --engine fastpath
cargo run --release --bin fastpath_bench --features fastpath
```

The prototype does not change the default feature set, the Coraza backend, the
prefilter artifact, or the WAF decision path.
---

# Part 2 — Production opt-in: compiled bodyless fast-allow path

# Bodyless fast path: compiled allowlist and sub-microsecond decisions

**Status:** implemented, opt-in (`waf.fast_allow`, default **off**).
**Branch:** `perf/bodyless-subus`.
**Engine:** default heuristic rules (content inspection, size/method, per-IP
and global rate limits); Coraza disabled for the component profile so the
numbers isolate the host-side decision path.
**Harness:** `src/bin/bodyless_bench.rs` (in-process, no sockets).

## TL;DR

The bodyless decision path now has a compiled `(method, path)` trie that
returns a precomputed `Allow` for explicitly configured routes. On a matching
route the request never builds a `RequestContext`, clones a `HeaderMap`,
formats a version string, acquires admission, runs the gRPC/GraphQL
pre-checks, dispatches inspection rules or constructs an audit event.

| path | p50 | p99 | notes |
|---|---:|---:|---|
| `evaluate_shared` (before, this engine) | 4.65 µs | 5.58 µs | context + admission + pre-checks + rules + audit |
| `fast_evaluate` (no allow audit) | 4.50 µs | 5.19 µs | still builds the context and runs inspection |
| **`fast_allow` (compiled route), c=1** | **0.380 µs** | **0.476 µs** | trie + bodyless checks + always-on gates |
| `fast_allow`, c=16 | 0.632 µs | 2.45 µs | per-request latency under concurrency |
| `fast_allow`, c=64 | 0.632 µs | 1.35 µs | per-request latency under concurrency |

The task's quoted research baseline (`2.79 µs` p50 / `3.20 µs` p99) was
measured on the separate native fast-path engine; the `evaluate_shared` row
above is the same in-process harness against this engine's full heuristic
chain, so the before/after comparison is like-for-like. The host was heavily
loaded by concurrent builds (load average 20+ on 6 CPUs) for this run, which
inflates the full-path tail more than the fast path.

Measured on the reference host with the in-process harness; see
[Measured results](#measured-results) for concurrency and RPS.

## Why

The full bodyless path spends its time on work that is irrelevant to a route
the operator has explicitly exempted:

| component | p50 |
|---|---:|
| `RequestContext` construction (HeaderMap/URI/method clone + `String`) | 158 ns |
| cheap admission (guard + metrics) | 32 ns |
| gRPC/GraphQL pre-check dispatch + async wrapper | ~51 ns |
| rule dispatch + content inspection (4 rules over URI/headers) | ~3.05 µs |
| audit event for an allow (lazy level check) | ~7 ns |
| metrics atomics | 31 ns |
| **compiled fast-allow (trie + bodyless + size/method + rate gates)** | **348 ns** |
| — of which per-IP + global rate-limit gates | ~157 ns |
| — trie + bodyless + size/method gates | ~191 ns |
| response decision (`Decision::Allow`) | ~1 ns |

Most of the cost is content inspection over headers and URI. For a route that
needs no per-request inspection, the compiled allowlist removes that cost while
keeping the always-on policy gates.

## Architecture

```
proxy::handle_request
  ├─ protocol version / framing / auth / WebSocket / WebTransport
  ├─ classify_request
  └─ WafEngine::fast_allow(method, uri, headers, client_ip, body_size, is_end_stream)
       ├─ route trie (exact method bit + exact path bytes)
       ├─ bodyless guard (no query, no body, no framing/encoding/upgrade)
       ├─ protocol-content guard (gRPC/GraphQL content types fall through)
       ├─ pass 1: every enabled rule must be Skip or Gate
       │           (any custom/unknown rule -> FallThrough)
       └─ pass 2: always-on gates
                    RequestSizeRule, MethodRule, RateLimiter,
                    GlobalRateLimiter, Adaptive/BurstRateLimiter,
                    GeoBlockingRule
```

`fast_allow` is also called at the top of `WafEngine::evaluate`,
`fast_evaluate` and `evaluate_shared`, so embedders that do not use the proxy
hook get the same behaviour. The proxy hook runs before `into_parts` and before
the body read, which is what removes the context construction and clone cost.

### Trie

`src/waf/fast_allow.rs` compiles `"METHOD /path"` entries into a byte trie:

* one `u16` method mask per terminal node (GET, HEAD, POST, PUT, DELETE,
  OPTIONS, PATCH, TRACE, CONNECT);
* sorted children, binary search at branching nodes and a single-child fast
  path;
* no allocation and no hashing at lookup time.

Path matching is byte-exact: no prefix, wildcard, trailing-slash folding,
percent-decoding or case folding. A query string never matches.

## Configuration

```toml
[waf.fast_allow]
enabled = false                 # default: off
routes = ["GET /health", "GET /ready", "GET /metrics"]
allow_audit_sample_rate = 0.0   # 0.0 = no allow audit; blocks always audited
```

`Config::validate` rejects:

* `enabled = true` with an empty route list;
* a route that is not `"METHOD /path"`, uses a non-standard method, has a
  query/fragment/whitespace, contains `..`, or is longer than 8192 bytes;
* duplicate routes;
* more than 4096 routes;
* `allow_audit_sample_rate` outside `0.0..=1.0`.

`WafEngine::with_config` also rejects invalid entries defensively (and disables
the allowlist with a warning) if a caller skipped validation.

## Soundness

The fast path is an explicit **route-scoped WAF exclusion for bodyless
requests**, not a generic cache:

1. **Only listed routes match.** Everything else falls through to the full
   engine byte-for-byte.
2. **Only bodyless, query-free requests match.** A query, a non-empty body, a
   `Transfer-Encoding`, a non-zero `Content-Length`, a `Content-Encoding`, an
   `Upgrade`, a gRPC/GraphQL content type or a streaming gRPC request never
   matches. These are the surfaces where inspection can block.
3. **Only inspection rules are skipped.** `ContentInspectionRule`, the Coraza
   rule and the SQLi/XSS rule opt into `Skip`. Every stateful policy gate runs
   on the fast path: request size, method, per-IP/global/adaptive/burst rate
   limits and geographic blocking.
4. **Unknown rules force a fall-through.** `WafRule::fast_allow_policy`
   defaults to `FallThrough`, so a custom rule can never be silently skipped.
5. **Blocks are audited.** A gate rejection returns the triggering rule and
   the proxy emits the normal audit event. Allows skip audit construction by
   default (`allow_audit_sample_rate = 0.0`), matching the existing
   `min_threat_level = "medium"` behaviour where allow events were constructed
   and then discarded.

The trade-off is deliberate and documented: a listed route is exempt from
header/URI/body inspection. Operators must only list routes whose requests are
known not to need inspection (health, readiness, metrics, static probes). This
is equivalent to a ModSecurity location exclusion, but it is opt-in, exact,
route-scoped and default-off.

### Audit short-circuit

`SecurityEventLogger::log_event` now determines the threat level **before**
constructing the event. With the default `min_threat_level = "medium"`, allow
events (level `low`) return without a UUID, timestamp, method/path strings or
`HashMap`. This is a behaviour-preserving optimisation for the full path and
removes ~0.3 µs from every allowed request.

### Rate-limit cleanup

`RateLimiter` used `rand::random::<f32>() < 0.01` on every evaluation to trigger
expired-bucket cleanup. The fast path replaces that with a deterministic
`AtomicU64` counter (once per 100 calls), removing an RNG draw from the gate
path without changing the cleanup rate materially.

## Tests

* `src/waf/fast_allow.rs`: route parsing, exact matching, bodyless guards,
  protocol content types, disabled default, audit sampling default.
* `src/waf/mod.rs`: disabled-by-default, exact method/path, body/query/
  framing/encoding fall-through, parity (a malicious query on a listed route
  still blocks), stateful rate-limit gate still blocks, custom rule falls
  through.
* `src/config.rs`: default-off, empty routes, invalid/duplicate routes,
  out-of-range sample rate.
* `src/metrics.rs`: fast-allow counters are rendered.

## Measured results

### Latency and throughput

`bodyless-bench --concurrency 1,16,64 --requests 5000 --warmup 500`, pinned to
four CPUs, on the loaded reference host:

| path | c | p50 | p95 | p99 | RPS |
|---|---:|---:|---:|---:|---:|
| `evaluate_shared` | 1 | 4.65 µs | 5.10 µs | 5.58 µs | 207 059 |
| `evaluate_shared` | 16 | 4.83 µs | 5.32 µs | 6.19 µs | 392 821 |
| `evaluate_shared` | 64 | 5.03 µs | 6.37 µs | 18.69 µs | 538 124 |
| `fast_evaluate` | 1 | 4.50 µs | 4.82 µs | 5.19 µs | 215 590 |
| `fast_evaluate` | 16 | 5.07 µs | 18.22 µs | 20.34 µs | 473 235 |
| `fast_evaluate` | 64 | 5.18 µs | 7.03 µs | 19.08 µs | 616 942 |
| **`fast_allow`** | **1** | **380 ns** | **406 ns** | **476 ns** | **2 337 055** |
| **`fast_allow`** | **16** | **632 ns** | **794 ns** | **2.45 µs** | **3 920 311** |
| **`fast_allow`** | **64** | **632 ns** | **775 ns** | **1.35 µs** | **4 116 652** |

The compiled path is ~12× lower p50 than the full path at c=1 and keeps the
c=1 p99 below 0.5 µs. At c=16/64 the p50 is ~0.63 µs; the extra ~0.25 µs over
the 0.38 µs single-threaded decision is Tokio scheduling and rate-limit lock
contention on four pinned CPUs, not additional per-request work. The p99 at
c=16/64 is dominated by host contention (other builds on the shared host);
the best observed c=64 p99 was 0.94 µs. Throughput at c=64 is ~4.1 M
decisions/s on four pinned CPUs; the full path is ~0.54 M/s.

### Component profile

`bodyless-bench --profile --samples 10000` (single-threaded nanoseconds):

| component | p50 | p95 | p99 | mean |
|---|---:|---:|---:|---:|
| context construction | 158 ns | 165 ns | 169 ns | 168 ns |
| admission (cheap) | 32 ns | 35 ns | 36 ns | 35 ns |
| metrics (request+allow) | 31 ns | 34 ns | 34 ns | 32 ns |
| `fast_evaluate` (no allow audit) | 3.13 µs | 3.26 µs | 3.59 µs | 3.20 µs |
| `evaluate_shared` (full) | 3.15 µs | 3.29 µs | 3.53 µs | 3.19 µs |
| dispatch (0 rules) | 83 ns | 87 ns | 100 ns | 88 ns |
| **`fast_allow` (compiled route)** | **348 ns** | **356 ns** | **406 ns** | **356 ns** |
| `fast_allow` (no rate gates) | 191 ns | 198 ns | 204 ns | 197 ns |
| audit (full − fast) | 7 ns | 14 ns | 0 ns | 4 ns |

The two rate-limit gates account for ~157 ns of the 348 ns fast path. The
compiled trie, bodyless/header checks, size/method gates and metrics account
for the remaining ~191 ns. The allow audit delta is ~7 ns because the event
logger now checks the threat level before constructing anything.

## Limitations

* The allowlist skips inspection for the listed route by design; it is not a
  proof that an arbitrary request to that route is benign. Keep the list
  minimal and route-specific.
* The fast path does not bypass authentication, framing validation, protocol
  version checks, WebSocket/WebTransport handling or the always-on gates.
* Rate limits still consume a token per fast-allowed request, so a listed route
  cannot be used to evade the configured rate policy.
* The harness measures the in-process decision path, not loopback proxy or TLS
  overhead; use `bench-subms` and the load harness for end-to-end numbers.
