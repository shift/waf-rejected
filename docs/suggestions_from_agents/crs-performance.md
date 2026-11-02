# OWASP CRS evaluation cost: profile, safe wins, and ranked next steps

**Status:** research report + one implemented sidecar change.
**Branch:** `perf/crs-cost` (worktree `.worktrees/crs-perf`), based on `main` @ `cf9ba16`.
**Date:** 2026-11-02
**Engine:** Coraza `v3.3.3`, OWASP CRS `4.14.0` (vendored bundle), paranoia level 1.
**Machine:** Intel i5-8400T (6 cores, 1.7/3.3 GHz), Linux, Go 1.24.5, `CGO_ENABLED=0`.
**Shared host:** other agents were compiling Rust during these runs, so load average
moved between 2 and 12. All A/B numbers below are **process CPU time**
(`getrusage(RUSAGE_SELF)`), pinned with `taskset`, interleaved, and reported as the
median of 6–9 evaluations or the min of two rounds. Ratios are reliable; absolute
values are indicative only.

## TL;DR

CRS scanning is still **99.8 %** of request cost, and it is **byte-linear at
~7.4 µs per inspected byte** (~135 KiB/s per core) with no single rule above ~11 %.
Nothing in the *engine configuration* makes benign body inspection cheaper:
argument limits are bypassed for request bodies by this Coraza version, audit/debug
are already effectively off, and GC/GOMAXPROCS only move the tail.

The one safe, measurable win is **CRS phase-1 early blocking** (`tx.early_blocking=1`,
CRS rule 900120). It does not change a single decision on the SQLi/XSS/LFI/RCE
corpus, costs nothing on benign traffic, and removes the body scan entirely for
requests that are *already blocked* by phase-1 rules — a cheap CPU-amplification
vector for an attacker (scanner User-Agent + 60 KiB body: **493 ms → 0.26 ms**).
It is implemented in the native sidecar behind `--early-blocking` (default on).

Everything else that actually reduces the dominant cost is either a **policy
knob** (cap inspected bytes), an **upstream/engine change** (literal prefilter,
Hyperscan), or a **wasm module rebuild**. Those are ranked with their security
tradeoffs at the end.

---

## 1. Method

Two harnesses, both out of tree:

1. **Uninstrumented harness** — a Go test in a copy of `native/coraza-sidecar`
   that builds the real CRS bundle (`WithRootFS` over
   `wasm/coraza_reactor/rules/crs/rules`, same preamble as production), drives
   `ProcessURI` → `AddRequestHeader` → `ProcessRequestHeaders` →
   `WriteRequestBody` → `ProcessRequestBody`, and measures **CPU time** around
   the transaction. Variants are selected with environment variables so each
   variant runs in a fresh process (no cross-engine cache/GC contamination).
2. **Instrumented Coraza** — a research-only copy of the vendored engine with
   `time.Now()` accounting around each rule/variable evaluation, split into
   transform time and operator time, plus a match counter. Overhead is ~1–2 % of
   total and is not removed from the shares.

Bodies are `application/x-www-form-urlencoded` (`data=` + `A` repeated), the
shape used in the earlier report, plus a 16/64/256/1000-argument form and a
short attack corpus. The repository was not modified for measurement; the
instrumented vendor tree and harness live in `/tmp/opencode/crs-prof`.

Reproduce the size/variant tables:

```sh
nix develop -c bash -c '
  cd /tmp/opencode/crs-prof
  export GOOS=linux GOARCH=amd64 GOFLAGS=-mod=vendor
  MODE=sizes REPS=6 go test -run TestProfileSizes -count 1 -v .
  MODE=one VARIANT=base SHAPE=8k REPS=9 go test -run TestProfileOne -count 1 -v .
  MODE=one VARIANT=early_blocking SHAPE=scanner SIZE=8 REPS=9 \
    go test -run TestProfileOne -count 1 -v .
'
```

---

## 2. Profile

### 2.1 Cost is linear in inspected bytes

Benign urlencoded body, full CRS PL1, CPU-time median:

| inspected body | p50 CPU | µs / byte | allocations / request |
|---:|---:|---:|---:|
| 0 (no body) | 0.55 ms | — | ~0.4 MB (fixed) |
| 1 KiB | 7.92 ms | 7.73 | 464 KB / 2 144 |
| 2 KiB | 15.39 ms | 7.52 | — |
| 4 KiB | 32.66 ms | 7.97 | 635 KB / 2 176 |
| 8 KiB | 60.94 ms | 7.44 | 849 KB / 2 178 |
| 16 KiB | 121.26 ms | 7.40 | 1 511 KB / 2 370 |
| 60 KiB | 479.40 ms | 7.80 | — |

Slope from 1→8 KiB: **7.5 µs/byte**; 0→60 KiB is linear within 5 %. The same
slope applies to a query string: a 7 KiB URI with no body cost **52 ms**
(`ARGS_GET`), i.e. the cost tracks *inspected bytes*, not the body specifically.
The fixed cost (no body) is ~0.55 ms, of which ~0.2 ms is transaction setup and
phase 1.

Allocation slope: **~54 bytes allocated per inspected body byte** plus ~420 KB
fixed. That is ~54 body-sized copies per request: one per distinct CRS
transformation set whose result is not yet in the per-transaction transform
cache. Transform *time* is only 2–3 % (see 2.4), but the copies are what drives
GC pressure and tail latency.

### 2.2 Cost per rule file (family), 8 KiB single-arg body

Instrumented run, 8 reps, pinned, total 95.5 ms/req (shares are stable across
runs; absolute values move with host load):

| family (rule file) | ms/req | share | rules touched |
|---|---:|---:|---:|
| 932 RCE | 24.56 | 28.7 % | 81 |
| 942 SQLi | 22.33 | 26.1 % | 107 |
| 934 generic | 8.96 | 10.5 % | 38 |
| 941 XSS | 7.72 | 9.0 % | 159 |
| 921 protocol attack | 6.78 | 7.9 % | 32 |
| 933 PHP | 5.44 | 6.4 % | 67 |
| 944 Java | 4.77 | 5.6 % | 42 |
| 931 RFI | 2.33 | 2.7 % | 8 |
| 930 LFI | 2.09 | 2.4 % | 20 |
| 943 session fixation | 0.41 | 0.5 % | 11 |
| 920 protocol enforcement | 0.07 | 0.1 % | 47 |
| 901 / 949 / 905 / 911 / 913 / 922 | <0.1 | ~0 % | 65 |

This matches the earlier attribution (932 ~29 %, 942 ~21 %, 934 ~11 %, 921 ~10 %,
941 ~9 %). A second run under heavier load put 932 at 25.6 %, 942 at 17.7 %,
921 at 12.8 %, 934 at 12.3 %, 941 at 11.5 % — the ordering of the top five is
stable, individual shares move a few points.

The family ranking tracks **regex source volume**: `REQUEST-932` contains 43
`@rx` operators totalling **110 KB** of pattern text (the four biggest are
6.2–11.0 KB each); `REQUEST-942` has 61 operators / 28 KB; `REQUEST-941` 30 /
13 KB. Go's RE2 simulation cost grows with the number of NFA states, so the
families with the largest alternations dominate.

### 2.3 Cost per target

| target | ms/req | share | rules |
|---|---:|---:|---:|
| `ARGS` | 78.24 | 91.4 % | 94 |
| `REQUEST_BODY` | 6.46 | 7.6 % | 7 |
| `ARGS_NAMES` | 0.33 | 0.4 % | 92 |
| `TX` | 0.17 | 0.2 % | 108 |
| `REQUEST_FILENAME` | 0.16 | 0.2 % | 40 |
| `REQUEST_HEADERS` | 0.09 | 0.1 % | 42 |
| `XML`, cookies, URI, method, protocol, files | <0.03 each | ~0 % | — |

`ARGS` is the whole game. `REQUEST_BODY` is scanned by only 7 rules but costs
7.6 % because it scans the raw 8 KiB body (and 921110 scans it *in addition to*
`ARGS`, so the same bytes are scanned twice). Response-only variables are never
populated (response body access is off) and cost nothing.

### 2.4 Top rules and transform overhead

Top 30 rule/variable pairs, 8 KiB benign body (no rule matched):

| rule | target | ms/req | share | transform % of rule | notes |
|---:|---|---:|---:|---:|---|
| 934100 | ARGS | 10.44 | 10.9 % | 8.4 % | Node.js injection |
| 932260 | ARGS | 6.12 | 6.4 % | 0 % | unix command (variant) |
| 932250 | ARGS | 6.04 | 6.3 % | 0 % | unix command (variant) |
| 932230 | ARGS | 5.13 | 5.4 % | 0 % | unix command (2–3 chars) |
| 932235 | ARGS | 5.05 | 5.3 % | 0 % | unix command (without evasion) |
| 921110 | ARGS | 3.59 | 3.8 % | 1.0 % | request smuggling |
| 921110 | REQUEST_BODY | 3.58 | 3.7 % | 11.6 % | same bytes scanned again |
| 942320 | ARGS | 3.27 | 3.4 % | 0 % | SQLi |
| 942550 | ARGS | 2.65 | 2.8 % | 3.3 % | SQLi |
| 942190 | ARGS | 2.19 | 2.3 % | 16.1 % | SQLi |
| 931110 | REQUEST_BODY | 2.06 | 2.2 % | 0.3 % | RFI |
| 930110 | ARGS | 2.00 | 2.1 % | 1.9 % | LFI |
| 933200 | ARGS | 1.95 | 2.0 % | 2.1 % | PHP wrapper |
| 944120 | REQUEST_BODY | 1.94 | 2.0 % | 0 % | Java |
| 941370 | ARGS | 1.86 | 1.9 % | 0.9 % | XSS |
| 942360 | ARGS | 1.85 | 1.9 % | 0 % | SQLi |
| 941160 | ARGS | 1.72 | 1.8 % | 0 % | XSS |
| 942240 | ARGS | 1.69 | 1.8 % | 0 % | SQLi |
| 944120 | ARGS | 1.56 | 1.6 % | 0 % | Java |
| 942230 | ARGS | 1.41 | 1.5 % | 0 % | SQLi |
| 933210 | ARGS | 1.37 | 1.4 % | 5.2 % | PHP |
| 932125 | ARGS | 1.37 | 1.4 % | 0 % | RCE |
| 941170 | ARGS | 1.33 | 1.4 % | 0 % | XSS |
| 942280 | ARGS | 1.18 | 1.2 % | 0 % | SQLi |
| 932130 | ARGS | 0.96 | 1.0 % | 0 % | RCE |
| 933140 | ARGS | 0.95 | 1.0 % | 0 % | PHP |
| 942170 | ARGS | 0.94 | 1.0 % | 0 % | SQLi |
| 941310 | ARGS | 0.93 | 1.0 % | 4.4 % | XSS |
| 932370 | ARGS | 0.85 | 0.9 % | 0 % | RCE |
| 941400 | ARGS | 0.84 | 0.9 % | 0 % | XSS |

Aggregate: **transform 2.7 %, operator 96.8 %** (the remainder is per-variable
bookkeeping). The four big 932 rules are **23.4 % combined** (25–29 % in other
runs); the top 30 pairs are ~80 %. No single rule exceeds 11 %, and there is no
catastrophic backtracking: Go's `regexp` is RE2-based and linear-time.

Two facts about those four rules matter for the ranking:

- `regexp.Regexp.LiteralPrefix()` returns `""` for all four (and for 932231 and
  932236). They start with `(?i)` and a giant alternation, so Go's literal-prefix
  fast path never engages; each byte is run through thousands of NFA states.
- They share a large common prefix structure (`b…u…s…y…b…o…x|…`), i.e. a
  multi-pattern engine or a required-literal prefilter could reject a benign
  body once instead of four times.

### 2.5 Argument-count scaling

8 KiB body split into N arguments (same total bytes):

| args | p50 CPU |
|---:|---:|
| 16 | 58.0 ms |
| 64 | 85.3 ms |
| 256 | 90.3 ms |
| 1000 | 165.8 ms |

Per-argument fixed cost adds ~50–80 % over a single argument at 64–256 args and
~2.8× at 1000 args. This is the vector a `SecArgumentsLimit` would cap — see
experiment E2: in this Coraza version it does not.

---

## 3. Experiments

### E1 — CRS early blocking (`tx.early_blocking=1`, rule 900120): **safe win, implemented**

What it does: CRS rule 949111 denies in phase 1 when the phase-1 anomaly score
already reached the threshold. The body phase is then never executed. CRS
documents the only downside: phase-2 alerts for a request that is already
blocked are not generated.

Benign 8 KiB body (no phase-1 score): **no change**

| body | phase-2 only | early blocking | delta |
|---:|---:|---:|---:|
| 1 KiB | 7.74 ms | 7.73 ms | ~0 |
| 4 KiB | 29.34 ms | 29.36 ms | ~0 |
| 8 KiB | 59.69 ms | 59.91 ms | +0.4 % (noise) |
| 16 KiB | 121.33 ms | 120.39 ms | −0.8 % (noise) |
| 60 KiB | 450.44 ms | 463.40 ms | +2.9 % (noise, min-of-2) |

Phase-1-blocked attack with the same body (scanner User-Agent, 913100 gives the
phase-1 critical score): **the body is never scanned**

| body | phase-2 only | early blocking | speedup |
|---:|---:|---:|---:|
| 1 KiB | 7.87 ms | 0.26 ms | 30× |
| 4 KiB | 29.76 ms | 0.26 ms | 115× |
| 8 KiB | 60.83 ms | 0.28 ms | 217× |
| 16 KiB | 119.87 ms | 0.29 ms | 413× |
| 60 KiB | 493.15 ms | 0.26 ms | **1 897×** |

Decision parity: the same request returns `403` either way. Only the
interruption rule changes (949111 in phase 1 vs 949110 in phase 2), so phase-2
telemetry for already-blocked requests is lost. The `TestEarlyBlocking*` tests
in `native/coraza-sidecar/early_blocking_test.go` run 15 attack payloads and 4
benign payloads in both query and body form through both configurations and
require identical decisions.

Security impact: none on block/allow. Operational impact: fewer phase-2 rule
hits in audit data for requests blocked by phase 1. This also removes a
CPU-amplification vector: today an attacker can make the WAF scan an arbitrary
body (up to `--max-body`) with a request that is guaranteed to be blocked.

### E2 — `SecArgumentsLimit`: **no effect on request bodies in Coraza 3.3.3**

Measured with 256-argument 8 KiB bodies: `SecArgumentsLimit 100/64/16/8` changed
cost by less than noise (85–104 ms, vs 94 ms baseline) and the `ARGS` target
time was unchanged (130–146 ms), i.e. the limit did not reduce the number of
values scanned.

Root cause: `internal/bodyprocessors/urlencoded.go` (and `json.go`,
`multipart.go`) write directly into the `ARGS_POST` collection with
`argsCol.Set(k, vs)`, bypassing `Transaction.AddPostRequestArgument`, which is
where `checkArgumentLimit` lives. The limit is only enforced for query-string
arguments (`ExtractGetArguments` → `AddGetRequestArgument`). This is a Coraza
bug/limitation, not a CRS one; it should be reported upstream. Until it is
fixed, the knob cannot contain the many-POST-parameters vector.

### E3 — `SecRequestBodyLimit` / `ProcessPartial` / `Reject`: **linear, policy only**

8 KiB body, varying the inspected limit:

| setting | inspected bytes | p50 CPU | effect |
|---|---:|---:|---:|
| default (64 KiB limit) | 8 KiB | 60.9 ms | baseline |
| limit 4 KiB, `ProcessPartial` | 4 KiB | 30.1 ms | −50 % |
| limit 2 KiB, `ProcessPartial` | 2 KiB | 15.1 ms | −75 % |
| limit 1 KiB, `ProcessPartial` | 1 KiB | 8.0 ms | −87 % |
| limit 1/2/4 KiB, `Reject` (8 KiB body) | 0 | 0.26 ms | −99.6 %, returns 413 |

Because cost is linear, the saving is exactly `min(body, limit) / body`. The
`ProcessPartial` mode inspects only the prefix and lets the rest through
uninspected; `Reject` returns `413` and forwards nothing. Both are **policy
decisions**: `ProcessPartial` silently loses detection past the cap, `Reject`
breaks large uploads/forms. They are not safe defaults and were not changed.
The sidecar already rejects bodies above `--max-body` (default 64 KiB), which is
why a 60 KiB body costs 479 ms rather than more.

### E4 — Removing duplicate / never-matching / response-only rules: **no safe candidates**

- **Response-only targets in the request phase:** none. `grep '^SecRule.*RESPONSE_'`
  over all `REQUEST-*.conf` returns nothing; response rules are not in the
  request bundle. `SecRuleUpdateTargetById` has nothing to drop, and the
  variables that are empty (`XML`, `REQUEST_COOKIES`) cost ~0.02 ms combined
  because evaluating an empty collection is free.
- **Exact duplicate operator+target lines:** 7 exist (e.g. the session-id
  `ARGS_NAMES` regex used by two session-fixation rules, `REQUEST_HEADERS:Accept
  "@rx ^$"`). Each belongs to a different rule ID with its own anomaly score
  and log message, so deleting one changes scoring/telemetry. Not safe.
- **Rules that never match on the benign corpus:** all of them — the benign body
  matches nothing, which is the point. "Never matched in this test" is not
  evidence of redundancy.

### E5 — Go runtime and Coraza logging knobs: **no steady-state effect**

| knob | result |
|---|---|
| `GOGC=100/200/400/600/off` | min CPU 60.1–63.6 ms; no steady-state difference. GC affects the *tail* (a collection landing mid-evaluation), not the work. `GOGC=off` did not help and removes the memory bound. Keep `600` + `SetMemoryLimit(192 MiB)`. |
| `GOMAXPROCS=1/2/6` | 59.5–60.2 ms single-request; no effect. Keep the default (lowering it would serialise concurrent evaluations). |
| `SecAuditEngine Off` | no measurable delta. Audit is already only built when a transaction is marked for audit, and no audit writer is configured. |
| `SecDebugLogLevel 0` | no delta; the default is already 0 and no debug logger is installed. |
| `SecResponseBodyAccess Off` | already set in both sidecar and reactor preamble. |

### E6 — Allocation / transform observations

`BenchmarkEvaluate` reports 849 KB and 2 178 allocations for 8 KiB, scaling at
~54 B per body byte. The instrumented engine shows transforms are only 2.7 % of
time because results are cached per `(arg pointer, variable, transform set)`.
The allocations come from the first evaluation of each distinct transform set:
~54 sets each copy the 8 KiB value. Reducing that would require engine changes
(cache sharing, zero-copy transforms), not configuration.

---

## 4. Faster regex path (research only, not integrated)

**Important premise: Coraza already uses RE2.** `github.com/corazawaf/coraza/v3`
compiles `@rx` with Go's `regexp`, which is the RE2 linear-time algorithm. There
is no backtracking and no ReDoS exposure. "Use RE2 bindings" is therefore not a
speedup — it is already the engine. The realistic options are:

### 4.1 Required-literal prefilter (best value, safe by construction)

Before running an `@rx`, extract a set of literals that *must* occur for the
regex to match (e.g. one of the ~200 command names in 932230/235/250/260, the
`<script`/`onerror` tokens in 941, the SQL keywords in 942). Run one
Aho-Corasick pass over the value; skip the regex if none is present.

- **Expected gain:** the four 932 rules are 23–29 % of benign cost and have no
  literal prefix; 932 alone is 25–29 %. A prefilter over 932+942+941 (64 % of
  cost) could plausibly remove **25–40 %** of benign body time. This is the
  ceiling; extraction must be conservative (only truly required literals).
- **Safety:** no false negatives *if* the literal set is derived correctly; a
  wrong extraction creates a bypass. It needs a verifier (differential testing
  against the full corpus plus fuzzing) before it can be trusted.
- **Complexity:** medium — a Coraza patch or a CRS toolchain change. Must be
  validated per rule and per transformation (the literal must be present in the
  *transformed* value). Cannot be done with `SecRuleUpdateTargetById`.
- **Licensing:** none (Apache-2.0 code).

### 4.2 Hyperscan / Vectorscan via cgo (biggest ceiling, biggest cost)

Compile all `@rx` patterns (per transform set) into one Hyperscan database and
map matches back to rule IDs.

- **Expected gain:** 2–4× on regex-heavy families, maybe **20–40 %** overall on
  benign bodies; more on the 932 family. Hyperscan's literal acceleration is
  exactly what these alternations need.
- **Complexity / risk:** high. Requires `cgo` (breaks the current
  `CGO_ENABLED=0` static build and the Nix sandbox), an x86-only dependency,
  per-variable scratch management, and partial capture support (`capture` and
  `logdata` are used by many CRS rules). It cannot be used in the WASI reactor
  at all, so native and wasm would diverge in engine implementation.
- **Licensing:** Hyperscan is BSD-3-Clause (compatible); Vectorscan is the
  maintained fork. Both add a native library to the supply chain and the
  container image.
- **Verdict:** not worth it until the literal prefilter has been tried; the
  prefilter captures much of the same benefit without cgo.

### 4.3 Precompiled pattern sets

CRS already ships `@pmFromFile` data for some rules. Converting the biggest
`@rx` alternations to `@pmFromFile` + a small verifier regex is a CRS-toolchain
change, not a runtime one. It would be the most maintainable form of 4.1, but it
changes rule semantics and must come from upstream CRS or a local rule fork with
its own test corpus. Not a safe local edit.

---

## 5. Ranked recommendations

| # | Change | Expected gain (benign 8 KiB) | Detection impact | Effort / owner | Status |
|---:|---|---|---|---|---|
| 1 | **Phase-1 early blocking** (`tx.early_blocking=1`) | 0 % benign; **30–1 900×** on requests already blocked in phase 1 (linear in body size) | none on allow/block; phase-2 alerts for already-blocked requests are not emitted | one line, sidecar flag | **implemented** (native). Reactor parity needs a module rebuild — product decision |
| 2 | **Required-literal prefilter for big `@rx` rules** | **25–40 %** (932+942+941 are 64 % of cost; top 4 rules 23–29 %) | none if extraction is proven; a bad extraction is a bypass | medium, Coraza/upstream | research; needs differential corpus + fuzz proof |
| 3 | **Hyperscan/Vectorscan via cgo** | 20–40 % overall, 2–4× on regex families | none if pattern-equivalent; capture semantics risk | high, native only, cgo + BSD-3 dependency | research; not recommended before #2 |
| 4 | **Inspect-body cap** (`SecRequestBodyLimit`, `ProcessPartial` or `Reject`) | linear: −50 % at 4 KiB, −87 % at 1 KiB, −99.6 % with `Reject` | **explicit**: `ProcessPartial` leaves the tail uninspected; `Reject` breaks large forms/uploads | config policy | product decision; not changed |
| 5 | **Fix `SecArgumentsLimit` for POST bodies** (upstream Coraza) | up to ~2.8× on 1000-arg bodies, 0 on normal forms | none (cap only kicks in above the limit) | small upstream patch | upstream bug; not changed |
| 6 | **GC / GOMAXPROCS / audit / debug tuning** | 0 % steady state; tail only | none | config | measured, no change |
| 7 | **Remove duplicate/response-only rules** | ~0 % | loses scoring/telemetry | — | rejected (no safe candidates) |
| 8 | **Move body inspection out of wasm** | 5–6× vs wasm | none | already available as the native sidecar; keep wasm opt-in | existing |

### Implemented vs product decision

**Implemented (this branch):** the native sidecar enables CRS rule 900120 by
default (`--early-blocking=true`), with an opt-out flag, tests, and docs. No rule
was weakened, no limit default changed, and the full SQLi/XSS/LFI/RCE corpus
still blocks.

**Needs a product decision:**

- Apply the same `SecAction 900120` to `wasm/coraza_reactor/main.go` and rebuild
  the 20 MB WASI module. The build is reproducible
  (`./scripts/build-coraza-reactor.sh --verify`), but it changes a shipped
  binary and its digest; the win is large for the default (wasm) backend on
  blocked traffic, and the telemetry caveat is the same.
- Any inspected-body cap (recommendation #4): choose `Reject` + documented size
  policy, not `ProcessPartial`.
- Sponsoring the literal prefilter (#2) or Hyperscan (#3): both need an owner
  and a detection-equivalence test corpus before they can ship.

---

## 6. Caveats

- The host is shared and throttles; absolute numbers moved up to 2.5× between
  runs. Every A/B comparison was pinned, interleaved and repeated; the ratios
  (especially early blocking, which is ~0.26 ms regardless of body size) are far
  outside the noise.
- CPU time includes Go GC worker time, so it can exceed wall time for a single
  request. That is the right metric for throughput and is consistent across
  variants.
- Per-rule attribution comes from an instrumented *copy* of Coraza v3.3.3; the
  committed vendor tree is untouched. The instrumentation adds ~1–2 %.
- The wasm numbers in the earlier report (`docs/suggestions_from_agents/coraza-body-performance.md`)
  still apply: wasm is ~5.2× native on the same workload. Nothing in this report
  changes that; it explains where the native 1× goes.
- The sidecar's `--max-body` (64 KiB) is the only bound on inspected bytes
  today. The proxy's `waf.coraza.max_payload_bytes` must stay at least as large.

## 7. Files changed

- `native/coraza-sidecar/main.go` — `--early-blocking` flag (default true);
  `newEngine` takes the flag and prepends CRS rule 900120.
- `native/coraza-sidecar/main_test.go` — test server helper takes the flag.
- `native/coraza-sidecar/early_blocking_test.go` — decision-parity corpus and
  phase-1/phase-2 interruption test.
- `native/coraza-sidecar/bench_test.go` — `BenchmarkEvaluateEarlyBlocking`.
- `docs/coraza-native-sidecar.md` — flag and performance note.
- `docs/suggestions_from_agents/crs-performance.md` — this report.
- `CHANGELOG.md`, `current-task.md` — release/task log.
