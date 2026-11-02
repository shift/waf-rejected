# Allow-verdict cache (research prototype)

**Status:** experimental, non-default feature `allow-cache`, disabled by default.
**Scope:** memoise only the `Allow` verdict of pure content rules for a short
TTL. Blocks, rate limits and anomaly verdicts are never cached.
**Branch:** `research/allow-cache`.

This document is the design review artifact for the prototype. It records the
canonicalisation rules, the injectivity argument, the threat model, the measured
replay results, and the conditions under which the cache must stay disabled.

## Why

CRS is byte-linear and dominates request cost: the native sidecar costs about
7.4 µs per inspected byte (1 KiB ≈ 7.6 ms, 8 KiB ≈ 61 ms on the reference
host), and the WASI reactor is several times slower. Benign traffic that repeats
the same request is common (health checks, polling, retries, static API calls),
so a short-lived allow cache can remove almost all of that cost for the repeated
subset without changing what is inspected on a miss.

The cache is deliberately **not** a default. It is an opt-in, per-deployment,
optionally per-route optimisation with a documented threat model.

## Architecture

```
proxy
  └─ WafEngine::evaluate / evaluate_shared / fast_evaluate
       ├─ admission classification (always runs; a hit still takes a permit)
       ├─ protocol pre-checks: GraphQL, then gRPC (always run; may strip body)
       ├─ init-failure gate (fail-closed)
       ├─ rules_with_cache
       │    ├─ route opt-in check
       │    ├─ canonical key (build_key)
       │    ├─ cache hit  -> rules_core_filtered(skip_cacheable = true)
       │    └─ cache miss -> rules_core(full chain); insert only on Allow
       └─ finish (audit event, identical to a normal allow)
```

New pieces:

- `src/waf/allow_cache.rs` — key construction, bounded sharded cache, metrics.
- `WafRule::cacheable()` — **defaults to `false`**. Only the Coraza backend
  (`WasmReactorRule`, `NativeCorazaRule`) and the built-in
  `ContentInspectionRule` opt in. Custom rules run on every request.
- `[waf.allow_cache]` configuration (default `enabled = false`).
- `waf_allow_cache_*` Prometheus metrics.

### What a hit skips, and what it never skips

A hit skips only rules whose verdict is a pure function of the canonical
request content. It still runs:

- admission control (the request is classified before the cache is consulted,
  so a hit cannot bypass heavy-inspection capacity accounting),
- the GraphQL and gRPC protocol pre-checks (so protobuf/GraphQL content is
  inspected on every request; only the subsequent CRS rule is memoised),
- the WASM/AI stages in builds that have them (they run before
  `rules_with_cache`),
- every non-cacheable rule: request-size and method checks, per-IP and global
  rate limiters, GeoIP rules, and any custom rule (the trait default).

This is a stronger integration than "return Allow immediately": a cached allow
can never bypass a stateful rule. The test
`cache_hit_cannot_bypass_a_stateful_block` changes a rate-limit rule to blocking
after an allow has been cached and asserts that the next request is still
blocked.

### Metrics and audit

- A hit still calls `finish`, so it emits exactly the same audit event as a
  normal allow.
- Request-level `waf_allowed_total`/`waf_blocked_total` behaviour is unchanged.
- `waf_coraza_evaluations_total` counts **actual** CRS evaluations, so it drops
  on hits. This is intentional; use the cache hit ratio to interpret it.
- New metrics: `waf_allow_cache_hits_total`, `waf_allow_cache_misses_total`,
  `waf_allow_cache_evictions_total`, `waf_allow_cache_expired_total`,
  `waf_allow_cache_skipped_total`, `waf_allow_cache_invalidations_total`,
  `waf_allow_cache_entries`.

## Configuration

```toml
[waf.allow_cache]
enabled = true          # non-default; opt in per deployment
ttl_secs = 30           # short by design
max_entries = 8192      # hard memory bound (no request bytes are stored)
max_body_bytes = 65536  # bodies above this are evaluated but never cached
routes = ["/api/v1"]    # optional path prefixes; empty = every route
```

Route prefixes match on a `/` boundary: `/api/v1` matches `/api/v1` and
`/api/v1/items`, never `/api/v1x`. `enabled = false` (the default) leaves the
engine byte-for-byte on the existing path.

## Canonicalisation rules

The key is a keyed hash of a strictly ordered, length-prefixed encoding. Every
normalisation is listed here; the default is **no normalisation**.

| Field | Encoding | Normalisation |
|---|---|---|
| Key version | `u8` | Constant `1`. |
| Policy generation | `u64` | Hash of the full `[waf]` config plus ordered rule names/enabled state. |
| Method | length-prefixed exact bytes of `Method::as_str()` | None. Hyper already canonicalises standard methods to uppercase; extension methods keep their exact case. HTTP methods are case-sensitive, so case folding would be lossy. |
| URI | length-prefixed exact bytes of `Uri::to_string()` | None. No percent-decoding, no dot-segment removal, no case folding, no query reordering, no trailing-slash folding. This is exactly the string sent to the Coraza payload. |
| HTTP version | length-prefixed exact bytes | None (`"1.1"`, `"2"`, `"3"` as set by the proxy). |
| Body presence | `u8` (`0`/`1`) | Distinguishes `None` from `Some(empty)`. |
| Body length | `u64` | Exact captured length. |
| Body bytes | length-prefixed exact bytes | None. Over `max_body_bytes` the request is not keyed at all. |
| Declared body size | `u8` presence + `u64` | Exact `RequestContext::body_size`. |
| Header count | `u64` | Number of distinct header names. |
| Header name | length-prefixed lowercase bytes | Hyper `HeaderName` is already lowercase. Names are sorted by lowercase form. |
| Header value count | `u64` | Per name; distinguishes one value from duplicate values. |
| Header values | length-prefixed exact bytes | None. No whitespace trimming, no comma splitting, no UTF-8 lossy conversion. Duplicate value order is preserved (the Coraza payload preserves it). |

Explicitly **not** in the key:

- `client_ip`. No memoised rule reads it: the Coraza payload does not send a
  remote address, and the built-in content inspector only reads method, URI,
  headers and body. Every IP-dependent rule (GeoIP, per-IP rate limiting) is
  non-cacheable and runs on a hit. If a future Coraza rule gains a
  `REMOTE_ADDR` target, the cache must be disabled or `client_ip` added to the
  key.
- `timestamp`. The memoised rules are pure; time-dependent rules must be marked
  non-cacheable.

### Header allowlist

`CRS_TARGETED_HEADERS` in `src/waf/allow_cache.rs` documents the headers that
OWASP CRS 4.14 request rules explicitly target (`User-Agent`, `Referer`,
`Cookie`, `Host`, `Content-Type`, `Content-Length`, `Transfer-Encoding`,
`Authorization`, `X-Forwarded-For`, etc.). The key deliberately hashes the
**complete** header set rather than filtering to that list: generic
`REQUEST_HEADERS` rules and the built-in content inspector evaluate every
header value, so filtering would break injectivity. The allowlist is therefore a
lower bound for operators, not a filter.

## Injectivity argument

**Claim:** if two requests differ in anything the memoised rules evaluate, they
produce different canonical encodings, and therefore different keys except with
negligible probability.

1. **Encoding is injective.** The encoding is a fixed sequence of fields. Every
   variable-length field is prefixed with its exact length (`u64`); every
   fixed-width field has a fixed width; header multiplicity is carried by the
   name count and per-name value count. A prefix-free, length-prefixed encoding
   has a unique parse, so two different tuples cannot produce the same byte
   string. There is no concatenation ambiguity: `("ab","c")` and `("a","bc")`
   encode differently.
2. **The fields cover the memoised rules' inputs.** The Coraza payload is
   `{method, uri, http_version, headers, body, body_size, body_original_size,
   body_encoding}`. We hash method, URI, HTTP version, all headers, body
   presence/length/bytes and `body_size`. `body_original_size` is the captured
   body length (or `body_size` when no body), and `body_encoding` is a function
   of the body bytes (UTF-8 or base64), so both are determined by hashed fields.
   The built-in content inspector reads URI path/query, all headers and the
   body; all are hashed. For bodies above the cache cap we do not key at all,
   and when the WAF itself truncates inspection we still hash the full captured
   body (stricter than necessary: a suffix change causes a miss, never a false
   hit).
3. **Header canonicalisation preserves the evaluated set.** CRS treats request
   headers as a multimap of name → values; order across different names is not
   semantically meaningful. Sorting by name is therefore a canonicalisation of
   the same evaluated set. Duplicate values of one name keep their order and
   count, so smuggling-style `Content-Length`/`Transfer-Encoding` variants
   cannot collapse onto a clean key. Header names are case-insensitive in HTTP
   and hyper already normalises them.
4. **Keyed hash.** The encoding is hashed with SipHash-2-4 in 128-bit output
   mode under a per-process secret. Without the secret an adversary cannot
   construct a colliding encoding except by chance; a second-preimage costs
   about 2^128 work, and a birthday collision about 2^64 (the cache is bounded
   far below that).
5. **Policy generation.** Every key includes the generation hash. A rule or
   `[waf]` config change produces a new generation, and `invalidate()` clears
   the map. Old entries are unreachable even if a clear were missed.

The one assumption is that the memoised rule set is exactly "Coraza + content
inspector". The trait default (`cacheable = false`) makes any new or custom rule
non-cacheable unless it explicitly opts in, so the assumption fails safe.

## Cache policy

- **Only `Allow` is inserted.** `Block` and `RateLimit` never reach `insert`;
  the insert is guarded by `outcome.decision == Decision::Allow`.
- **TTL** defaults to 30 s; entries carry an `Instant` deadline and are removed
  on lookup after expiry (counted as `expired`, not a hit).
- **Bounded memory.** A fixed 16-shard map with per-shard capacity derived
  exactly from `max_entries`. Eviction is arbitrary hash-order within a shard
  (a sharded map, not a strict LRU). No request bytes are stored: an entry is a
  128-bit key plus an `Instant` and a generation, roughly 50–100 bytes with
  `HashMap` overhead. 8192 entries is well under 1 MiB.
- **Concurrency.** Each shard is a `parking_lot::Mutex`; counters are atomics.
  The cache is `Send + Sync` and shared by engine clones.
- **Invalidation.** `invalidate()` bumps the generation and clears all shards;
  `add_rule` after construction does the same; `set_generation()` clears on
  change. Runtime rule reloads (native sidecar or external feed) must call
  `WafEngine::invalidate_allow_cache()`.
- **Bounded cost.** Hashing is O(total key bytes) and linear. The body is capped
  at `max_body_bytes` (default 64 KiB) and over-cap bodies are not cached.
  Key construction allocates one `Vec<&HeaderName>` (bounded by
  `MAX_HEADER_NAMES = 256`) and one URI `String` (bounded by the HTTP URI
  limit); header values and the body are hashed from borrowed slices. There is
  no per-header-name allocation.

## Threat model

| Threat | Mitigation |
|---|---|
| Collision flooding / cache poisoning | 128-bit keyed SipHash-2-4 with a process-lifetime secret; bounded entries; only allows; TTL. An attacker cannot choose the key or force a collision without ~2^128 second-preimage work. |
| Request smuggling / duplicate headers | All header names, counts and exact values are hashed. One `Content-Length: 5` vs `6`, duplicate `Content-Length`, `Transfer-Encoding: chunked` vs absent, and duplicate-value order all produce different keys (tests). |
| Whitespace / percent-encoding / case tricks | No trimming, no percent-decoding, no case folding, no query reordering. `/a%2Fb` and `/a/b`, `%41` and `A`, `a b` and `a  b` all differ. |
| Malicious input mapped onto a clean key | The canonical encoding is injective over the memoised inputs; the only lossy step would be a normalisation, and none is applied to a semantic field. |
| Rate-limit bypass | Per-IP and global rate limiters are non-cacheable and run on every hit. A cached allow cannot bypass a later rate limit (test). |
| GeoIP / IP-reputation bypass | Geo rules are non-cacheable and run on every hit; `client_ip` is not sent to the memoised Coraza payload. If IP-based Coraza rules are added, add `client_ip` to the key or disable the cache. |
| Policy drift / stale allow after a rule change | Policy generation in every key, `invalidate()` on `add_rule`, and a short TTL. External reloads must invalidate explicitly. |
| Stale allow after a threat-feed update | The feed is not part of the config hash; operators must call `invalidate_allow_cache()` on feed update, and the 30 s TTL bounds the window. This is a documented condition for enablement. |
| Cache as a timing oracle | Hit/miss timing can reveal that an identical request was seen recently. The information is low value and the cache is per-process, but it is a reason to keep the feature opt-in. |
| Memory exhaustion | Hard `max_entries` bound, no request bytes stored, body cap. |
| Eviction churn | An attacker can churn entries and reduce the hit rate (a performance effect, not a bypass). |
| Cross-process sharing | The secret is process-lifetime and never persisted. Do **not** share the cache across processes or nodes without a key-management and replay design. |
| Fail-closed behaviour | The cache is consulted after the init-failure gate. A cache miss/failure never turns a block into an allow; the cache has no error path that returns `Allow`. |

## Measured replay results

Harness: `examples/allow_cache_bench.rs`.

```sh
cargo run --release --example allow_cache_bench \
  --features wasm-reactor,allow-cache
```

Trace: 8 unique POST requests per body size, 3 header-order permutations and 2
query-parameter permutations per unique request, warmed once and replayed twice.
`ttl = 300 s` for the run (the shipped default is 30 s). The query permutations
are distinct keys by design, so they miss on the first replay pass and hit on the
second. Header-order permutations hit. Hit/miss samples are classified from the
cache counters around each full `WafEngine::evaluate` call (admission,
pre-checks, key construction, lookup, non-cacheable rules, audit).

WASM Coraza backend, release build, shared host (other agents were running; the
miss numbers are noisy — the 4 KiB miss p50 is higher than the 8 KiB uncached p50
on this host):

| Body | Hit rate | Hit p50 | Miss p50 | Cached overall p50 | Cached overall p95 | Uncached p50 | Uncached p95 |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 KiB | 80.0 % | 8.3 µs | 471.62 ms | 8.5 µs | 527.59 ms | 543.16 ms | 942.26 ms |
| 4 KiB | 80.0 % | 4.5 µs | 3 025.02 ms | 5.2 µs | 3 237.71 ms | 1 887.98 ms | 2 732.06 ms |
| 8 KiB | 80.0 % | 6.8 µs | 2 877.48 ms | 7.3 µs | 3 035.59 ms | 2 889.39 ms | 6 720.93 ms |

Interpretation:

- The **hit path is single-digit microseconds** and includes the full engine
  call, not just the map lookup. The uncached path is three orders of magnitude
  slower on this host and is byte-linear.
- The overall p95 is a miss (20 % of the trace), which is the expected shape:
  the cache removes cost for repeats, not for first-seen or semantically
  distinct requests.
- On the reference host in `docs/suggestions_from_agents/crs-performance.md`,
  uncached CRS is ~7.4 µs/byte (1 KiB ≈ 7.6 ms, 4 KiB ≈ 30 ms, 8 KiB ≈ 61 ms).
  A ~5 µs hit path there implies roughly 1 500×–12 000× lower latency for
  repeats. Those are projections, not measurements from this run.

### Native comparison

The replay harness accepts `WAF_BENCH_BACKEND=native` (with
`--features coraza-native` and a running sidecar). It was **not** run in this
session because the example had to be rebuilt with `coraza-native` and the
available sidecar is on a different socket; the native uncached baseline is the
existing one in `docs/suggestions_from_agents/crs-performance.md` (~7.4 µs per
inspected byte, with the WASI reactor ~5.2× slower). The cache-hit path is
backend-independent: it skips both backends and costs the same key construction
and rule pass. This is the main open measurement gap for the prototype.

## Tests

`cargo test --lib --features wasm-reactor,allow-cache` (365 passed; the
allow-cache subset is 26 tests):

- canonicalisation: determinism, header-order insensitivity, duplicate-header
  count/order, percent-encoding, query order, whitespace, method/body/protocol,
  body size;
- body cap and uncaptured-body skip;
- TTL expiry, bounded eviction, policy-generation invalidation, `set_generation`;
- route opt-in boundary matching;
- 50 000-key uniqueness sample, different secrets produce different keys;
- concurrent insert/get from 8 threads with a bounded map;
- integration: a hit skips cacheable rules but runs stateful rules; a cached
  allow cannot bypass a stateful block; blocks are never cached; invalidation
  forces re-evaluation; over-cap bodies are not cached; route opt-in;
  decision parity against an uncached engine; metrics export.

`cargo clippy --lib --features wasm-reactor,allow-cache -- --deny warnings` and
`cargo fmt -- --check` pass.

## Conditions under which it must stay disabled

1. Any rule that reads client IP, time, randomness, external threat-feed state,
   server-side session state or other non-request state is cacheable (i.e., not
   marked non-cacheable). The trait default prevents this for custom rules, but
   a future built-in rule could opt in incorrectly.
2. CRS is configured with IP-reputation or `REMOTE_ADDR`-dependent rules and
   `client_ip` is not added to the key.
3. The deployment requires a per-request CRS evaluation count for audit or
   billing (hits intentionally skip CRS).
4. Runtime policy/rule reloads cannot call `invalidate_allow_cache()` (the
   native sidecar hot-reload path, or an external rule feed). The 30 s TTL is a
   bound, not a substitute for invalidation.
5. The cache would be shared across processes, nodes or restarts without a key
   management and replay design. The secret is process-lifetime and the key is
   not portable.
6. The route handles per-user state that changes the WAF verdict but is not
   represented in the request (for example, a custom account-lockout rule).
7. The threat model requires that identical requests are always re-inspected
   (for example, a compliance rule that forbids memoised verdicts).
8. `max_body_bytes` is raised to a value that makes key construction a
   meaningful DoS surface, or `max_entries` is raised without accounting for the
   per-entry memory bound.

## Follow-ups (not implemented)

- Native sidecar replay measurement with `WAF_BENCH_BACKEND=native` on the
  same host and sidecar build.
- True LRU or CLOCK eviction if hit-rate experiments show hash-order eviction is
  too lossy.
- A `client_ip` key component plus a policy-generation component for CRS IP
  reputation rules, if such rules are deployed.
- A shared-secret/key-rotation design if the cache is ever shared across
  processes.
- BLAKE3 keyed mode as an alternative to SipHash-2-4 if the dependency and
  per-byte cost are acceptable; SipHash-2-4 is sufficient for a 128-bit tag and
  is already fast at these key sizes.
