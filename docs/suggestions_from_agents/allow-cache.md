# Allow-verdict cache (research prototype)

**Status:** experimental, non-default feature `allow-cache`, disabled by default.
**Scope:** memoise only the `Allow` verdict of pure content rules for a short
TTL. Blocks, rate limits and anomaly verdicts are never cached.
**Branch:** `perf/cache-subus` (sub-microsecond hit path on top of
`research/allow-cache`).

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
       ├─ early allow-cache probe (sync path, before the protocol pre-checks)
       │    ├─ route opt-in check
       │    ├─ fingerprint (metadata only; no body hashing)
       │    ├─ L1 probe -> shared shard probe -> body-digest verification
       │    └─ hit -> non-cacheable rules only -> Allow
       ├─ protocol pre-checks: GraphQL, then gRPC (miss path; may strip body)
       ├─ init-failure gate (fail-closed)
       ├─ rules_with_cache
       │    ├─ fingerprint + lookup (authoritative; counts the miss)
       │    └─ miss -> rules_core(full chain); insert only on Allow
       └─ finish (audit event, identical to a normal allow)
```

New pieces:

- `src/waf/allow_cache.rs` — two-level key construction, bounded sharded cache,
  thread-local L1, metrics.
- `WafRule::cacheable()` — **defaults to `false`**. Only the Coraza backend
  (`WasmReactorRule`, `NativeCorazaRule`) and the built-in
  `ContentInspectionRule` opt in. Custom rules run on every request.
- `[waf.allow_cache]` configuration (default `enabled = false`).
- `waf_allow_cache_*` Prometheus metrics.

### Two-level lookup

A hit never relies on a cheap fingerprint alone:

1. **Fingerprint** — a keyed 128-bit digest of the canonical *metadata*
   (version, policy generation, method, URI components, HTTP version, body
   presence/length, declared size, sorted header pairs). It never hashes the
   body, so a fingerprint miss costs no body work.
2. **Candidate bucket** — the fingerprint indexes a bucket of candidates in the
   sharded map. Each candidate stores a 128-bit keyed digest of the exact body
   bytes.
3. **Body verification** — the body digest is computed only when a bucket
   exists, and the request is allowed only if a live candidate's digest
   matches. A fingerprint collision on its own can never produce an `Allow`.

The body is hashed exactly once per hit (the interface hands the cache a
materialised `Bytes`, so there is no second pass to fold into a reader).

### What a hit skips, and what it never skips

A hit skips only work whose result is a pure function of the canonical request
content:

- the pure content rules (Coraza and the built-in content inspector), whose
  `Allow` was memoised;
- on the synchronous path, the stateless GraphQL/gRPC **pre-checks**. They are
  pure functions of method, URI, headers and body, all of which the fingerprint
  hashes. An early hit therefore implies the pre-checks already ran on this
  exact request and returned Allow without stripping the body: a stripped
  request hashes to a different fingerprint (body present vs absent), so it
  cannot hit early and falls through to the normal pre-check path. Protocol
  descriptor reloads are covered by the documented `invalidate_allow_cache()`
  contract.

A hit still runs:

- admission control (the request is classified before the cache is consulted,
  so a hit cannot bypass heavy-inspection capacity accounting),
- the fail-closed init gate (checked before the early probe, so a hit can never
  turn a 503 into an Allow),
- every non-cacheable rule: request-size and method checks, per-IP and global
  rate limiters, GeoIP rules, and any custom rule (the trait default),
- the audit event (`finish`), identical to a normal allow.

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
- A miss is counted exactly once: the early probe records only hits, and the
  authoritative lookup in the rule chain records the miss.
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

The fingerprint is a keyed hash of a strictly ordered, length-prefixed encoding.
Every normalisation is listed here; the default is **no normalisation**.

| Field | Encoding | Normalisation |
|---|---|---|
| Key version | `u8` | Constant `2`. |
| Policy generation | `u64` | Hash of the full `[waf]` config plus ordered rule names/enabled state. |
| Method | length-prefixed exact bytes of `Method::as_str()` | None. Hyper already canonicalises standard methods to uppercase; extension methods keep their exact case. HTTP methods are case-sensitive, so case folding would be lossy. |
| URI | presence + length-prefixed `scheme`, `authority`, `path_and_query` | None. No percent-decoding, no dot-segment removal, no case folding, no query reordering, no trailing-slash folding. Encoding the components is equivalent to `Uri::to_string()` but avoids a per-request `String` allocation. |
| HTTP version | length-prefixed exact bytes | None (`"1.1"`, `"2"`, `"3"` as set by the proxy). |
| Body presence | `u8` (`0`/`1`) | Distinguishes `None` from `Some(empty)`. |
| Body length | `u64` | Exact captured length. |
| Declared body size | `u8` presence + `u64` | Exact `RequestContext::body_size`. |
| Header count | `u64` | Number of header values. |
| Header pairs | sorted by a 16-byte name key, then iteration order; each pair is `u32 name_len, u32 value_len, name, value` | Names are sorted so header order is not part of the key. Duplicate values keep their insertion order and count. No whitespace trimming, no comma splitting, no UTF-8 lossy conversion. |
| Body bytes | **not in the fingerprint**; a separate 128-bit keyed digest is verified on a candidate hit | None. Over `max_body_bytes` the request is not keyed at all. |

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

## Hash choice

The fingerprint and the body digest use **keyed xxh3-128** (`xxhash-rust`,
`xxh3_128_with_secret`) with a 136-byte per-process secret drawn from the
OS-seeded CSPRNG. The previous prototype used keyed SipHash-2-4, which is
cryptographically strong but runs at roughly 1–2 GB/s; it dominated the hit path
(1.45 µs / 3.09 µs / 5.25 µs of fingerprint time for 1/4/8 KiB, because the body
was inside the key). xxh3-128 runs at ~16 GB/s on the reference host and the
body is no longer part of the fingerprint.

Security argument:

- **128-bit keyed output.** A false `Allow` requires a collision in either the
  fingerprint or the body digest. Without the secret, a second preimage costs
  about 2^128 work and a birthday collision about 2^64; the cache is bounded far
  below 2^32 entries, so the birthday term is negligible.
- **Secret never leaves the process** and is not persisted. Two processes
  produce different keys, which is why the cache must not be shared across
  processes without a key-management design.
- **xxh3 is not a cryptographic PRF.** The security argument rests on the secret
  being unknown to the attacker, exactly as with SipHash. If the secret leaks,
  an attacker can construct collisions; the mitigation is the same as for any
  keyed cache: process-local secret, no persistence, no cross-node sharing, and
  a short TTL. A deployment that requires cryptographic collision resistance
  even under key compromise should switch the body digest to keyed BLAKE3
  (several GB/s, still well under the 1 µs budget at 8 KiB) — the two-level
  design makes that a one-function change.
- **Two-level verification** means a fingerprint collision alone never allows:
  the body digest must also match, so an attacker would need to collide both
  128-bit values.

## Injectivity argument

**Claim:** if two requests differ in anything the memoised rules evaluate, they
produce different canonical encodings, and therefore different keys except with
negligible probability.

1. **Encoding is injective.** The encoding is a fixed sequence of fields. Every
   variable-length field is prefixed with its exact length; every fixed-width
   field has a fixed width; header multiplicity is carried by the pair count and
   the per-pair lengths. A prefix-free, length-prefixed encoding has a unique
   parse, so two different tuples cannot produce the same byte string. There is
   no concatenation ambiguity: `("ab","c")` and `("a","bc")` encode differently.
2. **The fields cover the memoised rules' inputs.** The Coraza payload is
   `{method, uri, http_version, headers, body, body_size, body_original_size,
   body_encoding}`. We hash method, URI, HTTP version, all headers, body
   presence/length and `body_size`, and verify the body bytes through the
   separate digest. `body_original_size` is the captured body length (or
   `body_size` when no body), and `body_encoding` is a function of the body
   bytes, so both are determined by hashed fields. The built-in content
   inspector reads URI path/query, all headers and the body; all are covered.
   For bodies above the cache cap we do not key at all, and when the WAF itself
   truncates inspection we still hash the full captured body (stricter than
   necessary: a suffix change causes a miss, never a false hit).
3. **Header canonicalisation preserves the evaluated set.** CRS treats request
   headers as a multimap of name → values; order across different names is not
   semantically meaningful. Sorting by name is therefore a canonicalisation of
   the same evaluated set. Duplicate values of one name keep their order and
   count, so smuggling-style `Content-Length`/`Transfer-Encoding` variants
   cannot collapse onto a clean key. Header names are case-insensitive in HTTP
   and hyper already normalises them.
4. **Keyed hash.** The encoding is hashed with keyed xxh3-128 under a
   per-process secret. Without the secret an adversary cannot construct a
   colliding encoding except by chance; a second-preimage costs about 2^128
   work, and a birthday collision about 2^64 (the cache is bounded far below
   that). The body digest is a second, independent 128-bit keyed value.
5. **Policy generation.** Every key includes the generation hash. A rule or
   `[waf]` config change produces a new generation, and `invalidate()` clears
   the map. Old entries are unreachable even if a clear were missed.

The one assumption is that the memoised rule set is exactly "Coraza + content
inspector". The trait default (`cacheable = false`) makes any new or custom rule
non-cacheable unless it explicitly opts in, so the assumption fails safe.

## Cache policy

- **Only `Allow` is inserted.** `Block` and `RateLimit` never reach `insert`;
  the insert is guarded by `outcome.decision == Decision::Allow`.
- **TTL** defaults to 30 s; entries carry a monotonic deadline and are removed
  on lookup after expiry (counted as `expired`, not a hit).
- **Bounded memory.** A fixed 64-shard map with per-shard capacity derived
  exactly from `max_entries`. Eviction is arbitrary hash-order within a shard
  (a sharded map, not a strict LRU). No request bytes are stored: an entry is a
  128-bit fingerprint, up to eight 128-bit body digests, a deadline and a
  generation. 8192 entries is well under 1 MiB.
- **Concurrency.** Each shard is a `parking_lot::RwLock`; the read path takes a
  shared lock. A per-thread direct-mapped L1 (256 slots) short-circuits the
  shared map for repeated hits. Counters are atomics. The cache is `Send + Sync`
  and shared by engine clones.
- **Invalidation.** `invalidate()` bumps the generation and clears all shards;
  `add_rule` after construction does the same; `set_generation()` clears on
  change. Runtime rule reloads (native sidecar or external feed) must call
  `WafEngine::invalidate_allow_cache()`.
- **Zero-allocation canonicalisation.** The fingerprint is written into
  per-thread scratch buffers (`Vec<u8>` reused across calls) and hashed in one
  pass. There is no `Uri::to_string`, no `Vec<&HeaderName>` sort, no `HeaderMap`
  clone and no per-header allocation. The only allocation on the hit path is
  none; on the miss path the shard bucket may grow.
- **Bounded cost.** Hashing is O(total key bytes) and linear. The body is capped
  at `max_body_bytes` (default 64 KiB) and over-cap bodies are not cached.

## Measured results

Harness: `examples/allow_cache_microbench.rs` (pinned with `taskset -c 3`,
release, in-process). The "before" column is the same harness adapted to the
original `build_key`/`get` API and run on `e186d7b` back-to-back with the new
build on the same host (a loaded 6-core i5-8400T; absolute numbers are inflated
by host load, the ratio is the meaningful figure).

### Component breakdown (after, ns/op, p50)

| component | 1 KiB | 4 KiB | 8 KiB |
|---|---:|---:|---:|
| fingerprint (canonical encode + hash) | 256 | 241 | 237 |
| body digest (keyed xxh3-128) | 67 | 237 | 467 |
| lookup, thread-local L1 hit | 104 | 274 | 503 |
| lookup, shared shard hit | 154 | 326 | 557 |
| insert (miss path) | 165 | 337 | 568 |
| lookup, fingerprint miss (no body hash) | 60 | 60 | 60 |
| **full `engine.evaluate` hit** | **560** | **730** | **960** |

The residual between the cache components and the full engine hit is admission,
the non-cacheable rule pass, the audit call and async plumbing (~200–250 ns).
The stateless protocol pre-checks cost ~75–120 ns and are skipped on a hit.

### Hit latency, before → after (p50 / p99)

| body | before p50 | after p50 | before p99 | after p99 | speedup |
|---:|---:|---:|---:|---:|---:|
| 1 KiB | 1.71 µs | **560 ns** | 1.90 µs | **642 ns** | 3.1× |
| 4 KiB | 3.43 µs | **730 ns** | 3.62 µs | **811 ns** | 4.7× |
| 8 KiB | 5.59 µs | **960 ns** | 6.00 µs | **1.06 µs** | 5.8× |

The original replay harness in `examples/allow_cache_bench.rs` reported
8.3 / 4.5 / 6.8 µs p50 for the same sizes on a busier host; the shape is the
same (SipHash over the body dominated and grew with body size).

### Throughput (hits/s, pinned)

| stage | threads | before | after |
|---|---:|---:|---:|
| lookup 1 KiB | 1 | 4.89 M | 6.92 M |
| lookup 1 KiB | 64 | 9.54 M | 5.99 M |
| lookup 8 KiB | 1 | 13.0 M | 1.83 M |
| lookup 8 KiB | 64 | 10.9 M | 1.77 M |
| engine hit 1 KiB | 1 | 0.18 M | 1.65 M |
| engine hit 1 KiB | 64 | 0.33 M | 0.47 M |
| engine hit 8 KiB | 1 | 0.18 M | 0.99 M |
| engine hit 8 KiB | 64 | 0.17 M | 0.78 M |

The raw `lookup` throughput is lower after the change for large bodies because
the old `get` only compared a precomputed key (the body was hashed once, in
`build_key`, outside the measured `get`), whereas the new `lookup` includes the
body-digest verification that makes the two-level design sound. The end-to-end
`engine hit` throughput — the number that matters — improves 5–9× at c=1 and
1.4–4.6× at c=64. At c=64 the shared shard locks and the host's 6 physical cores
bound the scaling; the thread-local L1 keeps the c=1 path lock-free.

## Tests

`cargo test --lib --features wasm-reactor,allow-cache` (455 passed; the
allow-cache subset is 33 tests):

- canonicalisation: determinism, header-order insensitivity, duplicate-header
  count/order, percent-encoding, query order, whitespace, method/body/protocol,
  body size;
- body cap and uncaptured-body skip;
- TTL expiry, bounded eviction, policy-generation invalidation, `set_generation`;
- route opt-in boundary matching;
- 50 000-key uniqueness sample, different secrets produce different keys;
- concurrent insert/get from 16 threads with a bounded map;
- two-level lookup: same fingerprint with a different body never allows, a
  simulated fingerprint collision requires a body-digest match, one fingerprint
  holds several body variants, the L1 never skips body verification, the L1 is
  scoped to one cache instance and does not survive invalidation;
- integration: a hit skips cacheable rules but runs stateful rules; a cached
  allow cannot bypass a stateful block; blocks are never cached; invalidation
  forces re-evaluation; over-cap bodies are not cached; route opt-in; decision
  parity against an uncached engine; same-metadata/different-body is not
  allowed; metrics export.

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
- Optional keyed-BLAKE3 body digest for deployments that want cryptographic
  collision resistance under key compromise; the two-level design isolates it
  to one function.
