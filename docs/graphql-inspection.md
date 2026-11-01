# GraphQL-over-HTTP Inspection

**Status:** enabled by default when `wasm-reactor` is available
**Module:** `src/waf/graphql.rs`
**Config:** `[waf.graphql]`

GraphQL request bodies are JSON envelopes around a query string, and running
the full CRS JSON body rule set over them is expensive: a byte-linear scan of
a 1 KiB body costs roughly 0.21–0.29 s, 4 KiB roughly 0.8–1.0 s, and 8 KiB
roughly 1.3–1.4 s on the reference host. Bodyless requests are 2–6 ms. This
module validates the GraphQL operation *before* Coraza runs and, when
explicitly configured, withholds the raw body from CRS body rules.

**Header and URI rules still run.** Only the JSON body is hidden, and only in
`graphql-only` mode.

## Body scan modes

`waf.graphql.body_scan` selects how much of the body CRS sees. This is the
central security/performance trade-off:

| Mode | CRS body rules | GraphQL checks | Notes |
| --- | --- | --- | --- |
| `crs` (default) | Full JSON body scan | Yes | No security change from today; the pre-check adds only protocol-aware policy checks. |
| `graphql-only` | **Skipped for matched GraphQL requests** | Yes | Removes ~0.2–1.4 s of JSON scanning per request, but CRS body-rule coverage is lost for that request. Requires a non-empty allowlist. |
| `off` | Full JSON body scan | No | Disables GraphQL-specific checks entirely. |

`graphql-only` is not a silent bypass: the operation must be allowlisted by
name or persisted-query hash, the limits below are enforced, and header/URI
rules continue to run. It is a deliberate acceptance that CRS JSON body rules
(including generic injection/XSS patterns inside variables) do not see this
request. Use `crs` if that coverage is mandatory.

## What is inspected

| Check | Behaviour |
| --- | --- |
| Detection | `POST` with `application/json`, `application/graphql+json` or `application/graphql`; `GET` with a `query` parameter |
| Body source | JSON object with a string `query`, optional string `operationName`, optional object `variables`; `application/graphql` is the raw query |
| Operation | Type (`query`/`mutation`/`subscription`) and name, with `operationName` taking precedence |
| Query hash | SHA-256 of the normalised query (comments removed, whitespace collapsed outside strings) |
| Limits | `max_body_bytes`, `max_query_bytes`, `max_variables_bytes`, `max_variables`, `max_depth`, `max_aliases`, `max_fields` |
| Operations | `allow_mutations`, `allow_subscriptions` |
| Allowlist | Operation name and/or SHA-256 hash, `monitor` or `block` unknown policy |

Depth is the maximum selection-set brace depth. Alias and field counts are
approximate counts from a lightweight GraphQL parser; they are DoS bounds,
not a full GraphQL validator.

## Decisions

| Condition | Decision |
| --- | --- |
| Checks pass (`crs`/`off`) | allow; body remains available to CRS |
| Checks pass (`graphql-only`) | allow; raw body withheld from downstream rules |
| Operation not in a non-empty allowlist, policy `block` | `403` |
| Mutation/subscription denied | `403` |
| Depth/alias/field/variable count exceeded | `400` |
| Body/query/variables bytes exceeded | `413` |
| Malformed JSON / unavailable body in `graphql-only`, `fail_mode = closed` | `503` |
| Malformed JSON / unavailable body in `graphql-only`, `fail_mode = open` | allow (body still withheld) |
| Malformed JSON in `crs` | allow; CRS scans the body as before |

Deterministic policy limits are always rejected, independent of `fail_mode`.
`fail_mode` only governs bodies that cannot be inspected.

## Configuration

```toml
[waf.graphql]
enabled = true
body_scan = "graphql-only"   # "crs" (default), "graphql-only" or "off"

# Operation names or 64-character SHA-256 query hashes.
operation_allowlist = [
  "GetUser",
  "9f2c...e1",                # hash of the normalised query
]

# Persisted-query artifact (JSON list of { "name", "sha256" }).
allowlist_file = "/etc/waf/graphql/allowlist.json"

# "monitor" or "block"; unset defaults to block when the effective
# allowlist is non-empty and monitor when it is empty.
unknown_operation_action = "block"

max_body_bytes = 8388608
max_query_bytes = 1048576
max_variables_bytes = 1048576
max_variables = 128
max_depth = 128
max_aliases = 1024
max_fields = 8192
allow_mutations = true
allow_subscriptions = true
```

`Config::validate` rejects an unknown `body_scan` or
`unknown_operation_action`, zero byte/count/depth limits, empty or malformed
allowlist entries, an `allowlist_file` that cannot be loaded, and
`body_scan = "graphql-only"` without a non-empty allowlist. A configured
artifact that cannot be read is a start-up error, not a silent empty
allowlist.

### Persisted-query allowlist artifact

The artifact is a JSON list (an object with an `operations` array is also
accepted):

```json
[
  {
    "name": "GetUser",
    "sha256": "8f14e45fceea167a5a36dedd4bea2543f0e6b1c4c4c4c4c4c4c4c4c4c4c4c4c4"
  },
  {
    "name": "ListOrders",
    "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
  }
]
```

`sha256` is the lowercase (or uppercase) hex SHA-256 of the normalised query.
Names and hashes from the artifact are merged with `operation_allowlist`. The
hash is over the query text, not the JSON envelope, so client `variables` do
not change it.

## Limitations

* **No GraphQL value-level inspection.** Variables and string literals are not
  decoded and matched against CRS. In `graphql-only` mode those bytes are not
  scanned at all. The allowlist, operation type and structural limits are the
  controls.
* The GraphQL parser is a lightweight structural parser, not a full
  specification validator. Rejecting a syntactically valid but unusual
  document is possible; malformed documents in `crs` mode are left to CRS.
* `application/graphql` raw-query bodies are supported, but clients commonly
  send `application/json`; both are covered.
* Streaming request bodies that are not buffered cannot be inspected. In
  `graphql-only` mode this is treated as an inspection failure (`fail_mode`).

## Tests and benchmark

`src/waf/graphql.rs` covers detection, hash stability, allowlist
allow/block/monitor, depth/alias/field/variable limits, mutation/subscription
denial, `crs` versus `graphql-only` body handling, malformed JSON, and artifact
loading. `src/waf/mod.rs` verifies that `graphql-only` withholds the body while
header/URI rules still run, `crs` keeps the body visible, malformed input fails
closed only in `graphql-only`, and an unlisted operation is blocked before
rules. `src/config.rs` validates modes, limits, allowlists and artifacts.

The engine-level benchmark (`examples/graphql_inspection.rs`, run with
`cargo run --release --features wasm-reactor --example graphql_inspection`)
reports p50 for 1/4/8 KiB GraphQL bodies in `crs` versus `graphql-only`; the
delta is the JSON body-scan cost removed by withholding. On the benchmark host
used for this change the measured p50 was 49/214/455 ms in `crs` versus
3/3/3 ms in `graphql-only` (1/4/8 KiB), i.e. deltas of ~47/211/452 ms.
Standalone CRS measurements on a slower reference host were ~0.2–1.4 s. Exact
numbers depend on hardware and the CRS rule set.
