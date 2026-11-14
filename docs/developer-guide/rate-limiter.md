# Per-IP Rate Limiter

`src/waf/rate_limit.rs` implements the per-IP token-bucket limiter used by the
request path and the bodyless fast path. This document describes the sharded
storage, the tracked-IP cap, and the capacity behaviour.

## Sharded storage

The limiter keeps 64 shards, each a `Mutex<HashMap<IpAddr, BucketEntry<V>>>`.
The shard is selected with a stable FNV-1a hash over the address bytes, so a
given client always maps to the same shard and unrelated clients only contend
when they collide. A request takes one shard lock, never a global lock.

Cleanup is incremental: every 100 evaluations one shard is swept round-robin
and entries older than twice the limiter window are removed. The sweep holds
only that shard's lock. There is no global cleanup pass and no lock is held
across an `await` (the limiter API is synchronous).

## Tracked-IP cap

`waf.rate_limit.max_tracked_ips` (default `100000`) is a hard cap on the total
number of tracked IPs. A shard insert reserves a slot with an atomic
compare-exchange, so concurrent inserts across shards cannot exceed the cap.
Expired entries are reclaimed before the capacity policy is applied.

`waf.rate_limit.capacity_policy` selects what happens when the cap is reached
and a new IP arrives:

| value | behaviour |
| --- | --- |
| `fail_closed` (default) | Reject the new IP with a 429 rate-limit decision. Existing IPs keep their buckets. |
| `evict_oldest` | Evict the least-recently-seen bucket from a shard (starting at the cleanup cursor), then admit the new IP. |

`fail_closed` is the safe default: an attacker cannot evict legitimate clients
or bypass limiting by spraying source addresses. `evict_oldest` keeps the
limiter available for new clients at the cost of bounded churn.

## Semantics preserved

Token-bucket capacity and refill, per-IP and global limits, metrics, and the
existing rule/fast-path integration are unchanged. The global limiter remains
a single bucket by design.

## Benchmark

`benches/rate_limit_shard.rs` compares the pre-sharding design (one global
`RwLock<HashMap>`) with the sharded limiter. Run each mode in its own process
so RSS deltas are clean:

```sh
cargo bench --bench rate_limit_shard -- baseline
cargo bench --bench rate_limit_shard -- sharded
cargo bench --bench rate_limit_shard -- baseline-concurrent
cargo bench --bench rate_limit_shard -- sharded-concurrent
```

The single-threaded workload is 1 000 000 operations over 100 000 unique IPs
(high-cardinality) and 1 000 000 operations on one IP (hot-IP). The concurrent
workload runs eight threads with 200 000 operations each. Results on the
reference host are recorded in
[performance-validation.md](../operations/performance-validation.md#rate-limiter-contention).
