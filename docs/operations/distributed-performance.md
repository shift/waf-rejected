# Distributed fabric hot-path performance

This page records the request-path cost of the `distri-kv` feature and the
`[waf.distributed]` controller. The controller is a control-plane component;
the claim under test is that it never blocks, delays or fails a request, even
when every endpoint is unreachable or accepts connections and then stalls.

Reproduce with:

```sh
nix develop -c ./scripts/bench-distributed.sh
# fast smoke run
nix develop -c ./scripts/bench-distributed.sh --quick --skip-build
# skip the second (no-feature) release build
nix develop -c ./scripts/bench-distributed.sh --no-baseline
```

The script builds the bench twice by default: once without `distri-kv` and
once with it, so the disabled row is compared with a genuine baseline rather
than with an older commit.

Artefacts (JSON rows, per-rep text, cache microbenchmark and `summary.md`) are
written to `target/bench-distributed/<utc>/`.

## Scenarios

| Scenario | `enabled` | Endpoint | Controller |
| --- | --- | --- | --- |
| `no-feature` | build without `distri-kv` | none | absent |
| `disabled` | `false` | none | not started |
| `enabled-refused` | `true`, `fallback = "local_only"` | `http://127.0.0.1:1` (connection refused) | started, reconnect loop |
| `enabled-blackhole` | `true`, `fallback = "local_only"` | TCP listener that accepts and never speaks HTTP/2 | started, RPCs time out in flight |

`bench-subms --only l2,l3 --no-wasm` runs the real proxy over loopback with the
Rust engine and a mock upstream. Sequential cells are 300 requests after 50
warm-ups; the throughput cell is 16 workers × 30 requests. The summary takes
the median of five interleaved repetitions per scenario.

Host for the recorded run: Intel Core i5-8400T, 6 logical CPUs, affinity
`taskset -c 2-3`, shared host with a 1-minute load average around 7–15. That
matters: absolute numbers are noisier than the pinned baseline in
`docs/suggestions_from_agents/wrapper-floor.md`, so treat same-run scenario
differences as the signal.

## Sequential request latency (L3 Rust WAF)

| scenario | size | p50 ms | p95 ms | p99 ms | allocs/op | alloc B/op |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| no-feature | bodyless | 0.314 | 0.414 | 0.450 | 150.0 | 51 375 |
| no-feature | 1 KiB | 0.447 | 0.487 | 0.504 | 166.0 | 55 538 |
| no-feature | 4 KiB | 0.807 | 0.860 | 0.884 | 166.0 | 58 610 |
| no-feature | 8 KiB | 1.207 | 1.293 | 1.418 | 166.0 | 79 090 |
| disabled | bodyless | 0.323 | 0.400 | 0.442 | 150.0 | 51 375 |
| disabled | 1 KiB | 0.463 | 0.539 | 0.576 | 166.0 | 55 538 |
| disabled | 4 KiB | 0.798 | 0.849 | 0.875 | 165.0 | 58 322 |
| disabled | 8 KiB | 1.180 | 1.241 | 1.290 | 166.0 | 79 090 |
| enabled-refused | bodyless | 0.317 | 0.387 | 0.431 | 150.0 | 51 375 |
| enabled-refused | 1 KiB | 0.461 | 0.509 | 0.538 | 166.0 | 55 538 |
| enabled-refused | 4 KiB | 0.795 | 1.011 | 2.019 | 166.0 | 58 610 |
| enabled-refused | 8 KiB | 1.180 | 1.242 | 1.264 | 166.0 | 79 090 |
| enabled-blackhole | bodyless | 0.317 | 0.415 | 0.439 | 150.0 | 51 375 |
| enabled-blackhole | 1 KiB | 0.445 | 0.506 | 0.550 | 166.0 | 55 538 |
| enabled-blackhole | 4 KiB | 0.794 | 0.838 | 0.869 | 166.0 | 58 610 |
| enabled-blackhole | 8 KiB | 1.184 | 1.266 | 1.330 | 166.0 | 79 090 |

Interpretation:

- Compiled-but-disabled is indistinguishable from a build without the
  feature: there is no controller task, no state handle and no additional
  per-request branch. The two rows differ by 0.006–0.027 ms at p50, well
  inside the run-to-run spread, and use identical allocations.
- Enabled endpoints add no allocation and no measurable p50 at any size. All
  four scenarios sit in the same 0.314–0.323 ms (bodyless), 0.445–0.463 ms
  (1 KiB), 0.794–0.807 ms (4 KiB) and 1.180–1.207 ms (8 KiB) bands. The one
  p99 excursion (enabled-refused, 4 KiB, 2.02 ms) is a single host scheduling
  spike; the median p50 and p99 of the other repetitions are in line.
- The silent endpoint cannot cause a request timeout: samples stay in the
  same microsecond band, and the maximum observed request in this run was
  10.8 ms. A request-path wait on the 200 ms RPC deadline would show up as a
  cluster of ~200 ms samples.
- `slow_endpoint_does_not_block_request_evaluation` pins this down in CI: a
  mock gRPC server stalls registration for 750 ms while 10 requests are
  evaluated. The slowest request must stay under 100 ms and the decision must
  equal the disabled engine's decision.

## Throughput (c = 16 × 30)

| scenario | size | p50 ms | p99 ms | throughput req/s |
| --- | --- | ---: | ---: | ---: |
| no-feature | bodyless | 2.00 | 4.11 | 7 669 |
| no-feature | 1 KiB | 5.38 | 5.58 | 2 969 |
| no-feature | 4 KiB | 10.19 | 10.63 | 1 566 |
| no-feature | 8 KiB | 16.45 | 17.27 | 969 |
| disabled | bodyless | 2.03 | 3.73 | 7 562 |
| disabled | 1 KiB | 5.32 | 5.75 | 2 987 |
| disabled | 4 KiB | 9.96 | 10.20 | 1 602 |
| disabled | 8 KiB | 16.04 | 16.43 | 995 |
| enabled-refused | bodyless | 2.01 | 3.82 | 7 683 |
| enabled-refused | 1 KiB | 5.30 | 5.48 | 3 008 |
| enabled-refused | 4 KiB | 9.98 | 10.51 | 1 595 |
| enabled-refused | 8 KiB | 16.03 | 16.39 | 995 |
| enabled-blackhole | bodyless | 2.01 | 4.47 | 7 598 |
| enabled-blackhole | 1 KiB | 5.30 | 5.60 | 2 997 |
| enabled-blackhole | 4 KiB | 9.90 | 10.39 | 1 608 |
| enabled-blackhole | 8 KiB | 16.04 | 16.78 | 994 |

Throughput is unchanged within noise across all four scenarios. The earlier
run on a busier host showed the same overlap but with much larger absolute
spread, which is why the script interleaves repetitions and reports the
median.

## Process CPU

The bench process runs the controller on the same runtime as the proxy, so the
whole-run CPU delta is an upper bound on controller cost.

| scenario | process CPU ms (median of 5) |
| --- | ---: |
| no-feature | 2 949 |
| disabled | 2 908 |
| enabled-refused | 2 903 |
| enabled-blackhole | 2 907 |

The controller adds no measurable process CPU in this run: the four values
differ by 1.6 % and the no-feature baseline is the highest. Connection
refused and the silent endpoint both recover through the same backoff loop;
the silent endpoint's 200 ms RPC deadline is paid by the controller task, not
by a request. Production should still set `request_timeout_ms` small enough
to bound shutdown/backoff latency and `reconnect_max_backoff_ms` to cap retry
frequency.

## Request-side cache cost

`distributed-cache-bench` measures the real `VersionedCache` types read by the
request path: a `String -> PolicySnapshot` cache and an `IpAddr ->
ReputationEntry` cache with a 65 536-entry bound. Median of 20 samples of
200 000 operations.

| operation | median | p99 |
| --- | ---: | ---: |
| policy fresh hit | 91 ns | 93 ns |
| reputation fresh hit | 93 ns | 96 ns |
| policy miss | 60 ns | 61 ns |
| reputation miss | 62 ns | 63 ns |
| generation invalidation (65 536 entries, whole cache) | 2.6 µs | 3.2 µs |

Earlier runs on the same host measured up to 102 ns for a fresh hit and
3.7 µs for invalidation, so treat the last digit as noise.

The cache uses one `RwLock` read and clones the entry. A hit is roughly
0.1 µs, i.e. under 0.03 % of a 0.33 ms bodyless request, and there is no
network call on a miss: the caller keeps the local decision in `local_only`
mode. Generation invalidation is a single write-lock clear, not a per-entry
walk.

## Shared-budget lease cost and limits

Leases are not on the hot path. A request either spends one cached unit
(atomic decrement under the lease-pool mutex) or does one non-blocking
`try_push` into the bounded request queue. It never performs an RPC. The
controller drains at most `lease_batch_max` (default 64) requests per
heartbeat and issues one `AcquireLease` per request; `lease_queue_capacity`
(default 4096) bounds memory and drops the oldest request when full.

The real-server end-to-end suite (`scripts/test-distri-e2e.sh`) proves the
server semantics that set the limits: a bucket shared by two WAF instances
cannot exceed its capacity, duplicate `idempotency_key` values return the
original grant without a second debit, expired leases are reaped without a
refund (fail closed), `ReleaseLease` refunds unused tokens, and lease state is
replayed after a cluster restart. distri-kv defaults to 100 tokens per bucket,
10 tokens/s refill, 1024 tokens per request, a 100–60 000 ms TTL clamp and a
600 s idempotency window.

Operational consequences:

- Lease TTL is the refund latency for unused capacity because the controller
  does not send `ReleaseLease` automatically. Long TTLs reduce RPC churn but
  hold tokens; short TTLs increase `AcquireLease` rate. Keep
  `lease_ttl_ms` comfortably below the server's 60 s maximum.
- `lease_batch_max × heartbeat_interval` is the maximum grant rate per node.
  If the request path drains a lease faster than that, it enqueues more work
  but still fails closed until a new grant arrives; it does not wait.
- Lease RPC failures are accounted once per batch
  (`waf_distributed_lease_fallback_total`). Because the request path never
  awaits, a refused, silent or slow cluster changes only shared-only
  decisions and leaves local token buckets untouched.
- A bucket's `remaining_tokens` is global unleased capacity, not this node's
  spendable balance; the client uses `granted_tokens` locally. Dashboards
  should track `lease_granted_units_total` and `lease_denied_total`, not the
  response's `remaining_tokens` as a per-node gauge.

## Endpoint failure behaviour

Exercise this with the controller tests:

- `controller_backs_off_and_activates_fallback_on_failure` — failed
  heartbeats produce reconnect attempts, `fallback_activations_total = 1` per
  outage, and `local_only` never turns the outage into a block.
- `queue_pressure_under_failure_stays_bounded` — 20 000 pushes against
  capacity-8 queues while the consumer is down leave the depth at 8 and
  account for every dropped item. Memory is bounded by the configured queue
  capacities plus the fixed cache bounds (64 policy, 65 536 reputation).
- `slow_endpoint_does_not_block_request_evaluation` — a 750 ms registration
  stall cannot delay request evaluation or change a decision.
- Reconnect backoff is `initial × 2` capped at `max` (default 100 ms → 30 s),
  pure and unit-tested. Telemetry drops oldest first and increments
  `waf_distributed_queue_dropped_total`.

## Control-plane measurements (beta 19)

These are server-side `shift/distri-kv` measurements, not WAF request-path
costs. Three nodes, 0 ms each-way RTT, release host (Intel i5-8400T, 6 logical
CPUs, shared):

| Measurement | Result |
| --- | ---: |
| Policy activation, leader Raft commit | 5.5 ms p50 (2.95 ms low-noise; follower-forwarded 4.6 ms) |
| Heartbeats | 6,707 ops/s |
| Lease acquire, 1 client | 3.08 ms p50 |
| Lease acquire, 8 clients | 8.06 ms p50 (target < 5 ms: **missed**) |
| Lease acquire, 64 clients | 34.5 ms p50, 510 ms p99 |
| Leader failover (`kill -9` to serving strict read) | ~0.46 s |

Honest limits for this release:

- Pub/sub is durable per node (topic log, replay, ack markers) but not
  Raft-replicated cluster-wide until the next distri-kv merge.
- Key routing uses the consistent-hash ring inside one replicated Raft group;
  independent per-partition Raft groups ("true Multi-Raft") are not wired.
- `Discover` partition/leader hints are registry-derived and marked partial.
- The 8-client lease target is missed at 8.06 ms on the release host; the gate
  is reported rather than relaxed.

## Limits and follow-ups

- No real distri-kv cluster was used. A real cluster adds policy/reputation
  fill work to the controller task, not to the request path; this run covers
  the failure modes (refused, silent, slow) that matter for the hot path.
- The cache benchmark uses synthetic entries; large `PolicySnapshot` allow/
  block lists would increase clone cost linearly. Keep policy snapshots small
  or add an `Arc`-shared snapshot before enabling large lists.
- Only loopback HTTP/1.1 is measured here. TLS/h2 cost is transport work
  shared with the non-distributed path and is covered by the normal
  performance gates.
- The shared host makes sub-10 % p50 differences non-significant. Use a quiet
  pinned host and more repetitions before making a capacity claim.
- A future client should keep all control-plane work on the controller task;
  no trait method may be called from the request path.
