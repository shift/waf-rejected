# distri-kv capability audit for WAF integration

- **Status:** Verified audit (read-only; no distri-kv changes)
- **Date:** 2026-11-08
- **Repository audited:** `/tmp/opencode/distri-kv`, commit `c6fd36d`
  (`Merge branch 'main' of https://github.com/shift/distri-kv`, 2025-12-16)
- **Companion:** [ADR-0007: Distributed WAF security fabric over distri-kv](./distributed-waf-architecture.md)
  — decisions are recorded as [ADR-0008](./distributed-waf-architecture.md#11-decision-log-adr-0008),
  reconciliation in [§12](./distributed-waf-architecture.md#12-reconciliation-with-the-distri-kv-audit),
  and the remaining dependency order in
  [§15](./distributed-waf-architecture.md#15-what-remains-before-implementation).
- **Licence:** `LICENSE` is MIT; `LICENSE-AGPL-3.0` is also present. Confirm before
  any code is copied.

## 0. Verdict

distri-kv today is **two disjoint stacks that never meet**:

1. A Raft KV stack (`ezraft::Node` + `RaftServiceImpl` + a `DistriKv` gRPC
   service). The Raft transport is real, but the client-facing service is a
   stub: `Get` is `unimplemented`, `Mutate` returns fabricated success without
   writing anything, `Watch` returns an empty stream, and `Publish`,
   `Subscribe`, `Acknowledge` and `ChangeConfig` are `unimplemented`.
2. A security stack (`distributed_rate_limit.rs`, `security_correlation.rs`)
   that keeps all state process-local — rate limits in the **local**
   `StorageAdapter` (sled), correlation in an in-memory `HashMap`. It never
   calls the `MultiRaftCluster` handle it holds, is never constructed by the
   server, and is not exposed through protobuf or the client.

The WAF-relevant capability described in the collaboration documents — shared
rate limits, shared threat intelligence, node discovery, policy propagation,
event streaming — **does not exist as an operable feature**. The highest-value
building blocks (token-bucket arithmetic, correlation scoring, the storage
adapter trait, the Raft log transport) are individually written, but they are
not integrated into a distributed, callable service.

The tree does not build as checked out: the `distri-kv` library has 39
unconditional compile errors (a missing `k8s_auto_config` module and broken
`synapse_gaming_*` modules), and `security_correlation.rs` does not compile
even after those are removed (E0689 at line 219). Only the standalone
`distri-kv-client` crate builds, and it can call only `change_config`, which
the server answers with `unimplemented`. See §1.

Hot-path answer: **a WAF cannot perform a synchronous distributed rate-limit or
reputation check against this repository today.** There is no RPC for it, the
client cannot issue one, and the library implementation is node-local rather
than replicated.

---

## 1. Build and test status

Commands run from `/tmp/opencode/distri-kv`; the devshell was realised from
`cache.nixos.org` (no network access to `cache.garnix.io`, which only slows the
first shell realisation). Nothing was skipped silently.

| Command | Result |
|---|---|
| `nix develop -c cargo check --workspace --all-targets` | **FAIL**, exit 101, 39 errors — the `distri-kv` library itself does not compile (§1.1) |
| `nix develop -c cargo test -p distri-kv --lib` | **cannot run**; fails at the same 39 lib errors |
| `nix develop -c cargo check -p distri-kv-client` | **PASS** (exit 0, 19.7 s) — the 38-line client compiles because it depends on nothing but generated protobuf |
| Scratch-copy probe, gaming/k8s modules excluded | `cargo check -p distri-kv --lib` **PASS**; `cargo test --lib` = 39 passed, 1 failed (§1.2) |
| Same probe with `security_correlation` also excluded | `cargo check` **PASS**, compiler warns `consensus` and `ttl_manager` are never read (§1.3) |

### 1.1 Why the library does not compile

```
error[E0583]: file not found for module `k8s_auto_config`
  --> distri-kv/src/lib.rs:31
error: expected `,`, found `.`
  --> distri-kv/src/synapse_gaming_test.rs:514
error[E0432]: unresolved import `rand`
  --> distri-kv/src/synapse_gaming_test.rs:14
error[E0277]: the trait bound `GamingOperationType: Hash` is not satisfied
  --> distri-kv/src/synapse_gaming_waf.rs (×10)
```

`lib.rs` declares `pub mod k8s_auto_config;` but no such file exists, and the
`synapse_gaming_*` modules contain syntax errors plus a missing `rand`
dependency. These are unconditional library errors, not test-only errors, so
`cargo build`, `cargo check` and `cargo test` all fail on the default tree.

The repository's flake also runs
`cargoClippy --all-targets -- --deny warnings` (`flake.nix:68-71`), which would
add the broken test and bench targets:

- `distri-kv/tests/distributed_rate_limit_test.rs` is syntactically invalid:
  `create_test_manager` is defined twice, there is orphaned test body text at
  file scope between the definitions, `IpAddr`/`Ipv4Addr`/`sleep` are not
  imported, `metrics.total_requests` does not exist, and
  `MultiRaftCluster::new(state_machine)` does not match
  `MultiRaftCluster::new(config, factory)`.
- `distri-kv/benches/distributed_rate_limit_bench.rs` constructs
  `MultiRaftConfig` with fields that no longer exist (`data_directory`,
  `node_id`, `listen_addr`, `bootstrap_peers`, `election_timeout`,
  `heartbeat_interval`; the real struct has `initial_partitions`,
  `replication_factor`, `split_threshold_ops_per_sec`, `merge_threshold_keys`,
  `raft_config`). `criterion` is not declared in `dev-dependencies`, so the
  bench target cannot resolve.

### 1.2 What does pass, in isolation

A scratch copy (`/tmp/opencode/dkv-probe`, original untouched) with
`k8s_auto_config` and the four `synapse_gaming_*` modules commented out of
`lib.rs` compiles. In that copy:

- `cargo test --lib`: **39 passed, 1 failed**. The failure is
  `monitoring::tests::test_monitoring_system_creation` (placeholder assertion,
  `monitoring.rs:647`).
- All five `distributed_rate_limit` unit tests pass — but they only exercise
  pure token arithmetic (`DistributedRateLimit::new/try_consume/
  update_threat_multiplier/node_contributions/refill`). **No test exercises
  `DistributedRateLimitManager`**: those tests live in the broken integration
  file.
- `security_correlation` was then excluded too, because it does not compile
  (next section). Its `demonstrate_waf_integration` and correlator paths are
  therefore untested and unbuildable.

### 1.3 `security_correlation.rs` does not compile

With the unrelated broken modules removed, the next error is the security
correlator itself:

```
error[E0689]: can't call method `max` on ambiguous numeric type `{float}`
   --> distri-kv/src/security_correlation.rs:219:45
    |
219 |     confidence = confidence.max(correlation_score);
    |
help: you must specify a type for this binding, like `f32`
```

`confidence` is initialised from the untyped literal `0.5` at line 211. The
module that provides the entire threat-correlation story has never been
compiled in this tree. `DISTRIBUTED_SECURITY_IMPLEMENTATION_STATUS.md`'s claim
that "all distributed rate limiting components now compile successfully" is
only true for `distributed_rate_limit.rs`, and only in isolation.

### 1.4 Dead replicated state, confirmed by the compiler

With only `distributed_rate_limit.rs` left, the build succeeds with:

```
warning: fields `consensus` and `ttl_manager` are never read
   --> distri-kv/src/distributed_rate_limit.rs:289
```

That is the compiler confirming §3.1: the consensus handle is never used and
no TTL cleanup is wired.

---

## 2. What actually runs

`src/main.rs` → `server::run_server` (`distri-kv/src/server.rs`):

| Component | Evidence | Reality |
|---|---|---|
| Client gRPC server | `server.rs:261` | Serves `DistriKv`; every method is a stub (§3.5) |
| Raft gRPC server | `server.rs:279` | Real `AppendEntries`/`RequestVote`/`PreVote` handling |
| Raft tick loop | `server.rs:300-372` | Real: ticks the node and sends messages to configured peers |
| KV state machine | `server.rs:44-56`, `store.rs:25-37` | `ezraft::Node<SledStore, SledStorage>` over sled |
| Cluster metadata group | `server.rs:186-201` | A **second** `ezraft::Node` with `HashMap::new()` peers, node id `+10_000`, own sled directory, never added to any gRPC server |
| Cluster metadata registration | `server.rs:193` | One `propose_command` at startup; return value discarded (`let _ =`) |
| Monitoring | `server.rs:217`, `start_monitoring_services` | warp `/metrics`, `/health`, `/status` bound to `127.0.0.1` only; storage stats are `100` keys / `1 MiB` placeholders (`server.rs:398-402`) |
| Rate limiter / correlator | nowhere | `DistributedRateLimitManager` and `DistributedSecurityCorrelator` are never constructed outside tests/benches |

There is no path from the client API into the Raft KV state machine.
`ezraft::Node::propose_command` exists (`ezraft/src/node.rs:71`) and is called
exactly once in the whole repository — for cluster metadata
(`server.rs:193`) — never for KV or security data.

---

## 3. Public API map

### 3.1 `distri-kv/src/distributed_rate_limit.rs` (727 lines)

**Types and construction**

- `DistributedRateLimit` (line 22): per-IP token bucket. Fields include
  `tokens_remaining`, `capacity`, `refill_rate`, `node_contributions:
  HashMap<NodeId,u32>`, `threat_multiplier: f64`, `version: u64`.
- `DistributedRateLimitConfig` (line 154): `node_id`, `default_capacity`
  (100), `default_refill_rate` (10/s), `cache_ttl` (100 ms),
  `max_cache_size` (100_000), `batch_interval` (50 ms), `max_batch_size`
  (1000), `enable_adaptive_limiting`.
- `DistributedRateLimitManager<S: StorageAdapter>::new(config, consensus,
  storage, ttl_manager)` (line 304). Spawns a batch task.
- `check_rate_limit(ip, tokens, threat_multiplier) -> RateLimitResult` (line 329).
- `update_threat_multiplier(ip, f64)` (line 654), `reset_rate_limit(ip)` (line 663).
- `get_metrics() -> &RateLimitMetrics` (line 647).
- `RateLimitResult::{Allow { tokens_remaining, reset_time },
  Block { reason, retry_after, tokens_remaining } }` (line 139).
- Metrics: atomic counters for checks, cache hits/misses, "consensus"
  reads/writes, batches, violations, moving-average latencies (line 219).

**Actual semantics**

1. **The `consensus` field is dead.** It is stored at line 289 and never read
   after construction. `get_consensus_state` (line 437) is a local
   `self.storage.get(...)` (line 440); `apply_consensus_update` (line 517) and
   the batch writers (lines 493, 554) are local `storage.put_with_ttl`.
2. **Cache hit path** (line 366) takes a process-wide
   `tokio::sync::RwLock` in write mode (`local_cache.write()`), then mutates
   an LRU entry. It is logically correct for one process but serialises all
   checks behind one lock.
3. **Cache miss path** performs a **synchronous sled read inside an async
   function** (line 440, no `spawn_blocking`). Under load this blocks the
   executor thread.
4. **Batching is write-only.** The background task (line 564) drains pending
   updates and calls `process_batch_update` (line 593), which serialises the
   whole batch into a `rate_limit_batch:<uuid>` record and writes it. It never
   applies the individual ops. Only the *size-triggered* path
   (`schedule_consensus_update` → `process_batch_updates`, line 476) applies
   ops, and it too writes locally.
5. **Bucket state is not durable in the deployed backend.** The manager writes
   with `put_with_ttl(..., 3600)`; the sled adapter ignores TTL (§3.4), so the
   `rate_limit_batch:*` keys accumulate forever — a slow disk leak on the hot
   path.
6. **Cache hits never enqueue an update.** `check_rate_limit` returns from
   `try_local_cache` at line 366 before `schedule_consensus_update`. The
   `dirty` flag set by `CacheEntry::mark_dirty` is never read anywhere. So the
   normal path (cache hit) produces no outbound state at all; only the rarer
   cache-miss path schedules one.
7. **`reset_rate_limit` is not durable.** It evicts the local cache entry and
   enqueues a `Reset`; if the queue never reaches `max_batch_size`, the
   background task records the reset without applying it, so the next cache
   miss re-reads the unreset bucket.
8. **`version` is never used** as a compare-and-swap or read-modify-write
   guard. Two nodes sharing storage would last-write-wins.
9. **No failure policy.** Storage errors propagate as `StorageError`. There is
   no fail-open/fail-closed mode, no circuit breaker, no local-only degraded
   mode.
10. **No replication.** Because nothing calls `consensus.put`, each node's
    window is independent. `N` nodes enforce approximately `N ×` the configured
    limit.

### 3.2 `distri-kv/src/security_correlation.rs` (443 lines)

- Event model (line 13): `SecurityEventType::{SuspiciousPattern,
  RateLimitViolation, MaliciousIp, DdosPattern, GeoAnomaly}`; `ThreatLevel`;
  `SecurityEvent { event_id: Uuid, timestamp, source_ip, node_id, event_type,
  metadata }`.
- `CorrelationResult` (line 66): `threat_multiplier`, `recommended_action`,
  `correlation_confidence`, `related_events: Vec<Uuid>`.
- `SecurityAction` (line 74): `Allow`, `RateLimit { tokens_per_second,
  burst_capacity }`, `TemporaryBlock { duration }`, `PermanentBlock`,
  `Challenge { challenge_type }`.
- `DistributedSecurityCorrelator::new(rate_limiter, node_id, config)` (line 152).
- `process_security_event(event) -> CorrelationResult` (line 169).
- `get_threat_assessment(ip) -> Option<f64>` (line 324).
- `demonstrate_waf_integration(...)` (line 355) — doc example, SQL-injection
  string match.

**Actual semantics**

- **The module does not compile**: `security_correlation.rs:219` calls
  `f64::max` on an untyped literal (`let mut confidence = 0.5;`), E0689. This
  is not hidden behind a feature flag; any build that includes the module
  fails. See §1.3.
- All state is an in-process `RwLock<HashMap<IpAddr, Vec<SecurityEvent>>>`
  (line 110, initialised line 159). **There is no storage write and no
  persistence key.** The module's claim of "distributed" is limited to the
  type name.
- Correlation is a fixed additive score over the local event window (0.3
  temporal, +0.4 repeated rate-limit, +0.5 known-malicious, +0.6 DDoS, else
  +0.1), clamped to 1.0 (lines 214-260).
- Actions are thresholds on `threat_multiplier` and `confidence` (line 262):
  `>=5.0` permanent block, `>=3.0` 1 h block, `>=2.0` captcha, `>=1.5` rate
  limit 1/s burst 5.
- Enforcement is **only** `rate_limiter.update_threat_multiplier(...)`
  (lines 300-320). `TemporaryBlock`/`PermanentBlock` map to multiplier
  `1000.0`, which `update_threat_multiplier` clamps to `10.0` — i.e. a
  "permanent block" is a 10× slower refill, not a block. Provider uses
  `SecurityAction` itself; distri-kv never blocks traffic.
- `TemporaryBlock.duration` is ignored.
- `enable_geo_correlation` is never read; there is no geo lookup.
- The test helper is `todo!("Create test correlator …")` (line 431).

### 3.3 `distri-kv/src/multi_raft.rs`, `ezraft/src/multi_raft.rs`

`distri-kv/src/multi_raft.rs` is an 11-line re-export of `ezraft::multi_raft`.

The real code is in `ezraft/src/multi_raft.rs`:

- `MultiRaftCluster::new(config, state_machine_factory)` (line 389) creates
  `initial_partitions` `RaftPartition`s, each with its own `Node`.
- `create_partition` (line 419) sets `peers: HashMap::new()` (line 463) — every
  partition is a **single-node Raft group**. The tick task discards outgoing
  messages with ``TODO: In a real implementation, these messages would be sent
  to other nodes`` (line 481).
- `put`/`delete` route through a consistent-hash ring and propose on that
  partition (lines 501-645). `get` (line 501) calls
  `state.state_machine.apply(b"GET <key>")`, which the distri-kv
  `GenericStateMachine` cannot parse (it expects a JSON `Command`), so `get`
  returns the bytes `Error: Invalid command` instead of `None`/value.
- Replication, partition split/merge, and jurisdiction partitioning are
  scaffolding only: `replication_factor` is unused, `split_threshold` is only
  used by `PartitionManager`, and jurisdiction is only a field.
- **The distri-kv server never instantiates `MultiRaftCluster`.** It uses
  `ezraft::Node` directly. The only `multi_raft` types used by the server are
  `ConsistentHashRing`/`PartitionId` for the jurisdiction router
  (`server.rs:200-215`, `router.rs`).

So "Multi-Raft" is not the deployed KV layer, and the deployed KV layer has no
client write path.

### 3.4 `storage_adapter.rs`, TTL

- `StorageAdapter` trait (line 27): synchronous `get`, `put`,
  `put_with_ttl`, `delete`, `delete_expired`, `is_empty`, `transaction`,
  `create_snapshot`, `restore_snapshot`, `get_stats`. It is a **blocking**
  trait, which is why the async manager blocks.
- `GenericStateMachine` (line 97) applies `Command::{Put, Delete, PutWithTtl,
  DeleteExpired}` encoded as JSON.
- `SledStorageAdapter` (`sled_adapter.rs:25-39`):
  `put_with_ttl` ignores the TTL (`_ttl_seconds`), `delete_expired` returns
  `Ok(0)`. **TTL does not exist on sled.** The server's KV store and the
  manager's test/demo storage are sled.
- `RedbStorageAdapter` does implement expiry with a second table
  (`redb_adapter.rs:105-180`), including `delete_expired`. It is not the
  backend the server wires by default.
- `TtlManager` (`ttl_manager.rs`) is a 60 s background `delete_expired` loop;
  it is never constructed by the server. `register_ttl_cleanup`
  (`distributed_rate_limit.rs:632`) is an empty `Ok(())` that only comments
  that some other component handles it — and no other component does.

### 3.5 `proto/distri_kv.proto`, `service.rs`, `server.rs`

Client service (`proto/distri_kv.proto:5-31`): `Mutate` (bidi stream), `Get`,
`Watch`, `Publish`, `Subscribe`, `Acknowledge`, `ChangeConfig`. There is **no
rate-limit, threat-intel, reputation, event, or node-registry RPC**.

`DistriKvService` (`service.rs`, 157 lines) implements none of them:

| RPC | Evidence | Behaviour |
|---|---|---|
| `Mutate` | `service.rs:70-104` | Parses the request, returns `SuccessResponse` **without writing** (two `TODO: Implement proper storage access via Raft propose`, lines 84/90). `Delete` silently succeeds. |
| `Get` | `service.rs:112-115` | `Status::unimplemented("get not implemented")` |
| `Watch` | `service.rs:117-123` | Returns an empty stream; `WatchManager` is never instantiated |
| `Publish` | `service.rs:126-131` | `unimplemented` |
| `Subscribe` | `service.rs:134-140` | Empty stream; `StreamingManager` never instantiated |
| `Acknowledge` | `service.rs:143-148` | `unimplemented` |
| `ChangeConfig` | `service.rs:151-156` | `unimplemented` — also means **no dynamic cluster membership**; peers are fixed from CLI args at boot |

The struct stores its dependencies with leading underscores (`_node`,
`_monitoring`, `_router`, `_kv_clients`), i.e. deliberately unused.

Raft service (`raft_service.rs`) is the only functional gRPC surface:
`AppendEntries`, `RequestVote`, `PreVote` update the node state machine and
forward generated messages to `peers_clients`. `change_config` on this service
applies locally but does not notify peers.

### 3.6 `distri-kv-client/src/lib.rs` (38 lines)

The entire client API is:

- `Client::connect(addr)`
- `Client::change_config(ChangeConfigRequest)`
- a comment ``// ... client methods for Get, Put, etc.``

`change_config` targets the server method that is `unimplemented`, so the
client cannot currently perform any successful operation beyond connecting.
`distri-kv-admin` only exposes `AddServer`/`RemoveServer`, both of which call
that same unimplemented method.

### 3.7 Watch, streaming, metadata, router

- `WatchManager` (446 lines) implements subscriptions, glob matching, a
  10 000-event replay buffer and revisions. It is **dead code**: never
  constructed, and `service.rs` returns an empty stream.
- `StreamingManager` (610 lines) implements topics, consumer groups,
  ack/nack, TTL and competing consumers in memory. Also **dead code**: never
  constructed, never persisted, no RPC wiring.
- `ClusterMetadataStore` (`cluster_metadata.rs:9-14`) has exactly one command:
  `Register { node_id, jurisdictions }`. There is no endpoint, address, role,
  heartbeat, timestamp, or deregistration. The watch channel and global cache
  are updated only when `apply` runs on that private node.
- `JurisdictionAwareRouter` is a `HashMap<String, ConsistentHashRing>` plus a
  default ring. It is populated only from the metadata cache in
  `server.rs:200-215`; because the metadata group has no peers and accepts no
  remote commands, its contents are just this node's own registration.

---

## 4. Documentation vs. code

### 4.1 `docs/WAF_INTEGRATION_GUIDE.md` (865 lines)

Almost every code sample is non-existent API. Specifically:

| Claim | Reality |
|---|---|
| Crate dependency `distri-kv-client = { version = "2.0", features = ["waf", "geo-aware"] }` | `distri-kv-client` is `0.1.0`, has no features, and 38 lines of client code |
| `WafDistriKvClient`, `WafConfig`, `GeoConfig`, `PerformanceTargets` | No such types |
| `check_rate_limit_with_geo(ip, resource, headers, RateLimitConfig)` | No such method, no geo, no `resource` dimension |
| `get_ip_reputation_with_geo(...)` / `ThreatIntelligenceResult` | No such method or type; no reputation store |
| `ingest_security_event_with_correlation(...)`, `CorrelationConfig` | Server-side correlator exists but has no RPC and accepts no `target_resource`, `attack_patterns`, or cross-region config |
| `subscribe_security_rule_updates(...)`, `deploy_security_rule_urgent(...)`, `SecurityRule` | No rule type, no rule RPC, no subscription wiring |
| `process_with_gdpr_compliance`, `execute_right_to_erasure`, `GdprConfig` | No GDPR code at all |
| `analyze_asn_threat_patterns`, `deploy_asn_security_rule`, ASN routing | No ASN code; `maxminddb` is not a dependency |
| `get_performance_metrics(...)`, SLA percentages | No such client API; no WAF-specific metrics are exported |
| P99 2 ms reputation / 3 ms rate limit / 5 ms regional, 100K ops/s, 50K events/s, 1K streams, 99.99 % uptime | No benchmark in the repo compiles or measures any of these. `GRPC_WAF_LOAD_TEST_REPORT.md` declares "✅ SUITABLE FOR PRODUCTION WAF DEPLOYMENT" while `Get` is unimplemented and `Mutate` fabricates success |

### 4.2 `docs/GEOAWARE.md` (1049 lines)

An implementation plan, not a description. It specifies `GeoIpv6`,
`WafGeoContext`, `WafValueType`, `GeoScope`, `maxminddb = "0.24"` and a
`src/waf/` module. None exist: `maxminddb` is absent from all `Cargo.toml`/
`Cargo.lock`, and the only geo-named code is
`synapse_gaming_waf.rs`, whose `GeoBlocker` and `GeolocationService` are
`todo!()` stubs (`synapse_gaming_waf.rs:719-746`). The document already marks
several SLAs with ✅ even though the checklist items are unchecked (`[ ]`)
later in the same file.

### 4.3 `DISTRIBUTED_SECURITY_IMPLEMENTATION_STATUS.md`

| Claim | Reality |
|---|---|
| "All distributed rate limiting components now compile successfully" | `distributed_rate_limit.rs` compiles in isolation, but the crate does not compile (`lib.rs:31`, gaming modules) and `security_correlation.rs` fails at `:219` (§1) |
| "Integration Tests: `distributed_rate_limit_test.rs` — manager creation, basic functionality, metrics" | File is syntactically invalid and refers to a non-existent `total_requests` metric |
| "Performance Benchmarks … sub-millisecond target validation framework" | Bench target does not compile; `criterion` is not a dependency |
| "`security_correlation.rs` (665+ lines)" | 443 lines |
| "Real-time event processing … correlate security events across cluster nodes" | Single-process `HashMap`; no node-to-node path |
| "Automated Response … immediate threat mitigation" | Only mutates a local `f64` multiplier; "block" is a clamped refill slowdown |
| "Consensus-based enforcement … Raft Consensus → Multi-Raft Cluster Storage" | `consensus` field unused; writes go to local sled |
| "Sub-millisecond response for cache hits (L1/L2/L3 caching)" | There is one LRU cache, not three tiers; no measurement exists |
| "Phase 1: Ready Now / WAF can immediately integrate" | There is no callable API to integrate with |

### 4.4 `docs/DISTRIBUTED_RATE_LIMITING_ARCHITECTURE.md`, `docs/DISTRIBUTED_SECURITY_EVENT_CORRELATION.md`

These are design documents (`Status: Design Phase` / `Architecture Design
Phase`) and are internally consistent as designs, but they describe types that
do not exist: `GlobalIpReputationSystem`, `IpReputation`, `AttackCoordinationEngine`,
`AttackPattern`, `SecurityEventPartitioner`, `CrossPartitionCorrelator`,
`ConsensusSecurityDecisionEngine`, `SecurityDecisionCache`,
`MultiRaftManager`, `SecurityLoadBalancer`. None appear in the crate.

---

## 5. Capability matrix

Legend: **Implemented** = works as described in the deployed binary;
**Partial** = code exists but is node-local, unwired, or semantically wrong;
**Documented-only** = no working code.

| # | Capability | Status | Evidence |
|---|---|---|---|
| 1 | KV `Get` over gRPC | Documented-only | `service.rs:112-115` returns `unimplemented`; `client/lib.rs` has no `get` |
| 2 | KV `Put`/`Delete` over gRPC | Documented-only | `service.rs:84-90` returns success without writing |
| 3 | `Watch` / change subscription | Documented-only | `service.rs:117-123` empty stream; `WatchManager` never constructed |
| 4 | `Publish`/`Subscribe`/`Ack` | Documented-only | `service.rs:126-148`; `StreamingManager` never constructed |
| 5 | `ChangeConfig` / dynamic membership | Documented-only | `service.rs:151-156`; peers fixed at boot |
| 6 | Raft log replication transport | Partial | `raft_service.rs` handles AppendEntries/Vote; `server.rs:300-372` sends to peers. Nothing proposes KV commands, so replication carries no payload |
| 7 | Multi-Raft partitioned KV | Partial / stub | `ezraft/src/multi_raft.rs:463,481` — empty peers, messages dropped; `get` returns `Error: Invalid command` |
| 8 | TTL expiry | Partial | redb only (`redb_adapter.rs:105-180`); sled ignores TTL (`sled_adapter.rs:25-39`); `TtlManager` not started by server |
| 9 | Local token bucket per IP | Implemented (library) | `distributed_rate_limit.rs:88-108, 329` |
| 10 | Cluster-wide rate limit / consensus | Documented-only | `consensus` unused (`:289,437-440`); batch replication never applied (`:593-610`) |
| 11 | Rate-limit metrics | Partial | In-memory atomics (`:219-266`); not exported by `monitoring.rs`; misleading `consensus_reads` |
| 12 | Security event model | Does not compile | Types present at `security_correlation.rs:13-73`; module fails at `:219` (E0689) |
| 13 | Event correlation scoring | Does not compile / local-only | `:207-260`; in-process window |
| 14 | Threat assessment | Does not compile / local-only | `:324-352`; `HashMap` average |
| 15 | Enforcement (block/challenge) | Partial | Only `update_threat_multiplier` (`:300-320`); clamp at 10.0 |
| 16 | Event persistence / shared event log | Absent | No storage calls in `security_correlation.rs` |
| 17 | Node registration | Partial | `cluster_metadata.rs:9-14` Register only; local, one-shot (`server.rs:193`) |
| 18 | Heartbeat / liveness / failover | Absent | No heartbeat, timestamp, or deregistration command |
| 19 | Endpoint / topology discovery | Absent | Register carries only `jurisdictions`; metadata node has no peers and no RPC server |
| 20 | Shared IP reputation / threat intel | Absent | No types, no keys, no RPC; `get_ip_reputation*` referenced only in docs |
| 21 | Allowlist / rule / config propagation with versioning | Absent | No command, no watch wiring; `version` fields are unused |
| 22 | Cross-node event ingestion + subscription | Absent | No RPC; correlator is in-process |
| 23 | GeoIP / ASN / jurisdiction enforcement | Absent | No `maxminddb`; gaming `GeoBlocker` is `todo!()` (`synapse_gaming_waf.rs:719`) |
| 24 | Client library (CRUD) | Partial | `distri-kv-client/src/lib.rs:20-37` — `change_config` only |
| 25 | Authn/authz/mTLS on client API | Absent | No TLS or auth configuration on the `DistriKv` server |
| 26 | Operator metrics/health | Partial | Loopback-only warp endpoints (`server.rs:460-500`); placeholder storage stats |
| 27 | Integration tests | Broken | `tests/distributed_rate_limit_test.rs` does not parse |
| 28 | Performance benchmarks | Broken | Missing `criterion`; invalid `MultiRaftConfig` fields |

---

## 6. What a WAF node needs, and what is missing

| WAF need | Required contract | distri-kv today | Gap |
|---|---|---|---|
| **Node registration / heartbeat / discovery** | Register node id + reachable endpoint + region + version; periodic heartbeat; lease expiry; `ListNodes` / watch | One local `Register { node_id, jurisdictions }` at boot on a private single-node group; no endpoint, no heartbeat, no TTL, no RPC | Full feature, including a network-exposed metadata group |
| **Shared threat intel / IP reputation read+write** | Versioned, TTL'd records keyed by IP/CIDR/ASN with confidence, source, expiry; read RPC + watch | None. Correlator state is an in-memory map; no keys or RPC | Full feature |
| **Distributed rate-limit check** | `TryAcquire{ip, resource, cost, window}` returning allow/deny + remaining + retry, with local cache and explicit failure mode | Local per-node bucket in sled; no replication; no `resource` dimension; no failure-mode config; synchronous storage in async path | RPC + replication + failure policy; or accept local-only semantics |
| **Config / allowlist propagation** | Versioned bundles with `generation`, `etag`, signature; push via watch; ack/nack | No bundle type, no versioned writes, no watch wiring, no signatures | Full feature |
| **Event ingestion / correlation / subscription** | Bounded async `IngestEvent`; windowed aggregates; `SubscribeThreats`/`SubscribeDecision` stream with resume token | In-process `HashMap`; no RPC; `StreamingManager` dead code | Full feature |
| **Audit / durability** | Durable, ordered event log with retention | sled KV with no working TTL; events not written at all | Full feature |

A WAF integration that assumes any of the five rows above is **blocked today**;
the ADR's two-plane design remains a design, not an integration against an
existing capability.

---

## 7. Latency, consistency, and failure analysis

### 7.1 Latency

No latency number in the repository is measured. The advertised figures
(2 ms reputation, 3 ms rate limit, sub-millisecond cache hits) have no
reproducible benchmark: the bench target does not compile, and the k6 report
tests a gRPC service that returns `unimplemented`/fabricated success.

Analytically, the library's local path is:

- **Cache hit:** one `tokio::sync::RwLock` write acquisition, one LRU lookup,
  and token arithmetic over `SystemTime`. This is microsecond-scale in
  isolation, but the write lock is per manager and serialises every concurrent
  check for the whole process. Under multi-core request concurrency this is a
  contention point, not a per-core fast path.
- **Cache miss:** a synchronous sled `get` executed on the async executor
  thread (`:440`). Expect tens of microseconds to milliseconds depending on
  cache/disk, and possible reactor stalls. There is no read-ahead, no
  `spawn_blocking`, and no batching of reads.
- **Write path:** a `Vec` push under an `RwLock`, then every 50 ms a bincode
  serialisation of every pending update plus a sled write. Because applied
  state is not updated in the background path, this cost buys no correctness.
- **Unbounded growth:** every batch record is retained on sled (TTL is a no-op),
  so steady-state traffic grows disk without bound.

### 7.2 Consistency

- **There is no cross-node consistency for rate limits, threat state, or
  reputation.** Each WAF node that embedded this library would enforce its own
  bucket. For an attacker spreading requests over `N` nodes, the effective
  budget is `N × capacity / refill`.
- The module's `consensus_reads`/`consensus_writes` metrics measure local sled
  I/O, so dashboards would falsely suggest consensus traffic.
- `version` is incremented but never compared; no CAS, no optimistic retry, no
  idempotency key on updates. If storage were shared, concurrent updates would
  silently overwrite.
- Ordering across nodes is undefined. `Uuid` batch ids give traceability but no
  ordering.
- The Raft stack that *does* replicate (`ezraft::Node` + raft service) is not
  connected to any of this state.

### 7.3 Failure behaviour

- `check_rate_limit` returns `Err(StorageError)` on any storage failure. The
  caller must invent fail-open/fail-closed behaviour; there is no configured
  policy and no "stale local state" mode.
- Dropping the manager leaves the batch task running with cloned `Arc`s (no
  shutdown signal), so background writes continue until process exit.
- `DistributedSecurityCorrelator` cannot fail on persistence because it never
  persists; a restart loses all correlation history. Any in-flight block is
  forgotten, which is a security regression on failover.
- The metadata registration result is discarded, so a node that fails to become
  metadata leader still believes it is registered.

### 7.4 Single points of failure

- **KV writes:** only a Raft leader can accept a write (`ezraft::Node::
  propose_command`), and the peer set is static at boot. Loss of quorum stops
  writes; `ChangeConfig` is unimplemented, so recovery requires restart with new
  CLI peers.
- **Client reads:** the only read path is unimplemented; there is no follower
  read option despite the proto's `ReadConsistency` enum.
- **Metadata/topology:** the metadata Raft group is a separate single-node node
  with no network listener. Topology is whatever each process registered for
  itself; there is no authoritative cluster view and no failover.
- **Monitoring:** bound to loopback, so no remote scrape without a sidecar.
- **Rate limiting:** no shared state, therefore no single point of failure —
  but also no correctness under horizontal scaling.

### 7.5 Hot-path verdict

**No.** A WAF cannot call this synchronously per request because:

1. no protobuf RPC exposes rate limiting, reputation, events, or policy;
2. the only client method targets an `unimplemented` server method;
3. the library path performs blocking disk I/O inside async code and holds a
   global write lock per check;
4. even if embedded in-process, the semantics are node-local, so the result is
   not a distributed decision.

The only defensible use today is as a **local token-bucket library** in a
single process, with TTL/consensus/metrics claims removed.

---

## 8. Reconciliation with ADR-0007

The ADR's §12 checklist, answered from code:

1. **API reality check (batch/delta vs per-key `try_acquire`).** distri-kv
   exposes per-key `check_rate_limit` only. There is no batch/delta API; the
   internal `RateLimitBatchUpdate` is a private storage record, not a callable
   contract. §4.4 of the ADR must be marked *aspirational* and needs an adapter
   (or a new service) before `CounterDelta` can exist.
2. **Correlation API.** `process_security_event` accepts a `SecurityEvent` and
   returns a `CorrelationResult`, but only in-process; there is no network
   ingest surface, no window-aggregate query, and no cross-node state. §6.3
   needs a new ingest/query surface. `get_threat_assessment` is the only
   aggregate and is per-IP, per-process.
3. **Geo APIs.** distri-kv has **no** GeoIP/ASN lookup and no `maxminddb`
   dependency. Remove any assumption that distri-kv supplies geo; the ADR's
   "GeoIP stays local" position is the only correct one.
4. **Consensus semantics.** The deployed KV is a single Raft group over static
   peers; `MultiRaftCluster` is not used and its partitions have no peers.
   There is no regional/global group split. §2.3 and Q1 must be revised: a
   regional/global tier needs to be built, not configured.
5. **Client API.** The gRPC IDL has only `Mutate/Get/Watch/Publish/Subscribe/
   Acknowledge/ChangeConfig`, all unimplemented on the client service, plus the
   internal `Raft` service. There is no auth, TLS, or SPIFFE. A WAF-facing
   contract must be added; mapping the current messages is insufficient
   because the semantics (fake success, empty streams) are unsafe.
6. **Licensing.** Root `LICENSE` is MIT, with a separate `LICENSE-AGPL-3.0`.
   The collaboration documents (`Requests_For_WAF-Rejected.md`,
   `WAF_CODE_REQUEST.md`) describe an AGPL-3.0 side. Treat the security modules
   as reference designs until licensing is confirmed; keep a protocol boundary.

Dated note for the ADR: the assumptions that distri-kv already provides
"batched counter/delta replication" and "windowed event aggregation" are not
met by commit `c6fd36d`. They are useful starting points, not capabilities.

**Update (2026-11-08):** ADR-0007 has been reconciled against this audit in its
[§12](./distributed-waf-architecture.md#12-reconciliation-with-the-distri-kv-audit).
All six items above are resolved as corrections: §4.4 is marked aspirational,
§6.3 requires a new ingest/query surface, GeoIP is confirmed local, the
regional/global tier is a build prerequisite, the `DistriWaf` contract is owned
by WAF-Rejected, and licensing stays a protocol boundary. The ordered
build/contract prerequisites are in
[§12.2](./distributed-waf-architecture.md#122-build-and-contract-prerequisites-ordered).

---

## 9. Findings that must be fixed before integration (ordered)

These are observations for the distri-kv owners; nothing here was changed.

0. **Make the crate build.** Restore or delete `k8s_auto_config`, repair or
   gate the `synapse_gaming_*` modules, add `rand`, and fix the untyped float
   in `security_correlation.rs:219`. Until then every other claim is
   unverifiable by CI.
1. **Stop advertising a service that is a stub.** Either implement `Get` and
   `Mutate` via `ezraft::Node::propose_command` or remove them from the
   published interface. Returning fabricated `SuccessResponse` is the most
   dangerous defect in the tree.
2. **Connect the security modules to a transport.** Add explicit protobuf
   messages (`TryAcquire`, `IngestEvent`, `GetReputation`, `WatchConfig`,
   `RegisterNode`, `Heartbeat`) and implement them against the managers.
3. **Decide what is replicated.** If rate-limit state is replicated, call
   `MultiRaftCluster::put` (or the `Node` proposal path) instead of local
   `storage.put`; if not, remove the `consensus` field and all "distributed"
   claims.
4. **Make the background batch path apply updates** (or delete it), and delete
   batch records after application.
5. **Fix TTL.** Sled ignores `put_with_ttl`; the server uses sled. Either wire
   redb or implement expiry metadata + `delete_expired` for sled before any
   TTL-dependent feature (rate limits, reputation, leases) is used.
6. **Do not block the async executor.** Move `StorageAdapter` calls to
   `spawn_blocking` or make the trait async, and shard the cache instead of one
   process-wide write lock.
7. **Add a failure-mode contract** (`stale_allow` / `stale_block` /
   `local_only`) and return it from `check_rate_limit`.
8. **Implement blocking, not multiplier inflation.** `PermanentBlock` must
   produce a deny verdict, not a clamped refill rate.
9. **Fix or delete the test/bench targets.** Add `criterion`, repair the config
   literals, and split `distri-kv/tests` so a syntax error cannot hide the
   entire suite.
10. **Add node identity and liveness.** Registration needs endpoint, region,
    heartbeat, lease expiry, and deregistration, served from the metadata group
    over gRPC if discovery is in scope.

---

## 10. Evidence index

| Topic | File:lines |
|---|---|
| Missing module / crate build failure | `distri-kv/src/lib.rs:31`, `distri-kv/src/synapse_gaming_test.rs:14,514` |
| Correlator compile error | `distri-kv/src/security_correlation.rs:211-219` |
| Unused consensus/TTL (compiler warning) | `distri-kv/src/distributed_rate_limit.rs:289-291` |
| Client RPC stubs | `distri-kv/src/service.rs:70-156` |
| Raft transport | `distri-kv/src/raft_service.rs:76-178` |
| Server wiring / metadata group | `distri-kv/src/server.rs:186-215, 261, 279, 300-372` |
| Unused consensus field | `distri-kv/src/distributed_rate_limit.rs:289, 437-440, 517-561` |
| Batch writer applies nothing | `distri-kv/src/distributed_rate_limit.rs:564-610` |
| Local cache lock + sync read | `distri-kv/src/distributed_rate_limit.rs:366-444` |
| In-memory correlation only | `distri-kv/src/security_correlation.rs:110, 159, 169-181, 324` |
| Block clamped to 10× slowdown | `distri-kv/src/security_correlation.rs:300-320` + `distributed_rate_limit.rs:112-115` |
| Multi-Raft single-node partitions | `ezraft/src/multi_raft.rs:389-490` |
| Broken multi-raft get | `ezraft/src/multi_raft.rs:501-540` |
| Sled TTL no-op | `distri-kv/src/sled_adapter.rs:25-39` |
| Redb TTL works | `distri-kv/src/redb_adapter.rs:105-180` |
| Metadata command surface | `distri-kv/src/cluster_metadata.rs:9-14, 39` |
| Dead watch/stream managers | `distri-kv/src/watch_manager.rs`, `streaming_manager.rs` (no constructors called) |
| Client surface | `distri-kv-client/src/lib.rs:20-37` |
| Protobuf surface | `proto/distri_kv.proto:5-38` |
| Broken tests | `distri-kv/tests/distributed_rate_limit_test.rs` (duplicate fn, orphan block, missing imports) |
| Broken bench | `distri-kv/benches/distributed_rate_limit_bench.rs:37-46` (invalid `MultiRaftConfig`), missing `criterion` |
| Geo stubs | `distri-kv/src/synapse_gaming_waf.rs:719-746` |
| Placeholder monitoring | `distri-kv/src/server.rs:398-402` |
