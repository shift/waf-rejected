# ADR-0007: Distributed WAF security fabric over distri-kv

- **Status:** Accepted (architecture decisions recorded in
  [§11 ADR-0008](#11-decision-log-adr-0008); design only, not implemented)
- **Date:** 2026-11-08
- **Owners:** WAF architecture group, distri-kv maintainers
- **Related:** [distri-kv capability audit](./distri-kv-audit.md),
  [Security model](../architecture/security-model.md),
  [gRPC transport](../architecture/grpc-transport.md),
  [`Requests_For_WAF-Rejected.md`](../../Requests_For_WAF-Rejected.md),
  [`WAF_CODE_REQUEST.md`](../../WAF_CODE_REQUEST.md),
  [`docs/Optimizations.md`](../Optimizations.md)
- **Implementation:** none in this change. This document defines the contract
  that both repositories implement against. The distri-kv prerequisites are in
  [§12.2](#122-build-and-contract-prerequisites-ordered); the end-to-end
  dependency order is in [§15](#15-what-remains-before-implementation).

> **Revision note (2026-11-08):** the architecture owner has resolved the open
> questions. This revision replaces the former §11 question table with a formal
> decision log (ADR-0008), sets the false-positive budget for automated
> distributed blocks to **0%**, reconciles §12 with
> [`distri-kv-audit.md`](./distri-kv-audit.md), and adds the dependency-ordered
> remainder list in §15.

---

## 0. Executive summary

WAF-Rejected is today a single-process reverse proxy with a local, sharded
token-bucket rate limiter (`src/waf/rate_limit.rs`), a local allow-verdict cache
(`src/waf/allow_cache.rs`), a local GeoIP service (`src/waf/geoip.rs`), local
security-event exporters (`src/waf/exporters/`), and an in-process threat
intelligence engine (`src/threat_intelligence.rs`). The security model
explicitly lists distributed state as a non-goal: “Rate limits, geo cache and
event storage are local to one process. There is no Redis/cluster
coordination.” ([security-model §6](../architecture/security-model.md#6-explicit-non-goals-and-residual-risks)).

This ADR defines how a fleet of WAF nodes shares security state through
distri-kv without putting Raft consensus on the request path.

The core decision is a **two-plane split**:

1. **Data plane (WAF process, hot path).** Every request is decided from
   process-local, already-compiled state: compiled CRS rules, the local
   rate-limit buckets, the local allow cache, a local reputation/blocklist
   cache, and local GeoIP. No Raft round trip, no blocking network call.
2. **Control plane (distri-kv cluster).** distri-kv owns authoritative
   policy bundles, the node registry, reputation/blocklists, correlation state
   and aggregated counters. WAF nodes are *clients*, not Raft voters. They pull
   versioned state through watches and push events/counters asynchronously
   through bounded queues and batches.

The invariant is: **a WAF node with a live local cache and no distri-kv
connectivity must still enforce its last-known-good policy and local limits.**
Consensus failures degrade freshness, not availability. The default is
`distributed.fallback_mode = "local_only"`; the other fallback modes are
explicit opt-ins (see §5.6).

The design intends to build on two distri-kv building blocks,
`distributed_rate_limit.rs` (batched counter/delta replication) and
`security_correlation.rs` (windowed event aggregation). The
[capability audit](./distri-kv-audit.md) shows that at commit `c6fd36d` these
are **node-local libraries with no RPC, no replication and a broken build**, so
the split below is a target design, not an integration against working
capability (§12).

**Global actions are conservative by construction.** No automated distributed
block is permitted from heuristics, ML or anomaly scoring. A global block is
applied only when it is either (a) an **exact-match deterministic indicator**
from an operator-supplied blocklist or a known-bad hash/URL, or (b) a
**heuristic candidate that an operator has explicitly approved**. Regional
corroboration is a *detection* signal that raises confidence and alert
priority; it never authorises an automatic global block. See §6.3, §6.4 and
ADR-0008 D2/D6.

---

## 1. Goals and non-goals

### 1.1 Goals

| ID | Goal |
|---|---|
| G1 | **Regional endpoints.** An IP added to a regional blocklist by an operator or an exact-match deterministic indicator is enforced by all nodes in that region within a bounded propagation target (p95 ≤ 5 s; see §4.6). Heuristic indicators are propagated as alerts/throttles, never as automatic blocks. |
| G2 | **Shared security data.** Threat intel, IP reputation, allow/block lists, ruleset versions and counters have one documented schema and one authority per object class. |
| G3 | **No consensus in the hot path.** p99 added latency attributable to the distributed feature is ≤ 200 µs for cache hits and 0 for a miss that falls back to local state. No request waits on a Raft leader. |
| G4 | **Availability under partition.** A WAF node keeps serving with last-known-good state. A regional distri-kv quorum loss never stops request processing. |
| G5 | **Bounded, auditable propagation.** Every shared object has a version, an author, a confidence and an expiry. Every action derived from shared state can be traced to a version and an event. |
| G6 | **Operational compatibility.** The feature is behind flags, defaults off, and composes with the existing local `RateLimiter`, `GlobalRateLimiter`, `AdaptiveRateLimiter`, `AllowCache`, `GeoIpService` and `SecurityEventLogger` rather than replacing them. |
| G7 | **No body/PII egress.** Security events sent to distri-kv contain metadata and rule IDs, never request bodies, credentials or raw header values. |

### 1.2 Non-goals

| ID | Non-goal | Reason |
|---|---|---|
| N1 | Replacing the local rate limiter with a synchronously consistent global limiter. | A strictly global token bucket requires a consensus round trip per request and violates G3. We use local buckets with asynchronous shared deltas (§4.4). |
| N2 | Shipping request or response bodies to distri-kv. | Data minimisation and legal exposure. Bodies stay in the WAF process. |
| N3 | Making WAF nodes Raft voters. | WAF fleets scale with traffic, not with consensus; adding voters increases quorum fragility. WAF nodes are stateless clients. |
| N4 | Exactly-once event delivery. | At-least-once with idempotent event IDs is sufficient for correlation; exactly-once would require distributed transactions on the hot path. |
| N5 | Global, strongly consistent IP block decisions across all regions. | Cross-region linearizability costs a WAN round trip. Global blocks are versioned policy decisions with bounded asynchronous propagation. |
| N6 | Storing full audit logs only in distri-kv. | distri-kv is not a WORM store. The existing exporters (`exporters/sled.rs`, `exporters/cef.rs`, `exporters/otel.rs`) remain the evidence path; distri-kv indexes for correlation. |
| N7 | Multi-tenant isolation below the cluster boundary. | The first version is single-tenant per cluster (ADR-0008 D7). |
| N8 | Solving GeoIP database distribution. | GeoIP remains a local `.mmdb` file via `waf.geo_blocking`; only *derived* country/ASN reputation is shared. |

### 1.3 Latency budget

The distributed feature is allowed to consume the following budget. These are
additive to the existing WAF p50/p99 numbers, not replacements.

| Path | Budget (p99) | Mechanism |
|---|---|---|
| Local reputation lookup (LRU + radix trie) | 20 µs | In-process, no allocation on hit |
| Local blocklist/allowlist lookup | 10 µs | Compressed radix trie, per-policy generation |
| Local distributed-rate-limit token check | 15 µs | Existing `ShardedBuckets` math; shared delta applied lazily |
| Cache-miss synchronous distri-kv read | **not on request path** | Miss returns the local policy default and triggers async fetch |
| Async counter flush | 0 on hot path | Bounded `mpsc`, background task |
| Event enqueue | ≤ 5 µs | `try_send` into bounded queue; drop-oldest with metric |
| Watch/applied config swap | 0 on hot path | `arc-swap` generation swap on a background task |

**Hard rule:** the request path may perform only lock-free/atomic reads and
in-memory lookups. It may never `await` a distri-kv RPC. A background task is
the only caller of the distri-kv client from within the WAF process.

### 1.4 Success criteria

- A WAF node can be killed and restarted and re-registers within 10 s.
- A regional distri-kv cluster can lose quorum for 30 minutes while WAF nodes
  continue to serve with `local_only` semantics (or an explicitly configured
  `stale_*` mode) without dropping requests.
- A new ruleset version is applied by 99% of regional WAF nodes within 30 s.
- An operator-approved or exact-IOC block is enforced by all regional nodes
  within 5 s p95 and all regions within 60 s p95.
- A heuristic indicator observed on 3 nodes raises an alert and regional
  throttle within 5 s p95; it does **not** become a block anywhere without
  operator approval.
- No request-handling task performs a network I/O operation outside upstream
  forwarding and response streaming.

---

## 2. Topology

### 2.1 Cells, regions and partitions

```
                         ┌──────────────────────────────────────┐
                         │ Global control plane (optional tier) │
                         │  policy approval, cross-region intel  │
                         │  one distri-kv group, 5 voters        │
                         └───────────────┬──────────────────────┘
                                         │ async replication (WAN)
          ┌──────────────────────────────┼──────────────────────────────┐
          │                              │                              │
┌─────────▼─────────┐          ┌─────────▼─────────┐          ┌─────────▼─────────┐
│ Region eu-west-1  │          │ Region us-east-1  │          │ Region ap-south-1 │
│ ┌───────────────┐ │          │ ┌───────────────┐ │          │ ┌───────────────┐ │
│ │ distri-kv     │ │          │ │ distri-kv     │ │          │ │ distri-kv     │ │
│ │ 3–5 voters    │ │          │ │ 3–5 voters    │ │          │ │ 3–5 voters    │ │
│ │ N partitions  │ │          │ │ N partitions  │ │          │ │ N partitions  │ │
│ └───────┬───────┘ │          │ └───────┬───────┘ │          │ └───────┬───────┘ │
│         │ gRPC    │          │         │ gRPC    │          │         │ gRPC    │
│  ┌──────▼──────┐  │          │  ┌──────▼──────┐  │          │  ┌──────▼──────┐  │
│  │ WAF node A  │  │          │  │ WAF node D  │  │          │  │ WAF node G  │  │
│  │ WAF node B  │  │          │  │ WAF node E  │  │          │  │ WAF node H  │  │
│  │ WAF node C  │  │          │  │ WAF node F  │  │          │  │ WAF node I  │  │
│  └─────────────┘  │          │  └─────────────┘  │          │  └─────────────┘  │
└───────────────────┘          └───────────────────┘          └───────────────────┘
```

- A **region** is the failure and consistency domain for policy, rate-limit
  accounting and blocklists. It contains one regional Multi-Raft cluster.
- A **cell** is one distri-kv Raft group (partition) plus the WAF nodes that
  primarily talk to it. A region has `partitions` cells; each cell has 3 or 5
  voters.
- **WAF nodes are clients only.** They are deployed in the same region, use a
  regional anycast/leader-aware endpoint, and never vote.
- **Global tier is optional and async.** A global group holds approved global
  policy and cross-region intel. It replicates to regional groups through
  distri-kv's existing replication channel with a bounded lag SLO. If it is
  absent, each region is autonomous; cross-region sharing degrades to
  operator-pushed bundles.

### 2.2 Where the planes sit

| Concern | Control plane (distri-kv) | Data plane (WAF) |
|---|---|---|
| Ruleset/config | Authoritative, versioned, signed bundles | Compiled, swapped by generation |
| Block/allow lists | Authoritative per scope | Cached radix trie |
| Threat intel/reputation | Authoritative with confidence + TTL | LRU with TTL + local overrides |
| Rate limits | Aggregated deltas, global observability | Local enforcement, local buckets |
| Node registry | Authoritative liveness/epoch | Heartbeat producer |
| Event correlation | Windowed aggregation, threat multipliers | Event producer, local pre-aggregation |
| Audit evidence | Index and correlation only | Primary export path (CEF/Sled/OTel) |

### 2.3 Why not a single global Raft group?

A single global group gives linearizable blocklists but makes every region’s
availability depend on WAN health and adds a WAN RTT to every control-plane
operation. The architecture owner has decided on **regional cells plus an
asynchronous global tier, with eventual global consistency** (ADR-0008 D1).
Regional consistency is the strong domain; global state is versioned and
eventually consistent. The combined behaviour required is “bounded staleness
with a visible version”, not global linearizability.

**Audit correction (§12):** distri-kv at `c6fd36d` does not provide this split.
The deployed KV is a single Raft group over static peers; `MultiRaftCluster` is
not instantiated and its partitions have no peers, so there is no
regional/global tier and no dynamic membership (`ChangeConfig` is
`unimplemented`). The two-tier topology is therefore a **build prerequisite**
for distri-kv, not a configuration choice. If the tier cannot be built, v1
degrades to a single regional group per deployment with no global tier, and
cross-region sharing reverts to operator-pushed bundles.

### 2.4 Placement rules

- WAF node and its regional distri-kv voters should be in the same
  low-latency zone group (RTT ≤ 2 ms p99).
- Cross-region replication uses dedicated links; it must not share the egress
  path used for client traffic.
- The global tier is active only when `distributed.global.enabled = true`;
  otherwise regional clusters are roots.

---

## 3. Node registry and discovery

### 3.1 Registration schema

Stored under `node/{region}/{node_id}` in the regional group, replicated
asynchronously to the global `node-index` namespace. The registry is soft
state: it never gates request processing.

```text
NodeRecord {
  node_id:            UUIDv7            // stable, generated on first boot
  region:             String            // "eu-west-1"
  zone:               String            // "eu-west-1a"
  cluster_id:         String            // distri-kv cluster identity
  endpoints:          NodeEndpoints     // see below
  version:            String            // WAF semver, e.g. "0.1.0-beta.20"
  build_commit:       String            // git SHA
  feature_bits:       u64               // compiled features (http3, allow-cache, ...)
  capabilities:       Vec<Capability>   // enum, see below
  policy_generation:  u64               // last applied policy generation
  ruleset_version:    String            // last applied CRS/ruleset version
  health:             NodeHealth        // healthy | degraded | draining
  started_at:         Timestamp
  last_heartbeat:     Timestamp         // server time, HLC
  epoch:              u64               // monotonic boot/registration epoch
  lease_ttl_secs:     u32               // writer-provided, default 30
  labels:             BTreeMap<String,String> // env, tenant, pool
}
```

`NodeEndpoints`:

```text
NodeEndpoints {
  grpc_ingest:   String   // "10.0.4.12:9443" for event/counter push
  metrics:       String   // "10.0.4.12:8081"
  health:        String   // "10.0.4.12:8081/health"
  admin:         Option<String>
}
```

`Capability` (bitmask on the wire, enum in Rust):

```text
Capability = POLICY_WATCH | EVENT_INGEST | RATE_DELTA | REPUTATION_WATCH
           | GEOPOLICY | GRPC_INSPECTION | GRAPHQL_INSPECTION | HTTP3
           | ALLOW_CACHE | FAST_ALLOW | RESPONSE_INSPECTION
```

`NodeHealth`:

```text
NodeHealth {
  state:              HEALTHY | DEGRADED | DRAINING | UNHEALTHY
  reason:             Option<String>
  distri_connected:   bool
  queue_depth:        u32
  last_error:         Option<String>
}
```

### 3.2 Heartbeat

- Default interval **10 s**, writer TTL **30 s** (`3 × interval`).
- Heartbeats are a **bidirectional stream** (§7.2) so the server can push
  lease extensions and `DRAIN` commands without a separate RPC.
- Each heartbeat carries `node_id`, `epoch`, `policy_generation`,
  `ruleset_version`, `queue_depth`, `distri_connected`, `health`, and a
  monotonic `sequence`.
- The server rejects a heartbeat whose `epoch` is lower than the stored epoch
  (`FAILED_PRECONDITION`); the node must re-register. This prevents a restarted
  process from resurrecting pre-restart state.

### 3.3 Liveness and failure handling

| State | Condition | Registry action | WAF action |
|---|---|---|---|
| Healthy | heartbeat within TTL | refresh `last_heartbeat` | normal |
| Suspect | TTL missed, < 3 × TTL | mark `DEGRADED`, emit alert | continue |
| Dead | 3 × TTL missed | tombstone after `dead_grace`; keep event shard ownership reassigned | re-register |
| Draining | operator/`DRAIN` command | keep record, no new rate-limit shards | finish in-flight, then exit |
| Restarted | same `node_id`, higher epoch | replace record, bump epoch | re-subscribe watches from last version |

Tombstones are retained for `distributed.registry.tombstone_ttl_secs`
(default 24 h) so that a stale node cannot rejoin with old state. A rejoin with
a lower epoch is rejected and logged as a security event.

### 3.4 Discovery

WAF nodes are configured with a **regional bootstrap endpoint** and discover
the current leader/partitions through the registry service:

1. `distributed.bootstrap_endpoints = ["https://dkv-eu.example:7443"]`.
2. `Discover(DiscoverRequest { region, capabilities })` returns the current
   partition map, leader hints, the watch endpoint, and the server certificate
   SPKI hash.
3. The client caches the partition map for `distributed.discovery_ttl_secs`
   (default 60 s) and refreshes on `UNAVAILABLE`/`FAILED_PRECONDITION`.
4. No DNS-based discovery is trusted for security decisions; the certificate
   and SPIFFE identity are pinned (§9).

### 3.5 Registry consistency

The registry is per-region linearizable within the Raft group. Cross-region
registry replication is eventual; a global view may be stale by the replication
lag. Consumers that need a real-time view (e.g. correlation assignment) read
the regional registry, not the global index.

---

## 4. Shared data model

### 4.1 Namespaces and key grammar

All keys are UTF-8, `/`-separated, with a version segment where mutation
matters. Prefix scans are used for watches; point reads for cache misses.

| Prefix | Object | Scope | Consistency | TTL |
|---|---|---|---|---|
| `cfg/active/{scope}` | active policy pointer | region/global | linearizable (regional) | none |
| `cfg/bundle/{scope}/{version}` | signed config/ruleset bundle | region/global | immutable | retention |
| `pol/block/{scope}/{cidr}` | explicit block entry | region/global | linearizable (regional) | optional |
| `pol/allow/{scope}/{cidr}` | explicit allow entry | region/global | linearizable (regional) | optional |
| `intel/ip/{family}/{addr}` | IP reputation | global→regional | CRDT/LWW | 5 min–24 h |
| `intel/asn/{asn}` | ASN reputation | global→regional | CRDT/LWW | 1 h–7 d |
| `intel/domain/{name}` | domain reputation | global→regional | CRDT/LWW | 1 h–24 h |
| `rl/{policy}/{window}/{shard}` | rate-limit counter | region | CRDT counter | 2 × window |
| `rlcfg/{policy}` | distributed limiter policy | region | linearizable | none |
| `node/{region}/{node_id}` | node record | region | linearizable | lease |
| `event/{region}/{yyyy-mm-dd}/{node_id}/{event_id}` | raw event | region | append-only | 7–30 d |
| `corr/{window}/{key}` | correlation aggregate | region | CRDT | 2 × window |
| `audit/{yyyy-mm}/{seq}` | audit chain entry | region/global | append-only | retention |
| `meta/schema_version` | schema version | region/global | linearizable | none |

Scope is one of `global`, `region:{id}`, `pool:{name}`, `app:{name}`. A lookup
walks the narrowest scope first and falls back to broader scopes.

### 4.2 Policy and ruleset bundles

A bundle is an immutable, content-addressed artifact:

```text
PolicyBundle {
  schema_version:  u16
  scope:           String
  version:         u64                  // monotonically increasing per scope
  generation:      u64                  // equals version for config
  created_at:      Timestamp
  author:          String               // operator identity / pipeline
  previous_hash:   [u8;32]              // hash chain
  content_hash:    [u8;32]              // SHA-256 over canonical payload
  signature:       Vec<u8>              // Ed25519 over content_hash
  key_id:          String
  payload:         BundlePayload
}

BundlePayload {
  ruleset_uri:        String            // object-store URI or inline ref
  ruleset_version:    String            // "crs-4.14.0"
  compiled_artifact:  Option<String>    // SHA-256 of compiled Rust engine DB
  rate_limit:         RateLimitPolicy
  geo:                GeoPolicy
  reputation:         ReputationPolicy
  features:           BTreeMap<String,bool>
}
```

Activation is a CAS on `cfg/active/{scope}`:

```text
ActivateBundle {
  scope: String,
  bundle_version: u64,
  expected_current: Option<u64>,   // optimistic concurrency
  reason: String,
  approval_id: String,             // change-management reference
}
```

The WAF verifies signature, hash chain and `schema_version` before compiling.
A failed verification keeps the previous generation and raises
`waf_distributed_policy_rejected_total`. Compilation happens in a background
task; the hot path swaps an `Arc<CompiledPolicy>` with `arc-swap` so a
request never sees a half-built ruleset.

### 4.3 Threat intelligence and IP reputation

```text
IpReputation {
  ip:             IpAddr             // key
  score:          f32                // 0.0 (benign) .. 1.0 (malicious)
  confidence:     f32                // 0.0 .. 1.0
  labels:         Vec<ReputationLabel> // scanner, botnet, tor, proxy, datacenter
  sources:        Vec<SourceRef>     // feed id, event window, node id
  first_seen:     Timestamp
  last_seen:      Timestamp
  expires_at:     Timestamp
  version:        u64                // per-key monotonic
  hlc:            Hlc                // (physical_ms, logical, node_id)
  review_state:   AUTO | QUARANTINED | APPROVED | REJECTED
}
```

- **Partitioning:** `hash(family || addr)` over `partitions`, or an explicit
  prefix map for CIDR-heavy policies. IPv4 and IPv6 are separate families so a
  single v6 /64 cannot dominate a v4 shard.
- **TTL:** reputation is always expiring. Default `intel.default_ttl_secs =
  3600`, clamped to `[300, 86400]`. An expired entry behaves as unknown, not
  benign.
- **Conflict resolution:** highest `(confidence, score, hlc)` wins for
  `APPROVED`/`AUTO` entries; any `REJECTED` tombstone wins until expiry. This
  is LWW with a confidence tiebreak, implemented as a CRDT register; the
  merge is deterministic and order-independent.
- **`AUTO` is not an authorisation to block.** `review_state = AUTO` only means
  the reputation *record* was written without human review; it does not permit
  an automatic distributed block (ADR-0008 D6). Reputation may drive local
  throttling and alerts. A block requires `APPROVED` (operator) or an exact
  deterministic IOC match.
- **Allowlist precedence:** an explicit `pol/allow` entry always beats
  reputation if `ReputationPolicy.allow_overrides = true` (default true) and
  the entry is unexpired. This is the operator’s emergency brake.
- **CIDR entries:** `pol/block` supports CIDR; `intel/ip` is per address to
  keep merge semantics simple. A CIDR blocklist is expanded into a local radix
  trie on the WAF, not into the intel namespace.

### 4.4 Distributed rate limits

This is the part most likely to be misunderstood, so it is specified
explicitly.

> **Audit status (2026-11-08): aspirational.** distri-kv at `c6fd36d` exposes
> **no** batch/delta API. `DistributedRateLimitManager::check_rate_limit` is a
> per-key, node-local token check backed by local sled; its `consensus` handle
> is never read, the batch writer applies nothing, cache hits enqueue no
> update, and sled ignores TTL. The `CounterDelta` shape below is a **new
> contract to be built**, not a mapping of an existing one. Until the §12.2
> prerequisites are met, rate-limit integration can only be `observe_only`, and
> the only defensible use of the distri-kv code is as a local token-bucket
> library.

**Enforcement is local. Accounting is distributed.**

A policy declares a *global* budget and a *local* budget:

```text
RateLimitPolicy {
  policy_id:        String            // "login", "api-default"
  window_secs:      u32
  global_capacity:  u32               // cluster-wide budget per window
  local_capacity:   u32               // per-node ceiling
  burst:            u32
  key:              RateKey           // ClientIp | ApiKeyIdHash | HeaderHash | Composite
  partition:        RatePartition     // by key hash, or by key prefix
  sync_mode:        SyncMode          // AsyncDelta (default) | ObserveOnly
  conflict:         CounterMerge      // GCRA | PNCounter
}
```

- Each WAF node maintains the existing `RateLimiter`/`ShardedBuckets` locally
  with `local_capacity` and the same window. It consumes tokens locally.
- Every `distributed.ratelimit.flush_interval_ms` (default 250 ms) it emits a
  delta: `{ policy_id, shard, key_hash, consumed, window_start, node_id }`.
- The regional distri-kv `distributed_rate_limit` module maintains a
  per-window PN-counter/GCRA state per shard and computes an **observed global
  rate**. It does not return a permit for each request.
- A controller watches the global aggregate and publishes a *throttle
  multiplier* (e.g. `0.5` when the fleet is at 2× the global budget). Nodes
  apply the multiplier to their local capacity on the next window. This is a
  feedback loop with hysteresis (§6.5), not a synchronous lock.
- **Accuracy tradeoff:** under a burst, up to `flush_interval × nodes` excess
  requests can pass before the multiplier applies. This is bounded and
  documented: worst case `2 × N × flush_interval` requests. It is the price of
  G3. Operators who need tight global enforcement set a short window and a
  lower `local_capacity`, accepting more local false positives.
- **Counter merge:** `PNCounter` is used for observation because it is
  order-independent and partition-tolerant. `GCRA` is used only for the
  per-node local bucket. Do not attempt to merge GCRA state across nodes; the
  state contains `Instant` and is not portable.

Keys:

```text
rl/{policy}/{window_start}/{shard}       -> PNCounter { pos: u64, neg: u64, contributors: map<node_id,u64> }
rlcfg/{policy}                           -> RateLimitPolicy
```

`window_start` is aligned to the window boundary in **server time**; nodes
include their clock offset estimate (§8.5) and the server normalises.

### 4.5 Counters (non-rate-limit)

Generic counters use the same PN-counter merge, keyed by
`counter/{name}/{shard}`. They are observability data, never enforcement
inputs. Examples: blocked-by-rule, events-ingested, correlation windows closed.

### 4.6 Versioning and propagation targets

| Object | Authoritative writer | Version | Propagation target |
|---|---|---|---|
| Policy bundle | control-plane operator/pipeline | per-scope `u64` | p99 ≤ 30 s regional |
| Block/allow entry | operator API, or exact-match deterministic IOC | per-key `u64` | p95 ≤ 5 s regional, ≤ 60 s global |
| Reputation | correlation engine / feed | per-key `u64` | p95 ≤ 5 s regional (throttle/alert input only) |
| Rate counter | WAF nodes | PN-counter | flush 250 ms; convergence ≤ 2 s |
| Node record | WAF node | `epoch` | heartbeat 10 s |
| Event | WAF node | `event_id` (UUIDv7) | p95 ≤ 2 s |

These are SLOs, not guarantees. Each object carries a `stale_after` so
consumers can report staleness.

---

## 5. Hot-path integration

### 5.1 Local state owned by the WAF process

| State | Existing code | New distributed role |
|---|---|---|
| Compiled rules | `src/waf/rust_engine/`, `src/waf/native_coraza.rs` | Bundle supplies ruleset version; compile in background |
| Local rate limit | `src/waf/rate_limit.rs` (`RateLimiter`, `GlobalRateLimiter`, `AdaptiveRateLimiter`) | Policy supplies capacity; deltas exported |
| Allow cache | `src/waf/allow_cache.rs` (`AllowCache`, `set_generation`) | Policy generation becomes the cache generation; invalidation on bundle swap |
| Fast allow | `src/waf/fast_allow.rs` | Routes come from the signed bundle; hot reload via generation |
| GeoIP | `src/waf/geoip.rs` (`GeoIpService`, `GeoBlockingRule`) | Local `.mmdb`; shared geo policy only |
| Reputation | new `src/waf/reputation.rs` (future) | LRU/TTL cache fed by `intel/*` watch |
| Block/allow list | new `src/waf/acl.rs` (future) | Radix trie, swap on watch event |
| Events | `src/waf/security_events.rs`, `src/waf/exporters/` | New `DistriExporter` alongside CEF/Sled/OTel |
| Audit | `src/waf/exporters/sled.rs` | Local chain + async index to distri-kv |

### 5.2 Read path

```
request
  └─ fast_allow (local)
  └─ auth (local)
  └─ admission (local)
  └─ WafEngine::evaluate
       ├─ reputation lookup (local cache; miss = local default)
       ├─ ACL lookup (local trie; miss = local default)
       ├─ RateLimiter::check (local bucket)
       └─ rules (local compiled)
  └─ decision
```

A cache miss on reputation/ACL **does not** call distri-kv inline. It returns
the configured `distributed.miss_policy` (default `"local"`; alternatives
`"allow"`, `"block"`) and schedules an async point read. The async fetch
result is inserted into the local cache for subsequent requests. This is
deliberately not read-your-writes: the first request after a cache miss may
not see a just-published block. The bound is the cache fill latency, measured
by `waf_distributed_cache_fill_seconds`.

### 5.3 Write path (counters and events)

```
request decision
  └─ security event constructed (existing SecurityEventLogger)
  └─ DistriExporter::export_event
       └─ try_send to bounded mpsc (capacity 8192)
            ├─ full: increment drop counter, drop oldest batch, never block
            └─ background flusher: batch 128 events or 100 ms, gRPC stream
```

Counter deltas follow the same queue but a separate high-priority channel with
a smaller batch (250 ms). Events and counters must never share a queue in a way
that lets an event burst starve rate-limit accounting.

### 5.4 Read-your-writes vs eventual

| Operation | Model | Rationale |
|---|---|---|
| Policy activation | Read-your-writes within a region after `ActivateBundle` returns | Operator must be able to roll back and observe it |
| Block/allow entry written via API | `ReadYourWrites = REGION` by default; `GLOBAL` optional (slower) | Emergency blocks must apply immediately in the writer’s region |
| Reputation write | Eventual | High volume, derived from correlation |
| Rate counters | Eventual | Observation only |
| Node registry | Read-your-writes for the node itself | Restart semantics |
| Event ingest | At-least-once, idempotent by `event_id` | Correlation tolerates duplicates |

The WAF exposes `distributed.consistency_mode = "regional" | "global"` for
writes it originates (e.g. an admin blocklist API, if one is added). Reads on
the request path are always local and therefore eventual.

### 5.5 Per-node cache invalidation

- Every shared object carries a `generation` or `version`. Watches deliver
  `WatchEvent { key, version, op, payload_hash }`.
- The WAF keeps a `last_seen_version` per prefix and rejects out-of-order
  events. On gap detection it performs a full prefix resync.
- Policy swap uses `allow_cache.set_generation(generation)` so existing allow
  verdicts are invalidated atomically when the ruleset changes
  (`src/waf/allow_cache.rs` already supports generation-based invalidation).
- ACL and reputation caches swap an `Arc` root; readers clone the `Arc` at
  request start, so an in-flight request sees one consistent generation.
- Invalidation is **push + TTL**: a missed watch event is corrected by the TTL
  and by a periodic resync (`distributed.resync_interval_secs`, default 300).

### 5.6 Behaviour when distri-kv is unavailable

`distributed.fallback_mode`:

| Mode | Policy/ACL | Rate limits | Unknown reputation | Intended use |
|---|---|---|---|---|
| `local_only` | last-known-good; no refresh | local only | local default | Default. Safest general mode. |
| `stale_allow` | last-known-good until `max_stale_secs`; then stop enforcing *new* shared blocks but keep local rules | local only | allow | Availability-first; documented risk |
| `stale_block` | last-known-good indefinitely; blocks stay enforced | local only, conservative (lower capacity) | block if last score ≥ threshold | Security-first during long partitions |
| `fail_closed` | reject non-local requests when policy is stale | reject | block | Regulated environments; not recommended for public traffic |

`max_stale_secs` default 900. On exceeding it, a `stale_allow` node emits a
critical alert and increments `waf_distributed_stale_policy_total`. A
`stale_block` node keeps the last blocklist but must never invent new blocks.

The existing `waf.fail_mode = "closed"` governs engine/WASM errors and is
**independent** of `distributed.fallback_mode`. Operators must not conflate
them; the runbook must state both.

### 5.7 Configuration surface

```toml
[distributed]
enabled = false
bootstrap_endpoints = ["https://dkv-eu.example:7443"]
region = "eu-west-1"
zone = "eu-west-1a"
node_id = ""                     # empty: generate and persist locally
cluster_id = "waf-eu-prod"
consistency_mode = "regional"    # regional | global
fallback_mode = "local_only"     # local_only (default) | stale_allow | stale_block | fail_closed
miss_policy = "local"            # local | allow | block
cross_region_egress = "hashed_metadata"  # hashed_metadata (default) | none
global_block_policy = "operator_approval_or_exact_ioc"
                                 # operator_approval_or_exact_ioc (default) | operator_approval_only
max_stale_secs = 900
resync_interval_secs = 300
request_timeout_ms = 2000         # background RPC only

[distributed.registry]
heartbeat_interval_secs = 10
lease_ttl_secs = 30
tombstone_ttl_secs = 86400
dead_grace_secs = 120

[distributed.watch]
batch_max_events = 512
resume_token_persist_path = "/var/lib/waf/distri-watch.token"

[distributed.events]
queue_capacity = 8192
batch_max_events = 128
flush_interval_ms = 100
max_event_bytes = 8192
drop_policy = "drop_oldest"       # drop_oldest | drop_newest

[distributed.ratelimit]
flush_interval_ms = 250
max_pending_deltas = 4096
sync_mode = "async_delta"         # async_delta | observe_only

[distributed.tls]
ca_path = "/etc/waf/distri/ca.pem"
client_cert_path = "/etc/waf/distri/client.pem"
client_key_path = "/etc/waf/distri/client.key"
server_name = "dkv-eu.example"
spiffe_trust_domain = "waf.example"

[distributed.quota]
max_inflight_rpcs = 64
max_event_bytes_per_sec = 4194304
max_counter_deltas_per_sec = 20000
```

All keys are validated at startup (consistent with the strict-config work in
`src/config.rs`); `deny_unknown_fields` applies. `enabled = false` must leave
the existing local behaviour bit-for-bit unchanged.

**Decision defaults (ADR-0008):**

- `fallback_mode = "local_only"` is the only default. `stale_*` and
  `fail_closed` must be chosen explicitly and documented in the runbook.
- `cross_region_egress = "hashed_metadata"`: only hashed/aggregated metadata
  may leave a region; raw events and raw IPs never do (§6.2, §9.4).
- `global_block_policy = "operator_approval_or_exact_ioc"`: a global block is
  applied only by operator approval or an exact-match deterministic IOC.
- `auto_block_min_confidence` **does not exist for heuristics**. There is no
  confidence threshold at which a heuristic, ML or anomaly signal may raise an
  automatic global block, because the false-positive budget is 0% (§6.4).
  A `min_block_confidence` key may only gate **alert/throttle** promotion, and
  must be named accordingly (e.g. `alert_min_confidence`) to avoid implying an
  automatic block path. If a future config carries
  `auto_block_min_confidence`, validation must reject it as unsupported.

There is deliberately **no** `max_false_positive_ratio` knob for automated
derived blocks: with a 0% budget there is nothing to tune.

---

## 6. Event correlation

### 6.1 Pipeline

```
WAF node                         regional distri-kv
────────                         ──────────────────
SecurityEvent (existing)
  │  filter: no body, no creds
  ▼
local pre-aggregate (1 s)
  │  batch + dedupe by event_id
  ▼
IngestEvents stream ──────────► security_correlation
                                  │  window (10 s / 60 s / 300 s)
                                  │  group by ip, asn, rule, path
                                  ▼
                               ThreatAssessment
                                  │  confidence + corroboration
                                  ▼
                     ┌────────────┴────────────┐
                     ▼                         ▼
              intel/ip update            ratelimit multiplier
                     │                         │
                     └──────────► Watch ◄──────┘
                                     │
                                     ▼
                              WAF local caches
```

### 6.2 Event envelope

Reuse the existing `SecurityEvent` (`src/waf/security_events.rs`) but add a
distributed envelope for idempotency and tenancy:

```text
SecurityEventEnvelope {
  event_id:        UUIDv7            // same as SecurityEvent.id
  node_id:         UUID
  region:          String
  observed_at:     Timestamp
  monotonic_seq:   u64
  schema_version:  u16
  event:           SecurityEvent    // existing struct, body-free
  rule_ids:        Vec<String>
  decision:        ALLOW | BLOCK | RATE_LIMIT | CHALLENGE | MONITOR
  threat_level:    LOW | MEDIUM | HIGH | CRITICAL
  ip_hash:         Option<[u8;16]>   // HMAC-SHA256(client_ip, cluster_salt) when raw IP not needed
  raw_client_ip:   Option<IpAddr>    // only if distributed.events.send_raw_ip = true
}
```

Body, query values, header values, cookies and authorization are never
included. `path` is normalised and truncated; if `distributed.events.redact_path
= true` (default in regulated deployments), only a route template is sent.

**Cross-region egress (ADR-0008 D4):** `distributed.cross_region_egress =
"hashed_metadata"`. Only hashed metadata (for example `ip_hash`, ASN/country
buckets, rule IDs, coarse counters) may leave the region in which it was
observed. Raw events, raw IPs and unhashed paths stay regional. When the
setting is `none`, no security event crosses a region boundary at all;
cross-region learning is limited to operator-pushed policy bundles.
`raw_client_ip` must never be populated on a cross-region export.

### 6.3 Correlation and threat multipliers

`security_correlation` owns the windowed aggregation. It produces:

```text
ThreatAssessment {
  key:             CorrelationKey      // ip | asn | rule | path-template
  window:          Window              // 10s | 60s | 300s
  event_count:     u64
  distinct_nodes:  u32
  distinct_regions:u32
  rule_ids:        Vec<String>
  score:           f32                 // 0..1
  confidence:      f32                 // 0..1
  verdict:         OBSERVE | THROTTLE | BLOCK_CANDIDATE | BLOCK
  hlc:             Hlc
}
```

Action mapping (default, tunable in `RateLimitPolicy`). **The verdict may never
authorise an automatic global block.** `BLOCK_CANDIDATE` is an *alert* state
that requires operator approval; only exact-match deterministic indicators
bypass the approval gate (ADR-0008 D2/D6).

| Condition | Action | Auto-enforced? |
|---|---|---|
| score ≥ 0.4 and distinct_nodes ≥ 2 | publish rate-limit multiplier `0.5` for 60 s (regional) | Yes — throttle only |
| score ≥ 0.6 and distinct_nodes ≥ 3 | publish `0.25` for 300 s (regional); open incident | Yes — throttle only |
| score ≥ 0.8 and distinct_nodes ≥ 3 and confidence ≥ 0.8 | emit `BLOCK_CANDIDATE` + alert with evidence; **no block** | No — operator approval required |
| `BLOCK_CANDIDATE` corroborated by ≥ 3 regions | escalate alert priority; attach corroboration to the review queue | No — operator approval required |
| exact match to operator-supplied blocklist / known-bad hash or URL | apply block at the configured scope | Yes — deterministic only |

Corroboration is therefore a **detection and prioritisation** signal. It helps
an analyst decide, and it raises the severity of an incident, but it does not
authorise an automatic global block. The former rule (“corroborated by ≥ 3
regions → `APPROVED`, global block”) is **withdrawn**.

### 6.4 Feedback loop and safeguards

- **Poisoning:** a single node cannot create a global block, and neither can a
  region. Heuristic signals are always quarantined as candidates; promotion
  requires operator approval. Exact-match deterministic indicators are the
  only automated path. Node contributions are weighted by `node_trust` from
  the registry, and a node whose recent events were rejected for malformed
  content loses weight.
- **Replay:** `event_id` is globally unique and deduplicated in the window;
  events older than `max_event_age_secs` (default 300) are counted and dropped.
- **Rate cap:** each node may submit at most `max_events_per_sec` (default
  2 000) and at most `max_intel_writes_per_min` (default 60) derived writes.
  Excess is `RESOURCE_EXHAUSTED`, not silently accepted.
- **No confidence floor for blocks:** there is no confidence value at which a
  heuristic becomes an automatic block. Confidence may only gate **throttle**
  and **alert** escalation. Below the alert threshold, signals are observation
  only.
- **False-positive budget = 0% for automated distributed blocks.** This is a
  hard rule, not a tunable: no heuristic, ML or anomaly-based global block may
  be automated. Only exact-match deterministic indicators (operator-supplied
  blocklists, known-bad hashes/URLs) or explicitly operator-approved blocks
  may block. Everything else may only throttle locally or raise an alert. There
  is no `max_false_positive_ratio` auto-demotion because there is no automated
  heuristic block to demote.
- **Allowlist wins:** `pol/allow` always suppresses a derived block.
- **Kill switch:** `distributed.correlation.enabled = false` stops derived
  actions while leaving ingestion and observation on.

### 6.5 Hysteresis and stability

Multiplier changes are rate-limited: at most one change per policy per
`multiplier_min_dwell_secs` (default 30 s), with a dead band of ±10% around the
target. Without this, a botnet oscillating around the threshold would produce
a flapping global budget.

---

## 7. Protocol

### 7.1 Transport

- gRPC over HTTP/2 with TLS 1.3, ALPN `h2`.
- mTLS is mandatory in production. Server certificate and client certificate
  are validated against `distributed.tls.ca_path`; SPIFFE IDs are mapped to
  roles.
- Message size cap: 4 MiB. Batch limits are enforced per method.
- Keepalive: client `PING` every 30 s, server `max_connection_age` 10 min.

### 7.2 Service definitions

The `.proto` below is the owned contract (ADR-0008 D5). It is **not yet
generated**; field numbers are stable once published and are owned by
WAF-Rejected. Operator approval of a heuristic block is a control-plane
operation under the `waf.controller` role (§7.4) — it is deliberately not a
WAF-node RPC, so a compromised node cannot approve its own block.

```proto
syntax = "proto3";
package waf.distri.v1;

service DistriWaf {
  rpc RegisterNode(RegisterNodeRequest) returns (RegisterNodeResponse);
  rpc Heartbeat(stream HeartbeatRequest) returns (stream HeartbeatResponse);
  rpc Discover(DiscoverRequest) returns (DiscoverResponse);

  rpc Watch(WatchRequest) returns (stream WatchEvent);
  rpc GetPolicy(GetPolicyRequest) returns (PolicyBundle);
  rpc ActivatePolicy(ActivatePolicyRequest) returns (ActivatePolicyResponse);

  rpc LookupReputation(LookupReputationRequest) returns (LookupReputationResponse);
  rpc BatchLookupReputation(BatchLookupReputationRequest) returns (BatchLookupReputationResponse);

  rpc IngestEvents(stream IngestEventsRequest) returns (IngestEventsResponse);
  rpc IngestCounterDeltas(stream CounterDeltaBatch) returns (CounterDeltaAck);

  rpc ReportHealth(ReportHealthRequest) returns (ReportHealthResponse);
}

message WatchRequest {
  string region = 1;
  repeated string prefixes = 2;      // e.g. ["cfg/active/", "intel/ip/"]
  uint64 from_version = 3;           // resume token
  string node_id = 4;
  bool include_initial_snapshot = 5;
}

message WatchEvent {
  string key = 1;
  uint64 version = 2;
  Op op = 3;                          // PUT | DELETE | RESET
  bytes payload = 4;                  // encoded object
  bytes payload_hash = 5;             // SHA-256(canonical payload)
  Timestamp committed_at = 6;
  string scope = 7;
}

message LookupReputationRequest {
  repeated IpAddr ips = 1;
  string scope = 2;
  uint32 max_age_ms = 3;
}
message LookupReputationResponse {
  repeated IpReputation entries = 1;
  uint64 as_of_version = 2;
  bool stale = 3;
}

message IngestEventsRequest {
  string node_id = 1;
  uint64 epoch = 2;
  repeated SecurityEventEnvelope events = 3; // <= 256
  string batch_id = 4;
}
message IngestEventsResponse {
  uint64 accepted = 1;
  uint64 duplicate = 2;
  uint64 rejected = 3;
  repeated Rejection rejections = 4;
  Duration retry_after = 5;
}

message CounterDeltaBatch {
  string node_id = 1;
  uint64 epoch = 2;
  repeated CounterDelta deltas = 3;   // <= 4096
  string batch_id = 4;
}
message CounterDelta {
  string policy_id = 1;
  uint32 window_start_unix = 2;
  uint32 shard = 3;
  bytes key_hash = 4;                 // 128-bit
  uint64 consumed = 5;
  uint64 rejected = 6;
  sint32 clock_offset_ms = 7;
}
```

### 7.3 Method semantics

| Method | Idempotency | Timeout | Retry | Notes |
|---|---|---|---|---|
| `RegisterNode` | `node_id` + `epoch` | 2 s | exponential, jittered | lower epoch → `FAILED_PRECONDITION` |
| `Heartbeat` | sequence | stream | reconnect with backoff | stream close ≠ death until TTL |
| `Discover` | none | 1 s | 3× | cached 60 s |
| `Watch` | resume token | long-lived | resume from `from_version` | `RESET` forces resync |
| `GetPolicy` | version | 2 s | 3× | used on cold start |
| `ActivatePolicy` | `expected_current` | 5 s | no blind retry | CAS; `ABORTED` on conflict |
| `LookupReputation` | none | 500 ms | 2× | background only |
| `IngestEvents` | `event_id` + `batch_id` | 5 s | at-least-once | duplicates return `duplicate` |
| `IngestCounterDeltas` | `batch_id` | 2 s | at-least-once | server dedupes `batch_id` for 10 min |
| `ReportHealth` | none | 1 s | best effort | used by registry, not hot path |

### 7.4 Authn/authz

- **Transport:** mTLS with short-lived certificates (24 h) issued by the
  cluster CA. SPIFFE ID format:
  `spiffe://waf.example/region/{region}/node/{node_id}`.
- **Roles:**
  - `waf.node` — register/heartbeat/watch/ingest/lookup for its own region.
  - `waf.controller` — activate policy, write allow/block, read audit.
  - `waf.correlator` — read events, write intel, propose quarantine promotion
    (an operator approves the block).
  - `waf.auditor` — read-only audit and registry.
- **Optional bearer token:** for environments without mTLS, a JWT (EdDSA,
  10 min TTL) with `scope` claims and `node_id` binding. Both mechanisms are
  mutually exclusive per cluster; mTLS is required for policy activation.
- **Authorization checks:** region match, scope match, capability match.
  A node in `eu-west-1` cannot write `intel` for `us-east-1` unless it holds
  `waf.correlator.global`.
- **Revocation:** SPIFFE certs are short-lived; the registry also has a
  `revoked_nodes` set propagated by watch. A revoked node gets
  `PERMISSION_DENIED` on the next RPC.

### 7.5 Quotas and backpressure

| Resource | Default limit | Signal |
|---|---|---|
| in-flight RPCs per node | 64 | `RESOURCE_EXHAUSTED` |
| event bytes/s per node | 4 MiB | `RESOURCE_EXHAUSTED` + `retry_after` |
| events/s per node | 2 000 | same |
| counter deltas/s per node | 20 000 | same |
| watch streams per node | 4 | `RESOURCE_EXHAUSTED` |
| policy activation/s per operator | 1 | `ABORTED` |

Backpressure is layered:

1. HTTP/2 flow control (transport).
2. Application quota tokens (above).
3. WAF-side bounded queues with drop-oldest and metrics.
4. Server `retry_after` hint; the client uses exponential backoff with jitter
   (base 100 ms, max 30 s).

The WAF must prefer dropping telemetry over blocking a request. Rate-limit
deltas are higher priority than events but still never block.

### 7.6 Streaming/watch semantics

- `Watch` is server-streaming. The server sends an initial snapshot when
  `include_initial_snapshot = true`, then incremental events.
- Ordering is per key, not globally. Clients must not assume cross-key order.
- Resume: the client persists the highest contiguous applied version per
  prefix. On reconnect it sends `from_version`. If the server has compacted
  below that version it returns `RESET`; the client clears the cache for that
  prefix and requests a snapshot.
- Heartbeats on the watch stream every 15 s; a client that misses 3 closes and
  reconnects.
- A watch event larger than 4 MiB is split by the server into chunked
  `PUT_CHUNK` events with a shared `object_id`; the client reassembles before
  applying.

---

## 8. Failure modes

### 8.1 Failure matrix

| Failure | Detection | WAF behaviour | distri-kv behaviour | Alert |
|---|---|---|---|---|
| WAF node isolated from regional cluster | heartbeat/watch error | `fallback_mode`; local limits; queue events until `max_queue_age` | marks node suspect after TTL | `WafDistriDisconnected` critical after 60 s |
| Regional Raft leader loss | RPC `UNAVAILABLE`/timeout | unchanged (local caches) | election; writes stall ≤ election timeout | `DistriLeaderElection` warning |
| Regional quorum loss | > 50% voters down | `fallback_mode`; stale policy warning | no writes; reads may serve stale if configured | `DistriQuorumLoss` critical |
| Global tier unavailable | replication lag grows | regional autonomy; global policy frozen | regional groups continue | `DistriGlobalLag` warning |
| Stale cache | `stale_after` exceeded | emit `stale_policy`; apply `fallback_mode` | — | `WafStalePolicy` warning/critical |
| Split-brain (two regional groups) | epoch/leader ID mismatch | only trust the group whose leader matches the pinned cluster ID; otherwise fall back | Raft prevents two leaders in one group; a misconfigured second cluster is rejected by cluster ID check | `DistriSplitBrain` critical |
| Clock skew | heartbeat `clock_offset_ms` | include offset in deltas; use HLC for merges | server normalises window start; rejects offset > `max_clock_skew_ms` (5 000) | `WafClockSkew` warning |
| Replay of events | duplicate `event_id`/`batch_id` | client retries same ID | dedupe window 10 min; older duplicates counted | `DistriReplayDetected` info |
| Poisoned intel | confidence/corroboration checks | quarantine; no immediate block | review queue; promotion requires approval | `DistriIntelQuarantine` warning |
| Malformed bundle signature | verify on apply | keep previous generation; refuse | reject activation | `WafPolicyRejected` critical |
| Queue overflow | depth metric | drop oldest, increment counter | — | `WafEventQueueDropped` warning |
| Certificate expiry | TLS handshake | fail to connect; local mode | rejects | `WafDistriCertExpiry` warning at 7 d |

### 8.2 Raft leader loss

A leader loss is a control-plane event. WAF request handling must be
unaffected because it never calls the leader synchronously. The only visible
effect is that new policy activations, blocklist writes and registration
heartbeats are delayed by the election timeout. The client retries with jitter
and treats `UNAVAILABLE` as retryable. It must **not** treat a failed
`ActivatePolicy` as success.

### 8.3 Split-brain

Within one Raft group, split-brain is prevented by the consensus protocol. The
realistic split-brain is **operator error**: a second cluster is started with
the same `cluster_id` but a different voter set, or a node is pointed at the
wrong region. Defences:

- Every RPC carries `cluster_id`; the server rejects a mismatch.
- Every registry record carries `region` and `cluster_id`; the client rejects
  a record from another cluster.
- The WAF pins the server certificate SPKI on first successful `Discover`
  (`distributed.tls.pin_on_first_use = true` by default in production).
- A node that sees two different leader IDs for the same term raises
  `DistriSplitBrain` and stops applying control-plane updates (but keeps
  serving local traffic).

### 8.4 Stale cache

Staleness is a first-class state, not an error:

```text
StalenessView {
  policy_age_secs:   u64
  intel_age_secs:    u64
  acl_age_secs:      u64
  watch_connected:   bool
  last_resync:       Timestamp
  mode:              FRESH | STALE | EXPIRED
}
```

Surfaced at `/health` and `/metrics`:
`waf_distributed_policy_age_seconds`,
`waf_distributed_intel_age_seconds`,
`waf_distributed_watch_connected`,
`waf_distributed_stale_policy_total`.

### 8.5 Clock skew

- All timestamps are UTC. Windows use server time.
- Nodes estimate offset from heartbeat responses and include
  `clock_offset_ms` in counter deltas.
- Reject offsets above 5 s; a node with a larger offset is `DEGRADED` and its
  deltas are quarantined, not merged.
- Conflict resolution uses HLC `(physical_ms, logical, node_id)`, which is
  monotonic even with bounded skew. HLC is not a substitute for NTP; it only
  makes merges deterministic.

### 8.6 Replay

- `event_id` is UUIDv7 and globally unique; the server keeps a dedupe index
  for `dedupe_window_secs` (default 600).
- `batch_id` is `node_id + epoch + sequence`; the server rejects a batch whose
  sequence is older than the last accepted for that node/epoch.
- An event with `observed_at` older than `max_event_age_secs` is rejected and
  counted, not correlated.

---

## 9. Security

### 9.1 Trust boundaries

| Boundary | Crossing | Control |
|---|---|---|
| TB-D1 | WAF process → regional distri-kv | mTLS + SPIFFE, per-node quotas, pinned CA |
| TB-D2 | distri-kv regional → global tier | mTLS, signed bundles, cluster IDs |
| TB-D3 | Operator → control plane | OIDC + RBAC, signed activation, audit |
| TB-D4 | Event stream → correlation | schema validation, size caps, confidence gates |
| TB-D5 | distri-kv → WAF cache | signed/hashed payloads, generation ordering, signature verification for bundles |
| TB-D6 | WAF → SIEM/exporters | existing CEF/Sled/OTel path, unchanged |

distri-kv is **not** trusted to make per-request decisions. It is trusted to
supply versioned data and to aggregate. A compromised distri-kv can feed bad
policy; signed bundles and the allowlist kill switch bound that.

### 9.2 Signed configuration and rulesets

- Every `PolicyBundle` is signed with Ed25519 by a control-plane key.
- The WAF has a trust store of public keys (`distributed.policy.trusted_keys`)
  and verifies `signature` over `content_hash` before compiling.
- `previous_hash` forms a hash chain; a gap or mismatch is an error.
- The compiled artifact hash is recorded in `BundlePayload` and checked after
  compilation.
- Key rotation: overlapping key IDs; the trust store accepts the old key for
  `distributed.policy.key_overlap_secs` (default 7 d).
- A rejected bundle never replaces the active one and emits a critical event.

### 9.3 Data integrity

- Every object has a `content_hash` (SHA-256 over canonical encoding).
- Watch events carry `payload_hash`; the client verifies before applying.
- The audit log is a hash chain: `audit/{yyyy-mm}/{seq}` contains
  `prev_hash`, `entry_hash`, `actor`, `action`, `object`, `version`, `hlc`.
- distri-kv stores the audit index; the authoritative chain is exported to
  Sled/CEF/SIEM so that a distri-kv compromise cannot erase history.
- Rate-limit deltas are not signed per message; they are bound to the mTLS
  session and the node epoch, and are only used for observation.

### 9.4 PII minimisation

- Events never include bodies, cookies, authorization headers, query values or
  raw header values. `SecurityEvent` already contains `path`, `user_agent`,
  `client_ip`, geo fields; the distributed envelope can redact them:
  - `distributed.events.send_raw_ip = false` → send `ip_hash` only.
  - `distributed.events.send_user_agent = false` → omit or hash.
  - `distributed.events.redact_path = true` → route template only.
- `ip_hash` = HMAC-SHA256(client_ip, cluster_salt) with a salt rotated every
  30 d and never shared across regions unless explicitly configured. This
  still permits correlation within a region without storing the address.
- Raw IPs are retained in distri-kv only when needed for enforcement, with a
  TTL and `raw_ip_retention_days` (default 7). Reputation entries store the IP
  because a block needs it; they are not exported to analytics.
- Geo fields are coarse (country/region); no city unless
  `distributed.events.send_city = true`.
- Retention: events 7 d default, audit 90 d, reputation 24 h max, counters 2×
  window.
- **Cross-region egress is hashed-only** (`distributed.cross_region_egress =
  "hashed_metadata"`, default). Raw events and raw IPs are regional; only
  hashed/aggregated metadata crosses a region boundary. Hashes use a
  per-region salt, so the same client cannot be trivially joined across
  regions unless the operator deliberately shares the salt.

### 9.5 Audit trail

Every control-plane mutation writes an audit entry:

```text
AuditEntry {
  seq:          u64
  timestamp:    Timestamp
  actor:        String          // SPIFFE ID or operator
  action:       String          // ACTIVATE_BUNDLE, BLOCK_IP, PROMOTE_INTEL
  object_key:   String
  object_version:u64
  before_hash:  Option<[u8;32]>
  after_hash:   [u8;32]
  reason:       String
  approval_id:  Option<String>
  prev_hash:    [u8;32]
  entry_hash:   [u8;32]
}
```

The chain is exported to the existing evidence path. distri-kv is an index, not
the system of record.

---

## 10. Rollout

### 10.1 Feature flags

| Flag | Default | Effect |
|---|---|---|
| `distributed.enabled` | `false` | Master switch; false = byte-for-byte local behaviour |
| `distributed.registry.enabled` | `false` | Registration/heartbeat only |
| `distributed.policy.enabled` | `false` | Watch/apply signed bundles |
| `distributed.events.enabled` | `false` | Event egress |
| `distributed.ratelimit.enabled` | `false` | Counter deltas + multiplier |
| `distributed.correlation.enabled` | `false` | Derived intel/actions |
| `distributed.actions.enabled` | `false` | Allow correlation to apply *exact-match deterministic* blocks and operator-approved blocks; heuristics still cannot block |
| `distributed.shadow` | `true` | Compute and log proposed actions, never enforce |

`shadow = true` is the default even when `enabled = true`: the node connects,
watches, ingests and computes, but derived blocks/multipliers are only logged.
This is the canary safety net.

### 10.2 Phases

| Phase | Scope | Exit criteria |
|---|---|---|
| P0 | Protocol + fake server, unit tests | schema, signing, watch resume, queue bounds |
| P1 | Registry only, 1 region | 100% nodes register; heartbeats stable 7 d; no hot-path change |
| P2 | Policy watch, `shadow` | 99% nodes on new generation ≤30 s; zero rejected bundles; rollback tested |
| P3 | Event egress, `shadow` correlation | event loss <0.1% at p99; no PII in payloads; SIEM parity |
| P4 | Rate-limit deltas, observation only | global aggregate within 10% of node sums; no enforcement |
| P5 | Correlation actions, 1 region canary | zero automated heuristic blocks; operator approval path works; exact-IOC path tested |
| P6 | Global replication, 2 regions | cross-region block ≤60 s p95; regional autonomy drill passes |
| P7 | Default-on for new deployments | runbooks, alarms, SLOs published |

Canary: 1 node → 10% of a region → one region → all regions. Each step
requires 24 h of clean metrics and a rollback drill.

### 10.3 Rollback

- `distributed.actions.enabled = false` immediately stops derived enforcement.
- `distributed.enabled = false` returns to the local path without restart
  (config reload for the distributed block only; the existing startup-only
  config limitation is noted in ADR-0008 D8).
- `distributed.fallback_mode = "local_only"` keeps the client connected but
  ignores shared blocks beyond local policy.
- The last-known-good bundle remains on disk
  (`distributed.policy.cache_path`), so a rollback can restart offline.
- Rollback of a bad bundle is `ActivatePolicy` with `expected_current` set to
  the bad version and `bundle_version` set to the previous one.

### 10.4 Compatibility with existing local components

- **Rate limiter:** `RateLimiter` keeps its sharded token bucket. The
  distributed layer only changes `capacity`/`refill_rate` via a policy object
  and reads deltas. `AdaptiveRateLimiter::set_threat_multiplier` is the
  natural integration point for the correlation multiplier; the existing
  clamp `[0.1, 10.0]` stays.
- **Allow cache:** `AllowCache::set_generation` is called on bundle swap;
  `KEY_VERSION` must be bumped if the canonical key changes. The distributed
  layer does not share allow-cache entries across nodes (the key is
  process-local and secret-keyed).
- **Exporters:** `DistriExporter` implements the existing
  `SecurityEventExporter` trait (`src/waf/exporters/mod.rs`) and is added to
  `ExporterDispatcher` alongside CEF/Sled/OTel. `fail_fast` remains `false`;
  a distri-kv failure must not fail the request or suppress local export.
- **GeoIP:** unchanged; the shared `GeoPolicy` only supplies country lists.
  Local `.mmdb` remains required for enforcement.
- **Health/metrics:** add distributed components to `HealthStatus`
  (`src/health.rs`) and new Prometheus counters in `src/metrics.rs`.
- **Config:** new `[distributed]` section, `deny_unknown_fields`, validated in
  `Config::validate()`. Existing configs remain valid because the section is
  optional with defaults.

---

## 11. Decision log (ADR-0008)

**Status:** Accepted by the architecture owner, 2026-11-08. This section
supersedes the former open-questions table. Where a decision changes earlier
prose, the earlier text carries a dated note.

### D1 — Topology: regional cells plus an asynchronous global tier

- **Decision:** Deploy per-region cells with regional consistency. A global
  tier may exist, but it is asynchronous and **global consistency is eventual**
  only. There is no global linearizable group on any request or control path.
- **Rationale:** preserves regional autonomy and the hot-path latency budget
  (G3), and matches the failure model in §8.
- **Consequences:** every global object carries a version and a visible
  staleness; cross-region reads may lag. distri-kv must build the tier split
  (§12.2 P1); it is not configurable today.
- **Supersedes:** former Q1.

### D2 — Global block authority (reconciles corroboration with approval)

- **Decision:** A **global auto-block may never originate from a single
  node**. Two paths exist:
  1. **Heuristic path (never automatic):** regional quorum corroboration is
     required to *detect and prioritise* a candidate, **and** operator
     approval is required to apply any block. Corroboration does not authorise
     an automatic global block.
  2. **Deterministic path (may auto-apply):** an **exact match** to an
     operator-supplied blocklist entry or a known-bad hash/URL may be applied
     automatically, at the scope the operator configured.
- **Rationale:** heuristics carry non-zero false-positive risk; an automatic
  global block turns one bad signal into fleet-wide denial of service. Exact
  deterministic IOCs have bounded, auditable provenance.
- **Consequences:** `BLOCK_CANDIDATE` is an alert state, never an enforced
  verdict. The former “≥ 3 regions ⇒ APPROVED global block” rule is withdrawn.
  Operator approval is recorded in the audit chain with `approval_id`.
- **Supersedes:** former Q2.

### D3 — Fallback: `local_only` by default; keep scope tight

- **Decision:** `distributed.fallback_mode = "local_only"` is the default and
  the only recommended general mode. `stale_allow`, `stale_block` and
  `fail_closed` are explicit opt-ins. The distri-kv integration stays focused
  on the capabilities in this ADR; **no scope expansion** beyond what the
  security fabric needs.
- **Rationale:** availability without inventing policy; a partitioned node must
  not silently change enforcement semantics.
- **Consequences:** on partition, shared state stops refreshing and local
  policy/limits continue. `stale_block` may keep existing blocks but must never
  create new ones.
- **Supersedes:** former Q3.

### D4 — Cross-region egress: hashed metadata only

- **Decision:** `distributed.cross_region_egress = "hashed_metadata"`. Only
  hashed or aggregated metadata may leave a region: `ip_hash`, ASN/country
  buckets, rule IDs, coarse counters. Raw events, raw IPs and unhashed paths
  stay regional. `none` disables cross-region event flow entirely.
- **Rationale:** data residency and PII minimisation; correlation still works
  within a region and across regions on hashed/aggregated keys.
- **Consequences:** no cross-region raw-event analysis; salts are per-region
  by default. See §6.2 and §9.4.
- **Supersedes:** former Q4.

### D5 — `DistriWaf` contract ownership and versioning

- **Decision:** **WAF-Rejected owns and versions the `DistriWaf` gRPC contract**
  (`waf.distri.v1`, §7.2), including field numbers, semantics and compatibility
  rules. distri-kv implements the server side against that contract. The
  contract is the integration boundary; no shared source crate.
- **Rationale:** one authority prevents a split wire format; a protocol
  boundary also sidesteps the unresolved licence question (§12.1 item 6).
- **Consequences:** breaking changes require a new package version
  (`waf.distri.v2`) and a migration window. distri-kv's existing
  `distri_kv.proto` is **not** the contract and must not be extended ad hoc.
- **Supersedes:** former Q5 and Q12 (client-only remains: the WAF does not
  serve the control API).

### D6 — False-positive budget for automated distributed blocks: 0%

- **Decision:** The accepted false-positive budget for **automated distributed
  blocks is 0%**. No heuristic, ML or anomaly-based global block may be
  automated. Only exact-match deterministic indicators or explicitly
  operator-approved blocks may block. Everything else may only **throttle
  locally** or **raise an alert**.
- **Rationale:** an automated block is an availability decision applied to
  third parties; at fleet scale even a small FP rate is unacceptable.
- **Consequences:** there is no `auto_block_min_confidence` for heuristics and
  no `max_false_positive_ratio` auto-demotion knob. Confidence thresholds may
  gate alerts/throttles only.
- **Reconciliation with D2:** corroboration is a *detection* input; approval is
  the *authorisation* input; exact IOC matching is the only automated
  authorisation. See §6.3, §6.4, §10.2 P5.
- **Supersedes:** former Q10.

### D7 — Tenancy deferred

- **Decision:** v1 is single-tenant per cluster. Namespaced multi-tenancy is
  out of scope.
- **Supersedes:** former Q7.

### D8 — Configuration reload

- **Decision:** structural `[distributed]` changes require a restart in v1.
  Only the safety switches `distributed.enabled`,
  `distributed.actions.enabled` and `distributed.shadow` are hot-switchable;
  the resulting restart, if any, is documented in the runbook.
- **Rationale:** the existing config loader is startup-only; adding a general
  reload path is a separate change.
- **Consequences:** rollback of a bad bundle does not need a restart (it is a
  control-plane `ActivatePolicy` CAS); changing endpoints/TLS does.
- **Supersedes:** former Q8.

### D9 — Reputation writes are brokered

- **Decision:** WAF nodes never write reputation directly; the correlator
  service is the only writer. Nodes contribute events.
- **Rationale:** keeps poisoning controls, quarantine and rate caps in one
  place.
- **Supersedes:** former Q9.

### D10 — Clocks

- **Decision:** NTP is required on all nodes. HLC is a deterministic merge aid,
  not a clock source. Offsets beyond `max_clock_skew_ms` quarantine deltas.
- **Supersedes:** former Q11.

### D11 — Residual prerequisites, not decisions

Capacity numbers (regional event volume, retention sizing) and the distri-kv
build/contract work are **prerequisites**, tracked in §12.2 and §15. They are
not open architecture questions.

---

## 12. Reconciliation with the distri-kv audit

`docs/design/distri-kv-audit.md` was not present when this ADR was first
written. It has now been read and applied. Verified result at commit `c6fd36d`:
distri-kv **does not build**, exposes **no** rate-limit/reputation/event/RPC
surface, and its “distributed” rate limiter never reads its consensus handle.
The two-plane split in this ADR is therefore **forward-looking**, not an
integration against existing capability. §4.4, §6.3 and the `DistriWaf`
contract are a construction plan.

### 12.1 Reconciliation results (audit facts override this ADR)

| # | ADR assumption | Audit finding | Correction applied |
|---|---|---|---|
| 1 | §4.4 relies on batched counter/delta replication in `distributed_rate_limit.rs`. | `check_rate_limit` is per-key, node-local, sled-backed. There is no batch/delta API; the batch writer applies nothing; cache hits enqueue nothing; `consensus` is never read. | §4.4 marked **aspirational**. `IngestCounterDeltas` is a new contract, not a mapping. Rate-limit integration stays `observe_only` until rebuilt. |
| 2 | §6.3 relies on `security_correlation.rs` accepting external events and exposing window aggregates. | Module **does not compile** (E0689 at `:219`); state is an in-process `HashMap`; no persistence, no RPC, no cross-node path; `get_threat_assessment` is per-IP per-process. | §6.3 requires a **new ingest + window-query surface**. The module is a reference algorithm only. |
| 3 | §9.4/§10.4 assume distri-kv might supply geo data. | No GeoIP/ASN code and no `maxminddb` dependency. | Confirmed: GeoIP stays local. No ADR change needed beyond this note. |
| 4 | §2/§2.3 assume a regional/global Multi-Raft split. | Deployed KV is a **single Raft group over static peers**. `MultiRaftCluster` is not instantiated and partitions have no peers; `ChangeConfig` is `unimplemented`, so membership is fixed at boot. | §2.3 revised: the tier split is a **build prerequisite**, not a config option. v1 fallback is one regional group, no global tier. |
| 5 | §7 assumes a gRPC surface and auth model that distri-kv can serve. | `DistriKv` methods are stubs: `Get`/`Publish`/`Subscribe`/`Acknowledge`/`ChangeConfig` are `unimplemented`; `Mutate` returns fabricated success without writing; `Watch` returns an empty stream. There is no TLS/auth/SPIFFE. | The `DistriWaf` contract is **new** and owned here (ADR-0008 D5). Mapping `distri_kv.proto` is rejected because its semantics are unsafe (fake success / empty streams). |
| 6 | Licensing allows code reuse. | Root `LICENSE` is MIT, with a separate `LICENSE-AGPL-3.0`; collaboration docs describe an AGPL side. | Confirmed: keep a **protocol boundary**, no shared source crate. This reinforces D5. |
| 7 | `security_correlation` blocks produce enforcement. | “Block” maps to a clamped 10× refill slowdown; duration is ignored; distri-kv never denies traffic. | The WAF owns enforcement. §6.3 now states that only the WAF decides, and only on approval or exact IOC. |

Where the audit and this document disagree, the audit’s verified facts win.

### 12.2 Build and contract prerequisites (ordered)

These must be true on the distri-kv side before the corresponding WAF phases
can start. Each is an exit gate, not a suggestion.

| P | Prerequisite | Blocks | Acceptance test |
|---|---|---|---|
| P0 | **Crate builds.** Restore/remove `k8s_auto_config`, repair or gate `synapse_gaming_*`, add `rand`, fix `security_correlation.rs:219`. | everything | `nix develop -c cargo check --workspace --all-targets` passes in distri-kv CI. |
| P1 | **Replication is real and tiered.** Propose KV/security state through the Raft path; make partitions multi-node or document a single-group v1; wire `ChangeConfig` or document static membership. | §2, §4.4, §6 | A value written on node A is read on node B after leader commit; membership change tested; regional/global split either implemented or explicitly deferred. |
| P2 | **`DistriWaf` contract published.** WAF-Rejected publishes `waf.distri.v1` (proto + semantics + versioning rules); distri-kv generates/implements the server stubs. | §7, P3–P6 | `buf breaking`/compat check in CI; generated client and server compile against the same tag. |
| P3 | **Durable TTL and storage.** Sled ignores `put_with_ttl`; wire redb or implement expiry metadata + `delete_expired`; start `TtlManager`. | registry leases, reputation, counters | An entry expires and is reaped within the documented window; no unbounded batch-key growth. |
| P4 | **Non-blocking hot path.** Move `StorageAdapter` calls off the async executor and replace the process-wide write lock with sharded cache. | rate-limit deltas | No blocking disk I/O inside async; per-check lock contention measured. |
| P5 | **Failure-mode contract.** Return an explicit degraded mode rather than `Err(StorageError)`. | §5.6 | `local_only`/`stale_*` observable in the API and tests. |
| P6 | **Authn/authz + TLS.** Add mTLS/SPIFFE (or the JWT fallback) to the client surface. | §7.4 | Unauthenticated client is rejected; role/region checks covered by tests. |
| P7 | **Fix tests/benches.** Add `criterion`, repair `MultiRaftConfig` literals, split the suite so one syntax error cannot hide it. | CI confidence | `cargo test` and `cargo bench --no-run` pass. |

### 12.3 Contract ownership rules (ADR-0008 D5)

- The canonical contract lives in WAF-Rejected as `waf.distri.v1`.
- Field numbers are never reused or renumbered. Removed fields are `reserved`.
- Additive changes are backward-compatible within `v1`; semantic changes
  (idempotency, ordering, error codes) are breaking and require `v2`.
- distri-kv may add server-side internals freely, but the wire contract and
  error semantics are defined here.
- Every published version is tagged and cross-linked from
  [`distri-kv-audit.md`](./distri-kv-audit.md) so both repositories reference
  the same revision.

---

## 13. Component index (source references)

| Concern | File |
|---|---|
| Local rate limiting / shards / capacity policy | `src/waf/rate_limit.rs` |
| Allow-verdict cache and generation invalidation | `src/waf/allow_cache.rs` |
| Bodyless fast allow | `src/waf/fast_allow.rs` |
| Admission control | `src/waf/admission.rs` |
| Security event model | `src/waf/security_events.rs` |
| Exporter trait / dispatcher | `src/waf/exporters/mod.rs`, `src/waf/exporters/dispatcher.rs` |
| CEF / Sled / OTel exporters | `src/waf/exporters/cef.rs`, `src/waf/exporters/sled.rs`, `src/waf/exporters/otel.rs` |
| GeoIP and geo blocking | `src/waf/geoip.rs` |
| Threat intelligence | `src/threat_intelligence.rs` |
| Config structs and validation | `src/config.rs` |
| Health/readiness | `src/health.rs` |
| Metrics | `src/metrics.rs` |
| Request pipeline | `src/proxy/service.rs`, `src/proxy/http3.rs` |
| Security model / trust boundaries | `docs/architecture/security-model.md` |
| gRPC transport behaviour | `docs/architecture/grpc-transport.md` |

---

## 14. Decision record (summary)

**Accepted (ADR-0008, 2026-11-08):**

1. Two-plane architecture: local enforcement, distributed control/observation.
2. Regional cells with an asynchronous global tier; global consistency is
   eventual (D1).
3. WAF nodes are clients, never Raft voters; WAF-Rejected owns and versions
   the `DistriWaf` contract (D5).
4. Local rate limiting + asynchronous delta accounting, with a hysteretic
   multiplier feedback loop.
5. Versioned, signed, hash-chained policy bundles; generation-based cache
   invalidation.
6. **Global blocks require operator approval for heuristics; only exact-match
   deterministic IOCs may auto-apply. Corroboration detects, it does not
   authorise (D2, D6).**
7. **False-positive budget for automated distributed blocks is 0% (D6).**
8. mTLS + SPIFFE, per-node quotas, bounded queues, drop-telemetry-never-request.
9. Explicit `fallback_mode`; default `local_only`; `stale_*` opt-in (D3).
10. Cross-region egress is hashed metadata only (D4).
11. Tenancy deferred; reputation writes brokered; NTP required; config
    changes restart-only (D7–D10).

**Rejected:**

1. Synchronous global token bucket per request.
2. WAF nodes as consensus voters.
3. Sending bodies/PII to distri-kv.
4. Direct, unapproved global blocks from a single node.
5. Automatic global blocks from heuristics, ML or anomaly scores at any
   confidence — including “≥ 3 regions corroboration ⇒ auto-block”.
6. Using distri-kv as the only audit system of record.
7. Reusing distri-kv's `distri_kv.proto` as the WAF contract.

---

## 15. What remains before implementation

Strict dependency order. Do not start a step until the previous one is
accepted; later steps assume the earlier artefacts exist.

| # | Step | Depends on | Exit criterion |
|---|---|---|---|
| 1 | **distri-kv build** — make the crate compile, tests parse, benches resolve; close audit §9 finding 0 and the test/bench item 9. |  | Workspace `cargo check`/`test` green in distri-kv CI. |
| 2 | **`DistriWaf` contract** — publish `waf.distri.v1`, generate stubs, define error/idempotency semantics, freeze field numbers. | 1 | Contract tagged; client and server compile against it; compatibility check in CI. |
| 3 | **Registry + reputation store** — node registration/heartbeat/lease, versioned reputation with TTL, watch + point-read. | 2 | Register→heartbeat→expire tested; reputation read/write with TTL; watch resume works. |
| 4 | **Rate-limit deltas** — batch delta ingest, PN-counter merge, multiplier publication; `observe_only` first. | 2, 3 | Aggregate within 10% of node sums; no hot-path network call; failure mode returns `local_only`. |
| 5 | **Event ingestion** — bounded `IngestEvents`, dedupe, windowed correlation, hashed cross-region egress. | 2, 3 | Event loss < 0.1% p99; no raw IP/PII crosses a region; correlation windows queryable. |
| 6 | **WAF client** — `DistriExporter`, watch/resync, local reputation/ACL caches, config surface, metrics, shadow mode. | 3, 4, 5 | `distributed.enabled` round-trip; shadow actions logged; `local_only` verified with the cluster down. |

Cross-cutting gates that apply to every step: the 0% FP rule (D6), hashed-only
cross-region egress (D4), `local_only` default (D3), and the audit/protocol
boundary (D5). Capacity numbers for event volume and retention remain an ops
input required before step 5 is sized.
