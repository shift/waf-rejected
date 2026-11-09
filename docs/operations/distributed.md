# Distributed security fabric (distri-kv) — operations

**Status:** client available, off by default. The non-default `distri-kv`
Cargo feature compiles the WAF-side boundary, local-only implementations,
caches, bounded queues, an async controller and a tonic client for the
`waf.distri.v1.DistriWaf` contract from
[shift/distri-kv](https://github.com/shift/distri-kv) (`proto/distri_waf.proto`,
complete at `9079588`). The default remains `enabled = false` and
`fallback = "local_only"`; no request path waits on the cluster. See
[the audit](../design/distri-kv-audit.md) and
[the architecture ADR](../design/distributed-waf-architecture.md). Deployment
artifacts and bootstrap/rotation/fallback procedures are in
[distributed-deployment.md](distributed-deployment.md).

## What is compiled

| Component | Path | Effect today |
| --- | --- | --- |
| Config + validation | `src/config.rs` (`DistributedConfig`) | Parsed in every build; `enabled = false` by default |
| Trait boundaries | `src/waf/distributed/traits.rs` | `PolicySource`, `ReputationSource`, `RateLimitSync`, `EventSink`, `NodeRegistry` |
| Local-only sources | `src/waf/distributed/local.rs` | Preserve single-process behaviour |
| Policy/reputation cache | `src/waf/distributed/cache.rs` | TTL + `max_stale`, generation invalidation, explicit `Blocked` |
| Controller | `src/waf/distributed/controller.rs` | Bounded queues, drop accounting, reconnect/backoff, graceful shutdown |
| gRPC client | `src/waf/distributed/grpc.rs` | Tonic implementation of all five traits with deadlines |
| Contract bindings | `src/waf/distributed/distri_waf.rs`, `distri_waf.proto` | Vendored from shift/distri-kv; no build-time `protoc` |
| State handle | `src/waf/distributed/state.rs` | Connectivity, heartbeat age, generation, multiplier, fallback |
| Metrics | `src/waf/distributed/metrics.rs`, `src/metrics.rs` | Prometheus families below |

The request path only reads already-applied state. It never awaits a
control-plane call and never blocks on a queue.

## Enabling the scaffold

```toml
[waf.distributed]
enabled = true
node_id = "waf-eu-1"
region = "eu-west-1"
policy_scope = "default"
endpoints = ["https://dkv-eu.example:7443"]
fallback = "local_only"
# Optional bearer token for clusters whose DistriWaf service uses token auth.
auth_token = ""
# SPIFFE workload identity asserted in request metadata. Only meaningful
# after mTLS; treated as an assertion, not a credential on its own.
spiffe_id = "spiffe://example.org/waf/waf-eu-1"
# Optional SPIFFE JWT-SVID when bearer auth is used.
spiffe_jwt = ""
# Mutual TLS. Both client fields must be set together; the CA bundle overrides
# the system roots for the control-plane server.
tls_ca_cert_path = "/etc/waf/certs/ca.pem"
tls_client_cert_path = "/etc/waf/certs/waf.pem"
tls_client_key_path = "/etc/waf/certs/waf-key.pem"
tls_server_name = ""
# Plaintext is never implied by an http:// URL. Set true only for a local
# TLS-terminating sidecar.
allow_insecure_transport = false
# Reject unsigned/bad-chain policy. The default is required verification.
require_policy_signature = true
policy_signing_public_key = "hex-or-base64-32-byte-ed25519-public-key"
policy_signing_key_id = "regional-key-1"
policy_initial_hash = ""
# Shared rate-limit leases (off by default).
leases_enabled = true
lease_ttl_ms = 5000
lease_batch_max = 64
lease_queue_capacity = 4096
# This node's own gRPC ingest endpoint advertised to the cluster. Required by
# the v1 contract; empty falls back to the first control-plane endpoint.
advertise_endpoint = "https://waf-eu-1.example:9443"
```

`node_id` and `region` are required once any endpoint is configured; the gRPC
`Register`/`Heartbeat` calls need a stable identity. Leaving `endpoints = []`
keeps the controller on the `LocalOnly` sources even with `enabled = true`.
`auth_token` is sent as `authorization: Bearer <token>` on every RPC. It is a
secret and is not written to startup logs; it is not a substitute for TLS on an
untrusted network. `spiffe_jwt` is used as the bearer token only when
`auth_token` is empty, so an operator can deploy a short-lived JWT-SVID without
copying a static token.

### Authentication and transport security

The production default is mutual TLS plus a SPIFFE identity assertion:

- `https://` endpoints use tonic's rustls transport. Server certificates are
  verified against `tls_ca_cert_path` when set, otherwise the system/webpki
  roots. `tls_server_name` overrides SNI/verification for a non-matching host.
- `tls_client_cert_path` + `tls_client_key_path` present the workload client
  certificate. Setting only one is a configuration error.
- `spiffe_id` must be a `spiffe://` URI and is attached as `x-spiffe-id` (or
  the configured `spiffe_metadata_key`) on every RPC. The server must still
  authorise it; the metadata is an assertion, not a bearer credential.
- `http://` endpoints are rejected unless `allow_insecure_transport = true`.
  That flag exists only for a local TLS-terminating sidecar.
- At least one credential (bearer token, JWT-SVID, SPIFFE identity or client
  certificate) is expected in production; the client logs a warning when none
  is configured. No credential is enabled by default.

### Policy integrity

Every fetched `PolicyBundle` is verified before it can change the applied
generation or rate-limit multiplier:

1. The canonical payload SHA-256 must equal `content_hash` (32 bytes).
2. A 64-byte Ed25519 `signature` over `content_hash` must verify against
   `policy_signing_public_key`; `key_id` must match when configured.
3. `generation` must not move backwards. A new generation must carry
   `previous_hash` equal to the last accepted `content_hash`; replaying the
   same generation requires identical content. `policy_initial_hash` pins the
   first non-empty link when bootstrapping.
4. Unsigned, tampered, out-of-order or broken-chain bundles are rejected with
   `Invalid`, counted in `waf_distributed_policy_rejected_total`, and the last
   verified policy stays applied. A rejected first bundle leaves
   `DistributedState::policy_integrity_ok() == false`; the configured
   `fallback` still governs shared-data callers (`local_only` keeps local
   decisions, `fail_closed` denies shared-only capacity).

With `require_policy_signature = true` (default), an empty or malformed key is
a client construction error, so unsigned policy cannot be applied by accident.
Disabling verification is an explicit, audited downgrade and still checks the
content hash, generation and chain.

### Rate-limit leases

When `leases_enabled = true`, local token buckets remain the first tier. Once
a local bucket is exhausted the request path may spend one unit from a cached
lease for the same key (per-IP or global) and is allowed. If no lease is
cached, the request performs only a non-blocking push into
`lease_queue_capacity`; the controller drains at most `lease_batch_max`
requests per heartbeat and calls `AcquireLease` off the request path. A full
queue drops the oldest request and increments
`waf_distributed_lease_request_dropped_total`.

Consumption never extends a lease. An expired lease is removed lazily and the
shared budget fails closed (requests over the local bucket are denied) while
local-only traffic continues to behave exactly as before. Lease grants,
expiry, denials and fallbacks are exported as metrics below. `shadow = true`
keeps leases observable but does not enforce them.

### Event and counter egress

Security events keep the bounded `event_queue_capacity` queue, drop-oldest
policy and `event_id` idempotency key. Counter deltas use
`counter_queue_capacity` with the same drop policy; the client derives a stable
UUIDv5 `batch_id` from `(node_id, epoch, deltas)`, so a retry of the same batch
is deduplicated server-side without persisting a mapping. Queue overflow only
drops telemetry and increments `waf_distributed_queue_dropped_total`.

Build with the feature:

```bash
nix develop -c cargo build --release --features distri-kv
nix develop -c cargo test --lib --features distri-kv
```

With no cluster and `fallback = "local_only"` every request decision is
identical to a build with the feature absent. This is asserted by the
`enabling_the_feature_does_not_change_decisions_without_a_cluster` test. The
controller is not on the request path: it runs its own task with bounded
queues.

If `enabled = true` is set in a build without the feature, the section still
parses and validates, startup logs a warning, and all decisions stay local.

## Fallback semantics

`waf.distributed.fallback` applies **only when a shared-data lookup cannot be
answered**. Local rule evaluation, local token buckets and local exporters are
never affected.

| Mode | Shared policy/ACL | Unknown reputation | Rate limits | Use |
| --- | --- | --- | --- | --- |
| `local_only` (default) | last applied values; no refresh | local default | local only | Never block on the cluster |
| `fail_open` | last applied values | allow | local only | Availability-first |
| `fail_closed` | last applied values | block | local only | Security-first; not for public traffic |

`counters`, security-event egress and heartbeats are always best-effort.

`waf.fail_mode` (WAF engine errors) and `waf.distributed.fallback` (control
plane) are independent. Set and document both.

## gRPC mapping

`DistriWafClient` (behind the feature) maps the five traits to the contract:

| Trait | RPC | Notes |
| --- | --- | --- |
| `NodeRegistry::register` | `Register` | Idempotent on `(node_id, epoch)`; lease 30 s |
| `NodeRegistry::heartbeat` | `Heartbeat` | Monotonic sequence; a `NotFound` lease triggers one re-register |
| `PolicySource` | `GetPolicy` | Active bundle for `policy_scope`; bundle generation drives invalidation |
| `ReputationSource` | `LookupReputation` | One address at a time; background only |
| `RateLimitSync` | `IngestCounterDeltas` | One batch per flush, stable UUIDv5 batch id |
| `LeaseSource` | `AcquireLease` | Batch drained from the bounded request queue; off the request path |
| `EventSink` | `IngestEvents` | Client-streaming batch of body-free records |

Every call carries `request_timeout_ms` as its gRPC deadline and the channel
is dropped on retryable statuses, so the controller reconnects with exponential
backoff. `https://` endpoints use tonic's rustls transport with the configured
CA/client identity (or webpki roots); `http://` requires the explicit
`allow_insecure_transport` opt-in. Mutual TLS and SPIFFE metadata are
configured as described above; the production default is never plaintext or
unauthenticated.

The bindings are vendored (`src/waf/distributed/distri_waf.rs`) so builds do
not need `protoc`. The WAF-side contract adds `AcquireLease` under the same
`waf.distri.v1` package; regenerate from the coordinated `distri_waf.proto`
with `tonic-build 0.11` when the server side lands.

## Metrics

| Metric | Type | Meaning |
| --- | --- | --- |
| `waf_distributed_connected` | gauge | `1` when the controller's last heartbeat succeeded |
| `waf_distributed_heartbeat_age_seconds` | gauge | Time since the last acknowledged heartbeat |
| `waf_distributed_policy_generation` | gauge | Last applied generation |
| `waf_distributed_cache_hits_total` | counter | Fresh cache reads |
| `waf_distributed_cache_misses_total` | counter | Miss/expired reads |
| `waf_distributed_cache_stale_total` | counter | Stale-but-servable reads |
| `waf_distributed_cache_blocked_total` | counter | Explicit blocked entries |
| `waf_distributed_cache_invalidations_total` | counter | Generation invalidations |
| `waf_distributed_queue_depth{queue}` | gauge | `events` / `counters` depth |
| `waf_distributed_queue_enqueued_total` | counter | Accepted items |
| `waf_distributed_queue_dropped_total` | counter | Dropped items (full or closed) |
| `waf_distributed_reconnects_total` | counter | Reconnect attempts after an error |
| `waf_distributed_fallback_activations_total` | counter | Outages where fallback applied |
| `waf_distributed_policy_rejected_total` | counter | Rejected policy generations |
| `waf_distributed_stale_policy_total` | counter | Policy reads past their freshness window |
| `waf_distributed_lease_granted_units_total` | counter | Shared rate-limit units granted |
| `waf_distributed_lease_expired_total` | counter | Leases removed after expiry |
| `waf_distributed_lease_denied_total` | counter | Lease requests/spends denied |
| `waf_distributed_lease_fallback_total` | counter | Shared-budget decisions without a lease |
| `waf_distributed_lease_request_dropped_total` | counter | Lease requests evicted from the bounded queue |

## Queues and backpressure

Security events and rate-limit counter deltas use separate bounded queues
(default 8192 and 4096). Enqueue is `try_push`; when a queue is full the drop
policy is `drop_oldest` and `waf_distributed_queue_dropped_total` increments.
A request is never blocked, delayed or failed by telemetry pressure.

On shutdown the controller stops accepting work (`PushOutcome::Closed`),
drains what is already queued, and the handle waits up to two seconds for the
task to finish.

## Cache semantics

- Entries are fresh until `policy_cache_ttl_secs` /
  `reputation_cache_ttl_secs`.
- Past the TTL they are `Stale` until `max_stale_secs`; after that they are a
  miss. An expired reputation entry is *unknown*, never benign.
- A higher policy generation atomically invalidates all prior entries.
- Explicitly blocked entries are reported as `Blocked`, so a caller can make a
  fail-closed decision without pretending the entry is fresh.

## End-to-end verification

`scripts/test-distri-e2e.sh` builds the real server from
`shift/distri-kv@9079588` (the complete `waf.distri.v1` contract) into
`/tmp/opencode/dkv-e2e`, builds `waf-ingress` with `--features
distri-kv,export-sled`, and runs the ignored tests in
`tests/integration/distri_e2e.rs`. The server checkout is never modified.

```bash
scripts/test-distri-e2e.sh
# or, with an existing build:
DISTRI_KV_SERVER_BIN=/path/to/distri-kv-server \
  nix develop -c cargo test --features distri-kv,export-sled \
  --test integration distri_e2e -- --ignored --test-threads=1
```

The harness starts every component on ephemeral ports in a temporary
directory. It does **not** disable server auth: the server runs its real
bearer-token mode with a per-run token written to a temp file, and the WAF
config carries the same `auth_token`. Ephemeral TLS certificates are not
needed because both processes use the plaintext listener and the token is the
authenticated credential; production mTLS/SPIFFE remains the default.

| Test | Verifies |
| --- | --- |
| `waf_client_registers_heartbeats_and_ingests` | `Register`/`Heartbeat` succeed, `Discover` lists the node, a seeded reputation entry round-trips, and security events plus counter deltas (including `batch_id` dedupe) are accepted |
| `policy_generation_change_invalidates_waf_cache` | The controller fetches generation 1, then generation 2 after `ActivatePolicy`, and the versioned cache records an invalidation |
| `proxy_registers_and_applies_policy_generations` | The real `waf-ingress` process connects, appears in `distri_waf_connected_nodes`, serves traffic, and advances `waf_distributed_policy_generation` after activation |
| `local_only_keeps_serving_while_cluster_is_down` | With an unreachable endpoint, `waf_distributed_fallback_activations_total` increments and the proxy still returns `200` |
| `fallback_modes_are_explicit` | `local_only` → local decision, `fail_open` → allow, `fail_closed` → block for unanswered shared lookups |

The reputation fixture is written directly into the server's sled namespace
before the server opens it, because the v1 WAF-node contract has no
reputation-write RPC.

## Performance

The controller never runs on the request path. `scripts/bench-distributed.sh`
measures the real proxy with the feature disabled, with an unreachable
endpoint, and with an endpoint that accepts connections but never responds.
Recorded p50/p95/p99, throughput, allocations, controller CPU and cache costs
are in [distributed-performance.md](distributed-performance.md).

## Rollout

1. Build with `--features distri-kv` and leave `enabled = false`. Confirm
   metrics and decisions are unchanged.
2. Set `enabled = true` with `endpoints = []` and `fallback = "local_only"`.
   The controller runs with local-only sources; no request decision changes.
3. Add endpoints and a `node_id`/`region`, keep `shadow = true` for the
   canary: derived multipliers/blocks are logged, not enforced. Verify
   `waf_distributed_connected`, heartbeat age and generation in `/metrics`.
4. Only then consider `fail_open`/`fail_closed`, with the runbook updated.

Rollback is `enabled = false` (restart required; the config block is
startup-only today) or a build without the feature.
