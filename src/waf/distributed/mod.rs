//! Distributed security fabric client scaffold (`distri-kv` feature).
//!
//! The design is a two-plane split: request decisions stay entirely local and
//! the distri-kv cluster supplies versioned policy, reputation, node liveness
//! and observation. This module is the WAF-side boundary, not a client for a
//! specific distri-kv build: distri-kv currently does not compile or expose a
//! WAF client, so no dependency is declared. A future client plugs into the
//! traits in [`traits`] and the controller drives it.
//!
//! Invariants:
//!
//! - The request path never `await`s a control-plane call. It reads caches and
//!   enqueues into bounded queues with `try_push`.
//! - `fallback = "local_only"` (default) means an unavailable cluster never
//!   changes a decision.
//! - Queue overflow drops telemetry, never a request.
//! - Policy/reputation caches are invalidated by generation, and stale entries
//!   are an explicit state rather than silently fresh data.
//!
//! See `docs/operations/distributed.md` and
//! `docs/design/distributed-waf-architecture.md`.

pub mod cache;
pub mod controller;
/// Vendored `waf.distri.v1` prost/tonic bindings. Generated code; do not edit.
#[allow(clippy::all, missing_docs)]
pub mod distri_waf;
pub mod grpc;
pub mod leases;
pub mod local;
pub mod metrics;
pub mod policy_verify;
pub mod state;
pub mod traits;

#[cfg(test)]
mod tests;

pub use crate::config::{DistributedConfig, DistributedFallbackMode};

pub use cache::{CacheLookup, CacheState, VersionedCache};
pub use controller::{
    next_backoff, BoundedQueue, ControllerHandle, DistributedController, DropPolicy, PushOutcome,
};
pub use grpc::DistriWafClient;
pub use leases::{LeaseConsume, LeaseGrant, LeaseKey, LeasePool, LeaseRequest, LeaseRequests};
pub use local::{
    LocalEventSink, LocalNodeRegistry, LocalPolicySource, LocalRateLimitSync, LocalReputationSource,
};
pub use metrics::DistributedMetrics;
pub use policy_verify::{payload_hash, PolicyVerificationState, PolicyVerifier};
pub use state::{DistributedState, UnavailableDecision};
pub use traits::{
    CounterDelta, DistributedError, DistributedErrorKind, EventDecision, EventSink,
    EventThreatLevel, HeartbeatAck, LeaseSource, NodeInfo, NodeRegistry, PolicySnapshot,
    PolicySource, RateLimitSync, ReputationEntry, ReputationSource, SecurityEventRecord,
};
