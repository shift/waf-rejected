//! `LocalOnly` source implementations.
//!
//! These preserve today's single-process behaviour exactly: the local policy
//! is generation 0 with no shared entries, reputation is always unknown, and
//! counter/event egress is a no-op because the existing local exporters remain
//! the evidence path. Enabling the `distri-kv` feature without a cluster uses
//! these and changes no request decision.

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;

use super::traits::{
    CounterDelta, DistributedError, EventSink, HeartbeatAck, NodeInfo, NodeRegistry,
    PolicySnapshot, PolicySource, RateLimitSync, ReputationEntry, ReputationSource,
    SecurityEventRecord,
};

/// Returns the process-local policy and never contacts a cluster.
#[derive(Debug, Default, Clone)]
pub struct LocalPolicySource;

#[async_trait]
impl PolicySource for LocalPolicySource {
    async fn current_policy(&self) -> Result<PolicySnapshot, DistributedError> {
        Ok(PolicySnapshot::local())
    }
}

/// Every address is unknown, so the caller applies its local default.
#[derive(Debug, Default, Clone)]
pub struct LocalReputationSource;

#[async_trait]
impl ReputationSource for LocalReputationSource {
    async fn lookup(&self, _ip: IpAddr) -> Result<Option<ReputationEntry>, DistributedError> {
        Ok(None)
    }
}

/// Drops counter deltas on the floor. Local enforcement is unchanged; the
/// counters only exist for cross-node observation.
#[derive(Debug, Default)]
pub struct LocalRateLimitSync {
    flushed: AtomicU64,
}

impl LocalRateLimitSync {
    pub fn flushed(&self) -> u64 {
        self.flushed.load(Ordering::Relaxed)
    }
}

#[async_trait]
impl RateLimitSync for LocalRateLimitSync {
    async fn flush(&self, deltas: &[CounterDelta]) -> Result<(), DistributedError> {
        self.flushed
            .fetch_add(deltas.len() as u64, Ordering::Relaxed);
        Ok(())
    }
}

/// Events remain on the existing local exporters; this sink is a no-op.
#[derive(Debug, Default)]
pub struct LocalEventSink {
    exported: AtomicU64,
}

impl LocalEventSink {
    pub fn exported(&self) -> u64 {
        self.exported.load(Ordering::Relaxed)
    }
}

#[async_trait]
impl EventSink for LocalEventSink {
    async fn export(&self, events: &[SecurityEventRecord]) -> Result<(), DistributedError> {
        self.exported
            .fetch_add(events.len() as u64, Ordering::Relaxed);
        Ok(())
    }
}

/// Registration succeeds locally but reports `connected = false`: there is no
/// cluster to be connected to.
#[derive(Debug, Default, Clone)]
pub struct LocalNodeRegistry;

#[async_trait]
impl NodeRegistry for LocalNodeRegistry {
    async fn register(&self, _node: &NodeInfo) -> Result<HeartbeatAck, DistributedError> {
        Ok(HeartbeatAck {
            connected: false,
            server_time_unix_ms: 0,
            policy_generation: None,
        })
    }

    async fn heartbeat(&self, _node: &NodeInfo) -> Result<HeartbeatAck, DistributedError> {
        Ok(HeartbeatAck {
            connected: false,
            server_time_unix_ms: 0,
            policy_generation: None,
        })
    }
}
