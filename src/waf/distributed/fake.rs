//! In-memory QuicCrunch transport used by transport-agnostic tests.
//!
//! It implements the exact same [`super::transport::TransportClient`] seam as
//! the real transports so controller tests can exercise registration,
//! heartbeat, policy refresh, reputation, counters, event ingest, reconnect
//! and `local_only` fallback without a network or the QuicCrunch dependency.

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;

use super::leases::{LeaseGrant, LeaseKey, LeaseRequest};
use super::traits::{
    CounterDelta, DistributedError, EventSink, HeartbeatAck, LeaseSource, NodeInfo, NodeRegistry,
    PolicySnapshot, PolicySource, RateLimitSync, ReputationEntry, ReputationSource,
    SecurityEventRecord,
};
use super::transport::TransportClient;

/// Scriptable, in-memory stand-in for the QuicCrunch transport.
#[derive(Default)]
pub struct FakeQuicCrunchTransport {
    generation: AtomicU64,
    registrations: AtomicU64,
    heartbeats: AtomicU64,
    events: AtomicU64,
    counters: AtomicU64,
    fail_heartbeat: AtomicBool,
    heartbeat_delay_ms: AtomicU64,
}

impl FakeQuicCrunchTransport {
    pub fn new(generation: u64) -> Self {
        Self {
            generation: AtomicU64::new(generation),
            ..Self::default()
        }
    }

    pub fn set_generation(&self, generation: u64) {
        self.generation.store(generation, Ordering::Release);
    }

    pub fn set_fail_heartbeat(&self, fail: bool) {
        self.fail_heartbeat.store(fail, Ordering::Release);
    }

    pub fn set_heartbeat_delay(&self, delay: Duration) {
        self.heartbeat_delay_ms
            .store(delay.as_millis() as u64, Ordering::Release);
    }

    pub fn registrations(&self) -> u64 {
        self.registrations.load(Ordering::Acquire)
    }

    pub fn heartbeats(&self) -> u64 {
        self.heartbeats.load(Ordering::Acquire)
    }

    pub fn events(&self) -> u64 {
        self.events.load(Ordering::Acquire)
    }

    pub fn counters(&self) -> u64 {
        self.counters.load(Ordering::Acquire)
    }
}

#[async_trait]
impl PolicySource for FakeQuicCrunchTransport {
    async fn current_policy(&self) -> Result<PolicySnapshot, DistributedError> {
        Ok(PolicySnapshot {
            generation: self.generation.load(Ordering::Acquire),
            ruleset_version: "fake-quiccrunch".to_string(),
            allowlist: Vec::new(),
            blocklist: Vec::new(),
            rate_limit_multiplier: 1.0,
            issued_at: UNIX_EPOCH,
        })
    }
}

#[async_trait]
impl ReputationSource for FakeQuicCrunchTransport {
    async fn lookup(&self, ip: IpAddr) -> Result<Option<ReputationEntry>, DistributedError> {
        if ip.to_string() == "203.0.113.7" {
            Ok(Some(ReputationEntry {
                ip,
                score: 0.93,
                confidence: 0.8,
                labels: vec!["scanner".to_string()],
                expires_at: None,
                version: 9,
            }))
        } else {
            Ok(None)
        }
    }
}

#[async_trait]
impl RateLimitSync for FakeQuicCrunchTransport {
    async fn flush(&self, deltas: &[CounterDelta]) -> Result<(), DistributedError> {
        self.counters
            .fetch_add(deltas.len() as u64, Ordering::AcqRel);
        Ok(())
    }
}

#[async_trait]
impl EventSink for FakeQuicCrunchTransport {
    async fn export(&self, events: &[SecurityEventRecord]) -> Result<(), DistributedError> {
        self.events.fetch_add(events.len() as u64, Ordering::AcqRel);
        Ok(())
    }
}

#[async_trait]
impl NodeRegistry for FakeQuicCrunchTransport {
    async fn register(&self, _node: &NodeInfo) -> Result<HeartbeatAck, DistributedError> {
        self.registrations.fetch_add(1, Ordering::AcqRel);
        Ok(HeartbeatAck {
            connected: true,
            server_time_unix_ms: now_millis(),
            policy_generation: Some(self.generation.load(Ordering::Acquire)),
        })
    }

    async fn heartbeat(&self, _node: &NodeInfo) -> Result<HeartbeatAck, DistributedError> {
        self.heartbeats.fetch_add(1, Ordering::AcqRel);
        let delay = self.heartbeat_delay_ms.load(Ordering::Acquire);
        if delay > 0 {
            tokio::time::sleep(Duration::from_millis(delay)).await;
        }
        if self.fail_heartbeat.load(Ordering::Acquire) {
            return Err(DistributedError::unavailable(
                "fake quiccrunch cluster is down",
            ));
        }
        Ok(HeartbeatAck {
            connected: true,
            server_time_unix_ms: now_millis(),
            policy_generation: Some(self.generation.load(Ordering::Acquire)),
        })
    }
}

#[async_trait]
impl LeaseSource for FakeQuicCrunchTransport {
    async fn acquire_leases(
        &self,
        requests: &[LeaseRequest],
    ) -> Result<Vec<LeaseGrant>, DistributedError> {
        Ok(requests
            .iter()
            .map(|request| LeaseGrant {
                lease_id: format!("fake-{}", request.policy_id),
                key: LeaseKey::new(&request.policy_id, request.shard, request.key_hash),
                granted: request.requested,
                remaining: request.requested,
                expires_in: Duration::from_secs(5),
                denied: false,
            })
            .collect())
    }
}

#[async_trait]
impl TransportClient for FakeQuicCrunchTransport {
    fn transport_name(&self) -> &'static str {
        "fake-quiccrunch"
    }
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Kept so tests can assert the fake never shares state accidentally.
impl std::fmt::Debug for FakeQuicCrunchTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FakeQuicCrunchTransport")
            .field("generation", &self.generation.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}
