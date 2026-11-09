//! Shared, lock-free handle exposed to the WAF engine and rate limiter.
//!
//! The handle never performs I/O. It records connectivity, heartbeat age,
//! the applied policy generation, the correlation rate-limit multiplier and
//! fallback activations. With the default config (`enabled = false`) the
//! engine does not create one, so current behaviour is unchanged.

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::config::{DistributedConfig, DistributedFallbackMode};

use super::leases::{LeaseConsume, LeaseKey, LeasePool, LeaseRequest, LeaseRequests};
use super::metrics::DistributedMetrics;

/// Decision to apply when shared data cannot be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnavailableDecision {
    /// Keep the local decision. This is the only mode that can never block on
    /// the cluster.
    LocalOnly,
    /// Allow (availability-first).
    Allow,
    /// Block (security-first).
    Block,
}

/// Handle shared by the controller, the engine and the rate limiter.
#[derive(Debug)]
pub struct DistributedState {
    enabled: bool,
    node_id: String,
    region: String,
    fallback: DistributedFallbackMode,
    shadow: bool,
    connected: AtomicBool,
    fallback_active: AtomicBool,
    policy_generation: AtomicU64,
    rate_limit_multiplier_bits: AtomicU32,
    heartbeat_interval: Duration,
    max_stale: Duration,
    last_heartbeat: Mutex<Option<Instant>>,
    leases_enabled: bool,
    lease_pool: LeasePool,
    lease_requests: LeaseRequests,
    policy_integrity_ok: AtomicBool,
    metrics: DistributedMetrics,
}

impl DistributedState {
    pub fn from_config(config: &DistributedConfig) -> Self {
        Self {
            enabled: config.enabled,
            node_id: config.node_id.clone(),
            region: config.region.clone(),
            fallback: config.fallback,
            shadow: config.shadow,
            connected: AtomicBool::new(false),
            fallback_active: AtomicBool::new(false),
            policy_generation: AtomicU64::new(0),
            rate_limit_multiplier_bits: AtomicU32::new(1.0f32.to_bits()),
            heartbeat_interval: Duration::from_secs(config.heartbeat_interval_secs.max(1)),
            max_stale: Duration::from_secs(config.max_stale_secs),
            last_heartbeat: Mutex::new(None),
            leases_enabled: config.leases_enabled,
            lease_pool: LeasePool::new(),
            lease_requests: LeaseRequests::new(config.lease_queue_capacity),
            policy_integrity_ok: AtomicBool::new(true),
            metrics: DistributedMetrics::default(),
        }
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    pub fn region(&self) -> &str {
        &self.region
    }

    pub fn fallback(&self) -> DistributedFallbackMode {
        self.fallback
    }

    pub fn shadow(&self) -> bool {
        self.shadow
    }

    pub fn heartbeat_interval(&self) -> Duration {
        self.heartbeat_interval
    }

    pub fn max_stale(&self) -> Duration {
        self.max_stale
    }

    pub fn connected(&self) -> bool {
        self.connected.load(Ordering::Acquire)
    }

    /// Record a successful control-plane operation.
    pub fn set_connected(&self, connected: bool) {
        if connected {
            self.connected.store(true, Ordering::Release);
            self.fallback_active.store(false, Ordering::Release);
            self.record_heartbeat();
        } else {
            self.connected.store(false, Ordering::Release);
            if !self.fallback_active.swap(true, Ordering::AcqRel) {
                // Count once per outage, not once per failed attempt.
                self.metrics.record_fallback_activation();
            }
        }
    }

    pub fn record_heartbeat(&self) {
        if let Ok(mut slot) = self.last_heartbeat.lock() {
            *slot = Some(Instant::now());
        }
        self.connected.store(true, Ordering::Release);
    }

    /// Age of the last acknowledged heartbeat, or `None` before the first one.
    pub fn heartbeat_age(&self) -> Option<Duration> {
        self.last_heartbeat
            .lock()
            .ok()
            .and_then(|slot| *slot)
            .map(|instant| instant.elapsed())
    }

    /// A heartbeat is considered fresh for `2 × interval`.
    pub fn heartbeat_is_fresh(&self) -> bool {
        self.heartbeat_age()
            .is_some_and(|age| age <= self.heartbeat_interval.saturating_mul(2))
    }

    pub fn policy_generation(&self) -> u64 {
        self.policy_generation.load(Ordering::Acquire)
    }

    /// Advance the applied generation. Returns `true` when it changed, which
    /// is the signal to invalidate generation-scoped caches.
    pub fn set_policy_generation(&self, generation: u64) -> bool {
        let previous = self.policy_generation.swap(generation, Ordering::AcqRel);
        previous != generation
    }

    pub fn rate_limit_multiplier(&self) -> f32 {
        f32::from_bits(self.rate_limit_multiplier_bits.load(Ordering::Relaxed))
    }

    /// Set the correlator's feedback multiplier. Clamped to the existing
    /// adaptive-limiter range `[0.1, 10.0]`.
    pub fn set_rate_limit_multiplier(&self, multiplier: f32) {
        let clamped = multiplier.clamp(0.1, 10.0);
        self.rate_limit_multiplier_bits
            .store(clamped.to_bits(), Ordering::Relaxed);
    }

    /// What to do when a shared lookup cannot be answered.
    ///
    /// `local_only` always returns [`UnavailableDecision::LocalOnly`], so the
    /// cluster can never block a request in the default mode.
    pub fn unavailable_decision(&self) -> UnavailableDecision {
        match self.fallback {
            DistributedFallbackMode::LocalOnly => UnavailableDecision::LocalOnly,
            DistributedFallbackMode::FailOpen => UnavailableDecision::Allow,
            DistributedFallbackMode::FailClosed => UnavailableDecision::Block,
        }
    }

    /// Convenience for callers that only need "block when the cluster is
    /// required but unavailable".
    pub fn should_block_without_cluster(&self) -> bool {
        self.unavailable_decision() == UnavailableDecision::Block
    }

    pub fn allows_without_cluster(&self) -> bool {
        self.unavailable_decision() == UnavailableDecision::Allow
    }

    /// Whether the most recently fetched policy bundle passed integrity
    /// checks. A rejected bundle flips this to `false`; a verified bundle
    /// restores it.
    pub fn policy_integrity_ok(&self) -> bool {
        self.policy_integrity_ok.load(Ordering::Acquire)
    }

    pub fn set_policy_integrity_ok(&self, ok: bool) {
        self.policy_integrity_ok.store(ok, Ordering::Release);
    }

    pub fn leases_enabled(&self) -> bool {
        self.leases_enabled
    }

    /// Non-blocking request for shared budget. Called only after the local
    /// bucket is exhausted, and never awaited.
    pub fn request_lease(&self, request: LeaseRequest) -> bool {
        if !self.leases_enabled {
            return false;
        }
        let accepted = self.lease_requests.try_push(request);
        if !accepted {
            self.metrics.record_lease_request_dropped();
        }
        accepted
    }

    pub fn lease_requests(&self) -> &LeaseRequests {
        &self.lease_requests
    }

    pub fn apply_lease(&self, grant: super::leases::LeaseGrant) {
        if grant.denied {
            self.metrics.record_lease_denied();
        } else {
            self.metrics
                .record_lease_granted(grant.remaining.max(grant.granted));
        }
        self.lease_pool.apply(grant, Instant::now());
    }

    /// Spend one unit of a cached lease. Returns `Unavailable` when there is
    /// no lease, which the caller treats as fail-closed for the shared budget.
    pub fn try_consume_lease(&self, key: &LeaseKey) -> LeaseConsume {
        let outcome = self.lease_pool.try_consume(key);
        match outcome {
            LeaseConsume::Expired => {
                self.metrics.record_lease_expired();
                self.metrics.record_lease_fallback();
            }
            LeaseConsume::Unavailable => {
                self.metrics.record_lease_fallback();
            }
            LeaseConsume::Exhausted => {
                self.metrics.record_lease_denied();
            }
            LeaseConsume::Consumed { .. } => {}
        }
        outcome
    }

    pub fn lease_pool(&self) -> &LeasePool {
        &self.lease_pool
    }

    pub fn metrics(&self) -> &DistributedMetrics {
        &self.metrics
    }

    /// Render this handle's metric families (without queue gauges).
    pub fn render_prometheus(&self, out: &mut String) {
        super::metrics::render_prometheus(
            out,
            self.connected(),
            self.heartbeat_age(),
            self.policy_generation(),
            &self.metrics,
            &[],
        );
    }
}
