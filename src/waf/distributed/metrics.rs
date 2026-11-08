//! Lock-free counters for the distributed client.
//!
//! The controller and the request-path caches update these atomics; the
//! Prometheus renderer reads them without taking a lock. Nothing here is on
//! the request path except cache hit/miss increments.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Counters shared by the controller, the caches and `DistributedState`.
#[derive(Debug, Default)]
pub struct DistributedMetrics {
    pub(crate) cache_hits: AtomicU64,
    pub(crate) cache_misses: AtomicU64,
    pub(crate) cache_stale: AtomicU64,
    pub(crate) cache_blocked: AtomicU64,
    pub(crate) cache_invalidations: AtomicU64,
    pub(crate) queue_dropped: AtomicU64,
    pub(crate) queue_enqueued: AtomicU64,
    pub(crate) reconnects: AtomicU64,
    pub(crate) fallback_activations: AtomicU64,
    pub(crate) policy_rejected: AtomicU64,
    pub(crate) stale_policy: AtomicU64,
}

impl DistributedMetrics {
    pub fn record_cache_hit(&self) {
        self.cache_hits.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_cache_miss(&self) {
        self.cache_misses.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_cache_stale(&self) {
        self.cache_stale.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_cache_blocked(&self) {
        self.cache_blocked.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_cache_invalidation(&self) {
        self.cache_invalidations.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_enqueued(&self) {
        self.queue_enqueued.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_drop(&self) {
        self.queue_dropped.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_reconnect(&self) {
        self.reconnects.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_fallback_activation(&self) {
        self.fallback_activations.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_policy_rejected(&self) {
        self.policy_rejected.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_stale_policy(&self) {
        self.stale_policy.fetch_add(1, Ordering::Relaxed);
    }

    pub fn cache_hits(&self) -> u64 {
        self.cache_hits.load(Ordering::Relaxed)
    }

    pub fn cache_misses(&self) -> u64 {
        self.cache_misses.load(Ordering::Relaxed)
    }

    pub fn cache_stale(&self) -> u64 {
        self.cache_stale.load(Ordering::Relaxed)
    }

    pub fn cache_blocked(&self) -> u64 {
        self.cache_blocked.load(Ordering::Relaxed)
    }

    pub fn cache_invalidations(&self) -> u64 {
        self.cache_invalidations.load(Ordering::Relaxed)
    }

    pub fn queue_enqueued(&self) -> u64 {
        self.queue_enqueued.load(Ordering::Relaxed)
    }

    pub fn queue_dropped(&self) -> u64 {
        self.queue_dropped.load(Ordering::Relaxed)
    }

    pub fn reconnects(&self) -> u64 {
        self.reconnects.load(Ordering::Relaxed)
    }

    pub fn fallback_activations(&self) -> u64 {
        self.fallback_activations.load(Ordering::Relaxed)
    }

    pub fn policy_rejected(&self) -> u64 {
        self.policy_rejected.load(Ordering::Relaxed)
    }

    pub fn stale_policy(&self) -> u64 {
        self.stale_policy.load(Ordering::Relaxed)
    }
}

/// Append the distributed metric family to a Prometheus text exposition.
///
/// Gauges that depend on a live handle are supplied by the caller so this
/// function stays free of state. `queues` is `(label, depth)`.
pub fn render_prometheus(
    out: &mut String,
    connected: bool,
    heartbeat_age: Option<Duration>,
    policy_generation: u64,
    metrics: &DistributedMetrics,
    queues: &[(&str, usize)],
) {
    use std::fmt::Write;

    let _ = writeln!(
        out,
        "# HELP waf_distributed_connected Whether the regional distri-kv watch/heartbeat is connected.\n\
         # TYPE waf_distributed_connected gauge\n\
         waf_distributed_connected {}",
        u8::from(connected)
    );
    let _ = writeln!(
        out,
        "# HELP waf_distributed_heartbeat_age_seconds Seconds since the last acknowledged heartbeat.\n\
         # TYPE waf_distributed_heartbeat_age_seconds gauge\n\
         waf_distributed_heartbeat_age_seconds {}",
        heartbeat_age.map(|age| age.as_secs_f64()).unwrap_or(0.0)
    );
    let _ = writeln!(
        out,
        "# HELP waf_distributed_policy_generation Last applied policy generation.\n\
         # TYPE waf_distributed_policy_generation gauge\n\
         waf_distributed_policy_generation {}",
        policy_generation
    );
    let _ = writeln!(
        out,
        "# HELP waf_distributed_cache_hits_total Distributed policy/reputation cache hits.\n\
         # TYPE waf_distributed_cache_hits_total counter\n\
         waf_distributed_cache_hits_total {}\n\
         # HELP waf_distributed_cache_misses_total Distributed policy/reputation cache misses.\n\
         # TYPE waf_distributed_cache_misses_total counter\n\
         waf_distributed_cache_misses_total {}\n\
         # HELP waf_distributed_cache_stale_total Stale (but within max_stale) cache reads.\n\
         # TYPE waf_distributed_cache_stale_total counter\n\
         waf_distributed_cache_stale_total {}\n\
         # HELP waf_distributed_cache_blocked_total Cache reads answered from an explicit blocked entry.\n\
         # TYPE waf_distributed_cache_blocked_total counter\n\
         waf_distributed_cache_blocked_total {}\n\
         # HELP waf_distributed_cache_invalidations_total Generation-based cache invalidations.\n\
         # TYPE waf_distributed_cache_invalidations_total counter\n\
         waf_distributed_cache_invalidations_total {}",
        metrics.cache_hits(),
        metrics.cache_misses(),
        metrics.cache_stale(),
        metrics.cache_blocked(),
        metrics.cache_invalidations(),
    );
    let _ = writeln!(
        out,
        "# HELP waf_distributed_queue_enqueued_total Items accepted into bounded queues.\n\
         # TYPE waf_distributed_queue_enqueued_total counter\n\
         waf_distributed_queue_enqueued_total {}\n\
         # HELP waf_distributed_queue_dropped_total Items dropped because a queue was full or closed.\n\
         # TYPE waf_distributed_queue_dropped_total counter\n\
         waf_distributed_queue_dropped_total {}\n\
         # HELP waf_distributed_reconnects_total Controller reconnect attempts after an error.\n\
         # TYPE waf_distributed_reconnects_total counter\n\
         waf_distributed_reconnects_total {}\n\
         # HELP waf_distributed_fallback_activations_total Times the configured fallback mode was applied.\n\
         # TYPE waf_distributed_fallback_activations_total counter\n\
         waf_distributed_fallback_activations_total {}\n\
         # HELP waf_distributed_policy_rejected_total Policy generations rejected before apply.\n\
         # TYPE waf_distributed_policy_rejected_total counter\n\
         waf_distributed_policy_rejected_total {}\n\
         # HELP waf_distributed_stale_policy_total Policy reads that exceeded their freshness window.\n\
         # TYPE waf_distributed_stale_policy_total counter\n\
         waf_distributed_stale_policy_total {}",
        metrics.queue_enqueued(),
        metrics.queue_dropped(),
        metrics.reconnects(),
        metrics.fallback_activations(),
        metrics.policy_rejected(),
        metrics.stale_policy(),
    );
    for (label, depth) in queues {
        let _ = writeln!(
            out,
            "waf_distributed_queue_depth{{queue=\"{label}\"}} {depth}"
        );
    }
}
