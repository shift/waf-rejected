//! Async controller skeleton.
//!
//! One background Tokio task owns every control-plane interaction. The request
//! path only enqueues into bounded queues (`try_push`, never `await`) and reads
//! already-applied caches. Queue overflow drops telemetry and increments a
//! counter; it never blocks or fails a request.
//!
//! The controller is transport agnostic. A future distri-kv client implements
//! [`PolicySource`], [`ReputationSource`], [`RateLimitSync`], [`EventSink`] and
//! [`NodeRegistry`]; this scaffold ships only the `LocalOnly` set.

use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{watch, Notify};
use tokio::task::JoinHandle;

use crate::config::DistributedConfig;

use super::cache::VersionedCache;
use super::local::{
    LocalEventSink, LocalNodeRegistry, LocalPolicySource, LocalRateLimitSync, LocalReputationSource,
};
use super::state::DistributedState;
use super::traits::{
    CounterDelta, DistributedError, EventSink, HeartbeatAck, LeaseSource, NodeInfo, NodeRegistry,
    PolicySnapshot, PolicySource, RateLimitSync, ReputationEntry, ReputationSource,
    SecurityEventRecord,
};

/// What happens when a bounded queue is full.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropPolicy {
    /// Evict the oldest item to make room. Preferred for telemetry: the most
    /// recent events/counters are the most useful.
    DropOldest,
    /// Reject the new item.
    DropNewest,
}

/// Result of a non-blocking enqueue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushOutcome {
    Enqueued,
    DroppedOldest,
    DroppedNewest,
    Closed,
}

/// Bounded, non-blocking queue with explicit drop accounting.
#[derive(Debug)]
pub struct BoundedQueue<T> {
    capacity: usize,
    policy: DropPolicy,
    inner: Mutex<VecDeque<T>>,
    notify: Notify,
    closed: AtomicBool,
    dropped: AtomicU64,
    enqueued: AtomicU64,
}

impl<T> BoundedQueue<T> {
    pub fn new(capacity: usize, policy: DropPolicy) -> Self {
        Self {
            capacity: capacity.max(1),
            policy,
            inner: Mutex::new(VecDeque::with_capacity(capacity.min(1024))),
            notify: Notify::new(),
            closed: AtomicBool::new(false),
            dropped: AtomicU64::new(0),
            enqueued: AtomicU64::new(0),
        }
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn len(&self) -> usize {
        self.inner.lock().expect("queue lock poisoned").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    pub fn enqueued(&self) -> u64 {
        self.enqueued.load(Ordering::Relaxed)
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    /// Enqueue without waiting. The lock is held only for the push.
    pub fn try_push(&self, item: T) -> PushOutcome {
        if self.is_closed() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return PushOutcome::Closed;
        }
        let mut queue = self.inner.lock().expect("queue lock poisoned");
        if self.is_closed() {
            drop(queue);
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return PushOutcome::Closed;
        }
        if queue.len() >= self.capacity {
            match self.policy {
                DropPolicy::DropOldest => {
                    queue.pop_front();
                    self.dropped.fetch_add(1, Ordering::Relaxed);
                    queue.push_back(item);
                    drop(queue);
                    self.enqueued.fetch_add(1, Ordering::Relaxed);
                    self.notify.notify_one();
                    return PushOutcome::DroppedOldest;
                }
                DropPolicy::DropNewest => {
                    drop(queue);
                    self.dropped.fetch_add(1, Ordering::Relaxed);
                    return PushOutcome::DroppedNewest;
                }
            }
        }
        queue.push_back(item);
        drop(queue);
        self.enqueued.fetch_add(1, Ordering::Relaxed);
        self.notify.notify_one();
        PushOutcome::Enqueued
    }

    /// Drain up to `max` items without waiting.
    pub fn drain_batch(&self, max: usize) -> Vec<T> {
        let mut queue = self.inner.lock().expect("queue lock poisoned");
        let count = queue.len().min(max);
        queue.drain(..count).collect()
    }

    /// Wait for at least one item and drain up to `max`; returns empty after
    /// [`Self::close`].
    pub async fn pop_batch(&self, max: usize) -> Vec<T> {
        loop {
            {
                let mut queue = self.inner.lock().expect("queue lock poisoned");
                if !queue.is_empty() {
                    let count = queue.len().min(max);
                    return queue.drain(..count).collect();
                }
                if self.is_closed() {
                    return Vec::new();
                }
            }
            self.notify.notified().await;
        }
    }

    /// Stop accepting work and wake every consumer.
    pub fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.notify.notify_waiters();
    }
}

/// Handle held by the server/proxy to feed the controller and observe it.
#[derive(Debug)]
pub struct ControllerHandle {
    shutdown: watch::Sender<bool>,
    join: Mutex<Option<JoinHandle<()>>>,
    state: Arc<DistributedState>,
    events: Arc<BoundedQueue<SecurityEventRecord>>,
    counters: Arc<BoundedQueue<CounterDelta>>,
    policy_cache: Arc<VersionedCache<String, PolicySnapshot>>,
    reputation_cache: Arc<VersionedCache<IpAddr, ReputationEntry>>,
}

impl ControllerHandle {
    pub fn state(&self) -> &Arc<DistributedState> {
        &self.state
    }

    pub fn enqueue_event(&self, event: SecurityEventRecord) -> PushOutcome {
        let outcome = self.events.try_push(event);
        if matches!(
            outcome,
            PushOutcome::DroppedOldest | PushOutcome::DroppedNewest | PushOutcome::Closed
        ) {
            self.state.metrics().record_drop();
        } else {
            self.state.metrics().record_enqueued();
        }
        outcome
    }

    pub fn enqueue_counter(&self, delta: CounterDelta) -> PushOutcome {
        let outcome = self.counters.try_push(delta);
        if matches!(
            outcome,
            PushOutcome::DroppedOldest | PushOutcome::DroppedNewest | PushOutcome::Closed
        ) {
            self.state.metrics().record_drop();
        } else {
            self.state.metrics().record_enqueued();
        }
        outcome
    }

    pub fn queue_depths(&self) -> [(&'static str, usize); 2] {
        [
            ("events", self.events.len()),
            ("counters", self.counters.len()),
        ]
    }

    pub fn policy_cache(&self) -> &Arc<VersionedCache<String, PolicySnapshot>> {
        &self.policy_cache
    }

    pub fn reputation_cache(&self) -> &Arc<VersionedCache<IpAddr, ReputationEntry>> {
        &self.reputation_cache
    }

    /// Signal shutdown and wait for the controller task to finish. Bounded by
    /// a short timeout so a stuck transport cannot hold process exit.
    pub async fn shutdown(&self) {
        let _ = self.shutdown.send(true);
        self.events.close();
        self.counters.close();
        let join = self
            .join
            .lock()
            .expect("controller join lock poisoned")
            .take();
        if let Some(join) = join {
            let _ = tokio::time::timeout(Duration::from_secs(2), join).await;
        }
    }
}

/// Background controller scaffold.
pub struct DistributedController {
    config: DistributedConfig,
    state: Arc<DistributedState>,
    node: NodeInfo,
    policy_source: Arc<dyn PolicySource>,
    reputation_source: Arc<dyn ReputationSource>,
    rate_limit_sync: Arc<dyn RateLimitSync>,
    event_sink: Arc<dyn EventSink>,
    registry: Arc<dyn NodeRegistry>,
    lease_source: Option<Arc<dyn LeaseSource>>,
    events: Arc<BoundedQueue<SecurityEventRecord>>,
    counters: Arc<BoundedQueue<CounterDelta>>,
    policy_cache: Arc<VersionedCache<String, PolicySnapshot>>,
    reputation_cache: Arc<VersionedCache<IpAddr, ReputationEntry>>,
    shutdown: watch::Sender<bool>,
}

impl DistributedController {
    /// Local-only controller: every source is a no-op and no network is used.
    pub fn local_only(config: &DistributedConfig) -> Self {
        let state = Arc::new(DistributedState::from_config(config));
        Self::with_sources(
            config,
            state,
            Arc::new(LocalPolicySource),
            Arc::new(LocalReputationSource),
            Arc::new(LocalRateLimitSync::default()),
            Arc::new(LocalEventSink::default()),
            Arc::new(LocalNodeRegistry),
        )
    }

    /// Build the controller from configuration.
    ///
    /// With no endpoints this is exactly [`Self::local_only`]. With endpoints
    /// every trait is backed by the tonic client; transport failures remain
    /// recoverable and `local_only` fallback still changes no decision.
    pub fn from_config(config: &DistributedConfig) -> Result<Self, DistributedError> {
        Self::from_config_with_state(config, Arc::new(DistributedState::from_config(config)))
    }

    /// Build the controller against an existing [`DistributedState`] so the
    /// engine and the controller observe the same connectivity/generation
    /// handle.
    pub fn from_config_with_state(
        config: &DistributedConfig,
        state: Arc<DistributedState>,
    ) -> Result<Self, DistributedError> {
        if config.endpoints.is_empty() {
            return Ok(Self::with_sources(
                config,
                state,
                Arc::new(LocalPolicySource),
                Arc::new(LocalReputationSource),
                Arc::new(LocalRateLimitSync::default()),
                Arc::new(LocalEventSink::default()),
                Arc::new(LocalNodeRegistry),
            ));
        }
        let client = Arc::new(super::grpc::DistriWafClient::new(config)?);
        let lease_source: Arc<dyn LeaseSource> = Arc::clone(&client) as Arc<dyn LeaseSource>;
        Ok(Self::with_sources(
            config,
            state,
            Arc::clone(&client) as Arc<dyn PolicySource>,
            Arc::clone(&client) as Arc<dyn ReputationSource>,
            Arc::clone(&client) as Arc<dyn RateLimitSync>,
            Arc::clone(&client) as Arc<dyn EventSink>,
            Arc::clone(&client) as Arc<dyn NodeRegistry>,
        )
        .with_lease_source(lease_source))
    }

    /// Attach an asynchronous lease source. Off by default so local-only and
    /// existing tests never construct a lease RPC.
    pub fn with_lease_source(mut self, lease_source: Arc<dyn LeaseSource>) -> Self {
        self.lease_source = Some(lease_source);
        self
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_sources(
        config: &DistributedConfig,
        state: Arc<DistributedState>,
        policy_source: Arc<dyn PolicySource>,
        reputation_source: Arc<dyn ReputationSource>,
        rate_limit_sync: Arc<dyn RateLimitSync>,
        event_sink: Arc<dyn EventSink>,
        registry: Arc<dyn NodeRegistry>,
    ) -> Self {
        let max_stale = Duration::from_secs(config.max_stale_secs);
        let (shutdown, _) = watch::channel(false);
        Self {
            config: config.clone(),
            node: NodeInfo {
                node_id: config.node_id.clone(),
                region: config.region.clone(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                epoch: 0,
            },
            state,
            policy_source,
            reputation_source,
            rate_limit_sync,
            event_sink,
            registry,
            lease_source: None,
            events: Arc::new(BoundedQueue::new(
                config.event_queue_capacity,
                DropPolicy::DropOldest,
            )),
            counters: Arc::new(BoundedQueue::new(
                config.counter_queue_capacity,
                DropPolicy::DropOldest,
            )),
            policy_cache: Arc::new(VersionedCache::new(
                Duration::from_secs(config.policy_cache_ttl_secs),
                max_stale,
                64,
            )),
            reputation_cache: Arc::new(VersionedCache::new(
                Duration::from_secs(config.reputation_cache_ttl_secs),
                max_stale,
                65_536,
            )),
            shutdown,
        }
    }

    pub fn state(&self) -> &Arc<DistributedState> {
        &self.state
    }

    pub fn policy_cache(&self) -> &Arc<VersionedCache<String, PolicySnapshot>> {
        &self.policy_cache
    }

    pub fn reputation_cache(&self) -> &Arc<VersionedCache<IpAddr, ReputationEntry>> {
        &self.reputation_cache
    }

    pub fn events(&self) -> &Arc<BoundedQueue<SecurityEventRecord>> {
        &self.events
    }

    pub fn counters(&self) -> &Arc<BoundedQueue<CounterDelta>> {
        &self.counters
    }

    /// Spawn the controller on the current Tokio runtime.
    pub fn spawn(self) -> ControllerHandle {
        let handle = self.handle();
        let join = tokio::spawn(async move {
            self.run().await;
        });
        *handle.join.lock().expect("controller join lock poisoned") = Some(join);
        handle
    }

    /// Create a handle without running the controller (tests and wiring).
    pub fn handle(&self) -> ControllerHandle {
        ControllerHandle {
            shutdown: self.shutdown.clone(),
            join: Mutex::new(None),
            state: Arc::clone(&self.state),
            events: Arc::clone(&self.events),
            counters: Arc::clone(&self.counters),
            policy_cache: Arc::clone(&self.policy_cache),
            reputation_cache: Arc::clone(&self.reputation_cache),
        }
    }

    /// Run until shutdown. Reconnect/backoff applies to heartbeat failures.
    pub async fn run(mut self) {
        let mut shutdown = self.shutdown.subscribe();
        let interval = Duration::from_secs(self.config.heartbeat_interval_secs.max(1));
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut backoff = Duration::from_millis(self.config.reconnect_initial_backoff_ms.max(1));
        let max_backoff = Duration::from_millis(self.config.reconnect_max_backoff_ms.max(1));

        // Best-effort registration; an error is just an offline start.
        if let Err(error) = self.registry.register(&self.node).await {
            tracing::debug!(%error, "distributed node registration failed; staying local");
            self.state.set_connected(false);
        }

        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                _ = ticker.tick() => {
                    let heartbeat = self.registry.heartbeat(&self.node).await;
                    match heartbeat {
                        Ok(ack) => {
                            self.on_heartbeat(ack);
                            backoff = Duration::from_millis(
                                self.config.reconnect_initial_backoff_ms.max(1),
                            );
                        }
                        Err(error) => {
                            self.on_offline(&error);
                            if !error.is_retryable() {
                                tracing::warn!(%error, "distributed heartbeat failed (non-retryable)");
                            }
                            if tokio::time::timeout(backoff, shutdown.changed())
                                .await
                                .is_ok()
                            {
                                break;
                            }
                            backoff = next_backoff(backoff, max_backoff);
                        }
                    }

                    self.flush_telemetry().await;
                    self.refresh_policy().await;
                    self.refresh_leases().await;
                }
            }
        }

        // Drain what is already queued, then stop. New pushes are rejected
        // with `PushOutcome::Closed`.
        self.flush_telemetry().await;
        self.events.close();
        self.counters.close();
        tracing::debug!("distributed controller stopped");
    }

    fn on_heartbeat(&mut self, ack: HeartbeatAck) {
        if ack.connected {
            self.state.set_connected(true);
        } else {
            self.state.set_connected(false);
        }
        if let Some(generation) = ack.policy_generation {
            if generation > self.state.policy_generation() {
                self.apply_generation(generation);
            }
        }
    }

    fn on_offline(&mut self, _error: &DistributedError) {
        self.state.set_connected(false);
        self.state.metrics().record_reconnect();
    }

    fn apply_generation(&mut self, generation: u64) {
        if self.state.set_policy_generation(generation) {
            self.policy_cache.set_generation(generation);
            self.reputation_cache.set_generation(generation);
            tracing::info!(generation, "applied distributed policy generation");
        }
    }

    async fn refresh_policy(&mut self) {
        let result = self.policy_source.current_policy().await;
        match result {
            Ok(snapshot) => {
                self.state.set_policy_integrity_ok(true);
                if snapshot.generation > self.state.policy_generation() {
                    self.apply_generation(snapshot.generation);
                }
                // Shadow mode never applies the feedback multiplier.
                if !self.config.shadow {
                    self.state
                        .set_rate_limit_multiplier(snapshot.rate_limit_multiplier);
                }
                self.policy_cache.insert_with_generation(
                    "active".to_string(),
                    snapshot,
                    self.state.policy_generation(),
                );
            }
            Err(error) => {
                self.state.metrics().record_stale_policy();
                if error.kind == super::traits::DistributedErrorKind::Invalid {
                    self.state.metrics().record_policy_rejected();
                    self.state.set_policy_integrity_ok(false);
                    tracing::warn!(%error, "policy bundle rejected by integrity checks");
                }
                self.on_offline(&error);
            }
        }
    }

    /// Drain the bounded lease-request queue and acquire grants off the
    /// request path. A transport error is accounted once per batch; the
    /// request path keeps failing closed for its shared budget.
    async fn refresh_leases(&mut self) {
        let Some(lease_source) = &self.lease_source else {
            return;
        };
        if !self.state.leases_enabled() {
            return;
        }
        self.state.lease_pool().sweep();
        let requests = self
            .state
            .lease_requests()
            .drain_batch(self.config.lease_batch_max.max(1));
        if requests.is_empty() {
            return;
        }
        match lease_source.acquire_leases(&requests).await {
            Ok(grants) => {
                for grant in grants {
                    self.state.apply_lease(grant);
                }
            }
            Err(error) => {
                tracing::debug!(%error, "distributed lease acquisition failed; shared budget unavailable");
                self.state.metrics().record_lease_fallback();
            }
        }
    }

    async fn flush_telemetry(&mut self) {
        let events = self.events.drain_batch(256);
        if !events.is_empty() {
            if let Err(error) = self.event_sink.export(&events).await {
                tracing::debug!(%error, "distributed event export failed; events dropped");
                self.state.metrics().record_drop();
            }
        }
        let counters = self.counters.drain_batch(4096);
        if !counters.is_empty() {
            if let Err(error) = self.rate_limit_sync.flush(&counters).await {
                tracing::debug!(%error, "distributed counter flush failed; deltas dropped");
                self.state.metrics().record_drop();
            }
        }
    }

    /// Background cache fill for a reputation miss. The request path must call
    /// this from a spawned task, never inline.
    pub async fn prefetch_reputation(&self, ip: IpAddr) {
        if matches!(
            self.reputation_cache.get(&ip),
            super::cache::CacheLookup::Hit { .. }
        ) {
            return;
        }
        match self.reputation_source.lookup(ip).await {
            Ok(Some(entry)) => self.reputation_cache.insert(ip, entry),
            Ok(None) => {
                // Cache "unknown" as an explicit blocked-free miss marker by
                // not inserting; the TTL path stays a miss.
            }
            Err(error) => tracing::debug!(%error, %ip, "reputation prefetch failed"),
        }
    }
}

/// Exponential backoff with a cap. Pure function so it is easy to test.
pub fn next_backoff(current: Duration, max: Duration) -> Duration {
    let doubled = current.saturating_mul(2);
    doubled.min(max).max(Duration::from_millis(1))
}
