use crate::waf::{Decision, RequestContext, WafRule};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use tracing::{debug, warn};

/// Number of independently locked shards used by the per-IP limiters.
///
/// A power of two keeps the shard selection cheap. 64 shards are enough to
/// remove the single global write lock from the request path without making
/// cleanup or memory accounting expensive.
pub const SHARD_COUNT: usize = 64;

/// Stable 128-bit hash used as the shared lease key for a client address.
#[cfg(feature = "distri-kv")]
fn lease_key_hash(ip: IpAddr) -> [u8; 16] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    match ip {
        IpAddr::V4(v4) => hasher.update(v4.octets()),
        IpAddr::V6(v6) => hasher.update(v6.octets()),
    }
    let digest = hasher.finalize();
    let mut hash = [0u8; 16];
    hash.copy_from_slice(&digest[..16]);
    hash
}

/// Default hard cap on the number of tracked client IPs per limiter.
pub const DEFAULT_MAX_TRACKED_IPS: usize = 100_000;

/// Behaviour when a per-IP limiter is at its tracked-IP capacity and a new IP
/// arrives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapacityPolicy {
    /// Reject new IPs with a rate-limit decision. This is the safe default: an
    /// attacker cannot evict legitimate clients or bypass limiting by spraying
    /// source addresses.
    FailClosed,
    /// Evict the least-recently-seen bucket from a shard to make room.
    /// Bounded, but an attacker with many source addresses can churn the table.
    EvictOldest,
}

impl Default for CapacityPolicy {
    fn default() -> Self {
        Self::FailClosed
    }
}

/// Token bucket for rate limiting
#[derive(Debug, Clone)]
pub struct TokenBucket {
    capacity: u32,
    tokens: u32,
    refill_rate: u32, // tokens per second
    last_refill: Instant,
}

impl TokenBucket {
    pub fn new(capacity: u32, refill_rate: u32) -> Self {
        Self {
            capacity,
            tokens: capacity,
            refill_rate,
            last_refill: Instant::now(),
        }
    }

    pub fn try_consume(&mut self, tokens: u32) -> bool {
        self.refill();

        if self.tokens >= tokens {
            self.tokens -= tokens;
            true
        } else {
            false
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill);
        let new_tokens = (elapsed.as_secs_f64() * self.refill_rate as f64) as u32;

        if new_tokens > 0 {
            self.tokens = (self.tokens + new_tokens).min(self.capacity);
            self.last_refill = now;
        }
    }

    pub fn available_tokens(&mut self) -> u32 {
        self.refill();
        self.tokens
    }
}

struct BucketEntry<V> {
    value: V,
    last_seen: Instant,
}

type ShardMap<V> = Mutex<HashMap<IpAddr, BucketEntry<V>>>;

/// Sharded, bounded map of per-IP state.
///
/// Each shard has its own mutex, so unrelated clients only contend when their
/// stable hash lands in the same shard. Cleanup is incremental: one shard is
/// swept per cleanup tick, never the whole table. The total number of entries
/// is tracked with an atomic reservation so the configured cap is hard even
/// when many shards insert concurrently.
struct ShardedBuckets<V> {
    shards: Box<[ShardMap<V>]>,
    max_tracked_ips: usize,
    capacity_policy: CapacityPolicy,
    total: AtomicUsize,
    cleanup_cursor: AtomicUsize,
    expiry: Duration,
}

impl<V> ShardedBuckets<V> {
    fn new(max_tracked_ips: usize, capacity_policy: CapacityPolicy, expiry: Duration) -> Self {
        let shards = (0..SHARD_COUNT)
            .map(|_| Mutex::new(HashMap::new()))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Self {
            shards,
            max_tracked_ips: max_tracked_ips.max(1),
            capacity_policy,
            total: AtomicUsize::new(0),
            cleanup_cursor: AtomicUsize::new(0),
            expiry,
        }
    }

    /// Stable FNV-1a hash over the address bytes. Unlike `DefaultHasher`, this
    /// does not depend on the standard library's per-process hash seed.
    fn shard_index(ip: IpAddr) -> usize {
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        let mut update = |bytes: &[u8]| {
            for byte in bytes {
                hash ^= u64::from(*byte);
                hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
            }
        };
        match ip {
            IpAddr::V4(v4) => update(&v4.octets()),
            IpAddr::V6(v6) => update(&v6.octets()),
        }
        (hash as usize) & (SHARD_COUNT - 1)
    }

    fn try_reserve(&self) -> bool {
        let mut current = self.total.load(Ordering::Relaxed);
        loop {
            if current >= self.max_tracked_ips {
                return false;
            }
            match self.total.compare_exchange_weak(
                current,
                current + 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(actual) => current = actual,
            }
        }
    }

    fn release(&self, count: usize) {
        if count > 0 {
            self.total.fetch_sub(count, Ordering::Relaxed);
        }
    }

    fn sweep_shard(&self, index: usize) {
        let mut map = self.shards[index].lock().unwrap();
        let now = Instant::now();
        let before = map.len();
        map.retain(|_, entry| now.duration_since(entry.last_seen) < self.expiry);
        self.release(before - map.len());
    }

    /// Sweep one shard every 100 evaluations. The caller supplies the
    /// evaluation counter so the trigger stays deterministic.
    fn maybe_cleanup(&self, evaluations: u64) {
        if evaluations.is_multiple_of(100) {
            let index = self.cleanup_cursor.fetch_add(1, Ordering::Relaxed) % SHARD_COUNT;
            self.sweep_shard(index);
        }
    }

    /// Evict the least-recently-seen entry from the first non-empty shard,
    /// starting at the cleanup cursor. Only one shard lock is held at a time.
    fn evict_one_any_shard(&self) -> bool {
        let start = self.cleanup_cursor.fetch_add(1, Ordering::Relaxed) % SHARD_COUNT;
        for offset in 0..SHARD_COUNT {
            let index = (start + offset) % SHARD_COUNT;
            let mut map = self.shards[index].lock().unwrap();
            let oldest = map
                .iter()
                .min_by_key(|(_, entry)| entry.last_seen)
                .map(|(ip, _)| *ip);
            if let Some(oldest) = oldest {
                map.remove(&oldest);
                drop(map);
                self.release(1);
                return true;
            }
        }
        false
    }

    /// Access (or create) the bucket for `ip` and run `f` while the shard lock
    /// is held. Returns `None` when the limiter is at capacity and the policy
    /// is `FailClosed`.
    fn access<T>(
        &self,
        ip: IpAddr,
        create: impl FnOnce() -> V,
        f: impl FnOnce(&mut V) -> T,
    ) -> Option<T> {
        let index = Self::shard_index(ip);
        let now = Instant::now();
        let mut map = self.shards[index].lock().unwrap();

        if let Some(entry) = map.get_mut(&ip) {
            entry.last_seen = now;
            return Some(f(&mut entry.value));
        }

        if !self.try_reserve() {
            // Reclaim expired entries in this shard before applying the
            // capacity policy.
            let before = map.len();
            map.retain(|_, entry| now.duration_since(entry.last_seen) < self.expiry);
            self.release(before - map.len());

            if !self.try_reserve() {
                match self.capacity_policy {
                    CapacityPolicy::FailClosed => return None,
                    CapacityPolicy::EvictOldest => {
                        // Drop this shard before touching another one so two
                        // shard locks are never held at the same time.
                        drop(map);
                        if !self.evict_one_any_shard() {
                            return None;
                        }
                        map = self.shards[index].lock().unwrap();
                        // Another thread may have inserted this IP while the
                        // lock was released.
                        if let Some(entry) = map.get_mut(&ip) {
                            entry.last_seen = now;
                            return Some(f(&mut entry.value));
                        }
                        if !self.try_reserve() {
                            return None;
                        }
                    }
                }
            }
        }

        let mut value = create();
        let result = f(&mut value);
        map.insert(
            ip,
            BucketEntry {
                value,
                last_seen: now,
            },
        );
        Some(result)
    }

    fn len(&self) -> usize {
        self.total.load(Ordering::Relaxed)
    }
}

/// Per-IP rate limiter
pub struct RateLimiter {
    name: String,
    buckets: ShardedBuckets<TokenBucket>,
    capacity: u32,
    refill_rate: u32,
    window_size: Duration,
    enabled: bool,
    /// Distributed fabric handle (`distri-kv` feature). When present, the
    /// correlation feedback multiplier adjusts new/updated bucket limits.
    /// `None` (the default) keeps the exact pre-existing arithmetic.
    #[cfg(feature = "distri-kv")]
    distributed: Option<Arc<crate::waf::distributed::DistributedState>>,
    /// Deterministic cleanup trigger; replaces a per-request RNG draw.
    evaluations: AtomicU64,
}

impl RateLimiter {
    pub fn new(name: &str, capacity: u32, refill_rate: u32, window_size: Duration) -> Self {
        Self {
            name: name.to_string(),
            buckets: ShardedBuckets::new(
                DEFAULT_MAX_TRACKED_IPS,
                CapacityPolicy::FailClosed,
                window_size * 2,
            ),
            capacity,
            refill_rate,
            window_size,
            enabled: true,
            #[cfg(feature = "distri-kv")]
            distributed: None,
            evaluations: AtomicU64::new(0),
        }
    }

    /// Attach the distributed fabric handle. Only the correlation feedback
    /// multiplier is read; enforcement stays local. Callers only do this when
    /// `waf.distributed.enabled` is true.
    #[cfg(feature = "distri-kv")]
    pub fn with_distributed_state(
        mut self,
        state: Arc<crate::waf::distributed::DistributedState>,
    ) -> Self {
        self.distributed = Some(state);
        self
    }

    #[cfg(feature = "distri-kv")]
    pub fn distributed_state(&self) -> Option<&Arc<crate::waf::distributed::DistributedState>> {
        self.distributed.as_ref()
    }

    /// Capacity/refill after the distributed feedback multiplier, if any.
    fn effective_limits(&self) -> (u32, u32) {
        #[cfg(feature = "distri-kv")]
        if let Some(state) = &self.distributed {
            let multiplier = state.rate_limit_multiplier();
            if (multiplier - 1.0).abs() > f32::EPSILON {
                let capacity = ((self.capacity as f32) / multiplier) as u32;
                let refill = ((self.refill_rate as f32) / multiplier) as u32;
                return (capacity.max(1), refill.max(1));
            }
        }
        (self.capacity, self.refill_rate)
    }

    /// Try the shared lease for an exhausted local bucket. The request path
    /// never awaits: it spends a cached grant, or enqueues one bounded request
    /// and fails closed for the shared budget.
    #[cfg(feature = "distri-kv")]
    fn try_shared_budget(&self, client_ip: IpAddr) -> Option<Decision> {
        let state = self.distributed.as_ref()?;
        if !state.leases_enabled() || state.shadow() {
            return None;
        }
        let key_hash = lease_key_hash(client_ip);
        let key = crate::waf::distributed::LeaseKey::new(&self.name, 0, key_hash);
        match state.try_consume_lease(&key) {
            crate::waf::distributed::LeaseConsume::Consumed { .. } => Some(Decision::Allow),
            crate::waf::distributed::LeaseConsume::Unavailable
            | crate::waf::distributed::LeaseConsume::Expired => {
                state.request_lease(crate::waf::distributed::LeaseRequest {
                    policy_id: self.name.clone(),
                    window_start_unix: 0,
                    shard: 0,
                    key_hash,
                    requested: u64::from(self.capacity.max(1)),
                });
                Some(Decision::RateLimit {
                    reason: "Shared rate-limit budget unavailable or expired".to_string(),
                })
            }
            crate::waf::distributed::LeaseConsume::Exhausted => Some(Decision::RateLimit {
                reason: "Shared rate-limit budget exhausted".to_string(),
            }),
        }
    }

    /// Override the tracked-IP cap and the behaviour at capacity.
    pub fn with_limits(mut self, max_tracked_ips: usize, capacity_policy: CapacityPolicy) -> Self {
        self.buckets = ShardedBuckets::new(max_tracked_ips, capacity_policy, self.window_size * 2);
        self
    }

    pub fn disabled(mut self) -> Self {
        self.enabled = false;
        self
    }

    /// Consume one token for `client_ip`. Shared by the full rule path and the
    /// bodyless fast path so both enforce the same bucket.
    fn check_ip(&self, client_ip: IpAddr) -> Decision {
        let evaluations = self.evaluations.fetch_add(1, Ordering::Relaxed);
        self.buckets.maybe_cleanup(evaluations);

        let (capacity, refill_rate) = self.effective_limits();
        let decision = self.buckets.access(
            client_ip,
            || TokenBucket::new(capacity, refill_rate),
            |bucket| {
                if bucket.capacity != capacity || bucket.refill_rate != refill_rate {
                    bucket.capacity = capacity;
                    bucket.refill_rate = refill_rate;
                    bucket.tokens = bucket.tokens.min(capacity);
                }
                if bucket.try_consume(1) {
                    debug!(
                        "Rate limit check passed for {}, {} tokens remaining",
                        client_ip,
                        bucket.available_tokens()
                    );
                    Decision::Allow
                } else {
                    warn!("Rate limit exceeded for {}", client_ip);
                    Decision::RateLimit {
                        reason: format!(
                            "Rate limit exceeded: {} requests per {} seconds",
                            self.capacity,
                            self.window_size.as_secs()
                        ),
                    }
                }
            },
        );

        #[cfg(feature = "distri-kv")]
        if let Some(Decision::RateLimit { .. }) = decision {
            if let Some(shared) = self.try_shared_budget(client_ip) {
                return shared;
            }
        }

        decision.unwrap_or_else(|| {
            warn!(
                "Per-IP rate limiter at capacity ({} tracked IPs); rejecting new IP {}",
                self.buckets.max_tracked_ips, client_ip
            );
            Decision::RateLimit {
                reason: format!(
                    "Rate limit capacity reached: {} tracked IPs",
                    self.buckets.max_tracked_ips
                ),
            }
        })
    }
}

impl WafRule for RateLimiter {
    fn name(&self) -> &str {
        &self.name
    }

    fn fast_allow_policy(&self) -> crate::waf::fast_allow::FastAllowPolicy {
        crate::waf::fast_allow::FastAllowPolicy::Gate
    }

    fn fast_allow_gate(&self, ctx: &crate::waf::fast_allow::FastAllowContext<'_>) -> Decision {
        self.check_ip(ctx.client_ip)
    }

    fn evaluate(&self, ctx: &RequestContext) -> Decision {
        self.check_ip(ctx.client_ip)
    }

    fn is_enabled(&self) -> bool {
        self.enabled
    }
}

/// Global rate limiter across all IPs
pub struct GlobalRateLimiter {
    name: String,
    bucket: Arc<RwLock<TokenBucket>>,
    enabled: bool,
    #[cfg(feature = "distri-kv")]
    distributed: Option<Arc<crate::waf::distributed::DistributedState>>,
}

impl GlobalRateLimiter {
    pub fn new(name: &str, capacity: u32, refill_rate: u32) -> Self {
        Self {
            name: name.to_string(),
            bucket: Arc::new(RwLock::new(TokenBucket::new(capacity, refill_rate))),
            enabled: true,
            #[cfg(feature = "distri-kv")]
            distributed: None,
        }
    }

    #[cfg(feature = "distri-kv")]
    pub fn with_distributed_state(
        mut self,
        state: Arc<crate::waf::distributed::DistributedState>,
    ) -> Self {
        self.distributed = Some(state);
        self
    }

    pub fn disabled(mut self) -> Self {
        self.enabled = false;
        self
    }

    #[cfg(feature = "distri-kv")]
    fn try_shared_budget(&self) -> Option<Decision> {
        let state = self.distributed.as_ref()?;
        if !state.leases_enabled() || state.shadow() {
            return None;
        }
        let key = crate::waf::distributed::LeaseKey::new(&self.name, 0, [0u8; 16]);
        match state.try_consume_lease(&key) {
            crate::waf::distributed::LeaseConsume::Consumed { .. } => Some(Decision::Allow),
            crate::waf::distributed::LeaseConsume::Unavailable
            | crate::waf::distributed::LeaseConsume::Expired => {
                state.request_lease(crate::waf::distributed::LeaseRequest {
                    policy_id: self.name.clone(),
                    window_start_unix: 0,
                    shard: 0,
                    key_hash: [0u8; 16],
                    requested: 1,
                });
                Some(Decision::RateLimit {
                    reason: "Shared global rate-limit budget unavailable or expired".to_string(),
                })
            }
            crate::waf::distributed::LeaseConsume::Exhausted => Some(Decision::RateLimit {
                reason: "Shared global rate-limit budget exhausted".to_string(),
            }),
        }
    }

    fn check_global(&self) -> Decision {
        let mut bucket = self.bucket.write().unwrap();

        if bucket.try_consume(1) {
            debug!(
                "Global rate limit check passed, {} tokens remaining",
                bucket.available_tokens()
            );
            Decision::Allow
        } else {
            #[cfg(feature = "distri-kv")]
            if let Some(shared) = self.try_shared_budget() {
                return shared;
            }
            warn!("Global rate limit exceeded");
            Decision::RateLimit {
                reason: "Global rate limit exceeded".to_string(),
            }
        }
    }
}

impl WafRule for GlobalRateLimiter {
    fn name(&self) -> &str {
        &self.name
    }

    fn fast_allow_policy(&self) -> crate::waf::fast_allow::FastAllowPolicy {
        crate::waf::fast_allow::FastAllowPolicy::Gate
    }

    fn fast_allow_gate(&self, _ctx: &crate::waf::fast_allow::FastAllowContext<'_>) -> Decision {
        self.check_global()
    }

    fn evaluate(&self, _ctx: &RequestContext) -> Decision {
        self.check_global()
    }

    fn is_enabled(&self) -> bool {
        self.enabled
    }
}

/// Adaptive rate limiter that adjusts based on threat levels
pub struct AdaptiveRateLimiter {
    name: String,
    buckets: ShardedBuckets<TokenBucket>,
    base_capacity: u32,
    base_refill_rate: u32,
    threat_multiplier: f32,
    enabled: bool,
}

impl AdaptiveRateLimiter {
    pub fn new(name: &str, base_capacity: u32, base_refill_rate: u32) -> Self {
        Self {
            name: name.to_string(),
            buckets: ShardedBuckets::new(
                DEFAULT_MAX_TRACKED_IPS,
                CapacityPolicy::FailClosed,
                Duration::from_secs(120),
            ),
            base_capacity,
            base_refill_rate,
            threat_multiplier: 1.0,
            enabled: true,
        }
    }

    pub fn with_limits(mut self, max_tracked_ips: usize, capacity_policy: CapacityPolicy) -> Self {
        self.buckets =
            ShardedBuckets::new(max_tracked_ips, capacity_policy, Duration::from_secs(120));
        self
    }

    pub fn set_threat_multiplier(&mut self, multiplier: f32) {
        self.threat_multiplier = multiplier.max(0.1).min(10.0);
    }

    pub fn disabled(mut self) -> Self {
        self.enabled = false;
        self
    }

    fn get_adjusted_limits(&self) -> (u32, u32) {
        let capacity = ((self.base_capacity as f32) / self.threat_multiplier) as u32;
        let refill_rate = ((self.base_refill_rate as f32) / self.threat_multiplier) as u32;
        (capacity.max(1), refill_rate.max(1))
    }

    fn check_ip(&self, client_ip: IpAddr) -> Decision {
        let (capacity, refill_rate) = self.get_adjusted_limits();
        let decision = self.buckets.access(
            client_ip,
            || TokenBucket::new(capacity, refill_rate),
            |bucket| {
                // Update existing bucket parameters if they've changed
                if bucket.capacity != capacity || bucket.refill_rate != refill_rate {
                    bucket.capacity = capacity;
                    bucket.refill_rate = refill_rate;
                    // Don't reduce tokens below the new capacity
                    bucket.tokens = bucket.tokens.min(capacity);
                }

                if bucket.try_consume(1) {
                    debug!(
                        "Adaptive rate limit check passed for {}, {} tokens remaining",
                        client_ip,
                        bucket.available_tokens()
                    );
                    Decision::Allow
                } else {
                    warn!(
                        "Adaptive rate limit exceeded for {} (multiplier: {})",
                        client_ip, self.threat_multiplier
                    );
                    Decision::RateLimit {
                        reason: format!(
                            "Adaptive rate limit exceeded: {} requests per second (threat level: {:.2})",
                            refill_rate, self.threat_multiplier
                        ),
                    }
                }
            },
        );

        decision.unwrap_or_else(|| {
            warn!(
                "Adaptive rate limiter at capacity ({} tracked IPs); rejecting new IP {}",
                self.buckets.max_tracked_ips, client_ip
            );
            Decision::RateLimit {
                reason: format!(
                    "Adaptive rate limit capacity reached: {} tracked IPs",
                    self.buckets.max_tracked_ips
                ),
            }
        })
    }
}

impl WafRule for AdaptiveRateLimiter {
    fn name(&self) -> &str {
        &self.name
    }

    fn fast_allow_policy(&self) -> crate::waf::fast_allow::FastAllowPolicy {
        crate::waf::fast_allow::FastAllowPolicy::Gate
    }

    fn fast_allow_gate(&self, ctx: &crate::waf::fast_allow::FastAllowContext<'_>) -> Decision {
        self.check_ip(ctx.client_ip)
    }

    fn evaluate(&self, ctx: &RequestContext) -> Decision {
        self.check_ip(ctx.client_ip)
    }

    fn is_enabled(&self) -> bool {
        self.enabled
    }
}

/// Burst rate limiter for handling traffic spikes
pub struct BurstRateLimiter {
    name: String,
    buckets: ShardedBuckets<(TokenBucket, TokenBucket)>,
    normal_capacity: u32,
    normal_refill: u32,
    burst_capacity: u32,
    burst_refill: u32,
    enabled: bool,
}

impl BurstRateLimiter {
    pub fn new(
        name: &str,
        normal_capacity: u32,
        normal_refill: u32,
        burst_capacity: u32,
        burst_refill: u32,
    ) -> Self {
        Self {
            name: name.to_string(),
            buckets: ShardedBuckets::new(
                DEFAULT_MAX_TRACKED_IPS,
                CapacityPolicy::FailClosed,
                Duration::from_secs(120),
            ),
            normal_capacity,
            normal_refill,
            burst_capacity,
            burst_refill,
            enabled: true,
        }
    }

    pub fn with_limits(mut self, max_tracked_ips: usize, capacity_policy: CapacityPolicy) -> Self {
        self.buckets =
            ShardedBuckets::new(max_tracked_ips, capacity_policy, Duration::from_secs(120));
        self
    }

    pub fn disabled(mut self) -> Self {
        self.enabled = false;
        self
    }

    fn check_ip(&self, client_ip: IpAddr) -> Decision {
        let decision = self.buckets.access(
            client_ip,
            || {
                (
                    TokenBucket::new(self.normal_capacity, self.normal_refill),
                    TokenBucket::new(self.burst_capacity, self.burst_refill),
                )
            },
            |(normal_bucket, burst_bucket)| {
                // Try normal bucket first
                if normal_bucket.try_consume(1) {
                    debug!("Normal rate limit check passed for {}", client_ip);
                    Decision::Allow
                }
                // Fall back to burst bucket
                else if burst_bucket.try_consume(1) {
                    debug!("Burst rate limit check passed for {}", client_ip);
                    Decision::Allow
                }
                // Both buckets exhausted
                else {
                    warn!("Burst rate limit exceeded for {}", client_ip);
                    Decision::RateLimit {
                        reason: "Burst rate limit exceeded".to_string(),
                    }
                }
            },
        );

        decision.unwrap_or_else(|| {
            warn!(
                "Burst rate limiter at capacity ({} tracked IPs); rejecting new IP {}",
                self.buckets.max_tracked_ips, client_ip
            );
            Decision::RateLimit {
                reason: format!(
                    "Burst rate limit capacity reached: {} tracked IPs",
                    self.buckets.max_tracked_ips
                ),
            }
        })
    }
}

impl WafRule for BurstRateLimiter {
    fn name(&self) -> &str {
        &self.name
    }

    fn fast_allow_policy(&self) -> crate::waf::fast_allow::FastAllowPolicy {
        crate::waf::fast_allow::FastAllowPolicy::Gate
    }

    fn fast_allow_gate(&self, ctx: &crate::waf::fast_allow::FastAllowContext<'_>) -> Decision {
        self.check_ip(ctx.client_ip)
    }

    fn evaluate(&self, ctx: &RequestContext) -> Decision {
        self.check_ip(ctx.client_ip)
    }

    fn is_enabled(&self) -> bool {
        self.enabled
    }
}

/// Rate limiter factory for creating common rate limiting configurations
pub struct RateLimiterFactory;

impl RateLimiterFactory {
    /// Creates a basic per-IP rate limiter (100 req/min)
    pub fn create_basic_rate_limiter() -> RateLimiter {
        RateLimiter::new(
            "basic_rate_limit",
            100, // capacity
            2,   // ~100 requests per minute
            Duration::from_secs(60),
        )
    }

    /// Creates a strict per-IP rate limiter (20 req/min)
    pub fn create_strict_rate_limiter() -> RateLimiter {
        RateLimiter::new(
            "strict_rate_limit",
            20, // capacity
            1,  // ~20 requests per minute
            Duration::from_secs(60),
        )
    }

    /// Creates a global rate limiter (1000 req/sec)
    pub fn create_global_rate_limiter() -> GlobalRateLimiter {
        GlobalRateLimiter::new(
            "global_rate_limit",
            1000, // capacity
            1000, // refill rate
        )
    }

    /// Creates an adaptive rate limiter
    pub fn create_adaptive_rate_limiter() -> AdaptiveRateLimiter {
        AdaptiveRateLimiter::new(
            "adaptive_rate_limit",
            50, // base capacity
            1,  // base refill rate
        )
    }

    /// Creates a burst rate limiter
    pub fn create_burst_rate_limiter() -> BurstRateLimiter {
        BurstRateLimiter::new(
            "burst_rate_limit",
            10, // normal capacity
            1,  // normal refill
            50, // burst capacity
            1,  // burst refill
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::{Method, Uri};
    use std::str::FromStr;
    use std::sync::atomic::AtomicUsize;
    use std::sync::Arc;
    use std::thread;

    fn create_test_context(ip: &str) -> RequestContext {
        RequestContext::new(
            IpAddr::from_str(ip).unwrap(),
            Method::GET,
            Uri::from_str("/test").unwrap(),
            hyper::HeaderMap::new(),
            None,
        )
    }

    fn ip(value: u32) -> IpAddr {
        IpAddr::from(std::net::Ipv4Addr::from(value))
    }

    #[test]
    fn test_token_bucket() {
        let mut bucket = TokenBucket::new(10, 5);

        // Should be able to consume initial capacity
        assert!(bucket.try_consume(10));
        assert_eq!(bucket.available_tokens(), 0);

        // Should not be able to consume more
        assert!(!bucket.try_consume(1));
    }

    #[test]
    fn test_rate_limiter() {
        let limiter = RateLimiter::new("test", 2, 1, Duration::from_secs(1));
        let ctx = create_test_context("192.168.1.1");

        // First two requests should pass
        assert_eq!(limiter.evaluate(&ctx), Decision::Allow);
        assert_eq!(limiter.evaluate(&ctx), Decision::Allow);

        // Third request should be rate limited
        match limiter.evaluate(&ctx) {
            Decision::RateLimit { .. } => {}
            _ => panic!("Expected RateLimit decision"),
        }
    }

    #[test]
    fn test_global_rate_limiter() {
        let limiter = GlobalRateLimiter::new("test", 1, 1);
        let ctx1 = create_test_context("192.168.1.1");
        let ctx2 = create_test_context("192.168.1.2");

        // First request should pass
        assert_eq!(limiter.evaluate(&ctx1), Decision::Allow);

        // Second request from different IP should be rate limited
        match limiter.evaluate(&ctx2) {
            Decision::RateLimit { .. } => {}
            _ => panic!("Expected RateLimit decision"),
        }
    }

    #[test]
    fn test_adaptive_rate_limiter() {
        let mut limiter = AdaptiveRateLimiter::new("test", 4, 1);
        let ctx = create_test_context("192.168.1.1");

        // With normal threat level, should allow 4 requests
        for _ in 0..4 {
            assert_eq!(limiter.evaluate(&ctx), Decision::Allow);
        }

        // Fifth should be limited
        match limiter.evaluate(&ctx) {
            Decision::RateLimit { .. } => {}
            _ => panic!("Expected RateLimit decision"),
        }

        // Increase threat level and test with same limiter
        limiter.set_threat_multiplier(2.0);
        let mut limiter2 = AdaptiveRateLimiter::new("test2", 4, 1);
        limiter2.set_threat_multiplier(2.0); // Apply threat multiplier to new instance
        let ctx2 = create_test_context("192.168.1.3");

        // Should now allow only 2 requests (4/2)
        assert_eq!(limiter2.evaluate(&ctx2), Decision::Allow);
        assert_eq!(limiter2.evaluate(&ctx2), Decision::Allow);

        match limiter2.evaluate(&ctx2) {
            Decision::RateLimit { .. } => {}
            _ => panic!("Expected RateLimit decision"),
        }
    }

    #[test]
    fn shard_index_is_stable_and_spreads_addresses() {
        let a = ShardedBuckets::<()>::shard_index(ip(0x0a00_0001));
        let b = ShardedBuckets::<()>::shard_index(ip(0x0a00_0001));
        assert_eq!(a, b);
        assert!(a < SHARD_COUNT);

        let mut seen = std::collections::HashSet::new();
        for value in 0..1024 {
            seen.insert(ShardedBuckets::<()>::shard_index(ip(value)));
        }
        assert!(seen.len() > SHARD_COUNT / 2, "hash is poorly distributed");
    }

    #[test]
    fn shards_are_independent_and_keep_per_ip_semantics() {
        let limiter = RateLimiter::new("test", 2, 1, Duration::from_secs(60));
        let first = create_test_context("10.0.0.1");
        let second = create_test_context("10.0.0.2");

        assert_eq!(limiter.evaluate(&first), Decision::Allow);
        assert_eq!(limiter.evaluate(&first), Decision::Allow);
        assert!(matches!(
            limiter.evaluate(&first),
            Decision::RateLimit { .. }
        ));

        // A different client has its own bucket even if it shares a shard.
        assert_eq!(limiter.evaluate(&second), Decision::Allow);
        assert_eq!(limiter.buckets.len(), 2);
    }

    #[test]
    fn capacity_fails_closed_for_new_ips() {
        let limiter = RateLimiter::new("test", 10, 1, Duration::from_secs(60))
            .with_limits(2, CapacityPolicy::FailClosed);

        assert_eq!(
            limiter.evaluate(&create_test_context("10.0.0.1")),
            Decision::Allow
        );
        assert_eq!(
            limiter.evaluate(&create_test_context("10.0.0.2")),
            Decision::Allow
        );

        // Existing IPs keep working.
        assert_eq!(
            limiter.evaluate(&create_test_context("10.0.0.1")),
            Decision::Allow
        );

        // A new IP is rejected rather than silently allowed.
        match limiter.evaluate(&create_test_context("10.0.0.3")) {
            Decision::RateLimit { reason } => assert!(reason.contains("capacity")),
            other => panic!("expected capacity rejection, got {other:?}"),
        }
        assert_eq!(limiter.buckets.len(), 2);
    }

    #[test]
    fn capacity_evicts_oldest_when_configured() {
        let limiter = RateLimiter::new("test", 10, 1, Duration::from_secs(60))
            .with_limits(2, CapacityPolicy::EvictOldest);

        assert_eq!(
            limiter.evaluate(&create_test_context("10.0.0.1")),
            Decision::Allow
        );
        assert_eq!(
            limiter.evaluate(&create_test_context("10.0.0.2")),
            Decision::Allow
        );
        assert_eq!(
            limiter.evaluate(&create_test_context("10.0.0.3")),
            Decision::Allow
        );

        assert_eq!(limiter.buckets.len(), 2);
        // The oldest entry was evicted, so it gets a fresh bucket.
        assert_eq!(
            limiter.evaluate(&create_test_context("10.0.0.1")),
            Decision::Allow
        );
    }

    #[test]
    fn cleanup_is_incremental_and_reclaims_expired_entries() {
        let limiter = RateLimiter::new("test", 10, 1, Duration::from_millis(1))
            .with_limits(100, CapacityPolicy::FailClosed);

        for value in 0..10 {
            assert_eq!(
                limiter.evaluate(&create_test_context(&format!("10.0.0.{value}"))),
                Decision::Allow
            );
        }
        assert_eq!(limiter.buckets.len(), 10);

        std::thread::sleep(Duration::from_millis(10));

        // Drive enough evaluations to sweep every shard at least once.
        for _ in 0..(SHARD_COUNT * 100) {
            let _ = limiter.evaluate(&create_test_context("10.0.0.1"));
        }
        assert_eq!(limiter.buckets.len(), 1);
    }

    #[test]
    fn concurrent_access_never_exceeds_capacity() {
        let limiter = Arc::new(
            RateLimiter::new("test", 100, 1, Duration::from_secs(60))
                .with_limits(64, CapacityPolicy::FailClosed),
        );
        let allowed = Arc::new(AtomicUsize::new(0));
        let rejected = Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::new();
        for thread_id in 0..8u32 {
            let limiter = Arc::clone(&limiter);
            let allowed = Arc::clone(&allowed);
            let rejected = Arc::clone(&rejected);
            handles.push(thread::spawn(move || {
                for offset in 0..100u32 {
                    let address = thread_id * 1000 + offset;
                    match limiter.evaluate(&create_test_context(&format!(
                        "10.1.{}.{}",
                        address / 256,
                        address % 256
                    ))) {
                        Decision::Allow => {
                            allowed.fetch_add(1, Ordering::Relaxed);
                        }
                        Decision::RateLimit { .. } => {
                            rejected.fetch_add(1, Ordering::Relaxed);
                        }
                        _ => panic!("unexpected decision"),
                    }
                }
            }));
        }
        for handle in handles {
            handle.join().unwrap();
        }

        assert_eq!(limiter.buckets.len(), 64);
        assert_eq!(allowed.load(Ordering::Relaxed), 64);
        assert_eq!(rejected.load(Ordering::Relaxed), 8 * 100 - 64);
    }

    #[test]
    fn request_path_is_synchronous_and_holds_no_await() {
        // The limiter API is deliberately synchronous: locks are acquired and
        // released inside `check_ip`, so no guard can be held across an await.
        fn assert_sync<F: Fn(&RateLimiter, IpAddr) -> Decision>(_f: F) {}
        assert_sync(|limiter, address| limiter.check_ip(address));
    }
}
