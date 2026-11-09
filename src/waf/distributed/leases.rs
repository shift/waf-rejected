//! Rate-limit leases shared across WAF nodes.
//!
//! The local token bucket stays the first tier and is never blocked. When it
//! is exhausted the request path may spend one unit of a previously granted
//! lease for that key. Lease acquisition is asynchronous: the request path
//! only performs a non-blocking push into a bounded request queue and fails
//! closed for the *shared* budget when no valid lease exists.
//!
//! An expired lease is removed lazily on read. Expiry therefore never extends
//! the shared budget and never changes local-only behaviour.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Identity of a shared counter/lease. `key_hash` is all-zero for the global
/// limiter's aggregate budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LeaseKey {
    pub policy_id_hash: u64,
    pub shard: u32,
    pub key_hash: [u8; 16],
}

impl LeaseKey {
    pub fn new(policy_id: &str, shard: u32, key_hash: [u8; 16]) -> Self {
        let mut hasher = sha2::Sha256::new();
        use sha2::Digest as _;
        hasher.update(policy_id.as_bytes());
        let digest = hasher.finalize();
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&digest[..8]);
        Self {
            policy_id_hash: u64::from_le_bytes(bytes),
            shard,
            key_hash,
        }
    }
}

/// A non-blocking request for shared budget.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseRequest {
    pub policy_id: String,
    pub window_start_unix: u64,
    pub shard: u32,
    pub key_hash: [u8; 16],
    pub requested: u64,
}

impl LeaseRequest {
    /// Canonical distri-kv `bucket_key`. The server contract identifies a
    /// shared bucket by an opaque string, so the WAF's
    /// `(policy_id, shard, key_hash)` tuple is length-prefixed and hashed to
    /// avoid delimiter collisions between policies.
    pub fn bucket_key(&self) -> String {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update((self.policy_id.len() as u64).to_le_bytes());
        hasher.update(self.policy_id.as_bytes());
        hasher.update(self.shard.to_le_bytes());
        hasher.update(self.key_hash);
        let digest = hasher.finalize();
        let mut key = String::with_capacity(4 + digest.len() * 2);
        key.push_str("v1-");
        for byte in digest {
            use std::fmt::Write as _;
            let _ = write!(key, "{byte:02x}");
        }
        key
    }
}

/// A granted lease. `granted` is the number of units leased to this node and
/// `remaining` is the local spendable balance for this grant. distri-kv's
/// `AcquireLeaseResponse.remaining_tokens` is the bucket's *unleased* balance,
/// so it is deliberately not used as this node's spendable budget.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseGrant {
    pub lease_id: String,
    pub key: LeaseKey,
    pub granted: u64,
    pub remaining: u64,
    pub expires_in: Duration,
    pub denied: bool,
}

/// Result of spending from the local lease cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseConsume {
    /// One unit was spent.
    Consumed { remaining: u64 },
    /// A lease existed but had no budget left.
    Exhausted,
    /// A lease existed but expired (it has been removed).
    Expired,
    /// No lease is cached; the caller may enqueue a request and fails closed
    /// for the shared budget.
    Unavailable,
}

/// Bounded, non-blocking queue of lease requests drained by the controller.
#[derive(Debug)]
pub struct LeaseRequests {
    capacity: usize,
    requests: Mutex<Vec<LeaseRequest>>,
    dropped: AtomicU64,
    enqueued: AtomicU64,
}

impl LeaseRequests {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            requests: Mutex::new(Vec::new()),
            dropped: AtomicU64::new(0),
            enqueued: AtomicU64::new(0),
        }
    }

    pub fn len(&self) -> usize {
        self.requests.lock().expect("lease request lock").len()
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

    /// Returns `true` when the request was accepted, `false` when the bounded
    /// queue was full (the oldest request is evicted).
    pub fn try_push(&self, request: LeaseRequest) -> bool {
        let mut queue = self.requests.lock().expect("lease request lock");
        let accepted = if queue.len() >= self.capacity {
            queue.remove(0);
            self.dropped.fetch_add(1, Ordering::Relaxed);
            false
        } else {
            true
        };
        queue.push(request);
        self.enqueued.fetch_add(1, Ordering::Relaxed);
        accepted
    }

    pub fn drain_batch(&self, max: usize) -> Vec<LeaseRequest> {
        let mut queue = self.requests.lock().expect("lease request lock");
        let count = queue.len().min(max);
        queue.drain(..count).collect()
    }
}

#[derive(Debug)]
struct LeaseEntry {
    lease_id: String,
    remaining: u64,
    expires_at: Instant,
}

/// Local cache of granted leases plus the lease counters used by metrics.
#[derive(Debug)]
pub struct LeasePool {
    entries: Mutex<HashMap<LeaseKey, LeaseEntry>>,
    granted: AtomicU64,
    expired: AtomicU64,
    denied: AtomicU64,
    consumed: AtomicU64,
    fallbacks: AtomicU64,
}

impl Default for LeasePool {
    fn default() -> Self {
        Self::new()
    }
}

impl LeasePool {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            granted: AtomicU64::new(0),
            expired: AtomicU64::new(0),
            denied: AtomicU64::new(0),
            consumed: AtomicU64::new(0),
            fallbacks: AtomicU64::new(0),
        }
    }

    /// Apply a grant received by the controller. A later grant for the same
    /// key replaces the old lease, matching the server's authoritative
    /// accounting.
    pub fn apply(&self, grant: LeaseGrant, now: Instant) {
        if grant.denied {
            self.denied.fetch_add(1, Ordering::Relaxed);
            self.entries.lock().expect("lease lock").remove(&grant.key);
            return;
        }
        let remaining = grant.remaining.max(grant.granted);
        if remaining == 0 {
            self.denied.fetch_add(1, Ordering::Relaxed);
            return;
        }
        self.granted.fetch_add(remaining, Ordering::Relaxed);
        self.entries.lock().expect("lease lock").insert(
            grant.key,
            LeaseEntry {
                lease_id: grant.lease_id,
                remaining,
                expires_at: now + grant.expires_in,
            },
        );
    }

    /// Spend one unit. Never waits on I/O and never extends an expired lease.
    pub fn try_consume(&self, key: &LeaseKey) -> LeaseConsume {
        let now = Instant::now();
        let mut entries = self.entries.lock().expect("lease lock");
        let Some(entry) = entries.get_mut(key) else {
            self.fallbacks.fetch_add(1, Ordering::Relaxed);
            return LeaseConsume::Unavailable;
        };
        if now >= entry.expires_at {
            entries.remove(key);
            self.expired.fetch_add(1, Ordering::Relaxed);
            self.fallbacks.fetch_add(1, Ordering::Relaxed);
            return LeaseConsume::Expired;
        }
        if entry.remaining == 0 {
            self.denied.fetch_add(1, Ordering::Relaxed);
            return LeaseConsume::Exhausted;
        }
        entry.remaining -= 1;
        self.consumed.fetch_add(1, Ordering::Relaxed);
        LeaseConsume::Consumed {
            remaining: entry.remaining,
        }
    }

    /// Remove and count expired entries. Returns the number removed.
    pub fn sweep(&self) -> usize {
        let now = Instant::now();
        let mut entries = self.entries.lock().expect("lease lock");
        let before = entries.len();
        entries.retain(|_, entry| entry.expires_at > now);
        let removed = before - entries.len();
        self.expired.fetch_add(removed as u64, Ordering::Relaxed);
        removed
    }

    pub fn active(&self) -> usize {
        self.entries.lock().expect("lease lock").len()
    }

    pub fn granted(&self) -> u64 {
        self.granted.load(Ordering::Relaxed)
    }

    pub fn expired(&self) -> u64 {
        self.expired.load(Ordering::Relaxed)
    }

    pub fn denied(&self) -> u64 {
        self.denied.load(Ordering::Relaxed)
    }

    pub fn consumed(&self) -> u64 {
        self.consumed.load(Ordering::Relaxed)
    }

    pub fn fallbacks(&self) -> u64 {
        self.fallbacks.load(Ordering::Relaxed)
    }
}
