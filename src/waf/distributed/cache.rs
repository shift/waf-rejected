//! TTL + generation policy/reputation cache.
//!
//! Reads are lock-then-clone, never network I/O. A higher policy generation
//! invalidates every prior entry atomically; an entry older than the TTL is
//! reported as `Stale` until `max_stale` expires, after which it is a miss.
//! Explicitly blocked entries are reported as `Blocked` so the caller can make
//! the fail-closed decision without pretending it is fresh data.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::{Duration, Instant};

use super::metrics::DistributedMetrics;

/// Freshness state of a cache read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheState {
    /// Within the TTL.
    Fresh,
    /// Past the TTL but within `max_stale`; usable only with an explicit
    /// fallback mode.
    Stale,
    /// An explicit block/quarantine entry.
    Blocked,
}

/// Result of a cache lookup.
#[derive(Debug, Clone, PartialEq)]
pub enum CacheLookup<T> {
    Hit { value: T, state: CacheState },
    Miss,
}

#[derive(Debug, Clone)]
struct Entry<T> {
    value: T,
    generation: u64,
    inserted: Instant,
    blocked: bool,
}

/// Bounded-by-policy TTL cache keyed by `K`.
#[derive(Debug)]
pub struct VersionedCache<K, T> {
    entries: RwLock<HashMap<K, Entry<T>>>,
    generation: AtomicU64,
    ttl: Duration,
    max_stale: Duration,
    max_entries: usize,
    metrics: DistributedMetrics,
}

impl<K, T> VersionedCache<K, T>
where
    K: Eq + Hash + Clone,
    T: Clone,
{
    pub fn new(ttl: Duration, max_stale: Duration, max_entries: usize) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            generation: AtomicU64::new(0),
            ttl,
            max_stale,
            max_entries: max_entries.max(1),
            metrics: DistributedMetrics::default(),
        }
    }

    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    pub fn len(&self) -> usize {
        self.entries.read().expect("cache lock poisoned").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn metrics(&self) -> &DistributedMetrics {
        &self.metrics
    }

    /// Insert at the current generation.
    pub fn insert(&self, key: K, value: T) {
        self.insert_with_generation(key, value, self.generation());
    }

    pub fn insert_with_generation(&self, key: K, value: T, generation: u64) {
        self.insert_at(key, value, generation, Instant::now(), false);
    }

    /// Mark an entry as an explicit block/quarantine. Reads report `Blocked`
    /// until it expires or the generation changes.
    pub fn block(&self, key: K, value: T) {
        let generation = self.generation();
        self.insert_at(key, value, generation, Instant::now(), true);
    }

    pub fn insert_at(&self, key: K, value: T, generation: u64, now: Instant, blocked: bool) {
        let mut entries = self.entries.write().expect("cache lock poisoned");
        if entries.len() >= self.max_entries && !entries.contains_key(&key) {
            // Evict the oldest entry. This is a cold path: the request path
            // never inserts.
            if let Some(oldest) = entries
                .iter()
                .min_by_key(|(_, entry)| entry.inserted)
                .map(|(key, _)| key.clone())
            {
                entries.remove(&oldest);
            }
        }
        entries.insert(
            key,
            Entry {
                value,
                generation,
                inserted: now,
                blocked,
            },
        );
    }

    /// Look up an entry relative to the current generation and `Instant::now`.
    pub fn get(&self, key: &K) -> CacheLookup<T> {
        self.get_at(key, Instant::now())
    }

    /// Deterministic-time lookup used by tests.
    pub fn get_at(&self, key: &K, now: Instant) -> CacheLookup<T> {
        let generation = self.generation();
        let mut entries = self.entries.write().expect("cache lock poisoned");
        let Some(entry) = entries.get(key) else {
            drop(entries);
            self.metrics.record_cache_miss();
            return CacheLookup::Miss;
        };
        if entry.generation != generation {
            entries.remove(key);
            drop(entries);
            self.metrics.record_cache_miss();
            return CacheLookup::Miss;
        }
        let age = now.saturating_duration_since(entry.inserted);
        if age > self.ttl.saturating_add(self.max_stale) {
            entries.remove(key);
            drop(entries);
            self.metrics.record_cache_miss();
            return CacheLookup::Miss;
        }
        let value = entry.value.clone();
        let state = if entry.blocked {
            self.metrics.record_cache_blocked();
            CacheState::Blocked
        } else if age > self.ttl {
            self.metrics.record_cache_stale();
            CacheState::Stale
        } else {
            self.metrics.record_cache_hit();
            CacheState::Fresh
        };
        CacheLookup::Hit { value, state }
    }

    /// Invalidate all entries from older generations. Returns `true` when the
    /// cache was actually cleared.
    pub fn set_generation(&self, generation: u64) -> bool {
        let previous = self.generation.swap(generation, Ordering::AcqRel);
        if previous == generation {
            return false;
        }
        self.entries.write().expect("cache lock poisoned").clear();
        self.metrics.record_cache_invalidation();
        true
    }

    pub fn clear(&self) {
        self.entries.write().expect("cache lock poisoned").clear();
        self.metrics.record_cache_invalidation();
    }
}
