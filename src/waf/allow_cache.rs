//! Experimental content-addressed allow-verdict cache.
//!
//! This module is compiled only with the non-default `allow-cache` feature and
//! is disabled unless `waf.allow_cache.enabled = true`. It memoises the
//! verdict of the *pure content rules* (the Coraza backend and the built-in
//! content inspector) for requests that produced an `Allow`. Blocks and rate
//! limits are never cached, and every stateful or IP-dependent rule is still
//! evaluated on a hit.
//!
//! # Two-level lookup
//!
//! A hit never relies on a cheap fingerprint alone. The lookup is:
//!
//! 1. **Fingerprint** — a keyed 128-bit digest of the canonical *metadata*
//!    (version, policy generation, method, URI components, HTTP version, body
//!    presence/length, declared size, sorted header digests). It never hashes
//!    the body, so a fingerprint miss costs no body work.
//! 2. **Candidate bucket** — the fingerprint indexes a bucket of candidates in
//!    the sharded map. Each candidate stores a 128-bit keyed digest of the
//!    exact body bytes.
//! 3. **Body verification** — the body digest is computed only when a bucket
//!    exists, and the request is allowed only if a live candidate's digest
//!    matches. A fingerprint collision on its own can never produce an
//!    `Allow`.
//!
//! The design, canonicalisation rules, injectivity argument, threat model and
//! measurements live in `docs/suggestions_from_agents/allow-cache.md`.

use std::cell::RefCell;
use std::collections::HashMap;
use std::hash::{BuildHasher, Hasher};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use hyper::Uri;
use parking_lot::RwLock;
use xxhash_rust::xxh3::{xxh3_128_with_secret, xxh3_64_with_seed};

use super::RequestContext;
use crate::config::{AllowCacheConfig, WafConfig};
use crate::metrics::Metrics;

/// Bump when the canonical encoding changes. Old entries become unreachable
/// because the version is part of every fingerprint.
///
/// v2: URI hashed by component (no `Uri::to_string` allocation), headers hashed
/// as sorted `(name-digest, values)` pairs, and the body moved out of the
/// fingerprint into a separately verified digest.
pub const KEY_VERSION: u8 = 2;

/// Domain separator for the policy-generation hash.
const POLICY_DOMAIN: u8 = 0xA1;
/// Domain separator for the request fingerprint.
const FINGERPRINT_DOMAIN: u8 = 0xB2;

/// Shard count for the bounded map. Fixed so the memory bound is predictable
/// and so a 64-thread replay does not converge on a handful of locks.
pub const SHARDS: usize = 64;

/// Defensive cap on the number of header values in a key. Hyper's default
/// header limit is far lower; this only prevents pathological input from making
/// key construction unbounded.
pub const MAX_HEADER_ENTRIES: usize = 256;

/// Maximum candidates stored under one fingerprint. Two requests with the same
/// metadata but different bodies share a fingerprint; a handful of variants is
/// normal, unbounded growth is not.
const MAX_BUCKET: usize = 8;

/// Thread-local L1: direct-mapped slots per thread. Only a fast path; the
/// shared sharded map remains authoritative.
const L1_SETS: usize = 256;

/// Size of the xxh3 custom secret. `SECRET_SIZE_MIN` is 136; anything shorter
/// makes xxh3 fall back to the default (unkeyed) secret.
const SECRET_BYTES: usize = 136;

/// Headers that OWASP CRS 4.14 request rules explicitly target.
///
/// This list documents the headers an operator should expect to influence a
/// cached verdict. It is deliberately **not** used as a filter: generic
/// `REQUEST_HEADERS` rules and the built-in content inspector evaluate every
/// header value, so the key hashes the complete header set. Filtering to this
/// list would break the injectivity argument in the module documentation.
pub const CRS_TARGETED_HEADERS: &[&str] = &[
    "accept",
    "accept-charset",
    "accept-encoding",
    "accept-language",
    "authorization",
    "connection",
    "content-encoding",
    "content-length",
    "content-type",
    "cookie",
    "expect",
    "host",
    "origin",
    "proxy-authorization",
    "range",
    "referer",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "user-agent",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-real-ip",
    "x-requested-with",
];

/// Process-lifetime keyed-hash secret.
///
/// The secret never leaves the process and is not persisted. Two processes
/// therefore produce different keys for the same request, which is why the
/// cache must not be shared across processes without a key-management design.
#[derive(Clone)]
pub struct Key {
    secret: [u8; SECRET_BYTES],
    /// Seed for the internal hash map. Not a security boundary: the map keys
    /// are already secret-keyed 128-bit digests, so a map collision only costs
    /// one extra comparison.
    map_seed: u64,
    /// Unique per cache instance, used to reject stale thread-local L1 slots
    /// from a previous engine in the same process.
    id: u64,
}

impl Key {
    /// Draw a fresh secret from the OS-seeded process CSPRNG.
    pub fn random() -> Self {
        use rand::RngCore as _;

        static NEXT_ID: AtomicU64 = AtomicU64::new(1);
        let mut secret = [0u8; SECRET_BYTES];
        rand::thread_rng().fill_bytes(&mut secret);
        Self {
            secret,
            map_seed: rand::random(),
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
        }
    }
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Key(<redacted>)")
    }
}

/// A 128-bit keyed digest of the canonical request metadata (no body bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Fingerprint(u128);

/// A 128-bit keyed digest of the exact body bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BodyDigest(u128);

/// Result of attempting to fingerprint a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyBuild {
    /// The request can be looked up under this fingerprint.
    Fingerprint(Fingerprint),
    /// The request is evaluated normally but never inserted or looked up.
    NotCacheable(NotCacheable),
}

/// Why a request was not keyed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotCacheable {
    /// The body is larger than `waf.allow_cache.max_body_bytes`.
    BodyTooLarge,
    /// A declared body exists but was not captured, so it cannot be hashed.
    BodyNotCaptured,
    /// The request carries more distinct header names than the defensive cap.
    TooManyHeaders,
}

impl NotCacheable {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BodyTooLarge => "body-too-large",
            Self::BodyNotCaptured => "body-not-captured",
            Self::TooManyHeaders => "too-many-headers",
        }
    }
}

/// Point-in-time cache counters, used by tests and the replay benchmark.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
    pub expired: u64,
    pub skipped: u64,
    pub entries: usize,
    pub generation: u64,
}

#[derive(Clone, Copy)]
struct Candidate {
    digest: BodyDigest,
    /// Monotonic nanoseconds since `AllowCache::epoch`.
    deadline_ns: u64,
    generation: u64,
}

struct Shard {
    entries: HashMap<Fingerprint, Vec<Candidate>, FingerprintHasherBuilder>,
    /// Total candidates in this shard (a fingerprint may hold several).
    live: usize,
}

/// Bounded, sharded, TTL-limited allow-verdict cache.
pub struct AllowCache {
    shards: Box<[RwLock<Shard>]>,
    capacities: Vec<usize>,
    ttl_ns: u64,
    epoch: Instant,
    max_body_bytes: usize,
    routes: Vec<String>,
    key: Key,
    generation: AtomicU64,
    metrics: Option<Arc<Metrics>>,
    entries: AtomicUsize,
    hits: AtomicU64,
    misses: AtomicU64,
    evictions: AtomicU64,
    expired: AtomicU64,
    skipped: AtomicU64,
}

impl AllowCache {
    pub fn new(
        config: &AllowCacheConfig,
        generation: u64,
        key: Key,
        metrics: Option<Arc<Metrics>>,
    ) -> Self {
        let max_entries = config.max_entries.max(1);
        let shard_count = SHARDS.min(max_entries);
        let base = max_entries / shard_count;
        let remainder = max_entries % shard_count;
        let capacities: Vec<usize> = (0..shard_count)
            .map(|index| base + usize::from(index < remainder))
            .collect();
        let hasher = FingerprintHasherBuilder { seed: key.map_seed };
        let shards: Box<[RwLock<Shard>]> = capacities
            .iter()
            .map(|_| {
                RwLock::new(Shard {
                    entries: HashMap::with_hasher(hasher),
                    live: 0,
                })
            })
            .collect();

        let cache = Self {
            shards,
            capacities,
            ttl_ns: config.ttl_secs.saturating_mul(1_000_000_000),
            epoch: Instant::now(),
            max_body_bytes: config.max_body_bytes,
            routes: config.routes.clone(),
            key,
            generation: AtomicU64::new(generation),
            metrics,
            entries: AtomicUsize::new(0),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            evictions: AtomicU64::new(0),
            expired: AtomicU64::new(0),
            skipped: AtomicU64::new(0),
        };
        cache.publish_entries();
        cache
    }

    /// True when the configured route opt-in covers this URI.
    ///
    /// An empty route list means "all routes" when the cache is enabled.
    /// Prefixes match on a `/` boundary: `/api` matches `/api` and `/api/x`,
    /// never `/apix`.
    pub fn applies_to(&self, uri: &Uri) -> bool {
        if self.routes.is_empty() {
            return true;
        }
        let path = uri.path();
        self.routes.iter().any(|route| {
            path == route
                || path
                    .strip_prefix(route)
                    .is_some_and(|rest| rest.starts_with('/'))
        })
    }

    /// Build the canonical fingerprint for a request.
    ///
    /// The encoding is injective: a version byte, domain separator, the policy
    /// generation, and then fixed-width or length-prefixed fields in a fixed
    /// order. Header names are sorted by a keyed digest of their lowercase form
    /// (hyper already normalises `HeaderName`), while duplicate values keep
    /// their original order and count. No percent-decoding, query reordering,
    /// case folding or whitespace normalisation is applied.
    ///
    /// Nothing is allocated: the encoding is written into per-thread scratch
    /// buffers that are reused across calls, then hashed in one pass.
    pub fn fingerprint(&self, ctx: &RequestContext) -> KeyBuild {
        let body = ctx.body.as_deref();
        if body.is_some_and(|body| body.len() > self.max_body_bytes) {
            return KeyBuild::NotCacheable(NotCacheable::BodyTooLarge);
        }
        if body.is_none() && ctx.body_size.unwrap_or(0) > 0 {
            return KeyBuild::NotCacheable(NotCacheable::BodyNotCaptured);
        }

        let generation = self.generation.load(Ordering::Acquire);
        let secret = &self.key.secret;

        SCRATCH.with(|cell| {
            let mut scratch = cell.borrow_mut();
            let scratch = &mut *scratch;
            scratch.values.clear();
            scratch.index.clear();

            // One pass over the map: `get_all` would hash the name with the
            // map's own hasher for every header, which costs more than the
            // whole fingerprint. Each (name, value) pair is copied verbatim
            // into the scratch buffer; the pair's only computed field is a
            // 64-bit sort key so the sort compares `u64`, not strings.
            let mut order = 0u32;
            for (name, value) in ctx.headers.iter() {
                order += 1;
                if order as usize > MAX_HEADER_ENTRIES {
                    return KeyBuild::NotCacheable(NotCacheable::TooManyHeaders);
                }
                let name_bytes = name.as_str().as_bytes();
                let value_bytes = value.as_bytes();
                let start = scratch.values.len();
                scratch.values.extend_from_slice(
                    &((name_bytes.len() as u64) | ((value_bytes.len() as u64) << 32)).to_le_bytes(),
                );
                scratch.values.extend_from_slice(name_bytes);
                scratch.values.extend_from_slice(value_bytes);
                scratch.index.push(HeaderRef {
                    sort_key: name_sort_key(name_bytes),
                    start: start as u32,
                    len: (scratch.values.len() - start) as u32,
                    order,
                });
            }

            // Sort by name so header order is not part of the key. Ties are
            // broken by iteration order, which is insertion order for
            // duplicate values, so `X: a, X: b` and `X: b, X: a` still differ.
            scratch.index.sort_unstable_by(|left, right| {
                left.sort_key
                    .cmp(&right.sort_key)
                    .then(left.order.cmp(&right.order))
            });

            let buffer = &mut scratch.fingerprint;
            buffer.clear();
            buffer.push(KEY_VERSION);
            buffer.push(FINGERPRINT_DOMAIN);
            put_u64(buffer, generation);
            put_bytes(buffer, ctx.method.as_str().as_bytes());
            put_uri(buffer, &ctx.uri);
            put_bytes(buffer, ctx.http_version.as_bytes());
            match body {
                Some(body) => {
                    buffer.push(1);
                    put_u64(buffer, body.len() as u64);
                }
                None => buffer.push(0),
            }
            match ctx.body_size {
                Some(size) => {
                    buffer.push(1);
                    put_u64(buffer, size as u64);
                }
                None => buffer.push(0),
            }
            put_u64(buffer, scratch.index.len() as u64);
            for entry in &scratch.index {
                let start = entry.start as usize;
                let end = start + entry.len as usize;
                buffer.extend_from_slice(&scratch.values[start..end]);
            }

            KeyBuild::Fingerprint(Fingerprint(xxh3_128_with_secret(buffer, secret)))
        })
    }

    /// Look up a fingerprint and verify the body digest.
    ///
    /// The body digest is computed only if the fingerprint is present in the
    /// thread-local L1 or in a shared shard bucket. A fingerprint match without
    /// a body-digest match is a miss: the fingerprint alone never authorises an
    /// `Allow`.
    pub fn lookup(&self, fingerprint: Fingerprint, body: &[u8]) -> bool {
        if self.lookup_inner(fingerprint, body) {
            self.record_hit();
            true
        } else {
            self.record_miss();
            false
        }
    }

    /// Early probe used before the stateless protocol pre-checks.
    ///
    /// Records a hit on success but leaves a miss uncounted: the authoritative
    /// [`Self::lookup`] in the rule chain runs next and counts it exactly once.
    pub fn probe(&self, fingerprint: Fingerprint, body: &[u8]) -> bool {
        if self.lookup_inner(fingerprint, body) {
            self.record_hit();
            true
        } else {
            false
        }
    }

    fn lookup_inner(&self, fingerprint: Fingerprint, body: &[u8]) -> bool {
        let now = self.now_ns();
        let generation = self.generation.load(Ordering::Acquire);

        match self.l1_probe(fingerprint, body, generation, now) {
            L1Probe::Hit => return true,
            L1Probe::Checked(digest) => {
                return self.shared_lookup(fingerprint, digest, generation, now);
            }
            L1Probe::Absent => {}
        }

        self.shared_lookup_lazy(fingerprint, body, generation, now)
    }

    /// Insert an allow verdict. The caller must only call this for `Allow`.
    pub fn insert(&self, fingerprint: Fingerprint, body: &[u8]) {
        let now = self.now_ns();
        let generation = self.generation.load(Ordering::Acquire);
        let digest = body_digest(&self.key.secret, body);
        let deadline_ns = now.saturating_add(self.ttl_ns);
        let index = self.shard_index(fingerprint);
        let capacity = self.capacities[index];

        {
            let mut shard = self.shards[index].write();
            let mut live = shard.live;
            let mut evicted = 0u64;
            let mut dropped_expired = 0u64;
            let mut added = 0u64;

            if let Some(bucket) = shard.entries.get_mut(&fingerprint) {
                let before = bucket.len();
                bucket.retain(|candidate| {
                    candidate.generation == generation && now < candidate.deadline_ns
                });
                live -= before - bucket.len();
                dropped_expired += (before - bucket.len()) as u64;
                if bucket.len() >= MAX_BUCKET {
                    // Drop the candidate closest to expiry.
                    if let Some((victim, _)) = bucket
                        .iter()
                        .enumerate()
                        .min_by_key(|(_, candidate)| candidate.deadline_ns)
                    {
                        bucket.swap_remove(victim);
                        live -= 1;
                        evicted += 1;
                    }
                }
            }

            if shard.entries.get(&fingerprint).is_none() && live >= capacity {
                if let Some(victim) = shard.entries.keys().next().copied() {
                    if let Some(bucket) = shard.entries.get_mut(&victim) {
                        live -= bucket.len();
                        evicted += bucket.len() as u64;
                    }
                    shard.entries.remove(&victim);
                }
            }

            let bucket = shard.entries.entry(fingerprint).or_default();
            if !bucket.iter().any(|candidate| candidate.digest == digest) {
                bucket.push(Candidate {
                    digest,
                    deadline_ns,
                    generation,
                });
                live += 1;
                added = 1;
            }
            shard.live = live;
            drop(shard);

            // The shard write lock keeps this counter consistent with
            // `clear()`, which holds every shard lock before resetting it.
            if added > 0 {
                self.entries.fetch_add(1, Ordering::Relaxed);
            }
            let removed = evicted + dropped_expired;
            if removed > 0 {
                self.entries
                    .try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                        Some(value.saturating_sub(removed as usize))
                    })
                    .ok();
            }
            self.publish_entries();

            if evicted > 0 {
                self.evictions.fetch_add(evicted, Ordering::Relaxed);
                if let Some(metrics) = &self.metrics {
                    for _ in 0..evicted {
                        metrics.record_allow_cache_eviction();
                    }
                }
            }
            if dropped_expired > 0 {
                self.expired.fetch_add(dropped_expired, Ordering::Relaxed);
                if let Some(metrics) = &self.metrics {
                    for _ in 0..dropped_expired {
                        metrics.record_allow_cache_expired();
                    }
                }
            }
        }

        self.l1_store(fingerprint, digest, deadline_ns, generation);
    }

    /// Body digest for the profiling harness only. Not part of the public
    /// contract and not used by the engine.
    #[doc(hidden)]
    pub fn body_digest_for_bench(&self, body: &[u8]) -> u128 {
        body_digest(&self.key.secret, body).0
    }

    /// Record a request the cache declined to key.
    pub fn record_skipped(&self, _reason: NotCacheable) {
        self.skipped.fetch_add(1, Ordering::Relaxed);
        if let Some(metrics) = &self.metrics {
            metrics.record_allow_cache_skipped();
        }
    }

    /// Invalidate every entry immediately and move to a new generation.
    pub fn invalidate(&self) {
        self.generation.fetch_add(1, Ordering::AcqRel);
        self.clear();
        if let Some(metrics) = &self.metrics {
            metrics.record_allow_cache_invalidation();
        }
    }

    /// Set the policy generation, clearing entries when it changes.
    pub fn set_generation(&self, generation: u64) {
        if self.generation.swap(generation, Ordering::AcqRel) != generation {
            self.clear();
            if let Some(metrics) = &self.metrics {
                metrics.record_allow_cache_invalidation();
            }
        }
    }

    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    pub fn len(&self) -> usize {
        self.entries.load(Ordering::Relaxed)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn stats(&self) -> CacheStats {
        CacheStats {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            evictions: self.evictions.load(Ordering::Relaxed),
            expired: self.expired.load(Ordering::Relaxed),
            skipped: self.skipped.load(Ordering::Relaxed),
            entries: self.len(),
            generation: self.generation(),
        }
    }

    fn record_hit(&self) {
        self.hits.fetch_add(1, Ordering::Relaxed);
        if let Some(metrics) = &self.metrics {
            metrics.record_allow_cache_hit();
        }
    }

    fn record_miss(&self) {
        self.misses.fetch_add(1, Ordering::Relaxed);
        if let Some(metrics) = &self.metrics {
            metrics.record_allow_cache_miss();
        }
    }

    fn l1_probe(
        &self,
        fingerprint: Fingerprint,
        body: &[u8],
        generation: u64,
        now: u64,
    ) -> L1Probe {
        L1.with(|cell| {
            let slots = &mut *cell.borrow_mut();
            let slot = &mut slots[(fingerprint.0 as usize) % L1_SETS];
            if slot.cache_id != self.key.id
                || slot.fingerprint != fingerprint.0
                || slot.generation != generation
            {
                return L1Probe::Absent;
            }
            if now >= slot.deadline_ns {
                slot.cache_id = 0;
                return L1Probe::Absent;
            }
            let digest = body_digest(&self.key.secret, body);
            if digest.0 == slot.digest {
                L1Probe::Hit
            } else {
                L1Probe::Checked(digest)
            }
        })
    }

    fn l1_store(
        &self,
        fingerprint: Fingerprint,
        digest: BodyDigest,
        deadline_ns: u64,
        generation: u64,
    ) {
        L1.with(|cell| {
            let slots = &mut *cell.borrow_mut();
            let slot = &mut slots[(fingerprint.0 as usize) % L1_SETS];
            *slot = L1Slot {
                cache_id: self.key.id,
                fingerprint: fingerprint.0,
                digest: digest.0,
                deadline_ns,
                generation,
            };
        });
    }

    fn shared_lookup(
        &self,
        fingerprint: Fingerprint,
        digest: BodyDigest,
        generation: u64,
        now: u64,
    ) -> bool {
        let index = self.shard_index(fingerprint);
        {
            let shard = self.shards[index].read();
            if let Some(bucket) = shard.entries.get(&fingerprint) {
                if bucket.iter().any(|candidate| {
                    candidate.digest == digest
                        && candidate.generation == generation
                        && now < candidate.deadline_ns
                }) {
                    return true;
                }
            }
        }
        self.prune(fingerprint, generation, now);
        false
    }

    fn shared_lookup_lazy(
        &self,
        fingerprint: Fingerprint,
        body: &[u8],
        generation: u64,
        now: u64,
    ) -> bool {
        let index = self.shard_index(fingerprint);
        {
            let shard = self.shards[index].read();
            let bucket = match shard.entries.get(&fingerprint) {
                None => return false,
                Some(bucket) => bucket,
            };
            if !bucket
                .iter()
                .any(|candidate| candidate.generation == generation && now < candidate.deadline_ns)
            {
                drop(shard);
                self.prune(fingerprint, generation, now);
                return false;
            }
            // A live bucket exists: only now is the body digest worth
            // computing. It runs under the read lock, which is shared.
            let digest = body_digest(&self.key.secret, body);
            if bucket.iter().any(|candidate| {
                candidate.digest == digest
                    && candidate.generation == generation
                    && now < candidate.deadline_ns
            }) {
                return true;
            }
        }
        self.prune(fingerprint, generation, now);
        false
    }

    /// Drop expired or stale-generation candidates under one fingerprint.
    fn prune(&self, fingerprint: Fingerprint, generation: u64, now: u64) {
        let index = self.shard_index(fingerprint);
        let dropped = {
            let mut shard = self.shards[index].write();
            let mut remove_bucket = false;
            let mut pruned = 0usize;
            if let Some(bucket) = shard.entries.get_mut(&fingerprint) {
                let before = bucket.len();
                bucket.retain(|candidate| {
                    candidate.generation == generation && now < candidate.deadline_ns
                });
                pruned = before - bucket.len();
                remove_bucket = bucket.is_empty();
            }
            shard.live -= pruned;
            if remove_bucket {
                shard.entries.remove(&fingerprint);
            }
            pruned as u64
        };
        if dropped > 0 {
            self.expired.fetch_add(dropped, Ordering::Relaxed);
            if let Some(metrics) = &self.metrics {
                for _ in 0..dropped {
                    metrics.record_allow_cache_expired();
                }
            }
            self.entries
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                    Some(value.saturating_sub(dropped as usize))
                })
                .ok();
            self.publish_entries();
        }
    }

    fn clear(&self) {
        // Hold every shard write lock so an insert cannot slip between a shard
        // clear and the counter reset. Single-shard operations never hold two
        // locks, so the fixed index order cannot deadlock.
        let mut guards: Vec<_> = self.shards.iter().map(|shard| shard.write()).collect();
        for shard in guards.iter_mut() {
            shard.entries.clear();
            shard.live = 0;
        }
        self.entries.store(0, Ordering::Relaxed);
        drop(guards);
        self.publish_entries();
    }

    fn publish_entries(&self) {
        if let Some(metrics) = &self.metrics {
            metrics.set_allow_cache_entries(self.len());
        }
    }

    fn shard_index(&self, key: Fingerprint) -> usize {
        (key.0 as usize) % self.shards.len()
    }

    fn now_ns(&self) -> u64 {
        self.epoch.elapsed().as_nanos() as u64
    }
}

enum L1Probe {
    Hit,
    Checked(BodyDigest),
    Absent,
}

#[derive(Clone, Copy)]
struct L1Slot {
    cache_id: u64,
    fingerprint: u128,
    digest: u128,
    deadline_ns: u64,
    generation: u64,
}

impl L1Slot {
    const EMPTY: Self = Self {
        cache_id: 0,
        fingerprint: 0,
        digest: 0,
        deadline_ns: 0,
        generation: 0,
    };
}

thread_local! {
    static L1: RefCell<[L1Slot; L1_SETS]> = const { RefCell::new([L1Slot::EMPTY; L1_SETS]) };
}

/// Sort key for a header name: the first 16 bytes, zero-padded, big-endian.
///
/// Two distinct HTTP header names cannot share a 16-byte prefix (names are
/// ASCII tokens, so a shared prefix means the names are equal), which makes the
/// key a faithful ordering without hashing every name on the hot path. The
/// exact name bytes are always encoded, so even a hypothetical collision would
/// only change the order, never the content.
#[inline]
fn name_sort_key(name: &[u8]) -> u128 {
    let mut key = [0u8; 16];
    let take = name.len().min(key.len());
    key[..take].copy_from_slice(&name[..take]);
    u128::from_be_bytes(key)
}

#[derive(Clone, Copy)]
struct HeaderRef {
    sort_key: u128,
    start: u32,
    len: u32,
    /// Iteration position, used to keep duplicate values in insertion order.
    order: u32,
}

#[derive(Default)]
struct Scratch {
    /// Encoded header values, reused across requests.
    values: Vec<u8>,
    /// Sorted header name digests pointing into `values`.
    index: Vec<HeaderRef>,
    /// Canonical metadata encoding, reused across requests.
    fingerprint: Vec<u8>,
}

thread_local! {
    static SCRATCH: RefCell<Scratch> = RefCell::new(Scratch::default());
}

#[inline]
fn put_u32(buffer: &mut Vec<u8>, value: u32) {
    buffer.extend_from_slice(&value.to_le_bytes());
}

#[inline]
fn put_u64(buffer: &mut Vec<u8>, value: u64) {
    buffer.extend_from_slice(&value.to_le_bytes());
}

#[inline]
fn put_bytes(buffer: &mut Vec<u8>, bytes: &[u8]) {
    put_u64(buffer, bytes.len() as u64);
    buffer.extend_from_slice(bytes);
}

/// Encode `Uri` by component. This is the same information as `Uri::to_string`
/// but without the per-request `String` allocation; presence bytes keep
/// `scheme`/`authority`/`path_and_query` from being confusable.
#[inline]
fn put_uri(buffer: &mut Vec<u8>, uri: &Uri) {
    match uri.scheme_str() {
        Some(scheme) => {
            buffer.push(1);
            put_bytes(buffer, scheme.as_bytes());
        }
        None => buffer.push(0),
    }
    match uri.authority() {
        Some(authority) => {
            buffer.push(1);
            put_bytes(buffer, authority.as_str().as_bytes());
        }
        None => buffer.push(0),
    }
    match uri.path_and_query() {
        Some(path) => {
            buffer.push(1);
            put_bytes(buffer, path.as_str().as_bytes());
        }
        None => buffer.push(0),
    }
}

#[inline]
fn body_digest(secret: &[u8; SECRET_BYTES], body: &[u8]) -> BodyDigest {
    BodyDigest(xxh3_128_with_secret(body, secret))
}

/// Hash a `u128` map key with xxh3. The key is already a secret-keyed digest,
/// so this only spreads buckets; a collision costs an extra comparison, never a
/// false allow.
#[derive(Clone, Copy)]
struct FingerprintHasherBuilder {
    seed: u64,
}

impl BuildHasher for FingerprintHasherBuilder {
    type Hasher = FingerprintHasher;

    fn build_hasher(&self) -> Self::Hasher {
        FingerprintHasher {
            buffer: [0u8; 16],
            len: 0,
            seed: self.seed,
        }
    }
}

struct FingerprintHasher {
    buffer: [u8; 16],
    len: usize,
    seed: u64,
}

impl Hasher for FingerprintHasher {
    fn finish(&self) -> u64 {
        xxh3_64_with_seed(&self.buffer[..self.len], self.seed)
    }

    fn write(&mut self, bytes: &[u8]) {
        let available = self.buffer.len() - self.len;
        let take = bytes.len().min(available);
        self.buffer[self.len..self.len + take].copy_from_slice(&bytes[..take]);
        self.len += take;
    }

    fn write_u128(&mut self, value: u128) {
        self.write(&value.to_le_bytes());
    }
}

/// Hash the policy generation: the full `[waf]` configuration plus the ordered
/// rule names and their enabled state. Any change to either produces a new
/// generation, which is part of every fingerprint and clears the cache at
/// start-up.
pub fn policy_generation<'a>(
    key: &Key,
    config: &WafConfig,
    rules: impl Iterator<Item = (&'a str, bool)>,
) -> u64 {
    let mut buffer = Vec::with_capacity(4096);
    buffer.push(POLICY_DOMAIN);
    buffer.push(KEY_VERSION);
    match serde_json::to_vec(config) {
        Ok(bytes) => buffer.extend_from_slice(&bytes),
        Err(_) => buffer.extend_from_slice(format!("{config:?}").as_bytes()),
    }
    for (name, enabled) in rules {
        put_bytes(&mut buffer, name.as_bytes());
        buffer.push(u8::from(enabled));
    }
    let digest = xxh3_128_with_secret(&buffer, &key.secret);
    (digest as u64) ^ ((digest >> 64) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::{HeaderName, HeaderValue};
    use hyper::{HeaderMap, Method};
    use std::net::{IpAddr, Ipv4Addr};
    use std::str::FromStr;

    fn cache_config(max_body_bytes: usize) -> AllowCacheConfig {
        AllowCacheConfig {
            enabled: true,
            ttl_secs: 30,
            max_entries: 128,
            max_body_bytes,
            routes: Vec::new(),
        }
    }

    fn cache(max_body_bytes: usize) -> AllowCache {
        AllowCache::new(&cache_config(max_body_bytes), 7, Key::random(), None)
    }

    fn ctx(method: &str, uri: &str, body: Option<&[u8]>) -> RequestContext {
        RequestContext::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            Method::from_bytes(method.as_bytes()).unwrap(),
            Uri::from_str(uri).unwrap(),
            HeaderMap::new(),
            body.map(<[u8]>::len),
        )
        .with_body(body.map(bytes::Bytes::copy_from_slice))
    }

    fn fingerprint(cache: &AllowCache, request: &RequestContext) -> Fingerprint {
        match cache.fingerprint(request) {
            KeyBuild::Fingerprint(key) => key,
            other => panic!("expected a fingerprint, got {other:?}"),
        }
    }

    fn body_of(request: &RequestContext) -> &[u8] {
        request.body.as_deref().unwrap_or(&[])
    }

    fn lookup(cache: &AllowCache, request: &RequestContext) -> bool {
        cache.lookup(fingerprint(cache, request), body_of(request))
    }

    fn insert(cache: &AllowCache, request: &RequestContext) {
        cache.insert(fingerprint(cache, request), body_of(request));
    }

    fn header_map(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.append(
                HeaderName::from_static(name),
                HeaderValue::from_static(value),
            );
        }
        headers
    }

    #[test]
    fn key_is_deterministic() {
        let cache = cache(1024);
        let a = ctx("GET", "/api/items?id=1", None);
        let b = ctx("GET", "/api/items?id=1", None);
        assert_eq!(fingerprint(&cache, &a), fingerprint(&cache, &b));
    }

    #[test]
    fn header_order_is_not_part_of_the_key() {
        let cache = cache(1024);
        let mut a = ctx("GET", "/api/items", None);
        a.headers = header_map(&[("user-agent", "probe"), ("accept", "*/*")]);
        let mut b = ctx("GET", "/api/items", None);
        b.headers = header_map(&[("accept", "*/*"), ("user-agent", "probe")]);
        assert_eq!(fingerprint(&cache, &a), fingerprint(&cache, &b));
    }

    #[test]
    fn duplicate_headers_are_counted_and_ordered() {
        let cache = cache(1024);
        let mut one = ctx("POST", "/api", Some(b"a=1"));
        one.headers = header_map(&[("x-test", "a")]);
        let mut two = ctx("POST", "/api", Some(b"a=1"));
        two.headers = header_map(&[("x-test", "a"), ("x-test", "b")]);
        let mut swapped = ctx("POST", "/api", Some(b"a=1"));
        swapped.headers = header_map(&[("x-test", "b"), ("x-test", "a")]);
        assert_ne!(fingerprint(&cache, &one), fingerprint(&cache, &two));
        assert_ne!(fingerprint(&cache, &two), fingerprint(&cache, &swapped));
    }

    #[test]
    fn percent_encoding_is_preserved() {
        let cache = cache(1024);
        let encoded = ctx("GET", "/a%2Fb?q=%41", None);
        let decoded = ctx("GET", "/a/b?q=A", None);
        assert_ne!(fingerprint(&cache, &encoded), fingerprint(&cache, &decoded));
    }

    #[test]
    fn query_order_is_preserved() {
        let cache = cache(1024);
        let first = ctx("GET", "/search?a=1&b=2", None);
        let second = ctx("GET", "/search?b=2&a=1", None);
        assert_ne!(fingerprint(&cache, &first), fingerprint(&cache, &second));
    }

    #[test]
    fn whitespace_and_smuggling_headers_do_not_collide() {
        let cache = cache(1024);
        let mut spaced = ctx("POST", "/api", Some(b"a=1"));
        spaced.headers = header_map(&[("x-note", "a b")]);
        let mut double = ctx("POST", "/api", Some(b"a=1"));
        double.headers = header_map(&[("x-note", "a  b")]);
        assert_ne!(fingerprint(&cache, &spaced), fingerprint(&cache, &double));

        let mut length_five = ctx("POST", "/api", Some(b"a=1"));
        length_five.headers = header_map(&[("content-length", "3")]);
        let mut length_six = ctx("POST", "/api", Some(b"a=1"));
        length_six.headers = header_map(&[("content-length", "6")]);
        assert_ne!(
            fingerprint(&cache, &length_five),
            fingerprint(&cache, &length_six)
        );

        let mut chunked = ctx("POST", "/api", Some(b"a=1"));
        chunked.headers = header_map(&[("transfer-encoding", "chunked")]);
        let mut not_chunked = ctx("POST", "/api", Some(b"a=1"));
        not_chunked.headers = HeaderMap::new();
        assert_ne!(
            fingerprint(&cache, &chunked),
            fingerprint(&cache, &not_chunked)
        );
    }

    #[test]
    fn method_body_and_protocol_are_injective() {
        let get = ctx("GET", "/api", None);
        let lower = ctx("get", "/api", None);
        let post = ctx("POST", "/api", Some(b""));
        let body_a = ctx("POST", "/api", Some(b"a"));
        let body_b = ctx("POST", "/api", Some(b"b"));
        let mut http2 = ctx("GET", "/api", None);
        http2.http_version = "2".to_string();

        // `body_a` and `body_b` deliberately share a fingerprint (the body
        // lives in the second lookup level), so injectivity is asserted on the
        // full two-level key: insert one and prove every other is a miss.
        let requests = [&get, &lower, &post, &body_a, &body_b, &http2];
        for (inserted, request) in requests.iter().enumerate() {
            let cache = cache(1024);
            insert(&cache, request);
            for (probed, other) in requests.iter().enumerate() {
                assert_eq!(
                    lookup(&cache, other),
                    inserted == probed,
                    "request {probed} must not hit the entry for request {inserted}"
                );
            }
        }
    }

    #[test]
    fn body_size_is_injective() {
        let cache = cache(1024);
        let mut declared = ctx("POST", "/api", Some(b"a=1"));
        declared.body_size = Some(3);
        let mut different = ctx("POST", "/api", Some(b"a=1"));
        different.body_size = Some(4);
        assert_ne!(
            fingerprint(&cache, &declared),
            fingerprint(&cache, &different)
        );
    }

    #[test]
    fn over_cap_bodies_are_not_cached() {
        let cache = cache(4);
        let request = ctx("POST", "/api", Some(b"12345"));
        assert_eq!(
            cache.fingerprint(&request),
            KeyBuild::NotCacheable(NotCacheable::BodyTooLarge)
        );
    }

    #[test]
    fn uncaptured_bodies_are_not_cached() {
        let cache = cache(1024);
        let mut request = ctx("POST", "/api", None);
        request.body_size = Some(10);
        assert_eq!(
            cache.fingerprint(&request),
            KeyBuild::NotCacheable(NotCacheable::BodyNotCaptured)
        );
    }

    #[test]
    fn ttl_expiry() {
        let config = AllowCacheConfig {
            ttl_secs: 0,
            ..cache_config(1024)
        };
        let cache = AllowCache::new(&config, 1, Key::random(), None);
        let request = ctx("GET", "/api", None);
        insert(&cache, &request);
        assert!(!lookup(&cache, &request));
        assert!(cache.is_empty());
        assert!(cache.stats().expired > 0);
    }

    #[test]
    fn eviction_is_bounded() {
        let config = AllowCacheConfig {
            max_entries: 8,
            ..cache_config(1024)
        };
        let cache = AllowCache::new(&config, 1, Key::random(), None);
        for index in 0..100 {
            let request = ctx("GET", &format!("/api/{index}"), None);
            insert(&cache, &request);
        }
        assert!(cache.len() <= 8, "entries = {}", cache.len());
        assert!(cache.stats().evictions > 0);
    }

    #[test]
    fn policy_generation_invalidates_every_entry() {
        let cache = cache(1024);
        let request = ctx("GET", "/api", None);
        insert(&cache, &request);
        assert!(lookup(&cache, &request));

        cache.invalidate();
        assert!(cache.is_empty());
        assert!(!lookup(&cache, &request));
        assert_ne!(cache.generation(), 7);
    }

    #[test]
    fn set_generation_clears_on_change_only() {
        let cache = cache(1024);
        let request = ctx("GET", "/api", None);
        insert(&cache, &request);
        cache.set_generation(7);
        assert_eq!(cache.len(), 1);
        cache.set_generation(8);
        assert!(cache.is_empty());
    }

    #[test]
    fn route_opt_in_matches_on_path_boundaries() {
        let config = AllowCacheConfig {
            routes: vec!["/api".to_string()],
            ..cache_config(1024)
        };
        let cache = AllowCache::new(&config, 1, Key::random(), None);
        assert!(cache.applies_to(&Uri::from_str("/api").unwrap()));
        assert!(cache.applies_to(&Uri::from_str("/api/items").unwrap()));
        assert!(!cache.applies_to(&Uri::from_str("/apix").unwrap()));
        assert!(!cache.applies_to(&Uri::from_str("/other").unwrap()));
    }

    #[test]
    fn keyed_hash_produces_no_collisions_in_a_large_sample() {
        let cache = cache(1024);
        let mut keys = std::collections::HashSet::new();
        for index in 0..50_000 {
            let request = ctx("GET", &format!("/api/{index}?id={index}"), None);
            keys.insert(fingerprint(&cache, &request));
        }
        assert_eq!(keys.len(), 50_000);
    }

    #[test]
    fn different_secrets_produce_different_keys() {
        let first = cache(1024);
        let second = cache(1024);
        let request = ctx("GET", "/api", None);
        assert_ne!(
            fingerprint(&first, &request),
            fingerprint(&second, &request)
        );
    }

    #[test]
    fn concurrent_access_is_safe_and_bounded() {
        let config = AllowCacheConfig {
            max_entries: 64,
            ..cache_config(1024)
        };
        let cache = Arc::new(AllowCache::new(&config, 1, Key::random(), None));
        let mut handles = Vec::new();
        for thread in 0..16 {
            let cache = Arc::clone(&cache);
            handles.push(std::thread::spawn(move || {
                for index in 0..500 {
                    let request = ctx("GET", &format!("/t{thread}/{index}"), None);
                    insert(&cache, &request);
                    let _ = lookup(&cache, &request);
                }
            }));
        }
        for handle in handles {
            handle.join().unwrap();
        }
        assert!(cache.len() <= 64, "entries = {}", cache.len());
    }

    #[test]
    fn same_fingerprint_with_a_different_body_never_allows() {
        let cache = cache(1024);
        // Same method, URI, headers and body length: only the body bytes differ.
        let allowed = ctx("POST", "/api", Some(b"data=benign"));
        let attacker = ctx("POST", "/api", Some(b"data=attack"));
        assert_eq!(
            fingerprint(&cache, &allowed),
            fingerprint(&cache, &attacker),
            "the fixture must share one fingerprint"
        );

        insert(&cache, &allowed);
        assert!(lookup(&cache, &allowed));
        assert!(
            !lookup(&cache, &attacker),
            "a fingerprint match alone must never allow"
        );
        assert_eq!(cache.stats().misses, 1);
    }

    #[test]
    fn fingerprint_collision_requires_a_body_digest_match() {
        let cache = cache(1024);
        let request = ctx("POST", "/api", Some(b"one"));
        let key = fingerprint(&cache, &request);

        // Simulate an adversary that forced a fingerprint collision: the map
        // contains an entry for this fingerprint with a different body digest.
        cache.insert(key, b"two");
        assert!(!cache.lookup(key, b"three"));
        assert!(!cache.lookup(key, b"two-two"));
        assert!(cache.lookup(key, b"two"));
    }

    #[test]
    fn one_fingerprint_holds_several_body_variants() {
        let cache = cache(1024);
        let first = ctx("POST", "/api", Some(b"aaaa"));
        let second = ctx("POST", "/api", Some(b"bbbb"));
        insert(&cache, &first);
        insert(&cache, &second);
        assert!(lookup(&cache, &first));
        assert!(lookup(&cache, &second));
    }

    #[test]
    fn l1_never_skips_body_verification() {
        let cache = cache(1024);
        let allowed = ctx("POST", "/api", Some(b"data=benign"));
        insert(&cache, &allowed);
        // Warm the thread-local L1 with the allowed body.
        assert!(lookup(&cache, &allowed));

        let attacker = ctx("POST", "/api", Some(b"data=attack"));
        assert!(!lookup(&cache, &attacker));
    }

    #[test]
    fn l1_does_not_survive_invalidation() {
        let cache = cache(1024);
        let request = ctx("GET", "/api", None);
        insert(&cache, &request);
        assert!(lookup(&cache, &request));
        cache.invalidate();
        assert!(!lookup(&cache, &request));
    }

    #[test]
    fn l1_is_scoped_to_one_cache_instance() {
        let first = cache(1024);
        let second = cache(1024);
        let request = ctx("GET", "/api", None);
        insert(&first, &request);
        assert!(lookup(&first, &request));
        assert!(
            !lookup(&second, &request),
            "a slot from another cache must never hit"
        );
    }
}
