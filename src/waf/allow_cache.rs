//! Experimental content-addressed allow-verdict cache.
//!
//! This module is compiled only with the non-default `allow-cache` feature and
//! is disabled unless `waf.allow_cache.enabled = true`. It memoises the
//! verdict of the *pure content rules* (the Coraza backend and the built-in
//! content inspector) for requests that produced an `Allow`. Blocks and rate
//! limits are never cached, and every stateful or IP-dependent rule is still
//! evaluated on a hit.
//!
//! The design, canonicalisation rules, injectivity argument, threat model and
//! measurements live in `docs/suggestions_from_agents/allow-cache.md`.

use std::collections::HashMap;
use std::hash::Hasher as _;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use hyper::header::HeaderName;
use hyper::Uri;
use parking_lot::Mutex;
use siphasher::sip128::{Hasher128, SipHasher24};

use super::RequestContext;
use crate::config::{AllowCacheConfig, WafConfig};
use crate::metrics::Metrics;

/// Bump when the canonical encoding changes. Old entries become unreachable
/// because the version is part of every key.
pub const KEY_VERSION: u8 = 1;

/// Domain separator for the policy-generation hash.
const POLICY_DOMAIN: u8 = 0xA1;

/// Shard count for the bounded map. Fixed so the memory bound is predictable.
pub const SHARDS: usize = 16;

/// Defensive cap on the number of distinct header names in a key. Hyper's
/// default header limit is far lower; this only prevents pathological input
/// from making key construction allocate without bound.
pub const MAX_HEADER_NAMES: usize = 256;

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
#[derive(Clone, Copy)]
pub struct Key {
    k0: u64,
    k1: u64,
}

impl Key {
    /// Draw a fresh secret from the OS-seeded process CSPRNG.
    pub fn random() -> Self {
        Self {
            k0: rand::random(),
            k1: rand::random(),
        }
    }
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Key(<redacted>)")
    }
}

/// A 128-bit keyed hash of the canonical request representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CacheKey(u128);

/// Result of attempting to key a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyBuild {
    /// The request can be looked up under this key.
    Key(CacheKey),
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

struct Entry {
    expires_at: Instant,
    generation: u64,
}

struct Shard {
    entries: HashMap<CacheKey, Entry>,
}

/// Bounded, sharded, TTL-limited allow-verdict cache.
pub struct AllowCache {
    shards: Vec<Mutex<Shard>>,
    capacities: Vec<usize>,
    ttl: Duration,
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
        let shards = capacities
            .iter()
            .map(|_| {
                Mutex::new(Shard {
                    entries: HashMap::new(),
                })
            })
            .collect();

        let cache = Self {
            shards,
            capacities,
            ttl: Duration::from_secs(config.ttl_secs),
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

    /// Build the canonical key for a request.
    ///
    /// The encoding is injective: a version byte, the policy generation, and
    /// then fixed-width or length-prefixed fields in a fixed order. Header
    /// names are sorted by their lowercase form (hyper already normalises
    /// `HeaderName`), while duplicate values keep their original order and
    /// count. No percent-decoding, query reordering, case folding or
    /// whitespace normalisation is applied.
    pub fn build_key(&self, ctx: &RequestContext) -> KeyBuild {
        let body = ctx.body.as_deref();
        if body.is_some_and(|body| body.len() > self.max_body_bytes) {
            return KeyBuild::NotCacheable(NotCacheable::BodyTooLarge);
        }
        if body.is_none() && ctx.body_size.unwrap_or(0) > 0 {
            return KeyBuild::NotCacheable(NotCacheable::BodyNotCaptured);
        }

        let mut names: Vec<&HeaderName> = ctx.headers.keys().collect();
        if names.len() > MAX_HEADER_NAMES {
            return KeyBuild::NotCacheable(NotCacheable::TooManyHeaders);
        }
        names.sort_unstable_by(|left, right| left.as_str().cmp(right.as_str()));

        let mut writer = KeyWriter::new(&self.key);
        writer.put_u64(self.generation.load(Ordering::Acquire));
        writer.put_bytes(ctx.method.as_str().as_bytes());
        // `Uri::to_string` is exactly what the Coraza payload sends, including
        // any scheme/authority. The one allocation is bounded by the URI limit.
        let uri = ctx.uri.to_string();
        writer.put_bytes(uri.as_bytes());
        writer.put_bytes(ctx.http_version.as_bytes());

        match body {
            Some(body) => {
                writer.put_u8(1);
                writer.put_u64(body.len() as u64);
                writer.put_bytes(body);
            }
            None => writer.put_u8(0),
        }
        match ctx.body_size {
            Some(size) => {
                writer.put_u8(1);
                writer.put_u64(size as u64);
            }
            None => writer.put_u8(0),
        }

        writer.put_u64(names.len() as u64);
        for name in names {
            writer.put_bytes(name.as_str().as_bytes());
            let values = ctx.headers.get_all(name);
            writer.put_u64(values.iter().count() as u64);
            for value in values.iter() {
                writer.put_bytes(value.as_bytes());
            }
        }

        KeyBuild::Key(CacheKey(writer.finish()))
    }

    /// Look up a key. Records a hit or a miss (including an expired entry).
    pub fn get(&self, key: CacheKey) -> bool {
        let now = Instant::now();
        let generation = self.generation.load(Ordering::Acquire);
        let index = self.shard_index(key);
        let mut shard = self.shards[index].lock();

        let live = shard
            .entries
            .get(&key)
            .is_some_and(|entry| entry.generation == generation && now < entry.expires_at);
        if live {
            drop(shard);
            self.hits.fetch_add(1, Ordering::Relaxed);
            if let Some(metrics) = &self.metrics {
                metrics.record_allow_cache_hit();
            }
            return true;
        }

        if let Some(entry) = shard.entries.get(&key) {
            let expired = entry.generation == generation && now >= entry.expires_at;
            shard.entries.remove(&key);
            // Decrement while the shard is still locked so a concurrent
            // `clear()` cannot store 0 between the removal and the decrement.
            self.entries
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                    Some(value.saturating_sub(1))
                })
                .ok();
            if expired {
                self.expired.fetch_add(1, Ordering::Relaxed);
                if let Some(metrics) = &self.metrics {
                    metrics.record_allow_cache_expired();
                }
            }
            drop(shard);
            self.publish_entries();
        }

        self.misses.fetch_add(1, Ordering::Relaxed);
        if let Some(metrics) = &self.metrics {
            metrics.record_allow_cache_miss();
        }
        false
    }

    /// Insert an allow verdict. The caller must only call this for `Allow`.
    pub fn insert(&self, key: CacheKey) {
        let generation = self.generation.load(Ordering::Acquire);
        let index = self.shard_index(key);
        let capacity = self.capacities[index];
        let mut shard = self.shards[index].lock();

        let already_present = shard.entries.contains_key(&key);
        if !already_present && shard.entries.len() >= capacity {
            // Sharded map with arbitrary (hash-order) eviction. This keeps the
            // memory bound strict without an intrusive LRU list.
            if let Some(victim) = shard.entries.keys().next().copied() {
                shard.entries.remove(&victim);
                self.entries.fetch_sub(1, Ordering::Relaxed);
                self.evictions.fetch_add(1, Ordering::Relaxed);
                if let Some(metrics) = &self.metrics {
                    metrics.record_allow_cache_eviction();
                }
            }
        }

        let expires_at = Instant::now()
            .checked_add(self.ttl)
            .unwrap_or_else(Instant::now);
        shard.entries.insert(
            key,
            Entry {
                expires_at,
                generation,
            },
        );
        if !already_present {
            self.entries.fetch_add(1, Ordering::Relaxed);
        }
        drop(shard);
        self.publish_entries();
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

    fn clear(&self) {
        // Hold every shard lock so an insert cannot slip between a shard clear
        // and the counter reset. Single-shard operations never hold two locks,
        // so the fixed index order cannot deadlock.
        let mut guards: Vec<_> = self.shards.iter().map(|shard| shard.lock()).collect();
        for shard in guards.iter_mut() {
            shard.entries.clear();
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

    fn shard_index(&self, key: CacheKey) -> usize {
        (key.0 as usize) % self.shards.len()
    }
}

/// Streaming, length-prefixed key writer.
struct KeyWriter {
    hasher: SipHasher24,
}

impl KeyWriter {
    fn new(key: &Key) -> Self {
        let mut hasher = SipHasher24::new_with_keys(key.k0, key.k1);
        hasher.write(&[KEY_VERSION]);
        Self { hasher }
    }

    fn put_u8(&mut self, value: u8) {
        self.hasher.write(&[value]);
    }

    fn put_u64(&mut self, value: u64) {
        self.hasher.write(&value.to_le_bytes());
    }

    fn put_bytes(&mut self, bytes: &[u8]) {
        self.put_u64(bytes.len() as u64);
        self.hasher.write(bytes);
    }

    fn finish(self) -> u128 {
        u128::from(self.hasher.finish128())
    }
}

/// Hash the policy generation: the full `[waf]` configuration plus the ordered
/// rule names and their enabled state. Any change to either produces a new
/// generation, which is part of every key and clears the cache at start-up.
pub fn policy_generation<'a>(
    key: &Key,
    config: &WafConfig,
    rules: impl Iterator<Item = (&'a str, bool)>,
) -> u64 {
    let mut hasher = SipHasher24::new_with_keys(key.k0, key.k1);
    hasher.write(&[POLICY_DOMAIN]);
    match serde_json::to_vec(config) {
        Ok(bytes) => hasher.write(&bytes),
        Err(_) => hasher.write(format!("{config:?}").as_bytes()),
    }
    for (name, enabled) in rules {
        hasher.write(&(name.len() as u64).to_le_bytes());
        hasher.write(name.as_bytes());
        hasher.write(&[u8::from(enabled)]);
    }
    hasher.finish128().h1
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
        .with_body(body.map(|body| bytes::Bytes::copy_from_slice(body)))
    }

    fn key(cache: &AllowCache, request: &RequestContext) -> CacheKey {
        match cache.build_key(request) {
            KeyBuild::Key(key) => key,
            other => panic!("expected a key, got {other:?}"),
        }
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
        assert_eq!(key(&cache, &a), key(&cache, &b));
    }

    #[test]
    fn header_order_is_not_part_of_the_key() {
        let cache = cache(1024);
        let mut a = ctx("GET", "/api/items", None);
        a.headers = header_map(&[("user-agent", "probe"), ("accept", "*/*")]);
        let mut b = ctx("GET", "/api/items", None);
        b.headers = header_map(&[("accept", "*/*"), ("user-agent", "probe")]);
        assert_eq!(key(&cache, &a), key(&cache, &b));
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
        assert_ne!(key(&cache, &one), key(&cache, &two));
        assert_ne!(key(&cache, &two), key(&cache, &swapped));
    }

    #[test]
    fn percent_encoding_is_preserved() {
        let cache = cache(1024);
        let encoded = ctx("GET", "/a%2Fb?q=%41", None);
        let decoded = ctx("GET", "/a/b?q=A", None);
        assert_ne!(key(&cache, &encoded), key(&cache, &decoded));
    }

    #[test]
    fn query_order_is_preserved() {
        let cache = cache(1024);
        let first = ctx("GET", "/search?a=1&b=2", None);
        let second = ctx("GET", "/search?b=2&a=1", None);
        assert_ne!(key(&cache, &first), key(&cache, &second));
    }

    #[test]
    fn whitespace_and_smuggling_headers_do_not_collide() {
        let cache = cache(1024);
        let mut spaced = ctx("POST", "/api", Some(b"a=1"));
        spaced.headers = header_map(&[("x-note", "a b")]);
        let mut double = ctx("POST", "/api", Some(b"a=1"));
        double.headers = header_map(&[("x-note", "a  b")]);
        assert_ne!(key(&cache, &spaced), key(&cache, &double));

        let mut length_five = ctx("POST", "/api", Some(b"a=1"));
        length_five.headers = header_map(&[("content-length", "3")]);
        let mut length_six = ctx("POST", "/api", Some(b"a=1"));
        length_six.headers = header_map(&[("content-length", "6")]);
        assert_ne!(key(&cache, &length_five), key(&cache, &length_six));

        let mut chunked = ctx("POST", "/api", Some(b"a=1"));
        chunked.headers = header_map(&[("transfer-encoding", "chunked")]);
        let mut not_chunked = ctx("POST", "/api", Some(b"a=1"));
        not_chunked.headers = HeaderMap::new();
        assert_ne!(key(&cache, &chunked), key(&cache, &not_chunked));
    }

    #[test]
    fn method_body_and_protocol_are_injective() {
        let cache = cache(1024);
        let get = ctx("GET", "/api", None);
        let lower = ctx("get", "/api", None);
        let post = ctx("POST", "/api", Some(b""));
        let body_a = ctx("POST", "/api", Some(b"a"));
        let body_b = ctx("POST", "/api", Some(b"b"));
        let mut http2 = ctx("GET", "/api", None);
        http2.http_version = "2".to_string();

        let keys = [
            key(&cache, &get),
            key(&cache, &lower),
            key(&cache, &post),
            key(&cache, &body_a),
            key(&cache, &body_b),
            key(&cache, &http2),
        ];
        let unique: std::collections::HashSet<_> = keys.iter().collect();
        assert_eq!(unique.len(), keys.len());
    }

    #[test]
    fn body_size_is_injective() {
        let cache = cache(1024);
        let mut declared = ctx("POST", "/api", Some(b"a=1"));
        declared.body_size = Some(3);
        let mut different = ctx("POST", "/api", Some(b"a=1"));
        different.body_size = Some(4);
        assert_ne!(key(&cache, &declared), key(&cache, &different));
    }

    #[test]
    fn over_cap_bodies_are_not_cached() {
        let cache = cache(4);
        let request = ctx("POST", "/api", Some(b"12345"));
        assert_eq!(
            cache.build_key(&request),
            KeyBuild::NotCacheable(NotCacheable::BodyTooLarge)
        );
    }

    #[test]
    fn uncaptured_bodies_are_not_cached() {
        let cache = cache(1024);
        let mut request = ctx("POST", "/api", None);
        request.body_size = Some(10);
        assert_eq!(
            cache.build_key(&request),
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
        let key = key(&cache, &request);
        cache.insert(key);
        assert!(!cache.get(key));
        assert!(cache.is_empty());
        assert_eq!(cache.stats().expired, 1);
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
            cache.insert(key(&cache, &request));
        }
        assert!(cache.len() <= 8, "entries = {}", cache.len());
        assert!(cache.stats().evictions > 0);
    }

    #[test]
    fn policy_generation_invalidates_every_entry() {
        let cache = cache(1024);
        let request = ctx("GET", "/api", None);
        let key = key(&cache, &request);
        cache.insert(key);
        assert!(cache.get(key));

        cache.invalidate();
        assert!(cache.is_empty());
        assert!(!cache.get(key));
        assert_ne!(cache.generation(), 7);
    }

    #[test]
    fn set_generation_clears_on_change_only() {
        let cache = cache(1024);
        let request = ctx("GET", "/api", None);
        let key = key(&cache, &request);
        cache.insert(key);
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
            keys.insert(key(&cache, &request));
        }
        assert_eq!(keys.len(), 50_000);
    }

    #[test]
    fn different_secrets_produce_different_keys() {
        let first = cache(1024);
        let second = cache(1024);
        let request = ctx("GET", "/api", None);
        assert_ne!(key(&first, &request), key(&second, &request));
    }

    #[test]
    fn concurrent_access_is_safe_and_bounded() {
        let config = AllowCacheConfig {
            max_entries: 64,
            ..cache_config(1024)
        };
        let cache = Arc::new(AllowCache::new(&config, 1, Key::random(), None));
        let mut handles = Vec::new();
        for thread in 0..8 {
            let cache = Arc::clone(&cache);
            handles.push(std::thread::spawn(move || {
                for index in 0..500 {
                    let request = ctx("GET", &format!("/t{thread}/{index}"), None);
                    let key = key(&cache, &request);
                    cache.insert(key);
                    let _ = cache.get(key);
                }
            }));
        }
        for handle in handles {
            handle.join().unwrap();
        }
        assert!(cache.len() <= 64, "entries = {}", cache.len());
    }
}
