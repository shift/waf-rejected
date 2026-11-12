use crate::error::WafError;
use chrono::{DateTime, Utc};
use hyper::HeaderMap;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;

/// Hard cap on the number of API-key buckets tracked by the auth limiter.
/// Reaching the cap fails closed for a new key rather than growing without
/// bound.
const MAX_TRACKED_AUTH_KEYS: usize = 4096;

/// Hard cap on the number of client-IP buckets tracked by the auth limiter.
const MAX_TRACKED_AUTH_IPS: usize = 100_000;

/// Number of hexadecimal SHA-256 characters used to key the per-presented-key
/// failure budget. The full digest is never retained, so the bucket key cannot
/// be used to recover the presented secret.
const KEY_DIGEST_PREFIX_LEN: usize = 16;

/// Rate limiting configuration for API-key authentication.
///
/// `requests_per_minute` is a per-key limit. The optional per-IP and global
/// limits are enforced in the same authentication stage, before the body is
/// read, so a stolen key cannot bypass the configured throttles.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RateLimitConfig {
    /// Requests per minute per key. Zero disables the per-key limit.
    pub requests_per_minute: u32,
    /// Enable a per-client-IP limit in the authentication stage.
    pub per_ip_enabled: bool,
    /// Maximum authenticated requests per IP per window.
    pub per_ip_max_requests: u32,
    /// Per-IP window size in seconds.
    pub per_ip_window_secs: u64,
    /// Enable a global limit in the authentication stage.
    pub global_enabled: bool,
    /// Maximum authenticated requests globally per window.
    pub global_max_requests: u32,
    /// Global window size in seconds.
    pub global_window_secs: u64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_minute: 60,
            per_ip_enabled: false,
            per_ip_max_requests: 100,
            per_ip_window_secs: 60,
            global_enabled: false,
            global_max_requests: 1000,
            global_window_secs: 60,
        }
    }
}

/// Stricter budget for *failed* authentication attempts, evaluated before a
/// presented key is validated. Disabled by default so existing deployments keep
/// their current behaviour.
///
/// It is keyed independently by resolved client IP and by the first
/// [`KEY_DIGEST_PREFIX_LEN`] hex characters of the presented key's SHA-256
/// digest (when a key is present). Failed attempts consume the budget; once
/// `max_failures` is reached within `window_secs` the source is locked out for
/// `lockout_secs`. A correct key presented from a locked-out source is still
/// rejected until the lockout expires.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FailureLimitConfig {
    /// Enable the pre-validation failure budget. Defaults to `false`.
    pub enabled: bool,
    /// Failures permitted per source within the window before lockout.
    pub max_failures: u32,
    /// Failure counting window in seconds.
    pub window_secs: u64,
    /// Lockout duration in seconds once the budget is exhausted.
    pub lockout_secs: u64,
}

impl Default for FailureLimitConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_failures: 10,
            window_secs: 60,
            lockout_secs: 300,
        }
    }
}

/// An API key with optional expiry metadata.
///
/// The legacy `security.auth.api_keys` list remains supported and maps to
/// entries without an expiry. During rotation both the old and new keys can
/// be listed, with `expires_at` set only on the retiring key.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiKeyEntry {
    /// Plaintext key; hashed at startup and never logged.
    pub key: String,
    /// Optional RFC 3339 timestamp after which the key is rejected.
    #[serde(default)]
    pub expires_at: Option<String>,
}

impl ApiKeyEntry {
    fn parsed_expiry(&self) -> Option<DateTime<Utc>> {
        // An unparseable timestamp fails closed as already expired. Config
        // validation rejects it before startup, so this is defence in depth.
        self.expires_at.as_deref().map(|value| {
            DateTime::parse_from_rfc3339(value)
                .map(|parsed| parsed.with_timezone(&Utc))
                .unwrap_or(DateTime::<Utc>::MIN_UTC)
        })
    }
}

/// Result of validating a presented key against the store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyValidation {
    Valid,
    Expired,
    Invalid,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuthConfig {
    pub enabled: bool,
    pub api_keys: Vec<String>,
    /// Keys carrying optional expiry metadata. Combined with `api_keys` so
    /// existing configurations and rotation entries can coexist.
    pub api_key_entries: Vec<ApiKeyEntry>,
    pub header_name: String,
    pub require_https: bool,
    /// Per-key, per-IP and global rate limiting for authenticated requests.
    pub rate_limit: Option<RateLimitConfig>,
    /// Pre-validation budget for failed authentication attempts.
    pub failure_limit: FailureLimitConfig,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            api_keys: vec![],
            api_key_entries: vec![],
            header_name: "X-API-Key".to_string(),
            require_https: true,
            rate_limit: None,
            failure_limit: FailureLimitConfig::default(),
        }
    }
}

impl AuthConfig {
    /// Validate expiry metadata supplied through `api_key_entries`.
    pub fn validate(&self) -> anyhow::Result<()> {
        for (index, entry) in self.api_key_entries.iter().enumerate() {
            if entry.key.is_empty() {
                anyhow::bail!("security.auth.api_key_entries[{index}].key must not be empty");
            }
            if let Some(expires_at) = entry.expires_at.as_deref() {
                DateTime::parse_from_rfc3339(expires_at).map_err(|e| {
                    anyhow::anyhow!(
                        "security.auth.api_key_entries[{index}].expires_at is not RFC 3339: {e}"
                    )
                })?;
            }
        }
        if self.failure_limit.enabled {
            if self.failure_limit.max_failures == 0 {
                anyhow::bail!(
                    "security.auth.failure_limit.max_failures must be greater than zero when enabled"
                );
            }
            if self.failure_limit.window_secs == 0 {
                anyhow::bail!(
                    "security.auth.failure_limit.window_secs must be greater than zero when enabled"
                );
            }
            if self.failure_limit.lockout_secs == 0 {
                anyhow::bail!(
                    "security.auth.failure_limit.lockout_secs must be greater than zero when enabled"
                );
            }
        }
        Ok(())
    }
}

pub trait ApiKeyStore: Send + Sync {
    fn validate(&self, key: &str) -> bool;
    /// Validate at an explicit instant so expiry can be evaluated
    /// deterministically. The default preserves stores without metadata.
    fn validate_at(&self, key: &str, _now: DateTime<Utc>) -> KeyValidation {
        if self.validate(key) {
            KeyValidation::Valid
        } else {
            KeyValidation::Invalid
        }
    }
    fn add_key(&mut self, key: String);
    fn remove_key(&mut self, key_hash: &str) -> bool;
    fn list_keys(&self) -> Vec<String>;
}

#[derive(Debug, Clone)]
struct StoredKey {
    digest: String,
    expires_at: Option<DateTime<Utc>>,
}

pub struct InMemoryKeyStore {
    keys: Arc<RwLock<Vec<StoredKey>>>,
}

impl InMemoryKeyStore {
    pub fn new(hashed_keys: Vec<String>) -> Self {
        Self {
            keys: Arc::new(RwLock::new(
                hashed_keys
                    .into_iter()
                    .map(|digest| StoredKey {
                        digest,
                        expires_at: None,
                    })
                    .collect(),
            )),
        }
    }

    /// Build a store from plaintext API keys by hashing them at startup.
    pub fn from_raw_keys(keys: &[String]) -> Self {
        Self::new(keys.iter().map(|key| Self::hash_key(key)).collect())
    }

    /// Build a store from keys carrying optional expiry metadata. Legacy
    /// `api_keys` and `api_key_entries` are both passed here.
    pub fn from_entries(entries: &[ApiKeyEntry]) -> Self {
        Self {
            keys: Arc::new(RwLock::new(
                entries
                    .iter()
                    .map(|entry| StoredKey {
                        digest: Self::hash_key(&entry.key),
                        expires_at: entry.parsed_expiry(),
                    })
                    .collect(),
            )),
        }
    }

    pub fn hash_key(key: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(key.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Digest prefix used as the presented-key failure-budget bucket. Never
    /// retain or log the full key.
    pub fn digest_prefix(key: &str) -> String {
        Self::hash_key(key)
            .chars()
            .take(KEY_DIGEST_PREFIX_LEN)
            .collect()
    }
}

impl ApiKeyStore for InMemoryKeyStore {
    fn validate(&self, key: &str) -> bool {
        self.validate_at(key, Utc::now()) == KeyValidation::Valid
    }

    fn validate_at(&self, key: &str, now: DateTime<Utc>) -> KeyValidation {
        let key_hash = Self::hash_key(key);
        let keys = self.keys.read().unwrap();
        // Compare every stored digest in constant time. Do not short-circuit on
        // the first match: the position of a key in the list must not influence
        // the time taken to validate a presented value, and an expired matching
        // key must not be distinguishable from an invalid one by timing.
        let mut matched_valid = 0u8;
        let mut matched_expired = 0u8;
        for stored in keys.iter() {
            let equal = stored
                .digest
                .as_bytes()
                .ct_eq(key_hash.as_bytes())
                .unwrap_u8();
            let expired = stored.expires_at.is_some_and(|expiry| now >= expiry) as u8;
            matched_valid |= equal & (1 - expired);
            matched_expired |= equal & expired;
        }
        if matched_valid == 1 {
            KeyValidation::Valid
        } else if matched_expired == 1 {
            KeyValidation::Expired
        } else {
            KeyValidation::Invalid
        }
    }

    fn add_key(&mut self, key: String) {
        let key_hash = Self::hash_key(&key);
        self.keys.write().unwrap().push(StoredKey {
            digest: key_hash,
            expires_at: None,
        });
    }

    fn remove_key(&mut self, key_hash: &str) -> bool {
        let mut keys = self.keys.write().unwrap();
        let before = keys.len();
        keys.retain(|stored| stored.digest != key_hash);
        keys.len() != before
    }

    fn list_keys(&self) -> Vec<String> {
        self.keys
            .read()
            .unwrap()
            .iter()
            .map(|stored| stored.digest.clone())
            .collect()
    }
}

#[derive(Debug, Clone, Copy)]
struct WindowCounter {
    window_start: Instant,
    count: u32,
}

impl Default for WindowCounter {
    fn default() -> Self {
        Self::new()
    }
}

impl WindowCounter {
    fn new() -> Self {
        Self {
            window_start: Instant::now(),
            count: 0,
        }
    }

    fn allow(&mut self, limit: u32, window: Duration) -> bool {
        if limit == 0 {
            return true;
        }
        let now = Instant::now();
        if now.duration_since(self.window_start) >= window {
            self.window_start = now;
            self.count = 0;
        }
        if self.count >= limit {
            false
        } else {
            self.count += 1;
            true
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct FailureTracker {
    window_start: Instant,
    failures: u32,
    locked_until: Option<Instant>,
}

impl FailureTracker {
    fn new() -> Self {
        Self {
            window_start: Instant::now(),
            failures: 0,
            locked_until: None,
        }
    }

    fn lockout_remaining(&self, now: Instant) -> Option<Duration> {
        self.locked_until
            .filter(|until| *until > now)
            .map(|until| until.saturating_duration_since(now))
    }

    /// Record one failure and return `true` when this attempt exhausted the
    /// budget and started a lockout.
    fn record_failure(&mut self, config: &FailureLimitConfig) -> bool {
        let now = Instant::now();
        if self
            .window_start
            .checked_add(Duration::from_secs(config.window_secs))
            .is_some_and(|end| now >= end)
        {
            self.window_start = now;
            self.failures = 0;
        }
        self.failures = self.failures.saturating_add(1);
        if self.failures >= config.max_failures {
            self.locked_until = Some(now + Duration::from_secs(config.lockout_secs));
            true
        } else {
            false
        }
    }

    fn reset(&mut self) {
        self.window_start = Instant::now();
        self.failures = 0;
        self.locked_until = None;
    }
}

#[derive(Default)]
struct AuthRateLimiter {
    per_key: Mutex<HashMap<String, WindowCounter>>,
    per_ip: Mutex<HashMap<IpAddr, WindowCounter>>,
    global: Mutex<WindowCounter>,
    // Separate failure maps: a failed attempt must not consume the successful
    // request budget, and a lockout must not be reset by a later valid key.
    failure_per_ip: Mutex<HashMap<IpAddr, FailureTracker>>,
    failure_per_key: Mutex<HashMap<String, FailureTracker>>,
}

impl AuthRateLimiter {
    fn check_failure_budget(
        &self,
        key_prefix: Option<&str>,
        client_ip: Option<IpAddr>,
        config: &FailureLimitConfig,
    ) -> Result<(), WafError> {
        if !config.enabled {
            return Ok(());
        }
        let client_ip = client_ip.ok_or_else(|| {
            WafError::AuthFailureLimited(
                "client IP unavailable for the auth failure budget (fail-closed)".to_string(),
            )
        })?;
        let now = Instant::now();

        {
            let buckets = self
                .failure_per_ip
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if !buckets.contains_key(&client_ip) && buckets.len() >= MAX_TRACKED_AUTH_IPS {
                return Err(WafError::AuthFailureLimited(
                    "auth failure-budget table is full (fail-closed)".to_string(),
                ));
            }
            if let Some(remaining) = buckets
                .get(&client_ip)
                .and_then(|tracker| tracker.lockout_remaining(now))
            {
                return Err(WafError::AuthFailureLimited(format!(
                    "client IP is locked out for another {}s",
                    remaining.as_secs()
                )));
            }
        }

        if let Some(prefix) = key_prefix {
            let buckets = self
                .failure_per_key
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if !buckets.contains_key(prefix) && buckets.len() >= MAX_TRACKED_AUTH_KEYS {
                return Err(WafError::AuthFailureLimited(
                    "auth failure-budget key table is full (fail-closed)".to_string(),
                ));
            }
            if let Some(remaining) = buckets
                .get(prefix)
                .and_then(|tracker| tracker.lockout_remaining(now))
            {
                return Err(WafError::AuthFailureLimited(format!(
                    "presented key is locked out for another {}s",
                    remaining.as_secs()
                )));
            }
        }
        Ok(())
    }

    /// Record a failed attempt against both budgets. Returns the lockout error
    /// when this failure exhausted either budget.
    fn record_failure(
        &self,
        key_prefix: Option<&str>,
        client_ip: Option<IpAddr>,
        config: &FailureLimitConfig,
    ) -> Result<(), WafError> {
        if !config.enabled {
            return Ok(());
        }
        let mut locked = false;
        if let Some(ip) = client_ip {
            let mut buckets = self
                .failure_per_ip
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if buckets.len() < MAX_TRACKED_AUTH_IPS || buckets.contains_key(&ip) {
                let tracker = buckets.entry(ip).or_insert_with(FailureTracker::new);
                locked |= tracker.record_failure(config);
            } else {
                return Err(WafError::AuthFailureLimited(
                    "auth failure-budget table is full (fail-closed)".to_string(),
                ));
            }
        }
        if let Some(prefix) = key_prefix {
            let mut buckets = self
                .failure_per_key
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if buckets.len() < MAX_TRACKED_AUTH_KEYS || buckets.contains_key(prefix) {
                let tracker = buckets
                    .entry(prefix.to_string())
                    .or_insert_with(FailureTracker::new);
                locked |= tracker.record_failure(config);
            } else {
                return Err(WafError::AuthFailureLimited(
                    "auth failure-budget key table is full (fail-closed)".to_string(),
                ));
            }
        }
        if locked {
            Err(WafError::AuthFailureLimited(
                "authentication failure budget exhausted; temporarily locked out".to_string(),
            ))
        } else {
            Ok(())
        }
    }

    /// A valid key from a source that is not locked out clears its failure
    /// counter. A locked-out source never reaches this path.
    fn record_success(&self, key_prefix: Option<&str>, client_ip: Option<IpAddr>) {
        if let Some(ip) = client_ip {
            if let Some(tracker) = self
                .failure_per_ip
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .get_mut(&ip)
            {
                tracker.reset();
            }
        }
        if let Some(prefix) = key_prefix {
            if let Some(tracker) = self
                .failure_per_key
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .get_mut(prefix)
            {
                tracker.reset();
            }
        }
    }

    fn check(
        &self,
        key_hash: &str,
        client_ip: Option<IpAddr>,
        config: &RateLimitConfig,
    ) -> Result<(), WafError> {
        if config.requests_per_minute > 0 {
            let mut buckets = self
                .per_key
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if !buckets.contains_key(key_hash) && buckets.len() >= MAX_TRACKED_AUTH_KEYS {
                return Err(WafError::RateLimitError(
                    "API-key rate-limit table is full (fail-closed)".to_string(),
                ));
            }
            let bucket = buckets
                .entry(key_hash.to_string())
                .or_insert_with(WindowCounter::new);
            if !bucket.allow(config.requests_per_minute, Duration::from_secs(60)) {
                return Err(WafError::RateLimitError(
                    "API-key rate limit exceeded".to_string(),
                ));
            }
        }

        if config.per_ip_enabled {
            let client_ip = client_ip.ok_or_else(|| {
                WafError::RateLimitError(
                    "client IP unavailable for the auth per-IP rate limit (fail-closed)"
                        .to_string(),
                )
            })?;
            let mut buckets = self
                .per_ip
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if !buckets.contains_key(&client_ip) && buckets.len() >= MAX_TRACKED_AUTH_IPS {
                return Err(WafError::RateLimitError(
                    "auth per-IP rate-limit table is full (fail-closed)".to_string(),
                ));
            }
            let bucket = buckets.entry(client_ip).or_insert_with(WindowCounter::new);
            if !bucket.allow(
                config.per_ip_max_requests,
                Duration::from_secs(config.per_ip_window_secs.max(1)),
            ) {
                return Err(WafError::RateLimitError(
                    "auth per-IP rate limit exceeded".to_string(),
                ));
            }
        }

        if config.global_enabled {
            let mut bucket = self
                .global
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if !bucket.allow(
                config.global_max_requests,
                Duration::from_secs(config.global_window_secs.max(1)),
            ) {
                return Err(WafError::RateLimitError(
                    "auth global rate limit exceeded".to_string(),
                ));
            }
        }

        Ok(())
    }
}

pub struct ApiKeyValidator {
    store: Arc<dyn ApiKeyStore>,
    config: AuthConfig,
    rate_limiter: AuthRateLimiter,
}

impl ApiKeyValidator {
    pub fn new(store: Arc<dyn ApiKeyStore>, config: AuthConfig) -> Self {
        Self {
            store,
            config,
            rate_limiter: AuthRateLimiter::default(),
        }
    }

    /// Validate a request without a resolved client IP.
    ///
    /// Kept for callers that do not have an address; a configured per-IP auth
    /// limit fails closed in this case. Prefer [`Self::validate_request_for_client`].
    pub fn validate_request(&self, headers: &HeaderMap, is_https: bool) -> Result<(), WafError> {
        self.validate_request_for_client(headers, is_https, None)
    }

    pub fn validate_request_for_client(
        &self,
        headers: &HeaderMap,
        is_https: bool,
        client_ip: Option<IpAddr>,
    ) -> Result<(), WafError> {
        if !self.config.enabled {
            return Ok(());
        }

        if self.config.require_https && !is_https {
            return Err(WafError::AuthError(
                "HTTPS required for API key authentication".to_string(),
            ));
        }

        let api_key = headers
            .get(&self.config.header_name)
            .and_then(|v| v.to_str().ok());

        // The failure budget is consulted before any digest comparison, so an
        // attacker cannot brute force keys at full speed. The bucket key is a
        // short digest prefix; the presented secret is never stored or logged.
        let key_prefix = api_key.map(InMemoryKeyStore::digest_prefix);
        if self.config.failure_limit.enabled {
            self.rate_limiter.check_failure_budget(
                key_prefix.as_deref(),
                client_ip,
                &self.config.failure_limit,
            )?;
        }

        let api_key = match api_key {
            Some(key) => key,
            None => {
                self.rate_limiter.record_failure(
                    key_prefix.as_deref(),
                    client_ip,
                    &self.config.failure_limit,
                )?;
                return Err(WafError::AuthMissingKey);
            }
        };

        match self.store.validate_at(api_key, Utc::now()) {
            KeyValidation::Valid => {}
            KeyValidation::Expired => {
                self.rate_limiter.record_failure(
                    key_prefix.as_deref(),
                    client_ip,
                    &self.config.failure_limit,
                )?;
                return Err(WafError::AuthExpiredKey);
            }
            KeyValidation::Invalid => {
                self.rate_limiter.record_failure(
                    key_prefix.as_deref(),
                    client_ip,
                    &self.config.failure_limit,
                )?;
                return Err(WafError::AuthInvalidKey);
            }
        }

        self.rate_limiter
            .record_success(key_prefix.as_deref(), client_ip);

        if let Some(rate_limit) = &self.config.rate_limit {
            let key_hash = InMemoryKeyStore::hash_key(api_key);
            self.rate_limiter.check(&key_hash, client_ip, rate_limit)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn validator_with_rate_limit(rate_limit: RateLimitConfig) -> ApiKeyValidator {
        let key = "valid-key";
        let hashed = InMemoryKeyStore::hash_key(key);
        let store = Arc::new(InMemoryKeyStore::new(vec![hashed]));
        let config = AuthConfig {
            enabled: true,
            rate_limit: Some(rate_limit),
            ..Default::default()
        };
        ApiKeyValidator::new(store, config)
    }

    fn headers_for(key: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("X-API-Key", key.parse().unwrap());
        headers
    }

    #[test]
    fn test_key_hashing() {
        let key = "test-api-key-12345";
        let hash1 = InMemoryKeyStore::hash_key(key);
        let hash2 = InMemoryKeyStore::hash_key(key);

        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64);
    }

    #[test]
    fn test_in_memory_store_validate() {
        let key = "test-key";
        let hashed = InMemoryKeyStore::hash_key(key);
        let store = InMemoryKeyStore::new(vec![hashed]);

        assert!(store.validate(key));
        assert!(!store.validate("wrong-key"));
    }

    #[test]
    fn api_key_validation_compares_every_stored_digest() {
        let keys = (0..64)
            .map(|index| format!("key-{index}"))
            .collect::<Vec<_>>();
        let store = InMemoryKeyStore::from_raw_keys(&keys);

        assert!(store.validate("key-0"));
        assert!(store.validate("key-63"));
        assert!(!store.validate("key-64"));
        assert!(!store.validate(""));
    }

    #[test]
    fn test_validator_disabled() {
        let store = Arc::new(InMemoryKeyStore::new(vec![]));
        let config = AuthConfig {
            enabled: false,
            ..Default::default()
        };
        let validator = ApiKeyValidator::new(store, config);

        let headers = HeaderMap::new();
        assert!(validator.validate_request(&headers, true).is_ok());
    }

    #[test]
    fn test_validator_missing_key() {
        let store = Arc::new(InMemoryKeyStore::new(vec![]));
        let config = AuthConfig {
            enabled: true,
            ..Default::default()
        };
        let validator = ApiKeyValidator::new(store, config);

        let headers = HeaderMap::new();
        assert!(validator.validate_request(&headers, true).is_err());
    }

    #[test]
    fn test_validator_valid_key() {
        let key = "valid-key";
        let hashed = InMemoryKeyStore::hash_key(key);
        let store = Arc::new(InMemoryKeyStore::new(vec![hashed]));
        let config = AuthConfig {
            enabled: true,
            ..Default::default()
        };
        let validator = ApiKeyValidator::new(store, config);

        let mut headers = HeaderMap::new();
        headers.insert("X-API-Key", key.parse().unwrap());

        assert!(validator.validate_request(&headers, true).is_ok());
    }

    #[test]
    fn test_validator_https_required() {
        let key = "valid-key";
        let hashed = InMemoryKeyStore::hash_key(key);
        let store = Arc::new(InMemoryKeyStore::new(vec![hashed]));
        let config = AuthConfig {
            enabled: true,
            require_https: true,
            ..Default::default()
        };
        let validator = ApiKeyValidator::new(store, config);

        let mut headers = HeaderMap::new();
        headers.insert("X-API-Key", key.parse().unwrap());

        assert!(validator.validate_request(&headers, false).is_err());
        assert!(validator.validate_request(&headers, true).is_ok());
    }

    #[test]
    fn per_key_rate_limit_is_enforced_after_validation() {
        let validator = validator_with_rate_limit(RateLimitConfig {
            requests_per_minute: 1,
            ..Default::default()
        });
        let headers = headers_for("valid-key");

        assert!(validator.validate_request(&headers, true).is_ok());
        assert!(matches!(
            validator.validate_request(&headers, true),
            Err(WafError::RateLimitError(_))
        ));
    }

    #[test]
    fn per_ip_rate_limit_is_enforced_across_keys() {
        let validator = validator_with_rate_limit(RateLimitConfig {
            requests_per_minute: 0,
            per_ip_enabled: true,
            per_ip_max_requests: 1,
            per_ip_window_secs: 60,
            ..Default::default()
        });
        let headers = headers_for("valid-key");
        let ip: IpAddr = "203.0.113.7".parse().unwrap();

        assert!(validator
            .validate_request_for_client(&headers, true, Some(ip))
            .is_ok());
        assert!(matches!(
            validator.validate_request_for_client(&headers, true, Some(ip)),
            Err(WafError::RateLimitError(_))
        ));
        assert!(validator
            .validate_request_for_client(&headers, true, Some("203.0.113.8".parse().unwrap()))
            .is_ok());
    }

    #[test]
    fn global_rate_limit_is_enforced_across_keys_and_ips() {
        let validator = validator_with_rate_limit(RateLimitConfig {
            requests_per_minute: 0,
            global_enabled: true,
            global_max_requests: 1,
            global_window_secs: 60,
            ..Default::default()
        });
        let headers = headers_for("valid-key");

        assert!(validator
            .validate_request_for_client(&headers, true, Some("203.0.113.7".parse().unwrap()))
            .is_ok());
        assert!(matches!(
            validator.validate_request_for_client(
                &headers,
                true,
                Some("203.0.113.8".parse().unwrap())
            ),
            Err(WafError::RateLimitError(_))
        ));
    }

    #[test]
    fn per_ip_rate_limit_fails_closed_without_a_client_ip() {
        let validator = validator_with_rate_limit(RateLimitConfig {
            requests_per_minute: 0,
            per_ip_enabled: true,
            per_ip_max_requests: 10,
            ..Default::default()
        });
        let headers = headers_for("valid-key");

        assert!(matches!(
            validator.validate_request(&headers, true),
            Err(WafError::RateLimitError(_))
        ));
    }

    fn validator_with_failure_limit(failure_limit: FailureLimitConfig) -> ApiKeyValidator {
        let key = "valid-key";
        let hashed = InMemoryKeyStore::hash_key(key);
        let store = Arc::new(InMemoryKeyStore::new(vec![hashed]));
        let config = AuthConfig {
            enabled: true,
            failure_limit,
            ..Default::default()
        };
        ApiKeyValidator::new(store, config)
    }

    #[test]
    fn wrong_keys_exhaust_the_failure_budget_and_lock_out_the_source() {
        let validator = validator_with_failure_limit(FailureLimitConfig {
            enabled: true,
            max_failures: 10,
            window_secs: 60,
            lockout_secs: 300,
        });
        let ip: IpAddr = "203.0.113.7".parse().unwrap();

        let mut saw_lockout = false;
        for index in 0..100 {
            let headers = headers_for(&format!("wrong-key-{index}"));
            match validator.validate_request_for_client(&headers, true, Some(ip)) {
                Err(WafError::AuthFailureLimited(_)) => saw_lockout = true,
                Err(WafError::AuthInvalidKey) => {}
                other => panic!("unexpected result for wrong key: {other:?}"),
            }
        }
        assert!(saw_lockout, "failure budget must eventually lock out");
        assert!(matches!(
            validator.validate_request_for_client(&headers_for("valid-key"), true, Some(ip)),
            Err(WafError::AuthFailureLimited(_))
        ));
    }

    #[test]
    fn correct_key_from_a_penalised_source_still_faces_the_failure_budget() {
        let validator = validator_with_failure_limit(FailureLimitConfig {
            enabled: true,
            max_failures: 2,
            window_secs: 60,
            lockout_secs: 300,
        });
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        let wrong = headers_for("not-the-key");

        assert!(matches!(
            validator.validate_request_for_client(&wrong, true, Some(ip)),
            Err(WafError::AuthInvalidKey)
        ));
        assert!(matches!(
            validator.validate_request_for_client(&wrong, true, Some(ip)),
            Err(WafError::AuthFailureLimited(_))
        ));
        assert!(matches!(
            validator.validate_request_for_client(&headers_for("valid-key"), true, Some(ip)),
            Err(WafError::AuthFailureLimited(_))
        ));
    }

    #[test]
    fn failure_budgets_are_isolated_per_source() {
        let validator = validator_with_failure_limit(FailureLimitConfig {
            enabled: true,
            max_failures: 1,
            window_secs: 60,
            lockout_secs: 300,
        });
        let bad: IpAddr = "203.0.113.7".parse().unwrap();
        let good: IpAddr = "203.0.113.8".parse().unwrap();

        assert!(matches!(
            validator.validate_request_for_client(&headers_for("wrong"), true, Some(bad)),
            Err(WafError::AuthFailureLimited(_))
        ));
        assert!(validator
            .validate_request_for_client(&headers_for("valid-key"), true, Some(good))
            .is_ok());
    }

    #[test]
    fn failure_budget_is_disabled_by_default() {
        let validator = validator_with_failure_limit(FailureLimitConfig::default());
        assert!(!validator.config.failure_limit.enabled);

        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        for index in 0..50 {
            assert!(matches!(
                validator.validate_request_for_client(
                    &headers_for(&format!("wrong-{index}")),
                    true,
                    Some(ip)
                ),
                Err(WafError::AuthInvalidKey)
            ));
        }
        // The legacy path still accepts a valid key and only then consults the
        // (absent) success rate limiter.
        assert!(validator
            .validate_request_for_client(&headers_for("valid-key"), true, Some(ip))
            .is_ok());
    }

    #[test]
    fn expired_key_is_rejected_and_rotation_accepts_old_and_new() {
        let entries = vec![
            ApiKeyEntry {
                key: "old-key".to_string(),
                expires_at: Some("2030-01-01T00:00:00Z".to_string()),
            },
            ApiKeyEntry {
                key: "new-key".to_string(),
                expires_at: None,
            },
            ApiKeyEntry {
                key: "expired-key".to_string(),
                expires_at: Some("2020-01-01T00:00:00Z".to_string()),
            },
        ];
        let store = Arc::new(InMemoryKeyStore::from_entries(&entries));
        let config = AuthConfig {
            enabled: true,
            ..Default::default()
        };
        let validator = ApiKeyValidator::new(store, config);
        let ip: IpAddr = "203.0.113.7".parse().unwrap();

        assert!(validator
            .validate_request_for_client(&headers_for("old-key"), true, Some(ip))
            .is_ok());
        assert!(validator
            .validate_request_for_client(&headers_for("new-key"), true, Some(ip))
            .is_ok());
        assert!(matches!(
            validator.validate_request_for_client(&headers_for("expired-key"), true, Some(ip)),
            Err(WafError::AuthExpiredKey)
        ));
    }
}
