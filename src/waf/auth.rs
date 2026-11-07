use crate::error::WafError;
use hyper::HeaderMap;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
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

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuthConfig {
    pub enabled: bool,
    pub api_keys: Vec<String>,
    pub header_name: String,
    pub require_https: bool,
    /// Per-key, per-IP and global rate limiting for authenticated requests.
    pub rate_limit: Option<RateLimitConfig>,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            api_keys: vec![],
            header_name: "X-API-Key".to_string(),
            require_https: true,
            rate_limit: None,
        }
    }
}

pub trait ApiKeyStore: Send + Sync {
    fn validate(&self, key: &str) -> bool;
    fn add_key(&mut self, key: String);
    fn remove_key(&mut self, key_hash: &str) -> bool;
    fn list_keys(&self) -> Vec<String>;
}

pub struct InMemoryKeyStore {
    keys: Arc<RwLock<HashSet<String>>>,
}

impl InMemoryKeyStore {
    pub fn new(hashed_keys: Vec<String>) -> Self {
        Self {
            keys: Arc::new(RwLock::new(hashed_keys.into_iter().collect())),
        }
    }

    /// Build a store from plaintext API keys by hashing them at startup.
    pub fn from_raw_keys(keys: &[String]) -> Self {
        Self::new(keys.iter().map(|key| Self::hash_key(key)).collect())
    }

    pub fn hash_key(key: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(key.as_bytes());
        hex::encode(hasher.finalize())
    }
}

impl ApiKeyStore for InMemoryKeyStore {
    fn validate(&self, key: &str) -> bool {
        let key_hash = Self::hash_key(key);
        let keys = self.keys.read().unwrap();
        // Compare every stored digest in constant time. Do not short-circuit on
        // the first match: the position of a key in the set must not influence
        // the time taken to validate a presented value.
        let mut matched = 0u8;
        for stored in keys.iter() {
            matched |= stored.as_bytes().ct_eq(key_hash.as_bytes()).unwrap_u8();
        }
        matched == 1
    }

    fn add_key(&mut self, key: String) {
        let key_hash = Self::hash_key(&key);
        self.keys.write().unwrap().insert(key_hash);
    }

    fn remove_key(&mut self, key_hash: &str) -> bool {
        self.keys.write().unwrap().remove(key_hash)
    }

    fn list_keys(&self) -> Vec<String> {
        self.keys.read().unwrap().iter().cloned().collect()
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

#[derive(Default)]
struct AuthRateLimiter {
    per_key: Mutex<HashMap<String, WindowCounter>>,
    per_ip: Mutex<HashMap<IpAddr, WindowCounter>>,
    global: Mutex<WindowCounter>,
}

impl AuthRateLimiter {
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
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| WafError::AuthError("Missing API key header".to_string()))?;

        if !self.store.validate(api_key) {
            return Err(WafError::AuthError("Invalid API key".to_string()));
        }

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
}
