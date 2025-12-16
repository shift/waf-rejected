use std::collections::HashSet;
use std::sync::{Arc, RwLock};
use hyper::HeaderMap;
use sha2::{Sha256, Digest};
use crate::error::WafError;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AuthConfig {
    pub enabled: bool,
    pub api_keys: Vec<String>,
    pub header_name: String,
    pub require_https: bool,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            api_keys: vec![],
            header_name: "X-API-Key".to_string(),
            require_https: true,
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
    
    fn hash_key(key: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(key.as_bytes());
        hex::encode(hasher.finalize())
    }
}

impl ApiKeyStore for InMemoryKeyStore {
    fn validate(&self, key: &str) -> bool {
        let key_hash = Self::hash_key(key);
        self.keys.read().unwrap().contains(&key_hash)
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

pub struct ApiKeyValidator {
    store: Arc<dyn ApiKeyStore>,
    config: AuthConfig,
}

impl ApiKeyValidator {
    pub fn new(store: Arc<dyn ApiKeyStore>, config: AuthConfig) -> Self {
        Self { store, config }
    }
    
    pub fn validate_request(&self, headers: &HeaderMap, is_https: bool) -> Result<(), WafError> {
        if !self.config.enabled {
            return Ok(());
        }
        
        if self.config.require_https && !is_https {
            return Err(WafError::AuthError(
                "HTTPS required for API key authentication".to_string()
            ));
        }
        
        let api_key = headers
            .get(&self.config.header_name)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| WafError::AuthError(
                "Missing API key header".to_string()
            ))?;
        
        if !self.store.validate(api_key) {
            return Err(WafError::AuthError(
                "Invalid API key".to_string()
            ));
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
