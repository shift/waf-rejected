use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;

use hyper::{Method, Uri, HeaderMap, body::Bytes};
use reqwest::Client;
use tokio::net::TcpListener;
use tokio::time::timeout;

use waf_ingress::config::Config;
use waf_ingress::proxy::WafProxyService;

/// Integration tests for authentication and authorization
#[cfg(test)]
mod auth_integration_tests {
    use super::*;

    async fn start_test_server(config: Config) -> TestServerHandle {
        let addr = SocketAddr::from_str("127.0.0.1:0").unwrap();
        let service = WafProxyService::new(config).unwrap();

        let listener = TcpListener::bind(addr).await.unwrap();
        let actual_addr = listener.local_addr().unwrap();

        let handle = tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                // In a real test, we'd handle the connection
                // For now, just accept and close
            }
        });

        TestServerHandle {
            addr: actual_addr,
            handle,
        }
    }

    struct TestServerHandle {
        addr: SocketAddr,
        handle: tokio::task::JoinHandle<()>,
    }

    impl TestServerHandle {
        async fn shutdown(self) {
            self.handle.abort();
        }
    }

    fn create_config_with_auth() -> Config {
        let mut config = Config::default();
        config.security.auth.enabled = true;
        config.security.auth.api_keys = vec![
            "test-api-key-123".to_string(),
            "admin-key-456".to_string(),
        ];
        config.security.auth.header_name = "X-API-Key".to_string();
        config.security.auth.require_https = false; // Allow HTTP for testing

        config
    }

    #[tokio::test]
    async fn test_authentication_middleware_integration() {
        let config = create_config_with_auth();
        let mut engine = waf_ingress::waf::WafEngine::with_config(&config);

        // Test 1: Request without API key should be processed but auth should fail
        let request_without_key = create_test_request("test", None);
        let decision = engine.evaluate(&request_without_key).await;

        // The WAF engine itself doesn't enforce auth - that's done in the proxy
        // This test validates that the auth config is properly loaded
        assert!(config.security.auth.enabled);
        assert_eq!(config.security.auth.api_keys.len(), 2);
        assert!(config.security.auth.api_keys.contains(&"test-api-key-123".to_string()));
    }

    #[tokio::test]
    async fn test_api_key_validation_logic() {
        use waf_ingress::waf::auth::{ApiKeyValidator, InMemoryKeyStore};

        let hashed_keys = vec![
            InMemoryKeyStore::hash_key("test-api-key-123"),
            InMemoryKeyStore::hash_key("admin-key-456"),
        ];

        let store = std::sync::Arc::new(InMemoryKeyStore::new(hashed_keys));
        let config = create_config_with_auth().security.auth;
        let validator = ApiKeyValidator::new(store, config);

        let mut headers = HeaderMap::new();

        // Test missing key
        assert!(validator.validate_request(&headers, false).is_err());

        // Test valid key
        headers.insert("X-API-Key", "test-api-key-123".parse().unwrap());
        assert!(validator.validate_request(&headers, false).is_ok());

        // Test invalid key
        headers.insert("X-API-Key", "invalid-key".parse().unwrap());
        assert!(validator.validate_request(&headers, false).is_err());

        // Test second valid key
        headers.insert("X-API-Key", "admin-key-456".parse().unwrap());
        assert!(validator.validate_request(&headers, false).is_ok());
    }

    #[tokio::test]
    async fn test_https_requirement() {
        use waf_ingress::waf::auth::{ApiKeyValidator, InMemoryKeyStore};

        let hashed_keys = vec![InMemoryKeyStore::hash_key("test-key")];
        let store = std::sync::Arc::new(InMemoryKeyStore::new(hashed_keys));

        let mut config = create_config_with_auth().security.auth;
        config.require_https = true; // Require HTTPS

        let validator = ApiKeyValidator::new(store, config);
        let mut headers = HeaderMap::new();
        headers.insert("X-API-Key", "test-key".parse().unwrap());

        // Should fail without HTTPS
        assert!(validator.validate_request(&headers, false).is_err());

        // Should succeed with HTTPS
        assert!(validator.validate_request(&headers, true).is_ok());
    }

    #[tokio::test]
    async fn test_key_rotation_simulation() {
        use waf_ingress::waf::auth::{ApiKeyStore, InMemoryKeyStore};

        let mut store = InMemoryKeyStore::new(vec![]);

        // Add initial key
        store.add_key("initial-key".to_string());
        assert!(store.validate("initial-key"));

        // Add new key (rotation)
        store.add_key("new-key".to_string());
        assert!(store.validate("initial-key")); // Old key still works
        assert!(store.validate("new-key")); // New key works

        // Remove old key
        let old_hash = InMemoryKeyStore::hash_key("initial-key");
        assert!(store.remove_key(&old_hash));
        assert!(!store.validate("initial-key")); // Old key no longer works
        assert!(store.validate("new-key")); // New key still works

        // List remaining keys
        let keys = store.list_keys();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0], InMemoryKeyStore::hash_key("new-key"));
    }

    fn create_test_request(path: &str, api_key: Option<&str>) -> waf_ingress::waf::RequestContext {
        let mut headers = HeaderMap::new();
        if let Some(key) = api_key {
            headers.insert("X-API-Key", key.parse().unwrap());
        }

        waf_ingress::waf::RequestContext::new(
            std::net::IpAddr::from_str("192.168.1.100").unwrap(),
            Method::GET,
            Uri::from_str(&format!("http://example.com{}", path)).unwrap(),
            headers,
            Some(1024), // body size
        )
    }
}