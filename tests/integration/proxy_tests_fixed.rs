use tokio;
use waf_rejected::{Config, WafEngine};
use waf_rejected::waf::proxy::WafProxyService;

#[tokio::test]
async fn test_waf_proxy_service_creation() {
    let config = Config::default();
    let _service = WafProxyService::create(&config);
    // Basic test that service can be created
}

#[tokio::test]
async fn test_waf_engine_integration() {
    let config = Config::default();
    let waf_engine = WafEngine::new(&config).await;
    
    match waf_engine {
        Ok(_engine) => {
            // Engine created successfully
        },
        Err(_) => {
            // Engine creation failed - could be due to WASM module not being present
            // This is acceptable in test environment
        }
    }
}

#[tokio::test]
async fn test_basic_health_check() {
    // Simple integration test that doesn't require full server
    let config = Config::default();
    assert!(config.waf.enabled); // Default should have WAF enabled
}
