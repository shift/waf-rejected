use waf_ingress::proxy::WafProxyService;
use waf_ingress::waf::WafEngine;
use waf_ingress::Config;

#[test]
fn test_waf_proxy_service_creation() {
    let mut config = Config::default();
    config.waf.coraza.enabled = false;
    let _service = WafProxyService::new(config).expect("proxy service should initialize");
}

#[test]
fn test_waf_engine_integration() {
    let mut config = Config::default();
    config.waf.coraza.enabled = false;
    let engine = WafEngine::with_config(&config);
    assert!(engine.rule_count() > 0);
}

#[test]
fn test_basic_health_check() {
    let config = Config::default();
    assert!(config.waf.enabled);
}
