use crate::Config;
use std::sync::Arc;

pub struct WafProxyService {
    config: Arc<Config>,
}

impl WafProxyService {
    pub fn create(config: &Config) -> Self {
        Self {
            config: Arc::new(config.clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Config;

    fn create_test_config() -> Config {
        Config::default()
    }

    #[tokio::test]
    async fn test_waf_service_creation() {
        let config = create_test_config();
        let _service = WafProxyService::create(&config);
        // Just test that service creation succeeds
    }

    #[test]
    fn test_waf_enabled() {
        let config = create_test_config();
        let service = WafProxyService::create(&config);
        // Basic test that the service can be created
        assert_eq!(service.config.waf.enabled, config.waf.enabled);
    }
}
