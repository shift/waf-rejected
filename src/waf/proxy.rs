use std::net::SocketAddr;
use hyper::{
    service::{make_service_fn, service_fn},
    Request, Response, StatusCode, Uri, Method
};
use hyper::body::{Incoming};
use http_body_util::Full;
use bytes::Bytes;
use std::convert::Infallible;
use std::sync::Arc;
use crate::Config;
use crate::waf::{
    content_inspection::ContentInspectionRuleFactory,
    geoip::GeoBlockingRuleFactory};

pub struct WafProxyService {
    config: Arc<Config>,
}

impl WafProxyService {
    pub fn create(config: &Config) -> Self {
        Self {
            config: Arc::new(config.clone()),
        }
    }

    pub async fn run(&self, addr: SocketAddr) -> crate::error::Result<()> {
        let config = Arc::clone(&self.config);
        
        let make_svc = make_service_fn(move |_conn| {
            let config = Arc::clone(&config);
            async move {
                let config = Arc::clone(&config);
                Ok::<_, Infallible>(service_fn(move |req| {
                    Self::handle_request(Arc::clone(&config), req)
                }))
            }
        });

        let server = hyper::server::Server::bind(&addr).serve(make_svc);
        
        if let Err(e) = server.await {
            eprintln!("Server error: {}", e);
        }
        
        Ok(())
    }
    
    async fn handle_request(
        config: Arc<Config>, 
        _req: Request<Incoming>
    ) -> Result<Response<Full<Bytes>>, Infallible> {
        // Simple response for now
        let response = Response::builder()
            .status(StatusCode::OK)
            .body(Full::new(Bytes::from("Hello, World!")))
            .unwrap();
            
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Config;
    use http_body_util::Empty;
    use bytes::Bytes;

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
        assert_eq!(service.config.server.port, config.server.port);
    }
}
