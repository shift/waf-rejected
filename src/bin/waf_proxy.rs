//! Compatibility binary for deployments that invoke `waf_proxy` directly.

use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    waf_ingress::server::run().await
}
