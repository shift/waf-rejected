//! WAF-Rejected main binary.

use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    waf_ingress::server::run()
}
