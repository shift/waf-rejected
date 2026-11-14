//! WAF-Rejected main binary.

use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    if let Some(arg) = args.next() {
        match arg.as_str() {
            "--version" | "-V" => {
                println!("waf-ingress {}", env!("CARGO_PKG_VERSION"));
                return Ok(());
            }
            "--help" | "-h" => {
                println!(
                    "waf-ingress {}\n\nUsage: waf-ingress [--version|--help]\n\nConfiguration is loaded from WAF_CONFIG_FILE (default: config.toml).",
                    env!("CARGO_PKG_VERSION")
                );
                return Ok(());
            }
            other => {
                eprintln!("error: unknown argument '{other}'");
                eprintln!("Usage: waf-ingress [--version|--help]");
                std::process::exit(2);
            }
        }
    }

    waf_ingress::server::run()
}
