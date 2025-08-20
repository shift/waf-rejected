#!/usr/bin/env cargo
//! # WAF-Rejected Main Binary
//!
//! Simple launcher that delegates to the main waf-ingress binary.

use std::env;
use std::process::Command;

fn main() {
    println!("🚀 WAF-Rejected v0.1.0-preview");
    println!("===============================");
    println!();
    println!("For the full WAF proxy server, please run:");
    println!("  cargo run --bin waf-ingress");
    println!();
    println!("For performance benchmarking:");
    println!("  cargo run --bin benchmark_core");
    println!();
    println!("For comprehensive testing:");
    println!("  cargo run --bin comprehensive_waf_test");
    println!();

    // Check if they want to run the proxy directly
    let args: Vec<String> = env::args().collect();
    if args.len() > 1 && args[1] == "--proxy" {
        println!("🔀 Launching WAF proxy server...");
        let status = Command::new("cargo")
            .args(["run", "--bin", "waf-ingress"])
            .status()
            .expect("Failed to launch waf-ingress");

        std::process::exit(status.code().unwrap_or(1));
    }

    println!("Use --proxy to launch the proxy server directly from this binary.");
}
