#!/usr/bin/env rust-script
//! Quick script to create sample events for testing the CLI utility

use serde_json::json;
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Create data directory
    std::fs::create_dir_all("./data")?;
    
    // Open Sled database
    let db = sled::open("./data/waf_security_events.sled")?;
    let tree = db.open_tree("security_events")?;
    
    println!("Creating sample security events...");
    
    // Sample events with different types and severities
    let sample_events = vec![
        json!({
            "event_type": "sql_injection_attempt",
            "severity": "high",
            "source_ip": "192.168.1.100",
            "user_agent": "Mozilla/5.0 (compatible; sqlmap/1.0)",
            "request_path": "/login.php",
            "blocked": true,
            "message": "SQL injection detected in query parameter"
        }),
        json!({
            "event_type": "xss_attempt", 
            "severity": "medium",
            "source_ip": "10.0.0.50",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "request_path": "/search",
            "blocked": true,
            "message": "XSS payload detected in form data"
        }),
        json!({
            "event_type": "rate_limit_exceeded",
            "severity": "low",
            "source_ip": "203.0.113.42", 
            "user_agent": "curl/7.68.0",
            "request_path": "/api/users",
            "blocked": true,
            "message": "Rate limit exceeded: 1000 requests in 60 seconds"
        }),
        json!({
            "event_type": "geo_blocking",
            "severity": "info",
            "source_ip": "185.220.100.240",
            "country_code": "RU", 
            "user_agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "request_path": "/admin",
            "blocked": true,
            "message": "Request blocked from restricted country: RU"
        }),
        json!({
            "event_type": "command_injection_attempt",
            "severity": "critical",
            "source_ip": "198.51.100.25",
            "user_agent": "Wget/1.20.3 (linux-gnu)",
            "request_path": "/upload.php",
            "blocked": true,
            "message": "Command injection detected: ; cat /etc/passwd"
        }),
        json!({
            "event_type": "path_traversal_attempt",
            "severity": "medium",
            "source_ip": "192.168.1.200",
            "user_agent": "Mozilla/5.0 (compatible; Googlebot/2.1)",
            "request_path": "/files/../../../etc/passwd",
            "blocked": true,
            "message": "Path traversal attempt detected"
        }),
    ];
    
    // Insert events with timestamps
    let base_time = chrono::Utc::now();
    for (i, event) in sample_events.iter().enumerate() {
        let timestamp = base_time - chrono::Duration::minutes((sample_events.len() - i) as i64 * 5);
        let key = timestamp.format("%Y-%m-%d_%H:%M:%S%.3f_UTC").to_string();
        let value = serde_json::to_string(event)?;
        
        tree.insert(key.as_bytes(), value.as_bytes())?;
    }
    
    // Force flush to disk
    tree.flush()?;
    
    println!("✅ Created {} sample events", sample_events.len());
    println!("💡 Try: cargo run --bin waf-events-query -- --info");
    println!("💡 Try: cargo run --bin waf-events-query -- --list 3");  
    println!("💡 Try: cargo run --bin waf-events-query -- --stats");
    
    Ok(())
}
