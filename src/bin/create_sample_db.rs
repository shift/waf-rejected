use sled;
use serde_json::json;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    println!("Creating sample database...");
    
    let db = sled::open("./data/waf_security_events.sled")?;
    let tree = db.open_tree("security_events")?;
    
    // Sample events
    let events = vec![
        ("2025-08-09_22:10:00.123_UTC", json!({
            "event_type": "sql_injection_attempt",
            "severity": "high", 
            "source_ip": "192.168.1.100",
            "user_agent": "sqlmap/1.0",
            "request_path": "/login",
            "blocked": true
        })),
        ("2025-08-09_22:15:00.456_UTC", json!({
            "event_type": "xss_attempt",
            "severity": "medium",
            "source_ip": "10.0.0.50", 
            "request_path": "/search",
            "blocked": true
        })),
        ("2025-08-09_22:20:00.789_UTC", json!({
            "event_type": "rate_limit_exceeded",
            "severity": "low",
            "source_ip": "203.0.113.42",
            "blocked": true
        })),
        ("2025-08-09_22:25:00.321_UTC", json!({
            "event_type": "command_injection_attempt", 
            "severity": "critical",
            "source_ip": "198.51.100.25",
            "blocked": true
        })),
    ];
    
    for (timestamp, event) in events {
        let value = serde_json::to_string(&event)?;
        tree.insert(timestamp, value.as_bytes())?;
    }
    
    tree.flush()?;
    println!("✅ Created {} sample events", tree.len());
    
    Ok(())
}
