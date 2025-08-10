//! Security Events Database Query Utility
//! 
//! Command-line utility for querying security events stored in Sled database

use clap::{Arg, Command};
use serde_json;
use std::path::Path;
use std::collections::HashMap;

// For now, let's provide a comprehensive utility with direct Sled access
// This demonstrates the full capabilities of our embedded database

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = Command::new("waf-events-query")
        .version("1.0.0")
        .about("Query security events from Sled database")
        .arg(
            Arg::new("db-path")
                .long("db-path")
                .value_name("PATH")
                .help("Path to the Sled database")
                .default_value("./data/waf_security_events.sled")
        )
        .arg(
            Arg::new("info")
                .long("info")
                .help("Show database info and statistics")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("list")
                .long("list")
                .value_name("COUNT")
                .help("List recent N events (default: 10)")
                .value_parser(clap::value_parser!(usize))
        )
        .arg(
            Arg::new("export")
                .long("export")
                .value_name("FILE")
                .help("Export all events to JSON file")
        )
        .arg(
            Arg::new("stats")
                .long("stats")
                .help("Show event statistics by type and severity")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("tree")
                .long("tree")
                .value_name("TREE_NAME")
                .help("Specify tree name (default: security_events)")
                .default_value("security_events")
        )
        .get_matches();

    let db_path = matches.get_one::<String>("db-path").unwrap();
    let tree_name = matches.get_one::<String>("tree").unwrap();
    
    // Check if database exists
    if !Path::new(db_path).exists() {
        println!("❌ Database not found at: {}", db_path);
        println!("💡 Make sure the WAF has been running with Sled persistence enabled.");
        println!("   Example configuration:");
        println!("   [waf.security_events]");
        println!("   enable_sled = true");
        println!("   sled_db_path = \"{}\"", db_path);
        return Ok(());
    }
    
    println!("📁 Database found at: {}", db_path);
    
    // Open database
    let db = match sled::open(db_path) {
        Ok(db) => db,
        Err(e) => {
            println!("❌ Error opening database: {}", e);
            return Ok(());
        }
    };
    
    // Open the events tree
    let tree = match db.open_tree(tree_name) {
        Ok(tree) => tree,
        Err(e) => {
            println!("❌ Error opening tree '{}': {}", tree_name, e);
            println!("💡 Available trees: {:?}", db.tree_names());
            return Ok(());
        }
    };

    // Handle different commands
    if matches.get_flag("info") {
        show_database_info(&db, &tree).await?;
    } else if let Some(&count) = matches.get_one::<usize>("list") {
        list_recent_events(&tree, count).await?;
    } else if let Some(export_file) = matches.get_one::<String>("export") {
        export_events_to_file(&tree, export_file).await?;
    } else if matches.get_flag("stats") {
        show_event_statistics(&tree).await?;
    } else {
        // Default: show basic info
        show_database_info(&db, &tree).await?;
    }
    
    Ok(())
}

async fn show_database_info(db: &sled::Db, tree: &sled::Tree) -> Result<(), Box<dyn std::error::Error>> {
    let count = tree.len();
    let size_on_disk = db.size_on_disk().unwrap_or(0);
    
    println!("📊 Database Information:");
    println!("   Events: {}", count);
    println!("   Size on disk: {:.2} MB", size_on_disk as f64 / 1024.0 / 1024.0);
    println!("   Tree name: security_events");
    
    if count > 0 {
        // Get first and last keys to show time range
        if let (Some(first), Some(last)) = (tree.first()?, tree.last()?) {
            let first_key = String::from_utf8_lossy(&first.0);
            let last_key = String::from_utf8_lossy(&last.0);
            println!("   Time range: {} → {}", first_key, last_key);
        }
        
        println!("\n💡 Use --list 10 to see recent events");
        println!("💡 Use --stats to see event statistics");
        println!("💡 Use --export events.json to export all events");
    }
    
    Ok(())
}

async fn list_recent_events(tree: &sled::Tree, count: usize) -> Result<(), Box<dyn std::error::Error>> {
    println!("📋 Recent {} events:", count);
    
    let mut events = Vec::new();
    for result in tree.iter().rev().take(count) {
        let (key, value) = result?;
        let timestamp = String::from_utf8_lossy(&key);
        
        if let Ok(event_json) = String::from_utf8(value.to_vec()) {
            events.push((timestamp.to_string(), event_json));
        }
    }
    
    if events.is_empty() {
        println!("   No events found");
        return Ok(());
    }
    
    for (i, (timestamp, event_json)) in events.iter().enumerate() {
        println!("\n   Event {} ({})", i + 1, timestamp);
        
        // Try to parse and pretty-print the JSON
        match serde_json::from_str::<serde_json::Value>(event_json) {
            Ok(parsed) => {
                if let Ok(pretty) = serde_json::to_string_pretty(&parsed) {
                    // Indent each line
                    for line in pretty.lines() {
                        println!("      {}", line);
                    }
                } else {
                    println!("      {}", event_json);
                }
            }
            Err(_) => {
                println!("      {}", event_json);
            }
        }
    }
    
    Ok(())
}

async fn export_events_to_file(tree: &sled::Tree, filename: &str) -> Result<(), Box<dyn std::error::Error>> {
    use std::fs::File;
    use std::io::Write;
    
    println!("💾 Exporting events to {}...", filename);
    
    let mut file = File::create(filename)?;
    let mut event_count = 0;
    
    file.write_all(b"[\n")?;
    
    for (i, result) in tree.iter().enumerate() {
        let (key, value) = result?;
        let timestamp = String::from_utf8_lossy(&key);
        
        if let Ok(event_json) = String::from_utf8(value.to_vec()) {
            if i > 0 {
                file.write_all(b",\n")?;
            }
            
            // Create a wrapper object with timestamp and event data
            let wrapper = serde_json::json!({
                "timestamp": timestamp,
                "event": serde_json::from_str::<serde_json::Value>(&event_json).unwrap_or_else(|_| serde_json::Value::String(event_json))
            });
            
            let pretty_json = serde_json::to_string_pretty(&wrapper)?;
            file.write_all(pretty_json.as_bytes())?;
            event_count += 1;
        }
    }
    
    file.write_all(b"\n]")?;
    
    println!("✅ Exported {} events to {}", event_count, filename);
    Ok(())
}

async fn show_event_statistics(tree: &sled::Tree) -> Result<(), Box<dyn std::error::Error>> {
    println!("📈 Event Statistics:");
    
    let mut event_types = HashMap::new();
    let mut severities = HashMap::new();
    let mut total_events = 0;
    
    for result in tree.iter() {
        let (_, value) = result?;
        total_events += 1;
        
        if let Ok(event_json) = String::from_utf8(value.to_vec()) {
            if let Ok(event) = serde_json::from_str::<serde_json::Value>(&event_json) {
                // Count by event type
                if let Some(event_type) = event.get("event_type").and_then(|v| v.as_str()) {
                    *event_types.entry(event_type.to_string()).or_insert(0) += 1;
                }
                
                // Count by severity
                if let Some(severity) = event.get("severity").and_then(|v| v.as_str()) {
                    *severities.entry(severity.to_string()).or_insert(0) += 1;
                }
            }
        }
    }
    
    println!("   Total events: {}", total_events);
    
    if !event_types.is_empty() {
        println!("\n   📊 By Event Type:");
        let mut sorted_types: Vec<_> = event_types.iter().collect();
        sorted_types.sort_by(|a, b| b.1.cmp(a.1));
        for (event_type, count) in sorted_types {
            let percentage = (*count as f64 / total_events as f64) * 100.0;
            println!("      {}: {} ({:.1}%)", event_type, count, percentage);
        }
    }
    
    if !severities.is_empty() {
        println!("\n   🚨 By Severity:");
        let severity_order = ["critical", "high", "medium", "low", "info"];
        for severity in severity_order.iter() {
            if let Some(count) = severities.get(*severity) {
                let percentage = (*count as f64 / total_events as f64) * 100.0;
                let emoji = match *severity {
                    "critical" => "🔴",
                    "high" => "🟠", 
                    "medium" => "🟡",
                    "low" => "🟢",
                    "info" => "🔵",
                    _ => "⚪"
                };
                println!("      {} {}: {} ({:.1}%)", emoji, severity, count, percentage);
            }
        }
    }
    
    Ok(())
}
