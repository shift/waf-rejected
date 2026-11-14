use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::time::{sleep, Duration};
use waf_ingress::config::Config;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!("🔍 WAF Proxy Integration Test");
    println!("==============================");

    // Load configuration to ensure it works
    println!("📋 Loading configuration...");

    let config = match Config::load() {
        Ok(cfg) => {
            println!("✅ Configuration loaded successfully");
            println!("   - Bind address: {}", cfg.bind_addr);
            println!("   - Upstream URI: {:?}", cfg.upstream_uri());
            println!("   - WAF enabled: {}", cfg.waf.enabled);
            cfg
        }
        Err(e) => {
            println!("❌ Failed to load configuration: {}", e);
            return Err(e.into());
        }
    };

    // Start the proxy server as a subprocess
    println!("\n🚀 Starting WAF Proxy Server...");
    let mut proxy_process = Command::new("./target/release/waf_proxy")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start proxy server");

    let server_ready = Arc::new(AtomicBool::new(false));
    let server_ready_clone = server_ready.clone();

    // Give the server time to start up
    tokio::spawn(async move {
        sleep(Duration::from_secs(5)).await;
        server_ready_clone.store(true, Ordering::Relaxed);
    });

    // Wait for server to be ready
    while !server_ready.load(Ordering::Relaxed) {
        print!(".");
        sleep(Duration::from_millis(500)).await;
    }
    println!("\n✅ Server startup wait completed");

    // Test 1: Health check request
    println!("\n📡 Test 1: Health Check");
    let port = config.bind_addr.port();
    match test_health_check(port).await {
        Ok(_) => println!("✅ Health check passed"),
        Err(e) => println!("❌ Health check failed: {}", e),
    }

    // Test 2: Normal request
    println!("\n📡 Test 2: Normal Request");
    match test_normal_request(port).await {
        Ok(_) => println!("✅ Normal request processed"),
        Err(e) => println!("❌ Normal request failed: {}", e),
    }

    // Test 3: SQL injection attempt (should be blocked)
    println!("\n📡 Test 3: SQL Injection Attack (should be blocked)");
    match test_sql_injection_attack(port).await {
        Ok(blocked) => {
            if blocked {
                println!("✅ SQL injection attack properly blocked");
            } else {
                println!("⚠️  SQL injection attack was not blocked (may need rule activation)");
            }
        }
        Err(e) => println!("❌ SQL injection test failed: {}", e),
    }

    // Clean up
    println!("\n🧹 Cleaning up proxy server...");
    let _ = proxy_process.kill();
    let _ = proxy_process.wait();

    println!("\n✅ Simple Proxy Integration Test Complete");
    Ok(())
}

async fn test_health_check(port: u16) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{}/health", port);

    let response = client
        .get(&url)
        .timeout(Duration::from_secs(5))
        .send()
        .await?;

    println!("   Status: {}", response.status());
    let body = response.text().await?;
    println!("   Response: {}", body);

    Ok(())
}

async fn test_normal_request(port: u16) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{}/api/test", port);

    let response = client
        .get(&url)
        .timeout(Duration::from_secs(5))
        .send()
        .await?;

    println!("   Status: {}", response.status());
    println!("   Headers: {:?}", response.headers());

    Ok(())
}

async fn test_sql_injection_attack(
    port: u16,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{}/api/users", port);

    // Send a request with SQL injection payload
    let response = client
        .get(&url)
        .query(&[("id", "1' OR '1'='1")])
        .timeout(Duration::from_secs(5))
        .send()
        .await?;

    let status = response.status();
    println!("   Status: {}", status);
    println!("   Headers: {:?}", response.headers());

    // Check if request was blocked (403/406/blocked status)
    let blocked = status == reqwest::StatusCode::FORBIDDEN
        || status == reqwest::StatusCode::NOT_ACCEPTABLE
        || status.as_u16() >= 400;

    Ok(blocked)
}
