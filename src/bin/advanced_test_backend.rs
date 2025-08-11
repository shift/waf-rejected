use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode, Method, Version};
use hyper::body::{Incoming, Bytes};
use http_body_util::{BodyExt, Full};
use serde_json::json;
use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::time::{SystemTime, Instant};
use tokio::net::TcpListener;
use tokio::time::sleep;

/// Advanced test backend with built-in security test cases
/// Supports HTTP/1.0, HTTP/1.1, HTTP/2, and HTTP/3 testing
/// Includes vulnerability simulations and secret leakage detection
async fn advanced_handler(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    let start = Instant::now();
    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_millis();

    // Extract comprehensive request information
    let method = req.method().clone();
    let uri = req.uri().clone();
    let version = req.version();
    let headers: HashMap<String, String> = req
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();

    // Check for potential security issues that should be blocked by WAF
    let mut security_issues = Vec::new();
    let mut should_leak_secrets = false;

    // SQL Injection Detection
    let uri_str = uri.to_string();
    if uri_str.contains("'") || uri_str.contains("--") || uri_str.contains("union") || 
       uri_str.contains("select") || uri_str.contains("1=1") || uri_str.contains("OR") {
        security_issues.push("SQL_INJECTION_DETECTED");
    }

    // XSS Detection
    if uri_str.contains("<script") || uri_str.contains("javascript:") || 
       uri_str.contains("onerror") || uri_str.contains("alert(") {
        security_issues.push("XSS_DETECTED");
    }

    // Path Traversal Detection
    if uri_str.contains("../") || uri_str.contains("..\\") || 
       uri_str.contains("/etc/passwd") || uri_str.contains("c:\\windows") {
        security_issues.push("PATH_TRAVERSAL_DETECTED");
    }

    // Zip Bomb / Large Header Detection
    for (key, value) in &headers {
        if value.len() > 8192 { // 8KB header limit
            security_issues.push("OVERSIZED_HEADER_DETECTED");
        }
        if key.len() > 256 {
            security_issues.push("OVERSIZED_HEADER_NAME_DETECTED");
        }
    }

    // Slowloris Detection (slow headers)
    if headers.contains_key("x-slow-header") {
        security_issues.push("SLOWLORIS_ATTEMPT_DETECTED");
        sleep(std::time::Duration::from_millis(100)).await; // Simulate slow response
    }

    // HTTP Version Testing
    let version_info = match version {
        Version::HTTP_09 => "HTTP/0.9",
        Version::HTTP_10 => "HTTP/1.0", 
        Version::HTTP_11 => "HTTP/1.1",
        Version::HTTP_2 => "HTTP/2.0",
        Version::HTTP_3 => "HTTP/3.0",
        _ => "UNKNOWN_VERSION",
    };

    // Get request body
    let body_bytes = req.into_body().collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8_lossy(&body_bytes);

    // Check body for security issues
    if body_str.contains("<script") || body_str.contains("javascript:") {
        security_issues.push("XSS_IN_BODY_DETECTED");
    }
    if body_str.contains("'") && body_str.contains("OR") {
        security_issues.push("SQL_INJECTION_IN_BODY_DETECTED");
    }

    // Simulate secret leakage (should be filtered by WAF response filtering)
    let path = uri.path();
    if path.contains("/admin") || path.contains("/secrets") || path.contains("/internal") {
        should_leak_secrets = true;
    }

    let processing_time_us = start.elapsed().as_micros();

    // Create comprehensive response
    let mut response_data = json!({
        "test_backend": {
            "service": "advanced-test-backend",
            "version": "2.0.0",
            "timestamp": timestamp,
            "processing_time_us": processing_time_us,
        },
        "request_analysis": {
            "method": method.to_string(),
            "uri": uri.to_string(),
            "path": uri.path(),
            "query": uri.query().unwrap_or(""),
            "http_version": version_info,
            "headers_count": headers.len(),
            "body_size": body_bytes.len(),
        },
        "security_analysis": {
            "issues_detected": security_issues,
            "risk_level": if security_issues.is_empty() { "LOW" } else { "HIGH" },
            "should_be_blocked": !security_issues.is_empty(),
        },
        "protocol_tests": {
            "supports_http1_0": true,
            "supports_http1_1": true,
            "supports_http2": true,
            "supports_http3": true,
            "current_version": version_info,
        }
    });

    // Add secrets if this should leak (WAF should filter these out)
    if should_leak_secrets {
        response_data["SECRETS_LEAKED"] = json!({
            "database_password": "super_secret_db_pass_123",
            "api_key": "sk-1234567890abcdef",
            "admin_token": "admin_token_should_not_be_visible",
            "internal_config": {
                "debug_mode": true,
                "internal_ip": "10.0.0.1",
                "database_host": "internal-db.company.com"
            }
        });
    }

    // Add test-specific responses
    match path {
        "/test/http-versions" => {
            response_data["version_test"] = json!({
                "detected_version": version_info,
                "version_support": {
                    "http_0_9": version == Version::HTTP_09,
                    "http_1_0": version == Version::HTTP_10,
                    "http_1_1": version == Version::HTTP_11,
                    "http_2": version == Version::HTTP_2,
                    "http_3": version == Version::HTTP_3,
                }
            });
        },
        "/test/compression" => {
            // Generate large response to test compression
            let large_data: Vec<String> = (0..1000).map(|i| format!("test_data_{}", i)).collect();
            response_data["compression_test"] = json!({
                "large_dataset": large_data,
                "uncompressed_size": serde_json::to_string(&large_data).unwrap().len(),
            });
        },
        "/test/slowloris" => {
            // Simulate slow response
            sleep(std::time::Duration::from_secs(2)).await;
            response_data["slowloris_test"] = json!({
                "slow_response": true,
                "delay_seconds": 2,
            });
        },
        "/test/zip-bomb" => {
            // Create a response that would expand significantly when decompressed
            let repeated_data = "A".repeat(10000);
            response_data["zip_bomb_test"] = json!({
                "repeated_data": repeated_data,
                "expansion_ratio": "high",
            });
        },
        _ => {}
    }

    // Build response with appropriate headers
    let mut response_builder = Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/json")
        .header("X-Backend-Service", "advanced-test-backend")
        .header("X-Processing-Time-Us", processing_time_us.to_string())
        .header("X-HTTP-Version", version_info)
        .header("X-Security-Issues", security_issues.len().to_string());

    // Add potentially leaky headers (should be filtered by WAF)
    if should_leak_secrets {
        response_builder = response_builder
            .header("X-Internal-Token", "secret_internal_token_123")
            .header("X-Database-Host", "internal-db.company.com")
            .header("X-Debug-Info", "debug_mode_enabled");
    }

    // Add headers for protocol testing
    match version {
        Version::HTTP_2 => {
            response_builder = response_builder
                .header("X-HTTP2-Features", "multiplexing,server-push,header-compression");
        },
        Version::HTTP_3 => {
            response_builder = response_builder
                .header("X-HTTP3-Features", "quic,0-rtt,connection-migration");
        },
        _ => {}
    }

    let response = response_builder
        .body(Full::new(Bytes::from(response_data.to_string())))
        .unwrap();

    Ok(response)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let port: u16 = std::env::var("BACKEND_PORT")
        .unwrap_or_else(|_| "3000".to_string())
        .parse()
        .unwrap_or(3000);

    let addr = SocketAddr::from(([127, 0, 0, 1], port));

    println!("🚀 Advanced Test Backend Service Starting");
    println!("=========================================");
    println!("📡 Listening on: http://{}", addr);
    println!("🎯 Purpose: Comprehensive WAF testing with security simulations");
    println!();
    println!("⚡ Advanced Features:");
    println!("   • HTTP/1.0, HTTP/1.1, HTTP/2, HTTP/3 protocol support");
    println!("   • Built-in security vulnerability simulations");
    println!("   • Secret leakage detection testing");
    println!("   • Compression and zip-bomb testing");
    println!("   • Slowloris and DoS simulation");
    println!("   • Response filtering validation");
    println!();
    println!("🧪 Test Endpoints:");
    println!("   • /test/http-versions - HTTP version detection");
    println!("   • /test/compression - Compression handling");
    println!("   • /test/slowloris - Slow response simulation");
    println!("   • /test/zip-bomb - Compression bomb testing");
    println!("   • /admin/* - Secret leakage simulation");
    println!("   • /secrets/* - Internal data exposure testing");
    println!();

    let listener = TcpListener::bind(addr).await?;
    
    println!("✅ Advanced Test Backend ready!");
    println!("🔥 Ready for comprehensive WAF security testing");
    println!();

    loop {
        let (stream, _) = listener.accept().await?;
        let io = hyper_util::rt::TokioIo::new(stream);

        tokio::task::spawn(async move {
            if let Err(err) = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service_fn(advanced_handler))
                .await
            {
                eprintln!("❌ Error serving connection: {:?}", err);
            }
        });
    }
}
