use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper::body::{Incoming, Bytes};
use http_body_util::{BodyExt, Full};
use serde_json::json;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::time::SystemTime;
use tokio::time::Instant;
use tokio::net::TcpListener;

/// Simple echo backend service for WAF testing
/// Returns request details and performance metrics
async fn echo_handler(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    let start = Instant::now();
    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_millis();

    // Extract request information
    let method = req.method().to_string();
    let uri = req.uri().to_string();
    let headers: std::collections::HashMap<String, String> = req
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();

    // Get request body
    let body_bytes = req.into_body().collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8_lossy(&body_bytes);

    let processing_time_us = start.elapsed().as_micros();

    // Create echo response
    let response_body = json!({
        "echo": {
            "method": method,
            "uri": uri,
            "headers": headers,
            "body": body_str,
            "timestamp": timestamp,
            "processing_time_us": processing_time_us,
        },
        "backend": {
            "service": "echo-backend",
            "version": "1.0.0",
            "status": "healthy"
        }
    });

    // Add some artificial processing time (0.1ms) to simulate real backend work
    tokio::time::sleep(tokio::time::Duration::from_micros(100)).await;

    let response = Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/json")
        .header("X-Backend-Service", "echo-backend")
        .header("X-Processing-Time-Us", processing_time_us.to_string())
        .body(Full::new(Bytes::from(response_body.to_string())))
        .unwrap();

    Ok(response)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Default to port 3000, but allow override via environment
    let port: u16 = std::env::var("BACKEND_PORT")
        .unwrap_or_else(|_| "3000".to_string())
        .parse()
        .unwrap_or(3000);

    let addr = SocketAddr::from(([127, 0, 0, 1], port));

    println!("🚀 Echo Backend Service Starting");
    println!("================================");
    println!("📡 Listening on: http://{}", addr);
    println!("🎯 Purpose: High-performance echo service for WAF testing");
    println!("⚡ Features:");
    println!("   • Request/Response echo with full details");
    println!("   • Performance timing metrics");
    println!("   • JSON structured responses");
    println!("   • Artificial 0.1ms processing delay");
    println!();

    let listener = TcpListener::bind(addr).await?;
    
    println!("✅ Echo Backend ready for WAF testing!");
    println!("🔥 Send requests to test the full WAF → Backend pipeline");
    println!();

    loop {
        let (stream, _) = listener.accept().await?;
        let io = hyper_util::rt::TokioIo::new(stream);

        tokio::task::spawn(async move {
            if let Err(err) = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service_fn(echo_handler))
                .await
            {
                eprintln!("❌ Error serving connection: {:?}", err);
            }
        });
    }
}
