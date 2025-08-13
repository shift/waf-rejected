use anyhow::Result;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_tungstenite::{accept_async, connect_async, tungstenite::Message};
use futures_util::{StreamExt, SinkExt};
use tracing::{info, warn, error};

/// High-Performance WebSocket Benchmark
/// 
/// Tests WebSocket throughput and connection performance similar to our HTTP benchmarks
#[derive(Debug)]
struct WebSocketBenchmarkResult {
    total_connections: usize,
    successful_connections: usize,
    total_messages: u64,
    successful_messages: u64,
    total_duration: Duration,
    connections_per_second: f64,
    messages_per_second: f64,
    avg_latency: Duration,
    p95_latency: Duration,
    p99_latency: Duration,
}

/// High-performance WebSocket echo server
async fn websocket_echo_server(port: u16) -> Result<()> {
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    let listener = TcpListener::bind(&addr).await?;
    info!("High-performance WebSocket server listening on {}", addr);

    while let Ok((stream, _)) = listener.accept().await {
        tokio::spawn(async move {
            if let Err(e) = handle_websocket_connection(stream).await {
                error!("WebSocket connection error: {}", e);
            }
        });
    }
    Ok(())
}

async fn handle_websocket_connection(stream: TcpStream) -> Result<()> {
    let ws_stream = accept_async(stream).await?;
    let (mut ws_sender, mut ws_receiver) = ws_stream.split();

    while let Some(msg) = ws_receiver.next().await {
        match msg? {
            Message::Text(text) => {
                // Echo back immediately for performance
                if ws_sender.send(Message::Text(text)).await.is_err() {
                    break;
                }
            }
            Message::Binary(data) => {
                if ws_sender.send(Message::Binary(data)).await.is_err() {
                    break;
                }
            }
            Message::Ping(data) => {
                if ws_sender.send(Message::Pong(data)).await.is_err() {
                    break;
                }
            }
            Message::Close(_) => break,
            _ => {} // Ignore other message types
        }
    }
    Ok(())
}

/// Concurrent WebSocket connection benchmark
async fn run_websocket_benchmark(
    server_url: &str,
    concurrent_connections: usize,
    messages_per_connection: usize,
    message_size: usize,
) -> Result<WebSocketBenchmarkResult> {
    info!("Starting WebSocket benchmark:");
    info!("  Concurrent connections: {}", concurrent_connections);
    info!("  Messages per connection: {}", messages_per_connection);
    info!("  Message size: {} bytes", message_size);

    let start_time = Instant::now();
    let successful_connections = Arc::new(AtomicU64::new(0));
    let successful_messages = Arc::new(AtomicU64::new(0));
    let total_messages = Arc::new(AtomicU64::new(0));
    let mut latencies = Vec::new();

    // Generate test message
    let test_message = "A".repeat(message_size);
    
    // Create concurrent connection tasks
    let mut tasks = Vec::with_capacity(concurrent_connections);
    
    for _i in 0..concurrent_connections {
        let url = server_url.to_string();
        let test_message = test_message.clone();
        let successful_connections = successful_connections.clone();
        let successful_messages = successful_messages.clone();
        let total_messages = total_messages.clone();

        let task = tokio::spawn(async move {
            let mut connection_latencies = Vec::new();
            
            // Connect to WebSocket server
            match timeout(Duration::from_secs(5), connect_async(&url)).await {
                Ok(Ok((ws_stream, _))) => {
                    successful_connections.fetch_add(1, Ordering::Relaxed);
                    let (mut ws_sender, mut ws_receiver) = ws_stream.split();
                    
                    // Send messages and measure latency
                    for _ in 0..messages_per_connection {
                        let msg_start = Instant::now();
                        total_messages.fetch_add(1, Ordering::Relaxed);
                        
                        // Send message
                        if ws_sender.send(Message::Text(test_message.clone())).await.is_ok() {
                            // Wait for echo response
                            if let Some(Ok(Message::Text(_))) = ws_receiver.next().await {
                                let latency = msg_start.elapsed();
                                connection_latencies.push(latency);
                                successful_messages.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                    
                    // Close connection gracefully
                    let _ = ws_sender.send(Message::Close(None)).await;
                }
                Ok(Err(e)) => {
                    warn!("WebSocket connection failed: {}", e);
                }
                Err(_) => {
                    warn!("WebSocket connection timeout");
                }
            }
            
            connection_latencies
        });
        
        tasks.push(task);
    }

    // Wait for all tasks to complete
    for task in tasks {
        if let Ok(task_latencies) = task.await {
            latencies.extend(task_latencies);
        }
    }

    let total_duration = start_time.elapsed();
    
    // Calculate statistics
    latencies.sort();
    let avg_latency = if !latencies.is_empty() {
        latencies.iter().sum::<Duration>() / latencies.len() as u32
    } else {
        Duration::from_nanos(0)
    };
    
    let p95_latency = if !latencies.is_empty() {
        latencies[(latencies.len() as f64 * 0.95) as usize]
    } else {
        Duration::from_nanos(0)
    };
    
    let p99_latency = if !latencies.is_empty() {
        latencies[(latencies.len() as f64 * 0.99) as usize]
    } else {
        Duration::from_nanos(0)
    };

    let successful_conn_count = successful_connections.load(Ordering::Relaxed) as usize;
    let successful_msg_count = successful_messages.load(Ordering::Relaxed);
    let total_msg_count = total_messages.load(Ordering::Relaxed);
    
    let connections_per_second = successful_conn_count as f64 / total_duration.as_secs_f64();
    let messages_per_second = successful_msg_count as f64 / total_duration.as_secs_f64();

    Ok(WebSocketBenchmarkResult {
        total_connections: concurrent_connections,
        successful_connections: successful_conn_count,
        total_messages: total_msg_count,
        successful_messages: successful_msg_count,
        total_duration,
        connections_per_second,
        messages_per_second,
        avg_latency,
        p95_latency,
        p99_latency,
    })
}

fn print_benchmark_results(result: &WebSocketBenchmarkResult) {
    println!("\n🚀 WebSocket Performance Benchmark Results");
    println!("==========================================");
    
    println!("📊 Connection Statistics:");
    println!("  Total Connections: {}", result.total_connections);
    println!("  Successful Connections: {}", result.successful_connections);
    println!("  Connection Success Rate: {:.1}%", 
        (result.successful_connections as f64 / result.total_connections as f64) * 100.0);
    println!("  Connections per Second: {:.1} conn/s", result.connections_per_second);
    
    println!("\n📈 Message Statistics:");
    println!("  Total Messages: {}", result.total_messages);
    println!("  Successful Messages: {}", result.successful_messages);
    println!("  Message Success Rate: {:.1}%", 
        (result.successful_messages as f64 / result.total_messages as f64) * 100.0);
    println!("  Messages per Second: {:.1} msg/s", result.messages_per_second);
    
    println!("\n⚡ Latency Statistics:");
    println!("  Average Latency: {:.2}ms", result.avg_latency.as_secs_f64() * 1000.0);
    println!("  95th Percentile: {:.2}ms", result.p95_latency.as_secs_f64() * 1000.0);
    println!("  99th Percentile: {:.2}ms", result.p99_latency.as_secs_f64() * 1000.0);
    
    println!("\n🕒 Timing:");
    println!("  Total Duration: {:.2}s", result.total_duration.as_secs_f64());
    
    // Performance grade based on messages per second
    let grade = match result.messages_per_second {
        x if x >= 10000.0 => "A+ (Excellent - 10K+ msg/s)",
        x if x >= 5000.0 => "A (Very Good - 5K+ msg/s)",
        x if x >= 2500.0 => "B+ (Good - 2.5K+ msg/s)",
        x if x >= 1000.0 => "B (Acceptable - 1K+ msg/s)",
        x if x >= 500.0 => "C (Below Expected - 500+ msg/s)",
        _ => "F (Poor - <500 msg/s)"
    };
    
    println!("\n🎖️  Performance Grade: {}", grade);
    // Explicit 10K threshold check
    println!(
        "✅ 10K msg/s threshold: {}",
        if result.messages_per_second >= 10_000.0 { "ACHIEVED" } else { "NOT MET" }
    );
    
    // Compare with HTTP performance
    let http_rps = 2533.0; // Our baseline HTTP RPS
    let efficiency = (result.messages_per_second / http_rps) * 100.0;
    println!("📊 Efficiency vs HTTP: {:.1}% ({:.1} msg/s vs {:.1} req/s)", 
        efficiency, result.messages_per_second, http_rps);
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    println!("🚀 WebSocket High-Performance Benchmark Suite");
    println!("==============================================");
    
    // Start WebSocket echo server
    let server_port = 8086;
    let server_url = format!("ws://127.0.0.1:{}", server_port);
    
    tokio::spawn(async move {
        if let Err(e) = websocket_echo_server(server_port).await {
            error!("WebSocket server error: {}", e);
        }
    });

    // Give server time to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Run progressive benchmarks
    let benchmarks = vec![
        ("Light Load", 10, 100, 64),        // 10 connections, 100 msgs, 64 bytes
        ("Medium Load", 50, 100, 256),      // 50 connections, 100 msgs, 256 bytes
        ("Heavy Load", 100, 100, 512),      // 100 connections, 100 msgs, 512 bytes
        ("Stress Test", 200, 50, 1024),     // 200 connections, 50 msgs, 1KB
        // Added heavier scenarios to validate 10K+ msg/s capability
        ("Ultra Load", 400, 100, 128),      // 400 connections, 100 msgs, 128 bytes
        ("10K Threshold Check", 200, 200, 128), // 200 connections, 200 msgs, 128 bytes
    ];

    for (test_name, connections, messages, size) in benchmarks {
        println!("\n🔥 Running {} Test", test_name);
        println!("   {} concurrent connections", connections);
        println!("   {} messages per connection", messages);
        println!("   {} bytes per message", size);
        
        match run_websocket_benchmark(&server_url, connections, messages, size).await {
            Ok(result) => print_benchmark_results(&result),
            Err(e) => error!("Benchmark failed: {}", e),
        }
        
        // Brief pause between tests
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    Ok(())
}
