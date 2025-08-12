use anyhow::Result;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, timeout};
use tokio_tungstenite::{accept_async, connect_async, tungstenite::Message};
use futures_util::{StreamExt, SinkExt};
use tracing::{debug, error, info, warn};

/// WebSocket attack patterns to test WAF detection
const WEBSOCKET_ATTACK_PATTERNS: &[(&str, &str, bool)] = &[
    // (name, payload, should_be_blocked)
    ("sql_injection_basic", "' OR 1=1 --", true),
    ("sql_injection_union", "UNION SELECT password FROM users", true),
    ("xss_script", "<script>alert('xss')</script>", true),
    ("xss_event_handler", "<img src=x onerror=alert('xss')>", true),
    ("lfi_basic", "../../../etc/passwd", true),
    ("lfi_null_byte", "../../../etc/passwd%00", true),
    ("rce_command", "cat /etc/passwd", true),
    ("rce_system", "system('cat /etc/passwd')", true),
    ("xxe_attack", "<!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM \"file:///etc/passwd\" >]>", true),
    ("ldap_injection", ")(|(objectClass=*))", true),
    ("command_injection", "; cat /etc/passwd", true),
    ("path_traversal", "....//....//....//etc/passwd", true),
    ("malicious_json", "{\"eval\": \"require('child_process').exec('rm -rf /')\"}", true),
    ("binary_exploit", "NOP_NOP_NOP_NOP_XOR_EAX_PUSH_EAX", true),
    ("legitimate_message", "Hello, this is a normal WebSocket message", false),
    ("json_data", "{\"user\": \"alice\", \"message\": \"hello world\"}", false),
    ("empty_message", "", false),
    ("ping_pong", "ping", false),
    ("chat_message", "User: How are you today?", false),
];

#[derive(Debug)]
struct WebSocketTestResult {
    name: String,
    payload: String,
    expected_blocked: bool,
    was_blocked: bool,
    response_time: Duration,
    error: Option<String>,
}

#[derive(Debug)]
struct WebSocketTestSummary {
    total_tests: usize,
    passed: usize,
    failed: usize,
    blocked_correctly: usize,
    allowed_correctly: usize,
    false_positives: usize,
    false_negatives: usize,
    avg_response_time: Duration,
    total_duration: Duration,
}

/// WebSocket echo server for testing
async fn websocket_echo_server(port: u16) -> Result<()> {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = TcpListener::bind(&addr).await?;
    info!("WebSocket echo server listening on {}", addr);

    while let Ok((stream, _)) = listener.accept().await {
        tokio::spawn(handle_websocket_connection(stream));
    }
    Ok(())
}

async fn handle_websocket_connection(stream: TcpStream) -> Result<()> {
    let ws_stream = accept_async(stream).await?;
    let (mut ws_sender, mut ws_receiver) = ws_stream.split();

    while let Some(msg) = ws_receiver.next().await {
        match msg? {
            Message::Text(text) => {
                debug!("Received text: {}", text);
                // Echo back the message
                ws_sender.send(Message::Text(format!("Echo: {}", text))).await?;
            }
            Message::Binary(data) => {
                debug!("Received binary data: {} bytes", data.len());
                ws_sender.send(Message::Binary(data)).await?;
            }
            Message::Close(_) => {
                info!("WebSocket connection closed");
                break;
            }
            Message::Ping(data) => {
                debug!("Received ping, sending pong");
                ws_sender.send(Message::Pong(data)).await?;
            }
            Message::Pong(_) => {
                debug!("Received pong");
            }
            Message::Frame(_) => {
                warn!("Received raw frame, ignoring");
            }
        }
    }
    Ok(())
}

async fn test_websocket_waf() -> Result<WebSocketTestSummary> {
    info!("🚀 Starting WebSocket WAF Testing Suite");
    let start_time = Instant::now();

    // Start echo server
    let echo_port = 8085;
    tokio::spawn(async move {
        if let Err(e) = websocket_echo_server(echo_port).await {
            error!("Echo server error: {}", e);
        }
    });

    // Give server time to start
    sleep(Duration::from_millis(100)).await;

    let mut results = Vec::new();
    let echo_url = format!("ws://127.0.0.1:{}", echo_port);

    info!("Testing {} attack patterns against WebSocket WAF", WEBSOCKET_ATTACK_PATTERNS.len());

    for (i, &(name, payload, expected_blocked)) in WEBSOCKET_ATTACK_PATTERNS.iter().enumerate() {
        info!("Test {}/{}: {}", i + 1, WEBSOCKET_ATTACK_PATTERNS.len(), name);
        
        let result = test_websocket_payload(&echo_url, name, payload, expected_blocked).await;
        results.push(result);

        // Small delay between tests
        sleep(Duration::from_millis(10)).await;
    }

    let summary = calculate_summary(results, start_time.elapsed());
    print_detailed_results(&summary);
    
    Ok(summary)
}

async fn test_websocket_payload(
    url: &str,
    name: &str,
    payload: &str,
    expected_blocked: bool,
) -> WebSocketTestResult {
    let start = Instant::now();
    
    // For this test, we'll simulate WAF behavior by connecting directly
    // In a real scenario, this would go through the WAF proxy
    match timeout(Duration::from_secs(5), connect_to_websocket(url, payload)).await {
        Ok(Ok(was_blocked)) => WebSocketTestResult {
            name: name.to_string(),
            payload: payload.to_string(),
            expected_blocked,
            was_blocked,
            response_time: start.elapsed(),
            error: None,
        },
        Ok(Err(e)) => WebSocketTestResult {
            name: name.to_string(),
            payload: payload.to_string(),
            expected_blocked,
            was_blocked: true, // Connection failed, assume blocked
            response_time: start.elapsed(),
            error: Some(e.to_string()),
        },
        Err(_) => WebSocketTestResult {
            name: name.to_string(),
            payload: payload.to_string(),
            expected_blocked,
            was_blocked: true, // Timeout, assume blocked
            response_time: Duration::from_secs(5),
            error: Some("Timeout".to_string()),
        },
    }
}

async fn connect_to_websocket(url: &str, payload: &str) -> Result<bool> {
    let (ws_stream, _) = connect_async(url).await?;
    let (mut ws_sender, mut ws_receiver) = ws_stream.split();

    // Send the test payload
    ws_sender.send(Message::Text(payload.to_string())).await?;

    // Wait for response or timeout
    match timeout(Duration::from_millis(500), ws_receiver.next()).await {
        Ok(Some(Ok(Message::Text(response)))) => {
            debug!("Received response: {}", response);
            // If we get a normal response, the message was not blocked
            Ok(false)
        }
        Ok(Some(Ok(Message::Close(_)))) => {
            // Connection was closed, likely blocked
            Ok(true)
        }
        Ok(Some(Err(_))) | Ok(None) | Err(_) => {
            // Error or timeout, assume blocked
            Ok(true)
        }
        Ok(Some(Ok(_))) => {
            // Other message types, assume not blocked
            Ok(false)
        }
    }
}

fn calculate_summary(results: Vec<WebSocketTestResult>, total_duration: Duration) -> WebSocketTestSummary {
    let total_tests = results.len();
    let mut passed = 0;
    let mut blocked_correctly = 0;
    let mut allowed_correctly = 0;
    let mut false_positives = 0;
    let mut false_negatives = 0;
    let mut total_response_time = Duration::from_millis(0);

    for result in &results {
        total_response_time += result.response_time;
        
        if result.expected_blocked == result.was_blocked {
            passed += 1;
            if result.was_blocked {
                blocked_correctly += 1;
            } else {
                allowed_correctly += 1;
            }
        } else if result.expected_blocked && !result.was_blocked {
            false_negatives += 1;
        } else if !result.expected_blocked && result.was_blocked {
            false_positives += 1;
        }
    }

    let failed = total_tests - passed;
    let avg_response_time = if total_tests > 0 {
        total_response_time / total_tests as u32
    } else {
        Duration::from_millis(0)
    };

    WebSocketTestSummary {
        total_tests,
        passed,
        failed,
        blocked_correctly,
        allowed_correctly,
        false_positives,
        false_negatives,
        avg_response_time,
        total_duration,
    }
}

fn print_detailed_results(summary: &WebSocketTestSummary) {
    println!("\n🎯 WebSocket WAF Test Results");
    println!("=============================");
    println!("Total Tests: {}", summary.total_tests);
    println!("Passed: {} ({:.1}%)", summary.passed, (summary.passed as f64 / summary.total_tests as f64) * 100.0);
    println!("Failed: {} ({:.1}%)", summary.failed, (summary.failed as f64 / summary.total_tests as f64) * 100.0);
    println!();
    println!("🛡️  Security Metrics:");
    println!("  Correctly Blocked: {}", summary.blocked_correctly);
    println!("  Correctly Allowed: {}", summary.allowed_correctly);
    println!("  False Positives: {}", summary.false_positives);
    println!("  False Negatives: {}", summary.false_negatives);
    println!();
    println!("⚡ Performance:");
    println!("  Average Response Time: {:.2}ms", summary.avg_response_time.as_secs_f64() * 1000.0);
    println!("  Total Duration: {:.2}s", summary.total_duration.as_secs_f64());

    let security_score = if summary.total_tests > 0 {
        (summary.passed as f64 / summary.total_tests as f64) * 100.0
    } else {
        0.0
    };

    println!("\n🎖️  Overall Security Score: {:.1}%", security_score);
    
    let grade = match security_score as u8 {
        90..=100 => "A+ (Excellent)",
        80..=89 => "A (Very Good)",
        70..=79 => "B (Good)",
        60..=69 => "C (Acceptable)",
        50..=59 => "D (Poor)",
        _ => "F (Failing)"
    };
    
    println!("🏆 Grade: {}", grade);
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    match test_websocket_waf().await {
        Ok(summary) => {
            if summary.failed == 0 && summary.false_negatives == 0 {
                println!("✅ All WebSocket WAF tests passed!");
                std::process::exit(0);
            } else {
                println!("❌ Some WebSocket WAF tests failed!");
                std::process::exit(1);
            }
        }
        Err(e) => {
            error!("WebSocket WAF testing failed: {}", e);
            std::process::exit(1);
        }
    }
}
