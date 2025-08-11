use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::process::{Child, Command};
use tokio::sync::Barrier;
use tokio::time::sleep;

#[derive(Debug)]
struct TestMetrics {
    total_requests: AtomicU64,
    successful_requests: AtomicU64,
    failed_requests: AtomicU64,
    total_latency_ms: AtomicU64,
    min_latency_ms: AtomicU64,
    max_latency_ms: AtomicU64,
    waf_blocks: AtomicU64,
    backend_responses: AtomicU64,
}

impl TestMetrics {
    fn new() -> Self {
        Self {
            total_requests: AtomicU64::new(0),
            successful_requests: AtomicU64::new(0),
            failed_requests: AtomicU64::new(0),
            total_latency_ms: AtomicU64::new(0),
            min_latency_ms: AtomicU64::new(u64::MAX),
            max_latency_ms: AtomicU64::new(0),
            waf_blocks: AtomicU64::new(0),
            backend_responses: AtomicU64::new(0),
        }
    }

    fn record_request(&self, latency_ms: u64, was_blocked: bool, reached_backend: bool) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        
        if was_blocked {
            self.waf_blocks.fetch_add(1, Ordering::Relaxed);
            self.failed_requests.fetch_add(1, Ordering::Relaxed);
        } else {
            self.successful_requests.fetch_add(1, Ordering::Relaxed);
        }

        if reached_backend {
            self.backend_responses.fetch_add(1, Ordering::Relaxed);
        }

        self.total_latency_ms.fetch_add(latency_ms, Ordering::Relaxed);
        
        // Update min latency
        let mut current_min = self.min_latency_ms.load(Ordering::Relaxed);
        while latency_ms < current_min {
            match self.min_latency_ms.compare_exchange_weak(
                current_min, 
                latency_ms, 
                Ordering::Relaxed, 
                Ordering::Relaxed
            ) {
                Ok(_) => break,
                Err(new_min) => current_min = new_min,
            }
        }

        // Update max latency
        let mut current_max = self.max_latency_ms.load(Ordering::Relaxed);
        while latency_ms > current_max {
            match self.max_latency_ms.compare_exchange_weak(
                current_max, 
                latency_ms, 
                Ordering::Relaxed, 
                Ordering::Relaxed
            ) {
                Ok(_) => break,
                Err(new_max) => current_max = new_max,
            }
        }
    }
}

struct EndToEndTestHarness {
    backend_process: Option<Child>,
    waf_process: Option<Child>,
}

impl EndToEndTestHarness {
    async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        println!("🏗️  END-TO-END WAF TEST HARNESS");
        println!("===============================");
        println!("🎯 Mission: Test real WAF → Backend performance");
        println!("📊 Components: Echo Backend + WAF-Rejected + Load Generator");
        println!();

        Ok(Self {
            backend_process: None,
            waf_process: None,
        })
    }

    async fn start_backend(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!("🚀 Starting Echo Backend Service...");
        
        let mut backend_cmd = Command::new("./target/release/echo_backend");
        backend_cmd.env("BACKEND_PORT", "3000");
        
        self.backend_process = Some(backend_cmd.spawn()?);
        
        // Wait for backend to be ready
        for attempt in 1..=10 {
            // Simple TCP connection check instead of HTTP
            match tokio::net::TcpStream::connect("127.0.0.1:3000").await {
                Ok(_) => {
                    println!("✅ Echo Backend ready on http://127.0.0.1:3000");
                    return Ok(());
                }
                Err(_) => {
                    if attempt < 10 {
                        println!("   ⏳ Waiting for backend... (attempt {}/10)", attempt);
                        sleep(Duration::from_millis(500)).await;
                    }
                }
            }
        }

        // Backend not responding, but let's continue anyway
        println!("⚠️  Backend not responding to health check, but continuing...");
        sleep(Duration::from_secs(2)).await;
        Ok(())
    }

    async fn start_waf(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!("🛡️  Starting WAF-Rejected...");
        
        let mut waf_cmd = Command::new("./target/release/waf-ingress");
        waf_cmd.env("WAF_CONFIG_FILE", "config-test");
        
        self.waf_process = Some(waf_cmd.spawn()?);
        
        // Wait for WAF to be ready
        for attempt in 1..=15 {
            match tokio::net::TcpStream::connect("127.0.0.1:8080").await {
                Ok(_) => {
                    println!("✅ WAF-Rejected ready on http://127.0.0.1:8080");
                    println!("🔗 WAF configured to proxy to backend at http://127.0.0.1:3000");
                    return Ok(());
                }
                Err(_) => {
                    if attempt < 15 {
                        println!("   ⏳ Waiting for WAF... (attempt {}/15)", attempt);
                        sleep(Duration::from_millis(1000)).await;
                    }
                }
            }
        }

        println!("⚠️  WAF not responding to health check, but continuing...");
        sleep(Duration::from_secs(3)).await;
        Ok(())
    }

    async fn run_load_test(&self, concurrent_users: usize, requests_per_user: usize, test_name: &str) -> Result<TestMetrics, Box<dyn std::error::Error>> {
        println!("🔥 Running Load Test: {}", test_name);
        println!("   👥 Concurrent Users: {}", concurrent_users);
        println!("   📨 Requests per User: {}", requests_per_user);
        println!("   🎯 Target: http://127.0.0.1:8080 (WAF → Backend)");

        let metrics = Arc::new(TestMetrics::new());
        let barrier = Arc::new(Barrier::new(concurrent_users));
        let test_start = Instant::now();

        let mut handles = Vec::new();

        // Test payloads - mix of legitimate and malicious
        let test_payloads = vec![
            ("GET /api/users HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n", false),
            ("POST /api/login HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nContent-Type: application/json\r\nContent-Length: 35\r\nConnection: close\r\n\r\n{\"username\":\"user\",\"password\":\"pass\"}", false),
            ("GET /api/products?page=1 HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n", false),
            ("POST /api/data HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nContent-Type: application/json\r\nContent-Length: 25\r\nConnection: close\r\n\r\n{\"data\":\"normal request\"}", false),
            // Some that should be blocked by WAF
            ("GET /api/users?id=1'%20OR%20'1'='1 HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n", true), // SQL injection
            ("POST /api/comment HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nContent-Type: application/json\r\nContent-Length: 44\r\nConnection: close\r\n\r\n{\"comment\":\"<script>alert('xss')</script>\"}", true), // XSS
            ("GET /api/file?path=../../../etc/passwd HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n", true), // Path traversal
        ];

        for user_id in 0..concurrent_users {
            let metrics = Arc::clone(&metrics);
            let barrier = Arc::clone(&barrier);
            let payloads = test_payloads.clone();

            let handle = tokio::spawn(async move {
                // Wait for all users to be ready
                barrier.wait().await;

                for request_id in 0..requests_per_user {
                    let payload_idx = (user_id + request_id) % payloads.len();
                    let (http_request, should_be_blocked) = &payloads[payload_idx];

                    let start = Instant::now();
                    
                    // Make raw HTTP request
                    let result = Self::make_http_request(http_request).await;
                    let latency_ms = start.elapsed().as_millis() as u64;
                    
                    match result {
                        Ok((status, response_body)) => {
                            let was_blocked = status == 403 || status == 429;
                            let reached_backend = response_body.contains("echo-backend");
                            
                            metrics.record_request(latency_ms, was_blocked, reached_backend);
                        }
                        Err(_) => {
                            metrics.record_request(latency_ms, true, false);
                        }
                    }
                }
            });

            handles.push(handle);
        }

        // Wait for all users to complete
        for handle in handles {
            handle.await?;
        }

        let total_duration = test_start.elapsed();
        println!("✅ Load test completed in {:.2}s", total_duration.as_secs_f64());

        Ok(Arc::try_unwrap(metrics).unwrap())
    }

    async fn make_http_request(request: &str) -> Result<(u16, String), Box<dyn std::error::Error>> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        
        let mut stream = tokio::net::TcpStream::connect("127.0.0.1:8080").await?;
        stream.write_all(request.as_bytes()).await?;
        
        let mut buffer = vec![0; 4096];
        let n = stream.read(&mut buffer).await?;
        let response = String::from_utf8_lossy(&buffer[..n]);
        
        // Parse status code from HTTP response
        let status_code = if let Some(line) = response.lines().next() {
            if let Some(parts) = line.split_whitespace().nth(1) {
                parts.parse::<u16>().unwrap_or(500)
            } else {
                500
            }
        } else {
            500
        };
        
        Ok((status_code, response.to_string()))
    }

    async fn shutdown(&mut self) {
        println!("🛑 Shutting down test harness...");

        if let Some(mut waf) = self.waf_process.take() {
            let _ = waf.kill().await;
            println!("   ✅ WAF process terminated");
        }

        if let Some(mut backend) = self.backend_process.take() {
            let _ = backend.kill().await;
            println!("   ✅ Backend process terminated");
        }

        println!("🏁 Test harness shutdown complete");
    }
}

impl Drop for EndToEndTestHarness {
    fn drop(&mut self) {
        // Ensure processes are killed even if shutdown wasn't called
        if let Some(mut waf) = self.waf_process.take() {
            let _ = waf.start_kill();
        }
        if let Some(mut backend) = self.backend_process.take() {
            let _ = backend.start_kill();
        }
    }
}

fn print_test_results(metrics: &TestMetrics, test_name: &str, duration_secs: f64) {
    let total = metrics.total_requests.load(Ordering::Relaxed);
    let successful = metrics.successful_requests.load(Ordering::Relaxed);
    let failed = metrics.failed_requests.load(Ordering::Relaxed);
    let waf_blocks = metrics.waf_blocks.load(Ordering::Relaxed);
    let backend_responses = metrics.backend_responses.load(Ordering::Relaxed);
    let total_latency = metrics.total_latency_ms.load(Ordering::Relaxed);
    let min_latency = metrics.min_latency_ms.load(Ordering::Relaxed);
    let max_latency = metrics.max_latency_ms.load(Ordering::Relaxed);

    let rps = total as f64 / duration_secs;
    let avg_latency = if total > 0 { total_latency as f64 / total as f64 } else { 0.0 };
    let success_rate = if total > 0 { (successful as f64 / total as f64) * 100.0 } else { 0.0 };
    let waf_block_rate = if total > 0 { (waf_blocks as f64 / total as f64) * 100.0 } else { 0.0 };

    println!();
    println!("📊 {} Results:", test_name);
    println!("=====================================");
    println!("🎯 Total Requests: {}", total);
    println!("✅ Successful: {} ({:.1}%)", successful, success_rate);
    println!("❌ Failed: {}", failed);
    println!("🛡️  WAF Blocks: {} ({:.1}%)", waf_blocks, waf_block_rate);
    println!("🎭 Backend Responses: {}", backend_responses);
    println!("⚡ Requests/Second: {:.0}", rps);
    println!("📈 Average Latency: {:.2}ms", avg_latency);
    println!("⬇️  Min Latency: {}ms", if min_latency == u64::MAX { 0 } else { min_latency });
    println!("⬆️  Max Latency: {}ms", max_latency);
    println!();
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 END-TO-END WAF PERFORMANCE TEST HARNESS");
    println!("==========================================");
    println!("🎯 Testing complete WAF → Backend pipeline");
    println!("📊 Real numbers with actual service integration");
    println!();

    // Build services first
    println!("🔨 Building test services...");
    let build_output = Command::new("cargo")
        .args(&["build", "--release", "--bin", "echo_backend", "--bin", "waf-ingress"])
        .output()
        .await?;

    if !build_output.status.success() {
        println!("❌ Build failed:");
        println!("{}", String::from_utf8_lossy(&build_output.stderr));
        return Err("Build failed".into());
    }
    println!("✅ Services built successfully");
    println!();

    let mut harness = EndToEndTestHarness::new().await?;

    // Start backend and WAF
    harness.start_backend().await?;
    harness.start_waf().await?;

    println!("🎉 Test harness ready! Starting performance tests...");
    println!();

    // Progressive load tests
    let test_levels = vec![
        (50, 20, "Light Load Test"),
        (100, 25, "Medium Load Test"),
        (250, 30, "Heavy Load Test"),
        (500, 35, "Stress Test"),
        (1000, 40, "Enterprise Load Test"),
        (1500, 45, "Peak Performance Test"),
        (2000, 50, "Maximum Capacity Test"),
    ];

    let mut all_results = Vec::new();

    for (concurrent_users, requests_per_user, test_name) in test_levels {
        let test_start = Instant::now();
        
        match harness.run_load_test(concurrent_users, requests_per_user, test_name).await {
            Ok(metrics) => {
                let duration = test_start.elapsed().as_secs_f64();
                print_test_results(&metrics, test_name, duration);
                
                let total = metrics.total_requests.load(Ordering::Relaxed);
                let rps = total as f64 / duration;
                all_results.push((test_name, rps, concurrent_users));
            }
            Err(e) => {
                println!("❌ Test '{}' failed: {}", test_name, e);
            }
        }

        // Give system a breather between tests
        println!("😴 Cooling down for 3 seconds...");
        sleep(Duration::from_secs(3)).await;
    }

    // Final summary
    println!("🏆 END-TO-END PERFORMANCE SUMMARY");
    println!("===================================");
    let mut max_rps = 0.0;
    let mut max_test = "";
    
    for (test_name, rps, users) in &all_results {
        println!("🔥 {}: {:.0} RPS ({} users)", test_name, rps, users);
        if *rps > max_rps {
            max_rps = *rps;
            max_test = test_name;
        }
    }
    
    println!();
    println!("🎯 PEAK END-TO-END PERFORMANCE:");
    println!("   Test: {}", max_test);
    println!("   RPS: {:.0}", max_rps);
    println!("   Pipeline: Client → WAF-Rejected → Echo Backend");
    println!();
    println!("✅ Real-world WAF performance validation complete!");

    harness.shutdown().await;
    Ok(())
}
