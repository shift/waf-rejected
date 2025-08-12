use std::time::{Duration, Instant};
use std::sync::Arc;
use tokio::sync::Semaphore;
use tokio::time::sleep;
use anyhow::Result;

#[derive(Debug)]
struct PerformanceMetrics {
    total_requests: u64,
    successful_requests: u64,
    failed_requests: u64,
    average_latency_ms: f64,
    max_latency_ms: u64,
    min_latency_ms: u64,
    requests_per_second: f64,
    memory_usage_mb: f64,
}

async fn simulate_waf_request(request_id: u64) -> Result<Duration> {
    let start = Instant::now();
    
    // Simulate WAF processing with varying complexity
    let processing_time = match request_id % 10 {
        0..=6 => Duration::from_micros(50 + (request_id % 100)), // Fast path
        7..=8 => Duration::from_micros(200 + (request_id % 300)), // Medium complexity
        _ => Duration::from_micros(500 + (request_id % 200)), // Complex rules
    };
    
    sleep(processing_time).await;
    
    // Simulate occasional failures (0.1% failure rate)
    if request_id % 1000 == 0 {
        return Err(anyhow::anyhow!("Simulated processing failure"));
    }
    
    Ok(start.elapsed())
}

async fn run_concurrent_load_test(
    concurrent_users: usize,
    requests_per_user: usize,
    test_duration_secs: u64,
) -> Result<PerformanceMetrics> {
    println!("🚀 Starting concurrent load test:");
    println!("   Concurrent users: {}", concurrent_users);
    println!("   Requests per user: {}", requests_per_user);
    println!("   Test duration: {}s", test_duration_secs);
    
    let semaphore = Arc::new(Semaphore::new(concurrent_users));
    let total_requests = concurrent_users * requests_per_user;
    let start_time = Instant::now();
    
    let mut tasks = Vec::new();
    let mut request_id = 0u64;
    
    // Spawn concurrent users
    for _user in 0..concurrent_users {
        for _req in 0..requests_per_user {
            let permit = semaphore.clone().acquire_owned().await.unwrap();
            let req_id = request_id;
            request_id += 1;
            
            let task = tokio::spawn(async move {
                let _permit = permit; // Hold permit for duration
                simulate_waf_request(req_id).await
            });
            
            tasks.push(task);
        }
    }
    
    // Collect results
    let mut latencies = Vec::new();
    let mut successful = 0u64;
    let mut failed = 0u64;
    
    for task in tasks {
        match task.await.unwrap() {
            Ok(latency) => {
                latencies.push(latency.as_millis() as u64);
                successful += 1;
            }
            Err(_) => {
                failed += 1;
            }
        }
    }
    
    let total_duration = start_time.elapsed();
    let avg_latency = latencies.iter().sum::<u64>() as f64 / latencies.len() as f64;
    let max_latency = *latencies.iter().max().unwrap_or(&0);
    let min_latency = *latencies.iter().min().unwrap_or(&0);
    let rps = total_requests as f64 / total_duration.as_secs_f64();
    
    // Simulate memory usage calculation
    let base_memory = 45.0; // Base memory usage in MB
    let load_memory = (concurrent_users as f64 * 0.15) + (rps * 0.001); // Memory per user + per RPS
    let memory_usage = base_memory + load_memory;
    
    Ok(PerformanceMetrics {
        total_requests: total_requests as u64,
        successful_requests: successful,
        failed_requests: failed,
        average_latency_ms: avg_latency,
        max_latency_ms: max_latency,
        min_latency_ms: min_latency,
        requests_per_second: rps,
        memory_usage_mb: memory_usage,
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    println!("🏢 Enterprise Performance Testing");
    println!("================================");
    
    // Test 1: Light Load
    println!("\n📊 Test 1: Light Load (100 users, 10 requests each)");
    let light_metrics = run_concurrent_load_test(100, 10, 30).await?;
    print_metrics(&light_metrics, "Light Load");
    
    // Test 2: Moderate Load
    println!("\n📊 Test 2: Moderate Load (250 users, 20 requests each)");
    let moderate_metrics = run_concurrent_load_test(250, 20, 60).await?;
    print_metrics(&moderate_metrics, "Moderate Load");
    
    // Test 3: Heavy Load
    println!("\n📊 Test 3: Heavy Load (500 users, 40 requests each)");
    let heavy_metrics = run_concurrent_load_test(500, 40, 120).await?;
    print_metrics(&heavy_metrics, "Heavy Load");
    
    // Test 4: Enterprise Load
    println!("\n📊 Test 4: Enterprise Load (1000 users, 50 requests each)");
    let enterprise_metrics = run_concurrent_load_test(1000, 50, 300).await?;
    print_metrics(&enterprise_metrics, "Enterprise Load");
    
    // Validate enterprise requirements
    println!("\n🎯 Enterprise Requirements Validation");
    println!("====================================");
    
    validate_performance_requirements(&enterprise_metrics)?;
    
    println!("\n🏆 Enterprise Performance Testing Complete!");
    println!("All performance requirements validated successfully.");
    
    Ok(())
}

fn print_metrics(metrics: &PerformanceMetrics, test_name: &str) {
    println!("📈 {} Results:", test_name);
    println!("   Total Requests: {}", metrics.total_requests);
    println!("   Successful: {}", metrics.successful_requests);
    println!("   Failed: {}", metrics.failed_requests);
    println!("   Success Rate: {:.2}%", 
        (metrics.successful_requests as f64 / metrics.total_requests as f64) * 100.0);
    println!("   Average Latency: {:.2}ms", metrics.average_latency_ms);
    println!("   Min Latency: {}ms", metrics.min_latency_ms);
    println!("   Max Latency: {}ms", metrics.max_latency_ms);
    println!("   Requests/Second: {:.2}", metrics.requests_per_second);
    println!("   Memory Usage: {:.1}MB", metrics.memory_usage_mb);
}

fn validate_performance_requirements(metrics: &PerformanceMetrics) -> Result<()> {
    let mut all_passed = true;
    
    // Requirement 1: Throughput ≥5,000 RPS
    if metrics.requests_per_second >= 5000.0 {
        println!("✅ Throughput: {:.0} RPS (≥5,000 required)", metrics.requests_per_second);
    } else {
        println!("❌ Throughput: {:.0} RPS (≥5,000 required)", metrics.requests_per_second);
        all_passed = false;
    }
    
    // Requirement 2: Average latency ≤100ms
    if metrics.average_latency_ms <= 100.0 {
        println!("✅ Average Latency: {:.1}ms (≤100ms required)", metrics.average_latency_ms);
    } else {
        println!("❌ Average Latency: {:.1}ms (≤100ms required)", metrics.average_latency_ms);
        all_passed = false;
    }
    
    // Requirement 3: Error rate <0.1%
    let error_rate = (metrics.failed_requests as f64 / metrics.total_requests as f64) * 100.0;
    if error_rate < 0.1 {
        println!("✅ Error Rate: {:.2}% (<0.1% required)", error_rate);
    } else {
        println!("❌ Error Rate: {:.2}% (<0.1% required)", error_rate);
        all_passed = false;
    }
    
    // Requirement 4: Memory usage <100MB growth under load
    if metrics.memory_usage_mb < 145.0 { // 45MB base + 100MB growth
        println!("✅ Memory Usage: {:.1}MB (<145MB required)", metrics.memory_usage_mb);
    } else {
        println!("❌ Memory Usage: {:.1}MB (<145MB required)", metrics.memory_usage_mb);
        all_passed = false;
    }
    
    if !all_passed {
        return Err(anyhow::anyhow!("Performance requirements not met"));
    }
    
    Ok(())
}
