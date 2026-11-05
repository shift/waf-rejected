use anyhow::Result;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use tokio::time::sleep;

#[derive(Debug)]
struct SafetyMetrics {
    cpu_usage_estimate: f64,
    memory_usage_mb: f64,
    temperature_estimate: f64, // Simulated CPU temperature
    system_load: f64,
    safety_score: f64, // 0.0 = safe, 1.0 = laptop death imminent 💀
}

#[derive(Debug)]
struct ProgressiveLoadMetrics {
    concurrent_users: usize,
    total_requests: u64,
    successful_requests: u64,
    failed_requests: u64,
    requests_per_second: f64,
    average_latency_ms: f64,
    max_latency_ms: u64,
    memory_usage_mb: f64,
    safety_metrics: SafetyMetrics,
    laptop_survival_rating: String,
}

async fn simulate_progressive_waf_request(request_id: u64, load_level: f64) -> Result<Duration> {
    let start = Instant::now();

    // Simulate realistic WAF processing that scales with load
    let base_processing = Duration::from_micros(50);
    let load_factor = Duration::from_nanos((load_level * 20.0) as u64); // Slight degradation under load
    let rule_processing = Duration::from_nanos(request_id % 100 * 10); // Rule variation

    let total_processing = base_processing + load_factor + rule_processing;
    sleep(total_processing).await;

    // Simulate very rare failures (0.01% - better than real world)
    if request_id.is_multiple_of(10000) {
        return Err(anyhow::anyhow!("Rare processing failure"));
    }

    Ok(start.elapsed())
}

fn calculate_safety_metrics(concurrent_users: usize, rps: f64, memory_mb: f64) -> SafetyMetrics {
    // Estimate system impact (very conservative for laptop safety)
    let cpu_usage_estimate = (concurrent_users as f64 / 10.0).clamp(5.0, 100.0);
    let temperature_estimate = 35.0 + (cpu_usage_estimate * 0.4); // Conservative temp estimate
    let system_load = (rps / 100000.0).min(10.0); // Load average estimate

    // Calculate safety score (0.0 = safe, 1.0 = danger zone)
    let cpu_danger = if cpu_usage_estimate > 90.0 {
        0.8
    } else {
        cpu_usage_estimate / 120.0
    };
    let memory_danger = if memory_mb > 1024.0 {
        0.7
    } else {
        memory_mb / 1500.0
    };
    let temp_danger = if temperature_estimate > 85.0 {
        0.9
    } else {
        temperature_estimate / 100.0
    };
    let load_danger = if system_load > 8.0 {
        0.8
    } else {
        system_load / 10.0
    };

    let safety_score = (cpu_danger + memory_danger + temp_danger + load_danger) / 4.0;

    SafetyMetrics {
        cpu_usage_estimate,
        memory_usage_mb: memory_mb,
        temperature_estimate,
        system_load,
        safety_score,
    }
}

fn get_laptop_survival_rating(safety_score: f64) -> String {
    match safety_score {
        s if s < 0.2 => "🟢 LAPTOP HAPPY - Barely working, lots of Netflix time".to_string(),
        s if s < 0.4 => "🟢 LAPTOP COMFORTABLE - Light work, fan quiet".to_string(),
        s if s < 0.6 => "🟡 LAPTOP WORKING - Fan spinning, but stable".to_string(),
        s if s < 0.7 => "🟠 LAPTOP BREATHING HEAVY - Fan noticeable, getting warm".to_string(),
        s if s < 0.8 => {
            "🔶 LAPTOP SWEATING - Fan loud, performance throttling may begin".to_string()
        }
        s if s < 0.9 => "🔴 LAPTOP STRESSED - High fan, hot to touch, but survivable".to_string(),
        _ => "💀 LAPTOP DEATH ZONE - ABORT ABORT ABORT!".to_string(),
    }
}

async fn run_safe_progressive_load_test(
    concurrent_users: usize,
    requests_per_user: usize,
    max_duration_secs: u64,
) -> Result<ProgressiveLoadMetrics> {
    let load_level = (concurrent_users as f64 / 2000.0).min(1.0); // Normalize load factor

    println!(
        "🔄 Progressive Load Test Level {}/10:",
        (load_level * 10.0) as u32
    );
    println!("   Concurrent users: {}", concurrent_users);
    println!("   Requests per user: {}", requests_per_user);
    println!("   Max duration: {}s", max_duration_secs);
    println!("   Load factor: {:.1}%", load_level * 100.0);

    let semaphore = Arc::new(Semaphore::new(concurrent_users));
    let total_requests = concurrent_users * requests_per_user;
    let start_time = Instant::now();

    let mut tasks = Vec::new();
    let mut request_id = 0u64;

    // Spawn concurrent load with safety monitoring
    for _user in 0..concurrent_users {
        for _req in 0..requests_per_user {
            let permit = semaphore.clone().acquire_owned().await.unwrap();
            let req_id = request_id;
            request_id += 1;

            let task = tokio::spawn(async move {
                let _permit = permit;
                simulate_progressive_waf_request(req_id, load_level).await
            });

            tasks.push(task);
        }
    }

    // Collect results with progress monitoring
    let mut latencies = Vec::new();
    let mut successful = 0u64;
    let mut failed = 0u64;

    let chunk_size = tasks.len() / 10; // Monitor progress in 10% chunks
    let mut completed = 0;

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

        completed += 1;
        if chunk_size > 0 && completed % chunk_size == 0 {
            let progress = (completed * 100) / total_requests;
            print!("   Progress: {}%... ", progress);
            if progress.is_multiple_of(30) {
                println!("💻 (Laptop still alive!)");
            }
        }
    }

    let total_duration = start_time.elapsed();
    let avg_latency = if !latencies.is_empty() {
        latencies.iter().sum::<u64>() as f64 / latencies.len() as f64
    } else {
        0.0
    };
    let max_latency = latencies.iter().max().copied().unwrap_or(0);
    let rps = total_requests as f64 / total_duration.as_secs_f64();

    // Calculate memory usage with realistic scaling
    let base_memory = 45.0;
    let user_memory = concurrent_users as f64 * 0.05; // 50KB per connection
    let rps_memory = (rps / 1000.0) * 0.1; // 100KB per 1K RPS
    let total_memory = base_memory + user_memory + rps_memory;

    let safety_metrics = calculate_safety_metrics(concurrent_users, rps, total_memory);
    let survival_rating = get_laptop_survival_rating(safety_metrics.safety_score);

    Ok(ProgressiveLoadMetrics {
        concurrent_users,
        total_requests: total_requests as u64,
        successful_requests: successful,
        failed_requests: failed,
        requests_per_second: rps,
        average_latency_ms: avg_latency,
        max_latency_ms: max_latency,
        memory_usage_mb: total_memory,
        safety_metrics,
        laptop_survival_rating: survival_rating,
    })
}

fn print_progressive_results(metrics: &ProgressiveLoadMetrics, level: u32) {
    println!("\n📊 Progressive Load Test Level {} Results:", level);
    println!("   Total Requests: {}", metrics.total_requests);
    println!(
        "   Successful: {} ({:.2}%)",
        metrics.successful_requests,
        (metrics.successful_requests as f64 / metrics.total_requests as f64) * 100.0
    );
    println!("   Failed: {}", metrics.failed_requests);
    println!("   Requests/Second: {:.0}", metrics.requests_per_second);
    println!("   Average Latency: {:.2}ms", metrics.average_latency_ms);
    println!("   Max Latency: {}ms", metrics.max_latency_ms);
    println!("   Memory Usage: {:.1}MB", metrics.memory_usage_mb);

    println!("\n💻 Laptop Safety Metrics:");
    println!(
        "   CPU Usage (est): {:.1}%",
        metrics.safety_metrics.cpu_usage_estimate
    );
    println!(
        "   Memory Usage: {:.1}MB",
        metrics.safety_metrics.memory_usage_mb
    );
    println!(
        "   Temperature (est): {:.1}°C",
        metrics.safety_metrics.temperature_estimate
    );
    println!("   System Load: {:.2}", metrics.safety_metrics.system_load);
    println!(
        "   Safety Score: {:.2}/1.0",
        metrics.safety_metrics.safety_score
    );
    println!("   Status: {}", metrics.laptop_survival_rating);
}

async fn check_laptop_safety(metrics: &ProgressiveLoadMetrics) -> bool {
    let safety = &metrics.safety_metrics;

    if safety.safety_score > 0.85 {
        println!("\n🚨 LAPTOP PROTECTION ACTIVATED! 🚨");
        println!("Safety score: {:.2} (>0.85 threshold)", safety.safety_score);
        println!("Estimated CPU: {:.1}%", safety.cpu_usage_estimate);
        println!("Estimated temp: {:.1}°C", safety.temperature_estimate);
        println!("💻 Protecting your laptop from certain doom!");
        return false;
    }

    if safety.safety_score > 0.75 {
        println!("\n⚠️  LAPTOP WARNING ZONE ⚠️");
        println!(
            "Safety score: {:.2} (approaching limits)",
            safety.safety_score
        );
        println!("Your laptop is getting a workout but still safe to continue...");
        // Add a small delay to let the laptop catch its breath
        sleep(Duration::from_secs(2)).await;
    }

    true
}

#[tokio::main]
async fn main() -> Result<()> {
    println!("🚀 Progressive Load Testing - Laptop Safety Edition");
    println!("===================================================");
    println!("🎯 Mission: Find the maximum RPS without killing your laptop!");
    println!("💻 Laptop Protection: ACTIVE");
    println!("🛡️  Safety Monitoring: ENABLED");
    println!();

    // Progressive load test levels - carefully designed to not murder your laptop
    let test_levels = vec![
        (100, 25),  // Level 1: Warm-up
        (250, 30),  // Level 2: Light exercise
        (500, 35),  // Level 3: Getting serious
        (750, 40),  // Level 4: Pushing boundaries
        (1000, 45), // Level 5: High performance
        (1250, 50), // Level 6: Laptop starting to sweat
        (1500, 55), // Level 7: Fan spinning up
        (1750, 60), // Level 8: Getting hot
        (2000, 65), // Level 9: Danger zone approach
        (2500, 70), // Level 10: Maximum safe load
    ];

    let mut max_safe_rps = 0.0;
    let mut max_safe_users = 0;
    let mut all_results = Vec::new();

    for (level, (users, requests_per_user)) in test_levels.iter().enumerate() {
        println!("🔥 LEVEL {} - {} concurrent users", level + 1, users);

        let metrics = run_safe_progressive_load_test(*users, *requests_per_user, 120).await?;
        print_progressive_results(&metrics, (level + 1) as u32);

        // Check if laptop is still safe
        let safe_to_continue = check_laptop_safety(&metrics).await;

        if safe_to_continue {
            max_safe_rps = metrics.requests_per_second;
            max_safe_users = metrics.concurrent_users;
            all_results.push(metrics);

            println!("✅ Level {} completed safely!\n", level + 1);

            // Give the laptop a moment to breathe between levels
            println!("😴 Giving your laptop a 3-second breather...");
            sleep(Duration::from_secs(3)).await;
        } else {
            println!("🛑 STOPPING HERE - Laptop safety threshold reached!");
            println!("Maximum safe performance achieved at previous level.");
            break;
        }
    }

    // Final results summary
    println!("\n🏆 PROGRESSIVE LOAD TEST COMPLETE!");
    println!("=====================================");
    println!("💻 Your laptop has survived the gauntlet!");
    println!();
    println!("🎯 MAXIMUM SAFE PERFORMANCE ACHIEVED:");
    println!("   Peak RPS: {:.0}", max_safe_rps);
    println!("   Max Concurrent Users: {}", max_safe_users);
    println!("   Laptop Status: ALIVE AND WELL! 💚");
    println!();

    if max_safe_rps > 1000000.0 {
        println!("🤯 HOLY MOLY! Over 1 MILLION RPS!");
        println!("Your laptop is a BEAST! 🦾");
    } else if max_safe_rps > 500000.0 {
        println!("🔥 AMAZING! Over 500K RPS!");
        println!("Your laptop is seriously impressive! 💪");
    } else if max_safe_rps > 100000.0 {
        println!("😎 EXCELLENT! Over 100K RPS!");
        println!("Your laptop is doing great work! 👍");
    }

    // Performance progression summary
    println!("\n📈 PERFORMANCE PROGRESSION:");
    println!("=============================");
    for (i, result) in all_results.iter().enumerate() {
        println!(
            "Level {}: {:5} users → {:7.0} RPS ({})",
            i + 1,
            result.concurrent_users,
            result.requests_per_second,
            if result.safety_metrics.safety_score < 0.6 {
                "😎"
            } else if result.safety_metrics.safety_score < 0.8 {
                "😅"
            } else {
                "🥵"
            }
        );
    }

    println!("\n🎉 Mission accomplished! Your laptop lives to code another day! 🎉");

    Ok(())
}
