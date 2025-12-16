#!/usr/bin/env cargo
//! # WAF-Rejected Core Performance Benchmark Suite (Simplified)
//!
//! Streamlined performance benchmarks focused on core WAF engine validation
//! for Strategic Roadmap v0.1 baseline establishment.

use waf_ingress::config::Config;
use waf_ingress::error::WafError;
use waf_ingress::waf::rules::{IpRule, MethodRule, RequestSizeRule};
use waf_ingress::waf::{RequestContext, WafEngine};

use hyper::{HeaderMap, Method};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Simplified benchmark configuration
#[derive(Debug, Clone)]
pub struct BenchmarkConfig {
    pub warmup_iterations: usize,
    pub test_iterations: usize,
    pub test_duration_seconds: u64,
}

impl Default for BenchmarkConfig {
    fn default() -> Self {
        Self {
            warmup_iterations: 1000,
            test_iterations: 50_000,
            test_duration_seconds: 10,
        }
    }
}

/// Simplified benchmark results
#[derive(Debug)]
pub struct BenchmarkResults {
    pub avg_latency_ns: f64,
    pub p99_latency_ns: f64,
    pub throughput_rps: f64,
    pub successful_evaluations: usize,
    pub total_evaluations: usize,
}

/// Simplified core benchmark suite
pub struct CoreBenchmarkSuite {
    config: BenchmarkConfig,
    engine: Arc<WafEngine>,
}

impl CoreBenchmarkSuite {
    pub async fn new(config: BenchmarkConfig) -> Result<Self, WafError> {
        println!("🚀 Initializing WAF-Rejected Core Benchmark Suite (Simplified)");
        println!("==============================================================");

        // Initialize core WAF engine with standard configuration
        let waf_config = Config::default();
        let mut engine = WafEngine::with_config(&waf_config);

        // Load additional rules for benchmarking
        engine.add_rule(RequestSizeRule::new("size_limit", 1024 * 1024));
        engine.add_rule(
            MethodRule::new("method_filter")
                .block_method(Method::DELETE)
                .block_method(Method::PATCH),
        );
        engine.add_rule(IpRule::new("ip_blocker").block_ip("192.168.1.100".parse().unwrap()));

        println!(
            "✅ WAF engine initialized with {} rules",
            engine.rule_count()
        );

        Ok(Self {
            config,
            engine: Arc::new(engine),
        })
    }

    /// Run complete benchmark suite
    pub async fn run_complete_benchmark(&self) -> Result<BenchmarkResults, WafError> {
        println!("\n🎯 Starting Simplified Performance Benchmark Suite");
        println!("================================================");

        // Phase 1: Warmup
        println!("\n1. Warming up system...");
        self.warmup_phase().await?;

        // Phase 2: Latency benchmarks
        println!("\n2. Running latency benchmarks...");
        let (avg_latency, p99_latency, successful_latency) = self.benchmark_latency().await?;

        // Phase 3: Throughput benchmarks
        println!("\n3. Running throughput benchmarks...");
        let (throughput_rps, successful_throughput, total_throughput) =
            self.benchmark_throughput().await?;

        let results = BenchmarkResults {
            avg_latency_ns: avg_latency,
            p99_latency_ns: p99_latency,
            throughput_rps,
            successful_evaluations: successful_latency.min(successful_throughput),
            total_evaluations: self.config.test_iterations.max(total_throughput),
        };

        self.print_comprehensive_results(&results);
        Ok(results)
    }

    /// Warmup phase to stabilize performance
    async fn warmup_phase(&self) -> Result<(), WafError> {
        let start = Instant::now();
        for i in 0..self.config.warmup_iterations {
            let ctx = self.create_test_context(i % 10);
            let _decision = self.engine.evaluate(&ctx).await;

            if i % 100 == 0 && i > 0 {
                print!(".");
            }
        }
        println!(" ✅ Warmup completed in {:?}", start.elapsed());
        Ok(())
    }

    /// Benchmark request evaluation latency
    async fn benchmark_latency(&self) -> Result<(f64, f64, usize), WafError> {
        let mut latencies = Vec::with_capacity(self.config.test_iterations);
        let mut successful_evaluations = 0;

        for i in 0..self.config.test_iterations {
            let ctx = self.create_test_context(i);
            let start = Instant::now();
            let _decision = self.engine.evaluate(&ctx).await;
            let elapsed = start.elapsed();
            latencies.push(elapsed.as_nanos() as f64);
            successful_evaluations += 1;

            if i % 5000 == 0 && i > 0 {
                print!(".");
            }
        }

        // Calculate statistics
        latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let avg_latency = latencies.iter().sum::<f64>() / latencies.len() as f64;
        let p99_index = (latencies.len() as f64 * 0.99) as usize;
        let p99_latency = latencies[p99_index.min(latencies.len() - 1)];

        println!(" ✅ Latency test completed");
        Ok((avg_latency, p99_latency, successful_evaluations))
    }

    /// Benchmark maximum throughput (single-threaded for simplicity)
    async fn benchmark_throughput(&self) -> Result<(f64, usize, usize), WafError> {
        let counter = Arc::new(AtomicUsize::new(0));
        let start = Instant::now();
        let test_duration = Duration::from_secs(self.config.test_duration_seconds);

        let mut i = 0;
        while start.elapsed() < test_duration {
            let ctx = self.create_test_context(i);
            let _decision = self.engine.evaluate(&ctx).await;
            counter.fetch_add(1, Ordering::Relaxed);
            i += 1;
        }

        let total_requests = counter.load(Ordering::Relaxed);
        let actual_duration = start.elapsed();
        let rps = total_requests as f64 / actual_duration.as_secs_f64();

        println!(
            " ✅ Throughput test: {} requests in {:?} ({:.0} RPS)",
            total_requests, actual_duration, rps
        );

        Ok((rps, total_requests, total_requests))
    }

    /// Create standard test request context
    fn create_test_context(&self, iteration: usize) -> RequestContext {
        let method = if iteration % 3 == 0 {
            Method::POST
        } else {
            Method::GET
        };
        let uri = format!("/api/test/{}", iteration % 100).parse().unwrap();
        let headers = HeaderMap::new();
        let client_ip = "192.168.1.10".parse().unwrap();
        let body_size = Some(1024 + (iteration % 500));

        RequestContext::new(client_ip, method, uri, headers, body_size)
    }

    /// Print comprehensive benchmark results
    fn print_comprehensive_results(&self, results: &BenchmarkResults) {
        println!("\n");
        println!("🎯 WAF-Rejected Core Performance Benchmark Results (Simplified)");
        println!("===============================================================");
        println!();

        // Latency Results
        println!("📊 LATENCY ANALYSIS:");
        println!(
            "   Average:  {:.0} ns ({:.3} μs)",
            results.avg_latency_ns,
            results.avg_latency_ns / 1000.0
        );
        println!(
            "   P99:      {:.0} ns ({:.3} μs)",
            results.p99_latency_ns,
            results.p99_latency_ns / 1000.0
        );
        println!();

        // Throughput Results
        println!("⚡ THROUGHPUT ANALYSIS:");
        println!("   Peak RPS: {:.0} requests/second", results.throughput_rps);
        println!(
            "   Success Rate: {:.1}%",
            (results.successful_evaluations as f64 / results.total_evaluations as f64) * 100.0
        );
        println!();

        // Performance Assessment
        println!("✅ PERFORMANCE ASSESSMENT:");
        let latency_target_met = results.p99_latency_ns < 1_000_000.0; // <1ms
        let throughput_target_met = results.throughput_rps > 50_000.0; // >50k RPS for simplified test
        let success_rate_acceptable =
            (results.successful_evaluations as f64 / results.total_evaluations as f64) > 0.99; // >99%

        println!(
            "   Latency Target (<1ms):     {}",
            if latency_target_met {
                "✅ PASS"
            } else {
                "❌ FAIL"
            }
        );
        println!(
            "   Throughput Target (>50k):  {}",
            if throughput_target_met {
                "✅ PASS"
            } else {
                "❌ FAIL"
            }
        );
        println!(
            "   Success Rate Target (>99%): {}",
            if success_rate_acceptable {
                "✅ PASS"
            } else {
                "❌ FAIL"
            }
        );
        println!();

        if latency_target_met && throughput_target_met && success_rate_acceptable {
            println!("🏆 OVERALL ASSESSMENT: READY FOR v0.1 MVP RELEASE");
            println!("📈 PERFORMANCE HIGHLIGHTS:");
            println!(
                "   • Core WAF evaluation: {:.3} μs average",
                results.avg_latency_ns / 1000.0
            );
            println!(
                "   • P99 latency: {:.3} μs",
                results.p99_latency_ns / 1000.0
            );
            println!(
                "   • Sustained throughput: {:.0} RPS",
                results.throughput_rps
            );
            println!(
                "   • Reliability: {:.2}% success rate",
                (results.successful_evaluations as f64 / results.total_evaluations as f64) * 100.0
            );
        } else {
            println!("⚠️  OVERALL ASSESSMENT: PERFORMANCE TUNING REQUIRED");
        }

        println!("===============================================================");
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let config = BenchmarkConfig::default();
    let benchmark_suite = CoreBenchmarkSuite::new(config).await?;

    let results = benchmark_suite.run_complete_benchmark().await?;

    // Final assessment for Strategic Roadmap progression
    let ready_for_next_phase = results.p99_latency_ns < 1_000_000.0
        && results.throughput_rps > 50_000.0
        && (results.successful_evaluations as f64 / results.total_evaluations as f64) > 0.99;

    if ready_for_next_phase {
        println!("\n🚀 Phase 1 Day 3 Complete: Ready for Strategic Roadmap v0.1 next phase");
        println!("   Next: Finalize core proxy logic and prepare for WASM integration");
    } else {
        println!("\n⚠️  Phase 1 Day 3: Performance optimization required before proceeding");
    }

    Ok(())
}
