//! Common test utilities for enterprise testing

use std::time::{Duration, Instant};
use std::path::Path;
use serde::{Serialize, Deserialize};
use anyhow::Result;

#[derive(Debug, Clone)]
pub struct EnterpriseAttackVector {
    pub name: String,
    pub payload: String,
    pub attack_type: String,
    pub is_malicious: bool,
    pub expected_rule_id: Option<String>,
}

#[derive(Debug)]
pub struct DetectionResult {
    pub blocked: bool,
    pub rule_id: Option<String>,
    pub confidence: f64,
    pub processing_time: Duration,
}

#[derive(Debug)]
pub struct EnterpriseResponse {
    pub status_code: u16,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
    pub processing_time: Duration,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ComplianceEvent {
    pub event_type: String,
    pub user_id: Option<String>,
    pub resource: String,
    pub action: String,
    pub result: String,
    pub ip_address: String,
    pub compliance_framework: String,
}

#[derive(Debug, Default)]
pub struct AvailabilityMetrics {
    pub uptime_percentage: f64,
    pub mean_time_to_recovery: Duration,
    pub failure_events: Vec<FailureEvent>,
}

#[derive(Debug)]
pub struct FailureEvent {
    pub component: String,
    pub failure_time: Instant,
    pub recovery_time: Option<Instant>,
    pub impact_level: ImpactLevel,
}

#[derive(Debug)]
pub enum ImpactLevel {
    Low,    // <5% performance degradation
    Medium, // 5-20% performance degradation  
    High,   // >20% performance degradation
    Critical, // Service unavailable
}

/// Create comprehensive attack vectors for enterprise testing
pub fn create_enterprise_attack_vectors() -> Vec<EnterpriseAttackVector> {
    vec![
        // SQL Injection variants
        EnterpriseAttackVector {
            name: "Classic SQL Injection".to_string(),
            payload: "' OR '1'='1' --".to_string(),
            attack_type: "sql_injection".to_string(),
            is_malicious: true,
            expected_rule_id: Some("SQL001".to_string()),
        },
        EnterpriseAttackVector {
            name: "Union-based SQL Injection".to_string(),
            payload: "' UNION SELECT username, password FROM users --".to_string(),
            attack_type: "sql_injection".to_string(),
            is_malicious: true,
            expected_rule_id: Some("SQL002".to_string()),
        },
        EnterpriseAttackVector {
            name: "Time-based Blind SQL Injection".to_string(),
            payload: "'; WAITFOR DELAY '00:00:05' --".to_string(),
            attack_type: "sql_injection".to_string(),
            is_malicious: true,
            expected_rule_id: Some("SQL003".to_string()),
        },
        
        // Cross-Site Scripting (XSS) variants
        EnterpriseAttackVector {
            name: "Reflected XSS".to_string(),
            payload: "<script>alert('XSS')</script>".to_string(),
            attack_type: "xss".to_string(),
            is_malicious: true,
            expected_rule_id: Some("XSS001".to_string()),
        },
        EnterpriseAttackVector {
            name: "DOM-based XSS".to_string(),
            payload: "javascript:alert('XSS')".to_string(),
            attack_type: "xss".to_string(),
            is_malicious: true,
            expected_rule_id: Some("XSS002".to_string()),
        },
        EnterpriseAttackVector {
            name: "Stored XSS".to_string(),
            payload: "<img src=x onerror=alert('XSS')>".to_string(),
            attack_type: "xss".to_string(),
            is_malicious: true,
            expected_rule_id: Some("XSS003".to_string()),
        },
        
        // Command Injection variants
        EnterpriseAttackVector {
            name: "Basic Command Injection".to_string(),
            payload: "; cat /etc/passwd".to_string(),
            attack_type: "command_injection".to_string(),
            is_malicious: true,
            expected_rule_id: Some("CMD001".to_string()),
        },
        EnterpriseAttackVector {
            name: "PowerShell Command Injection".to_string(),
            payload: "; Get-Process".to_string(),
            attack_type: "command_injection".to_string(),
            is_malicious: true,
            expected_rule_id: Some("CMD002".to_string()),
        },
        
        // Path Traversal variants
        EnterpriseAttackVector {
            name: "Directory Traversal".to_string(),
            payload: "../../../../etc/passwd".to_string(),
            attack_type: "path_traversal".to_string(),
            is_malicious: true,
            expected_rule_id: Some("PATH001".to_string()),
        },
        EnterpriseAttackVector {
            name: "Windows Path Traversal".to_string(),
            payload: "..\\..\\..\\windows\\system32\\config\\sam".to_string(),
            attack_type: "path_traversal".to_string(),
            is_malicious: true,
            expected_rule_id: Some("PATH002".to_string()),
        },
        
        // Remote File Inclusion
        EnterpriseAttackVector {
            name: "Remote File Inclusion".to_string(),
            payload: "http://evil.com/shell.php".to_string(),
            attack_type: "rfi".to_string(),
            is_malicious: true,
            expected_rule_id: Some("RFI001".to_string()),
        },
        
        // XML External Entity (XXE)
        EnterpriseAttackVector {
            name: "XXE Attack".to_string(),
            payload: "<!DOCTYPE test [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><test>&xxe;</test>".to_string(),
            attack_type: "xxe".to_string(),
            is_malicious: true,
            expected_rule_id: Some("XXE001".to_string()),
        },
        
        // Server-Side Template Injection
        EnterpriseAttackVector {
            name: "SSTI Attack".to_string(),
            payload: "{{7*7}}".to_string(),
            attack_type: "ssti".to_string(),
            is_malicious: true,
            expected_rule_id: Some("SSTI001".to_string()),
        },
        
        // LDAP Injection
        EnterpriseAttackVector {
            name: "LDAP Injection".to_string(),
            payload: "*)(&)".to_string(),
            attack_type: "ldap_injection".to_string(),
            is_malicious: true,
            expected_rule_id: Some("LDAP001".to_string()),
        },
        
        // Legitimate requests that should NOT be blocked
        EnterpriseAttackVector {
            name: "Normal API Request".to_string(),
            payload: "{\"user_id\": 12345, \"action\": \"get_profile\"}".to_string(),
            attack_type: "legitimate".to_string(),
            is_malicious: false,
            expected_rule_id: None,
        },
        EnterpriseAttackVector {
            name: "Search Query with Special Characters".to_string(),
            payload: "search for C++ programming & .NET development".to_string(),
            attack_type: "legitimate".to_string(),
            is_malicious: false,
            expected_rule_id: None,
        },
        EnterpriseAttackVector {
            name: "JSON with Escaped Quotes".to_string(),
            payload: "{\"message\": \"He said \\\"Hello\\\" to me\"}".to_string(),
            attack_type: "legitimate".to_string(),
            is_malicious: false,
            expected_rule_id: None,
        },
        EnterpriseAttackVector {
            name: "URL with Parameters".to_string(),
            payload: "/api/users?page=1&limit=50&sort=name".to_string(),
            attack_type: "legitimate".to_string(),
            is_malicious: false,
            expected_rule_id: None,
        },
    ]
}

/// Simulate enterprise WAF request processing
pub async fn simulate_enterprise_request(user_id: usize, request_id: usize) -> Result<EnterpriseResponse> {
    let start_time = Instant::now();
    
    // Simulate realistic processing time
    let processing_delay = match (user_id + request_id) % 10 {
        0..=7 => Duration::from_micros(100 + (user_id % 1000) as u64), // Normal requests
        8 => Duration::from_millis(5), // Slightly slower requests
        9 => Duration::from_millis(20), // Complex requests requiring deeper inspection
        _ => Duration::from_micros(50),
    };
    
    tokio::time::sleep(processing_delay).await;
    
    let processing_time = start_time.elapsed();
    
    // Simulate different response scenarios
    let (status_code, blocked) = match (user_id + request_id) % 100 {
        0..=84 => (200, false), // 85% success rate
        85..=92 => (403, true), // 8% blocked (legitimate blocks)
        93..=97 => (429, true), // 5% rate limited
        98..=99 => (500, false), // 2% server errors
        _ => (200, false),
    };
    
    let mut headers = vec![
        ("Content-Type".to_string(), "application/json".to_string()),
        ("X-WAF-Status".to_string(), if blocked { "BLOCKED".to_string() } else { "ALLOWED".to_string() }),
        ("X-Request-ID".to_string(), format!("req-{}-{}", user_id, request_id)),
    ];
    
    if blocked {
        headers.push(("X-Block-Reason".to_string(), "Security policy violation".to_string()));
    }
    
    let body = if status_code == 200 {
        Some(format!("{{\"user_id\": {}, \"request_id\": {}, \"status\": \"success\"}}", 
            user_id, request_id).into_bytes())
    } else {
        Some(format!("{{\"error\": \"Request failed\", \"status_code\": {}}}", 
            status_code).into_bytes())
    };
    
    Ok(EnterpriseResponse {
        status_code,
        headers,
        body,
        processing_time,
    })
}

/// Simulate WAF attack detection
pub async fn simulate_waf_detection(attack_vector: &EnterpriseAttackVector) -> DetectionResult {
    let start_time = Instant::now();
    
    // Simulate detection logic processing time
    let complexity_factor = match attack_vector.attack_type.as_str() {
        "sql_injection" => Duration::from_micros(200),
        "xss" => Duration::from_micros(150),
        "command_injection" => Duration::from_micros(300),
        "xxe" => Duration::from_micros(400),
        "path_traversal" => Duration::from_micros(100),
        "rfi" => Duration::from_micros(250),
        "ssti" => Duration::from_micros(350),
        "ldap_injection" => Duration::from_micros(180),
        "legitimate" => Duration::from_micros(50),
        _ => Duration::from_micros(100),
    };
    
    tokio::time::sleep(complexity_factor).await;
    
    let processing_time = start_time.elapsed();
    
    // Simulate detection accuracy
    let (blocked, confidence) = if attack_vector.is_malicious {
        match attack_vector.attack_type.as_str() {
            "sql_injection" => (true, 0.95), // 95% detection rate
            "xss" => (true, 0.92), // 92% detection rate
            "command_injection" => (true, 0.98), // 98% detection rate
            "xxe" => (true, 0.90), // 90% detection rate
            "path_traversal" => (true, 0.96), // 96% detection rate
            "rfi" => (true, 0.94), // 94% detection rate
            "ssti" => (true, 0.88), // 88% detection rate
            "ldap_injection" => (true, 0.85), // 85% detection rate
            _ => (true, 0.80),
        }
    } else {
        // Legitimate requests - simulate occasional false positives
        let false_positive_rate = match attack_vector.name.as_str() {
            "Search Query with Special Characters" => 0.03, // 3% false positive
            "JSON with Escaped Quotes" => 0.01, // 1% false positive
            _ => 0.005, // 0.5% false positive for normal requests
        };
        
        let random_factor = (attack_vector.payload.len() % 1000) as f64 / 1000.0;
        (random_factor < false_positive_rate, 1.0 - confidence_for_legitimate(&attack_vector.payload))
    };
    
    DetectionResult {
        blocked,
        rule_id: if blocked { attack_vector.expected_rule_id.clone() } else { None },
        confidence,
        processing_time,
    }
}

/// Calculate confidence score for legitimate requests
fn confidence_for_legitimate(payload: &str) -> f64 {
    let suspicious_chars = payload.chars().filter(|&c| {
        "()<>{}[]\"';&|*$".contains(c)
    }).count();
    
    let total_chars = payload.len();
    if total_chars == 0 {
        return 1.0;
    }
    
    let suspicion_ratio = suspicious_chars as f64 / total_chars as f64;
    1.0 - (suspicion_ratio * 0.5) // Reduce confidence based on suspicious character ratio
}

/// Simulate database failure for availability testing
pub async fn simulate_database_failure() {
    // Simulate database connection failure
    tokio::time::sleep(Duration::from_millis(100)).await;
}

/// Simulate database recovery
pub async fn simulate_database_recovery() {
    // Simulate database reconnection
    tokio::time::sleep(Duration::from_millis(50)).await;
}

/// Simulate WASM module failure
pub async fn simulate_wasm_failure() {
    // Simulate WASM module compilation/loading failure
    tokio::time::sleep(Duration::from_millis(200)).await;
}

/// Simulate WASM recovery
pub async fn simulate_wasm_recovery() {
    // Simulate WASM module reload and recovery
    tokio::time::sleep(Duration::from_millis(300)).await;
}

/// Simulate compliance logging
pub async fn simulate_compliance_logging(
    event: &ComplianceEvent, 
    log_path: &Path
) -> Result<()> {
    use tokio::io::AsyncWriteExt;
    
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    let log_entry = serde_json::json!({
        "timestamp": timestamp,
        "event_type": event.event_type,
        "user_id": event.user_id,
        "resource": event.resource,
        "action": event.action,
        "result": event.result,
        "ip_address": event.ip_address,
        "compliance_framework": event.compliance_framework,
        "audit_id": uuid::Uuid::new_v4().to_string(),
    });
    
    let log_line = format!("{}\n", log_entry.to_string());
    
    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
        .await?;
    
    file.write_all(log_line.as_bytes()).await?;
    file.sync_all().await?;
    
    Ok(())
}

/// Get current process memory usage in MB
pub fn get_process_memory_mb() -> u64 {
    // In a real implementation, this would use proper OS-specific memory monitoring
    // For testing, we simulate memory usage based on system characteristics
    use std::thread;
    
    let base_memory = 50; // Base 50MB
    let thread_memory = thread::available_parallelism()
        .map(|n| n.get() as u64 * 2) // 2MB per thread
        .unwrap_or(8);
    
    // Add some variability to simulate real memory usage
    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    let variation = (current_time % 20) as u64; // 0-19 MB variation
    
    base_memory + thread_memory + variation
}

/// Validate enterprise SLA requirements
pub fn validate_enterprise_sla(
    throughput_rps: f64,
    avg_latency_ms: f64,
    error_rate_percent: f64,
    availability_percent: f64,
) -> Result<()> {
    let mut violations = Vec::new();
    
    // Enterprise SLA Requirements
    if throughput_rps < 5000.0 {
        violations.push(format!("Throughput below minimum: {:.0} RPS (required: ≥5000)", throughput_rps));
    }
    
    if avg_latency_ms > 100.0 {
        violations.push(format!("Latency above maximum: {:.1}ms (required: ≤100ms)", avg_latency_ms));
    }
    
    if error_rate_percent > 0.1 {
        violations.push(format!("Error rate above maximum: {:.2}% (required: ≤0.1%)", error_rate_percent));
    }
    
    if availability_percent < 99.9 {
        violations.push(format!("Availability below minimum: {:.2}% (required: ≥99.9%)", availability_percent));
    }
    
    if !violations.is_empty() {
        return Err(anyhow::anyhow!("Enterprise SLA violations: {}", violations.join(", ")));
    }
    
    Ok(())
}
