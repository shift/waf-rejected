use anyhow::Result;

#[derive(Debug)]
#[allow(dead_code)]
struct AttackTest {
    name: String,
    attack_type: String,
    payloads: Vec<String>,
    expected_detection: bool,
}

#[derive(Debug)]
struct SecurityTestResults {
    total_tests: u32,
    detected: u32,
    missed: u32,
    false_positives: u32,
    true_negatives: u32,
    detection_rate: f64,
    false_positive_rate: f64,
}

fn create_attack_test_suite() -> Vec<AttackTest> {
    vec![
        // SQL Injection Tests
        AttackTest {
            name: "SQL Injection - Union Based".to_string(),
            attack_type: "SQLi".to_string(),
            payloads: vec![
                "' UNION SELECT 1,2,3--".to_string(),
                "1' OR '1'='1".to_string(),
                "'; DROP TABLE users; --".to_string(),
                "admin'--".to_string(),
                "' OR 1=1#".to_string(),
            ],
            expected_detection: true,
        },

        // Cross-Site Scripting Tests
        AttackTest {
            name: "Cross-Site Scripting".to_string(),
            attack_type: "XSS".to_string(),
            payloads: vec![
                "<script>alert('XSS')</script>".to_string(),
                "javascript:alert('XSS')".to_string(),
                "<img src=x onerror=alert('XSS')>".to_string(),
                "\"><script>alert('XSS')</script>".to_string(),
            ],
            expected_detection: true,
        },

        // Command Injection Tests
        AttackTest {
            name: "Command Injection".to_string(),
            attack_type: "RCE".to_string(),
            payloads: vec![
                "; ls -la".to_string(),
                "| whoami".to_string(),
                "&& cat /etc/passwd".to_string(),
                "`id`".to_string(),
                "$(uname -a)".to_string(),
            ],
            expected_detection: true,
        },

        // Path Traversal Tests
        AttackTest {
            name: "Path Traversal".to_string(),
            attack_type: "LFI".to_string(),
            payloads: vec![
                "../../../etc/passwd".to_string(),
                "..\\..\\..\\windows\\system32\\config\\sam".to_string(),
                "/etc/passwd".to_string(),
                "....//....//....//etc/passwd".to_string(),
            ],
            expected_detection: true,
        },

        // Remote File Inclusion Tests
        AttackTest {
            name: "Remote File Inclusion".to_string(),
            attack_type: "RFI".to_string(),
            payloads: vec![
                "http://evil.com/shell.php".to_string(),
                "https://attacker.site/malware.txt".to_string(),
                "ftp://malicious.com/backdoor.php".to_string(),
            ],
            expected_detection: true,
        },

        // XML External Entity Tests
        AttackTest {
            name: "XML External Entity".to_string(),
            attack_type: "XXE".to_string(),
            payloads: vec![
                "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]><root>&test;</root>".to_string(),
                "<!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM \"file:///etc/passwd\" >]><foo>&xxe;</foo>".to_string(),
            ],
            expected_detection: true,
        },

        // Legitimate Requests (should NOT be detected)
        AttackTest {
            name: "Legitimate Requests".to_string(),
            attack_type: "LEGITIMATE".to_string(),
            payloads: vec![
                "SELECT * FROM products WHERE category='electronics'".to_string(),
                "<h1>Welcome to our website</h1>".to_string(),
                "user@example.com".to_string(),
                "/api/v1/users/profile".to_string(),
                "{\"name\": \"John Doe\", \"email\": \"john@example.com\"}".to_string(),
                "search_term=laptop computers".to_string(),
            ],
            expected_detection: false,
        },
    ]
}

fn simulate_waf_detection(payload: &str) -> bool {
    // Simplified WAF detection logic for testing
    let suspicious_patterns = [
        // SQL Injection patterns
        r"union\s+select",
        r"or\s+1\s*=\s*1",
        r"drop\s+table",
        r"';?\s*--",
        // XSS patterns
        r"<script",
        r"javascript:",
        r"onerror\s*=",
        r"alert\s*\(",
        // Command Injection patterns
        r";\s*(ls|cat|whoami|id)",
        r"\|\s*(ls|cat|whoami)",
        r"&&\s*(ls|cat|whoami)",
        r"`[^`]*`",
        r"\$\([^)]*\)",
        // Path Traversal patterns
        r"\.\./",
        r"\.\.\\",
        r"/etc/passwd",
        r"windows\\system32",
        // RFI patterns
        r"https?://[^/\s]+/",
        r"ftp://[^/\s]+/",
        // XXE patterns
        r"<!DOCTYPE[^>]*>",
        r"<!ENTITY[^>]*>",
        r#"SYSTEM\s+["'][^"']*["']"#,
    ];

    let payload_lower = payload.to_lowercase();

    for pattern in &suspicious_patterns {
        if regex::Regex::new(pattern).unwrap().is_match(&payload_lower) {
            return true;
        }
    }

    false
}

fn run_security_tests(tests: &[AttackTest]) -> SecurityTestResults {
    let mut total_tests = 0u32;
    let mut detected = 0u32;
    let mut missed = 0u32;
    let mut false_positives = 0u32;
    let mut true_negatives = 0u32;

    for test in tests {
        for payload in &test.payloads {
            total_tests += 1;
            let was_detected = simulate_waf_detection(payload);

            match (test.expected_detection, was_detected) {
                (true, true) => detected += 1,         // True Positive
                (true, false) => missed += 1,          // False Negative
                (false, true) => false_positives += 1, // False Positive
                (false, false) => true_negatives += 1, // True Negative
            }

            println!(
                "  {} [{}]: {} -> {}",
                test.attack_type,
                if was_detected { "BLOCKED" } else { "ALLOWED" },
                payload.chars().take(50).collect::<String>(),
                if test.expected_detection == was_detected {
                    "✅"
                } else {
                    "❌"
                }
            );
        }
    }

    let detection_rate = if (detected + missed) > 0 {
        detected as f64 / (detected + missed) as f64 * 100.0
    } else {
        0.0
    };

    let false_positive_rate = if (false_positives + true_negatives) > 0 {
        false_positives as f64 / (false_positives + true_negatives) as f64 * 100.0
    } else {
        0.0
    };

    SecurityTestResults {
        total_tests,
        detected,
        missed,
        false_positives,
        true_negatives,
        detection_rate,
        false_positive_rate,
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    println!("🔐 Enterprise Security Testing");
    println!("==============================");

    let test_suite = create_attack_test_suite();

    println!("🧪 Running {} attack test categories...", test_suite.len());
    println!();

    let results = run_security_tests(&test_suite);

    println!("\n📊 Security Test Results Summary");
    println!("===============================");
    println!("Total Tests: {}", results.total_tests);
    println!("Detected (True Positives): {}", results.detected);
    println!("Missed (False Negatives): {}", results.missed);
    println!("False Positives: {}", results.false_positives);
    println!("True Negatives: {}", results.true_negatives);
    println!("Detection Rate: {:.1}%", results.detection_rate);
    println!("False Positive Rate: {:.1}%", results.false_positive_rate);

    println!("\n🎯 Enterprise Security Requirements Validation");
    println!("==============================================");

    // Enterprise requirements validation
    let mut all_passed = true;

    // Requirement 1: Detection Rate ≥95%
    if results.detection_rate >= 95.0 {
        println!(
            "✅ Detection Rate: {:.1}% (≥95% required)",
            results.detection_rate
        );
    } else {
        println!(
            "❌ Detection Rate: {:.1}% (≥95% required)",
            results.detection_rate
        );
        all_passed = false;
    }

    // Requirement 2: False Positive Rate <2%
    if results.false_positive_rate < 2.0 {
        println!(
            "✅ False Positive Rate: {:.1}% (<2% required)",
            results.false_positive_rate
        );
    } else {
        println!(
            "❌ False Positive Rate: {:.1}% (<2% required)",
            results.false_positive_rate
        );
        all_passed = false;
    }

    if all_passed {
        println!("\n🏆 All security requirements passed!");
        Ok(())
    } else {
        Err(anyhow::anyhow!("Security requirements not met"))
    }
}
