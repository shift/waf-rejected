use crate::waf::{Decision, RequestContext, WafRule};
use once_cell::sync::Lazy;
use regex::Regex;

/// Advanced content inspection rules for common web attacks (optimized for performance)
pub struct ContentInspectionRule {
    name: String,
    enabled: bool,
    patterns: Vec<ThreatPattern>,
    // Performance optimization: cache compiled patterns by priority
    high_priority_patterns: Vec<ThreatPattern>,
    low_priority_patterns: Vec<ThreatPattern>,
}

#[derive(Debug, Clone)]
pub struct ThreatPattern {
    pub name: String,
    pub pattern: Regex,
    pub severity: ThreatSeverity,
    pub attack_type: AttackType,
    pub check_uri: bool,
    pub check_headers: bool,
    pub check_body: bool,
}

#[derive(Debug, Clone)]
pub enum AttackType {
    SqlInjection,
    XssAttack,
    CommandInjection,
    PathTraversal,
    RemoteFileInclusion,
    LocalFileInclusion,
    XXEAttack,
    SSRFAttack,
}

#[derive(Debug, Clone)]
pub enum ThreatSeverity {
    Low,
    Medium,
    High,
    Critical,
}

// Pre-compiled patterns for performance
/// Truncate attacker-controlled text on a UTF-8 character boundary.
fn limited_match_text(value: &str) -> &str {
    if value.len() <= 100 {
        return value;
    }
    match value.char_indices().nth(100) {
        Some((index, _)) => &value[..index],
        None => value,
    }
}

fn percent_decode(input: &str) -> Option<String> {
    if !input.contains('%') && !input.contains('+') {
        return None;
    }
    urlencoding::decode(input)
        .ok()
        .map(|decoded| decoded.into_owned())
}

static COMMON_PATTERNS: Lazy<Vec<ThreatPattern>> = Lazy::new(|| {
    vec![
        // SQL Injection patterns
        ThreatPattern {
            name: "SQL Injection - UNION SELECT".to_string(),
            pattern: Regex::new(r"(?i)(?:^|[^a-z0-9_]|%20|\+)union(\s|%20|\+)+select(?:$|[^a-z0-9_]|%20|\+)").unwrap(),
            severity: ThreatSeverity::High,
            attack_type: AttackType::SqlInjection,
            check_uri: true,
            check_headers: true,
            check_body: true,
        },
        ThreatPattern {
            name: "SQL Injection - OR 1=1".to_string(),
            pattern: Regex::new(
                r#"(?i)(?:^|[^a-z0-9_]|%20|\+)or(\s|%20|\+)+['"]?\d+['"]?(\s|%20|\+)*=(\s|%20|\+)*['"]?\d+"#,
            )
            .unwrap(),
            severity: ThreatSeverity::High,
            attack_type: AttackType::SqlInjection,
            check_uri: true,
            check_headers: true,
            check_body: true,
        },
        ThreatPattern {
            name: "SQL Injection - DROP TABLE".to_string(),
            pattern: Regex::new(r"(?i)(?:^|[^a-z0-9_]|%20|\+)drop(\s|%20|\+)+table(?:$|[^a-z0-9_]|%20|\+)").unwrap(),
            severity: ThreatSeverity::Critical,
            attack_type: AttackType::SqlInjection,
            check_uri: true,
            check_headers: true,
            check_body: true,
        },
        // XSS patterns
        ThreatPattern {
            name: "XSS - Script tag".to_string(),
            pattern: Regex::new(r"(?i)(<|%3C)script[^>%]*?(>|%3E)").unwrap(),
            severity: ThreatSeverity::High,
            attack_type: AttackType::XssAttack,
            check_uri: true,
            check_headers: true,
            check_body: true,
        },
        ThreatPattern {
            name: "XSS - JavaScript protocol".to_string(),
            pattern: Regex::new(r"(?i)javascript:").unwrap(),
            severity: ThreatSeverity::Medium,
            attack_type: AttackType::XssAttack,
            check_uri: true,
            check_headers: true,
            check_body: true,
        },
        ThreatPattern {
            name: "XSS - Event handlers".to_string(),
            pattern: Regex::new(r"(?i)on(load|error|click|mouseover)(\s|%20|\+)*=").unwrap(),
            severity: ThreatSeverity::High,
            attack_type: AttackType::XssAttack,
            check_uri: true,
            check_headers: true,
            check_body: true,
        },
        // Command Injection patterns
        ThreatPattern {
            name: "Command Injection - Shell commands".to_string(),
            pattern: Regex::new(r"(?i)(;|&&|\|\|)(\s|%20|\+)*(cat|ls|ps|id|whoami|pwd)\b").unwrap(),
            severity: ThreatSeverity::Critical,
            attack_type: AttackType::CommandInjection,
            check_uri: true,
            check_headers: true,
            check_body: true,
        },
        ThreatPattern {
            name: "Command Injection - Pipe commands".to_string(),
            pattern: Regex::new(r"\|(\s|%20|\+)*(wget|curl|nc|netcat)\b").unwrap(),
            severity: ThreatSeverity::Critical,
            attack_type: AttackType::CommandInjection,
            check_uri: true,
            check_headers: true,
            check_body: true,
        },
        // Path Traversal patterns
        ThreatPattern {
            name: "Path Traversal - Directory traversal".to_string(),
            pattern: Regex::new(r"(\.\./|\.\.\\){2,}").unwrap(),
            severity: ThreatSeverity::High,
            attack_type: AttackType::PathTraversal,
            check_uri: true,
            check_headers: true,
            check_body: true,
        },
        ThreatPattern {
            name: "Path Traversal - Absolute paths".to_string(),
            pattern: Regex::new(r"(?i)(^|[^a-z])/etc/(passwd|shadow|hosts)").unwrap(),
            severity: ThreatSeverity::High,
            attack_type: AttackType::PathTraversal,
            check_uri: true,
            check_headers: true,
            check_body: true,
        },
        // File Inclusion patterns
        ThreatPattern {
            name: "Remote File Inclusion - HTTP URLs".to_string(),
            pattern: Regex::new(r"(?i)https?://[^/\s]+/").unwrap(),
            severity: ThreatSeverity::Medium,
            attack_type: AttackType::RemoteFileInclusion,
            check_uri: true,
            check_headers: false,
            check_body: true,
        },
        ThreatPattern {
            name: "Local File Inclusion - File protocol".to_string(),
            pattern: Regex::new(r"(?i)file://").unwrap(),
            severity: ThreatSeverity::High,
            attack_type: AttackType::LocalFileInclusion,
            check_uri: true,
            check_headers: false,
            check_body: true,
        },
        // XXE patterns
        ThreatPattern {
            name: "XXE Attack - External entity".to_string(),
            pattern: Regex::new(r"(?i)<!entity[^>]+system").unwrap(),
            severity: ThreatSeverity::High,
            attack_type: AttackType::XXEAttack,
            check_uri: false,
            check_headers: false,
            check_body: true,
        },
        // SSRF patterns
        ThreatPattern {
            name: "SSRF - Localhost access".to_string(),
            pattern: Regex::new(r"(?i)(localhost|127\.0\.0\.1|0\.0\.0\.0)").unwrap(),
            severity: ThreatSeverity::Medium,
            attack_type: AttackType::SSRFAttack,
            check_uri: true,
            check_headers: false,
            check_body: true,
        },
        ThreatPattern {
            name: "SSRF - Internal IP ranges".to_string(),
            pattern: Regex::new(r"(?i)(192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.)").unwrap(),
            severity: ThreatSeverity::Medium,
            attack_type: AttackType::SSRFAttack,
            check_uri: true,
            check_headers: false,
            check_body: true,
        },
    ]
});

impl ContentInspectionRule {
    pub fn new(name: &str) -> Self {
        let patterns = COMMON_PATTERNS.clone();
        let (high_priority, low_priority) = Self::categorize_patterns(&patterns);

        Self {
            name: name.to_string(),
            enabled: true,
            patterns,
            high_priority_patterns: high_priority,
            low_priority_patterns: low_priority,
        }
    }

    pub fn with_custom_patterns(name: &str, patterns: Vec<ThreatPattern>) -> Self {
        let (high_priority, low_priority) = Self::categorize_patterns(&patterns);

        Self {
            name: name.to_string(),
            enabled: true,
            patterns,
            high_priority_patterns: high_priority,
            low_priority_patterns: low_priority,
        }
    }

    pub fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    pub fn add_pattern(&mut self, pattern: ThreatPattern) {
        // Categorize new pattern for performance
        match pattern.severity {
            ThreatSeverity::Critical | ThreatSeverity::High => {
                self.high_priority_patterns.push(pattern.clone());
            }
            ThreatSeverity::Medium | ThreatSeverity::Low => {
                self.low_priority_patterns.push(pattern.clone());
            }
        }
        self.patterns.push(pattern);
    }

    /// Performance optimization: categorize patterns by priority
    fn categorize_patterns(patterns: &[ThreatPattern]) -> (Vec<ThreatPattern>, Vec<ThreatPattern>) {
        let mut high_priority = Vec::new();
        let mut low_priority = Vec::new();

        for pattern in patterns {
            match pattern.severity {
                ThreatSeverity::Critical | ThreatSeverity::High => {
                    high_priority.push(pattern.clone());
                }
                ThreatSeverity::Medium | ThreatSeverity::Low => {
                    low_priority.push(pattern.clone());
                }
            }
        }

        (high_priority, low_priority)
    }

    /// Check high-priority patterns.
    ///
    /// Regex matching is always performed. The SIMD helpers are only a
    /// fast-path optimisation and must never decide that content is safe,
    /// otherwise encodings such as `UNION+SELECT` or `%3Cscript%3E` bypass
    /// inspection.
    fn fast_check_content(&self, content: &str) -> Option<(&ThreatPattern, String)> {
        Self::find_match(&self.high_priority_patterns, content)
    }

    fn check_content(&self, content: &str) -> Option<(&ThreatPattern, String)> {
        // First check high-priority patterns, then medium/low severity ones.
        if let Some(result) = self.fast_check_content(content) {
            return Some(result);
        }
        Self::find_match(&self.low_priority_patterns, content)
    }

    /// Check both the raw value and its percent-decoded form. Attackers often
    /// encode quote/space/angle-bracket characters to bypass naive rules.
    fn check_with_decoding(&self, content: &str, full: bool) -> Option<(&ThreatPattern, String)> {
        let check = |value: &str| {
            if full {
                self.check_content(value)
            } else {
                self.fast_check_content(value)
            }
        };

        if let Some(found) = check(content) {
            return Some(found);
        }
        if let Some(decoded) = percent_decode(content) {
            if decoded != content {
                return check(&decoded);
            }
        }
        None
    }

    fn inspect_body(&self, content: &str) -> Option<(&ThreatPattern, String)> {
        for pattern in &self.patterns {
            if !pattern.check_body {
                continue;
            }
            if let Some(matched) = pattern.pattern.find(content) {
                return Some((pattern, limited_match_text(matched.as_str()).to_string()));
            }
        }
        None
    }

    fn find_match<'a>(
        patterns: &'a [ThreatPattern],
        content: &str,
    ) -> Option<(&'a ThreatPattern, String)> {
        for pattern in patterns {
            if let Some(matched) = pattern.pattern.find(content) {
                return Some((pattern, limited_match_text(matched.as_str()).to_string()));
            }
        }
        None
    }

    fn severity_to_status(&self, severity: &ThreatSeverity) -> u16 {
        match severity {
            ThreatSeverity::Low => 400,
            ThreatSeverity::Medium => 403,
            ThreatSeverity::High => 403,
            ThreatSeverity::Critical => 403,
        }
    }
}

impl WafRule for ContentInspectionRule {
    fn name(&self) -> &str {
        &self.name
    }

    fn is_enabled(&self) -> bool {
        self.enabled
    }

    fn evaluate(&self, ctx: &RequestContext) -> Decision {
        if !self.enabled {
            return Decision::Allow;
        }

        // Performance optimization: limit content size to prevent DoS
        const MAX_CONTENT_SIZE: usize = 8192; // 8KB limit for pattern matching

        // Check URI path (high priority). Over-length URIs are rejected rather
        // than skipped, otherwise padding can hide a payload.
        let uri_path = ctx.uri.path();
        if uri_path.len() > MAX_CONTENT_SIZE {
            return Decision::Block {
                status: 414,
                reason: "Content inspection: URI path too long".to_string(),
            };
        }
        if let Some((pattern, matched)) = self.check_with_decoding(uri_path, false) {
            if pattern.check_uri {
                return Decision::Block {
                    status: self.severity_to_status(&pattern.severity),
                    reason: format!(
                        "Content inspection: {} detected in URI: {}",
                        pattern.name, matched
                    ),
                };
            }
        }

        // Check query parameters (if present).
        if let Some(query) = ctx.uri.query() {
            if query.len() > MAX_CONTENT_SIZE {
                return Decision::Block {
                    status: 414,
                    reason: "Content inspection: query string too long".to_string(),
                };
            }
            // Use full check on query to include medium/low severity patterns.
            if let Some((pattern, matched)) = self.check_with_decoding(query, true) {
                if pattern.check_uri {
                    return Decision::Block {
                        status: self.severity_to_status(&pattern.severity),
                        reason: format!(
                            "Content inspection: {} detected in query: {}",
                            pattern.name, matched
                        ),
                    };
                }
            }
        }

        // Check headers (optimized for performance)
        for pattern in &self.high_priority_patterns {
            if pattern.check_headers {
                for (header_name, header_value) in ctx.headers.iter() {
                    if let Ok(header_str) = header_value.to_str() {
                        if pattern.pattern.is_match(header_str) {
                            return Decision::Block {
                                status: self.severity_to_status(&pattern.severity),
                                reason: format!(
                                    "Content inspection: {} detected in header {}",
                                    pattern.name, header_name
                                ),
                            };
                        }
                    }
                }
            }
        }

        // Inspect the complete accepted body. The proxy enforces
        // `server.max_body_size`; this hard cap is a final defence against
        // inspecting an unbounded buffer.
        const MAX_BODY_INSPECTION: usize = 16 * 1024 * 1024; // 16 MiB
        if let Some(body) = &ctx.body {
            if body.len() > MAX_BODY_INSPECTION {
                return Decision::Block {
                    status: 413,
                    reason: format!(
                        "Content inspection: body exceeds {} bytes",
                        MAX_BODY_INSPECTION
                    ),
                };
            }
            let content = String::from_utf8_lossy(body);
            let found = self.inspect_body(&content).or_else(|| {
                percent_decode(&content)
                    .filter(|decoded| decoded != &content)
                    .and_then(|decoded| self.inspect_body(&decoded))
            });
            if let Some((pattern, matched)) = found {
                return Decision::Block {
                    status: self.severity_to_status(&pattern.severity),
                    reason: format!(
                        "Content inspection: {} detected in body: {}",
                        pattern.name, matched
                    ),
                };
            }
        }

        Decision::Allow
    }
}

/// Factory for creating common content inspection rules
pub struct ContentInspectionRuleFactory;

impl ContentInspectionRuleFactory {
    /// Create a threat rule by pattern name
    pub fn create_threat_rule(pattern_name: &str) -> ContentInspectionRule {
        match pattern_name {
            "sql_injection" => Self::sql_injection_rule(),
            "xss" => Self::xss_rule(),
            "command_injection" => Self::command_injection_rule(),
            "path_traversal" => Self::path_traversal_rule(),
            _ => {
                // Default to a combined rule with all patterns
                ContentInspectionRule::new("Generic Threat Detection")
            }
        }
    }

    pub fn sql_injection_rule() -> ContentInspectionRule {
        let patterns = COMMON_PATTERNS
            .iter()
            .filter(|p| matches!(p.attack_type, AttackType::SqlInjection))
            .cloned()
            .collect();

        ContentInspectionRule::with_custom_patterns("SQL Injection Detection", patterns)
    }

    pub fn xss_rule() -> ContentInspectionRule {
        let patterns = COMMON_PATTERNS
            .iter()
            .filter(|p| matches!(p.attack_type, AttackType::XssAttack))
            .cloned()
            .collect();

        ContentInspectionRule::with_custom_patterns("XSS Detection", patterns)
    }

    pub fn command_injection_rule() -> ContentInspectionRule {
        let patterns = COMMON_PATTERNS
            .iter()
            .filter(|p| matches!(p.attack_type, AttackType::CommandInjection))
            .cloned()
            .collect();

        ContentInspectionRule::with_custom_patterns("Command Injection Detection", patterns)
    }

    pub fn path_traversal_rule() -> ContentInspectionRule {
        let patterns = COMMON_PATTERNS
            .iter()
            .filter(|p| matches!(p.attack_type, AttackType::PathTraversal))
            .cloned()
            .collect();

        ContentInspectionRule::with_custom_patterns("Path Traversal Detection", patterns)
    }

    pub fn all_attacks_rule() -> ContentInspectionRule {
        ContentInspectionRule::new("All Common Attacks Detection")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::{HeaderMap, Method, Uri};
    use std::str::FromStr;

    fn create_test_context(uri: &str, headers: Option<HeaderMap>) -> RequestContext {
        RequestContext::new(
            std::net::IpAddr::from_str("192.168.1.100").unwrap(),
            Method::GET,
            Uri::from_str(uri).unwrap(),
            headers.unwrap_or_default(),
            None,
        )
    }

    #[test]
    fn test_sql_injection_detection() {
        let rule = ContentInspectionRuleFactory::sql_injection_rule();

        // Test UNION SELECT attack (using + for spaces which should now work with updated regex)
        let ctx = create_test_context("/api/users?id=1+UNION+SELECT+*+FROM+passwords", None);
        match rule.evaluate(&ctx) {
            Decision::Block { reason, .. } => {
                assert!(reason.contains("SQL Injection"));
            }
            _ => panic!("Expected SQL injection to be blocked"),
        }

        // Test clean request
        let ctx = create_test_context("/api/users?id=123", None);
        assert_eq!(rule.evaluate(&ctx), Decision::Allow);
    }

    #[test]
    fn test_xss_detection() {
        let rule = ContentInspectionRuleFactory::xss_rule();

        // Test script tag injection (URL encoded, should now work with updated regex)
        let ctx = create_test_context("/search?q=%3Cscript%3Ealert('xss')%3C/script%3E", None);
        match rule.evaluate(&ctx) {
            Decision::Block { reason, .. } => {
                assert!(reason.contains("XSS"));
            }
            _ => panic!("Expected XSS to be blocked"),
        }

        // Test javascript protocol
        let ctx = create_test_context("/redirect?url=javascript:alert(1)", None);
        match rule.evaluate(&ctx) {
            Decision::Block { reason, .. } => {
                assert!(reason.contains("XSS"));
            }
            _ => panic!("Expected XSS to be blocked"),
        }
    }

    #[test]
    fn test_command_injection_detection() {
        let rule = ContentInspectionRuleFactory::command_injection_rule();

        // Test command chaining (should now work with updated regex for + characters)
        let ctx = create_test_context("/exec?cmd=test;cat+/etc/passwd", None);
        match rule.evaluate(&ctx) {
            Decision::Block { reason, .. } => {
                assert!(reason.contains("Command Injection"));
            }
            _ => panic!("Expected command injection to be blocked"),
        }
    }

    #[test]
    fn test_path_traversal_detection() {
        let rule = ContentInspectionRuleFactory::path_traversal_rule();

        // Test directory traversal
        let ctx = create_test_context("/file?path=../../../etc/passwd", None);
        match rule.evaluate(&ctx) {
            Decision::Block { reason, .. } => {
                assert!(reason.contains("Path Traversal"));
            }
            _ => panic!("Expected path traversal to be blocked"),
        }
    }

    #[test]
    fn test_disabled_rule() {
        let rule = ContentInspectionRuleFactory::sql_injection_rule().enabled(false);

        let ctx = create_test_context("/api/users?id=1+UNION+SELECT+*+FROM+passwords", None);
        assert_eq!(rule.evaluate(&ctx), Decision::Allow);
    }

    #[test]
    fn test_custom_pattern() {
        let custom_pattern = ThreatPattern {
            name: "Custom Attack Pattern".to_string(),
            pattern: Regex::new(r"CUSTOM_ATTACK").unwrap(),
            severity: ThreatSeverity::High,
            attack_type: AttackType::SqlInjection,
            check_uri: true,
            check_headers: false,
            check_body: false,
        };

        let mut rule = ContentInspectionRule::new("Custom Rule");
        rule.add_pattern(custom_pattern);

        let ctx = create_test_context("/test?param=CUSTOM_ATTACK", None);
        match rule.evaluate(&ctx) {
            Decision::Block { reason, .. } => {
                assert!(reason.contains("Custom Attack Pattern"));
            }
            _ => panic!("Expected custom pattern to be blocked"),
        }
    }

    #[test]
    fn test_header_inspection() {
        let pattern = ThreatPattern {
            name: "Header XSS".to_string(),
            pattern: Regex::new(r"(?i)<script").unwrap(),
            severity: ThreatSeverity::High,
            attack_type: AttackType::XssAttack,
            check_uri: false,
            check_headers: true,
            check_body: false,
        };

        let rule = ContentInspectionRule::with_custom_patterns("Header Rule", vec![pattern]);

        let mut headers = HeaderMap::new();
        headers.insert(
            "x-custom-header",
            "<script>alert('xss')</script>".parse().unwrap(),
        );
        let ctx = create_test_context("/", Some(headers));

        match rule.evaluate(&ctx) {
            Decision::Block { reason, .. } => {
                assert!(reason.contains("Header XSS"));
            }
            _ => panic!("Expected header XSS to be blocked"),
        }
    }

    #[test]
    fn test_severity_status_mapping() {
        let rule = ContentInspectionRule::new("test");

        assert_eq!(rule.severity_to_status(&ThreatSeverity::Low), 400);
        assert_eq!(rule.severity_to_status(&ThreatSeverity::Medium), 403);
        assert_eq!(rule.severity_to_status(&ThreatSeverity::High), 403);
        assert_eq!(rule.severity_to_status(&ThreatSeverity::Critical), 403);
    }

    #[test]
    fn test_overlong_uri_is_rejected_not_skipped() {
        let rule = ContentInspectionRuleFactory::sql_injection_rule();
        let uri = format!("/?q={}", "a".repeat(9000));
        let ctx = create_test_context(&uri, None);

        assert!(matches!(
            rule.evaluate(&ctx),
            Decision::Block { status: 414, .. }
        ));
    }

    #[test]
    fn test_body_payload_after_one_mib_is_inspected() {
        let rule = ContentInspectionRuleFactory::sql_injection_rule();
        let mut body = "A".repeat(1_100_000);
        body.push_str(" id=1 UNION SELECT * FROM users");

        let mut ctx = create_test_context("/login", None);
        ctx = ctx.with_body(Some(bytes::Bytes::from(body)));
        assert!(matches!(rule.evaluate(&ctx), Decision::Block { .. }));
    }
}
