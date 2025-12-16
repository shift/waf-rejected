use crate::config::Config;
use crate::waf::{Decision, RequestContext, WafRule};
use hyper::Method;
use regex::Regex;
use std::collections::HashSet;
use std::net::IpAddr;
use tracing::debug;

/// Rule for checking request size limits
pub struct RequestSizeRule {
    name: String,
    max_size: usize,
    enabled: bool,
}

impl RequestSizeRule {
    pub fn new(name: &str, max_size: usize) -> Self {
        Self {
            name: name.to_string(),
            max_size,
            enabled: true,
        }
    }

    pub fn disabled(mut self) -> Self {
        self.enabled = false;
        self
    }
}

impl WafRule for RequestSizeRule {
    fn name(&self) -> &str {
        &self.name
    }

    fn evaluate(&self, ctx: &RequestContext) -> Decision {
        if let Some(body_size) = ctx.body_size {
            if body_size > self.max_size {
                return Decision::Block {
                    status: 413,
                    reason: format!(
                        "Request body size {} exceeds limit {}",
                        body_size, self.max_size
                    ),
                };
            }
        }
        Decision::Allow
    }

    fn is_enabled(&self) -> bool {
        self.enabled
    }
}

/// Rule for blocking specific HTTP methods
pub struct MethodRule {
    name: String,
    blocked_methods: HashSet<Method>,
    enabled: bool,
}

impl MethodRule {
    pub fn new(name: &str) -> Self {
        let mut blocked_methods = HashSet::new();
        blocked_methods.insert(Method::TRACE);
        blocked_methods.insert(Method::CONNECT);

        Self {
            name: name.to_string(),
            blocked_methods,
            enabled: true,
        }
    }

    pub fn block_method(mut self, method: Method) -> Self {
        self.blocked_methods.insert(method);
        self
    }

    pub fn disabled(mut self) -> Self {
        self.enabled = false;
        self
    }
}

impl WafRule for MethodRule {
    fn name(&self) -> &str {
        &self.name
    }

    fn evaluate(&self, ctx: &RequestContext) -> Decision {
        if self.blocked_methods.contains(&ctx.method) {
            return Decision::Block {
                status: 405,
                reason: format!("HTTP method {} is not allowed", ctx.method),
            };
        }
        Decision::Allow
    }

    fn is_enabled(&self) -> bool {
        self.enabled
    }
}

/// Rule for enforcing security headers
pub struct HeaderRule {
    name: String,
    required_headers: Vec<String>,
    forbidden_headers: Vec<String>,
    enabled: bool,
}

impl HeaderRule {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            required_headers: Vec::new(),
            forbidden_headers: Vec::new(),
            enabled: true,
        }
    }

    pub fn require_header(mut self, header: &str) -> Self {
        self.required_headers.push(header.to_lowercase());
        self
    }

    pub fn forbid_header(mut self, header: &str) -> Self {
        self.forbidden_headers.push(header.to_lowercase());
        self
    }

    pub fn disabled(mut self) -> Self {
        self.enabled = false;
        self
    }
}

impl WafRule for HeaderRule {
    fn name(&self) -> &str {
        &self.name
    }

    fn evaluate(&self, ctx: &RequestContext) -> Decision {
        // Check for forbidden headers
        for forbidden in &self.forbidden_headers {
            if ctx.headers.contains_key(forbidden) {
                return Decision::Block {
                    status: 400,
                    reason: format!("Forbidden header '{}' present", forbidden),
                };
            }
        }

        // Check for required headers
        for required in &self.required_headers {
            if !ctx.headers.contains_key(required) {
                return Decision::Block {
                    status: 400,
                    reason: format!("Required header '{}' missing", required),
                };
            }
        }

        Decision::Allow
    }

    fn is_enabled(&self) -> bool {
        self.enabled
    }
}

/// Rule for SQL injection detection
pub struct SqlInjectionRule {
    name: String,
    patterns: Vec<Regex>,
    enabled: bool,
}

impl SqlInjectionRule {
    pub fn new(name: &str) -> Self {
        let patterns = vec![
            Regex::new(r"(?i)\bunion(\s|%20|\+)+select\b").unwrap(),
            Regex::new(r"(?i)\bselect(\s|%20|\+)+.*(\s|%20|\+)+from\b").unwrap(),
            Regex::new(r"(?i)\binsert(\s|%20|\+)+into\b").unwrap(),
            Regex::new(r"(?i)\bupdate(\s|%20|\+)+.*(\s|%20|\+)+set\b").unwrap(),
            Regex::new(r"(?i)\bdelete(\s|%20|\+)+from\b").unwrap(),
            Regex::new(r"(?i)\bdrop(\s|%20|\+)+table\b").unwrap(),
            Regex::new(r"(?i)\bor(\s|%20|\+)+.*(\s|%20|\+)*=").unwrap(),
            Regex::new(r"(?i)\band(\s|%20|\+)+.*(\s|%20|\+)*=").unwrap(),
            Regex::new(r"'.*(\bor\b|\band\b).*'").unwrap(),
            Regex::new(r"(?i)\b(exec|execute)\b").unwrap(),
        ];

        Self {
            name: name.to_string(),
            patterns,
            enabled: true,
        }
    }

    pub fn disabled(mut self) -> Self {
        self.enabled = false;
        self
    }
}

impl WafRule for SqlInjectionRule {
    fn name(&self) -> &str {
        &self.name
    }

    fn evaluate(&self, ctx: &RequestContext) -> Decision {
        let uri_str = ctx.uri.to_string();

        // Check URI for SQL injection patterns
        for pattern in &self.patterns {
            if pattern.is_match(&uri_str) {
                return Decision::Block {
                    status: 403,
                    reason: format!(
                        "SQL injection pattern detected in URI: {}",
                        pattern.as_str()
                    ),
                };
            }
        }

        // Check headers for SQL injection patterns
        for (name, value) in ctx.headers.iter() {
            if let Ok(value_str) = value.to_str() {
                for pattern in &self.patterns {
                    if pattern.is_match(value_str) {
                        return Decision::Block {
                            status: 403,
                            reason: format!(
                                "SQL injection pattern detected in header '{}': {}",
                                name.as_str(),
                                pattern.as_str()
                            ),
                        };
                    }
                }
            }
        }

        // Check body if present
        if let Some(ref body) = ctx.body {
            if let Ok(body_str) = std::str::from_utf8(body) {
                for pattern in &self.patterns {
                    if pattern.is_match(body_str) {
                        return Decision::Block {
                            status: 403,
                            reason: format!(
                                "SQL injection pattern detected in body: {}",
                                pattern.as_str()
                            ),
                        };
                    }
                }
            }
        }

        Decision::Allow
    }

    fn is_enabled(&self) -> bool {
        self.enabled
    }
}

/// Rule for XSS detection
pub struct XssRule {
    name: String,
    patterns: Vec<Regex>,
    enabled: bool,
}

impl XssRule {
    pub fn new(name: &str) -> Self {
        let patterns = vec![
            Regex::new(r"(?i)(<|%3C)script[^>%]*?(>|%3E)").unwrap(),
            Regex::new(r"(?i)(<|%3C)/script(>|%3E)").unwrap(),
            Regex::new(r"(?i)javascript:").unwrap(),
            Regex::new(r"(?i)on\w+(\s|%20)*=").unwrap(),
            Regex::new(r"(?i)(<|%3C)iframe[^>%]*?(>|%3E)").unwrap(),
            Regex::new(r"(?i)(<|%3C)object[^>%]*?(>|%3E)").unwrap(),
            Regex::new(r"(?i)(<|%3C)embed[^>%]*?(>|%3E)").unwrap(),
            Regex::new(r"(?i)expression(\s|%20)*\(").unwrap(),
            Regex::new(r"(?i)vbscript:").unwrap(),
            Regex::new(r"(?i)(<|%3C)meta[^>%]*http-equiv").unwrap(),
        ];

        Self {
            name: name.to_string(),
            patterns,
            enabled: true,
        }
    }

    pub fn disabled(mut self) -> Self {
        self.enabled = false;
        self
    }
}

impl WafRule for XssRule {
    fn name(&self) -> &str {
        &self.name
    }

    fn evaluate(&self, ctx: &RequestContext) -> Decision {
        let uri_str = ctx.uri.to_string();

        // Check URI for XSS patterns
        for pattern in &self.patterns {
            if pattern.is_match(&uri_str) {
                return Decision::Block {
                    status: 403,
                    reason: format!("XSS pattern detected in URI: {}", pattern.as_str()),
                };
            }
        }

        // Check headers for XSS patterns
        for (name, value) in ctx.headers.iter() {
            if let Ok(value_str) = value.to_str() {
                for pattern in &self.patterns {
                    if pattern.is_match(value_str) {
                        return Decision::Block {
                            status: 403,
                            reason: format!(
                                "XSS pattern detected in header '{}': {}",
                                name.as_str(),
                                pattern.as_str()
                            ),
                        };
                    }
                }
            }
        }

        // Check body if present
        if let Some(ref body) = ctx.body {
            if let Ok(body_str) = std::str::from_utf8(body) {
                for pattern in &self.patterns {
                    if pattern.is_match(body_str) {
                        return Decision::Block {
                            status: 403,
                            reason: format!("XSS pattern detected in body: {}", pattern.as_str()),
                        };
                    }
                }
            }
        }

        Decision::Allow
    }

    fn is_enabled(&self) -> bool {
        self.enabled
    }
}

/// Rule factory for creating common WAF rules
pub struct WafRuleFactory;

impl WafRuleFactory {
    pub fn create_basic_rules(config: &Config) -> Vec<Box<dyn WafRule>> {
        let mut rules: Vec<Box<dyn WafRule>> = Vec::new();

        // Request size rule
        rules.push(Box::new(RequestSizeRule::new(
            "max_body_size",
            config.server.max_body_size,
        )));

        // Method blocking rule
        rules.push(Box::new(MethodRule::new("blocked_methods")));

        // Security headers rule
        rules.push(Box::new(HeaderRule::new("security_headers")));

        // SQL injection detection
        rules.push(Box::new(SqlInjectionRule::new("sql_injection_detection")));

        // XSS detection
        rules.push(Box::new(XssRule::new("xss_detection")));

        debug!("Created {} basic WAF rules", rules.len());
        rules
    }
}

/// Rule for IP-based blocking/allowing
pub struct IpRule {
    name: String,
    blocked_ips: HashSet<IpAddr>,
    allowed_ips: HashSet<IpAddr>,
    enabled: bool,
}

impl IpRule {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            blocked_ips: HashSet::new(),
            allowed_ips: HashSet::new(),
            enabled: true,
        }
    }

    pub fn block_ip(mut self, ip: IpAddr) -> Self {
        self.blocked_ips.insert(ip);
        self
    }

    pub fn block_ip_str(mut self, ip_str: &str) -> Result<Self, std::net::AddrParseError> {
        let ip: IpAddr = ip_str.parse()?;
        self.blocked_ips.insert(ip);
        Ok(self)
    }

    pub fn allow_ip(mut self, ip: IpAddr) -> Self {
        self.allowed_ips.insert(ip);
        self
    }

    pub fn allow_ip_str(mut self, ip_str: &str) -> Result<Self, std::net::AddrParseError> {
        let ip: IpAddr = ip_str.parse()?;
        self.allowed_ips.insert(ip);
        Ok(self)
    }
}

impl WafRule for IpRule {
    fn name(&self) -> &str {
        &self.name
    }

    fn is_enabled(&self) -> bool {
        self.enabled
    }

    fn evaluate(&self, ctx: &RequestContext) -> Decision {
        // Check if IP is in blocked list
        if self.blocked_ips.contains(&ctx.client_ip) {
            return Decision::Block {
                status: 403,
                reason: format!("IP {} is blocked", ctx.client_ip),
            };
        }

        // If there's an allow list and IP is not in it, block
        if !self.allowed_ips.is_empty() && !self.allowed_ips.contains(&ctx.client_ip) {
            return Decision::Block {
                status: 403,
                reason: format!("IP {} is not in allow list", ctx.client_ip),
            };
        }

        Decision::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::{Method, Uri};
    use std::net::IpAddr;
    use std::str::FromStr;

    fn create_test_context() -> RequestContext {
        RequestContext::new(
            IpAddr::from_str("192.168.1.100").unwrap(),
            Method::GET,
            Uri::from_str("/test").unwrap(),
            HeaderMap::new(),
            Some(1000),
        )
    }

    #[test]
    fn test_request_size_rule() {
        let rule = RequestSizeRule::new("test", 500);
        let ctx = create_test_context();

        match rule.evaluate(&ctx) {
            Decision::Block { status, reason } => {
                assert_eq!(status, 413);
                assert!(reason.contains("exceeds limit"));
            }
            _ => panic!("Expected Block decision"),
        }
    }

    #[test]
    fn test_method_rule() {
        let rule = MethodRule::new("test").block_method(Method::GET);
        let ctx = create_test_context();

        match rule.evaluate(&ctx) {
            Decision::Block { status, reason } => {
                assert_eq!(status, 405);
                assert!(reason.contains("not allowed"));
            }
            _ => panic!("Expected Block decision"),
        }
    }

    #[test]
    fn test_sql_injection_rule() {
        let rule = SqlInjectionRule::new("test");
        let mut ctx = create_test_context();
        ctx.uri = Uri::from_str("/test?id=1+OR+1=1").unwrap();

        match rule.evaluate(&ctx) {
            Decision::Block { status, reason } => {
                assert_eq!(status, 403);
                assert!(reason.contains("SQL injection"));
            }
            _ => panic!("Expected Block decision"),
        }
    }

    #[test]
    fn test_xss_rule() {
        let rule = XssRule::new("test");
        let mut ctx = create_test_context();
        ctx.uri = Uri::from_str("/test?script=%3Cscript%3Ealert('xss')%3C/script%3E").unwrap();

        match rule.evaluate(&ctx) {
            Decision::Block { status, reason } => {
                assert_eq!(status, 403);
                assert!(reason.contains("XSS"));
            }
            _ => panic!("Expected Block decision"),
        }
    }
}
