//! Compiled bodyless allowlist fast path.
//!
//! This module implements the route trie and the eligibility checks for
//! [`crate::config::WafFastAllowConfig`]. The engine wires it into the request
//! path; see [`crate::waf::WafEngine::fast_allow`].
//!
//! A fast-allow route is an explicit WAF exclusion for **bodyless** requests
//! with no query string. Only routes listed in configuration can match, and a
//! match only skips inspection rules. Always-on policy gates (request size,
//! method, rate limits and geographic blocking) still run, so the fast path
//! cannot bypass those controls.

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};

use hyper::header::{
    CONNECTION, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, TRANSFER_ENCODING, UPGRADE,
};
use hyper::{HeaderMap, Method, Uri};

use crate::config::WafFastAllowConfig;
use crate::waf::Decision;

const METHOD_GET: u16 = 1 << 0;
const METHOD_HEAD: u16 = 1 << 1;
const METHOD_POST: u16 = 1 << 2;
const METHOD_PUT: u16 = 1 << 3;
const METHOD_DELETE: u16 = 1 << 4;
const METHOD_OPTIONS: u16 = 1 << 5;
const METHOD_PATCH: u16 = 1 << 6;
const METHOD_TRACE: u16 = 1 << 7;
const METHOD_CONNECT: u16 = 1 << 8;

/// Exact route parsed from a `"METHOD /path"` configuration entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteSpec<'a> {
    pub method: Method,
    pub path: &'a str,
}

/// Parse one `"METHOD /path"` entry.
///
/// The grammar is deliberately strict: one ASCII space, a standard uppercase
/// method, and an origin-form path with no query, fragment or whitespace.
pub fn parse_route_spec(spec: &str) -> Result<RouteSpec<'_>, String> {
    let (method_name, path) = spec
        .split_once(' ')
        .ok_or_else(|| "expected \"METHOD /path\"".to_string())?;
    if method_name.is_empty() {
        return Err("method is empty".to_string());
    }
    if path.is_empty() {
        return Err("path is empty".to_string());
    }
    if path.len() > 8192 {
        return Err("path must be at most 8192 bytes".to_string());
    }
    if !path.starts_with('/') {
        return Err("path must start with '/'".to_string());
    }
    if path.contains('?') || path.contains('#') {
        return Err("path must not contain a query or fragment".to_string());
    }
    if path.chars().any(char::is_whitespace) {
        return Err("path must not contain whitespace".to_string());
    }
    if path.contains("..") {
        return Err("path must not contain '..' segments".to_string());
    }
    let method = Method::from_bytes(method_name.as_bytes())
        .map_err(|_| format!("invalid HTTP method '{method_name}'"))?;
    if method_bit(&method).is_none() {
        return Err(format!(
            "method '{method_name}' is not supported; use an uppercase standard method"
        ));
    }
    Ok(RouteSpec { method, path })
}

fn method_bit(method: &Method) -> Option<u16> {
    Some(match method.as_str() {
        "GET" => METHOD_GET,
        "HEAD" => METHOD_HEAD,
        "POST" => METHOD_POST,
        "PUT" => METHOD_PUT,
        "DELETE" => METHOD_DELETE,
        "OPTIONS" => METHOD_OPTIONS,
        "PATCH" => METHOD_PATCH,
        "TRACE" => METHOD_TRACE,
        "CONNECT" => METHOD_CONNECT,
        _ => return None,
    })
}

#[derive(Debug, Default)]
struct Node {
    /// Sorted by byte so the hot lookup can binary-search.
    children: Vec<(u8, Box<Node>)>,
    methods: u16,
}

impl Node {
    fn insert(&mut self, path: &[u8], method: u16) {
        let mut node = self;
        for &byte in path {
            let index = match node.children.binary_search_by_key(&byte, |(key, _)| *key) {
                Ok(index) => index,
                Err(index) => {
                    node.children
                        .insert(index, (byte, Box::new(Node::default())));
                    index
                }
            };
            node = &mut node.children[index].1;
        }
        node.methods |= method;
    }

    fn lookup(&self, path: &[u8]) -> u16 {
        let mut node = self;
        for &byte in path {
            let next = match node.children.len() {
                0 => return 0,
                1 => {
                    let (key, child) = &node.children[0];
                    if *key != byte {
                        return 0;
                    }
                    child
                }
                _ => match node.children.binary_search_by_key(&byte, |(key, _)| *key) {
                    Ok(index) => &node.children[index].1,
                    Err(_) => return 0,
                },
            };
            node = next;
        }
        node.methods
    }
}

/// Compiled allowlist. Cloning is not required; the engine stores it in an
/// [`std::sync::Arc`].
#[derive(Debug)]
pub struct FastAllow {
    enabled: bool,
    root: Node,
    route_count: usize,
    allow_audit_sample_rate: f64,
    audit_counter: AtomicU64,
}

impl FastAllow {
    /// Build the trie from configuration. Invalid entries are rejected even
    /// when validation was not run, so a typo cannot silently allow a path.
    pub fn from_config(config: &WafFastAllowConfig) -> Result<Self, String> {
        if !config.enabled {
            return Ok(Self::disabled());
        }
        if config.routes.is_empty() {
            return Err("waf.fast_allow.routes is empty".to_string());
        }
        if !(0.0..=1.0).contains(&config.allow_audit_sample_rate) {
            return Err("allow_audit_sample_rate must be between 0.0 and 1.0".to_string());
        }
        let mut root = Node::default();
        for spec in &config.routes {
            let route = parse_route_spec(spec)?;
            let bit = method_bit(&route.method)
                .ok_or_else(|| format!("route '{spec}' uses an unsupported method"))?;
            root.insert(route.path.as_bytes(), bit);
        }
        Ok(Self {
            enabled: true,
            root,
            route_count: config.routes.len(),
            allow_audit_sample_rate: config.allow_audit_sample_rate,
            audit_counter: AtomicU64::new(0),
        })
    }

    /// Disabled allowlist: every lookup falls through.
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            root: Node::default(),
            route_count: 0,
            allow_audit_sample_rate: 0.0,
            audit_counter: AtomicU64::new(0),
        }
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn route_count(&self) -> usize {
        self.route_count
    }

    pub fn allow_audit_sample_rate(&self) -> f64 {
        self.allow_audit_sample_rate
    }

    /// Whether an allowed fast-path request should still emit an audit event.
    /// `0.0` is the default and takes one predictable branch; the counter is
    /// only touched when sampling is configured.
    pub fn should_sample_allow(&self) -> bool {
        if self.allow_audit_sample_rate <= 0.0 {
            return false;
        }
        if self.allow_audit_sample_rate >= 1.0 {
            return true;
        }
        let counter = self.audit_counter.fetch_add(1, Ordering::Relaxed);
        (counter % 10_000) as f64 / 10_000.0 < self.allow_audit_sample_rate
    }

    /// Exact method + path lookup. A query string never matches: the query is
    /// part of the inspected surface and must fall through.
    pub fn matches(&self, method: &Method, uri: &Uri) -> bool {
        if !self.enabled || uri.query().is_some() {
            return false;
        }
        let Some(bit) = method_bit(method) else {
            return false;
        };
        let path = uri.path().as_bytes();
        if path.is_empty() {
            return false;
        }
        self.root.lookup(path) & bit != 0
    }
}

/// Request view handed to always-on fast-path gates. It borrows the method,
/// URI and headers so the fast path never clones a `HeaderMap` or formats a
/// string.
#[derive(Debug, Clone, Copy)]
pub struct FastAllowContext<'a> {
    pub client_ip: IpAddr,
    pub method: &'a Method,
    pub uri: &'a Uri,
    pub headers: &'a HeaderMap,
    pub body_size: Option<usize>,
}

/// How a rule participates in the compiled fast path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FastAllowPolicy {
    /// Stateless inspection rule: skipped for an explicitly allowlisted route.
    Skip,
    /// Always-on policy/state gate: evaluated for every fast-allow request.
    Gate,
    /// Not safe to fast-allow; the request falls through to full evaluation.
    FallThrough,
}

/// Result of a fast-allow lookup.
#[derive(Debug, Clone, PartialEq)]
pub struct FastAllowOutcome {
    pub decision: Decision,
    pub triggered_rules: Vec<String>,
}

/// A request is bodyless only when framing headers say so and the body has
/// already ended. The proxy also passes `body.is_end_stream()`; this check is
/// the second, header-level guard.
pub fn is_bodyless_headers(headers: &HeaderMap) -> bool {
    if headers.contains_key(TRANSFER_ENCODING)
        || headers.contains_key(CONTENT_ENCODING)
        || headers.contains_key(UPGRADE)
    {
        return false;
    }
    if let Some(connection) = headers.get(CONNECTION) {
        if let Ok(value) = connection.to_str() {
            if value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
            {
                return false;
            }
        }
    }
    let mut lengths = headers.get_all(CONTENT_LENGTH).iter();
    match lengths.next() {
        None => true,
        Some(value) => {
            value.to_str().ok().is_some_and(|v| v.trim() == "0") && lengths.next().is_none()
        }
    }
}

/// gRPC and GraphQL bodies are inspected by protocol pre-checks. A request
/// that announces one of those content types falls through even when it is
/// bodyless, so the pre-check keeps deciding.
pub fn has_protocol_content_type(headers: &HeaderMap) -> bool {
    headers
        .get_all(CONTENT_TYPE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(|value| {
            let media = value.split(';').next().unwrap_or_default().trim();
            media
                .get(..16)
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case("application/grpc"))
                || media.eq_ignore_ascii_case("application/graphql")
                || media.eq_ignore_ascii_case("application/json")
                || media.eq_ignore_ascii_case("application/graphql+json")
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allow(routes: &[&str]) -> FastAllow {
        FastAllow::from_config(&WafFastAllowConfig {
            enabled: true,
            routes: routes.iter().map(|route| route.to_string()).collect(),
            allow_audit_sample_rate: 0.0,
        })
        .expect("valid routes")
    }

    #[test]
    fn parses_exact_route() {
        let route = parse_route_spec("GET /health").expect("route");
        assert_eq!(route.method, Method::GET);
        assert_eq!(route.path, "/health");
    }

    #[test]
    fn rejects_bad_routes() {
        for spec in [
            "GET",
            " /health",
            "GET ",
            "GET health",
            "GET /health?x=1",
            "GET /health#frag",
            "GET /health/../admin",
            "get /health",
            "BREW /health",
            "GET /health extra",
        ] {
            assert!(parse_route_spec(spec).is_err(), "should reject {spec:?}");
        }
    }

    #[test]
    fn matches_exact_method_and_path_only() {
        let fast = allow(&["GET /health", "POST /health"]);
        let get = Method::GET;
        let post = Method::POST;
        assert!(fast.matches(&get, &Uri::from_static("/health")));
        assert!(fast.matches(&post, &Uri::from_static("/health")));
        assert!(!fast.matches(&get, &Uri::from_static("/health?x=1")));
        assert!(!fast.matches(&get, &Uri::from_static("/health/")));
        assert!(!fast.matches(&get, &Uri::from_static("/healthz")));
        assert!(!fast.matches(&Method::HEAD, &Uri::from_static("/health")));
        assert!(!fast.matches(&get, &Uri::from_static("/other")));
    }

    #[test]
    fn disabled_never_matches() {
        let fast = FastAllow::disabled();
        assert!(!fast.matches(&Method::GET, &Uri::from_static("/health")));
        assert!(!fast.enabled());
        assert_eq!(fast.route_count(), 0);
    }

    #[test]
    fn bodyless_headers_are_strict() {
        let mut headers = HeaderMap::new();
        assert!(is_bodyless_headers(&headers));

        headers.insert(CONTENT_LENGTH, "0".parse().unwrap());
        assert!(is_bodyless_headers(&headers));

        headers.insert(CONTENT_LENGTH, "5".parse().unwrap());
        assert!(!is_bodyless_headers(&headers));

        headers.remove(CONTENT_LENGTH);
        headers.insert(TRANSFER_ENCODING, "chunked".parse().unwrap());
        assert!(!is_bodyless_headers(&headers));

        headers.remove(TRANSFER_ENCODING);
        headers.insert(CONTENT_ENCODING, "gzip".parse().unwrap());
        assert!(!is_bodyless_headers(&headers));
    }

    #[test]
    fn protocol_content_types_fall_through() {
        let mut headers = HeaderMap::new();
        assert!(!has_protocol_content_type(&headers));
        headers.insert(
            CONTENT_TYPE,
            "application/json; charset=utf-8".parse().unwrap(),
        );
        assert!(has_protocol_content_type(&headers));
        headers.insert(CONTENT_TYPE, "application/grpc+proto".parse().unwrap());
        assert!(has_protocol_content_type(&headers));
        headers.insert(CONTENT_TYPE, "text/plain".parse().unwrap());
        assert!(!has_protocol_content_type(&headers));
    }

    #[test]
    fn audit_sampling_defaults_off() {
        let fast = allow(&["GET /health"]);
        assert!(!fast.should_sample_allow());
    }
}
