//! Egress rules: fixed identifiers and their pure predicates.
//!
//! Every rule lives here as a function over data (a parsed URI, a resolved IP,
//! response text). The fetcher composes them; the handler only renders the
//! resulting verdict. Keeping the predicates pure is what lets the SSRF tests
//! run without performing a request.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use hyper::Uri;

use crate::config::{EgressConfig, EgressMode};

/// EG-1001: host resolves to a private/loopback/link-local address.
pub const EG_PRIVATE_ADDRESS: &str = "EG-1001";
/// EG-1002: host resolves to a cloud metadata address.
pub const EG_METADATA_ADDRESS: &str = "EG-1002";
/// EG-1003: scheme outside `allow_schemes`.
pub const EG_SCHEME: &str = "EG-1003";
/// EG-1004: port outside `allow_ports`.
pub const EG_PORT: &str = "EG-1004";
/// EG-1005: credential-looking query parameter.
pub const EG_CREDENTIAL_QUERY: &str = "EG-1005";
/// EG-1006: explicitly denied domain.
pub const EG_DENIED_DOMAIN: &str = "EG-1006";
/// EG-1007: domain not present in a non-empty allowlist.
pub const EG_DOMAIN_NOT_ALLOWED: &str = "EG-1007";
/// EG-2001: response contains an injection marker.
pub const EG_INJECTION: &str = "EG-2001";
/// EG-2002: response body exceeds the byte cap.
pub const EG_BODY_TOO_LARGE: &str = "EG-2002";
/// EG-2003: response content type outside `allow_content_types`.
pub const EG_CONTENT_TYPE: &str = "EG-2003";

/// Every id this service can emit, in stable order. `/metrics` renders one
/// counter per entry.
pub const ALL_RULE_IDS: [&str; 10] = [
    EG_PRIVATE_ADDRESS,
    EG_METADATA_ADDRESS,
    EG_SCHEME,
    EG_PORT,
    EG_CREDENTIAL_QUERY,
    EG_DENIED_DOMAIN,
    EG_DOMAIN_NOT_ALLOWED,
    EG_INJECTION,
    EG_BODY_TOO_LARGE,
    EG_CONTENT_TYPE,
];

/// Addresses that must never be fetched from: cloud metadata endpoints win
/// over the generic private-address rule so the refusal names the real hazard.
pub const METADATA_V4: Ipv4Addr = Ipv4Addr::new(169, 254, 169, 254);
pub const METADATA_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254);

const CREDENTIAL_QUERY_NAMES: [&str; 10] = [
    "token",
    "key",
    "api_key",
    "apikey",
    "secret",
    "password",
    "sig",
    "signature",
    "access_token",
    "auth",
];

/// Injection markers that make a page worth warning about. Matching is
/// case-insensitive; the marker is reported verbatim.
pub const INJECTION_MARKERS: [&str; 5] = [
    "ignore previous instructions",
    "ignore all previous",
    "system prompt",
    "you are now",
    "disregard the above",
];

/// The last 200 characters rule for hidden text.
pub const HIDDEN_TEXT_MIN_CHARS: usize = 200;

/// A rule match: the fixed id plus the human-readable reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleHit {
    pub id: &'static str,
    pub detail: String,
}

impl RuleHit {
    pub fn new(id: &'static str, detail: impl Into<String>) -> Self {
        Self {
            id,
            detail: detail.into(),
        }
    }

    /// Refusal text as returned to the caller. It always names the rule and
    /// the reason; it is never the bare word "forbidden".
    pub fn message(&self) -> String {
        format!("blocked by {}: {}", self.id, self.detail)
    }
}

/// Configuration reduced to the forms the checks need. Built once per fetch.
#[derive(Debug, Clone)]
pub struct EgressPolicy {
    pub allow_schemes: HashSet<String>,
    pub allow_ports: HashSet<u16>,
    pub allow_domains: Vec<String>,
    pub deny_domains: Vec<String>,
    pub allow_content_types: HashSet<String>,
    pub mode: EgressMode,
    pub max_redirects: usize,
    pub max_bytes: usize,
    pub timeout: Duration,
    /// Test seam: a local test server cannot be fetched under the production
    /// loopback refusal. Only [`crate::egress::EgressService::new_permissive_for_tests`]
    /// sets this, and it relaxes nothing except loopback/unspecified IPv4/IPv6.
    pub allow_loopback: bool,
}

impl EgressPolicy {
    pub fn from_config(config: &EgressConfig) -> Self {
        Self {
            allow_schemes: config
                .allow_schemes
                .iter()
                .map(|value| value.trim().to_ascii_lowercase())
                .collect(),
            allow_ports: config.allow_ports.iter().copied().collect(),
            allow_domains: normalise_domains(&config.allow_domains),
            deny_domains: normalise_domains(&config.deny_domains),
            allow_content_types: config
                .allow_content_types
                .iter()
                .map(|value| value.trim().to_ascii_lowercase())
                .collect(),
            mode: config.mode,
            max_redirects: config.max_redirects,
            max_bytes: config.max_bytes,
            timeout: Duration::from_millis(config.timeout_ms),
            allow_loopback: false,
        }
    }

    pub fn refuses_injection(&self) -> bool {
        self.mode == EgressMode::Refuse
    }
}

fn normalise_domains(values: &[String]) -> Vec<String> {
    values
        .iter()
        .map(|value| {
            value
                .trim()
                .trim_start_matches('.')
                .trim_end_matches('.')
                .to_ascii_lowercase()
        })
        .filter(|value| !value.is_empty())
        .collect()
}

/// The port that will actually be connected to, including scheme defaults.
pub fn effective_port(uri: &Uri) -> Option<u16> {
    if let Some(port) = uri.port_u16() {
        return Some(port);
    }
    match uri.scheme_str() {
        Some("https") => Some(443),
        Some("http") => Some(80),
        _ => None,
    }
}

/// Pre-connection checks for one hop, in rule order.
///
/// `EG-1003` (scheme), `EG-1004` (port), `EG-1006`/`EG-1007` (configured
/// domain policy) and `EG-1005` (credential query). IP checks need resolution
/// and run in [`check_ip`] once the name is resolved.
pub fn check_uri(uri: &Uri, policy: &EgressPolicy) -> Option<RuleHit> {
    let scheme = uri.scheme_str().map(|value| value.to_ascii_lowercase());
    match scheme.as_deref() {
        Some(scheme) if policy.allow_schemes.contains(scheme) => {}
        Some(scheme) => {
            return Some(RuleHit::new(
                EG_SCHEME,
                format!(
                    "scheme '{scheme}' is not in egress.allow_schemes (allowed: {})",
                    join(policy.allow_schemes.iter().map(String::as_str))
                ),
            ))
        }
        None => {
            return Some(RuleHit::new(
                EG_SCHEME,
                "URL has no scheme; egress.allow_schemes requires an explicit scheme",
            ))
        }
    }

    let port = effective_port(uri);
    match port {
        Some(port) if policy.allow_ports.contains(&port) => {}
        Some(port) => {
            return Some(RuleHit::new(
                EG_PORT,
                format!(
                    "port {port} is not in egress.allow_ports (allowed: {})",
                    join_owned(policy.allow_ports.iter().map(u16::to_string))
                ),
            ))
        }
        None => {
            return Some(RuleHit::new(
                EG_PORT,
                "URL has no port and the scheme has no default port",
            ))
        }
    }

    let Some(host) = uri.host() else {
        return Some(RuleHit::new(EG_SCHEME, "URL has no host"));
    };
    if let Some(hit) = check_domain(host, policy) {
        return Some(hit);
    }

    check_query_for_credentials(uri)
}

/// Configured domain policy. `deny_domains` wins over `allow_domains`.
pub fn check_domain(host: &str, policy: &EgressPolicy) -> Option<RuleHit> {
    let host = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim_end_matches('.')
        .to_ascii_lowercase();

    if policy
        .deny_domains
        .iter()
        .any(|pattern| domain_matches(&host, pattern))
    {
        return Some(RuleHit::new(
            EG_DENIED_DOMAIN,
            format!("host '{host}' matches egress.deny_domains"),
        ));
    }

    if !policy.allow_domains.is_empty()
        && !policy
            .allow_domains
            .iter()
            .any(|pattern| domain_matches(&host, pattern))
    {
        return Some(RuleHit::new(
            EG_DOMAIN_NOT_ALLOWED,
            format!("host '{host}' is not in egress.allow_domains"),
        ));
    }

    None
}

fn domain_matches(host: &str, pattern: &str) -> bool {
    host == pattern || host.ends_with(&format!(".{pattern}"))
}

/// `EG-1005`: a query parameter *name* that looks like a credential.
pub fn check_query_for_credentials(uri: &Uri) -> Option<RuleHit> {
    let query = uri.query()?;
    for pair in query.split('&') {
        let raw_name = pair.split('=').next().unwrap_or("");
        let name = urlencoding::decode(raw_name)
            .map(|value| value.into_owned())
            .unwrap_or_else(|_| raw_name.to_string())
            .trim()
            .to_ascii_lowercase();
        if CREDENTIAL_QUERY_NAMES.contains(&name.as_str()) {
            return Some(RuleHit::new(
                EG_CREDENTIAL_QUERY,
                format!(
                    "query parameter '{name}' looks like a credential; egress mode never \
                     forwards credentials"
                ),
            ));
        }
    }
    None
}

/// Classification of one resolved address. Metadata first, then private.
pub fn check_ip(ip: IpAddr, allow_loopback: bool) -> Option<RuleHit> {
    let ip = unmap_ipv4(ip);

    if is_metadata(ip) {
        return Some(RuleHit::new(
            EG_METADATA_ADDRESS,
            format!("host resolves to a cloud metadata address ({ip})"),
        ));
    }

    if allow_loopback && is_loopback_only(ip) {
        return None;
    }

    if is_private_or_local(ip) {
        return Some(RuleHit::new(
            EG_PRIVATE_ADDRESS,
            format!("host resolves to a private, loopback or link-local address ({ip})"),
        ));
    }

    None
}

fn unmap_ipv4(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        other => other,
    }
}

fn is_metadata(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4 == METADATA_V4,
        IpAddr::V6(v6) => v6 == METADATA_V6,
    }
}

fn is_loopback_only(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_unspecified(),
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified(),
    }
}

fn is_private_or_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.octets()[0] == 0
                || v4.is_multicast()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unique_local()
                || v6.is_unicast_link_local()
                || v6.is_unspecified()
                || v6.is_multicast()
        }
    }
}

/// Essence of a `Content-Type` value: lowercased, parameters removed.
pub fn content_type_essence(value: Option<&str>) -> Option<String> {
    let value = value?;
    let essence = value.split(';').next().unwrap_or("").trim();
    if essence.is_empty() {
        None
    } else {
        Some(essence.to_ascii_lowercase())
    }
}

/// `EG-2003`: content type outside the allowlist.
pub fn check_content_type(content_type: Option<&str>, policy: &EgressPolicy) -> Option<RuleHit> {
    let essence = content_type_essence(content_type);
    match essence.as_deref() {
        Some(value) if policy.allow_content_types.contains(value) => None,
        Some(value) => Some(RuleHit::new(
            EG_CONTENT_TYPE,
            format!("content type '{value}' is not in egress.allow_content_types"),
        )),
        None => Some(RuleHit::new(
            EG_CONTENT_TYPE,
            "response has no content type; egress.allow_content_types cannot be satisfied",
        )),
    }
}

/// `EG-2001`: injection marker in plain text. Returns the matched marker.
pub fn injection_marker(text: &str) -> Option<&'static str> {
    let haystack = text.to_ascii_lowercase();
    INJECTION_MARKERS
        .iter()
        .copied()
        .find(|marker| haystack.contains(marker))
}

/// `EG-2001` (hidden-text half): an HTML element with `display:none` or
/// `font-size:0` that carries more than [`HIDDEN_TEXT_MIN_CHARS`] characters of
/// text.
///
/// This is deliberately a small scanner, not a DOM: it exists to catch the
/// obvious "hide the instructions from the human" trick, and it fails towards
/// detection only when the closing tag is missing.
pub fn hidden_text_present(html: &str) -> bool {
    let lower = html.to_ascii_lowercase();
    let mut cursor = 0usize;

    while let Some(relative) = lower[cursor..].find('<') {
        let tag_start = cursor + relative;
        let Some(tag_end_rel) = lower[tag_start..].find('>') else {
            break;
        };
        let tag_end = tag_start + tag_end_rel;
        let tag_body = &lower[tag_start + 1..tag_end];

        // Skip comments, doctypes and closing tags.
        if tag_body.starts_with('!') || tag_body.starts_with('/') || tag_body.starts_with('?') {
            cursor = tag_end + 1;
            continue;
        }

        let name: String = tag_body
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '-')
            .collect();
        if name.is_empty() {
            cursor = tag_end + 1;
            continue;
        }

        let hidden = style_attribute_is_hidden(tag_body);
        if hidden {
            let closing = format!("</{name}");
            if let Some(close_rel) = lower[tag_end + 1..].find(&closing) {
                let close_start = tag_end + 1 + close_rel;
                let inner = &lower[tag_end + 1..close_start];
                if text_chars(inner) > HIDDEN_TEXT_MIN_CHARS {
                    return true;
                }
            }
        }

        cursor = tag_end + 1;
        // Keep scanning inside every element: nested hidden spans are common.
    }

    false
}

fn style_attribute_is_hidden(tag_body: &str) -> bool {
    let compact: String = tag_body.chars().filter(|c| !c.is_whitespace()).collect();
    compact.contains("style=")
        && (compact.contains("display:none")
            || compact.contains("font-size:0")
            || compact.contains("font-size:0.0")
            || compact.contains("font-size:0px"))
}

/// Count visible text characters inside an HTML fragment, ignoring tags and
/// collapsing runs of whitespace.
fn text_chars(fragment: &str) -> usize {
    let mut count = 0usize;
    let mut inside_tag = false;
    let mut last_was_space = true;
    for ch in fragment.chars() {
        match ch {
            '<' => inside_tag = true,
            '>' => inside_tag = false,
            _ if inside_tag => {}
            _ if ch.is_whitespace() => {
                if !last_was_space {
                    count += 1;
                    last_was_space = true;
                }
            }
            _ => {
                count += 1;
                last_was_space = false;
            }
        }
    }
    count
}

fn join<'a>(values: impl Iterator<Item = &'a str>) -> String {
    values.collect::<Vec<_>>().join(", ")
}

fn join_owned(values: impl Iterator<Item = String>) -> String {
    values.collect::<Vec<_>>().join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> EgressPolicy {
        EgressPolicy::from_config(&EgressConfig::default())
    }

    #[test]
    fn metadata_overrides_link_local() {
        let hit = check_ip(METADATA_V4.into(), false).expect("metadata is refused");
        assert_eq!(hit.id, EG_METADATA_ADDRESS);
        let hit = check_ip(METADATA_V6.into(), false).expect("metadata v6 is refused");
        assert_eq!(hit.id, EG_METADATA_ADDRESS);
    }

    #[test]
    fn mapped_metadata_is_unmapped() {
        let mapped: Ipv6Addr = "::ffff:169.254.169.254".parse().unwrap();
        let hit = check_ip(mapped.into(), false).expect("mapped metadata is refused");
        assert_eq!(hit.id, EG_METADATA_ADDRESS);
    }

    #[test]
    fn public_addresses_pass() {
        assert!(check_ip("93.184.216.34".parse().unwrap(), false).is_none());
        assert!(check_ip("2606:2800:220:1::1".parse().unwrap(), false).is_none());
    }

    #[test]
    fn scheme_is_case_insensitive() {
        let uri: Uri = "HTTPS://example.org/".parse().unwrap();
        assert!(check_uri(&uri, &policy()).is_none());
    }

    #[test]
    fn credential_query_is_detected_case_insensitively() {
        let uri: Uri = "https://example.org/?API_KEY=abc".parse().unwrap();
        assert_eq!(
            check_query_for_credentials(&uri).map(|hit| hit.id),
            Some(EG_CREDENTIAL_QUERY)
        );
    }

    #[test]
    fn harmless_query_is_not_a_credential() {
        let uri: Uri = "https://example.org/?q=rust&page=2".parse().unwrap();
        assert!(check_query_for_credentials(&uri).is_none());
    }

    #[test]
    fn hidden_text_ignores_short_snippets() {
        let html = r#"<div style="display:none">short</div>"#;
        assert!(!hidden_text_present(html));
    }

    #[test]
    fn hidden_text_handles_spacing_and_font_size() {
        let long = "x".repeat(HIDDEN_TEXT_MIN_CHARS + 1);
        let html = format!(r#"<span style="font-size: 0px">{long}</span>"#);
        assert!(hidden_text_present(&html));
    }
}
