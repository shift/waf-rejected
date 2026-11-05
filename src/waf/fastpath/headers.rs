//! Header and protocol checks for the request fast path.
//!
//! These checks are deliberately stricter than CRS. A rejection means "run
//! Coraza", never "block": the fast path is a conservative prefilter.

use std::collections::HashSet;

use super::matchers::ScannerMatcher;
use super::FastPathReason;

/// The default `tx.allowed_request_content_type` from CRS 4.14.
const DEFAULT_CONTENT_TYPES: &[&str] = &[
    "application/x-www-form-urlencoded",
    "multipart/form-data",
    "text/xml",
    "application/xml",
    "application/soap+xml",
    "application/json",
    "application/grpc",
    "application/grpc+proto",
    "application/grpc+json",
    "application/grpc-web",
    "application/grpc-web+proto",
    "application/grpc-web-text",
];

/// The default `tx.allowed_request_content_type_charset` from CRS 4.14.
const DEFAULT_CHARSETS: &[&str] = &["utf-8", "iso-8859-1", "iso-8859-15", "windows-1252"];

/// The default `tx.allowed_http_versions` from CRS 4.14.
const DEFAULT_VERSIONS: &[&str] = &[
    "HTTP/1.0", "HTTP/1.1", "HTTP/2", "HTTP/2.0", "HTTP/3", "HTTP/3.0",
];

/// Header names the fast path is willing to reason about. Unknown or
/// extension headers fall back to Coraza: several CRS rules (932170/932180,
/// 933110, 944140) inspect upload filename headers and generic header values.
const DEFAULT_HEADER_NAMES: &[&str] = &[
    "host",
    "user-agent",
    "accept",
    "accept-encoding",
    "accept-language",
    "connection",
    "content-type",
    "content-length",
    "cache-control",
    "pragma",
    "keep-alive",
    "proxy-connection",
    "origin",
    "x-forwarded-for",
    "x-forwarded-proto",
    "x-forwarded-host",
    "x-real-ip",
    "x-request-id",
    "x-correlation-id",
    "te",
    "trailer",
    "upgrade",
    "via",
    "warning",
    "dnt",
    "sec-fetch-site",
    "sec-fetch-mode",
    "sec-fetch-dest",
    "sec-fetch-user",
    "sec-ch-ua",
    "sec-ch-ua-mobile",
    "sec-ch-ua-platform",
];

/// The default `tx.restricted_headers_basic` from CRS 4.14.
const DEFAULT_RESTRICTED_HEADERS: &[&str] = &[
    "content-encoding",
    "proxy",
    "lock-token",
    "content-range",
    "if",
    "x-http-method-override",
    "x-http-method",
    "x-method-override",
    "x-middleware-subrequest",
];

/// Case-insensitive view over the request headers.
#[derive(Debug, Clone, Copy)]
pub struct HeaderView<'a> {
    entries: &'a [(&'a str, &'a str)],
}

impl<'a> HeaderView<'a> {
    /// Wraps a header slice.
    pub fn new(entries: &'a [(&'a str, &'a str)]) -> Self {
        Self { entries }
    }

    /// First value for `name`, compared ASCII case-insensitively.
    pub fn get(&self, name: &str) -> Option<&'a str> {
        self.entries
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| *value)
    }

    /// Number of headers named `name`.
    pub fn count(&self, name: &str) -> usize {
        self.entries
            .iter()
            .filter(|(key, _)| key.eq_ignore_ascii_case(name))
            .count()
    }

    /// All headers.
    pub fn iter(&self) -> impl Iterator<Item = (&'a str, &'a str)> + '_ {
        self.entries.iter().copied()
    }
}

/// Facts extracted from a validated header block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeaderFacts<'a> {
    /// `Content-Length`, when present and numeric.
    pub content_length: Option<usize>,
    /// Full `Content-Type` value, when present.
    pub content_type: Option<&'a str>,
    /// `Host` value.
    pub host: &'a str,
    /// `User-Agent` value.
    pub user_agent: &'a str,
}

/// Header policy derived from the CRS defaults.
pub struct HeaderPolicy {
    scanner: ScannerMatcher,
    content_types: HashSet<Box<str>>,
    charsets: HashSet<Box<str>>,
    versions: HashSet<Box<str>>,
    restricted_headers: HashSet<Box<str>>,
    allowed_headers: HashSet<Box<str>>,
}

impl std::fmt::Debug for HeaderPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HeaderPolicy")
            .field("scanner_patterns", &self.scanner.len())
            .field("content_types", &self.content_types.len())
            .field("versions", &self.versions.len())
            .finish()
    }
}

impl HeaderPolicy {
    /// Builds the default policy.
    pub fn crs_default() -> Result<Self, String> {
        Ok(Self {
            scanner: ScannerMatcher::embedded()?,
            content_types: DEFAULT_CONTENT_TYPES
                .iter()
                .map(|value| (*value).into())
                .collect(),
            charsets: DEFAULT_CHARSETS
                .iter()
                .map(|value| (*value).into())
                .collect(),
            versions: DEFAULT_VERSIONS
                .iter()
                .map(|value| (*value).into())
                .collect(),
            restricted_headers: DEFAULT_RESTRICTED_HEADERS
                .iter()
                .map(|value| (*value).into())
                .collect(),
            allowed_headers: DEFAULT_HEADER_NAMES
                .iter()
                .map(|value| (*value).into())
                .collect(),
        })
    }

    /// Validates the header block and extracts the facts the rest of the fast
    /// path needs.
    pub fn check<'a>(
        &self,
        method: &str,
        version: &str,
        view: HeaderView<'a>,
    ) -> Result<HeaderFacts<'a>, FastPathReason> {
        if !self.versions.contains(version) {
            return Err(FastPathReason::ProtocolVersionNotAllowed);
        }

        let mut content_length = None;
        let mut content_type = None;
        for (name, value) in view.iter() {
            if name.is_empty() || !name.bytes().all(is_token_byte) {
                return Err(FastPathReason::HeaderAnomaly("invalid header name"));
            }
            if !value.bytes().all(is_safe_header_value_byte) {
                return Err(FastPathReason::HeaderAnomaly("invalid header value"));
            }
            if contains_obfuscated_path(value) {
                return Err(FastPathReason::HeaderAnomaly("obfuscated path"));
            }
            let lower = name.to_ascii_lowercase();
            if self.restricted_headers.contains(lower.as_str()) {
                return Err(FastPathReason::HeaderAnomaly("restricted header"));
            }
            if !self.allowed_headers.contains(lower.as_str()) {
                return Err(FastPathReason::HeaderAnomaly("unknown header"));
            }
        }

        for name in [
            "host",
            "content-length",
            "transfer-encoding",
            "content-type",
        ] {
            if view.count(name) > 1 {
                return Err(FastPathReason::HeaderAnomaly("duplicate framing header"));
            }
        }

        let host = match view.get("host") {
            None => return Err(FastPathReason::HostMissing),
            Some("") => return Err(FastPathReason::HostInvalid),
            Some(value) => value,
        };
        if !valid_host(host) {
            return Err(FastPathReason::HostInvalid);
        }

        let user_agent = match view.get("user-agent") {
            None | Some("") => return Err(FastPathReason::HeaderAnomaly("missing user-agent")),
            Some(value) if !valid_user_agent(value) => {
                return Err(FastPathReason::HeaderAnomaly("unsafe user-agent"))
            }
            Some(value) => value,
        };
        if self.scanner.is_scanner(user_agent) {
            return Err(FastPathReason::ScannerUserAgent);
        }

        let accept = match view.get("accept") {
            None | Some("") => return Err(FastPathReason::HeaderAnomaly("missing accept")),
            Some(value) => value,
        };
        if !valid_accept(accept) {
            return Err(FastPathReason::HeaderAnomaly("invalid accept"));
        }

        if let Some(value) = view.get("content-type") {
            let parsed = parse_content_type(value)?;
            if !self.content_types.contains(parsed.media_type.as_str()) {
                return Err(FastPathReason::ContentTypeNotAllowed);
            }
            if let Some(charset) = parsed.charset {
                if !self.charsets.contains(charset.as_str()) {
                    return Err(FastPathReason::HeaderAnomaly("charset not allowed"));
                }
            }
            if parsed.charset_count > 1 {
                return Err(FastPathReason::HeaderAnomaly("multiple charsets"));
            }
            content_type = Some(value);
        }

        if let Some(value) = view.get("content-length") {
            if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(FastPathReason::HeaderAnomaly("invalid content-length"));
            }
            if value.len() > 1 && value.starts_with('0') {
                return Err(FastPathReason::HeaderAnomaly(
                    "non-canonical content-length",
                ));
            }
            let length = value
                .parse::<usize>()
                .map_err(|_| FastPathReason::HeaderAnomaly("content-length overflow"))?;
            if length > 0 && matches!(method, "GET" | "HEAD") {
                return Err(FastPathReason::HeaderAnomaly("body headers on GET/HEAD"));
            }
            content_length = Some(length);
        }

        if view.get("transfer-encoding").is_some() {
            return Err(FastPathReason::HeaderAnomaly(
                "transfer-encoding not covered",
            ));
        }

        if let Some(value) = view.get("connection") {
            let lower = value.to_ascii_lowercase();
            if lower != "close" && lower != "keep-alive" {
                return Err(FastPathReason::HeaderAnomaly("connection header"));
            }
        }

        if let Some(value) = view.get("accept-encoding") {
            if value.len() > 100 || !value.bytes().all(is_accept_encoding_byte) {
                return Err(FastPathReason::HeaderAnomaly("accept-encoding header"));
            }
        }

        for name in ["range", "request-range", "referer", "cookie"] {
            if view.get(name).is_some() {
                return Err(FastPathReason::HeaderAnomaly("header not covered"));
            }
        }

        if let Some(value) = view.get("origin") {
            if !valid_origin(value) {
                return Err(FastPathReason::HeaderAnomaly("origin header"));
            }
        }

        // CRS 920180: POST without Content-Length is suspicious on HTTP/1.x.
        if method == "POST"
            && content_length.is_none()
            && !version.starts_with("HTTP/2")
            && !version.starts_with("HTTP/3")
        {
            return Err(FastPathReason::HeaderAnomaly("POST without content-length"));
        }

        Ok(HeaderFacts {
            content_length,
            content_type,
            host,
            user_agent,
        })
    }
}

impl Default for HeaderPolicy {
    fn default() -> Self {
        Self::crs_default().expect("embedded CRS scanner list must compile")
    }
}

struct ParsedContentType {
    media_type: String,
    charset: Option<String>,
    charset_count: usize,
}

fn parse_content_type(value: &str) -> Result<ParsedContentType, FastPathReason> {
    let mut parts = value.split(';');
    let media_type = parts
        .next()
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .ok_or(FastPathReason::HeaderAnomaly("empty content-type"))?
        .to_ascii_lowercase();
    if !valid_media_type(&media_type) {
        return Err(FastPathReason::ContentTypeNotAllowed);
    }

    let mut charset = None;
    let mut charset_count = 0;
    for parameter in parts {
        let parameter = parameter.trim();
        if parameter.is_empty() {
            continue;
        }
        let (key, raw_value) = parameter
            .split_once('=')
            .ok_or(FastPathReason::HeaderAnomaly(
                "invalid content-type parameter",
            ))?;
        if raw_value.starts_with("  ") {
            return Err(FastPathReason::HeaderAnomaly(
                "invalid content-type whitespace",
            ));
        }
        let key = key.trim().to_ascii_lowercase();
        let value = raw_value.trim().trim_matches('"');
        if key == "charset" {
            charset_count += 1;
            charset = Some(value.to_ascii_lowercase());
        }
        if key == "boundary" && value.bytes().any(|byte| byte.is_ascii_whitespace()) {
            return Err(FastPathReason::HeaderAnomaly("invalid boundary"));
        }
        if !value.bytes().all(is_parameter_byte) {
            return Err(FastPathReason::HeaderAnomaly(
                "invalid content-type parameter",
            ));
        }
    }

    Ok(ParsedContentType {
        media_type,
        charset,
        charset_count,
    })
}

fn valid_media_type(value: &str) -> bool {
    let Some((kind, subtype)) = value.split_once('/') else {
        return false;
    };
    !kind.is_empty()
        && !subtype.is_empty()
        && kind.bytes().all(is_media_type_byte)
        && subtype.bytes().all(is_media_type_byte)
        && !subtype.contains('/')
}

fn valid_accept(value: &str) -> bool {
    if value.is_empty() || value.len() > 4096 {
        return false;
    }
    if !value.bytes().all(is_accept_byte) {
        return false;
    }
    let mut charset_count = 0usize;
    let valid = value.split(',').all(|range| {
        let range = range.trim();
        if range.is_empty() {
            return false;
        }
        let mut parts = range.split(';');
        let media = parts.next().unwrap_or_default().trim();
        if media != "*" && !valid_media_type(media) {
            return false;
        }
        parts.all(|parameter| {
            let parameter = parameter.trim();
            if parameter.is_empty() {
                return false;
            }
            parameter.split_once('=').is_some_and(|(key, value)| {
                let key = key.trim();
                let value = value.trim().trim_matches('"');
                if key.eq_ignore_ascii_case("charset") {
                    charset_count += 1;
                    if !DEFAULT_CHARSETS
                        .iter()
                        .any(|charset| value.eq_ignore_ascii_case(charset))
                    {
                        return false;
                    }
                }
                !key.is_empty()
                    && !value.is_empty()
                    && key.bytes().all(is_parameter_byte)
                    && value.bytes().all(is_parameter_byte)
            })
        })
    });
    valid && charset_count <= 1
}

fn contains_obfuscated_path(value: &str) -> bool {
    value.contains("..")
        || value
            .as_bytes()
            .windows(2)
            .any(|window| window.eq_ignore_ascii_case(b"0x"))
}

fn valid_user_agent(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && !value.contains("..")
        && value.bytes().all(is_safe_header_value_byte)
}

fn valid_host(value: &str) -> bool {
    if value.is_empty() || value.len() > 255 || value.contains("..") {
        return false;
    }
    // CRS 920350 blocks numeric IP hosts, including bracketed IPv6.
    if value.starts_with('[') {
        return false;
    }

    let host = match value.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') && port.bytes().all(|b| b.is_ascii_digit()) => {
            if port.is_empty() {
                return false;
            }
            host
        }
        _ => value,
    };

    if host.is_empty()
        || host.starts_with('.')
        || host.ends_with('.')
        || host.starts_with('-')
        || host.ends_with('-')
        || host.bytes().any(|byte| {
            !(byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'-' || byte == b'_')
        })
    {
        return false;
    }

    // Reject numeric IPv4 forms (920350).
    if host
        .split('.')
        .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
    {
        return false;
    }

    host.split('.').all(|label| {
        !label.is_empty() && label.len() <= 63 && !label.starts_with('-') && !label.ends_with('-')
    })
}

fn valid_origin(value: &str) -> bool {
    let Some(rest) = value
        .strip_prefix("http://")
        .or_else(|| value.strip_prefix("https://"))
    else {
        return false;
    };
    let authority = rest.split('/').next().unwrap_or_default();
    !authority.is_empty() && valid_host(authority)
}

fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn is_header_value_byte(byte: u8) -> bool {
    byte == b'\t' || (byte >= 0x20 && byte != 0x7f)
}

fn is_safe_header_value_byte(byte: u8) -> bool {
    // Encoded and template syntax is exactly what the header-injection and
    // obfuscated-XSS rules look for; anything containing it falls back.
    is_header_value_byte(byte)
        && !matches!(
            byte,
            b'%' | b'<' | b'>' | b'&' | b'!' | b'$' | b'{' | b'}' | b'`' | b'|' | b'\\' | b'^'
        )
}

fn is_accept_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b' ' | b'\t' | b',' | b';' | b'=' | b'.' | b'-' | b'_' | b'+' | b'*' | b'/'
        )
}

fn is_media_type_byte(byte: u8) -> bool {
    // Deliberately narrower than the HTTP token grammar: every byte accepted
    // here is also accepted by the CRS 920600/920470 media-type regexes.
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'+' | b'-' | b'*')
}

fn is_parameter_byte(byte: u8) -> bool {
    // Keep parameters to the conservative charset used by the corpus and by
    // the CRS content-type rules. Unknown syntax forces a Coraza fallback.
    byte.is_ascii_alphanumeric() || matches!(byte, b'*' | b'+' | b'-' | b'.' | b'_')
}

fn is_accept_encoding_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b' ' | b'\t' | b',' | b';' | b'=' | b'.' | b'-' | b'_' | b'*'
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> HeaderPolicy {
        HeaderPolicy::crs_default().expect("policy")
    }

    fn view<'a>(entries: &'a [(&'a str, &'a str)]) -> HeaderView<'a> {
        HeaderView::new(entries)
    }

    #[test]
    fn benign_headers_pass() {
        let headers = [
            ("Host", "example.test"),
            ("User-Agent", "Mozilla/5.0 Firefox/128.0"),
            ("Accept", "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8"),
        ];
        let facts = policy()
            .check("GET", "HTTP/1.1", view(&headers))
            .expect("benign headers");
        assert_eq!(facts.host, "example.test");
        assert_eq!(facts.content_length, None);
    }

    #[test]
    fn scanner_user_agent_is_rejected() {
        let headers = [
            ("Host", "example.test"),
            ("User-Agent", "sqlmap/1.8"),
            ("Accept", "*/*"),
        ];
        assert_eq!(
            policy().check("GET", "HTTP/1.1", view(&headers)),
            Err(FastPathReason::ScannerUserAgent)
        );
    }

    #[test]
    fn missing_host_is_rejected() {
        let headers = [("User-Agent", "Firefox"), ("Accept", "*/*")];
        assert_eq!(
            policy().check("GET", "HTTP/1.1", view(&headers)),
            Err(FastPathReason::HostMissing)
        );
    }

    #[test]
    fn disallowed_content_type_is_rejected() {
        let headers = [
            ("Host", "example.test"),
            ("User-Agent", "Firefox"),
            ("Accept", "*/*"),
            ("Content-Type", "text/plain"),
        ];
        assert_eq!(
            policy().check("POST", "HTTP/1.1", view(&headers)),
            Err(FastPathReason::ContentTypeNotAllowed)
        );
    }

    #[test]
    fn numeric_host_is_rejected() {
        let headers = [
            ("Host", "192.168.1.10"),
            ("User-Agent", "Firefox"),
            ("Accept", "*/*"),
        ];
        assert_eq!(
            policy().check("GET", "HTTP/1.1", view(&headers)),
            Err(FastPathReason::HostInvalid)
        );
    }

    #[test]
    fn non_canonical_content_length_is_rejected() {
        let headers = [
            ("Host", "example.test"),
            ("User-Agent", "Firefox"),
            ("Accept", "*/*"),
            ("Content-Length", "00"),
        ];
        assert_eq!(
            policy().check("GET", "HTTP/1.1", view(&headers)),
            Err(FastPathReason::HeaderAnomaly(
                "non-canonical content-length"
            ))
        );
    }

    #[test]
    fn content_type_parameters_are_validated() {
        let headers = [
            ("Host", "example.test"),
            ("User-Agent", "Firefox"),
            ("Accept", "*/*"),
            ("Content-Type", "application/json; charset=utf-8"),
            ("Content-Length", "2"),
        ];
        let facts = policy()
            .check("POST", "HTTP/1.1", view(&headers))
            .expect("json headers");
        assert_eq!(facts.content_type, Some("application/json; charset=utf-8"));
    }
}
