//! Compiled Rust request fast path for sub-millisecond WAF decisions.
//!
//! **Research prototype, non-default feature `fastpath`.**
//!
//! # Soundness model
//!
//! The fast path is a *conservative prefilter* (mode **a** in
//! `docs/suggestions_from_agents/fastpath-engine.md`). It can return
//! [`FastPathDecision::Clean`] only when every rule it replaces is provably
//! unable to match. Everything else returns
//! [`FastPathDecision::NeedsCoraza`], and the caller must run Coraza, which
//! remains the decision maker.
//!
//! The covered rule set is deliberately explicit:
//!
//! * method enforcement (CRS 911100) via [`matchers::MethodMatcher`],
//! * request-line/protocol checks (920100, 920160, 920170, 920180, 920210,
//!   920280, 920290, 920330, 920350, 920430, 920610) via the URI and header
//!   validators,
//! * content-type and charset policy (920420, 920470, 920480, 920530, 921421,
//!   922100) via [`headers::HeaderPolicy`],
//! * restricted extensions and OS-file probes (920440, 920500, 930130) via the
//!   path validator and [`matchers::LfiMatcher`],
//! * scanner user agents (913100) via [`matchers::ScannerMatcher`],
//! * header injection (921140) via the header-value byte check,
//! * body rules (920250, 920270, 920360-920380, 920390, 922100, 922130,
//!   941100, 942100, 930-944) via [`body::BodyInspector`].
//!
//! The body is the limiting factor: on stock CRS 4.14 the required-literal
//! artifact leaves `@detectSQLi`, `@detectXSS` and several obfuscation-tolerant
//! regexes ungated. A clean literal scan is therefore necessary but not
//! sufficient, and body-bearing requests return `NeedsCoraza` unless a caller
//! explicitly enables the (currently unavailable) body-withholding mode.

pub mod body;
pub mod headers;
pub mod matchers;

use std::fmt;

use body::{BodyInspector, BodyScan};
use headers::{HeaderPolicy, HeaderView};
use matchers::{LfiMatcher, LiteralListMatcher, MethodMatcher, PathAllowlist, RegexSignatures};

/// Reason a request could not be proven clean.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FastPathReason {
    /// Method is not in the CRS allowlist (911100).
    MethodNotAllowed,
    /// The configured path allowlist does not cover this path.
    PathNotAllowlisted,
    /// URI is not in the conservative origin-form subset.
    UriUnsafe(&'static str),
    /// A URI signature matched (SQLi/XSS/LFI/RCE).
    UriSignature,
    /// A header signature matched.
    HeaderSignature,
    /// The `Host` header is missing (920280).
    HostMissing,
    /// The `Host` header is empty or malformed (920290/920350).
    HostInvalid,
    /// The user agent matches the CRS scanner list (913100).
    ScannerUserAgent,
    /// A protocol/header anomaly outside the covered subset.
    HeaderAnomaly(&'static str),
    /// `Content-Type` is absent when a body is present or not allowed (920420).
    ContentTypeNotAllowed,
    /// HTTP version is not in the CRS allowlist (920430).
    ProtocolVersionNotAllowed,
    /// The body is larger than the configured fast-path cap.
    BodyTooLarge,
    /// A body signature matched.
    BodySignature,
    /// A gated body rule literal matched.
    BodyLiteral,
    /// The body is not valid UTF-8 (920250).
    BodyInvalidUtf8,
    /// The body contains a byte outside the CRS byte range (920270).
    BodyByteRange,
    /// Multipart part headers are not modelled by the fast path.
    MultipartNotCovered,
    /// A form/JSON argument exceeded the CRS limits (920360-920390).
    ArgumentLimit,
    /// At least one body-relevant CRS rule is ungated, so a clean literal scan
    /// is not a proof.
    BodyRuleUngated,
    /// The caller did not enable body withholding.
    BodyNotCovered,
    /// `Content-Length` does not match the supplied body.
    ContentLengthMismatch,
}

impl fmt::Display for FastPathReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MethodNotAllowed => f.write_str("method not allowed"),
            Self::PathNotAllowlisted => f.write_str("path not allowlisted"),
            Self::UriUnsafe(reason) => write!(f, "unsafe URI: {reason}"),
            Self::UriSignature => f.write_str("URI signature"),
            Self::HeaderSignature => f.write_str("header signature"),
            Self::HostMissing => f.write_str("host missing"),
            Self::HostInvalid => f.write_str("host invalid"),
            Self::ScannerUserAgent => f.write_str("scanner user-agent"),
            Self::HeaderAnomaly(reason) => write!(f, "header anomaly: {reason}"),
            Self::ContentTypeNotAllowed => f.write_str("content-type not allowed"),
            Self::ProtocolVersionNotAllowed => f.write_str("protocol version not allowed"),
            Self::BodyTooLarge => f.write_str("body too large"),
            Self::BodySignature => f.write_str("body signature"),
            Self::BodyLiteral => f.write_str("body literal"),
            Self::BodyInvalidUtf8 => f.write_str("body invalid UTF-8"),
            Self::BodyByteRange => f.write_str("body byte range"),
            Self::MultipartNotCovered => f.write_str("multipart not covered"),
            Self::ArgumentLimit => f.write_str("argument limit"),
            Self::BodyRuleUngated => f.write_str("body rule ungated"),
            Self::BodyNotCovered => f.write_str("body not covered"),
            Self::ContentLengthMismatch => f.write_str("content-length mismatch"),
        }
    }
}

/// Decision returned by the fast path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FastPathDecision {
    /// Every covered rule is provably unable to match; Coraza can be skipped.
    Clean {
        /// Number of structural checks that ran.
        checks: usize,
        /// Body bytes scanned (0 for bodyless requests).
        body_scanned: usize,
    },
    /// Run Coraza for the final decision.
    NeedsCoraza {
        /// Why the fast path stopped.
        reason: FastPathReason,
    },
}

impl FastPathDecision {
    /// True when the request was proven clean.
    pub fn is_clean(&self) -> bool {
        matches!(self, Self::Clean { .. })
    }

    /// The fallback reason, if any.
    pub fn reason(&self) -> Option<FastPathReason> {
        match self {
            Self::Clean { .. } => None,
            Self::NeedsCoraza { reason } => Some(*reason),
        }
    }
}

/// One request as seen by the fast path.
#[derive(Debug, Clone, Copy)]
pub struct FastPathRequest<'a> {
    /// HTTP method token.
    pub method: &'a str,
    /// Raw request target (origin-form, `*`, authority-form or absolute-form).
    pub uri: &'a str,
    /// HTTP version string, e.g. `HTTP/1.1`.
    pub http_version: &'a str,
    /// Header name/value pairs in wire order.
    pub headers: &'a [(&'a str, &'a str)],
    /// Request body, if any.
    pub body: Option<&'a [u8]>,
}

/// Fast-path configuration.
pub struct FastPathConfig {
    /// Method allowlist (default: CRS `GET HEAD POST OPTIONS`).
    pub methods: MethodMatcher,
    /// Optional path allowlist (default: empty, all paths eligible).
    pub paths: PathAllowlist,
    /// Header policy (default: CRS defaults).
    pub headers: HeaderPolicy,
    /// Maximum body bytes inspected (default: 4 KiB).
    pub max_body_bytes: usize,
    /// Allow a body-bearing request to return `Clean`. Requires the prefilter
    /// artifact to gate every body rule, which is false on stock CRS.
    pub allow_body_clean: bool,
}

impl Default for FastPathConfig {
    fn default() -> Self {
        Self {
            methods: MethodMatcher::crs_default(),
            paths: PathAllowlist::empty(),
            headers: HeaderPolicy::crs_default().expect("embedded CRS scanner list must compile"),
            max_body_bytes: body::DEFAULT_MAX_BODY_BYTES,
            allow_body_clean: false,
        }
    }
}

/// The compiled fast path.
pub struct FastPath {
    methods: MethodMatcher,
    paths: PathAllowlist,
    headers: HeaderPolicy,
    body: BodyInspector,
    lfi: LfiMatcher,
    restricted_files: LiteralListMatcher,
    php_functions: LiteralListMatcher,
    java_classes: LiteralListMatcher,
    signatures: RegexSignatures,
    allow_body_clean: bool,
}

impl fmt::Debug for FastPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FastPath")
            .field("methods", &self.methods.len())
            .field("scanner_patterns", &self.headers)
            .field("body", &self.body)
            .field("lfi_patterns", &self.lfi.len())
            .finish()
    }
}

impl FastPath {
    /// Builds a fast path from explicit configuration.
    pub fn new(config: FastPathConfig) -> Result<Self, String> {
        Ok(Self {
            methods: config.methods,
            paths: config.paths,
            headers: config.headers,
            body: BodyInspector::embedded()?.with_max_body_bytes(config.max_body_bytes),
            lfi: LfiMatcher::embedded()?,
            restricted_files: LiteralListMatcher::from_sources(&[matchers::RESTRICTED_FILES])?,
            php_functions: LiteralListMatcher::from_sources(&[
                matchers::PHP_FUNCTIONS_933150,
                matchers::PHP_FUNCTIONS_933151,
            ])?,
            java_classes: LiteralListMatcher::from_sources(&[matchers::JAVA_CLASSES])?,
            signatures: RegexSignatures::new()?,
            allow_body_clean: config.allow_body_clean,
        })
    }

    /// Builds the default (CRS 4.14) fast path.
    pub fn embedded() -> Result<Self, String> {
        Self::new(FastPathConfig::default())
    }

    /// Evaluates one request.
    pub fn evaluate(&self, request: &FastPathRequest<'_>) -> FastPathDecision {
        let mut checks = 0usize;

        if !self.methods.allows(request.method) {
            return needs(FastPathReason::MethodNotAllowed);
        }
        checks += 1;

        if !self.paths.is_allowed(path_of(request.uri)) {
            return needs(FastPathReason::PathNotAllowlisted);
        }
        checks += 1;

        if let Err(reason) = self.validate_uri(request.method, request.uri) {
            return needs(reason);
        }
        checks += 1;

        let view = HeaderView::new(request.headers);
        let facts = match self
            .headers
            .check(request.method, request.http_version, view)
        {
            Ok(facts) => facts,
            Err(reason) => return needs(reason),
        };
        checks += 1;

        if self.signatures.is_match(request.method.as_bytes())
            || self.signatures.is_match(request.uri.as_bytes())
            || self.signatures.is_match(request.http_version.as_bytes())
        {
            return needs(FastPathReason::HeaderSignature);
        }
        for (name, value) in view.iter() {
            if self.signatures.is_match(name.as_bytes())
                || self.signatures.is_match(value.as_bytes())
                || self.java_classes.is_match(value)
            {
                return needs(FastPathReason::HeaderSignature);
            }
        }
        checks += 1;

        let body_len = request.body.map(<[u8]>::len).unwrap_or(0);
        if body_len > 0 && matches!(request.method, "GET" | "HEAD") {
            return needs(FastPathReason::HeaderAnomaly("body on GET/HEAD"));
        }
        if let Some(content_length) = facts.content_length {
            if content_length != body_len {
                return needs(FastPathReason::ContentLengthMismatch);
            }
        }
        if body_len > 0 && facts.content_type.is_none() {
            return needs(FastPathReason::ContentTypeNotAllowed);
        }

        if body_len == 0 {
            return FastPathDecision::Clean {
                checks,
                body_scanned: 0,
            };
        }

        if !self.allow_body_clean {
            return needs(FastPathReason::BodyNotCovered);
        }

        let scan = self
            .body
            .scan(request.body.unwrap_or_default(), facts.content_type);
        match scan.reason {
            None => FastPathDecision::Clean {
                checks: checks + 1,
                body_scanned: scan.scanned_bytes,
            },
            Some(reason) => needs(reason),
        }
    }

    /// Runs only the body prefilter. Used by the benchmark and diagnostics.
    pub fn scan_body(&self, body: &[u8], content_type: Option<&str>) -> BodyScan {
        self.body.scan(body, content_type)
    }

    /// Number of compiled prefilter automata.
    pub fn automaton_count(&self) -> usize {
        self.body.automaton_count()
    }

    /// True when the prefilter artifact gates every body rule.
    pub fn all_body_rules_gated(&self) -> bool {
        self.body.all_body_rules_gated()
    }

    fn validate_uri(&self, method: &str, uri: &str) -> Result<(), FastPathReason> {
        if uri.is_empty() {
            return Err(FastPathReason::UriUnsafe("empty"));
        }
        if uri == "*" {
            return if method == "OPTIONS" {
                Ok(())
            } else {
                Err(FastPathReason::UriUnsafe("asterisk-form"))
            };
        }
        if !uri.starts_with('/') {
            return Err(FastPathReason::UriUnsafe("not origin-form"));
        }
        if uri.len() > 2048 {
            return Err(FastPathReason::UriUnsafe("too long"));
        }
        if uri.contains('?') || uri.contains('#') {
            return Err(FastPathReason::UriUnsafe("query or fragment not covered"));
        }
        if uri.contains("//") {
            return Err(FastPathReason::UriUnsafe("empty path segment"));
        }
        if uri
            .as_bytes()
            .windows(2)
            .any(|window| window.eq_ignore_ascii_case(b"0x"))
        {
            return Err(FastPathReason::UriUnsafe("hex-escaped path"));
        }
        for &byte in uri.as_bytes() {
            if byte < 0x21 || byte > 0x7e {
                return Err(FastPathReason::UriUnsafe("non-printable byte"));
            }
            if matches!(
                byte,
                b'\\'
                    | b'%'
                    | b'<'
                    | b'>'
                    | b'"'
                    | b'\''
                    | b'`'
                    | b'{'
                    | b'}'
                    | b'|'
                    | b'^'
                    | b'['
                    | b']'
                    | b';'
                    | b':'
                    | b'('
                    | b')'
            ) {
                return Err(FastPathReason::UriUnsafe("unsafe path byte"));
            }
        }

        for segment in uri.split('/').skip(1) {
            if segment == "." || segment == ".." {
                return Err(FastPathReason::UriUnsafe("dot segment"));
            }
            if segment.ends_with('~') {
                return Err(FastPathReason::UriUnsafe("backup file"));
            }
            if let Some((_, extension)) = segment.rsplit_once('.') {
                if is_restricted_extension(extension) {
                    return Err(FastPathReason::UriUnsafe("restricted extension"));
                }
            }
        }

        if self.lfi.is_suspicious(uri)
            || self.restricted_files.is_match(uri)
            || self.php_functions.is_match(uri)
            || self.java_classes.is_match(uri)
        {
            return Err(FastPathReason::UriSignature);
        }
        if self.signatures.is_match(uri.as_bytes()) {
            return Err(FastPathReason::UriSignature);
        }
        Ok(())
    }
}

fn needs(reason: FastPathReason) -> FastPathDecision {
    FastPathDecision::NeedsCoraza { reason }
}

fn path_of(uri: &str) -> &str {
    if uri == "*" {
        return uri;
    }
    let end = uri.find(['?', '#']).unwrap_or(uri.len());
    &uri[..end]
}

/// The default `tx.restricted_extensions` from CRS 4.14, without the dot.
const RESTRICTED_EXTENSIONS: &[&str] = &[
    "ani",
    "asa",
    "asax",
    "ascx",
    "backup",
    "bak",
    "bat",
    "cdx",
    "cer",
    "cfg",
    "cmd",
    "com",
    "compositefont",
    "config",
    "conf",
    "crt",
    "cs",
    "csproj",
    "csr",
    "dat",
    "db",
    "dbf",
    "dist",
    "dll",
    "dos",
    "dpkg-dist",
    "drv",
    "gadget",
    "hta",
    "htr",
    "htw",
    "ida",
    "idc",
    "idq",
    "inc",
    "inf",
    "ini",
    "jse",
    "key",
    "licx",
    "lnk",
    "log",
    "mdb",
    "msc",
    "ocx",
    "old",
    "pass",
    "pdb",
    "pfx",
    "pif",
    "pem",
    "pol",
    "prf",
    "printer",
    "pwd",
    "rdb",
    "rdp",
    "reg",
    "resources",
    "resx",
    "scr",
    "sct",
    "shs",
    "sql",
    "swp",
    "sys",
    "tlb",
    "tmp",
    "url",
    "vb",
    "vbe",
    "vbs",
    "vbproj",
    "vsdisco",
    "vxd",
    "webinfo",
    "ws",
    "wsc",
    "wsf",
    "wsh",
    "xsd",
    "xsx",
];

fn is_restricted_extension(extension: &str) -> bool {
    RESTRICTED_EXTENSIONS
        .iter()
        .any(|candidate| extension.eq_ignore_ascii_case(candidate))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fast_path() -> FastPath {
        FastPath::embedded().expect("fast path")
    }

    fn benign_headers() -> Vec<(&'static str, &'static str)> {
        vec![
            ("Host", "example.test"),
            (
                "User-Agent",
                "Mozilla/5.0 (X11; Linux x86_64) Firefox/128.0",
            ),
            ("Accept", "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8"),
            ("Accept-Encoding", "gzip, deflate"),
        ]
    }

    fn request<'a>(
        method: &'a str,
        uri: &'a str,
        headers: &'a [(&'a str, &'a str)],
    ) -> FastPathRequest<'a> {
        FastPathRequest {
            method,
            uri,
            http_version: "HTTP/1.1",
            headers,
            body: None,
        }
    }

    #[test]
    fn benign_bodyless_get_is_clean() {
        let fast = fast_path();
        let headers = benign_headers();
        let decision = fast.evaluate(&request("GET", "/", &headers));
        assert!(decision.is_clean(), "{decision:?}");
    }

    #[test]
    fn benign_options_asterisk_is_clean() {
        let fast = fast_path();
        let headers = benign_headers();
        assert!(fast.evaluate(&request("OPTIONS", "*", &headers)).is_clean());
    }

    #[test]
    fn scanner_user_agent_needs_coraza() {
        let fast = fast_path();
        let headers = vec![
            ("Host", "example.test"),
            ("User-Agent", "sqlmap/1.8"),
            ("Accept", "*/*"),
        ];
        assert_eq!(
            fast.evaluate(&request("GET", "/", &headers)).reason(),
            Some(FastPathReason::ScannerUserAgent)
        );
    }

    #[test]
    fn query_string_needs_coraza() {
        let fast = fast_path();
        let headers = benign_headers();
        assert_eq!(
            fast.evaluate(&request("GET", "/search?q=hello", &headers))
                .reason(),
            Some(FastPathReason::UriUnsafe("query or fragment not covered"))
        );
    }

    #[test]
    fn traversal_needs_coraza() {
        let fast = fast_path();
        let headers = benign_headers();
        assert_eq!(
            fast.evaluate(&request("GET", "/../../etc/passwd", &headers))
                .reason(),
            Some(FastPathReason::UriUnsafe("dot segment"))
        );
    }

    #[test]
    fn restricted_extension_needs_coraza() {
        let fast = fast_path();
        let headers = benign_headers();
        assert_eq!(
            fast.evaluate(&request("GET", "/backup.sql", &headers))
                .reason(),
            Some(FastPathReason::UriUnsafe("restricted extension"))
        );
    }

    #[test]
    fn body_bearing_request_needs_coraza_by_default() {
        let fast = fast_path();
        let headers = vec![
            ("Host", "example.test"),
            ("User-Agent", "Mozilla/5.0 Firefox/128.0"),
            ("Accept", "*/*"),
            ("Content-Type", "application/x-www-form-urlencoded"),
            ("Content-Length", "10"),
        ];
        let body = b"name=alice";
        let decision = fast.evaluate(&FastPathRequest {
            method: "POST",
            uri: "/submit",
            http_version: "HTTP/1.1",
            headers: &headers,
            body: Some(body),
        });
        assert_eq!(decision.reason(), Some(FastPathReason::BodyNotCovered));
    }

    #[test]
    fn unknown_upload_header_needs_coraza() {
        let fast = fast_path();
        let mut headers = benign_headers();
        headers.push(("X-Filename", "shell.php"));
        assert_eq!(
            fast.evaluate(&request("GET", "/", &headers)).reason(),
            Some(FastPathReason::HeaderAnomaly("unknown header"))
        );
    }

    #[test]
    fn php_function_path_needs_coraza() {
        let fast = fast_path();
        let headers = benign_headers();
        assert_eq!(
            fast.evaluate(&request("GET", "/get/phpinfo", &headers))
                .reason(),
            Some(FastPathReason::UriSignature)
        );
    }

    #[test]
    fn java_token_in_header_needs_coraza() {
        let fast = fast_path();
        let mut headers = benign_headers();
        headers.push(("Accept-Language", "java.lang.runtime"));
        assert_eq!(
            fast.evaluate(&request("GET", "/", &headers)).reason(),
            Some(FastPathReason::HeaderSignature)
        );
    }

    #[test]
    fn method_not_allowed_needs_coraza() {
        let fast = fast_path();
        let headers = benign_headers();
        assert_eq!(
            fast.evaluate(&request("DELETE", "/", &headers)).reason(),
            Some(FastPathReason::MethodNotAllowed)
        );
    }
}
