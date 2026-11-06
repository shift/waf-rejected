//! Native, Coraza-parity SQLi and XSS detection operators.
//!
//! `@detectSQLi` (CRS 942100) and `@detectXSS` (CRS 941100/941110/...) are the
//! two dominant *ungated* operators in the CRS body rule set: they have no
//! required literal, so the literal prefilter can never gate them and every
//! request body must be shipped to Coraza. This module removes that
//! dependency by porting the exact library Coraza calls — `libinjection` — to
//! Rust.
//!
//! ```
//! # use waf_ingress::waf::native_detect::{detect_sqli, detect_xss};
//! assert!(detect_sqli("1' OR '1'='1"));
//! assert!(!detect_sqli("hello world"));
//! assert!(detect_xss("<script>alert(1)</script>"));
//! assert!(!detect_xss("plain text"));
//! ```
//!
//! # Parity
//!
//! Coraza v3.3.3 implements `@detectSQLi` as `libinjection.IsSQLi` and
//! `@detectXSS` as `libinjection.IsXSS` from `libinjection-go` v0.2.2. The
//! tokenizer, folding rules, fingerprint blacklist/whitelist and the HTML5
//! tokenizer state machine are transcribed from that source, so decisions are
//! identical by construction. `tests/corpus/native-detect/oracle.json` pins
//! the parity claim: it records the upstream verdicts for every request value
//! in the CRS corpus plus a generated variant corpus, and
//! [`tests`] replays it.
//!
//! # Cost
//!
//! Both detectors are byte oriented, allocation-free and single pass:
//!
//! * SQLi: at most four tokenizer passes (as-is, MySQL reparse, single-quote
//!   and double-quote modes), a fixed 8-token vector, 32-byte inline token
//!   values, and binary search over static tables. No heap traffic.
//! * XSS: five HTML5 tokenizer passes (one per initial state), fixed-size
//!   stack state, no heap traffic.
//!
//! Work is linear in the value length; the only super-linear path is the
//! upstream quote-escape check, which searches for a repeated suffix and is
//! quadratic only for adversarial inputs built from a repeating quoted tail.
//! The engine's body-size limit bounds the worst case.
//!
//! # Licensing
//!
//! The logic and tables derive from `libinjection-go` (BSD-3-Clause, Coraza)
//! which derives from libinjection (BSD-3-Clause, Nick Galbreath). The full
//! notice is retained in `src/waf/native_detect/LICENSE.libinjection.txt`; see
//! also the module headers in `sqli_data.rs` / `xss_data.rs`.
//!
//! This module is **not enabled by default**: the request path still uses
//! Coraza. Enable the `native-detect` feature and call [`NativeOperator`] from
//! the native engine or prefilter.

pub mod sqli;
pub mod xss;

mod sqli_data;
mod xss_data;

/// Operators this module can evaluate natively.
///
/// The names match Coraza's operator identifiers (without the leading `@`), so
/// a rule set can map an operator name straight onto the implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeOperator {
    /// Coraza `@detectSQLi` / libinjection SQLi.
    DetectSqlInjection,
    /// Coraza `@detectXSS` / libinjection XSS.
    DetectXss,
}

impl NativeOperator {
    /// Map a Coraza operator name (`detectSQLi`, `detectXSS`) onto the native
    /// implementation. Returns `None` for operators this module does not own.
    pub fn from_coraza_name(name: &str) -> Option<Self> {
        let name = name.strip_prefix('@').unwrap_or(name);
        if name.eq_ignore_ascii_case("detectSQLi") {
            Some(Self::DetectSqlInjection)
        } else if name.eq_ignore_ascii_case("detectXSS") {
            Some(Self::DetectXss)
        } else {
            None
        }
    }

    /// Coraza operator name (without `@`).
    pub fn coraza_name(self) -> &'static str {
        match self {
            Self::DetectSqlInjection => "detectSQLi",
            Self::DetectXss => "detectXSS",
        }
    }

    /// Evaluate the operator on one value, matching Coraza's semantics.
    pub fn evaluate(self, value: &str) -> bool {
        match self {
            Self::DetectSqlInjection => detect_sqli(value),
            Self::DetectXss => detect_xss(value),
        }
    }
}

/// Evaluate a Coraza operator name natively, if it is one of ours.
///
/// This is the hook for the native engine and the prefilter: instead of
/// classifying `detectSQLi`/`detectXSS` as "ungated, must run Coraza", the
/// caller can evaluate the value here and skip the Coraza round trip.
pub fn evaluate_operator(name: &str, value: &str) -> Option<bool> {
    NativeOperator::from_coraza_name(name).map(|op| op.evaluate(value))
}

/// Returns `true` when libinjection classifies `value` as SQL injection.
///
/// Equivalent to Coraza's `@detectSQLi`. Allocation-free; linear in `value`.
pub fn detect_sqli(value: &str) -> bool {
    sqli::is_sqli(value.as_bytes())
}

/// Returns the libinjection fingerprint (the token-category string Coraza
/// captures on a `@detectSQLi` hit) when `value` is SQL injection.
pub fn detect_sqli_fingerprint(value: &str) -> Option<String> {
    sqli::sqli_fingerprint(value.as_bytes()).map(|fp| String::from_utf8_lossy(&fp).into_owned())
}

/// Returns `true` when libinjection classifies `value` as XSS.
///
/// Equivalent to Coraza's `@detectXSS`. Allocation-free; linear in `value`.
pub fn detect_xss(value: &str) -> bool {
    xss::is_xss_detect(value.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Upstream verdicts replayed from the pinned oracle. Regenerate with
    /// `native/coraza-sidecar` (see `docs/design/native-detect.md`).
    const ORACLE: &str = include_str!("../../../tests/corpus/native-detect/oracle.json");

    #[derive(serde::Deserialize)]
    struct OracleCase {
        /// Input value.
        s: String,
        /// Upstream `libinjection.IsSQLi`.
        q: bool,
        /// Upstream `libinjection.IsXSS`.
        x: bool,
        /// Provenance: `crs` or `variant`.
        k: String,
    }

    #[test]
    fn operator_names_round_trip() {
        for (name, op) in [
            ("detectSQLi", NativeOperator::DetectSqlInjection),
            ("@detectSQLi", NativeOperator::DetectSqlInjection),
            ("detectXSS", NativeOperator::DetectXss),
            ("@detectXSS", NativeOperator::DetectXss),
        ] {
            assert_eq!(NativeOperator::from_coraza_name(name), Some(op));
            assert_eq!(op.coraza_name(), name.trim_start_matches('@'));
        }
        assert_eq!(NativeOperator::from_coraza_name("rx"), None);
        assert_eq!(evaluate_operator("rx", "<script>"), None);
    }

    #[test]
    fn known_sqli_payloads_match_upstream() {
        for payload in [
            "-1' and 1=1 union/* foo */select load_file('/etc/passwd')--",
            "1' OR '1'='1",
            "1 UNION SELECT username, password FROM users",
            "admin'--",
            "1;DROP TABLE users",
            "' or 1=1#",
            "0xdeadbeef UNION ALL SELECT NULL",
        ] {
            assert!(detect_sqli(payload), "expected SQLi: {payload:?}");
        }
    }

    #[test]
    fn benign_values_are_not_sqli() {
        for value in [
            "hello world",
            "name=alice&city=paris",
            "The quick brown fox jumps over the lazy dog",
            "2026-11-02T12:00:00Z",
            "select a coffee",
            "1 and 2",
            "user@example.com",
        ] {
            assert!(!detect_sqli(value), "expected benign: {value:?}");
        }
    }

    #[test]
    fn known_xss_payloads_match_upstream() {
        for payload in [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<iframe src=\"javascript:alert(1)\">",
            "<svg/onload=alert(1)>",
            "<a href=\"data:text/html;base64,PHNjcmlwdD4=\">x</a>",
            "<body onload=alert(1)>",
            "<!--[if IE]><script>alert(1)</script><![endif]-->",
        ] {
            assert!(detect_xss(payload), "expected XSS: {payload:?}");
        }
    }

    #[test]
    fn sqli_fingerprint_is_reported_on_hit() {
        let fp = detect_sqli_fingerprint("1' OR '1'='1").expect("SQLi hit has a fingerprint");
        assert!(!fp.is_empty());
        assert!(
            fp.len() <= 5,
            "libinjection fingerprints are at most 5 tokens: {fp:?}"
        );
        assert_eq!(detect_sqli_fingerprint("hello world"), None);
    }

    #[test]
    fn benign_values_are_not_xss() {
        for value in [
            "plain text",
            "name=alice&city=paris",
            "a < b and b > c",
            "user@example.com",
            "https://example.com/path?q=1",
            "{\"json\":true}",
        ] {
            assert!(!detect_xss(value), "expected benign: {value:?}");
        }
    }

    /// The gate: zero decision differences against Coraza's operators on the
    /// pinned corpus.
    #[test]
    fn parity_with_coraza_on_pinned_oracle() {
        let cases: Vec<OracleCase> = serde_json::from_str(ORACLE).expect("oracle JSON parses");
        assert!(
            cases.len() > 5_000,
            "oracle unexpectedly small: {}",
            cases.len()
        );

        let mut sqli = (0usize, 0usize); // (false negatives, false positives)
        let mut xss = (0usize, 0usize);
        let mut examples: Vec<String> = Vec::new();

        for case in &cases {
            let got_q = detect_sqli(&case.s);
            let got_x = detect_xss(&case.s);

            if case.q && !got_q {
                sqli.0 += 1;
                examples.push(format!("SQLi FN [{}] {:?}", case.k, case.s));
            } else if !case.q && got_q {
                sqli.1 += 1;
                examples.push(format!("SQLi FP [{}] {:?}", case.k, case.s));
            }

            if case.x && !got_x {
                xss.0 += 1;
                examples.push(format!("XSS FN [{}] {:?}", case.k, case.s));
            } else if !case.x && got_x {
                xss.1 += 1;
                examples.push(format!("XSS FP [{}] {:?}", case.k, case.s));
            }
        }

        assert_eq!(
            (sqli.0, sqli.1),
            (0, 0),
            "SQLi parity broken; first differences: {:?}",
            &examples[..examples.len().min(10)]
        );
        assert_eq!(
            (xss.0, xss.1),
            (0, 0),
            "XSS parity broken; first differences: {:?}",
            &examples[..examples.len().min(10)]
        );
    }
}
