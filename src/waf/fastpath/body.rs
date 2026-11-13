//! Body prefilter for the request fast path.
//!
//! The body is scanned with the proven required-literal prefilter from
//! [`crate::waf::prefilter`] plus a small set of exact checks for the
//! non-literal CRS rules (UTF-8, byte range, argument limits, multipart).
//! On stock CRS 4.14 some body rules are still ungated (`@detectSQLi`,
//! `@detectXSS`, several obfuscation-tolerant regexes), so a clean literal
//! scan is necessary but not sufficient: [`BodyInspector::scan`] returns
//! `NeedsCoraza` unless the artifact proves every body rule is gated.

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use serde::Deserialize;

use crate::waf::prefilter::{Prefilter, PrefilterHit, EMBEDDED_ARTIFACT};

use super::matchers::RegexSignatures;
use super::FastPathReason;

/// Default maximum body size the fast path will inspect.
pub const DEFAULT_MAX_BODY_BYTES: usize = 4096;

/// CRS argument limits (defaults from `crs-setup.conf`).
const MAX_ARG_NAME_LENGTH: usize = 200;
const MAX_ARG_LENGTH: usize = 4000;
const MAX_NUM_ARGS: usize = 255;
const MAX_TOTAL_ARG_LENGTH: usize = 64_000;

/// Result of scanning one body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BodyScan {
    /// Final body verdict.
    pub reason: Option<FastPathReason>,
    /// True when the required-literal prefilter found no gated literal.
    pub prefilter_clean: bool,
    /// Number of body bytes scanned by the prefilter (representations can
    /// multiply this).
    pub scanned_bytes: usize,
    /// Up to a bounded number of rule ids that produced a literal hit.
    pub matched_rules: Vec<u32>,
}

impl BodyScan {
    /// True when the body is provably clean for the covered rule set.
    pub fn is_clean(&self) -> bool {
        self.reason.is_none()
    }
}

/// Single-automaton literal scan for bodies that contain no byte that any
/// CRS transform pipeline rewrites. Matching case-insensitively is a superset
/// of the per-group case sensitivity, so a miss is still a proof.
struct FastLiteralMatcher {
    automaton: AhoCorasick,
}

impl FastLiteralMatcher {
    fn embedded() -> Result<Self, String> {
        #[derive(Deserialize)]
        struct Artifact {
            rules: Vec<Gate>,
        }
        #[derive(Deserialize)]
        struct Gate {
            gated: bool,
            literal_groups: Vec<LiteralGroup>,
        }
        #[derive(Deserialize)]
        struct LiteralGroup {
            literals: Vec<String>,
        }

        let artifact: Artifact =
            serde_json::from_str(EMBEDDED_ARTIFACT).map_err(|err| err.to_string())?;
        let mut literals: Vec<String> = artifact
            .rules
            .into_iter()
            .filter(|gate| gate.gated)
            .flat_map(|gate| gate.literal_groups)
            .flat_map(|group| group.literals)
            .filter(|literal| !literal.is_empty())
            .collect();
        literals.sort_unstable();
        literals.dedup();
        let automaton = AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .match_kind(MatchKind::Standard)
            .build(&literals)
            .map_err(|err| err.to_string())?;
        Ok(Self { automaton })
    }

    fn is_match(&self, body: &[u8]) -> bool {
        self.automaton.is_match(body)
    }
}

/// Body scanner shared by every fast-path instance.
pub struct BodyInspector {
    prefilter: &'static Prefilter,
    fast_literals: FastLiteralMatcher,
    signatures: RegexSignatures,
    max_body_bytes: usize,
}

impl std::fmt::Debug for BodyInspector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BodyInspector")
            .field("automata", &self.prefilter.automaton_count())
            .field("max_body_bytes", &self.max_body_bytes)
            .finish()
    }
}

impl BodyInspector {
    /// Builds the inspector from the embedded prefilter artifact.
    pub fn embedded() -> Result<Self, String> {
        let prefilter = Prefilter::embedded().map_err(|err| err.to_string())?;
        Ok(Self {
            prefilter,
            fast_literals: FastLiteralMatcher::embedded()?,
            signatures: RegexSignatures::new()?,
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
        })
    }

    /// Overrides the inspected-body cap.
    pub fn with_max_body_bytes(mut self, max_body_bytes: usize) -> Self {
        self.max_body_bytes = max_body_bytes;
        self
    }

    /// Scans a body and reports whether the covered rule set can be skipped.
    pub fn scan(&self, body: &[u8], content_type: Option<&str>) -> BodyScan {
        if body.len() > self.max_body_bytes {
            return BodyScan {
                reason: Some(FastPathReason::BodyTooLarge),
                prefilter_clean: false,
                scanned_bytes: 0,
                matched_rules: Vec::new(),
            };
        }

        if self.signatures.is_match(body) {
            return BodyScan {
                reason: Some(FastPathReason::BodySignature),
                prefilter_clean: false,
                scanned_bytes: body.len(),
                matched_rules: Vec::new(),
            };
        }

        // When the body contains no byte rewritten by any CRS transform
        // pipeline, the raw body is a superset representation. A single
        // case-insensitive Aho-Corasick scan is then equivalent to (and much
        // cheaper than) the 84 per-group automata.
        let simple = body.iter().copied().all(|byte| !is_transform_trigger(byte));
        let (hit, scanned_bytes, matched_rules) = if simple {
            (self.fast_literals.is_match(body), body.len(), Vec::new())
        } else {
            let result = self.prefilter.evaluate(body);
            (result.hit, result.scanned_bytes, result.matched_rules)
        };

        if hit {
            return BodyScan {
                reason: Some(FastPathReason::BodyLiteral),
                prefilter_clean: false,
                scanned_bytes,
                matched_rules,
            };
        }

        if std::str::from_utf8(body).is_err() {
            return BodyScan {
                reason: Some(FastPathReason::BodyInvalidUtf8),
                prefilter_clean: true,
                scanned_bytes,
                matched_rules: Vec::new(),
            };
        }

        if body.contains(&0) {
            return BodyScan {
                reason: Some(FastPathReason::BodyByteRange),
                prefilter_clean: true,
                scanned_bytes,
                matched_rules: Vec::new(),
            };
        }

        if let Some(reason) = check_content_type(body, content_type) {
            return BodyScan {
                reason: Some(reason),
                prefilter_clean: true,
                scanned_bytes,
                matched_rules: Vec::new(),
            };
        }

        if !self.prefilter.all_body_rules_gated() {
            return BodyScan {
                reason: Some(FastPathReason::BodyRuleUngated),
                prefilter_clean: true,
                scanned_bytes,
                matched_rules: Vec::new(),
            };
        }

        BodyScan {
            reason: None,
            prefilter_clean: true,
            scanned_bytes,
            matched_rules: Vec::new(),
        }
    }

    /// Exposes the literal prefilter result for benchmarking and diagnostics.
    pub fn prefilter_only(&self, body: &[u8]) -> PrefilterHit {
        self.prefilter.evaluate(body)
    }

    /// Number of compiled prefilter automata.
    pub fn automaton_count(&self) -> usize {
        self.prefilter.automaton_count()
    }

    /// True when the artifact gates every body-relevant CRS rule.
    pub fn all_body_rules_gated(&self) -> bool {
        self.prefilter.all_body_rules_gated()
    }
}

/// Bytes that make at least one CRS transform pipeline non-identity.
fn is_transform_trigger(byte: u8) -> bool {
    !byte.is_ascii()
        || byte.is_ascii_whitespace()
        || matches!(
            byte,
            b'%' | b'&'
                | b'+'
                | b'\\'
                | b'<'
                | b'>'
                | b'{'
                | b'}'
                | b';'
                | b'/'
                | b'"'
                | b'\''
                | b'*'
                | b'.'
                | b'?'
                | b'#'
        )
}

fn check_content_type(body: &[u8], content_type: Option<&str>) -> Option<FastPathReason> {
    let Some(content_type) = content_type else {
        return Some(FastPathReason::ContentTypeNotAllowed);
    };
    let media_type = content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();

    match media_type.as_str() {
        "application/x-www-form-urlencoded" => check_form_body(body),
        // Multipart part headers and the `_charset_` argument are not modelled
        // by the prefilter; require full CRS.
        "multipart/form-data" => Some(FastPathReason::MultipartNotCovered),
        "application/json" => check_json_body(body),
        _ => None,
    }
}

fn check_form_body(body: &[u8]) -> Option<FastPathReason> {
    let text = std::str::from_utf8(body).ok()?;
    let mut count = 0usize;
    let mut total = 0usize;
    for pair in text.split('&') {
        if pair.is_empty() {
            continue;
        }
        count += 1;
        total += pair.len();
        if count > MAX_NUM_ARGS || total > MAX_TOTAL_ARG_LENGTH {
            return Some(FastPathReason::ArgumentLimit);
        }
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        if name.len() > MAX_ARG_NAME_LENGTH || value.len() > MAX_ARG_LENGTH {
            return Some(FastPathReason::ArgumentLimit);
        }
    }
    None
}

fn check_json_body(body: &[u8]) -> Option<FastPathReason> {
    // A full JSON parser is not needed for the conservative path: reject
    // anything that is not a single well-formed UTF-8 JSON value. The CRS JSON
    // body processor would otherwise expose structure the prefilter does not
    // model.
    let text = std::str::from_utf8(body).ok()?;
    let mut deserializer = serde_json::Deserializer::from_str(text);
    if serde::de::IgnoredAny::deserialize(&mut deserializer).is_err() {
        return Some(FastPathReason::BodyRuleUngated);
    }
    if deserializer.end().is_err() {
        return Some(FastPathReason::BodyRuleUngated);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_prefilter_loads() {
        let inspector = BodyInspector::embedded().expect("prefilter");
        assert!(inspector.automaton_count() > 0);
    }

    #[test]
    fn benign_form_body_is_literal_clean() {
        let inspector = BodyInspector::embedded().expect("prefilter");
        let scan = inspector.scan(
            b"name=alice&city=lisbon",
            Some("application/x-www-form-urlencoded"),
        );
        assert!(scan.prefilter_clean);
        // Stock CRS still has ungated body rules.
        assert_eq!(scan.reason, Some(FastPathReason::BodyRuleUngated));
    }

    #[test]
    fn sqli_body_hits_a_gated_literal() {
        let inspector = BodyInspector::embedded().expect("prefilter");
        let scan = inspector.scan(
            b"q=1%27%20UNION%20SELECT%20password%20FROM%20users",
            Some("application/x-www-form-urlencoded"),
        );
        assert!(!scan.prefilter_clean || scan.reason == Some(FastPathReason::BodyLiteral));
    }

    #[test]
    fn nul_byte_is_rejected() {
        let inspector = BodyInspector::embedded().expect("prefilter");
        let scan = inspector.scan(b"a=\0", Some("application/x-www-form-urlencoded"));
        assert_eq!(scan.reason, Some(FastPathReason::BodyByteRange));
    }

    #[test]
    fn oversized_body_is_rejected() {
        let inspector = BodyInspector::embedded().expect("prefilter");
        let body = vec![b'A'; DEFAULT_MAX_BODY_BYTES + 1];
        assert_eq!(
            inspector.scan(&body, Some("application/json")).reason,
            Some(FastPathReason::BodyTooLarge)
        );
    }
}
