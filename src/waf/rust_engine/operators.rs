//! Operator evaluation for the native CRS engine.

use std::net::IpAddr;

use super::error::EngineError;
use super::ir::{CompiledOperator, IpMatch, MacroString, OperatorKind};

/// Maximum number of capture groups Coraza exposes (`TX:0` through `TX:9`).
pub const MAX_CAPTURES: usize = 10;

/// Context used to expand `%{...}` macros in operator arguments.
pub trait MacroResolver {
    /// Expands every macro in `template`. Unknown macros expand to an empty
    /// string, matching Coraza's macro expansion for missing variables.
    fn expand(&self, template: &str) -> Vec<u8>;
}

/// Capture sink filled by a matching operator.
pub type Captures = [Vec<u8>; MAX_CAPTURES];

/// Result of evaluating one operator against one value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OperatorResult {
    pub matched: bool,
    pub captures: bool,
}

impl CompiledOperator {
    /// Evaluates the operator against one transformed value.
    pub fn evaluate(
        &self,
        value: &[u8],
        ctx: &dyn MacroResolver,
        capture: bool,
        captures: &mut Captures,
    ) -> bool {
        let matched = self.evaluate_inner(value, ctx, capture, captures);
        if self.negated {
            !matched
        } else {
            matched
        }
    }

    fn evaluate_inner(
        &self,
        value: &[u8],
        ctx: &dyn MacroResolver,
        capture: bool,
        captures: &mut Captures,
    ) -> bool {
        match &self.kind {
            OperatorKind::Rx(regex) => {
                if capture {
                    if let Some(found) = regex.captures(value) {
                        for (index, group) in found.iter().enumerate().take(MAX_CAPTURES) {
                            captures[index] =
                                group.map(|m| m.as_bytes().to_vec()).unwrap_or_default();
                        }
                        true
                    } else {
                        false
                    }
                } else {
                    regex.is_match(value)
                }
            }
            OperatorKind::Pm(automaton) | OperatorKind::PmFromFile(automaton) => {
                if capture {
                    let mut count = 0;
                    for found in automaton.find_iter(value).take(MAX_CAPTURES) {
                        captures[count] = value[found.start()..found.end()].to_vec();
                        count += 1;
                    }
                    count > 0
                } else {
                    automaton.is_match(value)
                }
            }
            OperatorKind::Contains(arg) => {
                let needle = ctx.expand(&arg.0);
                contains(value, &needle)
            }
            OperatorKind::BeginsWith(arg) => {
                let prefix = ctx.expand(&arg.0);
                value.starts_with(&prefix)
            }
            OperatorKind::EndsWith(arg) => {
                let suffix = ctx.expand(&arg.0);
                value.ends_with(&suffix)
            }
            OperatorKind::Within(arg) => {
                let haystack = ctx.expand(&arg.0);
                contains(&haystack, value)
            }
            OperatorKind::StrEq(arg) => {
                let expected = ctx.expand(&arg.0);
                value == expected.as_slice()
            }
            OperatorKind::Eq(arg) => numeric(value) == numeric(&ctx.expand(&arg.0)),
            OperatorKind::Lt(arg) => numeric(value) < numeric(&ctx.expand(&arg.0)),
            OperatorKind::Gt(arg) => numeric(value) > numeric(&ctx.expand(&arg.0)),
            OperatorKind::Ge(arg) => numeric(value) >= numeric(&ctx.expand(&arg.0)),
            OperatorKind::Le(arg) => numeric(value) <= numeric(&ctx.expand(&arg.0)),
            OperatorKind::ValidateByteRange(valid) => {
                !value.is_empty() && value.iter().any(|byte| !valid[usize::from(*byte)])
            }
            OperatorKind::ValidateUrlEncoding => validate_url_encoding(value),
            OperatorKind::ValidateUtf8Encoding => std::str::from_utf8(value).is_err(),
            OperatorKind::UnconditionalMatch => true,
            OperatorKind::IpMatch(entries) => {
                let Ok(text) = std::str::from_utf8(value) else {
                    return false;
                };
                let Ok(address) = text.trim().parse::<IpAddr>() else {
                    return false;
                };
                entries.iter().any(|entry| ip_match(entry, address))
            }
            OperatorKind::DetectSqlInjection => {
                #[cfg(feature = "native-detect")]
                {
                    if !crate::waf::native_detect::sqli::is_sqli(value) {
                        return false;
                    }
                    if capture {
                        if let Some(fingerprint) =
                            crate::waf::native_detect::sqli::sqli_fingerprint(value)
                        {
                            captures[0] = fingerprint;
                        }
                    }
                    true
                }
                #[cfg(not(feature = "native-detect"))]
                {
                    false
                }
            }
            OperatorKind::DetectXss => {
                #[cfg(feature = "native-detect")]
                {
                    crate::waf::native_detect::xss::is_xss_detect(value)
                }
                #[cfg(not(feature = "native-detect"))]
                {
                    false
                }
            }
        }
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if needle.len() > haystack.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// Coraza parses numeric operator arguments with `strconv.Atoi` and treats a
/// parse failure as zero.
fn numeric(value: &[u8]) -> i64 {
    std::str::from_utf8(value)
        .ok()
        .and_then(|text| text.trim().parse::<i64>().ok())
        .unwrap_or(0)
}

fn validate_url_encoding(value: &[u8]) -> bool {
    if value.is_empty() {
        return false;
    }
    let mut i = 0;
    while i < value.len() {
        if value[i] == b'%' {
            if i + 2 >= value.len() {
                return true;
            }
            if !value[i + 1].is_ascii_hexdigit() || !value[i + 2].is_ascii_hexdigit() {
                return true;
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    false
}

fn ip_match(entry: &IpMatch, address: IpAddr) -> bool {
    match entry {
        IpMatch::Exact(expected) => *expected == address,
        IpMatch::Cidr(network, prefix) => match (network, address) {
            (IpAddr::V4(network), IpAddr::V4(address)) => {
                let prefix = (*prefix).min(32);
                let mask = if prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - prefix)
                };
                (u32::from(*network) & mask) == (u32::from(address) & mask)
            }
            (IpAddr::V6(network), IpAddr::V6(address)) => {
                let prefix = (*prefix).min(128);
                let mask = if prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - prefix)
                };
                (u128::from(*network) & mask) == (u128::from(address) & mask)
            }
            _ => false,
        },
    }
}

/// Parses an `@ipMatch` argument list. Invalid entries are ignored, like
/// Coraza.
pub fn parse_ip_match(argument: &str) -> Vec<IpMatch> {
    let mut entries = Vec::new();
    for raw in argument.split(',') {
        let entry = raw.trim();
        if entry.is_empty() {
            continue;
        }
        if let Some((address, prefix)) = entry.split_once('/') {
            let Ok(address) = address.trim().parse::<IpAddr>() else {
                continue;
            };
            let Ok(prefix) = prefix.trim().parse::<u8>() else {
                continue;
            };
            entries.push(IpMatch::Cidr(address, prefix));
        } else if let Ok(address) = entry.parse::<IpAddr>() {
            entries.push(IpMatch::Exact(address));
        }
    }
    entries
}

/// Builds an ASCII-case-insensitive phrase automaton.
pub fn build_phrases<I, S>(phrases: I) -> Result<aho_corasick::AhoCorasick, EngineError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<[u8]>,
{
    aho_corasick::AhoCorasickBuilder::new()
        .ascii_case_insensitive(true)
        .match_kind(aho_corasick::MatchKind::LeftmostLongest)
        .build(phrases)
        .map_err(|_| EngineError::Internal("failed to build phrase automaton"))
}

/// Parses `@pm` arguments (`word1 word2`).
pub fn parse_pm_argument(argument: &str) -> Vec<Vec<u8>> {
    argument
        .split(' ')
        .filter(|phrase| !phrase.is_empty())
        .map(|phrase| phrase.to_ascii_lowercase().into_bytes())
        .collect()
}

/// Parses a `@validateByteRange` argument.
pub fn parse_byte_range(argument: &str) -> Result<[bool; 256], String> {
    let mut valid = [false; 256];
    for raw in argument.split(',') {
        let entry = raw.trim();
        if entry.is_empty() {
            continue;
        }
        if let Some((start, end)) = entry.split_once('-') {
            let start: usize = start
                .trim()
                .parse()
                .map_err(|_| format!("invalid byte `{entry}`"))?;
            let end: usize = end
                .trim()
                .parse()
                .map_err(|_| format!("invalid byte `{entry}`"))?;
            if start > 255 || end > 255 || start > end {
                return Err(format!("invalid byte range `{entry}`"));
            }
            for slot in &mut valid[start..=end] {
                *slot = true;
            }
        } else {
            let byte: usize = entry
                .parse()
                .map_err(|_| format!("invalid byte `{entry}`"))?;
            if byte > 255 {
                return Err(format!("invalid byte `{entry}`"));
            }
            valid[byte] = true;
        }
    }
    Ok(valid)
}

/// Convenience for building a `MacroString`.
pub fn macro_string(value: impl Into<String>) -> MacroString {
    MacroString(value.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Empty;
    impl MacroResolver for Empty {
        fn expand(&self, template: &str) -> Vec<u8> {
            template.as_bytes().to_vec()
        }
    }

    fn captures() -> Captures {
        std::array::from_fn(|_| Vec::new())
    }

    #[test]
    fn numeric_comparisons_are_coraza_compatible() {
        let operator = CompiledOperator {
            kind: OperatorKind::Eq(macro_string("0")),
            negated: false,
            argument: "0".to_string(),
        };
        assert!(operator.evaluate(b"not-a-number", &Empty, false, &mut captures()));
    }

    #[test]
    fn validate_url_encoding_detects_bad_percent() {
        assert!(validate_url_encoding(b"a%zz"));
        assert!(validate_url_encoding(b"a%2"));
        assert!(!validate_url_encoding(b"a%20"));
    }

    #[test]
    fn ip_match_cidr() {
        let entries = parse_ip_match("127.0.0.1,10.0.0.0/8,::1");
        assert!(entries
            .iter()
            .any(|entry| ip_match(entry, "10.1.2.3".parse::<IpAddr>().unwrap())));
        assert!(!entries
            .iter()
            .any(|entry| ip_match(entry, "192.168.1.1".parse::<IpAddr>().unwrap())));
        assert!(entries
            .iter()
            .any(|entry| ip_match(entry, "::1".parse::<IpAddr>().unwrap())));
    }
}
