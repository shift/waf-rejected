//! Compiled matchers used by the request fast path.
//!
//! Everything here is immutable after construction and safe to share between
//! worker threads. The method and path matchers are exact/trie lookups; the
//! scanner matcher is an Aho-Corasick automaton over the vendored CRS scanner
//! user-agent list; the signature matcher is a precompiled regex set used as a
//! conservative "run Coraza" trigger.

use std::collections::{BTreeMap, HashSet};

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use regex::bytes::RegexSet;

/// Vendored scanner user-agent list used by CRS rule 913100.
pub const SCANNERS_USER_AGENTS: &str =
    include_str!("../../../wasm/coraza_reactor/rules/crs/rules/scanners-user-agents.data");

/// Vendored OS-file list used by CRS rule 930130.
pub const LFI_OS_FILES: &str =
    include_str!("../../../wasm/coraza_reactor/rules/crs/rules/lfi-os-files.data");

/// Vendored restricted-file list used by CRS rule 930120.
pub const RESTRICTED_FILES: &str =
    include_str!("../../../wasm/coraza_reactor/rules/crs/rules/restricted-files.data");

/// Vendored Java class list used by CRS rule 944130.
pub const JAVA_CLASSES: &str =
    include_str!("../../../wasm/coraza_reactor/rules/crs/rules/java-classes.data");

/// Vendored PHP function lists used by CRS rules 933150/933160.
pub const PHP_FUNCTIONS_933150: &str =
    include_str!("../../../wasm/coraza_reactor/rules/crs/rules/php-function-names-933150.data");
/// Vendored PHP function list used by CRS rule 933160.
pub const PHP_FUNCTIONS_933151: &str =
    include_str!("../../../wasm/coraza_reactor/rules/crs/rules/php-function-names-933151.data");

/// Exact-match allowlist for HTTP methods.
#[derive(Debug, Clone)]
pub struct MethodMatcher {
    exact: HashSet<Box<str>>,
}

impl MethodMatcher {
    /// The methods CRS 4.14 allows by default (`tx.allowed_methods`).
    pub fn crs_default() -> Self {
        Self::from_iter(["GET", "HEAD", "POST", "OPTIONS"])
    }

    /// Builds a matcher from any iterator of method names.
    pub fn from_iter<I, S>(methods: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Self {
            exact: methods
                .into_iter()
                .map(|method| method.as_ref().to_ascii_uppercase().into_boxed_str())
                .collect(),
        }
    }

    /// Returns true when `method` is in the allowlist.
    pub fn allows(&self, method: &str) -> bool {
        // Method tokens are short; a borrowed lookup would require a hash of
        // the upper-cased form, so check the common CRS methods first and only
        // allocate for the uncommon path.
        if method.len() > 32 {
            return false;
        }
        if self.exact.contains(method) {
            return true;
        }
        if method.bytes().any(|b| b.is_ascii_lowercase()) {
            return self.exact.contains(method.to_ascii_uppercase().as_str());
        }
        false
    }

    /// Number of allowed methods.
    pub fn len(&self) -> usize {
        self.exact.len()
    }

    /// True when no method is allowed (the fast path never runs).
    pub fn is_empty(&self) -> bool {
        self.exact.is_empty()
    }
}

impl Default for MethodMatcher {
    fn default() -> Self {
        Self::crs_default()
    }
}

#[derive(Debug, Default)]
struct TrieNode {
    children: BTreeMap<u8, TrieNode>,
    terminal: bool,
}

/// Exact and prefix allowlist for request paths.
///
/// An empty allowlist means "no path restriction": every syntactically safe
/// path is eligible for the fast path. A non-empty allowlist restricts the
/// fast path to the listed exact paths and byte-trie prefixes; it never bypasses
/// the safety checks, it only decides whether the fast path may run at all.
#[derive(Debug, Default)]
pub struct PathAllowlist {
    exact: HashSet<Box<str>>,
    prefixes: TrieNode,
    enabled: bool,
}

impl PathAllowlist {
    /// Empty allowlist (all paths eligible).
    pub fn empty() -> Self {
        Self::default()
    }

    /// Builds an allowlist from exact paths and prefix paths.
    pub fn new<I, S, P, T>(exact: I, prefixes: P) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
        P: IntoIterator<Item = T>,
        T: AsRef<str>,
    {
        let exact: HashSet<Box<str>> = exact
            .into_iter()
            .map(|path| path.as_ref().to_string().into_boxed_str())
            .collect();
        let mut root = TrieNode::default();
        let mut enabled = !exact.is_empty();
        for prefix in prefixes {
            let prefix = prefix.as_ref();
            if prefix.is_empty() {
                continue;
            }
            enabled = true;
            let mut node = &mut root;
            for &byte in prefix.as_bytes() {
                node = node.children.entry(byte).or_default();
            }
            node.terminal = true;
        }
        Self {
            exact,
            prefixes: root,
            enabled,
        }
    }

    /// True when the fast path is allowed to consider `path`.
    pub fn is_allowed(&self, path: &str) -> bool {
        if !self.enabled {
            return true;
        }
        if self.exact.contains(path) {
            return true;
        }
        self.has_prefix(path)
    }

    fn has_prefix(&self, path: &str) -> bool {
        let bytes = path.as_bytes();
        let mut node = &self.prefixes;
        for (index, &byte) in bytes.iter().enumerate() {
            let Some(child) = node.children.get(&byte) else {
                return false;
            };
            node = child;
            if node.terminal {
                // A prefix only matches on a path-segment boundary so that
                // `/api` does not accidentally allow `/apix`.
                if index + 1 == bytes.len() || byte == b'/' || bytes[index + 1] == b'/' {
                    return true;
                }
            }
        }
        false
    }
}

/// Aho-Corasick matcher for the CRS scanner user-agent list.
pub struct ScannerMatcher {
    automaton: AhoCorasick,
}

impl std::fmt::Debug for ScannerMatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScannerMatcher")
            .field("patterns", &self.automaton.patterns_len())
            .finish()
    }
}

impl ScannerMatcher {
    /// Builds the matcher from the embedded CRS list.
    pub fn embedded() -> Result<Self, String> {
        let patterns: Vec<&str> = SCANNERS_USER_AGENTS
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .collect();
        let automaton = AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .match_kind(MatchKind::Standard)
            .build(&patterns)
            .map_err(|err| err.to_string())?;
        Ok(Self { automaton })
    }

    /// True when the user agent contains a known scanner token.
    pub fn is_scanner(&self, user_agent: &str) -> bool {
        self.automaton.is_match(user_agent.as_bytes())
    }

    /// Number of scanner patterns.
    pub fn len(&self) -> usize {
        self.automaton.patterns_len()
    }

    /// True when the list is empty.
    pub fn is_empty(&self) -> bool {
        self.automaton.patterns_len() == 0
    }
}

/// Aho-Corasick matcher for the CRS OS-file list (rule 930130).
pub struct LfiMatcher {
    automaton: AhoCorasick,
}

impl std::fmt::Debug for LfiMatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LfiMatcher")
            .field("patterns", &self.automaton.patterns_len())
            .finish()
    }
}

impl LfiMatcher {
    /// Builds the matcher from the embedded CRS list.
    pub fn embedded() -> Result<Self, String> {
        let patterns: Vec<&str> = LFI_OS_FILES
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .collect();
        let automaton = AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .match_kind(MatchKind::Standard)
            .build(&patterns)
            .map_err(|err| err.to_string())?;
        Ok(Self { automaton })
    }

    /// True when the path contains a known OS-file token.
    pub fn is_suspicious(&self, path: &str) -> bool {
        self.automaton.is_match(path.as_bytes())
    }

    /// Number of patterns.
    pub fn len(&self) -> usize {
        self.automaton.patterns_len()
    }

    /// True when the list is empty.
    pub fn is_empty(&self) -> bool {
        self.automaton.patterns_len() == 0
    }
}

/// Generic Aho-Corasick matcher over one or more CRS data files.
pub struct LiteralListMatcher {
    automaton: AhoCorasick,
}

impl std::fmt::Debug for LiteralListMatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LiteralListMatcher")
            .field("patterns", &self.automaton.patterns_len())
            .finish()
    }
}

impl LiteralListMatcher {
    /// Builds a matcher from CRS data-file contents.
    pub fn from_sources(sources: &[&str]) -> Result<Self, String> {
        let patterns: Vec<&str> = sources
            .iter()
            .flat_map(|source| source.lines())
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .collect();
        let automaton = AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .match_kind(MatchKind::Standard)
            .build(&patterns)
            .map_err(|err| err.to_string())?;
        Ok(Self { automaton })
    }

    /// True when any list token occurs in `haystack`.
    pub fn is_match(&self, haystack: &str) -> bool {
        self.automaton.is_match(haystack.as_bytes())
    }

    /// Number of patterns.
    pub fn len(&self) -> usize {
        self.automaton.patterns_len()
    }

    /// True when the list is empty.
    pub fn is_empty(&self) -> bool {
        self.automaton.patterns_len() == 0
    }
}

/// Conservative attack signatures.
///
/// A hit means "the fast path cannot prove this clean"; a miss is **not** a
/// proof by itself. The fast path only returns `Clean` after the structural
/// checks in [`super`] and the literal prefilter have also passed.
pub struct RegexSignatures {
    set: RegexSet,
}

impl std::fmt::Debug for RegexSignatures {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegexSignatures")
            .field("patterns", &self.set.len())
            .finish()
    }
}

impl RegexSignatures {
    /// Compiles the signature set.
    pub fn new() -> Result<Self, String> {
        // Keep these deliberately broad: they are prefilters, not the final
        // decision. Every pattern is bounded so a hostile body cannot turn a
        // match attempt into super-linear work.
        let set = RegexSet::new([
            r"(?i)(?:\bunion\b[\s\S]{0,64}\bselect\b|\bselect\b[\s\S]{0,64}\bfrom\b|\bor\b\s+\d+\s*=\s*\d+|--\s|\b(?:sleep|benchmark|pg_sleep)\s*\(|information_schema|xp_cmdshell)",
            r"(?i)(?:<\s*script|javascript\s*:|on(?:error|load|click|mouseover)\s*=|<svg|<iframe|document\.cookie)",
            r"(?:\.\./|\.\.\\|/etc/passwd|/proc/self/|boot\.ini|win\.ini)",
            r"(?i)(?:\|\s*(?:nc|netcat|bash|sh|cmd)\b|;\s*(?:id|whoami|uname|cat)\b|\$\(|`[^`]{1,200}`)",
            r"(?i)(?:java\.lang\.|clonetransformer|forclosure|instantiatefactory|instantiatetransformer|invokertransformer|prototypeclonefactory|prototypeserializationfactory|whileclosure|getproperty|filewriter|xmldecoder|runtime|processbuilder|jndi|\$\{)",
            r"(?i)(?:this\.constructor|__proto__|constructor\s*(?:\.|\[)\s*prototype|module\.exports|require\s*[\(\[]|process\.(?:env|binding|mainmodule|process|require)|child_process|string\.fromcharcode|_js_function|nd_func)",
            r"(?i)(?:0x2f|0x5c|\.\./|\.\.\\)",
        ])
        .map_err(|err| err.to_string())?;
        Ok(Self { set })
    }

    /// True when any signature matches the bytes.
    pub fn is_match(&self, haystack: &[u8]) -> bool {
        self.set.is_match(haystack)
    }

    /// Number of compiled signatures.
    pub fn len(&self) -> usize {
        self.set.len()
    }

    /// True when the set is empty.
    pub fn is_empty(&self) -> bool {
        self.set.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method_matcher_is_case_sensitive_like_crs() {
        let matcher = MethodMatcher::crs_default();
        assert!(matcher.allows("GET"));
        assert!(matcher.allows("get"));
        assert!(!matcher.allows("DELETE"));
        assert!(!matcher.allows("REALLYLONGUNREALMETHOD"));
    }

    #[test]
    fn path_trie_matches_segment_boundaries() {
        let allow = PathAllowlist::new(["/health"], ["/api", "/static/"]);
        assert!(allow.is_allowed("/health"));
        assert!(allow.is_allowed("/api"));
        assert!(allow.is_allowed("/api/v1/users"));
        assert!(allow.is_allowed("/static/app.js"));
        assert!(!allow.is_allowed("/apix"));
        assert!(!allow.is_allowed("/other"));
    }

    #[test]
    fn empty_path_allowlist_allows_everything() {
        let allow = PathAllowlist::empty();
        assert!(allow.is_allowed("/anything"));
    }

    #[test]
    fn scanner_matcher_finds_vendored_tokens() {
        let matcher = ScannerMatcher::embedded().expect("scanner list");
        assert!(matcher.is_scanner("sqlmap/1.8 (https://sqlmap.org)"));
        assert!(matcher.is_scanner("Mozilla/5.0 Arachni/2.0"));
        assert!(!matcher.is_scanner("Mozilla/5.0 (X11; Linux x86_64) Firefox/128.0"));
    }

    #[test]
    fn signatures_trigger_on_common_attacks() {
        let signatures = RegexSignatures::new().expect("signatures");
        assert!(signatures.is_match(b"1' UNION SELECT password FROM users"));
        assert!(signatures.is_match(b"<script>alert(1)</script>"));
        assert!(signatures.is_match(b"../../etc/passwd"));
        assert!(signatures.is_match(b"; id"));
        assert!(signatures.is_match(b"/get/this.constructor"));
        assert!(signatures.is_match(b"/get/__proto__"));
        assert!(!signatures.is_match(b"hello world"));
    }
}
