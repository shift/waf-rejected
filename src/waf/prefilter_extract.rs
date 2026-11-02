//! Offline extraction of *required literal sets* from the vendored OWASP CRS.
//!
//! The experimental [`crate::waf::prefilter`] runtime consumes the artifact this
//! module emits (`rules/crs/prefilter.json`).  The contract is deliberately
//! one-sided: for a gated rule, **every** value that can match the rule must
//! contain at least one of the extracted literals.  If that cannot be proven,
//! the rule is marked `ungated` and the caller must fall back to full CRS
//! evaluation.
//!
//! The extractor is conservative in three places:
//!
//! * `@rx` patterns are parsed with a small PCRE subset.  Constructs that are
//!   not understood (lookarounds, conditionals, unknown escapes) degrade to a
//!   `Class`/`Anchor` node, which yields no literal rather than a wrong one.
//! * Alternations produce a *disjunctive* literal set (one member must occur),
//!   not a single mandatory substring.  This is what makes large CRS
//!   alternations (the 932 command lists) useful.
//! * Transform chains are only gated when the runtime can reproduce them
//!   exactly; anything else is `ungated`.
//!
//! The module is feature-gated behind `crs-prefilter` because it is an
//! experimental analysis tool, not part of the default build.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Artifact schema version. Bumped whenever the JSON contract changes.
pub const SCHEMA_VERSION: u32 = 1;

/// Literals shorter than this are not useful for a prefilter: they hit benign
/// text constantly. A rule whose only derivable literals are shorter is
/// `ungated`.
pub const MIN_LITERAL_LEN: usize = 3;

/// Upper bound on the disjunctive literal set for one rule. Large sets are
/// still sound but inflate the artifact and the Aho-Corasick automaton.
pub const MAX_LITERALS_PER_RULE: usize = 4096;

/// CRS release the vendored bundle reports.
pub const CRS_VERSION: &str = "4.14.0";

/// A rule, or one member of a chained rule, that can be gated by literals.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Gate {
    /// CRS rule id (the id on the first member of a chain).
    pub id: u32,
    /// Position within a chain; `0` for a standalone rule.
    pub member: usize,
    /// Rule family (first three digits of the id).
    pub family: String,
    /// Operator name without the leading `@` (`rx`, `pmFromFile`, ...).
    pub operator: String,
    /// Variables the rule evaluates.
    pub targets: Vec<String>,
    /// True when at least one target can be populated from the request body.
    pub body_relevant: bool,
    /// Whether the literal gate is sound for this entry.
    pub gated: bool,
    /// Canonical transform chain for this member.
    pub transforms: Vec<String>,
    /// Flattened union of [`Self::literal_groups`], for humans and summaries.
    pub literals: Vec<String>,
    /// Literal sets grouped by transform chain and case sensitivity.
    pub literal_groups: Vec<LiteralGroup>,
    /// True when this entry is part of a chain.
    pub chain: bool,
    /// Why the entry could not be gated (only set when `gated == false`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// A set of literals that share one transform pipeline.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LiteralGroup {
    /// Canonical transforms applied before matching.
    pub transforms: Vec<String>,
    /// True when the literals are matched ASCII case-insensitively.
    pub case_insensitive: bool,
    /// Disjunctive literal set: a match must contain at least one member.
    pub literals: Vec<String>,
}

/// A rule that cannot be gated, with the reason.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UngatedRule {
    pub id: u32,
    pub member: usize,
    pub family: String,
    pub operator: String,
    pub targets: Vec<String>,
    pub body_relevant: bool,
    pub chain: bool,
    pub reason: String,
}

/// Aggregate coverage counters.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Coverage {
    /// Rules and chain members that were parsed.
    pub parsed_entries: usize,
    /// Entries whose targets can read body-derived data.
    pub body_relevant_entries: usize,
    /// Body-relevant entries with a sound literal gate.
    pub body_relevant_gated: usize,
    /// Body-relevant entries without a sound literal gate.
    pub body_relevant_ungated: usize,
    /// Distinct literals across all gated groups.
    pub distinct_literals: usize,
    /// Total literal members across gated groups (with duplicates).
    pub total_literals: usize,
    /// Ungated body-relevant entries grouped by operator.
    pub ungated_by_operator: BTreeMap<String, usize>,
    /// Ungated body-relevant entries grouped by CRS family.
    pub ungated_by_family: BTreeMap<String, usize>,
    /// Ungated body-relevant rule ids, sorted.
    pub ungated_rule_ids: Vec<u32>,
    /// True when the fast path is available for the whole rule set.
    pub all_body_rules_gated: bool,
}

/// The committed artifact.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrefilterArtifact {
    pub schema_version: u32,
    pub crs_version: String,
    /// Path of the parsed rule bundle, relative to the repository root.
    pub source: String,
    /// CRS paranoia level the artifact was generated for. Rules above this
    /// level are not included.
    pub paranoia_level: u32,
    pub min_literal_len: usize,
    pub rules: Vec<Gate>,
    pub ungated_rules: Vec<UngatedRule>,
    pub coverage: Coverage,
}

/// Errors surfaced by the extractor.
#[derive(Debug, thiserror::Error)]
pub enum ExtractError {
    #[error("failed to read {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("no SecRule entries found in {0}")]
    NoRules(String),
    #[error("invalid rule at {path}:{line}: {detail}")]
    Rule {
        path: String,
        line: usize,
        detail: String,
    },
    #[error("failed to serialise artifact: {0}")]
    Json(#[from] serde_json::Error),
}

/// Extracts the artifact from the rule bundle at `crs_conf`.
///
/// Data files referenced by `@pmFromFile` are resolved next to the bundle, in
/// the `rules/` subdirectory, matching both engines.
pub fn extract_from_path(crs_conf: &Path) -> Result<PrefilterArtifact, ExtractError> {
    extract_from_path_with_paranoia(crs_conf, 1)
}

/// Extracts the artifact for an explicit CRS paranoia level.
pub fn extract_from_path_with_paranoia(
    crs_conf: &Path,
    paranoia_level: u32,
) -> Result<PrefilterArtifact, ExtractError> {
    let text = read(crs_conf)?;
    let base = crs_conf
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("rules");
    extract_from_str(&text, &base, &display_path(crs_conf), paranoia_level)
}

/// Extracts the artifact from rule text. `rules_dir` is where `.data` files
/// live (normally `<crs_conf dir>/rules`).
pub fn extract_from_str(
    text: &str,
    rules_dir: &Path,
    source: &str,
    paranoia_level: u32,
) -> Result<PrefilterArtifact, ExtractError> {
    let chains = parse_chains(text, source)?;
    if chains.is_empty() {
        return Err(ExtractError::NoRules(source.to_string()));
    }

    let mut data_cache: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut rules = Vec::new();
    let mut ungated = Vec::new();

    for chain in &chains {
        // A chain above the configured paranoia level never runs. Excluding it
        // keeps the literal set (and the hit rate) aligned with the engine.
        if chain
            .members
            .iter()
            .any(|member| member.paranoia.is_some_and(|level| level > paranoia_level))
        {
            continue;
        }
        let chain_id = chain.members.iter().find_map(|m| m.id).unwrap_or_default();
        for (index, member) in chain.members.iter().enumerate() {
            let body_relevant = member.targets.iter().any(target_is_body);
            let operator = member.operator.name.clone();
            let targets: Vec<String> = member.targets.iter().map(|t| t.raw.clone()).collect();

            let (gated, transforms, groups, reason) =
                gate_member(member, rules_dir, &mut data_cache);

            let entry = Gate {
                id: chain_id,
                member: index,
                family: family_of(chain_id),
                operator: operator.clone(),
                targets: targets.clone(),
                body_relevant,
                gated: gated && body_relevant,
                transforms,
                literals: flatten(&groups),
                literal_groups: groups,
                chain: chain.members.len() > 1,
                reason: reason.clone(),
            };

            if entry.gated {
                rules.push(entry);
            } else {
                ungated.push(UngatedRule {
                    id: chain_id,
                    member: index,
                    family: family_of(chain_id),
                    operator,
                    targets,
                    body_relevant,
                    chain: chain.members.len() > 1,
                    reason: reason.unwrap_or_else(|| "no sound literal gate".to_string()),
                });
            }
        }
    }

    rules.sort_by_key(|g| (g.id, g.member));
    ungated.sort_by_key(|u| (u.id, u.member));

    let coverage = summarise(&rules, &ungated);
    Ok(PrefilterArtifact {
        schema_version: SCHEMA_VERSION,
        crs_version: CRS_VERSION.to_string(),
        source: source.to_string(),
        paranoia_level,
        min_literal_len: MIN_LITERAL_LEN,
        rules,
        ungated_rules: ungated,
        coverage,
    })
}

fn summarise(rules: &[Gate], ungated: &[UngatedRule]) -> Coverage {
    let mut cov = Coverage {
        parsed_entries: rules.len() + ungated.len(),
        ..Coverage::default()
    };
    let mut distinct = BTreeSet::new();
    for gate in rules {
        if !gate.body_relevant || !gate.gated {
            continue;
        }
        cov.body_relevant_gated += 1;
        for group in &gate.literal_groups {
            cov.total_literals += group.literals.len();
            distinct.extend(group.literals.iter().cloned());
        }
    }
    for rule in ungated {
        if !rule.body_relevant {
            continue;
        }
        cov.body_relevant_ungated += 1;
        *cov.ungated_by_operator
            .entry(rule.operator.clone())
            .or_default() += 1;
        *cov.ungated_by_family
            .entry(rule.family.clone())
            .or_default() += 1;
        cov.ungated_rule_ids.push(rule.id);
    }
    cov.body_relevant_entries = cov.body_relevant_gated + cov.body_relevant_ungated;
    cov.distinct_literals = distinct.len();
    cov.ungated_rule_ids.sort_unstable();
    cov.ungated_rule_ids.dedup();
    cov.all_body_rules_gated = cov.body_relevant_ungated == 0;
    cov
}

fn flatten(groups: &[LiteralGroup]) -> Vec<String> {
    let mut all: BTreeSet<String> = BTreeSet::new();
    for group in groups {
        all.extend(group.literals.iter().cloned());
    }
    all.into_iter().collect()
}

fn family_of(id: u32) -> String {
    let s = id.to_string();
    if s.len() >= 3 {
        s[..3].to_string()
    } else {
        s
    }
}

// ---------------------------------------------------------------------------
// Rule parsing
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Chain {
    members: Vec<RawRule>,
}

#[derive(Debug, Clone)]
struct RawRule {
    id: Option<u32>,
    targets: Vec<Target>,
    operator: Operator,
    transforms: Vec<String>,
    chain: bool,
    /// `tag:'paranoia-level/N'`, when present.
    paranoia: Option<u32>,
    line: usize,
}

#[derive(Debug, Clone)]
struct Target {
    raw: String,
    base: String,
}

#[derive(Debug, Clone)]
struct Operator {
    name: String,
    argument: String,
    negated: bool,
}

fn parse_chains(text: &str, source: &str) -> Result<Vec<Chain>, ExtractError> {
    let mut logical: Vec<(usize, String)> = Vec::new();
    let mut buffer = String::new();
    let mut start_line = 0usize;

    for (index, raw) in text.lines().enumerate() {
        let line_no = index + 1;
        let trimmed = raw.trim_start();
        if buffer.is_empty() {
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            start_line = line_no;
        }
        let mut piece = raw;
        if let Some(stripped) = piece.strip_suffix('\\') {
            piece = stripped;
            buffer.push_str(piece);
            buffer.push(' ');
            continue;
        }
        buffer.push_str(piece);
        let complete = std::mem::take(&mut buffer);
        let trimmed = complete.trim();
        if trimmed.starts_with("SecRule ") || trimmed.starts_with("SecRule\t") {
            logical.push((start_line, trimmed.to_string()));
        }
    }

    let mut chains: Vec<Chain> = Vec::new();
    for (line, text) in logical {
        let rule = parse_rule(&text, line, source)?;
        // A chained sub-rule follows a member whose actions contain `chain`.
        let attach = chains
            .last()
            .and_then(|chain| chain.members.last())
            .is_some_and(|member| member.chain);
        if attach {
            if let Some(last) = chains.last_mut() {
                last.members.push(rule);
            }
        } else {
            chains.push(Chain {
                members: vec![rule],
            });
        }
    }
    Ok(chains)
}

fn parse_rule(text: &str, line: usize, source: &str) -> Result<RawRule, ExtractError> {
    let rest = text
        .strip_prefix("SecRule")
        .ok_or_else(|| rule_error(source, line, "not a SecRule"))?
        .trim_start();
    let (target_text, rest) =
        split_first_token(rest).ok_or_else(|| rule_error(source, line, "missing target"))?;
    let rest = rest.trim_start();
    let (operator_text, rest) =
        take_quoted(rest).ok_or_else(|| rule_error(source, line, "operator must be quoted"))?;
    let actions_text = if rest.trim().is_empty() {
        String::new()
    } else {
        take_quoted(rest.trim_start())
            .map(|(s, _)| s)
            .ok_or_else(|| rule_error(source, line, "actions must be quoted"))?
    };

    let targets = parse_targets(target_text);
    let operator = parse_operator(&operator_text);
    let (id, transforms, chain, paranoia) = parse_actions(&actions_text);

    Ok(RawRule {
        id,
        targets,
        operator,
        transforms,
        chain,
        paranoia,
        line,
    })
}

fn rule_error(source: &str, line: usize, detail: &str) -> ExtractError {
    ExtractError::Rule {
        path: source.to_string(),
        line,
        detail: detail.to_string(),
    }
}

/// Splits the first whitespace-delimited token. Targets never contain spaces
/// in CRS; quoted keys are supported by the variable parser below.
fn split_first_token(s: &str) -> Option<(&str, &str)> {
    let s = s.trim_start();
    if s.is_empty() {
        return None;
    }
    if let Some(stripped) = s.strip_prefix('"') {
        let end = stripped.find('"')?;
        return Some((&stripped[..end], &stripped[end + 1..]));
    }
    match s.find(char::is_whitespace) {
        Some(i) => Some((&s[..i], &s[i..])),
        None => Some((s, "")),
    }
}

/// Takes a double-quoted string, handling backslash-escaped quotes.
fn take_quoted(s: &str) -> Option<(String, &str)> {
    let s = s.trim_start();
    let mut chars = s.char_indices();
    if chars.next()?.1 != '"' {
        return None;
    }
    let mut out = String::new();
    let mut escaped = false;
    for (index, c) in chars {
        if escaped {
            // Keep the backslash: the regex parser interprets it. A `\"` is a
            // literal quote for both PCRE and this parser.
            out.push('\\');
            out.push(c);
            escaped = false;
            continue;
        }
        match c {
            '\\' => escaped = true,
            '"' => return Some((out, &s[index + 1..])),
            _ => out.push(c),
        }
    }
    None
}

fn parse_targets(text: &str) -> Vec<Target> {
    let mut targets = Vec::new();
    for part in split_targets(text) {
        let raw = part.trim().to_string();
        if raw.is_empty() {
            continue;
        }
        let base = raw
            .trim_start_matches('!')
            .trim_start_matches('&')
            .split(':')
            .next()
            .unwrap_or("")
            .to_string();
        targets.push(Target { raw, base });
    }
    targets
}

/// Splits a target list on `|`, ignoring separators inside `/regex/` keys and
/// single-quoted keys.
fn split_targets(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut in_regex = false;
    let mut in_quote = false;
    let mut escaped = false;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' if in_regex => {
                current.push(c);
                if let Some(next) = chars.next() {
                    current.push(next);
                }
                escaped = false;
                continue;
            }
            '\'' if !in_regex => {
                in_quote = !in_quote;
                current.push(c);
            }
            '/' if !in_quote && !in_regex => {
                // A slash starts a key regex only after a colon.
                if current.ends_with(':') {
                    in_regex = true;
                }
                current.push(c);
            }
            '/' if in_regex && !escaped => {
                in_regex = false;
                current.push(c);
            }
            '|' if !in_regex && !in_quote => {
                out.push(std::mem::take(&mut current));
            }
            _ => {
                current.push(c);
                escaped = c == '\\';
            }
        }
    }
    out.push(current);
    out
}

fn parse_operator(text: &str) -> Operator {
    let text = text.trim();
    let (negated, rest) = match text.strip_prefix('!') {
        Some(rest) => (true, rest),
        None => (false, text),
    };
    if let Some(rest) = rest.strip_prefix('@') {
        let (name, argument) = match rest.find(char::is_whitespace) {
            Some(i) => (&rest[..i], rest[i..].trim()),
            None => (rest, ""),
        };
        Operator {
            name: name.to_string(),
            argument: argument.to_string(),
            negated,
        }
    } else {
        // No `@` means the default `@rx` operator.
        Operator {
            name: "rx".to_string(),
            argument: rest.to_string(),
            negated,
        }
    }
}

fn parse_actions(text: &str) -> (Option<u32>, Vec<String>, bool, Option<u32>) {
    let mut id = None;
    let mut transforms = Vec::new();
    let mut chain = false;
    let mut paranoia = None;
    for action in split_actions(text) {
        let action = action.trim();
        if action.is_empty() {
            continue;
        }
        if action == "chain" {
            chain = true;
            continue;
        }
        if let Some(value) = action.strip_prefix("id:") {
            id = value.trim().parse::<u32>().ok();
            continue;
        }
        if let Some(value) = action.strip_prefix("t:") {
            let name = value.trim().trim_matches('\'').trim_matches('"');
            if name.is_empty() {
                continue;
            }
            if name.eq_ignore_ascii_case("none") {
                transforms.clear();
            } else {
                transforms.push(name.to_string());
            }
            continue;
        }
        if let Some(value) = action.strip_prefix("tag:") {
            let value = value.trim().trim_matches('\'').trim_matches('"');
            if let Some(level) = value.strip_prefix("paranoia-level/") {
                paranoia = level.parse::<u32>().ok();
            }
        }
    }
    (id, transforms, chain, paranoia)
}

/// Splits an action list on commas that are not inside single quotes.
fn split_actions(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut in_single = false;
    let mut in_double = false;
    for c in text.chars() {
        match c {
            '\'' if !in_double => {
                in_single = !in_single;
                current.push(c);
            }
            '"' if !in_single => {
                in_double = !in_double;
                current.push(c);
            }
            ',' if !in_single && !in_double => {
                out.push(std::mem::take(&mut current));
            }
            _ => current.push(c),
        }
    }
    out.push(current);
    out
}

// ---------------------------------------------------------------------------
// Body relevance
// ---------------------------------------------------------------------------

/// Variables whose values are (or can be) derived from the request body.
fn target_is_body(target: &Target) -> bool {
    matches!(
        target.base.as_str(),
        "ARGS"
            | "ARGS_NAMES"
            | "ARGS_POST"
            | "ARGS_POST_NAMES"
            | "REQUEST_BODY"
            | "FILES"
            | "FILES_NAMES"
            | "FILES_SIZES"
            | "FILES_TMPNAMES"
            | "MULTIPART_PART_HEADERS"
            | "MULTIPART_FILENAME"
            | "MULTIPART_NAME"
            | "XML"
            | "JSON"
            | "REQBODY_ERROR"
    )
}

// ---------------------------------------------------------------------------
// Gating a member
// ---------------------------------------------------------------------------

/// Returns `(gated, transforms, groups, reason)`.
fn gate_member(
    member: &RawRule,
    rules_dir: &Path,
    data_cache: &mut BTreeMap<String, Vec<String>>,
) -> (bool, Vec<String>, Vec<LiteralGroup>, Option<String>) {
    let transforms = canonical_transforms(&member.transforms);
    if member.operator.negated {
        return (
            false,
            transforms,
            Vec::new(),
            Some(format!(
                "negated operator !@{} has no positive literal requirement",
                member.operator.name
            )),
        );
    }

    let op = member.operator.name.to_ascii_lowercase();

    // libinjection's XSS detector can only return true after it has seen a
    // tag open, a doctype or a tag comment; all of those require `<`. This is
    // a proven necessary condition, not a heuristic.
    if op == "detectxss" {
        let literal = "<".to_string();
        if !transforms_supported(&transforms, std::slice::from_ref(&literal)) {
            return (
                false,
                transforms,
                Vec::new(),
                Some("transform chain is not reproducible for the XSS gate".to_string()),
            );
        }
        let group = LiteralGroup {
            transforms: transforms.clone(),
            case_insensitive: false,
            literals: vec![literal],
        };
        return (true, transforms, vec![group], None);
    }

    let (literals, case_insensitive) = match op.as_str() {
        "rx" => match extract_regex_literals(&member.operator.argument) {
            Ok(set) => {
                let mut all = BTreeSet::new();
                let mut has_ci = false;
                let mut has_cs = false;
                for literal in set {
                    if literal.ci {
                        has_ci = true;
                    } else {
                        has_cs = true;
                    }
                    all.insert(literal.text);
                }
                (all.into_iter().collect::<Vec<_>>(), (has_ci, has_cs))
            }
            Err(reason) => return (false, transforms, Vec::new(), Some(reason)),
        },
        "pmfromfile" => {
            let file = member.operator.argument.trim();
            if file.is_empty() {
                return (
                    false,
                    transforms,
                    Vec::new(),
                    Some("@pmFromFile without a data file".to_string()),
                );
            }
            let phrases = match load_data_file(file, rules_dir, data_cache) {
                Ok(p) => p,
                Err(reason) => return (false, transforms, Vec::new(), Some(reason)),
            };
            if phrases.is_empty() {
                return (
                    false,
                    transforms,
                    Vec::new(),
                    Some(format!("@pmFromFile {file} contains no phrases")),
                );
            }
            (phrases, (true, false))
        }
        "pm" => {
            let phrases: Vec<String> = member
                .operator
                .argument
                .split_whitespace()
                .filter(|p| !p.is_empty())
                .map(|p| p.to_lowercase())
                .collect();
            if phrases.is_empty() {
                return (
                    false,
                    transforms,
                    Vec::new(),
                    Some("@pm without phrases".to_string()),
                );
            }
            (phrases, (true, false))
        }
        "contains" | "streq" | "beginswith" | "endswith" | "within" => {
            let literal = member
                .operator
                .argument
                .trim()
                .trim_matches('"')
                .to_string();
            if literal.is_empty() {
                return (
                    false,
                    transforms,
                    Vec::new(),
                    Some(format!("@{} without a literal", member.operator.name)),
                );
            }
            (vec![literal], (false, true))
        }
        "unconditionalmatch" | "nomatch" | "detectsqli" => {
            return (
                false,
                transforms,
                Vec::new(),
                Some(format!(
                    "operator @{} exposes no required literal",
                    member.operator.name
                )),
            );
        }
        _ => {
            return (
                false,
                transforms,
                Vec::new(),
                Some(format!(
                    "operator @{} is not a literal operator",
                    member.operator.name
                )),
            );
        }
    };

    if literals.is_empty() {
        return (
            false,
            transforms,
            Vec::new(),
            Some("no required literal could be derived".to_string()),
        );
    }
    if literals.len() > MAX_LITERALS_PER_RULE {
        return (
            false,
            transforms,
            Vec::new(),
            Some(format!(
                "literal set of {} exceeds the {} member cap",
                literals.len(),
                MAX_LITERALS_PER_RULE
            )),
        );
    }
    let too_short = literals
        .iter()
        .filter(|l| l.chars().count() < MIN_LITERAL_LEN)
        .count();
    if too_short > 0 {
        return (
            false,
            transforms,
            Vec::new(),
            Some(format!(
                "{too_short} literal(s) shorter than {MIN_LITERAL_LEN} characters"
            )),
        );
    }
    if !transforms_supported(&transforms, &literals) {
        let chain = transforms.join(",");
        return (
            false,
            transforms,
            Vec::new(),
            Some(format!(
                "transform chain [{chain}] is not reproducible by the prefilter"
            )),
        );
    }

    let (has_ci, has_cs) = case_insensitive;
    let mut groups = Vec::new();
    if has_ci {
        groups.push(LiteralGroup {
            transforms: transforms.clone(),
            case_insensitive: true,
            literals: literals.clone(),
        });
    }
    if has_cs || !has_ci {
        groups.push(LiteralGroup {
            transforms: transforms.clone(),
            case_insensitive: false,
            literals: literals.clone(),
        });
    }
    (true, transforms, groups, None)
}

fn canonical_transforms(raw: &[String]) -> Vec<String> {
    raw.iter()
        .map(|t| t.trim().to_ascii_lowercase())
        .filter(|t| !t.is_empty())
        .collect()
}

/// Transform names the Rust runtime can reproduce exactly. `utf8tounicode` is
/// accepted only when every literal is ASCII (it is the identity on ASCII).
fn transforms_supported(transforms: &[String], literals: &[String]) -> bool {
    let ascii_only = literals.iter().all(|l| l.is_ascii());
    transforms.iter().all(|t| match t.as_str() {
        "none" | "lowercase" | "uppercase" | "urldecode" | "urldecodeuni" | "removenulls"
        | "replacenulls" | "compresswhitespace" | "removewhitespace" | "trim" | "trimleft"
        | "trimright" | "normalizepath" | "normalizepathwin" | "normalisepath"
        | "normalisepathwin" | "escapeseqdecode" | "replacecomments" | "jsdecode" | "cssdecode"
        | "cmdline" => true,
        "utf8tounicode" => ascii_only,
        // The runtime decodes numeric references exactly and the ASCII
        // punctuation named entities listed in `prefilter::decode_entity`.
        // No HTML5 named entity expands to an ASCII letter or digit, so a
        // literal made only of those characters cannot be hidden by an
        // undecoded named entity.
        "htmlentitydecode" => literals
            .iter()
            .all(|literal| literal.bytes().all(html_entity_safe_byte)),
        _ => false,
    })
}

/// Bytes whose ASCII value can be produced by a named HTML entity that the
/// runtime decodes (plus alphanumerics, which no named entity produces).
fn html_entity_safe_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'<' | b'>'
                | b'"'
                | b'\''
                | b'&'
                | b';'
                | b':'
                | b'.'
                | b','
                | b'#'
                | b'%'
                | b'+'
                | b'='
                | b'?'
                | b'_'
                | b'|'
                | b'!'
                | b'$'
                | b'@'
                | b'['
                | b']'
                | b'{'
                | b'}'
                | b'('
                | b')'
                | b'/'
                | b'\\'
                | b'*'
                | b'-'
                | b'`'
                | b'^'
        )
}

fn load_data_file(
    name: &str,
    rules_dir: &Path,
    cache: &mut BTreeMap<String, Vec<String>>,
) -> Result<Vec<String>, String> {
    if let Some(cached) = cache.get(name) {
        return Ok(cached.clone());
    }
    let path = rules_dir.join(name);
    let text = fs::read_to_string(&path)
        .map_err(|e| format!("cannot read data file {}: {e}", path.display()))?;
    let mut phrases = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // `@pmFromFile` lowercases every phrase and matches ASCII
        // case-insensitively (Coraza `pm_from_file.go`).
        phrases.push(line.to_lowercase());
    }
    phrases.sort();
    phrases.dedup();
    cache.insert(name.to_string(), phrases.clone());
    Ok(phrases)
}

// ---------------------------------------------------------------------------
// Regex literal extraction
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Literal {
    text: String,
    ci: bool,
}

#[derive(Debug, Clone)]
enum Node {
    Empty,
    /// Literal text plus the case-insensitive flag in effect for that atom.
    Literal(String, bool),
    Class,
    Anchor,
    Concat(Vec<Node>),
    Alt(Vec<Node>),
    Repeat(Box<Node>, u32, Option<u32>),
}

struct RegexParser {
    chars: Vec<char>,
    pos: usize,
    ci: bool,
    extended: bool,
}

/// Extracts a disjunctive literal set from an `@rx` pattern.
///
/// Every value matched by the pattern contains at least one returned literal.
/// Returns `Err` when no useful set can be proven.
fn extract_regex_literals(pattern: &str) -> Result<Vec<Literal>, String> {
    let mut parser = RegexParser {
        chars: pattern.chars().collect(),
        pos: 0,
        ci: false,
        extended: false,
    };
    let node = parser
        .parse_alt()
        .map_err(|e| format!("cannot parse @rx pattern: {e}"))?;
    if parser.pos != parser.chars.len() {
        return Err(format!("unparsed regex suffix at character {}", parser.pos));
    }
    let set =
        required_set(&node).ok_or_else(|| "no required literal in @rx pattern".to_string())?;
    if set.is_empty() {
        return Err("empty required literal set".to_string());
    }
    Ok(set)
}

impl RegexParser {
    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn peek_at(&self, offset: usize) -> Option<char> {
        self.chars.get(self.pos + offset).copied()
    }

    fn bump(&mut self) -> Option<char> {
        let c = self.peek()?;
        self.pos += 1;
        Some(c)
    }

    fn eat(&mut self, expected: char) -> bool {
        if self.peek() == Some(expected) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn skip_extended(&mut self) {
        if !self.extended {
            return;
        }
        loop {
            match self.peek() {
                Some(c) if c.is_whitespace() => {
                    self.pos += 1;
                }
                Some('#') => {
                    while let Some(c) = self.bump() {
                        if c == '\n' {
                            break;
                        }
                    }
                }
                _ => break,
            }
        }
    }

    fn parse_alt(&mut self) -> Result<Node, String> {
        let saved_ci = self.ci;
        let saved_x = self.extended;
        let mut branches = vec![self.parse_seq()?];
        while self.peek() == Some('|') {
            self.pos += 1;
            branches.push(self.parse_seq()?);
        }
        self.ci = saved_ci;
        self.extended = saved_x;
        if branches.len() == 1 {
            Ok(branches.pop().expect("one branch"))
        } else {
            Ok(Node::Alt(branches))
        }
    }

    fn parse_seq(&mut self) -> Result<Node, String> {
        let mut nodes = Vec::new();
        loop {
            self.skip_extended();
            match self.peek() {
                None | Some('|') | Some(')') => break,
                _ => {}
            }
            let atom = self.parse_atom()?;
            let atom = self.parse_quantifier(atom)?;
            nodes.push(atom);
        }
        Ok(match nodes.len() {
            0 => Node::Empty,
            1 => nodes.pop().expect("one node"),
            _ => Node::Concat(nodes),
        })
    }

    fn parse_atom(&mut self) -> Result<Node, String> {
        let c = self.bump().ok_or("unexpected end of pattern")?;
        match c {
            '(' => self.parse_group(),
            '[' => {
                self.parse_class()?;
                Ok(Node::Class)
            }
            '.' => Ok(Node::Class),
            '^' | '$' => Ok(Node::Anchor),
            '\\' => self.parse_escape(),
            '*' | '+' | '?' => Err(format!("quantifier `{c}` without an atom")),
            '{' => {
                // A `{` that is not a quantifier is a literal brace.
                Ok(Node::Literal("{".to_string(), self.ci))
            }
            ')' => Err("unbalanced `)`".to_string()),
            other => Ok(Node::Literal(other.to_string(), self.ci)),
        }
    }

    fn parse_quantifier(&mut self, atom: Node) -> Result<Node, String> {
        let (min, max) = match self.peek() {
            Some('*') => {
                self.pos += 1;
                (0, None)
            }
            Some('+') => {
                self.pos += 1;
                (1, None)
            }
            Some('?') => {
                self.pos += 1;
                (0, Some(1))
            }
            Some('{') => match self.try_braces()? {
                Some(bounds) => bounds,
                None => return Ok(atom),
            },
            _ => return Ok(atom),
        };
        // Lazy/possessive suffix.
        if matches!(self.peek(), Some('?') | Some('+')) {
            self.pos += 1;
        }
        Ok(Node::Repeat(Box::new(atom), min, max))
    }

    fn try_braces(&mut self) -> Result<Option<(u32, Option<u32>)>, String> {
        let start = self.pos;
        self.pos += 1; // {
        let mut first = String::new();
        while let Some(c) = self.peek() {
            if c.is_ascii_digit() {
                first.push(c);
                self.pos += 1;
            } else {
                break;
            }
        }
        if first.is_empty() {
            self.pos = start;
            return Ok(None);
        }
        let min: u32 = first.parse().map_err(|_| "invalid repeat count")?;
        match self.peek() {
            Some('}') => {
                self.pos += 1;
                Ok(Some((min, Some(min))))
            }
            Some(',') => {
                self.pos += 1;
                let mut second = String::new();
                while let Some(c) = self.peek() {
                    if c.is_ascii_digit() {
                        second.push(c);
                        self.pos += 1;
                    } else {
                        break;
                    }
                }
                if self.eat('}') {
                    let max = if second.is_empty() {
                        None
                    } else {
                        Some(second.parse().map_err(|_| "invalid repeat bound")?)
                    };
                    Ok(Some((min, max)))
                } else {
                    self.pos = start;
                    Ok(None)
                }
            }
            _ => {
                self.pos = start;
                Ok(None)
            }
        }
    }

    fn parse_group(&mut self) -> Result<Node, String> {
        let saved_ci = self.ci;
        let saved_x = self.extended;
        if self.eat('?') {
            match self.peek() {
                Some(':') => {
                    self.pos += 1;
                    let node = self.parse_alt()?;
                    self.expect_close()?;
                    self.ci = saved_ci;
                    self.extended = saved_x;
                    Ok(Node::Concat(vec![node]))
                }
                Some('>') => {
                    self.pos += 1;
                    let node = self.parse_alt()?;
                    self.expect_close()?;
                    self.ci = saved_ci;
                    self.extended = saved_x;
                    Ok(node)
                }
                Some('=') | Some('!') => {
                    // Lookahead: zero-width. Parse and discard.
                    self.pos += 1;
                    let _ = self.parse_alt()?;
                    self.expect_close()?;
                    self.ci = saved_ci;
                    self.extended = saved_x;
                    Ok(Node::Empty)
                }
                Some('<') => {
                    self.pos += 1;
                    if matches!(self.peek(), Some('=') | Some('!')) {
                        self.pos += 1;
                        let _ = self.parse_alt()?;
                        self.expect_close()?;
                        self.ci = saved_ci;
                        self.extended = saved_x;
                        return Ok(Node::Empty);
                    }
                    // Named group `(?<name>`.
                    while let Some(c) = self.bump() {
                        if c == '>' {
                            break;
                        }
                    }
                    let node = self.parse_alt()?;
                    self.expect_close()?;
                    self.ci = saved_ci;
                    self.extended = saved_x;
                    Ok(node)
                }
                Some('P') => {
                    self.pos += 1;
                    if self.eat('<') {
                        while let Some(c) = self.bump() {
                            if c == '>' {
                                break;
                            }
                        }
                    }
                    let node = self.parse_alt()?;
                    self.expect_close()?;
                    self.ci = saved_ci;
                    self.extended = saved_x;
                    Ok(node)
                }
                Some('#') => {
                    self.pos += 1;
                    while let Some(c) = self.bump() {
                        if c == ')' {
                            return Ok(Node::Empty);
                        }
                    }
                    Err("unterminated comment group".to_string())
                }
                Some('(') => {
                    // Conditional group: parse conservatively.
                    self.skip_balanced()?;
                    self.ci = saved_ci;
                    self.extended = saved_x;
                    Ok(Node::Empty)
                }
                Some('i') | Some('m') | Some('s') | Some('x') | Some('U') | Some('J')
                | Some('-') => {
                    let mut enable = true;
                    loop {
                        match self.bump() {
                            Some('-') => enable = false,
                            Some('i') => self.ci = enable,
                            Some('x') => self.extended = enable,
                            Some('m') | Some('s') | Some('U') | Some('J') => {}
                            Some(':') => {
                                let node = self.parse_alt()?;
                                self.expect_close()?;
                                self.ci = saved_ci;
                                self.extended = saved_x;
                                return Ok(node);
                            }
                            Some(')') => {
                                // Flag setting applies to the rest of the
                                // enclosing group.
                                return Ok(Node::Empty);
                            }
                            Some(other) => {
                                return Err(format!("unsupported inline flag `{other}`"));
                            }
                            None => return Err("unterminated inline flags".to_string()),
                        }
                    }
                }
                Some(other) => Err(format!("unsupported group prefix `?{other}`")),
                None => Err("unterminated group".to_string()),
            }
        } else {
            let node = self.parse_alt()?;
            self.expect_close()?;
            self.ci = saved_ci;
            self.extended = saved_x;
            Ok(node)
        }
    }

    fn expect_close(&mut self) -> Result<(), String> {
        if self.eat(')') {
            Ok(())
        } else {
            Err("unterminated group".to_string())
        }
    }

    fn skip_balanced(&mut self) -> Result<(), String> {
        let mut depth = 1usize;
        while let Some(c) = self.bump() {
            match c {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        return Ok(());
                    }
                }
                '\\' => {
                    self.bump();
                }
                _ => {}
            }
        }
        Err("unterminated conditional group".to_string())
    }

    fn parse_class(&mut self) -> Result<(), String> {
        let mut first = true;
        while let Some(c) = self.bump() {
            match c {
                ']' if !first => return Ok(()),
                '\\' => {
                    self.bump();
                }
                _ => {}
            }
            first = false;
        }
        Err("unterminated character class".to_string())
    }

    fn parse_escape(&mut self) -> Result<Node, String> {
        let c = self.bump().ok_or("trailing backslash")?;
        match c {
            'b' | 'B' | 'A' | 'z' | 'Z' | 'G' => Ok(Node::Anchor),
            'd' | 'D' | 'w' | 'W' | 's' | 'S' | 'h' | 'H' | 'v' | 'V' | 'R' | 'X' | 'C' | 'K'
            | 'N' => Ok(Node::Class),
            'p' | 'P' => {
                if self.eat('{') {
                    while let Some(c) = self.bump() {
                        if c == '}' {
                            break;
                        }
                    }
                }
                Ok(Node::Class)
            }
            'n' => Ok(Node::Literal("\n".to_string(), self.ci)),
            'r' => Ok(Node::Literal("\r".to_string(), self.ci)),
            't' => Ok(Node::Literal("\t".to_string(), self.ci)),
            'f' => Ok(Node::Literal("\x0c".to_string(), self.ci)),
            'a' => Ok(Node::Literal("\x07".to_string(), self.ci)),
            'e' => Ok(Node::Literal("\x1b".to_string(), self.ci)),
            'x' => self.parse_hex_escape(),
            'u' => {
                // PCRE uses \x{...}; `\u` is not standard but be conservative.
                Ok(Node::Class)
            }
            '0' => {
                let mut value = 0u32;
                let mut digits = 0;
                while digits < 2 {
                    match self.peek() {
                        Some(d) if d.is_digit(8) => {
                            value = value * 8 + d.to_digit(8).unwrap_or(0);
                            self.pos += 1;
                            digits += 1;
                        }
                        _ => break,
                    }
                }
                if value == 0 {
                    Ok(Node::Literal("\0".to_string(), self.ci))
                } else {
                    Ok(Node::Class)
                }
            }
            '1'..='9' => Ok(Node::Class),
            'Q' => {
                let mut text = String::new();
                while let Some(c) = self.bump() {
                    if c == '\\' && self.peek() == Some('E') {
                        self.pos += 1;
                        break;
                    }
                    text.push(c);
                }
                if text.is_empty() {
                    Ok(Node::Empty)
                } else {
                    Ok(Node::Literal(text, self.ci))
                }
            }
            other if other.is_ascii_alphanumeric() => {
                // Unknown alphabetic escape: do not guess a literal.
                Ok(Node::Class)
            }
            other => Ok(Node::Literal(other.to_string(), self.ci)),
        }
    }

    fn parse_hex_escape(&mut self) -> Result<Node, String> {
        if self.eat('{') {
            let mut value = String::new();
            while let Some(c) = self.bump() {
                if c == '}' {
                    break;
                }
                value.push(c);
            }
            let code = u32::from_str_radix(&value, 16)
                .map_err(|_| format!("invalid \\x{{{value}}} escape"))?;
            let ch = char::from_u32(code).ok_or("invalid code point in \\x{} escape")?;
            Ok(Node::Literal(ch.to_string(), self.ci))
        } else {
            let mut value = String::new();
            for _ in 0..2 {
                match self.peek() {
                    Some(c) if c.is_ascii_hexdigit() => {
                        value.push(c);
                        self.pos += 1;
                    }
                    _ => break,
                }
            }
            if value.is_empty() {
                return Err("empty \\x escape".to_string());
            }
            let code = u32::from_str_radix(&value, 16).map_err(|_| "invalid hex escape")?;
            if code > 0x7f {
                // Byte-mode regexes can match a raw non-UTF-8 byte here; a
                // Rust string cannot represent that unambiguously.
                return Ok(Node::Class);
            }
            Ok(Node::Literal((code as u8 as char).to_string(), self.ci))
        }
    }
}

/// Computes a set such that every match of `node` contains at least one
/// member. Returns `None` when no such set can be proven.
fn required_set(node: &Node) -> Option<Vec<Literal>> {
    // A finite expansion is the strongest possible gate: every match is one
    // of the expanded strings, so any of them can be used as an indicator.
    if let Some(expanded) = literal_expansion(node) {
        if !expanded.is_empty()
            && expanded
                .iter()
                .all(|l| !l.text.is_empty() && l.text.chars().count() >= MIN_LITERAL_LEN)
            && expanded.len() <= MAX_LITERALS_PER_RULE
        {
            let mut deduped = expanded;
            deduped.sort();
            deduped.dedup();
            return Some(deduped);
        }
    }

    match node {
        Node::Literal(text, ci) => {
            if text.is_empty() {
                None
            } else {
                Some(vec![Literal {
                    text: text.clone(),
                    ci: *ci,
                }])
            }
        }
        Node::Class | Node::Anchor | Node::Empty => None,
        Node::Repeat(inner, min, _) => {
            if *min >= 1 {
                required_set(inner)
            } else {
                None
            }
        }
        Node::Concat(children) => required_concat(children),
        Node::Alt(branches) => required_alt(branches),
    }
}

/// Enumerates every string a finite node can match. Returns `None` when the
/// node is infinite (unbounded repeats), contains a character class, or the
/// expansion would exceed [`MAX_LITERALS_PER_RULE`].
fn literal_expansion(node: &Node) -> Option<Vec<Literal>> {
    match node {
        Node::Literal(text, ci) => Some(vec![Literal {
            text: text.clone(),
            ci: *ci,
        }]),
        Node::Anchor | Node::Empty => Some(vec![Literal {
            text: String::new(),
            ci: false,
        }]),
        Node::Class => None,
        Node::Repeat(inner, min, max) => {
            let max = (*max)?;
            if max > 8 || max < *min {
                return None;
            }
            let inner = literal_expansion(inner)?;
            if inner.is_empty() {
                return None;
            }
            let mut results = Vec::new();
            for count in *min..=max {
                let mut current = vec![Literal {
                    text: String::new(),
                    ci: false,
                }];
                for _ in 0..count {
                    current = cross_product(&current, &inner)?;
                    if current.len() > MAX_LITERALS_PER_RULE {
                        return None;
                    }
                }
                results.extend(current);
            }
            Some(results)
        }
        Node::Concat(children) => {
            let mut current = vec![Literal {
                text: String::new(),
                ci: false,
            }];
            for child in children {
                let expanded = literal_expansion(child)?;
                current = cross_product(&current, &expanded)?;
                if current.len() > MAX_LITERALS_PER_RULE {
                    return None;
                }
            }
            Some(current)
        }
        Node::Alt(branches) => {
            let mut results = Vec::new();
            for branch in branches {
                results.extend(literal_expansion(branch)?);
                if results.len() > MAX_LITERALS_PER_RULE {
                    return None;
                }
            }
            Some(results)
        }
    }
}

fn cross_product(prefixes: &[Literal], literals: &[Literal]) -> Option<Vec<Literal>> {
    if prefixes.len().saturating_mul(literals.len()) > MAX_LITERALS_PER_RULE {
        return None;
    }
    let mut out = Vec::with_capacity(prefixes.len() * literals.len());
    for prefix in prefixes {
        for literal in literals {
            // Empty strings come from anchors/optional parts and do not carry
            // a case flag. Mixing case-sensitive and case-insensitive text in
            // one literal cannot be represented; mark the rule ungated.
            let ci = if prefix.text.is_empty() {
                literal.ci
            } else if literal.text.is_empty() {
                prefix.ci
            } else if prefix.ci == literal.ci {
                prefix.ci
            } else {
                return None;
            };
            let mut text = String::with_capacity(prefix.text.len() + literal.text.len());
            text.push_str(&prefix.text);
            text.push_str(&literal.text);
            out.push(Literal { text, ci });
        }
    }
    Some(out)
}

fn required_concat(children: &[Node]) -> Option<Vec<Literal>> {
    // Merge adjacent literals so `a` + `bc` becomes `abc`.
    let mut merged: Vec<Node> = Vec::new();
    let push_literal = |merged: &mut Vec<Node>, text: &str, ci: bool| {
        if let Some(Node::Literal(prev, prev_ci)) = merged.last_mut() {
            if *prev_ci == ci {
                prev.push_str(text);
                return;
            }
        }
        merged.push(Node::Literal(text.to_string(), ci));
    };
    for child in children {
        match child {
            Node::Literal(text, ci) => push_literal(&mut merged, text, *ci),
            Node::Concat(inner) => {
                for node in inner {
                    if let Node::Literal(text, ci) = node {
                        push_literal(&mut merged, text, *ci);
                    } else {
                        merged.push(node.clone());
                    }
                }
            }
            other => merged.push(other.clone()),
        }
    }

    let mut best: Option<Vec<Literal>> = None;
    let mut best_score = 0usize;
    for child in &merged {
        if let Some(set) = required_set(child) {
            let score = set
                .iter()
                .map(|l| l.text.chars().count())
                .min()
                .unwrap_or(0);
            if score > best_score || best.is_none() {
                best_score = score;
                best = Some(set);
            }
        }
    }
    best
}

fn required_alt(branches: &[Node]) -> Option<Vec<Literal>> {
    let mut union: Vec<Literal> = Vec::new();
    for branch in branches {
        let set = required_set(branch)?;
        union.extend(set);
    }
    union.sort();
    union.dedup();

    // A branch whose only required literal is shorter than the minimum makes
    // the whole alternation ungated: a match could use just that branch.
    if union
        .iter()
        .any(|l| l.text.chars().count() < MIN_LITERAL_LEN)
    {
        return None;
    }

    if union.len() <= MAX_LITERALS_PER_RULE {
        return Some(union);
    }

    // Too many members: fall back to a literal common to every candidate.
    let texts: Vec<&str> = union.iter().map(|l| l.text.as_str()).collect();
    if let Some(common) = longest_common_substring(&texts, MIN_LITERAL_LEN) {
        let ci = union.iter().all(|l| l.ci);
        return Some(vec![Literal { text: common, ci }]);
    }
    None
}

fn longest_common_substring(strings: &[&str], min_len: usize) -> Option<String> {
    if strings.is_empty() {
        return None;
    }
    let shortest = strings.iter().min_by_key(|s| s.chars().count())?;
    let chars: Vec<char> = shortest.chars().collect();
    let max_len = chars.len();
    if max_len < min_len {
        return None;
    }
    for len in (min_len..=max_len).rev() {
        for start in 0..=max_len - len {
            let candidate: String = chars[start..start + len].iter().collect();
            if strings.iter().all(|s| s.contains(&candidate)) {
                return Some(candidate);
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Human-readable summary
// ---------------------------------------------------------------------------

/// Renders the deterministic Markdown summary committed next to the artifact.
pub fn render_summary(artifact: &PrefilterArtifact) -> String {
    let cov = &artifact.coverage;
    let mut out = String::new();
    out.push_str("# CRS literal-prefilter coverage\n\n");
    out.push_str("Generated by `crs-prefilter-extract`. Do not edit by hand.\n\n");
    out.push_str(&format!(
        "- CRS bundle: `{}` ({}), schema v{}\n",
        artifact.source, artifact.crs_version, artifact.schema_version
    ));
    out.push_str(&format!(
        "- Paranoia level: {} (higher-level rules are excluded)\n",
        artifact.paranoia_level
    ));
    out.push_str(&format!(
        "- Minimum literal length: {} characters\n",
        artifact.min_literal_len
    ));
    out.push_str(&format!(
        "- Body-relevant entries: {} gated, {} ungated (of {} total)\n",
        cov.body_relevant_gated, cov.body_relevant_ungated, cov.body_relevant_entries
    ));
    out.push_str(&format!(
        "- Fast path available for the whole rule set: **{}**\n",
        if cov.all_body_rules_gated {
            "yes"
        } else {
            "no"
        }
    ));
    out.push_str(&format!(
        "- Distinct gated literals: {} ({} members)\n\n",
        cov.distinct_literals, cov.total_literals
    ));

    out.push_str("## Ungated body-relevant entries by family\n\n");
    out.push_str("| family | entries |\n|---|---:|\n");
    for (family, count) in &cov.ungated_by_family {
        out.push_str(&format!("| {family} | {count} |\n"));
    }
    out.push_str("\n## Ungated body-relevant entries by operator\n\n");
    out.push_str("| operator | entries |\n|---|---:|\n");
    for (operator, count) in &cov.ungated_by_operator {
        out.push_str(&format!("| @{operator} | {count} |\n"));
    }

    out.push_str("\n## Ungated body-relevant rules\n\n");
    out.push_str("| id | family | operator | reason |\n|---:|---|---|---|\n");
    for rule in artifact.ungated_rules.iter().filter(|r| r.body_relevant) {
        out.push_str(&format!(
            "| {} | {} | @{} | {} |\n",
            rule.id, rule.family, rule.operator, rule.reason
        ));
    }

    out.push_str("\n## Gated rules by family\n\n");
    out.push_str("| family | gated entries | literals |\n|---|---:|---:|\n");
    let mut by_family: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    for gate in &artifact.rules {
        if !gate.gated {
            continue;
        }
        let entry = by_family.entry(gate.family.clone()).or_default();
        entry.0 += 1;
        entry.1 += gate.literals.len();
    }
    for (family, (entries, literals)) in by_family {
        out.push_str(&format!("| {family} | {entries} | {literals} |\n"));
    }

    out.push_str("\n## Soundness contract\n\n");
    out.push_str(
        "For every gated entry, a match requires at least one listed literal in \
         the transformed value. The prefilter scans the raw body plus the \
         extraction variants (URL-decode, JSON-unescape, HTML-entity-decode) \
         and every supported transform pipeline. A miss therefore proves the \
         rule cannot match a body-derived value. Any entry listed as ungated \
         forces full CRS evaluation.\n",
    );
    out
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn read(path: &Path) -> Result<String, ExtractError> {
    fs::read_to_string(path).map_err(|source| ExtractError::Io {
        path: path.display().to_string(),
        source,
    })
}

fn display_path(path: &Path) -> String {
    path.display().to_string()
}

/// Convenience: default artifact path used by the CLI and the runtime.
pub fn default_artifact_path() -> PathBuf {
    PathBuf::from("rules/crs/prefilter.json")
}

/// Convenience: default summary path used by the CLI.
pub fn default_summary_path() -> PathBuf {
    PathBuf::from("rules/crs/PREFILTER_SUMMARY.md")
}

/// Copy of the artifact embedded by the Go reactor and read by the native
/// sidecar. It is written by the extractor so the guest's gated-rule set can
/// never skew from the host's.
pub fn default_reactor_artifact_path() -> PathBuf {
    PathBuf::from("wasm/coraza_reactor/rules/crs/prefilter.json")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(pattern: &str) -> Vec<String> {
        let mut literals: Vec<String> = extract_regex_literals(pattern)
            .expect("pattern should gate")
            .into_iter()
            .map(|l| l.text)
            .collect();
        literals.sort();
        literals
    }

    #[test]
    fn literal_run_is_extracted() {
        assert_eq!(set(r"foo\.bar"), vec!["foo.bar"]);
        // The word boundary is zero-width, so the finite expansion is the
        // whole concatenation.
        assert_eq!(set(r"foo\bbar"), vec!["foobar"]);
    }

    #[test]
    fn alternation_is_disjunctive() {
        assert_eq!(
            set(r"(?:wget|curl|ncat)"),
            vec!["curl".to_string(), "ncat".to_string(), "wget".to_string()]
        );
    }

    #[test]
    fn alternation_keeps_every_branch() {
        // `select`/`selection` share the full `select` prefix, and the union
        // is small enough that both members are kept.
        assert_eq!(
            set(r"(?:select|selection)"),
            vec!["select".to_string(), "selection".to_string()]
        );
    }

    #[test]
    fn alternation_with_short_branch_is_ungated() {
        // A match could use the two-character branch, so no literal from the
        // other branch is required.
        assert!(extract_regex_literals(r"(?:select|se)").is_err());
    }

    #[test]
    fn optional_literal_is_not_required() {
        // `foo` is optional; the finite expansion keeps both complete forms,
        // and every one of them contains a usable literal.
        assert_eq!(set(r"(?:foo)?bar"), vec!["bar", "foobar"]);
    }

    #[test]
    fn star_branch_cannot_gate() {
        assert!(extract_regex_literals(r"(?:foo)*bar").is_ok());
        assert!(extract_regex_literals(r"(?:foo|bar)*").is_err());
    }

    #[test]
    fn lookahead_is_ignored_not_trusted() {
        // The lookahead must not be treated as a required literal.
        let literals = set(r"(?=foo)bar");
        assert_eq!(literals, vec!["bar"]);
    }

    #[test]
    fn negated_operator_is_ungated() {
        let raw = parse_rule(r#"SecRule ARGS "!@rx foo" "id:1,phase:2,block""#, 1, "test")
            .expect("rule parses");
        let (gated, _, _, reason) = gate_member(&raw, Path::new("."), &mut BTreeMap::new());
        assert!(!gated);
        assert!(reason.unwrap().contains("negated"));
    }

    #[test]
    fn escaped_quote_is_literal() {
        assert_eq!(set(r#"say \"hi\""#), vec![r#"say "hi""#]);
    }

    #[test]
    fn case_insensitive_flag_is_recorded() {
        let literals = extract_regex_literals(r"(?i)union\s+select").expect("gates");
        // A concatenation keeps the most selective child; `select` is longer.
        assert!(literals.iter().any(|l| l.text == "select"));
        assert!(literals.iter().all(|l| l.ci));
    }

    #[test]
    fn hex_escape_above_ascii_is_conservative() {
        // \xff is a raw byte in PCRE byte mode; do not pretend it is UTF-8.
        assert!(extract_regex_literals(r"\xffabc").is_ok());
        assert!(extract_regex_literals(r"\xffabc")
            .unwrap()
            .iter()
            .any(|l| l.text == "abc"));
    }

    #[test]
    fn parse_chains_groups_members() {
        let text = r#"
SecRule ARGS "@rx foo" "id:1,phase:2,block,chain"
    SecRule ARGS "@rx bar" "chain"
        SecRule ARGS "@rx baz" "t:none"
"#;
        let chains = parse_chains(text, "test").expect("parses");
        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0].members.len(), 3);
    }

    #[test]
    fn body_target_detection() {
        assert!(target_is_body(&parse_targets("ARGS")[0]));
        assert!(target_is_body(&parse_targets("REQUEST_COOKIES|ARGS")[1]));
        assert!(!target_is_body(
            &parse_targets("REQUEST_HEADERS:User-Agent")[0]
        ));
        assert!(target_is_body(&parse_targets("&ARGS")[0]));
        assert!(!target_is_body(&parse_targets("ARGS_GET")[0]));
    }

    #[test]
    fn summary_is_deterministic() {
        let text = r#"
SecRule ARGS "@pmFromFile unix-shell.data" "id:932250,phase:2,block,t:none"
"#;
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("wasm/coraza_reactor/rules/crs/rules");
        let a = extract_from_str(text, &dir, "test", 1).expect("extract");
        let b = extract_from_str(text, &dir, "test", 1).expect("extract");
        assert_eq!(render_summary(&a), render_summary(&b));
        assert_eq!(a, b);
    }
}
