//! Rule accounting for the pinned OWASP CRS request rules.
//!
//! The native engine must not silently drop a rule it cannot execute. This
//! module parses the pinned rule bundle into a deterministic manifest of every
//! directive, rule id, target, operator, transform, action and structural
//! construct. [`verify_complete`] then checks an engine's declared support
//! against that manifest and returns *all* gaps at once.
//!
//! The engine workstream calls:
//!
//! ```ignore
//! let manifest = engine::accounting::Manifest::from_path(
//!     engine::accounting::DEFAULT_RULES_PATH,
//! )?;
//! let support = engine::accounting::EngineSupport { /* declared sets */ .. };
//! engine::accounting::verify_complete(&manifest, &support)?;
//! ```
//!
//! The binary `rule_accounting` emits and checks the committed manifest:
//!
//! ```text
//! cargo run --bin rule_accounting -- --check
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Manifest format version. Bumped whenever the JSON contract changes.
pub const MANIFEST_FORMAT_VERSION: u32 = 1;

/// Pinned rule bundle shipped in the repository.
pub const DEFAULT_RULES_PATH: &str = "wasm/coraza_reactor/rules/crs/crs.conf";

/// Committed manifest consumed by the native engine build.
pub const DEFAULT_MANIFEST_PATH: &str = "rules/crs/rule-manifest.json";

/// CRS release reported by the pinned bundle.
pub const CRS_VERSION: &str = "4.14.0";

/// Directives that introduce or modify rules and therefore must be accounted
/// for. `SecDefaultAction` is included because its actions apply to every rule
/// that does not override them.
const RULE_DIRECTIVES: &[&str] = &["secrule", "secaction", "secmarker", "secdefaultaction"];

/// Rule-mutating directives the parser does not model. Their presence in the
/// pinned bundle is a hard failure rather than a silent omission.
const UNMODELLED_RULE_DIRECTIVES: &[&str] = &[
    "secruleupdateactionbyid",
    "secruleupdatetargetbyid",
    "secruleremovebyid",
    "secruleremovetargetbyid",
    "secruleremovebytag",
    "secrulescript",
    "secruleupdatebyid",
];

/// Non-rule ModSecurity directives that may appear in the bundle without
/// affecting rule accounting.
const CONFIG_DIRECTIVES: &[&str] = &[
    "secaction",
    "secauditengine",
    "secauditlog",
    "secauditlogparts",
    "secauditlogstoragedir",
    "secauditlogtype",
    "secargumentseparator",
    "seccollectiontimeout",
    "seccomponentsignature",
    "secconnengine",
    "secconnreadstatelimit",
    "secconnwritestatelimit",
    "seccontentinjection",
    "seccookieformat",
    "secdatadir",
    "secdebuglog",
    "secdebugloglevel",
    "secdefaultaction",
    "secinterceptonerror",
    "secmarker",
    "secpcrematchlimit",
    "secpcrematchlimitrecursion",
    "secrequestbodyaccess",
    "secrequestbodyinmemorylimit",
    "secrequestbodylimit",
    "secresponsebodyaccess",
    "secresponsebodylimit",
    "secresponsebodylimitaction",
    "secresponsebodymimetype",
    "secrule",
    "secruleengine",
    "secsensorid",
    "secstatusengine",
    "secstreaminbodyinspection",
    "secstreamoutbodyinspection",
    "sectmpdir",
    "secunicodemapfile",
];

/// One operator occurrence in a rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorSpec {
    /// Operator name without the leading `@` (`rx`, `pmFromFile`, ...).
    pub name: String,
    /// True when the operator was negated (`!@rx`).
    #[serde(default)]
    pub negated: bool,
    /// Operator argument exactly as written in the rule bundle.
    #[serde(default)]
    pub argument: String,
}

/// One directive occurrence in the rule bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleEntry {
    /// Directive name, lowercased (`secrule`, `secaction`, `secmarker`, ...).
    pub directive: String,
    /// CRS rule id, when the directive carries one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<u32>,
    /// One-based line in the parsed source.
    pub line: usize,
    /// Execution phase from the `phase` action, when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase: Option<u32>,
    /// True when this entry is the first member of a chained rule.
    pub chain: bool,
    /// Position inside a chain; `0` for a standalone rule.
    pub chain_member: usize,
    /// Rule id of the first member of the chain, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<u32>,
    /// Raw targets in evaluation order.
    pub targets: Vec<String>,
    /// Operator, when the directive has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator: Option<OperatorSpec>,
    /// Transform chain in application order (`t:none` clears it).
    pub transforms: Vec<String>,
    /// Distinct action names, lowercased and sorted.
    pub actions: Vec<String>,
    /// Structural features the engine must implement for this entry.
    pub constructs: Vec<String>,
}

/// Aggregate coverage counters for a manifest.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Coverage {
    /// Number of manifest entries.
    pub entries: usize,
    /// Number of distinct rule ids.
    pub rule_ids: usize,
    /// Number of chained rules (first member of each chain).
    pub chains: usize,
    /// Number of chained members after the first member.
    pub chain_members: usize,
    /// Entries grouped by directive.
    pub directives: BTreeMap<String, usize>,
    /// Entries grouped by operator name.
    pub operators: BTreeMap<String, usize>,
    /// Transform occurrences grouped by lowercased name.
    pub transforms: BTreeMap<String, usize>,
    /// Action occurrences grouped by lowercased name.
    pub actions: BTreeMap<String, usize>,
    /// Entries grouped by structural construct.
    pub constructs: BTreeMap<String, usize>,
    /// Sorted distinct rule ids.
    pub rule_id_list: Vec<u32>,
    /// Rule ids that appear more than once, if any.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub duplicate_rule_ids: Vec<u32>,
}

/// Deterministic manifest of the pinned rule bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// Manifest format version.
    pub format_version: u32,
    /// CRS release the bundle reports.
    pub crs_version: String,
    /// Repository-relative path of the parsed bundle.
    pub source: String,
    /// SHA-256 of the parsed bundle bytes.
    pub source_sha256: String,
    /// Every rule-bearing directive, in source order.
    pub entries: Vec<RuleEntry>,
    /// Aggregate coverage.
    pub coverage: Coverage,
}

/// What an engine declares it can execute.
///
/// Engine workstreams should start from [`EngineSupport::from_manifest`], then
/// remove anything they do not implement. Actions listed in `ignored_actions`
/// are accepted as metadata that may be dropped safely (for example `tag`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineSupport {
    /// Rule ids compiled into the engine.
    #[serde(default)]
    pub rule_ids: BTreeSet<u32>,
    /// Directives handled by the engine.
    #[serde(default)]
    pub directives: BTreeSet<String>,
    /// Operator names implemented by the engine.
    #[serde(default)]
    pub operators: BTreeSet<String>,
    /// Transform names implemented by the engine.
    #[serde(default)]
    pub transforms: BTreeSet<String>,
    /// Action names implemented by the engine.
    #[serde(default)]
    pub actions: BTreeSet<String>,
    /// Actions the engine may safely ignore.
    #[serde(default)]
    pub ignored_actions: BTreeSet<String>,
    /// Structural constructs implemented by the engine.
    #[serde(default)]
    pub constructs: BTreeSet<String>,
}

impl EngineSupport {
    /// Declares support for every item in the manifest.
    ///
    /// This is a template for the engine workstream; it deliberately makes the
    /// engine's claim explicit instead of treating an absent field as support.
    pub fn from_manifest(manifest: &Manifest) -> Self {
        let mut support = Self::default();
        for entry in &manifest.entries {
            if let Some(id) = entry.id {
                support.rule_ids.insert(id);
            }
            support.directives.insert(entry.directive.clone());
            if let Some(operator) = &entry.operator {
                support.operators.insert(operator.name.to_ascii_lowercase());
            }
            for transform in &entry.transforms {
                support.transforms.insert(transform.to_ascii_lowercase());
            }
            for action in &entry.actions {
                support.actions.insert(action.clone());
            }
            for construct in &entry.constructs {
                support.constructs.insert(construct.clone());
            }
        }
        support
    }

    /// Normalises case so declarations compare case-insensitively.
    pub fn normalize(&mut self) {
        self.directives = lower(&self.directives);
        self.operators = lower(&self.operators);
        self.transforms = lower(&self.transforms);
        self.actions = lower(&self.actions);
        self.ignored_actions = lower(&self.ignored_actions);
        self.constructs = lower(&self.constructs);
    }

    fn supports_action(&self, action: &str) -> bool {
        let action = action.to_ascii_lowercase();
        self.actions.contains(&action) || self.ignored_actions.contains(&action)
    }
}

fn lower(set: &BTreeSet<String>) -> BTreeSet<String> {
    set.iter().map(|value| value.to_ascii_lowercase()).collect()
}

/// All gaps between a manifest and an engine's declared support.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GapReport {
    /// Rule ids the engine did not declare. `0` represents anonymous
    /// directives (for example a `SecAction` without an id).
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub missing_rule_ids: BTreeSet<u32>,
    /// Directive -> rule ids that are not handled.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub unsupported_directives: BTreeMap<String, BTreeSet<u32>>,
    /// Operator -> rule ids that are not implemented.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub unsupported_operators: BTreeMap<String, BTreeSet<u32>>,
    /// Transform -> rule ids that are not implemented.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub unsupported_transforms: BTreeMap<String, BTreeSet<u32>>,
    /// Action -> rule ids that are not implemented.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub unsupported_actions: BTreeMap<String, BTreeSet<u32>>,
    /// Construct -> rule ids that are not implemented.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub unsupported_constructs: BTreeMap<String, BTreeSet<u32>>,
}

impl GapReport {
    /// True when the engine accounts for every manifest entry.
    pub fn is_empty(&self) -> bool {
        self.missing_rule_ids.is_empty()
            && self.unsupported_directives.is_empty()
            && self.unsupported_operators.is_empty()
            && self.unsupported_transforms.is_empty()
            && self.unsupported_actions.is_empty()
            && self.unsupported_constructs.is_empty()
    }

    /// Total number of distinct gaps.
    pub fn total(&self) -> usize {
        self.missing_rule_ids.len()
            + self.unsupported_directives.len()
            + self.unsupported_operators.len()
            + self.unsupported_transforms.len()
            + self.unsupported_actions.len()
            + self.unsupported_constructs.len()
    }

    fn record(map: &mut BTreeMap<String, BTreeSet<u32>>, name: &str, rule_id: u32) {
        map.entry(name.to_string()).or_default().insert(rule_id);
    }
}

/// Successful verification result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Verification {
    /// Entries checked.
    pub entries: usize,
    /// Rule ids checked.
    pub rule_ids: usize,
    /// Operators checked.
    pub operators: usize,
    /// Transforms checked.
    pub transforms: usize,
    /// Actions checked.
    pub actions: usize,
    /// Constructs checked.
    pub constructs: usize,
}

/// Rule accounting failures.
#[derive(Debug, thiserror::Error)]
pub enum AccountingError {
    /// The bundle or manifest could not be read.
    #[error("failed to read {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    /// The manifest is not valid JSON.
    #[error("failed to parse manifest JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// The manifest format is newer or older than this binary supports.
    #[error("unsupported manifest format version {found}; this binary supports {supported}")]
    UnsupportedFormat { found: u32, supported: u32 },
    /// A rule line could not be parsed.
    #[error("invalid rule at {path}:{line}: {detail}")]
    Parse {
        path: String,
        line: usize,
        detail: String,
    },
    /// Two rules share an id.
    #[error("duplicate rule id {id} at {path}:{line} (first at line {first_line})")]
    DuplicateRuleId {
        id: u32,
        path: String,
        line: usize,
        first_line: usize,
    },
    /// A rule-mutating directive is not modelled by the parser.
    #[error("unsupported rule directive `{directive}` at {path}:{line}")]
    UnsupportedDirective {
        directive: String,
        path: String,
        line: usize,
    },
    /// A manifest is structurally inconsistent.
    #[error("malformed rule manifest: {0}")]
    MalformedManifest(String),
    /// The engine does not account for every manifest entry.
    #[error("engine accounting incomplete: {} gap(s); first gap: {:?}", .gaps.total(), .gaps.first())]
    Incomplete { gaps: Box<GapReport> },
}

impl GapReport {
    fn first(&self) -> Option<String> {
        if let Some(id) = self.missing_rule_ids.iter().next() {
            return Some(format!("missing rule id {id}"));
        }
        if let Some((name, ids)) = self.unsupported_directives.iter().next() {
            return Some(format!("unsupported directive `{name}` for {ids:?}"));
        }
        if let Some((name, ids)) = self.unsupported_operators.iter().next() {
            return Some(format!("unsupported operator `{name}` for {ids:?}"));
        }
        if let Some((name, ids)) = self.unsupported_transforms.iter().next() {
            return Some(format!("unsupported transform `{name}` for {ids:?}"));
        }
        if let Some((name, ids)) = self.unsupported_actions.iter().next() {
            return Some(format!("unsupported action `{name}` for {ids:?}"));
        }
        self.unsupported_constructs
            .iter()
            .next()
            .map(|(name, ids)| format!("unsupported construct `{name}` for {ids:?}"))
    }
}

impl Manifest {
    /// Parses a rule bundle from disk.
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, AccountingError> {
        let path = path.as_ref();
        let bytes = fs::read(path).map_err(|err| AccountingError::Io {
            path: path.display().to_string(),
            source: err,
        })?;
        let text = String::from_utf8(bytes).map_err(|err| AccountingError::Parse {
            path: path.display().to_string(),
            line: 0,
            detail: format!("bundle is not valid UTF-8: {err}"),
        })?;
        Self::from_str(&text, &display_path(path))
    }

    /// Parses a rule bundle from text. `source` is recorded in the manifest.
    pub fn from_str(text: &str, source: &str) -> Result<Self, AccountingError> {
        let mut chains: Vec<Vec<ParsedEntry>> = Vec::new();

        for (line, logical) in logical_lines(text) {
            let directive = first_word(&logical).to_ascii_lowercase();
            if directive.is_empty() {
                continue;
            }
            if UNMODELLED_RULE_DIRECTIVES.contains(&directive.as_str()) {
                return Err(AccountingError::UnsupportedDirective {
                    directive,
                    path: source.to_string(),
                    line,
                });
            }
            if !RULE_DIRECTIVES.contains(&directive.as_str()) {
                if directive.starts_with("sec") && !CONFIG_DIRECTIVES.contains(&directive.as_str())
                {
                    return Err(AccountingError::UnsupportedDirective {
                        directive,
                        path: source.to_string(),
                        line,
                    });
                }
                continue;
            }

            let entry = parse_entry(&logical, line, source)?;
            let attach = chains
                .last()
                .and_then(|chain| chain.last())
                .is_some_and(|member| member.chain);
            if attach {
                chains.last_mut().expect("checked above").push(entry);
            } else {
                chains.push(vec![entry]);
            }
        }

        if chains.is_empty() {
            return Err(AccountingError::MalformedManifest(format!(
                "no SecRule entries found in {source}"
            )));
        }

        let mut entries = Vec::new();
        for chain in chains {
            let chain_id = chain.iter().find_map(|entry| entry.id);
            let chained = chain.len() > 1;
            for (index, parsed) in chain.into_iter().enumerate() {
                let mut constructs = parsed.constructs;
                if chained {
                    constructs.insert("chain".to_string());
                }
                if index > 0 {
                    constructs.insert("chain-member".to_string());
                }
                entries.push(RuleEntry {
                    directive: parsed.directive,
                    id: parsed.id,
                    line: parsed.line,
                    phase: parsed.phase,
                    chain: chained && index == 0,
                    chain_member: index,
                    chain_id: if chained { chain_id } else { parsed.id },
                    targets: parsed.targets,
                    operator: parsed.operator,
                    transforms: parsed.transforms,
                    actions: parsed.actions,
                    constructs: constructs.into_iter().collect(),
                });
            }
        }

        let mut seen: BTreeMap<u32, usize> = BTreeMap::new();
        for entry in &entries {
            if let Some(id) = entry.id {
                if let Some(first_line) = seen.insert(id, entry.line) {
                    return Err(AccountingError::DuplicateRuleId {
                        id,
                        path: source.to_string(),
                        line: entry.line,
                        first_line,
                    });
                }
            }
        }

        let coverage = summarise(&entries);
        let manifest = Self {
            format_version: MANIFEST_FORMAT_VERSION,
            crs_version: CRS_VERSION.to_string(),
            source: source.to_string(),
            source_sha256: sha256_hex(text.as_bytes()),
            entries,
            coverage,
        };
        manifest.validate()?;
        Ok(manifest)
    }

    /// Loads and validates a committed manifest.
    pub fn from_json_str(text: &str) -> Result<Self, AccountingError> {
        let manifest: Self = serde_json::from_str(text)?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// Loads a committed manifest from disk.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, AccountingError> {
        let path = path.as_ref();
        let text = fs::read_to_string(path).map_err(|err| AccountingError::Io {
            path: path.display().to_string(),
            source: err,
        })?;
        Self::from_json_str(&text)
    }

    /// Validates format version, coverage consistency and rule-id uniqueness.
    pub fn validate(&self) -> Result<(), AccountingError> {
        if self.format_version != MANIFEST_FORMAT_VERSION {
            return Err(AccountingError::UnsupportedFormat {
                found: self.format_version,
                supported: MANIFEST_FORMAT_VERSION,
            });
        }
        if self.source_sha256.len() != 64
            || !self.source_sha256.chars().all(|c| c.is_ascii_hexdigit())
        {
            return Err(AccountingError::MalformedManifest(
                "source_sha256 must be a 64-character hex digest".to_string(),
            ));
        }
        if self.entries.is_empty() {
            return Err(AccountingError::MalformedManifest(
                "manifest has no entries".to_string(),
            ));
        }
        if self.coverage.entries != self.entries.len() {
            return Err(AccountingError::MalformedManifest(format!(
                "coverage.entries is {}, but the manifest has {} entries",
                self.coverage.entries,
                self.entries.len()
            )));
        }
        let mut ids = BTreeSet::new();
        for entry in &self.entries {
            if let Some(id) = entry.id {
                if !ids.insert(id) {
                    return Err(AccountingError::MalformedManifest(format!(
                        "duplicate rule id {id} in manifest"
                    )));
                }
            }
        }
        if !self.coverage.duplicate_rule_ids.is_empty() {
            return Err(AccountingError::MalformedManifest(format!(
                "manifest records duplicate rule ids {:?}",
                self.coverage.duplicate_rule_ids
            )));
        }
        let expected: Vec<u32> = ids.into_iter().collect();
        if self.coverage.rule_id_list != expected {
            return Err(AccountingError::MalformedManifest(
                "coverage.rule_id_list does not match the manifest entries".to_string(),
            ));
        }
        Ok(())
    }

    /// Serialises the manifest with stable field and map ordering.
    pub fn to_json_pretty(&self) -> Result<String, AccountingError> {
        let mut text = serde_json::to_string_pretty(self)?;
        text.push('\n');
        Ok(text)
    }

    /// Writes the manifest, creating parent directories.
    pub fn write(&self, path: impl AsRef<Path>) -> Result<(), AccountingError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|err| AccountingError::Io {
                    path: parent.display().to_string(),
                    source: err,
                })?;
            }
        }
        fs::write(path, self.to_json_pretty()?).map_err(|err| AccountingError::Io {
            path: path.display().to_string(),
            source: err,
        })
    }
}

/// Checks that `support` accounts for every entry in `manifest`.
///
/// Returns every gap at once. This is the interface the native engine build
/// calls before it can claim the pinned rule set is supported.
pub fn verify_complete(
    manifest: &Manifest,
    support: &EngineSupport,
) -> Result<Verification, AccountingError> {
    manifest.validate()?;
    let mut support = support.clone();
    support.normalize();
    let mut gaps = GapReport::default();

    for entry in &manifest.entries {
        let rule_id = entry.id.unwrap_or(0);
        if let Some(id) = entry.id {
            if !support.rule_ids.contains(&id) {
                gaps.missing_rule_ids.insert(id);
            }
        }
        if !support.directives.contains(&entry.directive) {
            GapReport::record(&mut gaps.unsupported_directives, &entry.directive, rule_id);
        }
        if let Some(operator) = &entry.operator {
            let name = operator.name.to_ascii_lowercase();
            if !support.operators.contains(&name) {
                GapReport::record(&mut gaps.unsupported_operators, &name, rule_id);
            }
        }
        for transform in &entry.transforms {
            let name = transform.to_ascii_lowercase();
            if !support.transforms.contains(&name) {
                GapReport::record(&mut gaps.unsupported_transforms, &name, rule_id);
            }
        }
        for action in &entry.actions {
            if !support.supports_action(action) {
                GapReport::record(&mut gaps.unsupported_actions, action, rule_id);
            }
        }
        for construct in &entry.constructs {
            if !support.constructs.contains(construct) {
                GapReport::record(&mut gaps.unsupported_constructs, construct, rule_id);
            }
        }
    }

    if !gaps.is_empty() {
        return Err(AccountingError::Incomplete {
            gaps: Box::new(gaps),
        });
    }

    Ok(Verification {
        entries: manifest.entries.len(),
        rule_ids: manifest.coverage.rule_ids,
        operators: manifest.coverage.operators.len(),
        transforms: manifest.coverage.transforms.len(),
        actions: manifest.coverage.actions.len(),
        constructs: manifest.coverage.constructs.len(),
    })
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct ParsedEntry {
    directive: String,
    id: Option<u32>,
    line: usize,
    phase: Option<u32>,
    targets: Vec<String>,
    operator: Option<OperatorSpec>,
    transforms: Vec<String>,
    actions: Vec<String>,
    constructs: BTreeSet<String>,
    chain: bool,
}

fn parse_entry(text: &str, line: usize, source: &str) -> Result<ParsedEntry, AccountingError> {
    let (directive, rest) = split_first_word(text);
    let directive = directive.to_ascii_lowercase();
    match directive.as_str() {
        "secrule" => parse_secrule(rest, line, source),
        "secaction" | "secdefaultaction" => parse_secaction(&directive, rest, line, source),
        "secmarker" => Ok(parse_secmarker(rest, line)),
        _ => Err(AccountingError::UnsupportedDirective {
            directive,
            path: source.to_string(),
            line,
        }),
    }
}

fn parse_secrule(text: &str, line: usize, source: &str) -> Result<ParsedEntry, AccountingError> {
    let (target_text, rest) =
        split_first_token(text).ok_or_else(|| parse_error(source, line, "missing target"))?;
    let (operator_text, rest) = take_quoted(rest.trim_start())
        .ok_or_else(|| parse_error(source, line, "operator must be double-quoted"))?;
    let actions_text = if rest.trim().is_empty() {
        String::new()
    } else {
        take_quoted(rest.trim_start())
            .map(|(actions, _)| actions)
            .ok_or_else(|| parse_error(source, line, "actions must be double-quoted"))?
    };

    let targets = parse_targets(target_text);
    let operator = parse_operator(&operator_text, line, source)?;
    let parsed = parse_actions(&actions_text, line, source)?;

    let mut constructs = parsed.constructs;
    for target in &targets {
        if target.starts_with('&') {
            constructs.insert("target-count".to_string());
        }
        if target.starts_with('!') {
            constructs.insert("target-negation".to_string());
        }
        if has_regex_key(target) {
            constructs.insert("target-regex".to_string());
        }
        if target.contains(':') {
            constructs.insert("target-collection".to_string());
        } else {
            constructs.insert("target-variable".to_string());
        }
    }

    Ok(ParsedEntry {
        directive: "secrule".to_string(),
        id: parsed.id,
        line,
        phase: parsed.phase,
        targets,
        operator: Some(operator),
        transforms: parsed.transforms,
        actions: parsed.actions,
        constructs,
        chain: parsed.chain,
    })
}

fn parse_secaction(
    directive: &str,
    text: &str,
    line: usize,
    source: &str,
) -> Result<ParsedEntry, AccountingError> {
    let (actions_text, _) = take_quoted(text.trim_start())
        .ok_or_else(|| parse_error(source, line, "actions must be double-quoted"))?;
    let parsed = parse_actions(&actions_text, line, source)?;
    Ok(ParsedEntry {
        directive: directive.to_string(),
        id: parsed.id,
        line,
        phase: parsed.phase,
        targets: Vec::new(),
        operator: None,
        transforms: parsed.transforms,
        actions: parsed.actions,
        constructs: parsed.constructs,
        chain: parsed.chain,
    })
}

fn parse_secmarker(text: &str, line: usize) -> ParsedEntry {
    let marker = text.trim().trim_matches('"').to_string();
    let mut constructs = BTreeSet::new();
    constructs.insert("secmarker".to_string());
    if !marker.is_empty() {
        constructs.insert("marker".to_string());
    }
    ParsedEntry {
        directive: "secmarker".to_string(),
        id: None,
        line,
        phase: None,
        targets: Vec::new(),
        operator: None,
        transforms: Vec::new(),
        actions: Vec::new(),
        constructs,
        chain: false,
    }
}

struct ParsedActions {
    id: Option<u32>,
    phase: Option<u32>,
    transforms: Vec<String>,
    actions: Vec<String>,
    constructs: BTreeSet<String>,
    chain: bool,
}

fn parse_actions(text: &str, line: usize, source: &str) -> Result<ParsedActions, AccountingError> {
    let mut id = None;
    let mut phase = None;
    let mut transforms = Vec::new();
    let mut actions = BTreeSet::new();
    let mut constructs = BTreeSet::new();
    let mut chain = false;
    let mut has_macro = false;

    for action in split_actions(text) {
        let action = action.trim();
        if action.is_empty() {
            continue;
        }
        let (name, value) = match action.split_once(':') {
            Some((name, value)) => (name.trim(), value.trim()),
            None => (action, ""),
        };
        let name_lower = name.to_ascii_lowercase();
        if name_lower.is_empty() {
            continue;
        }
        actions.insert(name_lower.clone());
        if value.contains("%{") {
            has_macro = true;
        }

        match name_lower.as_str() {
            "id" => {
                let parsed = value.parse::<u32>().map_err(|_| {
                    parse_error(source, line, &format!("invalid rule id `{value}`"))
                })?;
                id = Some(parsed);
            }
            "phase" => {
                phase = value.parse::<u32>().ok();
            }
            "t" => {
                let transform = value.trim_matches('\'').trim_matches('"');
                if transform.eq_ignore_ascii_case("none") {
                    transforms.clear();
                } else if !transform.is_empty() {
                    transforms.push(transform.to_string());
                }
            }
            "chain" => chain = true,
            _ => {}
        }

        match name_lower.as_str() {
            "chain" => {
                constructs.insert("chain".to_string());
            }
            "capture" => {
                constructs.insert("capture".to_string());
            }
            "setvar" | "setenv" | "setuid" | "setsid" => {
                constructs.insert("variable-write".to_string());
            }
            "initcol" => {
                constructs.insert("collection-init".to_string());
            }
            "skipafter" => {
                constructs.insert("skip-after".to_string());
            }
            "skip" => {
                constructs.insert("skip".to_string());
            }
            "ctl" => {
                constructs.insert("ctl".to_string());
            }
            "multimatch" => {
                constructs.insert("multi-match".to_string());
            }
            "exec" => {
                constructs.insert("external-exec".to_string());
            }
            "pause" => {
                constructs.insert("external-pause".to_string());
            }
            "log" | "nolog" | "auditlog" | "noauditlog" => {
                constructs.insert("logging".to_string());
            }
            "deny" | "block" | "drop" | "pass" | "allow" | "redirect" | "status" => {
                constructs.insert("disruptive-action".to_string());
            }
            "msg" | "tag" | "ver" | "rev" | "severity" | "accuracy" | "maturity" | "logdata" => {
                constructs.insert("metadata".to_string());
            }
            "xmlns" => {
                constructs.insert("xml-namespace".to_string());
            }
            "proxy" => {
                constructs.insert("proxy".to_string());
            }
            "append" | "prepend" | "replace" => {
                constructs.insert("body-rewrite".to_string());
            }
            "sanitisearg"
            | "sanitisematched"
            | "sanitiserequestheader"
            | "sanitiseresponseheader" => {
                constructs.insert("sanitise".to_string());
            }
            "t" => {
                constructs.insert("transform".to_string());
            }
            _ => {}
        }
    }

    if has_macro {
        constructs.insert("macro-expansion".to_string());
    }

    Ok(ParsedActions {
        id,
        phase,
        transforms,
        actions: actions.into_iter().collect(),
        constructs,
        chain,
    })
}

fn parse_operator(text: &str, line: usize, source: &str) -> Result<OperatorSpec, AccountingError> {
    let text = text.trim();
    if text.is_empty() {
        return Err(parse_error(source, line, "operator is empty"));
    }
    let (negated, rest) = match text.strip_prefix('!') {
        Some(rest) => (true, rest),
        None => (false, text),
    };
    let rest = rest.trim_start();
    if let Some(rest) = rest.strip_prefix('@') {
        let (name, argument) = match rest.find(char::is_whitespace) {
            Some(index) => (&rest[..index], rest[index..].trim()),
            None => (rest, ""),
        };
        if name.is_empty() {
            return Err(parse_error(source, line, "operator name is empty"));
        }
        Ok(OperatorSpec {
            name: name.to_string(),
            negated,
            argument: argument.to_string(),
        })
    } else {
        Ok(OperatorSpec {
            name: "rx".to_string(),
            negated,
            argument: rest.to_string(),
        })
    }
}

fn parse_targets(text: &str) -> Vec<String> {
    let mut targets = Vec::new();
    for part in split_targets(text) {
        let raw = part.trim().to_string();
        if !raw.is_empty() {
            targets.push(raw);
        }
    }
    targets
}

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

fn split_actions(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;
    for c in text.chars() {
        if escaped {
            current.push(c);
            escaped = false;
            continue;
        }
        match c {
            '\\' if in_single || in_double => {
                current.push(c);
                escaped = true;
            }
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

fn logical_lines(text: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut buffer = String::new();
    let mut start = 0usize;

    for (index, raw) in text.lines().enumerate() {
        let raw = raw.strip_suffix('\r').unwrap_or(raw);
        let line_no = index + 1;
        let trimmed = raw.trim_start();
        if buffer.is_empty() {
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            start = line_no;
        }
        if let Some(stripped) = raw.strip_suffix('\\') {
            buffer.push_str(stripped);
            continue;
        }
        buffer.push_str(raw);
        out.push((start, std::mem::take(&mut buffer)));
    }
    if !buffer.trim().is_empty() {
        out.push((start, buffer));
    }
    out
}

fn first_word(text: &str) -> &str {
    text.trim_start()
        .split(char::is_whitespace)
        .next()
        .unwrap_or("")
}

fn split_first_word(text: &str) -> (&str, &str) {
    let text = text.trim_start();
    match text.find(char::is_whitespace) {
        Some(index) => (&text[..index], text[index..].trim_start()),
        None => (text, ""),
    }
}

fn split_first_token(text: &str) -> Option<(&str, &str)> {
    let text = text.trim_start();
    if text.is_empty() {
        return None;
    }
    if let Some(stripped) = text.strip_prefix('"') {
        let end = stripped.find('"')?;
        return Some((&stripped[..end], &stripped[end + 1..]));
    }
    match text.find(char::is_whitespace) {
        Some(index) => Some((&text[..index], &text[index..])),
        None => Some((text, "")),
    }
}

fn take_quoted(text: &str) -> Option<(String, &str)> {
    let text = text.trim_start();
    let mut chars = text.char_indices();
    if chars.next()?.1 != '"' {
        return None;
    }
    let mut out = String::new();
    let mut escaped = false;
    for (index, c) in chars {
        if escaped {
            out.push('\\');
            out.push(c);
            escaped = false;
            continue;
        }
        match c {
            '\\' => escaped = true,
            '"' => return Some((out, &text[index + 1..])),
            _ => out.push(c),
        }
    }
    None
}

fn has_regex_key(target: &str) -> bool {
    let target = target.trim_start_matches('!').trim_start_matches('&');
    match target.split_once(':') {
        Some((_, key)) => key.starts_with('/') && key.len() > 1,
        None => false,
    }
}

fn parse_error(source: &str, line: usize, detail: &str) -> AccountingError {
    AccountingError::Parse {
        path: source.to_string(),
        line,
        detail: detail.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Coverage
// ---------------------------------------------------------------------------

fn summarise(entries: &[RuleEntry]) -> Coverage {
    let mut coverage = Coverage {
        entries: entries.len(),
        ..Coverage::default()
    };
    let mut ids = BTreeSet::new();
    let mut duplicates = BTreeSet::new();

    for entry in entries {
        *coverage
            .directives
            .entry(entry.directive.clone())
            .or_default() += 1;
        if entry.chain {
            coverage.chains += 1;
        }
        if entry.chain_member > 0 {
            coverage.chain_members += 1;
        }
        if let Some(id) = entry.id {
            if !ids.insert(id) {
                duplicates.insert(id);
            }
        }
        if let Some(operator) = &entry.operator {
            *coverage
                .operators
                .entry(operator.name.to_ascii_lowercase())
                .or_default() += 1;
        }
        for transform in &entry.transforms {
            *coverage
                .transforms
                .entry(transform.to_ascii_lowercase())
                .or_default() += 1;
        }
        for action in &entry.actions {
            *coverage.actions.entry(action.clone()).or_default() += 1;
        }
        for construct in &entry.constructs {
            *coverage.constructs.entry(construct.clone()).or_default() += 1;
        }
    }

    coverage.rule_id_list = ids.iter().copied().collect();
    coverage.rule_ids = coverage.rule_id_list.len();
    coverage.duplicate_rule_ids = duplicates.into_iter().collect();
    coverage
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn display_path(path: &Path) -> String {
    let text = path.display().to_string();
    text.replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
# A comment
SecDefaultAction "phase:1,log,auditlog,pass"

SecRule ARGS:q "@rx (?i)union.*select" \
    "id:1001,phase:2,block,log,t:urlDecodeUni,t:lowercase,\
    tag:'OWASP_CRS',msg:'SQLi',chain"
    SecRule REQUEST_HEADERS:User-Agent "!@pm bad-agent" \
        "t:none,capture,setvar:'tx.foo=%{MATCHED_VAR}'"

SecRule REQUEST_URI "@beginsWith /admin" \
    "id:1002,phase:1,deny,status:403,skipAfter:END"

SecMarker "END"

SecAction "id:1003,phase:1,pass,nolog,setvar:'tx.x=1'"
"#;

    #[test]
    fn parses_every_rule_directive() {
        let manifest = Manifest::from_str(SAMPLE, "sample.conf").expect("parses");
        assert_eq!(manifest.format_version, MANIFEST_FORMAT_VERSION);
        assert_eq!(manifest.coverage.rule_id_list, vec![1001, 1002, 1003]);
        assert_eq!(manifest.coverage.chains, 1);
        assert_eq!(manifest.coverage.chain_members, 1);
        assert_eq!(manifest.coverage.operators.get("rx").copied(), Some(1));
        assert!(manifest.coverage.transforms.contains_key("urldecodeuni"));
        assert!(manifest.coverage.actions.contains_key("block"));
        assert!(manifest.coverage.constructs.contains_key("chain"));
        assert!(manifest.coverage.constructs.contains_key("macro-expansion"));
        let first = manifest
            .entries
            .iter()
            .find(|e| e.id == Some(1001))
            .unwrap();
        assert_eq!(first.operator.as_ref().unwrap().name, "rx");
        assert!(first.chain);
        let member = manifest
            .entries
            .iter()
            .find(|e| e.chain_member == 1)
            .unwrap();
        assert_eq!(member.chain_id, Some(1001));
        assert!(member.operator.as_ref().unwrap().negated);
    }

    #[test]
    fn rejects_duplicate_ids() {
        let text = SAMPLE.replace("id:1002", "id:1001");
        assert!(matches!(
            Manifest::from_str(&text, "sample.conf"),
            Err(AccountingError::DuplicateRuleId { id: 1001, .. })
        ));
    }

    #[test]
    fn rejects_unmodelled_rule_directive() {
        let text = format!("{SAMPLE}\nSecRuleUpdateTargetById 1001 \"!ARGS:foo\"\n");
        assert!(matches!(
            Manifest::from_str(&text, "sample.conf"),
            Err(AccountingError::UnsupportedDirective { directive, .. })
                if directive == "secruleupdatetargetbyid"
        ));
    }

    #[test]
    fn rejects_unknown_sec_directive() {
        let text = format!("{SAMPLE}\nSecFutureRuleThing 1\n");
        assert!(matches!(
            Manifest::from_str(&text, "sample.conf"),
            Err(AccountingError::UnsupportedDirective { directive, .. })
                if directive == "secfuturerulething"
        ));
    }

    #[test]
    fn verify_complete_passes_with_full_support() {
        let manifest = Manifest::from_str(SAMPLE, "sample.conf").unwrap();
        let support = EngineSupport::from_manifest(&manifest);
        let verification = verify_complete(&manifest, &support).expect("complete");
        assert_eq!(verification.entries, manifest.entries.len());
        assert_eq!(verification.rule_ids, 3);
    }

    #[test]
    fn verify_complete_reports_all_gaps() {
        let manifest = Manifest::from_str(SAMPLE, "sample.conf").unwrap();
        let mut support = EngineSupport::from_manifest(&manifest);
        support.rule_ids.remove(&1001);
        support.operators.remove("rx");
        support.transforms.remove("lowercase");
        support.actions.remove("block");
        support.constructs.remove("macro-expansion");
        match verify_complete(&manifest, &support) {
            Err(AccountingError::Incomplete { gaps }) => {
                assert!(gaps.missing_rule_ids.contains(&1001));
                assert!(gaps.unsupported_operators.contains_key("rx"));
                assert!(gaps.unsupported_transforms.contains_key("lowercase"));
                assert!(gaps.unsupported_actions.contains_key("block"));
                assert!(gaps.unsupported_constructs.contains_key("macro-expansion"));
            }
            other => panic!("expected incomplete, got {other:?}"),
        }
    }

    #[test]
    fn ignored_actions_are_explicit() {
        let manifest = Manifest::from_str(SAMPLE, "sample.conf").unwrap();
        let mut support = EngineSupport::from_manifest(&manifest);
        support.actions.remove("tag");
        support.ignored_actions.insert("tag".to_string());
        verify_complete(&manifest, &support).expect("tag is declared ignorable");
    }

    #[test]
    fn manifest_round_trips_through_json() {
        let manifest = Manifest::from_str(SAMPLE, "sample.conf").unwrap();
        let text = manifest.to_json_pretty().unwrap();
        let loaded = Manifest::from_json_str(&text).expect("round trip");
        assert_eq!(manifest, loaded);
    }

    #[test]
    fn pinned_bundle_is_accountable() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(DEFAULT_RULES_PATH);
        let manifest = Manifest::from_path(&path).expect("pinned bundle parses");
        assert!(manifest.coverage.rule_ids > 400);
        assert!(manifest.coverage.operators.contains_key("rx"));
        assert!(manifest.coverage.operators.contains_key("detectsqli"));
        assert!(manifest.coverage.transforms.contains_key("urldecodeuni"));
        assert!(manifest.coverage.constructs.contains_key("chain"));
        assert!(manifest.coverage.duplicate_rule_ids.is_empty());

        let support = EngineSupport::from_manifest(&manifest);
        let verification =
            verify_complete(&manifest, &support).expect("full support covers the pinned bundle");
        assert_eq!(verification.entries, manifest.entries.len());
        assert_eq!(verification.rule_ids, manifest.coverage.rule_ids);
    }

    #[test]
    fn pinned_manifest_matches_the_bundle() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(DEFAULT_RULES_PATH);
        let text = std::fs::read_to_string(&path).expect("read pinned bundle");
        let manifest = Manifest::from_str(&text, DEFAULT_RULES_PATH).expect("pinned bundle parses");
        let committed_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(DEFAULT_MANIFEST_PATH);
        let committed = Manifest::load(&committed_path).expect("committed manifest loads");
        assert_eq!(committed, manifest, "regenerate with rule_accounting");
    }
}
