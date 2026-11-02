//! Experimental required-literal prefilter for OWASP CRS request bodies.
//!
//! The prefilter answers one question: **can any body-relevant CRS rule match
//! this body?** It scans an over-approximation of every representation a CRS
//! rule can see (raw body, URL-decoded form value, JSON-unescaped string,
//! XML/HTML entity-decoded text) with one Aho-Corasick automaton per supported
//! transform pipeline. A miss is a proof that no gated rule can match a
//! body-derived value; a hit only means "run full CRS".
//!
//! Soundness is one-sided and deliberate:
//!
//! * Extra representations are always safe (they can only add hits).
//! * A literal is only used when the offline extractor proved that *every*
//!   match of the rule contains it.
//! * Rules whose operator, transform chain or target cannot be modelled are
//!   listed as `ungated` in the artifact. [`Prefilter::all_body_rules_gated`]
//!   is false when any of them exists, which disables the body-withholding
//!   fast path.
//!
//! This module is feature-gated behind `crs-prefilter` and is **not** enabled
//! by default.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::sync::OnceLock;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};

use crate::waf::prefilter_extract::{Coverage, PrefilterArtifact, SCHEMA_VERSION};

/// The committed artifact, embedded so the prefilter works in a single binary.
pub const EMBEDDED_ARTIFACT: &str = include_str!("../../rules/crs/prefilter.json");

/// Maximum number of rule ids reported for one hit.
const MAX_REPORTED_RULES: usize = 32;

/// Maximum number of per-rule removals accepted in one transaction payload.
///
/// This is a hard ABI bound, not a tuning knob: the guest rejects larger lists
/// outright. The stock CRS artifact has 62 gated rules, so the limit leaves
/// room for higher paranoia levels while keeping the payload bounded.
pub const MAX_REMOVE_RULE_IDS: usize = 256;

/// Errors returned while loading or building the prefilter.
#[derive(Debug, thiserror::Error)]
pub enum PrefilterError {
    #[error("invalid prefilter artifact: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unsupported prefilter artifact schema {found} (expected {expected})")]
    Schema { found: u32, expected: u32 },
    #[error("unknown transform `{0}` in prefilter artifact")]
    UnknownTransform(String),
    #[error("failed to build Aho-Corasick automaton: {0}")]
    Build(String),
    #[error("embedded prefilter artifact is invalid: {0}")]
    Embedded(String),
}

/// Where the prefilter sits in the evaluation path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PrefilterMode {
    /// Disabled (default).
    #[default]
    Off,
    /// Run the prefilter and record its verdict, but always run full CRS.
    /// Used to measure hit rates on a live rule set without changing
    /// decisions.
    DryRun,
    /// Withhold the body when the prefilter is clean **and** every
    /// body-relevant rule is gated. On stock CRS this is never available
    /// because `@detectSQLi`/`@detectXSS` and the body-size rules are ungated;
    /// see `docs/suggestions_from_agents/crs-prefilter.md`.
    BodyWithhold,
    /// Remove only the gated rules whose mandatory literals are absent from
    /// the request (body, URI, headers, cookies). Ungated rules always run, so
    /// this is sound on stock CRS and is the production integration.
    Gated,
}

impl From<crate::config::CorazaPrefilterMode> for PrefilterMode {
    fn from(mode: crate::config::CorazaPrefilterMode) -> Self {
        match mode {
            crate::config::CorazaPrefilterMode::Off => Self::Off,
            crate::config::CorazaPrefilterMode::DryRun => Self::DryRun,
            crate::config::CorazaPrefilterMode::Gated => Self::Gated,
        }
    }
}

/// Outcome of one prefilter evaluation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PrefilterHit {
    /// True when at least one gated literal was found, or the body contained a
    /// construct that forces full evaluation (a DTD/entity declaration).
    pub hit: bool,
    /// Why full evaluation is required even without a literal hit.
    pub forced_reason: Option<&'static str>,
    /// Number of bytes scanned across all representations.
    pub scanned_bytes: usize,
    /// Number of representations scanned before returning.
    pub representations: usize,
    /// Up to [`MAX_REPORTED_RULES`] rule ids that produced a literal hit.
    pub matched_rules: Vec<u32>,
}

impl PrefilterHit {
    fn forced(reason: &'static str) -> Self {
        Self {
            hit: true,
            forced_reason: Some(reason),
            ..Self::default()
        }
    }
}

/// Outcome of a per-rule gate evaluation over every request representation.
///
/// `removable_rule_ids` is the sound, bounded set of gated rules that cannot
/// match any scanned representation. Ungated rules are never included, even if
/// a caller asks for them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuleGate {
    /// Why full evaluation is required even without a literal hit.
    pub forced_reason: Option<&'static str>,
    /// Number of bytes scanned across all inputs and groups.
    pub scanned_bytes: usize,
    /// Gated rule ids that produced a literal hit (must keep running).
    pub matched_rules: Vec<u32>,
    /// Gated rule ids that can be removed for this transaction.
    pub removable_rule_ids: Vec<u32>,
}

impl RuleGate {
    /// True when no rule can be removed for this request.
    pub fn is_empty(&self) -> bool {
        self.removable_rule_ids.is_empty()
    }
}

/// One Aho-Corasick automaton over a (representation, transform, case) group.
struct CompiledGroup {
    extract: Extract,
    transforms: Vec<Transform>,
    automaton: AhoCorasick,
    /// Pattern index -> rule ids that share this literal.
    rules: Vec<Vec<u32>>,
}

/// A loaded prefilter.
pub struct Prefilter {
    groups: Vec<CompiledGroup>,
    gated_rule_ids: Vec<u32>,
    ungated_body_rule_ids: Vec<u32>,
    all_body_rules_gated: bool,
    coverage: Coverage,
}

impl std::fmt::Debug for Prefilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Prefilter")
            .field("groups", &self.groups.len())
            .field("gated_rules", &self.gated_rule_ids.len())
            .field("ungated_body_rules", &self.ungated_body_rule_ids.len())
            .field("all_body_rules_gated", &self.all_body_rules_gated)
            .finish()
    }
}

impl Prefilter {
    /// Loads the embedded artifact. The result is cached for the process.
    pub fn embedded() -> Result<&'static Prefilter, PrefilterError> {
        static CELL: OnceLock<Result<Prefilter, String>> = OnceLock::new();
        match CELL
            .get_or_init(|| Prefilter::from_json(EMBEDDED_ARTIFACT).map_err(|err| err.to_string()))
        {
            Ok(prefilter) => Ok(prefilter),
            Err(err) => Err(PrefilterError::Embedded(err.clone())),
        }
    }

    /// Parses an artifact and compiles its automata.
    pub fn from_json(json: &str) -> Result<Self, PrefilterError> {
        let artifact: PrefilterArtifact = serde_json::from_str(json)?;
        Self::from_artifact(artifact)
    }

    /// Compiles a parsed artifact.
    pub fn from_artifact(artifact: PrefilterArtifact) -> Result<Self, PrefilterError> {
        if artifact.schema_version != SCHEMA_VERSION {
            return Err(PrefilterError::Schema {
                found: artifact.schema_version,
                expected: SCHEMA_VERSION,
            });
        }

        let mut pending: BTreeMap<GroupKey, BTreeMap<String, std::collections::BTreeSet<u32>>> =
            BTreeMap::new();
        let mut gated = Vec::new();
        let mut ungated_body = Vec::new();

        for gate in &artifact.rules {
            if !gate.body_relevant {
                continue;
            }
            if !gate.gated {
                ungated_body.push(gate.id);
                continue;
            }
            gated.push(gate.id);
            for literal_group in &gate.literal_groups {
                let transforms = parse_transforms(&literal_group.transforms)?;
                for extract in Extract::ALL {
                    let key = GroupKey {
                        extract,
                        transforms: transforms.clone(),
                        case_insensitive: literal_group.case_insensitive,
                    };
                    let entry = pending.entry(key).or_default();
                    for literal in &literal_group.literals {
                        if !literal.is_empty() {
                            entry.entry(literal.clone()).or_default().insert(gate.id);
                        }
                    }
                }
            }
        }

        for rule in &artifact.ungated_rules {
            if rule.body_relevant {
                ungated_body.push(rule.id);
            }
        }

        gated.sort_unstable();
        gated.dedup();
        ungated_body.sort_unstable();
        ungated_body.dedup();

        let mut groups = Vec::with_capacity(pending.len());
        for (key, patterns) in pending {
            let (patterns, rules): (Vec<String>, Vec<Vec<u32>>) = patterns
                .into_iter()
                .map(|(literal, ids)| (literal, ids.into_iter().collect()))
                .unzip();
            let automaton = AhoCorasickBuilder::new()
                .ascii_case_insensitive(key.case_insensitive)
                .match_kind(MatchKind::Standard)
                .build(&patterns)
                .map_err(|err| PrefilterError::Build(err.to_string()))?;
            groups.push(CompiledGroup {
                extract: key.extract,
                transforms: key.transforms,
                automaton,
                rules,
            });
        }

        let all_body_rules_gated =
            artifact.coverage.all_body_rules_gated && ungated_body.is_empty();
        Ok(Self {
            groups,
            gated_rule_ids: gated,
            ungated_body_rule_ids: ungated_body,
            all_body_rules_gated,
            coverage: artifact.coverage,
        })
    }

    /// True when every body-relevant rule has a sound literal gate. Only then
    /// can the body be withheld on a clean prefilter result.
    pub fn all_body_rules_gated(&self) -> bool {
        self.all_body_rules_gated
    }

    /// Rule ids that have a sound literal gate.
    pub fn gated_rule_ids(&self) -> &[u32] {
        &self.gated_rule_ids
    }

    /// Body-relevant rule ids that force full CRS evaluation.
    pub fn ungated_body_rule_ids(&self) -> &[u32] {
        &self.ungated_body_rule_ids
    }

    /// Coverage counters from the artifact.
    pub fn coverage(&self) -> &Coverage {
        &self.coverage
    }

    /// Scans `body` and reports whether any gated rule can match it.
    ///
    /// The scan is an over-approximation: a `false` result is a proof that no
    /// gated body-relevant rule can match any value derived from `body`.
    pub fn evaluate(&self, body: &[u8]) -> PrefilterHit {
        // XML entity expansion can hide an arbitrary literal inside a DTD.
        // Force full evaluation whenever a declaration is present.
        if contains_ascii_case_insensitive(body, b"<!DOCTYPE")
            || contains_ascii_case_insensitive(body, b"<!ENTITY")
        {
            return PrefilterHit::forced("body contains an XML DTD/entity declaration");
        }

        let mut scanned = 0usize;
        let mut representations = 0usize;
        for group in &self.groups {
            let representation = apply_pipeline(body, group.extract, &group.transforms);
            scanned += representation.len();
            representations += 1;
            if group.automaton.is_match(&representation) {
                let mut matched = Vec::new();
                'outer: for mat in group.automaton.find_iter(&representation) {
                    for &rule in &group.rules[mat.pattern().as_usize()] {
                        if !matched.contains(&rule) {
                            matched.push(rule);
                            if matched.len() >= MAX_REPORTED_RULES {
                                break 'outer;
                            }
                        }
                    }
                }
                return PrefilterHit {
                    hit: true,
                    forced_reason: None,
                    scanned_bytes: scanned,
                    representations,
                    matched_rules: matched,
                };
            }
        }

        PrefilterHit {
            hit: false,
            forced_reason: None,
            scanned_bytes: scanned,
            representations,
            matched_rules: Vec::new(),
        }
    }

    /// Number of compiled automata (representations × transform pipelines).
    pub fn automaton_count(&self) -> usize {
        self.groups.len()
    }

    /// Scans every request representation and returns the gated rules that
    /// provably cannot match.
    ///
    /// Unlike [`Prefilter::evaluate`], this does not stop at the first hit: it
    /// collects the union of matching rule ids across every group and input so
    /// a body that hits one rule can still remove the others. A miss for a
    /// rule across **all** inputs is the same proof as [`Prefilter::evaluate`],
    /// extended to the URI, query string, headers and cookies.
    ///
    /// Inputs are scanned independently (never concatenated): some transforms
    /// (`replaceComments`, `normalizePath`, `cmdLine`) are not monotonic across
    /// value boundaries, so a concatenated representation could hide a literal
    /// that is present in one value. Scanning each value separately keeps the
    /// over-approximation sound.
    pub fn evaluate_inputs(&self, inputs: &[&[u8]]) -> RuleGate {
        // XML entity expansion can hide an arbitrary literal inside a DTD.
        // Force full evaluation whenever a declaration is present.
        for input in inputs {
            if contains_ascii_case_insensitive(input, b"<!DOCTYPE")
                || contains_ascii_case_insensitive(input, b"<!ENTITY")
            {
                return RuleGate {
                    forced_reason: Some("request contains an XML DTD/entity declaration"),
                    ..RuleGate::default()
                };
            }
        }

        let mut scanned = 0usize;
        let mut matched: Vec<u32> = Vec::new();
        for group in &self.groups {
            for input in inputs {
                if input.is_empty() {
                    continue;
                }
                let representation = apply_pipeline(input, group.extract, &group.transforms);
                scanned += representation.len();
                if !group.automaton.is_match(&representation) {
                    continue;
                }
                for mat in group.automaton.find_iter(&representation) {
                    for &rule in &group.rules[mat.pattern().as_usize()] {
                        if !matched.contains(&rule) {
                            matched.push(rule);
                        }
                    }
                }
            }
        }
        matched.sort_unstable();
        matched.dedup();

        let removable_rule_ids = self
            .gated_rule_ids
            .iter()
            .copied()
            .filter(|id| !matched.contains(id))
            .filter(|id| self.ungated_body_rule_ids.binary_search(id).is_err())
            .take(MAX_REMOVE_RULE_IDS)
            .collect();

        RuleGate {
            forced_reason: None,
            scanned_bytes: scanned,
            matched_rules: matched,
            removable_rule_ids,
        }
    }

    /// Scans the request context (URI, query, headers, cookies and body) and
    /// returns the rules that may be removed for this transaction.
    pub fn evaluate_request(&self, ctx: &crate::waf::RequestContext) -> RuleGate {
        let uri = ctx.uri.to_string();
        let mut inputs: Vec<&[u8]> = Vec::with_capacity(2 + ctx.headers.len() * 2);
        inputs.push(ctx.method.as_str().as_bytes());
        inputs.push(uri.as_bytes());
        if let Some(query) = ctx.uri.query() {
            inputs.push(query.as_bytes());
        }
        for (name, value) in ctx.headers.iter() {
            inputs.push(name.as_str().as_bytes());
            inputs.push(value.as_bytes());
        }
        if let Some(body) = ctx.body.as_deref() {
            inputs.push(body);
        }
        self.evaluate_inputs(&inputs)
    }

    /// Filters an untrusted id list down to the gated set.
    ///
    /// Unknown ids, ungated rules and duplicates are dropped, and the result is
    /// truncated to [`MAX_REMOVE_RULE_IDS`]. The host uses this before encoding
    /// a payload; the guest repeats the check against its own artifact copy so
    /// a forged payload cannot disable an ungated rule.
    pub fn sanitize_remove_rule_ids(&self, ids: &[u32]) -> Vec<u32> {
        let mut out = Vec::with_capacity(ids.len().min(MAX_REMOVE_RULE_IDS));
        for &id in ids {
            if out.len() >= MAX_REMOVE_RULE_IDS {
                break;
            }
            if self.gated_rule_ids.binary_search(&id).is_err() {
                continue;
            }
            if self.ungated_body_rule_ids.binary_search(&id).is_ok() {
                continue;
            }
            if !out.contains(&id) {
                out.push(id);
            }
        }
        out
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct GroupKey {
    extract: Extract,
    transforms: Vec<Transform>,
    case_insensitive: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Extract {
    Identity,
    UrlDecode,
    JsonUnescape,
    HtmlEntityDecode,
}

impl Extract {
    /// The extraction variants a CRS body processor can apply to a value.
    pub(crate) const ALL: [Extract; 4] = [
        Extract::Identity,
        Extract::UrlDecode,
        Extract::JsonUnescape,
        Extract::HtmlEntityDecode,
    ];

    pub(crate) fn apply(self, input: &[u8]) -> Cow<'_, [u8]> {
        match self {
            Extract::Identity => Cow::Borrowed(input),
            Extract::UrlDecode => Cow::Owned(url_decode(input, false)),
            Extract::JsonUnescape => Cow::Owned(json_unescape(input)),
            Extract::HtmlEntityDecode => Cow::Owned(html_entity_decode(input)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Transform {
    Lowercase,
    Uppercase,
    UrlDecode,
    UrlDecodeUni,
    RemoveNulls,
    ReplaceNulls,
    CompressWhitespace,
    RemoveWhitespace,
    Trim,
    TrimLeft,
    TrimRight,
    NormalizePath,
    NormalizePathWin,
    EscapeSeqDecode,
    ReplaceComments,
    JsDecode,
    CssDecode,
    HtmlEntityDecode,
    CmdLine,
}

pub(crate) fn parse_transforms(names: &[String]) -> Result<Vec<Transform>, PrefilterError> {
    let mut out = Vec::new();
    for name in names {
        match name.as_str() {
            // `none` is a reset marker; `utf8tounicode` is the identity for the
            // ASCII literals the extractor accepts.
            "none" | "utf8tounicode" => {}
            "lowercase" => out.push(Transform::Lowercase),
            "uppercase" => out.push(Transform::Uppercase),
            "urldecode" => out.push(Transform::UrlDecode),
            "urldecodeuni" => out.push(Transform::UrlDecodeUni),
            "removenulls" => out.push(Transform::RemoveNulls),
            "replacenulls" => out.push(Transform::ReplaceNulls),
            "compresswhitespace" => out.push(Transform::CompressWhitespace),
            "removewhitespace" => out.push(Transform::RemoveWhitespace),
            "trim" => out.push(Transform::Trim),
            "trimleft" => out.push(Transform::TrimLeft),
            "trimright" => out.push(Transform::TrimRight),
            "normalizepath" | "normalisepath" => out.push(Transform::NormalizePath),
            "normalizepathwin" | "normalisepathwin" => out.push(Transform::NormalizePathWin),
            "escapeseqdecode" => out.push(Transform::EscapeSeqDecode),
            "replacecomments" => out.push(Transform::ReplaceComments),
            "jsdecode" => out.push(Transform::JsDecode),
            "cssdecode" => out.push(Transform::CssDecode),
            "htmlentitydecode" => out.push(Transform::HtmlEntityDecode),
            "cmdline" => out.push(Transform::CmdLine),
            other => return Err(PrefilterError::UnknownTransform(other.to_string())),
        }
    }
    Ok(out)
}

pub(crate) fn apply_pipeline(input: &[u8], extract: Extract, transforms: &[Transform]) -> Vec<u8> {
    let mut current = extract.apply(input);
    for transform in transforms {
        current = Cow::Owned(transform.apply(&current));
    }
    current.into_owned()
}

/// Number of body extraction variants a CRS body processor can produce.
#[doc(hidden)]
pub const EXTRACTION_VARIANTS: usize = Extract::ALL.len();

/// Experimental helper for the Vectorscan/Hyperscan evaluation target.
///
/// A parsed transform chain that can be applied to a body for one extraction
/// variant without re-parsing the artifact's transform names on every scan.
/// Not part of the stable API; gated behind `crs-prefilter`.
#[doc(hidden)]
#[derive(Debug, Clone)]
pub struct TransformChain {
    transforms: Vec<Transform>,
}

impl TransformChain {
    #[doc(hidden)]
    pub fn parse(names: &[String]) -> Result<Self, PrefilterError> {
        Ok(Self {
            transforms: parse_transforms(names)?,
        })
    }

    /// Apply the chain to a body for one extraction variant.
    ///
    /// This is the naive path: extraction and every transform run for every
    /// group, matching the existing Aho-Corasick prefilter's structure.
    #[doc(hidden)]
    pub fn apply(&self, body: &[u8], extraction: usize) -> Vec<u8> {
        self.apply_view(&extract_view(body, extraction))
            .into_owned()
    }

    /// Apply the chain to an already-extracted view, skipping transforms that
    /// are provably the identity on this input.
    ///
    /// The skip predicate is conservative: a `false` result only means the
    /// transform runs. Reusing the input buffer when every transform is a
    /// no-op is what lets one extracted view feed every group's database.
    #[doc(hidden)]
    pub fn apply_view<'a>(&self, input: &'a [u8]) -> std::borrow::Cow<'a, [u8]> {
        let mut current = std::borrow::Cow::Borrowed(input);
        for transform in &self.transforms {
            if transform.is_identity_for(&current) {
                continue;
            }
            current = std::borrow::Cow::Owned(transform.apply(&current));
        }
        current
    }

    /// Apply the chain without the no-op skip, for an apples-to-apples
    /// comparison with the existing per-group prefilter.
    #[doc(hidden)]
    pub fn apply_view_naive(&self, input: &[u8]) -> Vec<u8> {
        let mut current = std::borrow::Cow::Borrowed(input);
        for transform in &self.transforms {
            current = std::borrow::Cow::Owned(transform.apply(&current));
        }
        current.into_owned()
    }

    #[doc(hidden)]
    pub fn is_identity(&self) -> bool {
        self.transforms.is_empty()
    }
}

/// Apply one body extraction variant without any rule transform.
#[doc(hidden)]
pub fn extract_view(body: &[u8], extraction: usize) -> std::borrow::Cow<'_, [u8]> {
    Extract::ALL
        .get(extraction)
        .copied()
        .unwrap_or(Extract::Identity)
        .apply(body)
}

impl Transform {
    /// Conservative identity test: true only when [`Self::apply`] would
    /// return the input unchanged.
    fn is_identity_for(self, input: &[u8]) -> bool {
        match self {
            Transform::Lowercase => {
                input.iter().all(u8::is_ascii) && !input.iter().any(u8::is_ascii_uppercase)
            }
            Transform::Uppercase => {
                input.iter().all(u8::is_ascii) && !input.iter().any(u8::is_ascii_lowercase)
            }
            Transform::UrlDecode | Transform::UrlDecodeUni => {
                !input.iter().any(|b| *b == b'%' || *b == b'+')
            }
            Transform::RemoveNulls | Transform::ReplaceNulls => !input.contains(&0),
            Transform::CompressWhitespace => !input
                .windows(2)
                .any(|pair| is_latin_space(pair[0]) && is_latin_space(pair[1])),
            Transform::RemoveWhitespace => !input.iter().any(|b| is_latin_space(*b)),
            Transform::Trim => {
                !input.first().is_some_and(|b| is_latin_space(*b))
                    && !input.last().is_some_and(|b| is_latin_space(*b))
            }
            Transform::TrimLeft => !input.first().is_some_and(|b| is_latin_space(*b)),
            Transform::TrimRight => !input.last().is_some_and(|b| is_latin_space(*b)),
            Transform::NormalizePath => !input.is_empty() && !input.contains(&b'/'),
            Transform::NormalizePathWin => {
                !input.is_empty() && !input.contains(&b'/') && !input.contains(&b'\\')
            }
            Transform::EscapeSeqDecode => !input.contains(&b'\\'),
            Transform::ReplaceComments => !input.windows(2).any(|pair| pair == b"/*"),
            Transform::JsDecode | Transform::CssDecode => !input.contains(&b'\\'),
            Transform::HtmlEntityDecode => !input.contains(&b'&'),
            Transform::CmdLine => {
                input.iter().all(u8::is_ascii)
                    && !input.iter().any(|b| {
                        matches!(
                            b,
                            b'"' | b'\''
                                | b'\\'
                                | b'^'
                                | b' '
                                | b','
                                | b';'
                                | b'\t'
                                | b'\r'
                                | b'\n'
                                | b'/'
                                | b'('
                        ) || b.is_ascii_uppercase()
                    })
            }
        }
    }

    fn apply(self, input: &[u8]) -> Vec<u8> {
        match self {
            Transform::Lowercase => map_case(input, true),
            Transform::Uppercase => map_case(input, false),
            Transform::UrlDecode => url_decode(input, false),
            Transform::UrlDecodeUni => url_decode(input, true),
            Transform::RemoveNulls => input.iter().copied().filter(|b| *b != 0).collect(),
            Transform::ReplaceNulls => input
                .iter()
                .map(|b| if *b == 0 { b' ' } else { *b })
                .collect(),
            Transform::CompressWhitespace => compress_whitespace(input),
            Transform::RemoveWhitespace => remove_whitespace(input),
            Transform::Trim => trim_bytes(input, true, true),
            Transform::TrimLeft => trim_bytes(input, true, false),
            Transform::TrimRight => trim_bytes(input, false, true),
            Transform::NormalizePath => clean_path(input),
            Transform::NormalizePathWin => {
                let replaced: Vec<u8> = input
                    .iter()
                    .map(|b| if *b == b'\\' { b'/' } else { *b })
                    .collect();
                clean_path(&replaced)
            }
            Transform::EscapeSeqDecode => escape_seq_decode(input),
            Transform::ReplaceComments => replace_comments(input),
            Transform::JsDecode => js_decode(input),
            Transform::CssDecode => css_decode(input),
            Transform::HtmlEntityDecode => html_entity_decode(input),
            Transform::CmdLine => cmd_line(input),
        }
    }
}

// ---------------------------------------------------------------------------
// Byte transforms
// ---------------------------------------------------------------------------

fn map_case(input: &[u8], lower: bool) -> Vec<u8> {
    // Preserve invalid UTF-8 bytes; only transform valid sequences.
    let mut out = Vec::with_capacity(input.len());
    let mut rest = input;
    loop {
        match std::str::from_utf8(rest) {
            Ok(text) => {
                for c in text.chars() {
                    if lower {
                        out.extend_from_slice(c.to_lowercase().collect::<String>().as_bytes());
                    } else {
                        out.extend_from_slice(c.to_uppercase().collect::<String>().as_bytes());
                    }
                }
                break;
            }
            Err(err) => {
                let valid = err.valid_up_to();
                if valid > 0 {
                    let text = std::str::from_utf8(&rest[..valid]).expect("valid prefix");
                    for c in text.chars() {
                        if lower {
                            out.extend_from_slice(c.to_lowercase().collect::<String>().as_bytes());
                        } else {
                            out.extend_from_slice(c.to_uppercase().collect::<String>().as_bytes());
                        }
                    }
                }
                match err.error_len() {
                    Some(len) => {
                        out.extend_from_slice(&rest[valid..valid + len]);
                        rest = &rest[valid + len..];
                    }
                    None => {
                        out.extend_from_slice(&rest[valid..]);
                        break;
                    }
                }
            }
        }
    }
    out
}

fn hex_value(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn hex_pair(input: &[u8], at: usize) -> Option<u8> {
    let hi = hex_value(*input.get(at)?)?;
    let lo = hex_value(*input.get(at + 1)?)?;
    Some((hi << 4) | lo)
}

/// Coraza-compatible `urlDecode`/`urlDecodeUni`.
fn url_decode(input: &[u8], uni: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0usize;
    while i < input.len() {
        match input[i] {
            b'%' => {
                if uni && i + 5 < input.len() && matches!(input[i + 1], b'u' | b'U') {
                    if let (Some(hi), Some(lo)) = (hex_pair(input, i + 2), hex_pair(input, i + 4)) {
                        let mut byte = lo;
                        if hi == 0xff && (1..=0x5e).contains(&byte) {
                            byte = byte.wrapping_add(0x20);
                        }
                        out.push(byte);
                        i += 6;
                        continue;
                    }
                }
                if let Some(byte) = hex_pair(input, i + 1) {
                    out.push(byte);
                    i += 3;
                } else {
                    out.push(b'%');
                    i += 1;
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    out
}

/// Decodes JSON string escapes (`\"`, `\\`, `\uXXXX`, ...).
fn json_unescape(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0usize;
    while i < input.len() {
        if input[i] != b'\\' || i + 1 >= input.len() {
            out.push(input[i]);
            i += 1;
            continue;
        }
        let escape = input[i + 1];
        match escape {
            b'"' | b'\\' | b'/' => {
                out.push(escape);
                i += 2;
            }
            b'b' => {
                out.push(0x08);
                i += 2;
            }
            b'f' => {
                out.push(0x0c);
                i += 2;
            }
            b'n' => {
                out.push(b'\n');
                i += 2;
            }
            b'r' => {
                out.push(b'\r');
                i += 2;
            }
            b't' => {
                out.push(b'\t');
                i += 2;
            }
            b'u' => {
                if let Some((ch, consumed)) = decode_json_unicode(&input[i..]) {
                    out.extend_from_slice(ch.to_string().as_bytes());
                    i += consumed;
                } else {
                    out.push(b'\\');
                    out.push(escape);
                    i += 2;
                }
            }
            _ => {
                out.push(b'\\');
                out.push(escape);
                i += 2;
            }
        }
    }
    out
}

fn decode_json_unicode(input: &[u8]) -> Option<(char, usize)> {
    // input starts with `\uXXXX`
    let first = u32::from(hex_pair(input, 2)?) << 8 | u32::from(hex_pair(input, 4)?);
    if (0xd800..=0xdbff).contains(&first) {
        if input.get(6) == Some(&b'\\') && input.get(7) == Some(&b'u') {
            let second = u32::from(hex_pair(input, 8)?) << 8 | u32::from(hex_pair(input, 10)?);
            if (0xdc00..=0xdfff).contains(&second) {
                let code = 0x10000 + ((first - 0xd800) << 10) + (second - 0xdc00);
                return char::from_u32(code).map(|ch| (ch, 12));
            }
        }
        return None;
    }
    char::from_u32(first).map(|ch| (ch, 6))
}

/// Decodes the XML/HTML entity forms that can hide a literal from a raw scan.
///
/// This is deliberately liberal: extra decodes can only create false
/// positives, and the raw (`Identity`) representation is always scanned too.
fn html_entity_decode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0usize;
    while i < input.len() {
        if input[i] != b'&' {
            out.push(input[i]);
            i += 1;
            continue;
        }
        if let Some((decoded, consumed)) = decode_entity(&input[i..]) {
            out.extend_from_slice(decoded.as_bytes());
            i += consumed;
        } else {
            out.push(b'&');
            i += 1;
        }
    }
    out
}

fn decode_entity(input: &[u8]) -> Option<(String, usize)> {
    debug_assert_eq!(input.first(), Some(&b'&'));
    if input.get(1) == Some(&b'#') {
        let (radix, start) = match input.get(2).copied() {
            Some(b'x') | Some(b'X') => (16, 3),
            _ => (10, 2),
        };
        let mut end = start;
        while end < input.len() && input[end].is_ascii_hexdigit() && radix == 16 {
            end += 1;
        }
        while end < input.len() && input[end].is_ascii_digit() && radix == 10 {
            end += 1;
        }
        if end == start {
            return None;
        }
        let digits = std::str::from_utf8(&input[start..end]).ok()?;
        let code = u32::from_str_radix(digits, radix).ok()?;
        let consumed = if input.get(end) == Some(&b';') {
            end + 1
        } else {
            // HTML5 allows numeric references without a semicolon.
            end
        };
        return char::from_u32(code).map(|ch| (ch.to_string(), consumed));
    }

    // Consume the maximum alphanumeric run, then look for a semicolon.
    let mut end = 1usize;
    while end < input.len() && input[end].is_ascii_alphanumeric() {
        end += 1;
    }
    if end == 1 {
        return None;
    }
    let run = std::str::from_utf8(&input[1..end])
        .ok()?
        .to_ascii_lowercase();
    if input.get(end) == Some(&b';') {
        if let Some(decoded) = decode_named_entity(&run) {
            return Some((decoded.to_string(), end + 1));
        }
    }
    // Legacy no-semicolon forms: Go tries the longest prefix (up to six
    // characters) against the entity table. Only `lt`, `gt`, `amp`, `quot`
    // and `nbsp` are relevant to the ASCII characters the extractor accepts.
    let max_len = run.len().min(6);
    for len in (2..=max_len).rev() {
        if let Some(decoded) = decode_legacy_entity(&run[..len]) {
            return Some((decoded.to_string(), 1 + len));
        }
    }
    None
}

fn decode_legacy_entity(name: &str) -> Option<&'static str> {
    match name {
        "lt" => Some("<"),
        "gt" => Some(">"),
        "amp" => Some("&"),
        "quot" => Some("\""),
        "nbsp" => Some("\u{00a0}"),
        _ => None,
    }
}

fn decode_named_entity(name: &str) -> Option<&'static str> {
    let decoded = match name {
        "lt" => "<",
        "gt" => ">",
        "amp" => "&",
        "quot" => "\"",
        "apos" => "'",
        "nbsp" => "\u{00a0}",
        "colon" => ":",
        "sol" => "/",
        "bsol" => "\\",
        "lpar" => "(",
        "rpar" => ")",
        "period" => ".",
        "comma" => ",",
        "semi" => ";",
        "num" => "#",
        "percnt" => "%",
        "equals" => "=",
        "quest" => "?",
        "plus" => "+",
        "lowbar" | "underbar" => "_",
        "ast" | "midast" => "*",
        "verbar" | "vert" | "verticalline" => "|",
        "grave" | "diacriticalgrave" => "`",
        "hat" => "^",
        "excl" => "!",
        "dollar" => "$",
        "commat" => "@",
        "lsqb" | "lbrack" => "[",
        "rsqb" | "rbrack" => "]",
        "lcub" | "lbrace" => "{",
        "rcub" | "rbrace" => "}",
        "tab" => "\t",
        "newline" => "\n",
        _ => return None,
    };
    Some(decoded)
}

/// `isLatinSpace` from Coraza's `compressWhitespace`.
fn is_latin_space(b: u8) -> bool {
    matches!(b, b'\t' | b'\n' | 0x0b | 0x0c | b'\r' | b' ' | 0x85 | 0xa0)
}

fn compress_whitespace(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut in_space = false;
    for &byte in input {
        if is_latin_space(byte) {
            if !in_space {
                out.push(b' ');
                in_space = true;
            }
        } else {
            out.push(byte);
            in_space = false;
        }
    }
    out
}

fn remove_whitespace(input: &[u8]) -> Vec<u8> {
    // Conservative subset of Go's `unicode.IsSpace`: removing fewer
    // characters can only leave extra bytes, which is safe.
    input
        .iter()
        .copied()
        .filter(|b| !matches!(b, b'\t' | b'\n' | 0x0b | 0x0c | b'\r' | b' ' | 0x85 | 0xa0))
        .collect()
}

fn trim_bytes(input: &[u8], left: bool, right: bool) -> Vec<u8> {
    let is_trim = |b: u8| matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0c | 0x0b);
    let mut start = 0usize;
    let mut end = input.len();
    if left {
        while start < end && is_trim(input[start]) {
            start += 1;
        }
    }
    if right {
        while end > start && is_trim(input[end - 1]) {
            end -= 1;
        }
    }
    input[start..end].to_vec()
}

/// Mirrors Go's `filepath.Clean` on Unix.
fn clean_path(input: &[u8]) -> Vec<u8> {
    if input.is_empty() {
        return b".".to_vec();
    }
    let rooted = input[0] == b'/';
    let mut parts: Vec<&[u8]> = Vec::new();
    for part in input.split(|b| *b == b'/') {
        if part.is_empty() || part == b"." {
            continue;
        }
        if part == b".." {
            if parts.last().is_some_and(|last| *last != b"..".as_slice()) {
                parts.pop();
            } else if !rooted {
                parts.push(part);
            }
            continue;
        }
        parts.push(part);
    }
    let mut out = Vec::with_capacity(input.len());
    if rooted {
        out.push(b'/');
    }
    for (index, part) in parts.iter().enumerate() {
        if index > 0 {
            out.push(b'/');
        }
        out.extend_from_slice(part);
    }
    if out.is_empty() {
        out.push(b'.');
    }
    out
}

/// Coraza's `escapeSeqDecode`.
fn escape_seq_decode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0usize;
    while i < input.len() {
        if input[i] == b'\\' && i + 1 < input.len() {
            let next = input[i + 1];
            let simple = match next {
                b'a' => Some(0x07),
                b'b' => Some(0x08),
                b'f' => Some(0x0c),
                b'n' => Some(b'\n'),
                b'r' => Some(b'\r'),
                b't' => Some(b'\t'),
                b'v' => Some(0x0b),
                b'\\' => Some(b'\\'),
                b'?' => Some(b'?'),
                b'\'' => Some(b'\''),
                b'"' => Some(b'"'),
                _ => None,
            };
            if let Some(byte) = simple {
                out.push(byte);
                i += 2;
                continue;
            }
            if matches!(next, b'x' | b'X') {
                if let Some(byte) = hex_pair(input, i + 2) {
                    out.push(byte);
                    i += 4;
                    continue;
                }
            }
            if (b'0'..=b'7').contains(&next) {
                let mut j = 2usize;
                while j < 4 && i + j < input.len() && (b'0'..=b'7').contains(&input[i + j]) {
                    j += 1;
                }
                let digits = std::str::from_utf8(&input[i + 1..i + j]).unwrap_or("0");
                let value = u32::from_str_radix(digits, 8).unwrap_or(0) as u8;
                out.push(value);
                i += j;
                continue;
            }
            out.push(next);
            i += 2;
        } else {
            out.push(input[i]);
            i += 1;
        }
    }
    out
}

/// Coraza's `cmdLine` (ModSecurity `cmd_line`).
fn cmd_line(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut space = false;
    for &byte in input {
        match byte {
            b'"' | b'\'' | b'\\' | b'^' => {}
            b' ' | b',' | b';' | b'\t' | b'\r' | b'\n' => {
                if !space {
                    out.push(b' ');
                    space = true;
                }
            }
            b'/' | b'(' => {
                if space {
                    out.pop();
                }
                space = false;
                out.push(byte);
            }
            other => {
                out.push(other.to_ascii_lowercase());
                space = false;
            }
        }
    }
    out
}

/// Coraza's `replaceComments`.
fn replace_comments(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0usize;
    let mut in_comment = false;
    while i < input.len() {
        if !in_comment {
            if input[i] == b'/' && input.get(i + 1) == Some(&b'*') {
                in_comment = true;
                i += 2;
            } else {
                out.push(input[i]);
                i += 1;
            }
        } else if input[i] == b'*' && input.get(i + 1) == Some(&b'/') {
            in_comment = false;
            i += 2;
            out.push(b' ');
        } else {
            i += 1;
        }
    }
    if in_comment {
        out.push(b' ');
    }
    out
}

/// Coraza's `jsDecode` (ModSecurity `js_decode`).
fn js_decode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0usize;
    while i < input.len() {
        if input[i] != b'\\' {
            out.push(input[i]);
            i += 1;
            continue;
        }
        if i + 5 < input.len()
            && input[i + 1] == b'u'
            && input[i + 2..i + 6].iter().all(u8::is_ascii_hexdigit)
        {
            let mut byte = hex_pair(input, i + 4).unwrap_or(0);
            if byte > 0
                && byte < 0x5f
                && matches!(input[i + 2], b'f' | b'F')
                && matches!(input[i + 3], b'f' | b'F')
            {
                byte = byte.wrapping_add(0x20);
            }
            out.push(byte);
            i += 6;
            continue;
        }
        if i + 3 < input.len()
            && input[i + 1] == b'x'
            && input[i + 2].is_ascii_hexdigit()
            && input[i + 3].is_ascii_hexdigit()
        {
            out.push(hex_pair(input, i + 2).unwrap_or(0));
            i += 4;
            continue;
        }
        if i + 1 < input.len() && (b'0'..=b'7').contains(&input[i + 1]) {
            let mut j = 0usize;
            while j < 3 && i + 1 + j < input.len() && (b'0'..=b'7').contains(&input[i + 1 + j]) {
                j += 1;
            }
            let digits = std::str::from_utf8(&input[i + 1..i + 1 + j]).unwrap_or("0");
            let value = u32::from_str_radix(digits, 8).unwrap_or(0) as u8;
            out.push(value);
            i += 1 + j;
            continue;
        }
        if i + 1 < input.len() {
            let decoded = match input[i + 1] {
                b'a' => 0x07,
                b'b' => 0x08,
                b'f' => 0x0c,
                b'n' => b'\n',
                b'r' => b'\r',
                b't' => b'\t',
                b'v' => 0x0b,
                other => other,
            };
            out.push(decoded);
            i += 2;
            continue;
        }
        out.extend_from_slice(&input[i..]);
        break;
    }
    out
}

/// Coraza's `cssDecode` (ModSecurity `css_decode`).
fn css_decode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0usize;
    while i < input.len() {
        if input[i] != b'\\' {
            out.push(input[i]);
            i += 1;
            continue;
        }
        if i + 1 >= input.len() {
            i += 1;
            continue;
        }
        i += 1;
        let mut j = 0usize;
        while j < 6 && i + j < input.len() && input[i + j].is_ascii_hexdigit() {
            j += 1;
        }
        if j > 0 {
            let mut full_check = false;
            let byte = match j {
                1 => {
                    let digit = input[i];
                    if digit >= b'A' {
                        ((digit & 0xdf) - b'A') + 10
                    } else {
                        digit - b'0'
                    }
                }
                2 | 3 => hex_pair(input, i + j - 2).unwrap_or(0),
                4 => {
                    full_check = true;
                    hex_pair(input, i + j - 2).unwrap_or(0)
                }
                5 => {
                    let byte = hex_pair(input, i + j - 2).unwrap_or(0);
                    if input[i] == b'0' {
                        full_check = true;
                        byte
                    } else {
                        out.push(byte);
                        i += j;
                        continue;
                    }
                }
                _ => {
                    let byte = hex_pair(input, i + j - 2).unwrap_or(0);
                    if input[i] == b'0' && input[i + 1] == b'0' {
                        full_check = true;
                        byte
                    } else {
                        out.push(byte);
                        i += j;
                        continue;
                    }
                }
            };
            let mut byte = byte;
            if full_check
                && byte > 0
                && byte < 0x5f
                && j >= 4
                && matches!(input[i + j - 3], b'f' | b'F')
                && matches!(input[i + j - 4], b'f' | b'F')
            {
                byte = byte.wrapping_add(0x20);
            }
            out.push(byte);
            if i + j < input.len() && is_css_space(input[i + j]) {
                j += 1;
            }
            i += j;
        } else if input[i] == b'\n' {
            i += 1;
        } else {
            out.push(input[i]);
            i += 1;
        }
    }
    out
}

fn is_css_space(b: u8) -> bool {
    matches!(b, b' ' | 0x0c | b'\n' | b'\t' | b'\r' | 0x0b)
}

fn contains_ascii_case_insensitive(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::waf::prefilter_extract::{
        Coverage, Gate, LiteralGroup, PrefilterArtifact, UngatedRule,
    };

    fn artifact(groups: Vec<LiteralGroup>, ungated: bool) -> PrefilterArtifact {
        let mut coverage = Coverage::default();
        coverage.body_relevant_entries = 1;
        coverage.body_relevant_gated = 1;
        coverage.all_body_rules_gated = !ungated;
        PrefilterArtifact {
            schema_version: SCHEMA_VERSION,
            crs_version: "test".to_string(),
            source: "test".to_string(),
            paranoia_level: 1,
            min_literal_len: 3,
            rules: vec![Gate {
                id: 942100,
                member: 0,
                family: "942".to_string(),
                operator: "rx".to_string(),
                targets: vec!["ARGS".to_string()],
                body_relevant: true,
                gated: true,
                transforms: vec!["none".to_string()],
                literals: groups.iter().flat_map(|g| g.literals.clone()).collect(),
                literal_groups: groups,
                chain: false,
                reason: None,
            }],
            ungated_rules: if ungated {
                vec![UngatedRule {
                    id: 942101,
                    member: 0,
                    family: "942".to_string(),
                    operator: "detectSQLi".to_string(),
                    targets: vec!["ARGS".to_string()],
                    body_relevant: true,
                    chain: false,
                    reason: "test".to_string(),
                }]
            } else {
                Vec::new()
            },
            coverage,
        }
    }

    fn simple(literals: &[&str], ci: bool, transforms: &[&str]) -> Prefilter {
        Prefilter::from_artifact(artifact(
            vec![LiteralGroup {
                transforms: transforms.iter().map(|s| s.to_string()).collect(),
                case_insensitive: ci,
                literals: literals.iter().map(|s| s.to_string()).collect(),
            }],
            false,
        ))
        .expect("prefilter builds")
    }

    #[test]
    fn benign_body_does_not_hit() {
        let prefilter = simple(&["union", "select"], true, &["none"]);
        let hit = prefilter.evaluate(b"name=alice&city=paris");
        assert!(!hit.hit);
        assert!(hit.representations > 0);
    }

    #[test]
    fn attack_body_hits() {
        let prefilter = simple(&["union", "select"], true, &["none"]);
        let hit = prefilter.evaluate(b"q=1%20UNION%20SELECT%20password");
        assert!(hit.hit);
        assert_eq!(hit.matched_rules, vec![942100]);
    }

    #[test]
    fn url_encoded_literal_is_found_after_extraction() {
        let prefilter = simple(&["<script"], false, &["none"]);
        assert!(prefilter.evaluate(b"q=%3Cscript%3Ealert(1)").hit);
    }

    #[test]
    fn json_escape_literal_is_found_after_extraction() {
        let prefilter = simple(&["<script"], false, &["none"]);
        assert!(prefilter.evaluate(br#"{"q":"\u003cscript\u003e"}"#).hit);
    }

    #[test]
    fn html_entity_literal_is_found_after_extraction() {
        let prefilter = simple(&["<script"], false, &["none"]);
        assert!(prefilter.evaluate(b"<x>&lt;script&gt;</x>").hit);
    }

    #[test]
    fn lowercase_transform_matches_uppercase_body() {
        let prefilter = simple(&["select"], false, &["lowercase"]);
        assert!(prefilter.evaluate(b"q=SELECT").hit);
    }

    #[test]
    fn null_removal_is_applied() {
        let prefilter = simple(&["select"], false, &["removenulls"]);
        assert!(prefilter.evaluate(b"se\x00lect").hit);
    }

    #[test]
    fn dtd_forces_full_evaluation() {
        let prefilter = simple(&["script"], false, &["none"]);
        let hit = prefilter
            .evaluate(b"<!DOCTYPE x [<!ENTITY e SYSTEM \"file:///etc/passwd\">]><x>&e;</x>");
        assert!(hit.hit);
        assert!(hit.forced_reason.is_some());
    }

    #[test]
    fn ungated_rules_disable_the_fast_path() {
        let prefilter = Prefilter::from_artifact(artifact(
            vec![LiteralGroup {
                transforms: vec![],
                case_insensitive: false,
                literals: vec!["select".to_string()],
            }],
            true,
        ))
        .expect("prefilter builds");
        assert!(!prefilter.all_body_rules_gated());
        assert_eq!(prefilter.ungated_body_rule_ids(), &[942101]);
    }

    #[test]
    fn cmd_line_matches_coraza() {
        // `cmdLine` removes spaces before `/` and `(`.
        assert_eq!(cmd_line(b"CAT /etc/passwd"), b"cat/etc/passwd");
        assert_eq!(cmd_line(b"cat  /etc/passwd"), b"cat/etc/passwd");
        assert_eq!(cmd_line(b"cat (x)"), b"cat(x)");
        assert_eq!(cmd_line(b"a;b,c"), b"a b c");
        assert_eq!(cmd_line(b"a\"b'c\\d^e"), b"abcde");
    }

    #[test]
    fn html_entity_forms_decode_like_go() {
        assert_eq!(html_entity_decode(b"&lt;script"), b"<script");
        assert_eq!(html_entity_decode(b"&#60;script"), b"<script");
        assert_eq!(html_entity_decode(b"&#x3c;script"), b"<script");
        assert_eq!(html_entity_decode(b"a&sol;b"), b"a/b");
        // `&hyphen;` is U+2010, not ASCII `-`; do not decode it as a hyphen.
        assert_eq!(html_entity_decode(b"a&hyphen;b"), b"a&hyphen;b");
    }

    #[test]
    fn html_entity_transform_matches_legacy_forms() {
        let prefilter = simple(&["<script"], false, &["htmlentitydecode"]);
        assert!(prefilter.evaluate(b"q=&ltscript&gtscript").hit);
    }

    #[test]
    fn clean_path_matches_go_examples() {
        assert_eq!(clean_path(b"/a/b/../c"), b"/a/c");
        assert_eq!(clean_path(b"a//b/./c/"), b"a/b/c");
        assert_eq!(clean_path(b""), b".");
        assert_eq!(clean_path(b"/"), b"/");
        assert_eq!(clean_path(b"../a"), b"../a");
    }

    #[test]
    fn embedded_artifact_compiles() {
        let prefilter = Prefilter::embedded().expect("embedded artifact is valid");
        assert!(prefilter.automaton_count() > 0);
        // The stock CRS bundle contains ungated operators (detectSQLi,
        // detectXSS, size checks), so the fast path must be unavailable.
        assert!(!prefilter.all_body_rules_gated());
    }

    #[test]
    fn embedded_artifact_is_deterministic() {
        let first = Prefilter::from_json(EMBEDDED_ARTIFACT).expect("valid");
        let second = Prefilter::from_json(EMBEDDED_ARTIFACT).expect("valid");
        assert_eq!(first.automaton_count(), second.automaton_count());
        assert_eq!(first.gated_rule_ids(), second.gated_rule_ids());
    }

    #[cfg(all(feature = "coraza-native", unix))]
    #[test]
    fn removal_bound_matches_the_wire_abi() {
        assert_eq!(
            MAX_REMOVE_RULE_IDS,
            crate::waf::coraza_wire::MAX_REMOVE_RULE_IDS
        );
    }

    #[test]
    fn guest_artifact_copy_is_byte_identical() {
        // The Go reactor embeds this copy and the native sidecar reads it at
        // runtime. They must never skew from the host's canonical artifact.
        let guest = include_str!("../../wasm/coraza_reactor/rules/crs/prefilter.json");
        assert_eq!(EMBEDDED_ARTIFACT, guest);
    }

    #[test]
    fn clean_request_removes_every_gated_rule() {
        let prefilter = Prefilter::embedded().expect("embedded artifact is valid");
        let gate = prefilter.evaluate_inputs(&[b"name=alice&city=paris"]);
        assert!(gate.forced_reason.is_none());
        assert!(gate.matched_rules.is_empty());
        assert_eq!(gate.removable_rule_ids, prefilter.gated_rule_ids());
    }

    #[test]
    fn literal_hit_keeps_the_matching_rule() {
        let prefilter = simple(&["union", "select"], true, &["none"]);
        let gate = prefilter.evaluate_inputs(&[b"q=1%20UNION%20SELECT%20password"]);
        assert_eq!(gate.matched_rules, vec![942100]);
        assert!(gate.removable_rule_ids.is_empty());
    }

    #[test]
    fn dtd_forces_no_removals() {
        let prefilter = simple(&["script"], false, &["none"]);
        let gate = prefilter
            .evaluate_inputs(&[b"<!DOCTYPE x [<!ENTITY e SYSTEM \"file:///etc/passwd\">]>"]);
        assert!(gate.forced_reason.is_some());
        assert!(gate.removable_rule_ids.is_empty());
    }

    #[test]
    fn ungated_rules_are_never_removable() {
        let prefilter = Prefilter::from_artifact(artifact(
            vec![LiteralGroup {
                transforms: vec![],
                case_insensitive: false,
                literals: vec!["select".to_string()],
            }],
            true,
        ))
        .expect("prefilter builds");
        // 942100 is gated, 942101 is an ungated member of the same id space.
        let gate = prefilter.evaluate_inputs(&[b"benign"]);
        assert_eq!(gate.removable_rule_ids, vec![942100]);
        assert_eq!(
            prefilter.sanitize_remove_rule_ids(&[942100, 942101, 999999, 942100]),
            vec![942100]
        );
    }

    #[test]
    fn sanitize_bounds_the_removal_list() {
        let prefilter = Prefilter::embedded().expect("embedded artifact is valid");
        let ids = prefilter.gated_rule_ids().to_vec();
        // Duplicates and unknown ids collapse; the result is a subset of the
        // gated set and never exceeds the ABI bound.
        let mut noisy = ids.clone();
        noisy.extend_from_slice(&ids);
        noisy.extend([999999u32; 64]);
        let sanitized = prefilter.sanitize_remove_rule_ids(&noisy);
        assert_eq!(sanitized, ids);
        assert!(sanitized.len() <= MAX_REMOVE_RULE_IDS);
    }

    #[test]
    fn transform_identity_predicate_is_conservative() {
        let samples: &[&[u8]] = &[
            b"",
            b"plain",
            b"MixedCase",
            b"%41",
            b"a+b",
            b"a&b",
            b"a\\b",
            b"a/*b",
            b"a  b",
            b" a ",
            b"a/b",
            b"a\\b",
            b"a,b;c",
            b"\x00",
            b"\"'^",
            b"caf\xc3\xa9",
            b"..",
            b".",
            b"/a/../b",
        ];
        let transforms = [
            Transform::Lowercase,
            Transform::Uppercase,
            Transform::UrlDecode,
            Transform::UrlDecodeUni,
            Transform::RemoveNulls,
            Transform::ReplaceNulls,
            Transform::CompressWhitespace,
            Transform::RemoveWhitespace,
            Transform::Trim,
            Transform::TrimLeft,
            Transform::TrimRight,
            Transform::NormalizePath,
            Transform::NormalizePathWin,
            Transform::EscapeSeqDecode,
            Transform::ReplaceComments,
            Transform::JsDecode,
            Transform::CssDecode,
            Transform::HtmlEntityDecode,
            Transform::CmdLine,
        ];
        for transform in transforms {
            for sample in samples {
                if transform.is_identity_for(sample) {
                    assert_eq!(
                        transform.apply(sample),
                        *sample,
                        "{transform:?} claimed identity on {sample:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn transform_chain_skip_matches_naive() {
        let chains: &[&[&str]] = &[
            &[],
            &["lowercase"],
            &["urldecodeuni"],
            &["urldecodeuni", "lowercase"],
            &["htmlentitydecode", "lowercase"],
            &[
                "urldecodeuni",
                "htmlentitydecode",
                "jsdecode",
                "cssdecode",
                "removenulls",
            ],
            &["normalizepathwin"],
            &["cmdline", "normalizepath"],
            &["compresswhitespace", "removewhitespace"],
        ];
        let samples: &[&[u8]] = &[
            b"plain",
            b"MixedCase",
            b"%41%2f%2e%2e+",
            b"a&ltscript&gt",
            b"a\\u0041\\x41\\101",
            b"a/*comment*/b",
            b"a  b\t\nc",
            b" /a/../b//c/ ",
            b"cmd /c dir",
            b"\x00a\x00",
        ];
        for names in chains {
            let names: Vec<String> = names.iter().map(|name| (*name).to_string()).collect();
            let chain = TransformChain::parse(&names).expect("known transforms");
            for sample in samples {
                assert_eq!(
                    chain.apply_view(sample).as_ref(),
                    chain.apply_view_naive(sample),
                    "chain {names:?} disagreed on {sample:?}"
                );
            }
        }
    }
}
