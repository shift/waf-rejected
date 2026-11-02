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
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::sync::OnceLock;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};

use crate::waf::prefilter_extract::{Coverage, PrefilterArtifact, SCHEMA_VERSION};
use crate::waf::transforms::{Transform, TransformCache, TransformError};

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

/// One logical (representation, transform, case) group.
struct CompiledGroup {
    /// Chain prefix ids for every step of this group's pipeline. Prefix 0 is
    /// the raw input; each later id adds one step.
    plan: Vec<u32>,
    case_insensitive: bool,
}

/// One Aho-Corasick automaton over the union of every literal with the same
/// case sensitivity, plus the groups that require each literal.
///
/// Scanning a representation once and attributing matches to the groups that
/// actually use that representation is equivalent to running one automaton per
/// group, but turns 84 passes into one pass per unique representation.
struct UnionAutomaton {
    automaton: AhoCorasick,
    /// Pattern index -> (group index, rule ids that require this literal).
    pattern_groups: PatternGroups,
}

/// Pattern index -> (group index, rule ids that require this literal).
type PatternGroups = Vec<Vec<(u32, Vec<u32>)>>;

/// Literal -> (group index, rule ids) for one case sensitivity.
type LiteralGroups = BTreeMap<String, Vec<(u32, Vec<u32>)>>;

/// Reusable scan buffers (resolved group ranges and a group bitset).
#[derive(Default)]
struct ScanScratch {
    /// `(start, end, group index)` for every group, sorted by range.
    resolved: Vec<(u32, u32, u32)>,
    bits: Vec<u64>,
}

/// A loaded prefilter.
pub struct Prefilter {
    groups: Vec<CompiledGroup>,
    /// Registered transform-chain prefixes. `prefixes[0]` is empty.
    prefixes: Vec<Vec<Transform>>,
    sensitive: Option<UnionAutomaton>,
    insensitive: Option<UnionAutomaton>,
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
                for extract in EXTRACT_STEPS {
                    let mut steps = Vec::with_capacity(1 + transforms.len());
                    steps.push(extract);
                    steps.extend(transforms.iter().copied());
                    let key = GroupKey {
                        steps,
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
        let mut prefix_index: BTreeMap<Vec<Transform>, u32> = BTreeMap::new();
        prefix_index.insert(Vec::new(), 0);
        // One literal map per case sensitivity: literal -> (group, rules).
        let mut case_maps: [LiteralGroups; 2] = [BTreeMap::new(), BTreeMap::new()];
        for (index, (key, patterns)) in pending.into_iter().enumerate() {
            let mut plan = Vec::with_capacity(key.steps.len());
            for length in 1..=key.steps.len() {
                let prefix = key.steps[..length].to_vec();
                let next = prefix_index.len() as u32;
                let id = *prefix_index.entry(prefix).or_insert(next);
                plan.push(id);
            }
            let case = usize::from(key.case_insensitive);
            for (literal, ids) in patterns {
                case_maps[case]
                    .entry(literal)
                    .or_default()
                    .push((index as u32, ids.into_iter().collect()));
            }
            groups.push(CompiledGroup {
                plan,
                case_insensitive: key.case_insensitive,
            });
        }
        let mut prefixes = vec![Vec::new(); prefix_index.len()];
        for (steps, id) in prefix_index {
            prefixes[id as usize] = steps;
        }

        let build_union = |map: LiteralGroups,
                           case_insensitive: bool|
         -> Result<Option<UnionAutomaton>, PrefilterError> {
            if map.is_empty() {
                return Ok(None);
            }
            let (patterns, pattern_groups): (Vec<String>, PatternGroups) = map.into_iter().unzip();
            let automaton = AhoCorasickBuilder::new()
                .ascii_case_insensitive(case_insensitive)
                .match_kind(MatchKind::Standard)
                .build(&patterns)
                .map_err(|err| PrefilterError::Build(err.to_string()))?;
            Ok(Some(UnionAutomaton {
                automaton,
                pattern_groups,
            }))
        };
        let [sensitive_map, insensitive_map] = case_maps;
        let sensitive = build_union(sensitive_map, false)?;
        let insensitive = build_union(insensitive_map, true)?;

        let all_body_rules_gated =
            artifact.coverage.all_body_rules_gated && ungated_body.is_empty();
        Ok(Self {
            groups,
            prefixes,
            sensitive,
            insensitive,
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
        with_transform_cache(|cache| self.evaluate_with_cache(body, cache))
    }

    /// [`Self::evaluate`] with an explicit cache (benchmarks and callers that
    /// already own a per-request arena).
    pub fn evaluate_with_cache(&self, body: &[u8], cache: &mut TransformCache) -> PrefilterHit {
        cache.begin_request(self.prefixes.len());
        let mut matched = Vec::new();
        let mut scanned = 0usize;
        let mut representations = 0usize;
        match self.scan_value(
            cache,
            body,
            &mut matched,
            &mut scanned,
            &mut representations,
            true,
        ) {
            Ok(true) => PrefilterHit {
                hit: true,
                forced_reason: None,
                scanned_bytes: scanned,
                representations,
                matched_rules: matched,
            },
            Ok(false) => PrefilterHit {
                hit: false,
                forced_reason: None,
                scanned_bytes: scanned,
                representations,
                matched_rules: Vec::new(),
            },
            Err(_) => PrefilterHit::forced(TRANSFORM_OVERFLOW),
        }
    }

    /// Resolves every group for one value, then scans each distinct
    /// representation once with the union automaton for its case sensitivity.
    ///
    /// Returns whether any literal of a group that owns the representation
    /// matched. When `stop_on_hit` is set, scanning stops at the first
    /// attributed match (the body-withhold path).
    fn scan_value(
        &self,
        cache: &mut TransformCache,
        input: &[u8],
        matched: &mut Vec<u32>,
        scanned: &mut usize,
        representations: &mut usize,
        stop_on_hit: bool,
    ) -> Result<bool, TransformError> {
        let value = cache.begin_value(input)?;
        with_scan_scratch(|scratch| {
            let ScanScratch { resolved, bits } = scratch;
            resolved.clear();
            for (index, group) in self.groups.iter().enumerate() {
                let range = cache.resolve(value, input, &group.plan, &self.prefixes)?;
                resolved.push((range.start as u32, range.end as u32, index as u32));
            }
            resolved.sort_unstable();

            let mut found = false;
            let mut index = 0usize;
            while index < resolved.len() {
                let (start, end, _) = resolved[index];
                let mut next = index + 1;
                while next < resolved.len() && resolved[next].0 == start && resolved[next].1 == end
                {
                    next += 1;
                }
                bits.fill(0);
                let mut has_sensitive = false;
                let mut has_insensitive = false;
                for &(_, _, group) in &resolved[index..next] {
                    let words = self.groups.len().div_ceil(64);
                    if bits.len() < words {
                        bits.resize(words, 0);
                    }
                    bits[group as usize / 64] |= 1u64 << (group % 64);
                    if self.groups[group as usize].case_insensitive {
                        has_insensitive = true;
                    } else {
                        has_sensitive = true;
                    }
                }
                let representation = cache.bytes(start as usize..end as usize);
                *scanned += representation.len();
                *representations += 1;
                if has_sensitive
                    && self.scan_representation(representation, bits, false, matched, stop_on_hit)
                {
                    found = true;
                }
                if has_insensitive
                    && self.scan_representation(representation, bits, true, matched, stop_on_hit)
                {
                    found = true;
                }
                if found && stop_on_hit {
                    return Ok(true);
                }
                index = next;
            }
            Ok(found)
        })
    }

    /// Scans one representation with the union automaton and keeps only the
    /// literals that belong to a group owning this representation.
    fn scan_representation(
        &self,
        representation: &[u8],
        groups: &[u64],
        case_insensitive: bool,
        matched: &mut Vec<u32>,
        stop_on_hit: bool,
    ) -> bool {
        let union = if case_insensitive {
            self.insensitive.as_ref()
        } else {
            self.sensitive.as_ref()
        };
        let Some(union) = union else {
            return false;
        };
        // `is_match` uses the DFA/prefilter path and is much faster than the
        // overlapping iterator. Clean values (the common case) stop here.
        if !union.automaton.is_match(representation) {
            return false;
        }
        let mut found = false;
        for mat in union.automaton.find_overlapping_iter(representation) {
            for (group, rules) in &union.pattern_groups[mat.pattern().as_usize()] {
                let bit = 1u64 << (group % 64);
                if groups
                    .get(*group as usize / 64)
                    .is_none_or(|word| word & bit == 0)
                {
                    continue;
                }
                for &rule in rules {
                    if !matched.contains(&rule) {
                        matched.push(rule);
                        if matched.len() >= MAX_REPORTED_RULES {
                            return true;
                        }
                    }
                }
                found = true;
            }
            if found && stop_on_hit {
                return true;
            }
        }
        found
    }

    /// Number of logical (representation × transform pipeline) groups.
    pub fn automaton_count(&self) -> usize {
        self.groups.len()
    }

    /// Number of physical Aho-Corasick automata (one per case sensitivity).
    pub fn union_automaton_count(&self) -> usize {
        usize::from(self.sensitive.is_some()) + usize::from(self.insensitive.is_some())
    }

    /// Number of distinct transform-chain prefixes, including the empty one.
    pub fn prefix_count(&self) -> usize {
        self.prefixes.len()
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
        with_transform_cache(|cache| self.evaluate_inputs_with_cache(inputs, cache))
    }

    /// [`Self::evaluate_inputs`] with an explicit cache.
    pub fn evaluate_inputs_with_cache(
        &self,
        inputs: &[&[u8]],
        cache: &mut TransformCache,
    ) -> RuleGate {
        cache.begin_request(self.prefixes.len());

        let mut scanned = 0usize;
        let mut matched: Vec<u32> = Vec::new();
        for input in inputs {
            if input.is_empty() {
                continue;
            }
            let mut representations = 0usize;
            if self
                .scan_value(
                    cache,
                    input,
                    &mut matched,
                    &mut scanned,
                    &mut representations,
                    false,
                )
                .is_err()
            {
                return transform_overflow_gate();
            }
        }
        matched.sort_unstable();
        matched.dedup();

        let mut removable_rule_ids =
            Vec::with_capacity(self.gated_rule_ids.len().min(MAX_REMOVE_RULE_IDS));
        removable_rule_ids.extend(
            self.gated_rule_ids
                .iter()
                .copied()
                .filter(|id| !matched.contains(id))
                .filter(|id| self.ungated_body_rule_ids.binary_search(id).is_err())
                .take(MAX_REMOVE_RULE_IDS),
        );

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
    /// Full pipeline: body-processor extraction followed by rule transforms.
    steps: Vec<Transform>,
    case_insensitive: bool,
}

/// The extraction variants a CRS body processor can apply to a value.
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
        let step = match self {
            Extract::Identity => Transform::Identity,
            Extract::UrlDecode => Transform::UrlDecode,
            Extract::JsonUnescape => Transform::JsonUnescape,
            Extract::HtmlEntityDecode => Transform::HtmlEntityDecode,
        };
        if step.is_identity_on(input) {
            Cow::Borrowed(input)
        } else {
            let mut output = Vec::new();
            step.apply_into(input, &mut output);
            Cow::Owned(output)
        }
    }
}

/// The extraction variants a CRS body processor can apply to a value.
const EXTRACT_STEPS: [Transform; 4] = [
    Transform::Identity,
    Transform::UrlDecode,
    Transform::JsonUnescape,
    Transform::HtmlEntityDecode,
];

/// Reason reported when the shared transform pipeline hits a bound.
const TRANSFORM_OVERFLOW: &str = "transform pipeline exceeded its bound";

fn transform_overflow_gate() -> RuleGate {
    RuleGate {
        forced_reason: Some(TRANSFORM_OVERFLOW),
        ..RuleGate::default()
    }
}

/// Per-thread reusable arena so `evaluate`/`evaluate_inputs` allocate nothing
/// per request after the first one. The cache is scoped to a single call.
fn with_transform_cache<R>(f: impl FnOnce(&mut TransformCache) -> R) -> R {
    thread_local! {
        static CACHE: RefCell<TransformCache> = RefCell::new(TransformCache::new());
    }
    CACHE.with(|cell| f(&mut cell.borrow_mut()))
}

/// Reusable per-thread scan buffers for the union-automaton pass.
fn with_scan_scratch<R>(f: impl FnOnce(&mut ScanScratch) -> R) -> R {
    thread_local! {
        static SCRATCH: RefCell<ScanScratch> = RefCell::new(ScanScratch::default());
    }
    SCRATCH.with(|cell| f(&mut cell.borrow_mut()))
}

fn parse_transforms(names: &[String]) -> Result<Vec<Transform>, PrefilterError> {
    let mut out = Vec::with_capacity(names.len());
    for name in names {
        if Transform::is_noop_name(name) {
            continue;
        }
        match Transform::from_rule_name(name) {
            Some(transform) => out.push(transform),
            None => return Err(PrefilterError::UnknownTransform(name.clone())),
        }
    }
    Ok(out)
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
    #[doc(hidden)]
    pub fn apply(&self, body: &[u8], extraction: usize) -> Vec<u8> {
        self.apply_view(&extract_view(body, extraction))
            .into_owned()
    }

    /// Apply the chain to an already-extracted view, skipping transforms that
    /// are provably the identity on this input.
    #[doc(hidden)]
    pub fn apply_view<'a>(&self, input: &'a [u8]) -> Cow<'a, [u8]> {
        let mut current = Cow::Borrowed(input);
        for transform in &self.transforms {
            if transform.is_identity_on(&current) {
                continue;
            }
            let mut output = Vec::new();
            transform.apply_into(&current, &mut output);
            current = Cow::Owned(output);
        }
        current
    }

    /// Apply the chain without the no-op skip, for an apples-to-apples
    /// comparison with the existing per-group prefilter.
    #[doc(hidden)]
    pub fn apply_view_naive(&self, input: &[u8]) -> Vec<u8> {
        let mut current = Cow::Borrowed(input);
        for transform in &self.transforms {
            let mut output = Vec::new();
            transform.apply_into(&current, &mut output);
            current = Cow::Owned(output);
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
pub fn extract_view(body: &[u8], extraction: usize) -> Cow<'_, [u8]> {
    Extract::ALL
        .get(extraction)
        .copied()
        .unwrap_or(Extract::Identity)
        .apply(body)
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

    fn apply(transform: Transform, input: &[u8]) -> Vec<u8> {
        let mut output = Vec::new();
        transform.apply_into(input, &mut output);
        output
    }

    #[test]
    fn cmd_line_matches_coraza() {
        // `cmdLine` removes spaces before `/` and `(`.
        assert_eq!(
            apply(Transform::CmdLine, b"CAT /etc/passwd"),
            b"cat/etc/passwd"
        );
        assert_eq!(
            apply(Transform::CmdLine, b"cat  /etc/passwd"),
            b"cat/etc/passwd"
        );
        assert_eq!(apply(Transform::CmdLine, b"cat (x)"), b"cat(x)");
        assert_eq!(apply(Transform::CmdLine, b"a;b,c"), b"a b c");
        assert_eq!(apply(Transform::CmdLine, b"a\"b'c\\d^e"), b"abcde");
    }

    #[test]
    fn html_entity_forms_decode_like_go() {
        assert_eq!(
            apply(Transform::HtmlEntityDecode, b"&lt;script"),
            b"<script"
        );
        assert_eq!(
            apply(Transform::HtmlEntityDecode, b"&#60;script"),
            b"<script"
        );
        assert_eq!(
            apply(Transform::HtmlEntityDecode, b"&#x3c;script"),
            b"<script"
        );
        assert_eq!(apply(Transform::HtmlEntityDecode, b"a&sol;b"), b"a/b");
        // `&hyphen;` is U+2010 (E2 80 90), not ASCII `-`; Coraza decodes it to
        // the Unicode hyphen.
        assert_eq!(
            apply(Transform::HtmlEntityDecode, b"a&hyphen;b"),
            b"a\xe2\x80\x90b"
        );
    }

    #[test]
    fn html_entity_transform_matches_legacy_forms() {
        let prefilter = simple(&["<script"], false, &["htmlentitydecode"]);
        assert!(prefilter.evaluate(b"q=&ltscript&gtscript").hit);
    }

    #[test]
    fn clean_path_matches_coraza_quirks() {
        assert_eq!(apply(Transform::NormalizePath, b"/a/b/../c"), b"/a/c");
        assert_eq!(apply(Transform::NormalizePath, b"a//b/./c/"), b"a/b/c/");
        assert_eq!(apply(Transform::NormalizePath, b""), b"");
        // Coraza re-appends the trailing slash, so "/" becomes "//".
        assert_eq!(apply(Transform::NormalizePath, b"/"), b"//");
        assert_eq!(apply(Transform::NormalizePath, b"../a"), b"../a");
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
                if transform.is_identity_on(sample) {
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
