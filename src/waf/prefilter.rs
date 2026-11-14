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
#[cfg(feature = "hyperscan-eval")]
use std::collections::BTreeSet;
use std::sync::OnceLock;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, AhoCorasickKind, MatchKind};
use memchr::memchr;

#[cfg(feature = "hyperscan-eval")]
use crate::waf::hyperscan::{HsError, LiteralPattern, SharedHsDatabase};
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
}

impl CompiledGroup {
    fn scan_prefix(&self) -> u32 {
        *self.plan.last().unwrap_or(&0)
    }
}

/// One Aho-Corasick automaton over the union of every literal with the same
/// case sensitivity, plus the groups that require each literal.
///
/// Scanning a representation once and attributing matches to the groups that
/// actually use that representation is equivalent to running one automaton per
/// group, but turns 84 passes into one pass per unique representation.
struct UnionAutomaton {
    automaton: AhoCorasick,
    /// Flattened per-pattern ownership and rule bitsets.
    patterns: PatternData,
}

/// Per-pattern bitsets. Attribution is a handful of word operations per match
/// instead of walking a group/rule list for every occurrence.
struct PatternData {
    group_words: usize,
    rule_words: usize,
    /// `patterns * group_words`: groups that need this literal's representation.
    group_bits: Box<[u64]>,
    /// `patterns * rule_words`: gated rules that require this literal.
    rule_bits: Box<[u64]>,
}

/// Literal -> (group index, rule ids) for one case sensitivity.
type LiteralGroups = BTreeMap<String, Vec<(u32, Vec<u32>)>>;

/// Pattern index -> (group index, rule ids) before the bitsets are built.
type PatternEntries = Vec<Vec<(u32, Vec<u32>)>>;

/// Reusable scan buffers (resolved group ranges and a group bitset).
#[derive(Default)]
struct ScanScratch {
    /// `(start, end, group index)` for every group, sorted by range.
    resolved: Vec<(u32, u32, u32)>,
    bits: Vec<u64>,
    /// Gated-rule hit bitset, accumulated across every input and group.
    matched_bits: Vec<u64>,
}

impl ScanScratch {
    fn reset_matched(&mut self, words: usize) {
        self.matched_bits.clear();
        self.matched_bits.resize(words.max(1), 0);
    }
}

/// One compiled Hyperscan database for a transform chain. Extraction is applied
/// once per representation and the same database is reused for every variant.
#[cfg(feature = "hyperscan-eval")]
struct HsChain {
    transforms: Vec<Transform>,
    database: SharedHsDatabase,
    required_byte: Option<u8>,
}

#[cfg(feature = "hyperscan-eval")]
type HsPendingGroups = BTreeMap<Vec<Transform>, BTreeMap<(String, bool), BTreeSet<u32>>>;

/// Production Hyperscan backend. Compiled once per process and shared via the
/// cached [`Prefilter`]. Empty when compilation failed; callers fall back to
/// the pure-Rust Aho-Corasick groups.
#[cfg(feature = "hyperscan-eval")]
struct HyperscanBackend {
    chains: Vec<HsChain>,
    patterns: usize,
    database_bytes: usize,
}

#[cfg(feature = "hyperscan-eval")]
impl std::fmt::Debug for HyperscanBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HyperscanBackend")
            .field("chains", &self.chains.len())
            .field("patterns", &self.patterns)
            .field("database_bytes", &self.database_bytes)
            .finish()
    }
}

/// A loaded prefilter.
pub struct Prefilter {
    groups: Vec<CompiledGroup>,
    /// Registered transform-chain prefixes. `prefixes[0]` is empty.
    prefixes: Vec<Vec<Transform>>,
    /// Parent prefix id for every prefix (parent-before-child order).
    prefix_parents: Vec<u32>,
    /// The step that turns a prefix's parent into the prefix itself.
    prefix_steps: Vec<Transform>,
    sensitive: Option<UnionAutomaton>,
    insensitive: Option<UnionAutomaton>,
    gated_rule_ids: Vec<u32>,
    ungated_body_rule_ids: Vec<u32>,
    all_body_rules_gated: bool,
    coverage: Coverage,
    /// Production Hyperscan backend. `None` when the feature is disabled or
    /// compilation failed; the Aho-Corasick groups are the bounded fallback.
    #[cfg(feature = "hyperscan-eval")]
    hyperscan: Option<HyperscanBackend>,
    /// Why Hyperscan is unavailable, for diagnostics and benchmarking.
    #[cfg(feature = "hyperscan-eval")]
    hyperscan_error: Option<String>,
}

impl std::fmt::Debug for Prefilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug = f.debug_struct("Prefilter");
        debug
            .field("groups", &self.groups.len())
            .field("gated_rules", &self.gated_rule_ids.len())
            .field("ungated_body_rules", &self.ungated_body_rule_ids.len())
            .field("all_body_rules_gated", &self.all_body_rules_gated);
        #[cfg(feature = "hyperscan-eval")]
        debug
            .field("hyperscan", &self.hyperscan)
            .field("hyperscan_error", &self.hyperscan_error);
        debug.finish()
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

    /// Parses an artifact and compiles only the pure-Rust Aho-Corasick
    /// automata. Used by the benchmark to measure the bounded fallback without
    /// paying the Hyperscan compile cost.
    #[cfg(feature = "hyperscan-eval")]
    pub fn from_json_aho(json: &str) -> Result<Self, PrefilterError> {
        let artifact: PrefilterArtifact = serde_json::from_str(json)?;
        Self::from_artifact_inner(artifact, false)
    }

    /// Compiles a parsed artifact.
    pub fn from_artifact(artifact: PrefilterArtifact) -> Result<Self, PrefilterError> {
        Self::from_artifact_inner(artifact, true)
    }

    fn from_artifact_inner(
        artifact: PrefilterArtifact,
        _use_hyperscan: bool,
    ) -> Result<Self, PrefilterError> {
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
        // Prefix tree: every prefix records its parent id and the step that
        // adds it, so one forward pass resolves the whole DAG per value.
        let mut prefix_parents: Vec<u32> = vec![u32::MAX];
        let mut prefix_steps: Vec<Transform> = vec![Transform::Identity];
        // One literal map per case sensitivity: literal -> (group, rules).
        let mut case_maps: [LiteralGroups; 2] = [BTreeMap::new(), BTreeMap::new()];
        for (index, (key, patterns)) in pending.into_iter().enumerate() {
            let mut plan = Vec::with_capacity(key.steps.len());
            for length in 1..=key.steps.len() {
                let prefix = key.steps[..length].to_vec();
                let parent = plan.last().copied().unwrap_or(0);
                let id = if let Some(&id) = prefix_index.get(&prefix) {
                    id
                } else {
                    let id = prefix_index.len() as u32;
                    prefix_index.insert(prefix, id);
                    prefix_parents.push(parent);
                    prefix_steps.push(key.steps[length - 1]);
                    id
                };
                plan.push(id);
            }
            let case = usize::from(key.case_insensitive);
            for (literal, ids) in patterns {
                case_maps[case]
                    .entry(literal)
                    .or_default()
                    .push((index as u32, ids.into_iter().collect()));
            }
            groups.push(CompiledGroup { plan });
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
            let (patterns, pattern_groups): (Vec<String>, PatternEntries) = map.into_iter().unzip();
            let group_words = groups.len().div_ceil(64).max(1);
            let rule_words = gated.len().div_ceil(64).max(1);
            let mut group_bits = vec![0u64; patterns.len() * group_words];
            let mut rule_bits = vec![0u64; patterns.len() * rule_words];
            for (pattern, entries) in pattern_groups.iter().enumerate() {
                for (group, rules) in entries {
                    group_bits[pattern * group_words + *group as usize / 64] |=
                        1u64 << (*group % 64);
                    for rule in rules {
                        if let Ok(index) = gated.binary_search(rule) {
                            rule_bits[pattern * rule_words + index / 64] |= 1u64 << (index % 64);
                        }
                    }
                }
            }
            let automaton = AhoCorasickBuilder::new()
                .ascii_case_insensitive(case_insensitive)
                .match_kind(MatchKind::Standard)
                .kind(Some(AhoCorasickKind::DFA))
                .build(&patterns)
                .map_err(|err| PrefilterError::Build(err.to_string()))?;
            Ok(Some(UnionAutomaton {
                automaton,
                patterns: PatternData {
                    group_words,
                    rule_words,
                    group_bits: group_bits.into_boxed_slice(),
                    rule_bits: rule_bits.into_boxed_slice(),
                },
            }))
        };
        // One case-insensitive automaton covers both case classes. Matching a
        // case-sensitive literal case-insensitively can only add hits, and a
        // hit only keeps a rule running; it never removes one. This halves the
        // automaton passes over every representation.
        let [mut combined_map, insensitive_map] = case_maps;
        for (literal, mut groups) in insensitive_map {
            combined_map.entry(literal).or_default().append(&mut groups);
        }
        let sensitive = build_union(combined_map, true)?;
        let insensitive = None;

        #[cfg(feature = "hyperscan-eval")]
        let (hyperscan, hyperscan_error) = if _use_hyperscan {
            match build_hyperscan_backend(&artifact) {
                Ok(backend) => (Some(backend), None),
                Err(err) => (None, Some(err)),
            }
        } else {
            (None, None)
        };

        let all_body_rules_gated =
            artifact.coverage.all_body_rules_gated && ungated_body.is_empty();
        Ok(Self {
            groups,
            prefixes,
            prefix_parents,
            prefix_steps,
            sensitive,
            insensitive,
            gated_rule_ids: gated,
            ungated_body_rule_ids: ungated_body,
            all_body_rules_gated,
            coverage: artifact.coverage,
            #[cfg(feature = "hyperscan-eval")]
            hyperscan,
            #[cfg(feature = "hyperscan-eval")]
            hyperscan_error,
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
        #[cfg(feature = "hyperscan-eval")]
        if let Some(backend) = &self.hyperscan {
            // Bounded fallback: a runtime error or unavailable platform falls
            // through to the pure-Rust automata below.
            if let Ok(Some(hit)) = evaluate_hyperscan(backend, body, true) {
                return hit;
            }
        }
        with_transform_cache(|cache| self.evaluate_with_cache(body, cache))
    }

    /// [`Self::evaluate`] with an explicit cache (benchmarks and callers that
    /// already own a per-request arena).
    pub fn evaluate_with_cache(&self, body: &[u8], cache: &mut TransformCache) -> PrefilterHit {
        cache.begin_request(self.prefixes.len());
        let words = self.gated_rule_ids.len().div_ceil(64);
        with_scan_scratch(|scratch| {
            scratch.reset_matched(words);
            let mut scanned = 0usize;
            let mut representations = 0usize;
            match self.scan_value(
                cache,
                body,
                scratch,
                &mut scanned,
                &mut representations,
                true,
            ) {
                Ok(hit) => PrefilterHit {
                    hit,
                    forced_reason: None,
                    scanned_bytes: scanned,
                    representations,
                    matched_rules: self.matched_rule_ids(&scratch.matched_bits),
                },
                Err(_) => PrefilterHit::forced(TRANSFORM_OVERFLOW),
            }
        })
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
        scratch: &mut ScanScratch,
        scanned: &mut usize,
        representations: &mut usize,
        stop_on_hit: bool,
    ) -> Result<bool, TransformError> {
        let value = cache.begin_value(input)?;
        cache.resolve_all(value, input, &self.prefix_steps, &self.prefix_parents)?;
        let ScanScratch {
            resolved,
            bits,
            matched_bits,
        } = scratch;
        resolved.clear();
        for (index, group) in self.groups.iter().enumerate() {
            let prefix = group.scan_prefix() as usize;
            let range = cache
                .prefix_range(value, prefix)
                .ok_or(TransformError::ArenaOverflow)?;
            resolved.push((range.start as u32, range.end as u32, index as u32));
        }
        resolved.sort_unstable();

        let group_words = self.groups.len().div_ceil(64).max(1);
        if bits.len() < group_words {
            bits.resize(group_words, 0);
        }
        let mut found = false;
        let mut index = 0usize;
        while index < resolved.len() {
            let (start, end, _) = resolved[index];
            let mut next = index + 1;
            while next < resolved.len() && resolved[next].0 == start && resolved[next].1 == end {
                next += 1;
            }
            bits[..group_words].fill(0);
            for &(_, _, group) in &resolved[index..next] {
                bits[group as usize / 64] |= 1u64 << (group % 64);
            }
            let representation = cache.bytes(start as usize..end as usize);
            *scanned += representation.len();
            *representations += 1;
            if self.scan_representation(
                representation,
                &bits[..group_words],
                false,
                matched_bits,
                stop_on_hit,
            ) {
                found = true;
            }
            if found && stop_on_hit {
                return Ok(true);
            }
            index = next;
        }
        Ok(found)
    }

    /// Scans one representation with the union automaton and keeps only the
    /// literals that belong to a group owning this representation.
    fn scan_representation(
        &self,
        representation: &[u8],
        groups: &[u64],
        case_insensitive: bool,
        matched_bits: &mut [u64],
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
        let data = &union.patterns;
        let mut found = false;
        for mat in union.automaton.find_overlapping_iter(representation) {
            let pattern = mat.pattern().as_usize();
            let group_at = pattern * data.group_words;
            let owns = data.group_bits[group_at..group_at + data.group_words]
                .iter()
                .zip(groups.iter())
                .any(|(pattern_groups, owner_groups)| pattern_groups & owner_groups != 0);
            if !owns {
                continue;
            }
            let rule_at = pattern * data.rule_words;
            for (target, source) in matched_bits
                .iter_mut()
                .zip(&data.rule_bits[rule_at..rule_at + data.rule_words])
            {
                *target |= *source;
            }
            found = true;
            if stop_on_hit {
                return true;
            }
        }
        found
    }

    /// Converts the accumulated rule bitset into the bounded, sorted rule-id
    /// list exposed by the public result types.
    fn matched_rule_ids(&self, bits: &[u64]) -> Vec<u32> {
        let mut ids = Vec::with_capacity(bits.len() * 4);
        for (word_index, word) in bits.iter().enumerate() {
            let mut word = *word;
            while word != 0 {
                let bit = word.trailing_zeros() as usize;
                let index = word_index * 64 + bit;
                if let Some(id) = self.gated_rule_ids.get(index) {
                    if ids.len() < MAX_REPORTED_RULES {
                        ids.push(*id);
                    }
                }
                word &= word - 1;
            }
        }
        ids
    }

    /// Diagnostics: run the union automata over one byte slice without any
    /// transform or attribution work.
    #[doc(hidden)]
    pub fn scan_bytes_for_bench(&self, bytes: &[u8]) -> usize {
        let mut hits = 0;
        if let Some(union) = &self.sensitive {
            hits += usize::from(union.automaton.is_match(bytes));
        }
        if let Some(union) = &self.insensitive {
            hits += usize::from(union.automaton.is_match(bytes));
        }
        hits
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

    /// True when the production Hyperscan backend compiled and is in use.
    #[cfg(feature = "hyperscan-eval")]
    pub fn hyperscan_active(&self) -> bool {
        self.hyperscan.is_some()
    }

    /// Why Hyperscan is unavailable, if compilation failed.
    #[cfg(feature = "hyperscan-eval")]
    pub fn hyperscan_error(&self) -> Option<&str> {
        self.hyperscan_error.as_deref()
    }

    /// Number of literal patterns compiled into Hyperscan databases.
    #[cfg(feature = "hyperscan-eval")]
    pub fn hyperscan_pattern_count(&self) -> usize {
        self.hyperscan
            .as_ref()
            .map_or(0, |backend| backend.patterns)
    }

    /// Total size of the compiled Hyperscan databases in bytes.
    #[cfg(feature = "hyperscan-eval")]
    pub fn hyperscan_database_bytes(&self) -> usize {
        self.hyperscan
            .as_ref()
            .map_or(0, |backend| backend.database_bytes)
    }

    /// Number of compiled Hyperscan transform-chain databases.
    #[cfg(feature = "hyperscan-eval")]
    pub fn hyperscan_chain_count(&self) -> usize {
        self.hyperscan
            .as_ref()
            .map_or(0, |backend| backend.chains.len())
    }

    /// Test-only: drop the Hyperscan backend to exercise the pure-Rust
    /// fallback path.
    #[cfg(all(test, feature = "hyperscan-eval"))]
    pub(crate) fn without_hyperscan(mut self) -> Self {
        self.hyperscan = None;
        self
    }

    fn gate_from_matched(&self, matched: Vec<u32>, scanned: usize) -> RuleGate {
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
        #[cfg(feature = "hyperscan-eval")]
        if let Some(backend) = &self.hyperscan {
            if let Ok((matched, scanned)) = evaluate_inputs_hyperscan(backend, inputs) {
                return self.gate_from_matched(matched, scanned);
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
        let words = self.gated_rule_ids.len().div_ceil(64);
        with_scan_scratch(|scratch| {
            scratch.reset_matched(words);
            let mut scanned = 0usize;
            for input in inputs {
                if input.is_empty() {
                    continue;
                }
                let mut representations = 0usize;
                if self
                    .scan_value(
                        cache,
                        input,
                        scratch,
                        &mut scanned,
                        &mut representations,
                        false,
                    )
                    .is_err()
                {
                    return transform_overflow_gate();
                }
            }
            let matched = self.matched_rule_ids(&scratch.matched_bits);

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
        })
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

    pub(crate) fn is_identity_for(self, input: &[u8]) -> bool {
        let step = match self {
            Extract::Identity => Transform::Identity,
            Extract::UrlDecode => Transform::UrlDecode,
            Extract::JsonUnescape => Transform::JsonUnescape,
            Extract::HtmlEntityDecode => Transform::HtmlEntityDecode,
        };
        step.is_identity_on(input)
    }

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

/// Applies a transform chain to an already-extracted view, skipping transforms
/// that are provably the identity on this input. This is the production fast
/// path used by both backends.
fn apply_transforms_view<'a>(transforms: &[Transform], input: &'a [u8]) -> Cow<'a, [u8]> {
    let mut current = Cow::Borrowed(input);
    for transform in transforms {
        if transform.is_identity_on(&current) {
            continue;
        }
        let mut output = Vec::new();
        transform.apply_into(&current, &mut output);
        current = Cow::Owned(output);
    }
    current
}

/// Computes a byte that every literal in a group must contain.
///
/// For case-insensitive groups each ASCII character contributes both cases, so
/// the returned byte may be checked case-insensitively. A `None` result means
/// the literals share no byte and no cheap skip is possible. The test is
/// conservative: a hit only means the group *might* match.
fn required_byte_for<'a>(patterns: impl Iterator<Item = &'a str>, caseless: bool) -> Option<u8> {
    let mut intersection: Option<[bool; 256]> = None;
    for literal in patterns {
        let mut set = [false; 256];
        for &byte in literal.as_bytes() {
            set[byte as usize] = true;
            if caseless && byte.is_ascii_alphabetic() {
                set[byte.to_ascii_lowercase() as usize] = true;
                set[byte.to_ascii_uppercase() as usize] = true;
            }
        }
        intersection = Some(match intersection {
            None => set,
            Some(previous) => {
                let mut next = [false; 256];
                for ((value, previous), current) in
                    next.iter_mut().zip(previous.iter()).zip(set.iter())
                {
                    *value = *previous && *current;
                }
                next
            }
        });
    }
    intersection.and_then(|set| (0..256).find(|&index| set[index]).map(|index| index as u8))
}

/// True when a representation contains the required byte, allowing for ASCII
/// case folding (safe over-approximation for case-insensitive groups).
fn representation_has_byte(haystack: &[u8], byte: u8) -> bool {
    haystack.contains(&byte)
        || (byte.is_ascii_alphabetic()
            && (haystack.contains(&byte.to_ascii_lowercase())
                || haystack.contains(&byte.to_ascii_uppercase())))
}

/// Builds the production Hyperscan backend from the artifact.
///
/// Databases are keyed by transform chain only: extraction is applied once per
/// representation and every chain is scanned against that view. This is the
/// same soundness contract as the Aho-Corasick groups, but the expensive
/// extraction and transform work is not repeated per group.
#[cfg(feature = "hyperscan-eval")]
fn build_hyperscan_backend(artifact: &PrefilterArtifact) -> Result<HyperscanBackend, String> {
    let mut pending: HsPendingGroups = BTreeMap::new();
    for gate in artifact.rules.iter().filter(|gate| gate.gated) {
        for literal_group in &gate.literal_groups {
            let transforms = parse_transforms(&literal_group.transforms)
                .map_err(|err| format!("hyperscan transform chain: {err}"))?;
            let entry = pending.entry(transforms).or_default();
            for literal in &literal_group.literals {
                if literal.is_empty() {
                    continue;
                }
                entry
                    .entry((literal.clone(), literal_group.case_insensitive))
                    .or_default()
                    .insert(gate.id);
            }
        }
    }

    let mut chains = Vec::with_capacity(pending.len());
    let mut patterns = 0usize;
    let mut database_bytes = 0usize;
    for (transforms, literals) in pending {
        let literal_patterns: Vec<LiteralPattern> = literals
            .into_iter()
            .map(|((literal, caseless), ids)| LiteralPattern {
                literal,
                caseless,
                rule_ids: ids.into_iter().collect(),
            })
            .collect();
        if literal_patterns.is_empty() {
            continue;
        }
        patterns += literal_patterns.len();
        let database = SharedHsDatabase::compile(&literal_patterns)
            .map_err(|err| format!("hyperscan compile failed: {err}"))?;
        database_bytes += database.database_size().unwrap_or(0);
        let required_byte = required_byte_for(
            literal_patterns
                .iter()
                .map(|pattern| pattern.literal.as_str()),
            literal_patterns.iter().any(|pattern| pattern.caseless),
        );
        chains.push(HsChain {
            transforms,
            database,
            required_byte,
        });
    }
    Ok(HyperscanBackend {
        chains,
        patterns,
        database_bytes,
    })
}

/// Scans one body with the production Hyperscan backend. Returns `Ok(None)` when
/// Hyperscan is unavailable or a scan error occurred; callers fall back to the
/// pure-Rust Aho-Corasick path.
#[cfg(feature = "hyperscan-eval")]
fn evaluate_hyperscan(
    backend: &HyperscanBackend,
    body: &[u8],
    first_only: bool,
) -> Result<Option<PrefilterHit>, HsError> {
    let mut scanned = 0usize;
    let mut representations = 0usize;
    for extract in Extract::ALL {
        let extracted = extract.apply(body);
        if extracted.is_empty() {
            continue;
        }
        representations += 1;
        for chain in &backend.chains {
            let view = apply_transforms_view(&chain.transforms, &extracted);
            scanned += view.len();
            if chain
                .required_byte
                .is_some_and(|byte| !representation_has_byte(&view, byte))
            {
                continue;
            }
            let matched = chain.database.scan(&view, first_only)?;
            if matched.hit {
                return Ok(Some(PrefilterHit {
                    hit: true,
                    forced_reason: None,
                    scanned_bytes: scanned,
                    representations,
                    matched_rules: matched.matched_rule_ids,
                }));
            }
        }
    }
    Ok(Some(PrefilterHit {
        hit: false,
        forced_reason: None,
        scanned_bytes: scanned,
        representations,
        matched_rules: Vec::new(),
    }))
}

/// Collects every matching rule id across all inputs, extractions and chains.
/// Unlike the boolean path this never terminates early, so per-rule removal
/// stays sound.
#[cfg(feature = "hyperscan-eval")]
fn evaluate_inputs_hyperscan(
    backend: &HyperscanBackend,
    inputs: &[&[u8]],
) -> Result<(Vec<u32>, usize), HsError> {
    let mut scanned = 0usize;
    let mut matched: Vec<u32> = Vec::new();
    for input in inputs {
        if input.is_empty() {
            continue;
        }
        for extract in Extract::ALL {
            let extracted = extract.apply(input);
            if extracted.is_empty() {
                continue;
            }
            for chain in &backend.chains {
                let view = apply_transforms_view(&chain.transforms, &extracted);
                scanned += view.len();
                if chain
                    .required_byte
                    .is_some_and(|byte| !representation_has_byte(&view, byte))
                {
                    continue;
                }
                let result = chain.database.scan(&view, false)?;
                if result.hit {
                    matched.extend(result.matched_rule_ids);
                }
            }
        }
    }
    matched.sort_unstable();
    matched.dedup();
    Ok((matched, scanned))
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
    // The only needles are `<!DOCTYPE`/`<!ENTITY`, so anchor on the rare `<`
    // instead of comparing a full window at every byte offset. This keeps the
    // mandatory pre-scan for DTD/entity declarations off the hot path.
    let first = needle[0];
    let mut start = 0usize;
    while let Some(offset) = memchr(first, &haystack[start..]) {
        let at = start + offset;
        if at + needle.len() > haystack.len() {
            return false;
        }
        if haystack[at..at + needle.len()].eq_ignore_ascii_case(needle) {
            return true;
        }
        start = at + 1;
    }
    false
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

    #[test]
    fn required_byte_is_intersection_of_literals() {
        assert_eq!(
            required_byte_for(["select", "script"].into_iter(), false),
            Some(b'c')
        );
        assert_eq!(required_byte_for(["abc", "def"].into_iter(), false), None);
        // Case-insensitive groups expand both cases, so a shared letter is
        // still a valid skip byte.
        assert!(required_byte_for(["Select", "SCRIPT"].into_iter(), true).is_some());
    }

    #[test]
    fn required_byte_check_is_case_insensitive_for_letters() {
        assert!(representation_has_byte(b"SELECT", b's'));
        assert!(representation_has_byte(b"select", b'S'));
        assert!(!representation_has_byte(b"select", b'z'));
    }

    #[test]
    fn extract_identity_predicate_is_conservative() {
        let samples: &[&[u8]] = &[
            b"",
            b"plain",
            b"%41",
            b"a+b",
            b"a\\b",
            b"a&b",
            "café".as_bytes(),
        ];
        for extract in Extract::ALL {
            for sample in samples {
                if extract.is_identity_for(sample) {
                    assert_eq!(
                        extract.apply(sample).as_ref(),
                        *sample,
                        "{extract:?} claimed identity on {sample:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn empty_input_does_not_hit() {
        let prefilter = simple(&["union", "select"], true, &["none"]);
        let hit = prefilter.evaluate(b"");
        assert!(!hit.hit);
        assert_eq!(hit.matched_rules, Vec::<u32>::new());
    }

    #[test]
    fn very_large_benign_input_does_not_hit() {
        let prefilter = simple(&["union", "select"], true, &["none"]);
        let body = vec![b'z'; 1024 * 1024];
        let hit = prefilter.evaluate(&body);
        // The pure-Rust transform arena may force full evaluation on a body
        // this large; that is safe. It must never report a literal hit.
        assert!(!hit.hit || hit.forced_reason.is_some());
    }

    #[test]
    fn unicode_literal_matches_utf8_bytes() {
        let prefilter = simple(&["café"], false, &["none"]);
        assert!(prefilter.evaluate("café".as_bytes()).hit);
        assert!(!prefilter.evaluate("cafe".as_bytes()).hit);
    }

    #[test]
    fn anchored_and_unanchored_literals_both_match() {
        let prefilter = simple(&["select"], false, &["none"]);
        assert!(prefilter.evaluate(b"select * from users").hit);
        assert!(prefilter.evaluate(b"q=1 select * from users").hit);
        assert!(!prefilter.evaluate(b"selec").hit);
    }

    #[test]
    fn case_insensitive_literal_matches_mixed_case() {
        let prefilter = simple(&["select"], true, &["none"]);
        assert!(prefilter.evaluate(b"SeLeCt").hit);
    }

    #[cfg(feature = "hyperscan-eval")]
    #[test]
    fn hyperscan_backend_is_active_for_embedded_artifact() {
        let prefilter = Prefilter::embedded().expect("embedded artifact is valid");
        assert!(
            prefilter.hyperscan_active(),
            "hyperscan unavailable: {:?}",
            prefilter.hyperscan_error()
        );
        assert!(prefilter.hyperscan_pattern_count() > 0);
        assert!(prefilter.hyperscan_chain_count() > 0);
    }

    #[cfg(feature = "hyperscan-eval")]
    #[test]
    fn hyperscan_matches_aho_on_edge_cases() {
        let prefilter = simple(&["union", "select", "café"], true, &["none"]);
        let fallback = simple(&["union", "select", "café"], true, &["none"]).without_hyperscan();
        assert!(prefilter.hyperscan_active());
        assert!(!fallback.hyperscan_active());

        let large = vec![b'z'; 256 * 1024];
        let cases: &[&[u8]] = &[
            b"",
            b"name=alice&city=paris",
            b"q=1%20UNION%20SELECT%20password",
            b"SeLeCt",
            "café".as_bytes(),
            b"selec",
            &large,
        ];
        for body in cases {
            let hs = prefilter.evaluate(body);
            let ac = fallback.evaluate(body);
            assert_eq!(hs.hit, ac.hit, "hit mismatch on {body:?}");
            assert_eq!(
                hs.matched_rules, ac.matched_rules,
                "rule mismatch on {body:?}"
            );
        }
    }

    #[cfg(feature = "hyperscan-eval")]
    #[test]
    fn hyperscan_fallback_keeps_removal_sound() {
        let prefilter = simple(&["union", "select"], true, &["none"]);
        let fallback = simple(&["union", "select"], true, &["none"]).without_hyperscan();
        let clean = prefilter.evaluate_inputs(&[b"name=alice"]);
        let clean_fallback = fallback.evaluate_inputs(&[b"name=alice"]);
        assert_eq!(clean.removable_rule_ids, clean_fallback.removable_rule_ids);
        assert_eq!(clean.matched_rules, clean_fallback.matched_rules);

        let attack = prefilter.evaluate_inputs(&[b"q=1 UNION SELECT password"]);
        let attack_fallback = fallback.evaluate_inputs(&[b"q=1 UNION SELECT password"]);
        assert_eq!(attack.matched_rules, attack_fallback.matched_rules);
        assert_eq!(
            attack.removable_rule_ids,
            attack_fallback.removable_rule_ids
        );
    }
}
