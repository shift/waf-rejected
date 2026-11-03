//! Per-rule mandatory-literal gates for the native CRS engine.
//!
//! The offline extractor (`crate::waf::prefilter_extract`) proves, for a
//! subset of CRS regexes, that every string matching the pattern contains at
//! least one literal from a required set, **after** the rule's transform
//! chain. The engine uses that proof as a cheap disqualifier before it pays
//! for the transform pipeline or the regex:
//!
//! * literals are grouped by `(transform pipeline, case sensitivity)`, so each
//!   distinct representation of a candidate value is scanned once per phase
//!   and the hit set is cached by value;
//! * a rule whose required literals are absent from that representation is
//!   skipped without transforming or running the regex;
//! * rules the artifact marks ungated (negated operators, libinjection,
//!   unsupported patterns) are never assigned a gate and always run;
//! * a missing/unreadable artifact leaves every rule ungated.
//!
//! The automata are compiled once at load time and shared through
//! [`Program::gates`](crate::waf::rust_engine::Program::gates).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use serde::Deserialize;

use super::ir::{OperatorKind, Program, ProgramItem};
use super::transforms::Transform;

/// Embedded CRS literal artifact produced by `crs-prefilter-extract`.
pub const EMBEDDED_PREFILTER: &str = include_str!("../../../rules/crs/prefilter.json");

/// Maximum number of gated rules. A multi-word hit mask scales with this; rules
/// beyond the cap stay ungated (sound, just slower).
const MAX_GATED_RULES: usize = 256;

/// Bits in one [`GateMask`] word.
const MASK_BITS: usize = 64;

/// Words in a [`GateMask`]: enough for [`MAX_GATED_RULES`] gates.
pub(crate) const GATE_MASK_WORDS: usize = MAX_GATED_RULES / MASK_BITS;

/// Bitset of gate ids hit by one transformed candidate value.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GateMask([u64; GATE_MASK_WORDS]);

impl GateMask {
    #[inline]
    pub(crate) fn set(&mut self, gate: u16) {
        let index = usize::from(gate);
        self.0[index / MASK_BITS] |= 1u64 << (index % MASK_BITS);
    }

    #[inline]
    pub(crate) fn insert(&mut self, gate: GateMask) {
        for (word, extra) in self.0.iter_mut().zip(gate.0) {
            *word |= extra;
        }
    }

    #[inline]
    pub(crate) fn contains(&self, gate: u16) -> bool {
        let index = usize::from(gate);
        index < MAX_GATED_RULES && self.0[index / MASK_BITS] & (1u64 << (index % MASK_BITS)) != 0
    }
}

#[derive(Debug, Deserialize)]
struct Artifact {
    rules: Vec<ArtifactRule>,
}

#[derive(Debug, Deserialize)]
struct ArtifactRule {
    id: u32,
    #[serde(default)]
    gated: bool,
    #[serde(default)]
    body_relevant: bool,
    #[serde(default)]
    literal_groups: Vec<ArtifactGroup>,
}

#[derive(Debug, Deserialize)]
struct ArtifactGroup {
    #[serde(default)]
    transforms: Vec<String>,
    #[serde(default)]
    case_insensitive: bool,
    #[serde(default)]
    literals: Vec<String>,
}

/// One `(transform pipeline, case sensitivity)` scan group.
pub(crate) struct GateGroup {
    /// Prefix ids to resolve for the value before scanning. A full rule
    /// pipeline uses its whole plan; a multi-match prefix uses a one-element
    /// plan that resolves just that intermediate representation.
    pub(crate) plan: Vec<u32>,
    pub(crate) automaton: AhoCorasick,
    /// Pattern index -> mask of gate ids.
    pub(crate) pattern_rules: Vec<GateMask>,
}

/// Compiled per-rule gates shared by every request on an engine.
pub struct GateSet {
    groups: Vec<GateGroup>,
    /// Number of compiled gates; gate ids are dense indexes below this.
    gated_rules: usize,
}

impl std::fmt::Debug for GateSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GateSet")
            .field("gated_rules", &self.gated_rules)
            .field("groups", &self.groups.len())
            .finish()
    }
}

impl GateSet {
    /// Number of rules with a compiled gate.
    pub fn len(&self) -> usize {
        self.gated_rules
    }

    /// True when no rule is gated.
    pub fn is_empty(&self) -> bool {
        self.gated_rules == 0
    }

    /// True when `mask` contains a required literal for `gate`.
    #[inline]
    pub fn allows(&self, gate: u16, mask: GateMask) -> bool {
        mask.contains(gate)
    }

    pub(crate) fn groups(&self) -> &[GateGroup] {
        &self.groups
    }
}

/// Compiles gates for every regex rule in `program` that the artifact marks
/// gated, and annotates [`super::ir::CompiledRule::gate`].
pub fn attach(program: &mut Program) -> Result<Option<Arc<GateSet>>, String> {
    let artifact: Artifact = serde_json::from_str(EMBEDDED_PREFILTER)
        .map_err(|error| format!("prefilter artifact: {error}"))?;

    // Only positive regex operators that exist in this program are eligible.
    let mut eligible = BTreeSet::new();
    for items in [
        &program.phase1,
        &program.phase2,
        &program.phase3,
        &program.phase4,
        &program.phase5,
    ] {
        for item in items {
            let ProgramItem::Rule(group) = item else {
                continue;
            };
            for rule in &group.rules {
                let Some(id) = rule.id else {
                    continue;
                };
                let Some(operator) = rule.operator.as_ref() else {
                    continue;
                };
                if !operator.negated && matches!(operator.kind, OperatorKind::Rx(_)) {
                    eligible.insert(id);
                }
            }
        }
    }

    // Rules that evaluate every intermediate transform representation. Their
    // gate must scan every prefix of the pipeline, not just the final value.
    let mut multi_match = BTreeSet::new();
    for items in [
        &program.phase1,
        &program.phase2,
        &program.phase3,
        &program.phase4,
        &program.phase5,
    ] {
        for item in items {
            let ProgramItem::Rule(group) = item else {
                continue;
            };
            for rule in &group.rules {
                if let Some(id) = rule.id {
                    if rule.multi_match() {
                        multi_match.insert(id);
                    }
                }
            }
        }
    }

    // gate id -> (pipeline, case insensitive) -> literals
    type Pending = BTreeMap<u32, BTreeMap<(Vec<Transform>, bool), BTreeSet<Vec<u8>>>>;
    let mut pending: Pending = BTreeMap::new();
    for rule in artifact.rules {
        if !rule.gated || !eligible.contains(&rule.id) {
            continue;
        }
        // Header/URI gating is supported by the artifact, but the per-value
        // gate scan costs more than the small regexes it avoids on typical
        // header values. Body values are the ones large enough to amortise it.
        if !rule.body_relevant {
            continue;
        }
        // A multi-match rule evaluates every intermediate transform
        // representation; a single-representation gate would be unsound, and
        // scanning every prefix costs more than the regex it avoids. Keep
        // these rules ungated (they run).
        if multi_match.contains(&rule.id) {
            continue;
        }
        for group in rule.literal_groups {
            let Some(pipeline) = parse_pipeline(&group.transforms) else {
                continue;
            };
            let entry = pending
                .entry(rule.id)
                .or_default()
                .entry((pipeline, group.case_insensitive))
                .or_default();
            for literal in group.literals {
                if !literal.is_empty() {
                    entry.insert(literal.into_bytes());
                }
            }
        }
    }
    pending.retain(|_, groups| !groups.is_empty());

    // Merge literals by representation, attributing every literal to the rule
    // ids that need it. A rule is gated only when *every* one of its
    // representations is resolvable: dropping one group would lose a literal
    // that can legitimately match, which would be a false negative.
    type Merged = BTreeMap<(Vec<u32>, bool), BTreeMap<Vec<u8>, BTreeSet<u32>>>;
    let mut merged: Merged = BTreeMap::new();
    let mut covered_rules = BTreeSet::new();
    let mut failed_rules = BTreeSet::new();
    for (id, groups) in &pending {
        for ((chain, case_insensitive), literals) in groups {
            let plan = resolve_plan(program, chain);
            let Some(plan) = plan else {
                failed_rules.insert(*id);
                continue;
            };
            covered_rules.insert(*id);
            let entry = merged.entry((plan, *case_insensitive)).or_default();
            for literal in literals {
                entry.entry(literal.clone()).or_default().insert(*id);
            }
        }
    }
    for id in failed_rules {
        covered_rules.remove(&id);
    }

    let mut gate_for_rule: BTreeMap<u32, u16> = BTreeMap::new();
    for id in covered_rules {
        if gate_for_rule.len() >= MAX_GATED_RULES {
            break;
        }
        gate_for_rule.insert(id, gate_for_rule.len() as u16);
    }
    if gate_for_rule.is_empty() {
        return Ok(None);
    }

    let mut groups = Vec::with_capacity(merged.len());
    for ((plan, case_insensitive), patterns) in merged {
        let mut literals = Vec::with_capacity(patterns.len());
        let mut masks = Vec::with_capacity(patterns.len());
        for (literal, ids) in patterns {
            let mut mask = GateMask::default();
            for id in ids {
                if let Some(gate) = gate_for_rule.get(&id) {
                    mask.set(*gate);
                }
            }
            if mask != GateMask::default() {
                literals.push(literal);
                masks.push(mask);
            }
        }
        if literals.is_empty() {
            continue;
        }
        let automaton = AhoCorasickBuilder::new()
            .ascii_case_insensitive(case_insensitive)
            .match_kind(MatchKind::Standard)
            .build(&literals)
            .map_err(|error| format!("prefilter automaton: {error}"))?;
        groups.push(GateGroup {
            plan,
            automaton,
            pattern_rules: masks,
        });
    }
    if groups.is_empty() {
        return Ok(None);
    }

    let mut attached = 0usize;
    for items in [
        &mut program.phase1,
        &mut program.phase2,
        &mut program.phase3,
        &mut program.phase4,
        &mut program.phase5,
    ] {
        for item in items.iter_mut() {
            let ProgramItem::Rule(group) = item else {
                continue;
            };
            for rule in &mut group.rules {
                let Some(id) = rule.id else {
                    continue;
                };
                let Some(&gate) = gate_for_rule.get(&id) else {
                    continue;
                };
                rule.gate = Some(gate);
                attached += 1;
            }
        }
    }
    if attached == 0 {
        return Ok(None);
    }
    Ok(Some(Arc::new(GateSet {
        groups,
        gated_rules: gate_for_rule.len(),
    })))
}

/// Resolves a transform chain to the prefix ids the cache understands.
///
/// Full rule pipelines are plan entries of [`Program::transform_prefixes`].
/// Multi-match intermediates are only prefix table entries, so they resolve to
/// a one-element plan.
fn resolve_plan(program: &Program, chain: &[Transform]) -> Option<Vec<u32>> {
    if let Some(index) = program
        .pipelines
        .iter()
        .position(|candidate| candidate == chain)
    {
        return Some(program.transform_prefixes.plan(index).to_vec());
    }
    program
        .transform_prefixes
        .prefixes()
        .iter()
        .position(|candidate| candidate == chain)
        .and_then(|index| u32::try_from(index).ok())
        .map(|index| vec![index])
}

fn parse_pipeline(names: &[String]) -> Option<Vec<Transform>> {
    let mut pipeline = Vec::with_capacity(names.len());
    for name in names {
        match name.as_str() {
            "none" => continue,
            other => pipeline.push(Transform::parse(other)?),
        }
    }
    Some(pipeline)
}

#[cfg(test)]
mod tests {
    use super::{GateMask, GateSet};
    use crate::waf::rust_engine::{CompilePolicy, RustEngine};

    #[test]
    fn embedded_artifact_gates_crs_regexes() {
        let path = crate::waf::rust_engine::default_crs_conf_path();
        if !path.exists() {
            return;
        }
        let engine =
            RustEngine::from_conf_path_with_policy(&path, CompilePolicy::Report).expect("engine");
        let gates = engine.gate_set().expect("gates compiled");
        assert!(gates.len() > 30, "expected a useful gate set");
        assert_eq!(engine.gated_rule_count(), gates.len());
    }

    #[test]
    fn gate_skips_only_when_its_own_literal_is_present() {
        // Adversarial: rule 0 requires literal 0; a value that matched some
        // other rule's literal (bit 1) must still run rule 0. This is the
        // property that makes a missing literal impossible to skip.
        let gates = GateSet {
            groups: Vec::new(),
            gated_rules: 2,
        };
        let mut mask = GateMask::default();
        assert!(!gates.allows(0, mask));
        mask.set(1);
        assert!(!gates.allows(0, mask), "another rule's hit must not allow");
        assert!(gates.allows(1, mask));
        mask.set(0);
        assert!(gates.allows(0, mask));
        // Bit 2 was never assigned a rule: it can never allow an out-of-range
        // gate id.
        mask.set(200);
        assert!(!gates.allows(255, mask));
    }

    #[test]
    fn gates_do_not_change_decisions() {
        let path = crate::waf::rust_engine::default_crs_conf_path();
        if !path.exists() {
            return;
        }
        let engine =
            RustEngine::from_conf_path_with_policy(&path, CompilePolicy::Report).expect("engine");
        let headers = vec![
            ("Host".to_string(), "localhost".to_string()),
            ("User-Agent".to_string(), "OWASP CRS test agent".to_string()),
            (
                "Content-Type".to_string(),
                "application/x-www-form-urlencoded".to_string(),
            ),
            ("Content-Length".to_string(), "9".to_string()),
        ];
        let body = b"data=AAAAAAAA";
        let request = crate::waf::rust_engine::EngineRequest {
            method: "POST",
            uri: "/post",
            http_version: "HTTP/1.1",
            headers: &headers,
            body: Some(body),
        };
        let outcome = engine.evaluate_detailed(&request).expect("evaluate");
        assert!(outcome.regex_evaluations_skipped > 0);
        assert!(matches!(outcome.decision, crate::waf::Decision::Allow));
    }
}
