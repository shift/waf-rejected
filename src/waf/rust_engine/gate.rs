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

/// Maximum number of gated rules. A single `u64` hit mask keeps the per-value
/// cache compact; rules beyond the cap stay ungated (sound, just slower).
const MAX_GATED_RULES: usize = 64;

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
    /// Pipeline id into [`Program::pipelines`].
    pub(crate) pipeline: u16,
    pub(crate) automaton: AhoCorasick,
    /// Pattern index -> bitmask of gate ids.
    pub(crate) pattern_rules: Vec<u64>,
}

/// Compiled per-rule gates shared by every request on an engine.
pub struct GateSet {
    groups: Vec<GateGroup>,
    /// Gate id -> rule bit in a value hit mask.
    rule_masks: Vec<u64>,
}

impl std::fmt::Debug for GateSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GateSet")
            .field("gated_rules", &self.rule_masks.len())
            .field("groups", &self.groups.len())
            .finish()
    }
}

impl GateSet {
    /// Number of rules with a compiled gate.
    pub fn len(&self) -> usize {
        self.rule_masks.len()
    }

    /// True when no rule is gated.
    pub fn is_empty(&self) -> bool {
        self.rule_masks.is_empty()
    }

    /// True when `mask` contains a required literal for `gate`.
    #[inline]
    pub fn allows(&self, gate: u16, mask: u64) -> bool {
        self.rule_masks
            .get(usize::from(gate))
            .is_some_and(|rule| mask & rule != 0)
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
    for items in [&program.phase1, &program.phase2] {
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

    // gate id -> (pipeline, case insensitive) -> literals
    type Pending = BTreeMap<u32, BTreeMap<(Vec<Transform>, bool), BTreeSet<Vec<u8>>>>;
    let mut pending: Pending = BTreeMap::new();
    for rule in artifact.rules {
        if !rule.gated || !eligible.contains(&rule.id) {
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
    // ids that need it. Rules whose pipeline is not in the program are dropped
    // first so an uncompiled gate can never suppress a rule.
    type Merged = BTreeMap<(u16, bool), BTreeMap<Vec<u8>, BTreeSet<u32>>>;
    let mut merged: Merged = BTreeMap::new();
    let mut covered_rules = BTreeSet::new();
    for (id, groups) in &pending {
        for ((pipeline, case_insensitive), literals) in groups {
            let Some(pipeline_id) = program
                .pipelines
                .iter()
                .position(|candidate| candidate == pipeline)
            else {
                continue;
            };
            let Ok(pipeline_id) = u16::try_from(pipeline_id) else {
                continue;
            };
            covered_rules.insert(*id);
            let entry = merged.entry((pipeline_id, *case_insensitive)).or_default();
            for literal in literals {
                entry.entry(literal.clone()).or_default().insert(*id);
            }
        }
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
    let rule_masks: Vec<u64> = gate_for_rule.values().map(|gate| 1u64 << gate).collect();

    let mut groups = Vec::with_capacity(merged.len());
    for ((pipeline, case_insensitive), patterns) in merged {
        let mut literals = Vec::with_capacity(patterns.len());
        let mut masks = Vec::with_capacity(patterns.len());
        for (literal, ids) in patterns {
            let mut mask = 0u64;
            for id in ids {
                if let Some(gate) = gate_for_rule.get(&id) {
                    mask |= 1u64 << gate;
                }
            }
            if mask != 0 {
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
            pipeline,
            automaton,
            pattern_rules: masks,
        });
    }
    if groups.is_empty() {
        return Ok(None);
    }

    let mut attached = 0usize;
    for items in [&mut program.phase1, &mut program.phase2] {
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
    Ok(Some(Arc::new(GateSet { groups, rule_masks })))
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
    use super::*;
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
