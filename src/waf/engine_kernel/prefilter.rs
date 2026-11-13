//! Compact prefilter layer built from `rules/crs/prefilter.json`.
//!
//! The offline CRS extractor proves that every match of a gated rule contains
//! at least one literal. The kernel uses that proof as a cheap disqualifier:
//! if no literal for a regex rule is present in any request value, the regex
//! group cannot match and is skipped. This is the same one-sided soundness
//! contract as `crs-prefilter`, but the data structures are request-local and
//! allocation-free.

use std::collections::BTreeMap;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use serde::Deserialize;

use super::state::{Arena, RequestInput};
use super::transform::Transform;

/// Embedded CRS literal artifact.
pub const EMBEDDED_PREFILTER: &str = include_str!("../../../rules/crs/prefilter.json");

#[derive(Debug, Deserialize)]
struct Artifact {
    rules: Vec<ArtifactRule>,
}

#[derive(Debug, Deserialize)]
struct ArtifactRule {
    id: u32,
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

/// One compiled gate group.
pub struct GateGroup {
    pipeline: Vec<Transform>,
    pipeline_index: usize,
    automaton: AhoCorasick,
    /// Pattern index -> gate indices.
    pattern_gates: Vec<Vec<usize>>,
}

/// Per-rule literal gates.
pub struct Prefilter {
    groups: Vec<GateGroup>,
    gate_for_rule: BTreeMap<u32, usize>,
    gate_count: usize,
}

impl Prefilter {
    /// Builds gates only for rules the kernel implements.
    pub fn build(implemented_rule_ids: &[u32]) -> Result<Self, String> {
        let artifact: Artifact = serde_json::from_str(EMBEDDED_PREFILTER)
            .map_err(|error| format!("prefilter artifact: {error}"))?;
        let implemented: std::collections::BTreeSet<u32> =
            implemented_rule_ids.iter().copied().collect();

        let mut gate_for_rule = BTreeMap::new();
        let mut pending: BTreeMap<GateKey, BTreeMap<String, Vec<usize>>> = BTreeMap::new();
        for rule in artifact.rules {
            if !rule.gated || !implemented.contains(&rule.id) {
                continue;
            }
            let mut any_group = false;
            let mut all_supported = true;
            for group in rule.literal_groups {
                let Some(pipeline) = parse_pipeline(&group.transforms) else {
                    // A gate is sound only if every literal group of the rule
                    // is modelled. If one is unsupported, leave the rule
                    // ungated so the regex always runs.
                    all_supported = false;
                    continue;
                };
                if group.literals.is_empty() {
                    continue;
                }
                let gate = if let Some(&gate) = gate_for_rule.get(&rule.id) {
                    gate
                } else {
                    let gate = gate_for_rule.len();
                    gate_for_rule.insert(rule.id, gate);
                    gate
                };
                any_group = true;
                let key = GateKey {
                    pipeline: pipeline.clone(),
                    case_insensitive: group.case_insensitive,
                };
                let entry = pending.entry(key).or_default();
                for literal in group.literals {
                    if !literal.is_empty() {
                        entry.entry(literal).or_default().push(gate);
                    }
                }
            }
            if !any_group || !all_supported {
                gate_for_rule.remove(&rule.id);
            }
        }

        let gate_count = gate_for_rule.len();
        let mut groups = Vec::with_capacity(pending.len());
        for (key, patterns) in pending {
            let (patterns, pattern_gates): (Vec<String>, Vec<Vec<usize>>) =
                patterns.into_iter().unzip();
            let automaton = AhoCorasickBuilder::new()
                .ascii_case_insensitive(key.case_insensitive)
                .match_kind(MatchKind::Standard)
                .build(&patterns)
                .map_err(|error| format!("prefilter automaton: {error}"))?;
            groups.push(GateGroup {
                pipeline: key.pipeline,
                pipeline_index: 0,
                automaton,
                pattern_gates,
            });
        }
        Ok(Self {
            groups,
            gate_for_rule,
            gate_count,
        })
    }

    /// Pipelines that the gate layer needs. The engine merges these into its
    /// per-value transform cache.
    pub fn pipelines(&self) -> Vec<Vec<Transform>> {
        let mut pipelines = Vec::new();
        for group in &self.groups {
            if !pipelines.iter().any(|pipeline| pipeline == &group.pipeline) {
                pipelines.push(group.pipeline.clone());
            }
        }
        pipelines
    }

    /// Resolves each gate group's pipeline to the engine's global pipeline id.
    pub fn bind(&mut self, global_pipelines: &[Vec<Transform>]) -> Result<(), String> {
        for group in &mut self.groups {
            group.pipeline_index = global_pipelines
                .iter()
                .position(|pipeline| pipeline == &group.pipeline)
                .ok_or_else(|| "prefilter pipeline was not merged".to_string())?;
        }
        Ok(())
    }

    pub fn gate_for_rule(&self) -> &BTreeMap<u32, usize> {
        &self.gate_for_rule
    }

    pub fn is_empty(&self) -> bool {
        self.groups.is_empty()
    }

    pub fn gate_count(&self) -> usize {
        self.gate_count
    }

    /// Scans every parsed value and records gate hits in the arena.
    pub fn scan(
        &self,
        request: &RequestInput<'_>,
        arena: &mut Arena,
        global_pipelines: &[Vec<Transform>],
    ) {
        if self.groups.is_empty() {
            return;
        }
        let mut hits = 0u64;
        for group in &self.groups {
            let pipeline = &global_pipelines[group.pipeline_index];
            for index in 0..arena.len() {
                let mask = {
                    let bytes = arena.transformed(request, index, group.pipeline_index, pipeline);
                    let mut mask = 0u64;
                    for found in group.automaton.find_iter(bytes) {
                        let pattern = found.pattern().as_usize();
                        if let Some(gates) = group.pattern_gates.get(pattern) {
                            for &gate in gates {
                                if gate < 64 {
                                    mask |= 1u64 << gate;
                                }
                            }
                        }
                    }
                    mask
                };
                hits |= mask;
            }
        }
        arena.add_gates(hits);
    }
}

fn parse_pipeline(names: &[String]) -> Option<Vec<Transform>> {
    let mut pipeline = Vec::with_capacity(names.len());
    for name in names {
        match name.as_str() {
            "none" => continue,
            other => pipeline.push(Transform::from_name(other)?),
        }
    }
    Some(pipeline)
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct GateKey {
    pipeline: Vec<Transform>,
    case_insensitive: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_artifact_compiles_gates_for_implemented_rules() {
        let prefilter = Prefilter::build(&[941110, 944130]).expect("prefilter");
        assert!(!prefilter.is_empty());
        assert!(prefilter.gate_for_rule().contains_key(&941110));
        assert!(prefilter.gate_for_rule().contains_key(&944130));
    }
}
