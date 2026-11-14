//! Compilation of the rule DAG.
//!
//! Rules are grouped by `(phase, target mask, transform pipeline)`. Cheap
//! predicates become direct comparisons, literal rules share one Aho-Corasick
//! automaton, and regex rules share one precompiled DFA (or a `regex` set when
//! a pattern is too large for a dense DFA). Nothing is allocated while a rule
//! runs; the only mutable state is the request arena.

use std::collections::BTreeMap;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use memchr::memmem;
use regex::bytes::Regex;
use regex_automata::dfa::dense;
use regex_automata::dfa::regex::Regex as DfaRegex;

use super::rules::RuleDef;
use super::state::{Arena, RequestInput, TargetMask, ValueKind};
use super::transform::Transform;

/// Request phase. CRS phase 1 is headers/URI/protocol; phase 2 is the body and
/// parsed arguments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Phase {
    One,
    Two,
}

/// Rule matcher source.
#[derive(Debug, Clone, Copy)]
pub enum MatcherDef {
    Predicate(Predicate),
    Literal(&'static [&'static str]),
    Lines {
        lines: &'static str,
        case_insensitive: bool,
    },
    Regex(&'static str),
    /// A regex with a cheap literal disqualifier. If the guard is absent the
    /// regex cannot match, so the expensive scan is skipped.
    RegexGuarded {
        pattern: &'static str,
        guard: Guard,
    },
    RegexConjunction {
        first: &'static str,
        second: &'static str,
    },
}

/// A cheap, sound disqualifier for a regex.
#[derive(Debug, Clone, Copy)]
pub enum Guard {
    /// At least one needle must occur in the value.
    ContainsAny(&'static [&'static [u8]]),
    /// ASCII-case-insensitive variant of [`Guard::ContainsAny`].
    ContainsAnyAsciiCaseInsensitive(&'static [&'static [u8]]),
}

impl Guard {
    fn matches(self, haystack: &[u8]) -> bool {
        match self {
            Self::ContainsAny(needles) => needles
                .iter()
                .any(|needle| memmem::find(haystack, needle).is_some()),
            Self::ContainsAnyAsciiCaseInsensitive(needles) => needles.iter().any(|needle| {
                haystack
                    .windows(needle.len())
                    .any(|window| window.eq_ignore_ascii_case(needle))
            }),
        }
    }
}

/// Cheap request- or value-level predicate.
#[derive(Debug, Clone, Copy)]
pub enum Predicate {
    MethodAllowed(&'static [&'static str]),
    ContentTypeAllowed(&'static [&'static str]),
    Value {
        targets: TargetMask,
        predicate: ValuePredicate,
    },
}

/// Predicates evaluated as direct byte comparisons.
#[derive(Debug, Clone, Copy)]
pub enum ValuePredicate {
    ContainsByte(u8),
    MinLen(usize),
    MaxLen(usize),
    Prefix(&'static [u8]),
    Suffix(&'static [u8]),
    Enum(&'static [&'static str]),
}

/// One compiled rule's metadata.
#[derive(Debug, Clone, Copy)]
pub struct RuleMeta {
    pub id: u32,
    pub score: u16,
    pub description: &'static str,
}

/// A request-level predicate in evaluation order.
#[derive(Debug, Clone)]
pub struct RequestPredicate {
    pub phase: Phase,
    pub meta: RuleMeta,
    pub predicate: Predicate,
}

/// A value-level predicate in evaluation order.
#[derive(Debug, Clone)]
pub struct ValuePredicateRule {
    pub phase: Phase,
    pub meta: RuleMeta,
    pub targets: TargetMask,
    pub pipeline: usize,
    pub predicate: ValuePredicate,
}

/// A group of literal rules sharing one Aho-Corasick automaton.
pub struct LiteralGroup {
    pub phase: Phase,
    pub targets: TargetMask,
    pub pipeline: usize,
    pub automaton: AhoCorasick,
    /// Pattern index -> rule indices in [`LiteralGroup::rules`].
    pub pattern_rules: Vec<Vec<usize>>,
    pub rules: Vec<RuleMeta>,
}

/// A group of regex rules sharing one compiled matcher.
pub struct RegexGroup {
    pub phase: Phase,
    pub targets: TargetMask,
    pub pipeline: usize,
    pub matcher: RegexMatcher,
    /// Cheap disqualifier evaluated before the regex.
    pub guard: Option<Guard>,
    /// For chained rules: both matchers must match the same value.
    pub second: Option<RegexMatcher>,
    /// Matcher pattern index -> rule index in [`RegexGroup::rules`].
    pub rule_indices: Vec<usize>,
    pub rules: Vec<RuleMeta>,
    /// Prefilter gate per rule; `None` means the rule is ungated.
    pub gates: Vec<Option<usize>>,
}

/// Precompiled regex backend.
pub enum RegexMatcher {
    /// Dense DFA over all patterns in the group.
    Dfa(Box<DfaRegex>),
    /// One linear-time `regex` automaton per pattern. Used when a dense DFA
    /// would exceed the size budget.
    Fallback(Vec<Regex>),
}

type RegexDef = (RuleMeta, &'static str, Option<&'static str>);

impl std::fmt::Debug for RegexMatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Dfa(_) => f.write_str("Dfa"),
            Self::Fallback(patterns) => f.debug_tuple("Fallback").field(&patterns.len()).finish(),
        }
    }
}

impl RegexMatcher {
    fn find(&self, haystack: &[u8]) -> Option<usize> {
        match self {
            Self::Dfa(regex) => regex.find(haystack).map(|found| found.pattern().as_usize()),
            Self::Fallback(patterns) => patterns
                .iter()
                .position(|pattern| pattern.is_match(haystack)),
        }
    }

    fn is_match(&self, haystack: &[u8]) -> bool {
        self.find(haystack).is_some()
    }
}

/// The compiled engine rule set.
pub struct CompiledRules {
    pub pipelines: Vec<Vec<Transform>>,
    pub request_predicates: Vec<RequestPredicate>,
    pub value_predicates: Vec<ValuePredicateRule>,
    pub literal_groups: Vec<LiteralGroup>,
    pub regex_groups: Vec<RegexGroup>,
    pub rule_ids: Vec<u32>,
    /// Rule id -> prefilter gate index.
    pub gate_for_rule: BTreeMap<u32, usize>,
}

impl CompiledRules {
    /// Compiles the hand-written rule set.
    pub fn compile(
        defs: &[RuleDef],
        gate_for_rule: BTreeMap<u32, usize>,
        extra_pipelines: Vec<Vec<Transform>>,
    ) -> Result<Self, String> {
        let mut pipelines: Vec<Vec<Transform>> = vec![Vec::new()];
        for pipeline in extra_pipelines {
            if !pipelines.contains(&pipeline) {
                pipelines.push(pipeline);
            }
        }
        for def in defs {
            if !pipelines.iter().any(|pipeline| pipeline == def.pipeline) {
                pipelines.push(def.pipeline.to_vec());
            }
        }
        let pipeline_index = |pipeline: &[Transform]| -> usize {
            pipelines
                .iter()
                .position(|candidate| candidate.as_slice() == pipeline)
                .expect("pipeline registered")
        };

        let mut request_predicates = Vec::new();
        let mut value_predicates = Vec::new();
        let mut literal_defs: BTreeMap<LiteralKey, BTreeMap<String, Vec<usize>>> = BTreeMap::new();
        let mut literal_meta: BTreeMap<LiteralKey, Vec<RuleMeta>> = BTreeMap::new();
        let mut regex_defs: BTreeMap<RegexKey, Vec<RegexDef>> = BTreeMap::new();
        let mut guarded_defs: Vec<(RegexKey, RuleMeta, &'static str, Guard)> = Vec::new();

        for def in defs {
            let meta = RuleMeta {
                id: def.id,
                score: def.score,
                description: def.description,
            };
            match def.matcher {
                MatcherDef::Predicate(predicate @ Predicate::MethodAllowed(_))
                | MatcherDef::Predicate(predicate @ Predicate::ContentTypeAllowed(_)) => {
                    request_predicates.push(RequestPredicate {
                        phase: def.phase,
                        meta,
                        predicate,
                    });
                }
                MatcherDef::Predicate(Predicate::Value { targets, predicate }) => {
                    value_predicates.push(ValuePredicateRule {
                        phase: def.phase,
                        meta,
                        targets,
                        pipeline: pipeline_index(def.pipeline),
                        predicate,
                    });
                }
                MatcherDef::Literal(patterns) => {
                    let key = LiteralKey {
                        phase: def.phase,
                        targets: def.targets.0,
                        pipeline: pipeline_index(def.pipeline),
                        case_insensitive: false,
                    };
                    let entry = literal_defs.entry(key).or_default();
                    let meta_entry = literal_meta.entry(key).or_default();
                    let rule_index = meta_entry.len();
                    meta_entry.push(meta);
                    for pattern in patterns {
                        if !pattern.is_empty() {
                            entry
                                .entry((*pattern).to_string())
                                .or_default()
                                .push(rule_index);
                        }
                    }
                }
                MatcherDef::Lines {
                    lines,
                    case_insensitive,
                } => {
                    let key = LiteralKey {
                        phase: def.phase,
                        targets: def.targets.0,
                        pipeline: pipeline_index(def.pipeline),
                        case_insensitive,
                    };
                    let entry = literal_defs.entry(key).or_default();
                    let meta_entry = literal_meta.entry(key).or_default();
                    let rule_index = meta_entry.len();
                    meta_entry.push(meta);
                    for line in lines.lines() {
                        let line = line.trim();
                        if line.is_empty() || line.starts_with('#') {
                            continue;
                        }
                        entry.entry(line.to_string()).or_default().push(rule_index);
                    }
                }
                MatcherDef::Regex(pattern) => {
                    let key = RegexKey {
                        phase: def.phase,
                        targets: def.targets.0,
                        pipeline: pipeline_index(def.pipeline),
                    };
                    regex_defs
                        .entry(key)
                        .or_default()
                        .push((meta, pattern, None));
                }
                MatcherDef::RegexGuarded { pattern, guard } => {
                    let key = RegexKey {
                        phase: def.phase,
                        targets: def.targets.0,
                        pipeline: pipeline_index(def.pipeline),
                    };
                    guarded_defs.push((key, meta, pattern, guard));
                }
                MatcherDef::RegexConjunction { first, second } => {
                    let key = RegexKey {
                        phase: def.phase,
                        targets: def.targets.0,
                        pipeline: pipeline_index(def.pipeline),
                    };
                    regex_defs
                        .entry(key)
                        .or_default()
                        .push((meta, first, Some(second)));
                }
            }
        }

        request_predicates.sort_by_key(|rule| rule.meta.id);
        value_predicates.sort_by_key(|rule| rule.meta.id);

        let mut literal_groups = Vec::with_capacity(literal_defs.len());
        for (key, patterns) in literal_defs {
            let rules = literal_meta.remove(&key).unwrap_or_default();
            let (patterns, pattern_rules): (Vec<String>, Vec<Vec<usize>>) =
                patterns.into_iter().unzip();
            let automaton = AhoCorasickBuilder::new()
                .ascii_case_insensitive(key.case_insensitive)
                .match_kind(MatchKind::Standard)
                .build(&patterns)
                .map_err(|error| format!("literal automaton: {error}"))?;
            literal_groups.push(LiteralGroup {
                phase: key.phase,
                targets: TargetMask(key.targets),
                pipeline: key.pipeline,
                automaton,
                pattern_rules,
                rules,
            });
        }
        literal_groups.sort_by_key(|group| {
            (
                group.phase,
                group.targets.0,
                group.pipeline,
                group.rules.first().map(|rule| rule.id).unwrap_or(0),
            )
        });

        let mut regex_groups = Vec::with_capacity(regex_defs.len());
        for (key, defs) in regex_defs {
            let rules: Vec<RuleMeta> = defs.iter().map(|(meta, _, _)| *meta).collect();
            let first_patterns: Vec<&str> = defs.iter().map(|(_, first, _)| *first).collect();
            let second_patterns: Option<Vec<&str>> = defs
                .iter()
                .map(|(_, _, second)| *second)
                .collect::<Option<Vec<_>>>();
            let matcher = build_regex(&first_patterns)?;
            let second = match second_patterns {
                Some(patterns) => Some(build_regex(&patterns)?),
                None => None,
            };
            let rule_indices: Vec<usize> = (0..rules.len()).collect();
            let gates = rules
                .iter()
                .map(|rule| gate_for_rule.get(&rule.id).copied())
                .collect();
            regex_groups.push(RegexGroup {
                phase: key.phase,
                targets: TargetMask(key.targets),
                pipeline: key.pipeline,
                matcher,
                guard: None,
                second,
                rule_indices,
                rules,
                gates,
            });
        }
        for (key, meta, pattern, guard) in guarded_defs {
            let matcher = build_regex(&[pattern])?;
            let gates = vec![gate_for_rule.get(&meta.id).copied()];
            regex_groups.push(RegexGroup {
                phase: key.phase,
                targets: TargetMask(key.targets),
                pipeline: key.pipeline,
                matcher,
                guard: Some(guard),
                second: None,
                rule_indices: vec![0],
                rules: vec![meta],
                gates,
            });
        }
        regex_groups.sort_by_key(|group| {
            (
                group.phase,
                group.targets.0,
                group.pipeline,
                group.rules.first().map(|rule| rule.id).unwrap_or(0),
            )
        });

        let mut rule_ids: Vec<u32> = defs.iter().map(|rule| rule.id).collect();
        rule_ids.sort_unstable();
        rule_ids.dedup();

        Ok(Self {
            pipelines,
            request_predicates,
            value_predicates,
            literal_groups,
            regex_groups,
            rule_ids,
            gate_for_rule,
        })
    }

    /// Number of transform pipelines that may be cached per value.
    pub fn pipeline_count(&self) -> usize {
        self.pipelines.len()
    }

    /// Evaluates request-level predicates for one phase. Returns the first
    /// matching rule.
    pub fn match_request_predicate(
        &self,
        phase: Phase,
        request: &RequestInput<'_>,
    ) -> Option<RuleMeta> {
        for rule in &self.request_predicates {
            if rule.phase != phase {
                continue;
            }
            let matched = match rule.predicate {
                Predicate::MethodAllowed(allowed) => !allowed.contains(&request.method),
                Predicate::ContentTypeAllowed(allowed) => {
                    let Some((_, value)) = request
                        .headers
                        .iter()
                        .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
                    else {
                        continue;
                    };
                    let mime = value.split(';').next().unwrap_or("").trim();
                    !mime.is_empty() && !allowed.contains(&mime.to_ascii_lowercase().as_str())
                }
                Predicate::Value { .. } => false,
            };
            if matched {
                return Some(rule.meta);
            }
        }
        None
    }

    /// Evaluates value-level predicates for one phase.
    pub fn match_value_predicate(
        &self,
        phase: Phase,
        request: &RequestInput<'_>,
        arena: &mut Arena,
    ) -> Option<RuleMeta> {
        for rule in &self.value_predicates {
            if rule.phase != phase {
                continue;
            }
            let pipeline = &self.pipelines[rule.pipeline];
            let mut matched = false;
            for index in 0..arena.len() {
                let value = arena.value_at(index);
                if !rule.targets.matches(value) {
                    continue;
                }
                let bytes = arena.transformed(request, index, rule.pipeline, pipeline);
                if value_predicate_matches(rule.predicate, bytes) {
                    matched = true;
                    break;
                }
            }
            if matched {
                return Some(rule.meta);
            }
        }
        None
    }

    /// Evaluates literal groups for one phase.
    pub fn match_literal_group(
        &self,
        phase: Phase,
        request: &RequestInput<'_>,
        arena: &mut Arena,
    ) -> Option<RuleMeta> {
        for group in &self.literal_groups {
            if group.phase != phase {
                continue;
            }
            let pipeline = &self.pipelines[group.pipeline];
            for index in 0..arena.len() {
                let value = arena.value_at(index);
                if !group.targets.matches(value) {
                    continue;
                }
                let bytes = arena.transformed(request, index, group.pipeline, pipeline);
                if let Some(found) = group.automaton.find_iter(bytes).next() {
                    let pattern = found.pattern().as_usize();
                    if let Some(rule_index) = group
                        .pattern_rules
                        .get(pattern)
                        .and_then(|rules| rules.first())
                    {
                        return group.rules.get(*rule_index).copied();
                    }
                }
            }
        }
        None
    }

    /// Evaluates regex groups for one phase.
    ///
    /// A group is skipped when every rule in it has a prefilter gate and no
    /// gate hit was recorded for this request.
    pub fn match_regex_group(
        &self,
        phase: Phase,
        request: &RequestInput<'_>,
        arena: &mut Arena,
    ) -> Option<RuleMeta> {
        for group in &self.regex_groups {
            if group.phase != phase {
                continue;
            }
            if group.gates.iter().all(Option::is_some)
                && !group
                    .gates
                    .iter()
                    .flatten()
                    .any(|gate| arena.gate_hit(*gate))
            {
                continue;
            }
            let pipeline = &self.pipelines[group.pipeline];
            for index in 0..arena.len() {
                let value = arena.value_at(index);
                if !group.targets.matches(value) {
                    continue;
                }
                let bytes = arena.transformed(request, index, group.pipeline, pipeline);
                if let Some(guard) = group.guard {
                    if !guard.matches(bytes) {
                        continue;
                    }
                }
                let Some(pattern) = group.matcher.find(bytes) else {
                    continue;
                };
                if let Some(second) = &group.second {
                    if !second.is_match(bytes) {
                        continue;
                    }
                }
                let rule_index = group.rule_indices.get(pattern).copied().unwrap_or(pattern);
                if let Some(rule) = group.rules.get(rule_index) {
                    return Some(*rule);
                }
            }
        }
        None
    }
}

fn value_predicate_matches(predicate: ValuePredicate, bytes: &[u8]) -> bool {
    match predicate {
        ValuePredicate::ContainsByte(needle) => bytes.contains(&needle),
        ValuePredicate::MinLen(minimum) => bytes.len() >= minimum,
        ValuePredicate::MaxLen(maximum) => bytes.len() <= maximum,
        ValuePredicate::Prefix(prefix) => bytes.starts_with(prefix),
        ValuePredicate::Suffix(suffix) => bytes.ends_with(suffix),
        ValuePredicate::Enum(values) => values.iter().any(|value| value.as_bytes() == bytes),
    }
}

fn build_regex(patterns: &[&str]) -> Result<RegexMatcher, String> {
    let dfa_ok = patterns.len() <= 8 && patterns.iter().all(|pattern| pattern.len() <= 4096);
    if dfa_ok {
        let mut builder = DfaRegex::builder();
        builder.dense(
            dense::Config::new()
                .dfa_size_limit(Some(4 * 1024 * 1024))
                .minimize(true),
        );
        if let Ok(regex) = builder.build_many(patterns) {
            return Ok(RegexMatcher::Dfa(Box::new(regex)));
        }
    }
    let mut compiled = Vec::with_capacity(patterns.len());
    for pattern in patterns {
        compiled.push(Regex::new(pattern).map_err(|error| format!("regex `{pattern}`: {error}"))?);
    }
    Ok(RegexMatcher::Fallback(compiled))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct LiteralKey {
    phase: Phase,
    targets: u16,
    pipeline: usize,
    case_insensitive: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct RegexKey {
    phase: Phase,
    targets: u16,
    pipeline: usize,
}

/// True when a value is a body/argument value (used by tests and diagnostics).
pub fn is_body_value(value: super::state::ValueRef) -> bool {
    matches!(
        value.kind,
        ValueKind::Body | ValueKind::ArgName | ValueKind::ArgValue
    )
}
