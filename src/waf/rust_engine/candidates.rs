//! Multi-pattern candidate gate for the residual engine regex subset.
//!
//! The literal prefilter ([`super::gate`]) proves that a rule cannot match when
//! a required literal is absent. It only covers rules where the offline
//! extractor could derive such a literal. Every other `@rx` rule still runs its
//! own `regex` automaton for every candidate value.
//!
//! This module replaces those per-rule scans with one Vectorscan/Hyperscan
//! block-mode scan per `(transform pipeline)` group:
//!
//! * at load time every positive, non-negated `@rx` without a literal gate is
//!   collected into a database keyed by `(target eligibility, transform
//!   pipeline)` — in practice the rule's own pipeline, so one scan serves
//!   every rule that targets the same value with the same transform chain;
//! * pattern ids map back to the rule's candidate-gate id;
//! * at request time the transformed value is scanned once per `(value,
//!   pipeline)` and the hit set is cached for the phase, just like the literal
//!   gate mask;
//! * a rule whose pattern did not hit is skipped with the same
//!   `regex_evaluations_skipped` counter;
//! * a pattern that cannot be represented, a database that exceeds its size
//!   budget, or a runtime scan error leaves the rule **ungated**, so the
//!   existing per-rule regex path runs unchanged.
//!
//! # Soundness
//!
//! The contract is one-sided: a database may report a hit where the reference
//! engine would not, but it must never omit a hit that the real regex would
//! produce. Patterns with constructs whose byte semantics could differ
//! (Unicode properties, backreferences, lookaround, atomic/conditional groups,
//! embedded end anchors, NUL bytes, non-ASCII text) are excluded before
//! compilation, mirroring the parser's `(?sm)(?-u)` compile settings with the
//! `DOTALL`/`MULTILINE` flags. The rest are compiled in exact mode; any
//! compile failure leaves the whole group on the per-rule path.
//!
//! This is a *candidate* pass only. A hit does not mean the rule matched; it
//! only means the full per-rule operator (and therefore captures,
//! `MATCHED_VARS` and anomaly scoring) must run.
//!
//! # Platform
//!
//! Vectorscan accelerates this path on x86-64 with SSSE3/AVX2. The library is
//! provided by `nixpkgs#vectorscan` and linked only when the non-default
//! `hyperscan-eval` feature is enabled. On an unsupported CPU
//! `hs_valid_platform()` fails and the engine keeps the existing path.

use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::waf::hyperscan::{RegexPattern, SharedHsDatabase};

use super::ir::{OperatorKind, Program, ProgramItem};

/// Upper bound on rules covered by the candidate pass. The per-value hit mask
/// is a 4-word bitset (32 bytes), allocated only for values that reach a
/// candidate-gated rule.
const MAX_CANDIDATE_RULES: usize = 256;
/// A single database larger than this is dropped (rules stay ungated).
const MAX_GROUP_DB_BYTES: usize = 16 * 1024 * 1024;
/// Total compiled database budget across all groups.
const MAX_TOTAL_DB_BYTES: usize = 64 * 1024 * 1024;
/// Values shorter than this keep the per-rule path. For a few dozen bytes the
/// regex is already cheap and the scan/setup overhead would dominate.
pub(crate) const MIN_VALUE_BYTES: usize = 2048;
/// Soft wall-clock ceiling for the whole compile, checked between groups.
/// Load-time only; when exceeded the remaining rules are left ungated, never
/// skipped. A single in-flight Vectorscan compile is not interruptible.
const COMPILE_DEADLINE: Duration = Duration::from_millis(5_000);

/// One Vectorscan database for a transform pipeline.
pub(crate) struct HsGroup {
    /// Index into [`Program::pipelines`].
    pub(crate) pipeline: u16,
    pub(crate) database: SharedHsDatabase,
}

/// Process-wide candidate gate set. Immutable after load, shared via `Arc`.
pub struct HsCandidateSet {
    groups: Vec<HsGroup>,
    /// Candidate-gate id -> rule id. Index is the bit position.
    rule_ids: Vec<u32>,
    /// Rule id -> candidate-gate id (only covered rules).
    gate_for_rule: BTreeMap<u32, u16>,
    words: usize,
    patterns: usize,
    database_bytes: usize,
    compile_micros: u64,
}

impl std::fmt::Debug for HsCandidateSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HsCandidateSet")
            .field("rules", &self.rule_ids.len())
            .field("groups", &self.groups.len())
            .field("patterns", &self.patterns)
            .field("database_bytes", &self.database_bytes)
            .field("compile_micros", &self.compile_micros)
            .finish()
    }
}

impl HsCandidateSet {
    /// Number of rules covered by the candidate pass.
    pub fn rule_count(&self) -> usize {
        self.rule_ids.len()
    }

    /// Number of compiled databases (one per transform pipeline).
    pub fn group_count(&self) -> usize {
        self.groups.len()
    }

    /// Number of compiled patterns across all databases.
    pub fn pattern_count(&self) -> usize {
        self.patterns
    }

    /// Total compiled database size in bytes.
    pub fn database_bytes(&self) -> usize {
        self.database_bytes
    }

    /// Load-time compile cost.
    pub fn compile_micros(&self) -> u64 {
        self.compile_micros
    }

    /// Number of `u64` words in a per-value hit mask.
    pub fn words(&self) -> usize {
        self.words
    }

    /// Database for a transform pipeline, when one compiled.
    #[inline]
    pub(crate) fn group(&self, pipeline: u16) -> Option<&HsGroup> {
        self.groups.iter().find(|group| group.pipeline == pipeline)
    }

    /// Candidate gate id for a rule id, if the rule compiled.
    #[inline]
    pub(crate) fn gate_for_rule(&self, id: u32) -> Option<u16> {
        self.gate_for_rule.get(&id).copied()
    }

    /// Sets the bit for `rule_id` in `mask` when the rule is covered.
    #[inline]
    pub(crate) fn set_rule(&self, mask: &mut [u64], rule_id: u32) {
        if let Some(gate) = self.gate_for_rule(rule_id) {
            let gate = usize::from(gate);
            if let Some(word) = mask.get_mut(gate / 64) {
                *word |= 1u64 << (gate % 64);
            }
        }
    }
}

/// Pipeline index -> expression -> rules that use it.
type Pending = BTreeMap<u16, BTreeMap<String, BTreeSet<u32>>>;

/// A compiled group before candidate-gate ids are assigned.
struct CompiledGroup {
    pipeline: u16,
    database: SharedHsDatabase,
    pattern_rules: Vec<Vec<u32>>,
}

/// Compiles candidate databases for every eligible regex rule and annotates
/// [`super::ir::CompiledRule::hs_gate`].
///
/// This never fails the load: any error leaves the affected rules on the
/// existing per-rule path and returns `None` when nothing compiled.
pub fn attach(program: &mut Program) -> Option<Arc<HsCandidateSet>> {
    let started = Instant::now();
    let pending = collect(program);
    if pending.is_empty() {
        return None;
    }

    // Database compilation is the startup cost (~seconds for the full CRS
    // subset). Cache the immutable set process-wide so a second engine load
    // with the same rule/pipeline mapping reuses it.
    let key = pending_key(&pending);
    if let Some(cached) = cached_set(key) {
        annotate_all(program, &cached);
        return Some(cached);
    }

    if std::env::var_os("WAF_HS_DEBUG").is_some() {
        eprintln!("hs candidates: pending groups {}", pending.len());
    }
    let mut compiled = Vec::new();
    let mut total_bytes = 0usize;
    for (pipeline, patterns) in pending {
        if started.elapsed() >= COMPILE_DEADLINE {
            break;
        }
        let Some(group) = compile_group(pipeline, patterns, started) else {
            continue;
        };
        let Some(size) = group.database.database_size() else {
            continue;
        };
        if size > MAX_GROUP_DB_BYTES || total_bytes.saturating_add(size) > MAX_TOTAL_DB_BYTES {
            continue;
        }
        total_bytes += size;
        compiled.push(group);
    }
    if std::env::var_os("WAF_HS_DEBUG").is_some() {
        eprintln!(
            "hs candidates: compiled groups {} bytes {} elapsed {:?} covered {}",
            compiled.len(),
            total_bytes,
            started.elapsed(),
            compiled
                .iter()
                .flat_map(|group| group.pattern_rules.iter().flatten())
                .collect::<BTreeSet<_>>()
                .len()
        );
    }
    if compiled.is_empty() {
        return None;
    }

    // A rule is covered only when its expression survived compilation in its
    // own pipeline group. Assign deterministic gate ids in rule-id order.
    let mut covered: BTreeSet<u32> = BTreeSet::new();
    for group in &compiled {
        for rules in &group.pattern_rules {
            covered.extend(rules.iter().copied());
        }
    }
    if covered.len() > MAX_CANDIDATE_RULES {
        covered = covered.into_iter().take(MAX_CANDIDATE_RULES).collect();
    }
    let rule_ids: Vec<u32> = covered.into_iter().collect();
    let gate_for_rule: BTreeMap<u32, u16> = rule_ids
        .iter()
        .enumerate()
        .map(|(gate, id)| (*id, gate as u16))
        .collect();
    let words = rule_ids.len().div_ceil(64);
    let patterns = compiled
        .iter()
        .map(|group| group.database.pattern_count())
        .sum();

    let groups: Vec<HsGroup> = compiled
        .into_iter()
        .map(|group| HsGroup {
            pipeline: group.pipeline,
            database: group.database,
        })
        .collect();
    let set = Arc::new(HsCandidateSet {
        groups,
        rule_ids,
        gate_for_rule: gate_for_rule.clone(),
        words,
        patterns,
        database_bytes: total_bytes,
        compile_micros: started.elapsed().as_micros() as u64,
    });

    remember_set(key, &set);
    annotate_all(program, &set);
    Some(set)
}

fn annotate_all(program: &mut Program, set: &HsCandidateSet) {
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
                if let Some(gate) = set.gate_for_rule(id) {
                    rule.hs_gate = Some(gate);
                }
            }
        }
    }
}

/// Process-wide compiled-database cache. Bounded so a process that loads many
/// distinct bundles cannot retain compiled databases without limit.
static CACHE: OnceLock<Mutex<HashMap<u64, Arc<HsCandidateSet>>>> = OnceLock::new();
const MAX_CACHED_SETS: usize = 8;

fn pending_key(pending: &Pending) -> u64 {
    let mut hasher = DefaultHasher::new();
    pending.len().hash(&mut hasher);
    for (pipeline, patterns) in pending {
        pipeline.hash(&mut hasher);
        patterns.len().hash(&mut hasher);
        for (expression, rules) in patterns {
            expression.hash(&mut hasher);
            rules.len().hash(&mut hasher);
            for rule in rules {
                rule.hash(&mut hasher);
            }
        }
    }
    hasher.finish()
}

fn cached_set(key: u64) -> Option<Arc<HsCandidateSet>> {
    CACHE
        .get()?
        .lock()
        .ok()
        .and_then(|cache| cache.get(&key).cloned())
}

fn remember_set(key: u64, set: &Arc<HsCandidateSet>) {
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(mut cache) = cache.lock() {
        if cache.len() < MAX_CACHED_SETS {
            cache.insert(key, Arc::clone(set));
        }
    }
}

/// Collects eligible rules grouped by transform pipeline. Order is
/// deterministic so load-time gate ids are stable.
fn collect(program: &Program) -> Pending {
    let mut pending: Pending = BTreeMap::new();
    let mut eligible = 0usize;
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
                if eligible >= MAX_CANDIDATE_RULES {
                    return pending;
                }
                let Some(id) = rule.id else {
                    continue;
                };
                let Some(operator) = rule.operator.as_ref() else {
                    continue;
                };
                if operator.negated || !matches!(operator.kind, OperatorKind::Rx(_)) {
                    continue;
                }
                // `multiMatch` expands one value into several derived values;
                // those values are not in the transform cache, so keep the
                // rule on the per-rule path.
                if rule.multi_match {
                    continue;
                }
                // Rules that already carry a mandatory-literal gate are the
                // cheap path; the residual subset is what this pass targets.
                if rule.gate.is_some() {
                    continue;
                }
                let expression = super::parser::normalize_pattern(&operator.argument);
                if !representable(&expression) {
                    continue;
                }
                // The per-value pipeline bookkeeping is a single `u64`; keep higher
                // pipeline ids on the per-rule path.
                if usize::from(rule.pipeline) >= 64
                    || usize::from(rule.pipeline) >= program.pipelines.len()
                {
                    continue;
                }
                eligible += 1;
                pending
                    .entry(rule.pipeline)
                    .or_default()
                    .entry(expression)
                    .or_default()
                    .insert(id);
            }
        }
    }
    pending
}

/// Compiles one pipeline group.
///
/// Vectorscan rejects a handful of PCRE constructs (embedded end anchors,
/// backreferences, lookaround) at compile time. The pre-filter in
/// [`representable`] removes the common ones; if a group still fails, all of
/// its rules stay on the per-rule path.
fn compile_group(
    pipeline: u16,
    patterns: BTreeMap<String, BTreeSet<u32>>,
    started: Instant,
) -> Option<CompiledGroup> {
    let patterns: Vec<RegexPattern> = patterns
        .into_iter()
        .map(|(expression, rules)| RegexPattern {
            expression,
            // The parser compiles every rule with a `(?sm)` prefix. Mirror the
            // two flags directly instead of relying on inline-flag support.
            caseless: false,
            dotall: true,
            multiline: true,
            rule_ids: rules.into_iter().collect(),
        })
        .collect();

    if patterns.is_empty() || started.elapsed() >= COMPILE_DEADLINE {
        return None;
    }
    let group_started = Instant::now();
    match SharedHsDatabase::compile_regex(&patterns) {
        Ok(database) => {
            if std::env::var_os("WAF_HS_DEBUG").is_some() {
                eprintln!(
                    "hs candidate group [{pipeline}]: {} patterns in {:.1} ms",
                    patterns.len(),
                    group_started.elapsed().as_secs_f64() * 1e3
                );
            }
            Some(CompiledGroup {
                pipeline,
                database,
                pattern_rules: patterns.iter().map(|p| p.rule_ids.clone()).collect(),
            })
        }
        Err(error) => {
            if std::env::var_os("WAF_HS_DEBUG").is_some() {
                eprintln!(
                    "hs candidate group [{pipeline}] failed after {:.1} ms: {error}",
                    group_started.elapsed().as_secs_f64() * 1e3
                );
            }
            // The rejected expression is left on the per-rule path with the
            // rest of its group; partial groups are not retried because the
            // large residual patterns dominate the load-time budget.
            None
        }
    }
}

/// Conservative allowlist of byte-level constructs whose Hyperscan semantics
/// match the `regex` crate used by the engine.
///
/// Anything doubtful is rejected; a rejected rule stays on the per-rule path.
fn representable(pattern: &str) -> bool {
    if pattern.is_empty() || !pattern.is_ascii() || pattern.contains('\0') {
        return false;
    }
    if pattern.contains("\\p")
        || pattern.contains("\\P")
        || pattern.contains("\\x{")
        || pattern.contains("\\u{")
    {
        return false;
    }
    let bytes = pattern.as_bytes();
    let mut index = 0usize;
    let mut in_class = false;
    while index < bytes.len() {
        match bytes[index] {
            b'\\' => {
                let Some(next) = bytes.get(index + 1).copied() else {
                    return false;
                };
                // Backreferences and the escape sequences Hyperscan does not
                // define for byte mode.
                if next.is_ascii_digit() || matches!(next, b'C' | b'R' | b'X' | b'K') {
                    return false;
                }
                // End-of-subject anchors are only representable at the very
                // end of the expression.
                if matches!(next, b'z' | b'Z') && index + 2 != bytes.len() {
                    return false;
                }
                index += 2;
            }
            b'[' if !in_class => {
                in_class = true;
                index += 1;
            }
            b']' if in_class => {
                in_class = false;
                index += 1;
            }
            b'$' if !in_class => {
                // Hyperscan supports `$` only as the final token; embedded
                // end anchors (for example `(?:a|$)`) are rejected and are
                // common in the large CRS RCE patterns.
                if index + 1 != bytes.len() {
                    return false;
                }
                index += 1;
            }
            b'(' if bytes.get(index + 1) == Some(&b'?') => {
                match bytes.get(index + 2).copied() {
                    // Lookaround, atomic/conditional groups, named groups,
                    // recursion and branch-reset groups.
                    Some(b'=') | Some(b'!') | Some(b'<') | Some(b'>') | Some(b'P') | Some(b'(')
                    | Some(b'&') | Some(b'|') | Some(b'R') => return false,
                    _ => index += 1,
                }
            }
            _ => index += 1,
        }
    }
    !in_class
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::waf::rust_engine::{CompilePolicy, EngineRequest, RustEngine};

    #[test]
    fn rejects_constructs_with_uncertain_semantics() {
        assert!(representable(r"^a+b$"));
        assert!(representable(r"(?:foo|bar)\d{2,4}"));
        assert!(representable(r"(?i)select\s+from"));
        assert!(!representable("café"));
        assert!(!representable(r"a(?=b)"));
        assert!(!representable(r"(?<=a)b"));
        assert!(!representable(r"(a)\1"));
        assert!(!representable(r"\p{L}+"));
        assert!(!representable(r"\x{41}"));
        assert!(!representable(""));
    }

    #[test]
    fn compiles_the_residual_crs_regex_subset() {
        let path = crate::waf::rust_engine::default_crs_conf_path();
        if !path.exists() {
            return;
        }
        let engine =
            RustEngine::from_conf_path_with_policy(&path, CompilePolicy::Report).expect("engine");
        let Some(set) = engine.hs_candidate_set() else {
            panic!("expected a candidate set");
        };
        assert!(set.rule_count() > 50, "covered {}", set.rule_count());
        assert!(set.pattern_count() > 0);
        assert!(set.database_bytes() > 0);
        assert!(set.group_count() > 1);
    }

    #[test]
    fn miss_gates_but_hit_runs_the_rule() {
        let path = crate::waf::rust_engine::default_crs_conf_path();
        if !path.exists() {
            return;
        }
        let engine =
            RustEngine::from_conf_path_with_policy(&path, CompilePolicy::Report).expect("engine");
        if engine.hs_candidate_set().is_none() {
            return;
        }
        let headers = vec![
            ("Host".to_string(), "localhost".to_string()),
            (
                "Content-Type".to_string(),
                "application/x-www-form-urlencoded".to_string(),
            ),
            ("Content-Length".to_string(), "4101".to_string()),
        ];
        let body = format!("data={}", "z".repeat(4096)).into_bytes();
        let request = EngineRequest {
            method: "POST",
            uri: "/post",
            http_version: "HTTP/1.1",
            headers: &headers,
            body: Some(&body),
        };
        let benign = engine.evaluate_detailed(&request).expect("evaluate");
        assert!(benign.hs_candidate_scans > 0);
        assert!(benign.hs_candidate_skips > 0);
        assert!(benign.regex_evaluations_skipped > 0);
        assert!(matches!(benign.decision, crate::waf::Decision::Allow));

        // A payload the covered rules must still confirm: the candidate pass
        // may hit, but the real regex decides.
        let body = b"data=1%27+OR+%271%27%3D%271";
        let headers = vec![
            ("Host".to_string(), "localhost".to_string()),
            (
                "Content-Type".to_string(),
                "application/x-www-form-urlencoded".to_string(),
            ),
            ("Content-Length".to_string(), body.len().to_string()),
        ];
        let request = EngineRequest {
            method: "POST",
            uri: "/post",
            http_version: "HTTP/1.1",
            headers: &headers,
            body: Some(body),
        };
        let attack = engine.evaluate_detailed(&request).expect("evaluate");
        assert!(matches!(
            attack.decision,
            crate::waf::Decision::Block { .. }
        ));
    }
}
