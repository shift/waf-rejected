//! Deterministic request evaluation for the native CRS engine.
//!
//! The engine walks a compiled [`Program`] in phase order, maintains the CRS
//! `TX` anomaly scores, applies `skipAfter`, and turns every runtime error into
//! a block (fail-closed). It never reads the wall clock, never uses randomness
//! and never runs a garbage collector.

use std::collections::HashSet;
use std::path::Path;

use super::budget::{Budget, Limits};
use super::error::{EngineError, LoadError};
use super::ir::{
    Action, Collection, CompiledRule, CtlAction, Disruptive, Phase, Program, ProgramItem,
    RuleGroup, VariableSpec,
};
use super::operators::{Captures, MacroResolver};
use super::parser::{parse_conf_path, parse_conf_str, CompilePolicy, SupportReport};
use super::request::{Collections, EngineRequest, ResolvedValue};
use crate::waf::Decision;

/// Default CRS inbound anomaly threshold.
const DEFAULT_ANOMALY_THRESHOLD: i64 = 5;

/// Default status used by the CRS blocking rules.
const DEFAULT_BLOCK_STATUS: u16 = 403;

/// Result of one request evaluation.
#[derive(Debug, Clone)]
pub struct Outcome {
    /// Final decision.
    pub decision: Decision,
    /// Rule ids that matched, in evaluation order.
    pub matched_rules: Vec<u32>,
    /// `tx.blocking_inbound_anomaly_score` after the request phases.
    pub blocking_inbound_anomaly_score: i64,
    /// `tx.inbound_anomaly_score_pl1`.
    pub inbound_anomaly_score_pl1: i64,
    /// Configured `tx.inbound_anomaly_score_threshold`.
    pub threshold: i64,
    /// `tx.early_blocking`.
    pub early_blocking: bool,
    /// Fail-closed error, if any.
    pub error: Option<String>,
}

/// A compiled native CRS engine.
#[derive(Debug, Clone)]
pub struct RustEngine {
    program: Program,
    report: SupportReport,
    limits: Limits,
    source: String,
}

impl RustEngine {
    /// Loads the pinned CRS bundle in strict mode. Any unsupported construct
    /// aborts with the rule id and construct.
    pub fn from_conf_path(path: impl AsRef<Path>) -> Result<Self, LoadError> {
        Self::from_conf_path_with_policy(path, CompilePolicy::Strict)
    }

    /// Loads a bundle with an explicit policy.
    pub fn from_conf_path_with_policy(
        path: impl AsRef<Path>,
        policy: CompilePolicy,
    ) -> Result<Self, LoadError> {
        let path = path.as_ref();
        let (program, report) = parse_conf_path(path, policy)?;
        Ok(Self {
            program,
            report,
            limits: Limits::default(),
            source: path.display().to_string(),
        })
    }

    /// Compiles a bundle from a string. `base_dir` resolves `Include` and
    /// `@pmFromFile` data files.
    pub fn from_conf_str(
        text: &str,
        base_dir: impl AsRef<Path>,
        policy: CompilePolicy,
    ) -> Result<Self, LoadError> {
        let (program, report) = parse_conf_str(text, base_dir, policy)?;
        Ok(Self {
            program,
            report,
            limits: Limits::default(),
            source: "<memory>".to_string(),
        })
    }

    /// Overrides the per-request budget (tests and benchmarks).
    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// Support matrix produced at load time.
    pub fn support_report(&self) -> &SupportReport {
        &self.report
    }

    /// Source path/name.
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Number of compiled rule groups.
    pub fn rule_groups(&self) -> usize {
        self.program
            .phase1
            .iter()
            .chain(self.program.phase2.iter())
            .filter(|item| matches!(item, ProgramItem::Rule(_)))
            .count()
    }

    /// Evaluates a request and always returns a decision. Internal failures
    /// are converted to a block.
    pub fn evaluate(&self, request: &EngineRequest<'_>) -> Decision {
        match self.evaluate_detailed(request) {
            Ok(outcome) => outcome.decision,
            Err(err) => Decision::Block {
                status: 500,
                reason: format!("rust-engine fail-closed: {err}"),
            },
        }
    }

    /// Evaluates a request and returns diagnostics.
    pub fn evaluate_detailed(&self, request: &EngineRequest<'_>) -> Result<Outcome, EngineError> {
        let mut budget = Budget::new(self.limits);
        let mut tx = Collections::new(request, &mut budget)?;
        let mut state = EvalState::default();
        let mut matched_rules = Vec::new();

        let phase1 = self.run_phase(
            Phase::RequestHeaders,
            &mut tx,
            &mut budget,
            &mut state,
            &mut matched_rules,
        )?;
        if let Some(decision) = phase1 {
            return Ok(self.outcome(tx, matched_rules, decision, None));
        }
        if let Some(decision) = self.check_anomaly(&tx, Phase::RequestHeaders) {
            return Ok(self.outcome(tx, matched_rules, decision, None));
        }
        if state.allow {
            return Ok(self.outcome(tx, matched_rules, Decision::Allow, None));
        }

        tx.process_body(request, &mut budget)?;

        let phase2 = self.run_phase(
            Phase::RequestBody,
            &mut tx,
            &mut budget,
            &mut state,
            &mut matched_rules,
        )?;
        if let Some(decision) = phase2 {
            return Ok(self.outcome(tx, matched_rules, decision, None));
        }
        if let Some(decision) = self.check_anomaly(&tx, Phase::RequestBody) {
            return Ok(self.outcome(tx, matched_rules, decision, None));
        }

        Ok(self.outcome(tx, matched_rules, Decision::Allow, None))
    }

    fn outcome(
        &self,
        tx: Collections,
        matched_rules: Vec<u32>,
        decision: Decision,
        error: Option<String>,
    ) -> Outcome {
        Outcome {
            decision,
            matched_rules,
            blocking_inbound_anomaly_score: tx_i64(&tx, "blocking_inbound_anomaly_score"),
            inbound_anomaly_score_pl1: tx_i64(&tx, "inbound_anomaly_score_pl1"),
            threshold: {
                let threshold = tx_i64(&tx, "inbound_anomaly_score_threshold");
                if threshold == 0 {
                    DEFAULT_ANOMALY_THRESHOLD
                } else {
                    threshold
                }
            },
            early_blocking: tx_i64(&tx, "early_blocking") == 1,
            error,
        }
    }

    fn check_anomaly(&self, tx: &Collections, phase: Phase) -> Option<Decision> {
        let detection = match tx.tx_get("detection_paranoia_level") {
            Some(value) => std::str::from_utf8(value)
                .ok()
                .and_then(|text| text.trim().parse::<i64>().ok())
                .unwrap_or(1),
            None => 1,
        };
        if detection < 1 {
            return None;
        }
        if phase == Phase::RequestHeaders && tx_i64(tx, "early_blocking") != 1 {
            return None;
        }
        let threshold = tx_i64(tx, "inbound_anomaly_score_threshold");
        let threshold = if threshold == 0 {
            DEFAULT_ANOMALY_THRESHOLD
        } else {
            threshold
        };
        let score = tx_i64(tx, "blocking_inbound_anomaly_score");
        if score >= threshold {
            Some(Decision::Block {
                status: DEFAULT_BLOCK_STATUS,
                reason: format!(
                    "Inbound Anomaly Score Exceeded (Total Score: {score}, threshold: {threshold})"
                ),
            })
        } else {
            None
        }
    }

    fn run_phase(
        &self,
        phase: Phase,
        tx: &mut Collections,
        budget: &mut Budget,
        state: &mut EvalState,
        matched_rules: &mut Vec<u32>,
    ) -> Result<Option<Decision>, EngineError> {
        let items = self.program.items(phase);
        let mut index = 0;
        while index < items.len() {
            match &items[index] {
                ProgramItem::Marker(_) => {
                    index += 1;
                }
                ProgramItem::Rule(group) => {
                    if self.group_removed(group, state) {
                        index += 1;
                        continue;
                    }
                    match self.eval_group(group, tx, budget, state)? {
                        GroupResult::NoMatch => {
                            index += 1;
                        }
                        GroupResult::Match { flow } => {
                            if let Some(id) = group.id() {
                                matched_rules.push(id);
                            }
                            if let Some(disruptive) = flow.disruptive {
                                match disruptive {
                                    Disruptive::Allow
                                    | Disruptive::AllowRequest
                                    | Disruptive::AllowAll => {
                                        state.allow = true;
                                        return Ok(Some(Decision::Allow));
                                    }
                                    Disruptive::AllowPhase => {
                                        return Ok(None);
                                    }
                                    Disruptive::Deny | Disruptive::Drop | Disruptive::Block => {
                                        let status = flow.status.unwrap_or(DEFAULT_BLOCK_STATUS);
                                        return Ok(Some(Decision::Block {
                                            status,
                                            reason: format!(
                                                "request blocked by rule {}",
                                                group
                                                    .id()
                                                    .map(|id| id.to_string())
                                                    .unwrap_or_else(|| "<chain>".to_string())
                                            ),
                                        }));
                                    }
                                    Disruptive::Pass => {}
                                }
                            }
                            if let Some(marker) = flow.skip_after {
                                match marker_index(items, &marker) {
                                    Some(target) => index = target + 1,
                                    None => index += 1,
                                }
                            } else {
                                index += 1;
                            }
                        }
                    }
                }
            }
        }
        Ok(None)
    }

    fn group_removed(&self, group: &RuleGroup, state: &EvalState) -> bool {
        if let Some(id) = group.id() {
            if state.removed_rules.contains(&id) {
                return true;
            }
        }
        group.rules.iter().any(|rule| {
            rule.metadata
                .tags
                .iter()
                .any(|tag| state.removed_tags.contains(tag))
        })
    }

    fn eval_group(
        &self,
        group: &RuleGroup,
        tx: &mut Collections,
        budget: &mut Budget,
        state: &mut EvalState,
    ) -> Result<GroupResult, EngineError> {
        tx.clear_matches();
        let mut all_matched = true;
        for rule in &group.rules {
            let matched = self.eval_rule(rule, tx, budget, state)?;
            if !matched {
                all_matched = false;
                break;
            }
        }
        if !all_matched {
            return Ok(GroupResult::NoMatch);
        }

        let parent = &group.rules[0];
        let mut flow = GroupFlow::default();
        for action in &parent.actions {
            match action {
                Action::Disruptive(disruptive) => flow.disruptive = Some(*disruptive),
                Action::SkipAfter(marker) => flow.skip_after = Some(marker.clone()),
                Action::Status(status) => flow.status = Some(*status),
                _ => {}
            }
        }
        Ok(GroupResult::Match { flow })
    }

    fn eval_rule(
        &self,
        rule: &CompiledRule,
        tx: &mut Collections,
        budget: &mut Budget,
        state: &mut EvalState,
    ) -> Result<bool, EngineError> {
        tx.clear_captures();
        if rule.operator.is_none() {
            self.apply_nondisruptive(rule, tx, state);
            return Ok(true);
        }

        let (positives, negatives): (Vec<&VariableSpec>, Vec<&VariableSpec>) =
            rule.variables.iter().partition(|spec| !spec.negated);

        let mut candidates = Vec::new();
        for spec in positives {
            candidates.extend(tx.resolve(spec, budget)?);
        }
        let mut exceptions = Vec::new();
        for spec in negatives {
            exceptions.extend(tx.resolve(spec, budget)?);
        }
        if !exceptions.is_empty() {
            candidates.retain(|candidate| !is_exception(candidate, &exceptions));
        }
        if candidates.is_empty() {
            return Ok(false);
        }

        let mut captures: Captures = std::array::from_fn(|_| Vec::new());
        let capture = rule.captures();
        let multi_match = rule.multi_match();
        let mut matched_any = false;
        for candidate in candidates {
            if target_removed(rule, &candidate, state) {
                continue;
            }
            let values = if multi_match {
                transform_multi(rule, &candidate.value, budget)?
            } else {
                vec![transform_value(rule, &candidate.value, budget)?]
            };
            for value in values {
                if rule
                    .operator
                    .as_ref()
                    .is_some_and(|operator| operator.evaluate(&value, tx, capture, &mut captures))
                {
                    budget.matched()?;
                    budget.bytes(value.len())?;
                    matched_any = true;
                    if capture {
                        for (index, captured) in captures.iter().enumerate() {
                            if !captured.is_empty() {
                                tx.set_capture(index, captured.clone());
                            }
                        }
                    }
                    tx.record_match(candidate.matched_name(), value);
                    // Coraza executes non-disruptive actions for every match,
                    // not once per rule. This matters for rules that build a
                    // TX variable per matched header/argument.
                    self.apply_nondisruptive(rule, tx, state);
                }
            }
        }
        Ok(matched_any)
    }

    fn apply_nondisruptive(
        &self,
        rule: &CompiledRule,
        tx: &mut Collections,
        state: &mut EvalState,
    ) {
        for action in &rule.actions {
            match action {
                Action::SetVar { name, op, value } => {
                    // Coraza expands macros in both the variable name and the
                    // value, e.g. `tx.header_name_920450_%{tx.0}`.
                    let expanded_name = tx.expand(name);
                    let expanded_name = String::from_utf8_lossy(&expanded_name).into_owned();
                    if expanded_name.is_empty() {
                        continue;
                    }
                    let expanded = tx.expand(&value.0);
                    match op {
                        super::ir::SetVarOp::Set => tx.tx_set(&expanded_name, expanded),
                        super::ir::SetVarOp::Add => tx.tx_add(&expanded_name, &expanded),
                        super::ir::SetVarOp::Sub => tx.tx_sub(&expanded_name, &expanded),
                        super::ir::SetVarOp::Remove => tx.tx_remove(&expanded_name),
                    }
                }
                Action::Ctl(ctl) => apply_ctl(ctl, tx, state),
                Action::Status(status) => state.status = Some(*status),
                Action::Capture
                | Action::MultiMatch
                | Action::SkipAfter(_)
                | Action::InitCol
                | Action::Disruptive(_) => {}
            }
        }
    }
}

fn apply_ctl(ctl: &CtlAction, tx: &mut Collections, state: &mut EvalState) {
    match ctl {
        CtlAction::RuleRemoveById(id) => {
            state.removed_rules.insert(*id);
        }
        CtlAction::RuleRemoveByTag(tag) => {
            state.removed_tags.insert(tag.clone());
        }
        CtlAction::RuleRemoveTargetById {
            id,
            collection,
            key,
        } => {
            state.removed_targets.push(RemovedTarget {
                rule_id: Some(*id),
                tag: None,
                collection: *collection,
                key: key.clone(),
            });
        }
        CtlAction::RuleRemoveTargetByTag {
            tag,
            collection,
            key,
        } => {
            state.removed_targets.push(RemovedTarget {
                rule_id: None,
                tag: Some(tag.clone()),
                collection: *collection,
                key: key.clone(),
            });
        }
        CtlAction::RequestBodyProcessor(processor) => {
            tx.set_request_body_processor(processor.clone());
        }
        CtlAction::ForceRequestBodyVariable(force) => {
            tx.set_force_request_body_variable(*force);
        }
        CtlAction::AuditEngine(_) => {}
    }
}

fn is_exception(candidate: &ResolvedValue, exceptions: &[ResolvedValue]) -> bool {
    exceptions.iter().any(|exception| {
        if !same_collection(candidate.collection, exception.collection) {
            return false;
        }
        match &exception.key {
            None => true,
            Some(key) => candidate
                .key
                .as_ref()
                .is_some_and(|candidate_key| candidate_key.eq_ignore_ascii_case(key)),
        }
    })
}

fn same_collection(left: Collection, right: Collection) -> bool {
    if left == right {
        return true;
    }
    matches!(
        (left, right),
        (Collection::ArgsGet, Collection::Args)
            | (Collection::ArgsPost, Collection::Args)
            | (Collection::ArgsGetNames, Collection::ArgsNames)
            | (Collection::ArgsPostNames, Collection::ArgsNames)
    )
}

fn target_removed(rule: &CompiledRule, candidate: &ResolvedValue, state: &EvalState) -> bool {
    state.removed_targets.iter().any(|target| {
        let matches_rule = match target.rule_id {
            Some(id) => rule.id == Some(id),
            None => target
                .tag
                .as_ref()
                .is_some_and(|tag| rule.metadata.tags.iter().any(|rule_tag| rule_tag == tag)),
        };
        if !matches_rule || !same_collection(candidate.collection, target.collection) {
            return false;
        }
        match &target.key {
            None => true,
            Some(key) => candidate
                .key
                .as_ref()
                .is_some_and(|candidate_key| candidate_key.eq_ignore_ascii_case(key)),
        }
    })
}

fn transform_value(
    rule: &CompiledRule,
    input: &[u8],
    budget: &mut Budget,
) -> Result<Vec<u8>, EngineError> {
    let mut value = input.to_vec();
    for transform in &rule.transforms {
        value = transform.apply(&value, budget)?;
    }
    Ok(value)
}

fn transform_multi(
    rule: &CompiledRule,
    input: &[u8],
    budget: &mut Budget,
) -> Result<Vec<Vec<u8>>, EngineError> {
    let mut values = vec![input.to_vec()];
    let mut value = input.to_vec();
    for transform in &rule.transforms {
        let next = transform.apply(&value, budget)?;
        if next != value {
            values.push(next.clone());
            value = next;
        }
    }
    Ok(values)
}

fn marker_index(items: &[ProgramItem], marker: &str) -> Option<usize> {
    items.iter().position(|item| match item {
        ProgramItem::Marker(name) => name == marker,
        ProgramItem::Rule(_) => false,
    })
}

fn tx_i64(tx: &Collections, name: &str) -> i64 {
    tx.tx_get(name)
        .and_then(|value| std::str::from_utf8(value).ok())
        .and_then(|text| text.trim().parse::<i64>().ok())
        .unwrap_or(0)
}

#[derive(Default)]
struct EvalState {
    removed_rules: HashSet<u32>,
    removed_tags: HashSet<String>,
    removed_targets: Vec<RemovedTarget>,
    status: Option<u16>,
    allow: bool,
}

struct RemovedTarget {
    rule_id: Option<u32>,
    tag: Option<String>,
    collection: Collection,
    key: Option<String>,
}

#[derive(Default)]
struct GroupFlow {
    disruptive: Option<Disruptive>,
    skip_after: Option<String>,
    status: Option<u16>,
}

enum GroupResult {
    NoMatch,
    Match { flow: GroupFlow },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine() -> RustEngine {
        let text = r#"
SecAction "id:900990,phase:1,pass,nolog,setvar:tx.crs_setup_version=4140"
SecRule &TX:inbound_anomaly_score_threshold "@eq 0" "id:901100,phase:1,pass,nolog,setvar:tx.inbound_anomaly_score_threshold=5"
SecRule &TX:early_blocking "@eq 0" "id:901115,phase:1,pass,nolog,setvar:tx.early_blocking=1"
SecRule &TX:blocking_paranoia_level "@eq 0" "id:901120,phase:1,pass,nolog,setvar:tx.blocking_paranoia_level=1"
SecRule &TX:detection_paranoia_level "@eq 0" "id:901125,phase:1,pass,nolog,setvar:tx.detection_paranoia_level=%{TX.blocking_paranoia_level}"
SecRule &TX:critical_anomaly_score "@eq 0" "id:901140,phase:1,pass,nolog,setvar:tx.critical_anomaly_score=5"
SecAction "id:901200,phase:1,pass,nolog,setvar:tx.inbound_anomaly_score_pl1=0,setvar:tx.blocking_inbound_anomaly_score=0"
SecRule ARGS "@rx evil" "id:1001,phase:2,block,capture,setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score},setvar:tx.blocking_inbound_anomaly_score=+%{tx.inbound_anomaly_score_pl1}"
SecRule TX:BLOCKING_INBOUND_ANOMALY_SCORE "@ge %{tx.inbound_anomaly_score_threshold}" "id:949110,phase:2,deny,status:403"
"#;
        RustEngine::from_conf_str(text, ".", CompilePolicy::Strict).expect("engine")
    }

    fn request(uri: &str) -> EngineRequest<'_> {
        EngineRequest {
            method: "GET",
            uri,
            http_version: "HTTP/1.1",
            headers: &[],
            body: None,
        }
    }

    #[test]
    fn anomaly_score_blocks() {
        let engine = engine();
        assert!(matches!(
            engine.evaluate(&request("/?q=evil")),
            Decision::Block { status: 403, .. }
        ));
        assert_eq!(engine.evaluate(&request("/?q=good")), Decision::Allow);
    }

    #[test]
    fn unsupported_operator_is_reported() {
        let text = r#"SecRule ARGS "@detectSQLi" "id:942100,phase:2,block""#;
        let err =
            RustEngine::from_conf_str(text, ".", CompilePolicy::Strict).expect_err("must reject");
        match err {
            LoadError::Unsupported(unsupported) => {
                assert_eq!(unsupported.rule_id, Some(942100));
                assert_eq!(unsupported.construct, "operator:@detectsqli");
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn report_mode_keeps_compiling_other_rules() {
        let text = r#"
SecRule ARGS "@detectSQLi" "id:942100,phase:2,block"
SecRule ARGS "@rx evil" "id:1001,phase:2,deny,status:403"
"#;
        let engine = RustEngine::from_conf_str(text, ".", CompilePolicy::Report).expect("engine");
        assert_eq!(engine.support_report().rules_compiled, 1);
        assert_eq!(engine.support_report().rules_skipped, 1);
        assert_eq!(engine.support_report().unsupported.len(), 1);
        assert!(matches!(
            engine.evaluate(&request("/?q=evil")),
            Decision::Block { .. }
        ));
    }

    #[test]
    fn pinned_crs_support_matrix_is_exact() {
        let path = crate::waf::rust_engine::default_crs_conf_path();
        if !path.exists() {
            return;
        }
        let engine =
            RustEngine::from_conf_path_with_policy(&path, CompilePolicy::Report).expect("CRS");
        let report = engine.support_report();
        assert_eq!(report.rules_seen, 505, "SecRule/SecAction directives");
        assert_eq!(report.rules_compiled, 501, "compiled rules");
        assert_eq!(report.rules_skipped, 4, "skipped rules");
        let ids: Vec<u32> = report
            .unsupported
            .iter()
            .filter_map(|unsupported| unsupported.rule_id)
            .collect();
        assert_eq!(ids, vec![941100, 941101, 942100, 942101]);

        // The production loader must refuse the bundle rather than silently
        // dropping the four libinjection rules.
        let err = RustEngine::from_conf_path(&path).expect_err("strict load must fail");
        match err {
            LoadError::Unsupported(unsupported) => {
                assert!(matches!(
                    unsupported.rule_id,
                    Some(941100 | 941101 | 942100 | 942101)
                ));
            }
            other => panic!("unexpected error: {other}"),
        }
    }
}
