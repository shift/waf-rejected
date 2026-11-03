//! Deterministic request evaluation for the native CRS engine.
//!
//! The engine walks a compiled [`Program`] in phase order, maintains the CRS
//! `TX` anomaly scores, applies `skipAfter`, and turns every runtime error into
//! a block (fail-closed). It never reads the wall clock, never uses randomness
//! and never runs a garbage collector.
//!
//! # Execution model
//!
//! The request is parsed once into immutable [`RequestData`] with borrowed
//! spans. Candidate values are borrowed from that data, and every transform
//! pipeline is interned at load time ([`Program::pipelines`]). A per-request
//! [`TransformCache`] therefore computes each `(value, pipeline)` pair at most
//! once, no matter how many rules share it. Capture slots and candidate
//! buffers are reused across rules, and a phase stops as soon as a disruptive
//! action or the anomaly threshold fires.

use std::cell::RefCell;
use std::collections::HashSet;
use std::path::Path;

use super::budget::{Budget, Limits};
use super::error::{EngineError, LoadError};
use super::gate::GateSet;
use super::ir::{
    Action, Collection, CompiledRule, CtlAction, Disruptive, Phase, Program, ProgramItem,
    RuleGroup, Selector,
};
use super::operators::{Captures, MacroResolver};
#[cfg(feature = "parallel-args")]
use super::parallel_args::{map_ordered, ArgsParallelConfig};
use super::parser::{parse_conf_path, parse_conf_str, CompilePolicy, SupportReport};
use super::request::{
    expand_macros_into, Candidate, Collections, EngineRequest, RequestData, TxState,
};
use super::transforms::Transform;
use crate::waf::transforms::{TransformCache, ValueId};
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
    /// Number of operator evaluations actually executed.
    pub operator_evaluations: u64,
    /// Number of regex evaluations skipped by mandatory-literal gates.
    pub regex_evaluations_skipped: u64,
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
    /// Regex with the largest capture-group count, used to size one reusable
    /// `CaptureLocations` per worker thread.
    capture_template: Option<regex::bytes::Regex>,
    /// Experimental candidate-level parallelism. `None` (the default) keeps the
    /// serial candidate loop; see `docs/suggestions_from_agents/parallel-args.md`.
    #[cfg(feature = "parallel-args")]
    parallel_args: Option<ArgsParallelConfig>,
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
        let capture_template = capture_template(&program);
        Ok(Self {
            program,
            report,
            limits: Limits::default(),
            source: path.display().to_string(),
            capture_template,
            #[cfg(feature = "parallel-args")]
            parallel_args: None,
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
        let capture_template = capture_template(&program);
        Ok(Self {
            program,
            report,
            limits: Limits::default(),
            source: "<memory>".to_string(),
            capture_template,
            #[cfg(feature = "parallel-args")]
            parallel_args: None,
        })
    }

    /// Overrides the per-request budget (tests and benchmarks).
    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// Enables the experimental per-argument parallel candidate path.
    ///
    /// Only available with the non-default `parallel-args` feature. The default
    /// engine keeps the deterministic serial loop.
    #[cfg(feature = "parallel-args")]
    pub fn with_parallel_args(mut self, config: ArgsParallelConfig) -> Self {
        self.parallel_args = Some(config);
        self
    }

    /// Support matrix produced at load time.
    pub fn support_report(&self) -> &SupportReport {
        &self.report
    }

    /// Compiled per-rule literal gates, when the bundle contains gated regex
    /// rules.
    pub fn gate_set(&self) -> Option<&GateSet> {
        self.program.gates.as_deref()
    }

    /// Number of compiled rules that carry a mandatory-literal gate.
    pub fn gated_rule_count(&self) -> usize {
        self.program
            .phase1
            .iter()
            .chain(self.program.phase2.iter())
            .filter_map(|item| match item {
                ProgramItem::Rule(group) => Some(group),
                ProgramItem::Marker(_) => None,
            })
            .flat_map(|group| group.rules.iter())
            .filter(|rule| rule.gate.is_some())
            .count()
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

    /// Number of interned transform pipelines.
    pub fn pipeline_count(&self) -> usize {
        self.program.pipelines.len()
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

    /// Evaluates a request under the hot-loop profiler.
    ///
    /// Only available with the non-default `engine-profile` feature. Returns
    /// the same decision and outcome diagnostics as [`Self::evaluate_detailed`]
    /// plus per-category timings and allocation counts.
    #[cfg(feature = "engine-profile")]
    pub fn evaluate_profiled(
        &self,
        request: &EngineRequest<'_>,
    ) -> (Decision, super::profile::Report) {
        super::profile::begin();
        let result = self.evaluate_detailed(request);
        let report = super::profile::finish();
        match result {
            Ok(outcome) => (outcome.decision, report),
            Err(err) => (
                Decision::Block {
                    status: 500,
                    reason: format!("rust-engine fail-closed: {err}"),
                },
                report,
            ),
        }
    }

    /// Evaluates a request and returns diagnostics.
    pub fn evaluate_detailed(&self, request: &EngineRequest<'_>) -> Result<Outcome, EngineError> {
        #[cfg(feature = "engine-profile")]
        let parse_sample = super::profile::sample();
        let mut budget = Budget::new(self.limits);
        let mut tx_state = SCRATCH
            .with(|cell| cell.borrow_mut().tx_state.take())
            .unwrap_or_default();
        tx_state.reset();
        let mut tx = Collections::new_with_state(request, &mut budget, tx_state)?;
        #[cfg(feature = "engine-profile")]
        super::profile::record(
            super::profile::Category::Parse,
            parse_sample.0,
            parse_sample.1,
        );
        let mut state = EvalState::default();
        let mut matched_rules = Vec::new();
        let mut captures: Captures = std::array::from_fn(|_| Vec::new());

        SCRATCH.with(|cell| {
            let mut scratch = cell.borrow_mut();
            let scratch = &mut *scratch;
            if scratch.capture_locations.is_none() {
                scratch.capture_locations = self
                    .capture_template
                    .as_ref()
                    .map(regex::bytes::Regex::capture_locations);
            }

            let phase1 = self.run_phase(
                Phase::RequestHeaders,
                &mut tx,
                &mut budget,
                &mut state,
                &mut matched_rules,
                &mut captures,
                scratch,
            )?;
            if let Some(decision) = phase1 {
                return Ok(self.outcome(tx, matched_rules, decision, None, &state, scratch));
            }
            if let Some(decision) = self.check_anomaly(&tx, Phase::RequestHeaders) {
                return Ok(self.outcome(tx, matched_rules, decision, None, &state, scratch));
            }
            if state.allow {
                return Ok(self.outcome(tx, matched_rules, Decision::Allow, None, &state, scratch));
            }

            #[cfg(feature = "engine-profile")]
            let body_sample = super::profile::sample();
            tx.process_body(request, &mut budget)?;
            #[cfg(feature = "engine-profile")]
            super::profile::record(
                super::profile::Category::Parse,
                body_sample.0,
                body_sample.1,
            );

            let phase2 = self.run_phase(
                Phase::RequestBody,
                &mut tx,
                &mut budget,
                &mut state,
                &mut matched_rules,
                &mut captures,
                scratch,
            )?;
            if let Some(decision) = phase2 {
                return Ok(self.outcome(tx, matched_rules, decision, None, &state, scratch));
            }
            if let Some(decision) = self.check_anomaly(&tx, Phase::RequestBody) {
                return Ok(self.outcome(tx, matched_rules, decision, None, &state, scratch));
            }

            Ok(self.outcome(tx, matched_rules, Decision::Allow, None, &state, scratch))
        })
    }

    fn outcome(
        &self,
        tx: Collections<'_>,
        matched_rules: Vec<u32>,
        decision: Decision,
        error: Option<String>,
        state: &EvalState,
        scratch: &mut Scratch,
    ) -> Outcome {
        let outcome = Outcome {
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
            operator_evaluations: state.operator_evaluations,
            regex_evaluations_skipped: state.regex_evaluations_skipped,
            error,
        };
        scratch.tx_state = Some(tx.into_state());
        outcome
    }

    fn check_anomaly(&self, tx: &Collections<'_>, phase: Phase) -> Option<Decision> {
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

    #[allow(clippy::too_many_arguments)]
    fn run_phase<'a>(
        &self,
        phase: Phase,
        tx: &mut Collections<'a>,
        budget: &mut Budget,
        state: &mut EvalState,
        matched_rules: &mut Vec<u32>,
        captures: &mut Captures,
        scratch: &mut Scratch,
    ) -> Result<Option<Decision>, EngineError> {
        scratch
            .cache
            .begin_request(self.program.transform_prefixes.len());
        let limits = budget.limits();
        scratch.cache.set_bounds(
            limits.max_value_bytes,
            limits.max_total_bytes.saturating_mul(2),
        );
        scratch.value_ids.clear();
        scratch.charged_transform_bytes = scratch.cache.transform_bytes();
        scratch.gate_masks.begin();
        let (data, tx_state) = tx.split();
        let mut candidates: Vec<Candidate<'_>> = Vec::new();
        let mut exceptions: Vec<Candidate<'_>> = Vec::new();
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
                    match self.eval_group(
                        group,
                        data,
                        tx_state,
                        budget,
                        state,
                        &mut candidates,
                        &mut exceptions,
                        captures,
                        scratch,
                    )? {
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

    #[allow(clippy::too_many_arguments)]
    fn eval_group<'r, 'a>(
        &self,
        group: &RuleGroup,
        data: &'r RequestData<'a>,
        tx_state: &mut TxState,
        budget: &mut Budget,
        state: &mut EvalState,
        candidates: &mut Vec<Candidate<'r>>,
        exceptions: &mut Vec<Candidate<'r>>,
        captures: &mut Captures,
        scratch: &mut Scratch,
    ) -> Result<GroupResult, EngineError> {
        tx_state.clear_matches();
        let record_matches = group_records_matches(group);
        let mut all_matched = true;
        for rule in &group.rules {
            let matched = self.eval_rule(
                rule,
                data,
                tx_state,
                budget,
                state,
                candidates,
                exceptions,
                captures,
                scratch,
                record_matches,
            )?;
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

    #[allow(clippy::too_many_arguments)]
    fn eval_rule<'r, 'a>(
        &self,
        rule: &CompiledRule,
        data: &'r RequestData<'a>,
        tx_state: &mut TxState,
        budget: &mut Budget,
        state: &mut EvalState,
        candidates: &mut Vec<Candidate<'r>>,
        exceptions: &mut Vec<Candidate<'r>>,
        captures: &mut Captures,
        scratch: &mut Scratch,
        record_matches: bool,
    ) -> Result<bool, EngineError> {
        tx_state.clear_captures();
        if rule.operator.is_none() {
            self.apply_nondisruptive(
                rule,
                data,
                tx_state,
                state,
                &mut scratch.macro_name,
                &mut scratch.macro_value,
            );
            return Ok(true);
        }

        if let Some(matched) = self.eval_tx_rule(
            rule,
            data,
            tx_state,
            budget,
            state,
            captures,
            scratch,
            record_matches,
        )? {
            return Ok(matched);
        }

        if let Some(matched) = self.eval_matched_rule(
            rule,
            data,
            tx_state,
            budget,
            state,
            captures,
            scratch,
            record_matches,
        )? {
            return Ok(matched);
        }

        #[cfg(feature = "engine-profile")]
        let candidates_sample = super::profile::sample();
        candidates.clear();
        exceptions.clear();
        for spec in &rule.variables {
            if !spec.negated {
                data.resolve_into(spec, tx_state, budget, candidates)?;
            }
        }
        for spec in &rule.variables {
            if spec.negated {
                data.resolve_into(spec, tx_state, budget, exceptions)?;
            }
        }
        if !exceptions.is_empty() {
            candidates.retain(|candidate| !is_exception(candidate, exceptions));
        }
        #[cfg(feature = "engine-profile")]
        super::profile::record(
            super::profile::Category::Candidates,
            candidates_sample.0,
            candidates_sample.1,
        );
        if candidates.is_empty() {
            return Ok(false);
        }

        let pipeline = self
            .program
            .pipelines
            .get(usize::from(rule.pipeline))
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let capture = rule.captures();
        let multi_match = rule.multi_match();
        let mut matched_any = false;

        #[cfg(feature = "parallel-args")]
        if let Some(config) = self.parallel_args {
            if config.applies(candidates.len()) && self.candidate_local(rule) {
                return self.eval_candidates_parallel(
                    rule,
                    data,
                    tx_state,
                    budget,
                    state,
                    candidates,
                    scratch,
                    record_matches,
                    capture,
                    config,
                );
            }
        }

        for candidate in candidates.iter() {
            if target_removed(rule, candidate, state) {
                continue;
            }
            if !multi_match {
                if let Some(gate) = rule.gate {
                    #[cfg(feature = "engine-profile")]
                    let gate_sample = super::profile::sample();
                    let mask = self.gate_mask(candidate, scratch, budget)?;
                    #[cfg(feature = "engine-profile")]
                    super::profile::record(
                        super::profile::Category::Gate,
                        gate_sample.0,
                        gate_sample.1,
                    );
                    if let Some(mask) = mask {
                        let gates = self
                            .program
                            .gates
                            .as_deref()
                            .expect("gate id implies gates");
                        if !gates.allows(gate, mask) {
                            #[cfg(feature = "engine-profile")]
                            super::profile::regex_skip();
                            state.regex_evaluations_skipped += 1;
                            continue;
                        }
                    }
                }
            }
            if multi_match {
                #[cfg(feature = "engine-profile")]
                let transform_sample = super::profile::sample();
                transform_multi_into(&candidate.value, pipeline, budget, &mut scratch.multi)?;
                #[cfg(feature = "engine-profile")]
                super::profile::record(
                    super::profile::Category::Transforms,
                    transform_sample.0,
                    transform_sample.1,
                );
                for value in scratch.multi.iter() {
                    state.operator_evaluations += 1;
                    #[cfg(feature = "engine-profile")]
                    let operator_sample = super::profile::sample();
                    let matched = eval_operator(
                        rule,
                        value,
                        data,
                        tx_state,
                        capture,
                        captures,
                        &mut scratch.op_macro,
                        scratch.capture_locations.as_mut(),
                    );
                    #[cfg(feature = "engine-profile")]
                    {
                        super::profile::record(
                            super::profile::Category::Operators,
                            operator_sample.0,
                            operator_sample.1,
                        );
                        if rule
                            .operator
                            .as_ref()
                            .is_some_and(|op| matches!(op.kind, super::ir::OperatorKind::Rx(_)))
                        {
                            super::profile::regex_run();
                        }
                    }
                    if matched {
                        budget.matched()?;
                        budget.bytes(value.len())?;
                        matched_any = true;
                        if capture {
                            copy_captures(tx_state, captures);
                        }
                        if record_matches {
                            tx_state.record_match(candidate.matched_name(), value);
                        }
                        self.apply_nondisruptive(
                            rule,
                            data,
                            tx_state,
                            state,
                            &mut scratch.macro_name,
                            &mut scratch.macro_value,
                        );
                    }
                }
            } else {
                #[cfg(feature = "engine-profile")]
                let transform_sample = super::profile::sample();
                let value: &[u8] = match candidate.cache_id {
                    Some(id) => {
                        let range = resolve_cached(
                            &mut scratch.cache,
                            &mut scratch.value_ids,
                            &self.program.transform_prefixes,
                            usize::from(rule.pipeline),
                            id,
                            &candidate.value,
                            &mut scratch.charged_transform_bytes,
                            budget,
                        )?;
                        scratch.cache.bytes(range)
                    }
                    None => {
                        transform_into(
                            &candidate.value,
                            pipeline,
                            budget,
                            &mut scratch.uncached,
                            &mut scratch.uncached_tmp,
                        )?;
                        &scratch.uncached
                    }
                };
                #[cfg(feature = "engine-profile")]
                super::profile::record(
                    super::profile::Category::Transforms,
                    transform_sample.0,
                    transform_sample.1,
                );
                state.operator_evaluations += 1;
                #[cfg(feature = "engine-profile")]
                let operator_sample = super::profile::sample();
                let matched = eval_operator(
                    rule,
                    value,
                    data,
                    tx_state,
                    capture,
                    captures,
                    &mut scratch.op_macro,
                    scratch.capture_locations.as_mut(),
                );
                #[cfg(feature = "engine-profile")]
                {
                    super::profile::record(
                        super::profile::Category::Operators,
                        operator_sample.0,
                        operator_sample.1,
                    );
                    if rule
                        .operator
                        .as_ref()
                        .is_some_and(|op| matches!(op.kind, super::ir::OperatorKind::Rx(_)))
                    {
                        super::profile::regex_run();
                    }
                }
                if matched {
                    budget.matched()?;
                    budget.bytes(value.len())?;
                    matched_any = true;
                    if capture {
                        copy_captures(tx_state, captures);
                    }
                    if record_matches {
                        tx_state.record_match(candidate.matched_name(), value);
                    }
                    // Coraza executes non-disruptive actions for every match,
                    // not once per rule. This matters for rules that build a
                    // TX variable per matched header/argument.
                    self.apply_nondisruptive(
                        rule,
                        data,
                        tx_state,
                        state,
                        &mut scratch.macro_name,
                        &mut scratch.macro_value,
                    );
                }
            }
        }
        Ok(matched_any)
    }

    /// True when every candidate of `rule` can be evaluated without observing
    /// another candidate's actions.
    ///
    /// The parallel path defers `setvar`/capture/MATCHED_VARS application to a
    /// serial reduction. That is only equivalent when the operator does not
    /// expand a macro (which could read TX written by the rule itself) and no
    /// `ctl` action can change which later candidates are evaluated.
    #[cfg(feature = "parallel-args")]
    fn candidate_local(&self, rule: &CompiledRule) -> bool {
        if rule.multi_match() {
            return false;
        }
        let Some(operator) = rule.operator.as_ref() else {
            return false;
        };
        if !matches!(
            operator.kind,
            super::ir::OperatorKind::Rx(_)
                | super::ir::OperatorKind::Pm(_)
                | super::ir::OperatorKind::PmFromFile(_)
                | super::ir::OperatorKind::ValidateByteRange(_)
                | super::ir::OperatorKind::ValidateUrlEncoding
                | super::ir::OperatorKind::ValidateUtf8Encoding
                | super::ir::OperatorKind::UnconditionalMatch
                | super::ir::OperatorKind::IpMatch(_)
                | super::ir::OperatorKind::DetectSqlInjection
                | super::ir::OperatorKind::DetectXss
        ) {
            return false;
        }
        if rule
            .actions
            .iter()
            .any(|action| matches!(action, Action::Ctl(_)))
        {
            return false;
        }
        rule.variables.iter().all(|spec| {
            matches!(
                spec.collection,
                Collection::Args
                    | Collection::ArgsGet
                    | Collection::ArgsPost
                    | Collection::ArgsNames
                    | Collection::ArgsGetNames
                    | Collection::ArgsPostNames
            )
        })
    }

    /// Evaluates the candidates of one candidate-local ARGS rule on the scoped
    /// worker set, then applies matches in candidate order.
    ///
    /// Operator evaluation is side-effect free (it reads TX without writing
    /// it). The reduction charges the budget, restores captures, records
    /// `MATCHED_VARS` and runs `setvar` actions in the exact order of the
    /// serial loop, so decisions, anomaly order and capture variables match.
    #[cfg(feature = "parallel-args")]
    #[allow(clippy::too_many_arguments)]
    fn eval_candidates_parallel<'r, 'a>(
        &self,
        rule: &CompiledRule,
        data: &'r RequestData<'a>,
        tx_state: &mut TxState,
        budget: &mut Budget,
        state: &mut EvalState,
        candidates: &[Candidate<'r>],
        scratch: &mut Scratch,
        record_matches: bool,
        capture: bool,
        config: ArgsParallelConfig,
    ) -> Result<bool, EngineError> {
        // Candidates in this rule were validated as candidate-local, so the
        // worker closure may read TX and the eval state immutably.
        let tx_shared: &TxState = tx_state;
        let eval_shared: &EvalState = state;
        let limits = budget.limits();
        let pipeline = self
            .program
            .pipelines
            .get(usize::from(rule.pipeline))
            .map(Vec::as_slice)
            .unwrap_or(&[]);

        let outcomes = map_ordered(candidates.len(), config.threads, |index| {
            let candidate = &candidates[index];
            if target_removed(rule, candidate, eval_shared) {
                return Ok(CandidateEval::Removed);
            }
            SCRATCH.with(|cell| {
                let mut guard = cell.borrow_mut();
                let worker_scratch = &mut *guard;
                // Scoped workers are fresh threads; reset the per-request cache
                // before the first candidate they evaluate.
                worker_scratch
                    .cache
                    .begin_request(self.program.transform_prefixes.len());
                worker_scratch.cache.set_bounds(
                    limits.max_value_bytes,
                    limits.max_total_bytes.saturating_mul(2),
                );
                worker_scratch.value_ids.clear();
                worker_scratch.charged_transform_bytes = worker_scratch.cache.transform_bytes();
                worker_scratch.gate_masks.begin();
                let mut worker_budget = Budget::new(limits);

                if let Some(gate) = rule.gate {
                    if let Some(mask) =
                        self.gate_mask(candidate, worker_scratch, &mut worker_budget)?
                    {
                        let gates = self
                            .program
                            .gates
                            .as_deref()
                            .expect("gate id implies gates");
                        if !gates.allows(gate, mask) {
                            return Ok(CandidateEval::GateSkipped {
                                used: worker_budget.used_bytes(),
                            });
                        }
                    }
                }

                let value: &[u8] = match candidate.cache_id {
                    Some(id) => {
                        let range = resolve_cached(
                            &mut worker_scratch.cache,
                            &mut worker_scratch.value_ids,
                            &self.program.transform_prefixes,
                            usize::from(rule.pipeline),
                            id,
                            &candidate.value,
                            &mut worker_scratch.charged_transform_bytes,
                            &mut worker_budget,
                        )?;
                        worker_scratch.cache.bytes(range)
                    }
                    None => {
                        transform_into(
                            &candidate.value,
                            pipeline,
                            &mut worker_budget,
                            &mut worker_scratch.uncached,
                            &mut worker_scratch.uncached_tmp,
                        )?;
                        &worker_scratch.uncached
                    }
                };
                let mut candidate_captures: Captures = std::array::from_fn(|_| Vec::new());
                let matched = eval_operator(
                    rule,
                    value,
                    data,
                    tx_shared,
                    capture,
                    &mut candidate_captures,
                    &mut worker_scratch.op_macro,
                    worker_scratch.capture_locations.as_mut(),
                );
                let recorded = if record_matches && matched {
                    Some(value.to_vec())
                } else {
                    None
                };
                Ok(CandidateEval::Evaluated {
                    matched,
                    len: value.len(),
                    used: worker_budget.used_bytes(),
                    captures: candidate_captures,
                    recorded,
                })
            })
        });

        let mut matched_any = false;
        for (candidate, outcome) in candidates.iter().zip(outcomes) {
            match outcome? {
                CandidateEval::Removed => {}
                CandidateEval::GateSkipped { used } => {
                    budget.absorb(used)?;
                    state.regex_evaluations_skipped += 1;
                }
                CandidateEval::Evaluated {
                    matched,
                    len,
                    used,
                    captures: candidate_captures,
                    recorded,
                } => {
                    budget.absorb(used)?;
                    state.operator_evaluations += 1;
                    if matched {
                        budget.matched()?;
                        budget.bytes(len)?;
                        matched_any = true;
                        if capture {
                            copy_captures(tx_state, &candidate_captures);
                        }
                        if let Some(value) = recorded {
                            tx_state.record_match(candidate.matched_name(), &value);
                        }
                        self.apply_nondisruptive(
                            rule,
                            data,
                            tx_state,
                            state,
                            &mut scratch.macro_name,
                            &mut scratch.macro_value,
                        );
                    }
                }
            }
        }
        Ok(matched_any)
    }

    /// Computes (and caches per phase) the mandatory-literal hit mask for one
    /// candidate value.
    ///
    /// Each distinct `(pipeline, case)` representation is transformed once and
    /// scanned at most once: duplicate byte representations (the common case
    /// for benign values whose transforms are identity) are collapsed before
    /// the Aho-Corasick scan. `is_match` is the fast clean path; the
    /// overlapping iterator only runs when a literal is present.
    fn gate_mask(
        &self,
        candidate: &Candidate<'_>,
        scratch: &mut Scratch,
        budget: &mut Budget,
    ) -> Result<Option<u64>, EngineError> {
        let Some(value_id) = candidate.cache_id else {
            return Ok(None);
        };
        let Some(gates) = self.program.gates.as_deref() else {
            return Ok(None);
        };
        if let Some(mask) = scratch.gate_masks.get(value_id) {
            return Ok(Some(mask));
        }
        let mut mask = 0u64;
        for group in gates.groups() {
            let range = resolve_cached(
                &mut scratch.cache,
                &mut scratch.value_ids,
                &self.program.transform_prefixes,
                usize::from(group.pipeline),
                value_id,
                &candidate.value,
                &mut scratch.charged_transform_bytes,
                budget,
            )?;
            let bytes = scratch.cache.bytes(range);
            if !group.automaton.is_match(bytes) {
                continue;
            }
            for found in group.automaton.find_overlapping_iter(bytes) {
                if let Some(bits) = group.pattern_rules.get(found.pattern().as_usize()) {
                    mask |= *bits;
                }
            }
        }
        scratch.gate_masks.set(value_id, mask);
        Ok(Some(mask))
    }

    /// Fast path for the common `SecRule TX:name ...` shape: a single keyed TX
    /// target. It evaluates the value in place instead of materialising an
    /// owned [`Candidate`], which removes the two clones per TX rule that
    /// dominated the allocation profile. Every semantic step (budget charges,
    /// exception handling, captures, actions) matches the generic path.
    #[allow(clippy::too_many_arguments)]
    fn eval_tx_rule<'r, 'a>(
        &self,
        rule: &CompiledRule,
        data: &'r RequestData<'a>,
        tx_state: &mut TxState,
        budget: &mut Budget,
        state: &mut EvalState,
        captures: &mut Captures,
        scratch: &mut Scratch,
        record_matches: bool,
    ) -> Result<Option<bool>, EngineError> {
        if rule.multi_match() || rule.variables.is_empty() {
            return Ok(None);
        }
        if !rule
            .variables
            .iter()
            .all(|spec| spec.collection == Collection::Tx && !spec.negated)
        {
            return Ok(None);
        }

        let pipeline = self
            .program
            .pipelines
            .get(usize::from(rule.pipeline))
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let all_key = rule
            .variables
            .iter()
            .all(|spec| matches!(spec.selector, Selector::Key(_)));
        if !all_key {
            if rule.variables.iter().any(|spec| spec.count)
                || rule
                    .variables
                    .iter()
                    .any(|spec| matches!(spec.selector, Selector::Key(_)))
            {
                return Ok(None);
            }
            // Allocation-free dry run: if no value matches, the rule cannot
            // match and no action needs to run. On the rare hit we fall back to
            // the generic path, which owns values while actions mutate TX.
            for spec in &rule.variables {
                for (_, raw) in tx_state.tx_entries_matching(&spec.selector) {
                    budget.value()?;
                    budget.bytes(raw.len())?;
                    transform_into(
                        raw,
                        pipeline,
                        budget,
                        &mut scratch.uncached,
                        &mut scratch.uncached_tmp,
                    )?;
                    let value = &scratch.uncached;
                    state.operator_evaluations += 1;
                    if eval_operator(
                        rule,
                        value,
                        data,
                        tx_state,
                        rule.captures(),
                        captures,
                        &mut scratch.op_macro,
                        scratch.capture_locations.as_mut(),
                    ) {
                        return Ok(None);
                    }
                }
            }
            return Ok(Some(false));
        }
        let capture = rule.captures();
        let mut matched_any = false;
        for spec in &rule.variables {
            if let Selector::Key(key) = &spec.selector {
                let stored = tx_state.tx_get(key);
                let raw: &[u8] = if spec.count {
                    if let Some(value) = stored {
                        budget.value()?;
                        budget.bytes(value.len())?;
                        b"1"
                    } else {
                        b"0"
                    }
                } else {
                    let Some(value) = stored else {
                        continue;
                    };
                    value
                };
                let matched_key = if spec.count { None } else { Some(key.as_str()) };
                if target_removed_parts(rule, Collection::Tx, matched_key, state) {
                    continue;
                }
                budget.value()?;
                budget.bytes(raw.len())?;
                transform_into(
                    raw,
                    pipeline,
                    budget,
                    &mut scratch.uncached,
                    &mut scratch.uncached_tmp,
                )?;
                let value = &scratch.uncached;
                state.operator_evaluations += 1;
                let matched = eval_operator(
                    rule,
                    value,
                    data,
                    tx_state,
                    capture,
                    captures,
                    &mut scratch.op_macro,
                    scratch.capture_locations.as_mut(),
                );
                if !matched {
                    continue;
                }
                matched_any = true;
                budget.matched()?;
                budget.bytes(value.len())?;
                let matched_name = if record_matches {
                    Some(match matched_key {
                        Some(key) => format!("{}:{key}", Collection::Tx.name()),
                        None => Collection::Tx.name().to_string(),
                    })
                } else {
                    None
                };
                if capture {
                    copy_captures(tx_state, captures);
                }
                if let Some(matched_name) = matched_name {
                    tx_state.record_match(matched_name, value);
                }
                self.apply_nondisruptive(
                    rule,
                    data,
                    tx_state,
                    state,
                    &mut scratch.macro_name,
                    &mut scratch.macro_value,
                );
                continue;
            }
        }
        Ok(Some(matched_any))
    }
    /// Fast path for a single `MATCHED_VARS`/`MATCHED_VARS_NAMES` target: it
    /// iterates the recorded matches in place instead of cloning every
    /// `(name, value)` pair into a candidate vector.
    #[allow(clippy::too_many_arguments)]
    fn eval_matched_rule<'r, 'a>(
        &self,
        rule: &CompiledRule,
        data: &'r RequestData<'a>,
        tx_state: &mut TxState,
        budget: &mut Budget,
        state: &mut EvalState,
        captures: &mut Captures,
        scratch: &mut Scratch,
        record_matches: bool,
    ) -> Result<Option<bool>, EngineError> {
        if rule.multi_match() || rule.variables.len() != 1 {
            return Ok(None);
        }
        let spec = &rule.variables[0];
        if spec.negated || spec.count || !matches!(spec.selector, Selector::All) {
            return Ok(None);
        }
        let names_only = match spec.collection {
            Collection::MatchedVars => false,
            Collection::MatchedVarsNames => true,
            _ => return Ok(None),
        };
        let collection = spec.collection;
        let limit = tx_state.matched_len();
        let pipeline = self
            .program
            .pipelines
            .get(usize::from(rule.pipeline))
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let capture = rule.captures();
        let mut matched_any = false;
        for index in 0..limit {
            let Some((name, stored)) = tx_state.matched_at(index) else {
                break;
            };
            let raw = if names_only { name.as_bytes() } else { stored };
            budget.value()?;
            budget.bytes(raw.len())?;
            transform_into(
                raw,
                pipeline,
                budget,
                &mut scratch.uncached,
                &mut scratch.uncached_tmp,
            )?;
            let value = &scratch.uncached;
            state.operator_evaluations += 1;
            let matched = eval_operator(
                rule,
                value,
                data,
                tx_state,
                capture,
                captures,
                &mut scratch.op_macro,
                scratch.capture_locations.as_mut(),
            );
            if !matched {
                continue;
            }
            matched_any = true;
            budget.matched()?;
            budget.bytes(value.len())?;
            let matched_name = if record_matches {
                Some(format!("{}:{name}", collection.name()))
            } else {
                None
            };
            if capture {
                copy_captures(tx_state, captures);
            }
            if let Some(matched_name) = matched_name {
                tx_state.record_match(matched_name, value);
            }
            self.apply_nondisruptive(
                rule,
                data,
                tx_state,
                state,
                &mut scratch.macro_name,
                &mut scratch.macro_value,
            );
        }
        Ok(Some(matched_any))
    }

    fn apply_nondisruptive(
        &self,
        rule: &CompiledRule,
        data: &RequestData<'_>,
        state: &mut TxState,
        eval: &mut EvalState,
        macro_name: &mut Vec<u8>,
        macro_value: &mut Vec<u8>,
    ) {
        #[cfg(feature = "engine-profile")]
        let scoring_sample = super::profile::sample();
        for action in &rule.actions {
            match action {
                Action::SetVar { name, op, value } => {
                    // Coraza expands macros in both the variable name and the
                    // value, e.g. `tx.header_name_920450_%{tx.0}`. Static names
                    // were lowercased at parse time, so the common path does
                    // not allocate or copy.
                    let expanded_name = if name.contains('%') {
                        expand_macros_into(data, state, name, macro_name);
                        match std::str::from_utf8(macro_name) {
                            Ok(text) => std::borrow::Cow::Borrowed(text),
                            Err(_) => std::borrow::Cow::Owned(
                                String::from_utf8_lossy(macro_name).into_owned(),
                            ),
                        }
                    } else {
                        std::borrow::Cow::Borrowed(name.as_str())
                    };
                    if expanded_name.is_empty() {
                        continue;
                    }
                    let expanded: &[u8] = if value.0.contains('%') {
                        expand_macros_into(data, state, &value.0, macro_value);
                        macro_value
                    } else {
                        value.0.as_bytes()
                    };
                    match op {
                        super::ir::SetVarOp::Set => {
                            state.tx_set_bytes(&expanded_name, expanded);
                        }
                        super::ir::SetVarOp::Add => state.tx_add(&expanded_name, expanded),
                        super::ir::SetVarOp::Sub => state.tx_sub(&expanded_name, expanded),
                        super::ir::SetVarOp::Remove => state.tx_remove(&expanded_name),
                    }
                }
                Action::Ctl(ctl) => apply_ctl(ctl, state, eval),
                Action::Status(status) => eval.status = Some(*status),
                Action::Capture
                | Action::MultiMatch
                | Action::SkipAfter(_)
                | Action::InitCol
                | Action::Disruptive(_) => {}
            }
        }
        #[cfg(feature = "engine-profile")]
        super::profile::record(
            super::profile::Category::Scoring,
            scoring_sample.0,
            scoring_sample.1,
        );
    }
}

fn copy_captures(tx_state: &mut TxState, captures: &Captures) {
    #[cfg(feature = "engine-profile")]
    let sample = super::profile::sample();
    for (index, captured) in captures.iter().enumerate() {
        if !captured.is_empty() {
            tx_state.set_capture(index, captured);
        }
    }
    #[cfg(feature = "engine-profile")]
    super::profile::record(super::profile::Category::Captures, sample.0, sample.1);
}

#[allow(clippy::too_many_arguments)]
fn eval_operator(
    rule: &CompiledRule,
    value: &[u8],
    data: &RequestData<'_>,
    state: &TxState,
    capture: bool,
    captures: &mut Captures,
    scratch: &mut Vec<u8>,
    capture_locations: Option<&mut regex::bytes::CaptureLocations>,
) -> bool {
    let Some(operator) = rule.operator.as_ref() else {
        return false;
    };
    let ctx = OpContext { data, state };
    operator.evaluate(value, &ctx, capture, captures, scratch, capture_locations)
}

struct OpContext<'a, 'b> {
    data: &'a RequestData<'b>,
    state: &'a TxState,
}

impl MacroResolver for OpContext<'_, '_> {
    fn expand_into(&self, template: &str, out: &mut Vec<u8>) {
        expand_macros_into(self.data, self.state, template, out);
    }
}

fn apply_ctl(ctl: &CtlAction, state: &mut TxState, eval: &mut EvalState) {
    match ctl {
        CtlAction::RuleRemoveById(id) => {
            eval.removed_rules.insert(*id);
        }
        CtlAction::RuleRemoveByTag(tag) => {
            eval.removed_tags.insert(tag.clone());
        }
        CtlAction::RuleRemoveTargetById {
            id,
            collection,
            key,
        } => {
            eval.removed_targets.push(RemovedTarget {
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
            eval.removed_targets.push(RemovedTarget {
                rule_id: None,
                tag: Some(tag.clone()),
                collection: *collection,
                key: key.clone(),
            });
        }
        CtlAction::RequestBodyProcessor(processor) => {
            state.request_body_processor_override = Some(processor.clone());
        }
        CtlAction::ForceRequestBodyVariable(force) => {
            state.force_request_body_variable = *force;
        }
        CtlAction::AuditEngine(_) => {}
    }
}

/// True when a group reads `MATCHED_VARS` or expands a matched-variable macro.
/// Groups that do neither skip the per-match bookkeeping entirely.
fn group_records_matches(group: &RuleGroup) -> bool {
    group.rules.iter().any(|rule| {
        rule.variables.iter().any(|spec| {
            matches!(
                spec.collection,
                Collection::MatchedVars | Collection::MatchedVarsNames
            )
        }) || rule.actions.iter().any(|action| match action {
            Action::SetVar { name, value, .. } => {
                name.contains("matched_var") || value.0.contains("matched_var")
            }
            _ => false,
        })
    })
}

fn is_exception(candidate: &Candidate<'_>, exceptions: &[Candidate<'_>]) -> bool {
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

fn target_removed(rule: &CompiledRule, candidate: &Candidate<'_>, state: &EvalState) -> bool {
    target_removed_parts(rule, candidate.collection, candidate.key.as_deref(), state)
}

fn target_removed_parts(
    rule: &CompiledRule,
    collection: Collection,
    key: Option<&str>,
    state: &EvalState,
) -> bool {
    state.removed_targets.iter().any(|target| {
        let matches_rule = match target.rule_id {
            Some(id) => rule.id == Some(id),
            None => target
                .tag
                .as_ref()
                .is_some_and(|tag| rule.metadata.tags.iter().any(|rule_tag| rule_tag == tag)),
        };
        if !matches_rule || !same_collection(collection, target.collection) {
            return false;
        }
        match &target.key {
            None => true,
            Some(expected) => {
                key.is_some_and(|candidate_key| candidate_key.eq_ignore_ascii_case(expected))
            }
        }
    })
}

/// Picks the regex with the most capture groups so one reused
/// `CaptureLocations` covers every rule in the program.
fn capture_template(program: &Program) -> Option<regex::bytes::Regex> {
    let mut best: Option<&regex::bytes::Regex> = None;
    for items in [&program.phase1, &program.phase2] {
        for item in items {
            let ProgramItem::Rule(group) = item else {
                continue;
            };
            for rule in &group.rules {
                let Some(operator) = rule.operator.as_ref() else {
                    continue;
                };
                let super::ir::OperatorKind::Rx(regex) = &operator.kind else {
                    continue;
                };
                if best.is_none_or(|current| regex.captures_len() > current.captures_len()) {
                    best = Some(regex);
                }
            }
        }
    }
    best.cloned()
}

fn transform_into(
    input: &[u8],
    pipeline: &[Transform],
    budget: &mut Budget,
    out: &mut Vec<u8>,
    tmp: &mut Vec<u8>,
) -> Result<(), EngineError> {
    out.clear();
    let Some((first, rest)) = pipeline.split_first() else {
        out.extend_from_slice(input);
        return Ok(());
    };
    first.apply_into(input, out, budget)?;
    let mut result_in_out = true;
    for transform in rest {
        if result_in_out {
            transform.apply_into(out, tmp, budget)?;
        } else {
            transform.apply_into(tmp, out, budget)?;
        }
        result_in_out = !result_in_out;
    }
    if !result_in_out {
        std::mem::swap(out, tmp);
    }
    Ok(())
}

fn transform_multi_into(
    input: &[u8],
    pipeline: &[Transform],
    budget: &mut Budget,
    multi: &mut MultiBuffer,
) -> Result<(), EngineError> {
    multi.begin(input);
    let MultiBuffer {
        slots,
        len,
        current,
        next,
    } = multi;
    for transform in pipeline {
        transform.apply_into(current, next, budget)?;
        if next != current {
            std::mem::swap(current, next);
            if *len == slots.len() {
                slots.push(Vec::new());
            }
            let slot = &mut slots[*len];
            slot.clear();
            slot.extend_from_slice(current);
            *len += 1;
        }
    }
    Ok(())
}

fn marker_index(items: &[ProgramItem], marker: &str) -> Option<usize> {
    items.iter().position(|item| match item {
        ProgramItem::Marker(name) => name == marker,
        ProgramItem::Rule(_) => false,
    })
}

fn tx_i64(tx: &Collections<'_>, name: &str) -> i64 {
    tx.tx_get(name)
        .and_then(|value| std::str::from_utf8(value).ok())
        .and_then(|text| text.trim().parse::<i64>().ok())
        .unwrap_or(0)
}

/// Immutable result of evaluating one candidate on a worker.
///
/// The `Evaluated` variant owns the capture slots; boxing it would add one
/// allocation per candidate, which is exactly what this experiment measures.
#[cfg(feature = "parallel-args")]
#[allow(clippy::large_enum_variant)]
enum CandidateEval {
    /// `ctl:ruleRemoveTarget*` already excluded this candidate.
    Removed,
    /// The mandatory-literal gate proved the rule cannot match.
    GateSkipped {
        /// Bytes materialised by the gate transforms in the worker.
        used: usize,
    },
    /// The operator ran. Matches are applied by the serial reduction.
    Evaluated {
        matched: bool,
        len: usize,
        /// Bytes materialised by transforms in the worker.
        used: usize,
        captures: Captures,
        /// Transformed value for `MATCHED_VAR*` bookkeeping, when recorded.
        recorded: Option<Vec<u8>>,
    },
}

/// Per-request transform cache and reusable buffers.
///
/// The cache is the shared prefix cache from [`crate::waf::transforms`], keyed
/// by `(value, chain prefix)`. It stores bytes in a bounded arena, aliases
/// identity steps, and keeps its capacity across requests, so steady-state
/// evaluation performs no transform allocations.
#[derive(Default)]
struct Scratch {
    cache: TransformCache<Transform>,
    value_ids: Vec<Option<ValueId>>,
    charged_transform_bytes: u64,
    uncached: Vec<u8>,
    uncached_tmp: Vec<u8>,
    multi: MultiBuffer,
    macro_name: Vec<u8>,
    macro_value: Vec<u8>,
    op_macro: Vec<u8>,
    capture_locations: Option<regex::bytes::CaptureLocations>,
    tx_state: Option<TxState>,
    gate_masks: GateMaskCache,
}

/// Resolves `plan` for one value through the shared prefix cache and returns
/// the output range. The value is registered on first use and re-registered if
/// the same engine value id now refers to a different buffer.
#[allow(clippy::too_many_arguments)]
fn resolve_cached(
    cache: &mut TransformCache<Transform>,
    value_ids: &mut Vec<Option<ValueId>>,
    prefixes: &crate::waf::transforms::PrefixTable<Transform>,
    plan_index: usize,
    value_id: u32,
    input: &[u8],
    charged: &mut u64,
    budget: &mut Budget,
) -> Result<std::ops::Range<usize>, EngineError> {
    let index = value_id as usize;
    if value_ids.len() <= index {
        value_ids.resize(index + 1, None);
    }
    let id = match value_ids[index] {
        Some(id) if cache.value_matches(id, input) => id,
        _ => {
            let id = cache.begin_value(input)?;
            value_ids[index] = Some(id);
            id
        }
    };
    let range = cache.resolve(id, input, prefixes.plan(plan_index), prefixes.prefixes())?;
    let total = cache.transform_bytes();
    let delta = total.saturating_sub(*charged);
    if delta > 0 {
        budget.materialised(delta as usize)?;
        *charged = total;
    }
    Ok(range)
}

#[derive(Default)]
struct MultiBuffer {
    slots: Vec<Vec<u8>>,
    len: usize,
    current: Vec<u8>,
    next: Vec<u8>,
}

impl MultiBuffer {
    fn begin(&mut self, input: &[u8]) {
        self.len = 0;
        self.current.clear();
        self.current.extend_from_slice(input);
        if self.len == self.slots.len() {
            self.slots.push(Vec::new());
        }
        let slot = &mut self.slots[0];
        slot.clear();
        slot.extend_from_slice(input);
        self.len = 1;
    }

    fn iter(&self) -> impl Iterator<Item = &[u8]> {
        self.slots[..self.len].iter().map(Vec::as_slice)
    }
}

/// Per-phase cache of mandatory-literal hit masks keyed by value id.
struct GateMaskCache {
    masks: Vec<u64>,
    generations: Vec<u32>,
    generation: u32,
}

impl Default for GateMaskCache {
    fn default() -> Self {
        Self {
            masks: Vec::new(),
            generations: Vec::new(),
            generation: 0,
        }
    }
}

impl GateMaskCache {
    fn begin(&mut self) {
        self.generation = self.generation.wrapping_add(1);
        if self.generation == 0 {
            self.generations.fill(0);
            self.generation = 1;
        }
        if self.masks.is_empty() {
            self.masks = vec![0; 8192];
            self.generations = vec![0; 8192];
        }
    }

    fn get(&self, value_id: u32) -> Option<u64> {
        let index = value_id as usize;
        if index >= self.masks.len() || self.generations[index] != self.generation {
            return None;
        }
        Some(self.masks[index])
    }

    fn set(&mut self, value_id: u32, mask: u64) {
        let index = value_id as usize;
        if index < self.masks.len() {
            self.masks[index] = mask;
            self.generations[index] = self.generation;
        }
    }
}

thread_local! {
    static SCRATCH: RefCell<Scratch> = RefCell::new(Scratch::default());
}

#[derive(Default)]
struct EvalState {
    removed_rules: HashSet<u32>,
    removed_tags: HashSet<String>,
    removed_targets: Vec<RemovedTarget>,
    status: Option<u16>,
    allow: bool,
    operator_evaluations: u64,
    regex_evaluations_skipped: u64,
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
        let result = RustEngine::from_conf_str(text, ".", CompilePolicy::Strict);
        #[cfg(feature = "native-detect")]
        {
            assert!(result.is_ok(), "native-detect must compile @detectSQLi");
        }
        #[cfg(not(feature = "native-detect"))]
        {
            match result.expect_err("must reject") {
                LoadError::Unsupported(unsupported) => {
                    assert_eq!(unsupported.rule_id, Some(942100));
                    assert_eq!(unsupported.construct, "operator:@detectsqli");
                }
                other => panic!("unexpected error: {other}"),
            }
        }
    }

    #[test]
    fn report_mode_keeps_compiling_other_rules() {
        let text = r#"
SecRule ARGS "@rx evil" "id:1001,phase:2,deny,status:403"
"#;
        let engine = RustEngine::from_conf_str(text, ".", CompilePolicy::Report).expect("engine");
        assert_eq!(engine.support_report().rules_compiled, 1);
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
        #[cfg(feature = "native-detect")]
        {
            assert_eq!(report.rules_compiled, 505, "compiled rules");
            assert_eq!(report.rules_skipped, 0, "skipped rules");
            assert!(report.unsupported.is_empty());
            // Strict load must now succeed with the full rule set.
            RustEngine::from_conf_path(&path).expect("strict load must compile 505/505");
        }
        #[cfg(not(feature = "native-detect"))]
        {
            assert_eq!(report.rules_compiled, 501, "compiled rules");
            assert_eq!(report.rules_skipped, 4, "skipped rules");
            let ids: Vec<u32> = report
                .unsupported
                .iter()
                .filter_map(|unsupported| unsupported.rule_id)
                .collect();
            assert_eq!(ids, vec![941100, 941101, 942100, 942101]);
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

    #[test]
    fn transform_cache_is_shared_across_rules() {
        let text = r#"
SecRule ARGS "@rx evil" "id:1001,phase:2,pass,t:lowercase"
SecRule ARGS "@rx evil" "id:1002,phase:2,pass,t:lowercase"
"#;
        let engine = RustEngine::from_conf_str(text, ".", CompilePolicy::Strict).expect("engine");
        assert_eq!(engine.pipeline_count(), 1);
        let outcome = engine
            .evaluate_detailed(&request("/?q=EVIL"))
            .expect("evaluate");
        assert_eq!(outcome.matched_rules, vec![1001, 1002]);
    }
}
