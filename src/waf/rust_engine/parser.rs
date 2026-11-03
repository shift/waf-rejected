//! SecLang parser and rule compiler for request phases.
//!
//! The parser is intentionally strict. Every `SecRule`/`SecAction` is either
//! compiled into the IR or reported as an [`UnsupportedConstruct`]. In
//! [`CompilePolicy::Strict`] the first unsupported construct aborts the load
//! with the rule id and construct; [`CompilePolicy::Report`] is the offline
//! tooling mode that records the full support matrix without dropping a rule
//! silently.

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

use regex::bytes::Regex as BytesRegex;
use regex::Regex as TextRegex;

use super::error::{LoadError, UnsupportedConstruct};
use super::ir::{
    Action, Collection, CompiledOperator, CompiledRule, CtlAction, Disruptive, MacroString,
    OperatorKind, Phase, Program, ProgramItem, RuleGroup, RuleMetadata, Selector, SetVarOp,
    TransformChain, VariableSpec,
};
use super::operators::{build_phrases, parse_byte_range, parse_ip_match, parse_pm_argument};
use super::transforms::Transform;

/// How the compiler treats constructs it does not implement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompilePolicy {
    /// Abort on the first unsupported construct (production/build mode).
    Strict,
    /// Record every unsupported construct and skip only the affected rule.
    /// Used by the offline support-matrix and parity tooling.
    Report,
}

/// One construct observed in the bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConstructUse {
    /// Number of occurrences.
    pub count: usize,
    /// Whether this slice implements it.
    pub supported: bool,
}

/// Full support matrix for a parsed bundle.
#[derive(Debug, Clone, Default)]
pub struct SupportReport {
    /// Directives seen (including markers and setup directives).
    pub directives: usize,
    /// `SecRule`/`SecAction` directives seen.
    pub rules_seen: usize,
    /// Rules compiled into the program.
    pub rules_compiled: usize,
    /// Rule groups skipped in report mode because of an unsupported construct.
    pub rules_skipped: usize,
    /// Unsupported constructs, in source order.
    pub unsupported: Vec<UnsupportedConstruct>,
    /// Per-construct usage.
    pub constructs: BTreeMap<String, ConstructUse>,
}

impl SupportReport {
    fn note(&mut self, construct: impl Into<String>, supported: bool) {
        let entry = self
            .constructs
            .entry(construct.into())
            .or_insert(ConstructUse {
                count: 0,
                supported,
            });
        entry.count += 1;
        entry.supported &= supported;
    }

    fn record(&mut self, construct: UnsupportedConstruct) {
        self.note(construct.construct.clone(), false);
        self.unsupported.push(construct);
    }
}

/// Parses a CRS configuration from disk.
pub fn parse_conf_path(
    path: impl AsRef<Path>,
    policy: CompilePolicy,
) -> Result<(Program, SupportReport), LoadError> {
    let path = path.as_ref();
    let text = std::fs::read_to_string(path).map_err(|err| LoadError::Io {
        path: path.display().to_string(),
        detail: err.to_string(),
    })?;
    parse_conf_str(
        &text,
        path.parent().unwrap_or_else(|| Path::new(".")),
        policy,
    )
}

/// Parses a CRS configuration from a string.
pub fn parse_conf_str(
    text: &str,
    base_dir: impl AsRef<Path>,
    policy: CompilePolicy,
) -> Result<(Program, SupportReport), LoadError> {
    let mut compiler = Compiler::new(base_dir.as_ref().to_path_buf(), policy);
    compiler.parse_text(text, "<memory>")?;
    compiler.finish()
}

struct Compiler {
    base_dir: PathBuf,
    policy: CompilePolicy,
    report: SupportReport,
    defaults: BTreeMap<Phase, DefaultAction>,
    program: Program,
    included: HashSet<PathBuf>,
    pending_chain: Option<Vec<RawRule>>,
}

#[derive(Debug, Clone)]
struct DefaultAction {
    actions: Vec<Action>,
    metadata: RuleMetadata,
    disruptive: Option<Disruptive>,
}

#[derive(Debug, Clone)]
struct RawRule {
    id: Option<u32>,
    variables: Option<String>,
    operator: Option<String>,
    actions: String,
    line: usize,
    file: String,
}

struct ParsedActions {
    id: Option<u32>,
    phase: Option<Phase>,
    transforms: TransformChain,
    actions: Vec<Action>,
    metadata: RuleMetadata,
    disruptive: Option<Disruptive>,
    chain: bool,
}

impl Compiler {
    fn new(base_dir: PathBuf, policy: CompilePolicy) -> Self {
        Self {
            base_dir,
            policy,
            report: SupportReport::default(),
            defaults: BTreeMap::new(),
            program: Program::default(),
            included: HashSet::new(),
            pending_chain: None,
        }
    }

    fn finish(mut self) -> Result<(Program, SupportReport), LoadError> {
        if let Some(chain) = self.pending_chain.take() {
            self.finish_group(chain)?;
        }
        self.resolve_skip_after()?;
        if self.program.phase1.is_empty() && self.program.phase2.is_empty() {
            return Err(LoadError::Empty);
        }
        self.program.intern_pipelines();
        let gates = crate::waf::rust_engine::gate::attach(&mut self.program)
            .map_err(|detail| LoadError::Parse { line: 0, detail })?;
        self.program.gates = gates;
        Ok((self.program, self.report))
    }

    fn parse_text(&mut self, text: &str, file: &str) -> Result<(), LoadError> {
        for (line, directive) in logical_lines(text) {
            self.report.directives += 1;
            self.parse_directive(&directive, line, file)?;
        }
        Ok(())
    }

    fn parse_directive(
        &mut self,
        directive: &str,
        line: usize,
        file: &str,
    ) -> Result<(), LoadError> {
        let tokens = tokenize(directive).map_err(|detail| LoadError::Parse { line, detail })?;
        let Some(name) = tokens.first() else {
            return Ok(());
        };
        match name.as_str() {
            "SecRule" => {
                self.report.rules_seen += 1;
                self.report.note("directive:SecRule", true);
                if tokens.len() < 3 {
                    return Err(LoadError::Parse {
                        line,
                        detail: "SecRule requires variables and an operator".to_string(),
                    });
                }
                let actions = tokens.get(3).cloned().unwrap_or_default();
                let raw = RawRule {
                    id: None,
                    variables: Some(tokens[1].clone()),
                    operator: Some(tokens[2].clone()),
                    actions,
                    line,
                    file: file.to_string(),
                };
                self.push_raw_rule(raw)
            }
            "SecAction" => {
                self.report.rules_seen += 1;
                self.report.note("directive:SecAction", true);
                let actions = tokens.get(1).cloned().unwrap_or_default();
                let raw = RawRule {
                    id: None,
                    variables: None,
                    operator: None,
                    actions,
                    line,
                    file: file.to_string(),
                };
                self.push_raw_rule(raw)
            }
            "SecDefaultAction" => {
                self.report.note("directive:SecDefaultAction", true);
                let Some(actions) = tokens.get(1) else {
                    return Err(LoadError::Parse {
                        line,
                        detail: "SecDefaultAction requires actions".to_string(),
                    });
                };
                self.parse_default_action(actions, line)
            }
            "SecMarker" => {
                self.report.note("directive:SecMarker", true);
                let Some(marker) = tokens.get(1) else {
                    return Err(LoadError::Parse {
                        line,
                        detail: "SecMarker requires a name".to_string(),
                    });
                };
                if self.pending_chain.is_some() {
                    return Err(LoadError::Parse {
                        line,
                        detail: "SecMarker inside a chain".to_string(),
                    });
                }
                // Markers are phase-independent in SecLang. Add the marker to
                // both request-phase programs so a `skipAfter` in either phase
                // can resolve it.
                self.program
                    .phase1
                    .push(ProgramItem::Marker(marker.clone()));
                self.program
                    .phase2
                    .push(ProgramItem::Marker(marker.clone()));
                Ok(())
            }
            "SecComponentSignature" | "SecServerSignature" | "SecRuleEngine" => {
                self.report.note(format!("directive:{name}"), true);
                Ok(())
            }
            "Include" => {
                self.report.note("directive:Include", true);
                let Some(path) = tokens.get(1) else {
                    return Err(LoadError::Parse {
                        line,
                        detail: "Include requires a path".to_string(),
                    });
                };
                self.include(path, line)
            }
            other => self.unsupported(
                None,
                line,
                format!("directive:{other}"),
                "directive is not part of the request-phase slice",
            ),
        }
    }

    fn include(&mut self, path: &str, line: usize) -> Result<(), LoadError> {
        let resolved = self.resolve_path(path);
        let canonical = resolved.canonicalize().unwrap_or_else(|_| resolved.clone());
        if !self.included.insert(canonical) {
            return Ok(());
        }
        let text = std::fs::read_to_string(&resolved).map_err(|err| LoadError::Io {
            path: resolved.display().to_string(),
            detail: err.to_string(),
        })?;
        self.parse_text(&text, &resolved.display().to_string())
            .map_err(|err| match err {
                LoadError::Parse { detail, .. } => LoadError::Parse { line, detail },
                other => other,
            })
    }

    fn parse_default_action(&mut self, text: &str, line: usize) -> Result<(), LoadError> {
        let parsed = self.parse_actions(text, line, None)?;
        let Some(phase) = parsed.phase else {
            return Err(LoadError::Parse {
                line,
                detail: "SecDefaultAction must specify a phase".to_string(),
            });
        };
        self.defaults.insert(
            phase,
            DefaultAction {
                actions: parsed.actions,
                metadata: parsed.metadata,
                disruptive: parsed.disruptive,
            },
        );
        Ok(())
    }

    fn push_raw_rule(&mut self, raw: RawRule) -> Result<(), LoadError> {
        if let Some(chain) = &mut self.pending_chain {
            let continues = raw_has_chain(&raw);
            chain.push(raw);
            if !continues {
                let chain = self.pending_chain.take().unwrap_or_default();
                self.finish_group(chain)?;
            }
            return Ok(());
        }
        if raw_has_chain(&raw) {
            self.pending_chain = Some(vec![raw]);
            Ok(())
        } else {
            self.finish_group(vec![raw])
        }
    }

    fn finish_group(&mut self, raws: Vec<RawRule>) -> Result<(), LoadError> {
        let mut rules = Vec::with_capacity(raws.len());
        let mut skipped = false;
        let parent = match self.compile_rule(&raws[0], None) {
            Ok(Some(rule)) => rule,
            Ok(None) => {
                // Still walk the members so report mode records their
                // constructs, but never add a group without a parent.
                for raw in &raws[1..] {
                    if let Ok(Some(_)) = self.compile_rule(raw, Some(Phase::RequestBody)) {
                        // discarded
                    }
                }
                self.report.rules_skipped += raws.len();
                return Ok(());
            }
            Err(err) => return Err(err),
        };
        let parent_phase = parent.phase;
        rules.push(parent);
        for raw in &raws[1..] {
            match self.compile_rule(raw, Some(parent_phase)) {
                Ok(Some(rule)) => rules.push(rule),
                Ok(None) => skipped = true,
                Err(err) => return Err(err),
            }
        }
        if skipped {
            self.report.rules_skipped += raws.len();
            return Ok(());
        }
        self.report.rules_compiled += rules.len();
        let line = raws[0].line;
        let group = RuleGroup { rules, line };
        match parent_phase {
            Phase::RequestHeaders => self.program.phase1.push(ProgramItem::Rule(Box::new(group))),
            Phase::RequestBody => self.program.phase2.push(ProgramItem::Rule(Box::new(group))),
        }
        Ok(())
    }

    fn compile_rule(
        &mut self,
        raw: &RawRule,
        forced_phase: Option<Phase>,
    ) -> Result<Option<CompiledRule>, LoadError> {
        let parsed = match self.parse_actions(&raw.actions, raw.line, raw.id) {
            Ok(parsed) => parsed,
            Err(LoadError::Unsupported(unsupported)) => {
                self.handle_unsupported(unsupported)?;
                return Ok(None);
            }
            Err(err) => {
                self.handle_fatal(err)?;
                return Ok(None);
            }
        };
        let phase = forced_phase.or(parsed.phase).unwrap_or(Phase::RequestBody);
        let defaults = self.defaults.get(&phase).cloned().unwrap_or(DefaultAction {
            actions: Vec::new(),
            metadata: RuleMetadata::default(),
            disruptive: None,
        });

        let variables = match &raw.variables {
            Some(variables) => match self.parse_variables(variables, raw.line) {
                Ok(variables) => variables,
                Err(LoadError::Unsupported(unsupported)) => {
                    self.handle_unsupported(unsupported)?;
                    return Ok(None);
                }
                Err(err) => {
                    self.handle_fatal(err)?;
                    return Ok(None);
                }
            },
            None => Vec::new(),
        };

        let operator = match &raw.operator {
            Some(operator) => match self.parse_operator(operator, raw.line, parsed.id) {
                Ok(operator) => Some(operator),
                Err(LoadError::Unsupported(unsupported)) => {
                    self.handle_unsupported(unsupported)?;
                    return Ok(None);
                }
                Err(err) => {
                    self.handle_fatal(err)?;
                    return Ok(None);
                }
            },
            None => None,
        };

        let mut actions = defaults.actions;
        actions.extend(parsed.actions);
        let mut metadata = defaults.metadata;
        merge_metadata(&mut metadata, &parsed.metadata);
        let disruptive = match parsed.disruptive {
            Some(Disruptive::Block) => defaults.disruptive.or(Some(Disruptive::Pass)),
            Some(other) => Some(other),
            None => defaults.disruptive.or(Some(Disruptive::Pass)),
        };
        if let Some(disruptive) = disruptive {
            actions.push(Action::Disruptive(disruptive));
        }

        Ok(Some(CompiledRule {
            id: parsed.id.or(raw.id),
            phase,
            variables,
            operator,
            transforms: parsed.transforms,
            pipeline: 0,
            actions,
            metadata,
            file: raw.file.clone(),
            line: raw.line,
            gate: None,
        }))
    }

    fn parse_actions(
        &mut self,
        text: &str,
        line: usize,
        id_hint: Option<u32>,
    ) -> Result<ParsedActions, LoadError> {
        let mut parsed = ParsedActions {
            id: id_hint,
            phase: None,
            transforms: Vec::new(),
            actions: Vec::new(),
            metadata: RuleMetadata::default(),
            disruptive: None,
            chain: false,
        };
        for raw_action in split_actions(text) {
            let raw_action = raw_action.trim();
            if raw_action.is_empty() {
                continue;
            }
            let (name, value) = match raw_action.split_once(':') {
                Some((name, value)) => (name.trim(), unquote(value.trim())),
                None => (raw_action, String::new()),
            };
            let lower = name.to_ascii_lowercase();
            match lower.as_str() {
                "id" => {
                    self.report.note("action:id", true);
                    parsed.id = Some(parse_u32(&value, line, "id")?);
                }
                "phase" => {
                    self.report.note("action:phase", true);
                    let number = parse_u32(&value, line, "phase")?;
                    let number = u8::try_from(number).map_err(|_| LoadError::Parse {
                        line,
                        detail: format!("invalid phase `{value}`"),
                    })?;
                    let phase = Phase::from_number(number).ok_or_else(|| {
                        LoadError::Unsupported(UnsupportedConstruct::new(
                            parsed.id,
                            line,
                            format!("action:phase:{number}"),
                            "only request phases 1 and 2 are implemented",
                        ))
                    })?;
                    parsed.phase = Some(phase);
                }
                "t" => {
                    let transform = Transform::parse(&value).ok_or_else(|| {
                        LoadError::Unsupported(UnsupportedConstruct::new(
                            parsed.id,
                            line,
                            format!("transform:{}", value.to_ascii_lowercase()),
                            "transform is not implemented",
                        ))
                    })?;
                    self.report
                        .note(format!("transform:{}", value.to_ascii_lowercase()), true);
                    if transform == Transform::None {
                        parsed.transforms.clear();
                    } else {
                        parsed.transforms.push(transform);
                    }
                }
                "block" => {
                    self.report.note("action:block", true);
                    parsed.disruptive = Some(Disruptive::Block);
                }
                "pass" => {
                    self.report.note("action:pass", true);
                    parsed.disruptive = Some(Disruptive::Pass);
                }
                "deny" => {
                    self.report.note("action:deny", true);
                    parsed.disruptive = Some(Disruptive::Deny);
                }
                "drop" => {
                    self.report.note("action:drop", true);
                    parsed.disruptive = Some(Disruptive::Drop);
                }
                "allow" => {
                    self.report.note("action:allow", true);
                    parsed.disruptive = Some(Disruptive::Allow);
                }
                "status" => {
                    self.report.note("action:status", true);
                    let status = parse_u32(&value, line, "status")?;
                    let status = u16::try_from(status).map_err(|_| LoadError::Parse {
                        line,
                        detail: format!("invalid status `{value}`"),
                    })?;
                    parsed.actions.push(Action::Status(status));
                }
                "chain" => {
                    self.report.note("action:chain", true);
                    parsed.chain = true;
                }
                "capture" => {
                    self.report.note("action:capture", true);
                    parsed.actions.push(Action::Capture);
                }
                "multimatch" => {
                    self.report.note("action:multiMatch", true);
                    parsed.actions.push(Action::MultiMatch);
                }
                "setvar" => {
                    self.report.note("action:setvar", true);
                    parsed.actions.push(self.parse_setvar(&value, line)?);
                }
                "ctl" => {
                    self.report.note("action:ctl", true);
                    parsed
                        .actions
                        .push(self.parse_ctl(&value, line, parsed.id)?);
                }
                "skipafter" => {
                    self.report.note("action:skipAfter", true);
                    parsed.actions.push(Action::SkipAfter(value));
                }
                "initcol" => {
                    self.report.note("action:initcol", true);
                    parsed.actions.push(Action::InitCol);
                }
                "msg" => {
                    self.report.note("action:msg", true);
                    parsed.metadata.msg = Some(value);
                }
                "logdata" => {
                    self.report.note("action:logdata", true);
                    parsed.metadata.logdata = Some(value);
                }
                "tag" => {
                    self.report.note("action:tag", true);
                    parsed.metadata.tags.push(value);
                }
                "severity" => {
                    self.report.note("action:severity", true);
                    parsed.metadata.severity = Some(value);
                }
                "rev" => {
                    self.report.note("action:rev", true);
                    parsed.metadata.rev = Some(value);
                }
                "ver" => {
                    self.report.note("action:ver", true);
                    parsed.metadata.ver = Some(value);
                }
                "log" => {
                    self.report.note("action:log", true);
                    parsed.metadata.log = true;
                }
                "nolog" => {
                    self.report.note("action:nolog", true);
                    parsed.metadata.log = false;
                }
                "auditlog" => {
                    self.report.note("action:auditlog", true);
                    parsed.metadata.audit_log = true;
                }
                "noauditlog" => {
                    self.report.note("action:noauditlog", true);
                    parsed.metadata.audit_log = false;
                }
                other => {
                    return Err(LoadError::Unsupported(UnsupportedConstruct::new(
                        parsed.id,
                        line,
                        format!("action:{other}"),
                        "action is not implemented",
                    )));
                }
            }
        }
        Ok(parsed)
    }

    fn parse_setvar(&mut self, value: &str, line: usize) -> Result<Action, LoadError> {
        let (name, raw_value) = value.split_once('=').ok_or_else(|| LoadError::Parse {
            line,
            detail: format!("invalid setvar `{value}`"),
        })?;
        let name = name.trim();
        let name = name.strip_prefix("tx.").unwrap_or(name);
        // TX variable names are case-insensitive. Intern the common static
        // form in lowercase so the request path never lowercases a name;
        // macro-bearing names stay verbatim and are expanded at runtime.
        let name = if name.contains('%') {
            name.to_string()
        } else {
            name.to_ascii_lowercase()
        };
        let (op, raw_value) = match raw_value.chars().next() {
            Some('+') => (SetVarOp::Add, &raw_value[1..]),
            Some('-') => (SetVarOp::Sub, &raw_value[1..]),
            Some('!') => (SetVarOp::Remove, &raw_value[1..]),
            _ => (SetVarOp::Set, raw_value),
        };
        Ok(Action::SetVar {
            name,
            op,
            value: MacroString(unquote(raw_value).to_string()),
        })
    }

    fn parse_ctl(
        &mut self,
        value: &str,
        line: usize,
        id: Option<u32>,
    ) -> Result<Action, LoadError> {
        let (name, argument) = value.split_once('=').ok_or_else(|| LoadError::Parse {
            line,
            detail: format!("invalid ctl `{value}`"),
        })?;
        let lower = name.trim().to_ascii_lowercase();
        let argument = unquote(argument.trim());
        let action = match lower.as_str() {
            "ruleremovebyid" => CtlAction::RuleRemoveById(parse_u32(&argument, line, "ctl")?),
            "ruleremovebytag" => CtlAction::RuleRemoveByTag(argument),
            "ruleremovetargetbyid" => {
                let (id_text, target) =
                    argument.split_once(';').ok_or_else(|| LoadError::Parse {
                        line,
                        detail: format!("invalid ctl target `{argument}`"),
                    })?;
                let (collection, key) = self.parse_target(target, line, id)?;
                CtlAction::RuleRemoveTargetById {
                    id: parse_u32(id_text, line, "ctl")?,
                    collection,
                    key,
                }
            }
            "ruleremovetargetbytag" => {
                let (tag, target) = argument.split_once(';').ok_or_else(|| LoadError::Parse {
                    line,
                    detail: format!("invalid ctl target `{argument}`"),
                })?;
                let (collection, key) = self.parse_target(target, line, id)?;
                CtlAction::RuleRemoveTargetByTag {
                    tag: tag.to_string(),
                    collection,
                    key,
                }
            }
            "requestbodyprocessor" => CtlAction::RequestBodyProcessor(argument),
            "forcerequestbodyvariable" => CtlAction::ForceRequestBodyVariable(matches!(
                argument.to_ascii_lowercase().as_str(),
                "on" | "1" | "true"
            )),
            "auditengine" => CtlAction::AuditEngine(matches!(
                argument.to_ascii_lowercase().as_str(),
                "on" | "1" | "true" | "relevantonly"
            )),
            other => {
                return Err(LoadError::Unsupported(UnsupportedConstruct::new(
                    id,
                    line,
                    format!("ctl:{other}"),
                    "ctl operation is not implemented",
                )));
            }
        };
        Ok(Action::Ctl(action))
    }

    fn parse_target(
        &mut self,
        target: &str,
        line: usize,
        id: Option<u32>,
    ) -> Result<(Collection, Option<String>), LoadError> {
        let (collection_name, key) = match target.split_once(':') {
            Some((collection, key)) => (collection, Some(key.to_string())),
            None => (target, None),
        };
        let collection = Collection::parse(collection_name.trim()).ok_or_else(|| {
            LoadError::Unsupported(UnsupportedConstruct::new(
                id,
                line,
                format!("collection:{}", collection_name.trim()),
                "unknown collection",
            ))
        })?;
        Ok((collection, key))
    }

    fn parse_variables(&mut self, text: &str, line: usize) -> Result<Vec<VariableSpec>, LoadError> {
        let mut specs = Vec::new();
        for raw in split_variables(text) {
            let raw = raw.trim();
            if raw.is_empty() {
                continue;
            }
            let mut rest = raw;
            let mut negated = false;
            let mut count = false;
            loop {
                if let Some(stripped) = rest.strip_prefix('!') {
                    negated = true;
                    rest = stripped;
                } else if let Some(stripped) = rest.strip_prefix('&') {
                    count = true;
                    rest = stripped;
                } else {
                    break;
                }
            }
            let (collection_name, selector_text) = match rest.split_once(':') {
                Some((collection, selector)) => (collection, Some(selector.to_string())),
                None => (rest, None),
            };
            let collection = Collection::parse(collection_name.trim()).ok_or_else(|| {
                LoadError::Unsupported(UnsupportedConstruct::new(
                    None,
                    line,
                    format!("collection:{}", collection_name.trim()),
                    "unknown collection",
                ))
            })?;
            self.report
                .note(format!("collection:{}", collection.name()), true);
            let selector = match selector_text.as_deref() {
                None => Selector::All,
                Some(selector) if selector.starts_with("/*") || selector.starts_with("//") => {
                    // XML/JSON XPath selectors are accepted but the reactor never
                    // enables the XML processor, so the collection is empty.
                    Selector::All
                }
                Some(selector)
                    if selector.len() >= 2
                        && selector.starts_with('/')
                        && selector.ends_with('/') =>
                {
                    let pattern = &selector[1..selector.len() - 1];
                    // Coraza lowercases the selector text for collections whose
                    // keys are not case sensitive. ARGS* keep the selector as
                    // written.
                    let pattern = if case_sensitive_selector(collection) {
                        pattern.to_string()
                    } else {
                        pattern.to_ascii_lowercase()
                    };
                    let regex = TextRegex::new(&pattern).map_err(|err| LoadError::Regex {
                        rule_id: None,
                        line,
                        pattern,
                        detail: err.to_string(),
                    })?;
                    Selector::Regex(regex)
                }
                Some(selector) => {
                    let selector = if case_sensitive_selector(collection) {
                        selector.to_string()
                    } else {
                        selector.to_ascii_lowercase()
                    };
                    Selector::Key(selector)
                }
            };
            specs.push(VariableSpec {
                collection,
                selector_text,
                selector,
                negated,
                count,
            });
        }
        Ok(specs)
    }

    fn parse_operator(
        &mut self,
        text: &str,
        line: usize,
        id: Option<u32>,
    ) -> Result<CompiledOperator, LoadError> {
        let (negated, rest) = match text.strip_prefix('!') {
            Some(rest) => (true, rest),
            None => (false, text),
        };
        let (name, argument) = if let Some(rest) = rest.strip_prefix('@') {
            match rest.split_once(' ') {
                Some((name, argument)) => (name, argument),
                None => (rest, ""),
            }
        } else {
            ("rx", rest)
        };
        let lower = name.to_ascii_lowercase();
        self.report.note(format!("operator:@{}", lower), true);
        let kind = match lower.as_str() {
            "rx" => OperatorKind::Rx(self.compile_rx(argument, line, id)?),
            "pm" => {
                let phrases = parse_pm_argument(argument);
                let automaton = build_phrases(phrases).map_err(|_| LoadError::Parse {
                    line,
                    detail: "failed to build @pm automaton".to_string(),
                })?;
                OperatorKind::Pm(automaton)
            }
            "pmfromfile" => {
                let phrases = self.load_phrases(argument, line, id)?;
                let automaton = build_phrases(phrases).map_err(|_| LoadError::Parse {
                    line,
                    detail: format!("failed to build @pmFromFile automaton for `{argument}`"),
                })?;
                OperatorKind::PmFromFile(automaton)
            }
            "contains" => OperatorKind::Contains(MacroString(argument.to_string())),
            "beginswith" => OperatorKind::BeginsWith(MacroString(argument.to_string())),
            "endswith" => OperatorKind::EndsWith(MacroString(argument.to_string())),
            "within" => OperatorKind::Within(MacroString(argument.to_string())),
            "streq" => OperatorKind::StrEq(MacroString(argument.to_string())),
            "eq" => OperatorKind::Eq(MacroString(argument.to_string())),
            "lt" => OperatorKind::Lt(MacroString(argument.to_string())),
            "gt" => OperatorKind::Gt(MacroString(argument.to_string())),
            "ge" => OperatorKind::Ge(MacroString(argument.to_string())),
            "le" => OperatorKind::Le(MacroString(argument.to_string())),
            "validatebyterange" => {
                let valid = parse_byte_range(argument)
                    .map_err(|detail| LoadError::Parse { line, detail })?;
                OperatorKind::ValidateByteRange(Box::new(valid))
            }
            "validateurlencoding" => OperatorKind::ValidateUrlEncoding,
            "validateutf8encoding" => OperatorKind::ValidateUtf8Encoding,
            "unconditionalmatch" => OperatorKind::UnconditionalMatch,
            "ipmatch" => OperatorKind::IpMatch(parse_ip_match(argument)),
            "detectsqli" => {
                #[cfg(feature = "native-detect")]
                {
                    OperatorKind::DetectSqlInjection
                }
                #[cfg(not(feature = "native-detect"))]
                {
                    return Err(LoadError::Unsupported(UnsupportedConstruct::new(
                        id,
                        line,
                        format!("operator:@{}", lower),
                        "requires the `native-detect` feature",
                    )));
                }
            }
            "detectxss" => {
                #[cfg(feature = "native-detect")]
                {
                    OperatorKind::DetectXss
                }
                #[cfg(not(feature = "native-detect"))]
                {
                    return Err(LoadError::Unsupported(UnsupportedConstruct::new(
                        id,
                        line,
                        format!("operator:@{}", lower),
                        "requires the `native-detect` feature",
                    )));
                }
            }
            other => {
                return Err(LoadError::Unsupported(UnsupportedConstruct::new(
                    id,
                    line,
                    format!("operator:@{other}"),
                    "operator is not implemented",
                )));
            }
        };
        Ok(CompiledOperator {
            kind,
            negated,
            argument: argument.to_string(),
        })
    }

    fn compile_rx(
        &mut self,
        pattern: &str,
        line: usize,
        id: Option<u32>,
    ) -> Result<BytesRegex, LoadError> {
        let normalized = normalize_pattern(pattern);
        let ascii_only = normalized.is_ascii()
            && !normalized.contains("\\x{")
            && !normalized.contains("\\p")
            && !normalized.contains("\\P");
        let prefixed = if ascii_only {
            format!("(?sm)(?-u){normalized}")
        } else {
            format!("(?sm){normalized}")
        };
        BytesRegex::new(&prefixed).map_err(|err| LoadError::Regex {
            rule_id: id,
            line,
            pattern: pattern.to_string(),
            detail: err.to_string(),
        })
    }

    fn load_phrases(
        &mut self,
        name: &str,
        line: usize,
        id: Option<u32>,
    ) -> Result<Vec<Vec<u8>>, LoadError> {
        let path = self.resolve_data_path(name);
        let text = std::fs::read_to_string(&path).map_err(|err| LoadError::DataFile {
            rule_id: id,
            line,
            path: path.display().to_string(),
            detail: err.to_string(),
        })?;
        let mut phrases = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            phrases.push(line.to_ascii_lowercase().into_bytes());
        }
        Ok(phrases)
    }

    fn resolve_path(&self, path: &str) -> PathBuf {
        let path = Path::new(path);
        if path.is_absolute() {
            return path.to_path_buf();
        }
        self.base_dir.join(path)
    }

    fn resolve_data_path(&self, name: &str) -> PathBuf {
        let direct = self.base_dir.join(name);
        if direct.exists() {
            return direct;
        }
        let rules = self.base_dir.join("rules").join(name);
        if rules.exists() {
            return rules;
        }
        direct
    }

    fn handle_unsupported(&mut self, unsupported: UnsupportedConstruct) -> Result<(), LoadError> {
        self.report.record(unsupported.clone());
        match self.policy {
            CompilePolicy::Strict => Err(LoadError::Unsupported(unsupported)),
            CompilePolicy::Report => Ok(()),
        }
    }

    fn handle_fatal(&mut self, err: LoadError) -> Result<(), LoadError> {
        match self.policy {
            CompilePolicy::Strict => Err(err),
            CompilePolicy::Report => {
                let unsupported = match err {
                    LoadError::Unsupported(unsupported) => unsupported,
                    other => UnsupportedConstruct::new(
                        None,
                        0,
                        "rule",
                        format!("rule failed to compile: {other}"),
                    ),
                };
                self.report.record(unsupported);
                Ok(())
            }
        }
    }

    fn unsupported(
        &mut self,
        id: Option<u32>,
        line: usize,
        construct: String,
        reason: &str,
    ) -> Result<(), LoadError> {
        self.handle_unsupported(UnsupportedConstruct::new(id, line, construct, reason))
    }

    fn resolve_skip_after(&mut self) -> Result<(), LoadError> {
        Self::resolve_skip_after_phase(&mut self.program.phase1)?;
        Self::resolve_skip_after_phase(&mut self.program.phase2)?;
        Ok(())
    }

    fn resolve_skip_after_phase(items: &mut [ProgramItem]) -> Result<(), LoadError> {
        let mut markers = BTreeMap::new();
        for (index, item) in items.iter().enumerate() {
            if let ProgramItem::Marker(name) = item {
                markers.insert(name.clone(), index);
            }
        }
        for item in items.iter() {
            let ProgramItem::Rule(group) = item else {
                continue;
            };
            for rule in &group.rules {
                for action in &rule.actions {
                    if let Action::SkipAfter(marker) = action {
                        if !markers.contains_key(marker) {
                            return Err(LoadError::UnknownMarker {
                                rule_id: rule.id,
                                line: rule.line,
                                marker: marker.clone(),
                            });
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

fn case_sensitive_selector(collection: Collection) -> bool {
    matches!(
        collection,
        Collection::Args
            | Collection::ArgsGet
            | Collection::ArgsPost
            | Collection::ArgsNames
            | Collection::ArgsGetNames
            | Collection::ArgsPostNames
    )
}

fn merge_metadata(target: &mut RuleMetadata, source: &RuleMetadata) {
    if source.msg.is_some() {
        target.msg = source.msg.clone();
    }
    if source.logdata.is_some() {
        target.logdata = source.logdata.clone();
    }
    if !source.tags.is_empty() {
        target.tags.extend(source.tags.iter().cloned());
    }
    if source.severity.is_some() {
        target.severity = source.severity.clone();
    }
    if source.rev.is_some() {
        target.rev = source.rev.clone();
    }
    if source.ver.is_some() {
        target.ver = source.ver.clone();
    }
    target.log = source.log || target.log;
    target.audit_log = source.audit_log || target.audit_log;
}

/// Normalises PCRE constructs that the Rust regex crate spells differently.
///
/// The transformations are semantics-preserving for the pinned CRS:
/// * `\x{XX}` (byte escapes) become `\xXX`;
/// * literal braces such as `{.*}` become `\{.\*\}`;
/// * escapes of non-metacharacters such as `\!` or `\<` lose the backslash.
fn normalize_pattern(pattern: &str) -> String {
    let converted = convert_hex_braces(pattern);
    let braces = escape_literal_braces(&converted);
    strip_unsupported_escapes(&braces)
}

fn convert_hex_braces(pattern: &str) -> String {
    let chars: Vec<char> = pattern.chars().collect();
    let mut out = String::with_capacity(pattern.len());
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '\\' && i + 2 < chars.len() && chars[i + 1] == 'x' && chars[i + 2] == '{' {
            if let Some(end) = chars[i + 3..].iter().position(|ch| *ch == '}') {
                let end = i + 3 + end;
                let digits: String = chars[i + 3..end].iter().collect();
                if let Ok(value) = u32::from_str_radix(&digits, 16) {
                    if value <= 0xff {
                        out.push_str(&format!("\\x{value:02x}"));
                        i = end + 1;
                        continue;
                    }
                }
            }
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

fn escape_literal_braces(pattern: &str) -> String {
    let chars: Vec<char> = pattern.chars().collect();
    let mut out = String::with_capacity(pattern.len());
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '\\' {
            out.push('\\');
            if i + 1 < chars.len() {
                out.push(chars[i + 1]);
                i += 2;
            } else {
                i += 1;
            }
            continue;
        }
        if chars[i] == '{' {
            if let Some(end) = quantifier_end(&chars, i) {
                out.extend(chars[i..=end].iter());
                i = end + 1;
            } else {
                out.push_str("\\{");
                i += 1;
            }
            continue;
        }
        if chars[i] == '}' {
            out.push_str("\\}");
            i += 1;
            continue;
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

fn quantifier_end(chars: &[char], start: usize) -> Option<usize> {
    let mut index = start + 1;
    let digits_start = index;
    while index < chars.len() && chars[index].is_ascii_digit() {
        index += 1;
    }
    if index == digits_start {
        return None;
    }
    if index < chars.len() && chars[index] == ',' {
        index += 1;
        while index < chars.len() && chars[index].is_ascii_digit() {
            index += 1;
        }
    }
    if index < chars.len() && chars[index] == '}' {
        Some(index)
    } else {
        None
    }
}

fn strip_unsupported_escapes(pattern: &str) -> String {
    let chars: Vec<char> = pattern.chars().collect();
    let mut out = String::with_capacity(pattern.len());
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '\\' && i + 1 < chars.len() {
            let next = chars[i + 1];
            let keep = next.is_ascii_alphanumeric()
                || matches!(
                    next,
                    '.' | '+'
                        | '*'
                        | '?'
                        | '('
                        | ')'
                        | '['
                        | ']'
                        | '{'
                        | '}'
                        | '|'
                        | '^'
                        | '$'
                        | '\\'
                        | '-'
                );
            if keep {
                out.push('\\');
                out.push(next);
            } else {
                out.push(next);
            }
            i += 2;
            continue;
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

fn parse_u32(value: &str, line: usize, field: &str) -> Result<u32, LoadError> {
    value.trim().parse::<u32>().map_err(|_| LoadError::Parse {
        line,
        detail: format!("invalid {field} `{value}`"),
    })
}

fn raw_has_chain(raw: &RawRule) -> bool {
    split_actions(&raw.actions)
        .iter()
        .any(|action| action.trim().eq_ignore_ascii_case("chain"))
}

fn unquote(value: &str) -> String {
    let value = value.trim();
    if value.len() >= 2 {
        let bytes = value.as_bytes();
        if (bytes[0] == b'\'' && bytes[value.len() - 1] == b'\'')
            || (bytes[0] == b'"' && bytes[value.len() - 1] == b'"')
        {
            return value[1..value.len() - 1].to_string();
        }
    }
    value.to_string()
}

/// Splits an action list on top-level commas, respecting quotes.
fn split_actions(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for ch in text.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
            continue;
        }
        if ch == '\\' {
            current.push(ch);
            escaped = true;
            continue;
        }
        match quote {
            Some(active) => {
                if ch == active {
                    quote = None;
                }
                current.push(ch);
            }
            None => {
                if ch == '\'' || ch == '"' {
                    quote = Some(ch);
                    current.push(ch);
                } else if ch == ',' {
                    out.push(std::mem::take(&mut current));
                } else {
                    current.push(ch);
                }
            }
        }
    }
    if !current.trim().is_empty() {
        out.push(current);
    }
    out
}

/// Splits a variable list on `|`, ignoring pipes inside a `/regex/` selector
/// and inside an XPath selector (`XML:/*`).
fn split_variables(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut collection = String::new();
    let mut after_colon = false;
    let mut in_regex = false;
    let mut in_xpath = false;
    let mut escaped = false;
    let mut previous = '\0';
    for ch in text.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
            previous = ch;
            continue;
        }
        if ch == '\\' {
            current.push(ch);
            escaped = true;
            previous = ch;
            continue;
        }
        if in_regex {
            current.push(ch);
            if ch == '/' {
                in_regex = false;
            }
            previous = ch;
            continue;
        }
        if in_xpath {
            if ch == '|' {
                out.push(std::mem::take(&mut current));
                collection.clear();
                after_colon = false;
                in_xpath = false;
            } else {
                current.push(ch);
            }
            previous = ch;
            continue;
        }
        if ch == ':' {
            after_colon = true;
            collection = current.clone();
            current.push(ch);
            if collection.eq_ignore_ascii_case("XML") || collection.eq_ignore_ascii_case("JSON") {
                in_xpath = true;
            }
            previous = ch;
            continue;
        }
        if after_colon && ch == '/' && previous == ':' {
            in_regex = true;
            current.push(ch);
            previous = ch;
            continue;
        }
        if ch == '|' {
            out.push(std::mem::take(&mut current));
            collection.clear();
            after_colon = false;
            previous = ch;
            continue;
        }
        current.push(ch);
        previous = ch;
    }
    if !current.trim().is_empty() {
        out.push(current);
    }
    out
}

/// Joins backslash-continued lines, skipping comment lines.
fn logical_lines(text: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut start_line = 0;
    for (index, line) in text.lines().enumerate() {
        let number = index + 1;
        if current.is_empty() && line.trim_start().starts_with('#') {
            continue;
        }
        let trimmed = line.trim_end();
        if let Some(stripped) = trimmed.strip_suffix('\\') {
            if current.is_empty() {
                start_line = number;
            }
            current.push_str(stripped);
        } else {
            if current.is_empty() {
                start_line = number;
            }
            current.push_str(line);
            if !current.trim().is_empty() {
                out.push((start_line, std::mem::take(&mut current)));
            } else {
                current.clear();
            }
        }
    }
    if !current.trim().is_empty() {
        out.push((start_line, current));
    }
    out
}

/// Splits a directive into whitespace-separated tokens, honouring quotes.
fn tokenize(text: &str) -> Result<Vec<String>, String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for ch in text.chars() {
        if escaped {
            if quote == Some(ch) {
                current.push(ch);
            } else {
                current.push('\\');
                current.push(ch);
            }
            escaped = false;
            continue;
        }
        match quote {
            Some(active) => {
                if ch == '\\' {
                    escaped = true;
                } else if ch == active {
                    quote = None;
                } else {
                    current.push(ch);
                }
            }
            None => {
                if ch == '"' || ch == '\'' {
                    quote = Some(ch);
                } else if ch.is_whitespace() {
                    if !current.is_empty() {
                        tokens.push(std::mem::take(&mut current));
                    }
                } else {
                    current.push(ch);
                }
            }
        }
    }
    if quote.is_some() {
        return Err("unterminated quoted string".to_string());
    }
    if escaped {
        current.push('\\');
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    Ok(tokens)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokenizes_quoted_regex_and_actions() {
        let tokens = tokenize(r#"SecRule ARGS "@rx \bfoo\b" "id:1,phase:2,block,t:lowercase""#)
            .expect("tokens");
        assert_eq!(tokens[0], "SecRule");
        assert_eq!(tokens[1], "ARGS");
        assert_eq!(tokens[2], r"@rx \bfoo\b");
        assert_eq!(tokens[3], "id:1,phase:2,block,t:lowercase");
    }

    #[test]
    fn splits_actions_with_quoted_commas() {
        let actions = split_actions("id:1,msg:'a,b',setvar:'tx.x=+1'");
        assert_eq!(actions, vec!["id:1", "msg:'a,b'", "setvar:'tx.x=+1'"]);
    }

    #[test]
    fn splits_variables_inside_regex() {
        let vars = split_variables(r"ARGS|!ARGS:/a|b/|REQUEST_URI");
        assert_eq!(vars, vec!["ARGS", r"!ARGS:/a|b/", "REQUEST_URI"]);
    }

    #[test]
    fn logical_lines_join_continuations() {
        let text = "SecRule ARGS \"@rx x\" \\\n    \"id:1,\\\n    phase:2\"\n";
        let lines = logical_lines(text);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].1.contains("phase:2"));
    }
}
