//! Compiled rule representation (IR) for the native CRS engine.
//!
//! The IR is produced once at load time. Regexes, phrase automata, selectors
//! and transform chains are all compiled up front; the request path only walks
//! immutable data and a bounded per-request budget.

use regex::bytes::Regex;
use regex::Regex as TextRegex;

use super::transforms::Transform;

/// Engine phases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Phase {
    /// `phase:1` — request headers are available.
    RequestHeaders,
    /// `phase:2` — the request body has been processed.
    RequestBody,
    /// `phase:3` — response headers are available.
    ResponseHeaders,
    /// `phase:4` — the response body has been processed.
    ResponseBody,
    /// `phase:5` — logging, after the response.
    Logging,
}

impl Phase {
    /// Numeric SecLang phase.
    pub fn number(self) -> u8 {
        match self {
            Self::RequestHeaders => 1,
            Self::RequestBody => 2,
            Self::ResponseHeaders => 3,
            Self::ResponseBody => 4,
            Self::Logging => 5,
        }
    }

    /// Parses a SecLang phase number.
    pub fn from_number(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::RequestHeaders),
            2 => Some(Self::RequestBody),
            3 => Some(Self::ResponseHeaders),
            4 => Some(Self::ResponseBody),
            5 => Some(Self::Logging),
            _ => None,
        }
    }

    /// True for phases that inspect the upstream response.
    pub fn is_response(self) -> bool {
        matches!(self, Self::ResponseHeaders | Self::ResponseBody)
    }
}

/// CRS collection / variable name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Collection {
    Args,
    ArgsGet,
    ArgsPost,
    ArgsNames,
    ArgsGetNames,
    ArgsPostNames,
    ArgsCombinedSize,
    RequestHeaders,
    RequestHeadersNames,
    RequestCookies,
    RequestCookiesNames,
    RequestUri,
    RequestUriRaw,
    RequestMethod,
    RequestBody,
    RequestBodyLength,
    RequestFilename,
    RequestBasename,
    RequestLine,
    RequestProtocol,
    QueryString,
    Tx,
    MatchedVars,
    MatchedVarsNames,
    Xml,
    Files,
    FilesNames,
    FilesSizes,
    FilesCombinedSize,
    MultipartPartHeaders,
    ReqbodyProcessor,
    RemoteAddr,
    UniqueId,
    Rule,
    Global,
    Ip,
    ResponseStatus,
    ResponseProtocol,
    ResponseHeaders,
    ResponseHeadersNames,
    ResponseBody,
    ResponseBodyLength,
    ResponseContentType,
    ResponseContentLength,
    ResponseArgs,
    ResponseXml,
    OutboundDataError,
}

impl Collection {
    /// True when the collection can be empty for a request (keyed values,
    /// bodies, TX and matched-variable state). Single request fields such as
    /// URI/method always resolve to one value, even when it is empty.
    pub fn is_dynamic(self) -> bool {
        matches!(
            self,
            Self::Args
                | Self::ArgsGet
                | Self::ArgsPost
                | Self::ArgsNames
                | Self::ArgsGetNames
                | Self::ArgsPostNames
                | Self::RequestHeaders
                | Self::RequestHeadersNames
                | Self::RequestCookies
                | Self::RequestCookiesNames
                | Self::RequestBody
                | Self::Files
                | Self::FilesNames
                | Self::FilesSizes
                | Self::MultipartPartHeaders
                | Self::Tx
                | Self::MatchedVars
                | Self::MatchedVarsNames
                | Self::Xml
        )
    }

    /// Canonical upper-case name used in `MATCHED_VAR_NAME` and reports.
    pub fn name(self) -> &'static str {
        match self {
            Self::Args => "ARGS",
            Self::ArgsGet => "ARGS_GET",
            Self::ArgsPost => "ARGS_POST",
            Self::ArgsNames => "ARGS_NAMES",
            Self::ArgsGetNames => "ARGS_GET_NAMES",
            Self::ArgsPostNames => "ARGS_POST_NAMES",
            Self::ArgsCombinedSize => "ARGS_COMBINED_SIZE",
            Self::RequestHeaders => "REQUEST_HEADERS",
            Self::RequestHeadersNames => "REQUEST_HEADERS_NAMES",
            Self::RequestCookies => "REQUEST_COOKIES",
            Self::RequestCookiesNames => "REQUEST_COOKIES_NAMES",
            Self::RequestUri => "REQUEST_URI",
            Self::RequestUriRaw => "REQUEST_URI_RAW",
            Self::RequestMethod => "REQUEST_METHOD",
            Self::RequestBody => "REQUEST_BODY",
            Self::RequestBodyLength => "REQUEST_BODY_LENGTH",
            Self::RequestFilename => "REQUEST_FILENAME",
            Self::RequestBasename => "REQUEST_BASENAME",
            Self::RequestLine => "REQUEST_LINE",
            Self::RequestProtocol => "REQUEST_PROTOCOL",
            Self::QueryString => "QUERY_STRING",
            Self::Tx => "TX",
            Self::MatchedVars => "MATCHED_VARS",
            Self::MatchedVarsNames => "MATCHED_VARS_NAMES",
            Self::Xml => "XML",
            Self::Files => "FILES",
            Self::FilesNames => "FILES_NAMES",
            Self::FilesSizes => "FILES_SIZES",
            Self::FilesCombinedSize => "FILES_COMBINED_SIZE",
            Self::MultipartPartHeaders => "MULTIPART_PART_HEADERS",
            Self::ReqbodyProcessor => "REQBODY_PROCESSOR",
            Self::RemoteAddr => "REMOTE_ADDR",
            Self::UniqueId => "UNIQUE_ID",
            Self::Rule => "RULE",
            Self::Global => "GLOBAL",
            Self::Ip => "IP",
            Self::ResponseStatus => "RESPONSE_STATUS",
            Self::ResponseProtocol => "RESPONSE_PROTOCOL",
            Self::ResponseHeaders => "RESPONSE_HEADERS",
            Self::ResponseHeadersNames => "RESPONSE_HEADERS_NAMES",
            Self::ResponseBody => "RESPONSE_BODY",
            Self::ResponseBodyLength => "RESPONSE_BODY_LENGTH",
            Self::ResponseContentType => "RESPONSE_CONTENT_TYPE",
            Self::ResponseContentLength => "RESPONSE_CONTENT_LENGTH",
            Self::ResponseArgs => "RESPONSE_ARGS",
            Self::ResponseXml => "RESPONSE_XML",
            Self::OutboundDataError => "OUTBOUND_DATA_ERROR",
        }
    }

    /// Parses a SecLang collection name (case-insensitive).
    pub fn parse(name: &str) -> Option<Self> {
        let upper = name.to_ascii_uppercase();
        Some(match upper.as_str() {
            "ARGS" => Self::Args,
            "ARGS_GET" => Self::ArgsGet,
            "ARGS_POST" => Self::ArgsPost,
            "ARGS_NAMES" => Self::ArgsNames,
            "ARGS_GET_NAMES" => Self::ArgsGetNames,
            "ARGS_POST_NAMES" => Self::ArgsPostNames,
            "ARGS_COMBINED_SIZE" => Self::ArgsCombinedSize,
            "REQUEST_HEADERS" => Self::RequestHeaders,
            "REQUEST_HEADERS_NAMES" => Self::RequestHeadersNames,
            "REQUEST_COOKIES" => Self::RequestCookies,
            "REQUEST_COOKIES_NAMES" => Self::RequestCookiesNames,
            "REQUEST_URI" => Self::RequestUri,
            "REQUEST_URI_RAW" => Self::RequestUriRaw,
            "REQUEST_METHOD" => Self::RequestMethod,
            "REQUEST_BODY" => Self::RequestBody,
            "REQUEST_BODY_LENGTH" => Self::RequestBodyLength,
            "REQUEST_FILENAME" => Self::RequestFilename,
            "REQUEST_BASENAME" => Self::RequestBasename,
            "REQUEST_LINE" => Self::RequestLine,
            "REQUEST_PROTOCOL" => Self::RequestProtocol,
            "QUERY_STRING" => Self::QueryString,
            "TX" => Self::Tx,
            "MATCHED_VARS" => Self::MatchedVars,
            "MATCHED_VARS_NAMES" => Self::MatchedVarsNames,
            "XML" => Self::Xml,
            "FILES" => Self::Files,
            "FILES_NAMES" => Self::FilesNames,
            "FILES_SIZES" => Self::FilesSizes,
            "FILES_COMBINED_SIZE" => Self::FilesCombinedSize,
            "MULTIPART_PART_HEADERS" => Self::MultipartPartHeaders,
            "REQBODY_PROCESSOR" => Self::ReqbodyProcessor,
            "REMOTE_ADDR" => Self::RemoteAddr,
            "UNIQUE_ID" => Self::UniqueId,
            "RULE" => Self::Rule,
            "GLOBAL" => Self::Global,
            "IP" => Self::Ip,
            "RESPONSE_STATUS" => Self::ResponseStatus,
            "RESPONSE_PROTOCOL" => Self::ResponseProtocol,
            "RESPONSE_HEADERS" => Self::ResponseHeaders,
            "RESPONSE_HEADERS_NAMES" => Self::ResponseHeadersNames,
            "RESPONSE_BODY" => Self::ResponseBody,
            "RESPONSE_BODY_LENGTH" => Self::ResponseBodyLength,
            "RESPONSE_CONTENT_TYPE" => Self::ResponseContentType,
            "RESPONSE_CONTENT_LENGTH" => Self::ResponseContentLength,
            "RESPONSE_ARGS" => Self::ResponseArgs,
            "RESPONSE_XML" => Self::ResponseXml,
            "OUTBOUND_DATA_ERROR" => Self::OutboundDataError,
            _ => return None,
        })
    }
}

/// Optional key selector applied to a keyed collection.
#[derive(Debug, Clone)]
pub enum Selector {
    /// No selector: every value in the collection.
    All,
    /// Exact key lookup (collections are case-insensitive, like Coraza).
    Key(String),
    /// Key regex (a `/.../` selector in SecLang).
    Regex(TextRegex),
}

/// One variable target of a rule.
#[derive(Debug, Clone)]
pub struct VariableSpec {
    pub collection: Collection,
    /// Raw selector text for diagnostics.
    pub selector_text: Option<String>,
    pub selector: Selector,
    /// `!VAR` — exception target.
    pub negated: bool,
    /// `&VAR` — evaluate the operator against the number of values.
    pub count: bool,
}

/// A macro-bearing string (`%{tx.foo}`) expanded at evaluation time.
#[derive(Debug, Clone, Default)]
pub struct MacroString(pub String);

/// Compiled operator.
#[derive(Debug, Clone)]
pub struct CompiledOperator {
    pub kind: OperatorKind,
    /// `!@rx` and friends.
    pub negated: bool,
    /// Original argument, retained for reports and diagnostics.
    pub argument: String,
}

/// Operator implementation.
#[derive(Debug, Clone)]
pub enum OperatorKind {
    /// `@rx` — PCRE-compatible subset compiled to a bytes regex.
    Rx(Regex),
    /// `@pm` — phrase match (Aho-Corasick, ASCII case-insensitive).
    Pm(aho_corasick::AhoCorasick),
    /// `@pmFromFile` — phrase match from a CRS data file.
    PmFromFile(aho_corasick::AhoCorasick),
    /// `@contains`.
    Contains(MacroString),
    /// `@beginsWith`.
    BeginsWith(MacroString),
    /// `@endsWith`.
    EndsWith(MacroString),
    /// `@within`.
    Within(MacroString),
    /// `@streq`.
    StrEq(MacroString),
    /// `@eq`.
    Eq(MacroString),
    /// `@lt`.
    Lt(MacroString),
    /// `@gt`.
    Gt(MacroString),
    /// `@ge`.
    Ge(MacroString),
    /// `@le`.
    Le(MacroString),
    /// `@validateByteRange`.
    ValidateByteRange(Box<[bool; 256]>),
    /// `@validateUrlEncoding`.
    ValidateUrlEncoding,
    /// `@validateUtf8Encoding`.
    ValidateUtf8Encoding,
    /// `@unconditionalMatch`.
    UnconditionalMatch,
    /// `@ipMatch`.
    IpMatch(Vec<IpMatch>),
    /// `@detectSQLi` — native libinjection port (`native-detect` feature).
    DetectSqlInjection,
    /// `@detectXSS` — native libinjection port (`native-detect` feature).
    DetectXss,
}

/// One `@ipMatch` entry.
#[derive(Debug, Clone)]
pub enum IpMatch {
    /// Exact address.
    Exact(std::net::IpAddr),
    /// CIDR network.
    Cidr(std::net::IpAddr, u8),
}

/// Transform chain. `t:none` is resolved at parse time.
pub type TransformChain = Vec<Transform>;

/// Non-disruptive / flow / disruptive action.
#[derive(Debug, Clone)]
pub enum Action {
    /// `setvar:'tx.name=value'`.
    SetVar {
        name: String,
        op: SetVarOp,
        value: MacroString,
    },
    /// `capture`.
    Capture,
    /// `multiMatch`.
    MultiMatch,
    /// `ctl:...`.
    Ctl(CtlAction),
    /// `skipAfter:marker`.
    SkipAfter(String),
    /// `initcol:...` (the collections are created but the stock CRS does not
    /// read them at PL1; kept explicit so the construct is not dropped).
    InitCol,
    /// `status:NNN`.
    Status(u16),
    /// Disruptive action.
    Disruptive(Disruptive),
}

/// `setvar` mutation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetVarOp {
    Set,
    Add,
    Sub,
    Remove,
}

/// Disruptive actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disruptive {
    Pass,
    /// `block` — use the phase default disruptive action.
    Block,
    Deny,
    Drop,
    Allow,
    AllowPhase,
    AllowRequest,
    AllowAll,
}

/// `ctl` operations used by the pinned CRS.
#[derive(Debug, Clone)]
pub enum CtlAction {
    RuleRemoveById(u32),
    RuleRemoveByTag(String),
    RuleRemoveTargetById {
        id: u32,
        collection: Collection,
        key: Option<String>,
    },
    RuleRemoveTargetByTag {
        tag: String,
        collection: Collection,
        key: Option<String>,
    },
    RequestBodyProcessor(String),
    ForceRequestBodyVariable(bool),
    AuditEngine(bool),
}

/// Rule metadata that does not affect the decision but is reported by the
/// harness and used by the support matrix.
#[derive(Debug, Clone, Default)]
pub struct RuleMetadata {
    pub msg: Option<String>,
    pub logdata: Option<String>,
    pub tags: Vec<String>,
    pub severity: Option<String>,
    pub rev: Option<String>,
    pub ver: Option<String>,
    pub log: bool,
    pub audit_log: bool,
}

/// A compiled rule.
#[derive(Debug, Clone)]
pub struct CompiledRule {
    pub id: Option<u32>,
    pub phase: Phase,
    pub variables: Vec<VariableSpec>,
    /// `None` for `SecAction`.
    pub operator: Option<CompiledOperator>,
    pub transforms: TransformChain,
    /// Index into [`Program::pipelines`]. Rules with identical transform chains
    /// share one pipeline id, so the per-value transform cache is keyed by
    /// `(value, pipeline)` rather than by rule.
    pub pipeline: u16,
    pub actions: Vec<Action>,
    pub metadata: RuleMetadata,
    pub file: String,
    pub line: usize,
    /// Optional mandatory-literal gate id (see [`super::gate`]). Assigned at
    /// load time only for positive regex rules the prefilter artifact proves
    /// gated; `None` means the rule always runs.
    pub gate: Option<u16>,
    /// Optional multi-pattern candidate gate id (see
    /// [`super::candidates`], `hyperscan-eval` only). Assigned at load time
    /// only when the rule's exact regex compiled into a Vectorscan database;
    /// `None` keeps the rule on the per-rule regex path.
    pub hs_gate: Option<u16>,
    /// Precomputed `multiMatch` flag (avoids rescanning actions per request).
    pub multi_match: bool,
    /// Precomputed `capture` flag (avoids rescanning actions per request).
    pub captures: bool,
    /// Dynamic collections (keyed values, body, TX, matched vars) this rule
    /// needs at least one value from. Static targets are not represented.
    pub presence: u64,
    /// True when the rule has a positive target that always has a value
    /// (URI, method, protocol, sizes, ...), so it must never be skipped.
    pub has_static_positive: bool,
    /// True when a `&COLLECTION` count target can match an absent collection.
    pub may_count: bool,
    /// True when the rule has at least one positive target.
    pub has_positive: bool,
    /// Pre-resolved `skipAfter` marker index in the phase program.
    pub skip_after: Option<u32>,
}

impl CompiledRule {
    /// True when the rule uses `multiMatch`.
    pub fn multi_match(&self) -> bool {
        self.multi_match
    }

    /// True when the rule captures regex groups into `TX:0..9`.
    pub fn captures(&self) -> bool {
        self.captures
    }
}

/// A rule plus its `chain` members. The first entry is the parent.
#[derive(Debug, Clone)]
pub struct RuleGroup {
    pub rules: Vec<CompiledRule>,
    pub line: usize,
    /// True when any rule in the group reads `MATCHED_VARS` or expands a
    /// matched-variable macro. Precomputed so `MATCHED_VARS` bookkeeping can
    /// be skipped for every other group.
    pub records_matches: bool,
}

impl RuleGroup {
    /// Parent rule id.
    pub fn id(&self) -> Option<u32> {
        self.rules.first().and_then(|rule| rule.id)
    }
}

/// One item in a phase program.
#[derive(Debug, Clone)]
pub enum ProgramItem {
    Rule(Box<RuleGroup>),
    Marker(String),
}

/// Compiled request program.
#[derive(Debug, Clone, Default)]
pub struct Program {
    pub phase1: Vec<ProgramItem>,
    pub phase2: Vec<ProgramItem>,
    /// `phase:3` response-header rules (opt-in response inspection).
    pub phase3: Vec<ProgramItem>,
    /// `phase:4` response-body rules.
    pub phase4: Vec<ProgramItem>,
    /// `phase:5` logging rules.
    pub phase5: Vec<ProgramItem>,
    /// Interned transform pipelines. `CompiledRule::pipeline` indexes this.
    pub pipelines: Vec<TransformChain>,
    /// Deduplicated prefix DAG over every interned pipeline, built once at load
    /// time. The per-request cache resolves prefixes through this table.
    pub transform_prefixes: crate::waf::transforms::PrefixTable<Transform>,
    /// Per-rule mandatory-literal gates, compiled once at load time and shared
    /// through an `Arc` when the engine is cloned across worker threads.
    pub gates: Option<std::sync::Arc<super::gate::GateSet>>,
    /// Multi-pattern Vectorscan candidate gate (`hyperscan-eval` only). `None`
    /// when the feature is off, the CPU is unsupported, or compilation failed.
    #[cfg(feature = "hyperscan-eval")]
    pub hs_candidates: Option<std::sync::Arc<super::candidates::HsCandidateSet>>,
}

impl Program {
    /// Returns the program for a phase.
    pub fn items(&self, phase: Phase) -> &[ProgramItem] {
        match phase {
            Phase::RequestHeaders => &self.phase1,
            Phase::RequestBody => &self.phase2,
            Phase::ResponseHeaders => &self.phase3,
            Phase::ResponseBody => &self.phase4,
            Phase::Logging => &self.phase5,
        }
    }

    /// Interns every rule's transform chain and assigns pipeline ids.
    ///
    /// Identical chains (the common case in CRS: `t:lowercase,t:urlDecodeUni`
    /// and friends) collapse to one id, which is what makes the per-value
    /// transform cache effective.
    pub fn intern_pipelines(&mut self) {
        let mut pipelines: Vec<TransformChain> = Vec::new();
        for items in [
            &mut self.phase1,
            &mut self.phase2,
            &mut self.phase3,
            &mut self.phase4,
            &mut self.phase5,
        ] {
            for item in items.iter_mut() {
                if let ProgramItem::Rule(group) = item {
                    for rule in &mut group.rules {
                        let id = match pipelines
                            .iter()
                            .position(|pipeline| *pipeline == rule.transforms)
                        {
                            Some(id) => id,
                            None => {
                                pipelines.push(rule.transforms.clone());
                                pipelines.len() - 1
                            }
                        };
                        rule.pipeline = u16::try_from(id).unwrap_or(u16::MAX);
                    }
                }
            }
        }
        self.pipelines = pipelines;
        self.transform_prefixes = crate::waf::transforms::PrefixTable::from_chains(&self.pipelines);
        for items in [&mut self.phase1, &mut self.phase2] {
            for item in items.iter_mut() {
                let ProgramItem::Rule(group) = item else {
                    continue;
                };
                group.records_matches = group.rules.iter().any(|rule| {
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
                });
            }
        }
    }
}
