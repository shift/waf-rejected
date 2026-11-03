//! Compiled rule representation (IR) for the native CRS engine.
//!
//! The IR is produced once at load time. Regexes, phrase automata, selectors
//! and transform chains are all compiled up front; the request path only walks
//! immutable data and a bounded per-request budget.

use regex::bytes::Regex;
use regex::Regex as TextRegex;

use super::transforms::Transform;

/// Request phases this slice implements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Phase {
    /// `phase:1` — request headers are available.
    RequestHeaders,
    /// `phase:2` — the request body has been processed.
    RequestBody,
}

impl Phase {
    /// Numeric SecLang phase.
    pub fn number(self) -> u8 {
        match self {
            Self::RequestHeaders => 1,
            Self::RequestBody => 2,
        }
    }

    /// Parses a SecLang phase number. Outbound phases are unsupported here.
    pub fn from_number(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::RequestHeaders),
            2 => Some(Self::RequestBody),
            _ => None,
        }
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
}

impl Collection {
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
}

impl CompiledRule {
    /// True when the rule uses `multiMatch`.
    pub fn multi_match(&self) -> bool {
        self.actions
            .iter()
            .any(|action| matches!(action, Action::MultiMatch))
    }

    /// True when the rule captures regex groups into `TX:0..9`.
    pub fn captures(&self) -> bool {
        self.actions
            .iter()
            .any(|action| matches!(action, Action::Capture))
    }
}

/// A rule plus its `chain` members. The first entry is the parent.
#[derive(Debug, Clone)]
pub struct RuleGroup {
    pub rules: Vec<CompiledRule>,
    pub line: usize,
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
    /// Interned transform pipelines. `CompiledRule::pipeline` indexes this.
    pub pipelines: Vec<TransformChain>,
}

impl Program {
    /// Returns the program for a phase.
    pub fn items(&self, phase: Phase) -> &[ProgramItem] {
        match phase {
            Phase::RequestHeaders => &self.phase1,
            Phase::RequestBody => &self.phase2,
        }
    }

    /// Interns every rule's transform chain and assigns pipeline ids.
    ///
    /// Identical chains (the common case in CRS: `t:lowercase,t:urlDecodeUni`
    /// and friends) collapse to one id, which is what makes the per-value
    /// transform cache effective.
    pub fn intern_pipelines(&mut self) {
        let mut pipelines: Vec<TransformChain> = Vec::new();
        for items in [&mut self.phase1, &mut self.phase2] {
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
    }
}
