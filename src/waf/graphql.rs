//! GraphQL-over-HTTP inspection.
//!
//! GraphQL requests are ordinary JSON (or raw GraphQL) HTTP bodies. Running
//! the full CRS JSON body rule set over them is expensive because those rules
//! are byte-linear and the JSON envelope grows with the operation. This module
//! validates the GraphQL envelope before Coraza runs, extracts the operation
//! type/name and a stable hash of the normalised query, and can then withhold
//! the raw body from CRS body rules.
//!
//! The withholding is **opt-in** via `waf.graphql.body_scan = "graphql-only"`.
//! The default, `crs`, keeps the full CRS JSON body scan; `off` disables the
//! GraphQL-specific checks entirely (CRS still scans the body).
//!
//! What is checked:
//!
//! * request shape (`POST` JSON/GraphQL, or `GET` with `?query=`),
//! * body/query/variables size limits and JSON nesting limits,
//! * approximate GraphQL depth, alias and field counts,
//! * mutation/subscription allow/deny,
//! * operation name / persisted-query SHA-256 allowlisting with
//!   `monitor`/`block` unknown-operation policy.
//!
//! Field-level GraphQL value inspection is not implemented here. The raw body
//! is only hidden from CRS in `graphql-only` mode, and that mode requires a
//! non-empty allowlist.

use std::collections::HashSet;
use std::path::Path;

use hyper::{Method, Uri};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::debug;

use crate::config::{WafGraphqlConfig, WafGraphqlScanMode};
use crate::waf::{Decision, RequestContext, WafRule};

/// Header/URI rule label used for GraphQL pre-check blocks and failures.
pub const RULE_NAME: &str = "graphql-protocol-inspection";

/// GraphQL operation kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GraphqlOperationType {
    Query,
    Mutation,
    Subscription,
}

impl GraphqlOperationType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Query => "query",
            Self::Mutation => "mutation",
            Self::Subscription => "subscription",
        }
    }
}

/// A parsed GraphQL request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphqlDocument {
    /// operation type from the document (defaults to `query` for shorthand).
    pub operation_type: GraphqlOperationType,
    /// operation name from the document, if any.
    pub operation_name: Option<String>,
    /// lowercase hex SHA-256 of [`Self::normalized_query`].
    pub query_hash: String,
    /// Normalised query text (whitespace collapsed, comments removed).
    pub normalized_query: String,
    /// Query size in bytes before normalisation.
    pub query_bytes: usize,
    /// Approximate maximum selection-set brace depth.
    pub depth: usize,
    /// Approximate number of alias selections.
    pub aliases: usize,
    /// Approximate number of field selections.
    pub fields: usize,
}

/// An un-inspectable GraphQL request (mapped through `fail_mode`) or a
/// deterministic policy limit (returned as a block regardless of `fail_mode`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphqlInspectionError {
    pub reason: String,
    /// When set, the request must be rejected with this status instead of
    /// being subject to `fail_mode`.
    pub reject_status: Option<u16>,
}

impl GraphqlInspectionError {
    fn malformed(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            reject_status: None,
        }
    }

    fn limit(status: u16, reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            reject_status: Some(status),
        }
    }
}

impl std::fmt::Display for GraphqlInspectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.reason)
    }
}

/// Inspection verdict for a GraphQL request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GraphqlVerdict {
    /// Checks passed. `strip_body` is set only in `graphql-only` mode.
    Allow {
        strip_body: bool,
        monitored: bool,
        operation_type: GraphqlOperationType,
        operation_name: Option<String>,
        query_hash: String,
    },
    /// Request rejected by GraphQL policy.
    Block { status: u16, reason: String },
}

impl GraphqlVerdict {
    fn allow(doc: &GraphqlDocument, strip_body: bool, monitored: bool) -> Self {
        Self::Allow {
            strip_body,
            monitored,
            operation_type: doc.operation_type,
            operation_name: doc.operation_name.clone(),
            query_hash: doc.query_hash.clone(),
        }
    }
}

/// One entry in a persisted-query allowlist artifact.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PersistedOperation {
    /// Operation name.
    pub name: String,
    /// Lowercase hex SHA-256 of the normalised query.
    pub sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum AllowlistArtifact {
    List(Vec<PersistedOperation>),
    Wrapped { operations: Vec<PersistedOperation> },
}

/// Loads and validates a persisted-query allowlist artifact.
///
/// The canonical artifact is a JSON list of `{ "name": ..., "sha256": ... }`
/// objects. An object with an `operations` array is also accepted for
/// forward compatibility.
pub fn load_operation_allowlist(path: impl AsRef<Path>) -> Result<Vec<PersistedOperation>, String> {
    let path = path.as_ref();
    let bytes = std::fs::read(path)
        .map_err(|error| format!("could not read {}: {error}", path.display()))?;
    let artifact: AllowlistArtifact = serde_json::from_slice(&bytes)
        .map_err(|error| format!("invalid JSON in {}: {error}", path.display()))?;
    let operations = match artifact {
        AllowlistArtifact::List(operations) | AllowlistArtifact::Wrapped { operations } => {
            operations
        }
    };
    validate_operations(&operations).map_err(|error| {
        format!(
            "invalid persisted-query allowlist {}: {error}",
            path.display()
        )
    })?;
    Ok(operations)
}

fn validate_operations(operations: &[PersistedOperation]) -> Result<(), String> {
    if operations.is_empty() {
        return Err("operation allowlist must not be empty".to_string());
    }
    let mut seen = HashSet::new();
    for operation in operations {
        if operation.name.trim().is_empty() {
            return Err("operation name must not be empty".to_string());
        }
        if !is_sha256_hex(&operation.sha256) {
            return Err(format!(
                "operation '{}' has an invalid sha256 (expected 64 hex characters)",
                operation.name
            ));
        }
        if !seen.insert((
            operation.name.as_str(),
            operation.sha256.to_ascii_lowercase(),
        )) {
            return Err(format!("duplicate operation '{}'", operation.name));
        }
    }
    Ok(())
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Protocol-aware GraphQL inspector built from `waf.graphql`.
#[derive(Debug, Clone)]
pub struct GraphqlInspector {
    mode: WafGraphqlScanMode,
    operation_names: HashSet<String>,
    query_hashes: HashSet<String>,
    unknown_operation_blocked: bool,
    max_body_bytes: usize,
    max_query_bytes: usize,
    max_variables_bytes: usize,
    max_variables: usize,
    max_depth: usize,
    max_aliases: usize,
    max_fields: usize,
    allow_mutations: bool,
    allow_subscriptions: bool,
}

impl GraphqlInspector {
    /// Builds an inspector from configuration without reading any files.
    pub fn from_config(config: &WafGraphqlConfig) -> Self {
        Self::build(config, None)
    }

    /// Builds an inspector from configuration, loading `allowlist_file` when
    /// set.
    pub fn try_from_config(config: &WafGraphqlConfig) -> Result<Self, String> {
        let artifact = match config.allowlist_file.as_deref() {
            Some(path) => Some(load_operation_allowlist(path)?),
            None => None,
        };
        Ok(Self::build(config, artifact.as_deref()))
    }

    fn build(config: &WafGraphqlConfig, artifact: Option<&[PersistedOperation]>) -> Self {
        let mut operation_names = HashSet::new();
        let mut query_hashes = HashSet::new();
        for entry in &config.operation_allowlist {
            let entry = entry.trim();
            if is_sha256_hex(entry) {
                query_hashes.insert(entry.to_ascii_lowercase());
            } else if !entry.is_empty() {
                operation_names.insert(entry.to_string());
            }
        }
        if let Some(artifact) = artifact {
            for operation in artifact {
                operation_names.insert(operation.name.clone());
                query_hashes.insert(operation.sha256.to_ascii_lowercase());
            }
        }

        let unknown_operation_blocked = match config.unknown_operation_action.as_deref() {
            Some(action) => action == "block",
            None => !config.operation_allowlist.is_empty() || artifact.is_some(),
        };

        Self {
            mode: config.scan_mode(),
            operation_names,
            query_hashes,
            unknown_operation_blocked,
            max_body_bytes: config.max_body_bytes,
            max_query_bytes: config.max_query_bytes,
            max_variables_bytes: config.max_variables_bytes,
            max_variables: config.max_variables,
            max_depth: config.max_depth,
            max_aliases: config.max_aliases,
            max_fields: config.max_fields,
            allow_mutations: config.allow_mutations,
            allow_subscriptions: config.allow_subscriptions,
        }
    }

    /// Whether this inspector withholds the raw body from CRS body rules.
    pub fn strips_body(&self) -> bool {
        self.mode == WafGraphqlScanMode::GraphqlOnly
    }

    /// Whether this request is GraphQL-shaped. Cheap: does not parse the body.
    pub fn matches(&self, ctx: &RequestContext) -> bool {
        if self.mode == WafGraphqlScanMode::Off {
            return false;
        }
        request_shape(ctx).is_some()
    }

    /// Runs all GraphQL-aware checks for a GraphQL request.
    pub fn inspect(&self, ctx: &RequestContext) -> Result<GraphqlVerdict, GraphqlInspectionError> {
        let Some(shape) = request_shape(ctx) else {
            return Ok(GraphqlVerdict::Allow {
                strip_body: false,
                monitored: false,
                operation_type: GraphqlOperationType::Query,
                operation_name: None,
                query_hash: String::new(),
            });
        };

        let doc = match self.parse_document(ctx, shape) {
            Ok(Some(doc)) => doc,
            Ok(None) => {
                return Ok(GraphqlVerdict::Allow {
                    strip_body: false,
                    monitored: false,
                    operation_type: GraphqlOperationType::Query,
                    operation_name: None,
                    query_hash: String::new(),
                })
            }
            Err(error) => {
                // A configured limit is a deterministic policy violation and
                // is enforced in every mode that enabled GraphQL checks.
                if let Some(status) = error.reject_status {
                    return Ok(GraphqlVerdict::Block {
                        status,
                        reason: error.reason,
                    });
                }
                // In `crs` mode CRS still scans the raw body, so an
                // unparseable body is left to the existing rules instead of
                // changing the default behaviour.
                if self.mode == WafGraphqlScanMode::Crs {
                    debug!(error = %error, "GraphQL body could not be parsed; leaving it to CRS");
                    return Ok(GraphqlVerdict::Allow {
                        strip_body: false,
                        monitored: false,
                        operation_type: GraphqlOperationType::Query,
                        operation_name: None,
                        query_hash: String::new(),
                    });
                }
                return Err(error);
            }
        };

        if let Some(decision) = self.enforce_limits(&doc) {
            return Ok(decision);
        }

        match doc.operation_type {
            GraphqlOperationType::Mutation if !self.allow_mutations => {
                return Ok(GraphqlVerdict::Block {
                    status: 403,
                    reason: "GraphQL mutations are disabled by waf.graphql.allow_mutations"
                        .to_string(),
                })
            }
            GraphqlOperationType::Subscription if !self.allow_subscriptions => {
                return Ok(GraphqlVerdict::Block {
                    status: 403,
                    reason: "GraphQL subscriptions are disabled by waf.graphql.allow_subscriptions"
                        .to_string(),
                })
            }
            _ => {}
        }

        let mut monitored = false;
        if !self.operation_names.is_empty() || !self.query_hashes.is_empty() {
            let name_allowed = doc
                .operation_name
                .as_deref()
                .is_some_and(|name| self.operation_names.contains(name));
            let hash_allowed = self.query_hashes.contains(&doc.query_hash);
            if !name_allowed && !hash_allowed {
                if self.unknown_operation_blocked {
                    return Ok(GraphqlVerdict::Block {
                        status: 403,
                        reason: format!(
                            "GraphQL operation '{}' ({}) is not in the allowlist",
                            doc.operation_name.as_deref().unwrap_or("<anonymous>"),
                            doc.query_hash
                        ),
                    });
                }
                monitored = true;
                debug!(
                    operation = doc.operation_name.as_deref().unwrap_or("<anonymous>"),
                    hash = %doc.query_hash,
                    "GraphQL operation is not in the allowlist; monitor mode allows it"
                );
            }
        }

        Ok(GraphqlVerdict::allow(
            &doc,
            self.mode == WafGraphqlScanMode::GraphqlOnly,
            monitored,
        ))
    }

    fn parse_document(
        &self,
        ctx: &RequestContext,
        shape: RequestShape,
    ) -> Result<Option<GraphqlDocument>, GraphqlInspectionError> {
        let mut client_operation_name = None;
        let raw = match shape {
            RequestShape::Get { query } => query.into_bytes(),
            RequestShape::Post { content_type } => {
                let body = match ctx.body.as_deref() {
                    Some(body) => body,
                    None => {
                        if ctx.body_size.unwrap_or(0) > 0 {
                            return Err(GraphqlInspectionError::malformed(
                                "GraphQL request body is not available for inspection",
                            ));
                        }
                        return Ok(None);
                    }
                };
                if body.len() > self.max_body_bytes {
                    return Err(GraphqlInspectionError::limit(
                        413,
                        format!(
                            "GraphQL body exceeds max_body_bytes ({} > {})",
                            body.len(),
                            self.max_body_bytes
                        ),
                    ));
                }
                if content_type == GraphqlContentType::Graphql {
                    body.to_vec()
                } else {
                    let value: serde_json::Value =
                        serde_json::from_slice(body).map_err(|error| {
                            GraphqlInspectionError::malformed(format!(
                                "malformed GraphQL JSON body: {error}"
                            ))
                        })?;
                    let Some(object) = value.as_object() else {
                        return Ok(None);
                    };
                    let Some(query) = object.get("query") else {
                        return Ok(None);
                    };
                    let query = query.as_str().ok_or_else(|| {
                        GraphqlInspectionError::malformed("GraphQL JSON 'query' must be a string")
                    })?;
                    if let Some(operation_name) = object.get("operationName") {
                        client_operation_name = Some(
                            operation_name
                                .as_str()
                                .ok_or_else(|| {
                                    GraphqlInspectionError::malformed(
                                        "GraphQL JSON 'operationName' must be a string",
                                    )
                                })?
                                .to_string(),
                        );
                    }
                    let variables = object.get("variables");
                    if let Some(variables) = variables {
                        let variables = variables.as_object().ok_or_else(|| {
                            GraphqlInspectionError::malformed(
                                "GraphQL JSON 'variables' must be an object",
                            )
                        })?;
                        if variables.len() > self.max_variables {
                            return Err(GraphqlInspectionError::limit(
                                400,
                                format!(
                                    "GraphQL variables exceed max_variables ({} > {})",
                                    variables.len(),
                                    self.max_variables
                                ),
                            ));
                        }
                        let variables_json = serde_json::to_vec(variables).map_err(|error| {
                            GraphqlInspectionError::malformed(format!(
                                "GraphQL variables could not be serialised: {error}"
                            ))
                        })?;
                        if variables_json.len() > self.max_variables_bytes {
                            return Err(GraphqlInspectionError::limit(
                                413,
                                format!(
                                    "GraphQL variables exceed max_variables_bytes ({} > {})",
                                    variables_json.len(),
                                    self.max_variables_bytes
                                ),
                            ));
                        }
                        let depth = json_depth(&serde_json::Value::Object(variables.clone()));
                        if depth > self.max_depth {
                            return Err(GraphqlInspectionError::limit(
                                400,
                                format!(
                                    "GraphQL variables depth {depth} exceeds max_depth {}",
                                    self.max_depth
                                ),
                            ));
                        }
                    }
                    query.as_bytes().to_vec()
                }
            }
        };

        if raw.len() > self.max_query_bytes {
            return Err(GraphqlInspectionError::limit(
                413,
                format!(
                    "GraphQL query exceeds max_query_bytes ({} > {})",
                    raw.len(),
                    self.max_query_bytes
                ),
            ));
        }
        let query = std::str::from_utf8(&raw).map_err(|error| {
            GraphqlInspectionError::malformed(format!("GraphQL query is not valid UTF-8: {error}"))
        })?;
        let mut doc = parse_query(query)?;
        if client_operation_name.is_some() {
            doc.operation_name = client_operation_name;
        }
        Ok(Some(doc))
    }

    fn enforce_limits(&self, doc: &GraphqlDocument) -> Option<GraphqlVerdict> {
        if doc.query_bytes > self.max_query_bytes {
            return Some(GraphqlVerdict::Block {
                status: 413,
                reason: format!(
                    "GraphQL query exceeds max_query_bytes ({} > {})",
                    doc.query_bytes, self.max_query_bytes
                ),
            });
        }
        if doc.depth > self.max_depth {
            return Some(GraphqlVerdict::Block {
                status: 400,
                reason: format!(
                    "GraphQL depth {} exceeds max_depth {}",
                    doc.depth, self.max_depth
                ),
            });
        }
        if doc.aliases > self.max_aliases {
            return Some(GraphqlVerdict::Block {
                status: 400,
                reason: format!(
                    "GraphQL alias count {} exceeds max_aliases {}",
                    doc.aliases, self.max_aliases
                ),
            });
        }
        if doc.fields > self.max_fields {
            return Some(GraphqlVerdict::Block {
                status: 400,
                reason: format!(
                    "GraphQL field count {} exceeds max_fields {}",
                    doc.fields, self.max_fields
                ),
            });
        }
        None
    }
}

impl WafRule for GraphqlInspector {
    fn name(&self) -> &str {
        RULE_NAME
    }

    fn evaluate(&self, ctx: &RequestContext) -> Decision {
        if !self.matches(ctx) {
            return Decision::Allow;
        }
        match self.inspect(ctx) {
            Ok(GraphqlVerdict::Allow { .. }) => Decision::Allow,
            Ok(GraphqlVerdict::Block { status, reason }) => Decision::Block { status, reason },
            Err(err) => Decision::Block {
                status: 400,
                reason: err.reason,
            },
        }
    }
}

/// Returns a copy of the context with the raw GraphQL body withheld from
/// subsequent rules. `body_size` is preserved so size rules still apply.
pub fn strip_body(ctx: &RequestContext) -> RequestContext {
    let mut scrubbed = ctx.clone();
    scrubbed.body = None;
    scrubbed
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum GraphqlContentType {
    Json,
    Graphql,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RequestShape {
    Get { query: String },
    Post { content_type: GraphqlContentType },
}

fn request_shape(ctx: &RequestContext) -> Option<RequestShape> {
    if ctx.method == Method::GET {
        let query = query_parameter(&ctx.uri, "query")?;
        return Some(RequestShape::Get { query });
    }
    if ctx.method != Method::POST {
        return None;
    }
    let content_type = graphql_content_type(&ctx.headers)?;
    Some(RequestShape::Post { content_type })
}

fn graphql_content_type(headers: &hyper::HeaderMap) -> Option<GraphqlContentType> {
    headers
        .get_all(hyper::header::CONTENT_TYPE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find_map(|value| {
            let media = value
                .split(';')
                .next()
                .unwrap_or_default()
                .trim()
                .to_ascii_lowercase();
            match media.as_str() {
                "application/graphql" => Some(GraphqlContentType::Graphql),
                "application/json" | "application/graphql+json" => Some(GraphqlContentType::Json),
                _ => None,
            }
        })
}

fn query_parameter(uri: &Uri, wanted: &str) -> Option<String> {
    let query = uri.query()?;
    for pair in query.split('&') {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        if key != wanted {
            continue;
        }
        return Some(
            urlencoding::decode(value)
                .map(|decoded| decoded.into_owned())
                .unwrap_or_else(|_| value.to_string()),
        );
    }
    None
}

/// Normalises a GraphQL document for hashing: whitespace outside strings is
/// collapsed to one space, comments are removed and leading/trailing
/// whitespace is trimmed.
pub fn normalize_query(query: &str) -> String {
    let mut out = String::with_capacity(query.len());
    let chars: Vec<char> = query.chars().collect();
    let mut index = 0usize;

    while index < chars.len() {
        let ch = chars[index];
        if ch == '"'
            && index + 2 < chars.len()
            && chars[index + 1] == '"'
            && chars[index + 2] == '"'
        {
            out.push_str("\"\"\"");
            index += 3;
            while index < chars.len() {
                if chars[index] == '"'
                    && index + 2 < chars.len()
                    && chars[index + 1] == '"'
                    && chars[index + 2] == '"'
                {
                    out.push_str("\"\"\"");
                    index += 3;
                    break;
                }
                out.push(chars[index]);
                index += 1;
            }
            continue;
        }
        if ch == '"' {
            out.push(ch);
            index += 1;
            let mut escaped = false;
            while index < chars.len() {
                let current = chars[index];
                out.push(current);
                index += 1;
                if escaped {
                    escaped = false;
                } else if current == '\\' {
                    escaped = true;
                } else if current == '"' {
                    break;
                }
            }
            continue;
        }
        if ch == '#' {
            while index < chars.len() && chars[index] != '\n' && chars[index] != '\r' {
                index += 1;
            }
            if !out.is_empty() && !out.ends_with(' ') {
                out.push(' ');
            }
            continue;
        }
        if ch.is_whitespace() {
            if !out.is_empty() && !out.ends_with(' ') {
                out.push(' ');
            }
            index += 1;
            continue;
        }
        out.push(ch);
        index += 1;
    }

    out.trim().to_string()
}

/// SHA-256 of the normalised query, lowercase hex.
pub fn query_hash(query: &str) -> String {
    let normalized = normalize_query(query);
    let mut hasher = Sha256::new();
    hasher.update(normalized.as_bytes());
    hex::encode(hasher.finalize())
}

fn parse_query(query: &str) -> Result<GraphqlDocument, GraphqlInspectionError> {
    let normalized = normalize_query(query);
    let tokens = tokenize(&normalized).map_err(GraphqlInspectionError::malformed)?;
    let mut parser = QueryParser::new(&tokens);
    let (operation_type, operation_name) = parser.parse_document()?;

    Ok(GraphqlDocument {
        operation_type,
        operation_name,
        query_hash: {
            let mut hasher = Sha256::new();
            hasher.update(normalized.as_bytes());
            hex::encode(hasher.finalize())
        },
        query_bytes: query.len(),
        normalized_query: normalized,
        depth: parser.max_depth,
        aliases: parser.aliases,
        fields: parser.fields,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Ident(String),
    LBrace,
    RBrace,
    LParen,
    RParen,
    LBracket,
    RBracket,
    Colon,
    At,
    Dollar,
    Spread,
    Bang,
    Equals,
    Other,
}

fn tokenize(query: &str) -> Result<Vec<Token>, String> {
    let mut tokens = Vec::new();
    let mut chars = query.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            ch if ch.is_whitespace() || ch == ',' => {}
            '"' => {
                if chars.peek() == Some(&'"') {
                    chars.next();
                    if chars.peek() == Some(&'"') {
                        chars.next();
                        loop {
                            match chars.next() {
                                Some('"') if chars.peek() == Some(&'"') => {
                                    chars.next();
                                    if chars.peek() == Some(&'"') {
                                        chars.next();
                                        break;
                                    }
                                }
                                Some(_) => {}
                                None => return Err("unterminated block string".to_string()),
                            }
                        }
                    } else {
                        return Err("malformed block string".to_string());
                    }
                } else {
                    let mut escaped = false;
                    loop {
                        match chars.next() {
                            Some('\\') if !escaped => escaped = true,
                            Some('"') if !escaped => break,
                            Some(_) => escaped = false,
                            None => return Err("unterminated string".to_string()),
                        }
                    }
                }
                tokens.push(Token::Other);
            }
            '{' => tokens.push(Token::LBrace),
            '}' => tokens.push(Token::RBrace),
            '(' => tokens.push(Token::LParen),
            ')' => tokens.push(Token::RParen),
            '[' => tokens.push(Token::LBracket),
            ']' => tokens.push(Token::RBracket),
            ':' => tokens.push(Token::Colon),
            '@' => tokens.push(Token::At),
            '$' => tokens.push(Token::Dollar),
            '!' => tokens.push(Token::Bang),
            '=' => tokens.push(Token::Equals),
            '.' if chars.peek() == Some(&'.') => {
                chars.next();
                if chars.peek() == Some(&'.') {
                    chars.next();
                    tokens.push(Token::Spread);
                } else {
                    return Err("malformed spread operator".to_string());
                }
            }
            ch if ch.is_ascii_alphabetic() || ch == '_' => {
                let mut ident = String::new();
                ident.push(ch);
                while let Some(next) = chars.peek() {
                    if next.is_ascii_alphanumeric() || *next == '_' {
                        ident.push(chars.next().unwrap());
                    } else {
                        break;
                    }
                }
                tokens.push(Token::Ident(ident));
            }
            ch if ch.is_ascii_digit() || ch == '-' => {
                while let Some(next) = chars.peek() {
                    if next.is_ascii_alphanumeric() || matches!(next, '.' | '-' | '+' | 'e' | 'E') {
                        chars.next();
                    } else {
                        break;
                    }
                }
                tokens.push(Token::Other);
            }
            _ => tokens.push(Token::Other),
        }
    }
    Ok(tokens)
}

struct QueryParser<'a> {
    tokens: &'a [Token],
    index: usize,
    max_depth: usize,
    aliases: usize,
    fields: usize,
}

impl<'a> QueryParser<'a> {
    fn new(tokens: &'a [Token]) -> Self {
        Self {
            tokens,
            index: 0,
            max_depth: 0,
            aliases: 0,
            fields: 0,
        }
    }

    fn parse_document(
        &mut self,
    ) -> Result<(GraphqlOperationType, Option<String>), GraphqlInspectionError> {
        let mut operation = GraphqlOperationType::Query;
        let mut name = None;
        let mut saw_operation = false;

        while self.index < self.tokens.len() {
            match &self.tokens[self.index] {
                Token::Ident(keyword)
                    if matches!(keyword.as_str(), "query" | "mutation" | "subscription") =>
                {
                    operation = match keyword.as_str() {
                        "mutation" => GraphqlOperationType::Mutation,
                        "subscription" => GraphqlOperationType::Subscription,
                        _ => GraphqlOperationType::Query,
                    };
                    saw_operation = true;
                    self.index += 1;
                    if let Some(Token::Ident(value)) = self.tokens.get(self.index) {
                        name = Some(value.clone());
                        self.index += 1;
                    }
                    self.skip_parens();
                    self.skip_directives();
                    if matches!(self.tokens.get(self.index), Some(Token::LBrace)) {
                        self.parse_selection_set(negligible_depth(), Division::Operation)?;
                    }
                }
                Token::Ident(keyword) if keyword == "fragment" => {
                    self.index += 1;
                    self.skip_ident();
                    self.skip_ident(); // "on"
                    self.skip_ident(); // type condition
                    self.skip_directives();
                    if matches!(self.tokens.get(self.index), Some(Token::LBrace)) {
                        self.parse_selection_set(negligible_depth(), Division::Fragment)?;
                    }
                }
                Token::LBrace if !saw_operation => {
                    saw_operation = true;
                    self.parse_selection_set(negligible_depth(), Division::Operation)?;
                }
                _ => self.index += 1,
            }
        }

        if !saw_operation {
            return Err(GraphqlInspectionError::malformed(
                "GraphQL document has no operation",
            ));
        }
        Ok((operation, name))
    }

    fn parse_selection_set(
        &mut self,
        depth: usize,
        division: Division,
    ) -> Result<(), GraphqlInspectionError> {
        if !matches!(self.tokens.get(self.index), Some(Token::LBrace)) {
            return Ok(());
        }
        self.index += 1;
        self.max_depth = self.max_depth.max(depth.max(1));

        while self.index < self.tokens.len() {
            match &self.tokens[self.index] {
                Token::RBrace => {
                    self.index += 1;
                    return Ok(());
                }
                Token::Spread => {
                    self.index += 1;
                    self.parse_fragment_spread(depth + 1)?;
                }
                _ => {
                    self.parse_field(depth + 1, division)?;
                }
            }
        }
        Err(GraphqlInspectionError::malformed(
            "unterminated GraphQL selection set",
        ))
    }

    fn parse_fragment_spread(&mut self, depth: usize) -> Result<(), GraphqlInspectionError> {
        if let Some(Token::Ident(keyword)) = self.tokens.get(self.index) {
            if keyword == "on" {
                self.index += 1;
                self.skip_ident();
                self.skip_directives();
                if matches!(self.tokens.get(self.index), Some(Token::LBrace)) {
                    self.parse_selection_set(depth, Division::Fragment)?;
                }
            } else {
                self.skip_ident();
                self.skip_directives();
            }
        }
        Ok(())
    }

    fn parse_field(
        &mut self,
        depth: usize,
        division: Division,
    ) -> Result<(), GraphqlInspectionError> {
        let Some(Token::Ident(_)) = self.tokens.get(self.index) else {
            self.index += 1;
            return Ok(());
        };
        if matches!(self.tokens.get(self.index + 1), Some(Token::Colon)) {
            self.aliases += 1;
            self.index += 1; // alias
            self.index += 1; // colon
        }
        if matches!(self.tokens.get(self.index), Some(Token::Ident(_))) {
            self.fields += 1;
            self.index += 1;
        } else {
            return Ok(());
        }
        self.skip_parens();
        self.skip_directives();
        if matches!(self.tokens.get(self.index), Some(Token::LBrace)) {
            self.parse_selection_set(depth, division)?;
        }
        Ok(())
    }

    fn skip_ident(&mut self) {
        if matches!(self.tokens.get(self.index), Some(Token::Ident(_))) {
            self.index += 1;
        }
    }

    fn skip_parens(&mut self) {
        if matches!(self.tokens.get(self.index), Some(Token::LParen)) {
            let mut level = 0usize;
            while self.index < self.tokens.len() {
                match self.tokens[self.index] {
                    Token::LParen => level += 1,
                    Token::RParen => {
                        level -= 1;
                        if level == 0 {
                            self.index += 1;
                            break;
                        }
                    }
                    _ => {}
                }
                self.index += 1;
            }
        }
    }

    fn skip_directives(&mut self) {
        while matches!(self.tokens.get(self.index), Some(Token::At)) {
            self.index += 1;
            self.skip_ident();
            self.skip_parens();
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Division {
    Operation,
    Fragment,
}

fn negligible_depth() -> usize {
    0
}

fn json_depth(value: &serde_json::Value) -> usize {
    match value {
        serde_json::Value::Array(values) => 1 + values.iter().map(json_depth).max().unwrap_or(0),
        serde_json::Value::Object(map) => 1 + map.values().map(json_depth).max().unwrap_or(0),
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use hyper::{HeaderMap, Method, Uri};
    use std::net::{IpAddr, Ipv4Addr};
    use std::str::FromStr;

    fn config(mode: WafGraphqlScanMode) -> WafGraphqlConfig {
        WafGraphqlConfig {
            enabled: true,
            body_scan: mode.as_str().to_string(),
            ..WafGraphqlConfig::default()
        }
    }

    fn context(
        method: Method,
        uri: &str,
        content_type: &str,
        body: Option<&str>,
    ) -> RequestContext {
        let mut headers = HeaderMap::new();
        if !content_type.is_empty() {
            headers.insert(
                hyper::header::CONTENT_TYPE,
                hyper::header::HeaderValue::from_str(content_type).unwrap(),
            );
        }
        let body_bytes = body.map(|body| Bytes::from(body.to_string()));
        RequestContext::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            method,
            Uri::from_str(uri).unwrap(),
            headers,
            body_bytes.as_ref().map(|body| body.len()),
        )
        .with_body(body_bytes)
    }

    fn json_body(query: &str) -> String {
        serde_json::json!({"query": query, "operationName": "GetUser"}).to_string()
    }

    #[test]
    fn detection_covers_post_json_graphql_and_get() {
        let inspector = GraphqlInspector::from_config(&config(WafGraphqlScanMode::Crs));
        let post = context(
            Method::POST,
            "/graphql",
            "application/json; charset=utf-8",
            Some(&json_body("{ user { id } }")),
        );
        assert!(inspector.matches(&post));

        let raw = context(
            Method::POST,
            "/graphql",
            "application/graphql",
            Some("{ user { id } }"),
        );
        assert!(inspector.matches(&raw));

        let get = context(
            Method::GET,
            "/graphql?query=%7B%20user%20%7B%20id%20%7D%20%7D",
            "",
            None,
        );
        assert!(inspector.matches(&get));

        let not_graphql = context(Method::POST, "/", "text/plain", Some("hello"));
        assert!(!inspector.matches(&not_graphql));
    }

    #[test]
    fn query_hash_is_stable_across_whitespace_and_comments() {
        let a = query_hash("query GetUser { user(id: 1) { id name } }");
        let b = query_hash("  query GetUser {\n\tuser(id: 1)   { id\n name } # trailing\n}  ");
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn operation_name_and_hash_allowlists_allow_block_and_monitor() {
        let query = "query GetUser { user { id } }";
        let body = json_body(query);

        let mut allow_name = config(WafGraphqlScanMode::Crs);
        allow_name.operation_allowlist = vec!["GetUser".to_string()];
        let inspector = GraphqlInspector::from_config(&allow_name);
        let ctx = context(Method::POST, "/graphql", "application/json", Some(&body));
        assert!(matches!(
            inspector.inspect(&ctx).unwrap(),
            GraphqlVerdict::Allow { .. }
        ));

        let mut allow_hash = config(WafGraphqlScanMode::Crs);
        allow_hash.operation_allowlist = vec![query_hash(query)];
        let inspector = GraphqlInspector::from_config(&allow_hash);
        assert!(matches!(
            inspector.inspect(&ctx).unwrap(),
            GraphqlVerdict::Allow { .. }
        ));

        let mut block = config(WafGraphqlScanMode::Crs);
        block.operation_allowlist = vec!["Other".to_string()];
        block.unknown_operation_action = Some("block".to_string());
        let inspector = GraphqlInspector::from_config(&block);
        assert!(matches!(
            inspector.inspect(&ctx).unwrap(),
            GraphqlVerdict::Block { status: 403, .. }
        ));

        let mut monitor = config(WafGraphqlScanMode::Crs);
        monitor.operation_allowlist = vec!["Other".to_string()];
        monitor.unknown_operation_action = Some("monitor".to_string());
        let inspector = GraphqlInspector::from_config(&monitor);
        assert!(matches!(
            inspector.inspect(&ctx).unwrap(),
            GraphqlVerdict::Allow {
                monitored: true,
                ..
            }
        ));
    }

    #[test]
    fn depth_alias_field_and_variable_limits_are_enforced() {
        let mut shallow = config(WafGraphqlScanMode::Crs);
        shallow.max_depth = 1;
        let inspector = GraphqlInspector::from_config(&shallow);
        let ctx = context(
            Method::POST,
            "/graphql",
            "application/json",
            Some(&json_body("{ a { b { c } } }")),
        );
        assert!(matches!(
            inspector.inspect(&ctx).unwrap(),
            GraphqlVerdict::Block { status: 400, .. }
        ));

        let mut aliases = config(WafGraphqlScanMode::Crs);
        aliases.max_aliases = 0;
        let inspector = GraphqlInspector::from_config(&aliases);
        let ctx = context(
            Method::POST,
            "/graphql",
            "application/json",
            Some(&json_body("{ one: a two: b }")),
        );
        assert!(matches!(
            inspector.inspect(&ctx).unwrap(),
            GraphqlVerdict::Block { status: 400, .. }
        ));

        let mut fields = config(WafGraphqlScanMode::Crs);
        fields.max_fields = 1;
        let inspector = GraphqlInspector::from_config(&fields);
        let ctx = context(
            Method::POST,
            "/graphql",
            "application/json",
            Some(&json_body("{ a b }")),
        );
        assert!(matches!(
            inspector.inspect(&ctx).unwrap(),
            GraphqlVerdict::Block { status: 400, .. }
        ));

        let mut variables = config(WafGraphqlScanMode::Crs);
        variables.max_variables = 0;
        let inspector = GraphqlInspector::from_config(&variables);
        let ctx = context(
            Method::POST,
            "/graphql",
            "application/json",
            Some(r#"{"query":"query Q($a:Int){x}","variables":{"a":1}}"#),
        );
        assert!(matches!(
            inspector.inspect(&ctx).unwrap(),
            GraphqlVerdict::Block { status: 400, .. }
        ));
    }

    #[test]
    fn mutation_and_subscription_can_be_denied() {
        let mut config = config(WafGraphqlScanMode::Crs);
        config.allow_mutations = false;
        config.allow_subscriptions = false;
        let inspector = GraphqlInspector::from_config(&config);
        for query in ["mutation M { update }", "subscription S { events }"] {
            let ctx = context(
                Method::POST,
                "/graphql",
                "application/json",
                Some(&json_body(query)),
            );
            assert!(matches!(
                inspector.inspect(&ctx).unwrap(),
                GraphqlVerdict::Block { status: 403, .. }
            ));
        }
    }

    #[test]
    fn crs_mode_never_strips_and_graphql_only_does() {
        let body = json_body("{ user { id } }");
        let ctx = context(Method::POST, "/graphql", "application/json", Some(&body));

        let crs = GraphqlInspector::from_config(&config(WafGraphqlScanMode::Crs));
        assert!(matches!(
            crs.inspect(&ctx).unwrap(),
            GraphqlVerdict::Allow {
                strip_body: false,
                ..
            }
        ));

        let mut only_config = config(WafGraphqlScanMode::GraphqlOnly);
        only_config.operation_allowlist = vec!["GetUser".to_string()];
        let only = GraphqlInspector::from_config(&only_config);
        assert!(matches!(
            only.inspect(&ctx).unwrap(),
            GraphqlVerdict::Allow {
                strip_body: true,
                ..
            }
        ));
    }

    #[test]
    fn malformed_json_is_left_to_crs_but_fails_closed_in_graphql_only() {
        let ctx = context(
            Method::POST,
            "/graphql",
            "application/json",
            Some("{ not json"),
        );

        let crs = GraphqlInspector::from_config(&config(WafGraphqlScanMode::Crs));
        assert!(matches!(
            crs.inspect(&ctx).unwrap(),
            GraphqlVerdict::Allow {
                strip_body: false,
                ..
            }
        ));

        let mut only_config = config(WafGraphqlScanMode::GraphqlOnly);
        only_config.operation_allowlist = vec!["GetUser".to_string()];
        let only = GraphqlInspector::from_config(&only_config);
        assert!(only.inspect(&ctx).is_err());
    }

    #[test]
    fn artifact_format_round_trips_and_validates() {
        let dir = std::env::temp_dir().join(format!(
            "graphql-allowlist-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("allowlist.json");
        let query = "query GetUser { user { id } }";
        std::fs::write(
            &path,
            serde_json::to_vec_pretty(&vec![serde_json::json!({
                "name": "GetUser",
                "sha256": query_hash(query),
            })])
            .unwrap(),
        )
        .unwrap();
        let operations = load_operation_allowlist(&path).unwrap();
        assert_eq!(operations.len(), 1);
        assert_eq!(operations[0].name, "GetUser");

        std::fs::write(&path, r#"[{"name":"x","sha256":"nope"}]"#).unwrap();
        assert!(load_operation_allowlist(&path).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
