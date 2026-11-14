//! Deterministic GraphQL persisted-query allowlist generation and loading.
//!
//! The GraphQL inspector (`src/waf/graphql.rs`) can allow operations by name
//! or by the SHA-256 of the normalised query. Maintaining that list by hand
//! drifts from the client build, so this module turns a manifest and/or a
//! directory of `.graphql` files into a reviewable JSON artifact:
//!
//! ```json
//! {
//!   "ir_version": 1,
//!   "source": {"kind": "manifest", "sha256": "..."},
//!   "operations": [
//!     {"name": "GetUser", "sha256": "...", "type": "query"}
//!   ],
//!   "unknown_operation_action": "block"
//! }
//! ```
//!
//! # Normalisation
//!
//! Queries are hashed after [`crate::waf::graphql::normalize_query`]:
//!
//! * comments (`# ...` to end of line) are removed,
//! * commas outside strings are treated as whitespace,
//! * runs of whitespace outside strings collapse to one space,
//! * leading/trailing whitespace is trimmed.
//!
//! String and block-string contents are preserved byte-for-byte, so a query
//! that differs only in insignificant whitespace, comments or commas hashes
//! identically. The hash is over the query text, not the JSON envelope, so
//! client `variables` do not change it.
//!
//! # Integration interface
//!
//! [`load_allowlist`] is the hook for `waf.graphql.allowlist_file`. The
//! inspector calls it once at start-up, merges the operations with the inline
//! `operation_allowlist`, and uses [`GraphqlAllowlist::allows_name`] /
//! [`GraphqlAllowlist::allows_hash`] for lookups. An explicit
//! `waf.graphql.unknown_operation_action` wins over the artifact's value.
//!
//! # Failure behaviour
//!
//! Every structural problem is an error with the offending file, operation or
//! manifest entry in the message: malformed JSON, empty queries, duplicate
//! names or hashes, invalid hashes, unsupported operation types, and
//! mutations/subscriptions that were not explicitly enabled. There is no
//! partial success.

use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::waf::graphql::{normalize_query, parse_query};

/// Version of the allowlist document produced by this module.
pub const ALLOWLIST_IR_VERSION: u32 = 1;

/// Default maximum raw query size accepted by the generator.
pub const DEFAULT_MAX_QUERY_BYTES: usize = 1024 * 1024;

/// Errors from generation, loading or CLI parsing.
#[derive(Debug)]
pub enum GraphqlAllowlistError {
    /// A manifest, query file or artifact could not be read or written.
    Io {
        path: String,
        source: std::io::Error,
    },
    /// The manifest is malformed or internally inconsistent.
    InvalidManifest(String),
    /// The generated or loaded allowlist document is invalid.
    InvalidArtifact(String),
    /// A query uses an operation type that was not enabled.
    UnsupportedOperation(String),
    /// Command-line arguments are invalid.
    Cli(String),
}

impl fmt::Display for GraphqlAllowlistError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => write!(formatter, "failed to access '{path}': {source}"),
            Self::InvalidManifest(message) => write!(formatter, "invalid manifest: {message}"),
            Self::InvalidArtifact(message) => write!(formatter, "invalid allowlist: {message}"),
            Self::UnsupportedOperation(message) => {
                write!(formatter, "unsupported operation: {message}")
            }
            Self::Cli(message) => write!(formatter, "{message}"),
        }
    }
}

impl std::error::Error for GraphqlAllowlistError {}

impl GraphqlAllowlistError {
    fn io(path: &Path, source: std::io::Error) -> Self {
        Self::Io {
            path: path.display().to_string(),
            source,
        }
    }
}

/// Provenance of the inputs used to produce the allowlist.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowlistSource {
    /// `manifest`, `directory`, `manifest+directory` or `legacy`.
    pub kind: String,
    /// Lowercase hex SHA-256 of the canonical input bytes.
    pub sha256: String,
}

/// One allowed GraphQL operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphqlAllowlistOperation {
    /// Operation name.
    pub name: String,
    /// Lowercase hex SHA-256 of the normalised query.
    pub sha256: String,
    /// `query`, `mutation` or `subscription`.
    #[serde(rename = "type")]
    pub operation_type: String,
}

/// Parsed allowlist artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphqlAllowlist {
    /// Artifact schema version.
    pub ir_version: u32,
    /// Input provenance.
    pub source: AllowlistSource,
    /// Allowed operations, in canonical name order.
    pub operations: Vec<GraphqlAllowlistOperation>,
    /// `allow` or `block` for operations outside the list.
    pub unknown_operation_action: String,
}

impl GraphqlAllowlist {
    /// Returns true when the artifact allows the operation name.
    pub fn allows_name(&self, name: &str) -> bool {
        self.operations
            .iter()
            .any(|operation| operation.name == name)
    }

    /// Returns true when the artifact allows the normalised query hash.
    pub fn allows_hash(&self, sha256: &str) -> bool {
        let sha256 = sha256.to_ascii_lowercase();
        self.operations
            .iter()
            .any(|operation| operation.sha256 == sha256)
    }

    /// Validates every field of the artifact.
    pub fn validate(&self) -> Result<(), GraphqlAllowlistError> {
        if self.ir_version != ALLOWLIST_IR_VERSION {
            return Err(GraphqlAllowlistError::InvalidArtifact(format!(
                "unsupported ir_version {} (expected {ALLOWLIST_IR_VERSION})",
                self.ir_version
            )));
        }
        if self.source.kind.trim().is_empty() {
            return Err(GraphqlAllowlistError::InvalidArtifact(
                "source.kind must not be empty".to_string(),
            ));
        }
        if !is_lower_sha256(&self.source.sha256) {
            return Err(GraphqlAllowlistError::InvalidArtifact(
                "source.sha256 must be 64 lowercase hex characters".to_string(),
            ));
        }
        if self.unknown_operation_action != "allow" && self.unknown_operation_action != "block" {
            return Err(GraphqlAllowlistError::InvalidArtifact(format!(
                "unknown_operation_action must be 'allow' or 'block', got '{}'",
                self.unknown_operation_action
            )));
        }
        if self.operations.is_empty() {
            return Err(GraphqlAllowlistError::InvalidArtifact(
                "operations is empty; an empty allowlist would disable operation enforcement"
                    .to_string(),
            ));
        }

        let mut names = BTreeSet::new();
        let mut hashes = BTreeSet::new();
        for operation in &self.operations {
            if !is_valid_name(&operation.name) {
                return Err(GraphqlAllowlistError::InvalidArtifact(format!(
                    "operation name '{}' is not a valid GraphQL name",
                    operation.name
                )));
            }
            if !is_lower_sha256(&operation.sha256) {
                return Err(GraphqlAllowlistError::InvalidArtifact(format!(
                    "operation '{}' has an invalid sha256 (expected 64 lowercase hex characters)",
                    operation.name
                )));
            }
            if !matches!(
                operation.operation_type.as_str(),
                "query" | "mutation" | "subscription"
            ) {
                return Err(GraphqlAllowlistError::InvalidArtifact(format!(
                    "operation '{}' has unsupported type '{}' (expected query, mutation or subscription)",
                    operation.name, operation.operation_type
                )));
            }
            if !names.insert(operation.name.as_str()) {
                return Err(GraphqlAllowlistError::InvalidArtifact(format!(
                    "duplicate operation name '{}'",
                    operation.name
                )));
            }
            if !hashes.insert(operation.sha256.as_str()) {
                return Err(GraphqlAllowlistError::InvalidArtifact(format!(
                    "duplicate operation hash '{}' (operation '{}')",
                    operation.sha256, operation.name
                )));
            }
        }
        Ok(())
    }

    /// Serializes the artifact to canonical, deterministic pretty JSON.
    ///
    /// Operations are sorted by name and a trailing newline is appended, so
    /// two runs over the same inputs produce byte-identical output.
    pub fn to_canonical_json(&self) -> Result<String, GraphqlAllowlistError> {
        let mut sorted = self.clone();
        sorted
            .operations
            .sort_by(|left, right| left.name.cmp(&right.name));
        sorted.validate()?;
        let mut json = serde_json::to_string_pretty(&sorted).map_err(|error| {
            GraphqlAllowlistError::InvalidArtifact(format!("failed to serialize: {error}"))
        })?;
        json.push('\n');
        Ok(json)
    }
}

/// Loads and validates an allowlist artifact from disk.
///
/// This is the integration point for `waf.graphql.allowlist_file`: the
/// inspector calls `load_allowlist(path)` once at start-up and keeps the
/// returned [`GraphqlAllowlist`]. Errors are descriptive and include the file
/// path.
pub fn load_allowlist(path: impl AsRef<Path>) -> Result<GraphqlAllowlist, GraphqlAllowlistError> {
    let path = path.as_ref();
    let bytes = fs::read(path).map_err(|error| GraphqlAllowlistError::io(path, error))?;
    parse_allowlist(&bytes).map_err(|error| match error {
        GraphqlAllowlistError::InvalidArtifact(message) => {
            GraphqlAllowlistError::InvalidArtifact(format!("{}: {message}", path.display()))
        }
        other => other,
    })
}

/// Parses and validates an allowlist artifact from JSON bytes.
///
/// The canonical form is the object emitted by the generator. For backwards
/// compatibility a bare list of `{ "name", "sha256" }` objects (and an object
/// with an `operations` array) is also accepted and treated as a `legacy`
/// source.
pub fn parse_allowlist(bytes: &[u8]) -> Result<GraphqlAllowlist, GraphqlAllowlistError> {
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|error| {
        GraphqlAllowlistError::InvalidArtifact(format!("malformed JSON: {error}"))
    })?;

    let allowlist = match value {
        serde_json::Value::Array(_) => legacy_allowlist(&value, bytes)?,
        serde_json::Value::Object(ref object)
            if object.contains_key("operations") && !object.contains_key("ir_version") =>
        {
            legacy_allowlist(&value, bytes)?
        }
        _ => serde_json::from_value(value).map_err(|error| {
            GraphqlAllowlistError::InvalidArtifact(format!("malformed JSON: {error}"))
        })?,
    };
    allowlist.validate()?;
    Ok(allowlist)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyOperation {
    name: String,
    sha256: String,
    #[serde(default, rename = "type")]
    operation_type: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum LegacyArtifact {
    List(Vec<LegacyOperation>),
    Wrapped { operations: Vec<LegacyOperation> },
}

fn legacy_allowlist(
    value: &serde_json::Value,
    bytes: &[u8],
) -> Result<GraphqlAllowlist, GraphqlAllowlistError> {
    let artifact: LegacyArtifact = serde_json::from_value(value.clone()).map_err(|error| {
        GraphqlAllowlistError::InvalidArtifact(format!("malformed legacy allowlist: {error}"))
    })?;
    let operations = match artifact {
        LegacyArtifact::List(operations) | LegacyArtifact::Wrapped { operations } => operations,
    };
    Ok(GraphqlAllowlist {
        ir_version: ALLOWLIST_IR_VERSION,
        source: AllowlistSource {
            kind: "legacy".to_string(),
            sha256: hex::encode(Sha256::digest(bytes)),
        },
        operations: operations
            .into_iter()
            .map(|operation| GraphqlAllowlistOperation {
                name: operation.name,
                sha256: operation.sha256.to_ascii_lowercase(),
                operation_type: operation
                    .operation_type
                    .unwrap_or_else(|| "query".to_string()),
            })
            .collect(),
        unknown_operation_action: "block".to_string(),
    })
}

/// Generation options shared by the CLI and the library entry points.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenerateOptions {
    /// Maximum raw query size in bytes.
    pub max_query_bytes: usize,
    /// Allow `mutation` operations.
    pub allow_mutations: bool,
    /// Allow `subscription` operations.
    pub allow_subscriptions: bool,
    /// `allow` or `block` for operations outside the list.
    pub unknown_operation_action: String,
}

impl Default for GenerateOptions {
    fn default() -> Self {
        Self {
            max_query_bytes: DEFAULT_MAX_QUERY_BYTES,
            allow_mutations: false,
            allow_subscriptions: false,
            unknown_operation_action: "block".to_string(),
        }
    }
}

impl GenerateOptions {
    fn validate(&self) -> Result<(), GraphqlAllowlistError> {
        if self.max_query_bytes == 0 {
            return Err(GraphqlAllowlistError::Cli(
                "max_query_bytes must be greater than zero".to_string(),
            ));
        }
        if self.unknown_operation_action != "allow" && self.unknown_operation_action != "block" {
            return Err(GraphqlAllowlistError::Cli(format!(
                "unknown_operation_action must be 'allow' or 'block', got '{}'",
                self.unknown_operation_action
            )));
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestEntry {
    name: String,
    #[serde(default)]
    query: Option<String>,
    #[serde(default)]
    sha256: Option<String>,
    #[serde(default, rename = "type")]
    operation_type: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Manifest {
    List(Vec<ManifestEntry>),
    Wrapped { operations: Vec<ManifestEntry> },
}

/// Builds a deterministic allowlist from a manifest and/or a directory of
/// `.graphql` files.
///
/// At least one input is required. Directory entries are read in file-name
/// order and named after the file stem. Manifest entries may provide either a
/// `query` (hashed after normalisation) or a pre-computed `sha256`; a
/// hash-only entry may set `type`, which defaults to `query`.
pub fn build_allowlist(
    manifest: Option<&[u8]>,
    directory: Option<&Path>,
    options: &GenerateOptions,
) -> Result<GraphqlAllowlist, GraphqlAllowlistError> {
    options.validate()?;
    if manifest.is_none() && directory.is_none() {
        return Err(GraphqlAllowlistError::Cli(
            "at least one of --manifest or --dir is required".to_string(),
        ));
    }

    let mut hasher = Sha256::new();
    let mut kinds = Vec::new();
    let mut operations = Vec::new();

    if let Some(bytes) = manifest {
        kinds.push("manifest");
        hasher.update(b"manifest\0");
        hasher.update(bytes);
        let manifest: Manifest = serde_json::from_slice(bytes).map_err(|error| {
            GraphqlAllowlistError::InvalidManifest(format!("malformed JSON: {error}"))
        })?;
        let entries = match manifest {
            Manifest::List(entries)
            | Manifest::Wrapped {
                operations: entries,
            } => entries,
        };
        if entries.is_empty() {
            return Err(GraphqlAllowlistError::InvalidManifest(
                "manifest must contain at least one operation".to_string(),
            ));
        }
        for (index, entry) in entries.into_iter().enumerate() {
            operations.push(operation_from_manifest(entry, index, options)?);
        }
    }

    if let Some(directory) = directory {
        kinds.push("directory");
        hasher.update(b"directory\0");
        let mut files = graphql_files(directory)?;
        if files.is_empty() {
            return Err(GraphqlAllowlistError::InvalidManifest(format!(
                "directory '{}' contains no .graphql files",
                directory.display()
            )));
        }
        files.sort();
        for path in files {
            let bytes = fs::read(&path).map_err(|error| GraphqlAllowlistError::io(&path, error))?;
            hasher.update(path.file_name().unwrap_or_default().as_encoded_bytes());
            hasher.update(b"\0");
            hasher.update(&bytes);
            hasher.update(b"\0");
            let name = path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .ok_or_else(|| {
                    GraphqlAllowlistError::InvalidManifest(format!(
                        "file '{}' has no valid UTF-8 stem",
                        path.display()
                    ))
                })?
                .to_string();
            let query = String::from_utf8(bytes).map_err(|error| {
                GraphqlAllowlistError::InvalidManifest(format!(
                    "file '{}' is not valid UTF-8: {error}",
                    path.display()
                ))
            })?;
            operations.push(operation_from_query(
                name,
                &query,
                None,
                &format!("file '{}'", path.display()),
                options,
            )?);
        }
    }

    let source_kind = kinds.join("+");
    let mut allowlist = GraphqlAllowlist {
        ir_version: ALLOWLIST_IR_VERSION,
        source: AllowlistSource {
            kind: source_kind,
            sha256: hex::encode(hasher.finalize()),
        },
        operations,
        unknown_operation_action: options.unknown_operation_action.clone(),
    };
    allowlist
        .operations
        .sort_by(|left, right| left.name.cmp(&right.name));
    allowlist.validate()?;
    Ok(allowlist)
}

fn graphql_files(directory: &Path) -> Result<Vec<PathBuf>, GraphqlAllowlistError> {
    let entries =
        fs::read_dir(directory).map_err(|error| GraphqlAllowlistError::io(directory, error))?;
    let mut files = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| GraphqlAllowlistError::io(directory, error))?;
        let path = entry.path();
        if path.is_file()
            && path
                .extension()
                .and_then(|extension| extension.to_str())
                .is_some_and(|extension| extension.eq_ignore_ascii_case("graphql"))
        {
            files.push(path);
        }
    }
    Ok(files)
}

fn operation_from_manifest(
    entry: ManifestEntry,
    index: usize,
    options: &GenerateOptions,
) -> Result<GraphqlAllowlistOperation, GraphqlAllowlistError> {
    let context = format!("manifest entry #{index} ('{}')", entry.name);
    match (entry.query, entry.sha256) {
        (Some(query), None) => operation_from_query(
            entry.name,
            &query,
            entry.operation_type.as_deref(),
            &context,
            options,
        ),
        (None, Some(sha256)) => {
            if !is_lower_sha256(&sha256) {
                return Err(GraphqlAllowlistError::InvalidManifest(format!(
                    "{context}: sha256 must be 64 lowercase hex characters"
                )));
            }
            let operation_type = entry.operation_type.unwrap_or_else(|| "query".to_string());
            validate_operation_type(&operation_type, &context, options)?;
            Ok(GraphqlAllowlistOperation {
                name: entry.name,
                sha256,
                operation_type,
            })
        }
        (Some(_), Some(_)) => Err(GraphqlAllowlistError::InvalidManifest(format!(
            "{context}: provide either 'query' or 'sha256', not both"
        ))),
        (None, None) => Err(GraphqlAllowlistError::InvalidManifest(format!(
            "{context}: provide either 'query' or 'sha256'"
        ))),
    }
}

fn operation_from_query(
    name: String,
    query: &str,
    declared_type: Option<&str>,
    context: &str,
    options: &GenerateOptions,
) -> Result<GraphqlAllowlistOperation, GraphqlAllowlistError> {
    if query.len() > options.max_query_bytes {
        return Err(GraphqlAllowlistError::InvalidManifest(format!(
            "{context}: query is {} bytes, exceeding max_query_bytes {}",
            query.len(),
            options.max_query_bytes
        )));
    }
    let normalized = normalize_query(query);
    if normalized.is_empty() {
        return Err(GraphqlAllowlistError::InvalidManifest(format!(
            "{context}: query is empty after normalisation"
        )));
    }
    let document = parse_query(query)
        .map_err(|error| GraphqlAllowlistError::InvalidManifest(format!("{context}: {error}")))?;
    let operation_type = document.operation_type.as_str().to_string();
    if let Some(declared_type) = declared_type {
        if declared_type != operation_type {
            return Err(GraphqlAllowlistError::InvalidManifest(format!(
                "{context}: declared type '{declared_type}' does not match parsed type '{operation_type}'"
            )));
        }
    }
    validate_operation_type(&operation_type, context, options)?;
    Ok(GraphqlAllowlistOperation {
        name,
        sha256: crate::waf::graphql::query_hash(query),
        operation_type,
    })
}

fn validate_operation_type(
    operation_type: &str,
    context: &str,
    options: &GenerateOptions,
) -> Result<(), GraphqlAllowlistError> {
    match operation_type {
        "query" => Ok(()),
        "mutation" if options.allow_mutations => Ok(()),
        "mutation" => Err(GraphqlAllowlistError::UnsupportedOperation(format!(
            "{context}: mutation operations require --allow-mutations"
        ))),
        "subscription" if options.allow_subscriptions => Ok(()),
        "subscription" => Err(GraphqlAllowlistError::UnsupportedOperation(format!(
            "{context}: subscription operations require --allow-subscriptions"
        ))),
        other => Err(GraphqlAllowlistError::UnsupportedOperation(format!(
            "{context}: unknown operation type '{other}'"
        ))),
    }
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn is_valid_name(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == '_')
        && chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(entries: serde_json::Value) -> Vec<u8> {
        serde_json::to_vec(&entries).unwrap()
    }

    fn options() -> GenerateOptions {
        GenerateOptions::default()
    }

    #[test]
    fn output_is_deterministic_and_sorted_by_name() {
        let input = manifest(serde_json::json!([
            {"name": "Zeta", "query": "query Zeta { z }"},
            {"name": "Alpha", "query": "query Alpha { a }"}
        ]));
        let first = build_allowlist(Some(&input), None, &options()).unwrap();
        let second = build_allowlist(Some(&input), None, &options()).unwrap();
        assert_eq!(
            first.to_canonical_json().unwrap(),
            second.to_canonical_json().unwrap()
        );
        assert_eq!(
            first
                .operations
                .iter()
                .map(|operation| operation.name.as_str())
                .collect::<Vec<_>>(),
            vec!["Alpha", "Zeta"]
        );
        assert!(first.to_canonical_json().unwrap().ends_with("}\n"));
    }

    #[test]
    fn normalisation_makes_whitespace_comments_and_commas_irrelevant() {
        let a = manifest(serde_json::json!([
            {"name": "GetUser", "query": "query GetUser { user(id: 1) { id name } }"}
        ]));
        let b = manifest(serde_json::json!([
            {"name": "GetUser", "query": "  query GetUser {\n\tuser(id: 1), { id\n name } # trailing\n}  "}
        ]));
        let a = build_allowlist(Some(&a), None, &options()).unwrap();
        let b = build_allowlist(Some(&b), None, &options()).unwrap();
        assert_eq!(a.operations[0].sha256, b.operations[0].sha256);
        assert_eq!(
            a.operations[0].sha256,
            crate::waf::graphql::query_hash("query GetUser { user(id: 1) { id name } }")
        );
    }

    #[test]
    fn duplicate_names_and_hashes_fail() {
        let duplicate_name = manifest(serde_json::json!([
            {"name": "GetUser", "query": "query GetUser { a }"},
            {"name": "GetUser", "query": "query GetUser { b }"}
        ]));
        let error = build_allowlist(Some(&duplicate_name), None, &options()).unwrap_err();
        assert!(
            error.to_string().contains("duplicate operation name"),
            "{error}"
        );

        let duplicate_hash = manifest(serde_json::json!([
            {"name": "One", "query": "query One { a }"},
            {"name": "Two", "query": "query One { a }"}
        ]));
        let error = build_allowlist(Some(&duplicate_hash), None, &options()).unwrap_err();
        assert!(
            error.to_string().contains("duplicate operation hash"),
            "{error}"
        );
    }

    #[test]
    fn invalid_manifest_entries_fail_with_context() {
        let empty = manifest(serde_json::json!([
            {"name": "Empty", "query": "  # only a comment\n"}
        ]));
        let error = build_allowlist(Some(&empty), None, &options()).unwrap_err();
        assert!(
            error.to_string().contains("empty after normalisation"),
            "{error}"
        );

        let both = manifest(serde_json::json!([
            {"name": "Both", "query": "query Both { a }", "sha256": "a".repeat(64)}
        ]));
        let error = build_allowlist(Some(&both), None, &options()).unwrap_err();
        assert!(error.to_string().contains("not both"), "{error}");

        let bad_hash = manifest(serde_json::json!([
            {"name": "Bad", "sha256": "nope"}
        ]));
        let error = build_allowlist(Some(&bad_hash), None, &options()).unwrap_err();
        assert!(error.to_string().contains("64 lowercase hex"), "{error}");

        let error = build_allowlist(Some(b"{not json"), None, &options()).unwrap_err();
        assert!(error.to_string().contains("malformed JSON"), "{error}");
    }

    #[test]
    fn unsupported_operations_require_explicit_flags() {
        let mutation = manifest(serde_json::json!([
            {"name": "Update", "query": "mutation Update { update }"}
        ]));
        let error = build_allowlist(Some(&mutation), None, &options()).unwrap_err();
        assert!(error.to_string().contains("--allow-mutations"), "{error}");

        let mut allowed = options();
        allowed.allow_mutations = true;
        let allowlist = build_allowlist(Some(&mutation), None, &allowed).unwrap();
        assert_eq!(allowlist.operations[0].operation_type, "mutation");

        let subscription = manifest(serde_json::json!([
            {"name": "Watch", "query": "subscription Watch { events }"}
        ]));
        let error = build_allowlist(Some(&subscription), None, &options()).unwrap_err();
        assert!(
            error.to_string().contains("--allow-subscriptions"),
            "{error}"
        );
    }

    #[test]
    fn directory_inputs_are_sorted_and_named_by_stem() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("Zeta.graphql"), "query Zeta { z }").unwrap();
        fs::write(dir.path().join("Alpha.graphql"), "query Alpha { a }").unwrap();
        fs::write(dir.path().join("ignored.txt"), "not graphql").unwrap();
        let allowlist = build_allowlist(None, Some(dir.path()), &options()).unwrap();
        assert_eq!(
            allowlist
                .operations
                .iter()
                .map(|operation| operation.name.as_str())
                .collect::<Vec<_>>(),
            vec!["Alpha", "Zeta"]
        );
        assert_eq!(allowlist.source.kind, "directory");
    }

    #[test]
    fn loader_accepts_generated_and_legacy_artifacts() {
        let input = manifest(serde_json::json!([
            {"name": "GetUser", "query": "query GetUser { user { id } }"}
        ]));
        let allowlist = build_allowlist(Some(&input), None, &options()).unwrap();
        let json = allowlist.to_canonical_json().unwrap();
        let parsed = parse_allowlist(json.as_bytes()).unwrap();
        assert_eq!(parsed, allowlist);
        assert!(parsed.allows_name("GetUser"));
        assert!(parsed.allows_hash(&allowlist.operations[0].sha256));

        let legacy = serde_json::to_vec(&serde_json::json!([
            {"name": "GetUser", "sha256": allowlist.operations[0].sha256}
        ]))
        .unwrap();
        let parsed = parse_allowlist(&legacy).unwrap();
        assert_eq!(parsed.source.kind, "legacy");
        assert!(parsed.allows_name("GetUser"));
    }

    #[test]
    fn loader_rejects_invalid_artifacts() {
        let valid = build_allowlist(
            Some(&manifest(serde_json::json!([
                {"name": "GetUser", "query": "query GetUser { user { id } }"}
            ]))),
            None,
            &options(),
        )
        .unwrap();
        let valid = valid.to_canonical_json().unwrap();

        let cases: Vec<(serde_json::Value, &str)> = vec![
            (
                {
                    let mut value: serde_json::Value = serde_json::from_str(&valid).unwrap();
                    value["ir_version"] = serde_json::json!(2);
                    value
                },
                "unsupported ir_version",
            ),
            (
                {
                    let mut value: serde_json::Value = serde_json::from_str(&valid).unwrap();
                    value["source"]["sha256"] = serde_json::json!("ABC");
                    value
                },
                "source.sha256",
            ),
            (
                {
                    let mut value: serde_json::Value = serde_json::from_str(&valid).unwrap();
                    value["unknown_operation_action"] = serde_json::json!("deny");
                    value
                },
                "unknown_operation_action",
            ),
            (
                {
                    let mut value: serde_json::Value = serde_json::from_str(&valid).unwrap();
                    value["operations"] = serde_json::json!([]);
                    value
                },
                "operations is empty",
            ),
            (
                {
                    let mut value: serde_json::Value = serde_json::from_str(&valid).unwrap();
                    value["operations"][0]["type"] = serde_json::json!("fragment");
                    value
                },
                "unsupported type",
            ),
            (
                {
                    let mut value: serde_json::Value = serde_json::from_str(&valid).unwrap();
                    value["operations"][0]["sha256"] = serde_json::json!("nope");
                    value
                },
                "invalid sha256",
            ),
        ];
        for (value, expected) in cases {
            let text = serde_json::to_string(&value).unwrap();
            let error = parse_allowlist(text.as_bytes()).unwrap_err();
            assert!(
                error.to_string().contains(expected),
                "expected '{expected}', got '{error}'"
            );
        }

        let error = parse_allowlist(b"{").unwrap_err();
        assert!(error.to_string().contains("malformed JSON"), "{error}");
    }

    #[test]
    fn load_allowlist_reads_a_file_and_reports_io_errors() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("allowlist.json");
        let allowlist = build_allowlist(
            Some(&manifest(serde_json::json!([
                {"name": "GetUser", "query": "query GetUser { user { id } }"}
            ]))),
            None,
            &options(),
        )
        .unwrap();
        fs::write(&path, allowlist.to_canonical_json().unwrap()).unwrap();
        assert_eq!(load_allowlist(&path).unwrap(), allowlist);

        let missing = dir.path().join("absent.json");
        let error = load_allowlist(&missing).unwrap_err();
        assert!(error.to_string().contains("failed to access"), "{error}");
    }
}
