//! `FileDescriptorSet`-driven gRPC method allowlist generation and loading.
//!
//! The gRPC inspector (`src/waf/grpc.rs`) enforces a list of fully-qualified
//! method paths (`/package.Service/Method`). Maintaining that list by hand does
//! not scale and drifts from the services actually deployed, so this module
//! turns a compiled protobuf descriptor set into a deterministic, reviewable
//! JSON artifact:
//!
//! ```json
//! {
//!   "ir_version": 2,
//!   "source": {"kind": "protobuf", "sha256": "..."},
//!   "methods": [
//!     {"path": "/pkg.Service/Method", "client_streaming": false,
//!      "server_streaming": false, "input": "pkg.Request",
//!      "output": "pkg.Response", "max_message_bytes": 4194304}
//!   ],
//!   "messages": [
//!     {"message": "pkg.Request", "fields": [
//!       {"name": "name", "number": 1, "type": "string", "repeated": false}
//!     ]}
//!   ],
//!   "unknown_method_action": "block"
//! }
//! ```
//!
//! Descriptor sets are read from both the binary `FileDescriptorSet` wire
//! format (`protoc --descriptor_set_out --include_imports`) and the protobuf
//! JSON mapping. Parsing is deliberately minimal: only services, methods,
//! streaming flags and message type names are decoded, which keeps the
//! dependency footprint at zero additional crates.
//!
//! # Integration interface
//!
//! The inspector can load a generated artifact with
//! [`load_allowlist`]. It validates the document and returns the parsed
//! [`GrpcAllowlist`]; [`GrpcAllowlist::max_message_bytes_for`] resolves the
//! per-method size limit. This module does not reference the inspector, so it
//! can be wired in independently (`waf.grpc.allowlist_file`).
//!
//! # Failure behaviour
//!
//! Every structural problem is an error with the offending file, service or
//! method in the message: malformed wire data, missing names/types, duplicate
//! method paths, type names that are not defined in the descriptor set, and
//! overrides for unknown methods. There is no partial success.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Version of the allowlist document produced by this module.
///
/// Version 2 adds the `messages` field metadata used for field-level
/// inspection. Version 1 artifacts are still accepted and fall back to
/// envelope-only inspection.
pub const ALLOWLIST_IR_VERSION: u32 = 2;

/// Oldest artifact schema version accepted by the loader.
pub const MIN_ALLOWLIST_IR_VERSION: u32 = 1;

/// Default per-message size limit, matching `[waf.grpc]`.
pub const DEFAULT_MAX_MESSAGE_BYTES: usize = 4 * 1024 * 1024;

/// Maximum nesting depth emitted for reachable request message types.
///
/// The encoder stops adding nested message definitions at this depth; deeper
/// messages remain opaque length-delimited fields at request time.
pub const MAX_MESSAGE_FIELD_DEPTH: usize = 16;

/// Source descriptor format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DescriptorFormat {
    /// Sniff based on the first non-whitespace byte (`{` means JSON).
    Auto,
    /// Binary protobuf wire format (`.binpb`, `.pb`, `.descriptor`).
    Binary,
    /// Protobuf JSON mapping (`.json`).
    Json,
}

impl DescriptorFormat {
    /// Parses a `--format` value.
    pub fn parse(value: &str) -> Result<Self, GrpcAllowlistError> {
        match value.to_ascii_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "binary" | "binpb" | "pb" => Ok(Self::Binary),
            "json" => Ok(Self::Json),
            other => Err(GrpcAllowlistError::Cli(format!(
                "unknown descriptor format '{other}' (expected auto, binpb or json)"
            ))),
        }
    }

    /// Picks a format from a file extension, falling back to [`Self::Auto`].
    pub fn from_path(path: &Path) -> Self {
        match path
            .extension()
            .and_then(|extension| extension.to_str())
            .map(|extension| extension.to_ascii_lowercase())
        {
            Some(extension) if extension == "json" => Self::Json,
            Some(extension) if extension == "binpb" || extension == "pb" => Self::Binary,
            _ => Self::Auto,
        }
    }
}

impl fmt::Display for DescriptorFormat {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Auto => "auto",
            Self::Binary => "binpb",
            Self::Json => "json",
        })
    }
}

/// Errors from generation, loading or CLI parsing.
#[derive(Debug)]
pub enum GrpcAllowlistError {
    /// The descriptor or allowlist file could not be read or written.
    Io {
        path: String,
        source: std::io::Error,
    },
    /// The descriptor set is malformed or internally inconsistent.
    Descriptor(String),
    /// The generated or loaded allowlist document is invalid.
    InvalidAllowlist(String),
    /// The optional per-method override file is invalid.
    InvalidOverrides(String),
    /// Command-line arguments are invalid.
    Cli(String),
}

impl fmt::Display for GrpcAllowlistError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => write!(formatter, "failed to access '{path}': {source}"),
            Self::Descriptor(message) => write!(formatter, "invalid descriptor: {message}"),
            Self::InvalidAllowlist(message) => write!(formatter, "invalid allowlist: {message}"),
            Self::InvalidOverrides(message) => {
                write!(formatter, "invalid override config: {message}")
            }
            Self::Cli(message) => write!(formatter, "{message}"),
        }
    }
}

impl std::error::Error for GrpcAllowlistError {}

impl GrpcAllowlistError {
    fn io(path: &Path, source: std::io::Error) -> Self {
        Self::Io {
            path: path.display().to_string(),
            source,
        }
    }
}

/// Provenance of the descriptor used to produce the allowlist.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowlistSource {
    /// Always `protobuf` for this generator.
    pub kind: String,
    /// Lowercase hex SHA-256 of the descriptor bytes as read.
    pub sha256: String,
}

/// One allowed gRPC method.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrpcAllowlistMethod {
    /// Fully-qualified path, `/package.Service/Method`.
    pub path: String,
    /// Client-streaming flag from the descriptor.
    pub client_streaming: bool,
    /// Server-streaming flag from the descriptor.
    pub server_streaming: bool,
    /// Fully-qualified request type without the leading dot.
    pub input: String,
    /// Fully-qualified response type without the leading dot.
    pub output: String,
    /// Per-message decoded size limit in bytes.
    pub max_message_bytes: usize,
}

/// Field metadata for one reachable request message type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrpcMessage {
    /// Fully-qualified message type without the leading dot.
    pub message: String,
    /// Fields sorted by field number.
    #[serde(default)]
    pub fields: Vec<GrpcMessageField>,
}

/// One protobuf field declaration from the descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrpcMessageField {
    /// Protobuf field name.
    pub name: String,
    /// Wire field number.
    pub number: u32,
    /// Normalised protobuf scalar type (`double`, `string`, `message`, ...).
    #[serde(rename = "type")]
    pub field_type: String,
    /// Whether the field is repeated.
    #[serde(default)]
    pub repeated: bool,
    /// Whether the descriptor marks the field as required (proto2 only).
    #[serde(default)]
    pub required: bool,
    /// Fully-qualified target type for `message` fields.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_type: Option<String>,
    /// Valid numeric values for `enum` fields, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enum_values: Option<Vec<i32>>,
}

/// Parsed allowlist artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrpcAllowlist {
    /// Artifact schema version.
    pub ir_version: u32,
    /// Descriptor provenance.
    pub source: AllowlistSource,
    /// Allowed methods, in canonical path order.
    pub methods: Vec<GrpcAllowlistMethod>,
    /// Field metadata for message types reachable from request types.
    #[serde(default)]
    pub messages: Vec<GrpcMessage>,
    /// `allow` or `block` for methods outside the list.
    pub unknown_method_action: String,
}

impl GrpcAllowlist {
    /// Looks up a method by path and returns its size limit.
    pub fn max_message_bytes_for(&self, path: &str) -> Option<usize> {
        self.methods
            .iter()
            .find(|method| method.path == path)
            .map(|method| method.max_message_bytes)
    }

    /// Returns true when the artifact allows the method.
    pub fn allows(&self, path: &str) -> bool {
        self.methods.iter().any(|method| method.path == path)
    }

    /// Returns the field metadata for a message type, when present.
    pub fn message_for(&self, message: &str) -> Option<&GrpcMessage> {
        self.messages
            .iter()
            .find(|definition| definition.message == message)
    }

    /// Validates every field of the artifact.
    ///
    /// Loaded artifacts are always validated; the generator validates its own
    /// output before writing it.
    pub fn validate(&self) -> Result<(), GrpcAllowlistError> {
        if !(MIN_ALLOWLIST_IR_VERSION..=ALLOWLIST_IR_VERSION).contains(&self.ir_version) {
            return Err(GrpcAllowlistError::InvalidAllowlist(format!(
                "unsupported ir_version {} (expected {MIN_ALLOWLIST_IR_VERSION}..={ALLOWLIST_IR_VERSION})",
                self.ir_version
            )));
        }
        if self.source.kind != "protobuf" {
            return Err(GrpcAllowlistError::InvalidAllowlist(format!(
                "source.kind must be 'protobuf', got '{}'",
                self.source.kind
            )));
        }
        if self.source.sha256.len() != 64
            || !self
                .source
                .sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(GrpcAllowlistError::InvalidAllowlist(
                "source.sha256 must be 64 lowercase hex characters".to_string(),
            ));
        }
        if self.unknown_method_action != "allow" && self.unknown_method_action != "block" {
            return Err(GrpcAllowlistError::InvalidAllowlist(format!(
                "unknown_method_action must be 'allow' or 'block', got '{}'",
                self.unknown_method_action
            )));
        }
        if self.methods.is_empty() {
            return Err(GrpcAllowlistError::InvalidAllowlist(
                "methods is empty; an empty allowlist would disable method enforcement".to_string(),
            ));
        }

        let mut seen = BTreeSet::new();
        for method in &self.methods {
            validate_method_path(&method.path).map_err(|reason| {
                GrpcAllowlistError::InvalidAllowlist(format!(
                    "method path '{}': {reason}",
                    method.path
                ))
            })?;
            validate_type_name(&method.input).map_err(|reason| {
                GrpcAllowlistError::InvalidAllowlist(format!(
                    "method '{}': input type '{}' {reason}",
                    method.path, method.input
                ))
            })?;
            validate_type_name(&method.output).map_err(|reason| {
                GrpcAllowlistError::InvalidAllowlist(format!(
                    "method '{}': output type '{}' {reason}",
                    method.path, method.output
                ))
            })?;
            if method.max_message_bytes == 0 {
                return Err(GrpcAllowlistError::InvalidAllowlist(format!(
                    "method '{}': max_message_bytes must be greater than zero",
                    method.path
                )));
            }
            if !seen.insert(method.path.as_str()) {
                return Err(GrpcAllowlistError::InvalidAllowlist(format!(
                    "duplicate method path '{}'",
                    method.path
                )));
            }
        }

        let mut seen_messages = BTreeSet::new();
        for message in &self.messages {
            validate_type_name(&message.message).map_err(|reason| {
                GrpcAllowlistError::InvalidAllowlist(format!(
                    "message type '{}': {reason}",
                    message.message
                ))
            })?;
            if !seen_messages.insert(message.message.as_str()) {
                return Err(GrpcAllowlistError::InvalidAllowlist(format!(
                    "duplicate message type '{}'",
                    message.message
                )));
            }
            let mut seen_fields = BTreeSet::new();
            for field in &message.fields {
                validate_ident(&field.name).map_err(|reason| {
                    GrpcAllowlistError::InvalidAllowlist(format!(
                        "message '{}' field '{}': {reason}",
                        message.message, field.name
                    ))
                })?;
                if field.number == 0 || field.number > 536_870_911 {
                    return Err(GrpcAllowlistError::InvalidAllowlist(format!(
                        "message '{}' field '{}': number {} is outside 1..=536870911",
                        message.message, field.name, field.number
                    )));
                }
                if !seen_fields.insert(field.number) {
                    return Err(GrpcAllowlistError::InvalidAllowlist(format!(
                        "message '{}': duplicate field number {}",
                        message.message, field.number
                    )));
                }
                if !is_grpc_field_type(&field.field_type) {
                    return Err(GrpcAllowlistError::InvalidAllowlist(format!(
                        "message '{}' field '{}': unsupported type '{}'",
                        message.message, field.name, field.field_type
                    )));
                }
                if field.field_type == "message" {
                    let target = field.message_type.as_deref().ok_or_else(|| {
                        GrpcAllowlistError::InvalidAllowlist(format!(
                            "message '{}' field '{}': message fields require message_type",
                            message.message, field.name
                        ))
                    })?;
                    validate_type_name(target).map_err(|reason| {
                        GrpcAllowlistError::InvalidAllowlist(format!(
                            "message '{}' field '{}': message_type '{target}' {reason}",
                            message.message, field.name
                        ))
                    })?;
                } else if field.message_type.is_some() {
                    return Err(GrpcAllowlistError::InvalidAllowlist(format!(
                        "message '{}' field '{}': message_type is only valid for message fields",
                        message.message, field.name
                    )));
                }
                if let Some(values) = &field.enum_values {
                    if values.is_empty() {
                        return Err(GrpcAllowlistError::InvalidAllowlist(format!(
                            "message '{}' field '{}': enum_values must not be empty when set",
                            message.message, field.name
                        )));
                    }
                    let mut seen_values = BTreeSet::new();
                    for value in values {
                        if !seen_values.insert(*value) {
                            return Err(GrpcAllowlistError::InvalidAllowlist(format!(
                                "message '{}' field '{}': duplicate enum value {value}",
                                message.message, field.name
                            )));
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Serializes the artifact to canonical, deterministic pretty JSON.
    ///
    /// Methods are sorted by path and a trailing newline is appended, so two
    /// runs over the same descriptor produce byte-identical output.
    pub fn to_canonical_json(&self) -> Result<String, GrpcAllowlistError> {
        let mut sorted = self.clone();
        sorted
            .methods
            .sort_by(|left, right| left.path.cmp(&right.path));
        sorted
            .messages
            .sort_by(|left, right| left.message.cmp(&right.message));
        for message in &mut sorted.messages {
            message.fields.sort_by_key(|field| field.number);
        }
        sorted.validate()?;
        let mut json = serde_json::to_string_pretty(&sorted).map_err(|error| {
            GrpcAllowlistError::InvalidAllowlist(format!("failed to serialize: {error}"))
        })?;
        json.push('\n');
        Ok(json)
    }
}

/// Loads and validates an allowlist artifact from disk.
///
/// This is the integration point for `waf.grpc.allowlist_file`: the inspector
/// calls `load_allowlist(path)` once at start-up and keeps the returned
/// [`GrpcAllowlist`]. Errors are descriptive and indicate the file path.
pub fn load_allowlist(path: impl AsRef<Path>) -> Result<GrpcAllowlist, GrpcAllowlistError> {
    let path = path.as_ref();
    let bytes = fs::read(path).map_err(|error| GrpcAllowlistError::io(path, error))?;
    parse_allowlist(&bytes).map_err(|error| match error {
        GrpcAllowlistError::InvalidAllowlist(message) => {
            GrpcAllowlistError::InvalidAllowlist(format!("{}: {message}", path.display()))
        }
        other => other,
    })
}

/// Parses and validates an allowlist artifact from JSON bytes.
pub fn parse_allowlist(bytes: &[u8]) -> Result<GrpcAllowlist, GrpcAllowlistError> {
    let allowlist: GrpcAllowlist = serde_json::from_slice(bytes).map_err(|error| {
        GrpcAllowlistError::InvalidAllowlist(format!("malformed JSON: {error}"))
    })?;
    allowlist.validate()?;
    Ok(allowlist)
}

/// Generation options shared by the CLI and the library entry points.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowlistOptions {
    /// Default per-message limit, before per-method overrides.
    pub max_message_bytes: usize,
    /// Per-method limit overrides keyed by fully-qualified path.
    pub method_overrides: BTreeMap<String, usize>,
    /// `allow` or `block` for methods outside the list.
    pub unknown_method_action: String,
}

impl Default for AllowlistOptions {
    fn default() -> Self {
        Self {
            max_message_bytes: DEFAULT_MAX_MESSAGE_BYTES,
            method_overrides: BTreeMap::new(),
            unknown_method_action: "block".to_string(),
        }
    }
}

impl AllowlistOptions {
    fn validate(&self) -> Result<(), GrpcAllowlistError> {
        if self.max_message_bytes == 0 {
            return Err(GrpcAllowlistError::InvalidOverrides(
                "max_message_bytes must be greater than zero".to_string(),
            ));
        }
        if self.unknown_method_action != "allow" && self.unknown_method_action != "block" {
            return Err(GrpcAllowlistError::InvalidOverrides(format!(
                "unknown_method_action must be 'allow' or 'block', got '{}'",
                self.unknown_method_action
            )));
        }
        for (path, limit) in &self.method_overrides {
            validate_method_path(path).map_err(|reason| {
                GrpcAllowlistError::InvalidOverrides(format!("method override '{path}': {reason}"))
            })?;
            if *limit == 0 {
                return Err(GrpcAllowlistError::InvalidOverrides(format!(
                    "method override '{path}': max_message_bytes must be greater than zero"
                )));
            }
        }
        Ok(())
    }
}

/// Builds an allowlist from descriptor bytes.
pub fn build_allowlist(
    descriptor: &[u8],
    format: DescriptorFormat,
    options: &AllowlistOptions,
) -> Result<GrpcAllowlist, GrpcAllowlistError> {
    options.validate()?;
    let descriptor_set = parse_descriptor_set(descriptor, format)?;
    let methods = collect_methods(&descriptor_set)?;
    let messages = collect_request_messages(&descriptor_set, &methods)?;

    let mut allowlist = GrpcAllowlist {
        ir_version: ALLOWLIST_IR_VERSION,
        source: AllowlistSource {
            kind: "protobuf".to_string(),
            sha256: hex::encode(Sha256::digest(descriptor)),
        },
        methods,
        messages,
        unknown_method_action: options.unknown_method_action.clone(),
    };

    for (path, limit) in &options.method_overrides {
        let method = allowlist
            .methods
            .iter_mut()
            .find(|method| &method.path == path)
            .ok_or_else(|| {
                GrpcAllowlistError::InvalidOverrides(format!(
                    "method override '{path}' does not match any method in the descriptor"
                ))
            })?;
        method.max_message_bytes = *limit;
    }

    for method in &mut allowlist.methods {
        if !options.method_overrides.contains_key(&method.path) {
            method.max_message_bytes = options.max_message_bytes;
        }
    }

    allowlist
        .methods
        .sort_by(|left, right| left.path.cmp(&right.path));
    allowlist.validate()?;
    Ok(allowlist)
}

/// Reads a descriptor file and builds an allowlist from it.
pub fn generate_from_descriptor_path(
    descriptor_path: impl AsRef<Path>,
    options: &AllowlistOptions,
) -> Result<GrpcAllowlist, GrpcAllowlistError> {
    let descriptor_path = descriptor_path.as_ref();
    let bytes = fs::read(descriptor_path)
        .map_err(|error| GrpcAllowlistError::io(descriptor_path, error))?;
    let format = DescriptorFormat::from_path(descriptor_path);
    build_allowlist(&bytes, format, options).map_err(|error| match error {
        GrpcAllowlistError::Descriptor(message) => {
            GrpcAllowlistError::Descriptor(format!("{}: {message}", descriptor_path.display()))
        }
        other => other,
    })
}

/// Parses a `FileDescriptorSet` from binary or JSON bytes.
pub fn parse_descriptor_set(
    bytes: &[u8],
    format: DescriptorFormat,
) -> Result<FileDescriptorSet, GrpcAllowlistError> {
    if bytes.is_empty() {
        return Err(GrpcAllowlistError::Descriptor(
            "descriptor set is empty".to_string(),
        ));
    }
    match resolve_format(bytes, format) {
        DescriptorFormat::Json => parse_json_descriptor_set(bytes),
        _ => parse_binary_descriptor_set(bytes),
    }
}

fn resolve_format(bytes: &[u8], format: DescriptorFormat) -> DescriptorFormat {
    match format {
        DescriptorFormat::Auto => {
            let first = bytes
                .iter()
                .find(|byte| !byte.is_ascii_whitespace())
                .copied();
            if first == Some(b'{') {
                DescriptorFormat::Json
            } else {
                DescriptorFormat::Binary
            }
        }
        other => other,
    }
}

/// A parsed descriptor set. Only the fields needed by the allowlist are kept.
#[derive(Debug, Default)]
pub struct FileDescriptorSet {
    files: Vec<FileDescriptorProto>,
}

#[derive(Debug, Default)]
struct FileDescriptorProto {
    name: Option<String>,
    package: Option<String>,
    messages: Vec<DescriptorProto>,
    enums: Vec<EnumDescriptorProto>,
    services: Vec<ServiceDescriptorProto>,
}

#[derive(Debug, Default)]
struct DescriptorProto {
    name: Option<String>,
    fields: Vec<FieldDescriptorProto>,
    nested: Vec<DescriptorProto>,
    enums: Vec<EnumDescriptorProto>,
}

#[derive(Debug, Clone, Default)]
struct FieldDescriptorProto {
    name: Option<String>,
    number: Option<u32>,
    label: Option<u32>,
    field_type: Option<u32>,
    type_name: Option<String>,
}

#[derive(Debug, Default)]
struct EnumDescriptorProto {
    name: Option<String>,
    values: Vec<EnumValueDescriptorProto>,
}

#[derive(Debug, Default)]
struct EnumValueDescriptorProto {
    name: Option<String>,
    number: Option<i32>,
}

#[derive(Debug, Default)]
struct ServiceDescriptorProto {
    name: Option<String>,
    methods: Vec<MethodDescriptorProto>,
}

#[derive(Debug, Default)]
struct MethodDescriptorProto {
    name: Option<String>,
    input_type: Option<String>,
    output_type: Option<String>,
    client_streaming: bool,
    server_streaming: bool,
}

impl FileDescriptorProto {
    fn label(&self, index: usize) -> String {
        match self.name.as_deref() {
            Some(name) if !name.is_empty() => format!("file #{index} ('{name}')"),
            _ => format!("file #{index}"),
        }
    }
}

fn collect_methods(
    descriptor_set: &FileDescriptorSet,
) -> Result<Vec<GrpcAllowlistMethod>, GrpcAllowlistError> {
    if descriptor_set.files.is_empty() {
        return Err(GrpcAllowlistError::Descriptor(
            "descriptor set contains no files".to_string(),
        ));
    }

    let mut types = BTreeSet::new();
    for (index, file) in descriptor_set.files.iter().enumerate() {
        let package = package_name(file, index)?;
        collect_message_types(&file.label(index), &package, &file.messages, &mut types)?;
    }

    let mut methods = Vec::new();
    for (index, file) in descriptor_set.files.iter().enumerate() {
        let label = file.label(index);
        let package = package_name(file, index)?;
        for (service_index, service) in file.services.iter().enumerate() {
            let service_name = service.name.as_deref().ok_or_else(|| {
                GrpcAllowlistError::Descriptor(format!(
                    "{label}: service #{service_index} is missing a name"
                ))
            })?;
            if service_name.is_empty() {
                return Err(GrpcAllowlistError::Descriptor(format!(
                    "{label}: service #{service_index} has an empty name"
                )));
            }
            validate_ident(service_name).map_err(|reason| {
                GrpcAllowlistError::Descriptor(format!(
                    "{label}: service #{service_index} name '{service_name}' {reason}"
                ))
            })?;
            let full_service = if package.is_empty() {
                service_name.to_string()
            } else {
                format!("{package}.{service_name}")
            };
            validate_type_name(&full_service).map_err(|reason| {
                GrpcAllowlistError::Descriptor(format!(
                    "{label}: service '{full_service}' {reason}"
                ))
            })?;

            for (method_index, method) in service.methods.iter().enumerate() {
                let method_name = method.name.as_deref().ok_or_else(|| {
                    GrpcAllowlistError::Descriptor(format!(
                        "{label}: method #{method_index} of service '{full_service}' is missing a name"
                    ))
                })?;
                if method_name.is_empty() {
                    return Err(GrpcAllowlistError::Descriptor(format!(
                        "{label}: method #{method_index} of service '{full_service}' has an empty name"
                    )));
                }
                validate_ident(method_name).map_err(|reason| {
                    GrpcAllowlistError::Descriptor(format!(
                        "{label}: method '{full_service}/{method_name}' {reason}"
                    ))
                })?;
                let path = format!("/{full_service}/{method_name}");
                validate_method_path(&path).map_err(|reason| {
                    GrpcAllowlistError::Descriptor(format!("{label}: method '{path}': {reason}"))
                })?;

                let input_type =
                    method_type_name(method.input_type.as_deref(), "input_type", &path)?;
                let output_type =
                    method_type_name(method.output_type.as_deref(), "output_type", &path)?;
                for (kind, type_name) in [("input", &input_type), ("output", &output_type)] {
                    if !types.contains(type_name.as_str()) {
                        return Err(GrpcAllowlistError::Descriptor(format!(
                            "{label}: method '{path}' {kind} type '.{type_name}' is not defined in the descriptor set (compile with --include_imports)"
                        )));
                    }
                }

                methods.push(GrpcAllowlistMethod {
                    path,
                    client_streaming: method.client_streaming,
                    server_streaming: method.server_streaming,
                    input: input_type,
                    output: output_type,
                    max_message_bytes: DEFAULT_MAX_MESSAGE_BYTES,
                });
            }
        }
    }

    if methods.is_empty() {
        return Err(GrpcAllowlistError::Descriptor(
            "descriptor set contains no services or methods".to_string(),
        ));
    }

    methods.sort_by(|left, right| left.path.cmp(&right.path));
    for pair in methods.windows(2) {
        if pair[0].path == pair[1].path {
            return Err(GrpcAllowlistError::Descriptor(format!(
                "duplicate method path '{}' in the descriptor set",
                pair[0].path
            )));
        }
    }

    Ok(methods)
}

fn package_name(file: &FileDescriptorProto, index: usize) -> Result<String, GrpcAllowlistError> {
    let package = file.package.as_deref().unwrap_or_default();
    if !package.is_empty() {
        validate_type_name(package).map_err(|reason| {
            GrpcAllowlistError::Descriptor(format!(
                "{}: package '{package}' {reason}",
                file.label(index)
            ))
        })?;
    }
    Ok(package.to_string())
}

fn collect_message_types(
    context: &str,
    prefix: &str,
    messages: &[DescriptorProto],
    types: &mut BTreeSet<String>,
) -> Result<(), GrpcAllowlistError> {
    for (index, message) in messages.iter().enumerate() {
        let name = message.name.as_deref().ok_or_else(|| {
            GrpcAllowlistError::Descriptor(format!("{context}: message #{index} is missing a name"))
        })?;
        if name.is_empty() {
            return Err(GrpcAllowlistError::Descriptor(format!(
                "{context}: message #{index} has an empty name"
            )));
        }
        validate_ident(name).map_err(|reason| {
            GrpcAllowlistError::Descriptor(format!(
                "{context}: message #{index} name '{name}' {reason}"
            ))
        })?;
        let full_name = if prefix.is_empty() {
            name.to_string()
        } else {
            format!("{prefix}.{name}")
        };
        if !types.insert(full_name.clone()) {
            return Err(GrpcAllowlistError::Descriptor(format!(
                "{context}: duplicate message type '{full_name}'"
            )));
        }
        collect_message_types(context, &full_name, &message.nested, types)?;
    }
    Ok(())
}

#[derive(Debug, Default)]
struct MessageDefinition {
    fields: Vec<FieldDescriptorProto>,
}

fn collect_request_messages(
    descriptor_set: &FileDescriptorSet,
    methods: &[GrpcAllowlistMethod],
) -> Result<Vec<GrpcMessage>, GrpcAllowlistError> {
    let mut message_definitions: BTreeMap<String, MessageDefinition> = BTreeMap::new();
    let mut enum_definitions: BTreeMap<String, Vec<i32>> = BTreeMap::new();

    for (index, file) in descriptor_set.files.iter().enumerate() {
        let package = package_name(file, index)?;
        collect_definitions(
            &file.label(index),
            &package,
            &file.messages,
            &file.enums,
            &mut message_definitions,
            &mut enum_definitions,
        )?;
    }

    let mut reachable = BTreeMap::new();
    for method in methods {
        collect_reachable_message(
            &method.input,
            &message_definitions,
            &enum_definitions,
            &mut reachable,
            0,
            MAX_MESSAGE_FIELD_DEPTH,
        )?;
    }

    Ok(reachable.into_values().collect())
}

fn collect_definitions(
    context: &str,
    prefix: &str,
    messages: &[DescriptorProto],
    enums: &[EnumDescriptorProto],
    message_definitions: &mut BTreeMap<String, MessageDefinition>,
    enum_definitions: &mut BTreeMap<String, Vec<i32>>,
) -> Result<(), GrpcAllowlistError> {
    for (index, enumeration) in enums.iter().enumerate() {
        let name = enumeration.name.as_deref().ok_or_else(|| {
            GrpcAllowlistError::Descriptor(format!("{context}: enum #{index} is missing a name"))
        })?;
        validate_ident(name).map_err(|reason| {
            GrpcAllowlistError::Descriptor(format!(
                "{context}: enum #{index} name '{name}' {reason}"
            ))
        })?;
        let full_name = if prefix.is_empty() {
            name.to_string()
        } else {
            format!("{prefix}.{name}")
        };
        let mut values = Vec::new();
        for (value_index, value) in enumeration.values.iter().enumerate() {
            let value_name = value.name.as_deref().ok_or_else(|| {
                GrpcAllowlistError::Descriptor(format!(
                    "{context}: enum '{full_name}' value #{value_index} is missing a name"
                ))
            })?;
            validate_ident(value_name).map_err(|reason| {
                GrpcAllowlistError::Descriptor(format!(
                    "{context}: enum '{full_name}' value name '{value_name}' {reason}"
                ))
            })?;
            let number = value.number.ok_or_else(|| {
                GrpcAllowlistError::Descriptor(format!(
                    "{context}: enum '{full_name}' value '{value_name}' is missing a number"
                ))
            })?;
            values.push(number);
        }
        values.sort_unstable();
        values.dedup();
        if enum_definitions.insert(full_name.clone(), values).is_some() {
            return Err(GrpcAllowlistError::Descriptor(format!(
                "{context}: duplicate enum type '{full_name}'"
            )));
        }
    }

    for (index, message) in messages.iter().enumerate() {
        let name = message.name.as_deref().ok_or_else(|| {
            GrpcAllowlistError::Descriptor(format!("{context}: message #{index} is missing a name"))
        })?;
        let full_name = if prefix.is_empty() {
            name.to_string()
        } else {
            format!("{prefix}.{name}")
        };
        if message_definitions
            .insert(
                full_name.clone(),
                MessageDefinition {
                    fields: message.fields.clone(),
                },
            )
            .is_some()
        {
            return Err(GrpcAllowlistError::Descriptor(format!(
                "{context}: duplicate message type '{full_name}'"
            )));
        }
        collect_definitions(
            context,
            &full_name,
            &message.nested,
            &message.enums,
            message_definitions,
            enum_definitions,
        )?;
    }
    Ok(())
}

fn collect_reachable_message(
    name: &str,
    message_definitions: &BTreeMap<String, MessageDefinition>,
    enum_definitions: &BTreeMap<String, Vec<i32>>,
    reachable: &mut BTreeMap<String, GrpcMessage>,
    depth: usize,
    max_depth: usize,
) -> Result<(), GrpcAllowlistError> {
    if reachable.contains_key(name) {
        return Ok(());
    }
    let Some(definition) = message_definitions.get(name) else {
        return Ok(());
    };

    let mut fields = Vec::with_capacity(definition.fields.len());
    for field in &definition.fields {
        let field_name = field.name.as_deref().ok_or_else(|| {
            GrpcAllowlistError::Descriptor(format!("message '{name}': field is missing a name"))
        })?;
        let number = field.number.ok_or_else(|| {
            GrpcAllowlistError::Descriptor(format!(
                "message '{name}' field '{field_name}' is missing a number"
            ))
        })?;
        let field_type = field.field_type.ok_or_else(|| {
            GrpcAllowlistError::Descriptor(format!(
                "message '{name}' field '{field_name}' is missing a type"
            ))
        })?;
        let normalized = normalize_field_type(field_type).ok_or_else(|| {
            GrpcAllowlistError::Descriptor(format!(
                "message '{name}' field '{field_name}' has unsupported type {field_type}"
            ))
        })?;
        let type_name = field
            .type_name
            .as_deref()
            .map(|value| value.strip_prefix('.').unwrap_or(value))
            .filter(|value| !value.is_empty())
            .map(str::to_string);

        let mut message_type = None;
        let mut enum_values = None;
        match normalized {
            "message" => {
                let target = type_name.clone().ok_or_else(|| {
                    GrpcAllowlistError::Descriptor(format!(
                        "message '{name}' field '{field_name}' is missing type_name"
                    ))
                })?;
                if depth < max_depth {
                    collect_reachable_message(
                        &target,
                        message_definitions,
                        enum_definitions,
                        reachable,
                        depth + 1,
                        max_depth,
                    )?;
                }
                message_type = Some(target);
            }
            "enum" => {
                if let Some(target) = type_name.as_deref() {
                    enum_values = enum_definitions.get(target).cloned();
                }
            }
            _ => {}
        }

        fields.push(GrpcMessageField {
            name: field_name.to_string(),
            number,
            field_type: normalized.to_string(),
            repeated: field.label == Some(3),
            required: field.label == Some(2),
            message_type,
            enum_values,
        });
    }
    fields.sort_by_key(|field| field.number);

    reachable.insert(
        name.to_string(),
        GrpcMessage {
            message: name.to_string(),
            fields,
        },
    );
    Ok(())
}

fn normalize_field_type(value: u32) -> Option<&'static str> {
    Some(match value {
        1 => "double",
        2 => "float",
        3 => "int64",
        4 => "uint64",
        5 => "int32",
        6 => "fixed64",
        7 => "fixed32",
        8 => "bool",
        // Groups are legacy message fields; wire handling matches messages.
        9 => "string",
        10 => "message",
        11 => "message",
        12 => "bytes",
        13 => "uint32",
        14 => "enum",
        // Signed fixed-width fields use the same wire representation.
        15 => "fixed32",
        16 => "fixed64",
        // Zig-zag fields use the varint wire representation.
        17 => "int32",
        18 => "int64",
        _ => return None,
    })
}

fn method_type_name(
    value: Option<&str>,
    field: &str,
    path: &str,
) -> Result<String, GrpcAllowlistError> {
    let value = value.ok_or_else(|| {
        GrpcAllowlistError::Descriptor(format!("method '{path}' is missing {field}"))
    })?;
    let value = value.strip_prefix('.').unwrap_or(value);
    if value.is_empty() {
        return Err(GrpcAllowlistError::Descriptor(format!(
            "method '{path}' has an empty {field}"
        )));
    }
    validate_type_name(value).map_err(|reason| {
        GrpcAllowlistError::Descriptor(format!("method '{path}' {field} '{value}' {reason}"))
    })?;
    Ok(value.to_string())
}

fn validate_ident(value: &str) -> Result<(), String> {
    let mut characters = value.chars();
    match characters.next() {
        Some(first) if first.is_ascii_alphabetic() || first == '_' => {}
        _ => return Err("must start with an ASCII letter or underscore".to_string()),
    }
    if !characters.all(|character| character.is_ascii_alphanumeric() || character == '_') {
        return Err("may only contain ASCII letters, digits and underscores".to_string());
    }
    Ok(())
}

fn is_grpc_field_type(value: &str) -> bool {
    matches!(
        value,
        "double"
            | "float"
            | "int64"
            | "uint64"
            | "int32"
            | "fixed64"
            | "fixed32"
            | "bool"
            | "string"
            | "bytes"
            | "uint32"
            | "enum"
            | "message"
    )
}

fn validate_type_name(value: &str) -> Result<(), String> {
    if value.starts_with('.') {
        return Err("must not start with '.'".to_string());
    }
    if value.is_empty() {
        return Err("must not be empty".to_string());
    }
    for segment in value.split('.') {
        validate_ident(segment)?;
    }
    Ok(())
}

/// Structural check shared with `waf.grpc.method_allowlist` validation.
fn validate_method_path(value: &str) -> Result<(), String> {
    let Some(rest) = value.strip_prefix('/') else {
        return Err("must start with '/'".to_string());
    };
    let mut parts = rest.split('/');
    let (Some(service), Some(method), None) = (parts.next(), parts.next(), parts.next()) else {
        return Err("must have the form '/package.Service/Method'".to_string());
    };
    validate_type_name(service)?;
    validate_ident(method)
}

// ---------------------------------------------------------------------------
// Binary FileDescriptorSet parsing
// ---------------------------------------------------------------------------

fn parse_binary_descriptor_set(bytes: &[u8]) -> Result<FileDescriptorSet, GrpcAllowlistError> {
    let mut reader = WireReader::new(bytes);
    let mut files = Vec::new();
    while let Some((field, wire)) = reader.read_tag()? {
        if field == 1 && wire == WIRE_LENGTH_DELIMITED {
            files.push(parse_file_descriptor(reader.read_length_delimited()?)?);
        } else {
            reader.skip(wire)?;
        }
    }
    if files.is_empty() {
        return Err(GrpcAllowlistError::Descriptor(
            "binary descriptor set contains no FileDescriptorProto entries".to_string(),
        ));
    }
    Ok(FileDescriptorSet { files })
}

fn parse_file_descriptor(bytes: &[u8]) -> Result<FileDescriptorProto, GrpcAllowlistError> {
    let mut reader = WireReader::new(bytes);
    let mut file = FileDescriptorProto::default();
    while let Some((field, wire)) = reader.read_tag()? {
        match (field, wire) {
            (1, WIRE_LENGTH_DELIMITED) => {
                file.name = Some(reader.read_string()?);
            }
            (2, WIRE_LENGTH_DELIMITED) => {
                file.package = Some(reader.read_string()?);
            }
            (4, WIRE_LENGTH_DELIMITED) => {
                file.messages
                    .push(parse_descriptor_proto(reader.read_length_delimited()?)?);
            }
            (5, WIRE_LENGTH_DELIMITED) => {
                file.enums
                    .push(parse_enum_descriptor(reader.read_length_delimited()?)?);
            }
            (6, WIRE_LENGTH_DELIMITED) => {
                file.services
                    .push(parse_service_descriptor(reader.read_length_delimited()?)?);
            }
            (_, wire) => reader.skip(wire)?,
        }
    }
    Ok(file)
}

fn parse_descriptor_proto(bytes: &[u8]) -> Result<DescriptorProto, GrpcAllowlistError> {
    let mut reader = WireReader::new(bytes);
    let mut message = DescriptorProto::default();
    while let Some((field, wire)) = reader.read_tag()? {
        match (field, wire) {
            (1, WIRE_LENGTH_DELIMITED) => {
                message.name = Some(reader.read_string()?);
            }
            (2, WIRE_LENGTH_DELIMITED) => {
                message
                    .fields
                    .push(parse_field_descriptor(reader.read_length_delimited()?)?);
            }
            (3, WIRE_LENGTH_DELIMITED) => {
                message
                    .nested
                    .push(parse_descriptor_proto(reader.read_length_delimited()?)?);
            }
            (4, WIRE_LENGTH_DELIMITED) => {
                message
                    .enums
                    .push(parse_enum_descriptor(reader.read_length_delimited()?)?);
            }
            (_, wire) => reader.skip(wire)?,
        }
    }
    Ok(message)
}

fn parse_field_descriptor(bytes: &[u8]) -> Result<FieldDescriptorProto, GrpcAllowlistError> {
    let mut reader = WireReader::new(bytes);
    let mut field = FieldDescriptorProto::default();
    while let Some((tag, wire)) = reader.read_tag()? {
        match (tag, wire) {
            (1, WIRE_LENGTH_DELIMITED) => field.name = Some(reader.read_string()?),
            (3, WIRE_VARINT) => {
                field.number = Some(u32::try_from(reader.read_varint()?).map_err(|_| {
                    GrpcAllowlistError::Descriptor(
                        "field number does not fit in 32 bits".to_string(),
                    )
                })?);
            }
            (4, WIRE_VARINT) => {
                field.label = Some(u32::try_from(reader.read_varint()?).map_err(|_| {
                    GrpcAllowlistError::Descriptor(
                        "field label does not fit in 32 bits".to_string(),
                    )
                })?);
            }
            (5, WIRE_VARINT) => {
                field.field_type = Some(u32::try_from(reader.read_varint()?).map_err(|_| {
                    GrpcAllowlistError::Descriptor("field type does not fit in 32 bits".to_string())
                })?);
            }
            (6, WIRE_LENGTH_DELIMITED) => field.type_name = Some(reader.read_string()?),
            (_, wire) => reader.skip(wire)?,
        }
    }
    Ok(field)
}

fn parse_enum_descriptor(bytes: &[u8]) -> Result<EnumDescriptorProto, GrpcAllowlistError> {
    let mut reader = WireReader::new(bytes);
    let mut enumeration = EnumDescriptorProto::default();
    while let Some((tag, wire)) = reader.read_tag()? {
        match (tag, wire) {
            (1, WIRE_LENGTH_DELIMITED) => enumeration.name = Some(reader.read_string()?),
            (2, WIRE_LENGTH_DELIMITED) => enumeration.values.push(parse_enum_value_descriptor(
                reader.read_length_delimited()?,
            )?),
            (_, wire) => reader.skip(wire)?,
        }
    }
    Ok(enumeration)
}

fn parse_enum_value_descriptor(
    bytes: &[u8],
) -> Result<EnumValueDescriptorProto, GrpcAllowlistError> {
    let mut reader = WireReader::new(bytes);
    let mut value = EnumValueDescriptorProto::default();
    while let Some((tag, wire)) = reader.read_tag()? {
        match (tag, wire) {
            (1, WIRE_LENGTH_DELIMITED) => value.name = Some(reader.read_string()?),
            (2, WIRE_VARINT) => value.number = Some(reader.read_varint()? as i32),
            (_, wire) => reader.skip(wire)?,
        }
    }
    Ok(value)
}

fn parse_service_descriptor(bytes: &[u8]) -> Result<ServiceDescriptorProto, GrpcAllowlistError> {
    let mut reader = WireReader::new(bytes);
    let mut service = ServiceDescriptorProto::default();
    while let Some((field, wire)) = reader.read_tag()? {
        match (field, wire) {
            (1, WIRE_LENGTH_DELIMITED) => {
                service.name = Some(reader.read_string()?);
            }
            (2, WIRE_LENGTH_DELIMITED) => {
                service
                    .methods
                    .push(parse_method_descriptor(reader.read_length_delimited()?)?);
            }
            (_, wire) => reader.skip(wire)?,
        }
    }
    Ok(service)
}

fn parse_method_descriptor(bytes: &[u8]) -> Result<MethodDescriptorProto, GrpcAllowlistError> {
    let mut reader = WireReader::new(bytes);
    let mut method = MethodDescriptorProto::default();
    while let Some((field, wire)) = reader.read_tag()? {
        match (field, wire) {
            (1, WIRE_LENGTH_DELIMITED) => {
                method.name = Some(reader.read_string()?);
            }
            (2, WIRE_LENGTH_DELIMITED) => {
                method.input_type = Some(reader.read_string()?);
            }
            (3, WIRE_LENGTH_DELIMITED) => {
                method.output_type = Some(reader.read_string()?);
            }
            (5, WIRE_VARINT) => {
                method.client_streaming = reader.read_varint()? != 0;
            }
            (6, WIRE_VARINT) => {
                method.server_streaming = reader.read_varint()? != 0;
            }
            (_, wire) => reader.skip(wire)?,
        }
    }
    Ok(method)
}

const WIRE_VARINT: u8 = 0;
const WIRE_64BIT: u8 = 1;
const WIRE_LENGTH_DELIMITED: u8 = 2;
const WIRE_32BIT: u8 = 5;

struct WireReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> WireReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }

    fn read_varint(&mut self) -> Result<u64, GrpcAllowlistError> {
        let mut value = 0u64;
        for shift in 0..10 {
            let byte = *self.bytes.get(self.offset).ok_or_else(|| {
                GrpcAllowlistError::Descriptor(format!(
                    "truncated varint at offset {}",
                    self.offset
                ))
            })?;
            self.offset += 1;
            value |= u64::from(byte & 0x7f) << (shift * 7);
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(GrpcAllowlistError::Descriptor(format!(
            "varint longer than 10 bytes at offset {}",
            self.offset
        )))
    }

    fn read_tag(&mut self) -> Result<Option<(u32, u8)>, GrpcAllowlistError> {
        if self.offset >= self.bytes.len() {
            return Ok(None);
        }
        let tag = self.read_varint()?;
        let field = u32::try_from(tag >> 3)
            .ok()
            .filter(|field| *field != 0)
            .ok_or_else(|| {
                GrpcAllowlistError::Descriptor(format!(
                    "invalid field number in tag at offset {}",
                    self.offset
                ))
            })?;
        let wire = (tag & 0x07) as u8;
        Ok(Some((field, wire)))
    }

    fn read_length_delimited(&mut self) -> Result<&'a [u8], GrpcAllowlistError> {
        let length = usize::try_from(self.read_varint()?).map_err(|_| {
            GrpcAllowlistError::Descriptor(format!(
                "length prefix too large at offset {}",
                self.offset
            ))
        })?;
        let end = self.offset.checked_add(length).ok_or_else(|| {
            GrpcAllowlistError::Descriptor(format!(
                "length prefix overflows at offset {}",
                self.offset
            ))
        })?;
        if end > self.bytes.len() {
            return Err(GrpcAllowlistError::Descriptor(format!(
                "truncated length-delimited field at offset {} (need {length} bytes, {} available)",
                self.offset,
                self.remaining()
            )));
        }
        let slice = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(slice)
    }

    fn read_string(&mut self) -> Result<String, GrpcAllowlistError> {
        let bytes = self.read_length_delimited()?;
        std::str::from_utf8(bytes).map(str::to_string).map_err(|_| {
            GrpcAllowlistError::Descriptor(format!(
                "string field is not valid UTF-8 at offset {}",
                self.offset
            ))
        })
    }

    fn skip(&mut self, wire: u8) -> Result<(), GrpcAllowlistError> {
        match wire {
            WIRE_VARINT => {
                self.read_varint()?;
            }
            WIRE_64BIT => {
                self.advance(8)?;
            }
            WIRE_LENGTH_DELIMITED => {
                self.read_length_delimited()?;
            }
            WIRE_32BIT => {
                self.advance(4)?;
            }
            other => {
                return Err(GrpcAllowlistError::Descriptor(format!(
                    "unsupported wire type {other} at offset {}",
                    self.offset
                )));
            }
        }
        Ok(())
    }

    fn advance(&mut self, amount: usize) -> Result<(), GrpcAllowlistError> {
        let end = self.offset.checked_add(amount).ok_or_else(|| {
            GrpcAllowlistError::Descriptor(format!("offset overflow at {}", self.offset))
        })?;
        if end > self.bytes.len() {
            return Err(GrpcAllowlistError::Descriptor(format!(
                "truncated field at offset {}",
                self.offset
            )));
        }
        self.offset = end;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// JSON FileDescriptorSet parsing
// ---------------------------------------------------------------------------

fn parse_json_descriptor_set(bytes: &[u8]) -> Result<FileDescriptorSet, GrpcAllowlistError> {
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|error| {
        GrpcAllowlistError::Descriptor(format!("malformed JSON descriptor set: {error}"))
    })?;
    let object = value
        .as_object()
        .ok_or_else(|| GrpcAllowlistError::Descriptor("descriptor set must be an object".into()))?;
    let files_value = json_array(object.get("file"), "file")?;
    let mut files = Vec::with_capacity(files_value.len());
    for (index, file) in files_value.iter().enumerate() {
        files.push(parse_json_file(file, index)?);
    }
    if files.is_empty() {
        return Err(GrpcAllowlistError::Descriptor(
            "JSON descriptor set contains no files".to_string(),
        ));
    }
    Ok(FileDescriptorSet { files })
}

fn parse_json_file(
    value: &serde_json::Value,
    index: usize,
) -> Result<FileDescriptorProto, GrpcAllowlistError> {
    let context = format!("file #{index}");
    let object = json_object(value, &context)?;
    let mut file = FileDescriptorProto {
        name: json_string(object, &["name"], &context)?,
        package: json_string(object, &["package"], &context)?,
        messages: Vec::new(),
        enums: Vec::new(),
        services: Vec::new(),
    };
    for (message_index, message) in
        json_array_field(object, &["messageType", "message_type"], &context)?
            .iter()
            .enumerate()
    {
        file.messages.push(parse_json_message(
            message,
            &format!("{context}: message #{message_index}"),
        )?);
    }
    for (enum_index, enumeration) in json_array_field(object, &["enumType", "enum_type"], &context)?
        .iter()
        .enumerate()
    {
        file.enums.push(parse_json_enum(
            enumeration,
            &format!("{context}: enum #{enum_index}"),
        )?);
    }
    for (service_index, service) in json_array_field(object, &["service"], &context)?
        .iter()
        .enumerate()
    {
        file.services.push(parse_json_service(
            service,
            &format!("{context}: service #{service_index}"),
        )?);
    }
    Ok(file)
}

fn parse_json_message(
    value: &serde_json::Value,
    context: &str,
) -> Result<DescriptorProto, GrpcAllowlistError> {
    let object = json_object(value, context)?;
    let mut message = DescriptorProto {
        name: json_string(object, &["name"], context)?,
        fields: Vec::new(),
        nested: Vec::new(),
        enums: Vec::new(),
    };
    for (index, field) in json_array_field(object, &["field"], context)?
        .iter()
        .enumerate()
    {
        message.fields.push(parse_json_field(
            field,
            &format!("{context}: field #{index}"),
        )?);
    }
    for (index, nested) in json_array_field(object, &["nestedType", "nested_type"], context)?
        .iter()
        .enumerate()
    {
        message.nested.push(parse_json_message(
            nested,
            &format!("{context}: nested message #{index}"),
        )?);
    }
    for (index, enumeration) in json_array_field(object, &["enumType", "enum_type"], context)?
        .iter()
        .enumerate()
    {
        message.enums.push(parse_json_enum(
            enumeration,
            &format!("{context}: enum #{index}"),
        )?);
    }
    Ok(message)
}

fn parse_json_field(
    value: &serde_json::Value,
    context: &str,
) -> Result<FieldDescriptorProto, GrpcAllowlistError> {
    let object = json_object(value, context)?;
    Ok(FieldDescriptorProto {
        name: json_string(object, &["name"], context)?,
        number: json_u32(object, &["number"], context)?,
        label: json_label(object, &["label"], context)?,
        field_type: json_field_type(object, &["type"], context)?,
        type_name: json_string(object, &["typeName", "type_name"], context)?,
    })
}

fn parse_json_enum(
    value: &serde_json::Value,
    context: &str,
) -> Result<EnumDescriptorProto, GrpcAllowlistError> {
    let object = json_object(value, context)?;
    let mut enumeration = EnumDescriptorProto {
        name: json_string(object, &["name"], context)?,
        values: Vec::new(),
    };
    for (index, value) in json_array_field(object, &["value"], context)?
        .iter()
        .enumerate()
    {
        enumeration.values.push(parse_json_enum_value(
            value,
            &format!("{context}: value #{index}"),
        )?);
    }
    Ok(enumeration)
}

fn parse_json_enum_value(
    value: &serde_json::Value,
    context: &str,
) -> Result<EnumValueDescriptorProto, GrpcAllowlistError> {
    let object = json_object(value, context)?;
    Ok(EnumValueDescriptorProto {
        name: json_string(object, &["name"], context)?,
        number: json_i32(object, &["number"], context)?,
    })
}

fn parse_json_service(
    value: &serde_json::Value,
    context: &str,
) -> Result<ServiceDescriptorProto, GrpcAllowlistError> {
    let object = json_object(value, context)?;
    let mut service = ServiceDescriptorProto {
        name: json_string(object, &["name"], context)?,
        methods: Vec::new(),
    };
    for (index, method) in json_array_field(object, &["method"], context)?
        .iter()
        .enumerate()
    {
        service.methods.push(parse_json_method(
            method,
            &format!("{context}: method #{index}"),
        )?);
    }
    Ok(service)
}

fn parse_json_method(
    value: &serde_json::Value,
    context: &str,
) -> Result<MethodDescriptorProto, GrpcAllowlistError> {
    let object = json_object(value, context)?;
    Ok(MethodDescriptorProto {
        name: json_string(object, &["name"], context)?,
        input_type: json_string(object, &["inputType", "input_type"], context)?,
        output_type: json_string(object, &["outputType", "output_type"], context)?,
        client_streaming: json_bool(object, &["clientStreaming", "client_streaming"], context)?,
        server_streaming: json_bool(object, &["serverStreaming", "server_streaming"], context)?,
    })
}

fn json_object<'a>(
    value: &'a serde_json::Value,
    context: &str,
) -> Result<&'a serde_json::Map<String, serde_json::Value>, GrpcAllowlistError> {
    value
        .as_object()
        .ok_or_else(|| GrpcAllowlistError::Descriptor(format!("{context} must be an object")))
}

fn json_lookup<'a>(
    object: &'a serde_json::Map<String, serde_json::Value>,
    names: &[&str],
    context: &str,
) -> Result<Option<&'a serde_json::Value>, GrpcAllowlistError> {
    let mut found: Option<&serde_json::Value> = None;
    for name in names {
        if let Some(value) = object.get(*name) {
            if found.is_some() {
                return Err(GrpcAllowlistError::Descriptor(format!(
                    "{context}: fields {names:?} are aliases and may not both be set"
                )));
            }
            found = Some(value);
        }
    }
    Ok(found)
}

fn json_string(
    object: &serde_json::Map<String, serde_json::Value>,
    names: &[&str],
    context: &str,
) -> Result<Option<String>, GrpcAllowlistError> {
    match json_lookup(object, names, context)? {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(GrpcAllowlistError::Descriptor(format!(
            "{context}: field '{}' must be a string",
            names[0]
        ))),
    }
}

fn json_bool(
    object: &serde_json::Map<String, serde_json::Value>,
    names: &[&str],
    context: &str,
) -> Result<bool, GrpcAllowlistError> {
    match json_lookup(object, names, context)? {
        None | Some(serde_json::Value::Null) => Ok(false),
        Some(serde_json::Value::Bool(value)) => Ok(*value),
        Some(_) => Err(GrpcAllowlistError::Descriptor(format!(
            "{context}: field '{}' must be a boolean",
            names[0]
        ))),
    }
}

fn json_u32(
    object: &serde_json::Map<String, serde_json::Value>,
    names: &[&str],
    context: &str,
) -> Result<Option<u32>, GrpcAllowlistError> {
    match json_lookup(object, names, context)? {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::Number(value)) => value
            .as_u64()
            .and_then(|value| u32::try_from(value).ok())
            .map(Some)
            .ok_or_else(|| {
                GrpcAllowlistError::Descriptor(format!(
                    "{context}: field '{}' must be a non-negative 32-bit integer",
                    names[0]
                ))
            }),
        Some(_) => Err(GrpcAllowlistError::Descriptor(format!(
            "{context}: field '{}' must be an integer",
            names[0]
        ))),
    }
}

fn json_i32(
    object: &serde_json::Map<String, serde_json::Value>,
    names: &[&str],
    context: &str,
) -> Result<Option<i32>, GrpcAllowlistError> {
    match json_lookup(object, names, context)? {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::Number(value)) => value
            .as_i64()
            .and_then(|value| i32::try_from(value).ok())
            .map(Some)
            .ok_or_else(|| {
                GrpcAllowlistError::Descriptor(format!(
                    "{context}: field '{}' must be a 32-bit integer",
                    names[0]
                ))
            }),
        Some(_) => Err(GrpcAllowlistError::Descriptor(format!(
            "{context}: field '{}' must be an integer",
            names[0]
        ))),
    }
}

fn json_label(
    object: &serde_json::Map<String, serde_json::Value>,
    names: &[&str],
    context: &str,
) -> Result<Option<u32>, GrpcAllowlistError> {
    match json_lookup(object, names, context)? {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::Number(value)) => value
            .as_u64()
            .and_then(|value| u32::try_from(value).ok())
            .map(Some)
            .ok_or_else(|| {
                GrpcAllowlistError::Descriptor(format!(
                    "{context}: field '{}' must be a label number",
                    names[0]
                ))
            }),
        Some(serde_json::Value::String(value)) => {
            let upper = value.to_ascii_uppercase();
            let normalised = upper.strip_prefix("LABEL_").unwrap_or(&upper);
            let label = match normalised {
                "OPTIONAL" => 1,
                "REQUIRED" => 2,
                "REPEATED" => 3,
                other => {
                    return Err(GrpcAllowlistError::Descriptor(format!(
                        "{context}: field '{}' has unknown label '{other}'",
                        names[0]
                    )))
                }
            };
            Ok(Some(label))
        }
        Some(_) => Err(GrpcAllowlistError::Descriptor(format!(
            "{context}: field '{}' must be a label number or name",
            names[0]
        ))),
    }
}

fn json_field_type(
    object: &serde_json::Map<String, serde_json::Value>,
    names: &[&str],
    context: &str,
) -> Result<Option<u32>, GrpcAllowlistError> {
    match json_lookup(object, names, context)? {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::Number(value)) => value
            .as_u64()
            .and_then(|value| u32::try_from(value).ok())
            .map(Some)
            .ok_or_else(|| {
                GrpcAllowlistError::Descriptor(format!(
                    "{context}: field '{}' must be a type number",
                    names[0]
                ))
            }),
        Some(serde_json::Value::String(value)) => {
            let upper = value.to_ascii_uppercase();
            let normalised = upper.strip_prefix("TYPE_").unwrap_or(&upper);
            let field_type = match normalised {
                "DOUBLE" => 1,
                "FLOAT" => 2,
                "INT64" => 3,
                "UINT64" => 4,
                "INT32" => 5,
                "FIXED64" => 6,
                "FIXED32" => 7,
                "BOOL" => 8,
                "STRING" => 9,
                "GROUP" => 10,
                "MESSAGE" => 11,
                "BYTES" => 12,
                "UINT32" => 13,
                "ENUM" => 14,
                "SFIXED32" => 15,
                "SFIXED64" => 16,
                "SINT32" => 17,
                "SINT64" => 18,
                other => {
                    return Err(GrpcAllowlistError::Descriptor(format!(
                        "{context}: field '{}' has unknown type '{other}'",
                        names[0]
                    )))
                }
            };
            Ok(Some(field_type))
        }
        Some(_) => Err(GrpcAllowlistError::Descriptor(format!(
            "{context}: field '{}' must be a type number or name",
            names[0]
        ))),
    }
}

fn json_array_field<'a>(
    object: &'a serde_json::Map<String, serde_json::Value>,
    names: &[&str],
    context: &str,
) -> Result<&'a [serde_json::Value], GrpcAllowlistError> {
    match json_lookup(object, names, context)? {
        None | Some(serde_json::Value::Null) => Ok(&[]),
        Some(value) => json_array(Some(value), names[0]),
    }
}

fn json_array<'a>(
    value: Option<&'a serde_json::Value>,
    field: &str,
) -> Result<&'a [serde_json::Value], GrpcAllowlistError> {
    match value {
        None => Ok(&[]),
        Some(serde_json::Value::Array(values)) => Ok(values),
        Some(_) => Err(GrpcAllowlistError::Descriptor(format!(
            "field '{field}' must be an array"
        ))),
    }
}

// ---------------------------------------------------------------------------
// Optional per-method override config
// ---------------------------------------------------------------------------

/// Optional TOML override file.
///
/// ```toml
/// max_message_bytes = 4194304
/// unknown_method_action = "block"
///
/// [methods."/acme.billing.v1.Billing/Charge"]
/// max_message_bytes = 8388608
/// ```
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct OverrideDocument {
    #[serde(default)]
    max_message_bytes: Option<usize>,
    #[serde(default)]
    unknown_method_action: Option<String>,
    #[serde(default)]
    methods: BTreeMap<String, MethodOverrideDocument>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MethodOverrideDocument {
    max_message_bytes: usize,
}

/// Parses an override document and applies it on top of `base`.
pub fn apply_overrides_toml(
    text: &str,
    base: AllowlistOptions,
) -> Result<AllowlistOptions, GrpcAllowlistError> {
    let document: OverrideDocument = toml::from_str(text).map_err(|error| {
        GrpcAllowlistError::InvalidOverrides(format!("malformed TOML: {error}"))
    })?;
    let mut options = base;
    if let Some(limit) = document.max_message_bytes {
        options.max_message_bytes = limit;
    }
    if let Some(action) = document.unknown_method_action {
        options.unknown_method_action = action;
    }
    for (path, method) in document.methods {
        options
            .method_overrides
            .insert(path, method.max_message_bytes);
    }
    options.validate()?;
    Ok(options)
}

/// Loads an override file and applies it on top of `base`.
pub fn load_overrides(
    path: impl AsRef<Path>,
    base: AllowlistOptions,
) -> Result<AllowlistOptions, GrpcAllowlistError> {
    let path = path.as_ref();
    let text = fs::read_to_string(path).map_err(|error| GrpcAllowlistError::io(path, error))?;
    apply_overrides_toml(&text, base).map_err(|error| match error {
        GrpcAllowlistError::InvalidOverrides(message) => {
            GrpcAllowlistError::InvalidOverrides(format!("{}: {message}", path.display()))
        }
        other => other,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn put_varint(mut value: u64, out: &mut Vec<u8>) {
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if value == 0 {
                return;
            }
        }
    }

    fn put_tag(field: u32, wire: u8, out: &mut Vec<u8>) {
        put_varint((u64::from(field) << 3) | u64::from(wire), out);
    }

    fn put_bytes(field: u32, bytes: &[u8], out: &mut Vec<u8>) {
        put_tag(field, WIRE_LENGTH_DELIMITED, out);
        put_varint(bytes.len() as u64, out);
        out.extend_from_slice(bytes);
    }

    fn put_string(field: u32, value: &str, out: &mut Vec<u8>) {
        put_bytes(field, value.as_bytes(), out);
    }

    fn put_bool(field: u32, value: bool, out: &mut Vec<u8>) {
        put_tag(field, WIRE_VARINT, out);
        put_varint(u64::from(value), out);
    }

    fn message(name: &str, nested: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        put_string(1, name, &mut out);
        for child in nested {
            put_bytes(3, child, &mut out);
        }
        out
    }

    fn field_descriptor(
        name: &str,
        number: u32,
        label: u32,
        field_type: u32,
        type_name: Option<&str>,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        put_string(1, name, &mut out);
        put_tag(3, WIRE_VARINT, &mut out);
        put_varint(u64::from(number), &mut out);
        put_tag(4, WIRE_VARINT, &mut out);
        put_varint(u64::from(label), &mut out);
        put_tag(5, WIRE_VARINT, &mut out);
        put_varint(u64::from(field_type), &mut out);
        if let Some(type_name) = type_name {
            put_string(6, type_name, &mut out);
        }
        out
    }

    fn enum_descriptor(name: &str, values: &[(&str, i32)]) -> Vec<u8> {
        let mut out = Vec::new();
        put_string(1, name, &mut out);
        for (value_name, number) in values {
            let mut value = Vec::new();
            put_string(1, value_name, &mut value);
            put_tag(2, WIRE_VARINT, &mut value);
            put_varint(*number as i64 as u64, &mut value);
            put_bytes(2, &value, &mut out);
        }
        out
    }

    fn message_with_fields(
        name: &str,
        fields: &[Vec<u8>],
        nested: &[Vec<u8>],
        enums: &[Vec<u8>],
    ) -> Vec<u8> {
        let mut out = Vec::new();
        put_string(1, name, &mut out);
        for field in fields {
            put_bytes(2, field, &mut out);
        }
        for child in nested {
            put_bytes(3, child, &mut out);
        }
        for enumeration in enums {
            put_bytes(4, enumeration, &mut out);
        }
        out
    }

    fn method(
        name: &str,
        input: &str,
        output: &str,
        client_streaming: bool,
        server_streaming: bool,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        put_string(1, name, &mut out);
        put_string(2, input, &mut out);
        put_string(3, output, &mut out);
        put_bool(5, client_streaming, &mut out);
        put_bool(6, server_streaming, &mut out);
        out
    }

    fn service(name: &str, methods: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        put_string(1, name, &mut out);
        for entry in methods {
            put_bytes(2, entry, &mut out);
        }
        out
    }

    fn file(name: &str, package: &str, messages: &[Vec<u8>], services: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        put_string(1, name, &mut out);
        if !package.is_empty() {
            put_string(2, package, &mut out);
        }
        for message in messages {
            put_bytes(4, message, &mut out);
        }
        for service in services {
            put_bytes(6, service, &mut out);
        }
        out
    }

    fn descriptor_set(files: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        for file in files {
            put_bytes(1, file, &mut out);
        }
        out
    }

    fn fixture_methods() -> Vec<Vec<u8>> {
        vec![
            method(
                "Watch",
                ".acme.billing.v1.Request",
                ".acme.billing.v1.Response",
                false,
                true,
            ),
            method(
                "Charge",
                ".acme.billing.v1.Request",
                ".acme.billing.v1.Response",
                false,
                false,
            ),
            method(
                "Upload",
                ".acme.billing.v1.Request.Item",
                ".acme.billing.v1.Response",
                true,
                false,
            ),
        ]
    }

    fn fixture_descriptor() -> Vec<u8> {
        descriptor_set(&[file(
            "acme/billing.proto",
            "acme.billing.v1",
            &[
                message("Request", &[message("Item", &[])]),
                message("Response", &[]),
            ],
            &[service("Billing", &fixture_methods())],
        )])
    }

    fn fixture_descriptor_json() -> String {
        serde_json::json!({
            "file": [{
                "name": "acme/billing.proto",
                "package": "acme.billing.v1",
                "messageType": [
                    {"name": "Request", "nestedType": [{"name": "Item"}]},
                    {"name": "Response"}
                ],
                "service": [{
                    "name": "Billing",
                    "method": [
                        {"name": "Watch",
                         "inputType": ".acme.billing.v1.Request",
                         "outputType": ".acme.billing.v1.Response",
                         "serverStreaming": true},
                        {"name": "Charge",
                         "inputType": ".acme.billing.v1.Request",
                         "outputType": ".acme.billing.v1.Response"},
                        {"name": "Upload",
                         "inputType": ".acme.billing.v1.Request.Item",
                         "outputType": ".acme.billing.v1.Response",
                         "clientStreaming": true}
                    ]
                }]
            }]
        })
        .to_string()
    }

    fn expected_methods() -> Vec<GrpcAllowlistMethod> {
        vec![
            GrpcAllowlistMethod {
                path: "/acme.billing.v1.Billing/Charge".to_string(),
                client_streaming: false,
                server_streaming: false,
                input: "acme.billing.v1.Request".to_string(),
                output: "acme.billing.v1.Response".to_string(),
                max_message_bytes: DEFAULT_MAX_MESSAGE_BYTES,
            },
            GrpcAllowlistMethod {
                path: "/acme.billing.v1.Billing/Upload".to_string(),
                client_streaming: true,
                server_streaming: false,
                input: "acme.billing.v1.Request.Item".to_string(),
                output: "acme.billing.v1.Response".to_string(),
                max_message_bytes: DEFAULT_MAX_MESSAGE_BYTES,
            },
            GrpcAllowlistMethod {
                path: "/acme.billing.v1.Billing/Watch".to_string(),
                client_streaming: false,
                server_streaming: true,
                input: "acme.billing.v1.Request".to_string(),
                output: "acme.billing.v1.Response".to_string(),
                max_message_bytes: DEFAULT_MAX_MESSAGE_BYTES,
            },
        ]
    }

    #[test]
    fn binary_fixture_produces_expected_allowlist() {
        let descriptor = fixture_descriptor();
        let allowlist = build_allowlist(
            &descriptor,
            DescriptorFormat::Binary,
            &AllowlistOptions::default(),
        )
        .expect("fixture must parse");

        assert_eq!(allowlist.ir_version, ALLOWLIST_IR_VERSION);
        assert_eq!(allowlist.source.kind, "protobuf");
        assert_eq!(
            allowlist.source.sha256,
            hex::encode(Sha256::digest(&descriptor))
        );
        assert_eq!(allowlist.unknown_method_action, "block");
        assert_eq!(allowlist.methods, expected_methods());

        assert!(allowlist.allows("/acme.billing.v1.Billing/Charge"));
        assert!(!allowlist.allows("/acme.billing.v1.Billing/Delete"));
        assert_eq!(
            allowlist.max_message_bytes_for("/acme.billing.v1.Billing/Watch"),
            Some(DEFAULT_MAX_MESSAGE_BYTES)
        );
    }

    #[test]
    fn request_field_metadata_is_generated() {
        let request = message_with_fields(
            "Request",
            &[
                field_descriptor("state", 1, 1, 14, Some(".acme.billing.v1.Request.State")),
                field_descriptor("payload", 2, 3, 12, None),
                field_descriptor("child", 3, 1, 11, Some(".acme.billing.v1.Request.Child")),
            ],
            &[message_with_fields(
                "Child",
                &[field_descriptor("name", 1, 1, 9, None)],
                &[],
                &[],
            )],
            &[enum_descriptor("State", &[("UNKNOWN", 0), ("READY", 2)])],
        );
        let descriptor = descriptor_set(&[file(
            "acme/billing.proto",
            "acme.billing.v1",
            &[request, message_with_fields("Response", &[], &[], &[])],
            &[service(
                "Billing",
                &[method(
                    "Charge",
                    ".acme.billing.v1.Request",
                    ".acme.billing.v1.Response",
                    false,
                    false,
                )],
            )],
        )]);
        let allowlist = build_allowlist(
            &descriptor,
            DescriptorFormat::Binary,
            &AllowlistOptions::default(),
        )
        .expect("field metadata fixture must parse");

        assert_eq!(allowlist.ir_version, ALLOWLIST_IR_VERSION);
        let request = allowlist
            .message_for("acme.billing.v1.Request")
            .expect("request metadata");
        assert_eq!(
            request
                .fields
                .iter()
                .map(|field| (field.name.as_str(), field.number, field.field_type.as_str()))
                .collect::<Vec<_>>(),
            vec![
                ("state", 1, "enum"),
                ("payload", 2, "bytes"),
                ("child", 3, "message"),
            ]
        );
        assert_eq!(request.fields[0].enum_values, Some(vec![0, 2]));
        assert!(request.fields[1].repeated);
        assert_eq!(
            request.fields[2].message_type.as_deref(),
            Some("acme.billing.v1.Request.Child")
        );
        let child = allowlist
            .message_for("acme.billing.v1.Request.Child")
            .expect("nested request metadata");
        assert_eq!(child.fields[0].field_type, "string");

        let first = allowlist.to_canonical_json().unwrap();
        let second = build_allowlist(
            &descriptor,
            DescriptorFormat::Binary,
            &AllowlistOptions::default(),
        )
        .unwrap()
        .to_canonical_json()
        .unwrap();
        assert_eq!(first, second);
        assert_eq!(parse_allowlist(first.as_bytes()).unwrap(), allowlist);
    }

    #[test]
    fn json_fixture_produces_the_same_methods() {
        let json = fixture_descriptor_json();
        let allowlist = build_allowlist(
            json.as_bytes(),
            DescriptorFormat::Json,
            &AllowlistOptions::default(),
        )
        .expect("JSON fixture must parse");

        assert_eq!(allowlist.methods, expected_methods());
        assert_eq!(
            allowlist.source.sha256,
            hex::encode(Sha256::digest(json.as_bytes()))
        );

        let auto = build_allowlist(
            json.as_bytes(),
            DescriptorFormat::Auto,
            &AllowlistOptions::default(),
        )
        .expect("auto format must detect JSON");
        assert_eq!(auto, allowlist);
    }

    #[test]
    fn snake_case_json_fields_are_accepted() {
        let json = fixture_descriptor_json()
            .replace("messageType", "message_type")
            .replace("nestedType", "nested_type")
            .replace("inputType", "input_type")
            .replace("outputType", "output_type")
            .replace("clientStreaming", "client_streaming")
            .replace("serverStreaming", "server_streaming");
        let allowlist = build_allowlist(
            json.as_bytes(),
            DescriptorFormat::Json,
            &AllowlistOptions::default(),
        )
        .expect("snake_case JSON must parse");
        assert_eq!(allowlist.methods, expected_methods());
    }

    #[test]
    fn output_is_byte_identical_across_runs() {
        let descriptor = fixture_descriptor();
        let first = build_allowlist(
            &descriptor,
            DescriptorFormat::Auto,
            &AllowlistOptions::default(),
        )
        .expect("first run");
        let second = build_allowlist(
            &descriptor,
            DescriptorFormat::Auto,
            &AllowlistOptions::default(),
        )
        .expect("second run");

        let first_json = first.to_canonical_json().expect("serialize");
        let second_json = second.to_canonical_json().expect("serialize");
        assert_eq!(first_json.as_bytes(), second_json.as_bytes());
        assert!(first_json.ends_with("}\n"));

        let parsed = parse_allowlist(first_json.as_bytes()).expect("round-trip");
        assert_eq!(parsed, first);
    }

    #[test]
    fn canonical_order_is_independent_of_descriptor_order() {
        let forward = descriptor_set(&[file(
            "acme/billing.proto",
            "acme.billing.v1",
            &[message("Request", &[]), message("Response", &[])],
            &[service(
                "Billing",
                &[
                    method(
                        "Charge",
                        ".acme.billing.v1.Request",
                        ".acme.billing.v1.Response",
                        false,
                        false,
                    ),
                    method(
                        "Refund",
                        ".acme.billing.v1.Request",
                        ".acme.billing.v1.Response",
                        false,
                        false,
                    ),
                ],
            )],
        )]);
        let reverse = descriptor_set(&[file(
            "acme/billing.proto",
            "acme.billing.v1",
            &[message("Request", &[]), message("Response", &[])],
            &[service(
                "Billing",
                &[
                    method(
                        "Refund",
                        ".acme.billing.v1.Request",
                        ".acme.billing.v1.Response",
                        false,
                        false,
                    ),
                    method(
                        "Charge",
                        ".acme.billing.v1.Request",
                        ".acme.billing.v1.Response",
                        false,
                        false,
                    ),
                ],
            )],
        )]);

        let forward = build_allowlist(
            &forward,
            DescriptorFormat::Auto,
            &AllowlistOptions::default(),
        )
        .expect("forward");
        let reverse = build_allowlist(
            &reverse,
            DescriptorFormat::Auto,
            &AllowlistOptions::default(),
        )
        .expect("reverse");
        assert_eq!(forward.methods, reverse.methods);
        assert_eq!(
            forward.methods[0].path,
            "/acme.billing.v1.Billing/Charge".to_string()
        );
    }

    #[test]
    fn size_overrides_are_applied_per_method() {
        let descriptor = fixture_descriptor();
        let options = AllowlistOptions {
            max_message_bytes: 1024,
            method_overrides: BTreeMap::from([(
                "/acme.billing.v1.Billing/Charge".to_string(),
                8388608usize,
            )]),
            unknown_method_action: "allow".to_string(),
        };
        let allowlist = build_allowlist(&descriptor, DescriptorFormat::Auto, &options)
            .expect("overrides must apply");

        assert_eq!(
            allowlist.max_message_bytes_for("/acme.billing.v1.Billing/Charge"),
            Some(8_388_608)
        );
        assert_eq!(
            allowlist.max_message_bytes_for("/acme.billing.v1.Billing/Watch"),
            Some(1024)
        );
        assert_eq!(allowlist.unknown_method_action, "allow");
    }

    #[test]
    fn override_for_unknown_method_fails() {
        let descriptor = fixture_descriptor();
        let options = AllowlistOptions {
            method_overrides: BTreeMap::from([(
                "/acme.billing.v1.Billing/Missing".to_string(),
                1024usize,
            )]),
            ..AllowlistOptions::default()
        };
        let error = build_allowlist(&descriptor, DescriptorFormat::Auto, &options)
            .expect_err("unknown override must fail");
        let message = error.to_string();
        assert!(message.contains("does not match any method"), "{message}");
    }

    #[test]
    fn override_toml_parses_and_rejects_typos() {
        let options = apply_overrides_toml(
            r#"
max_message_bytes = 2048
unknown_method_action = "allow"

[methods."/acme.billing.v1.Billing/Charge"]
max_message_bytes = 4096
"#,
            AllowlistOptions::default(),
        )
        .expect("valid override TOML");
        assert_eq!(options.max_message_bytes, 2048);
        assert_eq!(options.unknown_method_action, "allow");
        assert_eq!(
            options
                .method_overrides
                .get("/acme.billing.v1.Billing/Charge"),
            Some(&4096)
        );

        let error = apply_overrides_toml("surprise = true", AllowlistOptions::default())
            .expect_err("unknown keys must fail");
        assert!(error.to_string().contains("malformed TOML"), "{error}");
    }

    #[test]
    fn duplicate_methods_fail() {
        let descriptor = descriptor_set(&[file(
            "acme/billing.proto",
            "acme.billing.v1",
            &[message("Request", &[]), message("Response", &[])],
            &[service(
                "Billing",
                &[
                    method(
                        "Charge",
                        ".acme.billing.v1.Request",
                        ".acme.billing.v1.Response",
                        false,
                        false,
                    ),
                    method(
                        "Charge",
                        ".acme.billing.v1.Request",
                        ".acme.billing.v1.Response",
                        false,
                        false,
                    ),
                ],
            )],
        )]);
        let error = build_allowlist(
            &descriptor,
            DescriptorFormat::Auto,
            &AllowlistOptions::default(),
        )
        .expect_err("duplicate methods must fail");
        assert!(
            error.to_string().contains("duplicate method path"),
            "{error}"
        );
    }

    #[test]
    fn malformed_descriptors_fail_cleanly() {
        let options = AllowlistOptions::default();

        let empty = build_allowlist(&[], DescriptorFormat::Auto, &options)
            .expect_err("empty descriptor must fail");
        assert!(empty.to_string().contains("empty"), "{empty}");

        // Length prefix claims more bytes than remain.
        let mut truncated = vec![0x0a, 0x05, 0x01, 0x02];
        let error = build_allowlist(&truncated, DescriptorFormat::Binary, &options)
            .expect_err("truncated field must fail");
        assert!(error.to_string().contains("truncated"), "{error}");

        // Wire type 7 is not a valid protobuf wire type.
        truncated = vec![0x0f];
        let error = build_allowlist(&truncated, DescriptorFormat::Binary, &options)
            .expect_err("invalid wire type must fail");
        assert!(
            error.to_string().contains("unsupported wire type"),
            "{error}"
        );

        let error = build_allowlist(b"{not json", DescriptorFormat::Json, &options)
            .expect_err("malformed JSON must fail");
        assert!(error.to_string().contains("malformed JSON"), "{error}");
    }

    #[test]
    fn missing_fields_fail_with_context() {
        let options = AllowlistOptions::default();

        // Service without a name.
        let mut unnamed_service = Vec::new();
        put_bytes(
            2,
            &method("Charge", ".pkg.Request", ".pkg.Response", false, false),
            &mut unnamed_service,
        );
        let descriptor = descriptor_set(&[file(
            "acme/billing.proto",
            "acme.billing.v1",
            &[message("Request", &[]), message("Response", &[])],
            &[unnamed_service],
        )]);
        let error = build_allowlist(&descriptor, DescriptorFormat::Auto, &options)
            .expect_err("unnamed service must fail");
        assert!(error.to_string().contains("missing a name"), "{error}");

        // Method without an input type.
        let mut missing_input = Vec::new();
        put_string(1, "Charge", &mut missing_input);
        put_string(3, ".acme.billing.v1.Response", &mut missing_input);
        let descriptor = descriptor_set(&[file(
            "acme/billing.proto",
            "acme.billing.v1",
            &[message("Response", &[])],
            &[service("Billing", &[missing_input])],
        )]);
        let error = build_allowlist(&descriptor, DescriptorFormat::Auto, &options)
            .expect_err("missing input must fail");
        assert!(error.to_string().contains("missing input_type"), "{error}");

        // Method with an empty name.
        let mut empty_name = Vec::new();
        put_string(1, "", &mut empty_name);
        put_string(2, ".acme.billing.v1.Request", &mut empty_name);
        put_string(3, ".acme.billing.v1.Response", &mut empty_name);
        let descriptor = descriptor_set(&[file(
            "acme/billing.proto",
            "acme.billing.v1",
            &[message("Request", &[]), message("Response", &[])],
            &[service("Billing", &[empty_name])],
        )]);
        let error = build_allowlist(&descriptor, DescriptorFormat::Auto, &options)
            .expect_err("empty method name must fail");
        assert!(error.to_string().contains("empty name"), "{error}");
    }

    #[test]
    fn unresolved_types_fail() {
        let descriptor = descriptor_set(&[file(
            "acme/billing.proto",
            "acme.billing.v1",
            &[message("Response", &[])],
            &[service(
                "Billing",
                &[method(
                    "Charge",
                    ".acme.billing.v1.Nope",
                    ".acme.billing.v1.Response",
                    false,
                    false,
                )],
            )],
        )]);
        let error = build_allowlist(
            &descriptor,
            DescriptorFormat::Auto,
            &AllowlistOptions::default(),
        )
        .expect_err("unresolved type must fail");
        let message = error.to_string();
        assert!(message.contains("is not defined"), "{message}");
        assert!(message.contains("--include_imports"), "{message}");
    }

    #[test]
    fn descriptor_without_services_fails() {
        let descriptor = descriptor_set(&[file(
            "acme/empty.proto",
            "acme.empty",
            &[message("Request", &[])],
            &[],
        )]);
        let error = build_allowlist(
            &descriptor,
            DescriptorFormat::Auto,
            &AllowlistOptions::default(),
        )
        .expect_err("no services must fail");
        assert!(error.to_string().contains("no services"), "{error}");
    }

    fn valid_json() -> String {
        build_allowlist(
            &fixture_descriptor(),
            DescriptorFormat::Auto,
            &AllowlistOptions::default(),
        )
        .expect("fixture")
        .to_canonical_json()
        .expect("serialize")
    }

    #[test]
    fn loader_rejects_invalid_documents() {
        let valid = valid_json();
        parse_allowlist(valid.as_bytes()).expect("generated artifact must load");

        let mut legacy: serde_json::Value = serde_json::from_str(&valid).unwrap();
        legacy["ir_version"] = serde_json::json!(1);
        legacy.as_object_mut().unwrap().remove("messages");
        let legacy = parse_allowlist(serde_json::to_string(&legacy).unwrap().as_bytes())
            .expect("version 1 artifacts must still load");
        assert!(legacy.messages.is_empty());

        let cases: Vec<(serde_json::Value, &str)> = vec![
            (
                {
                    let mut value: serde_json::Value = serde_json::from_str(&valid).unwrap();
                    value["ir_version"] = serde_json::json!(3);
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
                    value["source"]["kind"] = serde_json::json!("openapi");
                    value
                },
                "source.kind",
            ),
            (
                {
                    let mut value: serde_json::Value = serde_json::from_str(&valid).unwrap();
                    value["unknown_method_action"] = serde_json::json!("deny");
                    value
                },
                "unknown_method_action",
            ),
            (
                {
                    let mut value: serde_json::Value = serde_json::from_str(&valid).unwrap();
                    value["methods"] = serde_json::json!([]);
                    value
                },
                "methods is empty",
            ),
            (
                {
                    let mut value: serde_json::Value = serde_json::from_str(&valid).unwrap();
                    value["methods"][0]["max_message_bytes"] = serde_json::json!(0);
                    value
                },
                "greater than zero",
            ),
            (
                {
                    let mut value: serde_json::Value = serde_json::from_str(&valid).unwrap();
                    value["methods"][1] = value["methods"][0].clone();
                    value
                },
                "duplicate method path",
            ),
            (
                {
                    let mut value: serde_json::Value = serde_json::from_str(&valid).unwrap();
                    value["methods"][0]["input"] = serde_json::json!(".acme.billing.v1.Request");
                    value
                },
                "must not start with '.'",
            ),
            (
                {
                    let mut value: serde_json::Value = serde_json::from_str(&valid).unwrap();
                    value["methods"][0]["path"] =
                        serde_json::json!("acme.billing.v1.Billing/Charge");
                    value
                },
                "must start with '/'",
            ),
        ];

        for (value, expected) in cases {
            let text = serde_json::to_string(&value).unwrap();
            let error = parse_allowlist(text.as_bytes()).expect_err(expected);
            assert!(
                error.to_string().contains(expected),
                "expected '{expected}', got '{error}'"
            );
        }

        let error = parse_allowlist(b"{").expect_err("malformed JSON must fail");
        assert!(error.to_string().contains("malformed JSON"), "{error}");
    }

    #[test]
    fn load_allowlist_reads_a_file_and_reports_io_errors() {
        let path = std::env::temp_dir().join(format!(
            "grpc-allowlist-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::write(&path, valid_json()).expect("write artifact");
        let loaded = load_allowlist(&path).expect("load artifact");
        assert_eq!(loaded.methods, expected_methods());
        fs::remove_file(&path).expect("cleanup");

        let missing = path.with_extension("absent");
        let error = load_allowlist(&missing).expect_err("missing file must fail");
        assert!(error.to_string().contains("failed to access"), "{error}");
    }

    #[test]
    fn generation_from_a_file_detects_the_format() {
        let path = std::env::temp_dir().join(format!(
            "grpc-descriptor-{}-{}.binpb",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::write(&path, fixture_descriptor()).expect("write descriptor");
        let allowlist = generate_from_descriptor_path(&path, &AllowlistOptions::default())
            .expect("generate from file");
        assert_eq!(allowlist.methods, expected_methods());
        fs::remove_file(&path).expect("cleanup");
    }
}
