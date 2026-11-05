//! Protocol-aware gRPC inspection.
//!
//! gRPC request bodies are length-prefixed protobuf frames. Passing those
//! bytes to CRS body rules is both meaningless (regular expressions cannot
//! understand protobuf) and expensive (byte-linear scans of megabytes). This
//! module therefore validates the gRPC envelope *before* the rest of the WAF
//! rule chain runs, and the engine withholds the protobuf body from CRS body
//! rules once the envelope is accepted.
//!
//! What is checked:
//!
//! * `content-type` (`application/grpc`, `application/grpc+proto`,
//!   `application/grpc+json`, `application/grpc-web*`),
//! * the HTTP/2 `:path` method (`/package.Service/Method`) against
//!   `waf.grpc.method_allowlist` and the generated
//!   `waf.grpc.allowlist_file` artifact,
//! * the 5-byte frame prefix (compressed flag `0`/`1`, 4-byte big-endian
//!   length), frame count, per-message size and truncation,
//! * `grpc-encoding` (`identity` only),
//! * base64 syntax of binary `-bin` metadata, which is excluded from text
//!   (regex) scanning,
//! * when the artifact carries descriptor metadata, the request message is
//!   decoded and each field is checked against `[waf.grpc]` field limits,
//!   unknown-field policy, enum declarations and string sanity rules.
//!
//! Field-level inspection only uses the descriptor metadata in the artifact.
//! Methods without metadata keep envelope-only behaviour, and the raw
//! protobuf body is still never handed to CRS.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use base64::Engine as _;
use hyper::header::HeaderValue;
use hyper::HeaderMap;
use tracing::debug;

use crate::config::WafGrpcConfig;
use crate::metrics::Metrics;
use crate::waf::coraza_payload;
use crate::waf::grpc_allowlist::{self, GrpcAllowlist, GrpcAllowlistError, GrpcMessage};
use crate::waf::protobuf::{self, CollectedField, DecodeLimits};
use crate::waf::{Decision, RequestContext, WafRule};

/// Bytes in a gRPC message prefix: 1 flag byte + 4 length bytes.
pub const FRAME_PREFIX_LEN: usize = 5;

/// Suffix identifying base64-encoded binary gRPC metadata.
pub const BINARY_METADATA_SUFFIX: &str = "-bin";

/// gRPC request protocol family derived from `content-type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrpcContentType {
    /// Standard gRPC over HTTP/2 (`application/grpc`, `+proto`, `+json`).
    Grpc,
    /// gRPC-Web binary framing (`application/grpc-web`, `+proto`, ...).
    GrpcWeb,
    /// gRPC-Web text framing: the frame sequence is base64-encoded.
    GrpcWebText,
    /// Not a gRPC request.
    NotGrpc,
}

impl GrpcContentType {
    /// Classifies a `content-type` header value.
    pub fn from_header(value: &str) -> Self {
        let media = value
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        if media == "application/grpc" || media.starts_with("application/grpc+") {
            Self::Grpc
        } else if media == "application/grpc-web-text"
            || media.starts_with("application/grpc-web-text+")
        {
            Self::GrpcWebText
        } else if media == "application/grpc-web" || media.starts_with("application/grpc-web+") {
            Self::GrpcWeb
        } else {
            Self::NotGrpc
        }
    }

    /// Whether this is any gRPC-family request.
    pub fn is_grpc(self) -> bool {
        self != Self::NotGrpc
    }
}

/// Message compression negotiated by `grpc-encoding`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GrpcEncoding {
    Identity,
    Gzip,
}

/// Returns the first gRPC `content-type` on the request, if any.
pub fn request_content_type(headers: &HeaderMap) -> Option<GrpcContentType> {
    headers
        .get_all(hyper::header::CONTENT_TYPE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .map(GrpcContentType::from_header)
        .find(|kind| kind.is_grpc())
}

/// A parsed `/package.Service/Method` path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrpcMethod {
    /// Normalised path including the leading slash.
    pub path: String,
    /// `package.Service` portion.
    pub service: String,
    /// RPC method name.
    pub method: String,
}

/// Errors from parsing a gRPC method path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MethodPathError {
    /// Path does not start with `/`.
    MissingLeadingSlash,
    /// Path is not exactly `/service/method`.
    Malformed,
    /// Service or method contains characters outside `[A-Za-z0-9_.]`.
    InvalidCharacters,
}

impl std::fmt::Display for MethodPathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingLeadingSlash => write!(f, "gRPC :path must start with '/'"),
            Self::Malformed => {
                write!(f, "gRPC :path must be '/package.Service/Method'")
            }
            Self::InvalidCharacters => {
                write!(f, "gRPC :path contains invalid characters")
            }
        }
    }
}

/// Parses and validates an HTTP/2 `:path` value.
pub fn parse_method_path(path: &str) -> Result<GrpcMethod, MethodPathError> {
    let rest = path
        .strip_prefix('/')
        .ok_or(MethodPathError::MissingLeadingSlash)?;
    let mut parts = rest.split('/');
    let (Some(service), Some(method), None) = (parts.next(), parts.next(), parts.next()) else {
        return Err(MethodPathError::Malformed);
    };
    if service.is_empty() || method.is_empty() {
        return Err(MethodPathError::Malformed);
    }
    if !service
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
        || !method
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return Err(MethodPathError::InvalidCharacters);
    }
    Ok(GrpcMethod {
        path: format!("/{service}/{method}"),
        service: service.to_string(),
        method: method.to_string(),
    })
}

/// Frame validation limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameLimits {
    /// Maximum decoded size of a single message.
    pub max_message_bytes: usize,
    /// Maximum number of frames in the body.
    pub max_frames: usize,
}

/// Result of validating a frame sequence.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FrameReport {
    /// Number of complete frames.
    pub frames: usize,
    /// Sum of declared message lengths (the decoded size for `identity`).
    pub decoded_bytes: usize,
    /// Number of frames whose compressed flag is set.
    pub compressed_frames: usize,
}

/// Frame-level validation failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    /// Fewer than 5 bytes remain where a prefix is expected.
    TruncatedPrefix { offset: usize, remaining: usize },
    /// The declared message extends past the end of the body.
    TruncatedMessage {
        index: usize,
        declared: usize,
        available: usize,
    },
    /// The compressed flag is neither 0 nor 1.
    InvalidCompressedFlag { index: usize, flag: u8 },
    /// The length field is not a valid non-negative protobuf length.
    InvalidLength { index: usize, length: u32 },
    /// A message exceeds `max_message_bytes`.
    MessageTooLarge {
        index: usize,
        size: usize,
        limit: usize,
    },
    /// The body contains more than `max_frames` messages.
    TooManyFrames { limit: usize },
    /// A gzip-compressed frame could not be decompressed.
    DecompressionFailed { index: usize, reason: String },
    /// Decompressed frame data exceeds the configured total limit.
    DecompressedTooLarge {
        index: usize,
        size: usize,
        limit: usize,
    },
}

impl FrameError {
    /// HTTP status used when reporting this frame error.
    pub fn status(&self) -> u16 {
        match self {
            Self::MessageTooLarge { .. }
            | Self::TooManyFrames { .. }
            | Self::DecompressedTooLarge { .. } => 413,
            _ => 400,
        }
    }
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TruncatedPrefix { offset, remaining } => write!(
                f,
                "truncated gRPC frame prefix at byte {offset} ({remaining} bytes remain, 5 required)"
            ),
            Self::TruncatedMessage {
                index,
                declared,
                available,
            } => write!(
                f,
                "truncated gRPC message {index}: declares {declared} bytes, only {available} available"
            ),
            Self::InvalidCompressedFlag { index, flag } => write!(
                f,
                "invalid gRPC compressed flag 0x{flag:02x} in frame {index} (must be 0 or 1)"
            ),
            Self::InvalidLength { index, length } => write!(
                f,
                "invalid gRPC length {length} in frame {index} (exceeds signed 32-bit range)"
            ),
            Self::MessageTooLarge { index, size, limit } => write!(
                f,
                "gRPC message {index} is {size} bytes, exceeding the {limit}-byte limit"
            ),
            Self::TooManyFrames { limit } => {
                write!(f, "gRPC body exceeds the {limit}-frame limit")
            }
            Self::DecompressionFailed { index, reason } => {
                write!(f, "gRPC frame {index} could not be decompressed: {reason}")
            }
            Self::DecompressedTooLarge { index, size, limit } => write!(
                f,
                "gRPC frame {index} decompresses to {size} bytes, exceeding the {limit}-byte limit"
            ),
        }
    }
}

/// Decompress one gzip-compressed gRPC message with a hard output cap.
///
/// The cap is checked while reading, so a small compressed payload cannot
/// expand into an unbounded allocation.
pub(crate) fn decompress_gzip(payload: &[u8], limit: usize) -> Result<Vec<u8>, String> {
    use std::io::Read;

    let mut decoder = flate2::read::GzDecoder::new(payload);
    let mut output = Vec::new();
    let mut chunk = [0u8; 8 * 1024];
    loop {
        let read = decoder
            .read(&mut chunk)
            .map_err(|error| format!("invalid gzip payload: {error}"))?;
        if read == 0 {
            break;
        }
        if output.len().saturating_add(read) > limit {
            return Err(format!("decompressed size exceeds {limit} bytes"));
        }
        output.extend_from_slice(&chunk[..read]);
    }
    Ok(output)
}

/// Validates a decoded gRPC frame sequence.
///
/// An empty body is a valid zero-frame body (for example a trailers-only or
/// streaming request whose payload is not buffered here).
pub fn validate_frames(body: &[u8], limits: FrameLimits) -> Result<FrameReport, FrameError> {
    let mut report = FrameReport::default();
    let mut offset = 0usize;
    let mut index = 0usize;

    while offset < body.len() {
        let remaining = body.len() - offset;
        if remaining < FRAME_PREFIX_LEN {
            return Err(FrameError::TruncatedPrefix { offset, remaining });
        }
        let flag = body[offset];
        if flag > 1 {
            return Err(FrameError::InvalidCompressedFlag { index, flag });
        }
        let length = u32::from_be_bytes([
            body[offset + 1],
            body[offset + 2],
            body[offset + 3],
            body[offset + 4],
        ]);
        if length > i32::MAX as u32 {
            return Err(FrameError::InvalidLength { index, length });
        }
        let declared = length as usize;

        if report.frames >= limits.max_frames {
            return Err(FrameError::TooManyFrames {
                limit: limits.max_frames,
            });
        }
        if declared > limits.max_message_bytes {
            return Err(FrameError::MessageTooLarge {
                index,
                size: declared,
                limit: limits.max_message_bytes,
            });
        }
        let available = body.len() - offset - FRAME_PREFIX_LEN;
        if declared > available {
            return Err(FrameError::TruncatedMessage {
                index,
                declared,
                available,
            });
        }

        report.frames += 1;
        report.decoded_bytes = report.decoded_bytes.saturating_add(declared);
        if flag == 1 {
            report.compressed_frames += 1;
        }
        offset += FRAME_PREFIX_LEN + declared;
        index += 1;
    }

    Ok(report)
}

/// Iterates over `(compressed_flag, payload)` pairs in a frame sequence
/// already accepted by [`validate_frames`].
fn frame_payloads_with_flags(body: &[u8]) -> impl Iterator<Item = (u8, &[u8])> {
    let mut offset = 0usize;
    std::iter::from_fn(move || {
        let start = offset.checked_add(FRAME_PREFIX_LEN)?;
        if start > body.len() {
            return None;
        }
        let flag = body[offset];
        let length = u32::from_be_bytes([
            body[offset + 1],
            body[offset + 2],
            body[offset + 3],
            body[offset + 4],
        ]) as usize;
        let end = start.checked_add(length)?;
        offset = end;
        body.get(start..end).map(|payload| (flag, payload))
    })
}

/// A binary metadata header (`-bin` suffix).
pub fn is_binary_metadata(name: &str) -> bool {
    name.len() > BINARY_METADATA_SUFFIX.len() && name.ends_with(BINARY_METADATA_SUFFIX)
}

/// Binary metadata that is not valid base64.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataError {
    /// Offending header name.
    pub header: String,
    /// Explanation for logs and audit events.
    pub reason: String,
}

impl std::fmt::Display for MetadataError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "invalid binary metadata {}: {}",
            self.header, self.reason
        )
    }
}

/// Validates base64 syntax of every `-bin` metadata value.
///
/// gRPC permits unpadded base64 and repeated headers; commas separate multiple
/// values in a single HTTP/2 field.
pub fn validate_binary_metadata(headers: &HeaderMap) -> Result<(), MetadataError> {
    for (name, value) in headers.iter() {
        let name_str = name.as_str();
        if !is_binary_metadata(name_str) {
            continue;
        }
        let Ok(text) = value.to_str() else {
            return Err(MetadataError {
                header: name_str.to_string(),
                reason: "value is not valid ASCII".to_string(),
            });
        };
        for token in text.split(',') {
            if !is_valid_base64(token.trim()) {
                return Err(MetadataError {
                    header: name_str.to_string(),
                    reason: "value is not valid base64".to_string(),
                });
            }
        }
    }
    Ok(())
}

fn is_valid_base64(value: &str) -> bool {
    let bytes = value.trim().as_bytes();
    let engine = base64::engine::general_purpose::STANDARD;
    engine.decode(bytes).is_ok()
        || base64::engine::general_purpose::STANDARD_NO_PAD
            .decode(bytes)
            .is_ok()
}

/// Metadata headers that may be scanned as text (everything except `-bin`).
///
/// Binary metadata is validated with [`validate_binary_metadata`] and never
/// fed to regex/body scanners.
pub fn text_metadata(headers: &HeaderMap) -> impl Iterator<Item = (&str, &HeaderValue)> {
    headers
        .iter()
        .filter(|(name, _)| !is_binary_metadata(name.as_str()))
        .map(|(name, value)| (name.as_str(), value))
}

/// Inspection verdict for a gRPC request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrpcVerdict {
    /// Protocol checks passed. When `strip_body` is set the engine must hide
    /// the protobuf body from the remaining (CRS/heuristic) rules.
    Allow { strip_body: bool, monitored: bool },
    /// Request rejected by the gRPC policy.
    Block { status: u16, reason: String },
}

/// Failure that makes the request un-inspectable (mapped via `fail_mode`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrpcInspectionError {
    /// Human-readable reason.
    pub reason: String,
}

impl std::fmt::Display for GrpcInspectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.reason)
    }
}

/// Direct Coraza backend used for gRPC field-content scanning.
///
/// Implementations call the backend without going through the gRPC pre-check,
/// so a content scan cannot recurse into another gRPC inspection.
pub trait GrpcContentScanner: Send + Sync {
    /// Evaluates a synthetic request payload and returns the backend decision.
    fn scan(&self, payload: &[u8]) -> Result<Decision, String>;
}

/// Protocol-aware gRPC inspector built from `waf.grpc`.
#[derive(Clone)]
pub struct GrpcInspector {
    allowlist: HashSet<String>,
    /// Per-method limits from the generated artifact, keyed by method path.
    method_max_message_bytes: HashMap<String, usize>,
    /// Request type per artifact method, used to select field metadata.
    method_input_types: HashMap<String, String>,
    /// Reachable request message metadata from the artifact.
    messages: HashMap<String, GrpcMessage>,
    max_message_bytes: usize,
    max_frames: usize,
    max_decompressed_bytes: usize,
    unknown_method_blocked: bool,
    decode_limits: DecodeLimits,
    content_scan: bool,
    max_content_scan_bytes: usize,
    content_scanner: Option<Arc<dyn GrpcContentScanner>>,
    metrics: Option<Arc<Metrics>>,
}

impl std::fmt::Debug for GrpcInspector {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GrpcInspector")
            .field("allowlist", &self.allowlist)
            .field("max_message_bytes", &self.max_message_bytes)
            .field("max_frames", &self.max_frames)
            .field("max_decompressed_bytes", &self.max_decompressed_bytes)
            .field("unknown_method_blocked", &self.unknown_method_blocked)
            .field("decode_limits", &self.decode_limits)
            .field("content_scan", &self.content_scan)
            .field("max_content_scan_bytes", &self.max_content_scan_bytes)
            .field("content_scanner", &self.content_scanner.is_some())
            .finish()
    }
}

impl GrpcInspector {
    /// Builds an inspector from configuration without reading any files.
    ///
    /// `waf.grpc.allowlist_file` is ignored here so callers (and tests) can
    /// build an inspector synchronously. Use [`Self::try_from_config`] to load
    /// and merge the generated artifact.
    pub fn from_config(config: &WafGrpcConfig) -> Self {
        Self::build(config, None)
    }

    /// Builds an inspector from configuration, loading `allowlist_file` when
    /// it is set.
    ///
    /// Artifact methods are merged with `method_allowlist`, artifact
    /// per-method `max_message_bytes` values win over the global limit, and an
    /// explicit `unknown_method_action` in the configuration wins over the
    /// artifact's.
    pub fn try_from_config(config: &WafGrpcConfig) -> Result<Self, GrpcAllowlistError> {
        let artifact = match config.allowlist_file.as_deref() {
            Some(path) => Some(grpc_allowlist::load_allowlist(path)?),
            None => None,
        };
        Ok(Self::build(config, artifact.as_ref()))
    }

    fn build(config: &WafGrpcConfig, artifact: Option<&GrpcAllowlist>) -> Self {
        let mut allowlist: HashSet<String> = config
            .method_allowlist
            .iter()
            .filter_map(|entry| parse_method_path(entry).ok())
            .map(|method| method.path)
            .collect();
        let mut method_max_message_bytes = HashMap::new();
        let mut method_input_types = HashMap::new();
        let mut messages = HashMap::new();
        if let Some(artifact) = artifact {
            for method in &artifact.methods {
                allowlist.insert(method.path.clone());
                method_max_message_bytes.insert(method.path.clone(), method.max_message_bytes);
                method_input_types.insert(method.path.clone(), method.input.clone());
            }
            for message in &artifact.messages {
                messages.insert(message.message.clone(), message.clone());
            }
        }

        // Precedence: explicit config value, then the artifact's policy, then
        // the built-in default (block for a non-empty allowlist).
        let unknown_method_blocked = match config.unknown_method_action.as_deref() {
            Some(action) => action == "block",
            None => match artifact {
                Some(artifact) => artifact.unknown_method_action == "block",
                None => config.unknown_method_action() == "block",
            },
        };

        Self {
            allowlist,
            method_max_message_bytes,
            method_input_types,
            messages,
            max_message_bytes: config.max_message_bytes,
            max_frames: config.max_frames,
            max_decompressed_bytes: config.max_decompressed_bytes,
            unknown_method_blocked,
            decode_limits: DecodeLimits {
                max_string_bytes: config.max_string_bytes,
                max_bytes_len: config.max_bytes_len,
                max_repeated: config.max_repeated,
                max_depth: config.max_depth,
                max_decoded_fields: config.max_decoded_fields,
                reject_unknown_fields: config.reject_unknown_fields,
                validate_strings: config.validate_strings,
            },
            content_scan: config.content_scan_enabled(),
            max_content_scan_bytes: config.max_content_scan_bytes,
            content_scanner: None,
            metrics: None,
        }
    }

    /// Attaches the direct Coraza backend used for field-content scanning.
    pub fn with_content_scanner(mut self, scanner: Arc<dyn GrpcContentScanner>) -> Self {
        self.content_scanner = Some(scanner);
        self
    }

    /// Attaches the process metrics registry for content-scan counters.
    pub fn with_metrics(mut self, metrics: Arc<Metrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Per-message limit for a method: the artifact's value when present,
    /// otherwise the global `waf.grpc.max_message_bytes`.
    fn max_message_bytes_for(&self, path: &str) -> usize {
        self.method_max_message_bytes
            .get(path)
            .copied()
            .unwrap_or(self.max_message_bytes)
    }

    /// Whether this request is gRPC (any `application/grpc*` content type).
    pub fn matches(&self, ctx: &RequestContext) -> bool {
        request_content_type(&ctx.headers).is_some()
    }

    /// Whether [`Self::inspect`] will run a Coraza field-content scan.
    ///
    /// Cheap and side-effect free: it reads the content type, the method path
    /// and the descriptor metadata, but never decodes the body. A malformed
    /// body that the pre-check later rejects with `400` is therefore still
    /// classified heavy. That over-approximation is the safe direction for
    /// admission control: a scan is never under-counted.
    pub fn scans_content(&self, ctx: &RequestContext) -> bool {
        if !self.content_scan || self.content_scanner.is_none() || !self.matches(ctx) {
            return false;
        }
        if !ctx.body.as_ref().is_some_and(|body| !body.is_empty()) {
            return false;
        }
        let path = ctx
            .headers
            .get(":path")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_else(|| ctx.uri.path());
        let Ok(method) = parse_method_path(path) else {
            return false;
        };
        self.method_input_types
            .get(&method.path)
            .is_some_and(|input| self.messages.contains_key(input))
    }

    /// Runs all protocol-aware checks for a gRPC request.
    pub fn inspect(&self, ctx: &RequestContext) -> Result<GrpcVerdict, GrpcInspectionError> {
        let content_type = match request_content_type(&ctx.headers) {
            Some(kind) => kind,
            None => {
                return Ok(GrpcVerdict::Allow {
                    strip_body: false,
                    monitored: false,
                })
            }
        };

        let path = ctx
            .headers
            .get(":path")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_else(|| ctx.uri.path());
        let method = parse_method_path(path).map_err(|err| GrpcInspectionError {
            reason: format!("invalid gRPC method path '{path}': {err}"),
        })?;

        let mut monitored = false;
        if !self.allowlist.is_empty() && !self.allowlist.contains(&method.path) {
            if self.unknown_method_blocked {
                return Ok(GrpcVerdict::Block {
                    status: 403,
                    reason: format!(
                        "gRPC method '{}' is not in waf.grpc.method_allowlist",
                        method.path
                    ),
                });
            }
            monitored = true;
            debug!(
                method = %method.path,
                "gRPC method is not in the allowlist; monitor mode allows it"
            );
        }

        let mut encodings = Vec::new();
        for value in ctx.headers.get_all("grpc-encoding").iter() {
            let text = value.to_str().map_err(|_| GrpcInspectionError {
                reason: "grpc-encoding is not valid ASCII".to_string(),
            })?;
            for token in text.split(',').map(str::trim).filter(|t| !t.is_empty()) {
                encodings.push(token.to_ascii_lowercase());
            }
        }
        let encoding = match encodings.as_slice() {
            [] => GrpcEncoding::Identity,
            [one] if one == "identity" => GrpcEncoding::Identity,
            [one] if one == "gzip" => GrpcEncoding::Gzip,
            [one] => {
                return Ok(GrpcVerdict::Block {
                    status: 400,
                    reason: format!(
                        "unsupported grpc-encoding '{one}'; only identity and gzip are accepted"
                    ),
                })
            }
            _ => {
                return Ok(GrpcVerdict::Block {
                    status: 400,
                    reason: format!(
                        "unsupported grpc-encoding '{}'; exactly one encoding is accepted",
                        encodings.join(", ")
                    ),
                })
            }
        };

        validate_binary_metadata(&ctx.headers)
            .map_err(|err| GrpcInspectionError { reason: err.reason })?;

        let body: Option<Vec<u8>> = match (content_type, ctx.body.as_deref()) {
            (_, None) => None,
            (GrpcContentType::GrpcWebText, Some(bytes)) => Some(decode_web_text(bytes)?),
            (_, Some(bytes)) => Some(bytes.to_vec()),
        };

        if let Some(body) = body.as_deref() {
            if !body.is_empty() {
                let report = match validate_frames(
                    body,
                    FrameLimits {
                        max_message_bytes: self.max_message_bytes_for(&method.path),
                        max_frames: self.max_frames,
                    },
                ) {
                    Ok(report) => report,
                    // A malformed or oversized frame is a client error, not an
                    // inspection failure: map it to the frame's own status
                    // (400/413) instead of the fail-closed 503 path.
                    Err(err) => {
                        return Ok(GrpcVerdict::Block {
                            status: err.status(),
                            reason: err.to_string(),
                        })
                    }
                };

                // `identity` means frames must not be compressed. With gzip,
                // each frame may independently be compressed (flag 1) or not
                // (flag 0), per the gRPC wire specification.
                if encoding == GrpcEncoding::Identity && report.compressed_frames > 0 {
                    return Ok(GrpcVerdict::Block {
                        status: 400,
                        reason: "gRPC frame is marked compressed but grpc-encoding is identity"
                            .to_string(),
                    });
                }

                // Decompress gzip frames once, even when the method has no
                // descriptor metadata. This bounds a gzip bomb before any
                // field decoding and keeps the envelope-only path safe.
                let decoded_frames: Option<Vec<Vec<u8>>> = if encoding == GrpcEncoding::Gzip {
                    let mut frames = Vec::new();
                    let mut decompressed_total = 0usize;
                    for (index, (flag, payload)) in frame_payloads_with_flags(body).enumerate() {
                        let decoded = if flag == 1 {
                            match decompress_gzip(
                                payload,
                                self.max_decompressed_bytes
                                    .saturating_sub(decompressed_total),
                            ) {
                                Ok(decoded) => decoded,
                                Err(reason) => {
                                    let error = if reason.contains("exceeds") {
                                        FrameError::DecompressedTooLarge {
                                            index,
                                            size: decompressed_total.saturating_add(payload.len()),
                                            limit: self.max_decompressed_bytes,
                                        }
                                    } else {
                                        FrameError::DecompressionFailed { index, reason }
                                    };
                                    return Ok(GrpcVerdict::Block {
                                        status: error.status(),
                                        reason: error.to_string(),
                                    });
                                }
                            }
                        } else {
                            payload.to_vec()
                        };
                        decompressed_total = decompressed_total.saturating_add(decoded.len());
                        if decompressed_total > self.max_decompressed_bytes {
                            let error = FrameError::DecompressedTooLarge {
                                index,
                                size: decompressed_total,
                                limit: self.max_decompressed_bytes,
                            };
                            return Ok(GrpcVerdict::Block {
                                status: error.status(),
                                reason: error.to_string(),
                            });
                        }
                        frames.push(decoded);
                    }
                    Some(frames)
                } else {
                    None
                };

                // Field inspection requires descriptor metadata in the
                // artifact. Methods without it (or version 1 artifacts) keep
                // the envelope-only behaviour.
                if let Some(input_type) = self.method_input_types.get(&method.path) {
                    if self.messages.contains_key(input_type) {
                        let mut collected: Vec<CollectedField> = Vec::new();
                        let mut collected_bytes = 0usize;
                        let payloads: Vec<&[u8]> = match decoded_frames.as_deref() {
                            Some(frames) => frames.iter().map(Vec::as_slice).collect(),
                            None => frame_payloads_with_flags(body)
                                .map(|(_, payload)| payload)
                                .collect(),
                        };
                        for payload in payloads {
                            let remaining =
                                self.max_content_scan_bytes.saturating_sub(collected_bytes);
                            match protobuf::decode_message_collect(
                                payload,
                                input_type,
                                &self.messages,
                                &self.decode_limits,
                                remaining,
                            ) {
                                Ok(fields) => {
                                    collected_bytes = collected_bytes.saturating_add(
                                        fields.iter().map(|field| field.value.len()).sum::<usize>(),
                                    );
                                    collected.extend(fields);
                                }
                                Err(error) => {
                                    return Ok(GrpcVerdict::Block {
                                        status: error.status(),
                                        reason: error.to_string(),
                                    });
                                }
                            }
                        }

                        if self.content_scan && !collected.is_empty() {
                            if let Some(scanner) = self.content_scanner.as_deref() {
                                if let Some(decision) =
                                    self.scan_content(scanner, ctx, &method.path, &collected)?
                                {
                                    return Ok(decision);
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(GrpcVerdict::Allow {
            strip_body: true,
            monitored,
        })
    }

    /// Evaluates collected field values through the direct Coraza backend.
    ///
    /// The synthetic payload is a form body (`f0`, `f1`, ...) with a
    /// `/__grpc__/...` URI, so CRS parses it as ordinary request content. The
    /// raw protobuf is never sent. Returns `None` when the backend allows.
    fn scan_content(
        &self,
        scanner: &dyn GrpcContentScanner,
        ctx: &RequestContext,
        method_path: &str,
        fields: &[CollectedField],
    ) -> Result<Option<GrpcVerdict>, GrpcInspectionError> {
        let mut body = String::new();
        for (index, field) in fields.iter().enumerate() {
            if index > 0 {
                body.push('&');
            }
            body.push_str(&format!("f{index}="));
            body.push_str(&form_encode(&field.value));
        }

        let uri = format!("/__grpc__{method_path}")
            .parse::<hyper::Uri>()
            .map_err(|error| GrpcInspectionError {
                reason: format!("failed to build gRPC content-scan URI: {error}"),
            })?;
        let mut headers = HeaderMap::new();
        headers.insert(
            hyper::header::CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        );
        // CRS expects a Host header; reuse the original so host-based rules
        // see the same virtual host as the real request.
        if let Some(host) = ctx
            .headers
            .get(hyper::header::HOST)
            .or_else(|| ctx.headers.get(":authority"))
        {
            headers.insert(hyper::header::HOST, host.clone());
        } else if let Some(authority) = ctx.uri.authority() {
            if let Ok(value) = HeaderValue::from_str(authority.as_str()) {
                headers.insert(hyper::header::HOST, value);
            }
        }
        if !headers.contains_key(hyper::header::HOST) {
            headers.insert(
                hyper::header::HOST,
                HeaderValue::from_static("grpc-content-scan.invalid"),
            );
        }
        // CRS also expects User-Agent and Accept; reuse the originals when
        // present so the synthetic request does not trip protocol warnings.
        if let Some(user_agent) = ctx.headers.get(hyper::header::USER_AGENT) {
            headers.insert(hyper::header::USER_AGENT, user_agent.clone());
        } else {
            headers.insert(
                hyper::header::USER_AGENT,
                HeaderValue::from_static("waf-grpc-content-scan/1.0"),
            );
        }
        if let Some(accept) = ctx.headers.get(hyper::header::ACCEPT) {
            headers.insert(hyper::header::ACCEPT, accept.clone());
        } else {
            headers.insert(hyper::header::ACCEPT, HeaderValue::from_static("*/*"));
        }
        // A POST without Content-Length trips CRS protocol rule 920180.
        if let Ok(length) = HeaderValue::from_str(&body.len().to_string()) {
            headers.insert(hyper::header::CONTENT_LENGTH, length);
        }
        let mut synthetic = RequestContext::new(
            // Reuse the original client address so IP-based rules stay
            // consistent with the real request.
            ctx.client_ip,
            hyper::Method::POST,
            uri,
            headers,
            Some(body.len()),
        );
        synthetic.body = Some(bytes::Bytes::from(body));

        let payload =
            coraza_payload::build_payload(&synthetic).map_err(|error| GrpcInspectionError {
                reason: format!("failed to encode gRPC content-scan payload: {error}"),
            })?;

        if let Some(metrics) = &self.metrics {
            metrics.record_grpc_content_scan();
        }

        match scanner.scan(&payload) {
            Ok(Decision::Allow) => Ok(None),
            Ok(Decision::Block { status, reason }) => {
                if let Some(metrics) = &self.metrics {
                    metrics.record_grpc_content_block();
                }
                let paths = fields
                    .iter()
                    .map(|field| field.path.as_str())
                    .collect::<Vec<_>>()
                    .join(", ");
                Ok(Some(GrpcVerdict::Block {
                    status,
                    reason: format!("gRPC content inspection blocked field(s) [{paths}]: {reason}"),
                }))
            }
            Ok(Decision::RateLimit { reason }) => Ok(Some(GrpcVerdict::Block {
                status: 429,
                reason: format!("gRPC content inspection rate limited: {reason}"),
            })),
            Err(error) => Err(GrpcInspectionError {
                reason: format!("gRPC content inspection failed: {error}"),
            }),
        }
    }
}

/// A frame rejected by incremental streaming inspection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrpcFrameBlock {
    /// HTTP status the proxy should use for the rejection.
    pub status: u16,
    /// Human-readable reason, also used for the gRPC `grpc-message` trailer.
    pub reason: String,
}

/// Per-message inspector used by the streaming gRPC body guard.
///
/// Implementations are synchronous by design: the existing `GrpcInspector`
/// (including its direct Coraza field-content scan) is synchronous. The guard
/// calls this once for every complete length-prefixed message *before* the
/// frame is forwarded upstream.
pub trait GrpcFrameInspector: Send + Sync {
    fn inspect_frame(&self, frame: &[u8]) -> Result<(), GrpcFrameBlock>;
}

/// A [`GrpcFrameInspector`] backed by the configured protocol-aware inspector.
///
/// Each frame is evaluated independently against the same request headers and
/// method policy. Structural limits, descriptor field checks and the synthetic
/// content scan therefore run for every message in a stream, not just for
/// buffered unary requests.
#[derive(Clone)]
pub struct GrpcStreamFrameInspector {
    inspector: GrpcInspector,
    context: RequestContext,
    fail_closed: bool,
}

impl GrpcStreamFrameInspector {
    /// Builds a per-message inspector from the request template and policy.
    pub fn new(inspector: GrpcInspector, context: RequestContext, fail_closed: bool) -> Self {
        Self {
            inspector,
            context,
            fail_closed,
        }
    }
}

impl GrpcFrameInspector for GrpcStreamFrameInspector {
    fn inspect_frame(&self, frame: &[u8]) -> Result<(), GrpcFrameBlock> {
        let mut context = self.context.clone();
        context.body_size = Some(frame.len());
        context.body = Some(bytes::Bytes::copy_from_slice(frame));
        match self.inspector.inspect(&context) {
            Ok(GrpcVerdict::Allow { .. }) => Ok(()),
            Ok(GrpcVerdict::Block { status, reason }) => Err(GrpcFrameBlock { status, reason }),
            Err(error) => {
                if self.fail_closed {
                    Err(GrpcFrameBlock {
                        status: 503,
                        reason: format!("gRPC inspection unavailable: {error}"),
                    })
                } else {
                    debug!(
                        error = %error,
                        "gRPC frame inspection failed; continuing because fail_mode is open"
                    );
                    Ok(())
                }
            }
        }
    }
}

/// Percent-encodes a field value for `application/x-www-form-urlencoded`.
fn form_encode(value: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::with_capacity(value.len());
    for &byte in value {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char);
            }
            b' ' => encoded.push('+'),
            _ => {
                encoded.push('%');
                encoded.push(HEX[(byte >> 4) as usize] as char);
                encoded.push(HEX[(byte & 0x0f) as usize] as char);
            }
        }
    }
    encoded
}

fn decode_web_text(bytes: &[u8]) -> Result<Vec<u8>, GrpcInspectionError> {
    let text: String = std::str::from_utf8(bytes)
        .map_err(|_| GrpcInspectionError {
            reason: "grpc-web-text body is not valid UTF-8".to_string(),
        })?
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    let engine = base64::engine::general_purpose::STANDARD;
    engine
        .decode(text.as_bytes())
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(text.as_bytes()))
        .map_err(|_| GrpcInspectionError {
            reason: "grpc-web-text body is not valid base64".to_string(),
        })
}

impl WafRule for GrpcInspector {
    fn name(&self) -> &str {
        "grpc-protocol-inspection"
    }

    fn evaluate(&self, ctx: &RequestContext) -> Decision {
        if !self.matches(ctx) {
            return Decision::Allow;
        }
        match self.inspect(ctx) {
            Ok(GrpcVerdict::Allow { .. }) => Decision::Allow,
            Ok(GrpcVerdict::Block { status, reason }) => Decision::Block { status, reason },
            Err(err) => Decision::Block {
                status: 400,
                reason: err.reason,
            },
        }
    }
}

/// Returns a copy of the context with the protobuf body withheld from
/// subsequent rules. `body_size` is preserved so size rules still apply.
pub fn strip_body(ctx: &RequestContext) -> RequestContext {
    let mut scrubbed = ctx.clone();
    scrubbed.body = None;
    scrubbed
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use hyper::{Method, Uri};
    use std::net::{IpAddr, Ipv4Addr};
    use std::str::FromStr;

    fn headers_with(content_type: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            hyper::header::CONTENT_TYPE,
            HeaderValue::from_str(content_type).unwrap(),
        );
        headers
    }

    fn grpc_context(path: &str, body: Option<Vec<u8>>) -> RequestContext {
        let mut headers = headers_with("application/grpc+proto");
        headers.insert("grpc-encoding", HeaderValue::from_static("identity"));
        let mut ctx = RequestContext::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            Method::POST,
            Uri::from_str(path).unwrap(),
            headers,
            body.as_ref().map(|b| b.len()),
        );
        if let Some(body) = body {
            ctx = ctx.with_body(Some(Bytes::from(body)));
        }
        ctx
    }

    fn grpc_context_with_content_type(content_type: &str, body: Option<Vec<u8>>) -> RequestContext {
        let mut headers = headers_with(content_type);
        headers.insert("grpc-encoding", HeaderValue::from_static("identity"));
        let mut ctx = RequestContext::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            Method::POST,
            Uri::from_str("/acme.Service/Method").unwrap(),
            headers,
            body.as_ref().map(|b| b.len()),
        );
        if let Some(body) = body {
            ctx = ctx.with_body(Some(Bytes::from(body)));
        }
        ctx
    }

    fn frame(flag: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(FRAME_PREFIX_LEN + payload.len());
        out.push(flag);
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    fn inspector(config: WafGrpcConfig) -> GrpcInspector {
        GrpcInspector::from_config(&config)
    }

    #[test]
    fn content_type_detection_covers_grpc_families() {
        for value in [
            "application/grpc",
            "application/grpc+proto",
            "application/grpc+json",
            "application/grpc; charset=utf-8",
        ] {
            assert_eq!(
                GrpcContentType::from_header(value),
                GrpcContentType::Grpc,
                "{value}"
            );
        }
        assert_eq!(
            GrpcContentType::from_header("application/grpc-web+proto"),
            GrpcContentType::GrpcWeb
        );
        assert_eq!(
            GrpcContentType::from_header("application/grpc-web-text+proto"),
            GrpcContentType::GrpcWebText
        );
        assert_eq!(
            GrpcContentType::from_header("application/json"),
            GrpcContentType::NotGrpc
        );
        assert_eq!(
            GrpcContentType::from_header("text/html; application/grpc"),
            GrpcContentType::NotGrpc
        );
    }

    #[test]
    fn method_path_parsing_accepts_fully_qualified_rpcs() {
        let method = parse_method_path("/acme.billing.v1.Billing/Charge").unwrap();
        assert_eq!(method.service, "acme.billing.v1.Billing");
        assert_eq!(method.method, "Charge");
        assert_eq!(method.path, "/acme.billing.v1.Billing/Charge");
    }

    #[test]
    fn method_path_parsing_rejects_malformed_paths() {
        assert_eq!(
            parse_method_path("acme.Service/Method"),
            Err(MethodPathError::MissingLeadingSlash)
        );
        assert_eq!(
            parse_method_path("/acme.Service"),
            Err(MethodPathError::Malformed)
        );
        assert_eq!(
            parse_method_path("/acme.Service/Method/Extra"),
            Err(MethodPathError::Malformed)
        );
        assert_eq!(
            parse_method_path("/acme.Service/Me thod"),
            Err(MethodPathError::InvalidCharacters)
        );
        assert_eq!(
            parse_method_path("/acme.Service/Method?x=1"),
            Err(MethodPathError::InvalidCharacters)
        );
    }

    #[test]
    fn valid_frames_are_accepted() {
        let mut body = frame(0, b"hello");
        body.extend_from_slice(&frame(0, b"world"));
        let report = validate_frames(
            &body,
            FrameLimits {
                max_message_bytes: 1024,
                max_frames: 4,
            },
        )
        .unwrap();
        assert_eq!(report.frames, 2);
        assert_eq!(report.decoded_bytes, 10);
        assert_eq!(report.compressed_frames, 0);
    }

    #[test]
    fn empty_body_is_zero_frames() {
        let report = validate_frames(
            &[],
            FrameLimits {
                max_message_bytes: 16,
                max_frames: 1,
            },
        )
        .unwrap();
        assert_eq!(report.frames, 0);
    }

    #[test]
    fn truncated_prefix_is_rejected() {
        let err = validate_frames(
            &[0, 0, 0],
            FrameLimits {
                max_message_bytes: 16,
                max_frames: 1,
            },
        )
        .unwrap_err();
        assert_eq!(
            err,
            FrameError::TruncatedPrefix {
                offset: 0,
                remaining: 3
            }
        );
        assert_eq!(err.status(), 400);
    }

    #[test]
    fn truncated_message_is_rejected() {
        let mut body = frame(0, b"hello");
        body.truncate(body.len() - 1);
        let err = validate_frames(
            &body,
            FrameLimits {
                max_message_bytes: 16,
                max_frames: 1,
            },
        )
        .unwrap_err();
        assert!(matches!(
            err,
            FrameError::TruncatedMessage { declared: 5, .. }
        ));
    }

    #[test]
    fn oversized_message_is_rejected() {
        let body = frame(0, b"0123456789");
        let err = validate_frames(
            &body,
            FrameLimits {
                max_message_bytes: 4,
                max_frames: 1,
            },
        )
        .unwrap_err();
        assert_eq!(
            err,
            FrameError::MessageTooLarge {
                index: 0,
                size: 10,
                limit: 4
            }
        );
        assert_eq!(err.status(), 413);
    }

    #[test]
    fn invalid_compressed_flags_are_rejected() {
        let body = frame(2, b"x");
        let err = validate_frames(
            &body,
            FrameLimits {
                max_message_bytes: 16,
                max_frames: 1,
            },
        )
        .unwrap_err();
        assert_eq!(err, FrameError::InvalidCompressedFlag { index: 0, flag: 2 });
    }

    #[test]
    fn negative_length_fields_are_rejected() {
        let mut body = vec![0u8];
        body.extend_from_slice(&u32::MAX.to_be_bytes());
        let err = validate_frames(
            &body,
            FrameLimits {
                max_message_bytes: 4096,
                max_frames: 1,
            },
        )
        .unwrap_err();
        assert!(matches!(err, FrameError::InvalidLength { .. }));
    }

    #[test]
    fn frame_count_limit_is_enforced() {
        let mut body = Vec::new();
        for _ in 0..3 {
            body.extend_from_slice(&frame(0, b"x"));
        }
        let err = validate_frames(
            &body,
            FrameLimits {
                max_message_bytes: 16,
                max_frames: 2,
            },
        )
        .unwrap_err();
        assert_eq!(err, FrameError::TooManyFrames { limit: 2 });
    }

    #[test]
    fn allowlisted_method_is_allowed_and_body_stripped() {
        let mut config = WafGrpcConfig::default();
        config.method_allowlist = vec!["/acme.Service/Method".to_string()];
        let inspector = inspector(config);

        let verdict = inspector
            .inspect(&grpc_context("/acme.Service/Method", Some(frame(0, b"ok"))))
            .unwrap();
        assert_eq!(
            verdict,
            GrpcVerdict::Allow {
                strip_body: true,
                monitored: false
            }
        );
    }

    #[test]
    fn unknown_method_is_blocked_by_default_with_allowlist() {
        let mut config = WafGrpcConfig::default();
        config.method_allowlist = vec!["/acme.Service/Method".to_string()];
        let inspector = inspector(config);

        let verdict = inspector
            .inspect(&grpc_context("/acme.Service/Other", Some(frame(0, b"ok"))))
            .unwrap();
        assert!(matches!(verdict, GrpcVerdict::Block { status: 403, .. }));
    }

    #[test]
    fn unknown_method_can_be_monitored() {
        let mut config = WafGrpcConfig::default();
        config.method_allowlist = vec!["/acme.Service/Method".to_string()];
        config.unknown_method_action = Some("allow".to_string());
        let inspector = inspector(config);

        let verdict = inspector
            .inspect(&grpc_context("/acme.Service/Other", Some(frame(0, b"ok"))))
            .unwrap();
        assert_eq!(
            verdict,
            GrpcVerdict::Allow {
                strip_body: true,
                monitored: true
            }
        );
    }

    #[test]
    fn empty_allowlist_is_monitor_only() {
        let config = WafGrpcConfig::default();
        assert_eq!(config.unknown_method_action(), "allow");
        let inspector = inspector(config);
        let verdict = inspector
            .inspect(&grpc_context(
                "/any.Service/Anything",
                Some(frame(0, b"ok")),
            ))
            .unwrap();
        assert_eq!(
            verdict,
            GrpcVerdict::Allow {
                strip_body: true,
                monitored: false
            }
        );
    }

    /// Writes a generated artifact and returns its directory (kept alive by
    /// the caller) and path.
    fn artifact_file(
        methods: &[(&str, usize)],
        unknown_method_action: &str,
    ) -> (tempfile::TempDir, String) {
        use crate::waf::grpc_allowlist::{
            AllowlistSource, GrpcAllowlist, GrpcAllowlistMethod, ALLOWLIST_IR_VERSION,
        };

        let allowlist = GrpcAllowlist {
            ir_version: ALLOWLIST_IR_VERSION,
            source: AllowlistSource {
                kind: "protobuf".to_string(),
                sha256: "b".repeat(64),
            },
            methods: methods
                .iter()
                .map(|(path, limit)| GrpcAllowlistMethod {
                    path: (*path).to_string(),
                    client_streaming: false,
                    server_streaming: false,
                    input: "acme.Request".to_string(),
                    output: "acme.Response".to_string(),
                    max_message_bytes: *limit,
                })
                .collect(),
            messages: Vec::new(),
            unknown_method_action: unknown_method_action.to_string(),
        };
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("allowlist.json");
        std::fs::write(&path, allowlist.to_canonical_json().unwrap()).unwrap();
        (dir, path.display().to_string())
    }

    fn artifact_file_with_messages(
        methods: &[(&str, usize)],
        messages: Vec<crate::waf::grpc_allowlist::GrpcMessage>,
    ) -> (tempfile::TempDir, String) {
        use crate::waf::grpc_allowlist::{
            AllowlistSource, GrpcAllowlist, GrpcAllowlistMethod, ALLOWLIST_IR_VERSION,
        };

        let allowlist = GrpcAllowlist {
            ir_version: ALLOWLIST_IR_VERSION,
            source: AllowlistSource {
                kind: "protobuf".to_string(),
                sha256: "c".repeat(64),
            },
            methods: methods
                .iter()
                .map(|(path, limit)| GrpcAllowlistMethod {
                    path: (*path).to_string(),
                    client_streaming: false,
                    server_streaming: false,
                    input: "acme.Request".to_string(),
                    output: "acme.Response".to_string(),
                    max_message_bytes: *limit,
                })
                .collect(),
            messages,
            unknown_method_action: "block".to_string(),
        };
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("allowlist.json");
        std::fs::write(&path, allowlist.to_canonical_json().unwrap()).unwrap();
        (dir, path.display().to_string())
    }

    fn request_field(
        name: &str,
        number: u32,
        field_type: &str,
        repeated: bool,
    ) -> crate::waf::grpc_allowlist::GrpcMessageField {
        crate::waf::grpc_allowlist::GrpcMessageField {
            name: name.to_string(),
            number,
            field_type: field_type.to_string(),
            repeated,
            required: false,
            message_type: None,
            enum_values: None,
        }
    }

    fn request_message(
        fields: Vec<crate::waf::grpc_allowlist::GrpcMessageField>,
    ) -> crate::waf::grpc_allowlist::GrpcMessage {
        crate::waf::grpc_allowlist::GrpcMessage {
            message: "acme.Request".to_string(),
            fields,
        }
    }

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

    fn put_tag(number: u32, wire: u8, out: &mut Vec<u8>) {
        put_varint((u64::from(number) << 3) | u64::from(wire), out);
    }

    fn put_string(number: u32, value: &str, out: &mut Vec<u8>) {
        put_tag(number, 2, out);
        put_varint(value.len() as u64, out);
        out.extend_from_slice(value.as_bytes());
    }

    fn field_inspector(
        config: &mut WafGrpcConfig,
        messages: Vec<crate::waf::grpc_allowlist::GrpcMessage>,
    ) -> (tempfile::TempDir, GrpcInspector) {
        let (dir, path) = artifact_file_with_messages(&[("/acme.Service/Method", 4096)], messages);
        config.allowlist_file = Some(path);
        let inspector = GrpcInspector::try_from_config(config).unwrap();
        (dir, inspector)
    }

    #[test]
    fn valid_descriptor_backed_message_is_allowed() {
        let mut config = WafGrpcConfig::default();
        let (_dir, inspector) = field_inspector(
            &mut config,
            vec![request_message(vec![request_field(
                "name", 1, "string", false,
            )])],
        );
        let mut payload = Vec::new();
        put_string(1, "alice", &mut payload);
        let verdict = inspector
            .inspect(&grpc_context(
                "/acme.Service/Method",
                Some(frame(0, &payload)),
            ))
            .unwrap();
        assert_eq!(
            verdict,
            GrpcVerdict::Allow {
                strip_body: true,
                monitored: false
            }
        );
    }

    struct FakeScanner {
        block: bool,
        calls: Arc<std::sync::atomic::AtomicUsize>,
        last_payload: std::sync::Mutex<Vec<u8>>,
    }

    impl FakeScanner {
        fn new(block: bool) -> Arc<Self> {
            Arc::new(Self {
                block,
                calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                last_payload: std::sync::Mutex::new(Vec::new()),
            })
        }
    }

    impl GrpcContentScanner for FakeScanner {
        fn scan(&self, payload: &[u8]) -> Result<Decision, String> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            *self.last_payload.lock().unwrap() = payload.to_vec();
            if self.block {
                Ok(Decision::Block {
                    status: 403,
                    reason: "CRS rule 942100".to_string(),
                })
            } else {
                Ok(Decision::Allow)
            }
        }
    }

    fn put_bytes(number: u32, value: &[u8], out: &mut Vec<u8>) {
        put_tag(number, 2, out);
        put_varint(value.len() as u64, out);
        out.extend_from_slice(value);
    }

    fn content_inspector(
        config: &mut WafGrpcConfig,
        fields: Vec<crate::waf::grpc_allowlist::GrpcMessageField>,
        scanner: Arc<FakeScanner>,
    ) -> (tempfile::TempDir, GrpcInspector) {
        let (dir, inspector) = field_inspector(config, vec![request_message(fields)]);
        (dir, inspector.with_content_scanner(scanner))
    }

    #[test]
    fn content_scan_blocks_sqli_and_xss_with_field_path() {
        for value in ["' OR '1'='1' --", "<script>alert(1)</script>"] {
            let mut config = WafGrpcConfig::default();
            let scanner = FakeScanner::new(true);
            let (_dir, inspector) = content_inspector(
                &mut config,
                vec![request_field("name", 1, "string", false)],
                Arc::clone(&scanner),
            );
            let mut payload = Vec::new();
            put_string(1, value, &mut payload);
            let verdict = inspector
                .inspect(&grpc_context(
                    "/acme.Service/Method",
                    Some(frame(0, &payload)),
                ))
                .unwrap();
            match verdict {
                GrpcVerdict::Block { status, reason } => {
                    assert_eq!(status, 403);
                    assert!(reason.contains("acme.Request.name"), "{reason}");
                    assert!(reason.contains("gRPC content inspection"), "{reason}");
                }
                other => panic!("expected content block, got {other:?}"),
            }
            assert_eq!(scanner.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        }
    }

    #[test]
    fn content_scan_allows_benign_strings() {
        let mut config = WafGrpcConfig::default();
        let scanner = FakeScanner::new(false);
        let (_dir, inspector) = content_inspector(
            &mut config,
            vec![request_field("name", 1, "string", false)],
            Arc::clone(&scanner),
        );
        let mut payload = Vec::new();
        put_string(1, "alice", &mut payload);
        let verdict = inspector
            .inspect(&grpc_context(
                "/acme.Service/Method",
                Some(frame(0, &payload)),
            ))
            .unwrap();
        assert!(matches!(verdict, GrpcVerdict::Allow { .. }));
        assert_eq!(scanner.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    fn binary_bytes_are_not_scanned_as_text() {
        let mut config = WafGrpcConfig::default();
        let scanner = FakeScanner::new(true);
        let (_dir, inspector) = content_inspector(
            &mut config,
            vec![request_field("blob", 1, "bytes", false)],
            Arc::clone(&scanner),
        );
        let mut payload = Vec::new();
        put_bytes(1, &[0xff, 0x00, 0xfe, 0x01], &mut payload);
        let verdict = inspector
            .inspect(&grpc_context(
                "/acme.Service/Method",
                Some(frame(0, &payload)),
            ))
            .unwrap();
        assert!(matches!(verdict, GrpcVerdict::Allow { .. }));
        assert_eq!(scanner.calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[test]
    fn content_scan_respects_byte_cap() {
        let mut config = WafGrpcConfig::default();
        config.max_content_scan_bytes = 8;
        let scanner = FakeScanner::new(false);
        let (_dir, inspector) = content_inspector(
            &mut config,
            vec![request_field("name", 1, "string", false)],
            Arc::clone(&scanner),
        );
        let mut payload = Vec::new();
        put_string(1, "abcdefghijklmnop", &mut payload);
        let verdict = inspector
            .inspect(&grpc_context(
                "/acme.Service/Method",
                Some(frame(0, &payload)),
            ))
            .unwrap();
        assert!(matches!(verdict, GrpcVerdict::Allow { .. }));
        let sent = scanner.last_payload.lock().unwrap().clone();
        let text = String::from_utf8(sent).unwrap();
        assert!(text.contains("f0=abcdefgh"), "{text}");
        assert!(!text.contains("ijklmnop"), "{text}");
    }

    #[test]
    fn content_scan_off_preserves_allow_behaviour() {
        let mut config = WafGrpcConfig::default();
        config.content_scan = "off".to_string();
        let scanner = FakeScanner::new(true);
        let (_dir, inspector) = content_inspector(
            &mut config,
            vec![request_field("name", 1, "string", false)],
            Arc::clone(&scanner),
        );
        let mut payload = Vec::new();
        put_string(1, "' OR '1'='1' --", &mut payload);
        let verdict = inspector
            .inspect(&grpc_context(
                "/acme.Service/Method",
                Some(frame(0, &payload)),
            ))
            .unwrap();
        assert!(matches!(verdict, GrpcVerdict::Allow { .. }));
        assert_eq!(scanner.calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[test]
    fn scans_content_reports_when_a_coraza_evaluation_will_run() {
        let mut config = WafGrpcConfig::default();
        let scanner = FakeScanner::new(false);
        let (_dir, inspector) = content_inspector(
            &mut config,
            vec![request_field("name", 1, "string", false)],
            Arc::clone(&scanner),
        );
        let mut payload = Vec::new();
        put_string(1, "hello", &mut payload);
        let request = grpc_context("/acme.Service/Method", Some(frame(0, &payload)));
        assert!(inspector.scans_content(&request));

        // No body means the pre-check performs envelope checks only.
        assert!(!inspector.scans_content(&grpc_context("/acme.Service/Method", None)));
        assert!(!inspector.scans_content(&grpc_context("/acme.Service/Method", Some(Vec::new()))));

        // Methods without descriptor metadata stay envelope-only.
        assert!(!inspector.scans_content(&grpc_context(
            "/acme.Service/Other",
            Some(frame(0, &payload))
        )));

        // A non-gRPC content type never runs the gRPC pre-check.
        assert!(!inspector.scans_content(&grpc_context_with_content_type(
            "application/json",
            Some(frame(0, &payload))
        )));
    }

    #[test]
    fn scans_content_is_false_when_content_scan_or_scanner_is_absent() {
        let mut config = WafGrpcConfig::default();
        let scanner = FakeScanner::new(false);
        let (_dir, _inspector) = content_inspector(
            &mut config,
            vec![request_field("name", 1, "string", false)],
            Arc::clone(&scanner),
        );
        let mut payload = Vec::new();
        put_string(1, "hello", &mut payload);
        let request = grpc_context("/acme.Service/Method", Some(frame(0, &payload)));

        let mut off_config = WafGrpcConfig::default();
        off_config.content_scan = "off".to_string();
        let (_off_dir, off_inspector) = content_inspector(
            &mut off_config,
            vec![request_field("name", 1, "string", false)],
            Arc::clone(&scanner),
        );
        assert!(!off_inspector.scans_content(&request));

        let mut no_scanner_config = WafGrpcConfig::default();
        let (_no_scanner_dir, no_scanner_inspector) = field_inspector(
            &mut no_scanner_config,
            vec![request_message(vec![request_field(
                "name", 1, "string", false,
            )])],
        );
        assert!(!no_scanner_inspector.scans_content(&request));
    }

    #[test]
    fn content_scan_metrics_increment_once() {
        let metrics = Arc::new(crate::metrics::Metrics::new());
        let mut config = WafGrpcConfig::default();
        let scanner = FakeScanner::new(true);
        let (_dir, inspector) = content_inspector(
            &mut config,
            vec![request_field("name", 1, "string", false)],
            Arc::clone(&scanner),
        );
        let inspector = inspector.with_metrics(Arc::clone(&metrics));
        let mut payload = Vec::new();
        put_string(1, "<script>alert(1)</script>", &mut payload);
        let _ = inspector
            .inspect(&grpc_context(
                "/acme.Service/Method",
                Some(frame(0, &payload)),
            ))
            .unwrap();
        assert_eq!(scanner.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        let rendered = metrics.render_prometheus();
        assert!(
            rendered.contains("waf_grpc_content_scans_total 1"),
            "{rendered}"
        );
        assert!(
            rendered.contains("waf_grpc_content_blocks_total 1"),
            "{rendered}"
        );
    }

    #[test]
    fn oversized_string_is_blocked_with_field_path() {
        let mut config = WafGrpcConfig::default();
        config.max_string_bytes = 4;
        let (_dir, inspector) = field_inspector(
            &mut config,
            vec![request_message(vec![request_field(
                "name", 1, "string", false,
            )])],
        );
        let mut payload = Vec::new();
        put_string(1, "abcdefgh", &mut payload);
        let verdict = inspector
            .inspect(&grpc_context(
                "/acme.Service/Method",
                Some(frame(0, &payload)),
            ))
            .unwrap();
        match verdict {
            GrpcVerdict::Block { status, reason } => {
                assert_eq!(status, 413);
                assert!(reason.contains("acme.Request.name"), "{reason}");
            }
            other => panic!("expected block, got {other:?}"),
        }
    }

    #[test]
    fn unknown_fields_follow_configuration() {
        let messages = vec![request_message(Vec::new())];
        let mut payload = Vec::new();
        put_string(99, "value", &mut payload);

        let mut config = WafGrpcConfig::default();
        let (_dir, inspector) = field_inspector(&mut config, messages.clone());
        let verdict = inspector
            .inspect(&grpc_context(
                "/acme.Service/Method",
                Some(frame(0, &payload)),
            ))
            .unwrap();
        assert!(matches!(verdict, GrpcVerdict::Allow { .. }));

        let mut config = WafGrpcConfig::default();
        config.reject_unknown_fields = true;
        let (_dir, inspector) = field_inspector(&mut config, messages);
        let verdict = inspector
            .inspect(&grpc_context(
                "/acme.Service/Method",
                Some(frame(0, &payload)),
            ))
            .unwrap();
        match verdict {
            GrpcVerdict::Block { status, reason } => {
                assert_eq!(status, 400);
                assert!(reason.contains("acme.Request.<field 99>"), "{reason}");
            }
            other => panic!("expected block, got {other:?}"),
        }
    }

    #[test]
    fn nested_depth_limit_is_enforced() {
        use crate::waf::grpc_allowlist::GrpcMessage;

        let mut parent_field = request_field("child", 1, "message", false);
        parent_field.message_type = Some("acme.Child".to_string());
        let mut child_field = request_field("grandchild", 1, "message", false);
        child_field.message_type = Some("acme.Grandchild".to_string());
        let leaf_field = request_field("leaf", 1, "string", false);
        let mut config = WafGrpcConfig::default();
        config.max_depth = 1;
        let (_dir, inspector) = field_inspector(
            &mut config,
            vec![
                request_message(vec![parent_field]),
                GrpcMessage {
                    message: "acme.Child".to_string(),
                    fields: vec![child_field],
                },
                GrpcMessage {
                    message: "acme.Grandchild".to_string(),
                    fields: vec![leaf_field],
                },
            ],
        );

        let mut grandchild = Vec::new();
        put_string(1, "leaf", &mut grandchild);
        let mut child = Vec::new();
        put_tag(1, 2, &mut child);
        put_varint(grandchild.len() as u64, &mut child);
        child.extend_from_slice(&grandchild);
        let mut payload = Vec::new();
        put_tag(1, 2, &mut payload);
        put_varint(child.len() as u64, &mut payload);
        payload.extend_from_slice(&child);

        assert_eq!(inspector.decode_limits.max_depth, 1);
        assert!(inspector.messages.contains_key("acme.Child"));
        assert!(inspector.messages.contains_key("acme.Grandchild"));
        assert_eq!(
            inspector.messages["acme.Request"].fields[0]
                .message_type
                .as_deref(),
            Some("acme.Child")
        );
        assert_eq!(
            inspector.messages["acme.Child"].fields[0]
                .message_type
                .as_deref(),
            Some("acme.Grandchild")
        );
        let direct = protobuf::decode_message(
            &payload,
            "acme.Request",
            &inspector.messages,
            &inspector.decode_limits,
        );
        assert!(direct.is_err(), "direct decode unexpectedly passed");
        let verdict = inspector
            .inspect(&grpc_context(
                "/acme.Service/Method",
                Some(frame(0, &payload)),
            ))
            .unwrap();
        assert!(
            matches!(verdict, GrpcVerdict::Block { status: 413, .. }),
            "unexpected verdict: {verdict:?}"
        );
    }

    #[test]
    fn malformed_wire_data_is_blocked_with_400() {
        let mut config = WafGrpcConfig::default();
        let (_dir, inspector) = field_inspector(
            &mut config,
            vec![request_message(vec![request_field(
                "name", 1, "string", false,
            )])],
        );
        // Field 1 claims 5 bytes but only 1 remains.
        let payload = vec![0x0a, 0x05, 0x01];
        let verdict = inspector
            .inspect(&grpc_context(
                "/acme.Service/Method",
                Some(frame(0, &payload)),
            ))
            .unwrap();
        assert!(
            matches!(verdict, GrpcVerdict::Block { status: 400, .. }),
            "unexpected verdict: {verdict:?}"
        );
    }

    #[test]
    fn missing_descriptor_metadata_falls_back_to_envelope_checks() {
        let mut config = WafGrpcConfig::default();
        config.reject_unknown_fields = true;
        let (_dir, inspector) = field_inspector(&mut config, Vec::new());
        let mut payload = Vec::new();
        put_string(99, "value", &mut payload);
        let verdict = inspector
            .inspect(&grpc_context(
                "/acme.Service/Method",
                Some(frame(0, &payload)),
            ))
            .unwrap();
        assert_eq!(
            verdict,
            GrpcVerdict::Allow {
                strip_body: true,
                monitored: false
            }
        );
    }

    #[test]
    fn artifact_allowlist_allows_listed_methods_and_blocks_unknown() {
        let (_dir, path) = artifact_file(&[("/acme.Service/Method", 1024)], "block");
        let mut config = WafGrpcConfig::default();
        config.allowlist_file = Some(path);

        let inspector = GrpcInspector::try_from_config(&config).unwrap();
        let verdict = inspector
            .inspect(&grpc_context("/acme.Service/Method", Some(frame(0, b"ok"))))
            .unwrap();
        assert_eq!(
            verdict,
            GrpcVerdict::Allow {
                strip_body: true,
                monitored: false
            }
        );

        let verdict = inspector
            .inspect(&grpc_context("/acme.Service/Other", Some(frame(0, b"ok"))))
            .unwrap();
        assert!(matches!(verdict, GrpcVerdict::Block { status: 403, .. }));
    }

    #[test]
    fn artifact_methods_merge_with_config_allowlist() {
        let (_dir, path) = artifact_file(&[("/acme.Service/FromArtifact", 1024)], "block");
        let mut config = WafGrpcConfig::default();
        config.allowlist_file = Some(path);
        config.method_allowlist = vec!["/acme.Service/FromConfig".to_string()];

        let inspector = GrpcInspector::try_from_config(&config).unwrap();
        for method in ["/acme.Service/FromArtifact", "/acme.Service/FromConfig"] {
            let verdict = inspector
                .inspect(&grpc_context(method, Some(frame(0, b"ok"))))
                .unwrap();
            assert_eq!(
                verdict,
                GrpcVerdict::Allow {
                    strip_body: true,
                    monitored: false
                },
                "{method} must be allowed"
            );
        }
    }

    #[test]
    fn artifact_per_method_limit_overrides_global() {
        let (_dir, path) = artifact_file(
            &[("/acme.Service/Upload", 8), ("/acme.Service/Ping", 4096)],
            "block",
        );
        let mut config = WafGrpcConfig::default();
        config.allowlist_file = Some(path);
        // Well above the artifact's 8-byte limit for Upload.
        config.max_message_bytes = 4096;

        let inspector = GrpcInspector::try_from_config(&config).unwrap();

        // The artifact limit is smaller than the global one and is enforced.
        let verdict = inspector
            .inspect(&grpc_context(
                "/acme.Service/Upload",
                Some(frame(0, b"0123456789")),
            ))
            .unwrap();
        match verdict {
            GrpcVerdict::Block { status, reason } => {
                assert_eq!(status, 413);
                assert!(
                    reason.contains("8-byte limit"),
                    "unexpected reason: {reason}"
                );
            }
            other => panic!("expected a 413 block, got {other:?}"),
        }

        // Another artifact method keeps its (larger) per-method limit.
        let verdict = inspector
            .inspect(&grpc_context(
                "/acme.Service/Ping",
                Some(frame(0, b"payload")),
            ))
            .unwrap();
        assert_eq!(
            verdict,
            GrpcVerdict::Allow {
                strip_body: true,
                monitored: false
            }
        );

        // Config-only methods fall back to the global limit.
        config.method_allowlist = vec!["/acme.Service/ConfigOnly".to_string()];
        let config_only = GrpcInspector::try_from_config(&config).unwrap();
        let verdict = config_only
            .inspect(&grpc_context(
                "/acme.Service/ConfigOnly",
                Some(frame(0, b"payload")),
            ))
            .unwrap();
        assert!(matches!(verdict, GrpcVerdict::Allow { .. }));
    }

    #[test]
    fn explicit_config_action_overrides_artifact_action() {
        let (_dir, path) = artifact_file(&[("/acme.Service/Method", 1024)], "block");
        let mut config = WafGrpcConfig::default();
        config.allowlist_file = Some(path);
        config.unknown_method_action = Some("allow".to_string());

        let inspector = GrpcInspector::try_from_config(&config).unwrap();
        let verdict = inspector
            .inspect(&grpc_context("/acme.Service/Other", Some(frame(0, b"ok"))))
            .unwrap();
        assert_eq!(
            verdict,
            GrpcVerdict::Allow {
                strip_body: true,
                monitored: true
            }
        );
    }

    #[test]
    fn artifact_action_applies_when_config_does_not_set_one() {
        let (_dir, path) = artifact_file(&[("/acme.Service/Method", 1024)], "allow");
        let mut config = WafGrpcConfig::default();
        config.allowlist_file = Some(path);
        assert!(config.unknown_method_action.is_none());

        let inspector = GrpcInspector::try_from_config(&config).unwrap();
        let verdict = inspector
            .inspect(&grpc_context("/acme.Service/Other", Some(frame(0, b"ok"))))
            .unwrap();
        assert_eq!(
            verdict,
            GrpcVerdict::Allow {
                strip_body: true,
                monitored: true
            }
        );
    }

    #[test]
    fn try_from_config_reports_an_unreadable_artifact() {
        let mut config = WafGrpcConfig::default();
        config.allowlist_file = Some("/nonexistent/grpc/allowlist.json".to_string());
        let error = GrpcInspector::try_from_config(&config).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("/nonexistent/grpc/allowlist.json"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn unsupported_encoding_is_rejected() {
        let mut ctx = grpc_context("/acme.Service/Method", Some(frame(0, b"ok")));
        ctx.headers
            .insert("grpc-encoding", HeaderValue::from_static("zstd"));
        let verdict = inspector(WafGrpcConfig::default()).inspect(&ctx).unwrap();
        assert!(matches!(verdict, GrpcVerdict::Block { status: 400, .. }));
    }

    #[test]
    fn gzip_compressed_frame_is_decompressed_and_inspected() {
        use std::io::Write;

        let payload = b"hello gzip";
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(payload).unwrap();
        let compressed = encoder.finish().unwrap();

        let mut ctx = grpc_context("/acme.Service/Method", Some(frame(1, &compressed)));
        ctx.headers
            .insert("grpc-encoding", HeaderValue::from_static("gzip"));
        let verdict = inspector(WafGrpcConfig::default()).inspect(&ctx).unwrap();
        assert!(matches!(verdict, GrpcVerdict::Allow { .. }));
    }

    #[test]
    fn gzip_bomb_is_bounded() {
        use std::io::Write;

        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&vec![b'A'; 64 * 1024]).unwrap();
        let compressed = encoder.finish().unwrap();

        let mut config = WafGrpcConfig::default();
        config.max_decompressed_bytes = 1024;
        let mut ctx = grpc_context("/acme.Service/Method", Some(frame(1, &compressed)));
        ctx.headers
            .insert("grpc-encoding", HeaderValue::from_static("gzip"));
        let verdict = inspector(config).inspect(&ctx).unwrap();
        assert!(
            matches!(verdict, GrpcVerdict::Block { status: 413, .. }),
            "gzip expansion beyond the cap must be rejected: {verdict:?}"
        );
    }

    #[test]
    fn malformed_gzip_frame_is_rejected() {
        let mut ctx = grpc_context("/acme.Service/Method", Some(frame(1, b"not gzip")));
        ctx.headers
            .insert("grpc-encoding", HeaderValue::from_static("gzip"));
        let verdict = inspector(WafGrpcConfig::default()).inspect(&ctx).unwrap();
        assert!(matches!(verdict, GrpcVerdict::Block { status: 400, .. }));
    }

    #[test]
    fn compressed_flag_with_identity_encoding_is_rejected() {
        let verdict = inspector(WafGrpcConfig::default())
            .inspect(&grpc_context("/acme.Service/Method", Some(frame(1, b"x"))))
            .unwrap();
        assert!(matches!(verdict, GrpcVerdict::Block { status: 400, .. }));
    }

    #[test]
    fn binary_metadata_must_be_valid_base64() {
        let mut headers = HeaderMap::new();
        headers.insert("x-tenant-bin", HeaderValue::from_static("dGVuYW50"));
        headers.insert("x-trace-bin", HeaderValue::from_static("AAECAw=="));
        assert!(validate_binary_metadata(&headers).is_ok());

        headers.insert("x-bad-bin", HeaderValue::from_static("not base64!!"));
        let err = validate_binary_metadata(&headers).unwrap_err();
        assert_eq!(err.header, "x-bad-bin");
    }

    #[test]
    fn binary_metadata_is_excluded_from_text_scanning() {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_static("application/grpc"));
        headers.insert("x-tenant-bin", HeaderValue::from_static("dGVuYW50"));
        let text: Vec<&str> = text_metadata(&headers).map(|(name, _)| name).collect();
        assert!(text.contains(&"content-type"));
        assert!(!text.contains(&"x-tenant-bin"));
    }

    #[test]
    fn grpc_web_text_frames_are_decoded_before_validation() {
        let decoded = frame(0, b"hello");
        let encoded = base64::engine::general_purpose::STANDARD.encode(&decoded);
        let mut ctx = grpc_context("/acme.Service/Method", Some(encoded.into_bytes()));
        ctx.headers.insert(
            hyper::header::CONTENT_TYPE,
            HeaderValue::from_static("application/grpc-web-text+proto"),
        );
        let verdict = inspector(WafGrpcConfig::default()).inspect(&ctx).unwrap();
        assert_eq!(
            verdict,
            GrpcVerdict::Allow {
                strip_body: true,
                monitored: false
            }
        );
    }

    #[test]
    fn oversized_frames_follow_the_configured_limit_in_inspector() {
        let mut config = WafGrpcConfig::default();
        config.max_message_bytes = 4;
        let verdict = inspector(config)
            .inspect(&grpc_context(
                "/acme.Service/Method",
                Some(frame(0, b"12345")),
            ))
            .unwrap();
        match verdict {
            GrpcVerdict::Block { status, reason } => {
                assert_eq!(status, 413);
                assert!(reason.contains("exceeding the 4-byte limit"));
            }
            other => panic!("expected a 413 block, got {other:?}"),
        }
    }

    #[test]
    fn non_grpc_requests_are_left_alone() {
        let mut ctx = grpc_context("/index.html", Some(b"a=b".to_vec()));
        ctx.headers.insert(
            hyper::header::CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        );
        let verdict = inspector(WafGrpcConfig::default()).inspect(&ctx).unwrap();
        assert_eq!(
            verdict,
            GrpcVerdict::Allow {
                strip_body: false,
                monitored: false
            }
        );
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    fn limits() -> FrameLimits {
        FrameLimits {
            max_message_bytes: usize::MAX,
            max_frames: 16,
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        #[test]
        fn arbitrary_bytes_never_panic(body in proptest::collection::vec(any::<u8>(), 0..2048)) {
            let _ = validate_frames(&body, limits());
        }

        #[test]
        fn frame_prefix_is_total(
            flag in any::<u8>(),
            length in any::<u32>(),
            payload in proptest::collection::vec(any::<u8>(), 0..256),
        ) {
            let mut body = Vec::with_capacity(FRAME_PREFIX_LEN + payload.len());
            body.push(flag);
            body.extend_from_slice(&length.to_be_bytes());
            body.extend_from_slice(&payload);

            let result = validate_frames(&body, limits());
            if flag > 1 {
                let is_flag_error = matches!(result, Err(FrameError::InvalidCompressedFlag { .. }));
                prop_assert!(is_flag_error);
            } else if length > i32::MAX as u32 {
                let is_length_error = matches!(result, Err(FrameError::InvalidLength { .. }));
                prop_assert!(is_length_error);
            } else if length as usize > payload.len() {
                let is_truncated = matches!(result, Err(FrameError::TruncatedMessage { .. }));
                prop_assert!(is_truncated);
            } else {
                let report = result.expect("complete frame must validate");
                prop_assert_eq!(report.frames, 1);
                prop_assert_eq!(report.decoded_bytes, length as usize);
                prop_assert_eq!(report.compressed_frames, usize::from(flag == 1));
            }
        }

        #[test]
        fn valid_frame_sequences_round_trip(
            frames in proptest::collection::vec(
                (any::<bool>(), proptest::collection::vec(any::<u8>(), 0..64)),
                0..8,
            ),
        ) {
            let mut body = Vec::new();
            let mut decoded = 0usize;
            let mut compressed = 0usize;
            for (is_compressed, payload) in &frames {
                body.push(u8::from(*is_compressed));
                body.extend_from_slice(&(payload.len() as u32).to_be_bytes());
                body.extend_from_slice(payload);
                decoded += payload.len();
                compressed += usize::from(*is_compressed);
            }
            let report = validate_frames(&body, limits()).expect("generated frames must validate");
            prop_assert_eq!(report.frames, frames.len());
            prop_assert_eq!(report.decoded_bytes, decoded);
            prop_assert_eq!(report.compressed_frames, compressed);
        }

        #[test]
        fn method_path_parser_is_total(path in ".*") {
            if let Ok(method) = parse_method_path(&path) {
                prop_assert!(method.path.starts_with('/'));
                prop_assert_eq!(method.path.matches('/').count(), 2);
                prop_assert_eq!(method.path, format!("/{}/{}", method.service, method.method));
            }
        }

        #[test]
        fn content_type_parser_is_total(value in ".*") {
            let _ = GrpcContentType::from_header(&value);
        }
    }
}
