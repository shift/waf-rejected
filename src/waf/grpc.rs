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
//!   (regex) scanning.
//!
//! Field-level protobuf inspection is **not** implemented here: it needs the
//! service descriptor (`FileDescriptorSet`) and is tracked separately.

use std::collections::{HashMap, HashSet};

use base64::Engine as _;
use hyper::header::HeaderValue;
use hyper::HeaderMap;
use tracing::debug;

use crate::config::WafGrpcConfig;
use crate::waf::grpc_allowlist::{self, GrpcAllowlist, GrpcAllowlistError};
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
}

impl FrameError {
    /// HTTP status used when reporting this frame error.
    pub fn status(&self) -> u16 {
        match self {
            Self::MessageTooLarge { .. } | Self::TooManyFrames { .. } => 413,
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
        }
    }
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
        report.decoded_bytes += declared;
        if flag == 1 {
            report.compressed_frames += 1;
        }
        offset += FRAME_PREFIX_LEN + declared;
        index += 1;
    }

    Ok(report)
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

/// Protocol-aware gRPC inspector built from `waf.grpc`.
#[derive(Debug, Clone)]
pub struct GrpcInspector {
    allowlist: HashSet<String>,
    /// Per-method limits from the generated artifact, keyed by method path.
    method_max_message_bytes: HashMap<String, usize>,
    max_message_bytes: usize,
    max_frames: usize,
    unknown_method_blocked: bool,
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
        if let Some(artifact) = artifact {
            for method in &artifact.methods {
                allowlist.insert(method.path.clone());
                method_max_message_bytes.insert(method.path.clone(), method.max_message_bytes);
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
            max_message_bytes: config.max_message_bytes,
            max_frames: config.max_frames,
            unknown_method_blocked,
        }
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

        for value in ctx.headers.get_all("grpc-encoding").iter() {
            let text = value.to_str().map_err(|_| GrpcInspectionError {
                reason: "grpc-encoding is not valid ASCII".to_string(),
            })?;
            for token in text.split(',').map(str::trim).filter(|t| !t.is_empty()) {
                if !token.eq_ignore_ascii_case("identity") {
                    return Ok(GrpcVerdict::Block {
                        status: 400,
                        reason: format!(
                            "unsupported grpc-encoding '{token}'; only identity is accepted"
                        ),
                    });
                }
            }
        }

        validate_binary_metadata(&ctx.headers)
            .map_err(|err| GrpcInspectionError { reason: err.reason })?;

        let body: Option<Vec<u8>> = match (content_type, ctx.body.as_deref()) {
            (_, None) => None,
            (GrpcContentType::GrpcWebText, Some(bytes)) => Some(decode_web_text(bytes)?),
            (_, Some(bytes)) => Some(bytes.to_vec()),
        };

        if let Some(body) = body.as_deref() {
            if !body.is_empty() {
                let report = validate_frames(
                    body,
                    FrameLimits {
                        max_message_bytes: self.max_message_bytes_for(&method.path),
                        max_frames: self.max_frames,
                    },
                )
                .map_err(|err| GrpcInspectionError {
                    reason: err.to_string(),
                })?;

                // `identity` means frames must not be compressed; the
                // compressed flag is only meaningful with a negotiated
                // encoding, and non-identity encodings are rejected above.
                if report.compressed_frames > 0 {
                    return Ok(GrpcVerdict::Block {
                        status: 400,
                        reason: "gRPC frame is marked compressed but grpc-encoding is identity"
                            .to_string(),
                    });
                }
            }
        }

        Ok(GrpcVerdict::Allow {
            strip_body: true,
            monitored,
        })
    }
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
            unknown_method_action: unknown_method_action.to_string(),
        };
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("allowlist.json");
        std::fs::write(&path, allowlist.to_canonical_json().unwrap()).unwrap();
        (dir, path.display().to_string())
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
        let error = inspector
            .inspect(&grpc_context(
                "/acme.Service/Upload",
                Some(frame(0, b"0123456789")),
            ))
            .unwrap_err();
        assert!(
            error.reason.contains("8-byte limit"),
            "unexpected error: {}",
            error.reason
        );

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
        let mut config = config;
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
        let err = inspector(config)
            .inspect(&grpc_context(
                "/acme.Service/Method",
                Some(frame(0, b"12345")),
            ))
            .unwrap_err();
        assert!(err.reason.contains("exceeding the 4-byte limit"));
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
