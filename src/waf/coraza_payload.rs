//! Shared request payload serialisation for Coraza backends.
//!
//! The WASI reactor and the native sidecar use the same JSON envelope, so the
//! two backends can be compared directly and the sidecar can be swapped in
//! without changing request construction.

use base64::Engine as _;

use crate::waf::RequestContext;

/// Payload `body_encoding` value for a body that is valid UTF-8.
pub const BODY_ENCODING_UTF8: &str = "utf8";
/// Payload `body_encoding` value for a base64-encoded binary body.
pub const BODY_ENCODING_BASE64: &str = "base64";

/// Serialises the request context into the reactor/sidecar JSON payload.
///
/// Bodies that are valid UTF-8 keep the `utf8` fast path. Binary bodies
/// (protobuf/gRPC, msgpack, compressed payloads) are base64-encoded and marked
/// `base64` so invalid UTF-8 bytes are never replaced with U+FFFD before
/// inspection. `body_size` is always the raw byte length; payloads that omit
/// `body_encoding` are treated as `utf8` by the guest for backwards
/// compatibility.
pub fn build_payload(ctx: &RequestContext) -> Result<Vec<u8>, serde_json::Error> {
    let headers: Vec<(String, String)> = ctx
        .headers
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_string(),
                String::from_utf8_lossy(value.as_bytes()).into_owned(),
            )
        })
        .collect();

    let (body, body_encoding) = match ctx.body.as_deref() {
        None => (None, BODY_ENCODING_UTF8),
        Some(bytes) => match std::str::from_utf8(bytes) {
            Ok(text) => (Some(text.to_string()), BODY_ENCODING_UTF8),
            Err(_) => (
                Some(base64::engine::general_purpose::STANDARD.encode(bytes)),
                BODY_ENCODING_BASE64,
            ),
        },
    };
    // The wire size is the raw body length, not the encoded JSON string length.
    let body_size = ctx.body.as_deref().map(<[u8]>::len).or(ctx.body_size);

    serde_json::to_vec(&serde_json::json!({
        "method": ctx.method.as_str(),
        "uri": ctx.uri.to_string(),
        "http_version": ctx.http_version,
        "headers": headers,
        "body_size": body_size,
        "body_encoding": body_encoding,
        "body": body,
    }))
}
