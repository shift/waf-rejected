//! Binary wire encoding for the native Coraza sidecar (protocol v1).
//!
//! Frames keep the 4-byte big-endian length prefix of the original protocol and
//! use the first payload byte to select the encoding:
//!
//! * `{` — legacy JSON envelope (still produced for the WASI reactor and still
//!   accepted by the sidecar),
//! * [`FRAME_MAGIC_BINARY`] — binary v1 request or response,
//! * [`FRAME_MAGIC_HANDSHAKE`] — capability negotiation.
//!
//! Binary v1 removes JSON escaping and base64: the body travels as raw bytes
//! and is written with `writev`, so a request costs one syscall and no body
//! copy. A request head is built once into a reused buffer; only the request
//! line and header strings are copied.
//!
//! The encoder is deliberately byte-for-byte equivalent in *meaning* to the
//! JSON envelope: the same method/URI/HTTP version, the same lossy UTF-8 header
//! conversion, the same inspected body bytes and the same body/original sizes.
//! That is what keeps native decisions identical between the two encodings.

use std::fmt;

use bytes::Bytes;

use crate::waf::coraza_payload::{select_body_parts, BodyInspectionPolicy, BodySelection};
use crate::waf::request_view::RequestView;
use crate::waf::RequestContext;

/// Payload discriminator for a legacy JSON envelope.
pub const FRAME_MAGIC_JSON: u8 = b'{';
/// Payload discriminator for a handshake frame.
pub const FRAME_MAGIC_HANDSHAKE: u8 = 0xC1;
/// Payload discriminator for a binary v1 request or response.
pub const FRAME_MAGIC_BINARY: u8 = 0xC2;
/// Binary wire version understood by this client.
pub const WIRE_VERSION: u8 = 1;

/// Fixed request header length (excluding the 4-byte frame length prefix).
pub const REQUEST_HEADER_LEN: usize = 28;
/// Fixed response header length (excluding the 4-byte frame length prefix).
pub const RESPONSE_HEADER_LEN: usize = 8;

/// The request carries an inspected body.
pub const FLAG_HAS_BODY: u8 = 1 << 0;
/// The inspected body was truncated to the configured prefix.
pub const FLAG_TRUNCATED: u8 = 1 << 1;
/// The frame carries a per-rule removal list between the header block and the
/// body. Only sent when the sidecar advertises [`CAP_REMOVE_RULES`].
pub const FLAG_HAS_REMOVE_RULES: u8 = 1 << 2;

/// Handshake capability bit: binary v1 framing.
pub const CAP_BINARY_V1: u8 = 1 << 0;
/// Handshake capability bit: `FLAG_HAS_REMOVE_RULES` frames are understood.
pub const CAP_REMOVE_RULES: u8 = 1 << 1;

/// Hard bound on the per-request removal list, matching the JSON ABI and the
/// guest-side validator.
pub const MAX_REMOVE_RULE_IDS: usize = 256;

/// Response decision: allow.
pub const DECISION_ALLOW: u8 = 0;
/// Response decision: block.
pub const DECISION_BLOCK: u8 = 1;

/// Errors produced while encoding a binary request.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WireError {
    /// A field does not fit the binary frame's `u16` length field.
    #[error("{field} of {len} bytes exceeds the {limit} byte binary frame limit")]
    FieldTooLong {
        field: &'static str,
        len: usize,
        limit: usize,
    },
}

/// Errors produced while decoding a binary response.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WireDecodeError {
    /// The frame is shorter than the fixed header.
    #[error("binary response frame of {0} bytes is shorter than its 8 byte header")]
    Short(usize),
    /// The frame magic or version is not binary v1.
    #[error("binary response frame has an unexpected magic or version")]
    BadHeader,
    /// The reason length does not match the frame length.
    #[error("binary response frame length does not match its header")]
    LengthMismatch,
    /// The decision byte is not allow/block.
    #[error("binary response frame carries unknown decision {0}")]
    UnknownDecision(u8),
}

/// A request encoded for the binary v1 protocol.
///
/// `head` holds the length prefix, the fixed header, the request line and the
/// header block. `body` is the inspected body, kept as refcounted [`Bytes`] so
/// no copy is made on the way to the socket.
#[derive(Debug)]
pub struct BinaryRequest {
    head: Vec<u8>,
    body: Option<Bytes>,
    body_len: usize,
}

impl BinaryRequest {
    /// Total frame size on the wire, including the 4-byte length prefix.
    pub fn frame_len(&self) -> usize {
        self.head.len() - 4 + self.body_len
    }

    /// Inspected body length.
    pub fn body_len(&self) -> usize {
        self.body_len
    }

    /// Frame prefix, fixed header, request line and header block.
    pub fn head(&self) -> &[u8] {
        &self.head
    }

    /// Raw inspected body bytes.
    pub fn body(&self) -> Option<&[u8]> {
        self.body.as_deref()
    }
}

/// Outcome of encoding a request for the binary protocol.
#[derive(Debug)]
pub enum WireBuild {
    /// A frame ready to write.
    Built {
        request: BinaryRequest,
        /// Number of body bytes actually handed to Coraza.
        inspected_bytes: usize,
        /// Whether the body was truncated to the inspection prefix.
        truncated: bool,
    },
    /// The policy rejected the request before evaluation.
    Reject { size: usize, limit: usize },
}

/// Encodes a request context into a binary v1 frame.
pub fn encode_request(
    ctx: &RequestContext,
    policy: &BodyInspectionPolicy,
) -> Result<WireBuild, WireError> {
    encode_request_with_rules(ctx, policy, &[])
}

/// Encodes a request context with an optional per-rule removal list.
///
/// The list is only written when non-empty; the frame then sets
/// [`FLAG_HAS_REMOVE_RULES`] and appends `u32 count` followed by `count`
/// big-endian ids after the header block and before the body. An empty list is
/// byte-for-byte identical to [`encode_request`].
pub fn encode_request_with_rules(
    ctx: &RequestContext,
    policy: &BodyInspectionPolicy,
    remove_rule_ids: &[u32],
) -> Result<WireBuild, WireError> {
    encode_request_view(&ctx.view(), policy, remove_rule_ids)
}

/// Encodes a borrowed request view into a binary v1 frame.
///
/// The URI is written directly into the frame head instead of being formatted
/// into a temporary `String`, and the body is sliced from the caller's
/// refcounted `Bytes` when one is available. This is the zero-copy path used
/// by the proxy hot path.
pub fn encode_request_view(
    view: &RequestView<'_>,
    policy: &BodyInspectionPolicy,
    remove_rule_ids: &[u32],
) -> Result<WireBuild, WireError> {
    let (body, inspected_bytes, original_size, truncated) =
        match select_body_parts(view.body, view.body_size, policy) {
            BodySelection::Inspect {
                body,
                inspected_bytes,
                original_size,
                truncated,
            } => (body, inspected_bytes, original_size, truncated),
            BodySelection::Reject { size, limit } => {
                return Ok(WireBuild::Reject { size, limit });
            }
        };

    let remove_rule_ids = &remove_rule_ids[..remove_rule_ids.len().min(MAX_REMOVE_RULE_IDS)];

    let method = view.method.as_str();
    let uri_len = uri_wire_len(view.uri);
    let version = view.http_version;
    let body_len = body.map(<[u8]>::len).unwrap_or(0);
    let body_size = body.map(<[u8]>::len).or(view.body_size).unwrap_or(0);

    let mut header_blob_len = 0usize;
    for (name, value) in view.headers.iter() {
        header_blob_len += 4 + name.as_str().len() + value.as_bytes().len();
    }
    let remove_len = if remove_rule_ids.is_empty() {
        0
    } else {
        4 + remove_rule_ids.len() * 4
    };

    let capacity = 4
        + REQUEST_HEADER_LEN
        + method.len()
        + uri_len
        + version.len()
        + header_blob_len
        + remove_len;
    let mut head = Vec::with_capacity(capacity);
    head.extend_from_slice(&[0u8; 4 + REQUEST_HEADER_LEN]);

    let mut flags = 0u8;
    // An empty body is indistinguishable from no body for CRS (the sidecar
    // only calls WriteRequestBody for non-empty bodies), so do not set the
    // flag for it.
    if body_len > 0 {
        flags |= FLAG_HAS_BODY;
    }
    if truncated {
        flags |= FLAG_TRUNCATED;
    }
    if remove_len > 0 {
        flags |= FLAG_HAS_REMOVE_RULES;
    }

    let h = &mut head[4..];
    h[0] = FRAME_MAGIC_BINARY;
    h[1] = WIRE_VERSION;
    h[2] = flags;
    put_u16(h, 4, method.len(), "method")?;
    put_u16(h, 6, uri_len, "uri")?;
    put_u16(h, 8, version.len(), "http_version")?;
    put_u16(h, 10, view.headers.len(), "header count")?;
    h[12..16].copy_from_slice(&(body_len as u32).to_be_bytes());
    h[16..20].copy_from_slice(&(body_size as u32).to_be_bytes());
    h[20..24].copy_from_slice(&(original_size.unwrap_or(0) as u32).to_be_bytes());
    h[24..28].copy_from_slice(&(header_blob_len as u32).to_be_bytes());

    head.extend_from_slice(method.as_bytes());
    write_uri(&mut head, view.uri);
    head.extend_from_slice(version.as_bytes());

    for (name, value) in view.headers.iter() {
        let name = name.as_str();
        // Mirrors the JSON builder: header values are lossy UTF-8, because the
        // Coraza ABI is string-based.
        let value = String::from_utf8_lossy(value.as_bytes());
        let value = value.as_bytes();
        let entry = head.len();
        head.extend_from_slice(&[0u8; 4]);
        put_u16(&mut head[entry..], 0, name.len(), "header name")?;
        put_u16(&mut head[entry..], 2, value.len(), "header value")?;
        head.extend_from_slice(name.as_bytes());
        head.extend_from_slice(value);
    }

    if remove_len > 0 {
        head.extend_from_slice(&(remove_rule_ids.len() as u32).to_be_bytes());
        for id in remove_rule_ids {
            head.extend_from_slice(&id.to_be_bytes());
        }
    }

    let frame_len = head.len() - 4 + body_len;
    head[0..4].copy_from_slice(&(frame_len as u32).to_be_bytes());

    // `Bytes::slice_ref` keeps the body zero-copy for the common case (the
    // whole request body is inspected) and still works for a truncated prefix.
    let body_bytes = if body_len == 0 {
        None
    } else {
        match (body, view.body_bytes) {
            (Some(selected), Some(full)) => Some(full.slice_ref(selected)),
            (Some(selected), None) => Some(Bytes::copy_from_slice(selected)),
            (None, _) => None,
        }
    };

    Ok(WireBuild::Built {
        request: BinaryRequest {
            head,
            body: body_bytes,
            body_len,
        },
        inspected_bytes,
        truncated,
    })
}

/// Length of the URI as written by `Uri`'s `Display` implementation.
fn uri_wire_len(uri: &hyper::Uri) -> usize {
    let mut len = 0;
    if let Some(scheme) = uri.scheme_str() {
        len += scheme.len() + 3;
    }
    if let Some(authority) = uri.authority() {
        len += authority.as_str().len();
    }
    if let Some(path_and_query) = uri.path_and_query() {
        len += path_and_query.as_str().len();
    }
    len
}

/// Writes the URI in the same form as `Uri`'s `Display` implementation.
fn write_uri(head: &mut Vec<u8>, uri: &hyper::Uri) {
    if let Some(scheme) = uri.scheme_str() {
        head.extend_from_slice(scheme.as_bytes());
        head.extend_from_slice(b"://");
    }
    if let Some(authority) = uri.authority() {
        head.extend_from_slice(authority.as_str().as_bytes());
    }
    if let Some(path_and_query) = uri.path_and_query() {
        head.extend_from_slice(path_and_query.as_str().as_bytes());
    }
}

fn put_u16(
    buf: &mut [u8],
    offset: usize,
    len: usize,
    field: &'static str,
) -> Result<(), WireError> {
    let value = u16::try_from(len).map_err(|_| WireError::FieldTooLong {
        field,
        len,
        limit: u16::MAX as usize,
    })?;
    buf[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
    Ok(())
}

/// A decoded binary response, borrowing the reason from the frame buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResponseView<'a> {
    /// [`DECISION_ALLOW`] or [`DECISION_BLOCK`].
    pub decision: u8,
    /// HTTP status the proxy should return for a block.
    pub status: u16,
    /// Raw reason bytes (empty for allow).
    pub reason: &'a [u8],
}

/// Decodes a binary v1 response frame, without its 4-byte length prefix.
pub fn decode_response(frame: &[u8]) -> Result<ResponseView<'_>, WireDecodeError> {
    if frame.len() < RESPONSE_HEADER_LEN {
        return Err(WireDecodeError::Short(frame.len()));
    }
    if frame[0] != FRAME_MAGIC_BINARY || frame[1] != WIRE_VERSION {
        return Err(WireDecodeError::BadHeader);
    }
    let status = u16::from_be_bytes([frame[4], frame[5]]);
    let reason_len = u16::from_be_bytes([frame[6], frame[7]]) as usize;
    if RESPONSE_HEADER_LEN + reason_len != frame.len() {
        return Err(WireDecodeError::LengthMismatch);
    }
    let decision = frame[2];
    if decision != DECISION_ALLOW && decision != DECISION_BLOCK {
        return Err(WireDecodeError::UnknownDecision(decision));
    }
    Ok(ResponseView {
        decision,
        status,
        reason: &frame[RESPONSE_HEADER_LEN..],
    })
}

/// A frame announcing binary protocol support, ready to write.
pub fn handshake_frame() -> [u8; 6] {
    [0, 0, 0, 2, FRAME_MAGIC_HANDSHAKE, WIRE_VERSION]
}

/// Returns the binary version announced by a handshake ack, if the frame is one.
pub fn decode_handshake(frame: &[u8]) -> Option<u8> {
    if frame.len() >= 2 && frame[0] == FRAME_MAGIC_HANDSHAKE {
        Some(frame[1])
    } else {
        None
    }
}

/// Returns the capability bits announced by a handshake ack.
///
/// A two-byte ack (the original v1 format) has no capabilities and reports
/// zero, which makes the client fall back to the baseline frame layout.
pub fn decode_handshake_capabilities(frame: &[u8]) -> u8 {
    if frame.len() >= 3 && frame[0] == FRAME_MAGIC_HANDSHAKE {
        frame[2]
    } else {
        0
    }
}

impl fmt::Display for ResponseView<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "decision={} status={} reason={}",
            self.decision,
            self.status,
            String::from_utf8_lossy(self.reason)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::waf::coraza_payload::build_payload;
    use hyper::{HeaderMap, Method, Uri};
    use std::net::IpAddr;

    fn context(uri: &str, body: Option<&[u8]>) -> RequestContext {
        let mut headers = HeaderMap::new();
        headers.insert("host", "example.test".parse().unwrap());
        headers.insert(
            "content-type",
            "application/x-www-form-urlencoded".parse().unwrap(),
        );
        RequestContext::new(
            "127.0.0.1".parse::<IpAddr>().unwrap(),
            Method::POST,
            uri.parse::<Uri>().unwrap(),
            headers,
            body.map(<[u8]>::len),
        )
        .with_body(body.map(Bytes::copy_from_slice))
    }

    fn built(ctx: &RequestContext) -> BinaryRequest {
        match encode_request(ctx, &BodyInspectionPolicy::default()).unwrap() {
            WireBuild::Built { request, .. } => request,
            WireBuild::Reject { .. } => panic!("default policy must not reject"),
        }
    }

    fn read_u16(buf: &[u8], offset: usize) -> u16 {
        u16::from_be_bytes([buf[offset], buf[offset + 1]])
    }

    fn read_u32(buf: &[u8], offset: usize) -> u32 {
        u32::from_be_bytes([
            buf[offset],
            buf[offset + 1],
            buf[offset + 2],
            buf[offset + 3],
        ])
    }

    #[test]
    fn encodes_request_header_and_body() {
        let body = b"name=world&ok=1";
        let ctx = context("/submit?q=1", Some(body));
        let req = built(&ctx);
        let head = req.head();
        assert_eq!(head[4], FRAME_MAGIC_BINARY);
        assert_eq!(head[5], WIRE_VERSION);
        assert_eq!(head[6] & FLAG_HAS_BODY, FLAG_HAS_BODY);
        assert_eq!(read_u32(head, 0) as usize, req.frame_len());
        assert_eq!(req.body(), Some(&body[..]));
        assert_eq!(req.body_len(), body.len());

        let method_len = read_u16(head, 8) as usize;
        let uri_len = read_u16(head, 10) as usize;
        let version_len = read_u16(head, 12) as usize;
        let header_count = read_u16(head, 14) as usize;
        let body_len = read_u32(head, 16) as usize;
        let body_size = read_u32(head, 20) as usize;
        let blob_len = read_u32(head, 28) as usize;
        assert_eq!(&head[32..32 + method_len], b"POST");
        assert_eq!(
            &head[32 + method_len..32 + method_len + uri_len],
            b"/submit?q=1"
        );
        assert_eq!(
            &head[32 + method_len + uri_len..32 + method_len + uri_len + version_len],
            ctx.http_version.as_bytes()
        );
        assert_eq!(header_count, 2);
        assert_eq!(body_len, body.len());
        assert_eq!(body_size, body.len());
        assert_eq!(
            32 + method_len + uri_len + version_len + blob_len + body_len,
            head.len() + body.len()
        );
    }

    #[test]
    fn binary_body_is_not_base64_encoded() {
        let raw = [0x00u8, 0xff, 0xfe, 0x01, 0x80];
        let req = built(&context("/grpc", Some(&raw)));
        assert_eq!(req.body(), Some(&raw[..]));
        assert_eq!(req.frame_len(), req.head().len() - 4 + raw.len());
    }

    #[test]
    fn matches_json_payload_semantics() {
        // The JSON envelope is the reference: the binary frame must carry the
        // same body bytes, sizes and header strings.
        let body = b"a=1&b=2";
        let ctx = context("/submit", Some(body));
        let json = build_payload(&ctx).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&json).unwrap();
        let req = built(&ctx);
        let head = req.head();

        assert_eq!(value["method"], "POST");
        assert_eq!(value["uri"], "/submit");
        assert_eq!(value["http_version"], ctx.http_version.as_str());
        assert_eq!(value["body_size"], body.len());
        assert_eq!(value["body_original_size"], body.len());
        assert_eq!(value["body"], "a=1&b=2");
        assert_eq!(req.body(), Some(&body[..]));
        assert_eq!(read_u32(head, 20) as usize, body.len());
        assert_eq!(read_u32(head, 24) as usize, body.len());
        assert_eq!(value["headers"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn truncation_sets_flag_and_original_size() {
        let policy = BodyInspectionPolicy {
            max_inspect_bytes: 4,
            oversize_action: crate::config::CorazaOversizeAction::ForwardUninspected,
        };
        let ctx = context("/submit", Some(b"0123456789"));
        let WireBuild::Built {
            request,
            inspected_bytes,
            truncated,
        } = encode_request(&ctx, &policy).unwrap()
        else {
            panic!("expected a built frame");
        };
        assert!(truncated);
        assert_eq!(inspected_bytes, 4);
        assert_eq!(request.body(), Some(&b"0123"[..]));
        assert_eq!(request.head()[6] & FLAG_TRUNCATED, FLAG_TRUNCATED);
        assert_eq!(read_u32(request.head(), 24) as usize, 10);
    }

    #[test]
    fn empty_body_is_encoded_as_no_body() {
        let ctx = context("/hello", Some(b""));
        let req = built(&ctx);
        assert_eq!(req.head()[6] & FLAG_HAS_BODY, 0);
        assert_eq!(req.body_len(), 0);
        assert_eq!(req.body(), None);
        assert_eq!(req.frame_len(), req.head().len() - 4);
    }

    #[test]
    fn rejects_oversized_bodies_under_reject_policy() {
        let policy = BodyInspectionPolicy {
            max_inspect_bytes: 4,
            oversize_action: crate::config::CorazaOversizeAction::Reject,
        };
        match encode_request(&context("/submit", Some(b"0123456789")), &policy).unwrap() {
            WireBuild::Reject { size, limit } => {
                assert_eq!(size, 10);
                assert_eq!(limit, 4);
            }
            WireBuild::Built { .. } => panic!("expected a rejection"),
        }
    }

    #[test]
    fn decodes_allow_and_block_responses() {
        let mut frame = vec![0u8; RESPONSE_HEADER_LEN];
        frame[0] = FRAME_MAGIC_BINARY;
        frame[1] = WIRE_VERSION;
        frame[2] = DECISION_ALLOW;
        let view = decode_response(&frame).unwrap();
        assert_eq!(view.decision, DECISION_ALLOW);
        assert!(view.reason.is_empty());

        frame[2] = DECISION_BLOCK;
        frame[4..6].copy_from_slice(&403u16.to_be_bytes());
        frame[6..8].copy_from_slice(&4u16.to_be_bytes());
        frame.extend_from_slice(b"nope");
        let view = decode_response(&frame).unwrap();
        assert_eq!(view.decision, DECISION_BLOCK);
        assert_eq!(view.status, 403);
        assert_eq!(view.reason, b"nope");
    }

    #[test]
    fn rejects_malformed_responses() {
        assert!(matches!(
            decode_response(&[0u8; 4]),
            Err(WireDecodeError::Short(4))
        ));

        let mut frame = vec![0u8; RESPONSE_HEADER_LEN];
        frame[0] = FRAME_MAGIC_BINARY;
        frame[1] = WIRE_VERSION + 1;
        assert_eq!(decode_response(&frame), Err(WireDecodeError::BadHeader));

        let mut frame = vec![0u8; RESPONSE_HEADER_LEN];
        frame[0] = FRAME_MAGIC_BINARY;
        frame[1] = WIRE_VERSION;
        frame[2] = DECISION_ALLOW;
        frame[6..8].copy_from_slice(&4u16.to_be_bytes());
        assert_eq!(
            decode_response(&frame),
            Err(WireDecodeError::LengthMismatch)
        );

        let mut frame = vec![0u8; RESPONSE_HEADER_LEN];
        frame[0] = FRAME_MAGIC_BINARY;
        frame[1] = WIRE_VERSION;
        frame[2] = 9;
        assert_eq!(
            decode_response(&frame),
            Err(WireDecodeError::UnknownDecision(9))
        );
    }

    #[test]
    fn handshake_round_trip() {
        let frame = handshake_frame();
        assert_eq!(read_u32(&frame, 0), 2);
        assert_eq!(decode_handshake(&frame[4..]), Some(WIRE_VERSION));
        assert_eq!(decode_handshake(b"{}"), None);
    }

    #[test]
    fn oversized_header_value_is_reported() {
        let mut headers = HeaderMap::new();
        let value = hyper::header::HeaderValue::from_bytes(&vec![b'a'; u16::MAX as usize + 1]);
        if let Ok(value) = value {
            headers.insert("x-big", value);
            let ctx = RequestContext::new(
                "127.0.0.1".parse::<IpAddr>().unwrap(),
                Method::GET,
                "/".parse::<Uri>().unwrap(),
                headers,
                None,
            );
            match encode_request(&ctx, &BodyInspectionPolicy::default()) {
                Err(WireError::FieldTooLong { field, .. }) => assert_eq!(field, "header value"),
                other => panic!("expected a field-too-long error, got {other:?}"),
            }
        }
    }

    #[test]
    fn view_encoder_matches_context_encoder() {
        let ctx = context("/submit?q=1", Some(b"a=1&b=2"));
        let view = ctx.view();
        let from_ctx =
            match encode_request_with_rules(&ctx, &BodyInspectionPolicy::default(), &[941100])
                .unwrap()
            {
                WireBuild::Built { request, .. } => request,
                WireBuild::Reject { .. } => panic!("default policy must not reject"),
            };
        let from_view = match encode_request_view(
            &view,
            &BodyInspectionPolicy::default(),
            &[941100],
        )
        .unwrap()
        {
            WireBuild::Built { request, .. } => request,
            WireBuild::Reject { .. } => panic!("default policy must not reject"),
        };
        assert_eq!(from_ctx.head(), from_view.head());
        assert_eq!(from_ctx.body(), from_view.body());
    }

    #[test]
    fn uri_wire_len_matches_display() {
        for raw in ["/", "/a?b=c", "http://example.test/x?y=1"] {
            let uri: hyper::Uri = raw.parse().unwrap();
            assert_eq!(uri_wire_len(&uri), uri.to_string().len());
            let mut buf = Vec::new();
            write_uri(&mut buf, &uri);
            assert_eq!(buf, uri.to_string().as_bytes());
        }
    }

    #[test]
    fn empty_remove_list_is_byte_identical() {
        let ctx = context("/submit", Some(b"a=1"));
        let plain = built(&ctx);
        let explicit =
            match encode_request_with_rules(&ctx, &BodyInspectionPolicy::default(), &[]).unwrap() {
                WireBuild::Built { request, .. } => request,
                WireBuild::Reject { .. } => panic!("default policy must not reject"),
            };
        assert_eq!(plain.head(), explicit.head());
        assert_eq!(plain.body(), explicit.body());
    }

    #[test]
    fn remove_list_is_appended_after_headers() {
        let body = b"a=1";
        let ctx = context("/submit", Some(body));
        let request = match encode_request_with_rules(
            &ctx,
            &BodyInspectionPolicy::default(),
            &[941100, 942200],
        )
        .unwrap()
        {
            WireBuild::Built { request, .. } => request,
            WireBuild::Reject { .. } => panic!("default policy must not reject"),
        };
        let head = request.head();
        assert_eq!(head[6] & FLAG_HAS_REMOVE_RULES, FLAG_HAS_REMOVE_RULES);
        let method_len = read_u16(head, 8) as usize;
        let uri_len = read_u16(head, 10) as usize;
        let version_len = read_u16(head, 12) as usize;
        let blob_len = read_u32(head, 28) as usize;
        let ids_at = 32 + method_len + uri_len + version_len + blob_len;
        assert_eq!(read_u32(head, ids_at), 2);
        assert_eq!(read_u32(head, ids_at + 4), 941100);
        assert_eq!(read_u32(head, ids_at + 8), 942200);
        // The ids section is part of the head, not the body.
        assert_eq!(request.body(), Some(&body[..]));
        assert_eq!(read_u32(head, 0) as usize, request.frame_len());
    }

    #[test]
    fn remove_list_is_bounded() {
        let ctx = context("/submit", Some(b"a=1"));
        let ids = vec![941100u32; MAX_REMOVE_RULE_IDS + 10];
        let request = match encode_request_with_rules(&ctx, &BodyInspectionPolicy::default(), &ids)
            .unwrap()
        {
            WireBuild::Built { request, .. } => request,
            WireBuild::Reject { .. } => panic!("default policy must not reject"),
        };
        let head = request.head();
        let method_len = read_u16(head, 8) as usize;
        let uri_len = read_u16(head, 10) as usize;
        let version_len = read_u16(head, 12) as usize;
        let blob_len = read_u32(head, 28) as usize;
        let ids_at = 32 + method_len + uri_len + version_len + blob_len;
        assert_eq!(read_u32(head, ids_at) as usize, MAX_REMOVE_RULE_IDS);
    }

    #[test]
    fn handshake_capabilities_are_optional() {
        let mut frame = vec![FRAME_MAGIC_HANDSHAKE, WIRE_VERSION];
        assert_eq!(decode_handshake_capabilities(&frame), 0);
        frame.push(CAP_BINARY_V1 | CAP_REMOVE_RULES);
        assert_eq!(
            decode_handshake_capabilities(&frame),
            CAP_BINARY_V1 | CAP_REMOVE_RULES
        );
        assert_eq!(decode_handshake_capabilities(b"{}"), 0);
    }
}
