//! Shared request payload serialisation for Coraza backends.
//!
//! The WASI reactor and the native sidecar use the same JSON envelope, so the
//! two backends can be compared directly and the sidecar can be swapped in
//! without changing request construction.

use base64::Engine as _;

use crate::config::{CorazaOversizeAction, WafCorazaConfig};
use crate::waf::RequestContext;

/// Payload `body_encoding` value for a body that is valid UTF-8.
pub const BODY_ENCODING_UTF8: &str = "utf8";
/// Payload `body_encoding` value for a base64-encoded binary body.
pub const BODY_ENCODING_BASE64: &str = "base64";

/// Opt-in body-size policy applied before the payload is handed to Coraza.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BodyInspectionPolicy {
    /// Maximum body bytes inspected. `0` means inspect the whole body.
    pub max_inspect_bytes: usize,
    /// What to do when the body is larger than `max_inspect_bytes`.
    pub oversize_action: CorazaOversizeAction,
}

impl Default for BodyInspectionPolicy {
    fn default() -> Self {
        Self {
            max_inspect_bytes: 0,
            oversize_action: CorazaOversizeAction::InspectAll,
        }
    }
}

impl From<&WafCorazaConfig> for BodyInspectionPolicy {
    fn from(config: &WafCorazaConfig) -> Self {
        Self {
            max_inspect_bytes: config.max_inspect_bytes,
            oversize_action: config.oversize_action,
        }
    }
}

/// Result of applying the body policy while building a payload.
#[derive(Debug)]
pub enum PayloadBuild {
    /// A payload ready for evaluation.
    Built {
        payload: Vec<u8>,
        /// Number of body bytes actually handed to Coraza.
        inspected_bytes: usize,
        /// Whether the body was truncated to the inspection prefix.
        truncated: bool,
    },
    /// The policy rejected the request before evaluation.
    Reject { size: usize, limit: usize },
}

/// Body selected for inspection after applying [`BodyInspectionPolicy`].
///
/// Shared by the JSON and binary encoders so both hand Coraza exactly the same
/// bytes and report the same inspected size.
#[derive(Debug)]
pub enum BodySelection<'a> {
    /// Body bytes to inspect (empty when the request has no body).
    Inspect {
        body: Option<&'a [u8]>,
        /// Number of body bytes actually handed to Coraza.
        inspected_bytes: usize,
        /// Full request body length before truncation, when known.
        original_size: Option<usize>,
        /// Whether the body was truncated to the inspection prefix.
        truncated: bool,
    },
    /// The policy rejected the request before evaluation.
    Reject { size: usize, limit: usize },
}

/// Applies the body-size policy to a request context.
pub fn select_body<'a>(
    ctx: &'a RequestContext,
    policy: &BodyInspectionPolicy,
) -> BodySelection<'a> {
    let full_body = ctx.body.as_deref();
    let original_size = full_body.map(<[u8]>::len).or(ctx.body_size);

    let mut inspected = full_body;
    let mut truncated = false;
    if policy.max_inspect_bytes > 0 {
        if let Some(bytes) = full_body {
            if bytes.len() > policy.max_inspect_bytes {
                match policy.oversize_action {
                    CorazaOversizeAction::InspectAll => {}
                    CorazaOversizeAction::ForwardUninspected => {
                        inspected = Some(&bytes[..policy.max_inspect_bytes]);
                        truncated = true;
                    }
                    CorazaOversizeAction::Reject => {
                        return BodySelection::Reject {
                            size: bytes.len(),
                            limit: policy.max_inspect_bytes,
                        };
                    }
                }
            }
        }
    }

    BodySelection::Inspect {
        body: inspected,
        inspected_bytes: inspected.map(<[u8]>::len).unwrap_or(0),
        original_size,
        truncated,
    }
}

/// Magic number at the start of the compact binary request envelope.
pub const BINARY_MAGIC: u32 = 0xCAFE_BABE;
/// Version of the compact binary request envelope.
pub const BINARY_VERSION: u16 = 1;

/// Hard cap on rule ids accepted in the binary envelope. Matches the guest's
/// `maxRemoveRuleIDs` and `crate::waf::prefilter::MAX_REMOVE_RULE_IDS`.
pub const MAX_BINARY_REMOVE_RULE_IDS: usize = 256;

/// Serialises the request context into the compact binary envelope.
///
/// Layout (all integers little-endian):
///
/// ```text
/// magic u32 | version u16 | flags u16
/// method_len u32 | uri_len u32 | http_version_len u32
/// body_len u32 | header_count u32 | remove_rule_count u32
/// method | uri | http_version | body
/// header_count * (name_len u32 | name | value_len u32 | value)
/// remove_rule_count * u32
/// ```
///
/// The body is sent as raw bytes (no base64), so binary bodies survive
/// inspection without an encode/decode round trip. `flags` bit 0 is set to
/// mark the envelope as binary; the guest uses the magic to distinguish it
/// from the legacy JSON payload.
pub fn build_binary_payload_with_policy_and_rules(
    ctx: &RequestContext,
    policy: &BodyInspectionPolicy,
    remove_rule_ids: &[u32],
) -> Result<PayloadBuild, serde_json::Error> {
    let (inspected, _original_size, truncated) = match select_body(ctx, policy) {
        BodySelection::Inspect {
            body,
            original_size,
            truncated,
            ..
        } => (body, original_size, truncated),
        BodySelection::Reject { size, limit } => {
            return Ok(PayloadBuild::Reject { size, limit });
        }
    };

    let method = ctx.method.as_str().as_bytes();
    let uri = ctx.uri.to_string();
    let uri = uri.as_bytes();
    let http_version = ctx.http_version.as_bytes();
    let body = inspected.unwrap_or(&[]);
    let inspected_bytes = body.len();

    let header_count = ctx.headers.len();
    let remove_count = remove_rule_ids.len().min(MAX_BINARY_REMOVE_RULE_IDS);

    let mut out = Vec::with_capacity(
        32 + method.len()
            + uri.len()
            + http_version.len()
            + body.len()
            + header_count * 16
            + remove_count * 4,
    );
    out.extend_from_slice(&BINARY_MAGIC.to_le_bytes());
    out.extend_from_slice(&BINARY_VERSION.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes()); // flags: binary
    out.extend_from_slice(&(method.len() as u32).to_le_bytes());
    out.extend_from_slice(&(uri.len() as u32).to_le_bytes());
    out.extend_from_slice(&(http_version.len() as u32).to_le_bytes());
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(&(header_count as u32).to_le_bytes());
    out.extend_from_slice(&(remove_count as u32).to_le_bytes());
    out.extend_from_slice(method);
    out.extend_from_slice(uri);
    out.extend_from_slice(http_version);
    out.extend_from_slice(body);
    for (name, value) in ctx.headers.iter() {
        let name = name.as_str().as_bytes();
        let value = value.as_bytes();
        out.extend_from_slice(&(name.len() as u32).to_le_bytes());
        out.extend_from_slice(name);
        out.extend_from_slice(&(value.len() as u32).to_le_bytes());
        out.extend_from_slice(value);
    }
    for id in &remove_rule_ids[..remove_count] {
        out.extend_from_slice(&id.to_le_bytes());
    }

    Ok(PayloadBuild::Built {
        payload: out,
        inspected_bytes,
        truncated,
    })
}

/// Serialises the request context into the reactor/sidecar JSON payload using
/// the default (inspect-all) policy.
pub fn build_payload(ctx: &RequestContext) -> Result<Vec<u8>, serde_json::Error> {
    match build_payload_with_policy(ctx, &BodyInspectionPolicy::default())? {
        PayloadBuild::Built { payload, .. } => Ok(payload),
        // The default policy never rejects.
        PayloadBuild::Reject { .. } => unreachable!("inspect-all never rejects"),
    }
}

/// Serialises the request context, applying an explicit body-size policy.
///
/// Bodies that are valid UTF-8 keep the `utf8` fast path. Binary bodies
/// (protobuf/gRPC, msgpack, compressed payloads) are base64-encoded and marked
/// `base64` so invalid UTF-8 bytes are never replaced with U+FFFD before
/// inspection.
///
/// For `forward-uninspected`, only the first `max_inspect_bytes` bytes are
/// sent as `body`; `body_size` is the length of that inspected prefix (the
/// guest requires it to match the decoded body) and `body_original_size`
/// retains the full request body length. The rest of the body is forwarded
/// upstream without CRS body inspection.
pub fn build_payload_with_policy(
    ctx: &RequestContext,
    policy: &BodyInspectionPolicy,
) -> Result<PayloadBuild, serde_json::Error> {
    build_payload_with_policy_and_rules(ctx, policy, &[])
}

/// Serialises the request context with an explicit per-rule removal list.
///
/// `remove_rule_ids` is the bounded, pre-validated set of gated rules that
/// provably cannot match this request. An empty list produces exactly the same
/// bytes as [`build_payload_with_policy`], so the `off` path is unchanged.
pub fn build_payload_with_policy_and_rules(
    ctx: &RequestContext,
    policy: &BodyInspectionPolicy,
    remove_rule_ids: &[u32],
) -> Result<PayloadBuild, serde_json::Error> {
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

    let (inspected, original_size, truncated) = match select_body(ctx, policy) {
        BodySelection::Inspect {
            body,
            original_size,
            truncated,
            ..
        } => (body, original_size, truncated),
        BodySelection::Reject { size, limit } => {
            return Ok(PayloadBuild::Reject { size, limit });
        }
    };

    let (body, body_encoding) = match inspected {
        None => (None, BODY_ENCODING_UTF8),
        Some(bytes) => match std::str::from_utf8(bytes) {
            Ok(text) => (Some(text.to_string()), BODY_ENCODING_UTF8),
            Err(_) => (
                Some(base64::engine::general_purpose::STANDARD.encode(bytes)),
                BODY_ENCODING_BASE64,
            ),
        },
    };
    // The wire size is the raw body length actually sent, not the encoded JSON
    // string length. For a truncated body this is the inspected prefix length.
    let body_size = inspected.map(<[u8]>::len).or(ctx.body_size);
    let inspected_bytes = inspected.map(<[u8]>::len).unwrap_or(0);

    let mut payload = serde_json::json!({
        "method": ctx.method.as_str(),
        "uri": ctx.uri.to_string(),
        "http_version": ctx.http_version,
        "headers": headers,
        "body_size": body_size,
        "body_original_size": original_size,
        "body_encoding": body_encoding,
        "body": body,
    });
    if !remove_rule_ids.is_empty() {
        payload["remove_rule_ids"] = serde_json::json!(remove_rule_ids);
    }

    Ok(PayloadBuild::Built {
        payload: serde_json::to_vec(&payload)?,
        inspected_bytes,
        truncated,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use hyper::{HeaderMap, Method, Uri};
    use std::net::IpAddr;

    fn context() -> RequestContext {
        let mut headers = HeaderMap::new();
        headers.insert("host", "example.test".parse().unwrap());
        RequestContext::new(
            "127.0.0.1".parse::<IpAddr>().unwrap(),
            Method::POST,
            "/submit".parse::<Uri>().unwrap(),
            headers,
            Some(3),
        )
        .with_body(Some(Bytes::from_static(b"a=1")))
    }

    #[test]
    fn empty_remove_list_keeps_the_legacy_payload() {
        let ctx = context();
        let policy = BodyInspectionPolicy::default();
        let plain = match build_payload_with_policy(&ctx, &policy).unwrap() {
            PayloadBuild::Built { payload, .. } => payload,
            PayloadBuild::Reject { .. } => panic!("default policy must not reject"),
        };
        let with_rules = match build_payload_with_policy_and_rules(&ctx, &policy, &[]).unwrap() {
            PayloadBuild::Built { payload, .. } => payload,
            PayloadBuild::Reject { .. } => panic!("default policy must not reject"),
        };
        assert_eq!(plain, with_rules);
        let value: serde_json::Value = serde_json::from_slice(&plain).unwrap();
        assert!(value.get("remove_rule_ids").is_none());
    }

    #[test]
    fn remove_list_is_serialised_when_present() {
        let ctx = context();
        let policy = BodyInspectionPolicy::default();
        let payload =
            match build_payload_with_policy_and_rules(&ctx, &policy, &[941100, 942200]).unwrap() {
                PayloadBuild::Built { payload, .. } => payload,
                PayloadBuild::Reject { .. } => panic!("default policy must not reject"),
            };
        let value: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(
            value["remove_rule_ids"],
            serde_json::json!([941100, 942200])
        );
    }

    #[test]
    fn binary_payload_round_trips_fields_and_keeps_raw_body() {
        let ctx = context();
        let policy = BodyInspectionPolicy::default();
        let payload =
            match build_binary_payload_with_policy_and_rules(&ctx, &policy, &[941100, 942200])
                .unwrap()
            {
                PayloadBuild::Built {
                    payload,
                    inspected_bytes,
                    truncated,
                } => {
                    assert_eq!(inspected_bytes, 3);
                    assert!(!truncated);
                    payload
                }
                PayloadBuild::Reject { .. } => panic!("default policy must not reject"),
            };
        assert_eq!(&payload[0..4], &BINARY_MAGIC.to_le_bytes());
        assert_eq!(&payload[4..6], &BINARY_VERSION.to_le_bytes());
        assert_eq!(&payload[6..8], &1u16.to_le_bytes());
        let method_len = u32::from_le_bytes(payload[8..12].try_into().unwrap()) as usize;
        let uri_len = u32::from_le_bytes(payload[12..16].try_into().unwrap()) as usize;
        let body_len = u32::from_le_bytes(payload[20..24].try_into().unwrap()) as usize;
        assert_eq!(method_len, 4); // POST
        assert_eq!(uri_len, 7); // /submit
        assert_eq!(body_len, 3); // a=1
        let body_off = 32 + method_len + uri_len + 3; // http_version "1.1"
        assert_eq!(&payload[body_off..body_off + body_len], b"a=1");
    }

    #[test]
    fn binary_payload_encodes_binary_bodies_without_base64() {
        let mut headers = HeaderMap::new();
        headers.insert("host", "example.test".parse().unwrap());
        let ctx = RequestContext::new(
            "127.0.0.1".parse::<IpAddr>().unwrap(),
            Method::POST,
            "/search".parse::<Uri>().unwrap(),
            headers,
            Some(4),
        )
        .with_body(Some(Bytes::from_static(b"\xff\xfeq=1")));
        let payload = match build_binary_payload_with_policy_and_rules(
            &ctx,
            &BodyInspectionPolicy::default(),
            &[],
        )
        .unwrap()
        {
            PayloadBuild::Built { payload, .. } => payload,
            PayloadBuild::Reject { .. } => panic!("default policy must not reject"),
        };
        assert!(payload.windows(5).any(|w| w == b"\xff\xfeq=1"));
    }
}
