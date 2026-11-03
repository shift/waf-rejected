//! Response (phases 3–5) inspection plumbing for the native engine.
//!
//! Coraza's outbound path is opt-in: response bodies are only inspected when
//! `SecResponseBodyAccess On` (and the response content type is processable),
//! while response *headers* are always available once `ProcessResponseHeaders`
//! runs. The pinned CRS 4.14 request bundle used by the reactor ships no
//! `RESPONSE-*` rule files, so enabling the response path never changes the
//! existing 505-rule request parity. It exists so a deployment can load
//! outbound rules into the same compiled [`Program`](super::ir::Program).
//!
//! This module only defines the input shape and the body-processor hooks. The
//! evaluator lives in [`RustEngine::evaluate_response`](super::RustEngine) so
//! it reuses the request engine's budget, transforms, operators, chains and
//! anomaly scoring instead of duplicating them.

use super::processors::{self, ProcessorLimits};

/// An upstream response as seen by the response phases.
#[derive(Debug, Clone, Copy)]
pub struct EngineResponse<'a> {
    /// HTTP status code, e.g. `200`.
    pub status: u16,
    /// Protocol string, e.g. `HTTP/1.1`.
    pub protocol: &'a str,
    /// Response headers in wire order.
    pub headers: &'a [(String, String)],
    /// Response body, when the caller captured it.
    pub body: Option<&'a [u8]>,
}

impl<'a> EngineResponse<'a> {
    /// A headers-only response.
    pub fn headers_only(status: u16, protocol: &'a str, headers: &'a [(String, String)]) -> Self {
        Self {
            status,
            protocol,
            headers,
            body: None,
        }
    }
}

/// Response inspection gating.
///
/// The defaults mirror Coraza's safe defaults: headers are inspected, the body
/// is not. Body inspection must be requested explicitly, and the body is
/// bounded so a huge upstream response cannot exhaust the per-request budget.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseConfig {
    /// Parse and expose `RESPONSE_BODY` / `RESPONSE_ARGS` / `RESPONSE_XML`.
    pub inspect_body: bool,
    /// Optional response body processor (`JSON`, `XML`, or `URLENCODED`).
    /// `None` exposes the raw body as `RESPONSE_BODY`, like Coraza.
    pub body_processor: Option<String>,
    /// Maximum body bytes handed to the processor.
    pub max_body_bytes: usize,
    /// Processor nesting/value bounds.
    pub processor_limits: ProcessorLimits,
}

impl Default for ResponseConfig {
    fn default() -> Self {
        Self {
            inspect_body: false,
            body_processor: None,
            max_body_bytes: 1024 * 1024,
            processor_limits: ProcessorLimits::default(),
        }
    }
}

impl ResponseConfig {
    /// Headers-only inspection (the default).
    pub fn headers_only() -> Self {
        Self::default()
    }

    /// Inspect the response body as-is.
    pub fn raw_body() -> Self {
        Self {
            inspect_body: true,
            ..Self::default()
        }
    }

    /// Inspect a JSON response body into `RESPONSE_ARGS`.
    pub fn json_body() -> Self {
        Self {
            inspect_body: true,
            body_processor: Some("JSON".to_string()),
            ..Self::default()
        }
    }

    /// Inspect an XML response body into `RESPONSE_XML`.
    pub fn xml_body() -> Self {
        Self {
            inspect_body: true,
            body_processor: Some("XML".to_string()),
            ..Self::default()
        }
    }
}

/// Flattened response body values for the response body processors.
#[derive(Debug, Clone, Default)]
pub struct ResponseBodyValues {
    /// `RESPONSE_ARGS` / `RESPONSE_XML` entries as `(key, value)`.
    pub entries: Vec<(String, Vec<u8>)>,
    /// Raw body for `RESPONSE_BODY` when no processor ran.
    pub raw: Option<Vec<u8>>,
}

/// Applies the configured body processor. Returns `Default` when body
/// inspection is off, and an empty result when the body is too large.
pub fn process_body(response: &EngineResponse<'_>, config: &ResponseConfig) -> ResponseBodyValues {
    if !config.inspect_body {
        return ResponseBodyValues::default();
    }
    let Some(body) = response.body else {
        return ResponseBodyValues::default();
    };
    if body.len() > config.max_body_bytes {
        // Coraza truncates at SecResponseBodyLimit; the native engine refuses
        // to inspect a partially captured body and exposes no values.
        return ResponseBodyValues::default();
    }
    let processor = config.body_processor.as_deref().unwrap_or("");
    if processor.eq_ignore_ascii_case("json") {
        return ResponseBodyValues {
            entries: processors::json::process(body, &config.processor_limits).unwrap_or_default(),
            raw: None,
        };
    }
    if processor.eq_ignore_ascii_case("xml") {
        let values = processors::xml::process(body).unwrap_or_default();
        let mut entries = Vec::with_capacity(values.attributes.len() + values.content.len());
        for value in values.attributes {
            entries.push(("//@*".to_string(), value));
        }
        for value in values.content {
            entries.push(("/*".to_string(), value));
        }
        return ResponseBodyValues { entries, raw: None };
    }
    if processor.eq_ignore_ascii_case("urlencoded") {
        let entries = crate::waf::rust_engine::request::parse_query(body, b'&')
            .into_iter()
            .map(|entry| (entry.key.into_owned(), entry.value.into_owned()))
            .collect();
        return ResponseBodyValues { entries, raw: None };
    }
    ResponseBodyValues {
        entries: Vec::new(),
        raw: Some(body.to_vec()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_inspection_is_opt_in() {
        let response = EngineResponse {
            status: 200,
            protocol: "HTTP/1.1",
            headers: &[],
            body: Some(b"{\"a\":1}"),
        };
        assert!(process_body(&response, &ResponseConfig::headers_only())
            .raw
            .is_none());
        let values = process_body(&response, &ResponseConfig::json_body());
        assert_eq!(values.entries, vec![("json.a".to_string(), b"1".to_vec())]);
        let raw = process_body(&response, &ResponseConfig::raw_body());
        assert_eq!(raw.raw.as_deref(), Some(b"{\"a\":1}".as_slice()));
    }

    #[test]
    fn oversized_bodies_are_not_inspected() {
        let response = EngineResponse {
            status: 200,
            protocol: "HTTP/1.1",
            headers: &[],
            body: Some(b"abcdef"),
        };
        let config = ResponseConfig {
            max_body_bytes: 3,
            ..ResponseConfig::raw_body()
        };
        assert!(process_body(&response, &config).raw.is_none());
    }
}
