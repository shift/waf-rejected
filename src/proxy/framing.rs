//! Request framing validation.
//!
//! Rejects ambiguous HTTP request framing that can be used for request
//! smuggling (CL/TE confusion, conflicting Content-Length values, malformed
//! lengths and unsupported transfer codings). The check is deliberately
//! strict: any ambiguity is rejected before a request body is read.
//!
//! HTTP/2 and HTTP/3 use length-delimited DATA frames instead of
//! `Transfer-Encoding`, so their ingress rejects `Transfer-Encoding` and every
//! connection-specific header field (RFC 9113 §8.2.2) before the shared
//! HTTP/1.1 framing checks run. Trailer blocks are validated separately because
//! they are read after the body.

use std::fmt;

use http::header::{CONTENT_LENGTH, TRANSFER_ENCODING};
use http::HeaderMap;

/// Header fields that are scoped to a single connection and are forbidden in
/// HTTP/2 and HTTP/3 (and in trailers).
const CONNECTION_SPECIFIC_HEADERS: [&str; 4] =
    ["connection", "keep-alive", "proxy-connection", "upgrade"];

/// Reason a request's framing was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FramingError {
    /// Both `Content-Length` and `Transfer-Encoding` were supplied.
    ContentLengthAndTransferEncoding,
    /// Content-Length fields or list members had different values.
    ConflictingContentLengthValues,
    /// A `Content-Length` value was empty, non-numeric or out of range.
    InvalidContentLength,
    /// `Transfer-Encoding` was present but was not exactly one `chunked` token.
    InvalidTransferEncoding,
    /// `Transfer-Encoding` is never valid on HTTP/2 or HTTP/3.
    TransferEncodingNotAllowed,
    /// `TE` on HTTP/2 or HTTP/3 contained a value other than `trailers`.
    InvalidTeHeader,
    /// A connection-specific header field was supplied on HTTP/2 or HTTP/3.
    ConnectionSpecificHeader(&'static str),
    /// A framing-related field was supplied in a trailer block.
    ForbiddenTrailerField(&'static str),
    /// The buffered body length did not match the declared `Content-Length`.
    ContentLengthMismatch { declared: u64, actual: u64 },
}

impl fmt::Display for FramingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ContentLengthAndTransferEncoding => {
                f.write_str("request has both Content-Length and Transfer-Encoding")
            }
            Self::ConflictingContentLengthValues => {
                f.write_str("request has conflicting Content-Length values")
            }
            Self::InvalidContentLength => f.write_str("request has an invalid Content-Length"),
            Self::InvalidTransferEncoding => {
                f.write_str("request has an invalid Transfer-Encoding")
            }
            Self::TransferEncodingNotAllowed => {
                f.write_str("Transfer-Encoding is not allowed on HTTP/2 or HTTP/3")
            }
            Self::InvalidTeHeader => {
                f.write_str("TE is only allowed with the value 'trailers' on HTTP/2 or HTTP/3")
            }
            Self::ConnectionSpecificHeader(name) => {
                write!(f, "connection-specific header '{name}' is not allowed")
            }
            Self::ForbiddenTrailerField(name) => {
                write!(
                    f,
                    "framing-related field '{name}' is not allowed in trailers"
                )
            }
            Self::ContentLengthMismatch { declared, actual } => write!(
                f,
                "Content-Length declares {declared} bytes but the body has {actual}"
            ),
        }
    }
}

impl std::error::Error for FramingError {}

/// HTTP version used to select protocol-specific framing rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FramingVersion {
    Http10,
    Http11,
    Http2,
    Http3,
}

impl FramingVersion {
    /// Map the proxy's wire version string (`"1.0"`, `"1.1"`, `"2"`, `"3"`).
    pub fn from_wire(version: &str) -> Self {
        match version {
            "2" => Self::Http2,
            "3" => Self::Http3,
            "1.0" => Self::Http10,
            _ => Self::Http11,
        }
    }

    fn is_multiplexed(self) -> bool {
        matches!(self, Self::Http2 | Self::Http3)
    }
}

/// Validate request framing for a specific HTTP version.
///
/// HTTP/2 and HTTP/3 reject `Transfer-Encoding` and connection-specific
/// headers, then run the same Content-Length checks as HTTP/1.x. HTTP/1.x keeps
/// its existing semantics: one unambiguous `Content-Length`, or a single
/// `Transfer-Encoding: chunked`.
pub fn validate_request_framing_for_version(
    headers: &HeaderMap,
    version: FramingVersion,
) -> Result<(), FramingError> {
    if version.is_multiplexed() {
        validate_connection_specific_headers(headers)?;
        if headers.contains_key(TRANSFER_ENCODING) {
            return Err(FramingError::TransferEncodingNotAllowed);
        }
        validate_te_header(headers)?;
    }

    if version == FramingVersion::Http10 && headers.contains_key(TRANSFER_ENCODING) {
        // HTTP/1.0 does not define the chunked transfer coding.
        return Err(FramingError::InvalidTransferEncoding);
    }

    validate_request_framing(headers)
}

/// Validate HTTP/1.x request framing headers.
///
/// Accepts requests with neither header, an unambiguous `Content-Length`
/// (including repeated, identical field values), or a single
/// `Transfer-Encoding: chunked`. Everything else is rejected as ambiguous or
/// malformed.
pub fn validate_request_framing(headers: &HeaderMap) -> Result<(), FramingError> {
    let has_content_length = headers.contains_key(CONTENT_LENGTH);
    let has_transfer_encoding = headers.contains_key(TRANSFER_ENCODING);

    if has_content_length && has_transfer_encoding {
        return Err(FramingError::ContentLengthAndTransferEncoding);
    }

    if has_transfer_encoding {
        validate_transfer_encoding(headers)?;
    }

    if has_content_length {
        validate_content_length(headers)?;
    }

    Ok(())
}

/// Validate a request trailer block.
///
/// Trailers must not carry framing or connection metadata: only end-to-end
/// fields such as gRPC `grpc-status` / `grpc-message` are forwarded.
pub fn validate_request_trailers(trailers: &HeaderMap) -> Result<(), FramingError> {
    // Trailers are end-to-end metadata only. Framing, connection, host and
    // representation headers must never appear there: an upstream that merges
    // trailers into its request view could otherwise be influenced after the
    // WAF has inspected the request head.
    const FORBIDDEN_TRAILER_FIELDS: [&str; 11] = [
        "content-length",
        "transfer-encoding",
        "trailer",
        "connection",
        "keep-alive",
        "proxy-connection",
        "upgrade",
        "host",
        "te",
        "content-encoding",
        "content-type",
    ];
    for name in FORBIDDEN_TRAILER_FIELDS {
        if trailers.contains_key(name) {
            return Err(FramingError::ForbiddenTrailerField(name));
        }
    }
    Ok(())
}

/// Compare the buffered body length with the declared `Content-Length`.
///
/// An absent `Content-Length` is valid (HTTP/2 and HTTP/3 commonly omit it);
/// a present value must match the bytes actually received. Callers run this
/// before decompression, because `Content-Length` describes the encoded body.
pub fn reconcile_content_length(headers: &HeaderMap, actual: usize) -> Result<(), FramingError> {
    let Some(declared) = declared_content_length(headers)? else {
        return Ok(());
    };
    let actual = actual as u64;
    if declared != actual {
        return Err(FramingError::ContentLengthMismatch { declared, actual });
    }
    Ok(())
}

fn validate_connection_specific_headers(headers: &HeaderMap) -> Result<(), FramingError> {
    for name in CONNECTION_SPECIFIC_HEADERS {
        if headers.contains_key(name) {
            return Err(FramingError::ConnectionSpecificHeader(name));
        }
    }
    Ok(())
}

fn validate_content_length(headers: &HeaderMap) -> Result<(), FramingError> {
    match declared_content_length(headers)? {
        Some(_) => Ok(()),
        None => Err(FramingError::InvalidContentLength),
    }
}

/// Parse the unambiguous `Content-Length` value, if present.
///
/// RFC 9112 permits repeated Content-Length fields only when every value is the
/// same decimal number. Identical duplicates are accepted; any disagreement is
/// rejected as conflicting. Every byte must be an ASCII digit: Rust's integer
/// parser would otherwise accept a leading `+`, which HTTP/1.1 peers reject.
fn declared_content_length(headers: &HeaderMap) -> Result<Option<u64>, FramingError> {
    let mut parsed = None;

    for header in headers.get_all(CONTENT_LENGTH) {
        let value = header
            .to_str()
            .map_err(|_| FramingError::InvalidContentLength)?;
        for part in value.split(',') {
            let part = part.trim();
            if part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(FramingError::InvalidContentLength);
            }
            let value = part
                .parse::<u64>()
                .map_err(|_| FramingError::InvalidContentLength)?;
            if let Some(previous) = parsed {
                if previous != value {
                    return Err(FramingError::ConflictingContentLengthValues);
                }
            } else {
                parsed = Some(value);
            }
        }
    }

    Ok(parsed)
}

fn validate_te_header(headers: &HeaderMap) -> Result<(), FramingError> {
    for header in headers.get_all("te") {
        let value = header.to_str().map_err(|_| FramingError::InvalidTeHeader)?;
        for token in value.split(',') {
            if !token.trim().eq_ignore_ascii_case("trailers") {
                return Err(FramingError::InvalidTeHeader);
            }
        }
    }
    Ok(())
}

fn validate_transfer_encoding(headers: &HeaderMap) -> Result<(), FramingError> {
    let mut values = headers.get_all(TRANSFER_ENCODING).iter();
    let first = values
        .next()
        .ok_or(FramingError::InvalidTransferEncoding)?
        .to_str()
        .map_err(|_| FramingError::InvalidTransferEncoding)?;

    // Multiple Transfer-Encoding header fields are not accepted.
    if values.next().is_some() {
        return Err(FramingError::InvalidTransferEncoding);
    }

    let mut tokens = first.split(',');
    let token = tokens
        .next()
        .map(str::trim)
        .ok_or(FramingError::InvalidTransferEncoding)?;

    // Exactly one token, and it must be `chunked`. This also rejects
    // `gzip, chunked`, `chunked, chunked` and token parameters.
    if tokens.next().is_some() || !token.eq_ignore_ascii_case("chunked") {
        return Err(FramingError::InvalidTransferEncoding);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::header::{HeaderName, HeaderValue};
    use http::HeaderMap;

    fn headers(values: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in values {
            map.append(
                HeaderName::from_bytes(name.as_bytes()).expect("valid header name"),
                HeaderValue::from_str(value).expect("valid header value"),
            );
        }
        map
    }

    #[test]
    fn accepts_no_framing_headers() {
        assert_eq!(validate_request_framing(&HeaderMap::new()), Ok(()));
    }

    #[test]
    fn accepts_single_content_length() {
        assert_eq!(
            validate_request_framing(&headers(&[("content-length", "42")])),
            Ok(())
        );
    }

    #[test]
    fn accepts_single_chunked_transfer_encoding() {
        assert_eq!(
            validate_request_framing(&headers(&[("transfer-encoding", "chunked")])),
            Ok(())
        );
        assert_eq!(
            validate_request_framing(&headers(&[("transfer-encoding", "Chunked")])),
            Ok(())
        );
    }

    #[test]
    fn rejects_content_length_with_transfer_encoding() {
        assert_eq!(
            validate_request_framing(&headers(&[
                ("content-length", "5"),
                ("transfer-encoding", "chunked"),
            ])),
            Err(FramingError::ContentLengthAndTransferEncoding)
        );
    }

    #[test]
    fn accepts_identical_duplicate_content_length_headers() {
        assert_eq!(
            validate_request_framing(&headers(&[
                ("content-length", "5"),
                ("content-length", "5"),
            ])),
            Ok(())
        );
    }

    #[test]
    fn rejects_conflicting_duplicate_content_length_headers() {
        assert_eq!(
            validate_request_framing(&headers(&[
                ("content-length", "5"),
                ("content-length", "6"),
            ])),
            Err(FramingError::ConflictingContentLengthValues)
        );
    }

    #[test]
    fn rejects_conflicting_content_length_list() {
        assert_eq!(
            validate_request_framing(&headers(&[("content-length", "5, 7")])),
            Err(FramingError::ConflictingContentLengthValues)
        );
    }

    #[test]
    fn accepts_identical_content_length_list() {
        assert_eq!(
            validate_request_framing(&headers(&[("content-length", "5, 5")])),
            Ok(())
        );
    }

    #[test]
    fn rejects_invalid_content_length() {
        for value in ["", "abc", "-1", "1.5", "0x10", "5,", ",5"] {
            assert_eq!(
                validate_request_framing(&headers(&[("content-length", value)])),
                Err(FramingError::InvalidContentLength),
                "value {value:?} should be rejected"
            );
        }
    }

    #[test]
    fn rejects_prefixed_content_length() {
        for value in ["+5", "+0", "  +5"] {
            assert_eq!(
                validate_request_framing(&headers(&[("content-length", value)])),
                Err(FramingError::InvalidContentLength),
                "value {value:?} should be rejected"
            );
        }
    }

    #[test]
    fn http10_rejects_transfer_encoding() {
        assert_eq!(
            validate_request_framing_for_version(
                &headers(&[("transfer-encoding", "chunked")]),
                FramingVersion::Http10,
            ),
            Err(FramingError::InvalidTransferEncoding)
        );
    }

    #[test]
    fn rejects_invalid_transfer_encoding() {
        for value in [
            "gzip",
            "chunked, gzip",
            "gzip, chunked",
            "chunked, chunked",
            "",
        ] {
            assert_eq!(
                validate_request_framing(&headers(&[("transfer-encoding", value)])),
                Err(FramingError::InvalidTransferEncoding),
                "value {value:?} should be rejected"
            );
        }
    }

    #[test]
    fn rejects_multiple_transfer_encoding_headers() {
        assert_eq!(
            validate_request_framing(&headers(&[
                ("transfer-encoding", "chunked"),
                ("transfer-encoding", "chunked"),
            ])),
            Err(FramingError::InvalidTransferEncoding)
        );
    }

    #[test]
    fn http1_allows_connection_specific_and_chunked_headers() {
        let request = headers(&[
            ("connection", "keep-alive"),
            ("keep-alive", "timeout=5"),
            ("proxy-connection", "keep-alive"),
            ("upgrade", "websocket"),
            ("transfer-encoding", "chunked"),
        ]);
        assert_eq!(
            validate_request_framing_for_version(&request, FramingVersion::Http11),
            Ok(())
        );
    }

    #[test]
    fn http2_and_http3_reject_transfer_encoding() {
        for version in [FramingVersion::Http2, FramingVersion::Http3] {
            assert_eq!(
                validate_request_framing_for_version(
                    &headers(&[("transfer-encoding", "chunked")]),
                    version,
                ),
                Err(FramingError::TransferEncodingNotAllowed)
            );
        }
    }

    #[test]
    fn http2_and_http3_reject_connection_specific_headers() {
        for version in [FramingVersion::Http2, FramingVersion::Http3] {
            for name in CONNECTION_SPECIFIC_HEADERS {
                assert_eq!(
                    validate_request_framing_for_version(
                        &headers(&[(name, "keep-alive")]),
                        version
                    ),
                    Err(FramingError::ConnectionSpecificHeader(name))
                );
            }
        }
    }

    #[test]
    fn http2_and_http3_validate_content_length() {
        for version in [FramingVersion::Http2, FramingVersion::Http3] {
            assert_eq!(
                validate_request_framing_for_version(&headers(&[("content-length", "5")]), version,),
                Ok(())
            );
            assert_eq!(
                validate_request_framing_for_version(
                    &headers(&[("content-length", "5"), ("content-length", "5")]),
                    version,
                ),
                Ok(())
            );
            assert_eq!(
                validate_request_framing_for_version(
                    &headers(&[("content-length", "5"), ("content-length", "6")]),
                    version,
                ),
                Err(FramingError::ConflictingContentLengthValues)
            );
            assert_eq!(
                validate_request_framing_for_version(
                    &headers(&[("content-length", "not-a-number")]),
                    version,
                ),
                Err(FramingError::InvalidContentLength)
            );
        }
    }

    #[test]
    fn http2_and_http3_restrict_te_to_trailers() {
        for version in [FramingVersion::Http2, FramingVersion::Http3] {
            assert_eq!(
                validate_request_framing_for_version(&headers(&[("te", "trailers")]), version),
                Ok(())
            );
            assert_eq!(
                validate_request_framing_for_version(
                    &headers(&[("te", "trailers, trailers")]),
                    version,
                ),
                Ok(())
            );
            for value in ["gzip", "trailers, gzip", "", "TRAILERS, deflate"] {
                assert_eq!(
                    validate_request_framing_for_version(&headers(&[("te", value)]), version),
                    Err(FramingError::InvalidTeHeader),
                    "TE value {value:?} should be rejected on {version:?}"
                );
            }
        }
    }

    #[test]
    fn content_length_is_reconciled_with_buffered_body() {
        let declared = headers(&[("content-length", "5")]);
        assert_eq!(reconcile_content_length(&declared, 5), Ok(()));
        assert_eq!(
            reconcile_content_length(&declared, 10),
            Err(FramingError::ContentLengthMismatch {
                declared: 5,
                actual: 10
            })
        );
        // An absent Content-Length is valid for HTTP/2 and HTTP/3.
        assert_eq!(reconcile_content_length(&HeaderMap::new(), 10), Ok(()));
        // A malformed value is still rejected.
        assert_eq!(
            reconcile_content_length(&headers(&[("content-length", "+5")]), 5),
            Err(FramingError::InvalidContentLength)
        );
    }

    #[test]
    fn trailers_reject_framing_and_connection_fields() {
        for field in [
            "content-length",
            "transfer-encoding",
            "trailer",
            "connection",
            "keep-alive",
            "proxy-connection",
            "upgrade",
            "host",
            "te",
            "content-encoding",
            "content-type",
        ] {
            assert_eq!(
                validate_request_trailers(&headers(&[(field, "1")])),
                Err(FramingError::ForbiddenTrailerField(field)),
                "trailer field {field:?} should be rejected"
            );
        }
    }

    #[test]
    fn trailers_allow_end_to_end_fields() {
        assert_eq!(
            validate_request_trailers(&headers(&[("grpc-status", "0"), ("grpc-message", "ok"),])),
            Ok(())
        );
    }
}
