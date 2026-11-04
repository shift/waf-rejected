//! Request framing validation.
//!
//! Rejects ambiguous HTTP request framing that can be used for request
//! smuggling (CL/TE confusion, conflicting Content-Length values, malformed
//! lengths and unsupported transfer codings). The check is deliberately
//! strict: any ambiguity is rejected before a request body is read.

use std::fmt;

use http::header::{CONTENT_LENGTH, TRANSFER_ENCODING};
use http::HeaderMap;

/// Reason a request's framing was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FramingError {
    /// Both `Content-Length` and `Transfer-Encoding` were supplied.
    ContentLengthAndTransferEncoding,
    /// More than one `Content-Length` header field was supplied.
    MultipleContentLengthHeaders,
    /// A comma-separated `Content-Length` list had conflicting values.
    ConflictingContentLengthValues,
    /// A `Content-Length` value was empty, non-numeric or out of range.
    InvalidContentLength,
    /// `Transfer-Encoding` was present but was not exactly one `chunked` token.
    InvalidTransferEncoding,
}

impl fmt::Display for FramingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::ContentLengthAndTransferEncoding => {
                "request has both Content-Length and Transfer-Encoding"
            }
            Self::MultipleContentLengthHeaders => "request has multiple Content-Length headers",
            Self::ConflictingContentLengthValues => "request has conflicting Content-Length values",
            Self::InvalidContentLength => "request has an invalid Content-Length",
            Self::InvalidTransferEncoding => "request has an invalid Transfer-Encoding",
        };
        f.write_str(message)
    }
}

impl std::error::Error for FramingError {}

/// Validate HTTP request framing headers.
///
/// Accepts requests with neither header, exactly one unambiguous
/// `Content-Length`, or a single `Transfer-Encoding: chunked`. Everything else
/// is rejected as ambiguous or malformed.
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

fn validate_content_length(headers: &HeaderMap) -> Result<(), FramingError> {
    let mut values = headers.get_all(CONTENT_LENGTH).iter();

    let first = values
        .next()
        .ok_or(FramingError::InvalidContentLength)?
        .to_str()
        .map_err(|_| FramingError::InvalidContentLength)?;

    // A second header field is always rejected, even if its value matches.
    if values.next().is_some() {
        return Err(FramingError::MultipleContentLengthHeaders);
    }

    let mut parsed = None;
    let mut list_len = 0usize;
    for part in first.split(',') {
        let part = part.trim();
        if part.is_empty() {
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
        list_len += 1;
    }

    // The loop always runs at least once for a present header, but guard
    // against an empty value being treated as valid.
    if list_len == 0 || parsed.is_none() {
        return Err(FramingError::InvalidContentLength);
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
    use http::header::{HeaderValue, CONTENT_LENGTH, TRANSFER_ENCODING};
    use http::HeaderMap;

    fn headers(values: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in values {
            map.append(
                if *name == "content-length" {
                    CONTENT_LENGTH
                } else {
                    TRANSFER_ENCODING
                },
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
    fn rejects_multiple_content_length_headers() {
        assert_eq!(
            validate_request_framing(&headers(&[
                ("content-length", "5"),
                ("content-length", "5"),
            ])),
            Err(FramingError::MultipleContentLengthHeaders)
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
}
