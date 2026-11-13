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
use std::time::Duration;

use http::header::{CONTENT_LENGTH, TRANSFER_ENCODING};
use http::HeaderMap;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

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

/// Reason a raw HTTP/1.x request head was rejected before hyper parsed it.
///
/// hyper normalises `Content-Length` + `Transfer-Encoding` (it drops the
/// `Content-Length`) and collapses duplicate identical `Content-Length`
/// fields while parsing. Once the request reaches the application neither
/// ambiguity is observable, so the wire-level head is validated before it is
/// handed to hyper.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestHeadError {
    /// The head violated the framing checks in [`validate_request_framing`].
    Framing(FramingError),
    /// The request line or a header field was not valid HTTP/1.x.
    Malformed,
    /// The request target was not origin-form or asterisk-form.
    InvalidRequestTarget,
    /// The method was rejected (CONNECT is a tunnel request; TRACE reflects).
    MethodNotAllowed,
}

impl RequestHeadError {
    /// HTTP status returned to the client for this rejection.
    pub fn status(self) -> u16 {
        match self {
            Self::MethodNotAllowed => 405,
            Self::Framing(_) | Self::Malformed | Self::InvalidRequestTarget => 400,
        }
    }

    /// Stable server-side reason for logs and metrics.
    pub fn reason(self) -> &'static str {
        match self {
            Self::Framing(_) => "invalid request framing",
            Self::Malformed => "malformed request head",
            Self::InvalidRequestTarget => "invalid request target",
            Self::MethodNotAllowed => "method not allowed",
        }
    }
}

impl fmt::Display for RequestHeadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Framing(error) => write!(f, "{error}"),
            Self::Malformed => f.write_str("malformed HTTP/1.x request head"),
            Self::InvalidRequestTarget => {
                f.write_str("request target must be origin-form or asterisk-form")
            }
            Self::MethodNotAllowed => {
                f.write_str("CONNECT and TRACE are not allowed on this listener")
            }
        }
    }
}

impl std::error::Error for RequestHeadError {}

/// Validate a complete HTTP/1.x request head (`...\r\n\r\n`) at the wire level.
///
/// This runs before hyper's parser so the WAF can see ambiguous framing that
/// hyper would otherwise normalise away. It is deliberately stricter than
/// [`validate_request_framing`]: any repeated `Content-Length` field (even an
/// identical value), any comma-separated length list, `CL`+`TE`, an invalid
/// `Transfer-Encoding`, absolute-form targets, whitespace before a header
/// colon, and obs-fold are rejected. `CONNECT` and `TRACE` are rejected with
/// `405` before any tunnel or reflection path is considered.
pub fn validate_request_head(head: &[u8]) -> Result<(), RequestHeadError> {
    let Some(header_end) = find_head_end(head) else {
        return Err(RequestHeadError::Malformed);
    };
    let head = &head[..header_end];
    // Every line ending must be CRLF; bare LF is ambiguous and rejected.
    if head
        .windows(2)
        .any(|window| window[1] == b'\n' && window[0] != b'\r')
    {
        return Err(RequestHeadError::Malformed);
    }

    let mut lines = head.split(|byte| *byte == b'\n');
    let request_line = lines.next().ok_or(RequestHeadError::Malformed)?;
    let request_line = request_line
        .strip_suffix(b"\r")
        .ok_or(RequestHeadError::Malformed)?;
    let mut parts = request_line.split(|byte| *byte == b' ');
    let method = parts.next().ok_or(RequestHeadError::Malformed)?;
    let target = parts.next().ok_or(RequestHeadError::Malformed)?;
    let version = parts.next().ok_or(RequestHeadError::Malformed)?;
    if parts.next().is_some() || method.is_empty() || target.is_empty() || version.is_empty() {
        return Err(RequestHeadError::Malformed);
    }
    if !method.iter().all(|byte| is_tchar(*byte)) {
        return Err(RequestHeadError::Malformed);
    }
    if method.eq_ignore_ascii_case(b"CONNECT") || method.eq_ignore_ascii_case(b"TRACE") {
        return Err(RequestHeadError::MethodNotAllowed);
    }
    // Origin-form (`/path`) and asterisk-form (`*`) only. Absolute-form and
    // authority-form request targets are not accepted by this proxy.
    if target != b"*" && !target.starts_with(b"/") {
        return Err(RequestHeadError::InvalidRequestTarget);
    }
    if target.iter().any(|byte| *byte <= b' ' || *byte == 0x7f) {
        return Err(RequestHeadError::InvalidRequestTarget);
    }
    let is_http_10 = match version {
        b"HTTP/1.1" => false,
        b"HTTP/1.0" => true,
        _ => return Err(RequestHeadError::Malformed),
    };

    let mut content_lengths: Vec<&[u8]> = Vec::new();
    let mut transfer_encodings: Vec<&[u8]> = Vec::new();

    for line in lines {
        if line.is_empty() {
            // The split includes a final empty element after the terminating
            // CRLF.
            break;
        }
        let line = line
            .strip_suffix(b"\r")
            .ok_or(RequestHeadError::Malformed)?;
        if line.is_empty() {
            // The blank line terminating the head.
            break;
        }
        // obs-fold (continuation lines) is obsolete and ambiguous.
        if line[0] == b' ' || line[0] == b'\t' {
            return Err(RequestHeadError::Malformed);
        }
        let Some(colon) = line.iter().position(|byte| *byte == b':') else {
            return Err(RequestHeadError::Malformed);
        };
        let (name, value) = line.split_at(colon);
        if name.is_empty() || !name.iter().all(|byte| is_tchar(*byte)) {
            // This also rejects whitespace before the colon (`Host : value`)
            // and whitespace inside the field name.
            return Err(RequestHeadError::Malformed);
        }
        let value = &value[1..];
        // Strip optional leading/trailing OWS.
        let value = trim_ows(value);
        if value.iter().any(|byte| *byte == b'\r' || *byte == b'\n') {
            return Err(RequestHeadError::Malformed);
        }
        if name.eq_ignore_ascii_case(b"content-length") {
            content_lengths.push(value);
        } else if name.eq_ignore_ascii_case(b"transfer-encoding") {
            transfer_encodings.push(value);
        }
    }

    if !content_lengths.is_empty() && !transfer_encodings.is_empty() {
        return Err(RequestHeadError::Framing(
            FramingError::ContentLengthAndTransferEncoding,
        ));
    }

    if !transfer_encodings.is_empty() {
        validate_raw_transfer_encoding(&transfer_encodings, is_http_10)?;
    }

    if !content_lengths.is_empty() {
        validate_raw_content_length(&content_lengths)?;
    }

    Ok(())
}

/// True when a validated HTTP/1.x head is an upgrade request (WebSocket).
///
/// Upgrade connections switch protocol after the response and must stay open;
/// every other HTTP/1.x connection is limited to one request per connection so
/// each head passes through [`validate_request_head`].
pub fn request_head_requests_upgrade(head: &[u8]) -> bool {
    let mut connection_upgrade = false;
    let mut has_upgrade = false;
    for line in head.split(|byte| *byte == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(colon) = line.iter().position(|byte| *byte == b':') else {
            continue;
        };
        let name = trim_ows(&line[..colon]);
        let value = trim_ows(&line[colon + 1..]);
        if name.eq_ignore_ascii_case(b"upgrade") {
            has_upgrade = true;
        } else if name.eq_ignore_ascii_case(b"connection") {
            connection_upgrade = value
                .split(|byte| *byte == b',')
                .any(|token| trim_ows(token).eq_ignore_ascii_case(b"upgrade"));
        }
    }
    has_upgrade && connection_upgrade
}

/// Read one HTTP/1.x request head from `stream`, stopping after `\r\n\r\n`.
///
/// Bytes read beyond the head are returned too so they can be replayed to
/// hyper (a body already in flight, or a pipelined request).
pub async fn read_request_head<S>(
    stream: &mut S,
    max_bytes: usize,
    timeout: Duration,
) -> Result<Vec<u8>, RequestHeadError>
where
    S: AsyncRead + Unpin,
{
    let mut buffer = Vec::with_capacity(1024);
    let mut chunk = [0u8; 2048];

    let read = async {
        loop {
            if find_head_end(&buffer).is_some() {
                return Ok(buffer);
            }
            if buffer.len() >= max_bytes {
                return Err(RequestHeadError::Malformed);
            }
            let read = stream
                .read(&mut chunk)
                .await
                .map_err(|_| RequestHeadError::Malformed)?;
            if read == 0 {
                return Err(RequestHeadError::Malformed);
            }
            buffer.extend_from_slice(&chunk[..read]);
            if buffer.len() > max_bytes {
                return Err(RequestHeadError::Malformed);
            }
        }
    };

    tokio::time::timeout(timeout, read)
        .await
        .map_err(|_| RequestHeadError::Malformed)?
}

/// A stream that replays an already-read prefix before reading from the inner
/// stream. Used to hand a validated request head back to hyper.
pub struct PrefixedStream<S> {
    prefix: Vec<u8>,
    position: usize,
    inner: S,
}

impl<S> PrefixedStream<S> {
    pub fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self {
            prefix,
            position: 0,
            inner,
        }
    }
}

impl<S> AsyncRead for PrefixedStream<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.position < this.prefix.len() {
            let remaining = &this.prefix[this.position..];
            let take = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..take]);
            this.position += take;
            return std::task::Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S> AsyncWrite for PrefixedStream<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Write a minimal fail-closed rejection and close the connection.
pub async fn reject_request_head<S>(stream: &mut S, error: RequestHeadError)
where
    S: AsyncWrite + Unpin,
{
    let status = error.status();
    let reason = match status {
        405 => "Method Not Allowed",
        _ => "Bad Request",
    };
    let body = format!("{status} {reason}");
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.shutdown().await;
}

fn find_head_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
}

fn is_tchar(byte: u8) -> bool {
    matches!(
        byte,
        b'!' | b'#'
            | b'$'
            | b'%'
            | b'&'
            | b'\''
            | b'*'
            | b'+'
            | b'-'
            | b'.'
            | b'^'
            | b'_'
            | b'`'
            | b'|'
            | b'~'
            | b'0'..=b'9'
            | b'A'..=b'Z'
            | b'a'..=b'z'
    )
}

fn trim_ows(mut value: &[u8]) -> &[u8] {
    while let [b' ' | b'\t', rest @ ..] = value {
        value = rest;
    }
    while let [rest @ .., b' ' | b'\t'] = value {
        value = rest;
    }
    value
}

fn validate_raw_content_length(values: &[&[u8]]) -> Result<(), RequestHeadError> {
    // A repeated field or a comma-separated list means the peer supplied more
    // than one length. Reject all of them: hyper collapses identical values,
    // which hides the ambiguity from every later stage.
    if values.len() != 1 || values[0].contains(&b',') {
        return Err(RequestHeadError::Framing(
            FramingError::ConflictingContentLengthValues,
        ));
    }
    let value = values[0];
    if value.is_empty() || !value.iter().all(|byte| byte.is_ascii_digit()) {
        return Err(RequestHeadError::Framing(
            FramingError::InvalidContentLength,
        ));
    }
    value
        .iter()
        .try_fold(0u64, |acc, byte| {
            acc.checked_mul(10)?.checked_add((byte - b'0') as u64)
        })
        .ok_or(RequestHeadError::Framing(
            FramingError::InvalidContentLength,
        ))?;
    Ok(())
}

fn validate_raw_transfer_encoding(
    values: &[&[u8]],
    is_http_10: bool,
) -> Result<(), RequestHeadError> {
    if is_http_10 || values.len() != 1 {
        return Err(RequestHeadError::Framing(
            FramingError::InvalidTransferEncoding,
        ));
    }
    let value = values[0];
    let mut tokens = value.split(|byte| *byte == b',');
    let Some(token) = tokens.next() else {
        return Err(RequestHeadError::Framing(
            FramingError::InvalidTransferEncoding,
        ));
    };
    let token = trim_ows(token);
    if tokens.next().is_some() || !token.eq_ignore_ascii_case(b"chunked") {
        return Err(RequestHeadError::Framing(
            FramingError::InvalidTransferEncoding,
        ));
    }
    Ok(())
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

    fn head(request_line: &str, fields: &[&str]) -> Vec<u8> {
        let mut raw = String::from(request_line);
        raw.push_str("\r\nHost: localhost\r\n");
        for field in fields {
            raw.push_str(field);
            raw.push_str("\r\n");
        }
        raw.push_str("\r\n");
        raw.into_bytes()
    }

    #[test]
    fn raw_head_accepts_clean_framing() {
        assert_eq!(
            validate_request_head(&head("POST /upload HTTP/1.1", &["Content-Length: 5"])),
            Ok(())
        );
        assert_eq!(
            validate_request_head(&head(
                "POST /upload HTTP/1.1",
                &["Transfer-Encoding: chunked"]
            )),
            Ok(())
        );
        assert_eq!(
            validate_request_head(&head("OPTIONS * HTTP/1.1", &[])),
            Ok(())
        );
    }

    #[test]
    fn raw_head_rejects_cl_te_in_either_order() {
        for fields in [
            &["Content-Length: 5", "Transfer-Encoding: chunked"][..],
            &["Transfer-Encoding: chunked", "Content-Length: 5"][..],
        ] {
            assert_eq!(
                validate_request_head(&head("POST / HTTP/1.1", fields)),
                Err(RequestHeadError::Framing(
                    FramingError::ContentLengthAndTransferEncoding
                ))
            );
        }
    }

    #[test]
    fn raw_head_rejects_identical_and_conflicting_duplicate_content_length() {
        for fields in [
            &["Content-Length: 5", "Content-Length: 5"][..],
            &["Content-Length: 5", "Content-Length: 6"][..],
            &["Content-Length: 5, 5"][..],
            &["Content-Length: 5, 6"][..],
        ] {
            assert_eq!(
                validate_request_head(&head("POST / HTTP/1.1", fields)),
                Err(RequestHeadError::Framing(
                    FramingError::ConflictingContentLengthValues
                ))
            );
        }
    }

    #[test]
    fn raw_head_rejects_non_chunked_and_stacked_transfer_encoding() {
        for value in [
            "gzip",
            "chunked, gzip",
            "gzip, chunked",
            "chunked, chunked",
            "xchunked",
            "",
        ] {
            let field = format!("Transfer-Encoding: {value}");
            assert_eq!(
                validate_request_head(&head("POST / HTTP/1.1", &[&field])),
                Err(RequestHeadError::Framing(
                    FramingError::InvalidTransferEncoding
                )),
                "value {value:?} should be rejected"
            );
        }
    }

    #[test]
    fn raw_head_rejects_absolute_form_and_authority_form_targets() {
        for line in [
            "GET http://example.com/ HTTP/1.1",
            "GET https://example.com/ HTTP/1.1",
            "CONNECT example.com:443 HTTP/1.1",
        ] {
            let error = validate_request_head(&head(line, &[])).unwrap_err();
            assert!(
                matches!(
                    error,
                    RequestHeadError::InvalidRequestTarget | RequestHeadError::MethodNotAllowed
                ),
                "{line:?} returned {error:?}"
            );
        }
    }

    #[test]
    fn raw_head_rejects_whitespace_before_colon_and_obs_fold() {
        for field in [
            "Content-Length : 5",
            "Content-Length\t: 5",
            " Content-Length: 5",
        ] {
            assert_eq!(
                validate_request_head(&head("POST / HTTP/1.1", &[field])),
                Err(RequestHeadError::Malformed),
                "field {field:?} should be rejected"
            );
        }
    }

    #[test]
    fn raw_head_rejects_trace_and_connect_with_405() {
        for line in ["TRACE / HTTP/1.1", "CONNECT example.com:443 HTTP/1.1"] {
            let error = validate_request_head(&head(line, &[])).unwrap_err();
            assert_eq!(error, RequestHeadError::MethodNotAllowed);
            assert_eq!(error.status(), 405);
        }
    }

    #[test]
    fn raw_head_detects_upgrade_requests() {
        assert!(request_head_requests_upgrade(&head(
            "GET /ws HTTP/1.1",
            &["Connection: Upgrade", "Upgrade: websocket"]
        )));
        assert!(!request_head_requests_upgrade(&head(
            "GET / HTTP/1.1",
            &["Connection: close"]
        )));
        assert!(!request_head_requests_upgrade(&head(
            "GET / HTTP/1.1",
            &["Upgrade: websocket"]
        )));
    }

    #[test]
    fn raw_head_rejects_bare_lf_line_endings() {
        let raw = b"POST / HTTP/1.1\nHost: localhost\nContent-Length: 5\n\n".to_vec();
        assert_eq!(
            validate_request_head(&raw),
            Err(RequestHeadError::Malformed)
        );
    }
}
