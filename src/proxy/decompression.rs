//! Bounded request-body decompression.
//!
//! Request bodies are decompressed before WAF inspection so compressed
//! payloads cannot bypass body rules. Only a small, explicit set of codings is
//! accepted and each request may carry at most one of them; stacked encodings
//! (for example `Content-Encoding: gzip, gzip`) are rejected rather than
//! decoded recursively.
//!
//! Decompressed output is capped at `server.max_body_size`. The compressed
//! input is already capped by the normal body-read path, but a small compressed
//! payload can expand dramatically, so the decoder checks the output limit on
//! every chunk and aborts as soon as it is exceeded.

use std::io::{Cursor, Read};

use bytes::Bytes;
use http::header::{CONTENT_ENCODING, CONTENT_LENGTH};
use http::HeaderMap;

/// Largest compressed input chunk read from a decoder at once.
const DECODE_CHUNK_SIZE: usize = 8 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum DecompressionError {
    /// The coding is not supported, or multiple codings were requested.
    UnsupportedEncoding(String),
    /// The decompressed body exceeds the configured limit.
    TooLarge,
    /// The payload is not valid for the declared coding.
    Malformed,
}

/// Decompress a request body according to its `Content-Encoding`.
///
/// On success the caller must drop `Content-Encoding` (and the now-stale
/// `Content-Length`) before forwarding the decompressed body upstream.
pub(crate) fn decompress_request_body(
    headers: &HeaderMap,
    body: Bytes,
    max_body_size: usize,
) -> Result<Bytes, DecompressionError> {
    let mut codings = Vec::new();
    for value in headers.get_all(CONTENT_ENCODING) {
        let value = value.to_str().map_err(|_| {
            DecompressionError::UnsupportedEncoding("<non-UTF-8 Content-Encoding>".to_string())
        })?;
        for token in value.split(',') {
            let token = token.trim();
            if token.is_empty() {
                return Err(DecompressionError::Malformed);
            }
            codings.push(token.to_ascii_lowercase());
        }
    }

    // No Content-Encoding (or an explicit single identity coding) means the
    // body is already in its identity form.
    if codings.is_empty() {
        return Ok(body);
    }
    if codings.len() == 1 && codings[0] == "identity" {
        return Ok(body);
    }
    if codings.len() != 1 {
        return Err(DecompressionError::UnsupportedEncoding(codings.join(", ")));
    }

    let coding = codings[0].as_str();
    if body.is_empty() && matches!(coding, "gzip" | "deflate" | "br") {
        // A compressed coding cannot describe an empty payload: every
        // supported format requires at least a header/end marker.
        return Err(DecompressionError::Malformed);
    }
    match coding {
        "gzip" => decode(
            flate2::read::GzDecoder::new(Cursor::new(body)),
            max_body_size,
        ),
        "deflate" => decode(
            flate2::read::ZlibDecoder::new(Cursor::new(body)),
            max_body_size,
        ),
        "br" => decode(
            brotli::Decompressor::new(Cursor::new(body), DECODE_CHUNK_SIZE),
            max_body_size,
        ),
        other => Err(DecompressionError::UnsupportedEncoding(other.to_string())),
    }
}

/// Remove headers that describe the compressed representation after the body
/// has been decoded. Hyper recomputes `Content-Length` from the `Full` body.
pub(crate) fn strip_encoding_headers(headers: &mut HeaderMap) {
    headers.remove(CONTENT_ENCODING);
    headers.remove(CONTENT_LENGTH);
}

fn decode<R: Read>(mut decoder: R, max_body_size: usize) -> Result<Bytes, DecompressionError> {
    let mut output = Vec::new();
    let mut chunk = [0u8; DECODE_CHUNK_SIZE];
    loop {
        let read = decoder
            .read(&mut chunk)
            .map_err(|_| DecompressionError::Malformed)?;
        if read == 0 {
            break;
        }
        if output.len().saturating_add(read) > max_body_size {
            return Err(DecompressionError::TooLarge);
        }
        output.extend_from_slice(&chunk[..read]);
    }
    Ok(Bytes::from(output))
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    fn gzip(data: &[u8]) -> Bytes {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(data).unwrap();
        Bytes::from(encoder.finish().unwrap())
    }

    fn deflate(data: &[u8]) -> Bytes {
        let mut encoder =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(data).unwrap();
        Bytes::from(encoder.finish().unwrap())
    }

    fn brotli(data: &[u8]) -> Bytes {
        let mut output = Vec::new();
        {
            let mut encoder = brotli::CompressorWriter::new(&mut output, 4096, 5, 22);
            encoder.write_all(data).unwrap();
        }
        Bytes::from(output)
    }

    fn headers(coding: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_ENCODING, coding.parse().unwrap());
        headers
    }

    #[test]
    fn gzip_round_trip_is_bounded() {
        let body = gzip(b"id=1 UNION SELECT * FROM users");
        let decoded = decompress_request_body(&headers("gzip"), body, 1024).unwrap();
        assert_eq!(decoded.as_ref(), b"id=1 UNION SELECT * FROM users");
    }

    #[test]
    fn deflate_and_brotli_round_trip() {
        let payload = b"id=1 UNION SELECT * FROM users";
        assert_eq!(
            decompress_request_body(&headers("deflate"), deflate(payload), 1024).unwrap(),
            payload.as_slice()
        );
        assert_eq!(
            decompress_request_body(&headers("br"), brotli(payload), 1024).unwrap(),
            payload.as_slice()
        );
    }

    #[test]
    fn oversized_output_is_rejected() {
        let body = gzip(&vec![b'A'; 4096]);
        assert_eq!(
            decompress_request_body(&headers("gzip"), body, 512),
            Err(DecompressionError::TooLarge)
        );
    }

    #[test]
    fn malformed_payload_is_rejected() {
        assert_eq!(
            decompress_request_body(&headers("gzip"), Bytes::from_static(b"nope"), 512),
            Err(DecompressionError::Malformed)
        );
    }

    #[test]
    fn unsupported_and_stacked_encodings_are_rejected() {
        assert!(matches!(
            decompress_request_body(&headers("zstd"), Bytes::new(), 512),
            Err(DecompressionError::UnsupportedEncoding(_))
        ));
        assert!(matches!(
            decompress_request_body(&headers("gzip, gzip"), Bytes::new(), 512),
            Err(DecompressionError::UnsupportedEncoding(_))
        ));
    }

    #[test]
    fn identity_passes_through() {
        let body = Bytes::from_static(b"plain");
        assert_eq!(
            decompress_request_body(&headers("identity"), body.clone(), 512).unwrap(),
            body
        );
        assert_eq!(
            decompress_request_body(&HeaderMap::new(), body.clone(), 512).unwrap(),
            body
        );
    }
}
