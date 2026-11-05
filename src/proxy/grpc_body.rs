//! Frame-aware gRPC request-body handling.
//!
//! HTTP/2 does not require `content-length`, so the old heuristic
//! (`is_grpc && !content-length` => streaming) forwarded ordinary unary RPCs
//! without body inspection. This module classifies a gRPC body from its actual
//! length-prefixed frame sequence instead:
//!
//! * exactly one complete message followed by end-of-stream (or trailers) is
//!   unary and is buffered for inspection;
//! * a second message, or a complete first message with the stream still open,
//!   is genuinely streaming.
//!
//! Streaming bodies are relayed through [`GrpcStreamGuard`], which enforces
//! total bytes, message count, duration and bounded gzip decompression across
//! the whole exchange.

use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use http_body_util::BodyExt;
use hyper::body::{Body, Frame};
use hyper::HeaderMap;

use crate::waf::grpc::{decompress_gzip, FRAME_PREFIX_LEN};

/// How long to wait for the next frame before treating an open stream as
/// genuinely streaming. Unary bodies end their stream on the final data frame,
/// so this only delays the first frame of a real stream.
const STREAM_DETECTION_GRACE: Duration = Duration::from_millis(25);

/// Classification of a gRPC request body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GrpcBodyMode {
    /// One complete length-prefixed message.
    Unary,
    /// More than one message, or a message followed by an open stream.
    Streaming,
}

/// Result of probing a gRPC body.
pub(crate) struct GrpcProbe {
    pub(crate) mode: GrpcBodyMode,
    /// Bytes already read from the client. For unary this is the whole body;
    /// for streaming it is the first frame (plus any read-ahead).
    pub(crate) prefix: Bytes,
    /// Request trailers observed while probing a unary body.
    pub(crate) trailers: Option<HeaderMap>,
}

/// Probe failures that map to a client error before forwarding.
#[derive(Debug)]
pub(crate) enum GrpcProbeError {
    TooLarge { limit: usize },
    Malformed(String),
    Read(String),
}

impl std::fmt::Display for GrpcProbeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLarge { limit } => {
                write!(f, "gRPC request body exceeds the {limit}-byte limit")
            }
            Self::Malformed(reason) => write!(f, "malformed gRPC request body: {reason}"),
            Self::Read(reason) => write!(f, "failed to read gRPC request body: {reason}"),
        }
    }
}

impl std::error::Error for GrpcProbeError {}

/// Returns the end offset of the first complete frame, or `None` when more
/// bytes are needed. Validates the prefix as soon as it is available.
fn first_frame_end(buffer: &[u8], max_bytes: usize) -> Result<Option<usize>, GrpcProbeError> {
    if buffer.len() < FRAME_PREFIX_LEN {
        return Ok(None);
    }
    let flag = buffer[0];
    if flag > 1 {
        return Err(GrpcProbeError::Malformed(format!(
            "invalid compressed flag 0x{flag:02x}"
        )));
    }
    let length = u32::from_be_bytes([buffer[1], buffer[2], buffer[3], buffer[4]]);
    if length > i32::MAX as u32 {
        return Err(GrpcProbeError::Malformed(format!(
            "invalid message length {length}"
        )));
    }
    let end = FRAME_PREFIX_LEN + length as usize;
    if end > max_bytes {
        return Err(GrpcProbeError::TooLarge { limit: max_bytes });
    }
    if buffer.len() >= end {
        Ok(Some(end))
    } else {
        Ok(None)
    }
}

/// Read enough of `body` to classify it as unary or streaming.
pub(crate) async fn probe_grpc_body<B>(
    body: &mut B,
    max_bytes: usize,
) -> Result<GrpcProbe, GrpcProbeError>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Display,
{
    let mut buffer = BytesMut::new();
    let mut trailers = None;
    let mut first_end: Option<usize> = None;

    loop {
        if let Some(end) = first_end {
            // A single DATA frame can contain the first message and the start
            // of a second one.
            if buffer.len() > end {
                return Ok(GrpcProbe {
                    mode: GrpcBodyMode::Streaming,
                    prefix: buffer.freeze(),
                    trailers: None,
                });
            }
            if body.is_end_stream() {
                return Ok(GrpcProbe {
                    mode: GrpcBodyMode::Unary,
                    prefix: buffer.freeze(),
                    trailers,
                });
            }

            match tokio::time::timeout(STREAM_DETECTION_GRACE, BodyExt::frame(&mut *body)).await {
                Ok(Some(Ok(frame))) => match frame.into_data() {
                    Ok(data) => {
                        // HTTP/2 peers may terminate a unary body with an
                        // empty DATA frame carrying END_STREAM. An empty frame
                        // is not a second message.
                        if data.is_empty() {
                            continue;
                        }
                        if buffer.len().saturating_add(data.len()) > max_bytes {
                            return Err(GrpcProbeError::TooLarge { limit: max_bytes });
                        }
                        buffer.extend_from_slice(&data);
                        return Ok(GrpcProbe {
                            mode: GrpcBodyMode::Streaming,
                            prefix: buffer.freeze(),
                            trailers: None,
                        });
                    }
                    Err(frame) => {
                        if let Ok(block) = frame.into_trailers() {
                            trailers = Some(block);
                        }
                        return Ok(GrpcProbe {
                            mode: GrpcBodyMode::Unary,
                            prefix: buffer.freeze(),
                            trailers,
                        });
                    }
                },
                Ok(Some(Err(error))) => return Err(GrpcProbeError::Read(error.to_string())),
                Ok(None) => {
                    return Ok(GrpcProbe {
                        mode: GrpcBodyMode::Unary,
                        prefix: buffer.freeze(),
                        trailers,
                    })
                }
                Err(_) => {
                    return Ok(GrpcProbe {
                        mode: GrpcBodyMode::Streaming,
                        prefix: buffer.freeze(),
                        trailers: None,
                    })
                }
            }
        }

        match BodyExt::frame(&mut *body).await {
            Some(Ok(frame)) => match frame.into_data() {
                Ok(data) => {
                    if buffer.len().saturating_add(data.len()) > max_bytes {
                        return Err(GrpcProbeError::TooLarge { limit: max_bytes });
                    }
                    buffer.extend_from_slice(&data);
                    first_end = first_frame_end(&buffer, max_bytes)?;
                }
                Err(frame) => {
                    if let Ok(block) = frame.into_trailers() {
                        trailers = Some(block);
                    }
                    if first_end.is_none() {
                        if buffer.is_empty() {
                            return Ok(GrpcProbe {
                                mode: GrpcBodyMode::Unary,
                                prefix: buffer.freeze(),
                                trailers,
                            });
                        }
                        return Err(GrpcProbeError::Malformed(
                            "truncated gRPC frame prefix or message".to_string(),
                        ));
                    }
                    return Ok(GrpcProbe {
                        mode: GrpcBodyMode::Unary,
                        prefix: buffer.freeze(),
                        trailers,
                    });
                }
            },
            Some(Err(error)) => return Err(GrpcProbeError::Read(error.to_string())),
            None => {
                if first_end.is_none() {
                    if buffer.is_empty() {
                        return Ok(GrpcProbe {
                            mode: GrpcBodyMode::Unary,
                            prefix: buffer.freeze(),
                            trailers,
                        });
                    }
                    return Err(GrpcProbeError::Malformed(
                        "truncated gRPC frame prefix or message".to_string(),
                    ));
                }
                return Ok(GrpcProbe {
                    mode: GrpcBodyMode::Unary,
                    prefix: buffer.freeze(),
                    trailers,
                });
            }
        }
    }
}

/// A body that yields an already-read prefix before continuing with `inner`.
pub(crate) struct PrefixedBody<B> {
    prefix: Option<Bytes>,
    inner: B,
}

impl<B> PrefixedBody<B> {
    pub(crate) fn new(prefix: Bytes, inner: B) -> Self {
        Self {
            prefix: Some(prefix),
            inner,
        }
    }
}

impl<B> Body for PrefixedBody<B>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    type Data = Bytes;
    type Error = Box<dyn std::error::Error + Send + Sync>;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let this = self.get_mut();
        if let Some(prefix) = this.prefix.take() {
            if !prefix.is_empty() {
                return Poll::Ready(Some(Ok(Frame::data(prefix))));
            }
        }
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => Poll::Ready(Some(Ok(frame))),
            Poll::Ready(Some(Err(error))) => Poll::Ready(Some(Err(error.into()))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Streaming-body limit violations surfaced to hyper as body errors.
#[derive(Debug)]
pub(crate) enum GrpcStreamError {
    BytesExceeded { limit: usize },
    MessagesExceeded { limit: usize },
    DurationExceeded { seconds: u64 },
    DecompressedExceeded { limit: usize },
    UnsupportedEncoding(String),
    Malformed(String),
}

impl std::fmt::Display for GrpcStreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BytesExceeded { limit } => {
                write!(f, "gRPC stream exceeds the {limit}-byte limit")
            }
            Self::MessagesExceeded { limit } => {
                write!(f, "gRPC stream exceeds the {limit}-message limit")
            }
            Self::DurationExceeded { seconds } => {
                write!(f, "gRPC stream exceeded its {seconds} second deadline")
            }
            Self::DecompressedExceeded { limit } => {
                write!(f, "gRPC stream decompresses beyond the {limit}-byte limit")
            }
            Self::UnsupportedEncoding(encoding) => {
                write!(f, "unsupported grpc-encoding '{encoding}'")
            }
            Self::Malformed(reason) => write!(f, "malformed gRPC stream: {reason}"),
        }
    }
}

impl std::error::Error for GrpcStreamError {}

/// Relay a streaming gRPC body while enforcing whole-stream limits.
///
/// Frames are buffered one at a time so the compressed flag, message count and
/// gzip expansion can be validated before the frame is forwarded. The original
/// (possibly compressed) bytes are emitted unchanged.
pub(crate) struct GrpcStreamGuard<B> {
    inner: B,
    encoding: GrpcEncoding,
    max_bytes: usize,
    max_messages: usize,
    max_decompressed: usize,
    max_seconds: u64,
    deadline: Pin<Box<tokio::time::Sleep>>,
    pending: BytesMut,
    total_bytes: usize,
    total_decompressed: usize,
    messages: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GrpcEncoding {
    Identity,
    Gzip,
}

impl<B> GrpcStreamGuard<B> {
    pub(crate) fn new(
        inner: B,
        encoding: Option<&str>,
        max_bytes: usize,
        max_messages: usize,
        max_decompressed: usize,
        max_duration: Duration,
    ) -> Result<Self, GrpcStreamError> {
        let encoding = match encoding.map(str::trim).filter(|value| !value.is_empty()) {
            None => GrpcEncoding::Identity,
            Some(value) if value.eq_ignore_ascii_case("identity") => GrpcEncoding::Identity,
            Some(value) if value.eq_ignore_ascii_case("gzip") => GrpcEncoding::Gzip,
            Some(value) => return Err(GrpcStreamError::UnsupportedEncoding(value.to_string())),
        };
        Ok(Self {
            inner,
            encoding,
            max_bytes,
            max_messages,
            max_decompressed,
            max_seconds: max_duration.as_secs(),
            deadline: Box::pin(tokio::time::sleep(max_duration)),
            pending: BytesMut::new(),
            total_bytes: 0,
            total_decompressed: 0,
            messages: 0,
        })
    }

    fn validate_frame(&mut self) -> Result<Option<Bytes>, GrpcStreamError> {
        if self.pending.len() < FRAME_PREFIX_LEN {
            return Ok(None);
        }
        let flag = self.pending[0];
        if flag > 1 {
            return Err(GrpcStreamError::Malformed(format!(
                "invalid compressed flag 0x{flag:02x}"
            )));
        }
        let length = u32::from_be_bytes([
            self.pending[1],
            self.pending[2],
            self.pending[3],
            self.pending[4],
        ]);
        if length > i32::MAX as u32 {
            return Err(GrpcStreamError::Malformed(format!(
                "invalid message length {length}"
            )));
        }
        let end = FRAME_PREFIX_LEN + length as usize;
        if self.pending.len() < end {
            return Ok(None);
        }

        let frame = self.pending.split_to(end).freeze();
        let payload = &frame[FRAME_PREFIX_LEN..];
        let decompressed_len = if flag == 1 {
            match self.encoding {
                GrpcEncoding::Identity => {
                    return Err(GrpcStreamError::Malformed(
                        "compressed frame with grpc-encoding identity".to_string(),
                    ))
                }
                GrpcEncoding::Gzip => {
                    let remaining = self
                        .max_decompressed
                        .saturating_sub(self.total_decompressed);
                    match decompress_gzip(payload, remaining) {
                        Ok(decoded) => decoded.len(),
                        Err(reason) if reason.contains("exceeds") => {
                            return Err(GrpcStreamError::DecompressedExceeded {
                                limit: self.max_decompressed,
                            })
                        }
                        Err(reason) => return Err(GrpcStreamError::Malformed(reason)),
                    }
                }
            }
        } else {
            payload.len()
        };

        self.total_decompressed = self.total_decompressed.saturating_add(decompressed_len);
        if self.total_decompressed > self.max_decompressed {
            return Err(GrpcStreamError::DecompressedExceeded {
                limit: self.max_decompressed,
            });
        }
        self.messages += 1;
        if self.messages > self.max_messages {
            return Err(GrpcStreamError::MessagesExceeded {
                limit: self.max_messages,
            });
        }
        Ok(Some(frame))
    }
}

impl<B> Body for GrpcStreamGuard<B>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    type Data = Bytes;
    type Error = Box<dyn std::error::Error + Send + Sync>;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let this = self.get_mut();
        if std::future::Future::poll(this.deadline.as_mut(), cx).is_ready() {
            return Poll::Ready(Some(Err(Box::new(GrpcStreamError::DurationExceeded {
                seconds: this.max_seconds,
            }))));
        }

        loop {
            match this.validate_frame() {
                Ok(Some(frame)) => return Poll::Ready(Some(Ok(Frame::data(frame)))),
                Ok(None) => {}
                Err(error) => return Poll::Ready(Some(Err(Box::new(error)))),
            }

            match Pin::new(&mut this.inner).poll_frame(cx) {
                Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                    Ok(data) => {
                        this.total_bytes = this.total_bytes.saturating_add(data.len());
                        if this.total_bytes > this.max_bytes {
                            return Poll::Ready(Some(Err(Box::new(
                                GrpcStreamError::BytesExceeded {
                                    limit: this.max_bytes,
                                },
                            ))));
                        }
                        this.pending.extend_from_slice(&data);
                    }
                    Err(frame) => {
                        if let Ok(block) = frame.into_trailers() {
                            if !this.pending.is_empty() {
                                return Poll::Ready(Some(Err(Box::new(
                                    GrpcStreamError::Malformed(
                                        "trailers after a truncated gRPC frame".to_string(),
                                    ),
                                ))));
                            }
                            return Poll::Ready(Some(Ok(Frame::trailers(block))));
                        }
                    }
                },
                Poll::Ready(Some(Err(error))) => return Poll::Ready(Some(Err(error.into()))),
                Poll::Ready(None) => {
                    if this.pending.is_empty() {
                        return Poll::Ready(None);
                    }
                    return Poll::Ready(Some(Err(Box::new(GrpcStreamError::Malformed(
                        "truncated gRPC frame at end of stream".to_string(),
                    )))));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::Full;

    fn frame(payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(FRAME_PREFIX_LEN + payload.len());
        out.push(0);
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    async fn collect<B>(body: B) -> Result<Vec<u8>, String>
    where
        B: Body<Data = Bytes> + Unpin,
        B::Error: std::fmt::Display,
    {
        let mut body = std::pin::pin!(body);
        let mut out = Vec::new();
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|error| error.to_string())?;
            if let Ok(data) = frame.into_data() {
                out.extend_from_slice(&data);
            }
        }
        Ok(out)
    }

    /// A body that yields a fixed sequence of data frames, including empty
    /// ones, then end-of-stream.
    struct ChunkedBody {
        chunks: std::collections::VecDeque<Bytes>,
    }

    impl Body for ChunkedBody {
        type Data = Bytes;
        type Error = std::convert::Infallible;

        fn poll_frame(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
            let this = self.get_mut();
            match this.chunks.pop_front() {
                Some(chunk) => Poll::Ready(Some(Ok(Frame::data(chunk)))),
                None => Poll::Ready(None),
            }
        }
    }

    #[tokio::test]
    async fn empty_data_frame_after_unary_message_is_not_streaming() {
        let mut body = ChunkedBody {
            chunks: [Bytes::from(frame(b"hello")), Bytes::new()]
                .into_iter()
                .collect(),
        };
        let probe = probe_grpc_body(&mut body, 1024).await.unwrap();
        assert_eq!(probe.mode, GrpcBodyMode::Unary);
        assert_eq!(probe.prefix, Bytes::from(frame(b"hello")));
    }

    #[tokio::test]
    async fn second_message_is_streaming() {
        let mut body = ChunkedBody {
            chunks: [Bytes::from([frame(b"one"), frame(b"two")].concat())]
                .into_iter()
                .collect(),
        };
        let probe = probe_grpc_body(&mut body, 1024).await.unwrap();
        assert_eq!(probe.mode, GrpcBodyMode::Streaming);
    }

    #[test]
    fn first_frame_end_validates_prefix() {
        assert_eq!(first_frame_end(&[0, 0, 0], 1024).unwrap(), None);
        assert_eq!(
            first_frame_end(&[0, 0, 0, 0, 2, b'a', b'b'], 1024).unwrap(),
            Some(7)
        );
        assert!(matches!(
            first_frame_end(&[2, 0, 0, 0, 0], 1024),
            Err(GrpcProbeError::Malformed(_))
        ));
        assert!(matches!(
            first_frame_end(&[0, 0, 0, 0, 9], 4),
            Err(GrpcProbeError::TooLarge { .. })
        ));
    }

    #[tokio::test]
    async fn guard_enforces_message_count() {
        let body = Full::new(Bytes::from(
            [frame(b"a"), frame(b"b"), frame(b"c")].concat(),
        ));
        let guard =
            GrpcStreamGuard::new(body, None, 1024, 2, 1024, Duration::from_secs(30)).unwrap();
        let error = collect(guard).await.unwrap_err();
        assert!(error.contains("2-message limit"), "{error}");
    }

    #[tokio::test]
    async fn guard_enforces_total_bytes() {
        let body = Full::new(Bytes::from(frame(b"0123456789")));
        let guard = GrpcStreamGuard::new(body, None, 8, 10, 1024, Duration::from_secs(30)).unwrap();
        let error = collect(guard).await.unwrap_err();
        assert!(error.contains("8-byte limit"), "{error}");
    }

    #[tokio::test]
    async fn guard_rejects_malformed_frame() {
        let body = Full::new(Bytes::from_static(&[0, 0, 0]));
        let guard =
            GrpcStreamGuard::new(body, None, 1024, 10, 1024, Duration::from_secs(30)).unwrap();
        let error = collect(guard).await.unwrap_err();
        assert!(error.contains("truncated"), "{error}");
    }

    #[tokio::test]
    async fn guard_bounds_gzip_expansion() {
        use std::io::Write;

        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&vec![b'A'; 64 * 1024]).unwrap();
        let compressed = encoder.finish().unwrap();
        let mut raw = Vec::new();
        raw.push(1);
        raw.extend_from_slice(&(compressed.len() as u32).to_be_bytes());
        raw.extend_from_slice(&compressed);

        let guard = GrpcStreamGuard::new(
            Full::new(Bytes::from(raw)),
            Some("gzip"),
            1024 * 1024,
            10,
            1024,
            Duration::from_secs(30),
        )
        .unwrap();
        let error = collect(guard).await.unwrap_err();
        assert!(error.contains("decompresses beyond"), "{error}");
    }

    #[tokio::test]
    async fn guard_rejects_unsupported_encoding() {
        let error = match GrpcStreamGuard::new(
            Full::new(Bytes::new()),
            Some("zstd"),
            1024,
            10,
            1024,
            Duration::from_secs(30),
        ) {
            Ok(_) => panic!("zstd must be rejected"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("zstd"));
    }
}
