//! Frame-aware gRPC request-body handling.
//!
//! HTTP/2 does not require `content-length`, so the old heuristic
//! (`is_grpc && !content-length` => streaming) forwarded ordinary unary RPCs
//! without body inspection. This module classifies a gRPC body from its actual
//! length-prefixed frame sequence instead:
//!
//! * exactly one complete message followed by end-of-stream (or trailers) is
//!   unary and is buffered for inspection;
//! * a second message, or additional bytes after the first complete message,
//!   is genuinely streaming.
//!
//! Classification never uses a timer: a client cannot force a unary RPC onto
//! the streaming path by delaying `END_STREAM`. Streaming bodies are relayed
//! through [`GrpcStreamGuard`], which inspects every complete message before
//! forwarding it and enforces total bytes, message count, duration,
//! per-message size and bounded gzip decompression across the whole exchange.

use std::collections::VecDeque;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use http_body_util::BodyExt;
use hyper::body::{Body, Frame};
use hyper::HeaderMap;

use crate::proxy::framing::validate_request_trailers;
use crate::waf::grpc::{decompress_gzip, GrpcFrameInspector, FRAME_PREFIX_LEN};

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

            // Wait for the next frame without a timeout. A unary client that
            // delays END_STREAM remains unary; only new bytes after the first
            // complete message make the body genuinely streaming.
            match BodyExt::frame(&mut *body).await {
                Some(Ok(frame)) => match frame.into_data() {
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
                Some(Err(error)) => return Err(GrpcProbeError::Read(error.to_string())),
                None => {
                    return Ok(GrpcProbe {
                        mode: GrpcBodyMode::Unary,
                        prefix: buffer.freeze(),
                        trailers,
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
    MessageTooLarge { limit: usize },
    MessagesExceeded { limit: usize },
    DurationExceeded { seconds: u64 },
    DecompressedExceeded { limit: usize },
    UnsupportedEncoding(String),
    Malformed(String),
    InspectionBlocked { status: u16, reason: String },
}

impl std::fmt::Display for GrpcStreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BytesExceeded { limit } => {
                write!(f, "gRPC stream exceeds the {limit}-byte limit")
            }
            Self::MessageTooLarge { limit } => {
                write!(f, "gRPC message exceeds the {limit}-byte limit")
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
            Self::InspectionBlocked { status, reason } => {
                write!(f, "gRPC message blocked by inspection ({status}): {reason}")
            }
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
    max_message_bytes: usize,
    max_messages: usize,
    max_decompressed: usize,
    max_seconds: u64,
    deadline: Pin<Box<tokio::time::Sleep>>,
    pending: BytesMut,
    ready: VecDeque<Bytes>,
    pending_trailers: Option<HeaderMap>,
    inner_done: bool,
    total_bytes: usize,
    total_decompressed: usize,
    messages: usize,
    inspector: Option<Arc<dyn GrpcFrameInspector>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GrpcEncoding {
    Identity,
    Gzip,
}

impl<B> GrpcStreamGuard<B>
where
    B: Body<Data = Bytes> + Unpin,
{
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
            max_message_bytes: max_bytes,
            max_messages,
            max_decompressed,
            max_seconds: max_duration.as_secs(),
            deadline: Box::pin(tokio::time::sleep(max_duration)),
            pending: BytesMut::new(),
            ready: VecDeque::new(),
            pending_trailers: None,
            inner_done: false,
            total_bytes: 0,
            total_decompressed: 0,
            messages: 0,
            inspector: None,
        })
    }

    /// Attaches the per-message protocol inspector. The guard calls it for
    /// every complete frame before making that frame visible to the upstream.
    pub(crate) fn with_inspector(mut self, inspector: Arc<dyn GrpcFrameInspector>) -> Self {
        self.inspector = Some(inspector);
        self
    }

    /// Caps the declared size of one length-prefixed message.
    pub(crate) fn with_max_message_bytes(mut self, max_message_bytes: usize) -> Self {
        if max_message_bytes > 0 {
            self.max_message_bytes = max_message_bytes;
        }
        self
    }

    /// Validate and stage a trailer block before it can be forwarded.
    fn accept_trailers(&mut self, block: HeaderMap) -> Result<(), GrpcStreamError> {
        validate_request_trailers(&block).map_err(|error| {
            GrpcStreamError::Malformed(format!("invalid gRPC trailers: {error}"))
        })?;
        self.pending_trailers = Some(block);
        self.inner_done = true;
        Ok(())
    }

    fn push_data(&mut self, data: &[u8]) -> Result<(), GrpcStreamError> {
        self.total_bytes = self.total_bytes.saturating_add(data.len());
        if self.total_bytes > self.max_bytes {
            return Err(GrpcStreamError::BytesExceeded {
                limit: self.max_bytes,
            });
        }
        self.pending.extend_from_slice(data);
        Ok(())
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
        if length as usize > self.max_message_bytes {
            return Err(GrpcStreamError::MessageTooLarge {
                limit: self.max_message_bytes,
            });
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
        if let Some(inspector) = self.inspector.as_deref() {
            inspector.inspect_frame(&frame).map_err(|block| {
                GrpcStreamError::InspectionBlocked {
                    status: block.status,
                    reason: block.reason,
                }
            })?;
        }
        Ok(Some(frame))
    }

    /// Reads and inspects the first complete message before the upstream
    /// request is sent.
    ///
    /// This lets a blocked first message produce a WAF `4xx` (rather than a
    /// generic upstream error), while later messages are still inspected
    /// incrementally as they arrive. It also removes any timing-based
    /// classification: a client that delays `END_STREAM` after a complete
    /// message is inspected exactly like any other.
    pub(crate) async fn prime(&mut self) -> Result<(), GrpcStreamError>
    where
        B: Body<Data = Bytes> + Unpin,
        B::Error: std::fmt::Display,
    {
        loop {
            if !self.ready.is_empty() || self.inner_done {
                return Ok(());
            }
            if let Some(frame) = self.validate_frame()? {
                self.ready.push_back(frame);
                return Ok(());
            }
            match BodyExt::frame(&mut self.inner).await {
                Some(Ok(frame)) => match frame.into_data() {
                    Ok(data) => {
                        if data.is_empty() {
                            continue;
                        }
                        self.push_data(&data)?;
                    }
                    Err(frame) => {
                        if let Ok(block) = frame.into_trailers() {
                            if !self.pending.is_empty() {
                                return Err(GrpcStreamError::Malformed(
                                    "trailers after a truncated gRPC frame".to_string(),
                                ));
                            }
                            self.accept_trailers(block)?;
                            return Ok(());
                        }
                    }
                },
                Some(Err(error)) => {
                    return Err(GrpcStreamError::Malformed(format!(
                        "failed to read gRPC frame: {error}"
                    )))
                }
                None => {
                    self.inner_done = true;
                    if !self.pending.is_empty() {
                        return Err(GrpcStreamError::Malformed(
                            "truncated gRPC frame at end of stream".to_string(),
                        ));
                    }
                    return Ok(());
                }
            }
        }
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

        if let Some(frame) = this.ready.pop_front() {
            return Poll::Ready(Some(Ok(Frame::data(frame))));
        }

        loop {
            match this.validate_frame() {
                Ok(Some(frame)) => return Poll::Ready(Some(Ok(Frame::data(frame)))),
                Ok(None) => {}
                Err(error) => return Poll::Ready(Some(Err(Box::new(error)))),
            }

            if this.inner_done {
                if let Some(trailers) = this.pending_trailers.take() {
                    return Poll::Ready(Some(Ok(Frame::trailers(trailers))));
                }
                if this.pending.is_empty() {
                    return Poll::Ready(None);
                }
                return Poll::Ready(Some(Err(Box::new(GrpcStreamError::Malformed(
                    "truncated gRPC frame at end of stream".to_string(),
                )))));
            }

            match Pin::new(&mut this.inner).poll_frame(cx) {
                Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                    Ok(data) => {
                        if let Err(error) = this.push_data(&data) {
                            return Poll::Ready(Some(Err(Box::new(error))));
                        }
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
                            if let Err(error) = this.accept_trailers(block) {
                                return Poll::Ready(Some(Err(Box::new(error))));
                            }
                        }
                    }
                },
                Poll::Ready(Some(Err(error))) => return Poll::Ready(Some(Err(error.into()))),
                Poll::Ready(None) => {
                    this.inner_done = true;
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::waf::grpc::GrpcFrameBlock;
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

    /// A body that yields one data frame and then never completes. This models
    /// a client that sends a complete unary message but delays END_STREAM.
    struct PendingAfterFirst {
        first: Option<Bytes>,
    }

    impl Body for PendingAfterFirst {
        type Data = Bytes;
        type Error = std::convert::Infallible;

        fn poll_frame(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
            let this = self.get_mut();
            match this.first.take() {
                Some(first) => Poll::Ready(Some(Ok(Frame::data(first)))),
                None => Poll::Pending,
            }
        }
    }

    #[tokio::test]
    #[ignore = "security finding H1: a unary RPC can be forced into streaming by delaying END_STREAM"]
    async fn unary_rpc_with_delayed_end_stream_is_not_forced_into_streaming() {
        let mut body = PendingAfterFirst {
            first: Some(Bytes::from(frame(b"hello"))),
        };
        let probe = probe_grpc_body(&mut body, 1024).await.unwrap();
        assert_eq!(
            probe.mode,
            GrpcBodyMode::Unary,
            "a single complete frame must stay unary even when END_STREAM is delayed"
        );
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

    /// A body that yields one complete message, then applies a delay before
    /// ending the stream. This models a client trying to exceed a probe
    /// window; classification must not depend on elapsed time.
    struct DelayedEndAfterFirst {
        first: Option<Bytes>,
        delay: Pin<Box<tokio::time::Sleep>>,
        ended: bool,
    }

    impl Body for DelayedEndAfterFirst {
        type Data = Bytes;
        type Error = std::convert::Infallible;

        fn poll_frame(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
            let this = self.get_mut();
            if let Some(first) = this.first.take() {
                return Poll::Ready(Some(Ok(Frame::data(first))));
            }
            if !this.ended {
                if std::future::Future::poll(this.delay.as_mut(), cx).is_pending() {
                    return Poll::Pending;
                }
                this.ended = true;
                return Poll::Ready(Some(Ok(Frame::data(Bytes::new()))));
            }
            Poll::Ready(None)
        }
    }

    struct RecordingInspector {
        inspected: std::sync::Mutex<Vec<Bytes>>,
        block_first: bool,
    }

    impl GrpcFrameInspector for RecordingInspector {
        fn inspect_frame(&self, frame: &[u8]) -> Result<(), GrpcFrameBlock> {
            let mut inspected = self.inspected.lock().unwrap();
            inspected.push(Bytes::copy_from_slice(frame));
            if self.block_first && inspected.len() == 1 {
                return Err(GrpcFrameBlock {
                    status: 403,
                    reason: "blocked by test inspector".to_string(),
                });
            }
            Ok(())
        }
    }

    #[tokio::test]
    async fn guard_inspects_every_message_before_forwarding() {
        let inspector = Arc::new(RecordingInspector {
            inspected: std::sync::Mutex::new(Vec::new()),
            block_first: false,
        });
        let body = Full::new(Bytes::from([frame(b"one"), frame(b"two")].concat()));
        let guard = GrpcStreamGuard::new(body, None, 1024, 10, 1024, Duration::from_secs(30))
            .unwrap()
            .with_inspector(inspector.clone());
        let forwarded = collect(guard).await.unwrap();
        assert_eq!(forwarded, [frame(b"one"), frame(b"two")].concat());
        assert_eq!(inspector.inspected.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn guard_prime_blocks_before_forwarding() {
        let inspector = Arc::new(RecordingInspector {
            inspected: std::sync::Mutex::new(Vec::new()),
            block_first: true,
        });
        let body = Full::new(Bytes::from([frame(b"bad"), frame(b"worse")].concat()));
        let mut guard = GrpcStreamGuard::new(body, None, 1024, 10, 1024, Duration::from_secs(30))
            .unwrap()
            .with_inspector(inspector);
        let error = guard.prime().await.unwrap_err();
        assert!(matches!(
            error,
            GrpcStreamError::InspectionBlocked { status: 403, .. }
        ));
    }

    #[tokio::test]
    async fn guard_enforces_per_message_size() {
        let body = Full::new(Bytes::from(frame(b"hello")));
        let guard = GrpcStreamGuard::new(body, None, 1024, 10, 1024, Duration::from_secs(30))
            .unwrap()
            .with_max_message_bytes(2);
        let error = collect(guard).await.unwrap_err();
        assert!(error.contains("2-byte limit"), "{error}");
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

    struct DataThenTrailers {
        data: Option<Bytes>,
        trailers: Option<HeaderMap>,
    }

    impl Body for DataThenTrailers {
        type Data = Bytes;
        type Error = std::convert::Infallible;

        fn poll_frame(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
            let this = self.get_mut();
            if let Some(data) = this.data.take() {
                return Poll::Ready(Some(Ok(Frame::data(data))));
            }
            if let Some(trailers) = this.trailers.take() {
                return Poll::Ready(Some(Ok(Frame::trailers(trailers))));
            }
            Poll::Ready(None)
        }
    }

    #[tokio::test]
    async fn guard_rejects_forbidden_trailers() {
        let mut trailers = HeaderMap::new();
        trailers.insert("content-length", "5".parse().unwrap());
        let body = DataThenTrailers {
            data: Some(Bytes::from(frame(b"hello"))),
            trailers: Some(trailers),
        };
        let guard =
            GrpcStreamGuard::new(body, None, 1024, 10, 1024, Duration::from_secs(30)).unwrap();
        let error = collect(guard).await.unwrap_err();
        assert!(error.contains("invalid gRPC trailers"), "{error}");
    }

    #[tokio::test]
    async fn guard_forwards_end_to_end_trailers() {
        let mut trailers = HeaderMap::new();
        trailers.insert("grpc-status", "0".parse().unwrap());
        let body = DataThenTrailers {
            data: Some(Bytes::from(frame(b"hello"))),
            trailers: Some(trailers),
        };
        let guard =
            GrpcStreamGuard::new(body, None, 1024, 10, 1024, Duration::from_secs(30)).unwrap();
        let mut guard = std::pin::pin!(guard);
        let mut saw_trailers = false;
        while let Some(frame) = guard.frame().await {
            let frame = frame.unwrap();
            if let Ok(block) = frame.into_trailers() {
                assert_eq!(block.get("grpc-status").unwrap(), "0");
                saw_trailers = true;
            }
        }
        assert!(saw_trailers, "end-to-end trailers must be forwarded");
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
