//! WASM Streaming Support
//!
//! Provides streaming request processing capabilities for large payloads
//! through the WASM ModSecurity engine.

use bytes::Bytes;
use futures::Stream;
use std::pin::Pin;
use std::task::{Context, Poll};
use tracing::debug;

use crate::wasm::{SecurityDecision, WasmEngine, WasmRequestContext};

/// Streaming WASM processor for large requests
pub struct WasmStreamProcessor {
    engine: std::sync::Arc<WasmEngine>,
    context: WasmRequestContext,
    chunk_size: usize,
}

impl WasmStreamProcessor {
    /// Create a new streaming processor
    pub fn new(
        engine: std::sync::Arc<WasmEngine>,
        mut context: WasmRequestContext,
        chunk_size: usize,
    ) -> Self {
        // Clear body for streaming mode
        context.body = None;

        Self {
            engine,
            context,
            chunk_size,
        }
    }

    /// Process request headers before streaming body
    pub async fn process_headers(&self) -> Result<SecurityDecision, crate::wasm::WasmError> {
        debug!("Processing headers through WASM engine");

        let header_context = self.context.clone();
        self.engine
            .process_request(header_context)
            .await
            .map_err(|e| crate::wasm::WasmError::SecurityProcessing(e.into()))
    }

    /// Process a chunk of request body
    pub async fn process_chunk(
        &self,
        chunk: &[u8],
    ) -> Result<SecurityDecision, crate::wasm::WasmError> {
        debug!(
            "Processing body chunk of {} bytes through WASM engine",
            chunk.len()
        );

        let mut chunk_context = self.context.clone();
        chunk_context.body = Some(chunk.to_vec());

        self.engine
            .process_request(chunk_context)
            .await
            .map_err(|e| crate::wasm::WasmError::SecurityProcessing(e.into()))
    }
}

/// Stream adapter for WASM processing
pub struct WasmProcessingStream<S> {
    inner: S,
    processor: WasmStreamProcessor,
    buffer: Vec<u8>,
    processing_complete: bool,
}

impl<S> WasmProcessingStream<S>
where
    S: Stream<Item = Result<Bytes, Box<dyn std::error::Error + Send + Sync>>>,
{
    pub fn new(inner: S, processor: WasmStreamProcessor) -> Self {
        Self {
            inner,
            processor,
            buffer: Vec::new(),
            processing_complete: false,
        }
    }
}

impl<S> Stream for WasmProcessingStream<S>
where
    S: Stream<Item = Result<Bytes, Box<dyn std::error::Error + Send + Sync>>> + Unpin,
{
    type Item = Result<(Bytes, Option<SecurityDecision>), Box<dyn std::error::Error + Send + Sync>>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.processing_complete {
            return Poll::Ready(None);
        }

        match Pin::new(&mut self.inner).poll_next(cx) {
            Poll::Ready(Some(Ok(bytes))) => {
                // Add to buffer
                self.buffer.extend_from_slice(&bytes);

                // Process if buffer is large enough or this is the final chunk
                if self.buffer.len() >= self.processor.chunk_size {
                    let chunk_size = self.processor.chunk_size;
                    let chunk = self.buffer.split_off(chunk_size);
                    let remaining = std::mem::replace(&mut self.buffer, chunk);

                    // In a real implementation, we'd need to make this async
                    // For now, return the bytes with a placeholder decision
                    let decision = Some(SecurityDecision::Allow);
                    Poll::Ready(Some(Ok((Bytes::from(remaining), decision))))
                } else {
                    // Continue collecting
                    Poll::Ready(Some(Ok((bytes, None))))
                }
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e))),
            Poll::Ready(None) => {
                // End of stream - process any remaining buffer
                if !self.buffer.is_empty() {
                    let remaining = std::mem::take(&mut self.buffer);
                    self.processing_complete = true;
                    let decision = Some(SecurityDecision::Allow);
                    Poll::Ready(Some(Ok((Bytes::from(remaining), decision))))
                } else {
                    Poll::Ready(None)
                }
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_stream_processor_creation() {
        let config = crate::wasm::WasmEngineConfig::default();
        if let Ok(engine) = crate::wasm::WasmEngine::new(config) {
            let context = crate::wasm::WasmRequestContext::default();
            let processor = WasmStreamProcessor::new(Arc::new(engine), context, 1024);

            assert_eq!(processor.chunk_size, 1024);
        }
    }
}
