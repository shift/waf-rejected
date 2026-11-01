//! High-performance buffer pooling for HTTP requests/responses
//!
//! This module provides object pools to eliminate allocations in hot paths,
//! designed for GKE/K8s deployment with optimal memory reuse patterns.

use bytes::{Bytes, BytesMut};
use http_body_util::Full;
use hyper::body::Incoming;
use parking_lot::Mutex;
use std::collections::VecDeque;
use std::sync::Arc;

/// Configurable buffer sizes optimized for typical HTTP traffic patterns
const SMALL_BUFFER_SIZE: usize = 4 * 1024; // 4KB - headers, small bodies
const MEDIUM_BUFFER_SIZE: usize = 64 * 1024; // 64KB - medium responses
const LARGE_BUFFER_SIZE: usize = 1024 * 1024; // 1MB - large uploads/downloads

/// Pool configuration optimized for GKE environments
const POOL_SIZE_SMALL: usize = 1000; // High frequency small requests
const POOL_SIZE_MEDIUM: usize = 200; // Medium frequency medium requests
const POOL_SIZE_LARGE: usize = 50; // Low frequency large requests

/// Reusable buffer wrapper with automatic pool return
pub struct PooledBuffer {
    inner: BytesMut,
    pool: Arc<BufferPool>,
    size_class: BufferSizeClass,
}

#[derive(Debug, Clone, Copy)]
enum BufferSizeClass {
    Small,
    Medium,
    Large,
}

impl PooledBuffer {
    /// Get a mutable reference to the buffer data
    pub fn as_mut(&mut self) -> &mut BytesMut {
        &mut self.inner
    }

    /// Copy the buffered data out and let this buffer return to the pool.
    ///
    /// A pooled `BytesMut` cannot be reused once its allocation has been
    /// converted into `Bytes`, so copying is the only way to keep the pool
    /// effective while handing the body to hyper.
    pub fn to_bytes(&self) -> Bytes {
        Bytes::copy_from_slice(&self.inner)
    }

    /// Consume the buffer as `Bytes` without returning it to the pool.
    ///
    /// This is intentionally not used by the proxy hot path because it defeats
    /// pooling; prefer [`PooledBuffer::to_bytes`].
    pub fn freeze(mut self) -> Bytes {
        let inner = std::mem::replace(&mut self.inner, BytesMut::new());
        std::mem::forget(self);
        inner.freeze()
    }

    /// Clear the buffer for reuse (called before returning to pool)
    fn clear(&mut self) {
        self.inner.clear();
    }

    /// Get current capacity
    pub fn capacity(&self) -> usize {
        self.inner.capacity()
    }

    /// Get current length
    pub fn len(&self) -> usize {
        self.inner.len()
    }
}

impl Drop for PooledBuffer {
    fn drop(&mut self) {
        // Clear and return to pool
        self.clear();
        self.pool
            .return_buffer(std::mem::take(&mut self.inner), self.size_class);
    }
}

/// High-performance buffer pool with size classes
///
/// Optimized for GKE/K8s environments where memory allocation patterns
/// are critical for performance under containerized workloads.
pub struct BufferPool {
    small_buffers: Mutex<VecDeque<BytesMut>>,
    medium_buffers: Mutex<VecDeque<BytesMut>>,
    large_buffers: Mutex<VecDeque<BytesMut>>,
}

impl BufferPool {
    /// Create a new buffer pool with pre-allocated buffers
    pub fn new() -> Arc<Self> {
        let pool = Arc::new(Self {
            small_buffers: Mutex::new(VecDeque::new()),
            medium_buffers: Mutex::new(VecDeque::new()),
            large_buffers: Mutex::new(VecDeque::new()),
        });

        // Pre-allocate buffers to avoid allocation during hot path
        pool.preallocate_buffers();
        pool
    }

    /// Pre-allocate buffers for immediate availability
    fn preallocate_buffers(&self) {
        // Pre-allocate small buffers
        let mut small_pool = self.small_buffers.lock();
        for _ in 0..POOL_SIZE_SMALL {
            small_pool.push_back(BytesMut::with_capacity(SMALL_BUFFER_SIZE));
        }

        // Pre-allocate medium buffers
        let mut medium_pool = self.medium_buffers.lock();
        for _ in 0..POOL_SIZE_MEDIUM {
            medium_pool.push_back(BytesMut::with_capacity(MEDIUM_BUFFER_SIZE));
        }

        // Pre-allocate large buffers
        let mut large_pool = self.large_buffers.lock();
        for _ in 0..POOL_SIZE_LARGE {
            large_pool.push_back(BytesMut::with_capacity(LARGE_BUFFER_SIZE));
        }
    }

    /// Get a buffer optimized for the expected size
    pub fn get_buffer(self: &Arc<Self>, expected_size: usize) -> PooledBuffer {
        let (size_class, pool, fallback_size) = if expected_size <= SMALL_BUFFER_SIZE {
            (
                BufferSizeClass::Small,
                &self.small_buffers,
                SMALL_BUFFER_SIZE,
            )
        } else if expected_size <= MEDIUM_BUFFER_SIZE {
            (
                BufferSizeClass::Medium,
                &self.medium_buffers,
                MEDIUM_BUFFER_SIZE,
            )
        } else {
            (
                BufferSizeClass::Large,
                &self.large_buffers,
                LARGE_BUFFER_SIZE,
            )
        };

        let inner = {
            let mut pool_guard = pool.lock();
            pool_guard
                .pop_front()
                .unwrap_or_else(|| BytesMut::with_capacity(fallback_size))
        };

        PooledBuffer {
            inner,
            pool: self.clone(),
            size_class,
        }
    }

    /// Get a small buffer for headers and control data
    pub fn get_small_buffer(self: &Arc<Self>) -> PooledBuffer {
        self.get_buffer(SMALL_BUFFER_SIZE)
    }

    /// Get a medium buffer for typical HTTP responses
    pub fn get_medium_buffer(self: &Arc<Self>) -> PooledBuffer {
        self.get_buffer(MEDIUM_BUFFER_SIZE)
    }

    /// Get a large buffer for file uploads/downloads
    pub fn get_large_buffer(self: &Arc<Self>) -> PooledBuffer {
        self.get_buffer(LARGE_BUFFER_SIZE)
    }

    /// Return a buffer to the appropriate pool
    fn return_buffer(&self, buffer: BytesMut, size_class: BufferSizeClass) {
        // Only return to pool if capacity matches expected size
        let (pool, expected_capacity) = match size_class {
            BufferSizeClass::Small => (&self.small_buffers, SMALL_BUFFER_SIZE),
            BufferSizeClass::Medium => (&self.medium_buffers, MEDIUM_BUFFER_SIZE),
            BufferSizeClass::Large => (&self.large_buffers, LARGE_BUFFER_SIZE),
        };

        // Only pool buffers with correct capacity to prevent memory growth
        if buffer.capacity() == expected_capacity {
            let mut pool_guard = pool.lock();

            // Limit pool size to prevent unbounded memory growth in K8s
            let max_pool_size = match size_class {
                BufferSizeClass::Small => POOL_SIZE_SMALL,
                BufferSizeClass::Medium => POOL_SIZE_MEDIUM,
                BufferSizeClass::Large => POOL_SIZE_LARGE,
            };

            if pool_guard.len() < max_pool_size {
                pool_guard.push_back(buffer);
            }
            // Otherwise drop the buffer (let it deallocate)
        }
    }

    /// Get pool statistics for monitoring
    pub fn stats(&self) -> PoolStats {
        PoolStats {
            small_available: self.small_buffers.lock().len(),
            medium_available: self.medium_buffers.lock().len(),
            large_available: self.large_buffers.lock().len(),
            small_capacity: POOL_SIZE_SMALL,
            medium_capacity: POOL_SIZE_MEDIUM,
            large_capacity: POOL_SIZE_LARGE,
        }
    }
}

impl Default for BufferPool {
    fn default() -> Self {
        Self {
            small_buffers: Mutex::new(VecDeque::new()),
            medium_buffers: Mutex::new(VecDeque::new()),
            large_buffers: Mutex::new(VecDeque::new()),
        }
    }
}

/// Buffer pool statistics for monitoring and alerting
#[derive(Debug, Clone)]
pub struct PoolStats {
    pub small_available: usize,
    pub medium_available: usize,
    pub large_available: usize,
    pub small_capacity: usize,
    pub medium_capacity: usize,
    pub large_capacity: usize,
}

impl PoolStats {
    /// Calculate utilization percentage for monitoring
    pub fn utilization(&self) -> f64 {
        let total_used = (self.small_capacity - self.small_available)
            + (self.medium_capacity - self.medium_available)
            + (self.large_capacity - self.large_available);
        let total_capacity = self.small_capacity + self.medium_capacity + self.large_capacity;

        (total_used as f64 / total_capacity as f64) * 100.0
    }

    /// Check if pool exhaustion is imminent (for alerting)
    pub fn is_pool_pressure(&self) -> bool {
        self.utilization() > 85.0
    }
}

/// Errors returned while collecting a request body.
#[derive(Debug)]
pub enum BodyReadError {
    /// The body exceeded the configured maximum size.
    TooLarge { limit: usize },
    /// The body stream could not be read.
    Read(String),
}

impl std::fmt::Display for BodyReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BodyReadError::TooLarge { limit } => {
                write!(f, "request body exceeds limit of {} bytes", limit)
            }
            BodyReadError::Read(message) => write!(f, "failed to read request body: {}", message),
        }
    }
}

impl std::error::Error for BodyReadError {}

/// HTTP-specific buffer utilities
impl BufferPool {
    /// Create a pooled HTTP response body
    pub fn create_response_body(self: &Arc<Self>, data: Bytes) -> Full<Bytes> {
        Full::new(data)
    }

    /// Efficiently read an incoming HTTP body into a pooled buffer.
    ///
    /// `max_size` is enforced while streaming, including for chunked bodies
    /// that do not advertise a `Content-Length`. Any trailing header block
    /// (gRPC `grpc-status` / `grpc-message`) is returned alongside the data so
    /// the caller can re-emit it unchanged.
    pub async fn read_incoming_body(
        self: &Arc<Self>,
        body: Incoming,
        size_hint: Option<usize>,
        max_size: Option<usize>,
    ) -> Result<(PooledBuffer, Option<hyper::HeaderMap>), BodyReadError> {
        let expected_size = size_hint.unwrap_or(MEDIUM_BUFFER_SIZE);
        let mut buffer = self.get_buffer(expected_size);
        let mut trailers = None;

        // Stream body data into pooled buffer
        let mut body = std::pin::pin!(body);
        loop {
            let frame = http_body_util::BodyExt::frame(&mut body).await;
            let Some(frame) = frame else { break };
            let chunk = frame.map_err(|e| BodyReadError::Read(e.to_string()))?;
            match chunk.into_data() {
                Ok(data) => {
                    if let Some(limit) = max_size {
                        if buffer.len().saturating_add(data.len()) > limit {
                            return Err(BodyReadError::TooLarge { limit });
                        }
                    }
                    buffer.as_mut().extend_from_slice(&data);
                }
                Err(frame) => {
                    if let Ok(block) = frame.into_trailers() {
                        trailers = Some(block);
                    }
                }
            }
        }

        Ok((buffer, trailers))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_buffer_pool_basic() {
        let pool = BufferPool::new();

        // Test small buffer
        let small = pool.get_small_buffer();
        assert!(small.capacity() >= SMALL_BUFFER_SIZE);

        // Test medium buffer
        let medium = pool.get_medium_buffer();
        assert!(medium.capacity() >= MEDIUM_BUFFER_SIZE);

        // Test large buffer
        let large = pool.get_large_buffer();
        assert!(large.capacity() >= LARGE_BUFFER_SIZE);
    }

    #[test]
    fn test_pool_reuse() {
        let pool = BufferPool::new();
        let initial_stats = pool.stats();

        // Take and return a buffer
        {
            let _buffer = pool.get_small_buffer();
            let during_stats = pool.stats();
            assert_eq!(
                during_stats.small_available,
                initial_stats.small_available - 1
            );
        }

        // Buffer should be returned
        let final_stats = pool.stats();
        assert_eq!(final_stats.small_available, initial_stats.small_available);
    }

    #[test]
    fn test_pool_stats() {
        let pool = BufferPool::new();
        let stats = pool.stats();

        assert!(stats.utilization() < 100.0);
        assert_eq!(stats.small_capacity, POOL_SIZE_SMALL);
        assert_eq!(stats.medium_capacity, POOL_SIZE_MEDIUM);
        assert_eq!(stats.large_capacity, POOL_SIZE_LARGE);
    }
}
