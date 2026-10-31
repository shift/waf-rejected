/// Network I/O optimizations for high-performance proxying
use super::traits::*;
use super::IoConfig;
use anyhow::{Context, Result};
use async_trait::async_trait;
use bytes::{BufMut, Bytes, BytesMut};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// High-performance network I/O handler with zero-copy optimizations
#[derive(Clone)]
pub struct NetworkIoHandler {
    config: IoConfig,
    stats: Arc<NetworkStatsTracker>,
}

impl NetworkIoHandler {
    pub fn new(config: IoConfig) -> Self {
        Self {
            config,
            stats: Arc::new(NetworkStatsTracker::new()),
        }
    }

    /// Get network I/O statistics
    pub fn get_stats(&self) -> NetworkIoStats {
        self.stats.get_stats()
    }

    /// Copy data between streams with optimized buffering
    pub async fn copy_bidirectional_optimized<L, R>(
        &self,
        left: &mut L,
        right: &mut R,
    ) -> Result<(u64, u64)>
    where
        L: AsyncRead + AsyncWrite + Unpin + Send + ?Sized,
        R: AsyncRead + AsyncWrite + Unpin + Send + ?Sized,
    {
        use tokio::io::copy_bidirectional;

        let start = Instant::now();
        let result = copy_bidirectional(left, right)
            .await
            .context("Failed to copy data between streams")?;

        let duration = start.elapsed();
        self.stats
            .record_bidirectional_copy(result.0 + result.1, duration.as_micros() as u64);

        Ok(result)
    }

    /// Optimized buffer allocation for network operations
    pub fn allocate_buffer(&self) -> BytesMut {
        BytesMut::with_capacity(self.config.buffer_size)
    }

    /// Read with optimal buffer sizing
    pub async fn read_with_buffer<R>(&self, stream: &mut R, buffer: &mut BytesMut) -> Result<usize>
    where
        R: AsyncRead + Unpin + Send + ?Sized,
    {
        let start = Instant::now();

        // Ensure buffer has capacity
        if buffer.remaining_mut() < self.config.buffer_size {
            buffer.reserve(self.config.buffer_size);
        }

        let bytes_read = stream
            .read_buf(buffer)
            .await
            .context("Failed to read from network stream")?;

        let latency_us = start.elapsed().as_micros() as u64;
        self.stats.record_read(bytes_read as u64, latency_us);

        Ok(bytes_read)
    }

    /// Write with optimal chunking
    pub async fn write_with_chunking<W>(&self, stream: &mut W, data: &[u8]) -> Result<()>
    where
        W: AsyncWrite + Unpin + Send + ?Sized,
    {
        let start = Instant::now();
        let chunk_size = self.config.buffer_size;

        if data.len() <= chunk_size {
            // Small write - send directly
            stream
                .write_all(data)
                .await
                .context("Failed to write to network stream")?;
        } else {
            // Large write - chunk it
            for chunk in data.chunks(chunk_size) {
                stream
                    .write_all(chunk)
                    .await
                    .context("Failed to write chunk to network stream")?;
            }
        }

        let latency_us = start.elapsed().as_micros() as u64;
        self.stats.record_write(data.len() as u64, latency_us);

        Ok(())
    }

    /// Efficient stream forwarding with minimal allocations
    pub async fn forward_stream<R, W>(
        &self,
        reader: &mut R,
        writer: &mut W,
        max_bytes: Option<u64>,
    ) -> Result<u64>
    where
        R: AsyncRead + Unpin + Send + ?Sized,
        W: AsyncWrite + Unpin + Send + ?Sized,
    {
        let start = Instant::now();
        let mut total_copied = 0u64;
        let mut buffer = self.allocate_buffer();

        loop {
            // Check if we've reached the limit
            if let Some(limit) = max_bytes {
                if total_copied >= limit {
                    break;
                }
            }

            // Read into buffer
            buffer.clear();
            let bytes_read = self.read_with_buffer(reader, &mut buffer).await?;

            if bytes_read == 0 {
                break; // EOF reached
            }

            // Write from buffer
            writer
                .write_all(&buffer[..bytes_read])
                .await
                .context("Failed to write forwarded data")?;

            total_copied += bytes_read as u64;

            // Yield occasionally for fairness
            if total_copied % (self.config.buffer_size as u64 * 16) == 0 {
                tokio::task::yield_now().await;
            }
        }

        writer
            .flush()
            .await
            .context("Failed to flush forwarded data")?;

        let duration = start.elapsed();
        self.stats
            .record_forward(total_copied, duration.as_micros() as u64);

        Ok(total_copied)
    }
}

#[async_trait]
impl NetworkIo for NetworkIoHandler {
    async fn read_stream(&self, stream: &mut (dyn AsyncRead + Unpin + Send)) -> Result<Bytes> {
        let start = Instant::now();
        let mut buffer = self.allocate_buffer();

        let bytes_read = stream
            .read_buf(&mut buffer)
            .await
            .context("Failed to read from network stream")?;

        let result = buffer.freeze().slice(0..bytes_read);
        let latency_us = start.elapsed().as_micros() as u64;

        self.stats.record_read(bytes_read as u64, latency_us);

        if self.config.enable_zero_copy {
            self.stats.record_zero_copy();
        }

        Ok(result)
    }

    async fn write_stream(
        &self,
        stream: &mut (dyn AsyncWrite + Unpin + Send),
        data: &[u8],
    ) -> Result<()> {
        let start = Instant::now();

        stream
            .write_all(data)
            .await
            .context("Failed to write to network stream")?;

        let latency_us = start.elapsed().as_micros() as u64;
        self.stats.record_write(data.len() as u64, latency_us);

        if self.config.enable_zero_copy {
            self.stats.record_zero_copy();
        }

        Ok(())
    }

    async fn copy_stream(
        &self,
        reader: &mut (dyn AsyncRead + Unpin + Send),
        writer: &mut (dyn AsyncWrite + Unpin + Send),
    ) -> Result<u64> {
        self.forward_stream(reader, writer, None).await
    }
}

/// Network I/O performance statistics
#[derive(Debug, Clone, Default)]
pub struct NetworkIoStats {
    /// Total bytes read from network
    pub bytes_read: u64,
    /// Total bytes written to network
    pub bytes_written: u64,
    /// Number of network read operations
    pub read_ops: u64,
    /// Number of network write operations
    pub write_ops: u64,
    /// Average read latency in microseconds
    pub avg_read_latency_us: u64,
    /// Average write latency in microseconds
    pub avg_write_latency_us: u64,
    /// Number of zero-copy operations
    pub zero_copy_ops: u64,
    /// Number of bidirectional copy operations
    pub bidirectional_copy_ops: u64,
    /// Total bytes forwarded
    pub bytes_forwarded: u64,
    /// Number of forward operations
    pub forward_ops: u64,
}

impl NetworkIoStats {
    /// Calculate total operations
    pub fn total_ops(&self) -> u64 {
        self.read_ops + self.write_ops + self.forward_ops
    }

    /// Calculate total bytes transferred
    pub fn total_bytes(&self) -> u64 {
        self.bytes_read + self.bytes_written + self.bytes_forwarded
    }

    /// Calculate average latency across all operations
    pub fn avg_latency_us(&self) -> u64 {
        let total_ops = self.read_ops + self.write_ops;
        if total_ops == 0 {
            return 0;
        }

        let total_latency = (self.read_ops * self.avg_read_latency_us)
            + (self.write_ops * self.avg_write_latency_us);
        total_latency / total_ops
    }

    /// Calculate throughput in bytes per second (requires duration context)
    pub fn throughput_bps(&self, duration_seconds: f64) -> f64 {
        if duration_seconds <= 0.0 {
            return 0.0;
        }
        self.total_bytes() as f64 / duration_seconds
    }
}

/// Internal statistics tracker for network I/O operations
struct NetworkStatsTracker {
    bytes_read: AtomicU64,
    bytes_written: AtomicU64,
    read_ops: AtomicU64,
    write_ops: AtomicU64,
    total_read_latency_us: AtomicU64,
    total_write_latency_us: AtomicU64,
    zero_copy_ops: AtomicU64,
    bidirectional_copy_ops: AtomicU64,
    bytes_forwarded: AtomicU64,
    forward_ops: AtomicU64,
}

impl NetworkStatsTracker {
    fn new() -> Self {
        Self {
            bytes_read: AtomicU64::new(0),
            bytes_written: AtomicU64::new(0),
            read_ops: AtomicU64::new(0),
            write_ops: AtomicU64::new(0),
            total_read_latency_us: AtomicU64::new(0),
            total_write_latency_us: AtomicU64::new(0),
            zero_copy_ops: AtomicU64::new(0),
            bidirectional_copy_ops: AtomicU64::new(0),
            bytes_forwarded: AtomicU64::new(0),
            forward_ops: AtomicU64::new(0),
        }
    }

    fn record_read(&self, bytes: u64, latency_us: u64) {
        self.bytes_read.fetch_add(bytes, Ordering::Relaxed);
        self.read_ops.fetch_add(1, Ordering::Relaxed);
        self.total_read_latency_us
            .fetch_add(latency_us, Ordering::Relaxed);
    }

    fn record_write(&self, bytes: u64, latency_us: u64) {
        self.bytes_written.fetch_add(bytes, Ordering::Relaxed);
        self.write_ops.fetch_add(1, Ordering::Relaxed);
        self.total_write_latency_us
            .fetch_add(latency_us, Ordering::Relaxed);
    }

    fn record_zero_copy(&self) {
        self.zero_copy_ops.fetch_add(1, Ordering::Relaxed);
    }

    fn record_bidirectional_copy(&self, bytes: u64, _latency_us: u64) {
        self.bidirectional_copy_ops.fetch_add(1, Ordering::Relaxed);
        self.bytes_forwarded.fetch_add(bytes, Ordering::Relaxed);
    }

    fn record_forward(&self, bytes: u64, _latency_us: u64) {
        self.forward_ops.fetch_add(1, Ordering::Relaxed);
        self.bytes_forwarded.fetch_add(bytes, Ordering::Relaxed);
    }

    fn get_stats(&self) -> NetworkIoStats {
        let read_ops = self.read_ops.load(Ordering::Relaxed);
        let write_ops = self.write_ops.load(Ordering::Relaxed);
        let total_read_latency = self.total_read_latency_us.load(Ordering::Relaxed);
        let total_write_latency = self.total_write_latency_us.load(Ordering::Relaxed);

        NetworkIoStats {
            bytes_read: self.bytes_read.load(Ordering::Relaxed),
            bytes_written: self.bytes_written.load(Ordering::Relaxed),
            read_ops,
            write_ops,
            avg_read_latency_us: if read_ops > 0 {
                total_read_latency / read_ops
            } else {
                0
            },
            avg_write_latency_us: if write_ops > 0 {
                total_write_latency / write_ops
            } else {
                0
            },
            zero_copy_ops: self.zero_copy_ops.load(Ordering::Relaxed),
            bidirectional_copy_ops: self.bidirectional_copy_ops.load(Ordering::Relaxed),
            bytes_forwarded: self.bytes_forwarded.load(Ordering::Relaxed),
            forward_ops: self.forward_ops.load(Ordering::Relaxed),
        }
    }
}
