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

#[cfg(all(feature = "io-uring", target_os = "linux"))]
use super::uring::{
    Uring, IORING_ACCEPT_MULTISHOT, IORING_CQE_F_MORE, IORING_OP_ACCEPT, IORING_OP_READ,
    IORING_OP_WRITE,
};
#[cfg(all(feature = "io-uring", target_os = "linux"))]
use std::os::unix::io::RawFd;
#[cfg(all(feature = "io-uring", target_os = "linux"))]
use tokio::sync::{mpsc, oneshot};

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
            if total_copied.is_multiple_of(self.config.buffer_size as u64 * 16) {
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
            avg_read_latency_us: total_read_latency.checked_div(read_ops).unwrap_or(0),
            avg_write_latency_us: total_write_latency.checked_div(write_ops).unwrap_or(0),
            zero_copy_ops: self.zero_copy_ops.load(Ordering::Relaxed),
            bidirectional_copy_ops: self.bidirectional_copy_ops.load(Ordering::Relaxed),
            bytes_forwarded: self.bytes_forwarded.load(Ordering::Relaxed),
            forward_ops: self.forward_ops.load(Ordering::Relaxed),
        }
    }
}

// ---------------------------------------------------------------------------
// io_uring network backend
// ---------------------------------------------------------------------------
//
// The `NetworkIo` trait is stream-oriented, which cannot expose the raw fd that
// io_uring needs. This handler therefore provides a real fd-based fast path
// (`read_fd`/`write_fd`/`accept_fd` + multishot accept) for the connection
// layer, and implements the stream trait by delegating to the tokio fallback so
// existing callers keep working unchanged. When kernel setup fails, `new`
// returns an error and callers fall back to `NetworkIoHandler`.

#[cfg(all(feature = "io-uring", target_os = "linux"))]
enum UringCommand {
    Read {
        fd: RawFd,
        len: usize,
        reply: oneshot::Sender<Result<(Vec<u8>, usize)>>,
    },
    Write {
        fd: RawFd,
        buf: Bytes,
        reply: oneshot::Sender<Result<usize>>,
    },
    Accept {
        fd: RawFd,
        reply: oneshot::Sender<Result<RawFd>>,
    },
    Shutdown {
        reply: oneshot::Sender<()>,
    },
}

#[cfg(all(feature = "io-uring", target_os = "linux"))]
enum PendingOp {
    Read {
        buf: Vec<u8>,
        reply: oneshot::Sender<Result<(Vec<u8>, usize)>>,
    },
    Write {
        // Keeps the payload alive until the kernel reports completion.
        _buf: Bytes,
        reply: oneshot::Sender<Result<usize>>,
    },
    Accept {
        reply: oneshot::Sender<Result<RawFd>>,
    },
}

/// Fixed-size read buffer pool. Buffers are handed back after the completion
/// is copied out, so the hot path stops allocating (and zeroing) a fresh
/// `Vec` for every read.
#[cfg(all(feature = "io-uring", target_os = "linux"))]
struct ReadPool {
    buf_size: usize,
    max_free: usize,
    free: Vec<Vec<u8>>,
}

#[cfg(all(feature = "io-uring", target_os = "linux"))]
impl ReadPool {
    fn new(buf_size: usize, max_free: usize) -> Self {
        Self {
            buf_size: buf_size.max(1),
            max_free,
            free: Vec::new(),
        }
    }

    fn take(&mut self, len: usize) -> Vec<u8> {
        if len <= self.buf_size {
            self.free.pop().unwrap_or_else(|| vec![0u8; self.buf_size])
        } else {
            // Oversized read: fall back to a one-off allocation and let it
            // drop rather than caching an unbounded buffer.
            vec![0u8; len]
        }
    }

    fn give(&mut self, buf: Vec<u8>) {
        if buf.len() == self.buf_size && self.free.len() < self.max_free {
            self.free.push(buf);
        }
    }
}

#[cfg(all(feature = "io-uring", target_os = "linux"))]
fn io_error(res: i32) -> anyhow::Error {
    std::io::Error::from_raw_os_error(-res).into()
}

#[cfg(all(feature = "io-uring", target_os = "linux"))]
fn complete_op(op: PendingOp, res: i32, pool: &mut ReadPool) {
    match op {
        PendingOp::Read { buf, reply } => {
            if res < 0 {
                pool.give(buf);
                let _ = reply.send(Err(io_error(res)));
            } else {
                let n = (res as usize).min(buf.len());
                let out = buf[..n].to_vec();
                pool.give(buf);
                let _ = reply.send(Ok((out, n)));
            }
        }
        PendingOp::Write { reply, .. } => {
            if res < 0 {
                let _ = reply.send(Err(io_error(res)));
            } else {
                let _ = reply.send(Ok(res as usize));
            }
        }
        PendingOp::Accept { reply } => {
            if res < 0 {
                let _ = reply.send(Err(io_error(res)));
            } else {
                let _ = reply.send(Ok(res as RawFd));
            }
        }
    }
}

#[cfg(all(feature = "io-uring", target_os = "linux"))]
fn fail_pending(op: PendingOp, pool: &mut ReadPool) {
    match op {
        PendingOp::Read { buf, reply } => {
            pool.give(buf);
            let _ = reply.send(Err(anyhow::anyhow!("io_uring loop stopped")));
        }
        PendingOp::Write { reply, .. } => {
            let _ = reply.send(Err(anyhow::anyhow!("io_uring loop stopped")));
        }
        PendingOp::Accept { reply } => {
            let _ = reply.send(Err(anyhow::anyhow!("io_uring loop stopped")));
        }
    }
}

/// Ring thread: accepts commands from many async callers, keeps up to half the
/// ring depth in flight, submits them with one `io_uring_enter`, and dispatches
/// completions as they arrive (which may be out of order).
#[cfg(all(feature = "io-uring", target_os = "linux"))]
fn run_uring_loop(ring: Uring, mut rx: mpsc::Receiver<UringCommand>, buf_size: usize) {
    use std::collections::HashMap;

    let max_inflight = (ring.entries() as usize).max(2) / 2;
    let mut pending: HashMap<u64, PendingOp> = HashMap::with_capacity(max_inflight);
    let mut pool = ReadPool::new(buf_size, max_inflight.max(8));
    let mut next_id: u64 = 1;
    let mut shutting_down = false;
    let mut deferred: Option<UringCommand> = None;

    loop {
        // Fill the in-flight window without blocking. Every command becomes
        // one SQE; the whole batch is submitted by the single enter below.
        while !shutting_down && pending.len() < max_inflight {
            let cmd = match deferred.take() {
                Some(cmd) => cmd,
                None => match rx.try_recv() {
                    Ok(cmd) => cmd,
                    Err(mpsc::error::TryRecvError::Empty) => break,
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        shutting_down = true;
                        break;
                    }
                },
            };

            match cmd {
                UringCommand::Read { fd, len, reply } => {
                    if len == 0 {
                        let _ = reply.send(Ok((Vec::new(), 0)));
                        continue;
                    }
                    let mut buf = pool.take(len);
                    let id = next_id;
                    next_id = next_id.wrapping_add(1);
                    let ptr = buf.as_mut_ptr() as u64;
                    let pushed = ring.push(|sqe| {
                        sqe.opcode = IORING_OP_READ;
                        sqe.fd = fd;
                        sqe.addr = ptr;
                        sqe.len = len as u32;
                        sqe.user_data = id;
                    });
                    if !pushed {
                        pool.give(buf);
                        let _ =
                            reply.send(Err(anyhow::anyhow!("io_uring submission queue is full")));
                        break;
                    }
                    pending.insert(id, PendingOp::Read { buf, reply });
                }
                UringCommand::Write { fd, buf, reply } => {
                    if buf.is_empty() {
                        let _ = reply.send(Ok(0));
                        continue;
                    }
                    let id = next_id;
                    next_id = next_id.wrapping_add(1);
                    let ptr = buf.as_ptr() as u64;
                    let len = buf.len() as u32;
                    let pushed = ring.push(|sqe| {
                        sqe.opcode = IORING_OP_WRITE;
                        sqe.fd = fd;
                        sqe.addr = ptr;
                        sqe.len = len;
                        sqe.user_data = id;
                    });
                    if !pushed {
                        let _ =
                            reply.send(Err(anyhow::anyhow!("io_uring submission queue is full")));
                        break;
                    }
                    pending.insert(id, PendingOp::Write { _buf: buf, reply });
                }
                UringCommand::Accept { fd, reply } => {
                    let id = next_id;
                    next_id = next_id.wrapping_add(1);
                    let pushed = ring.push(|sqe| {
                        sqe.opcode = IORING_OP_ACCEPT;
                        sqe.fd = fd;
                        // NULL sockaddr is allowed; the caller resolves the
                        // peer address from the accepted fd.
                        sqe.addr = 0;
                        sqe.off = 0;
                        sqe.user_data = id;
                    });
                    if !pushed {
                        let _ =
                            reply.send(Err(anyhow::anyhow!("io_uring submission queue is full")));
                        break;
                    }
                    pending.insert(id, PendingOp::Accept { reply });
                }
                UringCommand::Shutdown { reply } => {
                    let _ = reply.send(());
                    shutting_down = true;
                }
            }
        }

        // Reap everything already posted before deciding to wait.
        while let Some(cqe) = ring.peek_cqe() {
            ring.cqe_seen();
            if let Some(op) = pending.remove(&cqe.user_data) {
                complete_op(op, cqe.res, &mut pool);
            }
        }

        if shutting_down {
            for (_, op) in pending.drain() {
                fail_pending(op, &mut pool);
            }
            break;
        }

        if pending.is_empty() {
            match rx.blocking_recv() {
                Some(cmd) => deferred = Some(cmd),
                None => break,
            }
            continue;
        }

        // One enter submits the whole batch and waits for at least one
        // completion; already-submitted ops just wait.
        if let Err(e) = ring.submit(1) {
            eprintln!("io_uring submit failed: {e}");
            for (_, op) in pending.drain() {
                fail_pending(op, &mut pool);
            }
            break;
        }
    }
}

#[cfg(all(feature = "io-uring", target_os = "linux"))]
#[derive(Clone)]
pub struct IoUringNetworkHandler {
    config: IoConfig,
    stats: Arc<NetworkStatsTracker>,
    fallback: NetworkIoHandler,
    tx: mpsc::Sender<UringCommand>,
}

#[cfg(all(feature = "io-uring", target_os = "linux"))]
impl IoUringNetworkHandler {
    /// Build a real io_uring handler. Returns an error (never panics) when the
    /// kernel or seccomp policy does not allow io_uring; callers should then
    /// use `NetworkIoHandler`.
    pub fn new(config: IoConfig) -> Result<Self> {
        let entries = (config.concurrency.max(64) * 2) as u32;
        // SQPOLL needs extra privileges and was not beneficial on this host, so
        // it stays opt-in for measurement instead of being the default.
        let sqpoll = std::env::var_os("WAF_IO_URING_SQPOLL").is_some();
        let ring = if sqpoll {
            Uring::new_sqpoll(entries).or_else(|e| {
                tracing::warn!(error = %e, "io_uring SQPOLL unavailable; using normal ring");
                Uring::new(entries)
            })
        } else {
            Uring::new(entries)
        }
        .map_err(|e| anyhow::anyhow!("io_uring setup failed: {e}"))?;
        let (tx, rx) = mpsc::channel((config.concurrency.max(64) * 4).max(256));
        let buf_size = config.buffer_size;
        std::thread::Builder::new()
            .name("io-uring-loop".into())
            .spawn(move || run_uring_loop(ring, rx, buf_size))
            .map_err(|e| anyhow::anyhow!("failed to spawn io_uring loop: {e}"))?;
        tracing::info!(
            entries,
            concurrency = config.concurrency,
            sqpoll,
            "io_uring network backend initialised"
        );
        Ok(Self {
            stats: Arc::new(NetworkStatsTracker::new()),
            fallback: NetworkIoHandler::new(config.clone()),
            config,
            tx,
        })
    }

    pub fn get_stats(&self) -> NetworkIoStats {
        self.stats.get_stats()
    }

    pub fn allocate_buffer(&self) -> BytesMut {
        BytesMut::with_capacity(self.config.buffer_size)
    }

    /// Read up to `len` bytes from `fd` with a registered-buffer-capable SQE.
    pub async fn read_fd(&self, fd: RawFd, len: usize) -> Result<(Vec<u8>, usize)> {
        let start = Instant::now();
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(UringCommand::Read { fd, len, reply })
            .await
            .map_err(|_| anyhow::anyhow!("io_uring loop unavailable"))?;
        let res = rx
            .await
            .map_err(|_| anyhow::anyhow!("io_uring loop dropped"))??;
        let latency = start.elapsed().as_micros() as u64;
        self.stats.record_read(res.1 as u64, latency);
        if self.config.enable_zero_copy {
            self.stats.record_zero_copy();
        }
        Ok(res)
    }

    /// Write the whole buffer to `fd`, handling partial writes.
    pub async fn write_fd(&self, fd: RawFd, buf: &[u8]) -> Result<()> {
        let start = Instant::now();
        if buf.is_empty() {
            return Ok(());
        }
        // Copy once into a ref-counted buffer; retries for partial writes then
        // slice it instead of allocating a new Vec per chunk.
        let data = Bytes::copy_from_slice(buf);
        let mut written = 0usize;
        while written < data.len() {
            let chunk = data.slice(written..);
            let (reply, rx) = oneshot::channel();
            self.tx
                .send(UringCommand::Write {
                    fd,
                    buf: chunk,
                    reply,
                })
                .await
                .map_err(|_| anyhow::anyhow!("io_uring loop unavailable"))?;
            let n = rx
                .await
                .map_err(|_| anyhow::anyhow!("io_uring loop dropped"))??;
            if n == 0 {
                anyhow::bail!("io_uring write returned 0 before completing");
            }
            written += n;
        }
        let latency = start.elapsed().as_micros() as u64;
        self.stats.record_write(buf.len() as u64, latency);
        if self.config.enable_zero_copy {
            self.stats.record_zero_copy();
        }
        Ok(())
    }

    /// Accept a single connection from `listener_fd`.
    pub async fn accept_fd(&self, listener_fd: RawFd) -> Result<RawFd> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(UringCommand::Accept {
                fd: listener_fd,
                reply,
            })
            .await
            .map_err(|_| anyhow::anyhow!("io_uring loop unavailable"))?;
        rx.await
            .map_err(|_| anyhow::anyhow!("io_uring loop dropped"))?
    }

    /// Spawn a dedicated multishot-accept thread. Each accepted fd is sent on
    /// the returned channel until the acceptor is shut down or dropped.
    pub fn start_multishot_accept(
        &self,
        listener_fd: RawFd,
    ) -> Result<(mpsc::Receiver<RawFd>, MultishotAcceptor)> {
        start_multishot_accept(listener_fd)
    }

    /// Ask the background ring thread to stop. Dropping the handler also stops
    /// it via the channel closing.
    pub async fn shutdown(&self) {
        let (reply, rx) = oneshot::channel();
        if self.tx.send(UringCommand::Shutdown { reply }).await.is_ok() {
            let _ = rx.await;
        }
    }
}

/// Spawn a multishot-accept thread without constructing the read/write handler.
/// Used by the proxy listener, which only needs the accept fast path.
#[cfg(all(feature = "io-uring", target_os = "linux"))]
pub fn start_multishot_accept(
    listener_fd: RawFd,
) -> Result<(mpsc::Receiver<RawFd>, MultishotAcceptor)> {
    let ring = Uring::new(64)?;
    let (tx, rx) = mpsc::channel(256);
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let thread_stop = std::sync::Arc::clone(&stop);
    let handle = std::thread::Builder::new()
        .name("io-uring-accept".into())
        .spawn(move || run_multishot_accept(ring, listener_fd, tx, thread_stop))
        .map_err(|e| anyhow::anyhow!("failed to spawn accept loop: {e}"))?;
    Ok((
        rx,
        MultishotAcceptor {
            stop,
            handle: Some(handle),
        },
    ))
}

/// Handle to the multishot-accept thread. Dropping it stops the thread (within
/// one poll interval) so listener shutdown is deterministic.
#[cfg(all(feature = "io-uring", target_os = "linux"))]
pub struct MultishotAcceptor {
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

#[cfg(all(feature = "io-uring", target_os = "linux"))]
impl MultishotAcceptor {
    /// Stop the accept loop and wait for the thread to exit.
    pub fn shutdown(mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Release);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

#[cfg(all(feature = "io-uring", target_os = "linux"))]
impl Drop for MultishotAcceptor {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Release);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

#[cfg(all(feature = "io-uring", target_os = "linux"))]
fn arm_multishot_accept(ring: &Uring, listener_fd: RawFd) -> std::io::Result<()> {
    let pushed = ring.push(|sqe| {
        sqe.opcode = IORING_OP_ACCEPT;
        sqe.fd = listener_fd;
        // Multishot accept does not fill a sockaddr; addr/addr2 must be NULL.
        sqe.addr = 0;
        sqe.off = 0;
        // liburing also stores the multishot flag in sqe->ioprio.
        sqe.ioprio = IORING_ACCEPT_MULTISHOT as u16;
    });
    if !pushed {
        return Err(std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            "io_uring submission queue is full",
        ));
    }
    ring.submit(0)?;
    Ok(())
}

/// Multishot accept loop. The CQ ring fd is pollable, so the thread sleeps in
/// `poll(2)` instead of busy-spinning and still notices the stop flag promptly.
#[cfg(all(feature = "io-uring", target_os = "linux"))]
fn run_multishot_accept(
    ring: Uring,
    listener_fd: RawFd,
    tx: mpsc::Sender<RawFd>,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
) {
    use std::sync::atomic::Ordering;

    if let Err(e) = arm_multishot_accept(&ring, listener_fd) {
        eprintln!("multishot accept: arm failed: {e}");
        return;
    }
    let mut armed = true;

    loop {
        if stop.load(Ordering::Acquire) {
            break;
        }

        let mut pfd = libc::pollfd {
            fd: ring.fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // Bounded poll so shutdown never waits indefinitely.
        let ready = unsafe { libc::poll(&mut pfd, 1, 25) };
        if ready < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }
        if ready == 0 {
            continue;
        }

        while let Some(cqe) = ring.peek_cqe() {
            ring.cqe_seen();
            if cqe.res < 0 {
                let err = std::io::Error::from_raw_os_error(-cqe.res);
                match err.kind() {
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted => {}
                    _ => {
                        eprintln!("multishot accept: completion error: {err}");
                        // EMFILE/ENFILE and friends: back off before re-arming
                        // so the thread does not spin on a persistent error.
                        std::thread::sleep(std::time::Duration::from_millis(25));
                        armed = false;
                    }
                }
                if cqe.flags & IORING_CQE_F_MORE == 0 {
                    armed = false;
                }
                continue;
            }

            let fd = cqe.res as RawFd;
            if tx.blocking_send(fd).is_err() {
                // Receiver gone: close the accepted fd and stop.
                unsafe { libc::close(fd) };
                return;
            }
            if cqe.flags & IORING_CQE_F_MORE == 0 {
                armed = false;
            }
        }

        if !armed {
            match arm_multishot_accept(&ring, listener_fd) {
                Ok(()) => armed = true,
                Err(e) => {
                    eprintln!("multishot accept: re-arm failed: {e}");
                    std::thread::sleep(std::time::Duration::from_millis(25));
                }
            }
        }
    }
}

#[cfg(all(feature = "io-uring", target_os = "linux"))]
#[async_trait]
impl NetworkIo for IoUringNetworkHandler {
    async fn read_stream(&self, stream: &mut (dyn AsyncRead + Unpin + Send)) -> Result<Bytes> {
        // Stream objects hide their fd; use the tokio fallback for the trait.
        self.fallback.read_stream(stream).await
    }

    async fn write_stream(
        &self,
        stream: &mut (dyn AsyncWrite + Unpin + Send),
        data: &[u8],
    ) -> Result<()> {
        self.fallback.write_stream(stream, data).await
    }

    async fn copy_stream(
        &self,
        reader: &mut (dyn AsyncRead + Unpin + Send),
        writer: &mut (dyn AsyncWrite + Unpin + Send),
    ) -> Result<u64> {
        self.fallback.copy_stream(reader, writer).await
    }
}

#[cfg(all(test, feature = "io-uring", target_os = "linux"))]
mod uring_tests {
    use super::*;
    use crate::waf::io::IoBackend;
    use std::os::unix::io::AsRawFd;
    use tokio::net::{TcpListener, TcpStream};

    #[tokio::test]
    async fn read_write_roundtrip_or_fallback() {
        let config = IoConfig {
            backend: IoBackend::IoUring,
            enable_zero_copy: true,
            buffer_size: 1024,
            concurrency: 4,
        };
        let Ok(handler) = IoUringNetworkHandler::new(config) else {
            eprintln!("skipping: io_uring unavailable");
            return;
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::spawn(async move { TcpStream::connect(addr).await.unwrap() });
        let (server, _) = listener.accept().await.unwrap();
        let client = client.await.unwrap();

        handler
            .write_fd(server.as_raw_fd(), b"hello")
            .await
            .unwrap();
        let (buf, n) = handler.read_fd(client.as_raw_fd(), 16).await.unwrap();
        assert_eq!(n, 5);
        assert_eq!(&buf, b"hello");

        // Partial write path: large payload is looped internally.
        let big = vec![7u8; 5000];
        let writer = handler.write_fd(client.as_raw_fd(), &big);
        let reader = async {
            let mut got = Vec::new();
            while got.len() < big.len() {
                let (chunk, n) = handler.read_fd(server.as_raw_fd(), 4096).await.unwrap();
                if n == 0 {
                    break;
                }
                got.extend_from_slice(&chunk);
            }
            got
        };
        let (w, got) = tokio::join!(writer, reader);
        w.unwrap();
        assert_eq!(got.len(), big.len());
    }

    #[tokio::test]
    async fn shutdown_is_graceful() {
        let config = IoConfig {
            backend: IoBackend::IoUring,
            enable_zero_copy: false,
            buffer_size: 512,
            concurrency: 2,
        };
        let Ok(handler) = IoUringNetworkHandler::new(config) else {
            eprintln!("skipping: io_uring unavailable");
            return;
        };
        handler.shutdown().await;
    }

    #[tokio::test]
    async fn single_accept_or_skip() {
        let config = IoConfig {
            backend: IoBackend::IoUring,
            enable_zero_copy: false,
            buffer_size: 512,
            concurrency: 2,
        };
        let Ok(handler) = IoUringNetworkHandler::new(config) else {
            eprintln!("skipping: io_uring unavailable");
            return;
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::spawn(async move { TcpStream::connect(addr).await.unwrap() });
        let fd = handler.accept_fd(listener.as_raw_fd()).await;
        match fd {
            Ok(fd) => unsafe {
                libc::close(fd);
            },
            Err(e) => panic!("single accept failed: {e}"),
        }
        let _ = client.await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_reads_and_writes_stay_correct() {
        use std::sync::Arc;

        const CLIENTS: usize = 16;
        const ROUNDS: usize = 64;

        let config = IoConfig {
            backend: IoBackend::IoUring,
            enable_zero_copy: true,
            buffer_size: 8192,
            concurrency: 32,
        };
        let Ok(handler) = IoUringNetworkHandler::new(config) else {
            eprintln!("skipping: io_uring unavailable");
            return;
        };
        let handler = Arc::new(handler);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let mut clients = Vec::new();
        for i in 0..CLIENTS {
            clients.push(tokio::spawn(async move {
                let mut stream = TcpStream::connect(addr).await.unwrap();
                let payload = vec![i as u8 + 1; 256];
                for _ in 0..ROUNDS {
                    stream.write_all(&payload).await.unwrap();
                    let mut echoed = vec![0u8; payload.len()];
                    stream.read_exact(&mut echoed).await.unwrap();
                    assert_eq!(echoed, payload, "client {i} echo mismatch");
                }
            }));
        }

        let mut servers = Vec::new();
        for _ in 0..CLIENTS {
            let (stream, _) = listener.accept().await.unwrap();
            let handler = Arc::clone(&handler);
            servers.push(tokio::spawn(async move {
                use std::os::unix::io::AsRawFd;
                let fd = stream.as_raw_fd();
                // Keep the tokio stream alive while the ring owns the fd ops.
                let _stream = stream;
                for _ in 0..ROUNDS {
                    let mut got = Vec::new();
                    // Read with deliberately small chunks to exercise partial
                    // reads through the pipelined ring.
                    while got.len() < 256 {
                        let (chunk, n) = handler.read_fd(fd, 64).await.unwrap();
                        if n == 0 {
                            return;
                        }
                        got.extend_from_slice(&chunk);
                        if got.len() >= 256 {
                            break;
                        }
                    }
                    handler.write_fd(fd, &got).await.unwrap();
                }
            }));
        }

        for client in clients {
            client.await.unwrap();
        }
        for server in servers {
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn multishot_accept_or_skip() {
        let config = IoConfig {
            backend: IoBackend::IoUring,
            enable_zero_copy: false,
            buffer_size: 512,
            concurrency: 2,
        };
        let Ok(handler) = IoUringNetworkHandler::new(config) else {
            eprintln!("skipping: io_uring unavailable");
            return;
        };
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        // Queue a connection before arming multishot accept so DONTWAIT has
        // something to return immediately.
        let _client = std::thread::spawn(move || std::net::TcpStream::connect(addr).unwrap());
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let (mut accepted, _handle) = match handler.start_multishot_accept(listener.as_raw_fd()) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("skipping multishot accept: {e}");
                return;
            }
        };
        let fd = tokio::time::timeout(std::time::Duration::from_secs(2), accepted.recv())
            .await
            .ok()
            .flatten();
        assert!(fd.is_some(), "expected a multishot-accepted fd");
        if let Some(fd) = fd {
            unsafe { libc::close(fd) };
        }
    }
}
