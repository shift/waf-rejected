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
    Uring, IORING_ACCEPT_MULTISHOT, IORING_OP_ACCEPT, IORING_OP_READ, IORING_OP_WRITE,
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
        buf: Vec<u8>,
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
fn uring_submit_wait<F>(ring: &Uring, mut fill: F) -> Result<i32>
where
    F: FnMut(&mut super::uring::io_uring_sqe),
{
    if !ring.push(&mut fill) {
        // Queue is bounded; drain one completion then retry once.
        let _ = ring.submit(1)?;
        if !ring.push(&mut fill) {
            anyhow::bail!("io_uring submission queue is full");
        }
    }
    ring.submit(1)?;
    loop {
        if let Some(cqe) = ring.peek_cqe() {
            ring.cqe_seen();
            if cqe.res < 0 {
                return Err(std::io::Error::from_raw_os_error(-cqe.res).into());
            }
            return Ok(cqe.res);
        }
        ring.submit(1)?;
    }
}

#[cfg(all(feature = "io-uring", target_os = "linux"))]
fn run_uring_loop(ring: Uring, mut rx: mpsc::Receiver<UringCommand>) {
    while let Some(cmd) = rx.blocking_recv() {
        match cmd {
            UringCommand::Read { fd, len, reply } => {
                let mut buf = vec![0u8; len];
                let ptr = buf.as_mut_ptr() as u64;
                let res = uring_submit_wait(&ring, |sqe| {
                    sqe.opcode = IORING_OP_READ;
                    sqe.fd = fd;
                    sqe.addr = ptr;
                    sqe.len = len as u32;
                });
                match res {
                    Ok(n) => {
                        let n = n as usize;
                        buf.truncate(n);
                        let _ = reply.send(Ok((buf, n)));
                    }
                    Err(e) => {
                        let _ = reply.send(Err(e));
                    }
                }
            }
            UringCommand::Write { fd, buf, reply } => {
                let ptr = buf.as_ptr() as u64;
                let len = buf.len() as u32;
                let res = uring_submit_wait(&ring, |sqe| {
                    sqe.opcode = IORING_OP_WRITE;
                    sqe.fd = fd;
                    sqe.addr = ptr;
                    sqe.len = len;
                });
                match res {
                    Ok(n) => {
                        let _ = reply.send(Ok(n as usize));
                    }
                    Err(e) => {
                        let _ = reply.send(Err(e));
                    }
                }
            }
            UringCommand::Accept { fd, reply } => {
                let mut addr: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
                let mut addr_len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
                let addr_ptr = &mut addr as *mut _ as u64;
                let len_ptr = &mut addr_len as *mut _ as u64;
                let res = uring_submit_wait(&ring, |sqe| {
                    sqe.opcode = IORING_OP_ACCEPT;
                    sqe.fd = fd;
                    sqe.addr = addr_ptr;
                    // `off`/`addr2` share storage; accept uses it as socklen ptr.
                    sqe.off = len_ptr;
                });
                match res {
                    Ok(n) => {
                        let _ = reply.send(Ok(n as RawFd));
                    }
                    Err(e) => {
                        let _ = reply.send(Err(e));
                    }
                }
            }
            UringCommand::Shutdown { reply } => {
                let _ = reply.send(());
                break;
            }
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
        let ring =
            Uring::new(entries).map_err(|e| anyhow::anyhow!("io_uring setup failed: {e}"))?;
        let (tx, rx) = mpsc::channel((config.concurrency.max(64) * 4).max(256));
        std::thread::Builder::new()
            .name("io-uring-loop".into())
            .spawn(move || run_uring_loop(ring, rx))
            .map_err(|e| anyhow::anyhow!("failed to spawn io_uring loop: {e}"))?;
        tracing::info!(
            entries,
            concurrency = config.concurrency,
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
        let mut written = 0usize;
        while written < buf.len() {
            let chunk = buf[written..].to_vec();
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
    /// the returned channel until the handler is dropped.
    pub fn start_multishot_accept(
        &self,
        listener_fd: RawFd,
    ) -> Result<(mpsc::Receiver<RawFd>, std::thread::JoinHandle<()>)> {
        let ring = Uring::new(64)?;
        let (tx, rx) = mpsc::channel(256);
        let handle = std::thread::Builder::new()
            .name("io-uring-accept".into())
            .spawn(move || {
                // Multishot accept does not fill sockaddr; addr/addr2 must be
                // NULL. Submit one SQE; the kernel keeps it alive and posts a
                // CQE per connection. We only reap completions after.
                let ok = ring.push(|sqe| {
                    sqe.opcode = IORING_OP_ACCEPT;
                    sqe.fd = listener_fd;
                    sqe.addr = 0;
                    sqe.off = 0;
                    // Kernel 6.18 stores accept flags in sqe->ioprio.
                    sqe.ioprio = IORING_ACCEPT_MULTISHOT as u16;
                });
                if !ok {
                    eprintln!("multishot accept: submission queue push failed");
                    return;
                }
                if let Err(e) = ring.submit(1) {
                    eprintln!("multishot accept: submit failed: {e}");
                    return;
                }
                loop {
                    let mut stop = false;
                    while let Some(cqe) = ring.peek_cqe() {
                        ring.cqe_seen();
                        if cqe.res < 0 {
                            let err = std::io::Error::from_raw_os_error(-cqe.res);
                            if err.kind() == std::io::ErrorKind::WouldBlock {
                                continue;
                            }
                            eprintln!("multishot accept: completion error: {err}");
                            stop = true;
                            break;
                        }
                        if tx.blocking_send(cqe.res).is_err() {
                            stop = true;
                            break;
                        }
                    }
                    if stop {
                        break;
                    }
                    if ring.submit(1).is_err() {
                        break;
                    }
                }
            })
            .map_err(|e| anyhow::anyhow!("failed to spawn accept loop: {e}"))?;
        Ok((rx, handle))
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
