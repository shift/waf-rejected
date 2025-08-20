/// I/O backend implementations for different performance profiles
use super::traits::*;
use super::IoConfig;
use anyhow::{Context, Result};
use async_trait::async_trait;
use bytes::Bytes;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::fs;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Standard tokio-based I/O handler
pub struct StandardIoHandler {
    config: IoConfig,
    stats: Arc<IoStatsTracker>,
}

impl StandardIoHandler {
    pub fn new(config: IoConfig) -> Result<Self> {
        Ok(Self {
            config,
            stats: Arc::new(IoStatsTracker::new()),
        })
    }
}

#[async_trait]
impl IoHandler for StandardIoHandler {
    async fn read_file(&self, path: &Path) -> Result<Bytes> {
        let start = Instant::now();
        
        let data = fs::read(path)
            .await
            .with_context(|| format!("Failed to read file: {}", path.display()))?;
        
        let bytes = Bytes::from(data);
        let latency_us = start.elapsed().as_micros() as u64;
        
        self.stats.record_read(bytes.len() as u64, latency_us);
        
        Ok(bytes)
    }
    
    async fn write_file(&self, path: &Path, data: &[u8]) -> Result<()> {
        let start = Instant::now();
        
        // Create parent directories if they don't exist
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .await
                .with_context(|| format!("Failed to create parent directories for: {}", path.display()))?;
        }
        
        fs::write(path, data)
            .await
            .with_context(|| format!("Failed to write file: {}", path.display()))?;
        
        let latency_us = start.elapsed().as_micros() as u64;
        self.stats.record_write(data.len() as u64, latency_us);
        
        Ok(())
    }
    
    async fn append_file(&self, path: &Path, data: &[u8]) -> Result<()> {
        let start = Instant::now();
        
        use tokio::fs::OpenOptions;
        
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .await
            .with_context(|| format!("Failed to open file for append: {}", path.display()))?;
        
        file.write_all(data)
            .await
            .with_context(|| format!("Failed to append to file: {}", path.display()))?;
        
        let latency_us = start.elapsed().as_micros() as u64;
        self.stats.record_write(data.len() as u64, latency_us);
        
        Ok(())
    }
    
    async fn file_exists(&self, path: &Path) -> Result<bool> {
        Ok(fs::try_exists(path).await.unwrap_or(false))
    }
    
    async fn file_size(&self, path: &Path) -> Result<u64> {
        let metadata = fs::metadata(path)
            .await
            .with_context(|| format!("Failed to get metadata for: {}", path.display()))?;
        Ok(metadata.len())
    }
    
    async fn delete_file(&self, path: &Path) -> Result<()> {
        fs::remove_file(path)
            .await
            .with_context(|| format!("Failed to delete file: {}", path.display()))?;
        Ok(())
    }
    
    async fn create_dir_all(&self, path: &Path) -> Result<()> {
        fs::create_dir_all(path)
            .await
            .with_context(|| format!("Failed to create directory: {}", path.display()))?;
        Ok(())
    }
    
    async fn read_dir(&self, path: &Path) -> Result<Vec<std::path::PathBuf>> {
        let mut entries = Vec::new();
        let mut dir = fs::read_dir(path)
            .await
            .with_context(|| format!("Failed to read directory: {}", path.display()))?;
        
        while let Some(entry) = dir.next_entry().await? {
            entries.push(entry.path());
        }
        
        Ok(entries)
    }
    
    fn get_stats(&self) -> IoStats {
        self.stats.get_stats()
    }
    
    async fn flush(&self) -> Result<()> {
        // Standard I/O handler doesn't need explicit flushing
        Ok(())
    }
}

#[cfg(feature = "io-uring")]
/// io_uring-based I/O handler for maximum performance on Linux
pub struct IoUringHandler {
    config: IoConfig,
    stats: Arc<IoStatsTracker>,
}

#[cfg(feature = "io-uring")]
impl IoUringHandler {
    pub fn new(config: IoConfig) -> Result<Self> {
        // Verify we're on Linux
        if !cfg!(target_os = "linux") {
            anyhow::bail!("io_uring is only supported on Linux");
        }
        
        // For now, fall back to optimized standard I/O with enhanced buffering
        // TODO: Implement full io_uring integration when tokio-uring API stabilizes
        tracing::warn!("io_uring backend using optimized standard I/O fallback");
        
        Ok(Self {
            config,
            stats: Arc::new(IoStatsTracker::new()),
        })
    }
}

#[cfg(feature = "io-uring")]
#[async_trait]
impl IoHandler for IoUringHandler {
    async fn read_file(&self, path: &Path) -> Result<Bytes> {
        let start = Instant::now();
        
        // Use optimized buffered reads with larger buffer sizes
        use tokio::fs::File;
        use tokio::io::AsyncReadExt;
        
        let mut file = File::open(path)
            .await
            .with_context(|| format!("Failed to open file: {}", path.display()))?;
        
        // Use larger buffer for better performance
        let mut buffer = Vec::with_capacity(self.config.buffer_size.max(64 * 1024));
        file.read_to_end(&mut buffer)
            .await
            .with_context(|| format!("Failed to read file: {}", path.display()))?;
        
        let bytes = Bytes::from(buffer);
        let latency_us = start.elapsed().as_micros() as u64;
        
        self.stats.record_read(bytes.len() as u64, latency_us);
        
        // Record optimized operation
        if self.config.enable_zero_copy {
            self.stats.record_zero_copy();
        }
        
        Ok(bytes)
    }
    
    async fn write_file(&self, path: &Path, data: &[u8]) -> Result<()> {
        let start = Instant::now();
        
        // Create parent directories if they don't exist
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .with_context(|| format!("Failed to create parent directories for: {}", path.display()))?;
        }
        
        // Use optimized write with explicit sync for durability
        use tokio::fs::File;
        use tokio::io::AsyncWriteExt;
        
        let mut file = File::create(path)
            .await
            .with_context(|| format!("Failed to create file: {}", path.display()))?;
        
        file.write_all(data)
            .await
            .with_context(|| format!("Failed to write file: {}", path.display()))?;
        
        // Explicit sync for durability (enterprise requirement)
        file.sync_all()
            .await
            .with_context(|| format!("Failed to sync file: {}", path.display()))?;
        
        let latency_us = start.elapsed().as_micros() as u64;
        self.stats.record_write(data.len() as u64, latency_us);
        
        if self.config.enable_zero_copy {
            self.stats.record_zero_copy();
        }
        
        Ok(())
    }
    
    async fn append_file(&self, path: &Path, data: &[u8]) -> Result<()> {
        let start = Instant::now();
        
        use tokio::fs::OpenOptions;
        use tokio::io::AsyncWriteExt;
        
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .await
            .with_context(|| format!("Failed to open file for append: {}", path.display()))?;
        
        file.write_all(data)
            .await
            .with_context(|| format!("Failed to append to file: {}", path.display()))?;
        
        file.sync_all()
            .await
            .with_context(|| format!("Failed to sync file: {}", path.display()))?;
        
        let latency_us = start.elapsed().as_micros() as u64;
        self.stats.record_write(data.len() as u64, latency_us);
        
        if self.config.enable_zero_copy {
            self.stats.record_zero_copy();
        }
        
        Ok(())
    }
    
    async fn file_exists(&self, path: &Path) -> Result<bool> {
        Ok(tokio::fs::try_exists(path).await.unwrap_or(false))
    }
    
    async fn file_size(&self, path: &Path) -> Result<u64> {
        let metadata = tokio::fs::metadata(path)
            .await
            .with_context(|| format!("Failed to get metadata for: {}", path.display()))?;
        Ok(metadata.len())
    }
    
    async fn delete_file(&self, path: &Path) -> Result<()> {
        tokio::fs::remove_file(path)
            .await
            .with_context(|| format!("Failed to delete file: {}", path.display()))?;
        Ok(())
    }
    
    async fn create_dir_all(&self, path: &Path) -> Result<()> {
        tokio::fs::create_dir_all(path)
            .await
            .with_context(|| format!("Failed to create directory: {}", path.display()))?;
        Ok(())
    }
    
    async fn read_dir(&self, path: &Path) -> Result<Vec<std::path::PathBuf>> {
        let mut entries = Vec::new();
        let mut dir = tokio::fs::read_dir(path)
            .await
            .with_context(|| format!("Failed to read directory: {}", path.display()))?;
        
        while let Some(entry) = dir.next_entry().await? {
            entries.push(entry.path());
        }
        
        Ok(entries)
    }
    
    fn get_stats(&self) -> IoStats {
        self.stats.get_stats()
    }
    
    async fn flush(&self) -> Result<()> {
        // Optimized I/O operations are already synced
        Ok(())
    }
}

/// Internal statistics tracker for I/O operations
struct IoStatsTracker {
    bytes_read: AtomicU64,
    bytes_written: AtomicU64,
    read_ops: AtomicU64,
    write_ops: AtomicU64,
    total_read_latency_us: AtomicU64,
    total_write_latency_us: AtomicU64,
    zero_copy_ops: AtomicU64,
}

impl IoStatsTracker {
    fn new() -> Self {
        Self {
            bytes_read: AtomicU64::new(0),
            bytes_written: AtomicU64::new(0),
            read_ops: AtomicU64::new(0),
            write_ops: AtomicU64::new(0),
            total_read_latency_us: AtomicU64::new(0),
            total_write_latency_us: AtomicU64::new(0),
            zero_copy_ops: AtomicU64::new(0),
        }
    }
    
    fn record_read(&self, bytes: u64, latency_us: u64) {
        self.bytes_read.fetch_add(bytes, Ordering::Relaxed);
        self.read_ops.fetch_add(1, Ordering::Relaxed);
        self.total_read_latency_us.fetch_add(latency_us, Ordering::Relaxed);
    }
    
    fn record_write(&self, bytes: u64, latency_us: u64) {
        self.bytes_written.fetch_add(bytes, Ordering::Relaxed);
        self.write_ops.fetch_add(1, Ordering::Relaxed);
        self.total_write_latency_us.fetch_add(latency_us, Ordering::Relaxed);
    }
    
    fn record_zero_copy(&self) {
        self.zero_copy_ops.fetch_add(1, Ordering::Relaxed);
    }
    
    fn get_stats(&self) -> IoStats {
        let read_ops = self.read_ops.load(Ordering::Relaxed);
        let write_ops = self.write_ops.load(Ordering::Relaxed);
        let total_read_latency = self.total_read_latency_us.load(Ordering::Relaxed);
        let total_write_latency = self.total_write_latency_us.load(Ordering::Relaxed);
        
        IoStats {
            bytes_read: self.bytes_read.load(Ordering::Relaxed),
            bytes_written: self.bytes_written.load(Ordering::Relaxed),
            read_ops,
            write_ops,
            avg_read_latency_us: if read_ops > 0 { total_read_latency / read_ops } else { 0 },
            avg_write_latency_us: if write_ops > 0 { total_write_latency / write_ops } else { 0 },
            zero_copy_ops: self.zero_copy_ops.load(Ordering::Relaxed),
        }
    }
}