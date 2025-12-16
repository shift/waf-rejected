/// I/O traits for high-performance WAF operations
use async_trait::async_trait;
use anyhow::Result;
use bytes::Bytes;
use std::path::Path;

/// High-performance I/O operations interface
#[async_trait]
pub trait IoHandler: Send + Sync {
    /// Read a file asynchronously with optional zero-copy optimization
    async fn read_file(&self, path: &Path) -> Result<Bytes>;
    
    /// Write data to a file asynchronously with optional zero-copy optimization
    async fn write_file(&self, path: &Path, data: &[u8]) -> Result<()>;
    
    /// Append data to a file asynchronously
    async fn append_file(&self, path: &Path, data: &[u8]) -> Result<()>;
    
    /// Check if a file exists
    async fn file_exists(&self, path: &Path) -> Result<bool>;
    
    /// Get file size
    async fn file_size(&self, path: &Path) -> Result<u64>;
    
    /// Delete a file
    async fn delete_file(&self, path: &Path) -> Result<()>;
    
    /// Create directory (and parents if needed)
    async fn create_dir_all(&self, path: &Path) -> Result<()>;
    
    /// List directory contents
    async fn read_dir(&self, path: &Path) -> Result<Vec<std::path::PathBuf>>;
    
    /// Get I/O statistics
    fn get_stats(&self) -> IoStats;
    
    /// Flush any pending operations
    async fn flush(&self) -> Result<()>;
}

/// I/O performance statistics
#[derive(Debug, Clone, Default)]
pub struct IoStats {
    /// Total bytes read
    pub bytes_read: u64,
    /// Total bytes written
    pub bytes_written: u64,
    /// Number of read operations
    pub read_ops: u64,
    /// Number of write operations
    pub write_ops: u64,
    /// Average read latency in microseconds
    pub avg_read_latency_us: u64,
    /// Average write latency in microseconds
    pub avg_write_latency_us: u64,
    /// Number of zero-copy operations
    pub zero_copy_ops: u64,
}

impl IoStats {
    /// Calculate total operations
    pub fn total_ops(&self) -> u64 {
        self.read_ops + self.write_ops
    }
    
    /// Calculate total bytes transferred
    pub fn total_bytes(&self) -> u64 {
        self.bytes_read + self.bytes_written
    }
    
    /// Calculate average latency across all operations
    pub fn avg_latency_us(&self) -> u64 {
        let total_ops = self.total_ops();
        if total_ops == 0 {
            return 0;
        }
        
        let total_latency = (self.read_ops * self.avg_read_latency_us) 
            + (self.write_ops * self.avg_write_latency_us);
        total_latency / total_ops
    }
}

/// Network I/O operations for high-performance proxying
#[async_trait]
pub trait NetworkIo: Send + Sync {
    /// Read from a network stream with zero-copy optimization
    async fn read_stream(&self, stream: &mut (dyn AsyncRead + Unpin + Send)) -> Result<Bytes>;
    
    /// Write to a network stream with zero-copy optimization
    async fn write_stream(&self, stream: &mut (dyn AsyncWrite + Unpin + Send), data: &[u8]) -> Result<()>;
    
    /// Copy data between streams efficiently (simplified interface)
    async fn copy_stream(&self, reader: &mut (dyn AsyncRead + Unpin + Send), writer: &mut (dyn AsyncWrite + Unpin + Send)) -> Result<u64>;
}

// Re-export traits for convenience
use tokio::io::{AsyncRead, AsyncWrite};