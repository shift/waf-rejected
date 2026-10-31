/// High-performance I/O backends for WAF operations
///
/// This module provides pluggable I/O backends optimized for different scenarios:
/// - Standard tokio I/O for general compatibility
/// - io_uring backend for maximum performance on Linux
/// - Zero-copy operations where possible
pub mod backend;
pub mod network;
pub mod traits;

pub use backend::*;
pub use network::*;
pub use traits::*;

use anyhow::Result;

/// I/O configuration for WAF operations
#[derive(Debug, Clone)]
pub struct IoConfig {
    /// I/O backend to use
    pub backend: IoBackend,
    /// Enable zero-copy operations when supported
    pub enable_zero_copy: bool,
    /// Buffer size for I/O operations
    pub buffer_size: usize,
    /// Number of concurrent I/O operations
    pub concurrency: usize,
}

impl Default for IoConfig {
    fn default() -> Self {
        Self {
            backend: IoBackend::default(),
            enable_zero_copy: true,
            buffer_size: 8192,
            concurrency: num_cpus::get(),
        }
    }
}

/// Supported I/O backends
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoBackend {
    /// Standard tokio I/O
    Standard,
    /// Linux io_uring backend
    #[cfg(feature = "io-uring")]
    IoUring,
}

impl Default for IoBackend {
    fn default() -> Self {
        #[cfg(feature = "io-uring")]
        {
            // Use io_uring on Linux when available
            if cfg!(target_os = "linux") {
                Self::IoUring
            } else {
                Self::Standard
            }
        }
        #[cfg(not(feature = "io-uring"))]
        {
            Self::Standard
        }
    }
}

/// Create an I/O handler based on configuration
pub fn create_io_handler(config: &IoConfig) -> Result<Box<dyn IoHandler>> {
    match config.backend {
        IoBackend::Standard => Ok(Box::new(backend::StandardIoHandler::new(config.clone())?)),
        #[cfg(feature = "io-uring")]
        IoBackend::IoUring => Ok(Box::new(backend::IoUringHandler::new(config.clone())?)),
    }
}
