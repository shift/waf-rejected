/// I/O Performance Test for WAF Storage Operations
/// 
/// This binary tests the performance of different I/O backends:
/// - Standard tokio I/O
/// - io_uring (Linux only)
/// 
/// It measures file operations latency and throughput to validate
/// the P2-02 I/O optimization implementation.

use anyhow::{Context, Result};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tokio::time::sleep;
use tracing::{info, warn};
use waf_ingress::waf::io::{create_io_handler, IoBackend, IoConfig, IoHandler};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    info!("🚀 Starting I/O Performance Test");

    // Test directory setup
    let test_dir = PathBuf::from("./test_io_performance");
    tokio::fs::create_dir_all(&test_dir).await?;

    // Test configurations
    let test_configs = vec![
        ("Standard Tokio I/O", IoConfig {
            backend: IoBackend::Standard,
            enable_zero_copy: false,
            buffer_size: 8192,
            concurrency: 4,
        }),
        #[cfg(feature = "io-uring")]
        ("io_uring (Linux)", IoConfig {
            backend: IoBackend::IoUring,
            enable_zero_copy: true,
            buffer_size: 8192,
            concurrency: 4,
        }),
    ];

    for (name, config) in test_configs {
        info!("\n📊 Testing {}", name);
        
        match test_io_backend(&config, &test_dir).await {
            Ok(stats) => {
                info!("✅ {} Results:", name);
                info!("  📖 Read Operations: {} ops", stats.read_ops);
                info!("  ✍️  Write Operations: {} ops", stats.write_ops);
                info!("  📈 Bytes Read: {} bytes", stats.bytes_read);
                info!("  📉 Bytes Written: {} bytes", stats.bytes_written);
                info!("  ⏱️  Avg Read Latency: {}μs", stats.avg_read_latency_us);
                info!("  ⏱️  Avg Write Latency: {}μs", stats.avg_write_latency_us);
                info!("  🔄 Zero-copy Operations: {}", stats.zero_copy_ops);
                info!("  🎯 Total Operations: {}", stats.total_ops());
                info!("  💾 Total Bytes: {}", stats.total_bytes());
            }
            Err(e) => {
                warn!("❌ {} failed: {}", name, e);
            }
        }
    }

    // Cleanup
    if tokio::fs::try_exists(&test_dir).await.unwrap_or(false) {
        tokio::fs::remove_dir_all(&test_dir).await?;
        info!("🧹 Cleaned up test directory");
    }

    info!("✨ I/O Performance Test completed");
    Ok(())
}

async fn test_io_backend(config: &IoConfig, test_dir: &PathBuf) -> Result<waf_ingress::waf::io::IoStats> {
    let handler = create_io_handler(config)?;
    
    // Test parameters
    const NUM_FILES: usize = 100;
    const FILE_SIZE: usize = 1024; // 1KB files
    const NUM_ROUNDS: usize = 5;
    
    let test_data = vec![0xABu8; FILE_SIZE];
    
    info!("  🔧 Test Parameters:");
    info!("    - Files: {} x {}KB", NUM_FILES, FILE_SIZE / 1024);
    info!("    - Rounds: {}", NUM_ROUNDS);
    info!("    - Backend: {:?}", config.backend);
    info!("    - Zero-copy: {}", config.enable_zero_copy);

    // Performance test rounds
    for round in 1..=NUM_ROUNDS {
        info!("  📋 Round {}/{}", round, NUM_ROUNDS);
        
        let round_start = Instant::now();
        
        // Write test
        let write_start = Instant::now();
        for i in 0..NUM_FILES {
            let file_path = test_dir.join(format!("test_file_{}.bin", i));
            handler.write_file(&file_path, &test_data).await
                .with_context(|| format!("Failed to write test file {}", i))?;
        }
        let write_duration = write_start.elapsed();
        
        // Read test
        let read_start = Instant::now();
        for i in 0..NUM_FILES {
            let file_path = test_dir.join(format!("test_file_{}.bin", i));
            let _data = handler.read_file(&file_path).await
                .with_context(|| format!("Failed to read test file {}", i))?;
        }
        let read_duration = read_start.elapsed();
        
        // File operations test
        let ops_start = Instant::now();
        for i in 0..NUM_FILES {
            let file_path = test_dir.join(format!("test_file_{}.bin", i));
            
            // Check existence
            let exists = handler.file_exists(&file_path).await?;
            assert!(exists, "File should exist");
            
            // Check size
            let size = handler.file_size(&file_path).await?;
            assert_eq!(size, FILE_SIZE as u64, "File size mismatch");
        }
        let ops_duration = ops_start.elapsed();
        
        // Cleanup round files
        for i in 0..NUM_FILES {
            let file_path = test_dir.join(format!("test_file_{}.bin", i));
            handler.delete_file(&file_path).await?;
        }
        
        let round_duration = round_start.elapsed();
        
        info!("    ⏱️  Write: {:?} ({:.2} MB/s)", 
              write_duration, 
              (NUM_FILES * FILE_SIZE) as f64 / write_duration.as_secs_f64() / 1_000_000.0);
        info!("    ⏱️  Read:  {:?} ({:.2} MB/s)", 
              read_duration,
              (NUM_FILES * FILE_SIZE) as f64 / read_duration.as_secs_f64() / 1_000_000.0);
        info!("    ⏱️  Ops:   {:?}", ops_duration);
        info!("    ⏱️  Total: {:?}", round_duration);
        
        // Brief pause between rounds
        sleep(Duration::from_millis(100)).await;
    }
    
    // Flush any pending operations
    handler.flush().await?;
    
    Ok(handler.get_stats())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_standard_io_handler() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let config = IoConfig {
            backend: IoBackend::Standard,
            enable_zero_copy: false,
            buffer_size: 1024,
            concurrency: 2,
        };
        
        let handler = create_io_handler(&config)?;
        
        // Test basic file operations
        let test_file = temp_dir.path().join("test.txt");
        let test_data = b"Hello, WAF I/O!";
        
        // Write file
        handler.write_file(&test_file, test_data).await?;
        
        // Check existence
        assert!(handler.file_exists(&test_file).await?);
        
        // Check size
        assert_eq!(handler.file_size(&test_file).await?, test_data.len() as u64);
        
        // Read file
        let read_data = handler.read_file(&test_file).await?;
        assert_eq!(read_data, test_data);
        
        // Append to file
        let append_data = b" More data!";
        handler.append_file(&test_file, append_data).await?;
        
        // Verify appended content
        let final_data = handler.read_file(&test_file).await?;
        let expected = [test_data, append_data].concat();
        assert_eq!(final_data, expected.as_slice());
        
        // Delete file
        handler.delete_file(&test_file).await?;
        assert!(!handler.file_exists(&test_file).await?);
        
        // Check stats
        let stats = handler.get_stats();
        assert!(stats.read_ops > 0);
        assert!(stats.write_ops > 0);
        assert!(stats.total_ops() > 0);
        
        Ok(())
    }

    #[cfg(feature = "io-uring")]
    #[tokio::test]
    async fn test_io_uring_handler() -> Result<()> {
        if !cfg!(target_os = "linux") {
            println!("Skipping io_uring test on non-Linux platform");
            return Ok(());
        }
        
        let temp_dir = TempDir::new()?;
        let config = IoConfig {
            backend: IoBackend::IoUring,
            enable_zero_copy: true,
            buffer_size: 1024,
            concurrency: 2,
        };
        
        let handler = create_io_handler(&config)?;
        
        // Test basic file operations
        let test_file = temp_dir.path().join("test_uring.txt");
        let test_data = b"Hello, io_uring WAF!";
        
        // Write file
        handler.write_file(&test_file, test_data).await?;
        
        // Check existence
        assert!(handler.file_exists(&test_file).await?);
        
        // Read file
        let read_data = handler.read_file(&test_file).await?;
        assert_eq!(read_data, test_data);
        
        // Check stats (should show zero-copy operations)
        let stats = handler.get_stats();
        assert!(stats.zero_copy_ops > 0);
        
        Ok(())
    }
}