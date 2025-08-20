//! Storage Adapter Test Binary
//!
//! Simple test to validate storage adapter functionality

use std::time::Duration;
use tokio;
use waf_ingress::waf::storage::{
    MemoryStorageAdapter, ReadConsistency, StorageAdapter, StorageAdapterFactory,
    StorageBackend, StorageConfig,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::init();

    println!("🔧 Testing WAF Storage Adapters");

    // Test Memory Storage
    println!("\n📦 Testing MemoryStorageAdapter...");
    test_memory_storage().await?;

    // Test Storage Factory
    println!("\n🏭 Testing StorageAdapterFactory...");
    test_storage_factory().await?;

    println!("\n✅ All storage adapter tests passed!");
    Ok(())
}

async fn test_memory_storage() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = MemoryStorageAdapter::new(Some(100), Duration::from_secs(1)).await?;

    // Test basic operations
    adapter.set(b"test_key", b"test_value", None).await?;
    
    let value = adapter.get(b"test_key", ReadConsistency::Strong).await?;
    assert_eq!(value, Some(b"test_value".to_vec()));
    println!("  ✓ Basic set/get operations");

    // Test TTL
    adapter.set(b"ttl_key", b"ttl_value", Some(Duration::from_millis(100))).await?;
    assert!(adapter.exists(b"ttl_key").await?);
    
    tokio::time::sleep(Duration::from_millis(200)).await;
    
    // Force TTL cleanup
    let expired = adapter.expire_keys().await?;
    println!("  ✓ TTL functionality (expired {} keys)", expired);

    // Test statistics
    let stats = adapter.stats().await?;
    println!("  ✓ Statistics: {} keys, {} bytes", stats.key_count, stats.data_size);

    Ok(())
}

async fn test_storage_factory() -> Result<(), Box<dyn std::error::Error>> {
    let config = StorageConfig {
        backend: StorageBackend::Memory { max_size: Some(50) },
        enable_follower_reads: false,
        ttl_cleanup_interval: Duration::from_secs(30),
        enable_compression: false,
    };

    let adapter = StorageAdapterFactory::create(config).await?;
    
    // Test through the generic interface
    adapter.set(b"factory_test", b"factory_value", None).await?;
    let value = adapter.get(b"factory_test", ReadConsistency::Strong).await?;
    assert_eq!(value, Some(b"factory_value".to_vec()));
    
    println!("  ✓ Factory-created adapter works correctly");
    
    Ok(())
}