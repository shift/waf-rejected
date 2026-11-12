//! Storage Adapter Module
//!
//! This module provides a pluggable storage adapter interface for the WAF.
//! It supports multiple backend implementations including Sled, Redb, and in-memory storage.

use async_trait::async_trait;
use std::ops::Bound;
use std::time::Duration;
use thiserror::Error;

pub mod bulk_deletion;
pub mod memory;
pub mod migrate;
pub mod redb;
pub mod sled;
pub mod ttl_enhancements;

pub use bulk_deletion::{
    BulkDeletionConfig, BulkDeletionOptimizer, BulkDeletionResult, BulkDeletionStats, DeletionKey,
    TransactionResult,
};
pub use memory::MemoryStorageAdapter;
#[cfg(feature = "export-sled")]
pub use migrate::{legacy_event_trees, LegacySledTreeAdapter};
pub use migrate::{migrate, MigrationError, MigrationOptions, MigrationProgress, MigrationSummary};
pub use redb::RedbStorageAdapter;
pub use sled::SledStorageAdapter;
pub use ttl_enhancements::{
    CleanupResult, EnhancedTtlStats, TtlCleanupConfig, TtlEnhancementManager,
};

/// Upper bound (exclusive) for a byte prefix, or `None` when the prefix is the
/// whole key space (`[]` or all `0xff`).
pub fn prefix_upper_bound(prefix: &[u8]) -> Option<Vec<u8>> {
    let mut end = prefix.to_vec();
    while let Some(last) = end.last_mut() {
        if *last == u8::MAX {
            end.pop();
        } else {
            *last += 1;
            return Some(end);
        }
    }
    None
}

/// Read consistency levels for storage operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadConsistency {
    /// Strong consistency - read from primary storage
    Strong,
    /// Eventual consistency - allow follower reads for better performance
    Eventual,
}

impl Default for ReadConsistency {
    fn default() -> Self {
        Self::Strong
    }
}

/// Storage adapter errors
#[derive(Error, Debug)]
pub enum StorageError {
    #[error("Key not found: {key}")]
    KeyNotFound { key: String },

    #[error("Database error: {message}")]
    DatabaseError { message: String },

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("TTL operation failed: {message}")]
    TTLError { message: String },

    #[error("Transaction error: {message}")]
    TransactionError { message: String },

    #[error("Configuration error: {message}")]
    ConfigError { message: String },
}

/// Result type for storage operations
pub type StorageResult<T> = Result<T, StorageError>;

/// Storage adapter trait for pluggable backends
///
/// This trait provides a unified interface for different storage backends
/// including Sled, Redb, and in-memory storage implementations.
///
/// Semantics shared by every backend (enforced by `storage::parity_tests`):
///
/// * keys are byte strings ordered lexicographically;
/// * `get`/`exists`/`scan_*` never return an entry whose TTL has elapsed, even
///   before the background cleanup has removed it;
/// * `delete`/`delete_many` report whether a physical entry existed;
/// * `stats().key_count` counts physical entries (an expired entry that has not
///   been collected yet is still counted);
/// * an acknowledged `set` is durable across a process crash.
#[async_trait]
pub trait StorageAdapter: Send + Sync {
    /// Get a value by key with specified consistency level
    async fn get(&self, key: &[u8], consistency: ReadConsistency)
        -> StorageResult<Option<Vec<u8>>>;

    /// Set a key-value pair with optional TTL
    async fn set(&self, key: &[u8], value: &[u8], ttl: Option<Duration>) -> StorageResult<()>;

    /// Delete a key, returns true if the key existed
    async fn delete(&self, key: &[u8]) -> StorageResult<bool>;

    /// Check if a key exists
    async fn exists(&self, key: &[u8]) -> StorageResult<bool>;

    /// Expire keys that have exceeded their TTL
    /// Returns the number of keys that were expired
    async fn expire_keys(&self) -> StorageResult<u64>;

    /// Get storage statistics
    async fn stats(&self) -> StorageResult<StorageStats>;

    /// Flush any pending writes to disk
    async fn flush(&self) -> StorageResult<()>;

    /// Compact the storage (if supported by backend)
    async fn compact(&self) -> StorageResult<()>;

    /// Iterate live entries in ascending key order.
    ///
    /// `start` is inclusive or exclusive, `end` is normally exclusive. At most
    /// `limit` entries are returned. Expired entries are skipped.
    async fn scan_range(
        &self,
        start: Bound<&[u8]>,
        end: Bound<&[u8]>,
        limit: Option<usize>,
    ) -> StorageResult<Vec<(Vec<u8>, Vec<u8>)>>;

    /// Iterate live entries whose key starts with `prefix`, in ascending key
    /// order. At most `limit` entries are returned.
    async fn scan_prefix(
        &self,
        prefix: &[u8],
        limit: Option<usize>,
    ) -> StorageResult<Vec<(Vec<u8>, Vec<u8>)>> {
        let end = prefix_upper_bound(prefix);
        let end = match end.as_deref() {
            Some(end) => Bound::Excluded(end),
            None => Bound::Unbounded,
        };
        self.scan_range(Bound::Included(prefix), end, limit).await
    }

    /// Remaining TTL for a live key.
    ///
    /// `None` when the key is absent, has already expired, or was written
    /// without a TTL.
    async fn ttl(&self, key: &[u8]) -> StorageResult<Option<Duration>>;

    /// Delete several keys in one backend operation.
    ///
    /// Returns the number of physical entries that existed and were removed.
    /// Keys that do not exist are ignored.
    async fn delete_many(&self, keys: &[Vec<u8>]) -> StorageResult<u64>;

    /// Stable, human-readable backend name used by diagnostics and the
    /// migration tool.
    fn backend_name(&self) -> &'static str;
}

/// Storage statistics
#[derive(Debug, Clone)]
pub struct StorageStats {
    /// Number of key-value pairs stored
    pub key_count: u64,
    /// Total size of data in bytes
    pub data_size: u64,
    /// Size of database file on disk in bytes (if applicable)
    pub disk_size: Option<u64>,
    /// Number of expired keys cleaned up
    pub expired_keys: u64,
    /// Cache hit ratio (0.0 to 1.0)
    pub cache_hit_ratio: Option<f64>,
}

impl Default for StorageStats {
    fn default() -> Self {
        Self {
            key_count: 0,
            data_size: 0,
            disk_size: None,
            expired_keys: 0,
            cache_hit_ratio: None,
        }
    }
}

/// Storage backend configuration
#[derive(Debug, Clone)]
pub enum StorageBackend {
    /// Sled embedded database
    Sled { path: String, temporary: bool },
    /// Redb embedded database
    Redb {
        path: String,
        cache_size: Option<usize>,
    },
    /// In-memory storage (for testing)
    Memory { max_size: Option<usize> },
}

impl Default for StorageBackend {
    fn default() -> Self {
        // redb is the default security-event store. sled remains selectable
        // (`backend = "sled"`) for operators migrating off the legacy store,
        // and memory exists for tests. A default here must never create a
        // sled directory on a fresh deployment.
        Self::Redb {
            path: "./data/waf.redb".to_string(),
            cache_size: None,
        }
    }
}

/// Storage configuration
#[derive(Debug, Clone)]
pub struct StorageConfig {
    /// Storage backend type
    pub backend: StorageBackend,
    /// Enable follower reads for better performance
    pub enable_follower_reads: bool,
    /// TTL cleanup interval
    pub ttl_cleanup_interval: Duration,
    /// Enable compression for stored values
    pub enable_compression: bool,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            backend: StorageBackend::default(),
            enable_follower_reads: false,
            ttl_cleanup_interval: Duration::from_secs(60),
            enable_compression: false,
        }
    }
}

/// Factory for creating storage adapters
pub struct StorageAdapterFactory;

impl StorageAdapterFactory {
    /// Create a storage adapter from configuration
    pub async fn create(config: StorageConfig) -> StorageResult<Box<dyn StorageAdapter>> {
        match config.backend {
            #[cfg(feature = "export-sled")]
            StorageBackend::Sled { path, temporary } => {
                let adapter = crate::waf::storage::sled::SledStorageAdapter::new(
                    path,
                    temporary,
                    config.ttl_cleanup_interval,
                    config.enable_compression,
                )
                .await?;
                Ok(Box::new(adapter))
            }

            #[cfg(feature = "export-redb")]
            StorageBackend::Redb { path, cache_size } => {
                let adapter = crate::waf::storage::redb::RedbStorageAdapter::new(
                    path,
                    cache_size,
                    config.ttl_cleanup_interval,
                    config.enable_compression,
                )
                .await?;
                Ok(Box::new(adapter))
            }

            StorageBackend::Memory { max_size } => {
                let adapter = crate::waf::storage::memory::MemoryStorageAdapter::new(
                    max_size,
                    config.ttl_cleanup_interval,
                )
                .await?;
                Ok(Box::new(adapter))
            }

            #[cfg(not(feature = "export-sled"))]
            StorageBackend::Sled { .. } => Err(StorageError::ConfigError {
                message: "Sled backend not enabled. Enable 'export-sled' feature.".to_string(),
            }),

            #[cfg(not(feature = "export-redb"))]
            StorageBackend::Redb { .. } => Err(StorageError::ConfigError {
                message: "Redb backend not enabled. Enable 'export-redb' feature.".to_string(),
            }),
        }
    }
}

#[cfg(test)]
mod parity_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_storage_config_defaults() {
        let config = StorageConfig::default();
        assert!(!config.enable_follower_reads);
        assert_eq!(config.ttl_cleanup_interval, Duration::from_secs(60));
        assert!(!config.enable_compression);
    }

    #[test]
    fn test_read_consistency_default() {
        assert_eq!(ReadConsistency::default(), ReadConsistency::Strong);
    }

    #[tokio::test]
    async fn test_follower_reads_basic() {
        // Test that both consistency levels work with in-memory storage
        let adapter =
            crate::waf::storage::memory::MemoryStorageAdapter::new(None, Duration::from_secs(60))
                .await
                .unwrap();

        // Set a value
        adapter.set(b"test_key", b"test_value", None).await.unwrap();

        // Test strong consistency read
        let strong_result = adapter
            .get(b"test_key", ReadConsistency::Strong)
            .await
            .unwrap();
        assert_eq!(strong_result, Some(b"test_value".to_vec()));

        // Test eventual consistency read
        let eventual_result = adapter
            .get(b"test_key", ReadConsistency::Eventual)
            .await
            .unwrap();
        assert_eq!(eventual_result, Some(b"test_value".to_vec()));

        // Both should return the same result for in-memory storage
        assert_eq!(strong_result, eventual_result);
    }
}
