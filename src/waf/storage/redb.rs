//! Redb Storage Adapter
//!
//! High-performance storage implementation using the Redb embedded database

#[cfg(feature = "export-redb")]
use super::{ReadConsistency, StorageAdapter, StorageError, StorageResult, StorageStats};
#[cfg(feature = "export-redb")]
use async_trait::async_trait;
#[cfg(feature = "export-redb")]
use redb::{Database, ReadableTable, TableDefinition, ReadableDatabase};
#[cfg(feature = "export-redb")]
use std::path::Path;
#[cfg(feature = "export-redb")]
use std::sync::Arc;
#[cfg(feature = "export-redb")]
use std::time::{Duration, SystemTime, UNIX_EPOCH};
#[cfg(feature = "export-redb")]
use tokio::sync::RwLock;
#[cfg(feature = "export-redb")]
use tokio::task;
#[cfg(feature = "export-redb")]
use tokio::time::interval;
#[cfg(feature = "export-redb")]
use tracing::{debug, error};

#[cfg(feature = "export-redb")]
const DATA_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("data");

#[cfg(feature = "export-redb")]
const TTL_TABLE: TableDefinition<&[u8], u64> = TableDefinition::new("ttl_metadata");
// Key: same as data key, Value: expiration_timestamp_ms
// Simple 1:1 mapping for TTL metadata

#[cfg(feature = "export-redb")]
const EXPIRATION_INDEX: TableDefinition<u64, &[u8]> = TableDefinition::new("expiration_index");
// Key: composite key (expiration_timestamp_ms + key_hash), Value: original_key
// This allows efficient time-based cleanup while avoiding collisions

#[cfg(feature = "export-redb")]
/// Redb storage adapter
pub struct RedbStorageAdapter {
    db: Arc<Database>,
    ttl_cleanup_interval: Duration,
    enable_compression: bool,
    expired_count: Arc<RwLock<u64>>,
    cleanup_stats: Arc<RwLock<TtlCleanupStats>>,
}

/// TTL cleanup performance statistics
#[derive(Debug, Clone, Default)]
pub struct TtlCleanupStats {
    /// Total cleanup runs performed
    pub cleanup_runs: u64,
    /// Total keys expired across all runs
    pub total_expired_keys: u64,
    /// Average cleanup duration in milliseconds
    pub avg_cleanup_duration_ms: f64,
    /// Last cleanup duration in milliseconds
    pub last_cleanup_duration_ms: u64,
    /// Last cleanup key count
    pub last_cleanup_key_count: u64,
    /// Maximum cleanup duration observed
    pub max_cleanup_duration_ms: u64,
}

#[cfg(feature = "export-redb")]
impl RedbStorageAdapter {
    /// Create a new Redb storage adapter
    pub async fn new<P: AsRef<Path>>(
        db_path: P,
        cache_size: Option<usize>,
        ttl_cleanup_interval: Duration,
        enable_compression: bool,
    ) -> StorageResult<Self> {
        let db = task::spawn_blocking({
            let path = db_path.as_ref().to_path_buf();
            move || -> Result<Database, redb::Error> {
                let mut builder = redb::Builder::new();
                
                if let Some(cache_size) = cache_size {
                    builder.set_cache_size(cache_size);
                }
                
                let db = builder.create(&path)?;
                
                // Initialize tables
                let write_txn = db.begin_write()?;
                write_txn.open_table(DATA_TABLE)?;
                write_txn.open_table(TTL_TABLE)?;
                write_txn.open_table(EXPIRATION_INDEX)?;
                write_txn.commit()?;
                
                Ok(db)
            }
        })
        .await
        .map_err(|e| StorageError::DatabaseError {
            message: format!("Failed to spawn database task: {}", e),
        })?
        .map_err(|e| StorageError::DatabaseError {
            message: format!("Failed to create Redb database: {}", e),
        })?;
        
        let adapter = Self {
            db: Arc::new(db),
            ttl_cleanup_interval,
            enable_compression,
            expired_count: Arc::new(RwLock::new(0)),
            cleanup_stats: Arc::new(RwLock::new(TtlCleanupStats::default())),
        };
        
        // Start TTL cleanup task
        adapter.start_ttl_cleanup().await;
        
        Ok(adapter)
    }
    
    /// Start background TTL cleanup task with enhanced monitoring
    async fn start_ttl_cleanup(&self) {
        let db = self.db.clone();
        let expired_count = self.expired_count.clone();
        let cleanup_stats = self.cleanup_stats.clone();
        let cleanup_interval = self.ttl_cleanup_interval;
        
        tokio::spawn(async move {
            let mut interval = interval(cleanup_interval);
            
            loop {
                interval.tick().await;
                
                let start_time = SystemTime::now();
                match Self::cleanup_expired_keys_with_stats(db.clone(), expired_count.clone()).await {
                    Ok(expired_keys) => {
                        let cleanup_duration = start_time.elapsed().unwrap_or_default().as_millis() as u64;
                        
                        // Update cleanup statistics
                        let mut stats = cleanup_stats.write().await;
                        stats.cleanup_runs += 1;
                        stats.total_expired_keys += expired_keys;
                        stats.last_cleanup_duration_ms = cleanup_duration;
                        stats.last_cleanup_key_count = expired_keys;
                        stats.max_cleanup_duration_ms = stats.max_cleanup_duration_ms.max(cleanup_duration);
                        
                        // Update rolling average
                        if stats.cleanup_runs > 0 {
                            stats.avg_cleanup_duration_ms = 
                                (stats.avg_cleanup_duration_ms * (stats.cleanup_runs - 1) as f64 + cleanup_duration as f64) 
                                / stats.cleanup_runs as f64;
                        }
                        
                        debug!("TTL cleanup completed: {} keys in {}ms", expired_keys, cleanup_duration);
                    },
                    Err(e) => {
                        error!("TTL cleanup failed: {}", e);
                    }
                }
            }
        });
    }
    
    /// Clean up expired keys using the new TTL schema with enhanced monitoring
    async fn cleanup_expired_keys_with_stats(
        db: Arc<Database>,
        expired_count: Arc<RwLock<u64>>,
    ) -> StorageResult<u64> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        
        let db_clone = db.clone();
        let expired_keys = task::spawn_blocking(move || -> Result<Vec<Vec<u8>>, redb::Error> {
            let read_txn = db_clone.begin_read()?;
            let ttl_table = read_txn.open_table(TTL_TABLE)?;
            
            let mut expired = Vec::new();
            
            // Scan TTL table for expired keys
            let range = ttl_table.range::<&[u8]>(..)?;
            for result in range {
                let (key, expiry_time) = result?;
                if expiry_time.value() <= now {
                    expired.push(key.value().to_vec());
                }
            }
            
            Ok(expired)
        })
        .await
        .map_err(|e| StorageError::DatabaseError {
            message: format!("Failed to collect expired keys: {}", e),
        })?
        .map_err(|e| StorageError::DatabaseError {
            message: format!("Redb error during expiration collection: {}", e),
        })?;
        
        if expired_keys.is_empty() {
            return Ok(0);
        }
        
        // Remove expired keys in a separate transaction
        let db_clone = db.clone();
        let expired_count_val = task::spawn_blocking(move || -> Result<usize, redb::Error> {
            let write_txn = db_clone.begin_write()?;
            {
                let mut data_table = write_txn.open_table(DATA_TABLE)?;
                let mut ttl_table = write_txn.open_table(TTL_TABLE)?;
                let mut expiration_index = write_txn.open_table(EXPIRATION_INDEX)?;
                
                for key in &expired_keys {
                    // Remove from data table
                    data_table.remove(key.as_slice())?;
                    
                    // Remove from TTL table
                    ttl_table.remove(key.as_slice())?;
                    
                    // Clean up expiration index entries (optimized batch cleanup)
                    let mut index_keys_to_remove = Vec::new();
                    let range = expiration_index.range::<&[u8]>(..)?;
                    for result in range {
                        let (index_key, indexed_key) = result?;
                        if indexed_key.value() == key.as_slice() {
                            index_keys_to_remove.push(index_key.value().to_vec());
                        }
                    }
                    
                    for index_key in index_keys_to_remove {
                        expiration_index.remove(index_key.as_slice())?;
                    }
                }
            }
            write_txn.commit()?;
            Ok(expired_keys.len())
        })
        .await
        .map_err(|e| StorageError::DatabaseError {
            message: format!("Failed to remove expired keys: {}", e),
        })?
        .map_err(|e| StorageError::DatabaseError {
            message: format!("Redb error during key removal: {}", e),
        })?;
        
        // Update expired count
        let mut count = expired_count.write().await;
        *count += expired_count_val as u64;
        
        debug!("Cleaned up {} expired keys from Redb", expired_count_val);
        
        Ok(expired_count_val as u64)
    }
    
    /// Compress data if compression is enabled
    fn compress_if_enabled(&self, data: &[u8]) -> Vec<u8> {
        if self.enable_compression {
            // Simple compression placeholder - in production, use a real compression library
            data.to_vec()
        } else {
            data.to_vec()
        }
    }
    
    /// Decompress data if compression is enabled
    fn decompress_if_enabled(&self, data: &[u8]) -> Vec<u8> {
        if self.enable_compression {
            // Simple decompression placeholder - in production, use a real compression library
            data.to_vec()
        } else {
            data.to_vec()
        }
    }
}

#[cfg(feature = "export-redb")]
#[async_trait]
impl StorageAdapter for RedbStorageAdapter {
    async fn get(&self, key: &[u8], consistency: ReadConsistency) -> StorageResult<Option<Vec<u8>>> {
        let db = self.db.clone();
        let key = key.to_vec();
        
        let result = match consistency {
            ReadConsistency::Strong => {
                // Strong consistency - use a full read transaction with TTL checking
                task::spawn_blocking(move || -> Result<Option<Vec<u8>>, redb::Error> {
                    let read_txn = db.begin_read()?;
                    let data_table = read_txn.open_table(DATA_TABLE)?;
                    let ttl_table = read_txn.open_table(TTL_TABLE)?;
                    
                    // Check if key exists
                    if let Some(value_guard) = data_table.get(key.as_slice())? {
                        // Check TTL if it exists
                        if let Some(expiry_guard) = ttl_table.get(key.as_slice())? {
                            let expiry_time = expiry_guard.value();
                            let now = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_millis() as u64;
                            
                            if now >= expiry_time {
                                // Key has expired
                                return Ok(None);
                            }
                        }
                        
                        Ok(Some(value_guard.value().to_vec()))
                    } else {
                        Ok(None)
                    }
                })
                .await
                .map_err(|e| StorageError::DatabaseError {
                    message: format!("Failed to spawn strong consistency get task: {}", e),
                })?
                .map_err(|e| StorageError::DatabaseError {
                    message: format!("Redb strong consistency get error: {}", e),
                })?
            },
            ReadConsistency::Eventual => {
                // Eventual consistency - optimized read-only access with TTL checking
                task::spawn_blocking(move || -> Result<Option<Vec<u8>>, redb::Error> {
                    let read_txn = db.begin_read()?;
                    let data_table = read_txn.open_table(DATA_TABLE)?;
                    let ttl_table = read_txn.open_table(TTL_TABLE)?;
                    
                    // Check if key exists
                    if let Some(value_guard) = data_table.get(key.as_slice())? {
                        // Check TTL if it exists
                        if let Some(expiry_guard) = ttl_table.get(key.as_slice())? {
                            let expiry_time = expiry_guard.value();
                            let now = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_millis() as u64;
                            
                            if now >= expiry_time {
                                // Key has expired
                                return Ok(None);
                            }
                        }
                        
                        Ok(Some(value_guard.value().to_vec()))
                    } else {
                        Ok(None)
                    }
                })
                .await
                .map_err(|e| StorageError::DatabaseError {
                    message: format!("Failed to spawn eventual consistency get task: {}", e),
                })?
                .map_err(|e| StorageError::DatabaseError {
                    message: format!("Redb eventual consistency get error: {}", e),
                })?
            }
        };
        
        if let Some(data) = result {
            Ok(Some(self.decompress_if_enabled(&data)))
        } else {
            Ok(None)
        }
    }
    
    async fn set(&self, key: &[u8], value: &[u8], ttl: Option<Duration>) -> StorageResult<()> {
        let db = self.db.clone();
        let key = key.to_vec();
        let value = self.compress_if_enabled(value);
        
        task::spawn_blocking(move || -> Result<(), redb::Error> {
            let write_txn = db.begin_write()?;
            {
                let mut data_table = write_txn.open_table(DATA_TABLE)?;
                let mut ttl_table = write_txn.open_table(TTL_TABLE)?;
                let mut expiration_index = write_txn.open_table(EXPIRATION_INDEX)?;
                
                // Store the data
                data_table.insert(key.as_slice(), value.as_slice())?;
                
                // Handle TTL if specified
                if let Some(duration) = ttl {
                    let expires_at = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_millis() as u64
                        + duration.as_millis() as u64;
                    
                    // Store TTL metadata
                    ttl_table.insert(key.as_slice(), expires_at)?;
                    
                    // Create expiration index key (timestamp + key length + first 8 bytes of key to avoid collisions)
                    let mut index_key = Vec::with_capacity(8 + 4 + 8);
                    index_key.extend_from_slice(&expires_at.to_be_bytes());
                    index_key.extend_from_slice(&(key.len() as u32).to_be_bytes());
                    index_key.extend_from_slice(&key[..std::cmp::min(key.len(), 8)]);
                    
                    expiration_index.insert(index_key.as_slice(), key.as_slice())?;
                } else {
                    // Remove any existing TTL metadata if no TTL is set
                    ttl_table.remove(key.as_slice())?;
                    // Note: We don't clean up the expiration index here for performance
                    // It will be cleaned up during the next expiration cleanup
                }
            }
            write_txn.commit()?;
            Ok(())
        })
        .await
        .map_err(|e| StorageError::DatabaseError {
            message: format!("Failed to spawn set task: {}", e),
        })?
        .map_err(|e| StorageError::DatabaseError {
            message: format!("Redb set error: {}", e),
        })?;
        
        Ok(())
    }
    
    async fn delete(&self, key: &[u8]) -> StorageResult<bool> {
        let db = self.db.clone();
        let key = key.to_vec();
        
        let existed = task::spawn_blocking(move || -> Result<bool, redb::Error> {
            let write_txn = db.begin_write()?;
            let existed = {
                let mut data_table = write_txn.open_table(DATA_TABLE)?;
                let mut ttl_table = write_txn.open_table(TTL_TABLE)?;
                
                let existed = data_table.get(key.as_slice())?.is_some();
                
                if existed {
                    // Remove data
                    data_table.remove(key.as_slice())?;
                    
                    // Remove TTL metadata if it exists
                    ttl_table.remove(key.as_slice())?;
                    
                    // Note: We don't clean up the expiration index here for performance
                    // The cleanup process will handle stale entries
                }
                
                existed
            };
            write_txn.commit()?;
            Ok(existed)
        })
        .await
        .map_err(|e| StorageError::DatabaseError {
            message: format!("Failed to spawn delete task: {}", e),
        })?
        .map_err(|e| StorageError::DatabaseError {
            message: format!("Redb delete error: {}", e),
        })?;
        
        Ok(existed)
    }
    
    async fn exists(&self, key: &[u8]) -> StorageResult<bool> {
        let db = self.db.clone();
        let key = key.to_vec();
        
        let exists = task::spawn_blocking(move || -> Result<bool, redb::Error> {
            let read_txn = db.begin_read()?;
            let data_table = read_txn.open_table(DATA_TABLE)?;
            let ttl_table = read_txn.open_table(TTL_TABLE)?;
            
            // Check if key exists in data table
            if data_table.get(key.as_slice())?.is_some() {
                // Check TTL if it exists
                if let Some(expiry_guard) = ttl_table.get(key.as_slice())? {
                    let expiry_time = expiry_guard.value();
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_millis() as u64;
                    
                    if now >= expiry_time {
                        // Key has expired
                        return Ok(false);
                    }
                }
                
                Ok(true)
            } else {
                Ok(false)
            }
        })
        .await
        .map_err(|e| StorageError::DatabaseError {
            message: format!("Failed to spawn exists task: {}", e),
        })?
        .map_err(|e| StorageError::DatabaseError {
            message: format!("Redb exists error: {}", e),
        })?;
        
        Ok(exists)
    }
    
    async fn expire_keys(&self) -> StorageResult<u64> {
        Self::cleanup_expired_keys_with_stats(self.db.clone(), self.expired_count.clone()).await
    }
    
    async fn stats(&self) -> StorageResult<StorageStats> {
        let db = self.db.clone();
        let expired_count = *self.expired_count.read().await;
        
        let (key_count, data_size) = task::spawn_blocking(move || -> Result<(u64, u64), redb::Error> {
            let read_txn = db.begin_read()?;
            let table = read_txn.open_table(DATA_TABLE)?;
            
            let mut key_count = 0;
            let mut data_size = 0;
            
            let range = table.range::<&[u8]>(..)?;
            for result in range {
                let (key, value) = result?;
                key_count += 1;
                data_size += key.value().len() + value.value().len();
            }
            
            Ok((key_count, data_size as u64))
        })
        .await
        .map_err(|e| StorageError::DatabaseError {
            message: format!("Failed to spawn stats task: {}", e),
        })?
        .map_err(|e| StorageError::DatabaseError {
            message: format!("Redb stats error: {}", e),
        })?;
        
        Ok(StorageStats {
            key_count,
            data_size,
            disk_size: None, // Redb doesn't easily expose file size
            expired_keys: expired_count,
            cache_hit_ratio: None, // Not easily available from Redb
        })
    }
    
    /// Get TTL cleanup performance statistics
    pub async fn ttl_cleanup_stats(&self) -> TtlCleanupStats {
        self.cleanup_stats.read().await.clone()
    }
    
    async fn flush(&self) -> StorageResult<()> {
        // Redb automatically flushes on commit, no explicit flush needed
        Ok(())
    }
    
    async fn compact(&self) -> StorageResult<()> {
        // Redb compaction requires &mut self, which is not compatible with Arc<Database>
        // For now, return OK as redb handles space management automatically
        Ok(())
    }
}

#[cfg(not(feature = "export-redb"))]
pub struct RedbStorageAdapter;

#[cfg(not(feature = "export-redb"))]
impl RedbStorageAdapter {
    pub async fn new<P: AsRef<std::path::Path>>(
        _db_path: P,
        _cache_size: Option<usize>,
        _ttl_cleanup_interval: std::time::Duration,
        _enable_compression: bool,
    ) -> super::StorageResult<Self> {
        Err(super::StorageError::ConfigError {
            message: "Redb backend not enabled. Enable 'export-redb' feature.".to_string()
        })
    }
}

#[cfg(all(test, feature = "export-redb"))]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use tokio::time::{sleep, Duration};
    
    #[tokio::test]
    async fn test_redb_storage_basic_operations() {
        let temp_file = NamedTempFile::new().unwrap();
        let adapter = RedbStorageAdapter::new(
            temp_file.path(),
            Some(1024 * 1024), // 1MB cache
            Duration::from_secs(60),
            false,
        ).await.unwrap();
        
        // Test set and get
        adapter.set(b"key1", b"value1", None).await.unwrap();
        let result = adapter.get(b"key1", ReadConsistency::Strong).await.unwrap();
        assert_eq!(result, Some(b"value1".to_vec()));
        
        // Test exists
        assert!(adapter.exists(b"key1").await.unwrap());
        assert!(!adapter.exists(b"key2").await.unwrap());
        
        // Test delete
        assert!(adapter.delete(b"key1").await.unwrap());
        assert!(!adapter.delete(b"key1").await.unwrap());
    }
    
    #[tokio::test]
    async fn test_redb_storage_ttl() {
        let temp_file = NamedTempFile::new().unwrap();
        let adapter = RedbStorageAdapter::new(
            temp_file.path(),
            Some(1024 * 1024),
            Duration::from_millis(50),
            false,
        ).await.unwrap();
        
        // Set with TTL
        adapter.set(b"ttl_key", b"ttl_value", Some(Duration::from_millis(10))).await.unwrap();
        
        // Should exist immediately
        assert!(adapter.exists(b"ttl_key").await.unwrap());
        
        // Wait for expiration and cleanup
        sleep(Duration::from_millis(100)).await;
        
        // Force expiration
        let expired = adapter.expire_keys().await.unwrap();
        assert!(expired > 0);
        
        // Should be expired
        assert!(!adapter.exists(b"ttl_key").await.unwrap());
    }
}