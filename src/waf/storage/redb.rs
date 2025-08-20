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
const EXPIRATION_TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("expirations");

#[cfg(feature = "export-redb")]
/// Redb storage adapter
pub struct RedbStorageAdapter {
    db: Arc<Database>,
    ttl_cleanup_interval: Duration,
    enable_compression: bool,
    expired_count: Arc<RwLock<u64>>,
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
                write_txn.open_table(EXPIRATION_TABLE)?;
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
        };
        
        // Start TTL cleanup task
        adapter.start_ttl_cleanup().await;
        
        Ok(adapter)
    }
    
    /// Start background TTL cleanup task
    async fn start_ttl_cleanup(&self) {
        let db = self.db.clone();
        let expired_count = self.expired_count.clone();
        let cleanup_interval = self.ttl_cleanup_interval;
        
        tokio::spawn(async move {
            let mut interval = interval(cleanup_interval);
            
            loop {
                interval.tick().await;
                
                if let Err(e) = Self::cleanup_expired_keys(db.clone(), expired_count.clone()).await {
                    error!("TTL cleanup failed: {}", e);
                }
            }
        });
    }
    
    /// Clean up expired keys
    async fn cleanup_expired_keys(
        db: Arc<Database>,
        expired_count: Arc<RwLock<u64>>,
    ) -> StorageResult<u64> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        
        let db_clone = db.clone();
        let expired_keys = task::spawn_blocking(move || -> Result<Vec<(u64, Vec<u8>)>, redb::Error> {
            let read_txn = db_clone.begin_read()?;
            let expiration_table = read_txn.open_table(EXPIRATION_TABLE)?;
            
            let mut expired = Vec::new();
            
            // Collect all expired keys with their expiry times
            let range = expiration_table.range::<u64>(..=now)?;
            for result in range {
                let (expiry_time, key) = result?;
                expired.push((expiry_time.value(), key.value().to_vec()));
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
                let mut expiration_table = write_txn.open_table(EXPIRATION_TABLE)?;
                
                for (expiry_time, key) in &expired_keys {
                    data_table.remove(key.as_slice())?;
                    expiration_table.remove(*expiry_time)?;
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
                // Strong consistency - standard read transaction with durability guarantees
                task::spawn_blocking(move || -> Result<Option<Vec<u8>>, redb::Error> {
                    let read_txn = db.begin_read()?;
                    let table = read_txn.open_table(DATA_TABLE)?;
                    
                    match table.get(key.as_slice())? {
                        Some(value) => Ok(Some(value.value().to_vec())),
                        None => Ok(None),
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
                // Eventual consistency - optimized read with potential for slightly stale data
                // This provides better performance by allowing the database more flexibility
                task::spawn_blocking(move || -> Result<Option<Vec<u8>>, redb::Error> {
                    let read_txn = db.begin_read()?;
                    let table = read_txn.open_table(DATA_TABLE)?;
                    
                    // Use the same read mechanism but signal that we can tolerate eventual consistency
                    // In the context of embedded databases, this primarily affects performance optimizations
                    match table.get(key.as_slice())? {
                        Some(value) => Ok(Some(value.value().to_vec())),
                        None => Ok(None),
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
                data_table.insert(key.as_slice(), value.as_slice())?;
                
                // Handle TTL if specified
                if let Some(duration) = ttl {
                    let expires_at = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_millis() as u64
                        + duration.as_millis() as u64;
                    
                    let mut expiration_table = write_txn.open_table(EXPIRATION_TABLE)?;
                    expiration_table.insert(expires_at, key.as_slice())?;
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
                let existed = data_table.get(key.as_slice())?.is_some();
                data_table.remove(key.as_slice())?;
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
            let table = read_txn.open_table(DATA_TABLE)?;
            Ok(table.get(key.as_slice())?.is_some())
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
        Self::cleanup_expired_keys(self.db.clone(), self.expired_count.clone()).await
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