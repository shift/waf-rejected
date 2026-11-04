//! Sled Storage Adapter
//!
//! Storage implementation using the Sled embedded database

#[cfg(feature = "export-sled")]
use super::{ReadConsistency, StorageAdapter, StorageError, StorageResult, StorageStats};
#[cfg(feature = "export-sled")]
use async_trait::async_trait;
#[cfg(feature = "export-sled")]
use sled::{Db, Tree};
#[cfg(feature = "export-sled")]
use std::path::Path;
#[cfg(feature = "export-sled")]
use std::sync::Arc;
#[cfg(feature = "export-sled")]
use std::time::{Duration, SystemTime, UNIX_EPOCH};
#[cfg(feature = "export-sled")]
use tokio::sync::RwLock;
#[cfg(feature = "export-sled")]
use tokio::task;
#[cfg(feature = "export-sled")]
use tokio::time::interval;
#[cfg(feature = "export-sled")]
use tracing::{debug, error};

#[cfg(feature = "export-sled")]
/// Sled storage adapter
pub struct SledStorageAdapter {
    db: Arc<Db>,
    data_tree: Tree,
    ttl_tree: Tree,
    ttl_cleanup_interval: Duration,
    enable_compression: bool,
    expired_count: Arc<RwLock<u64>>,
}

#[cfg(feature = "export-sled")]
impl SledStorageAdapter {
    /// Create a new Sled storage adapter
    pub async fn new<P: AsRef<Path>>(
        db_path: P,
        temporary: bool,
        ttl_cleanup_interval: Duration,
        enable_compression: bool,
    ) -> StorageResult<Self> {
        let db = if temporary {
            task::spawn_blocking(|| sled::Config::new().temporary(true).open())
                .await
                .map_err(|e| StorageError::DatabaseError {
                    message: format!("Failed to spawn database task: {}", e),
                })?
                .map_err(|e| StorageError::DatabaseError {
                    message: format!("Failed to create temporary Sled database: {}", e),
                })?
        } else {
            task::spawn_blocking({
                let path = db_path.as_ref().to_path_buf();
                move || sled::open(&path)
            })
            .await
            .map_err(|e| StorageError::DatabaseError {
                message: format!("Failed to spawn database task: {}", e),
            })?
            .map_err(|e| StorageError::DatabaseError {
                message: format!("Failed to open Sled database: {}", e),
            })?
        };

        let data_tree = db
            .open_tree("data")
            .map_err(|e| StorageError::DatabaseError {
                message: format!("Failed to open data tree: {}", e),
            })?;

        let ttl_tree = db
            .open_tree("ttl")
            .map_err(|e| StorageError::DatabaseError {
                message: format!("Failed to open TTL tree: {}", e),
            })?;

        let adapter = Self {
            db: Arc::new(db),
            data_tree,
            ttl_tree,
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
        let data_tree = self.data_tree.clone();
        let ttl_tree = self.ttl_tree.clone();
        let expired_count = self.expired_count.clone();
        let cleanup_interval = self.ttl_cleanup_interval;

        tokio::spawn(async move {
            let mut interval = interval(cleanup_interval);

            loop {
                interval.tick().await;

                if let Err(e) =
                    Self::cleanup_expired_keys(&data_tree, &ttl_tree, &expired_count).await
                {
                    error!("TTL cleanup failed: {}", e);
                }
            }
        });
    }

    /// Clean up expired keys
    async fn cleanup_expired_keys(
        data_tree: &Tree,
        ttl_tree: &Tree,
        expired_count: &Arc<RwLock<u64>>,
    ) -> StorageResult<u64> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let data_tree = data_tree.clone();
        let ttl_tree = ttl_tree.clone();

        let expired_keys = task::spawn_blocking(move || -> Result<Vec<Vec<u8>>, sled::Error> {
            let mut expired = Vec::new();

            // Collect expired keys
            for result in ttl_tree.iter() {
                let (expiry_key, data_key) = result?;
                let expiry_time =
                    u64::from_be_bytes(expiry_key.as_ref().try_into().map_err(|_| {
                        sled::Error::Io(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "Invalid expiry time format",
                        ))
                    })?);

                if expiry_time <= now {
                    expired.push(data_key.to_vec());
                }
            }

            // Remove expired keys
            for key in &expired {
                data_tree.remove(key)?;

                // Remove TTL entry
                for result in ttl_tree.iter() {
                    let (expiry_key, data_key) = result?;
                    if data_key.as_ref() == key.as_slice() {
                        ttl_tree.remove(&expiry_key)?;
                        break;
                    }
                }
            }

            data_tree.flush()?;
            ttl_tree.flush()?;

            Ok(expired)
        })
        .await
        .map_err(|e| StorageError::DatabaseError {
            message: format!("Failed to cleanup expired keys: {}", e),
        })?
        .map_err(|e| StorageError::DatabaseError {
            message: format!("Sled error during cleanup: {}", e),
        })?;

        if !expired_keys.is_empty() {
            let mut count = expired_count.write().await;
            *count += expired_keys.len() as u64;
            debug!("Cleaned up {} expired keys from Sled", expired_keys.len());
        }

        Ok(expired_keys.len() as u64)
    }

    /// Create TTL key from expiry time and data key
    fn create_ttl_key(expiry_time: u64, data_key: &[u8]) -> Vec<u8> {
        let mut ttl_key = Vec::with_capacity(8 + data_key.len());
        ttl_key.extend_from_slice(&expiry_time.to_be_bytes());
        ttl_key.extend_from_slice(data_key);
        ttl_key
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

#[cfg(feature = "export-sled")]
#[async_trait]
impl StorageAdapter for SledStorageAdapter {
    async fn get(
        &self,
        key: &[u8],
        consistency: ReadConsistency,
    ) -> StorageResult<Option<Vec<u8>>> {
        let data_tree = self.data_tree.clone();
        let key = key.to_vec();

        let result = match consistency {
            ReadConsistency::Strong => {
                // Strong consistency - include explicit flush to ensure durability
                task::spawn_blocking(move || -> Result<Option<Vec<u8>>, sled::Error> {
                    data_tree.flush()?; // Ensure all pending writes are visible
                    match data_tree.get(&key)? {
                        Some(value) => Ok(Some(value.to_vec())),
                        None => Ok(None),
                    }
                })
                .await
                .map_err(|e| StorageError::DatabaseError {
                    message: format!("Failed to spawn strong consistency get task: {}", e),
                })?
                .map_err(|e| StorageError::DatabaseError {
                    message: format!("Sled strong consistency get error: {}", e),
                })?
            }
            ReadConsistency::Eventual => {
                // Eventual consistency - skip flush for better performance
                task::spawn_blocking(move || -> Result<Option<Vec<u8>>, sled::Error> {
                    match data_tree.get(&key)? {
                        Some(value) => Ok(Some(value.to_vec())),
                        None => Ok(None),
                    }
                })
                .await
                .map_err(|e| StorageError::DatabaseError {
                    message: format!("Failed to spawn eventual consistency get task: {}", e),
                })?
                .map_err(|e| StorageError::DatabaseError {
                    message: format!("Sled eventual consistency get error: {}", e),
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
        let data_tree = self.data_tree.clone();
        let ttl_tree = self.ttl_tree.clone();
        let key = key.to_vec();
        let value = self.compress_if_enabled(value);

        task::spawn_blocking(move || -> Result<(), sled::Error> {
            data_tree.insert(&key, value.as_slice())?;

            // Handle TTL if specified
            if let Some(duration) = ttl {
                let expires_at = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64
                    + duration.as_millis() as u64;

                let ttl_key = Self::create_ttl_key(expires_at, &key);
                ttl_tree.insert(ttl_key, key.as_slice())?;
            }

            data_tree.flush()?;
            if ttl.is_some() {
                ttl_tree.flush()?;
            }

            Ok(())
        })
        .await
        .map_err(|e| StorageError::DatabaseError {
            message: format!("Failed to spawn set task: {}", e),
        })?
        .map_err(|e| StorageError::DatabaseError {
            message: format!("Sled set error: {}", e),
        })?;

        Ok(())
    }

    async fn delete(&self, key: &[u8]) -> StorageResult<bool> {
        let data_tree = self.data_tree.clone();
        let ttl_tree = self.ttl_tree.clone();
        let key = key.to_vec();

        let existed = task::spawn_blocking(move || -> Result<bool, sled::Error> {
            let existed = data_tree.get(&key)?.is_some();
            data_tree.remove(&key)?;

            // Remove any TTL entries for this key
            let mut ttl_keys_to_remove = Vec::new();
            for result in ttl_tree.iter() {
                let (ttl_key, data_key) = result?;
                if data_key.as_ref() == key.as_slice() {
                    ttl_keys_to_remove.push(ttl_key.to_vec());
                }
            }

            for ttl_key in ttl_keys_to_remove {
                ttl_tree.remove(&ttl_key)?;
            }

            data_tree.flush()?;
            ttl_tree.flush()?;

            Ok(existed)
        })
        .await
        .map_err(|e| StorageError::DatabaseError {
            message: format!("Failed to spawn delete task: {}", e),
        })?
        .map_err(|e| StorageError::DatabaseError {
            message: format!("Sled delete error: {}", e),
        })?;

        Ok(existed)
    }

    async fn exists(&self, key: &[u8]) -> StorageResult<bool> {
        let data_tree = self.data_tree.clone();
        let key = key.to_vec();

        let exists = task::spawn_blocking(move || -> Result<bool, sled::Error> {
            Ok(data_tree.get(&key)?.is_some())
        })
        .await
        .map_err(|e| StorageError::DatabaseError {
            message: format!("Failed to spawn exists task: {}", e),
        })?
        .map_err(|e| StorageError::DatabaseError {
            message: format!("Sled exists error: {}", e),
        })?;

        Ok(exists)
    }

    async fn expire_keys(&self) -> StorageResult<u64> {
        Self::cleanup_expired_keys(&self.data_tree, &self.ttl_tree, &self.expired_count).await
    }

    async fn stats(&self) -> StorageResult<StorageStats> {
        let data_tree = self.data_tree.clone();
        let expired_count = *self.expired_count.read().await;

        let (key_count, data_size) =
            task::spawn_blocking(move || -> Result<(u64, u64), sled::Error> {
                let mut key_count = 0;
                let mut data_size = 0;

                for result in data_tree.iter() {
                    let (key, value) = result?;
                    key_count += 1;
                    data_size += key.len() + value.len();
                }

                Ok((key_count, data_size as u64))
            })
            .await
            .map_err(|e| StorageError::DatabaseError {
                message: format!("Failed to spawn stats task: {}", e),
            })?
            .map_err(|e| StorageError::DatabaseError {
                message: format!("Sled stats error: {}", e),
            })?;

        let disk_size = self
            .db
            .size_on_disk()
            .map_err(|e| StorageError::DatabaseError {
                message: format!("Failed to get disk size: {}", e),
            })?;

        Ok(StorageStats {
            key_count,
            data_size,
            disk_size: Some(disk_size),
            expired_keys: expired_count,
            cache_hit_ratio: None, // Not available from Sled
        })
    }

    async fn flush(&self) -> StorageResult<()> {
        let data_tree = self.data_tree.clone();
        let ttl_tree = self.ttl_tree.clone();

        task::spawn_blocking(move || -> Result<(), sled::Error> {
            data_tree.flush()?;
            ttl_tree.flush()?;
            Ok(())
        })
        .await
        .map_err(|e| StorageError::DatabaseError {
            message: format!("Failed to spawn flush task: {}", e),
        })?
        .map_err(|e| StorageError::DatabaseError {
            message: format!("Sled flush error: {}", e),
        })?;

        Ok(())
    }

    async fn compact(&self) -> StorageResult<()> {
        // Sled doesn't have explicit compaction, but we can trigger a flush
        self.flush().await
    }
}

#[cfg(not(feature = "export-sled"))]
pub struct SledStorageAdapter;

#[cfg(not(feature = "export-sled"))]
impl SledStorageAdapter {
    pub async fn new<P: AsRef<std::path::Path>>(
        _db_path: P,
        _temporary: bool,
        _ttl_cleanup_interval: std::time::Duration,
        _enable_compression: bool,
    ) -> super::StorageResult<Self> {
        Err(super::StorageError::ConfigError {
            message: "Sled backend not enabled. Enable 'export-sled' feature.".to_string(),
        })
    }
}

#[cfg(all(test, feature = "export-sled"))]
mod tests {
    use super::*;
    use tokio::time::{sleep, Duration};

    #[tokio::test]
    async fn test_sled_storage_basic_operations() {
        let adapter = SledStorageAdapter::new(
            "",
            true, // temporary
            Duration::from_secs(60),
            false,
        )
        .await
        .unwrap();

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
    async fn test_sled_storage_ttl() {
        let adapter = SledStorageAdapter::new("", true, Duration::from_millis(50), false)
            .await
            .unwrap();

        // Set with TTL
        adapter
            .set(b"ttl_key", b"ttl_value", Some(Duration::from_millis(10)))
            .await
            .unwrap();

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
