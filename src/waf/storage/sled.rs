//! Sled Storage Adapter
//!
//! **Legacy backend.** sled is kept selectable (`storage.backend = "sled"`) so
//! existing deployments keep working and so the migration tool has a source.
//! New deployments default to redb; see `docs/operations/migrating-event-store.md`.
//!
//! Durability: sled defaults to `flush_every_ms = 500`, which means an
//! acknowledged write can be lost on a crash. Every `set`/`delete` here
//! explicitly flushes before returning, at the cost of one fsync per write.

#[cfg(feature = "export-sled")]
use super::{ReadConsistency, StorageAdapter, StorageError, StorageResult, StorageStats};
#[cfg(feature = "export-sled")]
use async_trait::async_trait;
#[cfg(feature = "export-sled")]
use sled::{Db, Tree};
#[cfg(feature = "export-sled")]
use std::ops::Bound;
#[cfg(feature = "export-sled")]
use std::path::Path;
#[cfg(feature = "export-sled")]
use std::sync::{Arc, Weak};
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

/// Marker written once the TTL tree uses `data key -> expiry_ms` (schema 2).
/// Stores without it use the original `expiry_be ++ data key -> data key`
/// layout and are rewritten in place on open.
#[cfg(feature = "export-sled")]
const TTL_SCHEMA_VERSION: &[u8] = b"2";
#[cfg(feature = "export-sled")]
const TTL_SCHEMA_KEY: &[u8] = b"ttl_schema_version";

#[cfg(feature = "export-sled")]
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(feature = "export-sled")]
/// Sled storage adapter
pub struct SledStorageAdapter {
    db: Arc<Db>,
    data_tree: Tree,
    ttl_tree: Tree,
    meta_tree: Tree,
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

        let meta_tree = db
            .open_tree("meta")
            .map_err(|e| StorageError::DatabaseError {
                message: format!("Failed to open meta tree: {}", e),
            })?;

        Self::upgrade_ttl_schema(&ttl_tree, &meta_tree).map_err(|e| {
            StorageError::DatabaseError {
                message: format!("Failed to upgrade Sled TTL schema: {}", e),
            }
        })?;

        let adapter = Self {
            db: Arc::new(db),
            data_tree,
            ttl_tree,
            meta_tree,
            ttl_cleanup_interval,
            enable_compression,
            expired_count: Arc::new(RwLock::new(0)),
        };

        // Start TTL cleanup task
        adapter.start_ttl_cleanup().await;

        Ok(adapter)
    }

    /// Rewrite a pre-schema-2 TTL tree (`expiry_be ++ key -> key`) into
    /// `key -> expiry_ms`. New stores only get the marker.
    fn upgrade_ttl_schema(
        ttl_tree: &Tree,
        meta_tree: &Tree,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if meta_tree.get(TTL_SCHEMA_KEY)?.as_deref() == Some(TTL_SCHEMA_VERSION) {
            return Ok(());
        }

        if !ttl_tree.is_empty() {
            let mut upgraded = Vec::new();
            for result in ttl_tree.iter() {
                let (ttl_key, value) = result?;
                if ttl_key.len() < 8 {
                    continue;
                }
                let mut expiry = [0u8; 8];
                expiry.copy_from_slice(&ttl_key[..8]);
                upgraded.push((value.to_vec(), u64::from_be_bytes(expiry)));
            }
            ttl_tree.clear()?;
            for (key, expiry) in upgraded {
                ttl_tree.insert(key, expiry.to_be_bytes().to_vec())?;
            }
            ttl_tree.flush()?;
        }

        meta_tree.insert(TTL_SCHEMA_KEY, TTL_SCHEMA_VERSION)?;
        meta_tree.flush()?;
        Ok(())
    }

    /// Start background TTL cleanup task.
    ///
    /// The task holds only a `Weak` handle so dropping the adapter releases the
    /// sled directory for a restart/reopen test or for the migration tool.
    async fn start_ttl_cleanup(&self) {
        let db = Arc::downgrade(&self.db);
        let expired_count = self.expired_count.clone();
        let cleanup_interval = self.ttl_cleanup_interval;

        tokio::spawn(async move {
            let mut interval = interval(cleanup_interval);

            loop {
                interval.tick().await;

                let Some(db) = Weak::upgrade(&db) else {
                    return;
                };

                if let Err(e) = Self::cleanup_expired_keys(&db, &expired_count).await {
                    error!("TTL cleanup failed: {}", e);
                }
            }
        });
    }

    /// Clean up expired keys
    async fn cleanup_expired_keys(db: &Db, expired_count: &Arc<RwLock<u64>>) -> StorageResult<u64> {
        let now = now_ms();
        let db = db.clone();

        let expired = task::spawn_blocking(move || -> Result<u64, sled::Error> {
            let data_tree = db.open_tree("data")?;
            let ttl_tree = db.open_tree("ttl")?;

            let mut expired_keys = Vec::new();
            for result in ttl_tree.iter() {
                let (key, expiry) = result?;
                if expiry.len() != 8 {
                    continue;
                }
                let mut expiry_bytes = [0u8; 8];
                expiry_bytes.copy_from_slice(&expiry);
                if u64::from_be_bytes(expiry_bytes) <= now {
                    expired_keys.push(key.to_vec());
                }
            }

            for key in &expired_keys {
                data_tree.remove(key)?;
                ttl_tree.remove(key)?;
            }

            if !expired_keys.is_empty() {
                data_tree.flush()?;
                ttl_tree.flush()?;
            }

            Ok(expired_keys.len() as u64)
        })
        .await
        .map_err(|e| StorageError::DatabaseError {
            message: format!("Failed to cleanup expired keys: {}", e),
        })?
        .map_err(|e| StorageError::DatabaseError {
            message: format!("Sled error during cleanup: {}", e),
        })?;

        if expired > 0 {
            let mut count = expired_count.write().await;
            *count += expired;
            debug!("Cleaned up {} expired keys from Sled", expired);
        }

        Ok(expired)
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
        let ttl_tree = self.ttl_tree.clone();
        let key = key.to_vec();

        // sled reads always observe the latest state; `consistency` is accepted
        // for trait parity and does not change the result here.
        let _ = consistency;

        let result = task::spawn_blocking(move || -> Result<Option<Vec<u8>>, sled::Error> {
            if let Some(expiry) = ttl_tree.get(&key)? {
                if expiry.len() == 8 {
                    let mut bytes = [0u8; 8];
                    bytes.copy_from_slice(&expiry);
                    if now_ms() >= u64::from_be_bytes(bytes) {
                        return Ok(None);
                    }
                }
            }

            Ok(data_tree.get(&key)?.map(|value| value.to_vec()))
        })
        .await
        .map_err(|e| StorageError::DatabaseError {
            message: format!("Failed to spawn get task: {}", e),
        })?
        .map_err(|e| StorageError::DatabaseError {
            message: format!("Sled get error: {}", e),
        })?;

        Ok(result.map(|data| self.decompress_if_enabled(&data)))
    }

    async fn set(&self, key: &[u8], value: &[u8], ttl: Option<Duration>) -> StorageResult<()> {
        let data_tree = self.data_tree.clone();
        let ttl_tree = self.ttl_tree.clone();
        let key = key.to_vec();
        let value = self.compress_if_enabled(value);

        task::spawn_blocking(move || -> Result<(), sled::Error> {
            data_tree.insert(&key, value.as_slice())?;

            match ttl {
                Some(duration) => {
                    let expires_at = now_ms() + duration.as_millis() as u64;
                    ttl_tree.insert(&key, expires_at.to_be_bytes().to_vec())?;
                }
                // An overwrite without a TTL clears the previous expiry.
                None => {
                    ttl_tree.remove(&key)?;
                }
            }

            // Explicit flush: durability is an acceptance criterion, not a
            // tuning knob (sled would otherwise batch for up to 500 ms).
            data_tree.flush()?;
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
            if existed {
                data_tree.remove(&key)?;
                ttl_tree.remove(&key)?;
                data_tree.flush()?;
            }
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
        let ttl_tree = self.ttl_tree.clone();
        let key = key.to_vec();

        let exists = task::spawn_blocking(move || -> Result<bool, sled::Error> {
            if data_tree.get(&key)?.is_none() {
                return Ok(false);
            }
            if let Some(expiry) = ttl_tree.get(&key)? {
                if expiry.len() == 8 {
                    let mut bytes = [0u8; 8];
                    bytes.copy_from_slice(&expiry);
                    if now_ms() >= u64::from_be_bytes(bytes) {
                        return Ok(false);
                    }
                }
            }
            Ok(true)
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
        Self::cleanup_expired_keys(&self.db, &self.expired_count).await
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
        let meta_tree = self.meta_tree.clone();

        task::spawn_blocking(move || -> Result<(), sled::Error> {
            data_tree.flush()?;
            ttl_tree.flush()?;
            meta_tree.flush()?;
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

    async fn scan_range(
        &self,
        start: Bound<&[u8]>,
        end: Bound<&[u8]>,
        limit: Option<usize>,
    ) -> StorageResult<Vec<(Vec<u8>, Vec<u8>)>> {
        let data_tree = self.data_tree.clone();
        let ttl_tree = self.ttl_tree.clone();
        let start = to_owned_bound(start);
        let end = to_owned_bound(end);

        let entries =
            task::spawn_blocking(move || -> Result<Vec<(Vec<u8>, Vec<u8>)>, sled::Error> {
                let now = now_ms();
                let mut entries = Vec::new();

                for result in data_tree.range((start, end)) {
                    let (key, value) = result?;

                    if let Some(expiry) = ttl_tree.get(&key)? {
                        if expiry.len() == 8 {
                            let mut bytes = [0u8; 8];
                            bytes.copy_from_slice(&expiry);
                            if now >= u64::from_be_bytes(bytes) {
                                continue;
                            }
                        }
                    }

                    entries.push((key.to_vec(), value.to_vec()));
                    if let Some(limit) = limit {
                        if entries.len() >= limit {
                            break;
                        }
                    }
                }

                Ok(entries)
            })
            .await
            .map_err(|e| StorageError::DatabaseError {
                message: format!("Failed to spawn scan task: {}", e),
            })?
            .map_err(|e| StorageError::DatabaseError {
                message: format!("Sled scan error: {}", e),
            })?;

        Ok(entries)
    }

    async fn ttl(&self, key: &[u8]) -> StorageResult<Option<Duration>> {
        let data_tree = self.data_tree.clone();
        let ttl_tree = self.ttl_tree.clone();
        let key = key.to_vec();

        let ttl = task::spawn_blocking(move || -> Result<Option<Duration>, sled::Error> {
            if data_tree.get(&key)?.is_none() {
                return Ok(None);
            }

            let Some(expiry) = ttl_tree.get(&key)? else {
                return Ok(None);
            };
            if expiry.len() != 8 {
                return Ok(None);
            }
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&expiry);
            let expiry = u64::from_be_bytes(bytes);
            let now = now_ms();
            if now >= expiry {
                Ok(None)
            } else {
                Ok(Some(Duration::from_millis(expiry - now)))
            }
        })
        .await
        .map_err(|e| StorageError::DatabaseError {
            message: format!("Failed to spawn ttl task: {}", e),
        })?
        .map_err(|e| StorageError::DatabaseError {
            message: format!("Sled ttl error: {}", e),
        })?;

        Ok(ttl)
    }

    async fn delete_many(&self, keys: &[Vec<u8>]) -> StorageResult<u64> {
        if keys.is_empty() {
            return Ok(0);
        }

        let data_tree = self.data_tree.clone();
        let ttl_tree = self.ttl_tree.clone();
        let keys = keys.to_vec();

        let removed = task::spawn_blocking(move || -> Result<u64, sled::Error> {
            let mut removed = 0u64;
            for key in &keys {
                if data_tree.get(key)?.is_some() {
                    removed += 1;
                }
                data_tree.remove(key)?;
                ttl_tree.remove(key)?;
            }
            if removed > 0 {
                data_tree.flush()?;
            }
            Ok(removed)
        })
        .await
        .map_err(|e| StorageError::DatabaseError {
            message: format!("Failed to spawn delete_many task: {}", e),
        })?
        .map_err(|e| StorageError::DatabaseError {
            message: format!("Sled delete_many error: {}", e),
        })?;

        Ok(removed)
    }

    fn backend_name(&self) -> &'static str {
        "sled"
    }
}

#[cfg(feature = "export-sled")]
fn to_owned_bound(bound: Bound<&[u8]>) -> Bound<Vec<u8>> {
    match bound {
        Bound::Included(value) => Bound::Included(value.to_vec()),
        Bound::Excluded(value) => Bound::Excluded(value.to_vec()),
        Bound::Unbounded => Bound::Unbounded,
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

        adapter.set(b"key1", b"value1", None).await.unwrap();
        let result = adapter.get(b"key1", ReadConsistency::Strong).await.unwrap();
        assert_eq!(result, Some(b"value1".to_vec()));

        assert!(adapter.exists(b"key1").await.unwrap());
        assert!(!adapter.exists(b"key2").await.unwrap());

        assert!(adapter.delete(b"key1").await.unwrap());
        assert!(!adapter.delete(b"key1").await.unwrap());
    }

    #[tokio::test]
    async fn test_sled_storage_ttl() {
        let adapter = SledStorageAdapter::new("", true, Duration::from_secs(3600), false)
            .await
            .unwrap();

        adapter
            .set(b"ttl_key", b"ttl_value", Some(Duration::from_millis(1000)))
            .await
            .unwrap();

        assert!(adapter.exists(b"ttl_key").await.unwrap());

        sleep(Duration::from_millis(1100)).await;

        // Expired entries are invisible even before cleanup.
        assert_eq!(
            adapter
                .get(b"ttl_key", ReadConsistency::Strong)
                .await
                .unwrap(),
            None
        );
        assert!(!adapter.exists(b"ttl_key").await.unwrap());

        let expired = adapter.expire_keys().await.unwrap();
        assert_eq!(expired, 1);
        assert_eq!(adapter.stats().await.unwrap().key_count, 0);
    }

    #[tokio::test]
    async fn test_sled_overwrite_clears_ttl() {
        let adapter = SledStorageAdapter::new("", true, Duration::from_secs(60), false)
            .await
            .unwrap();

        adapter
            .set(b"k", b"v1", Some(Duration::from_millis(5)))
            .await
            .unwrap();
        adapter.set(b"k", b"v2", None).await.unwrap();

        sleep(Duration::from_millis(20)).await;

        assert_eq!(
            adapter.get(b"k", ReadConsistency::Strong).await.unwrap(),
            Some(b"v2".to_vec())
        );
        assert_eq!(adapter.ttl(b"k").await.unwrap(), None);
    }
}
