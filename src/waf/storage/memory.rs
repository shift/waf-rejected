//! Memory Storage Adapter
//!
//! In-memory storage implementation for testing and development

use super::{ReadConsistency, StorageAdapter, StorageError, StorageResult, StorageStats};
use async_trait::async_trait;
use std::collections::HashMap;
use std::ops::Bound;
use std::sync::{Arc, Weak};
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;
use tokio::time::interval;
use tracing::debug;

/// TTL entry with expiration time
#[derive(Debug, Clone)]
struct TTLEntry {
    value: Vec<u8>,
    expires_at: Option<SystemTime>,
}

/// In-memory storage adapter
pub struct MemoryStorageAdapter {
    data: Arc<RwLock<HashMap<Vec<u8>, TTLEntry>>>,
    max_size: Option<usize>,
    ttl_cleanup_interval: Duration,
    expired_count: Arc<RwLock<u64>>,
}

impl MemoryStorageAdapter {
    /// Create a new memory storage adapter
    pub async fn new(
        max_size: Option<usize>,
        ttl_cleanup_interval: Duration,
    ) -> StorageResult<Self> {
        let adapter = Self {
            data: Arc::new(RwLock::new(HashMap::new())),
            max_size,
            ttl_cleanup_interval,
            expired_count: Arc::new(RwLock::new(0)),
        };

        // Start TTL cleanup task
        adapter.start_ttl_cleanup().await;

        Ok(adapter)
    }

    /// Start background TTL cleanup task
    async fn start_ttl_cleanup(&self) {
        let data = Arc::downgrade(&self.data);
        let expired_count = self.expired_count.clone();
        let cleanup_interval = self.ttl_cleanup_interval;

        tokio::spawn(async move {
            let mut interval = interval(cleanup_interval);

            loop {
                interval.tick().await;

                let Some(data) = Weak::upgrade(&data) else {
                    return;
                };

                let now = SystemTime::now();
                let mut data_lock = data.write().await;
                let mut expired_lock = expired_count.write().await;

                let mut expired_keys = Vec::new();

                for (key, entry) in data_lock.iter() {
                    if let Some(expires_at) = entry.expires_at {
                        if now >= expires_at {
                            expired_keys.push(key.clone());
                        }
                    }
                }

                for key in &expired_keys {
                    data_lock.remove(key);
                }

                if !expired_keys.is_empty() {
                    *expired_lock += expired_keys.len() as u64;
                    debug!("Expired {} keys from memory storage", expired_keys.len());
                }
            }
        });
    }

    /// Check if storage has reached capacity
    async fn check_capacity(&self) -> StorageResult<()> {
        if let Some(max_size) = self.max_size {
            let data = self.data.read().await;
            if data.len() >= max_size {
                return Err(StorageError::DatabaseError {
                    message: format!(
                        "Memory storage capacity exceeded: {}/{}",
                        data.len(),
                        max_size
                    ),
                });
            }
        }
        Ok(())
    }
}

#[async_trait]
impl StorageAdapter for MemoryStorageAdapter {
    async fn get(
        &self,
        key: &[u8],
        consistency: ReadConsistency,
    ) -> StorageResult<Option<Vec<u8>>> {
        // For memory storage, consistency level doesn't affect the implementation much
        // since all data is immediately available. We'll use different lock strategies for performance.

        match consistency {
            ReadConsistency::Strong => {
                // Strong consistency - full read lock, ensures complete consistency
                let data = self.data.read().await;

                if let Some(entry) = data.get(key) {
                    // Check if entry has expired
                    if let Some(expires_at) = entry.expires_at {
                        if SystemTime::now() >= expires_at {
                            // Entry has expired, return None
                            return Ok(None);
                        }
                    }

                    Ok(Some(entry.value.clone()))
                } else {
                    Ok(None)
                }
            }
            ReadConsistency::Eventual => {
                // Eventual consistency - optimized read that can potentially
                // use try_read for better concurrency
                match self.data.try_read() {
                    Ok(data) => {
                        if let Some(entry) = data.get(key) {
                            // Check if entry has expired
                            if let Some(expires_at) = entry.expires_at {
                                if SystemTime::now() >= expires_at {
                                    return Ok(None);
                                }
                            }
                            Ok(Some(entry.value.clone()))
                        } else {
                            Ok(None)
                        }
                    }
                    Err(_) => {
                        // If try_read fails, fall back to regular read
                        let data = self.data.read().await;
                        if let Some(entry) = data.get(key) {
                            if let Some(expires_at) = entry.expires_at {
                                if SystemTime::now() >= expires_at {
                                    return Ok(None);
                                }
                            }
                            Ok(Some(entry.value.clone()))
                        } else {
                            Ok(None)
                        }
                    }
                }
            }
        }
    }

    async fn set(&self, key: &[u8], value: &[u8], ttl: Option<Duration>) -> StorageResult<()> {
        self.check_capacity().await?;

        let expires_at = ttl.map(|duration| SystemTime::now() + duration);

        let entry = TTLEntry {
            value: value.to_vec(),
            expires_at,
        };

        let mut data = self.data.write().await;
        data.insert(key.to_vec(), entry);

        Ok(())
    }

    async fn delete(&self, key: &[u8]) -> StorageResult<bool> {
        let mut data = self.data.write().await;
        Ok(data.remove(key).is_some())
    }

    async fn exists(&self, key: &[u8]) -> StorageResult<bool> {
        let data = self.data.read().await;

        if let Some(entry) = data.get(key) {
            // Check if entry has expired
            if let Some(expires_at) = entry.expires_at {
                if SystemTime::now() >= expires_at {
                    return Ok(false);
                }
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn expire_keys(&self) -> StorageResult<u64> {
        let now = SystemTime::now();
        let mut data = self.data.write().await;
        let mut expired_count = self.expired_count.write().await;

        let mut expired_keys = Vec::new();

        for (key, entry) in data.iter() {
            if let Some(expires_at) = entry.expires_at {
                if now >= expires_at {
                    expired_keys.push(key.clone());
                }
            }
        }

        for key in &expired_keys {
            data.remove(key);
        }

        let expired_len = expired_keys.len() as u64;
        *expired_count += expired_len;

        Ok(expired_len)
    }

    async fn stats(&self) -> StorageResult<StorageStats> {
        let data = self.data.read().await;
        let expired_count = *self.expired_count.read().await;

        let key_count = data.len() as u64;
        let data_size = data
            .iter()
            .map(|(k, v)| k.len() + v.value.len())
            .sum::<usize>() as u64;

        Ok(StorageStats {
            key_count,
            data_size,
            disk_size: None, // In-memory storage has no disk usage
            expired_keys: expired_count,
            cache_hit_ratio: Some(1.0), // All data is in memory
        })
    }

    async fn flush(&self) -> StorageResult<()> {
        // No-op for memory storage
        Ok(())
    }

    async fn compact(&self) -> StorageResult<()> {
        // No-op for memory storage
        Ok(())
    }

    async fn scan_range(
        &self,
        start: Bound<&[u8]>,
        end: Bound<&[u8]>,
        limit: Option<usize>,
    ) -> StorageResult<Vec<(Vec<u8>, Vec<u8>)>> {
        let data = self.data.read().await;
        let now = SystemTime::now();

        let mut entries: Vec<(Vec<u8>, Vec<u8>)> = data
            .iter()
            .filter(|(key, entry)| {
                if let Some(expires_at) = entry.expires_at {
                    if now >= expires_at {
                        return false;
                    }
                }
                in_range(key.as_slice(), &start, &end)
            })
            .map(|(key, entry)| (key.clone(), entry.value.clone()))
            .collect();

        // A HashMap has no order; the other backends return lexicographic key
        // order, so sort to keep the trait contract identical.
        entries.sort_unstable_by(|a, b| a.0.cmp(&b.0));

        if let Some(limit) = limit {
            entries.truncate(limit);
        }

        Ok(entries)
    }

    async fn ttl(&self, key: &[u8]) -> StorageResult<Option<Duration>> {
        let data = self.data.read().await;
        let Some(entry) = data.get(key) else {
            return Ok(None);
        };
        let Some(expires_at) = entry.expires_at else {
            return Ok(None);
        };

        match expires_at.duration_since(SystemTime::now()) {
            Ok(remaining) if !remaining.is_zero() => Ok(Some(remaining)),
            _ => Ok(None),
        }
    }

    async fn delete_many(&self, keys: &[Vec<u8>]) -> StorageResult<u64> {
        let mut data = self.data.write().await;
        let mut removed = 0u64;
        for key in keys {
            if data.remove(key).is_some() {
                removed += 1;
            }
        }
        Ok(removed)
    }

    fn backend_name(&self) -> &'static str {
        "memory"
    }
}

fn in_range(key: &[u8], start: &Bound<&[u8]>, end: &Bound<&[u8]>) -> bool {
    let after_start = match start {
        Bound::Included(start) => key >= *start,
        Bound::Excluded(start) => key > *start,
        Bound::Unbounded => true,
    };
    let before_end = match end {
        Bound::Included(end) => key <= *end,
        Bound::Excluded(end) => key < *end,
        Bound::Unbounded => true,
    };
    after_start && before_end
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{sleep, Duration};

    #[tokio::test]
    async fn test_memory_storage_basic_operations() {
        let adapter = MemoryStorageAdapter::new(None, Duration::from_secs(60))
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
    async fn test_memory_storage_ttl() {
        let adapter = MemoryStorageAdapter::new(None, Duration::from_millis(100))
            .await
            .unwrap();

        // Set with TTL
        adapter
            .set(b"ttl_key", b"ttl_value", Some(Duration::from_millis(50)))
            .await
            .unwrap();

        // Should exist immediately
        assert!(adapter.exists(b"ttl_key").await.unwrap());

        // Wait for expiration
        sleep(Duration::from_millis(100)).await;

        // Should be expired
        assert!(!adapter.exists(b"ttl_key").await.unwrap());
        let result = adapter
            .get(b"ttl_key", ReadConsistency::Strong)
            .await
            .unwrap();
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn test_memory_storage_capacity() {
        let adapter = MemoryStorageAdapter::new(Some(2), Duration::from_secs(60))
            .await
            .unwrap();

        // Add up to capacity
        adapter.set(b"key1", b"value1", None).await.unwrap();
        adapter.set(b"key2", b"value2", None).await.unwrap();

        // Should fail when exceeding capacity
        let result = adapter.set(b"key3", b"value3", None).await;
        assert!(result.is_err());
    }
}
