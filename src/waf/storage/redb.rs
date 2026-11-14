//! Redb Storage Adapter
//!
//! Default security-event store. redb is a pure-Rust, single-file,
//! copy-on-write B-tree with ACID transactions and crash-safe commits.
//!
//! Durability: every write transaction explicitly sets
//! [`redb::Durability::Immediate`], so an acknowledged `set` is fsynced before
//! the call returns (redb's documented default, pinned here so a future upgrade
//! cannot silently weaken it). The throughput cost is one fsync per write
//! transaction; callers that batch events should use a bulk write path.

#[cfg(feature = "export-redb")]
use super::{ReadConsistency, StorageAdapter, StorageError, StorageResult, StorageStats};
#[cfg(feature = "export-redb")]
use async_trait::async_trait;
#[cfg(feature = "export-redb")]
use redb::{
    Database, Durability, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition,
    WriteTransaction,
};
#[cfg(feature = "export-redb")]
use std::ops::Bound;
#[cfg(feature = "export-redb")]
use std::path::{Path, PathBuf};
#[cfg(feature = "export-redb")]
use std::sync::{Arc, Weak};
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

/// key -> expiration_timestamp_ms (1:1 with `data`)
#[cfg(feature = "export-redb")]
const TTL_TABLE: TableDefinition<&[u8], u64> = TableDefinition::new("ttl_metadata");

/// `expiration_timestamp_ms_be ++ key` -> key. Ordered by expiry first so TTL
/// cleanup reads only the expired prefix instead of the whole TTL table. The
/// full key is part of the index key, so entries are unique even when two keys
/// share a prefix, a length or a timestamp.
#[cfg(feature = "export-redb")]
const EXPIRATION_INDEX: TableDefinition<&[u8], &[u8]> = TableDefinition::new("expiration_index");

#[cfg(feature = "export-redb")]
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(feature = "export-redb")]
fn expiration_index_key(expires_at: u64, key: &[u8]) -> Vec<u8> {
    let mut index_key = Vec::with_capacity(8 + key.len());
    index_key.extend_from_slice(&expires_at.to_be_bytes());
    index_key.extend_from_slice(key);
    index_key
}

#[cfg(feature = "export-redb")]
fn parse_expiration(index_key: &[u8]) -> Option<u64> {
    let bytes: [u8; 8] = index_key.get(..8)?.try_into().ok()?;
    Some(u64::from_be_bytes(bytes))
}

/// `(expiration_index_key, data_key)` pairs collected for one cleanup pass.
#[cfg(feature = "export-redb")]
type ExpiredCandidates = Vec<(Vec<u8>, Vec<u8>)>;

/// Pin durability on every write transaction. See the module docs.
#[cfg(feature = "export-redb")]
fn begin_durable_write(db: &Database) -> Result<WriteTransaction, redb::Error> {
    let mut txn = db.begin_write()?;
    txn.set_durability(Durability::Immediate)?;
    Ok(txn)
}

#[cfg(feature = "export-redb")]
/// Redb storage adapter
pub struct RedbStorageAdapter {
    db: Arc<Database>,
    path: PathBuf,
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
    /// Open the database and make sure its tables (and the TTL index) are
    /// usable. Synchronous so the event exporter can be built from a sync
    /// constructor.
    fn open_database(path: &Path, cache_size: Option<usize>) -> StorageResult<Database> {
        let mut builder = redb::Builder::new();

        if let Some(cache_size) = cache_size {
            builder.set_cache_size(cache_size);
        }

        let db = builder
            .create(path)
            .map_err(|e| StorageError::DatabaseError {
                message: format!("Failed to create Redb database: {}", e),
            })?;

        let initialize = || -> Result<(), redb::Error> {
            // Initialize tables and repair the expiration index if it does not
            // agree with the TTL table (e.g. after an unclean copy).
            let txn = begin_durable_write(&db)?;
            {
                let _data_table = txn.open_table(DATA_TABLE)?;
                let ttl_table = txn.open_table(TTL_TABLE)?;
                let mut index = txn.open_table(EXPIRATION_INDEX)?;

                if index.len()? != ttl_table.len()? {
                    debug!("Rebuilding redb TTL expiration index");
                    let mut rebuilt = Vec::new();
                    for entry in ttl_table.iter()? {
                        let (key, expiry) = entry?;
                        rebuilt.push((
                            expiration_index_key(expiry.value(), key.value()),
                            key.value().to_vec(),
                        ));
                    }
                    index.retain(|_, _| false)?;
                    for (index_key, key) in rebuilt {
                        index.insert(index_key.as_slice(), key.as_slice())?;
                    }
                }
            }
            txn.commit()?;
            Ok(())
        };

        initialize().map_err(|e| StorageError::DatabaseError {
            message: format!("Failed to initialize Redb database: {}", e),
        })?;

        Ok(db)
    }

    /// Open a redb store without starting the background TTL collector.
    ///
    /// Used by the security-event exporter, which never writes TTLs and is
    /// constructed from a synchronous context.
    pub fn open_sync<P: AsRef<Path>>(
        db_path: P,
        cache_size: Option<usize>,
        enable_compression: bool,
    ) -> StorageResult<Self> {
        let path = db_path.as_ref().to_path_buf();
        let db = Self::open_database(&path, cache_size)?;

        Ok(Self {
            db: Arc::new(db),
            path,
            ttl_cleanup_interval: Duration::from_secs(24 * 60 * 60),
            enable_compression,
            expired_count: Arc::new(RwLock::new(0)),
            cleanup_stats: Arc::new(RwLock::new(TtlCleanupStats::default())),
        })
    }

    /// Create a new Redb storage adapter
    pub async fn new<P: AsRef<Path>>(
        db_path: P,
        cache_size: Option<usize>,
        ttl_cleanup_interval: Duration,
        enable_compression: bool,
    ) -> StorageResult<Self> {
        let path = db_path.as_ref().to_path_buf();
        let open_path = path.clone();

        let db = task::spawn_blocking(move || Self::open_database(&open_path, cache_size))
            .await
            .map_err(|e| StorageError::DatabaseError {
                message: format!("Failed to spawn database task: {}", e),
            })??;

        let adapter = Self {
            db: Arc::new(db),
            path,
            ttl_cleanup_interval,
            enable_compression,
            expired_count: Arc::new(RwLock::new(0)),
            cleanup_stats: Arc::new(RwLock::new(TtlCleanupStats::default())),
        };

        // Start TTL cleanup task
        adapter.start_ttl_cleanup().await;

        Ok(adapter)
    }

    /// Start background TTL cleanup task with enhanced monitoring.
    ///
    /// The task holds only a `Weak` handle so dropping the adapter releases the
    /// database file (which is what makes a restart/reopen test meaningful).
    async fn start_ttl_cleanup(&self) {
        let db = Arc::downgrade(&self.db);
        let expired_count = self.expired_count.clone();
        let cleanup_stats = self.cleanup_stats.clone();
        let cleanup_interval = self.ttl_cleanup_interval;

        tokio::spawn(async move {
            let mut interval = interval(cleanup_interval);

            loop {
                interval.tick().await;

                let Some(db) = Weak::upgrade(&db) else {
                    return;
                };

                let start_time = SystemTime::now();
                match Self::cleanup_expired_keys_with_stats(db, expired_count.clone()).await {
                    Ok(expired_keys) => {
                        let cleanup_duration =
                            start_time.elapsed().unwrap_or_default().as_millis() as u64;

                        // Update cleanup statistics
                        let mut stats = cleanup_stats.write().await;
                        stats.cleanup_runs += 1;
                        stats.total_expired_keys += expired_keys;
                        stats.last_cleanup_duration_ms = cleanup_duration;
                        stats.last_cleanup_key_count = expired_keys;
                        stats.max_cleanup_duration_ms =
                            stats.max_cleanup_duration_ms.max(cleanup_duration);

                        // Update rolling average
                        if stats.cleanup_runs > 0 {
                            stats.avg_cleanup_duration_ms = (stats.avg_cleanup_duration_ms
                                * (stats.cleanup_runs - 1) as f64
                                + cleanup_duration as f64)
                                / stats.cleanup_runs as f64;
                        }

                        debug!(
                            "TTL cleanup completed: {} keys in {}ms",
                            expired_keys, cleanup_duration
                        );
                    }
                    Err(e) => {
                        error!("TTL cleanup failed: {}", e);
                    }
                }
            }
        });
    }

    /// Clean up expired keys using the expiration index.
    ///
    /// Returns the number of live entries removed. Stale index entries (an
    /// expiry that no longer matches the key's TTL metadata, or a missing data
    /// key) are dropped without touching the data.
    async fn cleanup_expired_keys_with_stats(
        db: Arc<Database>,
        expired_count: Arc<RwLock<u64>>,
    ) -> StorageResult<u64> {
        let now = now_ms();

        let read_db = db.clone();
        let candidates = task::spawn_blocking(move || -> Result<ExpiredCandidates, redb::Error> {
            let read_txn = read_db.begin_read()?;
            let index = read_txn.open_table(EXPIRATION_INDEX)?;

            let mut expired = Vec::new();
            for result in index.range::<&[u8]>(..)? {
                let (index_key, data_key) = result?;
                let index_key = index_key.value();

                // Entries are ordered by expiry first, so stop at the first
                // entry that has not expired.
                match parse_expiration(index_key) {
                    Some(expiry) if expiry <= now => {
                        expired.push((index_key.to_vec(), data_key.value().to_vec()));
                    }
                    Some(_) => break,
                    // Malformed index key: drop it during the write pass.
                    None => expired.push((index_key.to_vec(), data_key.value().to_vec())),
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

        if candidates.is_empty() {
            return Ok(0);
        }

        let write_db = db.clone();
        let removed = task::spawn_blocking(move || -> Result<u64, redb::Error> {
            let txn = begin_durable_write(&write_db)?;
            let removed = {
                let mut data_table = txn.open_table(DATA_TABLE)?;
                let mut ttl_table = txn.open_table(TTL_TABLE)?;
                let mut index = txn.open_table(EXPIRATION_INDEX)?;

                let mut removed = 0u64;
                for (index_key, key) in &candidates {
                    let indexed_expiry = parse_expiration(index_key);
                    let current_expiry = ttl_table.get(key.as_slice())?.map(|g| g.value());

                    match (indexed_expiry, current_expiry) {
                        (Some(indexed), Some(current)) if indexed == current => {
                            if data_table.remove(key.as_slice())?.is_some() {
                                removed += 1;
                            }
                            ttl_table.remove(key.as_slice())?;
                            index.remove(index_key.as_slice())?;
                        }
                        _ => {
                            // Stale index entry; the key was overwritten,
                            // deleted or never existed.
                            index.remove(index_key.as_slice())?;
                        }
                    }
                }
                removed
            };
            txn.commit()?;
            Ok(removed)
        })
        .await
        .map_err(|e| StorageError::DatabaseError {
            message: format!("Failed to remove expired keys: {}", e),
        })?
        .map_err(|e| StorageError::DatabaseError {
            message: format!("Redb error during key removal: {}", e),
        })?;

        let mut count = expired_count.write().await;
        *count += removed;

        debug!("Cleaned up {} expired keys from Redb", removed);

        Ok(removed)
    }

    /// TTL cleanup performance statistics (monitoring only).
    pub async fn ttl_cleanup_stats(&self) -> TtlCleanupStats {
        self.cleanup_stats.read().await.clone()
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
    async fn get(
        &self,
        key: &[u8],
        consistency: ReadConsistency,
    ) -> StorageResult<Option<Vec<u8>>> {
        let db = self.db.clone();
        let key = key.to_vec();

        // redb read transactions always observe the latest committed state;
        // `consistency` is accepted for trait parity with follower-capable
        // backends and does not change the result here.
        let _ = consistency;

        let result = task::spawn_blocking(move || -> Result<Option<Vec<u8>>, redb::Error> {
            let read_txn = db.begin_read()?;
            let data_table = read_txn.open_table(DATA_TABLE)?;
            let ttl_table = read_txn.open_table(TTL_TABLE)?;

            if let Some(value_guard) = data_table.get(key.as_slice())? {
                if let Some(expiry_guard) = ttl_table.get(key.as_slice())? {
                    if now_ms() >= expiry_guard.value() {
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
            message: format!("Failed to spawn get task: {}", e),
        })?
        .map_err(|e| StorageError::DatabaseError {
            message: format!("Redb get error: {}", e),
        })?;

        Ok(result.map(|data| self.decompress_if_enabled(&data)))
    }

    async fn set(&self, key: &[u8], value: &[u8], ttl: Option<Duration>) -> StorageResult<()> {
        let db = self.db.clone();
        let key = key.to_vec();
        let value = self.compress_if_enabled(value);

        task::spawn_blocking(move || -> Result<(), redb::Error> {
            let txn = begin_durable_write(&db)?;
            {
                let mut data_table = txn.open_table(DATA_TABLE)?;
                let mut ttl_table = txn.open_table(TTL_TABLE)?;
                let mut index = txn.open_table(EXPIRATION_INDEX)?;

                data_table.insert(key.as_slice(), value.as_slice())?;

                // Drop any previous expiry/index entry before writing the new
                // one. Without this an overwrite without a TTL would keep the
                // old expiry, and the index would grow stale entries.
                if let Some(previous) = ttl_table.get(key.as_slice())?.map(|g| g.value()) {
                    index.remove(expiration_index_key(previous, &key).as_slice())?;
                }

                match ttl {
                    Some(duration) => {
                        let expires_at = now_ms() + duration.as_millis() as u64;
                        ttl_table.insert(key.as_slice(), expires_at)?;
                        index.insert(
                            expiration_index_key(expires_at, &key).as_slice(),
                            key.as_slice(),
                        )?;
                    }
                    None => {
                        ttl_table.remove(key.as_slice())?;
                    }
                }
            }
            txn.commit()?;
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
            let txn = begin_durable_write(&db)?;
            let existed = {
                let mut data_table = txn.open_table(DATA_TABLE)?;
                let mut ttl_table = txn.open_table(TTL_TABLE)?;
                let mut index = txn.open_table(EXPIRATION_INDEX)?;

                let existed = data_table.get(key.as_slice())?.is_some();
                if existed {
                    if let Some(previous) = ttl_table.get(key.as_slice())?.map(|g| g.value()) {
                        index.remove(expiration_index_key(previous, &key).as_slice())?;
                    }
                    data_table.remove(key.as_slice())?;
                    ttl_table.remove(key.as_slice())?;
                }
                existed
            };
            txn.commit()?;
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

            if data_table.get(key.as_slice())?.is_some() {
                if let Some(expiry_guard) = ttl_table.get(key.as_slice())? {
                    if now_ms() >= expiry_guard.value() {
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
        let path = self.path.clone();
        let expired_count = *self.expired_count.read().await;

        let (key_count, data_size) =
            task::spawn_blocking(move || -> Result<(u64, u64), redb::Error> {
                let read_txn = db.begin_read()?;
                let table = read_txn.open_table(DATA_TABLE)?;

                let mut key_count = 0;
                let mut data_size = 0;

                for result in table.range::<&[u8]>(..)? {
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

        let disk_size = std::fs::metadata(&path).ok().map(|m| m.len());

        Ok(StorageStats {
            key_count,
            data_size,
            disk_size,
            expired_keys: expired_count,
            cache_hit_ratio: None, // Not exposed by Redb
        })
    }

    /// Get TTL cleanup performance statistics
    async fn flush(&self) -> StorageResult<()> {
        // Every commit uses Durability::Immediate, so there is nothing pending.
        Ok(())
    }

    async fn compact(&self) -> StorageResult<()> {
        // redb's compaction API requires `&mut Database`. The adapter shares the
        // database through an `Arc` for concurrent readers, so compaction is not
        // available in-process. redb reclaims freed pages for reuse
        // automatically; the operator runbook covers offline compaction.
        Ok(())
    }

    async fn scan_range(
        &self,
        start: Bound<&[u8]>,
        end: Bound<&[u8]>,
        limit: Option<usize>,
    ) -> StorageResult<Vec<(Vec<u8>, Vec<u8>)>> {
        let db = self.db.clone();
        let start = bound_to_owned(start);
        let end = bound_to_owned(end);

        let entries =
            task::spawn_blocking(move || -> Result<Vec<(Vec<u8>, Vec<u8>)>, redb::Error> {
                let read_txn = db.begin_read()?;
                let data_table = read_txn.open_table(DATA_TABLE)?;
                let ttl_table = read_txn.open_table(TTL_TABLE)?;

                let lower = owned_bound_as_ref(&start);
                let upper = owned_bound_as_ref(&end);
                let now = now_ms();

                let mut entries = Vec::new();
                for result in data_table.range::<&[u8]>((lower, upper))? {
                    let (key, value) = result?;

                    if let Some(expiry_guard) = ttl_table.get(key.value())? {
                        if now >= expiry_guard.value() {
                            continue;
                        }
                    }

                    entries.push((key.value().to_vec(), value.value().to_vec()));
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
                message: format!("Redb scan error: {}", e),
            })?;

        Ok(entries)
    }

    async fn ttl(&self, key: &[u8]) -> StorageResult<Option<Duration>> {
        let db = self.db.clone();
        let key = key.to_vec();

        let ttl = task::spawn_blocking(move || -> Result<Option<Duration>, redb::Error> {
            let read_txn = db.begin_read()?;
            let data_table = read_txn.open_table(DATA_TABLE)?;
            let ttl_table = read_txn.open_table(TTL_TABLE)?;

            if data_table.get(key.as_slice())?.is_none() {
                return Ok(None);
            }

            let Some(expiry) = ttl_table.get(key.as_slice())?.map(|g| g.value()) else {
                return Ok(None);
            };

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
            message: format!("Redb ttl error: {}", e),
        })?;

        Ok(ttl)
    }

    async fn delete_many(&self, keys: &[Vec<u8>]) -> StorageResult<u64> {
        if keys.is_empty() {
            return Ok(0);
        }

        let db = self.db.clone();
        let keys = keys.to_vec();

        let removed = task::spawn_blocking(move || -> Result<u64, redb::Error> {
            let txn = begin_durable_write(&db)?;
            let removed = {
                let mut data_table = txn.open_table(DATA_TABLE)?;
                let mut ttl_table = txn.open_table(TTL_TABLE)?;
                let mut index = txn.open_table(EXPIRATION_INDEX)?;

                let mut removed = 0u64;
                for key in &keys {
                    if let Some(previous) = ttl_table.get(key.as_slice())?.map(|g| g.value()) {
                        index.remove(expiration_index_key(previous, key).as_slice())?;
                    }
                    if data_table.remove(key.as_slice())?.is_some() {
                        removed += 1;
                    }
                    ttl_table.remove(key.as_slice())?;
                }
                removed
            };
            txn.commit()?;
            Ok(removed)
        })
        .await
        .map_err(|e| StorageError::DatabaseError {
            message: format!("Failed to spawn delete_many task: {}", e),
        })?
        .map_err(|e| StorageError::DatabaseError {
            message: format!("Redb delete_many error: {}", e),
        })?;

        Ok(removed)
    }

    fn backend_name(&self) -> &'static str {
        "redb"
    }
}

#[cfg(feature = "export-redb")]
fn bound_to_owned(bound: Bound<&[u8]>) -> Bound<Vec<u8>> {
    match bound {
        Bound::Included(value) => Bound::Included(value.to_vec()),
        Bound::Excluded(value) => Bound::Excluded(value.to_vec()),
        Bound::Unbounded => Bound::Unbounded,
    }
}

#[cfg(feature = "export-redb")]
fn owned_bound_as_ref(bound: &Bound<Vec<u8>>) -> Bound<&[u8]> {
    match bound {
        Bound::Included(value) => Bound::Included(value.as_slice()),
        Bound::Excluded(value) => Bound::Excluded(value.as_slice()),
        Bound::Unbounded => Bound::Unbounded,
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
            message: "Redb backend not enabled. Enable 'export-redb' feature.".to_string(),
        })
    }
}

#[cfg(all(test, feature = "export-redb"))]
mod tests {
    use super::*;
    use tokio::time::{sleep, Duration};

    async fn temp_adapter(interval: Duration) -> (tempfile::TempDir, RedbStorageAdapter) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("waf.redb");
        let adapter = RedbStorageAdapter::new(path, Some(1024 * 1024), interval, false)
            .await
            .unwrap();
        (dir, adapter)
    }

    #[tokio::test]
    async fn test_redb_storage_basic_operations() {
        let (_dir, adapter) = temp_adapter(Duration::from_secs(60)).await;

        adapter.set(b"key1", b"value1", None).await.unwrap();
        let result = adapter.get(b"key1", ReadConsistency::Strong).await.unwrap();
        assert_eq!(result, Some(b"value1".to_vec()));

        assert!(adapter.exists(b"key1").await.unwrap());
        assert!(!adapter.exists(b"key2").await.unwrap());

        assert!(adapter.delete(b"key1").await.unwrap());
        assert!(!adapter.delete(b"key1").await.unwrap());
    }

    #[tokio::test]
    async fn test_redb_storage_ttl() {
        let (_dir, adapter) = temp_adapter(Duration::from_secs(3600)).await;

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
    async fn test_redb_overwrite_clears_ttl() {
        let (_dir, adapter) = temp_adapter(Duration::from_secs(60)).await;

        adapter
            .set(b"k", b"v1", Some(Duration::from_millis(5)))
            .await
            .unwrap();
        // Overwriting without a TTL must clear the old expiry.
        adapter.set(b"k", b"v2", None).await.unwrap();

        sleep(Duration::from_millis(20)).await;

        assert_eq!(
            adapter.get(b"k", ReadConsistency::Strong).await.unwrap(),
            Some(b"v2".to_vec())
        );
        assert_eq!(adapter.ttl(b"k").await.unwrap(), None);
    }
}
