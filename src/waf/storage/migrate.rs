//! Event-store migration between storage adapters.
//!
//! The primary use is the one-way cut-over from the legacy sled store to the
//! default redb store:
//!
//! ```text
//! waf-storage-migrate --from ./data/waf_security_events.sled --to ./data/waf.redb
//! ```
//!
//! The copy is:
//!
//! * **idempotent** — progress is checkpointed to a sidecar JSON file after
//!   every batch, so a killed migration resumes from the last committed key;
//! * **verified** — a second full pass compares key counts and a SHA-256 digest
//!   over `(key, value, ttl-presence)` in key order (or a sampled full compare
//!   with `--sample N`);
//! * **safe** — a non-empty destination is refused unless `--force` is given.
//!
//! `--reverse` performs the redb -> sled downgrade. See
//! `docs/operations/migrating-event-store.md`.

use super::{StorageAdapter, StorageError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::ops::Bound;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use thiserror::Error;

const BATCH_LIMIT: usize = 1024;
const STATE_VERSION: u32 = 1;

/// Migration failure.
#[derive(Debug, Error)]
pub enum MigrationError {
    #[error("destination is not empty ({keys} keys); re-run with --force to overwrite it")]
    DestinationNotEmpty { keys: u64 },

    #[error("source and destination are the same store")]
    SameStore,

    #[error("migration state does not match this migration: {0}")]
    StateMismatch(String),

    #[error("failed to read or write migration state: {0}")]
    State(String),

    #[error("verification failed: {0}")]
    Verification(String),

    #[error(transparent)]
    Storage(#[from] StorageError),
}

/// Migration tuning.
#[derive(Debug, Clone)]
pub struct MigrationOptions {
    /// Keys copied per checkpoint (also the scan batch size).
    pub batch_size: usize,
    /// Overwrite (and clear) a non-empty destination.
    pub force: bool,
    /// Verify only the first N entries instead of a full digest.
    pub sample: Option<usize>,
    /// Sidecar checkpoint path. Defaults to `<destination>.migrate-state.json`
    /// in [`migrate`]'s callers.
    pub state_path: Option<PathBuf>,
    /// Suppress per-batch progress lines.
    pub quiet: bool,
    /// Stable identifier for the source store (path + backend).
    pub source_id: String,
    /// Stable identifier for the destination store (path + backend).
    pub destination_id: String,
}

impl Default for MigrationOptions {
    fn default() -> Self {
        Self {
            batch_size: 1000,
            force: false,
            sample: None,
            state_path: None,
            quiet: false,
            source_id: String::new(),
            destination_id: String::new(),
        }
    }
}

/// Progress emitted after every checkpoint.
#[derive(Debug, Clone)]
pub struct MigrationProgress {
    /// Entries copied so far (including a resumed prefix).
    pub copied: u64,
    /// Wall-clock time since the run started.
    pub elapsed: Duration,
    /// Last key durably copied, if any.
    pub last_key: Option<Vec<u8>>,
}

/// Result of a completed, verified migration.
#[derive(Debug, Clone)]
pub struct MigrationSummary {
    /// Entries copied by this run.
    pub copied: u64,
    /// Source entries that had expired and were intentionally skipped.
    pub skipped_expired: u64,
    /// Source key count at verification time.
    pub source_keys: u64,
    /// Destination key count at verification time.
    pub destination_keys: u64,
    /// Source digest (hex SHA-256 over key/value/ttl-presence).
    pub source_digest: String,
    /// Destination digest.
    pub destination_digest: String,
    /// Resume point the run started from, if any.
    pub resumed_from: Option<Vec<u8>>,
    /// Whether verification passed.
    pub verified: bool,
    /// Total run time.
    pub elapsed: Duration,
}

#[derive(Debug, Serialize, Deserialize)]
struct ResumeState {
    version: u32,
    source_id: String,
    destination_id: String,
    last_key_hex: String,
    copied: u64,
}

impl ResumeState {
    fn last_key(&self) -> Vec<u8> {
        hex::decode(&self.last_key_hex).unwrap_or_default()
    }
}

/// Copy every live entry from `source` to `destination` and verify the result.
///
/// Both stores must be quiesced for the duration of the run (or at least not
/// written to) so the verification pass sees the same key space.
pub async fn migrate(
    source: &dyn StorageAdapter,
    destination: &dyn StorageAdapter,
    options: &MigrationOptions,
) -> Result<MigrationSummary, MigrationError> {
    if !options.source_id.is_empty()
        && !options.destination_id.is_empty()
        && options.source_id == options.destination_id
    {
        return Err(MigrationError::SameStore);
    }

    let started = Instant::now();
    let state_path = options.state_path.clone();
    let mut resumed_from = None;
    let mut copied = 0u64;

    // 1. Resume or refuse.
    let mut resume = load_state(state_path.as_deref(), options)?;
    if options.force {
        clear_destination(destination).await?;
        remove_state(state_path.as_deref());
        resume = None;
    }

    let destination_keys = destination.stats().await?.key_count;
    // A stale checkpoint against an empty destination is equivalent to a fresh
    // run; never trust it.
    let resume = if destination_keys == 0 { None } else { resume };

    if destination_keys > 0 {
        match &resume {
            Some(state) => {
                resumed_from = Some(state.last_key());
                copied = state.copied;
            }
            None => {
                return Err(MigrationError::DestinationNotEmpty {
                    keys: destination_keys,
                })
            }
        }
    }

    // 2. Copy in key order.
    let mut last_key = resumed_from.clone();
    let mut skipped_expired = 0u64;

    loop {
        let start = match &last_key {
            Some(key) => Bound::Excluded(key.as_slice()),
            None => Bound::Unbounded,
        };

        let batch = source
            .scan_range(start, Bound::Unbounded, Some(options.batch_size.max(1)))
            .await?;

        if batch.is_empty() {
            break;
        }

        for (key, value) in &batch {
            // Re-check liveness: an entry can expire between the scan and the
            // write. Migrating it would resurrect expired evidence.
            if source
                .get(key, super::ReadConsistency::Strong)
                .await?
                .is_none()
            {
                skipped_expired += 1;
                continue;
            }
            let ttl = source.ttl(key).await?;
            destination.set(key, value, ttl).await?;
            copied += 1;
        }

        last_key = batch.last().map(|(key, _)| key.clone());

        if let Some(path) = state_path.as_deref() {
            write_state(
                path,
                &ResumeState {
                    version: STATE_VERSION,
                    source_id: options.source_id.clone(),
                    destination_id: options.destination_id.clone(),
                    last_key_hex: hex::encode(last_key.clone().unwrap_or_default()),
                    copied,
                },
            )?;
        }

        if !options.quiet {
            let elapsed = started.elapsed();
            let rate = copied as f64 / elapsed.as_secs_f64().max(0.001);
            eprintln!(
                "migrate: copied={} elapsed={:.1}s rate={:.0}/s",
                copied,
                elapsed.as_secs_f64(),
                rate
            );
        }

        if batch.len() < options.batch_size.max(1) {
            break;
        }
    }

    // 3. Verify.
    let sample = options.sample.unwrap_or(0) as u64;
    let (source_keys, source_digest, source_first) = scan_digest(source, sample).await?;
    let (destination_keys, destination_digest, destination_first) =
        scan_digest(destination, sample).await?;

    if source_keys != destination_keys {
        return Err(MigrationError::Verification(format!(
            "key count mismatch: source={} destination={}",
            source_keys, destination_keys
        )));
    }

    let verified = if sample > 0 && sample < source_keys {
        if source_first != destination_first {
            return Err(MigrationError::Verification(format!(
                "sampled compare failed for the first {} entries",
                sample
            )));
        }
        true
    } else {
        if source_digest != destination_digest {
            return Err(MigrationError::Verification(format!(
                "digest mismatch: source={} destination={}",
                source_digest, destination_digest
            )));
        }
        true
    };

    // 4. A completed migration leaves no resume point behind. A later run then
    //    refuses the now non-empty destination unless --force is passed.
    remove_state(state_path.as_deref());

    Ok(MigrationSummary {
        copied,
        skipped_expired,
        source_keys,
        destination_keys,
        source_digest,
        destination_digest,
        resumed_from,
        verified,
        elapsed: started.elapsed(),
    })
}

async fn clear_destination(destination: &dyn StorageAdapter) -> Result<(), MigrationError> {
    let mut last_key: Option<Vec<u8>> = None;
    loop {
        let start = match &last_key {
            Some(key) => Bound::Excluded(key.as_slice()),
            None => Bound::Unbounded,
        };
        let batch = destination
            .scan_range(start, Bound::Unbounded, Some(BATCH_LIMIT))
            .await?;
        if batch.is_empty() {
            break;
        }
        let keys: Vec<Vec<u8>> = batch.iter().map(|(key, _)| key.clone()).collect();
        destination.delete_many(&keys).await?;
        last_key = batch.last().map(|(key, _)| key.clone());
    }
    Ok(())
}

async fn scan_digest(
    adapter: &dyn StorageAdapter,
    sample: u64,
) -> Result<(u64, String, Vec<(Vec<u8>, Vec<u8>)>), MigrationError> {
    let mut hasher = Sha256::new();
    let mut last_key: Option<Vec<u8>> = None;
    let mut count = 0u64;
    let mut first = Vec::new();

    loop {
        let start = match &last_key {
            Some(key) => Bound::Excluded(key.as_slice()),
            None => Bound::Unbounded,
        };
        let batch = adapter
            .scan_range(start, Bound::Unbounded, Some(BATCH_LIMIT))
            .await?;
        if batch.is_empty() {
            break;
        }

        for (key, value) in &batch {
            hasher.update((key.len() as u64).to_be_bytes());
            hasher.update(key);
            hasher.update((value.len() as u64).to_be_bytes());
            hasher.update(value);
            // Presence (not the absolute deadline) is what must survive.
            hasher.update([adapter.ttl(key).await?.is_some() as u8]);

            if (first.len() as u64) < sample {
                first.push((key.clone(), value.clone()));
            }
            count += 1;
        }

        last_key = batch.last().map(|(key, _)| key.clone());
    }

    Ok((count, hex::encode(hasher.finalize()), first))
}

fn load_state(
    path: Option<&Path>,
    options: &MigrationOptions,
) -> Result<Option<ResumeState>, MigrationError> {
    let Some(path) = path else {
        return Ok(None);
    };
    if !path.exists() {
        return Ok(None);
    }

    let bytes = std::fs::read(path).map_err(|e| MigrationError::State(e.to_string()))?;
    let state: ResumeState =
        serde_json::from_slice(&bytes).map_err(|e| MigrationError::State(e.to_string()))?;

    if state.version != STATE_VERSION {
        return Err(MigrationError::StateMismatch(format!(
            "state version {} (expected {})",
            state.version, STATE_VERSION
        )));
    }
    if state.source_id != options.source_id || state.destination_id != options.destination_id {
        return Err(MigrationError::StateMismatch(format!(
            "state is for {} -> {}, not {} -> {}",
            state.source_id, state.destination_id, options.source_id, options.destination_id
        )));
    }

    Ok(Some(state))
}

fn write_state(path: &Path, state: &ResumeState) -> Result<(), MigrationError> {
    let bytes = serde_json::to_vec(state).map_err(|e| MigrationError::State(e.to_string()))?;
    let tmp = path.with_extension("tmp");

    {
        let mut file = std::fs::File::create(&tmp)
            .map_err(|e| MigrationError::State(format!("{}: {}", tmp.display(), e)))?;
        file.write_all(&bytes)
            .map_err(|e| MigrationError::State(e.to_string()))?;
        // The checkpoint must survive a crash of the migration process.
        file.sync_all()
            .map_err(|e| MigrationError::State(e.to_string()))?;
    }

    std::fs::rename(&tmp, path).map_err(|e| MigrationError::State(e.to_string()))
}

fn remove_state(path: Option<&Path>) {
    if let Some(path) = path {
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(path.with_extension("tmp"));
    }
}

/// Legacy sled exporter tree names present in a store.
///
/// The pre-redb `SledExporter` used one tree (default `security_events`) with
/// `timestamp_ms ++ uuid` keys. The storage adapter uses `data`/`ttl`/`meta`.
/// Returns every user tree that is not an adapter tree, so the migration tool
/// can pick the event tree without operator input.
#[cfg(feature = "export-sled")]
pub fn legacy_event_trees(path: &Path) -> Result<Vec<String>, MigrationError> {
    let db = sled::open(path).map_err(|e| MigrationError::State(e.to_string()))?;
    let mut trees: Vec<String> = db
        .tree_names()
        .into_iter()
        .map(|name| String::from_utf8_lossy(&name).to_string())
        .filter(|name| !matches!(name.as_str(), "data" | "ttl" | "meta" | "__sled__default"))
        .collect();
    trees.sort();
    Ok(trees)
}

/// Adapter view over a legacy [`SledExporter`] tree.
///
/// Reads and writes the raw exporter layout so a pre-redb sled store can be
/// migrated (and a downgrade written back) without changing the legacy schema.
#[cfg(feature = "export-sled")]
pub struct LegacySledTreeAdapter {
    db: sled::Db,
    tree: sled::Tree,
}

#[cfg(feature = "export-sled")]
impl LegacySledTreeAdapter {
    /// Open (or create) `tree_name` in the sled database at `path`.
    pub fn new(path: &Path, tree_name: &str) -> Result<Self, MigrationError> {
        let db = sled::open(path).map_err(|e| MigrationError::State(e.to_string()))?;
        let tree = db
            .open_tree(tree_name)
            .map_err(|e| MigrationError::State(e.to_string()))?;
        Ok(Self { db, tree })
    }
}

#[cfg(feature = "export-sled")]
#[async_trait::async_trait]
impl StorageAdapter for LegacySledTreeAdapter {
    async fn get(
        &self,
        key: &[u8],
        _consistency: super::ReadConsistency,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(self
            .tree
            .get(key)
            .map_err(|e| StorageError::DatabaseError {
                message: e.to_string(),
            })?
            .map(|value| value.to_vec()))
    }

    async fn set(
        &self,
        key: &[u8],
        value: &[u8],
        _ttl: Option<Duration>,
    ) -> Result<(), StorageError> {
        self.tree
            .insert(key, value)
            .map_err(|e| StorageError::DatabaseError {
                message: e.to_string(),
            })?;
        self.tree.flush().map_err(|e| StorageError::DatabaseError {
            message: e.to_string(),
        })?;
        Ok(())
    }

    async fn delete(&self, key: &[u8]) -> Result<bool, StorageError> {
        let existed = self
            .tree
            .remove(key)
            .map_err(|e| StorageError::DatabaseError {
                message: e.to_string(),
            })?
            .is_some();
        self.tree.flush().map_err(|e| StorageError::DatabaseError {
            message: e.to_string(),
        })?;
        Ok(existed)
    }

    async fn exists(&self, key: &[u8]) -> Result<bool, StorageError> {
        Ok(self
            .tree
            .contains_key(key)
            .map_err(|e| StorageError::DatabaseError {
                message: e.to_string(),
            })?)
    }

    async fn expire_keys(&self) -> Result<u64, StorageError> {
        Ok(0)
    }

    async fn stats(&self) -> Result<super::StorageStats, StorageError> {
        let mut key_count = 0u64;
        let mut data_size = 0u64;
        for entry in self.tree.iter() {
            let (key, value) = entry.map_err(|e| StorageError::DatabaseError {
                message: e.to_string(),
            })?;
            key_count += 1;
            data_size += (key.len() + value.len()) as u64;
        }
        Ok(super::StorageStats {
            key_count,
            data_size,
            disk_size: self.db.size_on_disk().ok(),
            expired_keys: 0,
            cache_hit_ratio: None,
        })
    }

    async fn flush(&self) -> Result<(), StorageError> {
        self.tree.flush().map_err(|e| StorageError::DatabaseError {
            message: e.to_string(),
        })?;
        Ok(())
    }

    async fn compact(&self) -> Result<(), StorageError> {
        self.flush().await
    }

    async fn scan_range(
        &self,
        start: Bound<&[u8]>,
        end: Bound<&[u8]>,
        limit: Option<usize>,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError> {
        let start = owned_bound(start);
        let end = owned_bound(end);

        let mut entries = Vec::new();
        for entry in self.tree.range((start, end)) {
            let (key, value) = entry.map_err(|e| StorageError::DatabaseError {
                message: e.to_string(),
            })?;
            entries.push((key.to_vec(), value.to_vec()));
            if let Some(limit) = limit {
                if entries.len() >= limit {
                    break;
                }
            }
        }
        Ok(entries)
    }

    async fn ttl(&self, _key: &[u8]) -> Result<Option<Duration>, StorageError> {
        // The legacy exporter had no TTL support.
        Ok(None)
    }

    async fn delete_many(&self, keys: &[Vec<u8>]) -> Result<u64, StorageError> {
        let mut removed = 0u64;
        for key in keys {
            if self
                .tree
                .remove(key)
                .map_err(|e| StorageError::DatabaseError {
                    message: e.to_string(),
                })?
                .is_some()
            {
                removed += 1;
            }
        }
        self.tree.flush().map_err(|e| StorageError::DatabaseError {
            message: e.to_string(),
        })?;
        Ok(removed)
    }

    fn backend_name(&self) -> &'static str {
        "sled-legacy-tree"
    }
}

fn owned_bound(bound: Bound<&[u8]>) -> Bound<Vec<u8>> {
    match bound {
        Bound::Included(value) => Bound::Included(value.to_vec()),
        Bound::Excluded(value) => Bound::Excluded(value.to_vec()),
        Bound::Unbounded => Bound::Unbounded,
    }
}

#[cfg(all(test, feature = "export-sled", feature = "export-redb"))]
mod tests {
    use super::*;
    use crate::waf::storage::{RedbStorageAdapter, SledStorageAdapter};

    fn options(from: &Path, to: &Path, state: &Path) -> MigrationOptions {
        MigrationOptions {
            batch_size: 7,
            quiet: true,
            state_path: Some(state.to_path_buf()),
            source_id: format!("sled:{}", from.display()),
            destination_id: format!("redb:{}", to.display()),
            ..Default::default()
        }
    }

    async fn sled_store(path: &Path, events: usize) -> SledStorageAdapter {
        let adapter = SledStorageAdapter::new(path, false, Duration::from_secs(3600), false)
            .await
            .unwrap();
        for i in 0..events {
            let key = format!("event:{i:06}");
            let value = format!("{{\"id\":{i},\"detail\":\"security event {i}\"}}");
            let ttl = if i % 5 == 0 {
                Some(Duration::from_secs(3600))
            } else {
                None
            };
            adapter
                .set(key.as_bytes(), value.as_bytes(), ttl)
                .await
                .unwrap();
        }
        adapter
    }

    #[tokio::test]
    async fn migrates_every_event_and_reads_it_back_identically() {
        let dir = tempfile::tempdir().unwrap();
        let sled_path = dir.path().join("events.sled");
        let redb_path = dir.path().join("events.redb");
        let state_path = dir.path().join("migration.state.json");

        let source = sled_store(&sled_path, 50).await;
        let destination = RedbStorageAdapter::new(
            &redb_path,
            Some(1024 * 1024),
            Duration::from_secs(3600),
            false,
        )
        .await
        .unwrap();

        let summary = migrate(
            &source,
            &destination,
            &options(&sled_path, &redb_path, &state_path),
        )
        .await
        .unwrap();

        assert!(summary.verified);
        assert_eq!(summary.copied, 50);
        assert_eq!(summary.source_keys, 50);
        assert_eq!(summary.destination_keys, 50);
        assert_eq!(summary.source_digest, summary.destination_digest);
        assert!(!state_path.exists(), "completed run removes its checkpoint");

        for i in 0..50u64 {
            let key = format!("event:{i:06}");
            let expected = format!("{{\"id\":{i},\"detail\":\"security event {i}\"}}");
            let got = destination
                .get(key.as_bytes(), crate::waf::storage::ReadConsistency::Strong)
                .await
                .unwrap();
            assert_eq!(got, Some(expected.into_bytes()), "key {key}");
        }

        // TTLs are preserved as remaining time, not reset.
        let ttl = destination.ttl(b"event:000000").await.unwrap();
        assert!(ttl.is_some(), "TTL entry must survive the migration");
        assert!(ttl.unwrap() <= Duration::from_secs(3600));
        assert_eq!(destination.ttl(b"event:000001").await.unwrap(), None);
    }

    #[tokio::test]
    async fn refuses_a_non_empty_destination_without_force() {
        let dir = tempfile::tempdir().unwrap();
        let sled_path = dir.path().join("events.sled");
        let redb_path = dir.path().join("events.redb");
        let state_path = dir.path().join("migration.state.json");

        let source = sled_store(&sled_path, 5).await;
        let destination = RedbStorageAdapter::new(
            &redb_path,
            Some(1024 * 1024),
            Duration::from_secs(3600),
            false,
        )
        .await
        .unwrap();
        destination.set(b"existing", b"value", None).await.unwrap();

        let err = migrate(
            &source,
            &destination,
            &options(&sled_path, &redb_path, &state_path),
        )
        .await
        .unwrap_err();
        assert!(matches!(
            err,
            MigrationError::DestinationNotEmpty { keys: 1 }
        ));

        let forced = MigrationOptions {
            force: true,
            ..options(&sled_path, &redb_path, &state_path)
        };
        let summary = migrate(&source, &destination, &forced).await.unwrap();
        assert!(summary.verified);
        assert_eq!(
            destination
                .get(b"existing", crate::waf::storage::ReadConsistency::Strong)
                .await
                .unwrap(),
            None
        );
        assert_eq!(destination.stats().await.unwrap().key_count, 5);
    }

    #[tokio::test]
    async fn resumes_from_a_checkpoint_without_recopying() {
        let dir = tempfile::tempdir().unwrap();
        let sled_path = dir.path().join("events.sled");
        let redb_path = dir.path().join("events.redb");
        let state_path = dir.path().join("migration.state.json");

        let source = sled_store(&sled_path, 40).await;
        let destination = RedbStorageAdapter::new(
            &redb_path,
            Some(1024 * 1024),
            Duration::from_secs(3600),
            false,
        )
        .await
        .unwrap();

        // Simulate a process killed after 20 keys: the destination holds the
        // prefix and the checkpoint records the last key.
        for i in 0..20u64 {
            let key = format!("event:{i:06}");
            let value = format!("{{\"id\":{i},\"detail\":\"security event {i}\"}}");
            let ttl = if i % 5 == 0 {
                Some(Duration::from_secs(3600))
            } else {
                None
            };
            destination
                .set(key.as_bytes(), value.as_bytes(), ttl)
                .await
                .unwrap();
        }
        write_state(
            &state_path,
            &ResumeState {
                version: STATE_VERSION,
                source_id: format!("sled:{}", sled_path.display()),
                destination_id: format!("redb:{}", redb_path.display()),
                last_key_hex: hex::encode(b"event:000019"),
                copied: 20,
            },
        )
        .unwrap();

        let summary = migrate(
            &source,
            &destination,
            &options(&sled_path, &redb_path, &state_path),
        )
        .await
        .unwrap();

        assert!(summary.verified);
        assert_eq!(
            summary.resumed_from.as_deref(),
            Some(b"event:000019".as_slice())
        );
        assert_eq!(summary.copied, 40);
        assert_eq!(summary.destination_keys, 40);
    }

    #[tokio::test]
    async fn migrates_a_legacy_sled_exporter_tree() {
        let dir = tempfile::tempdir().unwrap();
        let sled_path = dir.path().join("events.sled");
        let redb_path = dir.path().join("events.redb");
        let state_path = dir.path().join("legacy.state.json");

        // Exactly what the pre-redb `SledExporter` writes: one tree with
        // `timestamp_ms_be ++ uuid` keys and JSON values.
        {
            let db = sled::open(&sled_path).unwrap();
            let tree = db.open_tree("security_events").unwrap();
            for i in 0..12u64 {
                let mut key = (1_700_000_000_000u64 + i).to_be_bytes().to_vec();
                key.extend_from_slice(uuid::Uuid::from_u128(i as u128).as_bytes());
                tree.insert(key, format!("{{\"event\":{i}}}").into_bytes())
                    .unwrap();
            }
            tree.flush().unwrap();
        }

        let source = LegacySledTreeAdapter::new(&sled_path, "security_events").unwrap();
        let destination = RedbStorageAdapter::new(
            &redb_path,
            Some(1024 * 1024),
            Duration::from_secs(3600),
            false,
        )
        .await
        .unwrap();

        let summary = migrate(
            &source,
            &destination,
            &MigrationOptions {
                source_id: "legacy".to_string(),
                destination_id: "redb".to_string(),
                ..options(&sled_path, &redb_path, &state_path)
            },
        )
        .await
        .unwrap();

        assert!(summary.verified);
        assert_eq!(summary.copied, 12);
        // Every event is readable through the redb exporter layout.
        let exporter_store = destination
            .scan_range(Bound::Unbounded, Bound::Unbounded, None)
            .await
            .unwrap();
        assert_eq!(exporter_store.len(), 12);
        assert_eq!(
            exporter_store[0].1, b"{\"event\":0}",
            "values are copied byte-for-byte"
        );
    }

    #[tokio::test]
    async fn reverse_migration_restores_a_sled_store() {
        let dir = tempfile::tempdir().unwrap();
        let redb_path = dir.path().join("events.redb");
        let sled_path = dir.path().join("reverse.sled");
        let state_path = dir.path().join("reverse.state.json");

        let source = RedbStorageAdapter::new(
            &redb_path,
            Some(1024 * 1024),
            Duration::from_secs(3600),
            false,
        )
        .await
        .unwrap();
        for i in 0..10u64 {
            source
                .set(
                    format!("event:{i:04}").as_bytes(),
                    format!("payload-{i}").as_bytes(),
                    None,
                )
                .await
                .unwrap();
        }

        let destination =
            SledStorageAdapter::new(&sled_path, false, Duration::from_secs(3600), false)
                .await
                .unwrap();

        let reversed = MigrationOptions {
            source_id: format!("redb:{}", redb_path.display()),
            destination_id: format!("sled:{}", sled_path.display()),
            ..options(&sled_path, &redb_path, &state_path)
        };
        let summary = migrate(&source, &destination, &reversed).await.unwrap();
        assert!(summary.verified);
        assert_eq!(summary.destination_keys, 10);
        assert_eq!(
            destination
                .get(b"event:0007", crate::waf::storage::ReadConsistency::Strong)
                .await
                .unwrap(),
            Some(b"payload-7".to_vec())
        );
    }
}
