//! Backend parity suite.
//!
//! Every scenario runs against **every** adapter through the `StorageAdapter`
//! trait. Any divergence is a backend bug, not a test-specific quirk.
//!
//! Run just this suite with:
//! `cargo test --lib waf::storage::parity_tests -- --nocapture`

use super::*;
use std::ops::Bound;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::time::sleep;

const CLEANUP_INTERVAL: Duration = Duration::from_secs(3600);

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum TestBackend {
    Redb,
    Sled,
    Memory,
}

impl TestBackend {
    fn name(self) -> &'static str {
        match self {
            TestBackend::Redb => "redb",
            TestBackend::Sled => "sled",
            TestBackend::Memory => "memory",
        }
    }

    fn supports_restart(self) -> bool {
        !matches!(self, TestBackend::Memory)
    }

    fn file_name(self) -> &'static str {
        match self {
            TestBackend::Redb => "store.redb",
            TestBackend::Sled => "store.sled",
            TestBackend::Memory => "store.memory",
        }
    }

    fn path(self, dir: &TempDir) -> PathBuf {
        dir.path().join(self.file_name())
    }
}

async fn open(backend: TestBackend, dir: &TempDir) -> StorageResult<Arc<dyn StorageAdapter>> {
    match backend {
        TestBackend::Redb => {
            #[cfg(feature = "export-redb")]
            {
                let adapter = RedbStorageAdapter::new(
                    backend.path(dir),
                    Some(1024 * 1024),
                    CLEANUP_INTERVAL,
                    false,
                )
                .await?;
                Ok(Arc::new(adapter))
            }
            #[cfg(not(feature = "export-redb"))]
            {
                unreachable!("redb parity backend selected without export-redb")
            }
        }
        TestBackend::Sled => {
            #[cfg(feature = "export-sled")]
            {
                let adapter =
                    SledStorageAdapter::new(backend.path(dir), false, CLEANUP_INTERVAL, false)
                        .await?;
                Ok(Arc::new(adapter))
            }
            #[cfg(not(feature = "export-sled"))]
            {
                unreachable!("sled parity backend selected without export-sled")
            }
        }
        TestBackend::Memory => Ok(Arc::new(
            MemoryStorageAdapter::new(None, CLEANUP_INTERVAL).await?,
        )),
    }
}

/// Run one scenario against every compiled-in backend.
async fn run_all<F, Fut>(scenario: F)
where
    F: Fn(TestBackend) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    #[cfg(feature = "export-redb")]
    scenario(TestBackend::Redb).await;
    #[cfg(feature = "export-sled")]
    scenario(TestBackend::Sled).await;
    scenario(TestBackend::Memory).await;
}

#[tokio::test]
async fn parity_insert_get_delete() {
    run_all(check_insert_get_delete).await;
}

async fn check_insert_get_delete(backend: TestBackend) {
    let dir = TempDir::new().unwrap();
    let store = open(backend, &dir).await.unwrap();
    let context = backend.name();

    assert_eq!(store.backend_name(), context);
    assert_eq!(
        store
            .get(b"missing", ReadConsistency::Strong)
            .await
            .unwrap(),
        None
    );

    store.set(b"k1", b"v1", None).await.unwrap();
    store.set(b"k2", b"", None).await.unwrap();
    store.set(&[0u8, 1, 255], b"binary", None).await.unwrap();

    for consistency in [ReadConsistency::Strong, ReadConsistency::Eventual] {
        assert_eq!(
            store.get(b"k1", consistency).await.unwrap(),
            Some(b"v1".to_vec()),
            "{context}: get k1"
        );
        assert_eq!(
            store.get(b"k2", consistency).await.unwrap(),
            Some(Vec::new()),
            "{context}: empty value round-trip"
        );
    }

    store.set(b"k1", b"v1-updated", None).await.unwrap();
    assert_eq!(
        store.get(b"k1", ReadConsistency::Strong).await.unwrap(),
        Some(b"v1-updated".to_vec()),
        "{context}: overwrite"
    );

    assert!(store.exists(b"k1").await.unwrap(), "{context}: exists");
    assert!(
        !store.exists(b"nope").await.unwrap(),
        "{context}: not exists"
    );
    assert_eq!(
        store
            .get(&[0u8, 1, 255], ReadConsistency::Strong)
            .await
            .unwrap(),
        Some(b"binary".to_vec())
    );

    assert!(
        store.delete(b"k1").await.unwrap(),
        "{context}: delete existing"
    );
    assert!(
        !store.delete(b"k1").await.unwrap(),
        "{context}: delete twice"
    );
    assert_eq!(
        store.get(b"k1", ReadConsistency::Strong).await.unwrap(),
        None
    );
    assert!(!store.exists(b"k1").await.unwrap());
}

#[tokio::test]
async fn parity_key_ordering_and_scans() {
    run_all(check_key_ordering_and_scans).await;
}

async fn check_key_ordering_and_scans(backend: TestBackend) {
    let dir = TempDir::new().unwrap();
    let store = open(backend, &dir).await.unwrap();
    let context = backend.name();

    for key in [b"c/1".as_slice(), b"a", b"b/2", b"ab", b"c", b"b/1"] {
        store.set(key, b"1", None).await.unwrap();
    }

    let all = store
        .scan_range(Bound::Unbounded, Bound::Unbounded, None)
        .await
        .unwrap();
    let keys: Vec<Vec<u8>> = all.iter().map(|(key, _)| key.clone()).collect();
    assert_eq!(
        keys,
        vec![
            b"a".to_vec(),
            b"ab".to_vec(),
            b"b/1".to_vec(),
            b"b/2".to_vec(),
            b"c".to_vec(),
            b"c/1".to_vec(),
        ],
        "{context}: ascending lexicographic order"
    );

    let prefix = store.scan_prefix(b"b/", None).await.unwrap();
    assert_eq!(
        prefix
            .iter()
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>(),
        vec![b"b/1".to_vec(), b"b/2".to_vec()],
        "{context}: prefix scan"
    );

    let empty_prefix = store.scan_prefix(b"zzz", None).await.unwrap();
    assert!(empty_prefix.is_empty(), "{context}: empty prefix");

    let range = store
        .scan_range(
            Bound::Included(b"b".as_slice()),
            Bound::Excluded(b"c".as_slice()),
            None,
        )
        .await
        .unwrap();
    assert_eq!(
        range.iter().map(|(key, _)| key.clone()).collect::<Vec<_>>(),
        vec![b"b/1".to_vec(), b"b/2".to_vec()],
        "{context}: half-open range"
    );

    let exclusive = store
        .scan_range(Bound::Excluded(b"a".as_slice()), Bound::Unbounded, Some(2))
        .await
        .unwrap();
    assert_eq!(
        exclusive
            .iter()
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>(),
        vec![b"ab".to_vec(), b"b/1".to_vec()],
        "{context}: exclusive start + limit"
    );

    // The prefix helper must handle a trailing 0xff correctly.
    assert_eq!(prefix_upper_bound(&[0x01, 0x02]), Some(vec![0x01, 0x03]));
    assert_eq!(prefix_upper_bound(&[0x01, 0xff]), Some(vec![0x02]));
    assert_eq!(prefix_upper_bound(&[0xff, 0xff]), None);
    store.set(&[0xff, 0xff, 0x01], b"tail", None).await.unwrap();
    assert_eq!(
        store.scan_prefix(&[0xff], None).await.unwrap().len(),
        1,
        "{context}: 0xff prefix"
    );
}

#[tokio::test]
async fn parity_ttl_expiry_and_cleanup() {
    run_all(check_ttl_expiry_and_cleanup).await;
}

async fn check_ttl_expiry_and_cleanup(backend: TestBackend) {
    let dir = TempDir::new().unwrap();
    let store = open(backend, &dir).await.unwrap();
    let context = backend.name();

    store
        .set(b"short", b"1", Some(Duration::from_millis(300)))
        .await
        .unwrap();
    store
        .set(b"long", b"2", Some(Duration::from_secs(3600)))
        .await
        .unwrap();
    store.set(b"forever", b"3", None).await.unwrap();

    // TTL visibility is consistent for both consistency levels.
    assert_eq!(store.ttl(b"forever").await.unwrap(), None);
    assert!(store.ttl(b"long").await.unwrap().unwrap() <= Duration::from_secs(3600));
    if let Some(remaining) = store.ttl(b"short").await.unwrap() {
        assert!(
            remaining <= Duration::from_millis(500),
            "{context}: ttl remaining"
        );
    }

    // Overwriting without a TTL clears the old deadline.
    store.set(b"short", b"1b", None).await.unwrap();
    assert_eq!(store.ttl(b"short").await.unwrap(), None);
    store
        .set(b"short", b"1c", Some(Duration::from_millis(500)))
        .await
        .unwrap();

    sleep(Duration::from_millis(700)).await;

    assert_eq!(
        store.get(b"short", ReadConsistency::Strong).await.unwrap(),
        None,
        "{context}: expired get"
    );
    assert!(
        !store.exists(b"short").await.unwrap(),
        "{context}: expired exists"
    );
    assert_eq!(
        store.ttl(b"short").await.unwrap(),
        None,
        "{context}: expired ttl"
    );

    let scanned = store
        .scan_range(Bound::Unbounded, Bound::Unbounded, None)
        .await
        .unwrap();
    assert_eq!(
        scanned
            .iter()
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>(),
        vec![b"forever".to_vec(), b"long".to_vec()],
        "{context}: scans skip expired entries"
    );

    // Expired entries remain physical until cleanup collects them.
    assert_eq!(
        store.stats().await.unwrap().key_count,
        3,
        "{context}: physical count before cleanup"
    );
    assert_eq!(
        store.expire_keys().await.unwrap(),
        1,
        "{context}: cleanup count"
    );
    assert_eq!(
        store.stats().await.unwrap().key_count,
        2,
        "{context}: physical count after cleanup"
    );
    assert_eq!(
        store.get(b"long", ReadConsistency::Strong).await.unwrap(),
        Some(b"2".to_vec()),
        "{context}: unexpired key survives cleanup"
    );

    // A deleted key must not leave a TTL behind that expires a later write.
    store.delete(b"long").await.unwrap();
    store.set(b"long", b"again", None).await.unwrap();
    sleep(Duration::from_millis(5)).await;
    assert_eq!(
        store.get(b"long", ReadConsistency::Strong).await.unwrap(),
        Some(b"again".to_vec())
    );
}

#[tokio::test]
async fn parity_bulk_deletion() {
    run_all(check_bulk_deletion).await;
}

async fn check_bulk_deletion(backend: TestBackend) {
    let dir = TempDir::new().unwrap();
    let store = open(backend, &dir).await.unwrap();
    let context = backend.name();

    let keys: Vec<Vec<u8>> = (0..10)
        .map(|i| format!("event:{i:04}").into_bytes())
        .collect();
    for key in &keys {
        store.set(key, b"payload", None).await.unwrap();
    }

    let mut to_delete: Vec<Vec<u8>> = keys[0..4].to_vec();
    to_delete.push(b"absent-a".to_vec());
    to_delete.push(b"absent-b".to_vec());

    assert_eq!(
        store.delete_many(&to_delete).await.unwrap(),
        4,
        "{context}: delete_many count"
    );
    assert_eq!(store.stats().await.unwrap().key_count, 6);
    assert_eq!(store.delete_many(&[]).await.unwrap(), 0);
    assert_eq!(
        store.delete_many(&to_delete).await.unwrap(),
        0,
        "{context}: idempotent"
    );

    let remaining = store
        .scan_range(Bound::Unbounded, Bound::Unbounded, None)
        .await
        .unwrap();
    assert_eq!(remaining.len(), 6);
    assert_eq!(remaining[0].0, keys[4], "{context}: surviving order");
}

#[tokio::test]
async fn parity_concurrent_readers_and_writers() {
    run_all(check_concurrent_readers_and_writers).await;
}

async fn check_concurrent_readers_and_writers(backend: TestBackend) {
    let dir = TempDir::new().unwrap();
    let store = open(backend, &dir).await.unwrap();
    let context = backend.name();

    let writers = 8usize;
    let per_writer = 40usize;

    let mut tasks = Vec::new();
    for writer in 0..writers {
        let store = store.clone();
        tasks.push(tokio::spawn(async move {
            for i in 0..per_writer {
                let key = format!("w{writer:02}:{i:04}");
                store
                    .set(key.as_bytes(), key.as_bytes(), None)
                    .await
                    .unwrap();
                if i % 10 == 0 {
                    assert_eq!(
                        store
                            .get(key.as_bytes(), ReadConsistency::Strong)
                            .await
                            .unwrap(),
                        Some(key.clone().into_bytes())
                    );
                }
            }
        }));
    }

    for reader in 0..4 {
        let store = store.clone();
        tasks.push(tokio::spawn(async move {
            for _ in 0..60 {
                let prefix = format!("w{reader:02}:");
                let entries = store.scan_prefix(prefix.as_bytes(), Some(5)).await.unwrap();
                assert!(entries.len() <= 5);
            }
        }));
    }

    for task in tasks {
        task.await.unwrap();
    }

    assert_eq!(
        store.stats().await.unwrap().key_count,
        (writers * per_writer) as u64
    );
    // Every key readable after the concurrent write storm.
    for writer in 0..writers {
        for i in 0..per_writer {
            let key = format!("w{writer:02}:{i:04}");
            assert_eq!(
                store
                    .get(key.as_bytes(), ReadConsistency::Strong)
                    .await
                    .unwrap(),
                Some(key.clone().into_bytes()),
                "{context}: lost write {key}"
            );
        }
    }
}

#[tokio::test]
async fn parity_restart_durability() {
    run_all(check_restart_durability).await;
}

async fn check_restart_durability(backend: TestBackend) {
    let dir = TempDir::new().unwrap();

    if !backend.supports_restart() {
        // Memory storage is explicitly non-durable; the test asserts that the
        // reopening behaviour is "fresh and empty" rather than pretending.
        let first = open(backend, &dir).await.unwrap();
        first.set(b"k", b"v", None).await.unwrap();
        assert_eq!(first.stats().await.unwrap().disk_size, None);
        drop(first);
        let second = open(backend, &dir).await.unwrap();
        assert_eq!(second.stats().await.unwrap().key_count, 0);
        return;
    }

    {
        let store = open(backend, &dir).await.unwrap();
        store.set(b"durable-1", b"payload-1", None).await.unwrap();
        store
            .set(b"durable-2", b"payload-2", Some(Duration::from_secs(3600)))
            .await
            .unwrap();
        // No explicit flush: an acknowledged write must already be durable.
        assert!(store.stats().await.unwrap().disk_size.is_some());
    }

    // Adapter (and its background task) dropped: the file lock is released and
    // the reopen must observe every acknowledged write.
    let reopened = open(backend, &dir).await.unwrap();
    assert_eq!(
        reopened
            .get(b"durable-1", ReadConsistency::Strong)
            .await
            .unwrap(),
        Some(b"payload-1".to_vec()),
        "{}: write lost across restart",
        backend.name()
    );
    assert_eq!(
        reopened
            .get(b"durable-2", ReadConsistency::Strong)
            .await
            .unwrap(),
        Some(b"payload-2".to_vec()),
        "{}: ttl write lost across restart",
        backend.name()
    );
    assert!(reopened.ttl(b"durable-2").await.unwrap().is_some());
}

#[tokio::test]
async fn parity_size_and_compaction_accounting() {
    run_all(check_size_and_compaction_accounting).await;
}

async fn check_size_and_compaction_accounting(backend: TestBackend) {
    let dir = TempDir::new().unwrap();
    let store = open(backend, &dir).await.unwrap();
    let context = backend.name();

    let mut expected_bytes = 0u64;
    for i in 0..20u64 {
        let key = format!("event:{i:04}");
        let value = format!("value-{i}-{}", "x".repeat(32));
        expected_bytes += (key.len() + value.len()) as u64;
        store
            .set(key.as_bytes(), value.as_bytes(), None)
            .await
            .unwrap();
    }

    let stats = store.stats().await.unwrap();
    assert_eq!(stats.key_count, 20, "{context}: key_count");
    assert_eq!(stats.data_size, expected_bytes, "{context}: data_size");
    match backend {
        TestBackend::Memory => assert_eq!(stats.disk_size, None, "{context}: no disk size"),
        _ => assert!(
            stats.disk_size.unwrap_or(0) > 0,
            "{context}: file-backed stores report disk size"
        ),
    }

    store.flush().await.unwrap();
    assert_eq!(
        store.stats().await.unwrap().key_count,
        20,
        "{context}: flush keeps data"
    );

    store.compact().await.unwrap();
    assert_eq!(
        store.stats().await.unwrap().key_count,
        20,
        "{context}: compact keeps data"
    );
    assert_eq!(
        store
            .get(b"event:0007", ReadConsistency::Strong)
            .await
            .unwrap(),
        Some(format!("value-7-{}", "x".repeat(32)).into_bytes())
    );
}

#[tokio::test]
async fn parity_error_cases() {
    run_all(check_error_cases).await;
}

async fn check_error_cases(backend: TestBackend) {
    let dir = TempDir::new().unwrap();
    let context = backend.name();

    match backend {
        TestBackend::Memory => {
            // Capacity is a memory-only failure mode; the other backends are
            // bounded by the filesystem, and disk-full is not simulated in the
            // hermetic test environment (see the runbook).
            let store = MemoryStorageAdapter::new(Some(2), CLEANUP_INTERVAL)
                .await
                .unwrap();
            store.set(b"a", b"1", None).await.unwrap();
            store.set(b"b", b"2", None).await.unwrap();
            let err = store.set(b"c", b"3", None).await.unwrap_err();
            assert!(matches!(err, StorageError::DatabaseError { .. }));
            assert_eq!(store.stats().await.unwrap().key_count, 2);
        }
        _ => {
            // 1. A corrupt store must fail to open, never silently truncate.
            let corrupt = dir.path().join("corrupt.store");
            std::fs::write(&corrupt, b"this is not a database file").unwrap();
            let corrupt_result = match backend {
                TestBackend::Redb => {
                    RedbStorageAdapter::new(&corrupt, Some(1024 * 1024), CLEANUP_INTERVAL, false)
                        .await
                        .map(|_| ())
                }
                TestBackend::Sled => {
                    SledStorageAdapter::new(&corrupt, false, CLEANUP_INTERVAL, false)
                        .await
                        .map(|_| ())
                }
                TestBackend::Memory => unreachable!(),
            };
            // sled treats a file path as an IO error; redb rejects the header.
            assert!(
                corrupt_result.is_err(),
                "{context}: corrupt store opened successfully"
            );

            // 2. A second concurrent handle on the same store must be refused
            //    by the backend lock, not corrupt the first writer.
            let path = backend.path(&dir);
            let store = open(backend, &dir).await.unwrap();
            store.set(b"live", b"1", None).await.unwrap();
            let second = match backend {
                TestBackend::Redb => {
                    RedbStorageAdapter::new(&path, Some(1024 * 1024), CLEANUP_INTERVAL, false)
                        .await
                        .map(|_| ())
                }
                TestBackend::Sled => SledStorageAdapter::new(&path, false, CLEANUP_INTERVAL, false)
                    .await
                    .map(|_| ()),
                TestBackend::Memory => unreachable!(),
            };
            assert!(
                second.is_err(),
                "{context}: second handle on the same store was allowed"
            );
            assert_eq!(
                store.get(b"live", ReadConsistency::Strong).await.unwrap(),
                Some(b"1".to_vec())
            );
        }
    }
}

#[test]
fn default_backend_is_redb() {
    match StorageBackend::default() {
        StorageBackend::Redb { path, .. } => assert_eq!(path, "./data/waf.redb"),
        other => panic!("default backend must be redb, got {other:?}"),
    }
    // Unknown configuration values must not fall back to sled either.
    let mut config = crate::config::StorageConfig::default();
    assert_eq!(config.backend, "redb");
    config.backend = "SLED".to_string();
    assert!(config.to_waf_storage_config().is_err());
}
