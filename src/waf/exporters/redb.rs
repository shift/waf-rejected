//! Redb Database Exporter for Security Events
//!
//! Default persistent event store. Records are stored with the same sortable
//! key layout as the legacy sled exporter (`timestamp_ms_be ++ uuid`), so a
//! store migrated with `waf-storage-migrate` is readable by this exporter and
//! vice versa.
//!
//! Durability: writes go through [`RedbStorageAdapter`], which pins
//! `Durability::Immediate` on every transaction. An `export_event` that returns
//! `Ok` has been fsynced and survives a crash.

use super::{ExportResult, SecurityEventExporter};
use crate::waf::security_events::SecurityEvent;
use crate::waf::storage::{ReadConsistency, RedbStorageAdapter, StorageAdapter};
use async_trait::async_trait;
use std::ops::Bound;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tracing::{debug, error, info};

/// redb-backed security event exporter.
pub struct RedbExporter {
    store: RedbStorageAdapter,
    max_events: Option<usize>,
    cleanup_interval: Duration,
    last_cleanup: Mutex<Instant>,
}

impl RedbExporter {
    /// Open (or create) the event store at `db_path`.
    ///
    /// Synchronous: `SecurityEventLogger::new` builds exporters from a sync
    /// context. The adapter is opened without the TTL collector because this
    /// exporter never writes TTLs.
    pub fn new<P: AsRef<Path>>(
        db_path: P,
        max_events: Option<usize>,
        cache_size: Option<usize>,
        cleanup_interval: Duration,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let store = RedbStorageAdapter::open_sync(db_path, cache_size, false)
            .map_err(|e| format!("failed to open redb event store: {e}"))?;

        info!("Opened redb database for security events");

        Ok(Self {
            store,
            max_events,
            cleanup_interval,
            last_cleanup: Mutex::new(Instant::now()),
        })
    }

    /// Sortable key: timestamp_ms (big-endian) then the event UUID.
    fn generate_key(event: &SecurityEvent) -> Vec<u8> {
        let mut key = Vec::with_capacity(8 + 16);
        key.extend_from_slice(&event.timestamp.timestamp_millis().to_be_bytes());
        key.extend_from_slice(event.id.as_bytes());
        key
    }

    /// Deserialize a stored event.
    pub fn deserialize_event(
        data: &[u8],
    ) -> Result<SecurityEvent, Box<dyn std::error::Error + Send + Sync>> {
        Ok(serde_json::from_slice(data)?)
    }

    async fn store_events(&self, events: &[SecurityEvent]) -> ExportResult {
        for event in events {
            let key = Self::generate_key(event);
            let value = serde_json::to_vec(event)?;
            self.store.set(&key, &value, None).await?;
        }

        self.cleanup_old_events().await?;
        Ok(())
    }

    /// Delete the oldest events when the retention cap is exceeded.
    ///
    /// A non-zero cleanup interval throttles the retention pass so a busy
    /// writer does not pay for a count scan on every event. Zero (the default
    /// for the legacy configuration path) preserves cleanup-after-every-write.
    async fn cleanup_old_events(&self) -> ExportResult {
        let Some(max_events) = self.max_events else {
            return Ok(());
        };

        if !self.cleanup_interval.is_zero() {
            let mut last = self
                .last_cleanup
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if last.elapsed() < self.cleanup_interval {
                return Ok(());
            }
            *last = Instant::now();
        }

        let current = self.store.stats().await?.key_count as usize;
        if current <= max_events {
            return Ok(());
        }

        let excess = current - max_events;
        let oldest = self
            .store
            .scan_range(Bound::Unbounded, Bound::Unbounded, Some(excess))
            .await?;
        if oldest.is_empty() {
            return Ok(());
        }

        let keys: Vec<Vec<u8>> = oldest.into_iter().map(|(key, _)| key).collect();
        let removed = self.store.delete_many(&keys).await?;
        debug!(
            "Cleaned up {} old security events from redb database",
            removed
        );
        Ok(())
    }

    /// Number of stored events.
    pub async fn event_count(&self) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
        Ok(self.store.stats().await?.key_count as usize)
    }

    /// Get events within a timestamp range (inclusive), in chronological order.
    pub async fn get_events_in_range(
        &self,
        start_timestamp: chrono::DateTime<chrono::Utc>,
        end_timestamp: chrono::DateTime<chrono::Utc>,
        limit: Option<usize>,
    ) -> Result<Vec<SecurityEvent>, Box<dyn std::error::Error + Send + Sync>> {
        let start = start_timestamp.timestamp_millis().to_be_bytes();
        let end_ms = end_timestamp.timestamp_millis();
        let end = end_ms
            .checked_add(1)
            .map(|next| next.to_be_bytes().to_vec());

        let end_bound = match end.as_deref() {
            Some(end) => Bound::Excluded(end),
            None => Bound::Unbounded,
        };

        let entries = self
            .store
            .scan_range(Bound::Included(&start), end_bound, limit)
            .await?;

        let mut events = Vec::with_capacity(entries.len());
        for (_, value) in entries {
            match Self::deserialize_event(&value) {
                Ok(event) => events.push(event),
                Err(e) => {
                    error!("Error decoding event from redb: {}", e);
                }
            }
        }
        Ok(events)
    }

    /// Most recent `limit` events in chronological order.
    pub async fn get_recent_events(
        &self,
        limit: usize,
    ) -> Result<Vec<SecurityEvent>, Box<dyn std::error::Error + Send + Sync>> {
        let total = self.store.stats().await?.key_count as usize;
        if total == 0 || limit == 0 {
            return Ok(Vec::new());
        }

        let entries = if total <= limit {
            self.store
                .scan_range(Bound::Unbounded, Bound::Unbounded, None)
                .await?
        } else {
            // The adapter exposes forward scans only; walk to the last `limit`
            // keys. O(total) but this is an operator query, not the hot path.
            self.store
                .scan_range(Bound::Unbounded, Bound::Unbounded, None)
                .await?
                .split_off(total - limit)
        };

        let mut events = Vec::with_capacity(entries.len());
        for (_, value) in entries {
            match Self::deserialize_event(&value) {
                Ok(event) => events.push(event),
                Err(e) => {
                    error!("Error decoding event from redb: {}", e);
                }
            }
        }
        Ok(events)
    }

    /// Flush the store. Writes are already durable on commit.
    pub async fn flush_db(&self) -> ExportResult {
        self.store.flush().await?;
        Ok(())
    }

    /// Store statistics.
    pub async fn get_stats(
        &self,
    ) -> Result<RedbDatabaseStats, Box<dyn std::error::Error + Send + Sync>> {
        let stats = self.store.stats().await?;
        let average_event_size = stats.data_size.checked_div(stats.key_count).unwrap_or(0);

        Ok(RedbDatabaseStats {
            event_count: stats.key_count as usize,
            size_on_disk: stats.disk_size.unwrap_or(0),
            estimated_size_in_memory: stats.data_size,
            average_event_size,
        })
    }
}

/// redb event-store statistics.
#[derive(Debug, Clone)]
pub struct RedbDatabaseStats {
    pub event_count: usize,
    pub size_on_disk: u64,
    pub estimated_size_in_memory: u64,
    pub average_event_size: u64,
}

#[async_trait]
impl SecurityEventExporter for RedbExporter {
    async fn export_event(&self, event: &SecurityEvent) -> ExportResult {
        self.store_events(std::slice::from_ref(event)).await?;
        debug!("Stored security event {} in redb database", event.id);
        Ok(())
    }

    async fn export_batch(&self, events: &[SecurityEvent]) -> ExportResult {
        if events.is_empty() {
            return Ok(());
        }
        self.store_events(events).await?;
        debug!(
            "Stored batch of {} security events in redb database",
            events.len()
        );
        Ok(())
    }

    async fn flush(&self) -> ExportResult {
        self.flush_db().await
    }

    fn name(&self) -> &'static str {
        "Redb"
    }

    async fn health_check(&self) -> bool {
        match self
            .store
            .get(b"__redb_health_probe__", ReadConsistency::Strong)
            .await
        {
            Ok(_) => true,
            Err(e) => {
                error!("redb health check failed: {}", e);
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::waf::security_events::{ThreatLevel, WafDecision};
    use std::collections::HashMap;
    use uuid::Uuid;

    fn test_event(id: Uuid, offset_ms: i64) -> SecurityEvent {
        SecurityEvent {
            id,
            timestamp: chrono::Utc::now() + chrono::Duration::milliseconds(offset_ms),
            client_ip: "192.168.1.100".parse().unwrap(),
            client_port: Some(12345),
            server_ip: Some("10.0.0.1".to_string()),
            server_port: Some(80),
            method: "GET".to_string(),
            path: "/test".to_string(),
            http_version: "1.1".to_string(),
            user_agent: Some("Test Agent".to_string()),
            decision: WafDecision::Block,
            threat_level: ThreatLevel::High,
            triggered_rules: vec!["TEST_RULE".to_string()],
            request_size: Some(512),
            response_status: Some(403),
            response_size: Some(256),
            processing_time_ms: Some(10),
            inspection_duration_ms: None,
            upstream_duration_ms: None,
            country_code: Some("US".to_string()),
            region: Some("California".to_string()),
            city: Some("San Francisco".to_string()),
            asn: Some(15169),
            custom_fields: HashMap::new(),
        }
    }

    #[tokio::test]
    async fn exports_and_queries_events() {
        let dir = tempfile::tempdir().unwrap();
        let exporter = RedbExporter::new(
            dir.path().join("events.redb"),
            None,
            None,
            std::time::Duration::ZERO,
        )
        .unwrap();

        let first = test_event(Uuid::new_v4(), 0);
        let second = test_event(Uuid::new_v4(), 10);
        exporter
            .export_batch(&[first.clone(), second.clone()])
            .await
            .unwrap();

        assert_eq!(exporter.event_count().await.unwrap(), 2);
        let recent = exporter.get_recent_events(1).await.unwrap();
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].id, second.id);

        let all = exporter
            .get_events_in_range(
                first.timestamp - chrono::Duration::seconds(1),
                second.timestamp + chrono::Duration::seconds(1),
                None,
            )
            .await
            .unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].id, first.id);
        assert!(exporter.health_check().await);
        assert!(exporter.get_stats().await.unwrap().size_on_disk > 0);
    }

    #[tokio::test]
    async fn enforces_max_events_retention() {
        let dir = tempfile::tempdir().unwrap();
        let exporter = RedbExporter::new(
            dir.path().join("events.redb"),
            Some(2),
            None,
            std::time::Duration::ZERO,
        )
        .unwrap();

        for i in 0..5 {
            exporter
                .export_event(&test_event(Uuid::new_v4(), i))
                .await
                .unwrap();
        }

        assert_eq!(exporter.event_count().await.unwrap(), 2);
    }

    #[tokio::test]
    async fn survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("events.redb");
        let event = test_event(Uuid::new_v4(), 0);

        {
            let exporter = RedbExporter::new(&path, None, None, std::time::Duration::ZERO).unwrap();
            exporter.export_event(&event).await.unwrap();
        }

        let reopened = RedbExporter::new(&path, None, None, std::time::Duration::ZERO).unwrap();
        let recent = reopened.get_recent_events(10).await.unwrap();
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].id, event.id);
    }
}
