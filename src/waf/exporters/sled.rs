//! Sled Database Exporter for Security Events
//!
//! This module provides persistent storage of security events using the Sled embedded database.
//! Perfect for local persistence before full K/V integration is available.

use super::{ExportResult, SecurityEventExporter};
use crate::waf::security_events::SecurityEvent;
use async_trait::async_trait;
use serde_json;
use sled::{Db, IVec};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::task;
use tracing::{debug, error, info, warn};

/// Sled database exporter for security events
pub struct SledExporter {
    db: Arc<Db>,
    tree_name: String,
    max_events: Option<usize>,
    cleanup_interval: Duration,
    last_cleanup: Mutex<Instant>,
}

impl SledExporter {
    /// Create a new Sled exporter
    pub fn new<P: AsRef<Path>>(
        db_path: P,
        tree_name: Option<String>,
        max_events: Option<usize>,
        cleanup_interval: Duration,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let db = sled::open(db_path)?;
        let tree_name = tree_name.unwrap_or_else(|| "security_events".to_string());

        info!(
            "Opened Sled database for security events at tree: {}",
            tree_name
        );

        Ok(Self {
            db: Arc::new(db),
            tree_name,
            max_events,
            cleanup_interval,
            last_cleanup: Mutex::new(Instant::now()),
        })
    }

    /// Create an in-memory Sled exporter for testing
    pub fn in_memory(
        tree_name: Option<String>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let config = sled::Config::new().temporary(true);
        let db = config.open()?;
        let tree_name = tree_name.unwrap_or_else(|| "security_events".to_string());

        debug!("Created in-memory Sled database for security events");

        Ok(Self {
            db: Arc::new(db),
            tree_name,
            max_events: None,
            cleanup_interval: Duration::ZERO,
            last_cleanup: Mutex::new(Instant::now()),
        })
    }

    /// Get the tree for security events
    fn get_tree(&self) -> Result<sled::Tree, sled::Error> {
        self.db.open_tree(&self.tree_name)
    }

    /// Generate a sortable key for the event (timestamp + UUID for uniqueness)
    fn generate_key(&self, event: &SecurityEvent) -> Vec<u8> {
        let timestamp_ms = event.timestamp.timestamp_millis();
        let uuid_bytes = event.id.as_bytes();

        let mut key = Vec::with_capacity(8 + 16);
        key.extend_from_slice(&timestamp_ms.to_be_bytes());
        key.extend_from_slice(uuid_bytes);
        key
    }

    /// Serialize event for storage
    fn serialize_event(
        &self,
        event: &SecurityEvent,
    ) -> Result<IVec, Box<dyn std::error::Error + Send + Sync>> {
        let json = serde_json::to_vec(event)?;
        Ok(IVec::from(json))
    }

    /// Deserialize event from storage
    pub fn deserialize_event(
        &self,
        data: &[u8],
    ) -> Result<SecurityEvent, Box<dyn std::error::Error + Send + Sync>> {
        let event: SecurityEvent = serde_json::from_slice(data)?;
        Ok(event)
    }

    /// Clean up old events if max_events is set.
    ///
    /// A non-zero cleanup interval throttles the retention pass; zero runs it
    /// after every write (the legacy behaviour).
    async fn cleanup_old_events(&self) -> ExportResult {
        if let Some(max_events) = self.max_events {
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

            let db = Arc::clone(&self.db);
            let tree_name = self.tree_name.clone();

            task::spawn_blocking(
                move || -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                    let tree = db.open_tree(tree_name)?;
                    let current_count = tree.len();

                    if current_count > max_events {
                        let excess = current_count - max_events;
                        let mut deleted = 0;

                        // Delete oldest entries (keys are timestamp-sorted)
                        for entry in tree.iter() {
                            if deleted >= excess {
                                break;
                            }

                            match entry {
                                Ok((key, _)) => {
                                    tree.remove(key)?;
                                    deleted += 1;
                                }
                                Err(e) => {
                                    error!("Error iterating Sled tree: {}", e);
                                    break;
                                }
                            }
                        }

                        if deleted > 0 {
                            debug!(
                                "Cleaned up {} old security events from Sled database",
                                deleted
                            );
                            tree.flush()?;
                        }
                    }

                    Ok(())
                },
            )
            .await??;
        }

        Ok(())
    }

    /// Get event count in database
    pub async fn event_count(&self) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
        let db = Arc::clone(&self.db);
        let tree_name = self.tree_name.clone();

        let count = task::spawn_blocking(move || -> Result<usize, sled::Error> {
            let tree = db.open_tree(tree_name)?;
            Ok(tree.len())
        })
        .await??;

        Ok(count)
    }

    /// Get events in time range
    pub async fn get_events_in_range(
        &self,
        start_timestamp: chrono::DateTime<chrono::Utc>,
        end_timestamp: chrono::DateTime<chrono::Utc>,
        limit: Option<usize>,
    ) -> Result<Vec<SecurityEvent>, Box<dyn std::error::Error + Send + Sync>> {
        let db = Arc::clone(&self.db);
        let tree_name = self.tree_name.clone();
        let start_key = start_timestamp.timestamp_millis().to_be_bytes().to_vec();
        let end_key = end_timestamp.timestamp_millis().to_be_bytes().to_vec();

        let events = task::spawn_blocking(
            move || -> Result<Vec<SecurityEvent>, Box<dyn std::error::Error + Send + Sync>> {
                let tree = db.open_tree(tree_name)?;
                let mut events = Vec::new();
                let mut count = 0;

                for entry in tree.range(start_key..=end_key) {
                    if let Some(limit) = limit {
                        if count >= limit {
                            break;
                        }
                    }

                    match entry {
                        Ok((_, value)) => {
                            let event: SecurityEvent = serde_json::from_slice(&value)?;
                            events.push(event);
                            count += 1;
                        }
                        Err(e) => {
                            error!("Error reading event from Sled: {}", e);
                            continue;
                        }
                    }
                }

                Ok(events)
            },
        )
        .await??;

        Ok(events)
    }

    /// Get recent events
    pub async fn get_recent_events(
        &self,
        limit: usize,
    ) -> Result<Vec<SecurityEvent>, Box<dyn std::error::Error + Send + Sync>> {
        let db = Arc::clone(&self.db);
        let tree_name = self.tree_name.clone();

        let events = task::spawn_blocking(
            move || -> Result<Vec<SecurityEvent>, Box<dyn std::error::Error + Send + Sync>> {
                let tree = db.open_tree(tree_name)?;
                let mut events = Vec::new();

                // Iterate in reverse order to get most recent events
                for entry in tree.iter().rev().take(limit) {
                    match entry {
                        Ok((_, value)) => {
                            let event: SecurityEvent = serde_json::from_slice(&value)?;
                            events.push(event);
                        }
                        Err(e) => {
                            error!("Error reading event from Sled: {}", e);
                            continue;
                        }
                    }
                }

                // Reverse to get chronological order
                events.reverse();
                Ok(events)
            },
        )
        .await??;

        Ok(events)
    }

    /// Flush database to disk
    pub async fn flush_db(&self) -> ExportResult {
        let db = Arc::clone(&self.db);

        task::spawn_blocking(move || -> Result<(), sled::Error> {
            db.flush()?;
            Ok(())
        })
        .await??;

        debug!("Flushed Sled database to disk");
        Ok(())
    }

    /// Get database statistics
    pub async fn get_stats(
        &self,
    ) -> Result<DatabaseStats, Box<dyn std::error::Error + Send + Sync>> {
        let db = Arc::clone(&self.db);
        let tree_name = self.tree_name.clone();

        let stats = task::spawn_blocking(
            move || -> Result<DatabaseStats, Box<dyn std::error::Error + Send + Sync>> {
                let tree = db.open_tree(tree_name)?;

                let event_count = tree.len();
                let size_on_disk = db.size_on_disk()?;

                // Calculate approximate size in memory
                let mut total_value_size = 0u64;
                let sample_size = std::cmp::min(1000, event_count); // Sample first 1000 events
                let mut sampled = 0;

                for entry in tree.iter().take(sample_size) {
                    match entry {
                        Ok((_, value)) => {
                            total_value_size += value.len() as u64;
                            sampled += 1;
                        }
                        Err(_) => continue,
                    }
                }

                let avg_event_size = if sampled > 0 {
                    total_value_size / sampled as u64
                } else {
                    0
                };

                Ok(DatabaseStats {
                    event_count,
                    size_on_disk,
                    estimated_size_in_memory: event_count as u64 * avg_event_size,
                    average_event_size: avg_event_size,
                })
            },
        )
        .await??;

        Ok(stats)
    }
}

/// Database statistics
#[derive(Debug, Clone)]
pub struct DatabaseStats {
    pub event_count: usize,
    pub size_on_disk: u64,
    pub estimated_size_in_memory: u64,
    pub average_event_size: u64,
}

#[async_trait]
impl SecurityEventExporter for SledExporter {
    async fn export_event(&self, event: &SecurityEvent) -> ExportResult {
        let db = Arc::clone(&self.db);
        let tree_name = self.tree_name.clone();
        let key = self.generate_key(event);
        let value = self.serialize_event(event)?;

        task::spawn_blocking(
            move || -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                let tree = db.open_tree(tree_name)?;
                tree.insert(key, value)?;
                Ok(())
            },
        )
        .await??;

        debug!("Stored security event {} in Sled database", event.id);

        // Cleanup old events if needed
        if let Err(e) = self.cleanup_old_events().await {
            warn!("Failed to cleanup old events: {}", e);
        }

        Ok(())
    }

    async fn export_batch(&self, events: &[SecurityEvent]) -> ExportResult {
        if events.is_empty() {
            return Ok(());
        }

        let db = Arc::clone(&self.db);
        let tree_name = self.tree_name.clone();
        // Prepare batch data
        let mut batch_data = Vec::new();
        for event in events {
            let key = self.generate_key(event);
            let value = self.serialize_event(event)?;
            batch_data.push((key, value));
        }

        task::spawn_blocking(
            move || -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                let tree = db.open_tree(tree_name)?;

                // Use batch insert for better performance
                for (key, value) in batch_data {
                    tree.insert(key, value)?;
                }

                // Flush after batch
                tree.flush()?;

                Ok(())
            },
        )
        .await??;

        debug!(
            "Stored batch of {} security events in Sled database",
            events.len()
        );

        // Cleanup old events if needed
        if let Err(e) = self.cleanup_old_events().await {
            warn!("Failed to cleanup old events: {}", e);
        }

        Ok(())
    }

    async fn flush(&self) -> ExportResult {
        self.flush_db().await
    }

    fn name(&self) -> &'static str {
        "Sled"
    }

    async fn health_check(&self) -> bool {
        // Try a simple operation to check database health
        match self.get_tree() {
            Ok(tree) => {
                // Try to get the length (lightweight operation)
                let _ = tree.len();
                true
            }
            Err(e) => {
                error!("Sled health check failed: {}", e);
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

    async fn create_test_event(id: Uuid) -> SecurityEvent {
        SecurityEvent {
            id,
            timestamp: chrono::Utc::now(),
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
    async fn test_sled_export_single_event() {
        let exporter = SledExporter::in_memory(None).unwrap();
        let event = create_test_event(Uuid::new_v4()).await;

        let result = exporter.export_event(&event).await;
        assert!(result.is_ok());

        let count = exporter.event_count().await.unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn test_sled_export_batch() {
        let exporter = SledExporter::in_memory(None).unwrap();

        let events = vec![
            create_test_event(Uuid::new_v4()).await,
            create_test_event(Uuid::new_v4()).await,
            create_test_event(Uuid::new_v4()).await,
        ];

        let result = exporter.export_batch(&events).await;
        assert!(result.is_ok());

        let count = exporter.event_count().await.unwrap();
        assert_eq!(count, 3);
    }

    #[tokio::test]
    async fn test_sled_get_recent_events() {
        let exporter = SledExporter::in_memory(None).unwrap();

        let events = vec![
            create_test_event(Uuid::new_v4()).await,
            create_test_event(Uuid::new_v4()).await,
            create_test_event(Uuid::new_v4()).await,
        ];

        exporter.export_batch(&events).await.unwrap();

        let recent = exporter.get_recent_events(2).await.unwrap();
        assert_eq!(recent.len(), 2);
    }

    #[tokio::test]
    async fn test_sled_health_check() {
        let exporter = SledExporter::in_memory(None).unwrap();
        assert!(exporter.health_check().await);
    }

    #[tokio::test]
    async fn test_sled_max_events_cleanup() {
        let exporter = SledExporter {
            db: Arc::new(sled::Config::new().temporary(true).open().unwrap()),
            tree_name: "test_events".to_string(),
            max_events: Some(2), // Only keep 2 events
            cleanup_interval: Duration::ZERO,
            last_cleanup: Mutex::new(Instant::now()),
        };

        // Add 3 events
        for _ in 0..3 {
            let event = create_test_event(Uuid::new_v4()).await;
            exporter.export_event(&event).await.unwrap();
            // Small delay to ensure different timestamps
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }

        // Should have cleaned up to 2 events
        let count = exporter.event_count().await.unwrap();
        assert!(count <= 2);
    }
}
