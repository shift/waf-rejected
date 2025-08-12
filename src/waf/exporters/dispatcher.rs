//! Exporter Dispatcher
//! 
//! This module provides a dispatcher that can send security events to multiple
//! exporters simultaneously with async handling and error resilience.

use super::{SecurityEventExporter, ExportResult};
use crate::waf::security_events::SecurityEvent;
use async_trait::async_trait;
use std::sync::Arc;
use tokio::task::JoinSet;
use tracing::{debug, error, warn};

/// Dispatcher for multiple security event exporters
pub struct ExporterDispatcher {
    exporters: Vec<Arc<dyn SecurityEventExporter>>,
    fail_fast: bool,
}

impl ExporterDispatcher {
    /// Create a new exporter dispatcher
    pub fn new(fail_fast: bool) -> Self {
        Self {
            exporters: Vec::new(),
            fail_fast,
        }
    }

    /// Add an exporter to the dispatcher
    pub fn add_exporter<T>(&mut self, exporter: T) -> &mut Self
    where
        T: SecurityEventExporter + 'static,
    {
        self.exporters.push(Arc::new(exporter));
        self
    }

    /// Get the number of registered exporters
    pub fn exporter_count(&self) -> usize {
        self.exporters.len()
    }

    /// Get list of exporter names
    pub fn exporter_names(&self) -> Vec<&'static str> {
        self.exporters.iter().map(|e| e.name()).collect()
    }

    /// Check health of all exporters
    pub async fn health_check_all(&self) -> Vec<(String, bool)> {
        let mut results = Vec::new();
        
        for exporter in &self.exporters {
            let name = exporter.name().to_string();
            let healthy = exporter.health_check().await;
            results.push((name, healthy));
        }
        
        results
    }

    /// Export event to all healthy exporters
    async fn export_to_all(&self, event: &SecurityEvent) -> ExportResult {
        if self.exporters.is_empty() {
            warn!("No exporters configured for security event dispatch");
            return Ok(());
        }

        let mut join_set = JoinSet::new();
        
        // Spawn tasks for each exporter
        for exporter in &self.exporters {
            let exporter_clone = Arc::clone(exporter);
            let event_clone = event.clone();
            
            join_set.spawn(async move {
                let name = exporter_clone.name();
                match exporter_clone.export_event(&event_clone).await {
                    Ok(()) => {
                        debug!("Successfully exported event {} to {}", event_clone.id, name);
                        Ok(name)
                    }
                    Err(e) => {
                        error!("Failed to export event {} to {}: {}", event_clone.id, name, e);
                        Err((name, e))
                    }
                }
            });
        }

        // Collect results
        let mut successful_exports = Vec::new();
        let mut failed_exports = Vec::new();
        
        while let Some(result) = join_set.join_next().await {
            match result {
                Ok(Ok(exporter_name)) => {
                    successful_exports.push(exporter_name);
                }
                Ok(Err((exporter_name, error))) => {
                    failed_exports.push((exporter_name, error));
                }
                Err(join_error) => {
                    error!("Exporter task panicked: {}", join_error);
                    failed_exports.push(("unknown", join_error.into()));
                }
            }
        }

        // Handle results based on fail_fast setting
        if !failed_exports.is_empty() {
            if self.fail_fast {
                let error_msg = format!(
                    "Export failed for {} exporters: {:?}",
                    failed_exports.len(),
                    failed_exports.iter().map(|(name, _)| name).collect::<Vec<_>>()
                );
                return Err(error_msg.into());
            } else {
                warn!(
                    "Export failed for {} out of {} exporters for event {}: {:?}",
                    failed_exports.len(),
                    self.exporters.len(),
                    event.id,
                    failed_exports.iter().map(|(name, _)| name).collect::<Vec<_>>()
                );
            }
        }

        debug!(
            "Successfully exported event {} to {} exporters: {:?}",
            event.id,
            successful_exports.len(),
            successful_exports
        );

        Ok(())
    }

    /// Export batch to all exporters
    async fn export_batch_to_all(&self, events: &[SecurityEvent]) -> ExportResult {
        if self.exporters.is_empty() {
            warn!("No exporters configured for batch security event dispatch");
            return Ok(());
        }

        let mut join_set = JoinSet::new();
        
        // Spawn batch tasks for each exporter
        for exporter in &self.exporters {
            let exporter_clone = Arc::clone(exporter);
            let events_clone = events.to_vec();
            
            join_set.spawn(async move {
                let name = exporter_clone.name();
                match exporter_clone.export_batch(&events_clone).await {
                    Ok(()) => {
                        debug!("Successfully exported {} events to {}", events_clone.len(), name);
                        Ok(name)
                    }
                    Err(e) => {
                        error!("Failed to export {} events to {}: {}", events_clone.len(), name, e);
                        Err((name, e))
                    }
                }
            });
        }

        // Collect results
        let mut successful_exports = Vec::new();
        let mut failed_exports = Vec::new();
        
        while let Some(result) = join_set.join_next().await {
            match result {
                Ok(Ok(exporter_name)) => {
                    successful_exports.push(exporter_name);
                }
                Ok(Err((exporter_name, error))) => {
                    failed_exports.push((exporter_name, error));
                }
                Err(join_error) => {
                    error!("Batch exporter task panicked: {}", join_error);
                    failed_exports.push(("unknown", join_error.into()));
                }
            }
        }

        // Handle results based on fail_fast setting
        if !failed_exports.is_empty() {
            if self.fail_fast {
                let error_msg = format!(
                    "Batch export failed for {} exporters: {:?}",
                    failed_exports.len(),
                    failed_exports.iter().map(|(name, _)| name).collect::<Vec<_>>()
                );
                return Err(error_msg.into());
            } else {
                warn!(
                    "Batch export failed for {} out of {} exporters for {} events: {:?}",
                    failed_exports.len(),
                    self.exporters.len(),
                    events.len(),
                    failed_exports.iter().map(|(name, _)| name).collect::<Vec<_>>()
                );
            }
        }

        debug!(
            "Successfully batch exported {} events to {} exporters: {:?}",
            events.len(),
            successful_exports.len(),
            successful_exports
        );

        Ok(())
    }
}

#[async_trait]
impl SecurityEventExporter for ExporterDispatcher {
    async fn export_event(&self, event: &SecurityEvent) -> ExportResult {
        self.export_to_all(event).await
    }

    async fn export_batch(&self, events: &[SecurityEvent]) -> ExportResult {
        self.export_batch_to_all(events).await
    }

    async fn flush(&self) -> ExportResult {
        if self.exporters.is_empty() {
            return Ok(());
        }

        let mut join_set = JoinSet::new();
        
        // Flush all exporters in parallel
        for exporter in &self.exporters {
            let exporter_clone = Arc::clone(exporter);
            
            join_set.spawn(async move {
                let name = exporter_clone.name();
                match exporter_clone.flush().await {
                    Ok(()) => {
                        debug!("Successfully flushed exporter {}", name);
                        Ok(name)
                    }
                    Err(e) => {
                        error!("Failed to flush exporter {}: {}", name, e);
                        Err((name, e))
                    }
                }
            });
        }

        let mut successful_flushes = Vec::new();
        let mut failed_flushes = Vec::new();
        
        while let Some(result) = join_set.join_next().await {
            match result {
                Ok(Ok(exporter_name)) => {
                    successful_flushes.push(exporter_name);
                }
                Ok(Err((exporter_name, error))) => {
                    failed_flushes.push((exporter_name, error));
                }
                Err(join_error) => {
                    error!("Flush task panicked: {}", join_error);
                    failed_flushes.push(("unknown", join_error.into()));
                }
            }
        }

        if !failed_flushes.is_empty() {
            if self.fail_fast {
                let error_msg = format!(
                    "Flush failed for {} exporters: {:?}",
                    failed_flushes.len(),
                    failed_flushes.iter().map(|(name, _)| name).collect::<Vec<_>>()
                );
                return Err(error_msg.into());
            } else {
                warn!(
                    "Flush failed for {} out of {} exporters: {:?}",
                    failed_flushes.len(),
                    self.exporters.len(),
                    failed_flushes.iter().map(|(name, _)| name).collect::<Vec<_>>()
                );
            }
        }

        debug!("Flushed {} exporters successfully: {:?}", successful_flushes.len(), successful_flushes);
        Ok(())
    }

    fn name(&self) -> &'static str {
        "ExporterDispatcher"
    }

    async fn health_check(&self) -> bool {
        if self.exporters.is_empty() {
            return false;
        }

        let health_results = self.health_check_all().await;
        let healthy_count = health_results.iter().filter(|(_, healthy)| *healthy).count();
        
        // Consider healthy if at least one exporter is healthy
        healthy_count > 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::waf::security_events::{SecurityEvent, ThreatLevel, WafDecision};
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};

    // Mock exporter for testing
    pub struct MockExporter {
        name: &'static str,
        export_count: AtomicUsize,
        should_fail: bool,
    }

    impl MockExporter {
        pub fn new(name: &'static str, should_fail: bool) -> Self {
            Self {
                name,
                export_count: AtomicUsize::new(0),
                should_fail,
            }
        }

        pub fn get_export_count(&self) -> usize {
            self.export_count.load(Ordering::Relaxed)
        }
    }

    #[async_trait]
    impl SecurityEventExporter for MockExporter {
        async fn export_event(&self, _event: &SecurityEvent) -> ExportResult {
            self.export_count.fetch_add(1, Ordering::Relaxed);
            
            if self.should_fail {
                Err(format!("{} exporter failed", self.name).into())
            } else {
                Ok(())
            }
        }

        fn name(&self) -> &'static str {
            self.name
        }

        async fn health_check(&self) -> bool {
            !self.should_fail
        }
    }

    #[tokio::test]
    async fn test_dispatcher_success() {
        let mut dispatcher = ExporterDispatcher::new(false);
        
        let mock1 = MockExporter::new("Mock1", false);
        let mock2 = MockExporter::new("Mock2", false);
        
        dispatcher.add_exporter(mock1);
        dispatcher.add_exporter(mock2);
        
        assert_eq!(dispatcher.exporter_count(), 2);
        
        let event = create_test_event();
        let result = dispatcher.export_event(&event).await;
        
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_dispatcher_partial_failure() {
        let mut dispatcher = ExporterDispatcher::new(false); // Don't fail fast
        
        let mock1 = MockExporter::new("Mock1", false);
        let mock2 = MockExporter::new("Mock2", true); // This will fail
        
        dispatcher.add_exporter(mock1);
        dispatcher.add_exporter(mock2);
        
        let event = create_test_event();
        let result = dispatcher.export_event(&event).await;
        
        // Should succeed because we don't fail fast
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_dispatcher_fail_fast() {
        let mut dispatcher = ExporterDispatcher::new(true); // Fail fast
        
        let mock1 = MockExporter::new("Mock1", false);
        let mock2 = MockExporter::new("Mock2", true); // This will fail
        
        dispatcher.add_exporter(mock1);
        dispatcher.add_exporter(mock2);
        
        let event = create_test_event();
        let result = dispatcher.export_event(&event).await;
        
        // Should fail because we fail fast
        assert!(result.is_err());
    }

    fn create_test_event() -> SecurityEvent {
        SecurityEvent {
            id: uuid::Uuid::new_v4(),
            timestamp: chrono::Utc::now(),
            client_ip: "192.168.1.100".parse().unwrap(),
            client_port: Some(12345),
            server_ip: Some("10.0.0.1".to_string()),
            server_port: Some(80),
            method: "GET".to_string(),
            path: "/test".to_string(),
            http_version: "1.1".to_string(),
            user_agent: None,
            decision: WafDecision::Allow,
            threat_level: ThreatLevel::Low,
            triggered_rules: Vec::new(),
            request_size: None,
            response_status: Some(200),
            response_size: None,
            processing_time_ms: None,
            country_code: None,
            region: None,
            city: None,
            asn: None,
            custom_fields: HashMap::new(),
        }
    }
}
