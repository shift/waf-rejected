//! Security Event Export System
//! 
//! This module provides comprehensive export capabilities for security events,
//! supporting multiple output formats and destinations.

pub mod cef;
pub mod dispatcher;

#[cfg(feature = "export-otel")]
pub mod otel;

#[cfg(feature = "export-sled")]
pub mod sled;

// Re-exports for easier access
pub use cef::CefExporter;
pub use dispatcher::ExporterDispatcher;

#[cfg(feature = "export-otel")]
pub use otel::OpenTelemetryExporter;

#[cfg(feature = "export-sled")]
pub use sled::SledExporter;

use crate::waf::security_events::SecurityEvent;
use async_trait::async_trait;
use std::error::Error;

/// Result type for export operations
pub type ExportResult = Result<(), Box<dyn Error + Send + Sync>>;

/// Common trait for all security event exporters
#[async_trait]
pub trait SecurityEventExporter: Send + Sync {
    /// Export a single security event
    async fn export_event(&self, event: &SecurityEvent) -> ExportResult;
    
    /// Export multiple security events in batch
    async fn export_batch(&self, events: &[SecurityEvent]) -> ExportResult {
        for event in events {
            self.export_event(event).await?;
        }
        Ok(())
    }
    
    /// Flush any pending exports
    async fn flush(&self) -> ExportResult {
        Ok(())
    }
    
    /// Get exporter name for logging
    fn name(&self) -> &'static str;
    
    /// Check if exporter is healthy/available
    async fn health_check(&self) -> bool {
        true
    }
}
