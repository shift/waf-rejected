//! OpenTelemetry (OTel) Exporter for Security Events
//!
//! This module provides OpenTelemetry integration for security events, enabling
//! export to observability platforms like Jaeger, Zipkin, and cloud providers.

use super::{ExportResult, SecurityEventExporter};
use crate::waf::security_events::{SecurityEvent, ThreatLevel, WafDecision};
use async_trait::async_trait;
use opentelemetry::trace::{Span, SpanBuilder, SpanKind, Status, Tracer};
use opentelemetry::{global, Context, KeyValue};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{debug, error, warn};

/// OpenTelemetry exporter for security events
pub struct OpenTelemetryExporter {
    tracer: global::BoxedTracer,
    service_name: String,
    service_version: String,
    export_traces: bool,
    export_logs: bool,
}

impl OpenTelemetryExporter {
    /// Create a new OpenTelemetry exporter
    pub fn new(
        service_name: Option<String>,
        service_version: Option<String>,
        export_traces: bool,
        export_logs: bool,
    ) -> Self {
        let service_name = service_name.unwrap_or_else(|| "waf-rejected".to_string());
        let service_version = service_version.unwrap_or_else(|| "1.0.0".to_string());

        // Resolve the globally installed tracer once. The default no-op
        // provider is used until the embedding application installs an SDK
        // provider; this crate deliberately does not depend on the SDK.
        let tracer = global::tracer("waf-security-events");

        Self {
            tracer,
            service_name,
            service_version,
            export_traces,
            export_logs,
        }
    }

    /// Export security event as OpenTelemetry span
    async fn export_as_span(&self, event: &SecurityEvent) -> ExportResult {
        let span_name = format!("waf_security_event_{}", event.decision);

        let span_builder = SpanBuilder::from_name(span_name)
            .with_kind(SpanKind::Server)
            .with_start_time(self.timestamp_to_system_time(event.timestamp))
            .with_attributes(self.build_span_attributes(event));

        // Set span status based on decision
        let span_status = match event.decision {
            WafDecision::Allow => Status::Ok,
            WafDecision::Block => Status::error("Request blocked by WAF"),
            WafDecision::Challenge => Status::error("Request challenged by WAF"),
            WafDecision::Monitor => Status::Ok,
        };

        let mut span = self
            .tracer
            .build_with_context(span_builder, &Context::current());
        span.set_status(span_status);

        // Add events to span for significant security events
        if !event.triggered_rules.is_empty() {
            let rule_attributes: Vec<KeyValue> = event
                .triggered_rules
                .iter()
                .enumerate()
                .map(|(i, rule)| KeyValue::new(format!("rule.{}", i), rule.clone()))
                .collect();

            span.add_event("security_rules_triggered", rule_attributes);
        }

        // End span immediately as this is a completed security event
        span.end();

        debug!("Exported security event as OTel span: {}", event.id);
        Ok(())
    }

    /// Export security event as OpenTelemetry log (using tracing)
    async fn export_as_log(&self, event: &SecurityEvent) -> ExportResult {
        // For now, use structured tracing instead of OpenTelemetry logs API
        // This provides similar functionality with better compatibility

        let severity = self.get_log_severity_text(&event.threat_level);

        match severity {
            "INFO" => {
                tracing::info!(
                    event_id = %event.id,
                    decision = %event.decision,
                    threat_level = %event.threat_level,
                    client_ip = %event.client_ip,
                    path = %event.path,
                    method = %event.method,
                    "Security event logged via OpenTelemetry"
                );
            }
            "WARN" => {
                tracing::warn!(
                    event_id = %event.id,
                    decision = %event.decision,
                    threat_level = %event.threat_level,
                    client_ip = %event.client_ip,
                    path = %event.path,
                    method = %event.method,
                    triggered_rules = ?event.triggered_rules,
                    "Security event logged via OpenTelemetry"
                );
            }
            "ERROR" | "FATAL" => {
                tracing::error!(
                    event_id = %event.id,
                    decision = %event.decision,
                    threat_level = %event.threat_level,
                    client_ip = %event.client_ip,
                    path = %event.path,
                    method = %event.method,
                    triggered_rules = ?event.triggered_rules,
                    "Security event logged via OpenTelemetry"
                );
            }
            _ => {
                tracing::debug!(
                    event_id = %event.id,
                    decision = %event.decision,
                    threat_level = %event.threat_level,
                    "Security event logged via OpenTelemetry"
                );
            }
        }

        debug!("Exported security event as OTel log: {}", event.id);
        Ok(())
    }

    /// Build span attributes from security event
    fn build_span_attributes(&self, event: &SecurityEvent) -> Vec<KeyValue> {
        let mut attributes = vec![
            // Service identification
            KeyValue::new("service.name", self.service_name.clone()),
            KeyValue::new("service.version", self.service_version.clone()),
            // Security event attributes
            KeyValue::new("security.event.id", event.id.to_string()),
            KeyValue::new("security.decision", event.decision.to_string()),
            KeyValue::new("security.threat_level", event.threat_level.to_string()),
            // HTTP attributes (following OpenTelemetry semantic conventions)
            KeyValue::new("http.method", event.method.clone()),
            KeyValue::new("http.target", event.path.clone()),
            KeyValue::new("http.version", event.http_version.clone()),
            KeyValue::new("http.client_ip", event.client_ip.to_string()),
        ];

        // Optional HTTP attributes
        if let Some(user_agent) = &event.user_agent {
            attributes.push(KeyValue::new("http.user_agent", user_agent.clone()));
        }

        if let Some(status) = event.response_status {
            attributes.push(KeyValue::new("http.status_code", status as i64));
        }

        if let Some(size) = event.request_size {
            attributes.push(KeyValue::new("http.request_content_length", size as i64));
        }

        if let Some(size) = event.response_size {
            attributes.push(KeyValue::new("http.response_content_length", size as i64));
        }

        // Network attributes
        if let Some(port) = event.client_port {
            attributes.push(KeyValue::new("net.peer.port", port as i64));
        }

        if let Some(server_ip) = &event.server_ip {
            attributes.push(KeyValue::new("net.host.ip", server_ip.clone()));
        }

        if let Some(port) = event.server_port {
            attributes.push(KeyValue::new("net.host.port", port as i64));
        }

        // Geographic attributes
        if let Some(country) = &event.country_code {
            attributes.push(KeyValue::new("geo.country_iso_code", country.clone()));
        }

        if let Some(region) = &event.region {
            attributes.push(KeyValue::new("geo.region_name", region.clone()));
        }

        if let Some(city) = &event.city {
            attributes.push(KeyValue::new("geo.city_name", city.clone()));
        }

        // ASN information
        if let Some(asn) = event.asn {
            attributes.push(KeyValue::new("net.peer.asn", asn as i64));
        }

        // Security-specific attributes
        if !event.triggered_rules.is_empty() {
            attributes.push(KeyValue::new(
                "security.rules_triggered_count",
                event.triggered_rules.len() as i64,
            ));

            // Add individual rules as separate attributes (limited to avoid too many attributes)
            for (i, rule) in event.triggered_rules.iter().take(10).enumerate() {
                attributes.push(KeyValue::new(format!("security.rule.{}", i), rule.clone()));
            }
        }

        // Performance attributes
        if let Some(duration) = event.processing_time_ms {
            attributes.push(KeyValue::new(
                "security.processing_time_ms",
                duration as f64,
            ));
        }

        // Custom fields (limited to avoid attribute explosion)
        for (key, value) in event.custom_fields.iter().take(20) {
            let sanitized_key = self.sanitize_attribute_key(key);
            attributes.push(KeyValue::new(
                format!("custom.{}", sanitized_key),
                value.clone(),
            ));
        }

        attributes
    }

    /// Convert chrono DateTime to SystemTime for OpenTelemetry
    fn timestamp_to_system_time(&self, timestamp: chrono::DateTime<chrono::Utc>) -> SystemTime {
        UNIX_EPOCH
            + Duration::from_secs(timestamp.timestamp() as u64)
            + Duration::from_nanos(timestamp.timestamp_subsec_nanos() as u64)
    }

    /// Get log severity text from threat level
    fn get_log_severity_text(&self, threat_level: &ThreatLevel) -> &'static str {
        match threat_level {
            ThreatLevel::Low => "INFO",
            ThreatLevel::Medium => "WARN",
            ThreatLevel::High => "ERROR",
            ThreatLevel::Critical => "FATAL",
        }
    }

    /// Sanitize attribute keys to comply with OpenTelemetry naming conventions
    fn sanitize_attribute_key(&self, key: &str) -> String {
        key.chars()
            .map(|c| {
                if c.is_alphanumeric() || c == '_' || c == '.' {
                    c
                } else {
                    '_'
                }
            })
            .collect::<String>()
            .to_lowercase()
    }
}

#[async_trait]
impl SecurityEventExporter for OpenTelemetryExporter {
    async fn export_event(&self, event: &SecurityEvent) -> ExportResult {
        let mut results = Vec::new();

        // Export as span if enabled
        if self.export_traces {
            if let Err(e) = self.export_as_span(event).await {
                error!("Failed to export security event as OTel span: {}", e);
                results.push(e);
            }
        }

        // Export as log if enabled
        if self.export_logs {
            if let Err(e) = self.export_as_log(event).await {
                error!("Failed to export security event as OTel log: {}", e);
                results.push(e);
            }
        }

        // Return error if all exports failed
        if !results.is_empty()
            && results.len()
                == [self.export_traces, self.export_logs]
                    .iter()
                    .filter(|&&x| x)
                    .count()
        {
            return Err(format!("All OTel exports failed: {:?}", results).into());
        }

        if !results.is_empty() {
            warn!("Some OTel exports failed: {:?}", results);
        }

        Ok(())
    }

    async fn export_batch(&self, events: &[SecurityEvent]) -> ExportResult {
        let mut failed_count = 0;

        for event in events {
            if let Err(e) = self.export_event(event).await {
                error!("Failed to export security event {}: {}", event.id, e);
                failed_count += 1;
            }
        }

        if failed_count > 0 {
            warn!(
                "Failed to export {} out of {} security events to OTel",
                failed_count,
                events.len()
            );
        }

        Ok(())
    }

    async fn flush(&self) -> ExportResult {
        // OpenTelemetry handles flushing internally through the global providers
        // We could add explicit flush calls here if needed
        debug!("OTel exporter flush requested");
        Ok(())
    }

    fn name(&self) -> &'static str {
        "OpenTelemetry"
    }

    async fn health_check(&self) -> bool {
        // Simple health check - in production this could verify connectivity
        // to the OTel collector or backend
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::waf::security_events::ThreatLevel;
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_otel_export() {
        let exporter = OpenTelemetryExporter::new(
            Some("test-waf".to_string()),
            Some("1.0.0".to_string()),
            true,
            true,
        );

        let event = SecurityEvent {
            id: uuid::Uuid::new_v4(),
            timestamp: chrono::Utc::now(),
            client_ip: "192.168.1.100".parse().unwrap(),
            client_port: Some(12345),
            server_ip: Some("10.0.0.1".to_string()),
            server_port: Some(80),
            method: "GET".to_string(),
            path: "/api/test".to_string(),
            http_version: "1.1".to_string(),
            user_agent: Some("Test Agent".to_string()),
            decision: WafDecision::Block,
            threat_level: ThreatLevel::High,
            triggered_rules: vec!["TEST_RULE".to_string()],
            request_size: Some(512),
            response_status: Some(403),
            response_size: Some(256),
            processing_time_ms: Some(10),
            country_code: Some("US".to_string()),
            region: None,
            city: None,
            asn: Some(15169),
            custom_fields: HashMap::new(),
        };

        // This should not panic or return errors
        let result = exporter.export_event(&event).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_attribute_sanitization() {
        let exporter = OpenTelemetryExporter::new(None, None, true, true);

        let sanitized = exporter.sanitize_attribute_key("Test-Key With Spaces!");
        assert_eq!(sanitized, "test_key_with_spaces_");
    }
}
