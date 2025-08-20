//! Common Event Format (CEF) Exporter
//!
//! CEF (Common Event Format) is a standard format used by ArcSight and many SIEM systems.
//! Format: CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|[Extension]

use super::{ExportResult, SecurityEventExporter};
use crate::waf::security_events::{SecurityEvent, ThreatLevel, WafDecision};
use async_trait::async_trait;
use std::fmt::Write;
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tracing::{debug, error};

/// CEF exporter for security events
pub struct CefExporter {
    output_file: Option<String>,
    device_vendor: String,
    device_product: String,
    device_version: String,
}

impl CefExporter {
    /// Create a new CEF exporter
    pub fn new(
        output_file: Option<String>,
        device_vendor: Option<String>,
        device_product: Option<String>,
        device_version: Option<String>,
    ) -> Self {
        Self {
            output_file,
            device_vendor: device_vendor.unwrap_or_else(|| "WAF-Rejected".to_string()),
            device_product: device_product.unwrap_or_else(|| "Security WAF".to_string()),
            device_version: device_version.unwrap_or_else(|| "1.0.0".to_string()),
        }
    }

    /// Format security event as CEF string
    fn format_cef(&self, event: &SecurityEvent) -> String {
        let mut cef = String::new();

        // CEF Header: CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity
        write!(
            &mut cef,
            "CEF:1|{}|{}|{}|{}|{}|{}",
            self.device_vendor,
            self.device_product,
            self.device_version,
            self.get_event_class_id(&event.decision, &event.threat_level),
            self.get_event_name(&event.decision, &event.threat_level),
            self.get_cef_severity(&event.threat_level)
        )
        .unwrap();

        // CEF Extensions
        let extensions = self.build_extensions(event);
        if !extensions.is_empty() {
            cef.push('|');
            cef.push_str(&extensions);
        }

        cef
    }

    /// Get CEF event class ID based on decision and threat level
    fn get_event_class_id(
        &self,
        decision: &WafDecision,
        threat_level: &ThreatLevel,
    ) -> &'static str {
        match decision {
            WafDecision::Allow => "WAF_ALLOW",
            WafDecision::Block => match threat_level {
                ThreatLevel::Critical => "WAF_BLOCK_CRITICAL",
                ThreatLevel::High => "WAF_BLOCK_HIGH",
                ThreatLevel::Medium => "WAF_BLOCK_MEDIUM",
                ThreatLevel::Low => "WAF_BLOCK_LOW",
            },
            WafDecision::Challenge => "WAF_CHALLENGE",
            WafDecision::Monitor => "WAF_MONITOR",
        }
    }

    /// Get human-readable event name
    fn get_event_name(&self, decision: &WafDecision, threat_level: &ThreatLevel) -> String {
        match decision {
            WafDecision::Allow => "WAF Request Allowed".to_string(),
            WafDecision::Block => format!("WAF Request Blocked - {} Threat", threat_level),
            WafDecision::Challenge => "WAF Challenge Issued".to_string(),
            WafDecision::Monitor => "WAF Request Monitored".to_string(),
        }
    }

    /// Convert threat level to CEF severity (0-10 scale)
    fn get_cef_severity(&self, threat_level: &ThreatLevel) -> u8 {
        match threat_level {
            ThreatLevel::Low => 3,
            ThreatLevel::Medium => 6,
            ThreatLevel::High => 8,
            ThreatLevel::Critical => 10,
        }
    }

    /// Build CEF extension fields
    fn build_extensions(&self, event: &SecurityEvent) -> String {
        let mut extensions = Vec::new();

        // Basic fields
        extensions.push(format!("rt={}", event.timestamp.timestamp_millis()));
        extensions.push(format!("src={}", event.client_ip));
        extensions.push(format!("spt={}", event.client_port.unwrap_or(0)));
        extensions.push(format!(
            "dst={}",
            event.server_ip.as_deref().unwrap_or("unknown")
        ));
        extensions.push(format!("dpt={}", event.server_port.unwrap_or(80)));
        extensions.push(format!("requestMethod={}", event.method));
        extensions.push(format!("requestURL={}", event.path));
        extensions.push(format!("requestProtocol=HTTP/{}", event.http_version));

        // User agent (escape special characters)
        if let Some(user_agent) = &event.user_agent {
            extensions.push(format!(
                "requestClientApplication={}",
                self.escape_cef_value(user_agent)
            ));
        }

        // Request size
        if let Some(size) = event.request_size {
            extensions.push(format!("requestSize={}", size));
        }

        // Response status
        if let Some(status) = event.response_status {
            extensions.push(format!("responseStatus={}", status));
        }

        // Response size
        if let Some(size) = event.response_size {
            extensions.push(format!("responseSize={}", size));
        }

        // Processing time
        if let Some(duration) = event.processing_time_ms {
            extensions.push(format!("processingTime={}", duration));
        }

        // Threat information
        extensions.push(format!("threatLevel={}", event.threat_level));

        if !event.triggered_rules.is_empty() {
            let rules = event.triggered_rules.join(",");
            extensions.push(format!("triggeredRules={}", self.escape_cef_value(&rules)));
        }

        // Geographic information
        if let Some(country) = &event.country_code {
            extensions.push(format!("sourceGeoCountry={}", country));
        }

        if let Some(region) = &event.region {
            extensions.push(format!("sourceGeoRegion={}", self.escape_cef_value(region)));
        }

        if let Some(city) = &event.city {
            extensions.push(format!("sourceGeoCity={}", self.escape_cef_value(city)));
        }

        // ASN information
        if let Some(asn) = event.asn {
            extensions.push(format!("sourceASN={}", asn));
        }

        // Custom fields
        for (key, value) in &event.custom_fields {
            extensions.push(format!(
                "{}={}",
                self.sanitize_field_name(key),
                self.escape_cef_value(value)
            ));
        }

        extensions.join(" ")
    }

    /// Escape CEF special characters in field values
    fn escape_cef_value(&self, value: &str) -> String {
        value
            .replace('\\', "\\\\") // Backslash must be first
            .replace('=', "\\=") // Equals sign
            .replace('\n', "\\n") // Newline
            .replace('\r', "\\r") // Carriage return
    }

    /// Sanitize field names for CEF compliance
    fn sanitize_field_name(&self, name: &str) -> String {
        name.chars()
            .map(|c| {
                if c.is_alphanumeric() || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect()
    }

    /// Write CEF log to file or stdout
    async fn write_cef_log(&self, cef_line: &str) -> ExportResult {
        let log_line = format!("{}\n", cef_line);

        match &self.output_file {
            Some(file_path) => {
                let mut file = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(file_path)
                    .await
                    .map_err(|e| format!("Failed to open CEF log file {}: {}", file_path, e))?;

                file.write_all(log_line.as_bytes())
                    .await
                    .map_err(|e| format!("Failed to write CEF log: {}", e))?;

                file.flush()
                    .await
                    .map_err(|e| format!("Failed to flush CEF log: {}", e))?;
            }
            None => {
                // Write to stdout if no file specified
                print!("{}", log_line);
            }
        }

        Ok(())
    }
}

#[async_trait]
impl SecurityEventExporter for CefExporter {
    async fn export_event(&self, event: &SecurityEvent) -> ExportResult {
        let cef_line = self.format_cef(event);

        debug!("Exporting CEF event: {}", cef_line);

        self.write_cef_log(&cef_line).await?;

        Ok(())
    }

    async fn export_batch(&self, events: &[SecurityEvent]) -> ExportResult {
        for event in events {
            if let Err(e) = self.export_event(event).await {
                error!("Failed to export CEF event: {}", e);
                // Continue with other events rather than failing the entire batch
            }
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "CEF"
    }

    async fn health_check(&self) -> bool {
        // Check if we can write to the output file
        if let Some(file_path) = &self.output_file {
            match OpenOptions::new().append(true).open(file_path).await {
                Ok(_) => true,
                Err(e) => {
                    error!(
                        "CEF exporter health check failed for file {}: {}",
                        file_path, e
                    );
                    false
                }
            }
        } else {
            true // stdout is always available
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::waf::security_events::ThreatLevel;
    use std::collections::HashMap;

    #[test]
    fn test_cef_formatting() {
        let exporter = CefExporter::new(None, None, None, None);

        let mut custom_fields = HashMap::new();
        custom_fields.insert("attack_type".to_string(), "sql_injection".to_string());

        let event = SecurityEvent {
            id: uuid::Uuid::new_v4(),
            timestamp: Utc::now(),
            client_ip: "192.168.1.100".parse().unwrap(),
            client_port: Some(12345),
            server_ip: Some("10.0.0.1".to_string()),
            server_port: Some(80),
            method: "POST".to_string(),
            path: "/api/login".to_string(),
            http_version: "1.1".to_string(),
            user_agent: Some("Mozilla/5.0".to_string()),
            decision: WafDecision::Block,
            threat_level: ThreatLevel::High,
            triggered_rules: vec!["SQL_INJECTION".to_string()],
            request_size: Some(1024),
            response_status: Some(403),
            response_size: Some(512),
            processing_time_ms: Some(15),
            country_code: Some("US".to_string()),
            region: Some("California".to_string()),
            city: Some("San Francisco".to_string()),
            asn: Some(15169),
            custom_fields,
        };

        let cef = exporter.format_cef(&event);

        assert!(cef.starts_with("CEF:1|WAF-Rejected|Security WAF|1.0.0|WAF_BLOCK_HIGH|"));
        assert!(cef.contains("src=192.168.1.100"));
        assert!(cef.contains("requestMethod=POST"));
        assert!(cef.contains("threatLevel=High"));
        assert!(cef.contains("attack_type=sql_injection"));
    }
}
