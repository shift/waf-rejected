use crate::config::SecurityEventsConfig;
use crate::waf::{Decision, RequestContext};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;

// Import exporters
use super::exporters::{CefExporter, ExporterDispatcher, SecurityEventExporter};

#[cfg(feature = "export-otel")]
use super::exporters::OpenTelemetryExporter;

#[cfg(feature = "export-sled")]
use super::exporters::SledExporter;

/// Enhanced security event structure for comprehensive logging and export
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    /// Unique event identifier
    pub id: uuid::Uuid,
    /// Event timestamp
    pub timestamp: DateTime<Utc>,

    /// Network information
    pub client_ip: IpAddr,
    pub client_port: Option<u16>,
    pub server_ip: Option<String>,
    pub server_port: Option<u16>,

    /// HTTP request details
    pub method: String,
    pub path: String,
    pub http_version: String,
    pub user_agent: Option<String>,

    /// WAF decision and threat assessment
    pub decision: WafDecision,
    pub threat_level: ThreatLevel,
    pub triggered_rules: Vec<String>,

    /// Request/response metrics
    pub request_size: Option<u64>,
    pub response_status: Option<u16>,
    pub response_size: Option<u64>,
    pub processing_time_ms: Option<u64>,

    /// Geographic and network context
    pub country_code: Option<String>,
    pub region: Option<String>,
    pub city: Option<String>,
    pub asn: Option<u32>,

    /// Custom fields for extensibility
    pub custom_fields: HashMap<String, String>,
}

/// WAF decision enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WafDecision {
    Allow,
    Block,
    Challenge,
    Monitor,
}

impl fmt::Display for WafDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WafDecision::Allow => write!(f, "Allow"),
            WafDecision::Block => write!(f, "Block"),
            WafDecision::Challenge => write!(f, "Challenge"),
            WafDecision::Monitor => write!(f, "Monitor"),
        }
    }
}

/// Threat level enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThreatLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for ThreatLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ThreatLevel::Low => write!(f, "Low"),
            ThreatLevel::Medium => write!(f, "Medium"),
            ThreatLevel::High => write!(f, "High"),
            ThreatLevel::Critical => write!(f, "Critical"),
        }
    }
}

// Legacy types for backward compatibility
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityEventType {
    BlockedRequest,
    RateLimited,
    SuspiciousActivity,
    AttackAttempt,
    AllowedRequest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecuritySeverity {
    Low,
    Medium,
    High,
    Critical,
}

// Legacy decision type for backward compatibility
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityEventDecision {
    Allow,
    Block { status: u16, reason: String },
    RateLimit { reason: String },
}

impl From<&Decision> for WafDecision {
    fn from(decision: &Decision) -> Self {
        match decision {
            Decision::Allow => WafDecision::Allow,
            Decision::Block { .. } => WafDecision::Block,
            Decision::RateLimit { .. } => WafDecision::Monitor,
        }
    }
}

impl From<&Decision> for SecurityEventDecision {
    fn from(decision: &Decision) -> Self {
        match decision {
            Decision::Allow => SecurityEventDecision::Allow,
            Decision::Block { status, reason } => SecurityEventDecision::Block {
                status: *status,
                reason: reason.clone(),
            },
            Decision::RateLimit { reason } => SecurityEventDecision::RateLimit {
                reason: reason.clone(),
            },
        }
    }
}

/// Enhanced security event logger with multiple export capabilities
pub struct SecurityEventLogger {
    dispatcher: ExporterDispatcher,
    config: SecurityEventsConfig,
}

impl SecurityEventLogger {
    /// Create a new security event logger with configuration
    pub fn new(config: SecurityEventsConfig) -> Self {
        let mut dispatcher = ExporterDispatcher::new(false); // Don't fail fast for resilience

        // Add CEF exporter if enabled
        if config.enable_cef {
            let cef_exporter = CefExporter::new(
                config.cef_output_file.clone(),
                config.cef_device_vendor.clone(),
                config.cef_device_product.clone(),
                config.cef_device_version.clone(),
            );
            dispatcher.add_exporter(cef_exporter);
        }

        // Add OpenTelemetry exporter if enabled
        #[cfg(feature = "export-otel")]
        if config.enable_otel {
            let otel_exporter = OpenTelemetryExporter::new(
                config.otel_service_name.clone(),
                config.otel_service_version.clone(),
                config.otel_export_traces.unwrap_or(true),
                config.otel_export_logs.unwrap_or(true),
            );
            dispatcher.add_exporter(otel_exporter);
        }

        // Add Sled database exporter if enabled
        #[cfg(feature = "export-sled")]
        if config.enable_sled {
            let sled_path = config
                .sled_db_path
                .as_deref()
                .unwrap_or("./waf_security_events.sled");
            match SledExporter::new(
                sled_path,
                Some("security_events".to_string()),
                config.sled_max_events,
                config.sled_compress,
            ) {
                Ok(sled_exporter) => {
                    dispatcher.add_exporter(sled_exporter);
                }
                Err(e) => {
                    tracing::error!("Failed to initialize Sled exporter: {}", e);
                }
            }
        }

        Self { dispatcher, config }
    }

    /// Create a default logger with basic tracing output
    pub fn default_logger() -> Self {
        let config = SecurityEventsConfig::default();
        Self::new(config)
    }

    /// Log a security event from WAF evaluation with enhanced data
    pub async fn log_event(
        &self,
        ctx: &RequestContext,
        decision: &Decision,
        triggered_rules: Vec<String>,
    ) {
        if !self.config.enabled {
            return;
        }
        let event = self.create_security_event(ctx, decision, triggered_rules);

        // Skip events below minimum threat level
        if !self.should_log_event(&event) {
            return;
        }

        // Export through dispatcher (handles CEF, OTel, etc.)
        if let Err(e) = self.dispatcher.export_event(&event).await {
            tracing::error!("Failed to export security event {}: {}", event.id, e);
        }

        // Always do basic tracing output as fallback
        self.log_to_tracing(&event, decision);
    }

    /// Create a comprehensive security event from request context
    fn create_security_event(
        &self,
        ctx: &RequestContext,
        decision: &Decision,
        triggered_rules: Vec<String>,
    ) -> SecurityEvent {
        let threat_level = self.determine_threat_level(decision, &triggered_rules);

        SecurityEvent {
            id: uuid::Uuid::new_v4(),
            timestamp: Utc::now(),

            // Network information
            client_ip: ctx.client_ip,
            client_port: None, // TODO: Extract from connection if available
            server_ip: None,   // TODO: Extract from server context
            server_port: None, // TODO: Extract from server context

            // HTTP request details
            method: ctx.method.to_string(),
            path: ctx.uri.to_string(),
            http_version: "1.1".to_string(), // TODO: Extract actual HTTP version
            user_agent: ctx
                .headers
                .get("user-agent")
                .and_then(|h| h.to_str().ok())
                .map(|s| s.to_string()),

            // WAF decision and threat assessment
            decision: decision.into(),
            threat_level,
            triggered_rules,

            // Request/response metrics
            request_size: ctx.body_size.map(|size| size as u64),
            response_status: match decision {
                Decision::Block { status, .. } => Some(*status),
                Decision::Allow => Some(200), // Assume success for allowed requests
                Decision::RateLimit { .. } => Some(429),
            },
            response_size: None,      // TODO: Track response size
            processing_time_ms: None, // TODO: Track processing time

            // Geographic and network context (TODO: Implement GeoIP lookup)
            country_code: None,
            region: None,
            city: None,
            asn: None,

            // Custom fields for extensibility
            custom_fields: self.build_custom_fields(ctx, decision),
        }
    }

    /// Determine if event should be logged based on threat level
    fn should_log_event(&self, event: &SecurityEvent) -> bool {
        let min_level = self.config.min_threat_level.to_ascii_lowercase();

        match (min_level.as_str(), &event.threat_level) {
            ("low", _) => true,
            ("medium", ThreatLevel::Medium | ThreatLevel::High | ThreatLevel::Critical) => true,
            ("high", ThreatLevel::High | ThreatLevel::Critical) => true,
            ("critical", ThreatLevel::Critical) => true,
            _ => false,
        }
    }

    /// Determine threat level based on decision and triggered rules
    fn determine_threat_level(
        &self,
        decision: &Decision,
        triggered_rules: &[String],
    ) -> ThreatLevel {
        match decision {
            Decision::Allow => ThreatLevel::Low,
            Decision::RateLimit { .. } => ThreatLevel::Medium,
            Decision::Block { status, .. } => {
                // Higher threat level based on status code and rules
                if triggered_rules
                    .iter()
                    .any(|rule| rule.contains("SQL") || rule.contains("XSS"))
                {
                    ThreatLevel::High
                } else if *status >= 500 {
                    ThreatLevel::High
                } else if triggered_rules.len() > 3 {
                    ThreatLevel::High
                } else {
                    ThreatLevel::Medium
                }
            }
        }
    }

    /// Build custom fields from context and decision
    fn build_custom_fields(
        &self,
        ctx: &RequestContext,
        decision: &Decision,
    ) -> HashMap<String, String> {
        let mut fields = HashMap::new();

        // Add referer if available
        if let Some(referer) = ctx.headers.get("referer").and_then(|h| h.to_str().ok()) {
            fields.insert("referer".to_string(), referer.to_string());
        }

        // Add x-forwarded-for if available
        if let Some(xff) = ctx
            .headers
            .get("x-forwarded-for")
            .and_then(|h| h.to_str().ok())
        {
            fields.insert("x_forwarded_for".to_string(), xff.to_string());
        }

        // Add decision reason if available
        match decision {
            Decision::Block { reason, .. } | Decision::RateLimit { reason } => {
                fields.insert("block_reason".to_string(), reason.clone());
            }
            _ => {}
        }

        fields
    }

    /// Fallback tracing output (legacy compatibility)
    fn log_to_tracing(&self, event: &SecurityEvent, decision: &Decision) {
        match decision {
            Decision::Allow => {
                tracing::info!(
                    event_id = %event.id,
                    client_ip = %event.client_ip,
                    method = %event.method,
                    path = %event.path,
                    decision = "allow",
                    threat_level = %event.threat_level,
                    "Security event: request allowed"
                );
            }
            Decision::Block { status, reason } => {
                tracing::warn!(
                    event_id = %event.id,
                    client_ip = %event.client_ip,
                    method = %event.method,
                    path = %event.path,
                    status = status,
                    reason = %reason,
                    rules = ?event.triggered_rules,
                    threat_level = %event.threat_level,
                    decision = "block",
                    "Security event: request blocked"
                );
            }
            Decision::RateLimit { reason } => {
                tracing::warn!(
                    event_id = %event.id,
                    client_ip = %event.client_ip,
                    method = %event.method,
                    path = %event.path,
                    reason = %reason,
                    rules = ?event.triggered_rules,
                    threat_level = %event.threat_level,
                    decision = "rate_limit",
                    "Security event: request rate limited"
                );
            }
        }
    }

    /// Get exporter health status
    pub async fn health_check(&self) -> bool {
        self.dispatcher.health_check().await
    }

    /// Flush all exporters
    pub async fn flush(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.dispatcher.flush().await
    }

    /// Get list of active exporters
    pub fn active_exporters(&self) -> Vec<&'static str> {
        self.dispatcher.exporter_names()
    }

    /// Get recent events from Sled database if available
    pub async fn get_recent_events(
        &self,
        _limit: usize,
    ) -> Result<Vec<SecurityEvent>, Box<dyn std::error::Error + Send + Sync>> {
        // This is a simple implementation - in a real system you'd want to track which exporter is Sled
        // For now, return an error indicating this feature needs the specific Sled instance
        Err("Direct event retrieval requires access to specific Sled exporter instance".into())
    }

    // Legacy methods for backward compatibility
    fn classify_event_type(&self, decision: &Decision) -> SecurityEventType {
        match decision {
            Decision::Allow => SecurityEventType::AllowedRequest,
            Decision::Block { .. } => SecurityEventType::BlockedRequest,
            Decision::RateLimit { .. } => SecurityEventType::RateLimited,
        }
    }

    fn determine_severity(&self, decision: &Decision) -> SecuritySeverity {
        match decision {
            Decision::Allow => SecuritySeverity::Low,
            Decision::RateLimit { .. } => SecuritySeverity::Medium,
            Decision::Block { status, .. } => match *status {
                400..=499 => SecuritySeverity::Medium,
                500..=599 => SecuritySeverity::High,
                _ => SecuritySeverity::Medium,
            },
        }
    }

    fn safe_headers(&self, headers: &hyper::HeaderMap) -> serde_json::Value {
        let mut safe_headers = serde_json::Map::new();

        // Only include safe headers, exclude sensitive ones
        let safe_header_names = [
            "user-agent",
            "accept",
            "accept-language",
            "accept-encoding",
            "content-type",
            "content-length",
            "x-forwarded-for",
            "x-real-ip",
        ];

        for name in &safe_header_names {
            if let Some(value) = headers.get(*name) {
                if let Ok(value_str) = value.to_str() {
                    safe_headers.insert(
                        name.to_string(),
                        serde_json::Value::String(value_str.to_string()),
                    );
                }
            }
        }

        serde_json::Value::Object(safe_headers)
    }
}

impl Default for SecurityEventLogger {
    fn default() -> Self {
        Self::default_logger()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::{HeaderMap, Method, Uri};
    use std::str::FromStr;

    fn create_test_context() -> RequestContext {
        let mut headers = HeaderMap::new();
        headers.insert("user-agent", "test-browser/1.0".parse().unwrap());
        headers.insert("x-forwarded-for", "203.0.113.1".parse().unwrap());

        RequestContext::new(
            IpAddr::from_str("192.168.1.100").unwrap(),
            Method::GET,
            Uri::from_str("/api/test").unwrap(),
            headers,
            Some(1024),
        )
    }

    #[tokio::test]
    async fn test_security_event_creation() {
        let logger = SecurityEventLogger::default_logger();
        let ctx = create_test_context();
        let decision = Decision::Allow;

        // Should not panic
        logger.log_event(&ctx, &decision, vec![]).await;
    }

    #[test]
    fn test_waf_decision_conversion() {
        let allow_decision = Decision::Allow;
        let converted: WafDecision = (&allow_decision).into();

        assert_eq!(converted, WafDecision::Allow);

        let block_decision = Decision::Block {
            status: 403,
            reason: "Blocked by rule".to_string(),
        };
        let converted: WafDecision = (&block_decision).into();

        assert_eq!(converted, WafDecision::Block);

        let rate_limit_decision = Decision::RateLimit {
            reason: "Too many requests".to_string(),
        };
        let converted: WafDecision = (&rate_limit_decision).into();

        assert_eq!(converted, WafDecision::Monitor);
    }

    #[test]
    fn test_event_type_classification() {
        let logger = SecurityEventLogger::default_logger();

        assert!(matches!(
            logger.classify_event_type(&Decision::Allow),
            SecurityEventType::AllowedRequest
        ));

        assert!(matches!(
            logger.classify_event_type(&Decision::Block {
                status: 403,
                reason: "test".to_string()
            }),
            SecurityEventType::BlockedRequest
        ));

        assert!(matches!(
            logger.classify_event_type(&Decision::RateLimit {
                reason: "test".to_string()
            }),
            SecurityEventType::RateLimited
        ));
    }

    #[test]
    fn test_severity_determination() {
        let logger = SecurityEventLogger::default_logger();

        assert!(matches!(
            logger.determine_severity(&Decision::Allow),
            SecuritySeverity::Low
        ));

        assert!(matches!(
            logger.determine_severity(&Decision::Block {
                status: 403,
                reason: "test".to_string()
            }),
            SecuritySeverity::Medium
        ));

        assert!(matches!(
            logger.determine_severity(&Decision::RateLimit {
                reason: "test".to_string()
            }),
            SecuritySeverity::Medium
        ));
    }

    #[test]
    fn test_threat_level_determination() {
        let logger = SecurityEventLogger::default_logger();

        assert_eq!(
            logger.determine_threat_level(&Decision::Allow, &[]),
            ThreatLevel::Low
        );

        assert_eq!(
            logger.determine_threat_level(
                &Decision::Block {
                    status: 403,
                    reason: "test".to_string()
                },
                &["SQL_INJECTION".to_string()]
            ),
            ThreatLevel::High
        );

        assert_eq!(
            logger.determine_threat_level(
                &Decision::Block {
                    status: 403,
                    reason: "test".to_string()
                },
                &["GENERIC_RULE".to_string()]
            ),
            ThreatLevel::Medium
        );
    }

    #[tokio::test]
    async fn test_exporter_health_check() {
        // Create logger with custom mock exporter so health check passes
        let config = SecurityEventsConfig::default();
        let mut logger = SecurityEventLogger::new(config);

        // Create a simple mock exporter inline
        use crate::waf::exporters::SecurityEventExporter;
        use async_trait::async_trait;

        struct SimpleMockExporter;

        #[async_trait]
        impl SecurityEventExporter for SimpleMockExporter {
            async fn export_event(
                &self,
                _event: &SecurityEvent,
            ) -> crate::waf::exporters::ExportResult {
                Ok(())
            }

            fn name(&self) -> &'static str {
                "test-mock"
            }

            async fn health_check(&self) -> bool {
                true
            }
        }

        logger.dispatcher.add_exporter(SimpleMockExporter);

        // Should be healthy with mock exporter
        assert!(logger.health_check().await);
    }

    #[test]
    fn test_should_log_event() {
        let config = SecurityEventsConfig {
            min_threat_level: "medium".to_string(),
            ..Default::default()
        };
        let logger = SecurityEventLogger::new(config);

        let low_event = SecurityEvent {
            threat_level: ThreatLevel::Low,
            ..create_test_security_event()
        };
        assert!(!logger.should_log_event(&low_event));

        let medium_event = SecurityEvent {
            threat_level: ThreatLevel::Medium,
            ..create_test_security_event()
        };
        assert!(logger.should_log_event(&medium_event));

        let high_event = SecurityEvent {
            threat_level: ThreatLevel::High,
            ..create_test_security_event()
        };
        assert!(logger.should_log_event(&high_event));
    }

    fn create_test_security_event() -> SecurityEvent {
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
