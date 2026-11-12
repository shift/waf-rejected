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

#[cfg(feature = "export-redb")]
use super::exporters::RedbExporter;

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
    /// Total time from request receipt to the audit record being written.
    pub processing_time_ms: Option<u64>,
    /// WAF inspection time, measured from request receipt to the decision.
    #[serde(default)]
    pub inspection_duration_ms: Option<u64>,
    /// Upstream round-trip time, when a response was forwarded from an origin.
    #[serde(default)]
    pub upstream_duration_ms: Option<u64>,

    /// Geographic and network context
    pub country_code: Option<String>,
    pub region: Option<String>,
    pub city: Option<String>,
    pub asn: Option<u32>,

    /// Custom fields for extensibility
    pub custom_fields: HashMap<String, String>,
}

/// Final response and timing details for an audit event.
///
/// The WAF decision is made before the upstream response exists, so the
/// proxy defers the audit record until the final status is known and fills
/// these fields in. `Default` preserves the decision-only event shape for
/// callers that audit at evaluation time.
#[derive(Debug, Clone, Copy, Default)]
pub struct EventDetails {
    /// Final HTTP status sent to the client (block, error or upstream).
    pub response_status: Option<u16>,
    /// Size of the response body when known.
    pub response_size: Option<u64>,
    /// Time spent in WAF inspection.
    pub inspection_duration_ms: Option<u64>,
    /// Time spent waiting for the upstream response.
    pub upstream_duration_ms: Option<u64>,
    /// Total request lifetime when a later stage measured it.
    pub total_duration_ms: Option<u64>,
}

impl EventDetails {
    /// Status implied by a decision. Allowed requests have no known upstream
    /// status at inspection time, so they stay `None` rather than a made-up
    /// `200`.
    pub fn from_decision(decision: &Decision) -> Self {
        Self {
            response_status: match decision {
                Decision::Block { status, .. } => Some(*status),
                Decision::RateLimit { .. } => Some(429),
                Decision::Allow => None,
            },
            ..Self::default()
        }
    }
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

        // Add the persistent event store. redb is the default when a store is
        // selected; sled remains available as the legacy backend.
        match config.resolved_store_backend() {
            #[cfg(feature = "export-redb")]
            Some("redb") => {
                let path = config.resolved_store_path();
                match RedbExporter::new(&path, config.resolved_store_max_events()) {
                    Ok(exporter) => {
                        dispatcher.add_exporter(exporter);
                    }
                    Err(e) => {
                        tracing::error!("Failed to initialize redb event store at {}: {}", path, e);
                    }
                }
            }
            #[cfg(feature = "export-sled")]
            Some("sled") => {
                let sled_path = config
                    .store_path
                    .as_deref()
                    .or(config.sled_db_path.as_deref())
                    .unwrap_or("./waf_security_events.sled");
                match SledExporter::new(
                    sled_path,
                    Some("security_events".to_string()),
                    config.resolved_store_max_events(),
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
            #[cfg(not(feature = "export-redb"))]
            Some("redb") => {
                tracing::error!(
                    "waf.security_events.store_backend = \"redb\" but this build has no \
                     `export-redb` feature; no persistent event store is active"
                );
            }
            #[cfg(not(feature = "export-sled"))]
            Some("sled") => {
                tracing::error!(
                    "waf.security_events.store_backend = \"sled\" but this build has no \
                     `export-sled` feature; no persistent event store is active"
                );
            }
            _ => {}
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
        self.log_event_with_details(
            ctx,
            decision,
            triggered_rules,
            EventDetails::from_decision(decision),
        )
        .await;
    }

    /// Audit an evaluation with the final response status and timings.
    ///
    /// The proxy uses this for deferred audit after the upstream response (or
    /// a block/error response) is known, so the record reflects the status the
    /// client actually received.
    pub async fn log_event_with_details(
        &self,
        ctx: &RequestContext,
        decision: &Decision,
        triggered_rules: Vec<String>,
        details: EventDetails,
    ) {
        if !self.config.enabled {
            return;
        }

        // Determine the level before constructing the event. The default
        // minimum is `medium`, so allowed requests (level `low`) return here
        // without a UUID, timestamp, header strings or a `HashMap`.
        let threat_level = self.determine_threat_level(decision, &triggered_rules);
        if !self.threat_level_logged(threat_level) {
            return;
        }

        let event = self.create_security_event_with_level(
            ctx,
            decision,
            triggered_rules,
            threat_level,
            details,
        );

        // Export through dispatcher (handles CEF, OTel, etc.)
        if let Err(e) = self.dispatcher.export_event(&event).await {
            tracing::error!("Failed to export security event {}: {}", event.id, e);
        }

        // Always do basic tracing output as fallback
        self.log_to_tracing(&event, decision);
    }

    /// Create a comprehensive security event from request context
    fn create_security_event_with_level(
        &self,
        ctx: &RequestContext,
        decision: &Decision,
        triggered_rules: Vec<String>,
        threat_level: ThreatLevel,
        details: EventDetails,
    ) -> SecurityEvent {
        let now_ms = ctx.timestamp.elapsed().as_millis() as u64;
        let response_status = details
            .response_status
            .or_else(|| EventDetails::from_decision(decision).response_status);

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
            http_version: ctx.http_version.to_string(),
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
            response_status,
            response_size: details.response_size,
            processing_time_ms: Some(details.total_duration_ms.unwrap_or(now_ms)),
            inspection_duration_ms: Some(details.inspection_duration_ms.unwrap_or(now_ms)),
            upstream_duration_ms: details.upstream_duration_ms,

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
        self.threat_level_logged(event.threat_level)
    }

    /// Minimum-level check without allocating a lowercase copy of the
    /// configured level. Used on the hot audit path before event construction.
    fn threat_level_logged(&self, level: ThreatLevel) -> bool {
        let min_level = self.config.min_threat_level.as_str();
        if min_level.eq_ignore_ascii_case("low") {
            return true;
        }
        if min_level.eq_ignore_ascii_case("medium") {
            return matches!(
                level,
                ThreatLevel::Medium | ThreatLevel::High | ThreatLevel::Critical
            );
        }
        if min_level.eq_ignore_ascii_case("high") {
            return matches!(level, ThreatLevel::High | ThreatLevel::Critical);
        }
        if min_level.eq_ignore_ascii_case("critical") {
            return matches!(level, ThreatLevel::Critical);
        }
        false
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

    /// Whether allowed requests produce audit records under the configured
    /// minimum threat level. The proxy uses this to avoid cloning the request
    /// context on the hot allow path when the event would be filtered anyway.
    pub fn logs_allowed_requests(&self) -> bool {
        self.config.enabled && self.threat_level_logged(ThreatLevel::Low)
    }

    /// Per-exporter health, used by readiness. Includes the event store
    /// (`Sled`) when it is configured.
    pub async fn exporter_health(&self) -> Vec<(String, bool)> {
        self.dispatcher.health_check_all().await
    }

    /// Exporters selected by configuration, whether or not the build feature
    /// is available. Readiness treats a configured-but-missing exporter as a
    /// down dependency rather than silently ignoring it.
    pub fn configured_exporters(&self) -> Vec<&'static str> {
        let mut exporters = Vec::new();
        if self.config.enable_cef {
            exporters.push("CEF");
        }
        if self.config.enable_otel {
            exporters.push("OpenTelemetry");
        }
        match self.config.resolved_store_backend() {
            Some("redb") => exporters.push("Redb"),
            Some("sled") => exporters.push("Sled"),
            _ => {}
        }
        exporters
    }

    /// Whether the persistent event store is configured for this process.
    pub fn event_store_configured(&self) -> bool {
        self.config.resolved_store_backend().is_some()
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
    fn audit_event_records_protocol_version_and_block_status() {
        let logger = SecurityEventLogger::new(SecurityEventsConfig {
            min_threat_level: "low".to_string(),
            ..Default::default()
        });
        let h2 = RequestContext::with_http_version(
            IpAddr::from_str("192.168.1.100").unwrap(),
            Method::GET,
            Uri::from_str("/api/h2").unwrap(),
            HeaderMap::new(),
            Some(0),
            "2",
        );
        let h11 = RequestContext::with_http_version(
            IpAddr::from_str("192.168.1.100").unwrap(),
            Method::GET,
            Uri::from_str("/api/h11").unwrap(),
            HeaderMap::new(),
            Some(0),
            "1.1",
        );
        let block = Decision::Block {
            status: 403,
            reason: "test".to_string(),
        };

        let event_h2 = logger.create_security_event_with_level(
            &h2,
            &block,
            vec!["rule".to_string()],
            ThreatLevel::Medium,
            EventDetails::default(),
        );
        let event_h11 = logger.create_security_event_with_level(
            &h11,
            &block,
            vec!["rule".to_string()],
            ThreatLevel::Medium,
            EventDetails::default(),
        );

        assert_eq!(event_h2.http_version, "2");
        assert_eq!(event_h11.http_version, "1.1");
        assert_eq!(event_h2.response_status, Some(403));
        assert_eq!(event_h11.response_status, Some(403));
        assert!(event_h2.inspection_duration_ms.is_some());
        assert_eq!(event_h2.upstream_duration_ms, None);
    }

    #[test]
    fn audit_event_records_upstream_502_and_timings() {
        let logger = SecurityEventLogger::new(SecurityEventsConfig {
            min_threat_level: "low".to_string(),
            ..Default::default()
        });
        let ctx = RequestContext::with_http_version(
            IpAddr::from_str("192.168.1.100").unwrap(),
            Method::GET,
            Uri::from_str("/api/upstream").unwrap(),
            HeaderMap::new(),
            Some(0),
            "1.1",
        );
        let event = logger.create_security_event_with_level(
            &ctx,
            &Decision::Allow,
            vec![],
            ThreatLevel::Low,
            EventDetails {
                response_status: Some(502),
                inspection_duration_ms: Some(3),
                upstream_duration_ms: Some(17),
                total_duration_ms: Some(20),
                ..EventDetails::default()
            },
        );

        assert_eq!(event.response_status, Some(502));
        assert_eq!(event.inspection_duration_ms, Some(3));
        assert_eq!(event.upstream_duration_ms, Some(17));
        assert_eq!(event.processing_time_ms, Some(20));
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
            inspection_duration_ms: None,
            upstream_duration_ms: None,
            country_code: None,
            region: None,
            city: None,
            asn: None,
            custom_fields: HashMap::new(),
        }
    }
}
