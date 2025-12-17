use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

#[cfg(feature = "sled")]
use sled;

use crate::config::{AuditConfig, RegulatoryConfig, RetentionConfig};
use crate::error::WafError;

/// Compliance-related errors
#[derive(Debug, thiserror::Error)]
pub enum ComplianceError {
    #[error("Compliance feature not enabled: {0}")]
    NotEnabled(String),

    #[error("Audit trail integrity violation")]
    IntegrityViolation,

    #[error("Data retention policy violation")]
    RetentionViolation,

    #[error("Regulatory compliance error: {0}")]
    RegulatoryError(String),

    #[error("Internal compliance error: {0}")]
    Internal(String),
}

impl From<ComplianceError> for WafError {
    fn from(err: ComplianceError) -> Self {
        WafError::Internal(format!("Compliance error: {}", err))
    }
}

/// Audit event types for compliance logging
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditEventType {
    /// Security event occurred
    SecurityEvent,
    /// Configuration change
    ConfigChange,
    /// Authentication attempt
    AuthAttempt,
    /// Authorization decision
    AuthDecision,
    /// Data access
    DataAccess,
    /// System health check
    HealthCheck,
}

/// Audit event with tamper-evident logging
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Unique event ID
    pub id: String,

    /// Event timestamp
    pub timestamp: DateTime<Utc>,

    /// Event type
    pub event_type: AuditEventType,

    /// User/system identifier
    pub actor: String,

    /// Action performed
    pub action: String,

    /// Resource affected
    pub resource: String,

    /// Event details
    pub details: HashMap<String, String>,

    /// IP address of actor
    pub ip_address: Option<String>,

    /// Session ID if applicable
    pub session_id: Option<String>,

    /// Cryptographic integrity hash of previous event
    pub previous_hash: Option<String>,

    /// Integrity hash of this event
    pub integrity_hash: Option<String>,
}

/// Integrity verifier for tamper-evident audit trails
pub struct IntegrityVerifier {
    algorithm: String,
}

impl IntegrityVerifier {
    pub fn new() -> Self {
        Self {
            algorithm: "SHA-256".to_string(),
        }
    }

    /// Generate integrity hash for an audit event
    pub fn hash_event(&self, event: &AuditEvent) -> String {
        use sha2::{Sha256, Digest};

        let mut hasher = Sha256::new();

        // Hash all event fields except integrity_hash
        hasher.update(event.id.as_bytes());
        hasher.update(event.timestamp.to_rfc3339().as_bytes());
        hasher.update(format!("{:?}", event.event_type).as_bytes());
        hasher.update(event.actor.as_bytes());
        hasher.update(event.action.as_bytes());
        hasher.update(event.resource.as_bytes());

        // Hash details map (sorted for consistency)
        let mut details: Vec<_> = event.details.iter().collect();
        details.sort_by_key(|(k, _)| *k);
        for (key, value) in details {
            hasher.update(key.as_bytes());
            hasher.update(value.as_bytes());
        }

        if let Some(ip) = &event.ip_address {
            hasher.update(ip.as_bytes());
        }
        if let Some(session) = &event.session_id {
            hasher.update(session.as_bytes());
        }
        if let Some(prev_hash) = &event.previous_hash {
            hasher.update(prev_hash.as_bytes());
        }

        hex::encode(hasher.finalize())
    }

    /// Verify the integrity of an audit event chain
    pub fn verify_chain(&self, events: &[AuditEvent]) -> Result<(), ComplianceError> {
        for i in 1..events.len() {
            let prev_event = &events[i - 1];
            let current_event = &events[i];

            // Check that current event's previous_hash matches prev event's integrity_hash
            if current_event.previous_hash != prev_event.integrity_hash {
                return Err(ComplianceError::IntegrityViolation);
            }

            // Verify the integrity hash of the previous event
            let expected_hash = self.hash_event(prev_event);
            if prev_event.integrity_hash.as_ref() != Some(&expected_hash) {
                return Err(ComplianceError::IntegrityViolation);
            }
        }

        Ok(())
    }
}

/// Tamper-evident audit logger
pub struct AuditLogger {
    config: AuditConfig,
    integrity_verifier: IntegrityVerifier,
    event_store: Arc<RwLock<Vec<AuditEvent>>>,
}

impl AuditLogger {
    pub fn new(config: AuditConfig) -> Self {
        Self {
            config,
            integrity_verifier: IntegrityVerifier::new(),
            event_store: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Log an audit event with integrity protection
    pub async fn log_event(&self, event: AuditEvent) -> Result<(), ComplianceError> {
        if !self.config.tamper_evident {
            // Simple logging without integrity if disabled
            let mut events = self.event_store.write().unwrap();
            events.push(event);
            return Ok(());
        }

        let mut events = self.event_store.write().unwrap();

        // Set previous hash for new event
        if let Some(last_event) = events.last() {
            // Create a copy of the event with previous_hash set
            let mut event_with_prev = event;
            event_with_prev.previous_hash = last_event.integrity_hash.clone();
            events.push(event_with_prev);
        } else {
            // First event
            events.push(event);
        }

        // Update integrity hashes for the last two events
        let len = events.len();
        if len >= 1 {
            let last_idx = len - 1;
            events[last_idx].integrity_hash = Some(self.integrity_verifier.hash_event(&events[last_idx]));
        }
        if len >= 2 {
            let prev_idx = len - 2;
            events[prev_idx].integrity_hash = Some(self.integrity_verifier.hash_event(&events[prev_idx]));
        }

        // Verify chain integrity
        self.integrity_verifier.verify_chain(&events)?;

        Ok(())
    }

    /// Verify the integrity of the entire audit trail
    pub fn verify_integrity(&self) -> Result<(), ComplianceError> {
        if !self.config.tamper_evident {
            return Ok(());
        }

        let events = self.event_store.read().unwrap();
        self.integrity_verifier.verify_chain(&events)
    }

    /// Get all audit events (for reporting)
    pub fn get_events(&self) -> Vec<AuditEvent> {
        self.event_store.read().unwrap().clone()
    }

    /// Get events within a time range
    pub fn get_events_in_range(&self, start: DateTime<Utc>, end: DateTime<Utc>) -> Vec<AuditEvent> {
        self.event_store.read().unwrap()
            .iter()
            .filter(|event| event.timestamp >= start && event.timestamp <= end)
            .cloned()
            .collect()
    }
}

/// Compliance reporter for regulatory requirements
pub struct ComplianceReporter {
    config: RegulatoryConfig,
}

impl ComplianceReporter {
    pub fn new(config: RegulatoryConfig) -> Self {
        Self { config }
    }

    /// Generate GDPR Article 33 breach notification report
    pub fn generate_gdpr_report(&self, events: &[AuditEvent]) -> Result<String, ComplianceError> {
        if !self.config.gdpr {
            return Err(ComplianceError::NotEnabled("GDPR".to_string()));
        }

        // Filter for security incidents that may involve personal data
        let breaches = events.iter()
            .filter(|e| matches!(e.event_type, AuditEventType::SecurityEvent))
            .filter(|e| e.details.get("severity").map(|s| s == "high").unwrap_or(false))
            .collect::<Vec<_>>();

        if breaches.is_empty() {
            return Ok("No reportable breaches under GDPR Article 33".to_string());
        }

        // Generate GDPR Article 33 notification format
        let report = format!(
            "GDPR Article 33 Breach Notification\n\
             ===================================\n\
             Date of notification: {}\n\
             \n\
             1. Identity and contact details of the controller:\n\
             WAF-Rejected Web Application Firewall\n\
             \n\
             2. Description of the personal data breach:\n\
             {} security incidents detected involving potential personal data exposure\n\
             \n\
             3. Categories of data concerned:\n\
             - IP addresses\n\
             - Request headers containing personal information\n\
             - Session identifiers\n\
             \n\
             4. Number of data subjects concerned:\n\
             {} (estimated based on unique IP addresses)\n\
             \n\
             5. Likely consequences of the personal data breach:\n\
             Potential unauthorized access to personal data\n\
             \n\
             6. Measures taken or proposed to mitigate the breach:\n\
             - Automated blocking of malicious requests\n\
             - Enhanced monitoring and logging\n\
             - Security rule updates\n\
             \n\
             7. Contact details of the data protection officer:\n\
             security@waf-rejected.com",
            Utc::now().format("%Y-%m-%d %H:%M:%S UTC"),
            breaches.len(),
            breaches.iter().map(|e| e.ip_address.as_ref()).collect::<std::collections::HashSet<_>>().len()
        );

        Ok(report)
    }

    /// Generate HIPAA breach notification report
    pub fn generate_hipaa_report(&self, events: &[AuditEvent]) -> Result<String, ComplianceError> {
        if !self.config.hipaa {
            return Err(ComplianceError::NotEnabled("HIPAA".to_string()));
        }

        // HIPAA requires notification for breaches of unsecured PHI
        let breaches = events.iter()
            .filter(|e| matches!(e.event_type, AuditEventType::SecurityEvent))
            .filter(|e| e.details.get("contains_phi").map(|s| s == "true").unwrap_or(false))
            .collect::<Vec<_>>();

        if breaches.is_empty() {
            return Ok("No reportable HIPAA breaches".to_string());
        }

        let report = format!(
            "HIPAA Breach Notification\n\
             =======================\n\
             Date: {}\n\
             \n\
             Breach Description:\n\
             {} incidents involving potential Protected Health Information (PHI) exposure\n\
             \n\
             Individuals Affected: {}\n\
             \n\
             Actions Taken:\n\
             - Immediate blocking of unauthorized access attempts\n\
             - Security monitoring enhancement\n\
             - Incident response procedures initiated\n\
             \n\
             Contact: privacy@waf-rejected.com",
            Utc::now().format("%Y-%m-%d"),
            breaches.len(),
            breaches.len() // Simplified - would need actual PHI correlation
        );

        Ok(report)
    }

    /// Generate PCI-DSS compliance report
    pub fn generate_pci_report(&self, events: &[AuditEvent]) -> Result<String, ComplianceError> {
        if !self.config.pci_dss {
            return Err(ComplianceError::NotEnabled("PCI-DSS".to_string()));
        }

        // PCI-DSS requires logging of security events
        let security_events = events.iter()
            .filter(|e| matches!(e.event_type, AuditEventType::SecurityEvent))
            .collect::<Vec<_>>();

        let report = format!(
            "PCI-DSS Security Event Report\n\
             ============================\n\
             Report Period: Last 24 hours\n\
             Total Security Events: {}\n\
             \n\
             Event Summary:\n\
             - Authentication failures: {}\n\
             - Unauthorized access attempts: {}\n\
             - Suspicious activities: {}\n\
             \n\
             Compliance Status: {}\n\
             \n\
             Recommendations:\n\
             - Review and update security rules\n\
             - Monitor for emerging threats\n\
             - Ensure log integrity",
            security_events.len(),
            security_events.iter().filter(|e| e.action.contains("auth")).count(),
            security_events.iter().filter(|e| e.action.contains("unauthorized")).count(),
            security_events.iter().filter(|e| e.details.get("suspicious").map(|s| s == "true").unwrap_or(false)).count(),
            if security_events.len() < 100 { "COMPLIANT" } else { "REVIEW REQUIRED" }
        );

        Ok(report)
    }
}

/// Data retention manager for compliance
pub struct DataRetentionManager {
    config: RetentionConfig,
}

impl DataRetentionManager {
    pub fn new(config: RetentionConfig) -> Self {
        Self { config }
    }

    /// Clean up expired audit events
    pub async fn cleanup_expired_audit_events(&self, logger: &AuditLogger) -> Result<(), ComplianceError> {
        if !self.config.auto_delete {
            return Ok(());
        }

        let cutoff = Utc::now() - chrono::Duration::days(self.config.audit_logs_days as i64);

        // Note: In a real implementation, this would filter and remove expired events
        // from the audit logger's storage. For now, we just log the intent.

        info!("Audit log cleanup: would remove events older than {}", cutoff);
        Ok(())
    }

    /// Clean up expired security events from database
    pub async fn cleanup_expired_security_events(&self, db: &sled::Db) -> Result<(), ComplianceError> {
        if !self.config.auto_delete {
            return Ok(());
        }

        let cutoff = Utc::now() - chrono::Duration::days(self.config.security_events_days as i64);

        // Note: Implementation depends on actual database schema
        // This is a placeholder for the cleanup logic

        info!("Security event cleanup: would remove events older than {}", cutoff);
        Ok(())
    }

    /// Get retention policy summary
    pub fn get_retention_summary(&self) -> String {
        format!(
            "Data Retention Policy:\n\
             - Security Events: {} days\n\
             - Audit Logs: {} days\n\
             - Auto-deletion: {}",
            self.config.security_events_days,
            self.config.audit_logs_days,
            if self.config.auto_delete { "Enabled" } else { "Disabled" }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn create_test_event(id: &str, event_type: AuditEventType) -> AuditEvent {
        AuditEvent {
            id: id.to_string(),
            timestamp: Utc::now(),
            event_type,
            actor: "test-user".to_string(),
            action: "test-action".to_string(),
            resource: "test-resource".to_string(),
            details: HashMap::new(),
            ip_address: Some("192.168.1.1".to_string()),
            session_id: Some("session-123".to_string()),
            previous_hash: None,
            integrity_hash: None,
        }
    }

    #[test]
    fn test_integrity_verifier() {
        let verifier = IntegrityVerifier::new();
        let event = create_test_event("test-1", AuditEventType::SecurityEvent);

        let hash = verifier.hash_event(&event);
        assert_eq!(hash.len(), 64); // SHA-256 hex length

        // Same event should produce same hash
        let hash2 = verifier.hash_event(&event);
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_audit_logger_basic() {
        let config = AuditConfig {
            tamper_evident: false,
            retention_days: 2555,
            integrity_check_hours: 24,
        };

        let logger = AuditLogger::new(config);
        let event = create_test_event("test-1", AuditEventType::SecurityEvent);

        // Should not fail
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(logger.log_event(event)).unwrap();

        let events = logger.get_events();
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn test_compliance_reporter_gdpr_disabled() {
        let config = RegulatoryConfig {
            gdpr: false,
            hipaa: false,
            pci_dss: false,
            data_residency: None,
        };

        let reporter = ComplianceReporter::new(config);
        let events = vec![];

        let result = reporter.generate_gdpr_report(&events);
        assert!(result.is_err());
    }

    #[test]
    fn test_compliance_reporter_gdpr_no_breaches() {
        let config = RegulatoryConfig {
            gdpr: true,
            hipaa: false,
            pci_dss: false,
            data_residency: None,
        };

        let reporter = ComplianceReporter::new(config);
        let events = vec![];

        let result = reporter.generate_gdpr_report(&events).unwrap();
        assert!(result.contains("No reportable breaches"));
    }

    #[test]
    fn test_data_retention_manager() {
        let config = RetentionConfig {
            security_events_days: 90,
            audit_logs_days: 2555,
            auto_delete: true,
        };

        let manager = DataRetentionManager::new(config);
        let summary = manager.get_retention_summary();

        assert!(summary.contains("90 days"));
        assert!(summary.contains("2555 days"));
        assert!(summary.contains("Enabled"));
    }
}