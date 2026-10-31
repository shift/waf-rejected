use chrono::{DateTime, Utc};
use std::collections::HashMap;

use waf_ingress::compliance::{
    AuditEvent, AuditEventType, AuditLogger, ComplianceError, ComplianceReporter, IntegrityVerifier,
};
use waf_ingress::config::{AuditConfig, RegulatoryConfig};

/// Integration tests for compliance features
#[cfg(test)]
mod compliance_integration_tests {
    use super::*;

    fn create_audit_config() -> AuditConfig {
        AuditConfig {
            tamper_evident: true,
            retention_days: 2555,
            integrity_check_hours: 24,
        }
    }

    fn create_regulatory_config() -> RegulatoryConfig {
        RegulatoryConfig {
            gdpr: true,
            hipaa: false,
            pci_dss: true,
            ai_act: true,
            nis2: true,
            cra: true,
            data_residency: Some("EU".to_string()),
        }
    }

    fn create_test_audit_event(id: &str, event_type: AuditEventType) -> AuditEvent {
        AuditEvent {
            id: id.to_string(),
            timestamp: Utc::now(),
            event_type,
            actor: "test-user".to_string(),
            action: "test-action".to_string(),
            resource: "test-resource".to_string(),
            details: {
                let mut map = HashMap::new();
                map.insert("test_key".to_string(), "test_value".to_string());
                map
            },
            ip_address: Some("192.168.1.100".to_string()),
            session_id: Some("session-123".to_string()),
            previous_hash: None,
            integrity_hash: None,
        }
    }

    #[tokio::test]
    async fn test_audit_logger_tamper_evident() {
        let config = create_audit_config();
        let logger = AuditLogger::new(config);

        // Log multiple events
        let event1 = create_test_audit_event("event-1", AuditEventType::SecurityEvent);
        let event2 = create_test_audit_event("event-2", AuditEventType::AuthAttempt);
        let event3 = create_test_audit_event("event-3", AuditEventType::ConfigChange);

        logger.log_event(event1).await.unwrap();
        logger.log_event(event2).await.unwrap();
        logger.log_event(event3).await.unwrap();

        // Verify integrity
        assert!(logger.verify_integrity().is_ok());

        // Check that events are stored
        let events = logger.get_events();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].id, "event-1");
        assert_eq!(events[1].id, "event-2");
        assert_eq!(events[2].id, "event-3");
    }

    #[tokio::test]
    async fn test_audit_logger_integrity_violation() {
        let config = create_audit_config();
        let logger = AuditLogger::new(config);

        let event = create_test_audit_event("test-event", AuditEventType::SecurityEvent);
        logger.log_event(event).await.unwrap();

        // Simulate tampering through the public verifier: mutating a field must
        // change the integrity hash.
        let verifier = IntegrityVerifier::new();
        let mut tampered = logger.get_events().remove(0);
        let original_hash = verifier.hash_event(&tampered);
        tampered.action = "tampered-action".to_string();

        assert_ne!(original_hash, verifier.hash_event(&tampered));
        assert!(logger.verify_integrity().is_ok());
    }

    #[tokio::test]
    async fn test_audit_event_time_filtering() {
        let config = create_audit_config();
        let logger = AuditLogger::new(config);

        let past_time = Utc::now() - chrono::Duration::hours(2);
        let future_time = Utc::now() + chrono::Duration::hours(2);

        // Create events at different times
        let mut event1 = create_test_audit_event("event-1", AuditEventType::SecurityEvent);
        event1.timestamp = past_time;

        let event2 = create_test_audit_event("event-2", AuditEventType::AuthAttempt);
        // event2 has current time

        let mut event3 = create_test_audit_event("event-3", AuditEventType::ConfigChange);
        event3.timestamp = future_time;

        logger.log_event(event1).await.unwrap();
        logger.log_event(event2).await.unwrap();
        logger.log_event(event3).await.unwrap();

        // Query events in time range
        let start = Utc::now() - chrono::Duration::hours(1);
        let end = Utc::now() + chrono::Duration::hours(1);

        let filtered_events = logger.get_events_in_range(start, end);
        assert_eq!(filtered_events.len(), 1); // Only event2 should be in range
        assert_eq!(filtered_events[0].id, "event-2");
    }

    #[test]
    fn test_gdpr_compliance_reporting() {
        let config = create_regulatory_config();
        let reporter = ComplianceReporter::new(config);

        // Create mock high-severity security events
        let mut events = vec![
            create_test_audit_event("breach-1", AuditEventType::SecurityEvent),
            create_test_audit_event("breach-2", AuditEventType::SecurityEvent),
        ];
        for event in &mut events {
            event
                .details
                .insert("severity".to_string(), "high".to_string());
        }

        // Generate GDPR report
        let report = reporter.generate_gdpr_report(&events).unwrap();

        // Verify report content
        assert!(report.contains("GDPR Article 33 Breach Notification"));
        assert!(report.contains("2 security incidents"));
        assert!(report.contains("Categories of data concerned"));
        assert!(report.contains("Number of data subjects concerned"));
    }

    #[test]
    fn test_gdpr_disabled() {
        let mut config = create_regulatory_config();
        config.gdpr = false;
        let reporter = ComplianceReporter::new(config);

        let events = vec![];
        let result = reporter.generate_gdpr_report(&events);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ComplianceError::NotEnabled(ref s) if s == "GDPR"));
    }

    #[test]
    fn test_pci_dss_compliance_reporting() {
        let config = create_regulatory_config();
        let reporter = ComplianceReporter::new(config);

        // Create mock security events
        let events = vec![
            create_test_audit_event("auth-fail-1", AuditEventType::SecurityEvent),
            create_test_audit_event("auth-fail-2", AuditEventType::SecurityEvent),
            create_test_audit_event("access-1", AuditEventType::SecurityEvent),
        ];

        let report = reporter.generate_pci_report(&events).unwrap();

        // Verify PCI-DSS report content
        assert!(report.contains("PCI-DSS Security Event Report"));
        assert!(report.contains("3")); // Total events
        assert!(report.to_lowercase().contains("authentication failures"));
        assert!(
            report.contains("EVIDENCE GENERATED - ASSESSMENT REQUIRED")
                || report.contains("REVIEW REQUIRED")
        );
        assert!(!report.contains("Compliance Status: COMPLIANT"));
    }

    #[test]
    fn test_pci_dss_disabled() {
        let mut config = create_regulatory_config();
        config.pci_dss = false;
        let reporter = ComplianceReporter::new(config);

        let events = vec![];
        let result = reporter.generate_pci_report(&events);

        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), ComplianceError::NotEnabled(ref s) if s == "PCI-DSS")
        );
    }

    #[test]
    fn test_gdpr_no_breaches() {
        let config = create_regulatory_config();
        let reporter = ComplianceReporter::new(config);

        // No security events
        let events = vec![
            create_test_audit_event("normal-1", AuditEventType::AuthAttempt),
            create_test_audit_event("normal-2", AuditEventType::DataAccess),
        ];

        let report = reporter.generate_gdpr_report(&events).unwrap();
        assert!(report.contains("No reportable breaches"));
    }

    #[tokio::test]
    async fn test_audit_logger_disabled_tamper_evident() {
        let mut config = create_audit_config();
        config.tamper_evident = false;
        let logger = AuditLogger::new(config);

        let event = create_test_audit_event("test-event", AuditEventType::SecurityEvent);
        logger.log_event(event).await.unwrap();

        // Should work without integrity checks
        assert!(logger.verify_integrity().is_ok());

        let events = logger.get_events();
        assert_eq!(events.len(), 1);
    }
}
