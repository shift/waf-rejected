//! WASM Component Bindings
//! 
//! Defines the interface bindings for Go-compiled ModSecurity WASM modules.
//! This module handles the communication protocol between the Rust host
//! and the WASM guest modules.

use wasmtime::component::{Component, Linker};
use anyhow::Result;

// Note: In production, these would be auto-generated using wit-bindgen
// For now, we use a simplified interface for the MVP

/// WASM component interface for ModSecurity
pub struct ModSecurityComponent {
    /// Component instance (simplified for MVP)
    _component: Component,
}

/// Security decision returned by WASM component
#[derive(Clone, Debug, PartialEq)]
pub enum SecurityDecision {
    /// Allow the request to proceed
    Allow,
    /// Block the request
    Block {
        rule_id: String,
        message: String,
        severity: Severity,
    },
    /// Log the request but allow it
    Log {
        rule_id: String,
        message: String,
        severity: Severity,
    },
    /// Challenge the request (CAPTCHA, etc.)
    Challenge {
        challenge_type: ChallengeType,
        message: String,
    },
}

/// Security error from WASM component
#[derive(Clone, Debug, PartialEq)]
pub enum SecurityError {
    /// Invalid request format
    InvalidRequest(String),
    /// Rules not loaded
    RulesNotLoaded,
    /// Processing timeout
    Timeout,
    /// Internal engine error
    InternalError(String),
    /// Memory limit exceeded
    MemoryLimitExceeded,
}

impl From<anyhow::Error> for SecurityError {
    fn from(err: anyhow::Error) -> Self {
        SecurityError::InternalError(err.to_string())
    }
}

/// Severity levels for security events
#[derive(Clone, Debug, PartialEq)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// Challenge types for suspicious requests
#[derive(Clone, Debug, PartialEq)]
pub enum ChallengeType {
    Captcha,
    RateLimit,
    Authentication,
    BehaviorAnalysis,
}

/// Engine statistics from WASM component
#[derive(Clone, Debug)]
pub struct EngineStats {
    /// Total requests processed
    pub total_requests: u64,
    /// Requests blocked
    pub blocked_requests: u64,
    /// Requests logged
    pub logged_requests: u64,
    /// Rules loaded
    pub rules_loaded: u32,
    /// Memory usage in bytes
    pub memory_usage: u64,
    /// Average processing time in microseconds
    pub avg_processing_time_us: u64,
}

/// Geographic context update request
#[derive(Clone, Debug)]
pub struct GeoUpdateRequest {
    /// Client IP to update
    pub client_ip: String,
    /// Country code
    pub country: String,
    /// Region/state
    pub region: Option<String>,
    /// City
    pub city: Option<String>,
    /// ISP information
    pub isp: Option<String>,
    /// Threat intelligence data
    pub threat_data: Vec<ThreatIndicator>,
}

/// Threat indicator from external sources
#[derive(Clone, Debug)]
pub struct ThreatIndicator {
    /// Indicator type
    pub indicator_type: ThreatType,
    /// Indicator value
    pub value: String,
    /// Confidence level (0-100)
    pub confidence: u8,
    /// Source of the indicator
    pub source: String,
    /// Expiration timestamp
    pub expires_at: u64,
}

/// Types of threat indicators
#[derive(Clone, Debug, PartialEq)]
pub enum ThreatType {
    MaliciousIp,
    BotNetwork,
    KnownAttacker,
    Suspicious,
    Scanner,
}

/// Host functions provided to WASM modules
pub trait WasmHostFunctions {
    /// Log a security event
    fn log_security_event(&mut self, event: &SecurityEvent) -> Result<()>;
    
    /// Query K/V store for threat intelligence
    fn query_threat_intel(&mut self, ip: &str) -> Result<Vec<ThreatIndicator>>;
    
    /// Update rate limiting counters
    fn update_rate_limit(&mut self, key: &str, increment: u32) -> Result<u32>;
    
    /// Get geographic information for IP
    fn get_geo_info(&mut self, ip: &str) -> Result<GeoInfo>;
}

/// Security event for logging
#[derive(Clone, Debug)]
pub struct SecurityEvent {
    /// Event ID
    pub id: String,
    /// Event timestamp
    pub timestamp: u64,
    /// Client IP
    pub client_ip: String,
    /// Event type
    pub event_type: String,
    /// Severity level
    pub severity: Severity,
    /// Rule that triggered the event
    pub rule_id: String,
    /// Event message
    pub message: String,
    /// Additional metadata
    pub metadata: std::collections::HashMap<String, String>,
}

/// Geographic information
#[derive(Clone, Debug)]
pub struct GeoInfo {
    /// Country code
    pub country: String,
    /// Region/state
    pub region: Option<String>,
    /// City
    pub city: Option<String>,
    /// ISP
    pub isp: Option<String>,
    /// ASN
    pub asn: Option<u32>,
}

/// WASM component loader and manager
pub struct ComponentManager {
    engine: wasmtime::Engine,
    linker: Linker<WasmHostContext>,
}

/// Host context for WASM execution
pub struct WasmHostContext {
    /// Host functions implementation
    pub host_functions: Box<dyn WasmHostFunctions + Send + Sync>,
    /// Request context
    pub request_context: Option<crate::wasm::context::WasmRequestContext>,
}

impl ComponentManager {
    /// Create a new component manager
    pub fn new() -> Result<Self> {
        let mut config = wasmtime::Config::new();
        config.wasm_component_model(true);
        config.async_support(true);
        
        let engine = wasmtime::Engine::new(&config)?;
        let mut linker = Linker::new(&engine);
        
        // Add host function bindings
        Self::add_host_functions(&mut linker)?;
        
        Ok(Self { engine, linker })
    }
    
    /// Load a WASM component from bytes
    pub fn load_component(&self, bytes: &[u8]) -> Result<Component> {
        Component::new(&self.engine, bytes)
    }
    
    /// Create an instance of a component
    pub async fn instantiate(
        &self,
        component: &Component,
        store: &mut wasmtime::Store<WasmHostContext>,
    ) -> Result<ModSecurityComponent> {
        // Simplified instantiation for MVP
        // In production, this would use the component model
        
        Ok(ModSecurityComponent {
            _component: component.clone(),
        })
    }
    
    fn add_host_functions(linker: &mut Linker<WasmHostContext>) -> Result<()> {
        // Add host function implementations
        // This would bind the actual host functions to the WASM module
        
        // Example binding (simplified):
        // linker.func_wrap("env", "log_security_event", |caller: wasmtime::Caller<'_, WasmHostContext>, event_ptr: u32| -> Result<()> {
        //     // Implementation
        //     Ok(())
        // })?;
        
        Ok(())
    }
}

impl std::fmt::Display for SecurityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecurityError::InvalidRequest(msg) => write!(f, "Invalid request: {}", msg),
            SecurityError::RulesNotLoaded => write!(f, "Security rules not loaded"),
            SecurityError::Timeout => write!(f, "Processing timeout"),
            SecurityError::InternalError(msg) => write!(f, "Internal error: {}", msg),
            SecurityError::MemoryLimitExceeded => write!(f, "Memory limit exceeded"),
        }
    }
}

impl std::error::Error for SecurityError {}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_security_decision_types() {
        let allow = SecurityDecision::Allow;
        assert!(matches!(allow, SecurityDecision::Allow));
        
        let block = SecurityDecision::Block {
            rule_id: "test".to_string(),
            message: "blocked".to_string(),
            severity: Severity::High,
        };
        
        if let SecurityDecision::Block { severity, .. } = block {
            assert_eq!(severity, Severity::High);
        }
    }
    
    #[test]
    fn test_component_manager_creation() {
        let manager = ComponentManager::new();
        assert!(manager.is_ok());
    }
}
