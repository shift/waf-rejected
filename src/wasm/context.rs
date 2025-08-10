//! WASM Request and Security Context
//! 
//! Defines the context structures passed to WASM ModSecurity modules
//! for request processing and security evaluation.

use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use wasmtime_wasi::{WasiCtx, ResourceTable};

/// Request context passed to WASM ModSecurity engine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmRequestContext {
    /// HTTP method (GET, POST, etc.)
    pub method: String,
    /// Request URI
    pub uri: String,
    /// HTTP version
    pub http_version: String,
    /// Request headers
    pub headers: HashMap<String, String>,
    /// Client IP address
    pub client_ip: String,
    /// Request body (truncated for security)
    pub body: Option<Vec<u8>>,
    /// Geographic context (for K/V store integration)
    pub geo_context: Option<GeoContext>,
    /// Additional security metadata
    pub security_metadata: SecurityMetadata,
}

/// Geographic context for request processing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoContext {
    /// Country code (ISO 3166-1 alpha-2)
    pub country: String,
    /// Region/state
    pub region: Option<String>,
    /// City
    pub city: Option<String>,
    /// ISP information
    pub isp: Option<String>,
    /// ASN (Autonomous System Number)
    pub asn: Option<u32>,
    /// Threat intelligence flags
    pub threat_flags: Vec<String>,
}

/// Security metadata for enhanced processing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityMetadata {
    /// Request timestamp (Unix timestamp)
    pub timestamp: u64,
    /// Request ID for correlation
    pub request_id: String,
    /// Previous violations from this IP
    pub violation_history: u32,
    /// Rate limiting context
    pub rate_limit_context: RateLimitContext,
    /// Session information
    pub session_info: Option<SessionInfo>,
}

/// Rate limiting context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitContext {
    /// Current request count in window
    pub current_count: u32,
    /// Window size in seconds
    pub window_size: u32,
    /// Maximum allowed requests
    pub max_requests: u32,
    /// Time until window reset
    pub reset_time: u64,
}

/// Session information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    /// Session ID
    pub session_id: String,
    /// User ID (if authenticated)
    pub user_id: Option<String>,
    /// Session creation time
    pub created_at: u64,
    /// Last activity time
    pub last_activity: u64,
    /// Authentication level
    pub auth_level: AuthLevel,
}

/// Authentication level
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthLevel {
    Anonymous,
    Basic,
    MFA,
    Administrative,
}

impl Default for WasmRequestContext {
    fn default() -> Self {
        Self {
            method: "GET".to_string(),
            uri: "/".to_string(),
            http_version: "HTTP/1.1".to_string(),
            headers: HashMap::new(),
            client_ip: "127.0.0.1".to_string(),
            body: None,
            geo_context: None,
            security_metadata: SecurityMetadata::default(),
        }
    }
}

impl Default for SecurityMetadata {
    fn default() -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        
        Self {
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            request_id: uuid::Uuid::new_v4().to_string(),
            violation_history: 0,
            rate_limit_context: RateLimitContext::default(),
            session_info: None,
        }
    }
}

impl Default for RateLimitContext {
    fn default() -> Self {
        Self {
            current_count: 0,
            window_size: 60, // 1 minute
            max_requests: 100,
            reset_time: 0,
        }
    }
}

/// WASM security context for the store
pub struct WasmSecurityContext {
    pub wasi: WasiCtx,
    pub table: ResourceTable,
    pub limiter: wasmtime::StoreLimits,
}

impl WasmSecurityContext {
    pub fn new(wasi: WasiCtx) -> Self {
        let table = ResourceTable::new();
        let limiter = wasmtime::StoreLimitsBuilder::new()
            .memory_size(16 * 1024 * 1024) // 16MB
            .table_elements(1000)
            .instances(1)
            .tables(1)
            .memories(1)
            .build();
            
        Self {
            wasi,
            table,
            limiter,
        }
    }
}

impl WasmRequestContext {
    /// Create a new request context from HTTP components
    pub fn from_http_request(
        method: &str,
        uri: &str,
        headers: &[(&str, &str)],
        client_ip: &str,
        body: Option<&[u8]>,
    ) -> Self {
        let headers_map: HashMap<String, String> = headers.iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
            
        Self {
            method: method.to_string(),
            uri: uri.to_string(),
            http_version: "HTTP/1.1".to_string(),
            headers: headers_map,
            client_ip: client_ip.to_string(),
            body: body.map(|b| b.to_vec()),
            geo_context: None,
            security_metadata: SecurityMetadata::default(),
        }
    }
    
    /// Add geographic context (for K/V store integration)
    pub fn with_geo_context(mut self, geo: GeoContext) -> Self {
        self.geo_context = Some(geo);
        self
    }
    
    /// Add session information
    pub fn with_session_info(mut self, session: SessionInfo) -> Self {
        self.security_metadata.session_info = Some(session);
        self
    }
    
    /// Update rate limit context
    pub fn with_rate_limit_context(mut self, rate_limit: RateLimitContext) -> Self {
        self.security_metadata.rate_limit_context = rate_limit;
        self
    }
    
    /// Get request size for memory management
    pub fn estimated_size(&self) -> usize {
        let headers_size: usize = self.headers.iter()
            .map(|(k, v)| k.len() + v.len())
            .sum();
            
        let body_size = self.body.as_ref()
            .map(|b| b.len())
            .unwrap_or(0);
            
        // Rough estimate including all fields
        self.method.len() + 
        self.uri.len() + 
        headers_size + 
        body_size + 
        1024 // Metadata overhead
    }
    
    /// Check if request should be processed by WASM
    pub fn should_process_with_wasm(&self) -> bool {
        // Skip WASM for very large requests to avoid memory issues
        if self.estimated_size() > 1024 * 1024 { // 1MB limit
            return false;
        }
        
        // Skip WASM for internal health checks
        if self.uri.starts_with("/health") || self.uri.starts_with("/metrics") {
            return false;
        }
        
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_request_context_creation() {
        let ctx = WasmRequestContext::from_http_request(
            "GET",
            "/test",
            &[("Host", "example.com"), ("User-Agent", "test")],
            "192.168.1.1",
            Some(b"test body"),
        );
        
        assert_eq!(ctx.method, "GET");
        assert_eq!(ctx.uri, "/test");
        assert_eq!(ctx.client_ip, "192.168.1.1");
        assert_eq!(ctx.headers.len(), 2);
        assert!(ctx.body.is_some());
    }
    
    #[test]
    fn test_size_estimation() {
        let mut ctx = WasmRequestContext::default();
        ctx.body = Some(vec![0u8; 1000]);
        
        let size = ctx.estimated_size();
        assert!(size > 1000);
        assert!(size < 2000); // Should include overhead but not be excessive
    }
    
    #[test]
    fn test_wasm_processing_decision() {
        let mut ctx = WasmRequestContext::default();
        
        // Normal request should be processed
        assert!(ctx.should_process_with_wasm());
        
        // Health check should be skipped
        ctx.uri = "/health".to_string();
        assert!(!ctx.should_process_with_wasm());
        
        // Large request should be skipped
        ctx.uri = "/normal".to_string();
        ctx.body = Some(vec![0u8; 2 * 1024 * 1024]); // 2MB
        assert!(!ctx.should_process_with_wasm());
    }
}
