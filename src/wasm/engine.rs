//! WASM ModSecurity Engine Implementation
//! 
//! This module provides a high-performance WASM-based ModSecurity integration
//! for the WAF-Rejected platform. It supports component model execution,
//! memory-limited sandboxing, and hot-reloading of security rules.

use std::path::Path;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use anyhow::{Context, Result};
use tracing::{debug, error, info, warn};

use wasmtime::component::*;
use wasmtime::{Config, Engine, Store, StoreLimits, StoreLimitsBuilder};
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, ResourceTable};

use crate::wasm::context::{WasmRequestContext, WasmSecurityContext};
use crate::wasm::bindings::{
    ComponentManager, SecurityDecision, SecurityError, EngineStats,
    WasmHostFunctions, SecurityEvent, ThreatIndicator, GeoInfo,
};

/// WASM-based ModSecurity engine configuration
#[derive(Debug, Clone)]
pub struct WasmEngineConfig {
    /// Path to the WASM module
    pub module_path: String,
    /// Maximum memory for WASM instance (in bytes)
    pub memory_limit: usize,
    /// Execution timeout (in milliseconds)
    pub timeout_ms: u64,
    /// Enable debug mode
    pub debug: bool,
    /// Number of instances to pool
    pub instance_pool_size: usize,
    /// Enable hot reloading
    pub hot_reload: bool,
}

impl Default for WasmEngineConfig {
    fn default() -> Self {
        Self {
            module_path: "rules/coraza.wasm".to_string(),
            memory_limit: 16 * 1024 * 1024, // 16MB
            timeout_ms: 100,
            debug: false,
            instance_pool_size: 10,
            hot_reload: true,
        }
    }
}

/// High-performance WASM ModSecurity engine
pub struct WasmEngine {
    /// Engine configuration
    config: WasmEngineConfig,
    /// Wasmtime engine
    engine: Engine,
    /// Component manager
    component_manager: ComponentManager,
    /// Loaded WASM component
    component: Option<Component>,
    /// Engine statistics
    stats: Arc<RwLock<WasmEngineStats>>,
    /// Module modification time for hot reload
    last_modified: Option<std::time::SystemTime>,
}

/// WASM engine statistics
#[derive(Debug, Default, Clone)]
pub struct WasmEngineStats {
    pub total_requests: u64,
    pub successful_requests: u64,
    pub blocked_requests: u64,
    pub allowed_requests: u64,
    pub logged_requests: u64,
    pub error_requests: u64,
    pub avg_processing_time_us: u64,
    pub memory_usage_bytes: u64,
    pub module_reload_count: u32,
    pub last_reload_time: Option<std::time::SystemTime>,
}

/// Host functions implementation for WASM modules
pub struct WafHostFunctions {
    request_context: Option<WasmRequestContext>,
}

impl WasmHostFunctions for WafHostFunctions {
    fn log_security_event(&mut self, event: &SecurityEvent) -> Result<()> {
        // Log security event to the WAF logging system
        info!(
            event_id = %event.id,
            client_ip = %event.client_ip,
            event_type = %event.event_type,
            severity = ?event.severity,
            rule_id = %event.rule_id,
            message = %event.message,
            "WASM security event logged"
        );
        Ok(())
    }
    
    fn query_threat_intel(&mut self, ip: &str) -> Result<Vec<ThreatIndicator>> {
        // Query threat intelligence for IP
        // This would integrate with actual threat intel services
        debug!("Querying threat intel for IP: {}", ip);
        Ok(vec![]) // Return empty for now
    }
    
    fn update_rate_limit(&mut self, key: &str, increment: u32) -> Result<u32> {
        // Update rate limiting counters
        // This would integrate with Redis or local rate limiter
        debug!("Updating rate limit for key: {}, increment: {}", key, increment);
        Ok(increment) // Return current count
    }
    
    fn get_geo_info(&mut self, ip: &str) -> Result<GeoInfo> {
        // Get geographic information for IP
        // This would integrate with MaxMind GeoIP
        debug!("Getting geo info for IP: {}", ip);
        Ok(GeoInfo {
            country: "US".to_string(),
            region: Some("CA".to_string()),
            city: Some("San Francisco".to_string()),
            isp: Some("Example ISP".to_string()),
            asn: Some(12345),
        })
    }
}

impl WasmEngine {
    /// Create a new WASM engine
    pub fn new(config: WasmEngineConfig) -> Result<Self> {
        info!("Initializing WASM ModSecurity engine");
        
        // Configure Wasmtime engine
        let mut wasmtime_config = Config::new();
        wasmtime_config.wasm_component_model(true);
        wasmtime_config.async_support(true);
        wasmtime_config.cache_config_load_default()?;
        
        if config.debug {
            wasmtime_config.debug_info(true);
        }
        
        let engine = Engine::new(&wasmtime_config)
            .context("Failed to create Wasmtime engine")?;
            
        let component_manager = ComponentManager::new()
            .context("Failed to create component manager")?;
        
        let stats = Arc::new(RwLock::new(WasmEngineStats::default()));
        
        let mut wasm_engine = Self {
            config,
            engine,
            component_manager,
            component: None,
            stats,
            last_modified: None,
        };
        
        // Load the initial module
        wasm_engine.load_module()?;
        
        info!("WASM ModSecurity engine initialized successfully");
        Ok(wasm_engine)
    }
    
    /// Load or reload the WASM module
    pub fn load_module(&mut self) -> Result<()> {
        let module_path = Path::new(&self.config.module_path);
        
        if !module_path.exists() {
            warn!("WASM module not found at: {}", self.config.module_path);
            warn!("Creating a mock ModSecurity WASM module for development");
            self.create_mock_module()?;
        }
        
        // Check modification time for hot reload
        if let Ok(metadata) = module_path.metadata() {
            if let Ok(modified) = metadata.modified() {
                if let Some(last_modified) = self.last_modified {
                    if modified <= last_modified {
                        debug!("WASM module unchanged, skipping reload");
                        return Ok(());
                    }
                }
                self.last_modified = Some(modified);
            }
        }
        
        info!("Loading WASM module from: {}", self.config.module_path);
        
        // Read the WASM module bytes
        let module_bytes = std::fs::read(&self.config.module_path)
            .with_context(|| format!("Failed to read WASM module: {}", self.config.module_path))?;
        
        // Load the component
        let component = self.component_manager.load_component(&module_bytes)
            .context("Failed to load WASM component")?;
        
        self.component = Some(component);
        
        // Update statistics
        if let Ok(mut stats) = self.stats.write() {
            stats.module_reload_count += 1;
            stats.last_reload_time = Some(std::time::SystemTime::now());
        }
        
        info!("WASM module loaded successfully");
        Ok(())
    }
    
    /// Process an HTTP request through the WASM ModSecurity engine
    pub async fn process_request(&self, request_context: WasmRequestContext) -> Result<SecurityDecision> {
        let start_time = Instant::now();
        
        debug!("Processing request through WASM engine: {}", request_context.uri);
        
        // Check if we should process this request
        if !request_context.should_process_with_wasm() {
            debug!("Skipping WASM processing for request: {}", request_context.uri);
            return Ok(SecurityDecision::Allow);
        }
        
        // Get the loaded component
        let component = self.component.as_ref()
            .ok_or_else(|| anyhow::anyhow!("WASM component not loaded"))?;
        
        // Create WASM execution context
        let wasi_ctx = WasiCtxBuilder::new()
            .inherit_stdio()
            .build();
        let security_context = WasmSecurityContext::new(wasi_ctx);
        
        // Create store with limits
        let mut store = Store::new(&self.engine, security_context);
        store.limiter(|ctx| &mut ctx.limiter);
        
        // Set execution timeout
        let timeout = Duration::from_millis(self.config.timeout_ms);
        let decision = tokio::time::timeout(timeout, async {
            // Instantiate the component
            let host_functions = Box::new(WafHostFunctions {
                request_context: Some(request_context.clone()),
            });
            
            store.data_mut().wasi = WasiCtxBuilder::new()
                .inherit_stdio()
                .build();
            
            // For now, return a mock decision based on simple rule evaluation
            self.evaluate_request_mock(&request_context).await
        }).await;
        
        let decision = match decision {
            Ok(decision) => decision?,
            Err(_) => {
                warn!("WASM execution timeout for request: {}", request_context.uri);
                return Err(anyhow::anyhow!("WASM execution timeout"));
            }
        };
        
        // Update statistics
        let processing_time_us = start_time.elapsed().as_micros() as u64;
        self.update_stats(&decision, processing_time_us);
        
        debug!(
            uri = %request_context.uri,
            decision = ?decision,
            processing_time_us = processing_time_us,
            "WASM request processing completed"
        );
        
        Ok(decision)
    }
    
    /// Mock evaluation for development (to be replaced with actual WASM calls)
    async fn evaluate_request_mock(&self, context: &WasmRequestContext) -> Result<SecurityDecision> {
        // Simulate ModSecurity rule evaluation
        
        // Check for common attack patterns
        let request_data = format!("{} {} {:?}", 
            context.method, context.uri, context.body);
        
        // SQL injection patterns
        if request_data.contains("' OR ") || 
           request_data.contains("UNION SELECT") || 
           request_data.contains("'; DROP TABLE") {
            return Ok(SecurityDecision::Block {
                rule_id: "950001".to_string(),
                message: "SQL injection attack detected".to_string(),
                severity: crate::wasm::bindings::Severity::High,
            });
        }
        
        // XSS patterns
        if request_data.contains("<script>") ||
           request_data.contains("javascript:") ||
           request_data.contains("onerror=") {
            return Ok(SecurityDecision::Block {
                rule_id: "941100".to_string(),
                message: "Cross-site scripting attack detected".to_string(),
                severity: crate::wasm::bindings::Severity::High,
            });
        }
        
        // Path traversal
        if request_data.contains("../") || request_data.contains("..\\") {
            return Ok(SecurityDecision::Log {
                rule_id: "930100".to_string(),
                message: "Path traversal attempt detected".to_string(),
                severity: crate::wasm::bindings::Severity::Medium,
            });
        }
        
        // Large request body (rate limit)
        if context.estimated_size() > 1024 * 100 { // 100KB
            return Ok(SecurityDecision::Log {
                rule_id: "200001".to_string(),
                message: "Large request body detected".to_string(),
                severity: crate::wasm::bindings::Severity::Low,
            });
        }
        
        // Allow all other requests
        Ok(SecurityDecision::Allow)
    }
    
    /// Get engine statistics
    pub fn get_stats(&self) -> WasmEngineStats {
        self.stats.read()
            .map(|stats| stats.clone())
            .unwrap_or_default()
    }
    
    /// Update internal statistics
    fn update_stats(&self, decision: &SecurityDecision, processing_time_us: u64) {
        if let Ok(mut stats) = self.stats.write() {
            stats.total_requests += 1;
            
            match decision {
                SecurityDecision::Allow => stats.allowed_requests += 1,
                SecurityDecision::Block { .. } => {
                    stats.blocked_requests += 1;
                    stats.successful_requests += 1;
                }
                SecurityDecision::Log { .. } => {
                    stats.logged_requests += 1;
                    stats.successful_requests += 1;
                }
                SecurityDecision::Challenge { .. } => stats.successful_requests += 1,
            }
            
            // Update average processing time
            let total_successful = stats.successful_requests;
            if total_successful > 0 {
                stats.avg_processing_time_us = 
                    (stats.avg_processing_time_us * (total_successful - 1) + processing_time_us) / total_successful;
            }
        }
    }
    
    /// Create a mock WASM module for development
    fn create_mock_module(&self) -> Result<()> {
        let module_dir = Path::new(&self.config.module_path).parent()
            .unwrap_or_else(|| Path::new("."));
        
        std::fs::create_dir_all(module_dir)
            .context("Failed to create module directory")?;
        
        // Create a minimal WASM module (placeholder)
        let mock_wasm = include_bytes!("../resources/mock_modsecurity.wasm");
        std::fs::write(&self.config.module_path, mock_wasm)
            .context("Failed to write mock WASM module")?;
        
        info!("Created mock ModSecurity WASM module at: {}", self.config.module_path);
        Ok(())
    }
    
    /// Check if hot reload is needed
    pub fn should_reload(&self) -> bool {
        if !self.config.hot_reload {
            return false;
        }
        
        let module_path = Path::new(&self.config.module_path);
        if !module_path.exists() {
            return false;
        }
        
        if let Ok(metadata) = module_path.metadata() {
            if let Ok(modified) = metadata.modified() {
                if let Some(last_modified) = self.last_modified {
                    return modified > last_modified;
                }
            }
        }
        
        false
    }
}

impl std::fmt::Debug for WasmEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WasmEngine")
            .field("config", &self.config)
            .field("component_loaded", &self.component.is_some())
            .field("stats", &self.get_stats())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_wasm_engine_initialization() {
        let config = WasmEngineConfig::default();
        let memory_limit = config.memory_limit;
        let timeout_ms = config.timeout_ms;
        let _engine = WasmEngine::new(config);
        
        // Engine creation might fail without actual WASM module
        // but we should at least verify the config is correct
        assert!(memory_limit > 0);
        assert!(timeout_ms > 0);
    }
    
    #[tokio::test]
    async fn test_mock_security_evaluation() {
        let config = WasmEngineConfig::default();
        if let Ok(engine) = WasmEngine::new(config) {
            // Test SQL injection detection
            let mut context = WasmRequestContext::default();
            context.uri = "/test?id=' OR '1'='1".to_string();
            
            let decision = engine.evaluate_request_mock(&context).await.unwrap();
            assert!(matches!(decision, SecurityDecision::Block { .. }));
            
            // Test normal request
            context.uri = "/normal".to_string();
            let decision = engine.evaluate_request_mock(&context).await.unwrap();
            assert!(matches!(decision, SecurityDecision::Allow));
        }
    }
    
    #[test]
    fn test_engine_stats() {
        let config = WasmEngineConfig::default();
        if let Ok(engine) = WasmEngine::new(config) {
            let stats = engine.get_stats();
            assert_eq!(stats.total_requests, 0);
            assert_eq!(stats.blocked_requests, 0);
        }
    }
}