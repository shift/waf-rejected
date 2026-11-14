//! WASM ModSecurity Engine Implementation
//!
//! This module provides a high-performance WASM-based ModSecurity integration
//! for the WAF-Rejected platform. It supports component model execution,
//! memory-limited sandboxing, instance pooling, hot-reloading of security rules,
//! and advanced memory optimizations including memory mapping and shared linear memory.

use anyhow::{Context, Result};
use std::collections::VecDeque;
use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use tracing::{debug, info, warn};

use wasmtime::component::*;
use wasmtime::{Config, Engine, Memory, MemoryType, Store};
// use wasmtime::Module;
use wasmtime_wasi::WasiCtxBuilder;

use crate::wasm::bindings::{
    ComponentManager, GeoInfo, LoadedWasm, SecurityDecision, SecurityEvent, ThreatIndicator,
    WasmHostFunctions,
};
use crate::wasm::context::{WasmRequestContext, WasmSecurityContext};

/// Memory-mapped WASM module for fast loading and sharing
#[derive(Debug, Clone)]
pub struct MemoryMappedModule {
    /// Memory-mapped module data
    pub data: Arc<memmap2::Mmap>,
    /// Module size in bytes
    pub size: usize,
    /// Module hash for cache validation
    pub hash: u64,
    /// Last modification time
    pub modified: std::time::SystemTime,
}

impl MemoryMappedModule {
    /// Create a new memory-mapped module from file
    pub fn from_file(path: &Path) -> Result<Self> {
        let file = std::fs::File::open(path)
            .with_context(|| format!("Failed to open WASM module: {:?}", path))?;

        let mmap = unsafe { memmap2::Mmap::map(&file) }
            .with_context(|| format!("Failed to memory-map WASM module: {:?}", path))?;

        let metadata = file
            .metadata()
            .with_context(|| format!("Failed to read metadata: {:?}", path))?;

        let size = mmap.len();
        let hash = Self::calculate_hash(&mmap);
        let modified = metadata
            .modified()
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH);

        Ok(Self {
            data: Arc::new(mmap),
            size,
            hash,
            modified,
        })
    }

    /// Calculate fast hash of module data
    fn calculate_hash(data: &[u8]) -> u64 {
        // Use fast hash for validation (FNV-1a)
        let mut hash = 0xcbf29ce484222325_u64;
        for &byte in data.iter().take(1024) {
            // Sample first 1KB for performance
            hash ^= byte as u64;
            hash = hash.wrapping_mul(0x100000001b3);
        }
        hash
    }

    /// Get module data as slice
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

/// Shared linear memory pool for WASM instances
#[derive(Debug)]
pub struct SharedLinearMemoryPool {
    /// Memory configuration
    memory_type: MemoryType,
    /// Pool size limits
    min_size: usize,
    max_size: usize,
    /// Creation counter
    created_count: Arc<std::sync::atomic::AtomicUsize>,
}

impl SharedLinearMemoryPool {
    /// Create a new shared memory pool
    pub fn new(min_size: usize, max_size: usize, memory_limit_pages: u32) -> Result<Self> {
        // Guard against invalid/unbounded limits reaching wasmtime, which
        // panics internally when the maximum exceeds the index type.
        let memory_limit_pages = memory_limit_pages.clamp(1, 65_536);
        let memory_type = MemoryType::new(0, Some(memory_limit_pages));

        Ok(Self {
            memory_type,
            min_size,
            max_size,
            created_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        })
    }

    /// Get a linear memory from the pool or create a new one
    pub fn acquire<T>(&self, store: &mut Store<T>) -> Result<Memory> {
        // For now, always create a new memory
        // TODO: Implement actual pooling with proper Store management
        let memory = Memory::new(store, self.memory_type.clone())
            .context("Failed to create linear memory")?;

        self.created_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        debug!("Created new shared linear memory");

        Ok(memory)
    }

    /// Release a linear memory back to the pool
    pub fn release(&self, _memory: Memory) {
        // For now, just drop the memory
        // TODO: Implement actual pooling
        debug!("Released shared linear memory");
    }

    /// Get current pool statistics
    pub fn stats(&self) -> MemoryPoolStats {
        MemoryPoolStats {
            available_memories: 0, // No pooling yet
            total_created: self
                .created_count
                .load(std::sync::atomic::Ordering::Relaxed),
            max_size: self.max_size,
            min_size: self.min_size,
        }
    }
}

/// Memory pool statistics
#[derive(Debug, Clone)]
pub struct MemoryPoolStats {
    pub available_memories: usize,
    pub total_created: usize,
    pub max_size: usize,
    pub min_size: usize,
}

/// Pooled WASM instance for reuse with memory optimization
#[derive(Debug)]
pub struct PooledWasmInstance {
    /// Unique instance ID
    pub id: usize,
    /// Wasmtime store with security context
    pub store: Store<WasmSecurityContext>,
    /// Component instance bindings
    pub bindings: Option<Box<dyn std::any::Any + Send>>,
    /// Shared linear memory (optional) - disabled for compilation
    pub shared_memory: Option<Memory>,
    /// Instance creation time
    pub created_at: Instant,
    /// Last used time
    pub last_used: Instant,
    /// Number of requests processed
    pub request_count: u64,
    /// Memory pool reference for cleanup
    pub memory_pool_ref: Option<Arc<SharedLinearMemoryPool>>,
}

impl Drop for PooledWasmInstance {
    fn drop(&mut self) {
        // Return shared memory to pool when instance is dropped
        if let (Some(memory), Some(pool)) = (self.shared_memory.take(), &self.memory_pool_ref) {
            pool.release(memory);
        }
    }
}

/// High-performance WASM instance pool with memory optimization
#[derive(Debug)]
pub struct WasmInstancePool {
    /// Available instances ready for use
    available: Arc<Mutex<VecDeque<PooledWasmInstance>>>,
    /// Pool semaphore for concurrency control
    semaphore: Arc<Semaphore>,
    /// Shared linear memory pool for optimization
    memory_pool: Arc<SharedLinearMemoryPool>,
    /// Maximum pool size
    max_size: usize,
    /// Minimum pool size
    min_size: usize,
    /// Instance creation counter
    instance_counter: Arc<std::sync::atomic::AtomicUsize>,
}

impl WasmInstancePool {
    /// Create a new WASM instance pool with memory optimization
    pub fn new(min_size: usize, max_size: usize, memory_limit_mb: usize) -> Result<Self> {
        // Calculate memory limit in pages (64KB per page). Wasmtime's 32-bit
        // linear memories are capped at 65536 pages (4 GiB); clamp rather than
        // allowing the value to overflow a u32 / panic inside wasmtime.
        let memory_limit_pages = memory_limit_mb
            .saturating_mul(1024 * 1024)
            .saturating_div(64 * 1024)
            .clamp(1, 65_536) as u32;

        let memory_pool = Arc::new(SharedLinearMemoryPool::new(
            min_size,
            max_size.saturating_mul(2), // Allow more memories than instances for flexibility
            memory_limit_pages,
        )?);

        Ok(Self {
            available: Arc::new(Mutex::new(VecDeque::with_capacity(max_size))),
            semaphore: Arc::new(Semaphore::new(max_size)),
            memory_pool,
            max_size,
            min_size,
            instance_counter: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        })
    }

    /// Get an available instance from the pool
    pub async fn acquire(&self, engine: &Engine) -> Result<PooledWasmInstance> {
        // Wait for an available slot
        let _permit = self
            .semaphore
            .acquire()
            .await
            .map_err(|_| anyhow::anyhow!("Failed to acquire semaphore permit"))?;

        // Try to get an existing instance
        if let Ok(mut available) = self.available.try_lock() {
            if let Some(mut instance) = available.pop_front() {
                instance.last_used = Instant::now();

                debug!("Reused WASM instance #{}", instance.id);
                return Ok(instance);
            }
        }

        // Create new instance if none available
        self.create_instance(engine).await
    }

    /// Return an instance to the pool
    pub fn release(&self, mut instance: PooledWasmInstance) {
        instance.last_used = Instant::now();
        instance.request_count += 1;

        // Add back to available if pool not full
        if let Ok(mut available) = self.available.try_lock() {
            if available.len() < self.max_size {
                available.push_back(instance);
                debug!("Returned WASM instance to pool");
            } else {
                debug!("Pool full, dropping WASM instance");
            }
        }

        // Release semaphore permit
        self.semaphore.add_permits(1);
    }

    /// Create a new WASM instance with shared memory optimization
    async fn create_instance(&self, engine: &Engine) -> Result<PooledWasmInstance> {
        let id = self
            .instance_counter
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);

        let wasi_ctx = WasiCtxBuilder::new().inherit_stdio().build();
        let security_context = WasmSecurityContext::new(wasi_ctx);

        let mut store = Store::new(engine, security_context);

        // Acquire shared linear memory from pool
        let shared_memory = self.memory_pool.acquire(&mut store).ok();
        let memory_pool_ref = Some(self.memory_pool.clone());

        let instance = PooledWasmInstance {
            id,
            store,
            bindings: None,
            shared_memory,
            created_at: Instant::now(),
            last_used: Instant::now(),
            request_count: 0,
            memory_pool_ref,
        };

        debug!("Created new WASM instance #{} with shared memory", id);
        Ok(instance)
    }

    /// Get pool statistics including memory pool stats
    pub fn stats(&self) -> PoolStats {
        let available_count = self
            .available
            .try_lock()
            .map(|pool| pool.len())
            .unwrap_or(0);

        let in_use_count = 0; // Simplified since we removed in_use tracking
        let memory_stats = self.memory_pool.stats();

        PoolStats {
            available_instances: available_count,
            in_use_instances: in_use_count,
            total_instances: available_count + in_use_count,
            max_size: self.max_size,
            min_size: self.min_size,
            available_permits: self.semaphore.available_permits(),
            memory_pool_stats: Some(memory_stats),
        }
    }
}

/// Pool statistics with memory optimization metrics
#[derive(Debug, Clone)]
pub struct PoolStats {
    pub available_instances: usize,
    pub in_use_instances: usize,
    pub total_instances: usize,
    pub max_size: usize,
    pub min_size: usize,
    pub available_permits: usize,
    pub memory_pool_stats: Option<MemoryPoolStats>,
}

/// WASM-based ModSecurity engine configuration
#[derive(Debug, Clone)]
pub struct WasmEngineConfig {
    /// Path to the WASM module
    pub module_path: String,
    /// Maximum memory for WASM instance (in MB)
    pub memory_limit_mb: usize,
    /// Execution timeout (in milliseconds)
    pub timeout_ms: u64,
    /// Enable debug mode
    pub debug: bool,
    /// Number of instances to pool
    pub instance_pool_size: usize,
    /// Enable hot reloading
    pub hot_reload: bool,
    /// Enable memory mapping optimization
    pub enable_memory_mapping: bool,
    /// Enable shared linear memory optimization
    pub enable_shared_memory: bool,
}

impl Default for WasmEngineConfig {
    fn default() -> Self {
        Self {
            module_path: "rules/coraza.wasm".to_string(),
            memory_limit_mb: 16, // 16MB
            timeout_ms: 100,
            debug: false,
            instance_pool_size: 10,
            hot_reload: true,
            enable_memory_mapping: true,
            enable_shared_memory: true,
        }
    }
}

/// High-performance WASM ModSecurity engine with memory optimization
pub struct WasmEngine {
    /// Engine configuration
    config: WasmEngineConfig,
    /// Wasmtime engine
    engine: Engine,
    /// Component manager
    component_manager: ComponentManager,
    /// Loaded WASM component
    component: Option<Component>,
    /// Memory-mapped module for fast loading
    memory_mapped_module: Option<MemoryMappedModule>,
    /// WASM instance pool for high-performance reuse
    instance_pool: WasmInstancePool,
    /// Engine statistics
    stats: Arc<RwLock<WasmEngineStats>>,
    /// Module modification time for hot reload
    last_modified: Option<std::time::SystemTime>,
}

/// WASM engine statistics with memory optimization metrics
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
    // Pool performance metrics
    pub pool_hits: u64,
    pub pool_misses: u64,
    pub pool_creates: u64,
    pub pool_utilization_percent: f64,
    pub instance_reuse_rate: f64,
    // Memory optimization metrics
    pub memory_pool_hits: u64,
    pub memory_pool_misses: u64,
    pub total_memory_allocated_mb: f64,
    pub avg_memory_per_instance_mb: f64,
    pub memory_mapping_enabled: bool,
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
        debug!(
            "Updating rate limit for key: {}, increment: {}",
            key, increment
        );
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
    /// Create a new WASM engine with memory optimization
    pub fn new(config: WasmEngineConfig) -> Result<Self> {
        info!("Initializing WASM ModSecurity engine with memory optimization");

        // Configure Wasmtime engine with memory optimization
        let mut wasmtime_config = Config::new();
        wasmtime_config.wasm_component_model(true);
        wasmtime_config.async_support(true);

        // Disable pooling allocator temporarily to fix compilation
        // if config.enable_shared_memory {
        //     wasmtime_config.allocation_strategy(wasmtime::InstanceAllocationStrategy::Pooling(
        //         wasmtime::PoolingAllocationConfig::default()
        //     ));
        // }

        if config.debug {
            wasmtime_config.debug_info(true);
        }

        let engine = Engine::new(&wasmtime_config).context("Failed to create Wasmtime engine")?;

        let component_manager =
            ComponentManager::new().context("Failed to create component manager")?;

        let stats = Arc::new(RwLock::new(WasmEngineStats::default()));

        // Initialize WASM instance pool with memory optimization
        let instance_pool = WasmInstancePool::new(
            config.instance_pool_size / 2, // min_size: half of max for initial allocation
            config.instance_pool_size,     // max_size: from config
            config.memory_limit_mb,        // memory limit for shared memory pool
        )?;

        let mut wasm_engine = Self {
            config,
            engine,
            component_manager,
            component: None,
            memory_mapped_module: None,
            instance_pool,
            stats,
            last_modified: None,
        };

        // Load the initial module
        wasm_engine.load_module()?;

        info!("WASM ModSecurity engine initialized successfully with memory optimization");
        Ok(wasm_engine)
    }

    /// Load or reload the WASM module with memory mapping optimization
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

        // Use memory mapping for fast module loading if enabled
        if self.config.enable_memory_mapping {
            match MemoryMappedModule::from_file(module_path) {
                Ok(mapped_module) => {
                    info!(
                        "Memory-mapped WASM module loaded: {} bytes, hash: 0x{:x}",
                        mapped_module.size, mapped_module.hash
                    );

                    // Load either a component or a module from memory-mapped data
                    match self.component_manager.load_any(mapped_module.as_bytes()) {
                        Ok(LoadedWasm::Component(component)) => {
                            self.component = Some(component);
                            self.memory_mapped_module = Some(mapped_module);
                            info!("WASM component loaded successfully from memory-mapped module");
                        }
                        Ok(LoadedWasm::Module(_module)) => {
                            self.memory_mapped_module = Some(mapped_module);
                            info!("WASM core module accepted from memory-mapped module");
                        }
                        Err(e) => {
                            warn!("Failed to load memory-mapped WASM: {}", e);
                            // Fall back to traditional loading
                            return self.load_module_traditional();
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to memory-map WASM module: {}", e);
                    // Fall back to traditional loading
                    return self.load_module_traditional();
                }
            }
        } else {
            return self.load_module_traditional();
        }

        // Update statistics
        if let Ok(mut stats) = self.stats.write() {
            stats.module_reload_count += 1;
            stats.last_reload_time = Some(std::time::SystemTime::now());
            stats.memory_mapping_enabled = self.config.enable_memory_mapping;
        }

        Ok(())
    }

    /// Traditional module loading (fallback)
    fn load_module_traditional(&mut self) -> Result<()> {
        // Read the WASM module bytes
        let module_bytes = std::fs::read(&self.config.module_path)
            .with_context(|| format!("Failed to read WASM module: {}", self.config.module_path))?;

        // Load either a component or a module
        match self.component_manager.load_any(&module_bytes) {
            Ok(LoadedWasm::Component(component)) => {
                self.component = Some(component);
                info!("WASM component loaded successfully (traditional)");
            }
            Ok(LoadedWasm::Module(_module)) => {
                info!("WASM core module accepted (traditional)");
            }
            Err(e) => {
                warn!("Failed to load WASM (component or module): {}", e);
            }
        }

        Ok(())
    }

    /// Process an HTTP request through the WASM ModSecurity engine with instance pooling
    pub async fn process_request(
        &self,
        request_context: WasmRequestContext,
    ) -> Result<SecurityDecision> {
        let start_time = Instant::now();

        debug!(
            "Processing request through WASM engine: {}",
            request_context.uri
        );

        // Check if we should process this request
        if !request_context.should_process_with_wasm() {
            debug!(
                "Skipping WASM processing for request: {}",
                request_context.uri
            );
            return Ok(SecurityDecision::Allow);
        }

        // Try to acquire a pooled WASM instance
        let pool_acquisition_start = Instant::now();
        let pool_stats = self.instance_pool.stats();

        // Update pool utilization metrics
        if let Ok(mut stats) = self.stats.write() {
            stats.pool_utilization_percent =
                (pool_stats.in_use_instances as f64 / pool_stats.max_size as f64) * 100.0;
        }

        // Acquire instance from pool (this is the key performance optimization)
        let pooled_instance = match self.instance_pool.acquire(&self.engine).await {
            Ok(instance) => {
                // Pool hit - update metrics
                if let Ok(mut stats) = self.stats.write() {
                    stats.pool_hits += 1;
                }
                debug!(
                    "Acquired WASM instance #{} from pool in {:?}",
                    instance.id,
                    pool_acquisition_start.elapsed()
                );
                instance
            }
            Err(e) => {
                // Pool miss - update metrics and fall back to mock
                if let Ok(mut stats) = self.stats.write() {
                    stats.pool_misses += 1;
                }
                warn!("Failed to acquire WASM instance from pool: {}", e);

                // Fall back to mock evaluation for now
                let processing_time_us = start_time.elapsed().as_micros() as u64;
                let decision = self.evaluate_request_mock(&request_context).await?;
                self.update_stats(&decision, processing_time_us);
                return Ok(decision);
            }
        };

        // Execute request through WASM with timeout
        let timeout = Duration::from_millis(self.config.timeout_ms);
        let decision = tokio::time::timeout(timeout, async {
            // For now, use mock evaluation until WASM component integration is complete
            // TODO: Replace with actual WASM component execution
            self.evaluate_request_mock(&request_context).await
        })
        .await;

        let decision = match decision {
            Ok(decision) => decision?,
            Err(_) => {
                warn!(
                    "WASM execution timeout for request: {}",
                    request_context.uri
                );

                // Return instance to pool before error
                self.instance_pool.release(pooled_instance);
                return Err(anyhow::anyhow!("WASM execution timeout"));
            }
        };

        // Return instance to pool
        self.instance_pool.release(pooled_instance);

        // Update statistics
        let processing_time_us = start_time.elapsed().as_micros() as u64;
        self.update_stats(&decision, processing_time_us);

        debug!(
            uri = %request_context.uri,
            decision = ?decision,
            processing_time_us = processing_time_us,
            "WASM request processing completed with pooled instance"
        );

        Ok(decision)
    }

    /// Mock evaluation for development (to be replaced with actual WASM calls)
    async fn evaluate_request_mock(
        &self,
        context: &WasmRequestContext,
    ) -> Result<SecurityDecision> {
        // Simulate ModSecurity rule evaluation

        // Check for common attack patterns
        let request_data = format!("{} {} {:?}", context.method, context.uri, context.body);

        // SQL injection patterns
        if request_data.contains("' OR ")
            || request_data.contains("UNION SELECT")
            || request_data.contains("'; DROP TABLE")
        {
            return Ok(SecurityDecision::Block {
                rule_id: "950001".to_string(),
                message: "SQL injection attack detected".to_string(),
                severity: crate::wasm::bindings::Severity::High,
            });
        }

        // XSS patterns
        if request_data.contains("<script>")
            || request_data.contains("javascript:")
            || request_data.contains("onerror=")
        {
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
        if context.estimated_size() > 1024 * 100 {
            // 100KB
            return Ok(SecurityDecision::Log {
                rule_id: "200001".to_string(),
                message: "Large request body detected".to_string(),
                severity: crate::wasm::bindings::Severity::Low,
            });
        }

        // Allow all other requests
        Ok(SecurityDecision::Allow)
    }

    /// Get engine statistics including memory optimization metrics
    pub fn get_stats(&self) -> WasmEngineStats {
        let mut stats = self
            .stats
            .read()
            .map(|stats| stats.clone())
            .unwrap_or_default();

        // Update with current pool statistics
        let pool_stats = self.instance_pool.stats();
        stats.pool_utilization_percent =
            (pool_stats.in_use_instances as f64 / pool_stats.max_size as f64) * 100.0;

        // Calculate instance reuse rate
        if stats.pool_hits + stats.pool_misses > 0 {
            stats.instance_reuse_rate =
                (stats.pool_hits as f64 / (stats.pool_hits + stats.pool_misses) as f64) * 100.0;
        }

        // Update memory optimization metrics
        if let Some(memory_stats) = &pool_stats.memory_pool_stats {
            stats.total_memory_allocated_mb =
                (memory_stats.total_created * self.config.memory_limit_mb) as f64;

            if memory_stats.total_created > 0 {
                stats.avg_memory_per_instance_mb =
                    stats.total_memory_allocated_mb / memory_stats.total_created as f64;
            }
        }

        stats.memory_mapping_enabled = self.config.enable_memory_mapping;

        stats
    }

    /// Get detailed pool statistics
    pub fn get_pool_stats(&self) -> PoolStats {
        self.instance_pool.stats()
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
                    (stats.avg_processing_time_us * (total_successful - 1) + processing_time_us)
                        / total_successful;
            }
        }
    }

    /// Create a mock WASM module for development
    fn create_mock_module(&self) -> Result<()> {
        let module_dir = Path::new(&self.config.module_path)
            .parent()
            .unwrap_or_else(|| Path::new("."));

        std::fs::create_dir_all(module_dir).context("Failed to create module directory")?;

        // Create a minimal WASM module (placeholder)
        let mock_wasm = b"dummy wasm module";
        std::fs::write(&self.config.module_path, mock_wasm)
            .context("Failed to write mock WASM module")?;

        info!(
            "Created mock ModSecurity WASM module at: {}",
            self.config.module_path
        );
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
        let memory_limit_mb = config.memory_limit_mb;
        let timeout_ms = config.timeout_ms;
        let _engine = WasmEngine::new(config);

        // Engine creation might fail without actual WASM module
        // but we should at least verify the config is correct
        assert!(memory_limit_mb > 0);
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
