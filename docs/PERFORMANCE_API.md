# WAF Performance Optimizations API Reference

This document provides comprehensive API documentation for the WAF-Rejected performance optimization features, including buffer pooling and SIMD acceleration.

## Buffer Pool API (`src/proxy/buffer_pool.rs`)

### BufferPool

High-performance buffer pooling system for zero-allocation HTTP processing.

```rust
pub struct BufferPool {
    pools: [Pool; 3],
}

impl BufferPool {
    /// Creates a new buffer pool with default configuration
    pub fn new() -> Self
    
    /// Creates a buffer pool with custom configuration
    pub fn with_config(config: BufferPoolConfig) -> Self
    
    /// Gets a buffer suitable for the specified size
    pub fn get_buffer(&self, size: usize) -> BufferGuard
    
    /// Returns pool statistics
    pub fn stats(&self) -> BufferPoolStats
}
```

### BufferGuard

RAII wrapper ensuring automatic buffer return to pool.

```rust
pub struct BufferGuard {
    buffer: Option<Box<[u8]>>,
    pool: Arc<BufferPool>,
    size_class: usize,
}

impl BufferGuard {
    /// Returns the size of the buffer
    pub fn len(&self) -> usize
    
    /// Returns true if the buffer is empty
    pub fn is_empty(&self) -> bool
    
    /// Gets a mutable slice to the buffer data
    pub fn as_mut_slice(&mut self) -> &mut [u8]
    
    /// Gets an immutable slice to the buffer data
    pub fn as_slice(&self) -> &[u8]
}

impl Drop for BufferGuard {
    fn drop(&mut self) {
        // Automatically returns buffer to pool
    }
}
```

### BufferPoolConfig

Configuration options for buffer pool behavior.

```rust
pub struct BufferPoolConfig {
    pub small_buffer_size: usize,      // Default: 4KB
    pub medium_buffer_size: usize,     // Default: 64KB  
    pub large_buffer_size: usize,      // Default: 1MB
    pub max_buffers_per_size: usize,   // Default: 1000
}

impl Default for BufferPoolConfig {
    fn default() -> Self {
        Self {
            small_buffer_size: 4 * 1024,
            medium_buffer_size: 64 * 1024,
            large_buffer_size: 1024 * 1024,
            max_buffers_per_size: 1000,
        }
    }
}
```

### BufferPoolStats

Runtime statistics for monitoring buffer pool performance.

```rust
pub struct BufferPoolStats {
    pub total_allocations: u64,
    pub total_deallocations: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub current_allocated: [usize; 3],  // Per size class
    pub peak_allocated: [usize; 3],     // Per size class
}

impl BufferPoolStats {
    /// Calculates cache hit ratio as percentage
    pub fn hit_ratio(&self) -> f64 {
        if self.total_allocations == 0 {
            0.0
        } else {
            (self.cache_hits as f64 / self.total_allocations as f64) * 100.0
        }
    }
    
    /// Returns total memory currently allocated
    pub fn total_memory_allocated(&self) -> usize
}
```

## SIMD Operations API (`src/waf/simd_ops.rs`)

### CPU Feature Detection

```rust
pub struct SimdCapabilities {
    pub has_avx512: bool,
    pub has_avx2: bool,
    pub has_sse42: bool,
}

impl SimdCapabilities {
    /// Detects available SIMD capabilities at runtime
    pub fn detect() -> Self
    
    /// Returns the best available SIMD instruction set
    pub fn best_available(&self) -> SimdInstructionSet
}

pub enum SimdInstructionSet {
    Avx512,
    Avx2,
    Sse42,
    Scalar,
}
```

### Pattern Matching Functions

```rust
/// Fast pattern search using best available SIMD instructions
pub fn fast_pattern_search(haystack: &[u8], pattern: &[u8]) -> Option<usize>

/// Check if content contains SQL injection patterns
pub fn contains_sql_injection_patterns(content: &[u8]) -> bool

/// Check if content contains XSS patterns  
pub fn contains_xss_patterns(content: &[u8]) -> bool

/// Multi-pattern search for security threats
pub fn scan_for_threats(content: &[u8]) -> Vec<ThreatMatch>
```

### ThreatMatch

```rust
pub struct ThreatMatch {
    pub threat_type: ThreatType,
    pub position: usize,
    pub pattern: String,
    pub confidence: f32,
}

pub enum ThreatType {
    SqlInjection,
    XssAttack,
    PathTraversal,
    CommandInjection,
}
```

### SIMD Implementation Functions

Lower-level SIMD implementations for specific instruction sets.

```rust
/// AVX-512 implementation (unsafe)
pub unsafe fn fast_pattern_search_avx512(haystack: &[u8], pattern: &[u8]) -> Option<usize>

/// AVX2 implementation (unsafe)
pub unsafe fn fast_pattern_search_avx2(haystack: &[u8], pattern: &[u8]) -> Option<usize>

/// SSE4.2 implementation (unsafe)
pub unsafe fn fast_pattern_search_sse42(haystack: &[u8], pattern: &[u8]) -> Option<usize>

/// Scalar fallback implementation
pub fn fast_pattern_search_scalar(haystack: &[u8], pattern: &[u8]) -> Option<usize>
```

## Integration APIs

### Proxy Service Integration

```rust
// src/proxy/service.rs
impl ProxyService {
    /// Handle HTTP request with buffer pool optimization
    pub async fn handle_request_optimized(&self, req: Request<Body>) -> Result<Response<Body>>
    
    /// Read request body into pooled buffer
    async fn read_body_into_buffer(&self, body: Body, buffer: &BufferGuard) -> Result<&[u8]>
}
```

### Content Inspection Integration

```rust
// src/waf/content_inspection.rs
impl ContentInspector {
    /// Fast-path content inspection using SIMD
    pub async fn inspect_content_fast_path(&self, content: &[u8]) -> InspectionResult
    
    /// Full content inspection with regex fallback
    pub async fn inspect_content_full(&self, content: &[u8]) -> InspectionResult
}

pub enum InspectionResult {
    Allowed,
    Blocked(String),
    Suspicious(String),
}
```

## Performance Validation API

```rust
// src/performance_validation.rs

/// Run buffer pool performance tests
pub fn test_buffer_pool_performance() -> Result<PerformanceResult, String>

/// Run SIMD operations performance tests
pub fn test_simd_performance() -> Result<PerformanceResult, String>

/// Run integrated performance tests
pub fn test_integrated_performance() -> Result<PerformanceResult, String>

pub struct PerformanceResult {
    pub test_name: String,
    pub latency_p99_ns: u64,
    pub throughput_ops_per_sec: u64,
    pub memory_usage_mb: f64,
    pub cpu_usage_percent: f64,
    pub passed: bool,
}
```

## Configuration Integration

### TOML Configuration

```toml
[buffer_pool]
small_buffer_size = 4096          # 4KB buffers
medium_buffer_size = 65536        # 64KB buffers  
large_buffer_size = 1048576       # 1MB buffers
max_buffers_per_size = 1000       # Maximum pooled buffers
enable_buffer_pool = true         # Enable buffer pooling

[simd]
enable_simd = true                # Enable SIMD acceleration
force_cpu_features = []           # Override CPU detection (testing only)
simd_pattern_threshold = 256      # Minimum content size for SIMD
enable_fast_path = true           # Enable SIMD pre-filtering

[performance]
enable_performance_metrics = true # Enable runtime performance tracking
metrics_collection_interval = 60  # Seconds between metrics collection
```

### Configuration Loading

```rust
// src/config.rs
#[derive(Deserialize)]
pub struct Config {
    pub buffer_pool: BufferPoolConfig,
    pub simd: SimdConfig, 
    pub performance: PerformanceConfig,
}

impl Config {
    /// Load configuration from TOML file
    pub fn from_file(path: &str) -> Result<Self, ConfigError>
    
    /// Create configuration with performance optimizations enabled
    pub fn with_performance_optimizations() -> Self
}
```

## Error Handling

```rust
#[derive(Debug, thiserror::Error)]
pub enum PerformanceError {
    #[error("Buffer pool exhausted")]
    BufferPoolExhausted,
    
    #[error("SIMD operation failed: {0}")]
    SimdOperationFailed(String),
    
    #[error("Performance requirement not met: expected {expected}, got {actual}")]
    PerformanceRequirementNotMet {
        expected: String,
        actual: String,
    },
    
    #[error("Configuration error: {0}")]
    ConfigurationError(String),
}
```

## Usage Examples

### Basic Buffer Pool Usage

```rust
use waf_clean::proxy::buffer_pool::{BufferPool, BufferPoolConfig};

// Create buffer pool with default configuration
let pool = BufferPool::new();

// Get buffer for 8KB request
let buffer_guard = pool.get_buffer(8192);

// Use buffer (automatically returned when guard drops)
let data = buffer_guard.as_slice();
println!("Buffer size: {}", data.len());

// Check pool statistics
let stats = pool.stats();
println!("Hit ratio: {:.1}%", stats.hit_ratio());
```

### SIMD Pattern Matching

```rust
use waf_clean::waf::simd_ops::{fast_pattern_search, contains_sql_injection_patterns};

let content = b"SELECT * FROM users WHERE id = 1";

// Fast pattern search
if let Some(pos) = fast_pattern_search(content, b"SELECT") {
    println!("Found SELECT at position {}", pos);
}

// Check for SQL injection patterns
if contains_sql_injection_patterns(content) {
    println!("Potential SQL injection detected!");
}
```

### Integrated Usage in Proxy

```rust
use waf_clean::proxy::{ProxyService, buffer_pool::BufferPool};
use waf_clean::waf::content_inspection::ContentInspector;

// Setup optimized proxy service
let buffer_pool = Arc::new(BufferPool::new());
let content_inspector = ContentInspector::new();
let proxy = ProxyService::new(buffer_pool, content_inspector);

// Handle request with optimizations
let response = proxy.handle_request_optimized(request).await?;
```

## Performance Benchmarks

Expected performance characteristics:

| Operation | Latency | Throughput | Memory |
|-----------|---------|------------|---------|
| Buffer Pool Get | <100μs | >100k ops/s | 99.9% reuse |
| SIMD Pattern Match (AVX-512) | <50ns | >2M ops/s | Zero-copy |
| SIMD Pattern Match (AVX2) | <100ns | >1M ops/s | Zero-copy |
| Integrated HTTP Processing | <650μs P99 | >140k req/s | <85MB |

## Thread Safety

All APIs are designed to be thread-safe:

- **BufferPool**: Thread-safe with parking_lot mutexes and atomic counters
- **SIMD Operations**: Stateless functions safe for concurrent use
- **Performance Metrics**: Atomic counters for thread-safe statistics collection

## Memory Management

- **Buffer Pool**: Pre-allocated buffers with RAII cleanup
- **SIMD Operations**: Zero-copy operations where possible
- **No Memory Leaks**: Automatic cleanup through Drop implementations