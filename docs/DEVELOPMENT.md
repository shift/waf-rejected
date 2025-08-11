# Development Guide

**Complete guide for developers working on WAF-Rejected**

## Development Environment Setup

### Prerequisites

- **Rust 1.89+** with cargo
- **Git** for version control
- **Linux or macOS** (Windows via WSL2)
- **Docker** (optional, for testing)
- **Nix** (recommended for reproducible environment)

### Quick Setup with Nix

The fastest way to get a development environment is using our Nix flake:

```bash
# Clone the repository
git clone https://github.com/your-org/waf-rejected.git
cd waf-rejected

# Enter development shell (installs all dependencies)
nix develop

# Verify setup
cargo --version
rustc --version
```

### Manual Setup

If you prefer not to use Nix:

```bash
# Install Rust via rustup
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Install required components
rustup component add clippy rustfmt

# Install system dependencies
# Ubuntu/Debian:
sudo apt install build-essential pkg-config libssl-dev

# macOS:
xcode-select --install
brew install openssl pkg-config

# Clone and build
git clone https://github.com/your-org/waf-rejected.git
cd waf-rejected
cargo build
```

## Project Structure

```
waf-rejected/
├── src/                    # Source code
│   ├── main.rs            # Main application entry point
│   ├── config.rs          # Configuration management
│   ├── waf/               # WAF-specific modules
│   │   ├── mod.rs         # WAF module exports
│   │   ├── middleware.rs  # HTTP middleware implementation
│   │   ├── proxy.rs       # Reverse proxy functionality
│   │   ├── rate_limit.rs  # Rate limiting implementation
│   │   └── rules.rs       # Security rule engine
│   ├── modsecurity/       # ModSecurity integration
│   │   ├── mod.rs         # ModSecurity module exports
│   │   ├── engine.rs      # Security engine core
│   │   ├── rules.rs       # Rule management
│   │   └── transaction.rs # Request/response processing
│   ├── proxy/             # Reverse proxy implementation
│   │   ├── mod.rs         # Proxy module exports
│   │   └── service.rs     # HTTP proxy service
│   ├── health.rs          # Health check endpoints
│   ├── error.rs           # Error handling and types
│   └── bin/               # Additional binaries
├── tests/                 # Integration tests
├── benches/              # Performance benchmarks
├── docs/                 # Documentation
├── config/               # Configuration examples
├── scripts/              # Build and deployment scripts
├── Cargo.toml           # Rust project configuration
├── flake.nix            # Nix development environment
└── justfile             # Command runner (just)
```

## Development Workflow

### Building and Testing

```bash
# Build in development mode
cargo build

# Build optimized release version
cargo build --release

# Run unit tests
cargo test

# Run integration tests
cargo test --features integration-tests

# Run benchmarks
cargo bench

# Check code formatting
cargo fmt --check

# Run linter
cargo clippy -- -D warnings

# Run all checks (recommended before committing)
just check-all
```

### Code Quality Tools

We use several tools to maintain code quality:

#### Rustfmt (Code Formatting)
```bash
# Format all code
cargo fmt

# Check formatting without changing files
cargo fmt -- --check
```

Configuration in `rustfmt.toml`:
```toml
edition = "2021"
max_width = 100
hard_tabs = false
tab_spaces = 4
newline_style = "Unix"
use_small_heuristics = "Default"
```

#### Clippy (Linting)
```bash
# Run clippy with all warnings as errors
cargo clippy -- -D warnings

# Run clippy for all features
cargo clippy --all-features -- -D warnings
```

#### Security Audit
```bash
# Install cargo-audit
cargo install cargo-audit

# Run security audit
cargo audit
```

### Working with Features

WAF-Rejected uses Cargo features for optional functionality:

```toml
[features]
default = ["wasm-waf", "export-system"]
wasm-waf = ["wasmtime", "wasmtime-wasi", "wasmtime-wasi-http"]
geoip = ["maxminddb"]
export-system = ["sled", "opentelemetry", "opentelemetry_sdk"]
export-otel = ["opentelemetry", "opentelemetry_sdk"]
export-sled = ["sled"]
```

Build with specific features:
```bash
# Build with all features
cargo build --all-features

# Build with specific features
cargo build --features "geoip,export-otel"

# Build without default features
cargo build --no-default-features --features "wasm-waf"
```

## Architecture Deep Dive

### HTTP Processing Pipeline

The request processing follows a layered architecture:

```rust
// Simplified flow
async fn handle_request(req: Request<Body>) -> Result<Response<Body>, WafError> {
    let context = RequestContext::new(&req);
    
    // Security analysis
    let decision = security_engine.analyze(&context).await?;
    
    match decision {
        SecurityDecision::Allow => proxy_to_upstream(req).await,
        SecurityDecision::Block { reason, rule_id } => {
            log_security_event(&context, &reason, &rule_id).await;
            Ok(create_block_response(reason))
        }
        SecurityDecision::Monitor { threat_level } => {
            log_security_event(&context, "monitoring", "").await;
            proxy_to_upstream(req).await
        }
    }
}
```

### Security Module System

Security modules implement a common trait:

```rust
#[async_trait]
pub trait SecurityModule: Send + Sync {
    /// Analyze a request and return security decision
    async fn analyze_request(
        &self,
        context: &RequestContext,
    ) -> Result<SecurityDecision, SecurityError>;
    
    /// Module name for logging and metrics
    fn module_name(&self) -> &'static str;
    
    /// Priority for execution order (lower = higher priority)
    fn priority(&self) -> u32;
    
    /// Whether this module can be bypassed under load
    fn is_essential(&self) -> bool { true }
}

pub enum SecurityDecision {
    Allow,
    Block { reason: String, rule_id: String },
    Monitor { threat_level: ThreatLevel },
}
```

Example security module implementation:

```rust
pub struct SqlInjectionDetector {
    patterns: Vec<CompiledPattern>,
}

impl SqlInjectionDetector {
    pub fn new() -> Result<Self, SecurityError> {
        let patterns = compile_patterns(&[
            r"(?i)union.*select",
            r"(?i)drop.*table", 
            r"(?i)'; *--",
            r"(?i)or.*1.*=.*1",
        ])?;
        
        Ok(Self { patterns })
    }
}

#[async_trait]
impl SecurityModule for SqlInjectionDetector {
    async fn analyze_request(
        &self,
        context: &RequestContext,
    ) -> Result<SecurityDecision, SecurityError> {
        // Check URL parameters
        for (param, value) in &context.query_params {
            if self.check_sql_injection(value) {
                return Ok(SecurityDecision::Block {
                    reason: format!("SQL injection detected in parameter: {}", param),
                    rule_id: "SQLI_001".to_string(),
                });
            }
        }
        
        // Check request body if present
        if let Some(body) = &context.body {
            if self.check_sql_injection(body) {
                return Ok(SecurityDecision::Block {
                    reason: "SQL injection detected in request body".to_string(),
                    rule_id: "SQLI_002".to_string(),
                });
            }
        }
        
        Ok(SecurityDecision::Allow)
    }
    
    fn module_name(&self) -> &'static str {
        "sql_injection_detector"
    }
    
    fn priority(&self) -> u32 {
        100  // High priority
    }
}
```

### Configuration System

The configuration system uses a layered approach with Serde:

```rust
#[derive(Debug, Clone, Deserialize)]
pub struct WafConfig {
    pub server: ServerConfig,
    pub upstream: UpstreamConfig,
    pub security: SecurityConfig,
    pub logging: LoggingConfig,
    pub exports: Option<ExportsConfig>,
}

impl WafConfig {
    pub fn load() -> Result<Self, ConfigError> {
        let mut settings = config::Config::builder()
            // Default values
            .add_source(config::File::from_str(
                include_str!("../config/defaults.toml"),
                config::FileFormat::Toml,
            ))
            // User config file
            .add_source(
                config::File::with_name("config")
                    .required(false)
                    .format(config::FileFormat::Toml),
            )
            // Environment variables (prefixed with WAF_)
            .add_source(
                config::Environment::with_prefix("WAF")
                    .prefix_separator("_")
                    .separator("__"),
            )
            .build()?;
            
        settings.try_deserialize()
    }
}
```

### Error Handling

WAF-Rejected uses comprehensive error handling with `thiserror`:

```rust
#[derive(Error, Debug)]
pub enum WafError {
    #[error("Configuration error: {0}")]
    Config(#[from] ConfigError),
    
    #[error("Security module error: {0}")]
    Security(#[from] SecurityError),
    
    #[error("Proxy error: {0}")]
    Proxy(#[from] ProxyError),
    
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("HTTP error: {0}")]
    Http(#[from] hyper::Error),
}

impl WafError {
    pub fn to_http_response(&self) -> Response<Body> {
        match self {
            WafError::Security(_) => Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Body::from("Request blocked by security policy"))
                .unwrap(),
            _ => Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR) 
                .body(Body::from("Internal server error"))
                .unwrap(),
        }
    }
}
```

## Testing Strategy

### Unit Tests

Each module should have comprehensive unit tests:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_sql_injection_detection() {
        let detector = SqlInjectionDetector::new().unwrap();
        
        let context = RequestContext {
            query_params: vec![
                ("id".to_string(), "1".to_string()),
                ("filter".to_string(), "1' OR 1=1--".to_string()),
            ],
            body: None,
            ..Default::default()
        };
        
        let decision = detector.analyze_request(&context).await.unwrap();
        
        match decision {
            SecurityDecision::Block { reason, rule_id } => {
                assert!(reason.contains("SQL injection"));
                assert_eq!(rule_id, "SQLI_001");
            }
            _ => panic!("Expected block decision"),
        }
    }
    
    #[test]
    fn test_config_loading() {
        let config_str = r#"
            [server]
            host = "127.0.0.1"
            port = 8080
            
            [upstream]
            base_url = "http://localhost:3000"
        "#;
        
        let config: WafConfig = toml::from_str(config_str).unwrap();
        assert_eq!(config.server.host, "127.0.0.1");
        assert_eq!(config.server.port, 8080);
    }
}
```

### Integration Tests

Integration tests verify end-to-end functionality:

```rust
// tests/integration/security_tests.rs
use waf_ingress::*;
use hyper::{Body, Request, Response, StatusCode};
use tokio::net::TcpListener;

#[tokio::test]
async fn test_sql_injection_blocking() {
    // Start test WAF instance
    let config = WafConfig::test_config();
    let waf = WafService::new(config).await.unwrap();
    
    // Start background server
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        waf.serve(listener).await.unwrap();
    });
    
    // Send malicious request
    let client = hyper::Client::new();
    let uri = format!("http://{}/test?id=1' OR 1=1--", addr).parse().unwrap();
    let response = client.get(uri).await.unwrap();
    
    // Should be blocked
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}
```

### Benchmarking

Performance benchmarks use Criterion:

```rust
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn benchmark_security_modules(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let detector = SqlInjectionDetector::new().unwrap();
    
    let context = RequestContext {
        query_params: vec![("q".to_string(), "SELECT * FROM users".to_string())],
        ..Default::default()
    };
    
    c.bench_function("sql_injection_detection", |b| {
        b.to_async(&rt).iter(|| async {
            let result = detector.analyze_request(black_box(&context)).await.unwrap();
            black_box(result);
        })
    });
}

criterion_group!(benches, benchmark_security_modules);
criterion_main!(benches);
```

## Contributing Guidelines

### Code Style

- Follow Rust standard formatting (`cargo fmt`)
- Use meaningful variable and function names
- Add comprehensive documentation for public APIs
- Include unit tests for all new functionality
- Keep functions focused and small (generally <50 lines)

### Commit Messages

Use conventional commit format:

```
type(scope): description

feat(security): add XSS detection module
fix(config): handle missing upstream URL gracefully  
docs(api): update authentication examples
test(proxy): add integration tests for rate limiting
perf(engine): optimize pattern matching with SIMD
```

### Pull Request Process

1. **Create Feature Branch**: `git checkout -b feature/add-xss-detection`
2. **Implement Changes**: Follow coding standards and add tests
3. **Run Quality Checks**: `just check-all` passes without errors
4. **Update Documentation**: Update relevant docs and examples
5. **Create Pull Request**: Include description and test results
6. **Address Review Comments**: Respond to feedback promptly
7. **Merge**: Squash commits for clean history

### Testing Requirements

All PRs must include:
- Unit tests for new functionality (aim for >90% coverage)
- Integration tests for new security modules
- Benchmarks for performance-critical code
- Documentation updates for public APIs

## Release Process

### Version Management

We follow semantic versioning (SemVer):
- **Major**: Breaking API changes
- **Minor**: New features, backward compatible
- **Patch**: Bug fixes, backward compatible

### Release Checklist

1. **Update Version**: Update `Cargo.toml` and documentation
2. **Update Changelog**: Document all changes since last release
3. **Run Full Test Suite**: All tests pass including security tests
4. **Performance Validation**: Benchmarks meet performance targets
5. **Security Audit**: `cargo audit` passes without issues
6. **Build Release Artifacts**: Build for all supported platforms
7. **Tag Release**: `git tag v0.2.0` and push to GitHub
8. **Publish**: Cargo publish and Docker image push
9. **Update Documentation**: Deploy updated docs to website

## Debugging and Profiling

### Debug Builds

```bash
# Build with debug info
cargo build

# Run with detailed logging
RUST_LOG=debug ./target/debug/waf-ingress

# Run with async runtime debugging
TOKIO_CONSOLE_BIND=127.0.0.1:6669 ./target/debug/waf-ingress
```

### Performance Profiling

```bash
# Profile with perf (Linux)
perf record --call-graph dwarf ./target/release/waf-ingress
perf report

# Memory profiling with valgrind
valgrind --tool=massif ./target/release/waf-ingress

# Flame graph generation
cargo flamegraph --bin waf-ingress
```

### Load Testing

```bash
# Apache Bench
ab -n 10000 -c 100 http://localhost:8080/

# wrk
wrk -t12 -c400 -d30s http://localhost:8080/

# Custom load test
cargo run --bin load-test -- --target http://localhost:8080 --rps 1000
```

## Security Considerations

### Secure Development Practices

- **Input Validation**: All external input must be validated
- **Error Handling**: Never expose internal details in error messages
- **Resource Limits**: Implement bounds checking and rate limiting
- **Dependency Scanning**: Regular security audits of dependencies
- **Secret Management**: No secrets in code or configuration files

### Security Testing

- **Fuzzing**: Use `cargo-fuzz` for finding edge cases
- **Static Analysis**: Regular `cargo-clippy` and `cargo-audit` runs
- **Dynamic Testing**: Integration tests with malicious payloads
- **Penetration Testing**: Regular security assessments

This development guide provides the foundation for contributing effectively to WAF-Rejected while maintaining our high standards for performance, security, and code quality.
