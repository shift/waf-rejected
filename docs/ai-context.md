# AI Agent Context - WAF-Rejected Web Application Firewall

## Project Overview

WAF-Rejected is a high-performance, enterprise-grade Web Application Firewall (WAF) implemented in Rust. It functions as a reverse proxy with integrated security filtering, supporting HTTP/1-3, WebSocket, and WebTransport protocols. The system prioritizes security-first design with sub-millisecond latency and comprehensive threat detection.

**Key Technologies**: Rust, Tokio (async), Hyper (HTTP), Wasmtime (WASM), Sled (embedded DB), OpenTelemetry.

**Architecture**: Modular design with core WAF engine, proxy service, security modules, and event exporters.

## Quick Start for AI Agents

### Essential Files to Read First
1. `AGENTS.md` - Coding guidelines and workflow
2. `current-task.md` - Current development task and status
3. `src/lib.rs` - Library exports and module structure
4. `src/main.rs` - Main binary entry point
5. `Cargo.toml` - Dependencies and feature flags

### Build Commands
- **Development shell**: `nix develop`
- **Build all**: `nix build`
- **Test**: `nix develop -c cargo test --lib` and `nix develop -c cargo test --test integration`
- **Format check**: `nix develop -c cargo fmt -- --check`
- **Lint check**: `nix develop -c cargo clippy -- --deny warnings`

### Current Development Status
- **Release line**: `0.1.0-beta.14` plus Unreleased changes.
- **Default engine**: native Rust CRS engine (`rust-engine`); Coraza 3.3.3 WASI
  reactor is the reference and explicit `backend = "wasm"` switch-back.
- **Security status**: see the control matrix in
  `docs/architecture/security-model.md`; it is not a certification.

## Architecture Summary

### Core Components
- **WAF Engine** (`src/waf/`): Rule evaluation, security decisions
- **Proxy Service** (`src/proxy/`): Multi-protocol reverse proxy
- **Security Modules**: Content inspection, rate limiting, geo-blocking
- **Event System**: CEF/OTEL/Sled exporters for security events
- **WASM Integration**: Coraza 3.3.3 WASI reactor (reference/fallback); the legacy `rules/coraza.wasm` is not a Coraza engine

### Key Patterns
- **Async-First**: Tokio runtime for concurrency
- **Tower Middleware**: Composable service stack
- **Trait-Based Rules**: Extensible security logic
- **Configuration-Driven**: TOML-based settings with environment overrides

### Security Requirements
- **Fail-Safe**: Configurable fail-open/fail-closed modes
- **Audit Trails**: Persistent security event logging
- **Compliance**: Enterprise security standards
- **Performance**: Sub-millisecond latency requirements

## Common AI Agent Tasks

### Adding New Security Rules
```rust
// Example: Implement custom rule in src/waf/rules.rs
pub struct CustomRule {
    pattern: Regex,
}

impl WafRule for CustomRule {
    fn evaluate(&self, ctx: &RequestContext) -> Decision {
        if self.pattern.is_match(&ctx.uri) {
            Decision::Block {
                status: StatusCode::FORBIDDEN,
                reason: "Custom rule violation".to_string(),
            }
        } else {
            Decision::Allow
        }
    }
}
```

### Modifying Proxy Behavior
```rust
// Integration point in src/proxy/service.rs around line 320
// Add middleware after body collection but before WAF evaluation
let body_bytes = collect_body().await?;

// Insert custom logic here
if custom_condition(&body_bytes) {
    return create_error_response(StatusCode::BAD_REQUEST, "Custom validation failed");
}

// Continue to WAF evaluation
let decision = waf_engine.evaluate(&request_context).await?;
```

### Configuration Extensions
```toml
# Add to config/*.toml
[security.custom_module]
enabled = true
rules = ["rule1", "rule2"]
threshold = 100
```

## File Navigation Guide

### For Security Features
- Rules: `src/waf/rules.rs`, `rules/coraza.conf`
- Content Inspection: `src/waf/content_inspection.rs`
- Rate Limiting: `src/waf/rate_limit.rs`
- Geo Blocking: `src/waf/geoip.rs`

### For Proxy Features
- Core Proxy: `src/proxy/service.rs`
- WebSocket: `src/proxy/websocket.rs`
- WASM: `src/wasm/`

### For Configuration
- Main Config: `src/config.rs`
- Examples: `config/*.toml`

### For Testing
- Unit Tests: Alongside source files (e.g., `src/waf/rules.rs` has tests)
- Integration: `tests/integration/`
- Benchmarks: `benches/`, `benchmarks/`

## Development Workflow

1. **Read AGENTS.md** for guidelines
2. **Check current-task.md** for active work
3. **Create feature branch**: `git checkout -b type/short-description`
4. **Implement with tests**
5. **Run checks**: Format, lint, build, test
6. **Commit atomically**: `git commit -m "type(scope): description"`
7. **Create PR** with detailed description

## Security Considerations

- **Never compromise security** for simplicity
- **Validate all inputs** and prevent injection
- **Log security events** persistently
- **Use secure defaults** (HTTPS required, etc.)
- **Document security decisions** in code comments

## Performance Targets

- **Latency**: Sub-millisecond for simple requests
- **Throughput**: High concurrency with async processing
- **Memory**: Efficient streaming for large payloads
- **CPU**: Optimized rule evaluation with fast paths

This document provides the minimum context needed for AI agents to contribute effectively to WAF-Rejected development.