//! WASM ModSecurity Integration
//!
//! This module provides a complete WASM-based ModSecurity integration for
//! the WAF-Rejected platform, enabling sandboxed rule execution with
//! high performance and hot-reloading capabilities.

pub mod bindings;
pub mod context;
pub mod engine;
pub mod middleware;
pub mod streaming;

// Re-export main components
pub use bindings::{
    ChallengeType, ComponentManager, EngineStats, SecurityDecision, SecurityError, Severity,
    WasmHostFunctions,
};
pub use context::{GeoContext, SecurityMetadata, WasmRequestContext, WasmSecurityContext};
pub use engine::{WasmEngine, WasmEngineConfig, WasmEngineStats};
pub use middleware::WasmMiddleware;

/// WASM ModSecurity integration result type
pub type WasmResult<T> = std::result::Result<T, WasmError>;

/// WASM-specific error types
#[derive(Debug, thiserror::Error)]
pub enum WasmError {
    #[error("Engine initialization failed: {0}")]
    EngineInit(#[from] anyhow::Error),

    #[error("Module loading failed: {0}")]
    ModuleLoad(String),

    #[error("Execution timeout: {0}ms")]
    Timeout(u64),

    #[error("Security processing failed: {0}")]
    SecurityProcessing(#[from] bindings::SecurityError),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Resource limit exceeded: {0}")]
    ResourceLimit(String),
}

impl From<WasmError> for crate::error::WafError {
    fn from(err: WasmError) -> Self {
        crate::error::WafError::internal(err.to_string())
    }
}
