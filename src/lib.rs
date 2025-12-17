//! # WAF-Rejected Main Library Entry Point
//!
//! Core WAF library providing enterprise-grade web application firewall
//! functionality with integrated reverse proxy capabilities.
//!
//! Strategic Roadmap v0.1 "The Stable Core" implementation.

// Core modules for Strategic Roadmap v0.1
pub mod config;
pub mod error;
pub mod health;
pub mod proxy;
pub mod waf;
// Performance validation module for optimizations
#[cfg(test)]
pub mod performance_validation;

// Compliance and security modules
#[cfg(feature = "compliance")]
pub mod compliance;

// Legacy AI modules (kept for compatibility)
pub mod advanced_ai_waf_integration;
pub mod advanced_ml_models;
pub mod ai_optimization_engine;
pub mod ai_threat_detection;
pub mod ai_waf_integration;
pub mod threat_intelligence;

// Advanced modules for future phases
pub mod modsecurity;

#[cfg(feature = "wasm-waf")]
pub mod wasm;

// Re-export main components for easy access
pub use config::Config;
pub use error::WafError;
pub use health::HealthService;
pub use proxy::{BufferPool, WafProxyService};
pub use waf::{Decision, RequestContext, WafEngine};

// Legacy re-exports for compatibility
pub use advanced_ai_waf_integration::{AdvancedAiWafIntegration, RequestAnalysisData};
pub use ai_optimization_engine::{AiOptimizationEngine, OptimizedThreatAnalysis};
pub use ai_threat_detection::{RequestFeatures, ThreatAnalysis, ThreatDetectionService};
pub use error::WafResult;
