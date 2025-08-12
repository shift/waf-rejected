//! # WAF-Rejected Main Library Entry Point
//! 
//! Core WAF library providing enterprise-grade web application firewall
//! functionality with integrated reverse proxy capabilities.
//! 
//! Strategic Roadmap v0.1 "The Stable Core" implementation.

// Core modules for Strategic Roadmap v0.1
pub mod waf;
pub mod proxy;
pub mod health;
pub mod config;
pub mod error;

// Legacy AI modules (kept for compatibility)
pub mod ai_threat_detection;
pub mod threat_intelligence;
pub mod advanced_ml_models;
pub mod ai_waf_integration;
pub mod ai_optimization_engine;
pub mod advanced_ai_waf_integration;

// Advanced modules for future phases
pub mod modsecurity;

#[cfg(feature = "wasm-waf")]
pub mod wasm;

// Re-export main components for easy access
pub use config::Config;
pub use proxy::WafProxyService;
pub use health::HealthService;
pub use waf::{WafEngine, RequestContext, Decision};
pub use error::WafError;

// Legacy re-exports for compatibility
pub use ai_threat_detection::{ThreatDetectionService, RequestFeatures, ThreatAnalysis};
pub use ai_optimization_engine::{AiOptimizationEngine, OptimizedThreatAnalysis};
pub use advanced_ai_waf_integration::{AdvancedAiWafIntegration, RequestAnalysisData};
pub use error::WafResult;