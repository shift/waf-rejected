// WAF Ingress Library
// High-Performance Rust-Based WAF with AI/ML Threat Detection

pub mod ai_threat_detection;
pub mod waf;
pub mod proxy;
pub mod health;
pub mod config;
pub mod error;
pub mod modsecurity;
pub mod threat_intelligence;
pub mod advanced_ml_models;
pub mod ai_waf_integration;
pub mod ai_optimization_engine;
pub mod advanced_ai_waf_integration;

// Re-export commonly used types
pub use ai_threat_detection::{ThreatDetectionService, RequestFeatures, ThreatAnalysis};
pub use ai_optimization_engine::{AiOptimizationEngine, OptimizedThreatAnalysis};
pub use advanced_ai_waf_integration::{AdvancedAiWafIntegration, RequestAnalysisData};
pub use config::Config;
pub use error::{WafError, WafResult};