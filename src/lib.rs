//! # WAF-Rejected Main Library Entry Point
//!
//! Core WAF library providing enterprise-grade web application firewall
//! functionality with integrated reverse proxy capabilities.
//!
//! Strategic Roadmap v0.1 "The Stable Core" implementation.

// Several advanced AI/threat-intelligence modules are experimental and not
// wired into the live pipeline yet. Keep their code but do not fail the build
// on their unused internals.
#![allow(dead_code)]
// Legacy AI/analytics modules carry a large amount of stylistic lint debt.
// These allows are limited to style; correctness lints remain enabled.
#![allow(
    clippy::new_without_default,
    clippy::field_reassign_with_default,
    clippy::manual_range_contains,
    clippy::derivable_impls,
    clippy::manual_clamp,
    clippy::manual_div_ceil,
    clippy::manual_flatten,
    clippy::unnecessary_map_or,
    clippy::unnecessary_get_then_check,
    clippy::len_without_is_empty,
    clippy::if_same_then_else,
    clippy::collapsible_if,
    clippy::needless_borrows_for_generic_args,
    clippy::explicit_auto_deref,
    clippy::should_implement_trait,
    clippy::match_like_matches_macro,
    clippy::manual_ignore_case_cmp,
    clippy::vec_init_then_push,
    clippy::unwrap_or_default,
    clippy::empty_line_after_doc_comments
)]

// Optional global allocator selection for benchmarking. The system allocator
// remains the default; these features are non-default and opt-in.
#[cfg(feature = "alloc-mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[cfg(feature = "alloc-jemalloc")]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

// Optional CPU affinity/pinning helpers (non-default `cpu-pinning` feature).
pub mod affinity;

// Core modules for Strategic Roadmap v0.1
pub mod config;
pub mod engine;
pub mod error;
pub mod health;
pub mod metrics;
pub mod proxy;
pub mod server;
pub mod waf;
// Performance validation module for optimizations
#[cfg(test)]
pub mod performance_validation;

// Compliance and security modules. Gated: the evidence/audit surface is
// outside the default security boundary (see docs/operations/module-scope.md).
#[cfg(feature = "compliance")]
pub mod compliance;

// Quarantined experimental surface: legacy AI/ML heuristics, threat
// intelligence and the ModSecurity scaffolding. Compiled only with the
// non-default `experimental` feature (or `ai-threat-detection`, which implies
// it). Nothing here is on the default request path.
#[cfg(feature = "experimental")]
pub mod advanced_ai_waf_integration;
#[cfg(feature = "experimental")]
pub mod advanced_ml_models;
#[cfg(feature = "experimental")]
pub mod ai_optimization_engine;
#[cfg(feature = "experimental")]
pub mod ai_threat_detection;
#[cfg(feature = "experimental")]
pub mod ai_waf_integration;
#[cfg(feature = "experimental")]
pub mod threat_intelligence;

// Advanced modules for future phases (quarantined with the experimental
// surface; nothing in the core pipeline references it).
#[cfg(feature = "experimental")]
pub mod modsecurity;

// The historical `wasm` module is retained in-tree but is not compiled:
// the Coraza/ModSecurity component ABI is not implemented for Beta.
// The `wasm-waf` feature is intentionally empty and not enabled by default.
//
// `waf::wasm_reactor` hosts the Coraza WASI reactor on wasmtime behind the
// non-default `wasm-reactor` feature; see docs/coraza-wasi-reactor.md.

// Re-export main components for easy access
pub use config::Config;
pub use error::WafError;
pub use health::HealthService;
pub use proxy::{BufferPool, WafProxyService};
pub use waf::{Decision, RequestContext, WafEngine};

// Legacy re-exports for compatibility (quarantined `experimental` surface).
#[cfg(feature = "experimental")]
pub use advanced_ai_waf_integration::{AdvancedAiWafIntegration, RequestAnalysisData};
#[cfg(feature = "experimental")]
pub use ai_optimization_engine::{AiOptimizationEngine, OptimizedThreatAnalysis};
#[cfg(feature = "experimental")]
pub use ai_threat_detection::{RequestFeatures, ThreatAnalysis, ThreatDetectionService};
pub use error::WafResult;
