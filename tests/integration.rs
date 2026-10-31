//! Aggregated integration test target.
//!
//! Cargo only auto-discovers `tests/*.rs` and `tests/*/main.rs`; the files in
//! `tests/integration/` were previously never compiled.

#[path = "integration/ai_tests.rs"]
mod ai_tests;

#[path = "integration/auth_tests.rs"]
mod auth_tests;

#[cfg(feature = "compliance")]
#[path = "integration/compliance_tests.rs"]
mod compliance_tests;

#[path = "integration/maxmind_tests.rs"]
mod maxmind_tests;

#[path = "integration/pipeline_tests.rs"]
mod pipeline_tests;

#[path = "integration/proxy_tests_fixed.rs"]
mod proxy_tests;

#[path = "integration/waf_features_tests.rs"]
mod waf_features_tests;

#[path = "integration/websocket_tests.rs"]
mod websocket_tests;
