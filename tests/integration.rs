//! Aggregated integration test target.
//!
//! Cargo only auto-discovers `tests/*.rs` and `tests/*/main.rs`; the files in
//! `tests/integration/` were previously never compiled.

#[path = "integration/ai_tests.rs"]
mod ai_tests;

#[path = "integration/auth_tests.rs"]
mod auth_tests;

#[path = "integration/grpc_tests.rs"]
mod grpc_tests;

#[cfg(feature = "wasm-reactor")]
#[path = "integration/grpc_h2_e2e.rs"]
mod grpc_h2_e2e;

#[cfg(feature = "compliance")]
#[path = "integration/compliance_tests.rs"]
mod compliance_tests;

#[path = "integration/maxmind_tests.rs"]
mod maxmind_tests;

#[cfg(all(feature = "coraza-native", unix))]
#[path = "integration/native_coraza_tests.rs"]
mod native_coraza_tests;

#[path = "integration/https_upstream_tests.rs"]
mod https_upstream_tests;

#[path = "integration/http2_tuning_tests.rs"]
mod http2_tuning_tests;

#[path = "integration/pipeline_tests.rs"]
mod pipeline_tests;

#[path = "integration/proxy_tests_fixed.rs"]
mod proxy_tests;

#[path = "integration/waf_features_tests.rs"]
mod waf_features_tests;

#[path = "integration/websocket_tests.rs"]
mod websocket_tests;

#[cfg(feature = "webtransport")]
#[path = "integration/webtransport_tests.rs"]
mod webtransport_tests;
