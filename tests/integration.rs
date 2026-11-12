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

// Real distri-kv end-to-end tests. Ignored by default; run
// `scripts/test-distri-e2e.sh`. `export-sled` provides the reputation fixture
// writer and the WAF's own sled exporter is not otherwise required.
#[cfg(all(feature = "distri-kv", feature = "export-sled"))]
#[path = "integration/distri_e2e.rs"]
mod distri_e2e;

#[cfg(all(feature = "io-uring", target_os = "linux"))]
#[path = "integration/io_uring_proxy_bench.rs"]
mod io_uring_proxy_bench;

#[path = "integration/pipeline_tests.rs"]
mod pipeline_tests;

#[path = "integration/proxy_tests_fixed.rs"]
mod proxy_tests;

#[path = "integration/resource_limits_tests.rs"]
mod resource_limits_tests;

#[path = "integration/waf_features_tests.rs"]
mod waf_features_tests;

#[path = "integration/websocket_tests.rs"]
mod websocket_tests;

#[cfg(feature = "webtransport")]
#[path = "integration/webtransport_tests.rs"]
mod webtransport_tests;
