# Module Scope and Quarantine Boundary

**Release line:** `0.1.0-beta.16`
**Status:** default build boundary for review and release.

This document defines what is inside the beta WAF security boundary, what is
quarantined behind features, and how to build each surface. Nothing was
deleted: experimental and compliance code stays in the tree, reachable only by
an explicit feature.

> **Security boundary statement.** Quarantined modules are **outside the
> security boundary**. They receive no release testing, no security review and
> no compatibility guarantee unless their feature is explicitly enabled and
> their output is separately evaluated. Do not deploy a build that enables
> `experimental`, `compliance` or `enterprise-proto` without treating that
> build as a research artifact.

## Feature map

| Feature | Default | Contents | Notes |
| --- | --- | --- | --- |
| _(none — default set)_ | yes | `waf-ingress`, proxy, config, health, metrics, WAF core, native Rust CRS engine (`rust-engine`), Coraza WASI reactor (`wasm-reactor`), security events/exporters, WebSocket, distributed client seam (`distri-kv` is a non-default feature but core-owned) | The review boundary. |
| `export-system` | yes | sled-backed event export and the legacy sled adapter | Existing default; implies `export-sled`. |
| `export-redb` | yes | redb-backed event store (default backend) | Default since the redb cut-over. |
| `export-sled` | yes | sled event exporter and storage adapter (legacy backend) | Kept for existing deployments and the migration source. |
| `websocket` | yes | WebSocket upgrade/frame inspection | Existing default. |
| `wasm-reactor` | yes | Coraza/OWASP CRS WASI reactor (reference path) | Existing default. |
| `rust-engine` | yes | Native Rust CRS engine (default backend) | Existing default. |
| `distri-kv` | no | Distributed security fabric client | Core-owned, opt-in at runtime (`[waf.distributed].enabled`). |
| `experimental` | **no** | Legacy AI/ML heuristics (`advanced_*`, `ai_*`, `threat_intelligence`), ModSecurity scaffolding, engine kernel, fast path, allow cache, CRS prefilter, io_uring prototype, legacy AI detector stage (`ai-threat-detection`, which implies `experimental`), ad-hoc test servers/demos | Quarantined. Not on the default request path. |
| `compliance` | **no** | Audit trail, retention and regulatory evidence module (`src/compliance.rs`) | Quarantined. |
| `enterprise-proto` | **no** | Enterprise acceptance/evidence test binaries | Quarantined; implies `compliance`. |

Additional non-default features that stay attached to their specific
prototype: `hyperscan-eval` (links system `libhs`, kept separate so
`experimental` does not require `vectorscan`), `coraza-native` (native Go
sidecar backend), `http3`, `webtransport`, `parallel-args`, `allow-cache`,
`crs-prefilter`, `fastpath`, `engine-kernel`, `io-uring`, `alloc-*`,
`cpu-pinning`, `export-otel`.

## Binary classification

`required-features` is set on every non-core `[[bin]]`, so `cargo build` and
`cargo build --bins` build only CORE and SUPPORT.

### CORE

| Binary | Why |
| --- | --- |
| `waf-ingress` | The shipped ingress proxy (`src/main.rs`). |
| `waf_proxy` | Compatibility alias for `waf_ingress::server::run()`; same core entry point. |

### SUPPORT — needed to build/verify the core (built by default where their feature is default)

| Binary | Why |
| --- | --- |
| `load-validate` | Config validator; the documented pre-deploy gate. |
| `crs_corpus` | Pinned CRS corpus runner and engine parity harness. |
| `rule_accounting` | Engine accounting guarantee gate. |
| `rust-engine-parity` | Differential parity harness for the default engine. Requires `rust-engine` (default). |
| `waf-events-query` | Event-export inspection tool. Requires `export-sled`. |
| `create_sample_db` | Event-store fixture builder. Requires `export-sled`. |
| `waf-storage-migrate` | Verified sled ↔ redb event-store migration (requires `export-sled` and `export-redb`, both default). |
| `grpc-allowlist` | Generates the gRPC descriptor allowlist used by shipped configs. |
| `graphql-allowlist` | Generates the GraphQL persisted-query allowlist. Requires `wasm-reactor`. |
| `coraza_abi_bench` | Coraza reactor ABI benchmark (reference path). Requires `wasm-reactor`. |
| `memory-soak` | Reactor memory soak used by the reference-path docs. Requires `wasm-reactor`. |
| `native_detect_bench` | Benchmark for the native SQLi/XSS operators. Requires `native-detect`. |
| `bodyless-bench` | Benchmark used by `docs/operations/performance-verification.md` and `scripts/verify-performance.sh`. |
| `bench-subms` | End-to-end sub-millisecond benchmark used by the perf docs. Requires `coraza-native`. |
| `distributed-cache-bench` | Distributed cache latency benchmark; distributed support is core-owned. Requires `distri-kv`. |
| `echo_backend` | Fixture upstream for e2e and performance harnesses. |
| `end_to_end_test` | Automated allow/block/413/auth proxy verification. |

### EXPERIMENTAL — quarantined (`experimental`, or the listed proto feature)

| Binary | Required feature |
| --- | --- |
| `storage_adapter_test` | `experimental` |
| `io_performance_test` | `experimental` |
| `network_io_performance_test` | `experimental` |
| `progressive_load_test` | `experimental` |
| `soak-load` | `experimental` |
| `advanced_test_backend` | `experimental` |
| `comprehensive_waf_test` | `experimental` |
| `simple_multi_protocol_test` | `experimental` |
| `phase4_comprehensive_test` | `experimental` |
| `phase4_standalone_test` | `experimental` |
| `benchmark_core` | `experimental` |
| `fastpath_bench` | `fastpath` (in `experimental`) |
| `engine-kernel-bench` | `engine-kernel` (in `experimental`) |
| `engine-kernel-corpus` | `engine-kernel` (in `experimental`) |
| `perf-gate-bench` | `wasm-reactor,rust-engine,engine-kernel` |
| `crs-prefilter-extract` | `crs-prefilter` (in `experimental`) |
| `crs-prefilter-bench` | `crs-prefilter` (in `experimental`) |
| `transform-bench` | `crs-prefilter` (in `experimental`) |
| `parallel-args-bench` | `rust-engine,parallel-args` |
| `io-uring-network-bench` | `io-uring` (in `experimental`) |
| `hyperscan-bench` | `hyperscan-eval` (kept separate: system `libhs`) |
| `benchmark_simple` | `experimental` |
| `bulk_deletion_performance_test` | `experimental` |
| `comprehensive_ttl_validation_test` | `experimental` |
| `comprehensive_waf_test_clean` | `experimental` |
| `comprehensive_waf_test_fixed` | `experimental` |
| `enhanced_ttl_performance_test` | `experimental` |
| `multi_protocol_waf_test` | `experimental` |
| `owasp_comprehensive_test` | `experimental` |
| `owasp_crs_compliance_test` | `experimental` |
| `simple_proxy_test` | `experimental` |
| `smoke_test` | `experimental` |

### COMPLIANCE / ENTERPRISE — quarantined (`enterprise-proto`)

| Binary | Why |
| --- | --- |
| `enterprise_performance_test` | Enterprise throughput evidence generator. |
| `enterprise_security_test` | Enterprise security control evidence generator. |
| `enterprise_compliance_test` | PCI/HIPAA/GDPR evidence generator. |
| `enterprise_availability_test` | Availability/resilience evidence generator. |
| `enterprise_modsecurity_test` | ModSecurity rule compliance evidence generator. |

### Previously auto-discovered targets

Cargo auto-discovers every `src/bin/*.rs`, so these files were previously built
by every `cargo build --bins` even though they had no `[[bin]]` entry. They are
now declared explicitly and quarantined. Nothing was deleted; `waf_proxy` is
declared as a CORE alias instead:

`benchmark_simple.rs`, `bulk_deletion_performance_test.rs`,
`comprehensive_ttl_validation_test.rs`, `comprehensive_waf_test_clean.rs`,
`comprehensive_waf_test_fixed.rs`, `enhanced_ttl_performance_test.rs`,
`multi_protocol_waf_test.rs`, `owasp_comprehensive_test.rs`,
`owasp_crs_compliance_test.rs`, `simple_proxy_test.rs`, `smoke_test.rs`
(all `experimental`), plus `waf_proxy.rs` (CORE).

`src/ai_waf_integration_clean.rs` and `src/helper_functions.rs` are not
referenced from `src/lib.rs` and are not compiled.

## Borderline decisions

- `echo_backend`, `end_to_end_test`: these are test servers, which would
  normally be EXPERIMENTAL. They are SUPPORT because the core proxy cannot be
  verified end-to-end without a fixture upstream; they exercise only core
  paths and do not add dependencies.
- `bench-subms`, `distributed-cache-bench`: SUPPORT with an existing
  non-default feature because the distributed/Coraza-native paths are owned by
  the core roadmap; they are not prototypes of a new detection engine.
- `coraza_abi_bench`, `memory-soak`, `native_detect_bench`: SUPPORT because
  they measure the reference path and the default engine's operators.
- `progressive_load_test`, `comprehensive_waf_test`, `simple_multi_protocol_test`:
  EXPERIMENTAL even though the flake packages them, because they are ad-hoc
  acceptance suites with their own assertions and no release gate.
- `parallel-args-bench`: EXPERIMENTAL. `parallel-args` is a candidate-level
  ARGS evaluation experiment, not part of the default request path.
- `hyperscan-eval`: not folded into `experimental` because it links the system
  `libhs`; requiring `vectorscan` for every quarantined build would make the
  feature unusable on plain hosts.

## Build recipes

```bash
# Default review boundary (CORE + SUPPORT).
cargo build --bins

# Core library tests, default and distributed.
cargo test --lib
cargo test --lib --features distri-kv

# Quarantined experimental surface (AI heuristics, prototypes, demos).
cargo build --bins --features experimental

# Quarantined compliance/enterprise evidence tooling.
cargo build --bins --features experimental,compliance,enterprise-proto

# Vectorscan/Hyperscan harness (needs system libhs, e.g. nix devShell).
cargo build --bin hyperscan-bench --features hyperscan-eval

# The shipped package (unchanged).
nix build .#waf-ingress
```

The dependency tree is also split: `reqwest` is an optional dependency tied to
`experimental`, so the default build does not compile the AI/threat-intel
heuristics or their HTTP client stack. Integration tests and benchmark examples
receive it as a dev-dependency only. Dependencies needed by core code were not
made optional.

## Enforcement

`scripts/ci-feature-matrix.sh` runs the default, `distri-kv`, `experimental`
and `compliance` library test sets and an all-targets check for
`experimental,compliance,enterprise-proto`, so the quarantined surfaces are
compiled in CI rather than silently skipped. The `justfile` exposes
`build-core`, `build-experimental`, `build-enterprise` and `test-core`.
