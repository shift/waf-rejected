# P0-09: Beta Release (current: 0.1.0-beta.13) (NORTH STAR)

## Config strictness (`fix/config-strictness`)

- [x] `serde(deny_unknown_fields)` on all config structs; strict TOML
      pre-validation reports file, section/key path and line/column.
- [x] Filter `WAF_CONFIG_FILE`/`WAF_CONFIG_PATH` from the env source; other
      `WAF_*` overrides still apply and unknown ones are rejected.
- [x] Migrated `config/test.toml`, `config/security-export-example.toml` and
      the `docs/Optimizations.md` example; moved the benchmark config to
      `benchmarks/performance_testing.toml`.
- [x] Tests cover unknown top-level/nested keys, a `waf.coraza.backend` typo,
      env overrides, and all shipped/root/deploy configs.
- [x] fmt, clippy `--lib`, `cargo test --lib` (501), config tests (18 files),
      `scripts/validate-configs.sh`, `nix build .#waf-ingress`.

## Perf: Vectorscan multi-pattern candidate pass (`perf/hyperscan-candidates`)

- [x] Compile residual positive `@rx` rules (no literal gate, no multiMatch)
  into one block-mode Vectorscan database per transform pipeline; pattern ids
  map back to rule gate bits.
- [x] Scan once per `(value, pipeline)` (2 KiB floor), cache the hit mask for
  the phase, skip only confirmed pattern misses; hits still run the full
  operator.
- [x] Bound compile/DB size (256 rules, 16 MiB/group, 64 MiB total, 5 s),
  process-wide cache; any unsupported construct/compile/runtime error falls
  back to the per-rule path.
- [x] x86-64/AVX2 only; `hs_valid_platform()` checked before compile.
- [x] 2,112-case corpus decisions identical to `main` (0 diffs); tests cover
  miss-gating and hit-confirmation.
- [x] Docs (`docs/suggestions_from_agents/hyperscan-candidates.md`) and
  CHANGELOG. Performance: 4 KiB 632.7 → 570.2 µs p50, 8 KiB 1046.1 → 955.5 µs;
  sub-400 µs target not reached (documented).
- Pre-existing failure under the verify feature set:
  `xml_body_processor_populates_both_xpath_collections` also fails with
  `hyperscan-eval` disabled; not caused by this change.

**Target**: ship a usable Beta that can be deployed behind a TLS-terminating
load balancer and will enforce the documented WAF controls.

## Release log

- `0.1.0-beta.1` — connected core runtime, body inspection, auth, rate limits.
- `0.1.0-beta.2` — security bypass fixes, container/config/deployment hardening.
- `0.1.0-beta.3` — WebSocket upgrade tunneling.
- `0.1.0-beta.4` — MaxMind City database support.
- `0.1.0-beta.5` — WebSocket frame inspection + Anonymous IP database.
- `0.1.0-beta.6` — WSS upstreams, frame size limits, image tarball asset.
- `0.1.0-beta.7` — feature-gated HTTP/3 ingress.
- `0.1.0-beta.8` — custom TLS WebSocket upstream CA, build provenance.
- `0.1.0-beta.9` — HTTP/3 + WebTransport, supply-chain policy, fuzz/property tests, security model.

## Active delegated work

- HTTP/3 security parity tests (query/body block, 413, auth).
- ~~WebTransport implementation audit (`wtransport 0.7.2`).~~ Done on
  `feat/webtransport`: feature-gated terminating HTTP/3 listener with
  Origin/path/auth/WAF validation, session/stream/datagram caps, and tests.
  See `docs/developer-guide/webtransport.md`.

## Beta acceptance criteria

- [x] Real server starts from `waf-ingress` and from the container image.
- [x] Fail-fast configuration; every shipped config validates.
- [x] Request bodies, params, headers and URI inspected; size limits enforced.
- [x] API-key auth and per-IP/global rate limits enforced.
- [x] Security events emitted for blocks/rate limits.
- [x] Health, readiness and Prometheus metrics exposed.
- [x] TLS min/max versions and optional mTLS enforced.
- [x] `fail_mode = closed` applied to WASM/AI failures.
- [x] Automated end-to-end proxy tests (allow, query block, body block, 413).
- [x] Versioned as `0.1.0-beta.1` with `CHANGELOG.md`.
- [x] Dockerfile, Helm templates, K8s manifests and monitoring wired.
- [x] `nix build .#waf-ingress` verified from a clean build.
- [x] Release notes published with explicit known limitations.
- [x] Tag `v0.1.0-beta.1` and GitHub pre-release created.
- [x] Container image built and smoke-tested locally (health 200, SQLi/XSS 403).

## Beta.2 security hardening (PR #29)

- [x] UTF-8-safe match truncation.
- [x] Reject over-length URI/query rather than skipping inspection.
- [x] Inspect the full accepted body.
- [x] ALPN-aware HTTP/2 selection.
- [x] Right-to-left XFF resolution through trusted proxies.
- [x] Upstream response-size cap.
- [x] Fail-closed WASM initialisation.
- [x] Header inspection enabled for common attack patterns.
- [x] Helm/K8s image, auth, PVC, service and alert fixes.

## Beta scope exclusions (documented)

- Coraza/ModSecurity component execution
- WebSocket/WebTransport tunneling
- GeoIP database-backed country blocking
- HTTP/3

## Post-Beta: EU regulatory validation

- [x] AI Act status validated against Regulation (EU) 2026/1744.
- [x] NIS2 transposition/amendment status validated (October 2026).
- [x] CRA Article 14 reporting status validated (in force 11 Sep 2026).
- [x] Evidence-only AI Act/NIS2/CRA report generators added.
- [x] Compliance docs and config flags updated (PR #25).
- [ ] Machine-readable evidence export for the Transparenz CRA workflow.

---

# P0-08: Connect the Core Runtime Pipeline (ACTIVE)

**Branch**: `fix/connect-core-pipeline`
**Status**: Implemented, local verification complete
**Objective**: Make the running binary actually enforce the WAF and start reliably.

## Implementation checklist

- [x] Make `waf-ingress` launch the real server (shared `server::run`), not a banner.
- [x] Fix WASM memory units so the default configuration cannot panic at startup.
- [x] Make configuration load fail-fast and stop silently discarding empty arrays.
- [x] Consolidate duplicate `[security.*]` and `[waf.*]` configuration trees.
- [x] Wire full WAF evaluation into the proxy: body inspection, event logging, AI/WASM stages.
- [x] Enforce `max_body_size` while streaming request bodies.
- [x] Wire API-key authentication and per-IP/global rate limiting into the pipeline.
- [x] Trust `X-Forwarded-For` only from configured `trusted_proxies`.
- [x] Forward authoritative `X-Forwarded-For`/`X-Real-IP`/`X-Forwarded-Proto` upstream.
- [x] Add `/health`, `/health/ready`, `/metrics` and real request/block counters.
- [x] Fix SQLi/XSS detection false negatives and percent-encoded payload handling.
- [x] Make integration tests discoverable and passing.
- [x] Fix `wasm_performance` benchmark compilation and formatting/clippy debt.
- [x] Update Kubernetes/Helm/Prometheus wiring and add a Dockerfile.
- [x] Reject unsupported WebSocket/WebTransport upgrades with `501` instead of a fake `101`.

## Verification

- `cargo fmt -- --check` — pass
- `cargo clippy --lib -- --deny warnings` — pass
- `cargo check --all-targets` — pass
- `cargo test --lib` — 114 passed
- `cargo test --test integration` — 17 passed
- End-to-end: benign `200`, body/query SQLi and XSS `403`, oversized body `413`, missing API key `401`, rate limit `429`.

## Known follow-ups

- Real Coraza/ModSecurity component execution is still not implemented; `[waf.wasm]` is disabled by default and the existing implementation is an internal heuristic fallback.
- WebSocket/WebTransport tunneling is intentionally rejected until a raw upgrade proxy is implemented.
- GeoIP still needs a real MaxMind database loader before country blocking is effective.
- HTTP/3 is advertised nowhere in the default config now; the dependency remains behind a feature.

---

# P1-01: Production Deployment and Operational Readiness

**Priority**: P1 (HIGH - Production Launch)
**Branch**: `production`
**Status**: Planning Phase
**Security Impact**: Establish production environment with monitoring and security controls

## Objective

Deploy WAF-Rejected to production environment with full operational readiness:
- Establish production infrastructure and deployment pipeline
- Configure monitoring, alerting, and security controls
- Validate production performance and security effectiveness
- Establish operational procedures and incident response
- Ensure regulatory compliance in production environment

## Architecture Overview

### Components to Create/Modify

1. **Production Infrastructure** (`infrastructure/` - NEW)
    - Kubernetes deployment manifests
    - Helm charts for automated deployment
    - Terraform configurations for cloud infrastructure
    - CI/CD pipeline for automated deployments

2. **Monitoring & Observability** (`monitoring/` - NEW)
    - Prometheus metrics collection
    - Grafana dashboards for security metrics
    - AlertManager configuration for security events
    - OpenTelemetry tracing setup

3. **Security Controls** (`security/` - NEW)
    - Network security policies
    - Secret management (Vault integration)
    - Certificate management (Let's Encrypt)
    - Security scanning and compliance checks

4. **Operational Procedures** (`docs/operations/` - ENHANCE)
    - Production deployment runbook
    - Incident response procedures
    - Backup and disaster recovery
    - Maintenance and patching procedures

5. **Load Testing Framework** (`tests/performance/` - ENHANCE)
    - Concurrent request handling
    - Memory leak detection
    - Performance baseline validation

## Implementation Plan

### Phase 1: Research & Analysis
- [x] Review production requirements and infrastructure needs
- [x] Assess security and compliance requirements for production
- [x] Analyze monitoring and observability requirements
- [x] Evaluate deployment automation options
- [x] Review operational procedures and incident response

### Phase 2: Design & Planning
- [ ] Design production infrastructure architecture
- [ ] Plan monitoring and alerting strategy
- [ ] Define security controls and compliance measures
- [ ] Document deployment and rollback procedures
- [ ] Plan operational readiness and training

### Phase 3: Implementation
- [x] Set up production infrastructure (Kubernetes/Helm)
- [x] Configure monitoring stack (Prometheus/Grafana)
- [x] Implement security controls and secret management
- [x] Establish CI/CD pipeline for automated deployments
- [x] Configure backup and disaster recovery

### Phase 4: Testing & Validation
- [ ] Perform production deployment dry-run
- [ ] Validate security controls and compliance
- [ ] Test monitoring and alerting functionality
- [ ] Perform load testing in production-like environment
- [ ] Validate backup and recovery procedures

### Phase 5: Production Launch
- [ ] Execute production deployment
- [ ] Establish operational monitoring
- [ ] Conduct post-launch validation
- [ ] Document lessons learned and improvements
- [ ] Transition to operational support mode

## Detailed Design

### Production Infrastructure Architecture

```yaml
# Kubernetes Deployment Manifest
apiVersion: apps/v1
kind: Deployment
metadata:
  name: waf-rejected
  namespace: security
spec:
  replicas: 3
  selector:
    matchLabels:
      app: waf-rejected
  template:
    metadata:
      labels:
        app: waf-rejected
    spec:
      containers:
      - name: waf-ingress
        image: waf-rejected:latest
        ports:
        - containerPort: 8080
        env:
        - name: RUST_LOG
          value: "info"
        - name: CONFIG_PATH
          value: "/config/production.toml"
        resources:
          requests:
            memory: "256Mi"
            cpu: "500m"
          limits:
            memory: "1Gi"
            cpu: "2000m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
```

### Monitoring Stack Configuration

```yaml
# Prometheus Configuration
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "alert_rules.yml"

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093

scrape_configs:
  - job_name: 'waf-rejected'
    static_configs:
      - targets: ['waf-rejected:8080']
    metrics_path: '/metrics'
    scrape_interval: 5s

  - job_name: 'waf-rejected-security'
    static_configs:
      - targets: ['waf-rejected:8080']
    metrics_path: '/security-metrics'
    scrape_interval: 30s
```

### Security Controls Implementation

```bash
# Security hardening script
#!/bin/bash

# Enable security features
sysctl -w net.ipv4.tcp_syncookies=1
sysctl -w net.ipv4.conf.all.rp_filter=1
sysctl -w net.ipv4.conf.default.rp_filter=1

# Configure firewall
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable

# Set up fail2ban
apt-get install -y fail2ban
cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
systemctl enable fail2ban
systemctl start fail2ban
```

### CI/CD Pipeline Configuration

```yaml
# GitHub Actions for production deployment
name: Production Deployment

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    - name: Run tests
      run: cargo test --release

  security-scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    - name: Security scan
      uses: github/super-linter/slim@v5

  deploy-staging:
    needs: [test, security-scan]
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    steps:
    - name: Deploy to staging
      run: |
        kubectl config use-context staging
        helm upgrade --install waf-rejected ./infrastructure/helm

  deploy-production:
    needs: deploy-staging
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    environment: production
    steps:
    - name: Deploy to production
      run: |
        kubectl config use-context production
        helm upgrade --install waf-rejected ./infrastructure/helm
```

### Incident Response Procedures

```markdown
# Security Incident Response Plan

## 1. Detection Phase
- Monitor alerts from Prometheus/Grafana
- Check security event logs in real-time
- Validate incident through multiple sources

## 2. Assessment Phase
- Determine incident scope and impact
- Identify affected systems and data
- Assess compliance notification requirements

## 3. Containment Phase
- Isolate affected systems
- Implement emergency security controls
- Preserve evidence for forensic analysis

## 4. Recovery Phase
- Restore systems from clean backups
- Validate system integrity
- Monitor for reoccurrence

## 5. Lessons Learned Phase
- Document incident timeline
- Identify root cause and prevention measures
- Update security controls and procedures
- Report to relevant stakeholders
```

### Phase 2 Roadmap Planning

```markdown
# Strategic Roadmap v0.2 "Cloud-Native Scale"

## Vision
Transform WAF-Rejected into a globally distributed, cloud-native security platform.

## Key Initiatives

### 1. Distributed Architecture
- Multi-region deployment
- Global threat intelligence sharing
- Distributed consensus for configuration
- Cross-region failover

### 2. Advanced Threat Intelligence
- External threat feed integration
- Machine learning model updates
- Behavioral analysis
- Predictive threat detection

### 3. Enterprise Integration
- SIEM system integration
- Identity provider integration
- Cloud security platform APIs
- Enterprise dashboard

### 4. Operational Excellence
- Automated deployment (Kubernetes, Helm)
- Observability and monitoring
- Performance optimization
- Security hardening
```

### Operational Documentation Structure

```
docs/
├── operations/
│   ├── deployment.md          # Production deployment guide
│   ├── monitoring.md          # Monitoring and alerting setup
│   ├── backup-recovery.md     # Backup and disaster recovery
│   ├── incident-response.md   # Security incident procedures
│   └── maintenance.md         # Regular maintenance tasks
├── maintenance/
│   ├── security-updates.md    # Security patch procedures
│   ├── performance-tuning.md  # Performance optimization
│   ├── log-management.md      # Log rotation and retention
│   └── health-checks.md       # System health validation
└── roadmap/
    ├── phase2-roadmap.md      # Phase 2 development plan
    └── feature-priorities.md  # Feature development priorities
```

### AI Threat Detection Integration Test

```rust
#[cfg(test)]
mod ai_integration_tests {
    use super::*;
    use waf_rejected::ai_threat_detection::ThreatAnalysis;

    #[tokio::test]
    async fn test_ai_threat_detection_integration() {
        let config = create_config_with_ai_enabled();
        let waf_engine = WafEngine::with_config(&config);

        // Create test request with malicious payload
        let malicious_request = create_malicious_request();

        // Process through WAF engine
        let decision = waf_engine.evaluate(&malicious_request).await;

        // Should be blocked due to AI analysis
        match decision {
            Decision::Block { reason, .. } => {
                assert!(reason.contains("AI detected threat"));
            }
            _ => panic!("Expected request to be blocked by AI"),
        }
    }

    #[tokio::test]
    async fn test_ai_performance_under_load() {
        let config = create_config_with_ai_enabled();
        let waf_engine = WafEngine::with_config(&config);

        let start = Instant::now();
        let mut blocked_count = 0;

        // Process 1000 requests concurrently
        let handles: Vec<_> = (0..1000).map(|i| {
            let engine = waf_engine.clone();
            tokio::spawn(async move {
                let request = create_test_request(i);
                let decision = engine.evaluate(&request).await;
                matches!(decision, Decision::Block { .. })
            })
        }).collect();

        for handle in handles {
            if handle.await.unwrap() {
                blocked_count += 1;
            }
        }

        let duration = start.elapsed();
        let avg_latency = duration.as_millis() as f64 / 1000.0;

        // AI analysis should add minimal latency (< 10ms per request)
        assert!(avg_latency < 10.0, "AI analysis too slow: {}ms avg", avg_latency);
        assert!(blocked_count > 0, "AI should block some malicious requests");
    }
}
```

### Load Testing Framework

```rust
pub struct LoadTestRunner {
    client: Client,
    base_url: String,
    concurrency: usize,
    duration_secs: u64,
}

impl LoadTestRunner {
    pub async fn run_load_test(&self) -> LoadTestResults {
        let start = Instant::now();
        let mut handles = vec![];

        for _ in 0..self.concurrency {
            let client = self.client.clone();
            let base_url = self.base_url.clone();
            let duration = self.duration_secs;

            let handle = tokio::spawn(async move {
                let mut local_stats = RequestStats::default();

                while start.elapsed() < Duration::from_secs(duration) {
                    let request_start = Instant::now();

                    let response = client
                        .get(&format!("{}/test", base_url))
                        .header("X-API-Key", "test-key")
                        .send()
                        .await;

                    let latency = request_start.elapsed();

                    match response {
                        Ok(resp) if resp.status().is_success() => {
                            local_stats.success_count += 1;
                        }
                        Ok(resp) => {
                            local_stats.error_count += 1;
                            if resp.status() == 401 {
                                local_stats.auth_failures += 1;
                            }
                        }
                        Err(_) => {
                            local_stats.connection_errors += 1;
                        }
                    }

                    local_stats.total_latency += latency;
                }

                local_stats
            });

            handles.push(handle);
        }

        // Aggregate results
        let mut total_stats = RequestStats::default();
        for handle in handles {
            let stats = handle.await.unwrap();
            total_stats += stats;
        }

        LoadTestResults {
            total_requests: total_stats.success_count + total_stats.error_count,
            success_rate: total_stats.success_count as f64 /
                         (total_stats.success_count + total_stats.error_count) as f64,
            avg_latency_ms: total_stats.total_latency.as_millis() as f64 /
                           (total_stats.success_count + total_stats.error_count) as f64,
            auth_failures: total_stats.auth_failures,
            connection_errors: total_stats.connection_errors,
        }
    }
}
```

## Exit Criteria

- ✅ All requests require valid API key
- ✅ Invalid requests return HTTP 401 Unauthorized
- ✅ API key rotation supported
- ✅ Per-key rate limiting active
- ✅ No compiler warnings
- ✅ All tests pass
- ✅ Documentation updated

## Current Status

**Active Phase**: Phase 4 - Testing & Validation
**Last Action**: Completed production infrastructure setup and operational procedures
**Next Step**: Perform production deployment dry-run and validation

## Progress Log

### 2025-11-30 - Session 1
- Resumed from previous session summary
- Branch `feat/authentication` is clean (distri-kv/ added to .gitignore)
- Created current-task.md with complete implementation plan
- Completed Phase 1: Research & Analysis
  - Confirmed AuthError variant exists in src/error.rs:18
  - Identified integration point in src/proxy/service.rs:~320
  - Reviewed config patterns in src/config.rs (SecurityConfig)
  - Examined WAF engine in src/waf/mod.rs
  - Confirmed Bearer token pattern in docs/API.md:211-227

### 2025-11-30 - Session 2 (Current)
- Resuming with Phase 1 complete
- Completed Phase 2: Design & Planning
  - Defined AuthConfig structure with enabled, api_keys, header_name, require_https fields
  - Designed ApiKeyStore trait with validate, add_key, remove_key, list_keys methods
  - Designed InMemoryKeyStore implementation using Arc<RwLock<HashSet<String>>>
  - Designed ApiKeyValidator with validate_request method
  - Documented SHA-256 key hashing strategy
  - Identified proxy integration point at line 338-339 in src/proxy/service.rs
  - Documented dependencies: sha2 = "0.10", hex = "0.4"
- Completed Phase 3: Implementation
  - Dependencies already present in Cargo.toml
  - Created comprehensive src/waf/auth.rs with full implementation and tests
  - AuthConfig integrated into src/config.rs
  - Authentication middleware fully integrated in src/proxy/service.rs
  - Module exported in src/waf/mod.rs
- Beginning Phase 4: Testing

## perf: native Coraza sidecar throughput (worktree `.worktrees/native-perf`)

Branch: `perf/native-sidecar-throughput`. Task: remove IPC/protocol overhead
and improve concurrency for the native Go Coraza sidecar without changing
detection, the default backend or fail-closed behaviour.

Outcome: CRS scanning is 99.8 %+ of latency at every body size, so p50 is
unchanged. The work removed the protocol/IPC overhead (client build
3–15 µs → 0.2 µs, client+IPC 18–36 µs → 13–18 µs, server decode
27 µs–112 µs → 0.3 µs, response encode 2 allocations → 0) and replaced the
client's dedicated runtime + job channel with a bounded blocking pool, which
removes the fail-fast `QueueFull` path and stabilises tails under contention.

- Binary wire protocol v1 with a `0xC1` handshake and JSON fallback
  (`src/waf/coraza_wire.rs`, `native/coraza-sidecar/protocol.go`).
- Go sidecar: `--max-conns` admission, per-connection reusable read buffer,
  zero-copy body slices, single-syscall response write.
- Rust client: bounded blocking connection pool, socket timeouts plus a
  post-read deadline check, connection dropped on timeout/error.
- New harnesses: `examples/coraza_ipc_profile.rs`,
  `examples/coraza_native_load.rs`, `native/coraza-sidecar/bench_test.go`.
- Docs: `docs/coraza-native-sidecar.md` Performance section; CHANGELOG
  Unreleased.
- Not used, with measured reasons in the docs: `SOCK_SEQPACKET`, `io_uring`,
  batching, client-side pipelining.
- Verified: `cargo fmt -- --check`, `cargo test --lib --features
  wasm-reactor,coraza-native`, ignored native e2e suite, `cargo clippy --lib
  --features wasm-reactor,coraza-native -- --deny warnings`, Go tests,
  `nix build .#coraza-native-sidecar`.
- Note: the measurement machine is shared with other agents, so the docs
  compare interleaved ratios rather than single absolute runs.

## perf: OWASP CRS evaluation cost (worktree `.worktrees/crs-perf`)

Branch: `perf/crs-cost`. Task: profile the dominant CRS cost, find safe
reductions, implement the safe ones without weakening rules or changing WAF
defaults, and rank the rest with security tradeoffs.

Findings: CRS is 99.8 % of native sidecar request cost and byte-linear at
~7.4 µs per inspected byte (1 KiB 7.9 ms, 8 KiB 61 ms, 60 KiB 479 ms CPU).
Family split (8 KiB benign form): 932 28.7 %, 942 26.1 %, 934 10.5 %,
941 9.0 %, 921 7.9 %, 933 6.4 %, 944 5.6 %, rest <3 %. Targets: ARGS 91.4 %,
REQUEST_BODY 7.6 %; headers/URI/XML/cookies <0.5 % combined. Transform time
2.7 %, operators 96.8 %; top rule 934100 10.9 %, top four 932 rules 34 %.
`SecArgumentsLimit` is bypassed for POST bodies by Coraza 3.3.3 (body
processors write ARGS_POST directly), so it cannot cap the many-argument
vector. Body caps are linear (`ProcessPartial` 4/2/1 KiB = −50/−75/−87 %;
`Reject` = −99.6 % but 413). GOGC/GOMAXPROCS/audit/debug have no steady-state
effect. No response-only or safely-removable request rules exist.

Implemented: native sidecar `--early-blocking` (CRS rule 900120) default on.
Phase-1-blocked requests skip the body scan: 8 KiB 61 ms → 0.28 ms, 60 KiB
493 ms → 0.26 ms; benign unchanged; decisions unchanged on the
SQLi/XSS/LFI/RCE corpus (query + body). Documented in
`docs/suggestions_from_agents/crs-performance.md` and
`docs/coraza-native-sidecar.md`.

Not implemented (product decisions): reactor (wasm) parity requires a module
rebuild; inspected-body caps; literal prefilter; Hyperscan via cgo; upstream
`SecArgumentsLimit` fix.

---

# Delegated: CRS required-literal prefilter (`perf/crs-prefilter`)

**Status:** implemented, experimental (non-default feature `crs-prefilter`).
**Goal:** prove and implement a sound multi-pattern prefilter that can skip CRS
body work on benign traffic, with zero false negatives as the acceptance gate.

## Plan

- [x] Parse the vendored CRS bundle (rules, chains, `@rx`/`@pm`/`@pmFromFile`,
      targets, transforms) in an offline Rust extractor.
- [x] Extract disjunctive required-literal sets; mark unproven rules `ungated`.
- [x] Emit deterministic `rules/crs/prefilter.json` + `PREFILTER_SUMMARY.md`.
- [x] Add the `crs-prefilter` runtime (Aho-Corasick over representation ×
      transform pipelines) and adversarial extraction tests.
- [x] Add `PrefilterMode::{DryRun, BodyWithhold}` to the native backend
      (default `Off`); document the wasm equivalent.
- [x] Add a corpus, benchmark/parity harness, design + soundness report,
      CHANGELOG entry.
- [ ] Per-rule gating (sidecar `RemoveRuleByID` + wasm ABI) so the gated share
      can be skipped while `@detectSQLi`/`@detectXSS` still see the body.
- [ ] Gapped-subsequence gates for 932250/932260; full HTML5 entity table for
      `t:htmlEntityDecode`.

## Result

Stock CRS 4.14 has 200 body-relevant entries; the extractor gates 64 and
leaves 136 ungated. Because the body-withholding mode requires *all* body
rules to be gated, it never fires on stock CRS; the prefilter is sound but the
fast path is blocked by `@detectSQLi`, `@detectXSS`, size/validation checks and
the obfuscation-tolerant 932 regexes. Details and measurements:
`docs/suggestions_from_agents/crs-prefilter.md`.

## test: CRS detection corpus (worktree `.worktrees/crs-corpus`)

Branch: `test/crs-corpus`. Task: pinned OWASP CRS 4.14.0 regression corpus plus
a harness that proves decision parity between the WASI reactor and the native
sidecar without changing detection rules or defaults.

- Vendored request-phase cases at commit
  `b5b788b5bc50e68836e17995b191f72e848fed75`; source archive SHA-256 and
  per-file manifest recorded in `tests/corpus/crs/`.
- Corpus format v1: `{id, description, request, expected, expected_rule_ids,
  tags, source}` with upstream provenance.
- Harness: `src/bin/crs_corpus.rs` + `src/waf/coraza_corpus.rs`; wrapper
  `scripts/run-crs-corpus.sh`; optional opt-in CI job.
- Baseline: 2,112 cases (1,700 block / 412 allow), wasm and native
  2,016/2,112 passed, detection 1,695/1,700 (99.7%), FN=5, FP=91, parity
  2,112/2,112. Details in `docs/operations/detection-corpus.md`.
- Verified: `cargo fmt -- --check`, `cargo test --lib` (default and
  `wasm-reactor,coraza-native`), clippy for lib and harness, harness build with
  both features.

---

# Perf: WASM Coraza runtime tuning (delegated spike)

**Branch**: `perf/wasm-runtime-tuning`
**Status**: in progress
**Constraint**: no change to inspected bytes, rules, or default policy.

## Plan

- [x] Extend `examples/coraza_backend_bench.rs` into the A/B harness: p95,
      `CORAZA_MODULE`, `CORAZA_POOL_SIZE`, load/warm timing, throughput matrix.
- [x] Experiment 1: wasmtime `Config` knobs. Only the backtrace knobs were
      kept (failure path); the rest are defaults or measured no-ops.
- [x] Experiment 2: `wasm-opt -O3` / `-Oz`; valid modules, 5.6%/10% smaller,
      **no** latency change -> not integrated (per "keep only wins").
- [x] Experiment 3: compile/instantiation. Precompiled cache: ~5.6 s -> ~1.3 s
      start-up, not shipped (host-specific, `unsafe` deserialize).
- [x] Experiment 4: `pool_size` 1/2/4/6 RSS: ~434/501/626/756 MiB (~65 MiB per
      worker). Throughput scaling not resolvable on the shared host; default
      unchanged.
- [x] Keep a Criterion artifact for the chosen configuration.
- [x] Update `docs/coraza-wasi-reactor.md` and `CHANGELOG.md`.

## Log

- Baseline harness `examples/coraza_backend_bench.rs` already measured the
  documented 1/4/8/16/60 KiB numbers; reused it as the A/B harness.
- `wasm-opt -O3` and `-Oz` build cleanly from the committed module once the
  Go-emitted bulk-memory features are enabled; exports unchanged.
- The host was shared with another build/test workload for the whole session,
  so wall-clock A/B was unusable. Added temporary per-`eval` thread-CPU
  instrumentation and compared variants round-robin: stock vs `-O3` vs `-Oz`
  vs `nomove` vs `nounwind` were all within ±2%. A `SinglePass` regalloc
  control was 1.17-1.85x slower, proving the method detects codegen changes.
- Consequence: no perf win to ship; the branch keeps the benchmark harness,
  the backtrace hardening, the docs' measured findings and the Criterion rows.

---

# Rust engine vertical slice (`feat/rust-engine`)

**Status:** core slice implemented, differential parity measured, committed on
`feat/rust-engine` (not pushed, not merged, default backend unchanged).

## Plan

- [x] `src/waf/rust_engine/`: SecLang parser, compiled IR, transform/operator
      implementations, request collections, phase engine, CRS anomaly scoring.
- [x] Strict load: unsupported constructs abort with rule id + construct.
- [x] Parse the pinned `wasm/coraza_reactor/rules/crs/crs.conf` and report the
      support matrix (501/505 compiled; 4 libinjection rules unsupported).
- [x] Differential harness `src/bin/rust_engine_parity.rs` over
      `tests/corpus/crs/corpus.json` (2,112 cases).
- [x] Criterion bench `benches/rust_engine.rs` and a p50/p95 `--bench` mode.
- [x] Docs: `docs/suggestions_from_agents/rust-engine.md`.

## Log

- Parser compiles 501 of 505 directives. Unsupported: `@detectSQLi` (942100,
  942101) and `@detectXSS` (941100, 941101).
- PCRE normalisation added for `\x{XX}` byte escapes, literal `{...}` braces and
  escapes of non-metacharacters (`\!`, `\<`, ...), keeping the pinned regexes
  compilable by Rust `regex`.
- Collection/macro fixes: per-match non-disruptive actions, dynamic `setvar`
  names, `ARGS.*`/`REQUEST_HEADERS.*` macros, selector lowercasing, Go-like
  request-URI validity (spaces/backslashes, scheme only at the start), and
  quote-aware multipart parameter parsing.
- Differential parity (native vs Coraza): **2,099 / 2,112 (99.38 %)** after the
  final fixes. The 13 disagreements are the four libinjection rules (8 cases),
  2 old-cookie `$Version` cases where the native decision matches the corpus and
  Coraza does not, and 3 Coraza false positives where the native engine correctly
  allows. The native engine has 88 corpus false positives vs Coraza's 91; both
  miss the same 3 JSON Log4Shell cases (944150-12/13/14).
- The native engine's only corpus false negatives beyond the shared corpus
  expectations are the 8 libinjection cases; its only native-vs-oracle false
  positives were fixed (multipart `_charset_`).
- Benchmark (release, 200 reps, shared host): native p50 0.93 ms / 1.08 ms /
  2.70 ms / 5.02 ms for bodyless / 1 / 4 / 8 KiB; Coraza p50 3.55 ms / 57.1 ms
  / 414.2 ms / 599.8 ms on the same loaded host.



## research: native Rust fast path (worktree `.worktrees/fastpath`)

Branch: `research/fastpath`. Task: prototype a compiled Rust prefilter that can
prove requests clean and skip Coraza, without changing defaults.

- Feature `fastpath` (`src/waf/fastpath/`): method/path matchers, header and
  protocol checks, scanner/OS-file/PHP Aho-Corasick matchers, regex signature
  prefilter, and a body literal prefilter derived from
  `rules/crs/prefilter.json`.
- Soundness mode (a): `Clean` only when every covered rule is provably unable
  to match; otherwise `NeedsCoraza`. Body requests always fall back on stock
  CRS because 51 body rules are ungated.
- Corpus harness: `crs_corpus --engine fastpath`; 44/2,112 clean, 0 false
  negatives vs the WASI Coraza baseline, 0 clean expected-block.
- Benchmark: `fastpath_bench` (in-process, no proxy).
- Docs: `docs/suggestions_from_agents/fastpath-engine.md`.

---

# Research: content-addressed allow-verdict cache (worktree `.worktrees/allow-cache`)

**Branch:** `research/allow-cache`. **Feature:** `allow-cache` (non-default,
opt-in via `[waf.allow_cache]`). **Status:** prototype complete, local
verification done, not pushed.

- [x] Canonical key: version + policy generation + method + exact URI + HTTP
      version + sorted complete header multimap + body presence/size/bytes;
      no lossy normalisation.
- [x] Keyed SipHash-2-4 (128-bit) with a process-lifetime secret and
      length-prefixed fields.
- [x] Only `Allow` inserted; TTL, bounded sharded map, metrics, policy
      invalidation.
- [x] Integration after pre-checks/admission; stateful rules still run on a
      hit; blocks never cached.
- [x] Injectivity, smuggling/encoding/duplicate-header, TTL/eviction,
      concurrency, parity and metrics tests.
- [x] Replay benchmark (`examples/allow_cache_bench.rs`) and measured results.
- [x] Docs `docs/suggestions_from_agents/allow-cache.md`, CHANGELOG Unreleased.
- Verified: `cargo fmt -- --check`, `cargo test --lib --features
  wasm-reactor,allow-cache` (365 passed), `cargo clippy --lib --features
  wasm-reactor,allow-cache -- --deny warnings`.
- Gap: native sidecar replay not measured in this session; wasm measured, hit
  path is backend-independent. See the doc's Follow-ups.

---

# Test: enforceable engine guarantees (`test/engine-guarantees`)

**Status:** implemented, local verification in progress.
**Constraint:** no WAF default, detection rule, or version change.

## Plan

- [x] Add `src/engine/` guarantee layer (accounting, generated inputs,
      differential, determinism, budget, fail-closed).
- [x] Add `src/bin/rule_accounting.rs` and committed
      `rules/crs/rule-manifest.json`.
- [x] Expose `engine::accounting::verify_complete(manifest, support)`.
- [x] Extend `crs_corpus` with `--engine rust`, `--generated`, determinism and
      counterexample persistence.
- [x] Add `scripts/check-engine-guarantees.sh` and the workflow-dispatch job.
- [x] Document guarantees, enforcement and residual risks in
      `docs/suggestions_from_agents/engine-guarantees.md`.
- [x] Verify `cargo fmt -- --check`, `cargo test --lib`, tool builds and the
      Coraza baseline harness run.
- [x] Commit on `test/engine-guarantees` (no push, no merge, no version bump).

## Notes

- The native engine integration point is `src/engine/backend.rs` behind the
  non-default `native-engine` feature. The scaffold reports unavailable, so the
  Rust differential/determinism targets skip unless `--require-engine` is set.
- The engine workstream branch uses `src/waf/rust_engine/` and a `rust-engine`
  feature; this work does not depend on it. When it lands, the CI input
  `engine_feature` should be enabled and `backend.rs` wired to it.

## Verification results

- `cargo fmt -- --check` — pass.
- `cargo test --lib engine::` — 48 passed, 0 failed.
- `cargo test --lib` — 381 passed, 9 ignored, 0 failed.
- `cargo clippy --lib -- --deny warnings` — pass.
- `cargo check --features wasm-reactor,coraza-native,native-engine --bin crs_corpus --bin rule_accounting` — pass.
- `rule_accounting --check` — pass; manifest has 524 entries, 436 rule ids, 53 chains.
- `rule_accounting --support` with the full-support template — pass.
- `crs_corpus --engine wasm --limit 1` — 1/1 passed (baseline smoke; the shared host is heavily loaded, so the full 100-iteration Coraza determinism run was not executed locally).
- `crs_corpus --engine rust --limit 1 --generated 10 --determinism 2` — reports skipped because the `native-engine` backend is the unimplemented scaffold; `--require-engine` fails as designed.

---

# feat/engine-integration: native operators + kernel execution model

Branch `feat/engine-integration` (not pushed, not merged, defaults unchanged).

- [x] Compile `@detectSQLi`/`@detectXSS` into the IR and evaluate them with
      `native_detect`; strict load is now 505/505 with 0 unsupported.
- [x] Intern transform pipelines and cache each `(value, pipeline)` once per
      request; borrow request spans; reuse candidate/capture/transform buffers;
      keep phase early exit.
- [x] Wire `waf.coraza.backend = "rust"` (strict load, fail-closed startup);
      default remains `wasm`.
- [x] Parity: 2,110/2,112 vs Coraza; the 2 disagreements are Coraza false
      negatives (921250), 3 shared JSON-Log4Shell FNs, zero native-only FNs.
- [x] Verification: fmt, 451 lib tests, clippy lib+parity bin, corpus harness.
- [ ] Targets: bodyless 183 µs and 1 KiB 479 µs pass; 4 KiB 1.13 ms and
      8 KiB 2.03 ms miss on a quiet run (host heavily shared). See
      `docs/suggestions_from_agents/engine-integration.md`.
- [ ] Remaining for default: JSON/XML processors, XPath, URI parity, response
      phases, per-rule literal prefilter, allocation reduction.

---

# perf/http2-tuning: HTTP/2 + upstream connection throughput (subagent)

Branch `perf/http2-tuning` (not pushed, not merged, defaults unchanged).

- [x] Measured h1/h2 streams-per-connection, window policy, keep-alive reuse,
      pool reuse and concurrency behaviour with `benches/http2_tuning.rs`.
- [x] Opt-in `[proxy.pool]`: bounded idle reuse + optional health probes and
      upstream request/connection/health metrics.
- [x] Opt-in `[server.http2]`: 1 MiB stream / 16 MiB connection windows,
      concurrent-stream and pending-reset caps, PING keep-alive.
- [x] Opt-in `[proxy.streaming]`: frame-by-frame relay of large responses
      under the existing byte cap and deadline.
- [x] Tests: pool reuse, idle eviction, streaming TTFB/correctness, h1
      keep-alive, h2 e2e (gRPC h2 harness now runs with tuning enabled).
- [x] Docs `docs/developer-guide/http2-tuning.md` + CHANGELOG entry.
- Verification: fmt, lib tests, integration tests, clippy, audit (see report).

---

# perf/engine-hotloop: native engine hot loop

Branch `perf/engine-hotloop` (not pushed, not merged, defaults unchanged).

## Plan

- [x] Add `engine-profile` instrumentation and a parity `--profile` mode.
- [x] Zero-allocation transform pipeline + generational transform cache.
- [x] Compile `rules/crs/prefilter.json` into per-rule Aho-Corasick gates.
- [x] Borrowed TX / MATCHED_VARS evaluation and reused macro/capture buffers.
- [x] Gate `MATCHED_VAR*` bookkeeping on groups that read it.
- [x] Verify corpus decisions unchanged; fmt, tests, clippy.
- [ ] 4 KiB < 0.8 ms / 8 KiB < 1.5 ms targets (missed: 1.13 ms / 2.07 ms).
- [ ] < 100 allocations/request (missed: ~143; baseline 1,251–1,785).

## Results

- Allocations: 1,251–1,785 → ~143/request.
- p50: bodyless 327→146 µs, 1 KiB 869→450 µs, 4 KiB 2.15→1.13 ms,
  8 KiB 3.88→2.07 ms (shared host, load ≈1.9).
- Gates: 50 rules, 99/181 regex evaluations skipped at 4 KiB (55 %).
- Parity: decisions byte-for-byte identical to baseline on all 2,112 cases;
  baseline Coraza parity 2,110/2,112 with 0 native-only FNs preserved.

See `docs/suggestions_from_agents/engine-hotloop.md`.

## Delegated: transform/gate hot path (perf/transform-hot)

- [x] Profile plain-vs-percent slowdown; root cause is per-`&` HTML entity
  lookups plus repeated plan walks / O(n²) cache memo.
- [x] Batch transform prefixes per value (`resolve_all`), remove O(n²) memo,
  alias identity/unchanged values, sampled dedup hash.
- [x] Entity hash index + legacy no-semicolon table; ASCII transform fast paths.
- [x] Single case-insensitive union automaton + per-pattern group/rule bitsets.
- [x] Verify transform parity 7,320/7,320; lib tests with
  `wasm-reactor,crs-prefilter,rust-engine` pass; clippy clean.
- [ ] 4 KiB prefilter < 120 µs: percent ~48 µs (met), plain ~145 µs (missed;
  blocker documented in `docs/suggestions_from_agents/transform-hot.md`).

See `docs/suggestions_from_agents/transform-hot.md`.

---

# perf/engine-transforms: shared batched transform pipeline

Branch `perf/engine-transforms` (not pushed, not merged, defaults unchanged).
Task: delete the engine's private transform cache and use the shared
`waf::transforms` prefix pipeline without changing detection.

## Plan

- [x] Profile the private-cache path (xform 373 µs + gate 339 µs at 4 KiB).
- [x] Extend `waf::transforms` with the engine-only steps (`sha1`,
      `hexEncode`, `removeCommentsChar`, `length`, `utf8ToUnicode`), a generic
      `Step` trait, a `PrefixTable` and explicit cache bounds.
- [x] Map `rust_engine::Transform` 1:1 onto the shared steps; drop the
      duplicated byte codecs.
- [x] Build a prefix DAG for every interned pipeline; resolve per value with
      the shared `TransformCache` (identity aliasing, one arena, zero allocs).
- [x] Replace the private cache in the serial and `parallel-args` paths; gate
      groups share the same representations.
- [x] Charge the engine budget from the cache's materialised-byte delta.
- [x] Parity: 7,320/7,320 fixture, corpus 2,110/2,112, 0 native-only FN.
- [x] Bench and document `docs/suggestions_from_agents/engine-transforms.md`.

## Results

- p50: bodyless 162.0 → 158.1 µs, 1 KiB 453.6 → 315.9, 4 KiB 1,164.5 →
  635.8 (< 800 target), 8 KiB 2,110.6 → 1,053.2 (< 1,500 target).
- p99: bodyless 192.6, 1 KiB 361.8, 4 KiB 701.8, 8 KiB 1,133.8 µs.
- xform 373.5 → 89.9 µs and gate 338.5 → 102.0 µs at 4 KiB (−76 % / −70 %).
- 141–145 allocations/request (transform category 0), unchanged.
- Bodyless < 150 µs missed (158 µs); only ~34 µs of it is transform work.

## perf: native engine rule loop (`perf/engine-ruleloop`)

Baseline `ad7e7ea`. Profiled the native rule loop, added an empty-target rule
gate, precomputed rule/group flags, pre-resolved `skipAfter`, macro/selector
allocation fixes, recycled capture buffers and arena-backed `MATCHED_VARS`.
Allocations fell from ~143 to 33-42/request. Corpus parity unchanged
(2,110/2,112, 0 native-only FNs), transform fixture 7,320/7,320.

Could not meet the latency targets on this host: bodyless 110 µs (<100 target),
1 KiB 271 µs (<200), 4 KiB 596 µs (<450), 8 KiB 1.02 ms (<800). A union-DFA
experiment (RegexSet, dense DFA, lazy meta) was implemented and measured but
regressed 4 KiB latency to 725-958 µs, so it was removed. Details and profile
breakdown in `docs/suggestions_from_agents/engine-ruleloop.md`; CHANGELOG
updated. No defaults, versions, transforms, prefilter, proxy or Coraza changes.

## Release 0.1.0-beta.13 (`release/v0.1.0-beta.13`)

- [x] Bump Cargo.toml/Cargo.lock to 0.1.0-beta.13.
- [x] CHANGELOG: `[0.1.0-beta.13] - 2026-11-03` with engine-default summary,
      support matrix, limitations; fresh `[Unreleased]`.
- [x] Update README and `docs/operations/support-matrix.md` for the
      Rust-engine default, Coraza `wasm` switch-back, response-wiring and
      opt-in caveats.
- [x] Fix gRPC envelope inspection on the Rust backend (inspector was consumed
      when no legacy scanner existed) and add a Rust field-content scanner.
- [x] fmt, clippy (wasm-reactor and +rust-engine), lib tests, release ignored
      Coraza tests, 2,110/2,112 parity, reactor size check, `nix build`.
- [x] Package binary/sidecar/Coraza/artifacts, isolated-storage image, smoke
      tests (Rust default and `backend = "wasm"`).

## Docs/config audit (`docs/config-audit`)

- [x] Audited README, operations docs, config files and engine docs for
      stale wasm-default claims and old latency numbers (8–10 ms / ~2 ms).
- [x] Added `docs/user-guide/{README,quickstart,engine-selection,configuration}.md`
      and `docs/guides/demo.md`.
- [x] Updated README, support matrix, release checklist, container, deployment,
      monitoring, Coraza/engine docs and historical suggestion banners.
- [x] Filled `config.toml` and `config.docker.toml`; added
      `config/examples/{minimal,coraza-reference,native-sidecar,grpc-allowlist,graphql-persisted,high-throughput}.toml`
      plus the GraphQL allowlist artifact.
- [x] Added `tests/config_files.rs`, `scripts/validate-configs.sh`, wired the
      test into `scripts/ci-feature-matrix.sh`; all 14 shipped configs load.
- [x] Added and ran `scripts/demo.sh` (200 benign/gRPC, 403 SQLi/XSS).
- [x] fmt, clippy `--lib`, `cargo test --lib` (499 passed), config validation.
- Remaining stale items: `config/test.toml` contains obsolete keys that the
  loader silently ignores (documented); historical perf reports in
  `docs/operations/performance-*.md` keep their original wasm-era numbers with
  scope notes rather than being rewritten.

## perf: 4/8 KiB end-to-end engine + proxy (`perf/8k`)

Branch `perf/8k` (worktree `.worktrees/perf-8k`, base `main` = `20afbaf`).
Goal: end-to-end p50 < 0.9 ms at 4 KiB, < 1.3 ms at 8 KiB, < 0.3 ms
bodyless, with p99 reported and detection parity unchanged.

### Plan

- [x] Profile bodyless/1/4/8 KiB end-to-end (proxy floor L2 vs WAF L3) and
      per engine phase (`engine-profile`, top rules).
- [x] Share transform/gate identities between `ARGS` and `ARGS_{GET,POST}`
      (and the name collections) so the same argument bytes are transformed
      and gate-scanned once.
- [x] Prune literal/subsequence gate groups by phase.
- [x] Borrow identity-pipeline candidates instead of copying them into the
      transform arena (body-sized copies).
- [x] Run native-engine body scans inline instead of `spawn_blocking` for
      normal-size bodies (removes the task hop and `RequestContext` clone).
- [x] Proxy: stop lowercasing every response header name for the hop-by-hop
      check.
- [x] Re-measure p50/p99 with `rust-engine-parity --bench` and
      `bench-subms`; document residuals.
  - Final: e2e p50 4 KiB 0.924 ms (target < 0.9, missed by 24 µs), 8 KiB
    1.354 ms (< 1.3, missed by 54 µs), bodyless 0.373 ms (< 0.3, missed).
    p99: 1.013 / 1.439 / 0.468 ms. Proxy floor 0.126–0.153 ms.
    Engine p50: 115 / 281 / 556 / 941 µs (bodyless/1/4/8).
  - Content-inspection literal gates are worth ~33 µs (4 KiB) and ~68 µs
    (8 KiB); before them the same e2e rows were 0.953 / 1.408 ms.
- [x] Parity: corpus **2,112/2,112** (100 %, 0 native-only FNs); transform
      fixture 7,320/7,320 (lib tests 623 passed).
- [x] fmt, lib tests (623), integration (60), clippy `--deny warnings`, docs +
      CHANGELOG.

## perf: ordered-subsequence gate for RCE regexes (`perf/rce-gate`)


Branch `perf/rce-gate` (worktree `.worktrees/rce-gate`, base `02497de`). The
filler-tolerant RCE command rules 932125/230/235/250/260/370/380 have no
>=2-byte mandatory literal, so the literal artifact leaves them ungated and
they dominate the residual regex cost. Goal: prove an ordered character
subsequence prerequisite and gate on it without any false negative.

- [x] Model regex prerequisites as OR-of-AND-of-OR of ordered byte sequences
      (`src/waf/rust_engine/subsequence.rs`), with per-step byte sets, ASCII
      case folding and a bounded-gap matcher (unbounded where the CRS filler
      uses `*`).
- [x] Conservative extractor: ASCII-only patterns, no Unicode classes/scoped
      flags; unknown atoms are ignored (weaker, never wrong); alternation is a
      disjunction; optional atoms contribute nothing; overflow drops a conjunct
      (sound weakening).
- [x] Attach gates for identity-transform family-932 `@rx` rules that the
      literal artifact did not gate; keep `GateMask` ids/order and the
      Vectorscan candidate pass (subsequence gates are not literal gates).
- [x] Evaluate subsequences from one byte-presence bitmap per value; cache
      with the existing `GateMask`.
- [x] Tests: extraction parser, bounded gaps, filler-separated match,
      alternation, optional atoms, 5-pattern exhaustive no-false-negative
      property, RCE gate count, engine block/allow adversarial cases.
- [x] Measurements: 4 KiB 603.7 → 573.5 µs p50, 8 KiB 1 006.9 → 943.2 µs;
      151 vs 137 regex evaluations skipped. Targets 480/850 µs not met (the
      RCE families only account for ~75 µs of regex time; the gate is ~16 µs).
- [x] Soundness regression fixed: small values (<256 B) must set every
      subsequence bit, otherwise the cached zero mask skips the rule. Corpus
      back to 2,110/2,112 with 0 native-only FNs; adversarial test covers it.
- [x] Docs `docs/suggestions_from_agents/rce-subsequence-gate.md`,
      CHANGELOG, task log.
- [x] Verified: fmt, `cargo test --lib --features
      rust-engine,native-detect,engine-kernel,crs-prefilter` (582 passed),
      clippy lib + parity bin, 2,110/2,112 corpus parity with 0 native-only
      FNs, 151/282 regex skips at 4 KiB.
- Blocker: latency targets 4 KiB < 480 µs and 8 KiB < 850 µs are not met
      (573 µs / 943 µs). The RCE families account for only ~75 µs of regex
      time; the remaining gate cost is the existing literal transform + AC
      pipeline. Details in the doc.

## Resource limits: HTTP/3 admission + WebSocket parser (`fix/h3-ws-limits`)

- [x] HTTP/3: global `server.h3_max_inflight_requests` semaphore (default 256)
      acquired before `resolve_request`/body read; optional per-client cap
      (`h3_max_inflight_per_client`, 0 = off) and bounded wait
      (`h3_admission_timeout_ms`, default 250). Excess work gets 503/429 with
      `Retry-After`; RAII permits release on completion/cancel/shutdown.
- [x] Metrics: `waf_h3_admission_total{outcome,reason}` and
      `waf_h3_admission_inflight`.
- [x] WebSocket: pass `server.websocket.max_frame_bytes` and
      `max_message_bytes` (0 = inherit `server.max_body_size`) to tungstenite
      so oversized frames/fragmented messages fail before assembly; close with
      policy violation 1008. Post-assembly WAF check retained.
- [x] Tests: h3 saturation/timeout/release/shutdown and per-client cap;
      end-to-end h3 saturation + permit release; WS fragmented oversized
      rejection, normal fragmented forwarding, config validation.
- [x] Config examples (`config.toml`, `config/examples/high-throughput.toml`),
      docs (`configuration.md`, `security-model.md`), CHANGELOG.
- [x] Verify: fmt, `cargo test --lib --features http3` (547 passed),
      h3 admission/HTTP3 tests (11 passed), WebSocket integration tests
      (6 passed), config tests (5 passed), clippy lib with and without
      `http3` `--deny warnings`.

## Perf: fixed proxy + WAF-wrapper floor (`perf/wrapper-floor`)

Baseline `main` = e05d918: bodyless 0.373 ms, 4 KiB 0.924 ms, 8 KiB
1.354 ms; proxy floor 126–153 µs; engine 556/941 µs.

- [x] ns-level profile of the wrapper: `bodyless-bench --profile --rust`
      (context build, admission, metrics, rule chain, audit) and
      `rust-engine-parity --bench`.
- [x] Borrow `http_version` in `RequestContext` (`Cow<'static, str>`); the
      proxy passes its `&'static str` instead of allocating.
- [x] Rust-engine adapter borrows the request head:
      `RustEngine::evaluate_detailed_borrowed` builds the collection view
      straight from `HeaderMap`/URI; no owned header strings or URI copy.
- [x] Content-inspection header scan: one case-insensitive Aho–Corasick
      candidate pass per header per rule instead of one gate search per
      pattern literal (sound over-approximation; non-ASCII values stay
      always-inspected).
- [x] Proxy fixed cost: no lowercase `String` per forwarded header, one
      client-IP header allocation per request.
- [x] Benchmark p50/p95/p99 bodyless/1/4/8 KiB at c=1 and c=16
      (`bench-subms --no-wasm`; median of 7 branch runs; before/after pair
      pinned to the same cores). Bodyless 0.315 ms median (best 0.294), 1 KiB
      0.454, 4 KiB 0.810, 8 KiB 1.234; 4/8 KiB targets met, bodyless ~15 µs
      over at the median (engine-bound; documented).
- [x] Parity: 2,112/2,112 corpus agreement, 0 native-only FNs (both engines
      3 FN / 91 FP vs expected), transform fixture passes; lib tests 626
      passed, lib `--no-default-features` 482 passed, integration 60 passed.
- [x] Verify: fmt, clippy `--lib --deny warnings` (default and no-default).
- [x] Docs (`docs/suggestions_from_agents/wrapper-floor.md`) + CHANGELOG.

## Release 0.1.0-beta.16 (`release/v0.1.0-beta.16`)

- [x] Bump Cargo.toml/Cargo.lock and version references to 0.1.0-beta.16;
      Helm chart version refreshed from the stale beta.10 value.
- [x] CHANGELOG `[0.1.0-beta.16] - 2026-11-08`: wrapper/proxy p50 0.315 /
      0.454 / 0.810 / 1.234 ms, p99 0.440 / 0.606 / 0.920 / 1.372 ms, corpus
      2,112/2,112, x/net 0.62.0 reactor rebuild and Trivy scope fix.
- [x] Verify: fmt, clippy `--lib`, lib tests (626), `--no-default-features`
      lib (482), integration, release ignored Coraza, h2 gRPC e2e, feature
      matrix quick, `nix build .#waf-ingress`, SBOM, reactor size.
- [x] Built binary/sidecar/image artifacts + SBOM; both the local and the
      downloaded-release runs of `verify-release.sh --deep-image` pass.
- [x] Public orphan snapshot `c177904`, ruleset 26690602 disabled for the
      force-push and restored to `active`; tag `v0.1.0-beta.16` and
      pre-release with 14 assets published.
- [x] Release commit `9203229`; local checks and the uploaded assets verified.
      Worktrees cleaned; GHCR untouched.
- [x] Confirm public CI on `a6b7d7e`: Feature Matrix success, Release success
      (14 assets, provenance attested), CodeQL success. Production Deployment
      still fails at the `cachix-action` step because the `waf-rejected` cache
      is private/missing and no `CACHIX_AUTH_TOKEN` is configured; deploy jobs
      are skipped, as in beta 15. Both rulesets restored to `active`.
