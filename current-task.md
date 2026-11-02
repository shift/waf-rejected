# P0-09: Beta Release (current: 0.1.0-beta.9) (NORTH STAR)

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
