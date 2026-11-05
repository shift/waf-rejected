# Monitoring and Alerting Guide

## Overview

WAF-Rejected provides comprehensive monitoring capabilities through OpenTelemetry metrics, Prometheus integration, and Grafana dashboards.

## Metrics

### Request Metrics

- `waf_requests_total` - Total requests received
- `waf_allowed_total` - Requests allowed by the WAF
- `waf_blocked_total` - Requests blocked or rate limited by the WAF
- `waf_auth_failures_total` - Requests rejected by API-key authentication
- `waf_rate_limited_total` - Requests rejected by rate limiting
- `waf_upstream_errors_total` - Upstream connection/read failures
- `waf_request_duration_seconds` - Request processing duration histogram
  (buckets `le="0.001"` through `le="5"`, plus `+Inf`, with `_sum` and `_count`)
- `waf_uptime_seconds` - Process uptime in seconds
- `waf_webtransport_sessions_total` - WebTransport sessions accepted
- `waf_webtransport_allowed_total` - WebTransport sessions allowed by the WAF
- `waf_webtransport_blocked_total` - WebTransport sessions or payloads blocked
- `waf_webtransport_streams_total` - WebTransport streams inspected
- `waf_webtransport_datagrams_total` - WebTransport datagrams inspected

### Coraza Reactor Metrics

These metrics are emitted by the built-in `/metrics` endpoint when a
`WasmReactorRule` is registered with the process metrics registry
(`with_metrics`). The reactor is compiled in by default but is only on the
request path when `waf.coraza.backend = "wasm"` or `fallback = "wasm"` is
armed. With the default Rust engine and `fallback = "none"` these series stay
at zero; they also stay at zero when `waf.coraza.enabled = false` or the binary
is built without the `wasm-reactor` feature.

- `waf_coraza_evaluations_total` - Coraza reactor evaluations
- `waf_coraza_blocks_total` - Requests blocked by the Coraza reactor
- `waf_coraza_errors_total` - Coraza reactor evaluation or payload failures
- `waf_coraza_evaluation_duration_seconds` - Coraza evaluation duration
  histogram (buckets `le="0.001"` through `le="5"`, plus `+Inf`, with `_sum`
  and `_count`)

### Protocol decision metrics

The gRPC and GraphQL pre-checks emit one counter with a bounded `decision`
label (`allow`, `block`, `error`). Cardinality is fixed at three series per
protocol; no method, operation name, client or rule label is attached, so the
series count does not grow with traffic.

- `waf_grpc_decisions_total{decision}` - gRPC protocol pre-check outcomes
- `waf_graphql_decisions_total{decision}` - GraphQL protocol pre-check outcomes

The metrics above are emitted by the built-in `/metrics` endpoint. The
following extended metrics are planned or emitted by optional integrations:

- `waf_request_size_bytes` - Request body size distribution
- `waf_response_size_bytes` - Response body size distribution

### Security Metrics (extended integrations)

- `waf_security_events_total{severity, rule, category}` - Security events by severity and category
- `waf_blocked_requests_total{reason, rule}` - Blocked requests by reason
- `waf_auth_attempts_total{result}` - Authentication attempts (success/failure)
- `waf_ai_analysis_duration_seconds` - AI threat analysis processing time

### System Metrics

- `waf_memory_usage_bytes` - Current memory usage
- `waf_cpu_usage_percent` - CPU utilization percentage
- `waf_active_connections` - Number of active connections
- `waf_buffer_pool_usage` - Buffer pool utilization

### Compliance Metrics

- `waf_audit_events_total{type, actor}` - Audit events by type and actor
- `waf_compliance_checks_total{check_type, result}` - Compliance check results
- `waf_data_retention_cleanups_total` - Data retention cleanup operations

## Prometheus Configuration

### Scrape Configuration

```yaml
scrape_configs:
  - job_name: 'waf-rejected'
    static_configs:
      - targets: ['waf-rejected:8081']
    metrics_path: '/metrics'
    scrape_interval: 15s

  - job_name: 'waf-rejected-security'
    static_configs:
      - targets: ['waf-rejected:8081']
    metrics_path: '/security-metrics'
    scrape_interval: 30s
```

### Service Monitor (Kubernetes)

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: waf-rejected
  namespace: monitoring
spec:
  selector:
    matchLabels:
      app: waf-rejected
  endpoints:
  - port: metrics
    interval: 30s
    path: /metrics
  - port: metrics
    interval: 60s
    path: /security-metrics
```

## Alerting Rules

### Critical Alerts

```yaml
# High security event rate
- alert: HighSecurityEvents
  expr: rate(waf_security_events_total{severity="high"}[5m]) > 10
  for: 2m
  labels:
    severity: critical
  annotations:
    summary: "High rate of security events"

# Authentication failures
- alert: AuthFailureSpike
  expr: rate(waf_auth_attempts_total{result="failure"}[5m]) > 50
  for: 5m
  labels:
    severity: warning
  annotations:
    summary: "High authentication failure rate"
```

### Coraza Reactor Alerts

These rules use only the Coraza metrics emitted above. The error-rate rule
guards against a failing reactor (fail-closed `503`s); the block-spike rule
catches unexpected rule behaviour or an active attack.

```yaml
# Coraza evaluation error rate
- alert: CorazaEvaluationErrorRate
  expr: |
    rate(waf_coraza_errors_total[5m])
    /
    clamp_min(rate(waf_coraza_evaluations_total[5m]), 0.001)
    > 0.05
  for: 2m
  labels:
    severity: critical
  annotations:
    summary: "Coraza reactor evaluation errors"
    description: "{{ $value | humanizePercentage }} of Coraza evaluations are failing"

# Coraza block spike
- alert: CorazaBlockSpike
  expr: rate(waf_coraza_blocks_total[5m]) > 10
  for: 2m
  labels:
    severity: warning
  annotations:
    summary: "Coraza block spike"
    description: "Coraza is blocking {{ $value | humanize }} requests per second"
```

### Performance Alerts

```yaml
# High latency
- alert: HighLatency
  expr: histogram_quantile(0.95, rate(waf_request_duration_seconds_bucket[5m])) > 0.1
  for: 5m
  labels:
    severity: warning
  annotations:
    summary: "High request latency detected"

# High error rate
- alert: HighErrorRate
  expr: rate(waf_requests_total{status=~"5.."}[5m]) / rate(waf_requests_total[5m]) > 0.05
  for: 2m
  labels:
    severity: warning
  annotations:
    summary: "High error rate detected"
```

### System Health Alerts

```yaml
# Pod restarting
- alert: PodRestarting
  expr: rate(kube_pod_container_status_restarts_total{namespace="security"}[5m]) > 0
  for: 2m
  labels:
    severity: warning
  annotations:
    summary: "WAF pod restarting"

# High resource usage
- alert: HighMemoryUsage
  expr: container_memory_usage_bytes{namespace="security"} / container_spec_memory_limit_bytes > 0.8
  for: 5m
  labels:
    severity: warning
  annotations:
    summary: "High memory usage"
```

## Grafana Dashboards

### WAF Overview dashboard

`infrastructure/monitoring/dashboards/waf-overview.json` is the production
overview. It uses only series emitted by `src/metrics.rs`:

| row | panels |
| --- | --- |
| Traffic | request rate, allow/block/rate-limit/auth-failure rate, upstream error rate, request latency p50/p95/p99 |
| Coraza | evaluations/blocks/errors, evaluation-duration p95/p99 and heatmap |
| Body policy | truncation/rejection rate, inspected-bytes heatmap and mean |
| Admission | queue depth/enqueue rate, in-flight by class, admitted/rejected, wait p95/p99 |
| Protocol | gRPC and GraphQL decisions, block ratio |
| Coverage note | reactor pool/worker and RSS are not exported; see the metric gap below |

Validate the dashboard and alert metric references with:

```bash
bash scripts/check-dashboards.sh
```

### Alert inventory

`infrastructure/monitoring/alert_rules.yml` contains the following
actionable rules. Each links to a triage section in
[`runbook.md`](runbook.md).

| alert | signal |
| --- | --- |
| `CorazaAdmissionHeavyRejections` | sustained admission rejection |
| `CorazaAdmissionQueueSaturated` | admission queue depth > 0 |
| `CorazaBodyTruncationSpike` | body-policy truncation rate |
| `CorazaBodyRejectionSpike` | body-policy 413 rate |
| `CorazaEvaluationErrorRate` | Coraza error ratio |
| `CorazaEvaluationDurationSLOBurn` | Coraza p99 evaluation duration |
| `CorazaBlockSpike` | Coraza block rate |
| `GrpcBlockRateAnomaly` | gRPC block ratio |
| `GraphqlBlockRateAnomaly` | GraphQL block ratio |
| `ReactorPoolExhaustion` | heavy queue + heavy in-flight |
| `HighRequestLatency` | request p95 |
| `UpstreamErrorRate` | upstream error ratio |

### Metric gaps

Reactor pool size, idle/busy workers, worker restarts and process RSS are not
exported by `/metrics`. The dashboard uses admission queue depth, heavy
in-flight and Coraza errors as pool-pressure proxies, and the runbook points
at cAdvisor/kubelet for RSS. Adding direct pool gauges would be a bounded
follow-up (one series per pool, not per worker).

### Security Overview Dashboard

```json
{
  "title": "WAF-Rejected Security Overview",
  "panels": [
    {
      "title": "Security Events by Severity",
      "type": "bargauge",
      "targets": [
        {
          "expr": "sum(rate(waf_security_events_total[5m])) by (severity)",
          "legendFormat": "{{severity}}"
        }
      ]
    },
    {
      "title": "Blocked Requests Over Time",
      "type": "graph",
      "targets": [
        {
          "expr": "rate(waf_blocked_requests_total[5m])",
          "legendFormat": "Blocked Requests"
        }
      ]
    }
  ]
}
```

### Performance Dashboard

```json
{
  "title": "WAF-Rejected Performance",
  "panels": [
    {
      "title": "Request Latency (95th percentile)",
      "type": "graph",
      "targets": [
        {
          "expr": "histogram_quantile(0.95, rate(waf_request_duration_seconds_bucket[5m]))",
          "legendFormat": "95th percentile"
        }
      ]
    },
    {
      "title": "Requests per Second",
      "type": "graph",
      "targets": [
        {
          "expr": "rate(waf_requests_total[5m])",
          "legendFormat": "RPS"
        }
      ]
    }
  ]
}
```

## Log Aggregation

### Structured Logging

WAF-Rejected outputs structured JSON logs for easy aggregation:

```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "level": "INFO",
  "service": "waf-rejected",
  "request_id": "req-12345",
  "client_ip": "192.168.1.100",
  "method": "POST",
  "path": "/api/login",
  "status": 200,
  "duration_ms": 45,
  "security_events": 0,
  "ai_analysis": true
}
```

### Log Levels

- `ERROR`: Security incidents, system failures
- `WARN`: Performance issues, configuration problems
- `INFO`: Normal operations, security events
- `DEBUG`: Detailed debugging information

## Health Checks

### Application Health

```bash
# Liveness probe
curl -f http://localhost:8081/health

# Readiness probe
curl -f http://localhost:8081/health/ready

# Metrics endpoint
curl -f http://localhost:8080/metrics
```

### System Health

```bash
# Check pod status
kubectl get pods -n security

# Check resource usage
kubectl top pods -n security

# Check logs
kubectl logs -f deployment/waf-rejected -n security
```

## Troubleshooting

### High Latency Issues

1. Check system resources:
   ```bash
   kubectl top pods -n security
   ```

2. Review slow queries in logs:
   ```bash
   kubectl logs deployment/waf-rejected -n security | grep "slow"
   ```

3. Check AI analysis timeouts:
   ```bash
   kubectl logs deployment/waf-rejected -n security | grep "AI analysis timeout"
   ```

### Security Event Spikes

1. Check for attack patterns:
   ```bash
   kubectl logs deployment/waf-rejected -n security | grep "blocked"
   ```

2. Review recent configuration changes:
   ```bash
   kubectl get configmap waf-rejected-config -n security -o yaml
   ```

3. Check upstream service health:
   ```bash
   curl -f http://upstream-service/health
   ```

### Memory Issues

1. Check memory usage:
   ```bash
   kubectl exec -it deployment/waf-rejected -n security -- ps aux
   ```

2. Review buffer pool usage:
   ```bash
   curl http://localhost:8081/metrics | grep buffer
   ```

3. Check for memory leaks:
   ```bash
   kubectl logs deployment/waf-rejected -n security | grep "memory"
   ```

## Maintenance

### Regular Tasks

- **Log Rotation**: Logs are automatically rotated based on size/time
- **Metrics Retention**: Configure Prometheus retention policies
- **Security Updates**: Regular dependency updates and security patches
- **Performance Tuning**: Monitor and adjust resource limits

### Emergency Procedures

1. **High Security Event Rate**:
   - Scale up deployment: `kubectl scale deployment waf-rejected --replicas=5`
   - Enable emergency blocking mode
   - Notify security team

2. **Service Unavailable**:
   - Check pod status: `kubectl get pods -n security`
   - Restart deployment: `kubectl rollout restart deployment/waf-rejected`
   - Check upstream connectivity

3. **Performance Degradation**:
   - Check resource usage
   - Scale vertically by increasing resource limits
   - Enable performance debugging mode