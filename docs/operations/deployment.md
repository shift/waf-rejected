# Production Deployment Guide

## Overview

This guide covers the production deployment of WAF-Rejected using Kubernetes and Helm.

The default image runs the native Rust CRS engine
(`waf.coraza.backend = "rust"`). Coraza remains the reference implementation and
the explicit `"wasm"` switch-back; see
[engine selection](../user-guide/engine-selection.md) before choosing a backend.
Configuration sections are documented in
[configuration](../user-guide/configuration.md).

## Prerequisites

- Kubernetes cluster (v1.24+)
- Helm 3.0+
- kubectl configured for the cluster
- Container registry access
- TLS certificates (Let's Encrypt or custom)

## Quick Start

### 1. Install from the chart in this repository

The Helm chart lives in [`infrastructure/helm`](../../infrastructure/helm). If
your organisation publishes it to a chart repository, add that repository and
use `waf-rejected/waf-rejected` instead of the local path.

```bash
helm repo add waf-rejected https://charts.example.com
helm repo update
```

### 2. Install WAF-Rejected

```bash
# Create namespace
kubectl create namespace security

# Install the chart shipped with this repository
helm install waf-rejected ./infrastructure/helm \
  --namespace security \
  --set upstream.url="http://your-backend-service"
```

### 3. Verify Installation

```bash
# Check pod status
kubectl get pods -n security

# Check service
kubectl get svc -n security

# Check logs
kubectl logs -f deployment/waf-rejected -n security
```

## Configuration

### Basic Configuration

```yaml
# values.yaml
replicaCount: 3

upstream:
  url: "http://backend-service:8080"

security:
  auth:
    enabled: true
  ai:
    enabled: true
  compliance:
    enabled: true
```

### Advanced Configuration

```yaml
# Production values.yaml
image:
  tag: "v0.1.0-beta.16"

resources:
  requests:
    memory: "512Mi"
    cpu: "1000m"
  limits:
    memory: "2Gi"
    cpu: "4000m"

monitoring:
  prometheus:
    enabled: true
  grafana:
    enabled: true

persistence:
  enabled: true
  size: "50Gi"
  storageClass: "fast-ssd"
```

## Engine and configuration

The chart passes `upstream.url` and the container image loads
`/etc/waf/config.toml`. For anything beyond the chart values, mount a ConfigMap
with a full TOML file:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: waf-config
  namespace: security
data:
  config.toml: |
    bind_addr = "0.0.0.0:8080"
    health_bind_addr = "0.0.0.0:8081"
    upstream_uri = "http://backend-service:8080"

    [waf]
    enabled = true
    fail_mode = "closed"

    [waf.coraza]
    # Default in default builds: native Rust CRS engine.
    # backend = "rust"
    # Explicit switch-back to the Coraza reference reactor:
    # backend = "wasm"
    # Opt-in native sidecar (also deploy the sidecar and shared socket):
    # backend = "native"
    # native_socket_path = "/run/waf/coraza.sock"
    fallback = "none"
    max_payload_bytes = 65536
    max_inspect_bytes = 0
    oversize_action = "inspect-all"
```

```bash
kubectl create configmap waf-config -n security \
  --from-file=config.toml=./config.toml

# Mount it at /etc/waf/config.toml in the Deployment, or use the chart's
# extraVolumes/extraVolumeMounts values if present.
```

Validate the file before deploying:

```bash
./scripts/validate-configs.sh
```

Unknown top-level or nested keys are hard errors, reported with the file,
section/key path and line before any listener binds. Keep `fail_mode = "closed"`;
a backend outage or runtime error must block, not silently allow. See
[engine selection](../user-guide/engine-selection.md) and the
[container guide](container.md) for backend-specific memory and start-up
guidance.

## Security Configuration

The trust boundaries, request-path enforcement points, bypass classes and
residual risks are described in the
[security architecture and threat model](../architecture/security-model.md).
Read it before choosing authentication, TLS termination or trusted-proxy
settings.

### API Key Authentication

```yaml
security:
  auth:
    enabled: true
    headerName: "X-API-Key"
    requireHttps: true

# Create secret with API keys
kubectl create secret generic waf-api-keys \
  --from-literal=key1=your-api-key-1 \
  --from-literal=key2=your-api-key-2 \
  --namespace security
```

### Request framing and decompression

The proxy validates request framing before reading a body and rejects ambiguous
`Content-Length`/`Transfer-Encoding` combinations with a generic `400`. It also
decodes one `gzip`, `deflate` or `br` request coding before inspection, capped
at `server.max_body_size`. Keep both behaviours enabled; do not place a second
HTTP parser or a recursive decompressor in front of the proxy. Size memory
limits for the decompressed body, not the compressed one.

### WebTransport (terminating endpoint)

WebTransport is **not** an HTTP upstream proxy. When built with
`--features http3,webtransport` and enabled under `[server.webtransport]`, it
accepts QUIC sessions on its own UDP port, validates Origin/path/API key,
applies session/stream/datagram limits, inspects payloads locally and echoes
bidirectional streams. It does **not** forward application WebTransport
payloads to an upstream; that bridge is not implemented. HTTP/1.1
`Upgrade: webtransport` remains `501`.

```toml
[server.webtransport]
enabled = true
bind_addr = "0.0.0.0:4434"          # must not collide with the HTTP/3 UDP port
require_origin = true
allowed_origins = ["https://app.example.com"]
allowed_paths = ["/echo"]
max_sessions = 1024
max_sessions_per_ip = 32
inspect_streams = true
inspect_datagrams = true
```

Expose the UDP port only if the terminating/echo behaviour is intended. If an
application-specific WebTransport service is required, terminate WebTransport
outside this proxy until an upstream bridge exists. See
[`../developer-guide/webtransport.md`](../developer-guide/webtransport.md).

### TLS Configuration

```yaml
# Enable TLS
service:
  tls:
    enabled: true
    secretName: waf-tls-cert

# Using cert-manager
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: waf-tls-cert
  namespace: security
spec:
  secretName: waf-tls-cert
  issuerRef:
    name: letsencrypt-prod
    kind: ClusterIssuer
  dnsNames:
  - waf.example.com
```

## Monitoring Setup

### Prometheus Integration

```yaml
monitoring:
  prometheus:
    enabled: true
    serviceMonitor:
      enabled: true
      namespace: monitoring
      interval: 30s
```

### Grafana Dashboards

```yaml
monitoring:
  grafana:
    enabled: true
    dashboards:
      waf-security:
        enabled: true
        datasource: prometheus
```

## Scaling

### Horizontal Scaling

```bash
# Scale deployment
kubectl scale deployment waf-rejected --replicas=5 -n security
```

### Vertical Scaling

```yaml
resources:
  requests:
    memory: "1Gi"
    cpu: "2000m"
  limits:
    memory: "4Gi"
    cpu: "8000m"
```

## Backup and Recovery

### Configuration Backup

```bash
# Backup Helm values
helm get values waf-rejected -n security > backup-values.yaml

# Backup ConfigMaps and Secrets
kubectl get configmap,secret -n security -o yaml > backup-config.yaml
```

### Database Backup

```bash
# Backup security event database
kubectl exec -n security deployment/waf-rejected -- \
  sled export /var/log/waf/security.db > security-backup.db
```

### Recovery

```bash
# Restore from backup
helm upgrade waf-rejected ./infrastructure/helm \
  --namespace security \
  --values backup-values.yaml

# Restore database
kubectl cp security-backup.db security/waf-rejected-pod:/var/log/waf/security.db
```

## Troubleshooting

### Common Issues

#### Pod Not Starting
```bash
# Check pod events
kubectl describe pod waf-rejected-xxx -n security

# Check logs
kubectl logs waf-rejected-xxx -n security
```

#### High Memory Usage
```bash
# Check resource usage
kubectl top pods -n security

# Adjust resource limits
kubectl edit deployment waf-rejected -n security
```

#### Authentication Failures
```bash
# Check API key configuration
kubectl get secret waf-api-keys -n security -o yaml

# Verify header configuration
kubectl logs deployment/waf-rejected -n security | grep auth
```

### Health Checks

```bash
# Manual health check
curl -f http://waf-service/health

# Readiness check
curl -f http://waf-service:8081/health/ready

# Metrics check
curl -f http://waf-service:8081/metrics
```

## Maintenance

### Updates

```bash
# Update Helm chart
helm repo update
helm upgrade waf-rejected waf-rejected/waf-rejected -n security

# Rolling restart
kubectl rollout restart deployment/waf-rejected -n security
```

### Log Rotation

```yaml
# Configure log rotation
config:
  logging:
    max_file_size: "100MB"
    max_files: 10
    compress: true
```

### Security Updates

```bash
# Update to latest security patch
helm upgrade waf-rejected waf-rejected/waf-rejected \
  --set image.tag=v0.1.0-beta.16 \
  -n security
```