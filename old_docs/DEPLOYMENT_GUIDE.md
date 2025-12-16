# WAF-Rejected Quick Deployment Guide

**Status:** ✅ Production Ready (Validated Aug 10, 2025)  
**Binary:** 4.1M optimized release build  
**Hardware:** Optimized for laptop/SMB deployment (Lenovo X1 Yoga Gen4 tested)

## 🚀 Deployment Options

### Option 1: Development/Testing (Single Instance)
**Target:** Local development, testing, proof-of-concept
**Resources:** Laptop hardware (4-core CPU, 8GB+ RAM)
**Expected Performance:** 500-800 RPS

```bash
# Quick start for development
cd /home/shift/code/waf-rejected

# Build optimized binary (if not already built)
nix-shell -p gcc cmake pkg-config openssl zlib zstd bc --run "cargo build --release"

# Run with default configuration
./target/release/waf-ingress

# Or with custom config
WAF_CONFIG_FILE=config/production.toml ./target/release/waf-ingress
```

### Option 2: Small Business Production (2-3 Instance Cluster)
**Target:** Small business production deployment
**Resources:** 2-3 servers/VMs (4-core CPU, 16GB+ RAM each)
**Expected Performance:** 1200+ RPS total

```bash
# Load balancer setup required
# Example with HAProxy or nginx upstream
# Deploy identical instances with shared Redis/Sled backend
```

### Option 3: Enterprise Kubernetes (Horizontal Scaling)
**Target:** Enterprise production with auto-scaling
**Resources:** Kubernetes cluster with HPA
**Expected Performance:** Auto-scaling based on load

```bash
# Kubernetes deployment manifests needed
# Container image build required
# Helm chart for enterprise deployment
```

## ⚙️ Configuration Examples

### Minimal Production Config
```toml
# config/minimal-prod.toml
bind_addr = "0.0.0.0:8080"
upstream_uri = "http://backend:3000"

[server]
max_connections = 1000

[waf]
enabled = true

[waf.geo_blocking]
enabled = true
blocked_countries = ["CN", "RU", "KP"]
```

### Enterprise Production Config
```toml
# config/enterprise-prod.toml
bind_addr = "0.0.0.0:8080"
upstream_uri = "http://backend-service:3000"

[server]
max_connections = 5000
timeout_seconds = 30
graceful_shutdown_seconds = 15

[waf]
enabled = true

[waf.rate_limit]
per_ip_enabled = true
per_ip_requests = 1000
per_ip_window_seconds = 60

[waf.security_events]
enabled = true
log_blocked_requests = true
log_rate_limited_requests = true

[waf.geo_blocking]
enabled = true
blocked_countries = ["CN", "RU", "KP", "IR"]
block_tor = true
block_datacenter = false
```

## 🔧 Docker Deployment

### Dockerfile
```dockerfile
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy binary and configuration
COPY target/release/waf-ingress /usr/local/bin/
COPY config/ /etc/waf-ingress/

# Create non-root user
RUN useradd -r -s /bin/false waf-ingress

USER waf-ingress
EXPOSE 8080

CMD ["waf-ingress"]
```

### Docker Compose
```yaml
# docker-compose.yml
version: '3.8'

services:
  waf-ingress:
    build: .
    ports:
      - "8080:8080"
    environment:
      - WAF_CONFIG_FILE=/etc/waf-ingress/production.toml
      - WAF_UPSTREAM_URI=http://backend:3000
    volumes:
      - ./config:/etc/waf-ingress:ro
    restart: unless-stopped
    
  backend:
    image: your-backend-image
    expose:
      - "3000"
```

## 📊 Monitoring Setup

### Prometheus Metrics
```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'waf-ingress'
    static_configs:
      - targets: ['waf-ingress:8080']
    scrape_interval: 15s
```

### Grafana Dashboard
- Import WAF-Ingress dashboard (dashboard.json)
- Monitor key metrics: RPS, latency, security events
- Set up alerting for threshold violations

## 🛡️ Security Checklist

### Pre-Production Security Review
- [ ] Review blocked country list for compliance
- [ ] Configure rate limiting thresholds
- [ ] Set up log aggregation for security events
- [ ] Test failover scenarios
- [ ] Validate SSL/TLS termination
- [ ] Configure proper upstream health checks

### Production Security Monitoring
- [ ] Security event alerting (failed authentications, blocked IPs)
- [ ] Performance monitoring (latency, throughput)
- [ ] Resource monitoring (CPU, memory, connections)
- [ ] Log analysis and SIEM integration

## 🔄 Deployment Process

### Step 1: Pre-Deployment Validation
```bash
# Run comprehensive tests
./comprehensive_test_report.sh

# Verify configuration
./target/release/waf-ingress --check-config

# Test upstream connectivity
curl -I http://your-backend-service/health
```

### Step 2: Deployment Execution
```bash
# Blue-green deployment recommended
# Deploy to staging first
# Validate functionality
# Switch traffic gradually
```

### Step 3: Post-Deployment Validation
```bash
# Health check
curl -f http://waf-instance:8080/health

# Performance test
ab -n 1000 -c 10 http://waf-instance:8080/

# Security validation
curl -H "User-Agent: sqlmap" http://waf-instance:8080/
```

## 📞 Support & Troubleshooting

### Common Issues
1. **High Latency:** Check upstream connectivity and response times
2. **Memory Usage:** Monitor Sled database size and connection pools
3. **Security Events:** Review WAF rule triggers and tune thresholds

### Debug Commands
```bash
# Check configuration
./target/release/waf-ingress --config-check

# Verbose logging
WAF_LOG_LEVEL=debug ./target/release/waf-ingress

# Connection testing
netstat -tlnp | grep 8080
```

### Log Analysis
- Security events logged in CEF 1.0 format
- Performance metrics available via OpenTelemetry
- System logs in structured JSON format

---

**Next Steps:** Choose deployment option and execute deployment plan
**Support:** See FINAL_COMPREHENSIVE_TEST_REPORT.md for complete validation results
**Documentation:** Full API docs and configuration references available
