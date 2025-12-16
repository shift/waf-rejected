# User Guide

**Complete guide for using WAF-Rejected in production environments**

## Getting Started

### First-Time Setup

After installation, WAF-Rejected needs basic configuration to start protecting your applications.

#### 1. Create Configuration File

Create a configuration file suitable for your environment:

```bash
# Create configuration directory
sudo mkdir -p /etc/waf-rejected

# Create basic configuration
sudo tee /etc/waf-rejected/config.toml << EOF
[server]
host = "0.0.0.0"
port = 8080

[upstream]
base_url = "http://localhost:3000"  # Your backend application

[security]
enable_geo_blocking = true
enable_content_inspection = true
blocked_countries = ["CN", "RU", "IR"]

[logging]
level = "info"
format = "json"
EOF
```

#### 2. Start WAF-Rejected

```bash
# Start the service
waf-ingress --config /etc/waf-rejected/config.toml

# Or if using systemd
sudo systemctl start waf-rejected
```

#### 3. Update Your Application Routing

Configure your load balancer or reverse proxy to route traffic through WAF-Rejected:

**nginx configuration:**
```nginx
upstream waf_backend {
    server 127.0.0.1:8080;  # WAF-Rejected
}

server {
    listen 80;
    server_name example.com;
    
    location / {
        proxy_pass http://waf_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

**HAProxy configuration:**
```
backend waf_backend
    server waf1 127.0.0.1:8080 check

frontend web_frontend
    bind *:80
    default_backend waf_backend
```

## Configuration Guide

### Basic Configuration Options

#### Server Configuration
```toml
[server]
host = "0.0.0.0"        # Bind address (0.0.0.0 for all interfaces)
port = 8080             # HTTP port
https_port = 8443       # HTTPS port (optional)
workers = 4             # Number of worker threads (auto-detect if 0)
max_connections = 1000  # Maximum concurrent connections
```

#### Upstream Configuration
```toml
[upstream]
base_url = "http://backend:3000"  # Backend application URL
timeout = "30s"                   # Request timeout
max_connections = 100             # Connection pool size
keepalive_timeout = "60s"         # Keep-alive timeout
retry_attempts = 3                # Retry failed requests
```

#### Logging Configuration
```toml
[logging]
level = "info"                    # Log level: trace, debug, info, warn, error
format = "json"                   # Format: json, text
file = "/var/log/waf/waf.log"    # Log file path
max_size = "100MB"               # Max log file size
rotate = true                    # Enable log rotation
```

### Security Configuration

#### Geographic Blocking
```toml
[security.geo_blocking]
enabled = true

# Block specific countries (ISO country codes)
blocked_countries = [
    "CN",  # China
    "RU",  # Russia
    "IR",  # Iran
    "KP"   # North Korea
]

# Or allow only specific countries
# allowed_countries = ["US", "CA", "GB", "DE"]

# Block known VPN/proxy providers
block_vpns = true
block_tor = true

# Custom message for blocked requests
block_message = "Access denied from your location"
```

#### Content Inspection
```toml
[security.content_inspection]
enabled = true

# SQL Injection Detection
[security.content_inspection.sql_injection]
enabled = true
patterns = [
    "(?i)union.*select",
    "(?i)drop.*table",
    "(?i)insert.*into",
    "(?i)'; *--",
    "(?i)or.*1.*=.*1"
]

# Cross-Site Scripting (XSS) Detection  
[security.content_inspection.xss]
enabled = true
patterns = [
    "(?i)<script[^>]*>",
    "(?i)javascript:",
    "(?i)on\\w+\\s*=",
    "(?i)<iframe[^>]*>",
    "(?i)vbscript:"
]

# Path Traversal Detection
[security.content_inspection.path_traversal]
enabled = true
patterns = [
    "\\.\\./",
    "(?i)etc/passwd",
    "(?i)web\\.config",
    "(?i)cmd\\.exe"
]
```

#### Rate Limiting
```toml
[security.rate_limiting]
enabled = true

# Global rate limits
global_requests_per_minute = 10000
global_burst_capacity = 1000

# Per-IP rate limits
per_ip_requests_per_minute = 100
per_ip_burst_capacity = 20
per_ip_window = "1m"

# Per-path rate limits
[[security.rate_limiting.path_limits]]
path = "/api/login"
requests_per_minute = 5
burst_capacity = 2

[[security.rate_limiting.path_limits]]
path = "/api/register" 
requests_per_minute = 3
burst_capacity = 1

[[security.rate_limiting.path_limits]]
path = "/api/password-reset"
requests_per_minute = 2
burst_capacity = 1
```

#### Custom Security Rules
```toml
# Define custom security rules
[[security.custom_rules]]
name = "Block User-Agent Scanners"
pattern = "(?i)(sqlmap|nmap|masscan|nessus)"
field = "user_agent"
action = "block"
severity = "high"

[[security.custom_rules]]
name = "Suspicious File Extensions"
pattern = "\\.(php|asp|jsp|cgi)$"
field = "path"
action = "monitor"  # Log but don't block
severity = "medium"

[[security.custom_rules]]
name = "Admin Panel Access"
pattern = "^/(admin|wp-admin|phpmyadmin)"
field = "path"
action = "block"
severity = "high"
# Only block from specific countries
geo_restrictions = ["CN", "RU"]
```

### TLS/SSL Configuration

#### Basic TLS Setup
```toml
[tls]
enabled = true
cert_file = "/etc/waf-rejected/certs/server.crt"
key_file = "/etc/waf-rejected/certs/server.key"

# TLS version settings
min_version = "1.2"
max_version = "1.3"

# Cipher suites (optional - defaults to secure modern ciphers)
cipher_suites = [
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_128_GCM_SHA256"
]
```

#### Client Certificate Authentication
```toml
[tls.client_auth]
enabled = true
ca_file = "/etc/waf-rejected/certs/client-ca.crt"
require_cert = false  # Set to true for mandatory client certs
verify_depth = 3
```

#### ACME/Let's Encrypt Integration
```toml
[tls.acme]
enabled = true
email = "admin@example.com"
directory_url = "https://acme-v02.api.letsencrypt.org/directory"  # Production
# directory_url = "https://acme-staging-v02.api.letsencrypt.org/directory"  # Staging

# Domains to obtain certificates for
domains = ["example.com", "www.example.com"]

# Challenge type
challenge_type = "http-01"  # or "tls-alpn-01"
```

### Monitoring and Observability

#### Metrics Configuration
```toml
[metrics]
enabled = true
bind_address = "127.0.0.1:9090"  # Prometheus metrics endpoint
path = "/metrics"

# Custom metrics
[metrics.custom]
# Track specific paths
track_paths = ["/api/*", "/admin/*"]
# Track response codes
track_status_codes = [200, 403, 404, 500]
```

#### OpenTelemetry Integration
```toml
[telemetry]
enabled = true
service_name = "waf-rejected"
service_version = "0.1.0"

# OTLP exporter
[telemetry.otlp]
endpoint = "http://jaeger:4317"  # gRPC endpoint
# endpoint = "http://jaeger:4318/v1/traces"  # HTTP endpoint
headers = { "api-key" = "your-api-key" }

# Sampling configuration
[telemetry.sampling]
type = "probabilistic"  # or "always_on", "always_off"
probability = 0.1  # Sample 10% of requests
```

#### Health Check Configuration
```toml
[health]
enabled = true
path = "/health"
detailed = true  # Include detailed system information

# Custom health checks
[[health.checks]]
name = "upstream_connectivity"
type = "http"
url = "http://backend:3000/health"
timeout = "5s"
interval = "30s"

[[health.checks]]
name = "redis_connectivity"
type = "redis"
url = "redis://localhost:6379"
timeout = "2s"
```

### Export and Integration

#### SIEM Integration (CEF Format)
```toml
[exports.cef]
enabled = true
facility = "local0"  # Syslog facility
severity = "info"    # Syslog severity
vendor = "WafRejected"
product = "WAF"
version = "1.0"

# Export specific event types
event_types = ["sql_injection", "xss", "geo_block", "rate_limit"]
min_severity = "medium"
```

#### Webhook Notifications
```toml
[[exports.webhooks]]
name = "security_alerts"
url = "https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"
events = ["sql_injection", "xss"]
min_severity = "high"
timeout = "10s"
retry_attempts = 3

# Custom headers
headers = { "Authorization" = "Bearer your-token" }

# Custom payload template
template = """
{
  "text": "🚨 WAF Alert: {{.threat_type}} from {{.source_ip}}",
  "attachments": [{
    "color": "danger",
    "fields": [
      {"title": "Path", "value": "{{.target_path}}", "short": true},
      {"title": "Rule ID", "value": "{{.rule_id}}", "short": true}
    ]
  }]
}
"""

[[exports.webhooks]]
name = "security_team"
url = "https://api.pagerduty.com/incidents"
events = ["*"]
min_severity = "critical"
headers = { 
  "Authorization" = "Token token=your-pagerduty-token",
  "Content-Type" = "application/json"
}
```

## Operating WAF-Rejected

### Starting and Stopping

#### Systemd (Linux)
```bash
# Start service
sudo systemctl start waf-rejected

# Stop service  
sudo systemctl stop waf-rejected

# Restart service
sudo systemctl restart waf-rejected

# Check status
sudo systemctl status waf-rejected

# View logs
journalctl -u waf-rejected -f
```

#### Docker
```bash
# Start container
docker start waf-rejected

# Stop container
docker stop waf-rejected

# Restart container
docker restart waf-rejected

# View logs
docker logs -f waf-rejected
```

#### Manual Process
```bash
# Start WAF
./waf-ingress --config /path/to/config.toml

# Stop gracefully (SIGTERM)
kill -TERM $(pgrep waf-ingress)

# Force stop (SIGKILL)
kill -KILL $(pgrep waf-ingress)
```

### Configuration Management

#### Hot Configuration Reload
```bash
# Reload configuration without restart
curl -X POST http://localhost:9090/admin/reload \
  -H "Authorization: Bearer your-admin-token"

# Or send USR1 signal
sudo kill -USR1 $(pgrep waf-ingress)
```

#### Configuration Validation
```bash
# Validate configuration file
waf-ingress --config /path/to/config.toml --dry-run

# Check current configuration
curl http://localhost:9090/admin/config \
  -H "Authorization: Bearer your-admin-token"
```

### Security Rule Management

#### Viewing Active Rules
```bash
# List all active security rules
curl http://localhost:9090/admin/rules \
  -H "Authorization: Bearer your-admin-token"

# Get specific rule details
curl http://localhost:9090/admin/rules/SQLI_001 \
  -H "Authorization: Bearer your-admin-token"
```

#### Updating Rules
```bash
# Add new rule
curl -X POST http://localhost:9090/admin/rules \
  -H "Authorization: Bearer your-admin-token" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "CUSTOM_001",
    "name": "Block WordPress Attacks",
    "pattern": "(?i)wp-(admin|content|includes)",
    "field": "path",
    "action": "block",
    "severity": "medium"
  }'

# Update existing rule
curl -X PUT http://localhost:9090/admin/rules/CUSTOM_001 \
  -H "Authorization: Bearer your-admin-token" \
  -H "Content-Type: application/json" \
  -d '{
    "pattern": "(?i)wp-(admin|content|includes|login)",
    "action": "monitor"
  }'

# Delete rule
curl -X DELETE http://localhost:9090/admin/rules/CUSTOM_001 \
  -H "Authorization: Bearer your-admin-token"
```

### Monitoring and Alerting

#### Key Metrics to Monitor

**Performance Metrics:**
- `waf_request_duration_seconds` - Request processing latency
- `waf_requests_total` - Total requests processed
- `waf_upstream_duration_seconds` - Backend response time
- `waf_memory_usage_bytes` - Memory consumption
- `waf_cpu_usage_percent` - CPU utilization

**Security Metrics:**
- `waf_threats_blocked_total` - Blocked security threats
- `waf_threats_by_type` - Threats by category (SQL injection, XSS, etc.)
- `waf_geo_blocks_total` - Geographic blocks by country
- `waf_rate_limits_exceeded_total` - Rate limiting violations

**System Metrics:**
- `waf_connections_active` - Active connections
- `waf_uptime_seconds` - Service uptime
- `waf_config_reload_timestamp` - Last configuration reload

#### Setting Up Alerts

**Prometheus Alerting Rules:**
```yaml
# prometheus-alerts.yml
groups:
- name: waf-rejected.alerts
  rules:
  - alert: WAFHighLatency
    expr: histogram_quantile(0.95, waf_request_duration_seconds) > 0.1
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "WAF is experiencing high latency"
      
  - alert: WAFHighThreatVolume
    expr: rate(waf_threats_blocked_total[5m]) > 10
    for: 2m
    labels:
      severity: critical
    annotations:
      summary: "High volume of security threats detected"
      
  - alert: WAFServiceDown
    expr: up{job="waf-rejected"} == 0
    for: 1m
    labels:
      severity: critical
    annotations:
      summary: "WAF service is down"
```

### Log Management

#### Log Analysis
```bash
# View recent logs
tail -100 /var/log/waf-rejected/waf.log

# Filter security events
grep "SECURITY_EVENT" /var/log/waf-rejected/waf.log | jq '.'

# Analyze blocked IPs
grep "blocked.*true" /var/log/waf-rejected/waf.log | \
  jq -r '.source_ip' | sort | uniq -c | sort -nr

# Monitor specific threat types
grep "sql_injection" /var/log/waf-rejected/waf.log | \
  jq -r '.timestamp + " " + .source_ip + " " + .target_path'
```

#### Log Rotation
```bash
# Configure logrotate
sudo tee /etc/logrotate.d/waf-rejected << EOF
/var/log/waf-rejected/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
EOF
```

### Troubleshooting Common Issues

#### High CPU Usage
```bash
# Check if specific security modules are causing issues
curl http://localhost:9090/admin/stats/modules \
  -H "Authorization: Bearer your-admin-token"

# Reduce security rule complexity
# Consider disabling resource-intensive features temporarily
```

#### High Memory Usage  
```bash
# Check memory usage by component
curl http://localhost:9090/admin/stats/memory \
  -H "Authorization: Bearer your-admin-token"

# Adjust connection limits
[server]
max_connections = 500  # Reduce if needed
```

#### False Positives
```bash
# Review blocked legitimate requests
grep "blocked.*true" /var/log/waf-rejected/waf.log | \
  grep "your-legitimate-ip"

# Add whitelist rules for legitimate traffic
[[security.whitelist]]
source_ip = "192.168.1.100"
reason = "Internal admin access"

[[security.whitelist]]
path = "/api/legacy/*"
reason = "Legacy API compatibility"
```

#### SSL/TLS Issues
```bash
# Test SSL configuration
openssl s_client -connect localhost:8443 -servername example.com

# Check certificate validity
openssl x509 -in /etc/waf-rejected/certs/server.crt -text -noout

# Verify certificate chain
openssl verify -CAfile /etc/ssl/certs/ca-certificates.crt /etc/waf-rejected/certs/server.crt
```

### Performance Optimization

#### Tuning for High Traffic

**Connection Settings:**
```toml
[server]
workers = 8  # Match CPU cores
max_connections = 2000
tcp_nodelay = true
tcp_keepalive = true
```

**Upstream Settings:**
```toml
[upstream]
max_connections = 200
keepalive_timeout = "60s"
connection_timeout = "5s"
```

**Memory Management:**
```toml
[performance]
# Pre-allocate memory pools
request_pool_size = 1000
response_pool_size = 1000
string_pool_size = 5000

# Garbage collection tuning
gc_interval = "30s"
```

#### OS-Level Optimizations

**Increase file descriptor limits:**
```bash
# /etc/security/limits.conf
waf-rejected soft nofile 65536
waf-rejected hard nofile 65536
```

**Kernel network tuning:**
```bash
# /etc/sysctl.conf
net.core.somaxconn = 65535
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_rmem = 4096 87380 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728
```

This user guide provides comprehensive coverage of operating WAF-Rejected in production environments, from basic setup to advanced optimization techniques.
