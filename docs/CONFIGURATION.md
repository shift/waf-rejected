# Configuration Reference

**Complete configuration options for WAF-Rejected**

## Configuration File Format

WAF-Rejected uses TOML format for configuration files. The configuration system supports:

- Default values built into the application
- Configuration file overrides
- Environment variable overrides  
- Command-line argument overrides

### Configuration Loading Priority

1. **Built-in Defaults** (lowest priority)
2. **Configuration File** (`config.toml`)
3. **Environment Variables** (prefixed with `WAF_`)
4. **Command Line Arguments** (highest priority)

## Server Configuration

### Basic Server Settings

```toml
[server]
# Bind address (use "0.0.0.0" for all interfaces)
host = "127.0.0.1"

# HTTP port 
port = 8080

# HTTPS port (optional)
https_port = 8443

# Number of worker threads (0 = auto-detect based on CPU cores)
workers = 0

# Maximum concurrent connections
max_connections = 1000

# TCP socket settings
tcp_nodelay = true
tcp_keepalive = true

# Socket timeout settings
socket_timeout = "30s"
keepalive_timeout = "60s"
```

### Advanced Server Settings

```toml
[server.advanced]
# Request body size limits
max_request_body_size = "10MB"
max_header_size = "8KB"
max_uri_length = 4096

# Connection handling
connection_timeout = "30s"
request_timeout = "60s"
graceful_shutdown_timeout = "10s"

# Performance tuning
backlog = 2048
reuse_port = true
```

## TLS/SSL Configuration

### Basic TLS Setup

```toml
[tls]
enabled = true

# Certificate and private key files
cert_file = "/etc/waf/certs/server.crt"
key_file = "/etc/waf/certs/server.key"

# Minimum and maximum TLS versions
min_version = "1.2"  # Options: "1.0", "1.1", "1.2", "1.3"
max_version = "1.3"

# Certificate chain file (optional)
cert_chain_file = "/etc/waf/certs/chain.crt"
```

### Advanced TLS Settings

```toml
[tls.advanced]
# Cipher suites (leave empty for defaults)
cipher_suites = [
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256", 
    "TLS_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
]

# ECDH curves
curves = ["X25519", "prime256v1", "secp384r1"]

# Session settings
session_timeout = "12h"
session_cache_size = 1000

# ALPN protocols
alpn_protocols = ["h2", "http/1.1"]
```

### Client Certificate Authentication

```toml
[tls.client_auth]
enabled = false

# Client CA certificate file
ca_file = "/etc/waf/certs/client-ca.crt"

# Require client certificate
require_cert = false

# Verification depth
verify_depth = 3

# Client certificate revocation list (optional)
crl_file = "/etc/waf/certs/client.crl"
```

### ACME/Let's Encrypt Integration

```toml
[tls.acme]
enabled = false

# ACME directory URL
directory_url = "https://acme-v02.api.letsencrypt.org/directory"
# Staging: "https://acme-staging-v02.api.letsencrypt.org/directory"

# Account email
email = "admin@example.com"

# Domains to obtain certificates for
domains = ["example.com", "www.example.com", "api.example.com"]

# Challenge type
challenge_type = "http-01"  # Options: "http-01", "tls-alpn-01"

# Certificate storage path
cert_cache_dir = "/var/lib/waf/acme"

# Renewal settings
renew_days_before_expiry = 30
```

## Upstream Configuration

### Basic Upstream Settings

```toml
[upstream]
# Backend server URL
base_url = "http://localhost:3000"

# Request timeout
timeout = "30s"

# Connection pool settings
max_connections = 100
keepalive_timeout = "60s"
connection_timeout = "10s"

# Retry settings
retry_attempts = 3
retry_delay = "1s"
retry_backoff_multiplier = 2.0
```

### Load Balancing

```toml
# Multiple upstream servers
[[upstream.servers]]
url = "http://backend1:3000"
weight = 100
health_check = true

[[upstream.servers]]
url = "http://backend2:3000" 
weight = 50
health_check = true

[[upstream.servers]]
url = "http://backend3:3000"
weight = 25
health_check = false

[upstream.load_balancing]
# Algorithm: "round_robin", "weighted_round_robin", "least_connections", "ip_hash"
algorithm = "weighted_round_robin"

# Health check settings
health_check_interval = "30s"
health_check_timeout = "5s"
health_check_path = "/health"
unhealthy_threshold = 3
healthy_threshold = 2
```

### Circuit Breaker

```toml
[upstream.circuit_breaker]
enabled = true

# Failure threshold before opening circuit
failure_threshold = 10

# Success threshold for closing circuit  
success_threshold = 5

# Timeout before attempting to close circuit
timeout = "60s"

# Request volume threshold
request_volume_threshold = 20
```

## Security Configuration

### Geographic Blocking

```toml
[security.geo_blocking]
enabled = true

# Block specific countries (ISO 3166-1 alpha-2 codes)
blocked_countries = [
    "CN",  # China
    "RU",  # Russia
    "IR",  # Iran
    "KP"   # North Korea
]

# Alternative: allow only specific countries
# allowed_countries = ["US", "CA", "GB", "DE", "FR"]

# Block known VPN/proxy providers
block_vpns = true
block_tor = true
block_hosting_providers = false

# Custom block message
block_message = "Access denied from your location"

# GeoIP database settings
geoip_database_path = "/var/lib/waf/GeoLite2-Country.mmdb"
geoip_update_interval = "24h"
```

### Content Inspection

```toml
[security.content_inspection]
enabled = true

# Maximum body size to inspect
max_body_size = "1MB"

# Content types to inspect
inspect_content_types = [
    "application/json",
    "application/x-www-form-urlencoded",
    "text/plain",
    "text/xml"
]
```

#### SQL Injection Detection

```toml
[security.content_inspection.sql_injection]
enabled = true

# Detection patterns (regex)
patterns = [
    "(?i)union.*select",
    "(?i)drop.*table",
    "(?i)insert.*into",
    "(?i)update.*set",
    "(?i)delete.*from",
    "(?i)'; *--",
    "(?i)or.*1.*=.*1",
    "(?i)and.*1.*=.*1",
    "(?i)exec.*\\(",
    "(?i)sp_executesql"
]

# Action: "block", "monitor", "log"
action = "block"

# Severity level
severity = "high"
```

#### Cross-Site Scripting (XSS) Detection

```toml
[security.content_inspection.xss]
enabled = true

patterns = [
    "(?i)<script[^>]*>",
    "(?i)</script>",
    "(?i)javascript:",
    "(?i)vbscript:",
    "(?i)on\\w+\\s*=",
    "(?i)<iframe[^>]*>",
    "(?i)<object[^>]*>",
    "(?i)<embed[^>]*>",
    "(?i)<link[^>]*>",
    "(?i)<meta[^>]*>"
]

action = "block"
severity = "high"

# Content rewriting (sanitize instead of block)
enable_content_rewriting = false
```

#### Path Traversal Detection

```toml
[security.content_inspection.path_traversal]
enabled = true

patterns = [
    "\\.\\./",
    "\\.\\.\\\\",
    "(?i)/etc/passwd",
    "(?i)/etc/shadow",
    "(?i)web\\.config",
    "(?i)cmd\\.exe",
    "(?i)%2e%2e%2f",  # URL encoded ../
    "(?i)%252e%252e%252f"  # Double URL encoded ../
]

action = "block"
severity = "medium"
```

#### Command Injection Detection

```toml
[security.content_inspection.command_injection]
enabled = true

patterns = [
    "(?i)\\|\\s*\\w+",
    "(?i)&&\\s*\\w+",
    "(?i);\\s*\\w+",
    "(?i)\\$\\(.*\\)",
    "(?i)`.*`",
    "(?i)eval\\s*\\(",
    "(?i)exec\\s*\\(",
    "(?i)system\\s*\\(",
    "(?i)shell_exec\\s*\\("
]

action = "block"
severity = "critical"
```

### Rate Limiting

```toml
[security.rate_limiting]
enabled = true

# Rate limiting algorithm: "token_bucket", "sliding_window", "fixed_window"
algorithm = "token_bucket"

# Global rate limits (across all IPs)
global_requests_per_minute = 10000
global_burst_capacity = 1000

# Per-IP rate limits
per_ip_requests_per_minute = 100
per_ip_burst_capacity = 20
per_ip_window_duration = "1m"

# Rate limit storage: "memory", "redis" 
storage = "memory"

# Redis settings (if storage = "redis")
redis_url = "redis://localhost:6379"
redis_key_prefix = "waf:ratelimit:"
```

#### Path-Specific Rate Limits

```toml
# Protect login endpoints
[[security.rate_limiting.path_limits]]
path = "/api/login"
method = "POST"
requests_per_minute = 5
burst_capacity = 2
window_duration = "1m"

# Protect registration  
[[security.rate_limiting.path_limits]]
path = "/api/register"
method = "POST" 
requests_per_minute = 3
burst_capacity = 1
window_duration = "5m"

# Protect password reset
[[security.rate_limiting.path_limits]]
path = "/api/password-reset"
method = "POST"
requests_per_minute = 2
burst_capacity = 1
window_duration = "10m"

# Protect API endpoints
[[security.rate_limiting.path_limits]]
path = "/api/*"
requests_per_minute = 1000
burst_capacity = 100
```

### Custom Security Rules

```toml
# Block known bad user agents
[[security.custom_rules]]
name = "Block Security Scanners"
field = "user_agent"
pattern = "(?i)(sqlmap|nmap|masscan|nessus|nikto|burpsuite|owasp zap)"
action = "block"
severity = "high"
message = "Security scanner detected"

# Monitor admin panel access
[[security.custom_rules]]
name = "Admin Panel Access"
field = "path" 
pattern = "^/(admin|wp-admin|phpmyadmin|cpanel)"
action = "monitor"
severity = "medium"
geo_restrictions = ["CN", "RU", "IR"]  # Only apply to these countries

# Block suspicious file extensions
[[security.custom_rules]]
name = "Suspicious File Extensions"
field = "path"
pattern = "\\.(php|asp|jsp|cgi|pl)$"
action = "block"
severity = "medium"
exceptions = ["/api/upload.php"]  # Allow specific paths

# Block common attack patterns
[[security.custom_rules]]
name = "Common Attack Patterns"
field = "any"  # Check all fields
pattern = "(?i)(eval|base64_decode|shell_exec|system|passthru)"
action = "block"
severity = "critical"
```

### Whitelist Rules

```toml
# IP-based whitelist
[[security.whitelist]]
type = "ip"
value = "192.168.1.0/24"
reason = "Internal network"

[[security.whitelist]]
type = "ip"
value = "10.0.0.100"
reason = "Admin workstation"

# Path-based whitelist
[[security.whitelist]]
type = "path"
value = "/api/webhook/*"
reason = "GitHub webhooks"

# User agent whitelist
[[security.whitelist]]
type = "user_agent"
value = "HealthCheck/1.0"
reason = "Load balancer health checks"

# Combined conditions
[[security.whitelist]]
type = "combined"
conditions = [
    { field = "ip", value = "203.0.113.0/24" },
    { field = "path", value = "/admin/*" }
]
reason = "Admin access from office"
```

## Logging Configuration

### Basic Logging

```toml
[logging]
# Log level: "trace", "debug", "info", "warn", "error"
level = "info"

# Log format: "json", "text", "compact"
format = "json"

# Log output: file path or "stdout"/"stderr"
output = "/var/log/waf/waf.log"

# Include source code location in logs
include_location = false

# Include thread ID in logs
include_thread_id = true
```

### Advanced Logging

```toml
[logging.advanced]
# Log rotation
max_file_size = "100MB"
max_files = 10
compress_rotated = true

# Async logging for better performance
async_logging = true
async_buffer_size = 8192

# Structured logging fields
include_request_id = true
include_user_agent = true
include_referer = true
```

### Security Event Logging

```toml
[logging.security_events]
enabled = true

# Separate file for security events
file = "/var/log/waf/security.log"

# Security event format: "json", "cef", "text"
format = "json"

# Include request/response bodies in security logs
include_request_body = false
include_response_body = false

# Log all requests (not just blocked ones)
log_all_requests = false

# Fields to include in security events
fields = [
    "timestamp",
    "source_ip",
    "user_agent", 
    "method",
    "path",
    "query_string",
    "threat_type",
    "rule_id",
    "severity",
    "action",
    "response_time"
]
```

## Monitoring and Metrics

### Prometheus Metrics

```toml
[metrics]
enabled = true

# Metrics endpoint
bind_address = "127.0.0.1:9090"
path = "/metrics"

# Basic authentication for metrics endpoint
username = "prometheus"
password = "secure_password"

# Histogram buckets for response time metrics
response_time_buckets = [
    0.001, 0.005, 0.01, 0.025, 0.05,
    0.1, 0.25, 0.5, 1.0, 2.5, 5.0
]
```

### Custom Metrics

```toml
[metrics.custom]
# Track specific paths
track_paths = ["/api/*", "/admin/*", "/login"]

# Track specific status codes
track_status_codes = [200, 301, 302, 400, 401, 403, 404, 500, 502, 503]

# Track user agents
track_user_agents = true

# Geographic metrics
track_countries = true
```

### Health Checks

```toml
[health]
enabled = true
path = "/health"

# Include detailed system information
detailed = true

# Custom health check probes
[[health.checks]]
name = "upstream_connectivity"
type = "http"
target = "http://backend:3000/health"
timeout = "5s"
interval = "30s"
healthy_threshold = 2
unhealthy_threshold = 3

[[health.checks]]
name = "redis_connectivity" 
type = "tcp"
target = "redis:6379"
timeout = "2s"
interval = "10s"

[[health.checks]]
name = "database_connectivity"
type = "custom"
command = "/usr/local/bin/check-db.sh"
timeout = "10s"
interval = "60s"
```

## Export Systems

### OpenTelemetry Integration

```toml
[exports.opentelemetry]
enabled = true

# Service information
service_name = "waf-rejected"
service_version = "0.1.0"
service_namespace = "security"

# OTLP exporter settings
[exports.opentelemetry.otlp]
# Endpoint (gRPC)
endpoint = "http://jaeger:4317"
# HTTP endpoint alternative
# endpoint = "http://jaeger:4318/v1/traces"

# Authentication headers
headers = { "api-key" = "your-api-key" }

# Export timeout
timeout = "10s"

# Batch settings
max_export_batch_size = 512
export_timeout = "30s"
max_queue_size = 2048

# Sampling configuration
[exports.opentelemetry.sampling]
# Type: "always_on", "always_off", "probabilistic", "rate_limiting"
type = "probabilistic" 
probability = 0.1  # Sample 10% of requests

# Parent-based sampling
parent_based = true
```

### SIEM Integration (CEF Format)

```toml
[exports.cef]
enabled = true

# Syslog settings
facility = "local0"  # Options: local0-local7, user, daemon, etc.
severity = "info"    # Options: emerg, alert, crit, err, warning, notice, info, debug

# CEF header fields
vendor = "WAF-Rejected"
product = "WAF"
version = "1.0"

# Export settings
export_all_events = false  # Only export security events
min_severity = "medium"    # Only export medium+ severity events

# Event types to export
event_types = [
    "sql_injection",
    "xss", 
    "path_traversal",
    "command_injection",
    "geo_block",
    "rate_limit",
    "custom_rule"
]

# Syslog destination
syslog_server = "siem.company.com:514"
protocol = "udp"  # Options: udp, tcp, tls
```

### Database Export (Sled)

```toml
[exports.sled]
enabled = true

# Database path
path = "/var/lib/waf/events.db"

# Retention settings
max_events = 1000000
retention_days = 90

# Compression
compress = true

# Export settings
batch_size = 100
flush_interval = "30s"

# Index settings for fast queries
enable_indexes = true
index_fields = ["timestamp", "source_ip", "threat_type", "severity"]
```

### Webhook Notifications

```toml
# Slack notifications for high-severity events
[[exports.webhooks]]
name = "security_alerts_slack"
url = "https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"

# Events to send
events = ["sql_injection", "xss", "command_injection"]
min_severity = "high"

# Request settings  
timeout = "10s"
retry_attempts = 3
retry_delay = "5s"

# Custom headers
headers = { 
    "Content-Type" = "application/json"
}

# Custom payload template
template = """
{
  "text": "🚨 WAF Security Alert",
  "attachments": [{
    "color": "danger",
    "fields": [
      {"title": "Threat Type", "value": "{{.threat_type}}", "short": true},
      {"title": "Source IP", "value": "{{.source_ip}}", "short": true},
      {"title": "Target Path", "value": "{{.target_path}}", "short": true}, 
      {"title": "Rule ID", "value": "{{.rule_id}}", "short": true},
      {"title": "Severity", "value": "{{.severity}}", "short": true},
      {"title": "Timestamp", "value": "{{.timestamp}}", "short": true}
    ]
  }]
}
"""

# PagerDuty notifications for critical events  
[[exports.webhooks]]
name = "critical_alerts_pagerduty"
url = "https://events.pagerduty.com/v2/enqueue"

events = ["*"]
min_severity = "critical"

timeout = "15s"
retry_attempts = 5

headers = { 
    "Content-Type" = "application/json"
}

template = """
{
  "routing_key": "YOUR_PAGERDUTY_INTEGRATION_KEY",
  "event_action": "trigger",
  "payload": {
    "summary": "WAF Critical Security Event: {{.threat_type}}",
    "source": "{{.source_ip}}",
    "severity": "critical",
    "component": "waf-rejected",
    "group": "security",
    "class": "{{.threat_type}}",
    "custom_details": {
      "target_path": "{{.target_path}}",
      "rule_id": "{{.rule_id}}",
      "user_agent": "{{.user_agent}}"
    }
  }
}
"""
```

## Administrative Interface

### Admin API

```toml
[admin]
enabled = true

# Admin API bind address (use 127.0.0.1 for local only)
bind_address = "127.0.0.1:9091"

# Authentication
api_token = "waf_admin_token_change_me"

# TLS for admin interface
tls_enabled = false
tls_cert_file = "/etc/waf/admin.crt"
tls_key_file = "/etc/waf/admin.key"

# CORS settings for web UI
cors_enabled = true
cors_origins = ["http://localhost:3000", "https://admin.example.com"]
```

### gRPC API

```toml
[grpc]
enabled = true
bind_address = "127.0.0.1:9092"

# TLS settings
tls_enabled = false
tls_cert_file = "/etc/waf/grpc.crt" 
tls_key_file = "/etc/waf/grpc.key"

# Client authentication
client_ca_file = "/etc/waf/client-ca.crt"
require_client_cert = false

# Connection settings
max_connections = 100
connection_timeout = "30s"
```

## Environment Variable Overrides

Any configuration value can be overridden using environment variables with the prefix `WAF_`:

```bash
# Server settings
export WAF_SERVER__HOST="0.0.0.0"
export WAF_SERVER__PORT="8080"

# Upstream settings
export WAF_UPSTREAM__BASE_URL="http://backend:3000"

# Security settings
export WAF_SECURITY__GEO_BLOCKING__ENABLED="true"
export WAF_SECURITY__GEO_BLOCKING__BLOCKED_COUNTRIES="CN,RU,IR"

# Logging settings
export WAF_LOGGING__LEVEL="info"
export WAF_LOGGING__FORMAT="json"
```

## Configuration Validation

WAF-Rejected provides configuration validation:

```bash
# Validate configuration without starting
waf-ingress --config /path/to/config.toml --dry-run

# Check current running configuration
curl http://localhost:9091/admin/config \
  -H "Authorization: Bearer your-admin-token"
```

This comprehensive configuration reference covers all available options for customizing WAF-Rejected behavior to meet your specific security and operational requirements.
