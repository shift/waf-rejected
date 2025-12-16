# Installation Guide

**Complete installation instructions for WAF-Rejected across different platforms and deployment scenarios**

## System Requirements

### Minimum Requirements
- **CPU**: 2 cores (x86_64 or ARM64)
- **Memory**: 4GB RAM
- **Storage**: 1GB available space
- **Network**: Internet connection for updates
- **OS**: Linux (Ubuntu 20.04+, CentOS 8+, Debian 11+) or macOS 12+

### Recommended Requirements
- **CPU**: 4+ cores with AVX2 support
- **Memory**: 8GB RAM
- **Storage**: 10GB SSD storage
- **Network**: Dedicated network interface for WAF traffic
- **OS**: Linux with kernel 5.4+ for optimal performance

### Production Requirements
- **CPU**: 8+ cores (Intel Xeon or AMD EPYC)
- **Memory**: 16GB+ RAM
- **Storage**: 50GB+ SSD with high IOPS
- **Network**: 1Gbps+ network interface
- **OS**: Enterprise Linux (RHEL, Ubuntu LTS, SLES)

## Installation Methods

### Option 1: Nix Flake (Recommended)

The Nix flake provides a reproducible development environment with all dependencies.

```bash
# Prerequisites: Install Nix with flakes enabled
sh <(curl -L https://nixos.org/nix/install) --daemon
echo "experimental-features = nix-command flakes" >> ~/.config/nix/nix.conf

# Clone and build
git clone https://github.com/your-org/waf-rejected.git
cd waf-rejected

# Enter development environment (downloads all dependencies)
nix develop

# Build WAF-Rejected
cargo build --release

# The binary is now available at ./target/release/waf-ingress
```

**Advantages:**
- ✅ Reproducible builds across different systems
- ✅ All dependencies managed automatically  
- ✅ Isolated environment prevents conflicts
- ✅ Same environment used in CI/CD

### Option 2: Native Rust Installation

Install Rust toolchain and build directly on your system.

#### Install Rust
```bash
# Install Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# Verify installation
rustc --version  # Should show 1.89+
cargo --version
```

#### Install System Dependencies

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install -y \
    build-essential \
    pkg-config \
    libssl-dev \
    curl \
    git
```

**CentOS/RHEL/Fedora:**
```bash
sudo dnf install -y \
    gcc \
    gcc-c++ \
    openssl-devel \
    pkg-config \
    curl \
    git
```

**macOS:**
```bash
# Install Xcode command line tools
xcode-select --install

# Install Homebrew if not already installed
/bin/bash -c \"$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\"

# Install dependencies
brew install openssl pkg-config
```

#### Build WAF-Rejected
```bash
# Clone repository
git clone https://github.com/your-org/waf-rejected.git
cd waf-rejected

# Build with all features
cargo build --release --features \"wasm-waf,export-system,geoip\"

# The binary is now available at ./target/release/waf-ingress
```

### Option 3: Docker Installation

Use pre-built Docker images for quick deployment.

#### Pull and Run
```bash
# Pull latest image
docker pull ghcr.io/your-org/waf-rejected:latest

# Run with basic configuration
docker run -d \
  --name waf-rejected \
  -p 8080:8080 \
  -p 8443:8443 \
  -v $(pwd)/config.toml:/app/config.toml:ro \
  ghcr.io/your-org/waf-rejected:latest

# Check status
docker logs waf-rejected
```

#### Docker Compose
```yaml
# docker-compose.yml
version: '3.8'
services:
  waf-rejected:
    image: ghcr.io/your-org/waf-rejected:latest
    ports:
      - \"80:8080\"
      - \"443:8443\"
    volumes:
      - ./config.toml:/app/config.toml:ro
      - ./certs:/app/certs:ro
      - waf-data:/app/data
    environment:
      - RUST_LOG=info
      - WAF_SERVER_HOST=0.0.0.0
    restart: unless-stopped
    healthcheck:
      test: [\"CMD\", \"curl\", \"-f\", \"http://localhost:8080/health\"]
      interval: 30s
      timeout: 10s
      retries: 3

  # Optional: Redis for rate limiting
  redis:
    image: redis:7-alpine
    command: redis-server --appendonly yes
    volumes:
      - redis-data:/data
    restart: unless-stopped

  # Optional: Monitoring stack
  prometheus:
    image: prom/prometheus:latest
    ports:
      - \"9090:9090\"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml:ro
    restart: unless-stopped

  grafana:
    image: grafana/grafana:latest
    ports:
      - \"3000:3000\"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
    volumes:
      - grafana-data:/var/lib/grafana
    restart: unless-stopped

volumes:
  waf-data:
  redis-data:
  grafana-data:
```

#### Build Custom Docker Image
```dockerfile
# Dockerfile
FROM rust:1.89-slim as builder

WORKDIR /app
COPY . .

RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

RUN cargo build --release --features \"wasm-waf,export-system\"

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/waf-ingress /usr/local/bin/
COPY --from=builder /app/config.toml /app/config.toml

WORKDIR /app

EXPOSE 8080 8443 9090

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8080/health || exit 1

CMD [\"waf-ingress\"]
```

### Option 4: Package Manager Installation

Pre-built packages for various distributions.

#### Debian/Ubuntu (APT)
```bash
# Add repository
curl -fsSL https://packages.waf-rejected.com/gpg.key | sudo apt-key add -
echo \"deb https://packages.waf-rejected.com/debian stable main\" | sudo tee /etc/apt/sources.list.d/waf-rejected.list

# Install
sudo apt update
sudo apt install waf-rejected

# Start service
sudo systemctl enable waf-rejected
sudo systemctl start waf-rejected
```

#### CentOS/RHEL (YUM/DNF)
```bash
# Add repository
sudo tee /etc/yum.repos.d/waf-rejected.repo << EOF
[waf-rejected]
name=WAF-Rejected Repository
baseurl=https://packages.waf-rejected.com/rhel/\$releasever/\$basearch/
gpgcheck=1
gpgkey=https://packages.waf-rejected.com/gpg.key
enabled=1
EOF

# Install
sudo dnf install waf-rejected

# Start service
sudo systemctl enable waf-rejected
sudo systemctl start waf-rejected
```

#### macOS (Homebrew)
```bash
# Add tap
brew tap your-org/waf-rejected

# Install
brew install waf-rejected

# Start service
brew services start waf-rejected
```

## Configuration

### Basic Configuration

Create `/etc/waf-rejected/config.toml`:

```toml
# Basic WAF configuration
[server]
host = \"0.0.0.0\"
port = 8080
workers = 4

[upstream]
base_url = \"http://localhost:3000\"
timeout = \"30s\"
max_connections = 1000

[security]
enable_geo_blocking = true
enable_content_inspection = true
enable_rate_limiting = true

# Geographic filtering
blocked_countries = [\"CN\", \"RU\", \"IR\", \"KP\"]

[logging]
level = \"info\"
format = \"json\"
file = \"/var/log/waf-rejected/waf.log\"

[metrics]
enabled = true
bind_address = \"127.0.0.1:9090\"
```

### TLS Configuration

For HTTPS traffic handling:

```toml
[tls]
enabled = true
cert_file = \"/etc/waf-rejected/certs/server.crt\"
key_file = \"/etc/waf-rejected/certs/server.key\"
min_version = \"1.2\"
max_version = \"1.3\"

# Client certificate authentication (optional)
client_ca_file = \"/etc/waf-rejected/certs/client-ca.crt\"
require_client_cert = false
```

### Advanced Security Configuration

```toml
[security.content_inspection]
# SQL injection patterns
sql_patterns = [
    \"(?i)union.*select\",
    \"(?i)drop.*table\",
    \"(?i)'; *--\",
    \"(?i)or.*1.*=.*1\"
]

# XSS patterns  
xss_patterns = [
    \"(?i)<script[^>]*>\",
    \"(?i)javascript:\",
    \"(?i)on\\\\w+\\\\s*=\"
]

# Path traversal patterns
path_traversal_patterns = [
    \"\\\\.\\\\.[\\\\/\\\\\\\\]\",
    \"(?i)etc/passwd\",
    \"(?i)web\\\\.config\"
]

[security.rate_limiting]
# Global limits
global_requests_per_minute = 10000
global_burst_capacity = 1000

# Per-IP limits
per_ip_requests_per_minute = 100
per_ip_burst_capacity = 20

# Per-path limits
[[security.rate_limiting.path_limits]]
path = \"/api/login\"
requests_per_minute = 5
burst_capacity = 2

[[security.rate_limiting.path_limits]]
path = \"/api/register\"
requests_per_minute = 3
burst_capacity = 1
```

### Database Integration

For persistent storage and advanced features:

```toml
[database]
# Local embedded database
type = \"sled\"
path = \"/var/lib/waf-rejected/data\"

# Or Redis for distributed deployments
# type = \"redis\"
# url = \"redis://localhost:6379\"
# pool_size = 10

[exports]
# CEF (Common Event Format) for SIEM
enable_cef = true
cef_facility = \"local0\"
cef_severity = \"info\"

# OpenTelemetry for distributed tracing
enable_otel = true
otel_endpoint = \"http://jaeger:14268/api/traces\"
otel_service_name = \"waf-rejected\"

# Webhook notifications
[[exports.webhooks]]
name = \"security_alerts\"
url = \"https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK\"
events = [\"sql_injection\", \"xss\", \"geo_block\"]
min_severity = \"medium\"
```

## Service Installation

### systemd Service (Linux)

Create `/etc/systemd/system/waf-rejected.service`:

```ini
[Unit]
Description=WAF-Rejected Web Application Firewall
Documentation=https://github.com/your-org/waf-rejected
After=network.target
Wants=network.target

[Service]
Type=exec
User=waf-rejected
Group=waf-rejected
ExecStart=/usr/local/bin/waf-ingress --config /etc/waf-rejected/config.toml
ExecReload=/bin/kill -USR1 $MAINPID
Restart=on-failure
RestartSec=5s
TimeoutStopSec=30s

# Security settings
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/waf-rejected /var/log/waf-rejected

# Resource limits
LimitNOFILE=65536
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
```

**Setup service:**
```bash
# Create user and directories
sudo useradd --system --no-create-home --shell /bin/false waf-rejected
sudo mkdir -p /etc/waf-rejected /var/lib/waf-rejected /var/log/waf-rejected
sudo chown waf-rejected:waf-rejected /var/lib/waf-rejected /var/log/waf-rejected

# Install and start service
sudo systemctl daemon-reload
sudo systemctl enable waf-rejected
sudo systemctl start waf-rejected

# Check status
sudo systemctl status waf-rejected
```

### launchd Service (macOS)

Create `/Library/LaunchDaemons/com.yourorg.waf-rejected.plist`:

```xml
<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">
<plist version=\"1.0\">
<dict>
    <key>Label</key>
    <string>com.yourorg.waf-rejected</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/waf-ingress</string>
        <string>--config</string>
        <string>/usr/local/etc/waf-rejected/config.toml</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/usr/local/var/log/waf-rejected/stdout.log</string>
    <key>StandardErrorPath</key>
    <string>/usr/local/var/log/waf-rejected/stderr.log</string>
</dict>
</plist>
```

**Install service:**
```bash
# Load and start service
sudo launchctl load /Library/LaunchDaemons/com.yourorg.waf-rejected.plist
sudo launchctl start com.yourorg.waf-rejected

# Check status
sudo launchctl list | grep waf-rejected
```

## Kubernetes Installation

### Helm Chart Installation

```bash
# Add Helm repository
helm repo add waf-rejected https://charts.waf-rejected.com
helm repo update

# Install with default values
helm install waf-rejected waf-rejected/waf-rejected

# Or install with custom values
cat > values.yaml << EOF
replicaCount: 3

image:
  repository: ghcr.io/your-org/waf-rejected
  tag: latest

config:
  security:
    enable_geo_blocking: true
    blocked_countries: [\"CN\", \"RU\", \"IR\"]

resources:
  requests:
    memory: \"256Mi\"
    cpu: \"250m\"
  limits:
    memory: \"512Mi\"
    cpu: \"500m\"

service:
  type: LoadBalancer
  ports:
    - port: 80
      targetPort: 8080
    - port: 443
      targetPort: 8443

ingress:
  enabled: true
  className: nginx
  hosts:
    - host: waf.example.com
      paths:
        - path: /
          pathType: Prefix

monitoring:
  enabled: true
  serviceMonitor:
    enabled: true
EOF

helm install waf-rejected waf-rejected/waf-rejected -f values.yaml
```

### Manual Kubernetes Deployment

```yaml
# namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: waf-rejected

---
# configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: waf-rejected-config
  namespace: waf-rejected
data:
  config.toml: |
    [server]
    host = \"0.0.0.0\"
    port = 8080
    
    [upstream]
    base_url = \"http://backend.default.svc.cluster.local\"
    
    [security]
    enable_geo_blocking = true
    blocked_countries = [\"CN\", \"RU\", \"IR\"]
    
    [logging]
    level = \"info\"
    format = \"json\"

---
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: waf-rejected
  namespace: waf-rejected
  labels:
    app: waf-rejected
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
      - name: waf-rejected
        image: ghcr.io/your-org/waf-rejected:latest
        ports:
        - containerPort: 8080
          name: http
        - containerPort: 8443
          name: https
        - containerPort: 9090
          name: metrics
        volumeMounts:
        - name: config
          mountPath: /app/config.toml
          subPath: config.toml
        resources:
          requests:
            memory: \"256Mi\"
            cpu: \"250m\"
          limits:
            memory: \"512Mi\"
            cpu: \"500m\"
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
      volumes:
      - name: config
        configMap:
          name: waf-rejected-config

---
# service.yaml
apiVersion: v1
kind: Service
metadata:
  name: waf-rejected
  namespace: waf-rejected
spec:
  selector:
    app: waf-rejected
  ports:
  - name: http
    port: 80
    targetPort: 8080
  - name: https
    port: 443
    targetPort: 8443
  - name: metrics
    port: 9090
    targetPort: 9090
  type: LoadBalancer
```

**Deploy to Kubernetes:**
```bash
kubectl apply -f namespace.yaml
kubectl apply -f configmap.yaml
kubectl apply -f deployment.yaml
kubectl apply -f service.yaml

# Check deployment
kubectl get pods -n waf-rejected
kubectl logs -f deployment/waf-rejected -n waf-rejected
```

## Verification

### Basic Functionality Test

```bash
# Test health endpoint
curl http://localhost:8080/health

# Expected response:
# {\"status\":\"healthy\",\"version\":\"0.1.0\"}

# Test metrics endpoint
curl http://localhost:8080/metrics

# Test security blocking (should be blocked)
curl -X POST http://localhost:8080/test \
  -H \"Content-Type: application/json\" \
  -d '{\"query\": \"SELECT * FROM users WHERE id = 1 OR 1=1\"}'

# Test geographic blocking (from blocked country)
curl -H \"X-Forwarded-For: 114.114.114.114\" http://localhost:8080/
```

### Performance Test

```bash
# Install Apache Bench if not available
sudo apt install apache2-utils  # Ubuntu/Debian
brew install apache2            # macOS

# Run performance test
ab -n 1000 -c 10 http://localhost:8080/health

# Should show throughput matching benchmark results
```

### Security Test

```bash
# Run built-in security tests
cargo run --bin enterprise_security_test

# Or run comprehensive test suite
./enterprise_waf_test.sh
```

## Troubleshooting

### Common Issues

**Issue: Port already in use**
```bash
# Check what's using the port
sudo netstat -tlnp | grep :8080
sudo lsof -i :8080

# Kill process or change port in config
```

**Issue: Permission denied**
```bash
# Make sure binary is executable
chmod +x ./target/release/waf-ingress

# Check if binding to privileged ports (< 1024)
# Either run as root or use higher ports
```

**Issue: TLS certificate errors**
```bash
# Verify certificate files exist and are readable
ls -la /path/to/certs/
openssl x509 -in server.crt -text -noout
openssl rsa -in server.key -check
```

**Issue: High memory usage**
```bash
# Check for memory leaks in logs
tail -f /var/log/waf-rejected/waf.log | grep -i memory

# Adjust memory limits in config
[server]
max_connections = 100  # Reduce if needed
```

### Log Analysis

```bash
# Real-time log monitoring
tail -f /var/log/waf-rejected/waf.log

# Search for security events
grep \"SECURITY_EVENT\" /var/log/waf-rejected/waf.log

# Analyze blocked requests
grep \"blocked.*true\" /var/log/waf-rejected/waf.log | jq '.source_ip' | sort | uniq -c
```

### Getting Help

If you encounter issues during installation:

1. **Check the logs** - Most issues are logged with detailed error messages
2. **Verify configuration** - Use `waf-ingress --dry-run` to validate config
3. **Review system requirements** - Ensure your system meets minimum requirements
4. **Consult documentation** - Check the troubleshooting guide
5. **Open an issue** - Report bugs on GitHub with logs and system info

The installation process is designed to be straightforward, but the modular architecture allows for extensive customization based on your specific deployment needs.
