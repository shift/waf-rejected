# WAF-Rejected

A Rust reverse-proxy web application firewall. Requests are inspected by a
configurable rule chain (SQL injection, XSS, command injection, path traversal,
request-size and rate limits) before being forwarded to an upstream service.

## What works

- Reverse proxy with HTTP/1.1 and HTTP/2 over TLS.
- URI, query-string, header and **request-body** inspection.
- Percent-encoded payload decoding (`%20`, `%27`, `%3C`, ...).
- API-key authentication (`X-API-Key` by default).
- Per-IP and global token-bucket rate limiting.
- Configurable maximum request-body size (enforced while streaming).
- Trusted-proxy aware client IP resolution (`X-Forwarded-For` is ignored unless
  the peer is listed in `server.trusted_proxies`).
- Security event logging (JSON console, CEF, Sled, optional OpenTelemetry).
- Health, readiness and Prometheus metrics endpoints.
- Graceful shutdown on `SIGTERM`/`Ctrl+C`.

## Quick start

```bash
nix develop
cargo run --bin waf-ingress
```

The server loads `WAF_CONFIG_FILE` (or `CONFIG_PATH`). With no file it uses the
built-in defaults:

- proxy: `0.0.0.0:8080`
- health/metrics: `0.0.0.0:8081`
- upstream: `http://127.0.0.1:3000`

Configuration errors are fatal; the server will not silently run with defaults.

```bash
WAF_CONFIG_FILE=./config.toml cargo run --bin waf-ingress
```

### Endpoints

| Endpoint | Purpose |
|---|---|
| `GET /health` | JSON health status |
| `GET /health/ready` | Readiness probe |
| `GET /metrics` | Prometheus metrics |
| everything else | Inspected and forwarded upstream |

### Example request

```bash
# allowed
curl -i http://127.0.0.1:8080/hello

# blocked (SQL injection)
curl -i "http://127.0.0.1:8080/?id=1%20UNION%20SELECT%20*%20FROM%20users"

# blocked (body inspection)
curl -i -X POST --data "id=1 UNION SELECT * FROM users" http://127.0.0.1:8080/login
```

## Configuration

See [`config.toml`](config.toml) for a complete example. Key sections:

```toml
bind_addr = "0.0.0.0:8080"
health_bind_addr = "0.0.0.0:8081"
upstream_uri = "http://127.0.0.1:3000"

[server]
trusted_proxies = ["10.0.0.0/8"]
max_body_size = 10485760

[waf.rate_limit]
per_ip_enabled = true
per_ip_max_requests = 100
per_ip_window_secs = 60

[waf.content_inspection]
enabled = true
inspect_body = true
threat_patterns = ["sql_injection", "xss", "command_injection", "path_traversal"]

[security.auth]
enabled = true
api_keys = ["replace-me"]      # prefer injecting from a secret
header_name = "X-API-Key"
require_https = true
```

## Build and test

```bash
nix develop -c cargo fmt -- --check
nix develop -c cargo clippy --lib -- --deny warnings
nix develop -c cargo test --lib
nix develop -c cargo test --test integration
nix develop -c cargo check --all-targets
nix build .#waf-ingress
```

## Deployment

- Docker: `docker build -t waf-rejected .`
- Kubernetes manifests: [`infrastructure/kubernetes`](infrastructure/kubernetes)
- Helm chart: [`infrastructure/helm`](infrastructure/helm)
- Monitoring: [`infrastructure/monitoring`](infrastructure/monitoring)

## Security limitations (read before production)

- **ModSecurity/Coraza WASM execution is not implemented.** The engine currently
  uses an internal heuristic fallback. `[waf.wasm] enabled = false` is the safe
  default; do not enable it expecting OWASP CRS coverage.
- **WebSocket and WebTransport tunneling are not implemented.** Upgrade requests
  are rejected with `501` rather than returning a misleading `101`.
- **GeoIP blocking needs a database loader.** Without a MaxMind database only the
  built-in test addresses resolve, so country rules are not effective.
- **HTTP/3 is not implemented.** Keep `enable_http3 = false`; use TLS + HTTP/2.
- The legacy AI/threat-intelligence modules are experimental and are not on the
  request path by default.

## License

MIT OR Apache-2.0.
