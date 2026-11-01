# WAF-Rejected

**Current Beta:** `0.1.0-beta.9` · prebuilt image tarball attached to the GitHub release

A Rust reverse-proxy web application firewall. Requests are inspected by a
configurable rule chain (SQL injection, XSS, command injection, path traversal,
request-size and rate limits) before being forwarded to an upstream service.

## What works

- Reverse proxy with HTTP/1.1, HTTP/2 over TLS, and feature-gated HTTP/3 (QUIC).
- HTTP and HTTPS upstreams over HTTP/1.1 and HTTP/2. HTTPS upstreams are
  verified against `webpki-roots`, with an optional private CA bundle via
  `proxy.upstream_ca_path`.
- WebSocket upgrade proxying with per-frame WAF inspection.
- TLS WebSocket upstreams (`https://`) verified against `webpki-roots`, with an
  optional private CA bundle via `proxy.upstream_ca_path`.
- URI, query-string, header and **request-body** inspection.
- Bounded `gzip`, `deflate` and `br` request decompression before WAF
  inspection, capped at `server.max_body_size`.
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

### Request decompression

Requests may use a single `Content-Encoding` of `gzip`, `deflate`
(zlib-wrapped DEFLATE) or `br`. The body is decompressed before WAF inspection,
and the decompressed output must not exceed `server.max_body_size`; larger
output is rejected with `413`. Malformed compressed data returns `400` and any
other coding returns `415`. Stacked encodings such as `gzip, gzip` are rejected
with `415` rather than decoded recursively.

Successful requests are forwarded in their decompressed `identity` form: the
proxy removes `Content-Encoding` (and the stale `Content-Length`, which is
recomputed for the new body). This ensures the upstream cannot re-interpret
already-inspected bytes as a different representation. Requests without a
`Content-Encoding`, or with an explicit `identity`, are forwarded unchanged.

## Build and test

```bash
nix develop -c cargo fmt -- --check
nix develop -c cargo clippy --lib -- --deny warnings
nix develop -c cargo test --lib
nix develop -c cargo test --test integration
nix develop -c cargo check --all-targets
nix build .#waf-ingress
```

MaxMind-backed integration tests are skipped unless local databases are
provided. Licensed `.mmdb` files are never committed; see
[`docs/operations/maxmind-testing.md`](docs/operations/maxmind-testing.md) for
licensing, placement and failure handling.

```bash
MAXMIND_CITY_DB=/path/to/GeoLite2-City.mmdb \
MAXMIND_ANONYMOUS_DB=/path/to/GeoIP2-Anonymous-IP.mmdb \
nix develop -c cargo test --test integration maxmind
```

Run the full local pipeline (format, lint for default/compliance/http3,
checks, unit and integration tests, optional audit, supply-chain policy and
Helm validation) with:

```bash
./scripts/ci-local.sh     # or: just ci-local
```

`SKIP_AUDIT=1` skips `cargo audit`, `SKIP_DENY=1` skips `cargo deny check`
(warned and skipped automatically when the tools are not installed), and
`BUILD_IMAGE=1` additionally builds the container image (`CONTAINER_ENGINE`
defaults to `docker`).

### Fuzzing

Nightly-only `cargo-fuzz` harnesses live in [`fuzz/`](fuzz/) and are isolated
from the default workspace. Targets cover content inspection (query/body),
WebSocket frame inspection and TOML configuration deserialization:

```bash
cd fuzz
cargo +nightly fuzz run content_inspection -- -runs=10000 -max_total_time=60
```

See [`fuzz/README.md`](fuzz/README.md) for prerequisites, seed corpora, run
limits and CI guidance. Fuzzing is not part of `nix build`.

## Deployment

- Docker: `docker build -t waf-rejected .`
- Released image tarball, digest pinning, upgrade and rollback:
  [`docs/operations/container.md`](docs/operations/container.md)
- Kubernetes manifests: [`infrastructure/kubernetes`](infrastructure/kubernetes)
- Helm chart: [`infrastructure/helm`](infrastructure/helm)
- Monitoring: [`infrastructure/monitoring`](infrastructure/monitoring)

## Security and support

- **Reporting a vulnerability:** follow the coordinated disclosure process in
  [`SECURITY.md`](SECURITY.md). Do not open a public issue for a security
  report.
- **Support period, patch targets and end of life:**
  [`docs/operations/support-policy.md`](docs/operations/support-policy.md).
- **Security architecture and threat model:** trust boundaries, request-path
  enforcement points, bypass classes and deployment assumptions:
  [`docs/architecture/security-model.md`](docs/architecture/security-model.md).
- **Container operations:** loading the released image tarball, pinning by
  digest, health/metrics ports (`8081`), upgrade and rollback:
  [`docs/operations/container.md`](docs/operations/container.md).
- **SBOM:** every tagged release attaches a CycloneDX SBOM
  (`waf-rejected-<version>.cdx.json`) generated by `cargo cyclonedx`, and
  includes it in the binary tarball.
- **Supply chain:** dependency advisories, licences, duplicate versions and
  registries are enforced by `cargo-deny`, and release filesystems and
  container images are scanned by Trivy (HIGH/CRITICAL findings block a
  release) in CI and locally; see
  [`docs/operations/supply-chain.md`](docs/operations/supply-chain.md).
- WAF-Rejected is **not certified** and is not CRA-conformant or CE-marked. The
  policies above are project commitments and inputs for a downstream
  manufacturer's own conformity work.

## EU regulatory mapping

The compliance module can produce evidence packs for GDPR, HIPAA, PCI-DSS, the
EU AI Act, NIS2 and the Cyber Resilience Act. They are **not certifications**.
Current dates and obligations (validated 2026-10-31) are documented in
[`docs/compliance/eu-regulatory-status.md`](docs/compliance/eu-regulatory-status.md).

Key points:

- **AI Act:** amended by Regulation (EU) 2026/1744. General application and
  Article 50 transparency apply from 2 August 2026; Annex III high-risk duties
  are deferred to 2 December 2027, Annex I to 2 August 2028.
- **NIS2:** in force, but national transposition remains uneven. The January
  2026 amendment proposals were still in the legislative process in October 2026.
- **CRA:** Article 14 reporting obligations have applied since 11 September
  2026; main essential requirements and CE marking apply from 11 December 2027.

## Security limitations (read before production)

- **ModSecurity/Coraza WASM execution is not implemented.** The bundled
  `rules/coraza.wasm` is a Go-JS demo module, not Coraza/CRS. The WASM runtime
  dependency was removed from the Beta build; see
  [`docs/wasm-integration-status.md`](docs/wasm-integration-status.md). Do not
  expect OWASP CRS coverage.
- **WebTransport is feature-gated and terminating.** Build with
  `--features webtransport`, enable `server.webtransport`, and configure Origin
  and path allowlists. It inspects sessions locally; it does **not** proxy
  arbitrary WebTransport applications upstream. HTTP/1.1
  `Upgrade: webtransport` remains `501`. See
  [`docs/webtransport-plan.md`](docs/webtransport-plan.md) and
  [`docs/developer-guide/webtransport.md`](docs/developer-guide/webtransport.md).
- **GeoIP requires a MaxMind database.** Set `waf.geo_blocking.database_path` to a
  GeoLite2/GeoIP2 City `.mmdb`; without it only built-in test addresses resolve.
  Tor/VPN/datacenter detection additionally requires a GeoIP2 Anonymous IP
  `.mmdb` via `waf.geo_blocking.anonymous_database_path`; without it those flags
  remain false.
- **HTTP/3 is feature-gated.** Build with `--features http3`, enable TLS 1.3 and
  `server.enable_http3`, and add `"3"` to `server.supported_http_versions`.
  HTTP/3 and WebTransport datagrams/streams are not inspected frame-by-frame.
- The legacy AI/threat-intelligence modules are experimental and are not on the
  request path by default.

## License

MIT OR Apache-2.0.
