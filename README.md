# WAF-Rejected

**Current Beta:** `0.1.0-beta.16` · image
`ghcr.io/shift/waf-rejected-waf:v0.1.0-beta.16` · tarball attached to the
GitHub release

A Rust reverse-proxy web application firewall. Requests are inspected by a
configurable rule chain (SQL injection, XSS, command injection, path traversal,
request-size and rate limits) before being forwarded to an upstream service.
The default inspection backend is the native Rust CRS engine; Coraza remains
the reference oracle and an explicit `waf.coraza.backend = "wasm"` switch-back.

## What works

- Reverse proxy with HTTP/1.1, HTTP/2 over TLS, and feature-gated HTTP/3 (QUIC).
- Default native Rust CRS engine with 505/505 OWASP CRS rules, plus the Coraza
  WASI reference engine as an explicit switch-back (`waf.coraza.backend = "wasm"`)
  and an opt-in native sidecar (`"native"`). See
  [`docs/user-guide/engine-selection.md`](docs/user-guide/engine-selection.md).
- HTTP and HTTPS upstreams over HTTP/1.1 and HTTP/2. HTTPS upstreams are
  verified against `webpki-roots`, with an optional private CA bundle via
  `proxy.upstream_ca_path`. Upstream mutual TLS is enabled by setting both
  `proxy.upstream_client_cert_path` and `proxy.upstream_client_key_path`.
- WebSocket upgrade proxying with per-frame WAF inspection.
- TLS WebSocket upstreams (`https://`) verified against `webpki-roots`, with an
  optional private CA bundle via `proxy.upstream_ca_path`.
- URI, query-string, header and **request-body** inspection.
- Protocol-aware gRPC (frame/field validation, method allowlists, bounded
  decoded-field content scan) and GraphQL-over-HTTP inspection. Unary RPCs are
  fully inspected, including bodies without `content-length` and delayed
  `END_STREAM`; genuinely streaming RPCs follow `server.grpc_streaming_policy`
  (`reject` default, or explicit `transport-only` with per-message inspection).
- Bounded `gzip`, `deflate` and `br` request decompression before WAF
  inspection, capped at `server.max_body_size`.
- Request-framing validation (CL/TE ambiguity, duplicate/conflicting lengths)
  before any body read on HTTP/1.1, HTTP/2 and HTTP/3.
- Percent-encoded payload decoding (`%20`, `%27`, `%3C`, ...).
- API-key authentication (`X-API-Key` by default).
- Per-IP and global token-bucket rate limiting, with a hard
  `max_tracked_ips` cap and fail-closed capacity policy.
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

For a minimal configuration and a manual walkthrough (health check and a
verified block), see
[`docs/user-guide/quickstart.md`](docs/user-guide/quickstart.md). For a
one-command run, execute [`scripts/demo.sh`](scripts/demo.sh) — see
[`docs/guides/demo.md`](docs/guides/demo.md).

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

See [`config.toml`](config.toml) for the complete annotated configuration and
[`docs/user-guide/configuration.md`](docs/user-guide/configuration.md) for every
section. Focused examples live in [`config/examples/`](config/examples/):
minimal, Coraza switch-back, native sidecar, gRPC allowlist, GraphQL persisted
queries and high-throughput tuning. Validate edits with:

```bash
./scripts/validate-configs.sh
```

Key sections:

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

[waf.coraza]
# backend = "rust"        # compiled default in default builds
# fallback = "none"       # fail closed; "wasm" re-evaluates with Coraza
# max_inspect_bytes = 0   # 0 = inspect the whole body
# oversize_action = "inspect-all"  # or "reject" / "forward-uninspected"

[security.auth]
enabled = true
api_keys = ["replace-me"]      # prefer injecting from a secret
header_name = "X-API-Key"
require_https = true
```

Unknown keys are hard errors, including misspelled security settings and
`WAF_*` overrides. The loader names the file, section/key path and line before
binding any listener; run the validation script after editing a file.

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

### Request framing and smuggling defenses

Before any request body is read, the proxy validates request framing on
HTTP/1.1, HTTP/2 and HTTP/3. Requests are rejected with a generic `400` when
they contain both `Content-Length` and `Transfer-Encoding`, multiple
`Content-Length` header fields, comma-separated conflicting `Content-Length`
values, a non-numeric or malformed `Content-Length`, or a
`Transfer-Encoding` value other than a single `chunked` token. Rejection
details are logged server-side but never sent to the client.

## Build and test

```bash
nix develop -c cargo fmt -- --check
nix develop -c cargo clippy --lib -- --deny warnings
nix develop -c cargo test --lib
nix develop -c cargo test --test integration
nix develop -c cargo check --all-targets
./scripts/validate-configs.sh
./scripts/demo.sh
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
- Published image: `ghcr.io/shift/waf-rejected-waf:v<version>`, for example:

  ```bash
  docker pull ghcr.io/shift/waf-rejected-waf:v0.1.0-beta.16
  docker run -p 8080:8080 -p 8081:8081 \
    ghcr.io/shift/waf-rejected-waf@sha256:<digest>
  ```

  The `-waf` suffix is deliberate: it is the canonical GHCR package, chosen
  because the repository-named package rejected blob uploads with HTTP 403.
  Tag releases publish it by default; `image-digest.txt` on the release
  records the immutable digest. When registry publishing was disabled or
  rejected, load the attached `waf-rejected-<version>-image.tar.gz` instead.
- Released image tarball, digest pinning, upgrade and rollback:
  [`docs/operations/container.md`](docs/operations/container.md)
- Kubernetes manifests: [`infrastructure/kubernetes`](infrastructure/kubernetes)
- Helm chart: [`infrastructure/helm`](infrastructure/helm)
- Monitoring: [`infrastructure/monitoring`](infrastructure/monitoring)
- Distributed WAF + distri-kv regional cell (compose, Kubernetes, mTLS
  certificates, smoke test): [`deploy/distributed`](deploy/distributed) and
  [`docs/operations/distributed-deployment.md`](docs/operations/distributed-deployment.md)

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

- **The native Rust CRS engine is the default request-inspection backend.**
  Builds with the default features compile `rust-engine` and select
  `waf.coraza.backend = "rust"`. Start-up compiles the pinned OWASP CRS 4.14
  bundle (505/505 rules) into the engine IR once in ~210 ms and the process
  reaches readiness in ~276 ms with ~30 MiB RSS. The engine matches the Coraza
  oracle on 2,110/2,112 corpus cases (the two differences are documented and
  match the corpus labels), executes all 505/505 rules, and fails closed on any
  load or runtime error. End-to-end proxy p50 is 0.414 / 0.642 / 1.091 /
  1.614 ms for bodyless / 1 / 4 / 8 KiB, versus Coraza 4.47 / 40.13 / 169.56 /
  354.09 ms. Those sub-millisecond figures are path claims (bodyless,
  allow-cache, prefilter/fast-allow and the engine request path); the engine's
  own request path is ~566–591 µs at 4 KiB and ~992 µs at 8 KiB. Coraza remains
  the **reference implementation** and can be selected with
  `waf.coraza.backend = "wasm"`; `waf.coraza.fallback = "wasm"` opts into
  re-evaluating a request with Coraza after a Rust-engine runtime error.
  Response inspection is plumbed in the engine but not proxy-wired yet, and
  io_uring/Hyperscan remain opt-in. See
  [`docs/suggestions_from_agents/rust-engine.md`](docs/suggestions_from_agents/rust-engine.md).
- **Body inspection is bounded by policy, not silently truncated.** The wasm
  payload contract is 64 KiB. `waf.coraza.max_inspect_bytes = 0` (default)
  inspects the whole body up to `max_payload_bytes` and fails closed above it;
  `oversize_action = "reject"` returns `413`; `forward-uninspected` leaves an
  explicit tail gap. `waf.admission` bounds concurrent heavy scans and returns
  `503 + Retry-After` when saturated, never a silent allow.
- **Protocol-aware inspection is enabled for gRPC and GraphQL.** gRPC frames
  are structurally validated and withheld from CRS body rules; an empty method
  allowlist is monitor-only. GraphQL defaults to the full CRS JSON scan;
  `graphql-only` is an opt-in coverage trade-off that requires a non-empty
  operation allowlist. See
  [`docs/grpc-inspection.md`](docs/grpc-inspection.md) and
  [`docs/graphql-inspection.md`](docs/graphql-inspection.md).
- **ModSecurity/Coraza WASM execution remains available and unchanged.** The
  bundled `rules/coraza.wasm` is a Go-JS demo module; the live Coraza engine is
  a WASI reactor on wasmtime 49 compiled by the default `wasm-reactor` feature.
  It embeds OWASP CRS 4.14 (request-side, paranoia level 1) and runs before the
  built-in heuristic rules when selected or used as the fallback.
  `waf.coraza.enabled = false` (or `--no-default-features`) disables it.
  Start-up compiles the ~20 MiB module once (~4.5 s) and warms the reactor pool
  (~1.1 s) before readiness. When selected, end-to-end proxy p50 is 4.47 / 40.13
  / 169.56 / 354.09 ms for bodyless / 1 / 4 / 8 KiB bodies on the reference
  host. The reactor is not instantiated when the default Rust engine is selected
  with `fallback = "none"`, so its memory footprint does not apply to the
  default path. See
  [`docs/coraza-wasi-reactor.md`](docs/coraza-wasi-reactor.md) and
  [`docs/wasm-integration-status.md`](docs/wasm-integration-status.md).
- **A native Coraza sidecar profile is available for high-throughput body
  inspection.** It is opt-in (`config/performance-native.toml`, Compose and
  Kubernetes examples under `deploy/`), requires the `coraza-native` feature and
  a sidecar process, and is about 6× faster on body inspection than wasm. It is
  selected explicitly (`waf.coraza.backend = "native"`); the default backend is
  `rust` (or `wasm` in builds without `rust-engine`). See
  [`docs/operations/native-performance-profile.md`](docs/operations/native-performance-profile.md).
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
  HTTP/3 requests reuse the same framing, auth, decompression, WAF and
  response-cap pipeline as HTTP/1.1 and HTTP/2. There is no cap on concurrent
  QUIC connections or streams, and no stateless retry.
- **WebTransport is terminating, not a proxy.** When built with
  `--features webtransport`, it authenticates, inspects and echoes sessions
  locally under Origin/path/session/stream/datagram limits. Application
  WebTransport payloads are **not** forwarded upstream; that bridge is not
  implemented. HTTP/1.1 `Upgrade: webtransport` remains `501`.
- The legacy AI/threat-intelligence modules are experimental and are not on the
  request path by default.

## License

MIT OR Apache-2.0.
