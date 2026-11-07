# Quick Start

This guide takes you from a checkout to a running WAF-Rejected proxy with the
default native Rust CRS engine, then verifies health and a block.

**Prerequisites:** Nix (recommended) or a Rust toolchain. The examples assume
the repository root as the working directory.

## 1. Build

```bash
nix build .#waf-ingress
./result/bin/waf-ingress --version
```

For development, use the pinned toolchain instead:

```bash
nix develop
cargo build --bin waf-ingress
```

## 2. Start an upstream

Any HTTP service works. For a throwaway local check without dependencies:

```bash
mkdir -p /tmp/opencode/waf-quickstart
cd /tmp/opencode/waf-quickstart
printf 'ok\n' > index.html
python3 -m http.server 3000 --bind 127.0.0.1
```

Or use [`scripts/demo.sh`](../guides/demo.md), which starts a mock upstream and
the WAF on throwaway ports for you.

## 3. Minimal configuration

[`config/examples/minimal.toml`](../../config/examples/minimal.toml) is the
smallest useful configuration. The important lines are:

```toml
bind_addr = "0.0.0.0:8080"
health_bind_addr = "0.0.0.0:8081"
upstream_uri = "http://127.0.0.1:3000"

[waf]
enabled = true
fail_mode = "closed"

[waf.content_inspection]
enabled = true
inspect_headers = true
inspect_body = true
```

No `[waf.coraza]` block is needed: a default build compiles the `rust-engine`
feature and selects `waf.coraza.backend = "rust"`. See
[engine selection](engine-selection.md) for the Coraza and native sidecar
alternatives, and [configuration](configuration.md) for every section.

## 4. Run

From the repository root:

```bash
WAF_CONFIG_FILE=config/examples/minimal.toml ./result/bin/waf-ingress
```

The process logs the selected backend, the compiled CRS rule count and the
listener addresses, then becomes ready. Configuration errors are fatal; the
server never silently falls back to built-in defaults when a file is
configured.

## 5. Verify health

```bash
curl -fsS http://127.0.0.1:8081/health
curl -fsS http://127.0.0.1:8081/health/ready
curl -fsS http://127.0.0.1:8081/metrics | head
```

`/health` is liveness, `/health/ready` is readiness and `/metrics` is
Prometheus text. Bind the health listener to a private interface or protect it
with network policy; it is not meant for untrusted clients.

## 6. Verify a benign request and a block

```bash
# Benign: forwarded to the upstream
curl -i http://127.0.0.1:8080/

# SQL injection in the query string: 403
curl -o /dev/null -w '%{http_code}\n' \
  'http://127.0.0.1:8080/?id=1%20UNION%20SELECT%20*%20FROM%20users'

# XSS in the body: 403
curl -o /dev/null -w '%{http_code}\n' \
  -X POST --data '<script>alert(1)</script>' http://127.0.0.1:8080/login
```

A block is logged to the console as a security event and counted in the
`/metrics` block counter. The response body is intentionally generic.

## 7. Stop

Send `SIGTERM` (or `Ctrl+C`) for a graceful shutdown:

```bash
kill -TERM <pid>
```

## Next steps

- [Configuration reference](configuration.md) — every section, default and
  security trade-off.
- [Engine selection](engine-selection.md) — Rust vs Coraza wasm vs native
  sidecar, switch-back and fallback semantics.
- [Runnable demo](../guides/demo.md) — benign, SQLi, XSS and gRPC requests.
- [Container image](../operations/container.md) — run the released image.
- [Production deployment](../operations/deployment.md) — Kubernetes and Helm.
- [Support matrix](../operations/support-matrix.md) — measured performance and
  known limitations.
