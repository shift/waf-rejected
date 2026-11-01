# Running the Container Image

This guide covers loading a released WAF-Rejected image tarball, running it,
pinning by digest, exposing health and metrics, and upgrading or rolling back.

The image is a Debian slim runtime with the `waf-ingress` binary, the bundled
`rules/` directory and `/etc/waf/config.toml`. It runs as UID/GID `1000` with
`/var/lib/waf` as the working directory.

## Image reference

| Item | Value |
|---|---|
| Registry image | `ghcr.io/shift/waf-rejected` |
| Tag convention | `v<version>`, for example `v0.1.0-beta.6` |
| Tarball convention | `waf-rejected-<version>-image.tar.gz` |
| Checksum asset | `waf-rejected-<version>-image.tar.gz.sha256` |
| Proxy port | `8080` (`bind_addr`) |
| Health/metrics port | `8081` (`health_bind_addr`) |
| Config path | `/etc/waf/config.toml` |
| Coraza reactor | `/usr/share/waf/wasm/coraza_reactor.wasm` |
| Reactor licence/provenance | `/usr/share/waf/wasm/LICENSE-CRS`, `/usr/share/waf/wasm/PROVENANCE.md`, `/usr/share/waf/wasm/SHA256SUMS` |
| Data and logs | `/var/lib/waf/data`, `/var/lib/waf/logs` |
| User | `1000` |

Tags are mutable; a digest is not. Pin by digest for anything that matters.

Every tagged release publishes the image tarball, the binary tarball and the
CycloneDX SBOM, each with a matching `<asset>.sha256` checksum file and a GitHub
build provenance attestation.

## Load the released tarball

```bash
# Verify the asset against the checksum published with the release
sha256sum --check waf-rejected-0.1.0-beta.6-image.tar.gz.sha256

# Verify the tarball was built by this repository's Release workflow
gh attestation verify waf-rejected-0.1.0-beta.6-image.tar.gz --repo shift/waf-rejected

docker load -i waf-rejected-0.1.0-beta.6-image.tar.gz
# Loaded image: ghcr.io/shift/waf-rejected:v0.1.0-beta.6
```

The provenance attestation is published for the image tarball, the binary
tarball and the CycloneDX SBOM. `gh attestation verify` exits non-zero if the
file does not match the signed attestation, which is a stronger check than the
checksum alone: it binds the bytes to a specific workflow run and commit.

Use the asset name shown on the release page if it differs from the convention
above. Podman uses the same archive:

```bash
podman load -i waf-rejected-0.1.0-beta.6-image.tar.gz
```

Alternatively pull from the registry:

```bash
docker pull ghcr.io/shift/waf-rejected:v0.1.0-beta.6
```

If the release notes list a digest, confirm the loaded image matches it:

```bash
docker image inspect --format '{{index .RepoDigests 0}}' \
  ghcr.io/shift/waf-rejected:v0.1.0-beta.6
```

An image loaded from a local tarball may not carry a `RepoDigests` entry until
it has been pulled or pushed. In that case compare the image ID in the release
notes, or verify the tarball against its published `.sha256` file, instead.

## Run it

```bash
docker run -d --name waf-rejected \
  -p 8080:8080 \
  -p 8081:8081 \
  -e WAF_UPSTREAM_URI=http://backend:3000 \
  -v "$PWD/config.toml:/etc/waf/config.toml:ro" \
  -v waf-data:/var/lib/waf \
  ghcr.io/shift/waf-rejected@sha256:<digest>
```

Notes:

- `WAF_CONFIG_FILE` already defaults to `/etc/waf/config.toml`. Any `WAF_*`
  environment variable overrides the file, using `__` for nesting, for example
  `WAF_SERVER__MAX_BODY_SIZE=10485760`.
- The bundled `config.docker.toml` has **authentication disabled**. Enable
  `security.auth` with keys injected from a secret before exposing the proxy.
- Mount the config read-only. The container needs write access only to
  `/var/lib/waf` for the Sled event store and CEF log file.
- Do not publish `8081` to untrusted networks. It exposes health and Prometheus
  metrics, not just liveness.
- `SIGTERM` triggers graceful shutdown, so use `docker stop` rather than
  `docker kill`.

### Coraza reactor artifact

The image bundles the Coraza WASI reactor at
`/usr/share/waf/wasm/coraza_reactor.wasm`, with `LICENSE-CRS`,
`PROVENANCE.md` and `SHA256SUMS` in the same directory. The image build
enables the default `wasm-reactor` feature explicitly, verifies the digest and
checks that the module is at most 32 MiB (the current build is about 18 MiB).

The reactor is enabled by default and validates the module at startup, failing
closed if it is missing, malformed, over budget, missing required exports or
fails pool warm-up. Start-up pays about 4.5 s to compile the module and about
1.1 s to warm the pool before readiness; steady-state cost is about 8–10 ms
p50 per request with the full CRS. Set `waf.coraza.enabled = false` in the
configuration file/environment to skip validation and warm-up entirely.
`waf.coraza.module_path` selects an alternate module file;
the embedded module is used when it is unset.

```bash
docker run --rm --entrypoint sha256sum \
  ghcr.io/shift/waf-rejected@sha256:<digest> \
  /usr/share/waf/wasm/coraza_reactor.wasm
```

Compare the digest with the release asset, `wasm/coraza_reactor/SHA256SUMS`
and the CycloneDX SBOM component named `coraza_reactor.wasm`.

Verify:

```bash
curl -fsS http://127.0.0.1:8081/health
curl -fsS http://127.0.0.1:8081/health/ready
curl -fsS http://127.0.0.1:8081/metrics | head
curl -o /dev/null -w '%{http_code}\n' \
  'http://127.0.0.1:8080/?id=1%20UNION%20SELECT%201'   # expect 403
```

## Pin by digest

```bash
docker pull ghcr.io/shift/waf-rejected:v0.1.0-beta.6
docker image inspect --format '{{index .RepoDigests 0}}' \
  ghcr.io/shift/waf-rejected:v0.1.0-beta.6
# ghcr.io/shift/waf-rejected@sha256:...
```

Use the resulting `@sha256:` reference in Compose, Kubernetes, Helm values or
systemd units. Digest pinning is what makes a rollback deterministic and what
lets an SBOM or advisory refer to exactly one artifact.

If you publish a re-tagged copy into your own registry, keep the digest
reference in your deployment manifest and record the upstream digest in your
change ticket.

## Health and metrics

| Endpoint | Port | Purpose |
|---|---|---|
| `GET /health` | 8081 | JSON health status |
| `GET /health/ready` (alias `/ready`) | 8081 | Readiness probe |
| `GET /metrics` | 8081 | Prometheus metrics |
| everything else | 8080 | Inspected and forwarded upstream |

Docker health check:

```bash
--health-cmd 'curl -fsS http://127.0.0.1:8081/health/ready || exit 1' \
--health-interval 15s --health-timeout 3s --health-retries 3
```

Kubernetes probes use the same paths on container port `8081`; the proxy
Service should expose only `8080`.

## Upgrade

1. Read the release notes and `CHANGELOG.md` for configuration or on-disk
   changes. Check the support matrix in
   [`support-policy.md`](support-policy.md).
2. Pull the new digest and confirm the SBOM attached to the release lists the
   dependency changes you expect. Verify the release assets with
   `sha256sum --check *.sha256` before loading or deploying them.
3. Start the new container alongside the old one if your load balancer allows
   it, or drain the old one first: remove it from the upstream pool, then
   `docker stop waf-rejected` and wait for graceful shutdown.
4. Start the new container with the same config and volume, then check
   `/health/ready` and the block-rate metrics before restoring traffic.
5. Record the new digest in your inventory.

```bash
docker pull ghcr.io/shift/waf-rejected:v0.1.0-beta.7
docker stop waf-rejected && docker rm waf-rejected
docker run -d --name waf-rejected ... ghcr.io/shift/waf-rejected@sha256:<new-digest>
```

## Rollback

Rollback is the same procedure with the previous digest:

```bash
docker stop waf-rejected && docker rm waf-rejected
docker run -d --name waf-rejected ... ghcr.io/shift/waf-rejected@sha256:<previous-digest>
```

- The Sled event store is forward compatible within a supported line. If a
  release notes a store format change, keep a copy of `/var/lib/waf/data` before
  upgrading so that rollback can restore it.
- Rollback is supported while the previous release is inside its support
  window. See [`support-policy.md`](support-policy.md).
- After a rollback caused by a security issue, keep the advisory open and
  re-test the fixed digest before retrying the upgrade.

## Related documents

- [Deployment](deployment.md)
- [Monitoring](monitoring.md)
- [Backup and recovery](backup-recovery.md)
- [Support policy](support-policy.md)
- [Security policy](../../SECURITY.md)
