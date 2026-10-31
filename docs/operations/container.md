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
| Tarball convention | `waf-rejected-<version>-image.tar` |
| Proxy port | `8080` (`bind_addr`) |
| Health/metrics port | `8081` (`health_bind_addr`) |
| Config path | `/etc/waf/config.toml` |
| Data and logs | `/var/lib/waf/data`, `/var/lib/waf/logs` |
| User | `1000` |

Tags are mutable; a digest is not. Pin by digest for anything that matters.

## Load the released tarball

```bash
# Compare against the checksum or digest published with the release
sha256sum waf-rejected-0.1.0-beta.6-image.tar

docker load -i waf-rejected-0.1.0-beta.6-image.tar
# Loaded image: ghcr.io/shift/waf-rejected:v0.1.0-beta.6
```

Use the asset name shown on the release page if it differs from the convention
above. Podman uses the same archive:

```bash
podman load -i waf-rejected-0.1.0-beta.6-image.tar
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
notes, or the `sha256` of the tarball, instead.

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
   dependency changes you expect.
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
