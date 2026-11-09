# Running the Container Image

This guide covers loading a released WAF-Rejected image tarball, running it,
pinning by digest, exposing health and metrics, and upgrading or rolling back.

The image is a Debian slim runtime with the `waf-ingress` binary, the bundled
`rules/` directory and `/etc/waf/config.toml`. It runs as UID/GID `1000` with
`/var/lib/waf` as the working directory.

## Image reference

| Item | Value |
|---|---|
| Registry image | `ghcr.io/shift/waf-rejected-waf` |
| Tag convention | `v<version>`, for example `v0.1.0-beta.18` |
| Additional tag | `sha-<commit>` (same manifest as the release tag) |
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

The canonical package is `ghcr.io/shift/waf-rejected-waf`, not
`ghcr.io/shift/waf-rejected`. Publishing under the repository-named package
failed with HTTP 403 on blob upload, while the `-waf` package accepts the same
image. The package name is therefore a deliberate exception to the usual
`ghcr.io/<owner>/<repository>` convention; keep using `-waf` even though the
repository is `shift/waf-rejected`.

Every tagged release publishes the image tarball, the binary tarball, the
CycloneDX SBOM and `image-digest.txt`, each with a matching `<asset>.sha256`
checksum file. Releases built by the GitHub Release workflow also carry a
build provenance attestation.

## Registry publishing

The Release workflow publishes the image to GHCR by default on tag releases.
Set the repository variable `PUSH_IMAGE=false` to disable it; see
[`ci.md`](ci.md#ghcr-publishing). When the registry accepts the push, the
immutable `ghcr.io/shift/waf-rejected-waf@sha256:...` reference is recorded in
`image-digest.txt` and appended to the release body. If registry publishing is
disabled or the push is rejected (for example the workflow token lacks package
write access and GHCR returns HTTP 403), the image tarball attached to the
release is the supported fallback: load it with `docker load` or `podman load`
as shown below.

The same image can be built and pushed manually from a machine with registry
credentials:

```bash
VERSION=0.1.0-beta.18
IMAGE=ghcr.io/shift/waf-rejected-waf

# Build the same image as the Release workflow.
podman build -t "${IMAGE}:v${VERSION}" .
# or: docker build -t "${IMAGE}:v${VERSION}" .

# Authenticate with a token that has write:packages for the repository.
podman login ghcr.io
# or: docker login ghcr.io

podman push "${IMAGE}:v${VERSION}"
# or: docker push "${IMAGE}:v${VERSION}"

# Record the immutable digest in the release notes.
podman image inspect --format '{{index .RepoDigests 0}}' "${IMAGE}:v${VERSION}"
# or: docker image inspect --format '{{index .RepoDigests 0}}' "${IMAGE}:v${VERSION}"
```

If the registry is unavailable, export the image and attach it to the release
instead:

```bash
podman save "${IMAGE}:v${VERSION}" | gzip -9 > "waf-rejected-${VERSION}-image.tar.gz"
# or: docker save "${IMAGE}:v${VERSION}" | gzip -9 > "waf-rejected-${VERSION}-image.tar.gz"
sha256sum "waf-rejected-${VERSION}-image.tar.gz" > "waf-rejected-${VERSION}-image.tar.gz.sha256"
```

The tarball is a complete, loadable image; consumers do not need GHCR access.
`scripts/verify-release.sh` validates the tarball's gzip stream and Docker
manifest, and `--deep-image` also checks the reactor digest inside the image.

## Load the released tarball

```bash
# Verify the asset against the checksum published with the release
sha256sum --check waf-rejected-0.1.0-beta.18-image.tar.gz.sha256

# Verify the tarball was built by this repository's Release workflow
gh attestation verify waf-rejected-0.1.0-beta.18-image.tar.gz --repo shift/waf-rejected

docker load -i waf-rejected-0.1.0-beta.18-image.tar.gz
# Loaded image: ghcr.io/shift/waf-rejected-waf:v0.1.0-beta.18
```

The provenance attestation is published for the image tarball, the binary
tarball and the CycloneDX SBOM. `gh attestation verify` exits non-zero if the
file does not match the signed attestation, which is a stronger check than the
checksum alone: it binds the bytes to a specific workflow run and commit.

Use the asset name shown on the release page if it differs from the convention
above. Podman uses the same archive:

```bash
podman load -i waf-rejected-0.1.0-beta.18-image.tar.gz
```

Alternatively pull from the registry (see
[Registry publishing](#registry-publishing)):

```bash
docker pull ghcr.io/shift/waf-rejected-waf:v0.1.0-beta.18
```

The release attaches `image-digest.txt`. When the image was published, it
contains the immutable `ghcr.io/shift/waf-rejected-waf@sha256:...` reference;
confirm the pulled or loaded image matches it:

```bash
docker image inspect --format '{{index .RepoDigests 0}}' \
  ghcr.io/shift/waf-rejected-waf:v0.1.0-beta.18

# Or check the registry reference directly.
./scripts/verify-release.sh --dir . --version 0.1.0-beta.18 --verify-registry
```

An image loaded from a local tarball may not carry a `RepoDigests` entry until
it has been pulled or pushed. If `image-digest.txt` records
`registry: not published`, use the local image ID and the tarball checksum
instead.

## Run it

```bash
docker run -d --name waf-rejected \
  -p 8080:8080 \
  -p 8081:8081 \
  -e WAF_UPSTREAM_URI=http://backend:3000 \
  -v "$PWD/config.toml:/etc/waf/config.toml:ro" \
  -v waf-data:/var/lib/waf \
  ghcr.io/shift/waf-rejected-waf@sha256:<digest>
```

Notes:

- `WAF_CONFIG_FILE` already defaults to `/etc/waf/config.toml`. Known `WAF_*`
  environment variables override the file, using `__` for nesting, for example
  `WAF_SERVER__MAX_BODY_SIZE=10485760` or
  `WAF_WAF__CORAZA__BACKEND=wasm`. Unknown keys are rejected at start-up.
- The default backend is the native Rust CRS engine. Select the Coraza reference
  reactor with `WAF_WAF__CORAZA__BACKEND=wasm` or the opt-in sidecar with
  `"native"`; see [engine selection](../user-guide/engine-selection.md).
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

The request-inspection backend is the native Rust CRS engine
(`waf.coraza.backend = "rust"`) in the default image. With the default
`fallback = "none"`, the wasm reactor is **not instantiated**, so start-up is
~276 ms with ~30 MiB RSS and the ~801 MiB reactor footprint does not apply.

The reactor remains available as the reference implementation and explicit
switch-back. Set `[waf.coraza] backend = "wasm"` to select it. When selected,
start-up pays about 4.5 s to compile the module and about 1.1 s to warm the
pool before readiness, and end-to-end proxy p50 is 4.47 / 40.13 / 169.56 /
354.09 ms for bodyless / 1 / 4 / 8 KiB bodies on the reference host.
`waf.coraza.module_path` selects an alternate module file; the embedded module
is used when it is unset. `waf.coraza.enabled = false` disables request
inspection entirely. See
[engine selection](../user-guide/engine-selection.md).

```bash
docker run --rm --entrypoint sha256sum \
  ghcr.io/shift/waf-rejected-waf@sha256:<digest> \
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
docker pull ghcr.io/shift/waf-rejected-waf:v0.1.0-beta.18
docker image inspect --format '{{index .RepoDigests 0}}' \
  ghcr.io/shift/waf-rejected-waf:v0.1.0-beta.18
# ghcr.io/shift/waf-rejected-waf@sha256:...
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
docker pull ghcr.io/shift/waf-rejected-waf:v0.1.0-beta.18
docker stop waf-rejected && docker rm waf-rejected
docker run -d --name waf-rejected ... ghcr.io/shift/waf-rejected-waf@sha256:<new-digest>
```

## Rollback

Rollback is the same procedure with the previous digest:

```bash
docker stop waf-rejected && docker rm waf-rejected
docker run -d --name waf-rejected ... ghcr.io/shift/waf-rejected-waf@sha256:<previous-digest>
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
