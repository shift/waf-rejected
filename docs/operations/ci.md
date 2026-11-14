# CI and GitHub Actions

This page describes the workflows in `.github/workflows/`, when they run, the
credentials they consume, and the fallbacks used when a credential or registry
capability is unavailable. The local equivalents live in `scripts/ci-local.sh`,
`scripts/ci-feature-matrix.sh` and `scripts/check-coraza-reactor-size.sh`.

All workflow files are checked with
[actionlint](https://github.com/rhysd/actionlint):

```bash
nix shell nixpkgs#actionlint -c actionlint .github/workflows/*.yml
```

## Workflow summary

| Workflow | Trigger | Jobs | Write permissions |
| --- | --- | --- | --- |
| `release.yml` | Push of a `v*` tag | `build-image`, `sbom`, `trivy-filesystem`, `trivy-image`, `build-release` | `contents: write` (release), `packages: write` (image), `security-events: write` (SARIF), `id-token`/`attestations` (provenance) |
| `publish-image.yml` | Manual dispatch with a release tag | `publish` | `packages: write` (image) |
| `production-deployment.yml` | Push and pull request to `main` or `production` | `security-scan`, `test`, `build-image`, `preflight`, `deploy-staging`, `deploy-production`, `rollback` | `security-events: write` (SARIF), `packages: write` (image) |
| `feature-matrix.yml` | Push/PR to `main` for Rust and rule paths; manual dispatch | `fmt-clippy`, `lib-tests`, `compile`, optional corpus/engine jobs | None |
| CodeQL | GitHub default code scanning setup | Managed by GitHub | Managed by GitHub |

Pull requests from forks do not receive repository secrets, so the deployment
jobs skip rather than fail.

## Release workflow

`release.yml` is tag-driven; it has no `workflow_dispatch` input because the
version is derived from `GITHUB_REF_NAME`. A release is re-run with
`gh run rerun <run-id>` or by tagging a new version. Do not move an existing
tag.

The jobs produce:

- `build-image` — builds the container image, exports a loadable
  `waf-rejected-<version>-image.tar.gz`, pushes the canonical
  `ghcr.io/shift/waf-rejected-waf` package by default, and records the
  resulting digest in `image-digest.txt`.
- `sbom` — installs Nix and runs `scripts/generate-sbom.sh` inside
  `nix develop`, then uploads the CycloneDX SBOM and its checksum.
- `trivy-filesystem` — scans the checkout and dependency manifests.
- `trivy-image` — scans the image tarball produced by `build-image`.
- `build-release` — builds the binary and Coraza sidecar with Nix, packages
  every asset with a `.sha256`, attests build provenance, and publishes the
  GitHub pre-release.

### GHCR publishing

Tag releases publish `ghcr.io/shift/waf-rejected-waf` by default, with both
the release tag (`v<version>`) and `sha-<commit>` tags. This canonical package
name is deliberately **not** `ghcr.io/shift/waf-rejected`: the
repository-named package rejected blob uploads with HTTP 403, while the `-waf`
package accepts the same image. Keep `-waf` in every workflow, script and
deployment manifest.

Set `PUSH_IMAGE=false` to disable registry publishing:

```bash
# Disable publishing (the image tarball remains a release asset).
gh variable set PUSH_IMAGE --body false --repo shift/waf-rejected

# Re-enable it (the default).
gh variable delete PUSH_IMAGE --repo shift/waf-rejected
```

When `PUSH_IMAGE=false`:

- the GHCR login and push steps are skipped;
- the image is still built and exported;
- `waf-rejected-<version>-image.tar.gz` is attached to the release and covered
  by the provenance attestation and checksums;
- `image-digest.txt` records `registry: not published` and the local image ID.

The push treats a rejected upload as a warning. A missing package-write
capability or an organization policy that returns HTTP 403 therefore cannot
block the release: the tarball is still attached. Inspect the run log for the
`GHCR rejected the image push` warning and fix the credential before expecting
the image in the registry.

On success, `build-image` writes the immutable
`ghcr.io/shift/waf-rejected-waf@sha256:...` reference to `image-digest.txt`,
uploads it as the `image-digest` artifact, and `build-release` attaches it to
the release and appends it to the release body. The tarball remains the
supported fallback: `docker load`/`podman load` it as described in
[`container.md`](container.md#load-the-released-tarball). Verify a published
digest with:

```bash
./scripts/verify-release.sh --dir .release-assets --version <version> \
  --verify-registry
```

### Manual image publish

`publish-image.yml` is a `workflow_dispatch` fallback for re-publishing an
existing release tag without re-running the whole release. It builds the same
Dockerfile and pushes the same canonical package and tags
(`ghcr.io/shift/waf-rejected-waf:<tag>` and `:sha-<commit>`). It does not
modify release assets or `image-digest.txt`.

### Vulnerability policy

Trivy reports `HIGH` and `CRITICAL` findings as SARIF in the code-scanning
dashboard with separate `trivy-filesystem` and `trivy-image` categories.
`ignore-unfixed: true` means only a finding with an upstream fix available
fails the scan job and blocks `build-release`. Unfixed advisories are still
visible in the dashboard and must be triaged; they are recorded in
[`supply-chain.md`](supply-chain.md). If the scan is not actionable, fix the
dependency or document the accepted risk rather than disabling the job.

## Production deployment pipeline

`production-deployment.yml` runs on every push and pull request to `main` or
`production`.

- `security-scan` runs `cargo audit`, `cargo deny check` and a Trivy
  filesystem scan. The Trivy SARIF upload requires
  `permissions: security-events: write`; the job requests it explicitly.
- `test` runs formatting, clippy, the Nix build, all-target compile checks,
  library tests and integration tests.
- `build-image` builds the image on every trigger. It pushes to GHCR only on
  a non-pull-request event when `PUSH_IMAGE=true`; pull requests only build.
- `preflight` checks whether the kubeconfig secrets exist and publishes
  `staging_configured`/`production_configured` job outputs.
- `deploy-staging`, `deploy-production` and `rollback` consume those outputs.
  Missing credentials make the job **skip** instead of failing.

GitHub does not expose the `secrets` context to `jobs.<job_id>.if`, so a
direct `if: ${{ secrets.STAGING_KUBE_CONFIG != '' }}` is not valid. The
`preflight` job performs the check in a step (where secrets are available) and
the deploy jobs gate on its outputs. Configure the kubeconfigs as **repository
or organization secrets**; environment-scoped secrets are only visible to jobs
that declare the environment and would not be seen by `preflight`.

| Name | Kind | Required by | Purpose |
| --- | --- | --- | --- |
| `STAGING_KUBE_CONFIG` | Secret (optional) | `deploy-staging` | Base64-encoded kubeconfig for the staging cluster; missing means the job skips |
| `PRODUCTION_KUBE_CONFIG` | Secret (optional) | `deploy-production`, `rollback` | Base64-encoded kubeconfig for the production cluster; missing means the jobs skip |
| `CACHIX_AUTH_TOKEN` | Secret (optional) | `test` | Push access to the `waf-rejected` Cachix cache. Missing means the build uses the default Nix substituters only |
| `PUSH_IMAGE` | Repository variable (optional) | `build-image` | Tag releases publish by default; set to `false` to disable. Snapshot publishing stays opt-in with `true` |

No secret is required for the pipeline to pass: `security-scan`, `test` and
`build-image` always run. The only mandatory capability is the default
`GITHUB_TOKEN` (`contents: read`), which every workflow receives.

### Optional Cachix cache

`test` installs Nix unconditionally with `cachix/install-nix-action` and then
runs `cachix/cachix-action` only when the token exists. Because GitHub does not
expose `secrets` to a step-level `if`, `preflight` publishes
`cachix_configured`; the cache step is gated on that output and marked
`continue-on-error` so an unreachable or non-writable cache cannot fail the
build. With no token the job runs plain `nix build`/`nix develop` against the
public substituters — slower on a cold cache, but functionally identical.

The deploy jobs also reference the `staging` and `production` GitHub
environments, so environment protection rules (required reviewers, wait
timers) still apply when the jobs run.

## Feature matrix

`feature-matrix.yml` guards feature-combination regressions (default features,
`wasm-reactor`, `coraza-native`, `http3`, `webtransport`,
`ai-threat-detection`, and no-default-features). It runs on push/PR to `main`
when Rust sources, tests, benchmarks, Cargo manifests, the flake or the
workflow itself change. The optional CRS corpus and engine-guarantee jobs are
manual `workflow_dispatch` inputs.

## Troubleshooting

| Symptom | Cause and action |
| --- | --- |
| GHCR push returns `403 Forbidden` | The token cannot write packages, or organization policy blocks it. The release continues with the image tarball and `image-digest.txt` marking the fallback; fix the package write credential before the next tag. Do not switch back to `ghcr.io/shift/waf-rejected`, which rejects blob uploads. |
| `sbom` fails with `nix: command not found` | The job installs Nix with `cachix/install-nix-action`. Check that the action step was not skipped. |
| SARIF upload fails with `Resource not accessible by integration` | The job is missing `security-events: write`, or code scanning is disabled for the repository. |
| Deploy jobs report "skipped" | `preflight` did not find the matching repository/organization kubeconfig secret. Add it, or accept that deployment is disabled. |
| `test` logs "CACHIX_AUTH_TOKEN is not configured" | Expected on forks and unconfigured repositories. The build continues with public substituters; add the secret to speed it up. |
| Security scan produces SARIF but the upload is skipped | `upload-sarif` runs with `if: always()`; the job still needs `security-events: write`, which it declares, and code scanning must be enabled. |
| Trivy blocks a release | At least one fixable `HIGH`/`CRITICAL` finding exists. Upgrade or remove the dependency; unfixed findings do not block. |

Release and production workflows intentionally have no `workflow_dispatch`
trigger. To exercise them, merge the change to the public repository, then
push a test tag (`Release`) or push to `main` (`Production Deployment
Pipeline`); use `gh run rerun` for an existing run.