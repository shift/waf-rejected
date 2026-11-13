# Release and tag policy

This note defines how WAF-Rejected tags and publishes releases. The mechanical
release steps remain in [`release-checklist.md`](release-checklist.md).

## Version and tag format

- Release tags use `vMAJOR.MINOR.PATCH`, for example `v0.1.0`.
- Pre-release tags use `vMAJOR.MINOR.PATCH-beta.N`, for example
  `v0.1.0-beta.22`.
- Beta tags are published as GitHub **pre-releases**, never as the latest
  stable release.
- Tags are immutable. Do not move, delete or re-point a published tag. If a
  release is wrong, publish a new tag with a higher version.
- The tag, `Cargo.toml`, `CHANGELOG.md` and the README must name the same
  version before the tag is pushed.

## Signing

- Prefer signed, annotated tags: `git tag -s v0.1.0-beta.22 -m "..."`.
- Verify a tag before trusting it: `git tag -v v0.1.0-beta.22`.
- If the release maintainer has no signing key configured, use an annotated tag
  (`git tag -a`) and state in the release notes that the tag is unsigned. Do not
  use lightweight tags for releases.
- The `release-tags` ruleset blocks deletion and force-updates of `v*` tags.

## Assets and verification

Each release publishes the binary tarball, the Coraza sidecar tarball, the
container image tarball, a CycloneDX SBOM, the standalone reactor module, an
`image-digest.txt` and a `.sha256` file for every asset.

The canonical container package is `ghcr.io/shift/waf-rejected-waf`. It
differs from the repository name (`shift/waf-rejected`) because GHCR rejected
blob uploads for the repository-named package with HTTP 403. Do not rewrite
workflow image names or deployment manifests to `ghcr.io/shift/waf-rejected`;
published digests live under `-waf`.

`image-digest.txt` contains the immutable
`ghcr.io/shift/waf-rejected-waf@sha256:...` reference when the image was
published. If registry publishing was disabled or rejected, it records
`registry: not published`, the local image ID and the tarball fallback.

Verify downloaded assets in this order:

1. Check the checksum: `sha256sum -c <asset>.sha256`.
2. Verify build provenance when an attestation exists:
   `gh attestation verify <asset> --repo shift/waf-rejected`.
3. Run the local verifier:
   `./scripts/verify-release.sh --dir <artifact-dir> --version <version>`.
4. Verify the registry digest when the image was published:
   `./scripts/verify-release.sh --dir <artifact-dir> --version <version> --verify-registry`.

A failed checksum or attestation means the file must not be deployed. Report it
through the private channel in [`SECURITY.md`](../../SECURITY.md).

Releases published by the tag-driven `Release` workflow carry a provenance
attestation. Locally built releases do not; record that fact in the release
notes. Checksums and `scripts/verify-release.sh` still apply. See
[`ci.md`](ci.md) for triggers, GHCR publishing and fallbacks.
