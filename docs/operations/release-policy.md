# Release and tag policy

This note defines how WAF-Rejected tags and publishes releases. The mechanical
release steps remain in [`release-checklist.md`](release-checklist.md).

## Version and tag format

- Release tags use `vMAJOR.MINOR.PATCH`, for example `v0.1.0`.
- Pre-release tags use `vMAJOR.MINOR.PATCH-beta.N`, for example
  `v0.1.0-beta.13`.
- Beta tags are published as GitHub **pre-releases**, never as the latest
  stable release.
- Tags are immutable. Do not move, delete or re-point a published tag. If a
  release is wrong, publish a new tag with a higher version.
- The tag, `Cargo.toml`, `CHANGELOG.md` and the README must name the same
  version before the tag is pushed.

## Signing

- Prefer signed, annotated tags: `git tag -s v0.1.0-beta.13 -m "..."`.
- Verify a tag before trusting it: `git tag -v v0.1.0-beta.13`.
- If the release maintainer has no signing key configured, use an annotated tag
  (`git tag -a`) and state in the release notes that the tag is unsigned. Do not
  use lightweight tags for releases.
- The `release-tags` ruleset blocks deletion and force-updates of `v*` tags.

## Assets and verification

Each release publishes the binary tarball, the Coraza sidecar tarball, the
container image tarball, the CycloneDX SBOM, the standalone reactor module and
a `.sha256` file for every asset.

Verify downloaded assets in this order:

1. Check the checksum: `sha256sum -c <asset>.sha256`.
2. Verify build provenance when an attestation exists:
   `gh attestation verify <asset> --repo shift/waf-rejected`.
3. Run the local verifier:
   `./scripts/verify-release.sh --dir <artifact-dir> --version <version>`.

A failed checksum or attestation means the file must not be deployed. Report it
through the private channel in [`SECURITY.md`](../../SECURITY.md).

While GitHub Actions is billing-blocked, releases are built locally and have no
provenance attestation. Record that fact in the release notes; checksums and
`scripts/verify-release.sh` still apply.
