# Release Checklist

## Beta 0.1.0-beta.9

### Verification

- [ ] `./scripts/ci-local.sh` (or `just ci-local`) passes locally
- [ ] `cargo fmt -- --check`
- [ ] `cargo clippy --lib -- --deny warnings`
- [ ] `cargo check --all-targets`
- [ ] `cargo test --lib`
- [ ] `cargo test --test integration`
- [ ] `nix build .#waf-ingress`
- [ ] Container image starts and answers `/health` on port 8081

### Verify provenance

Every tagged release publishes a GitHub build provenance attestation
(`actions/attest-build-provenance`) for the binary tarball, the image tarball
and the CycloneDX SBOM. The attestation is signed by the Release workflow's
OIDC identity, so it proves which workflow, commit and repository produced the
bytes you downloaded.

```bash
gh attestation verify waf-rejected-v<version>-x86_64-linux.tar.gz --repo shift/waf-rejected
gh attestation verify waf-rejected-<version>-image.tar.gz --repo shift/waf-rejected
gh attestation verify waf-rejected-<version>.cdx.json --repo shift/waf-rejected
```

A passing check prints the workflow, the source commit and the signer identity.
Checksums and attestations are complementary: the `.sha256` file detects
corruption, the attestation binds the artifact to this repository's release
pipeline.

### Smoke test

```bash
WAF_CONFIG_FILE=config.toml ./result/bin/waf-ingress
curl -f http://127.0.0.1:8081/health
curl -f http://127.0.0.1:8081/metrics
curl -o /dev/null -w '%{http_code}\n' 'http://127.0.0.1:8080/?id=1%20UNION%20SELECT%201'  # 403
curl -o /dev/null -w '%{http_code}\n' -X POST --data '<script>alert(1)</script>' http://127.0.0.1:8080/  # 403
```

### Publishing

- [ ] Commit release version and changelog.
- [ ] Tag `v0.1.0-beta.9`.
- [ ] Push branch and tag.
- [ ] Confirm the Release workflow built and attached every asset:
      - `waf-rejected-v<version>-x86_64-linux.tar.gz` (binary tarball)
      - `waf-rejected-<version>-image.tar.gz` (prebuilt container image)
      - `waf-rejected-<version>.cdx.json` (CycloneDX SBOM)
      - `<asset>.sha256` for each of the three assets above
- [ ] Confirm the image is still pushed to GHCR under `v<version>`.
- [ ] Download the assets and verify them: `sha256sum --check *.sha256`.
- [ ] Verify build provenance for each asset:
      `gh attestation verify <asset> --repo shift/waf-rejected`.
- [ ] Publish the GitHub pre-release with the known-limitations section from
      `CHANGELOG.md`.
