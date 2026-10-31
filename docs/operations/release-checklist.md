# Release Checklist

## Beta 0.1.0-beta.3

### Verification

- [ ] `cargo fmt -- --check`
- [ ] `cargo clippy --lib -- --deny warnings`
- [ ] `cargo check --all-targets`
- [ ] `cargo test --lib`
- [ ] `cargo test --test integration`
- [ ] `nix build .#waf-ingress`
- [ ] Container image starts and answers `/health` on port 8081

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
- [ ] Tag `v0.1.0-beta.3`.
- [ ] Push branch and tag.
- [ ] Confirm the Release workflow built and attached every asset:
      - `waf-rejected-v<version>-x86_64-linux.tar.gz` (binary tarball)
      - `waf-rejected-<version>-image.tar.gz` (prebuilt container image)
      - `waf-rejected-<version>.cdx.json` (CycloneDX SBOM)
      - `<asset>.sha256` for each of the three assets above
- [ ] Confirm the image is still pushed to GHCR under `v<version>`.
- [ ] Download the assets and verify them: `sha256sum --check *.sha256`.
- [ ] Publish the GitHub pre-release with the known-limitations section from
      `CHANGELOG.md`.
