# Release Checklist

Tag naming, signing and asset-verification rules are in
[`release-policy.md`](release-policy.md).

## Beta 0.1.0-beta.21

### Verification

- [ ] `./scripts/ci-local.sh` (or `just ci-local`) passes locally
- [ ] `cargo fmt -- --check`
- [ ] `cargo clippy --lib -- --deny warnings`
- [ ] `cargo clippy --lib --features wasm-reactor,coraza-native -- --deny warnings`
- [ ] `cargo check --all-targets`
- [ ] `cargo test --lib`
- [ ] `cargo test --test integration`
- [ ] `./scripts/validate-configs.sh` passes (loads every `config/*.toml`,
      `config/examples/*.toml`, `config.toml`, `config.docker.toml`, the root
      test configs and `deploy/compose/config.native.toml` through
      `Config::load`; unknown keys are hard errors with file/key locations)
- [ ] `./scripts/demo.sh` passes (benign 200, SQLi/XSS 403, gRPC forwarded)
- [ ] `nix build .#waf-ingress`
- [ ] `nix build .#coraza-native-sidecar`
- [ ] `./scripts/run-native-profile.sh` passes (benign 200, SQLi/XSS 403,
      gRPC 200) and the sidecar `--probe` readiness check works
- [ ] `./scripts/check-coraza-reactor-size.sh` passes (digest matches and the
      module is at most 32 MiB; current build is about 18 MiB)
- [ ] `./scripts/generate-sbom.sh <version>` produces
      `waf-rejected-<version>.cdx.json` and `.sha256` (the script uses the
      dev-shell `cargo-cyclonedx` or a pinned `nix shell` fallback)
- [ ] `result/share/waf/wasm/coraza_reactor.wasm` exists in the Nix
      package, alongside `LICENSE-CRS`, `PROVENANCE.md` and `SHA256SUMS`
- [ ] `result/share/waf/rules/crs/crs.conf` exists in the Nix package (the
      default Rust engine needs the full CRS bundle, not just the module)
- [ ] Container image contains `/usr/share/waf/wasm/coraza_reactor.wasm` and
      the module digest matches `SHA256SUMS`
- [ ] The default release build includes `rust-engine` and `wasm-reactor`, and
      a default `Config` resolves `waf.coraza.enabled = true` with
      `waf.coraza.backend = "rust"`
- [ ] The release build also includes `coraza-native`, but the default
      `Config` does **not** select it (the native profile is opt-in via
      `config/performance-native.toml`)
- [ ] Switching `waf.coraza.backend = "wasm"` still starts, compiles/warms the
      reactor and serves (`config/examples/coraza-reference.toml`)
- [ ] A `wasm-reactor` build fails closed when the module is missing or has
      broken exports (see `docs/coraza-wasi-reactor.md`)
- [ ] Startup smoke test: with the default config the binary compiles the Rust
      engine bundle before readiness (~276 ms) and serves; setting
      `waf.coraza.enabled = false` skips inspection. With `backend = "wasm"` the
      reactor warm-up is paid before readiness (~5.6 s)
- [ ] `waf.coraza.fallback = "wasm"` re-evaluates only after a Rust-engine
      runtime error and still fails closed if Coraza also errors
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

Local releases built without the Release workflow have no provenance
attestation. In that case `scripts/verify-release.sh` still validates the
checksums, SBOM, module digest, tarball contents, `--version` and health smoke
test; record in the release notes that provenance attestations are absent.

### Smoke test

```bash
./result/bin/waf-ingress --version   # waf-ingress 0.1.0-beta.21
WAF_CONFIG_FILE=config.toml ./result/bin/waf-ingress
curl -f http://127.0.0.1:8081/health
curl -f http://127.0.0.1:8081/metrics
curl -o /dev/null -w '%{http_code}\n' 'http://127.0.0.1:8080/?id=1%20UNION%20SELECT%201'  # 403
curl -o /dev/null -w '%{http_code}\n' -X POST --data '<script>alert(1)</script>' http://127.0.0.1:8080/  # 403
```

### Publishing

- [ ] Confirm `Cargo.toml`, `CHANGELOG.md`, the tag and the README/support
      matrix all name the same version (`0.1.0-beta.21` today).
- [ ] Commit release version and changelog.
- [ ] Tag `v0.1.0-beta.21`.
- [ ] Push branch and tag.
- [ ] Let the `Release` workflow publish the assets, or build them locally
      with `./create_release_artifacts.sh <version>` if Actions or GHCR is
      unavailable. See [`ci.md`](ci.md) for the GHCR fallback.
- [ ] Confirm the release contains every asset:
      - `waf-rejected-v<version>-x86_64-linux.tar.gz` (binary tarball,
        includes `wasm/coraza_reactor.wasm`, `wasm/LICENSE-CRS`,
        `wasm/PROVENANCE.md`, `wasm/SHA256SUMS`, the installed layout under
        `share/waf/wasm/` and `share/waf/rules/crs/`, and the native profile
        under `native/coraza-sidecar` + `native/coraza/`)
      - `waf-rejected-v<version>-coraza-sidecar-x86_64-linux.tar.gz`
        (standalone sidecar binary + CRS rules)
      - `waf-rejected-<version>-image.tar.gz` (prebuilt container image; this
        is the fallback when GHCR is unavailable)
      - `image-digest.txt` (published digest reference, or the fallback note)
      - `waf-rejected-<version>.cdx.json` (CycloneDX SBOM, with the reactor
        file component, SHA-256 and Apache-2.0 licence note)
      - `waf-rejected-<version>-coraza_reactor.wasm` (standalone module)
      - `waf-rejected-<version>-coraza-LICENSE`
      - `waf-rejected-<version>-coraza-PROVENANCE.md`
      - `<asset>.sha256` for each of the assets above
- [ ] Run `./scripts/verify-release.sh --dir <artifact-dir> --version <version>`
      (add `--deep-image` to check the module digest inside the image,
      `--verify-registry` to resolve the published digest, and `--attestations`
      when the assets have GitHub attestations).
- [ ] Confirm the Release workflow pushed
      `ghcr.io/shift/waf-rejected-waf:v<version>` and `:sha-<commit>` and that
      the release body lists the `ghcr.io/shift/waf-rejected-waf@sha256:...`
      reference from `image-digest.txt`. A rejected push is a warning, not a
      release failure: keep the image tarball as the fallback. Never publish
      under the repository-named `ghcr.io/shift/waf-rejected` package, which
      rejects blob uploads with HTTP 403.
- [ ] Verify build provenance for each asset when attestations exist:
      `gh attestation verify <asset> --repo shift/waf-rejected`.
- [ ] Publish the GitHub pre-release with the known-limitations section from
      `CHANGELOG.md`.
