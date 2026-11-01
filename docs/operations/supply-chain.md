# Supply-chain policy

WAF-Rejected enforces a dependency supply-chain policy with
[`cargo-deny`](https://github.com/EmbarkStudios/cargo-deny). The policy lives in
[`deny.toml`](../../deny.toml) at the repository root and is the single source of
truth for what is allowed into the build.

The policy is enforced in two places:

- **CI:** `.github/workflows/production-deployment.yml` (`security-scan` job)
  installs `cargo-deny` and runs `cargo deny check` on every push and pull
  request to `main`/`production`.
- **Local:** `scripts/ci-local.sh` runs `cargo deny check` as a pipeline stage
  and prints a warning instead of failing when `cargo-deny` is not installed.

## Running the check

```bash
# Nix shell (preferred, no global install)
nix shell nixpkgs#cargo-deny nixpkgs#cargo -c cargo deny check

# Individual sections
nix shell nixpkgs#cargo-deny nixpkgs#cargo -c cargo deny check advisories
nix shell nixpkgs#cargo-deny nixpkgs#cargo -c cargo deny check licenses
nix shell nixpkgs#cargo-deny nixpkgs#cargo -c cargo deny check bans
nix shell nixpkgs#cargo-deny nixpkgs#cargo -c cargo deny check sources
```

`SKIP_DENY=1 ./scripts/ci-local.sh` skips the stage locally (for example on an
air-gapped machine where the RustSec advisory database cannot be fetched). CI
never skips it.

## Policy sections

### Advisories

- **Vulnerabilities:** denied. Any RUSTSEC advisory with a vulnerability
  classification fails the build.
- **Unmaintained crates:** `unmaintained = "workspace"`, so only unmaintained
  crates that are direct dependencies fail; transitive occurrences are reported
  without breaking the build.
- **Yanked crates:** warned, not denied, because a yanked release already in
  `Cargo.lock` is still reproducible; upgrades should be scheduled.
- **Ignored advisories:** must be listed in `advisories.ignore` with an `id` and
  a `reason`. An ignore entry is a time-boxed risk acceptance, not a waiver of
  the policy; every entry names the follow-up needed to remove it.

Current exceptions:

| Advisory | Crate | Reason |
| --- | --- | --- |
| `RUSTSEC-2025-0134` | `rustls-pemfile` 2.2.0 | Crate archived with no fixed release. Used only to parse operator-supplied PEM TLS material (`src/waf/tls_config.rs`, `src/proxy/http3.rs`). Follow-up: migrate to `rustls-pki-types` `PemObject`. |

### Licences

Only the following licences are accepted. Everything else fails the build and
requires an explicit policy change (a reviewed edit to `deny.toml`), never an
ad-hoc exception in a pull request.

| Licence | Why |
| --- | --- |
| `MIT`, `Apache-2.0`, `Apache-2.0 WITH LLVM-exception` | Dominant Rust ecosystem licences; no obligations beyond attribution. |
| `BSD-2-Clause`, `BSD-3-Clause`, `ISC` | Permissive; attribution only. |
| `Unicode-3.0` | Unicode data tables (IDNA/segmentation); permissive. |
| `Zlib` | Permissive; attribution only. |
| `MPL-2.0` | Weak copyleft scoped to individual files; we do not modify covered files. |
| `CC0-1.0` | Public-domain dedication for data/tables. |
| `OpenSSL` | Permissive with advertising clause; used by OpenSSL-derived crates. |
| `bzip2-1.0.6` | Permissive; used by bzip2 bindings. |
| `CDLA-Permissive-2.0` | Mozilla CA root data in `webpki-roots`; data only. |

`unused-allowed-license = "allow"` is set deliberately: the list is a standing
pre-approval for future dependencies, so an allowance that the current tree does
not exercise (for example `Zlib` or `MPL-2.0`) is not an error. The list is
still reviewed whenever it changes.

### Bans

- **Multiple versions:** `warn`. Duplicate major versions of the same crate are
  reported for review (they are common in async/TLS stacks) but do not fail the
  build.
- **Wildcard requirements:** `deny`. A `*` version requirement makes builds
  non-reproducible; pin a range instead.
- Default features are allowed for workspace and external crates; the policy
  currently has no explicit bans or skips.

### Sources

- **Registries:** only crates.io is allowed
  (`https://github.com/rust-lang/crates.io-index` and
  `sparse+https://index.crates.io/`). Any other registry is denied.
- **Git sources:** `allow-git = []` and `unknown-git = "deny"`, because the
  current `Cargo.lock` contains no git dependencies. Adding a git dependency
  requires an explicit, reviewed addition here with a pinned `rev`.

## CycloneDX SBOM and the Coraza reactor

`cargo cyclonedx` inventories Rust crates only. The release workflow therefore
adds the shipped Coraza WASI reactor as an explicit CycloneDX `file`
component, including:

- `name: coraza_reactor.wasm` and version `coraza-3.3.3`;
- the SHA-256 digest of `wasm/coraza_reactor/coraza_reactor.wasm`;
- an `Apache-2.0` licence entry covering Coraza and the referenced OWASP CRS
  material;
- `waf:component`, `waf:license-note` and `waf:source` properties pointing at
  `wasm/coraza_reactor/LICENSE-CRS` and `main.go`.

Verify the SBOM component after download:

```bash
jq '.components[] | select(.name == "coraza_reactor.wasm")' \
  waf-rejected-<version>.cdx.json
```

The release also enforces a 32 MiB budget for the module and publishes its
standalone digest asset; see
[`docs/coraza-wasi-reactor.md`](../coraza-wasi-reactor.md).

## Container and filesystem vulnerability scanning

Tagged releases additionally run [Trivy](https://github.com/aquasecurity/trivy)
through `aquasecurity/trivy-action` in `.github/workflows/release.yml`:

- **`trivy-filesystem`** scans the checked-out repository (`scan-type: fs`):
  dependency manifests/lockfiles, vendored assets and configuration in the
  source tree.
- **`trivy-image`** scans the release container image tarball produced by the
  `build-image` job (`scan-type: image`), covering OS packages as well as
  application dependencies layered into the image.

Both scans:

- report `HIGH` and `CRITICAL` findings only;
- fail the job when any finding is present (`exit-code: 1`), including findings
  without an upstream fix (`ignore-unfixed: false`);
- emit SARIF to the repository's code-scanning dashboard with separate
  `trivy-filesystem` and `trivy-image` categories, even when the scan fails.

`build-release` depends on both scan jobs, so a failing scan blocks the release.
The jobs request `contents: read` and `security-events: write`; the latter is
required to upload SARIF. If the repository has code scanning disabled, the
scan still blocks the release even though the SARIF upload step reports an
error.

### Running Trivy locally

The local CI runner runs the filesystem scan only when explicitly requested:

```bash
TRIVY=1 ./scripts/ci-local.sh
```

The stage is skipped with a warning if `trivy` is not installed. If it is
missing, use the Nix shell:

```bash
# Filesystem/dependency scan (same thresholds as CI)
nix shell nixpkgs#trivy -c trivy fs \
  --scanners vuln --severity HIGH,CRITICAL --exit-code 1 .

# Release image scan from the published tag, a locally built image, or a
# release tarball (`trivy image --input waf-rejected-<version>-image.tar.gz`)
nix shell nixpkgs#trivy -c trivy image \
  --severity HIGH,CRITICAL --exit-code 1 ghcr.io/shift/waf-rejected:<tag>
nix shell nixpkgs#trivy -c trivy image \
  --severity HIGH,CRITICAL --exit-code 1 waf-rejected:local-ci
```

Trivy downloads its vulnerability database on first use; on an air-gapped host,
pre-populate the cache or mirror the database before running the scan. CI never
skips the scans.

## Changing the policy

1. Open a pull request that edits `deny.toml` and this document together.
2. Explain why the new licence/advisory/source is required.
3. Confirm `cargo deny check` passes locally and in CI.

Adding a dependency is a policy event: reviewers should check the new crate's
licence, maintenance status and source against this document rather than relying
on the check alone.
