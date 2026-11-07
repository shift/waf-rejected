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

### Dependency remediation (November 2026)

GitHub Dependabot reported 27 alerts (4 high, 23 moderate) against the public
repository. The Rust graph was already clean: `cargo audit` and
`cargo deny check advisories` reported no vulnerabilities, only the accepted
`rustls-pemfile` unmaintained warning. The alerts came from the two Go modules
that ship the Coraza engine (`wasm/coraza_reactor` and
`native/coraza-sidecar`), which share one vendored dependency tree.

`govulncheck` reproduced 11 reachable Coraza advisories and 4 reachable
`golang.org/x/net` advisories. All 15 module advisories are fixed by the
upgrade below; the remaining `govulncheck` findings are Go standard-library
advisories in the build toolchain, not module dependencies.

| Module | Before | After | Advisories fixed |
| --- | --- | --- | --- |
| `github.com/corazawaf/coraza/v3` | `v3.3.3` | `v3.8.1` | `GO-2026-6699`, `GO-2026-6698`, `GO-2026-6697`, `GO-2026-6696`, `GO-2026-6694`, `GO-2026-6693`, `GO-2026-6692`, `GO-2026-6691`, `GO-2026-6690`, `GO-2026-6669`, `GO-2026-6668` |
| `golang.org/x/net` | `v0.37.0` | `v0.60.0` | `GO-2026-6617`, `GO-2026-6612`, `GO-2026-6611`, `GO-2026-6603` |
| `github.com/corazawaf/libinjection-go` | `v0.2.2` | `v0.3.3` | pulled in by Coraza v3.8.1 |
| `golang.org/x/sync` | `v0.12.0` | `v0.23.0` | pulled in by Coraza v3.8.1 |
| `google.golang.org/protobuf` | `v1.35.1` | `v1.36.11` | pulled in by Coraza v3.8.1 |

The Coraza upgrade keeps the pinned OWASP CRS bundle (`4.14.0`) and the
`coraza-coreruleset` module revision unchanged. The local
`types.Transaction.RemoveRuleByID` patch still applies to v3.8.1 and was
renamed to `patches/coraza-remove-rule-by-id.patch`. The committed WASI
reactor was rebuilt with Go 1.26.10 and its digest updated.

**Go standard library.** The previous `nixpkgs` pin provided Go 1.26.4, which
`govulncheck` flagged for standard-library advisories fixed in Go 1.26.5–1.26.10
(`crypto/tls`, `crypto/x509`, `net/http`, `net/url`, `net/textproto`,
`encoding/xml`, `encoding/asn1`). The `nixpkgs` flake input was updated to the
2026-11-03 revision, which provides Go 1.26.10. `govulncheck` now reports
`No vulnerabilities found` for both Go modules. The reactor and sidecar were
rebuilt with the updated toolchain.

**OpenTelemetry SDK advisory (resolved).** Dependabot reported one moderate
advisory: `opentelemetry_sdk` 0.20.0, CVE-2026-48504 / GHSA-w9wp-h8wv-79jx,
unbounded memory allocation while extracting W3C Baggage. The old tree pulled
the SDK in through `opentelemetry` even though the binary never installed an SDK
`TracerProvider` and never called baggage extraction. The `export-otel`
exporter only creates spans through the global API, so the remediation removes
`opentelemetry_sdk` from the dependency graph entirely and upgrades the API
crate `opentelemetry` from 0.20.0 to 0.33.1 (the current release superseding the
0.32.1 fix line). There is no `opentelemetry-otlp` dependency in this tree;
export to a collector is performed by a provider installed by the embedding
application. `export-system` no longer enables OpenTelemetry transitively.
Embedders that want spans install their own matching 0.33 SDK provider before
constructing the WAF; with the default provider the exporter is a no-op. No SDK
provider or baggage propagator ships with the binary, so CVE-2026-48504 is no
longer reachable and no affected crate remains in `Cargo.lock`.

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

Generate the release SBOM with the repository script:

```bash
# From the Nix dev shell (cargo-cyclonedx is a dev-shell dependency)
./scripts/generate-sbom.sh 0.1.0-beta.15

# Outside the dev shell the script falls back to a pinned nixpkgs invocation
nix shell nixpkgs#cargo-cyclonedx nixpkgs#cargo nixpkgs#jq \
  -c ./scripts/generate-sbom.sh 0.1.0-beta.15
```

The script writes `waf-rejected-<version>.cdx.json` and
`waf-rejected-<version>.cdx.json.sha256`. It sets `SOURCE_DATE_EPOCH` from the
current commit so the metadata timestamp is stable for a source revision.
`cargo-cyclonedx` 0.5.9 names its raw output `<name>.json`; the script renames
it to the `.cdx.json` asset name used by the release and verification tooling.

`cargo cyclonedx` inventories Rust crates only. The script therefore adds the
shipped Coraza WASI reactor as an explicit CycloneDX `file` component,
including:

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

# Full release verification (checksums, SBOM, module digest, tarballs, smoke)
./scripts/verify-release.sh --dir <artifact-dir> --version <version>
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
- fail the job only when a finding has an upstream fix available
  (`exit-code: 1`, `ignore-unfixed: true`);
- report findings without a fix in SARIF without blocking the release;
- emit SARIF to the repository's code-scanning dashboard with separate
  `trivy-filesystem` and `trivy-image` categories, even when the scan fails.

`build-release` depends on both scan jobs, so a fixable `HIGH`/`CRITICAL`
finding blocks the release. Unfixed advisories must still be triaged and
recorded here. The jobs request `contents: read` and `security-events: write`;
the latter is required to upload SARIF. If the repository has code scanning
disabled, the SARIF upload step reports an error; the scan result itself still
gates the release. See [`ci.md`](ci.md#vulnerability-policy).

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
  --scanners vuln --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 .

# Release image scan from the published tag, a locally built image, or a
# release tarball (`trivy image --input waf-rejected-<version>-image.tar.gz`)
nix shell nixpkgs#trivy -c trivy image \
  --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 ghcr.io/shift/waf-rejected:<tag>
nix shell nixpkgs#trivy -c trivy image \
  --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 waf-rejected:local-ci
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
