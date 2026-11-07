# Third-party licences and notices

WAF-Rejected is licensed under MIT OR Apache-2.0 (see `LICENSE-MIT` and
`LICENSE-APACHE`). It includes or links against the following third-party
components. Full licence texts are kept next to the vendored sources where
applicable.

## Runtime components

| Component | Version / pin | Licence | Location |
|---|---|---|---|
| Coraza WAF | v3.3.3 | Apache-2.0 | `wasm/coraza_reactor/vendor/github.com/corazawaf/coraza/v3/` |
| OWASP Core Rule Set | 4.14.0 (`b5b788b5`) | Apache-2.0 | `wasm/coraza_reactor/rules/crs/LICENSE` |
| libinjection (Rust port) | libinjection-go v0.2.2 lineage | BSD-3-Clause | `src/waf/native_detect/LICENSE.libinjection.txt` |
| Vectorscan (Hyperscan fork) | 5.4.12 | BSD-3-Clause | system/Nix package `vectorscan` |
| Go standard library and vendored Go modules | Go 1.24 | BSD-3-Clause and module-specific licences | `wasm/coraza_reactor/vendor/` |

## Rust crates

The Rust dependency tree is permissively licensed. The allowed licence set is
enforced by `cargo deny` using [`deny.toml`](deny.toml):

```sh
nix shell nixpkgs#cargo-deny nixpkgs#cargo -c cargo deny check
```

Run `cargo metadata` or `cargo deny` to produce the complete crate-by-crate
inventory for a given build.

## Rule data

The bundled OWASP CRS rules and their data files are Apache-2.0. Deployment
specific exclusions or custom rules remain the responsibility of the operator
and are not covered by this project's licence.

## Container base images

The release image is built from Debian `bookworm-slim` and includes
`ca-certificates`. Their licences are distributed inside the image and are
available from Debian.

If you redistribute WAF-Rejected, retain this file, the upstream licence files
listed above, and the notices shipped with the container image.
