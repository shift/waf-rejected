# Coraza WASI reactor provenance

- Module: `coraza_reactor.wasm`
- Source: `wasm/coraza_reactor/main.go`
- Build: `scripts/build-coraza-reactor.sh`
- Go: `go1.26.10` (or newer 1.26.x), `GOOS=wasip1 GOARCH=wasm`
- Build mode: `c-shared` (`-buildmode=c-shared -trimpath -ldflags="-s -w"`)
- Coraza: `github.com/corazawaf/coraza/v3 v3.8.1`
- Licence: Coraza and the referenced OWASP CRS material are Apache-2.0.
  See `LICENSE-CRS` in this directory.

## Reproduce

```sh
nix develop
./scripts/build-coraza-reactor.sh
sha256sum wasm/coraza_reactor/coraza_reactor.wasm
```

`SHA256SUMS` records the committed module digest. The release checksum step
also publishes the digest as a standalone `.sha256` asset.

## Local patches

The vendored tree carries one local patch, recorded in
`patches/coraza-remove-rule-by-id.patch`:

- **`types.Transaction.RemoveRuleByID(int)`** — the implementation already
  exists on `*internal/corazawaf.Transaction` (it backs the `ctl` action), but
  it is not part of the public `types.Transaction` interface. The patch adds
  the method to the interface so the reactor and the native sidecar can apply
  a per-transaction rule-removal list before phase 1.

Both Go build paths share one vendor tree (`native/coraza-sidecar/vendor` is a
symlink to this directory) and run `scripts/apply-coraza-patches.sh` before
compiling. The script is idempotent and detects an already-patched tree, so a
fresh `go mod vendor` is repaired deterministically. `--check` verifies the
patch is present without modifying anything.

The embedded gated-rule set lives in
`wasm/coraza_reactor/rules/crs/prefilter.json`. It is a byte-identical copy of
`rules/crs/prefilter.json`, written by `crs-prefilter-extract` and verified by
a Rust unit test; a missing copy disables per-rule gating (every rule runs),
which is always sound.
