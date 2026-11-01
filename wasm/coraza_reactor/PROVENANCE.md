# Coraza WASI reactor provenance

- Module: `coraza_reactor.wasm`
- Source: `wasm/coraza_reactor/main.go`
- Build: `scripts/build-coraza-reactor.sh`
- Go: `go1.24.5` (or newer 1.24.x), `GOOS=wasip1 GOARCH=wasm`
- Build mode: `c-shared` (`-buildmode=c-shared -trimpath -ldflags="-s -w"`)
- Coraza: `github.com/corazawaf/coraza/v3 v3.3.3`
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
