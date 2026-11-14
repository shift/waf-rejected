#!/usr/bin/env bash
# Build the experimental native Go Coraza sidecar.
#
# It reuses the Coraza source and OWASP CRS bundle vendored for the WASI
# reactor, so there is no second ruleset to keep in sync.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
"$repo_root/scripts/apply-coraza-patches.sh"
cd "$repo_root/native/coraza-sidecar"

# The development shell exports GOOS=js GOARCH=wasm for the reactor. Override
# them explicitly or the sidecar is built as a wasm module.
export GOOS="${GOOS_NATIVE:-linux}"
case "$(uname -m)" in
  aarch64|arm64) default_arch="arm64" ;;
  *) default_arch="amd64" ;;
esac
export GOARCH="${GOARCH_NATIVE:-$default_arch}"
export CGO_ENABLED=0
export GOFLAGS=-mod=vendor

out="${1:-$repo_root/target/native/coraza-sidecar}"
mkdir -p "$(dirname "$out")"
go build -trimpath -ldflags="-s -w" -o "$out" .
echo "built $out"
