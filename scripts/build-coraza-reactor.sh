#!/usr/bin/env bash
# Build the Coraza WASI reactor. Run from the repository root.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/wasm/coraza_reactor/coraza_reactor.wasm"

cd "$ROOT/wasm/coraza_reactor"
GOOS=wasip1 GOARCH=wasm go build \
    -tags no_fs_access \
    -buildmode=c-shared \
    -trimpath \
    -ldflags="-s -w" \
    -o "$OUT" \
    .

echo "built $OUT"
