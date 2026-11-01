#!/usr/bin/env bash
# Build the Coraza WASI reactor reproducibly. Run from the repository root.
#
# Usage:
#   ./scripts/build-coraza-reactor.sh          # build, verify and write checksum
#   ./scripts/build-coraza-reactor.sh --verify # rebuild and compare to checksum
#
# The module is built from the committed vendor tree with a local Go 1.24
# toolchain only. Deterministic flags (trimpath, empty build ID, no VCS stamp)
# make repeated builds byte-identical.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$ROOT/wasm/coraza_reactor"
OUT="$SRC/coraza_reactor.wasm"
CHECKSUM="$OUT.sha256"
MODE="${1:-build}"

if [[ "$MODE" != "build" && "$MODE" != "--verify" ]]; then
    echo "usage: $0 [--verify]" >&2
    exit 2
fi

command -v go >/dev/null 2>&1 || {
    echo "error: go not found; run inside 'nix develop'" >&2
    exit 1
}

GO_VERSION="$(go env GOVERSION)"
case "$GO_VERSION" in
    go1.24.*) ;;
    *)
        echo "error: pinned Go 1.24.x required, found $GO_VERSION" >&2
        exit 1
        ;;
esac

[[ -f "$SRC/vendor/modules.txt" ]] || {
    echo "error: missing vendor tree; run 'go mod vendor' in $SRC" >&2
    exit 1
}

cd "$SRC"

# Pinned, offline, deterministic Go 1.24 WASI build settings.
export CGO_ENABLED=0
export GOOS=wasip1
export GOARCH=wasm
export GOFLAGS=-mod=vendor
export GOTOOLCHAIN=local
export GOPROXY=off
export GO111MODULE=on

TMP="$(mktemp "$SRC/.coraza_reactor.XXXXXX.wasm")"
trap 'rm -f "$TMP"' EXIT

go build \
    -tags no_fs_access \
    -buildmode=c-shared \
    -trimpath \
    -buildvcs=false \
    -ldflags="-s -w -buildid=" \
    -o "$TMP" \
    .

# Verify the reactor ABI against the module that will be installed.
if command -v wasm-tools >/dev/null 2>&1; then
    EXPORTS="$(wasm-tools print "$TMP")"
    for sym in _initialize input_base init eval free; do
        grep -q "\"$sym\"" <<<"$EXPORTS" || {
            echo "error: wasm-tools did not find export '$sym'" >&2
            exit 1
        }
    done
elif command -v wasm-objdump >/dev/null 2>&1; then
    EXPORTS="$(wasm-objdump -x "$TMP")"
    for sym in _initialize input_base init eval free; do
        grep -Eq -- "-> \"$sym\"$" <<<"$EXPORTS" || {
            echo "error: wasm-objdump did not find export '$sym'" >&2
            exit 1
        }
    done
else
    echo "warning: neither wasm-tools nor wasm-objdump found; skipping export check" >&2
fi

if command -v wasmtime >/dev/null 2>&1; then
    wasmtime compile "$TMP" -o /dev/null
fi

NEW_HASH="$(sha256sum "$TMP" | awk '{print $1}')"

if [[ "$MODE" == "--verify" ]]; then
    [[ -f "$CHECKSUM" ]] || {
        echo "error: missing $CHECKSUM; run without --verify first" >&2
        exit 1
    }
    EXPECTED_HASH="$(awk '{print $1}' "$CHECKSUM")"
    if [[ "$NEW_HASH" != "$EXPECTED_HASH" ]]; then
        echo "error: non-reproducible build" >&2
        echo "  committed: $EXPECTED_HASH" >&2
        echo "  rebuilt:   $NEW_HASH" >&2
        exit 1
    fi
    echo "verified $OUT ($NEW_HASH)"
    exit 0
fi

mv -f "$TMP" "$OUT"
printf '%s  %s\n' "$NEW_HASH" "coraza_reactor.wasm" > "$CHECKSUM"
echo "built $OUT"
echo "sha256 $NEW_HASH"
