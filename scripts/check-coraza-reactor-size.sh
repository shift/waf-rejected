#!/usr/bin/env bash
# Verify the committed Coraza reactor matches SHA256SUMS and the release size
# budget. Run from the repository root or any CI job checkout.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIR="$ROOT/wasm/coraza_reactor"
MODULE="$DIR/coraza_reactor.wasm"
LIMIT=$((32 * 1024 * 1024))

test -s "$MODULE" || {
    echo "error: missing Coraza reactor: $MODULE" >&2
    exit 1
}

(cd "$DIR" && sha256sum --check SHA256SUMS)

SIZE=$(stat -c%s "$MODULE")
if (( SIZE > LIMIT )); then
    echo "error: coraza_reactor.wasm is $SIZE bytes; budget is $LIMIT bytes (32 MiB)" >&2
    exit 1
fi

echo "ok: coraza_reactor.wasm $(numfmt --to=iec --suffix=B "$SIZE") (budget 32 MiB)"
