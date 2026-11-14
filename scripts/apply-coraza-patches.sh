#!/usr/bin/env bash
# Apply the committed local patches to the vendored Coraza tree.
#
# Both Go build paths (WASI reactor and native sidecar) share one vendor tree:
# native/coraza-sidecar/vendor is a symlink to wasm/coraza_reactor/vendor. A
# fresh `go mod vendor` regenerates the tree from upstream and drops local
# changes, so every build path runs this script first. It is idempotent: an
# already-applied patch is detected by its marker and skipped.
#
# Usage: ./scripts/apply-coraza-patches.sh [--check]
#   --check  exit non-zero if any patch is missing instead of applying it
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENDOR="$ROOT/wasm/coraza_reactor/vendor/github.com/corazawaf/coraza/v3"
PATCH_DIR="$ROOT/patches"
MODE="${1:-apply}"

if [[ "$MODE" != "apply" && "$MODE" != "--check" ]]; then
    echo "usage: $0 [--check]" >&2
    exit 2
fi

[[ -d "$VENDOR" ]] || {
    echo "error: missing Coraza vendor tree at $VENDOR" >&2
    exit 1
}

apply_patch() {
    local patch="$1" marker="$2" target="$3"
    if grep -q -- "$marker" "$target"; then
        echo "already applied: $(basename "$patch")"
        return 0
    fi
    if [[ "$MODE" == "--check" ]]; then
        echo "error: patch not applied: $(basename "$patch")" >&2
        return 1
    fi
    (cd "$ROOT" && patch -p1 --forward --batch < "$patch")
    grep -q -- "$marker" "$target" || {
        echo "error: patch did not apply: $(basename "$patch")" >&2
        return 1
    }
    echo "applied: $(basename "$patch")"
}

# Expose (*internal/corazawaf.Transaction).RemoveRuleByID on the public
# types.Transaction interface. The implementation already exists upstream.
apply_patch \
    "$PATCH_DIR/coraza-remove-rule-by-id.patch" \
    "RemoveRuleByID(id int)" \
    "$VENDOR/types/transaction.go"
