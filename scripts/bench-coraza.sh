#!/usr/bin/env bash
# Build and run the Coraza WASI reactor benchmarks.
#
# Usage:
#   ./scripts/bench-coraza.sh [extra criterion args...]
#
# The committed reactor module (wasm/coraza_reactor/coraza_reactor.wasm) must
# exist; rebuild it with ./scripts/build-coraza-reactor.sh after Go changes.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ ! -f wasm/coraza_reactor/coraza_reactor.wasm ]]; then
    echo "missing wasm/coraza_reactor/coraza_reactor.wasm" >&2
    echo "run ./scripts/build-coraza-reactor.sh first" >&2
    exit 1
fi

# Cargo's `bench` profile is optimised (LTO, opt-level 3), so this is the
# release-equivalent build of the library and the benchmark target.
exec cargo bench --features wasm-reactor --bench coraza "$@"
