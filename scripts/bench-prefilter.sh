#!/usr/bin/env bash
# Benchmark the CRS literal prefilter and its production Hyperscan backend.
#
# Measures, at 1/4/8 KiB bodies:
#   * prefilter-only scan (Hyperscan and pure-Rust Aho-Corasick fallback),
#   * process-cache reuse (cold `Prefilter::embedded` vs warm hit),
#   * prefilter + engine, using the engine-kernel p50 as the engine reference.
#
# Everything runs through `nix develop` so the vectorscan library and the
# pinned toolchain match CI. No network access is required.
#
# Usage:
#   scripts/bench-prefilter.sh [--reps N] [--warmup N] [--json-out PATH]
#                              [--with-engine]
#
# The script is read-only: it prints results and optionally writes JSON. The
# human-readable report lives in docs/design/simd-prefilter.md.

set -euo pipefail

REPS="${REPS:-50}"
WARMUP="${WARMUP:-5}"
JSON_OUT=""
WITH_ENGINE=0

usage() {
    sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --reps)
            REPS="${2:?--reps needs a value}"
            shift 2
            ;;
        --warmup)
            WARMUP="${2:?--warmup needs a value}"
            shift 2
            ;;
        --json-out)
            JSON_OUT="${2:?--json-out needs a value}"
            shift 2
            ;;
        --with-engine)
            WITH_ENGINE=1
            shift
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        *)
            echo "unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if ! command -v nix >/dev/null 2>&1; then
    echo "nix is required; run inside the project dev environment" >&2
    exit 1
fi

BENCH_ARGS=(--reps "$REPS" --warmup "$WARMUP")
if [[ -n "$JSON_OUT" ]]; then
    BENCH_ARGS+=(--json-out "$JSON_OUT")
fi

echo "== prefilter benchmark =="
echo "reps=$REPS warmup=$WARMUP engine=$WITH_ENGINE"
echo

nix develop -c cargo run --release --no-default-features \
    --features hyperscan-eval --bin hyperscan-bench -- "${BENCH_ARGS[@]}"

if [[ "$WITH_ENGINE" -eq 1 ]]; then
    echo
    echo "== prefilter + engine reference =="
    # engine-kernel is owned by another workstream; build it read-only here.
    # Its 4 KiB p50 is the published 0.74 ms figure the prefilter must budget
    # against. If the feature does not build in this environment the script
    # reports the documented reference instead of failing the prefilter run.
    if nix develop -c cargo run --release --no-default-features \
        --features engine-kernel --bin engine-kernel-bench \
        >/tmp/opencode/prefilter-engine-bench.log 2>&1; then
        cat /tmp/opencode/prefilter-engine-bench.log
    else
        echo "engine-kernel-bench unavailable; using documented reference:"
        echo "  1 KiB 189.69 µs, 4 KiB 741.28 µs, 8 KiB 1740.08 µs (p50, CPU time)"
    fi
fi
