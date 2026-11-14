#!/usr/bin/env bash
# Short, bounded fuzz smoke run for the security-critical parsers.
#
# Usage:
#   scripts/fuzz-smoke.sh [seconds-per-target]
#
# Defaults to 30 seconds per target. Requires a nightly toolchain and
# cargo-fuzz; if either is unavailable the script prints instructions and
# exits successfully so it is safe to invoke from a normal dev shell.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SECONDS_PER_TARGET="${1:-${FUZZ_SECONDS:-30}}"
TARGETS=(protobuf grpc_frames graphql_body allowlist_json)

if ! command -v cargo >/dev/null 2>&1; then
    echo "cargo not found; skipping fuzz smoke" >&2
    exit 0
fi

if ! cargo +nightly fuzz --version >/dev/null 2>&1; then
    echo "cargo-fuzz/nightly not available; skipping fuzz smoke." >&2
    echo "Install with: rustup toolchain install nightly && cargo install cargo-fuzz" >&2
    exit 0
fi

cd "$ROOT/fuzz"

for target in "${TARGETS[@]}"; do
    echo "==> fuzzing ${target} for ${SECONDS_PER_TARGET}s"
    cargo +nightly fuzz run "$target" -- \
        -max_total_time="$SECONDS_PER_TARGET" \
        -timeout=10 \
        -rss_limit_mb=2048
done

echo "fuzz smoke complete"
