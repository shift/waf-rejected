#!/usr/bin/env bash
# Enforce the native Rust engine guarantees.
#
# Usage:
#   ./scripts/check-engine-guarantees.sh
#   ENGINE_FEATURE=1 ./scripts/check-engine-guarantees.sh
#
# `ENGINE_FEATURE=1` additionally requires the native Rust engine to be linked
# and makes the differential target blocking. Without it, accounting and
# determinism against the Coraza baseline are still enforced, while the Rust
# differential target is reported as skipped.
#
# Exit codes: 0 all enforced checks passed; non-zero any check failed.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

ENGINE_FEATURE="${ENGINE_FEATURE:-0}"
OUT_DIR="${ENGINE_GUARANTEE_OUT_DIR:-target/engine-guarantees}"
mkdir -p "$OUT_DIR"

run() {
  echo "+ $*"
  nix develop -c "$@"
}

echo "== engine guarantees: formatting =="
run cargo fmt -- --check

echo "== engine guarantees: rule accounting =="
run cargo run --quiet --bin rule_accounting -- --check

echo "== engine guarantees: guarantee-layer unit tests =="
run cargo test --lib engine::

echo "== engine guarantees: native-engine feature compiles =="
run cargo check --features native-engine --bin crs_corpus --bin rule_accounting

echo "== engine guarantees: Coraza determinism baseline =="
run cargo run --quiet --bin crs_corpus --features wasm-reactor -- \
  --engine wasm \
  --limit 64 \
  --determinism 100 \
  --determinism-threads 4 \
  --determinism-limit 64 \
  --fail-on-mismatch \
  --json "$OUT_DIR/coraza-determinism.json"

if [[ "$ENGINE_FEATURE" == "1" ]]; then
  echo "== engine guarantees: native Rust differential + determinism (blocking) =="
  run cargo run --quiet --bin crs_corpus --features wasm-reactor,native-engine -- \
    --engine rust \
    --limit 64 \
    --require-engine \
    --generated 500 \
    --generated-seed 2654435761 \
    --determinism 100 \
    --determinism-threads 4 \
    --determinism-limit 64 \
    --counterexamples tests/corpus/engine/counterexamples.json \
    --fail-on-mismatch \
    --json "$OUT_DIR/rust-differential.json"
else
  echo "== engine guarantees: native Rust differential skipped =="
  echo "   native-engine feature is not enabled (set ENGINE_FEATURE=1 to make it blocking)"
fi

echo "engine guarantees passed"
