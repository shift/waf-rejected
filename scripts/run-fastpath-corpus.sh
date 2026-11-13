#!/usr/bin/env bash
# Runs the pinned CRS corpus through the WASI Coraza baseline and the
# experimental fast path, then reports false negatives on the covered subset.
#
# Usage: scripts/run-fastpath-corpus.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
OUT="${OUT:-target/fastpath-corpus}"
mkdir -p "$OUT"

nix develop -c cargo run --quiet --bin crs_corpus --features fastpath -- \
  --engine wasm --json "$OUT/wasm.json"
nix develop -c cargo run --quiet --bin crs_corpus --features fastpath -- \
  --engine fastpath --json "$OUT/fastpath.json"

jq -n \
  --slurpfile wasm "$OUT/wasm.json" \
  --slurpfile fp "$OUT/fastpath.json" '
  ($wasm[0].engines.wasm.cases | map({key: .id, value: .observed}) | from_entries) as $observed |
  ($fp[0].fastpath.cases | map(select(.clean))) as $clean |
  {
    total: $fp[0].fastpath.total,
    clean: ($clean | length),
    fallback: $fp[0].fastpath.fallback,
    false_negatives_vs_coraza: ([$clean[] | select($observed[.id] == "block")] | length),
    false_negative_ids: [$clean[] | select($observed[.id] == "block") | .id],
    clean_expected_block: ([$clean[] | select(.expected == "block")] | length)
  }'
