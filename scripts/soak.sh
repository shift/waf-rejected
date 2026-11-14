#!/usr/bin/env bash
# Soak and fault-injection entry point for WAF-Rejected.
#
# Short CI-friendly run (default):
#   SOAK_DURATION=60s ./scripts/soak.sh
#
# Fault scenarios only:
#   ./scripts/soak.sh faults
#
# Long operator soak (not a CI run):
#   SOAK_DURATION=2h SOAK_WARMUP=10m SOAK_CONCURRENCY=64 ./scripts/soak.sh
#
# See docs/operations/soak-testing.md for thresholds and evidence.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
PROFILE="${SOAK_PROFILE:-release}"
FEATURES="${SOAK_FEATURES:-experimental}"
DURATION="${SOAK_DURATION:-60s}"
WARMUP="${SOAK_WARMUP:-10s}"
CONCURRENCY="${SOAK_CONCURRENCY:-16}"
MIX="${SOAK_MIX:-benign=40,blocked=20,oversized=5,malformed=5,grpc=15,websocket=15}"
BODY_SIZE="${SOAK_BODY_SIZE:-4096}"
OVERSIZED_BYTES="${SOAK_OVERSIZED_BYTES:-1572864}"
SAMPLE_INTERVAL="${SOAK_SAMPLE_INTERVAL:-2s}"
MAX_RSS_SLOPE="${SOAK_MAX_RSS_SLOPE_MB_PER_MIN:-2.0}"
MAX_FD_GROWTH="${SOAK_MAX_FD_GROWTH:-32}"
MAX_CONN_GROWTH="${SOAK_MAX_CONN_GROWTH:-32}"
MAX_ERROR_RATE="${SOAK_MAX_ERROR_RATE:-0.01}"
MIN_BLOCK_RATE="${SOAK_MIN_BLOCK_RATE:-0.99}"
REPORT="${SOAK_REPORT:-$TARGET_DIR/soak-report.json}"
WORK_DIR="${SOAK_WORK_DIR:-$TARGET_DIR/soak-work}"
MODE="${1:-soak}"

mkdir -p "$TARGET_DIR" "$WORK_DIR"

echo "building soak-load and waf-ingress (profile=$PROFILE features=$FEATURES)"
cargo build --profile "$PROFILE" --features "$FEATURES" --bin soak-load --bin waf-ingress

BIN="$TARGET_DIR/$PROFILE/soak-load"
WAF="$TARGET_DIR/$PROFILE/waf-ingress"
if [[ ! -x "$BIN" || ! -x "$WAF" ]]; then
  echo "error: expected binaries at $BIN and $WAF" >&2
  exit 1
fi

case "$MODE" in
  soak)
    exec "$BIN" soak \
      --waf-bin "$WAF" \
      --self-bin "$BIN" \
      --duration "$DURATION" \
      --warmup "$WARMUP" \
      --concurrency "$CONCURRENCY" \
      --mix "$MIX" \
      --body-size "$BODY_SIZE" \
      --oversized-bytes "$OVERSIZED_BYTES" \
      --sample-interval "$SAMPLE_INTERVAL" \
      --max-rss-slope-mb-per-min "$MAX_RSS_SLOPE" \
      --max-fd-growth "$MAX_FD_GROWTH" \
      --max-conn-growth "$MAX_CONN_GROWTH" \
      --max-error-rate "$MAX_ERROR_RATE" \
      --min-block-rate "$MIN_BLOCK_RATE" \
      --report "$REPORT" \
      --work-dir "$WORK_DIR"
    ;;
  faults)
    exec "$BIN" faults \
      --waf-bin "$WAF" \
      --self-bin "$BIN" \
      --work-dir "$WORK_DIR"
    ;;
  *)
    echo "usage: $0 [soak|faults]" >&2
    exit 2
    ;;
esac
