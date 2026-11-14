#!/usr/bin/env bash
# Validate monitoring dashboards and alert rules against the Rust metric source.
#
# Checks:
#   1. every dashboard JSON file parses;
#   2. every `waf_*` series referenced by a dashboard or alert rule exists in
#      `src/` (histogram suffixes are normalised to their base metric name).
#
# This is intentionally a grep-based guard, not a Prometheus parser. It catches
# typos and invented series without requiring a live Prometheus.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DASHBOARD_DIR="$ROOT/infrastructure/monitoring/dashboards"
ALERT_FILE="$ROOT/infrastructure/monitoring/alert_rules.yml"
SRC_DIR="$ROOT/src"

fail=0

if ! command -v jq >/dev/null 2>&1; then
  echo "error: jq is required to validate dashboard JSON" >&2
  exit 1
fi

if [[ ! -d "$DASHBOARD_DIR" ]]; then
  echo "error: dashboard directory not found: $DASHBOARD_DIR" >&2
  exit 1
fi

shopt -s nullglob
dashboards=("$DASHBOARD_DIR"/*.json)
if [[ ${#dashboards[@]} -eq 0 ]]; then
  echo "error: no dashboard JSON files in $DASHBOARD_DIR" >&2
  exit 1
fi

echo "Validating dashboard JSON..."
for dashboard in "${dashboards[@]}"; do
  if jq empty "$dashboard" >/dev/null 2>&1; then
    echo "  ok: ${dashboard#"$ROOT"/}"
  else
    echo "  FAIL: invalid JSON: ${dashboard#"$ROOT"/}" >&2
    fail=1
  fi
done

if [[ ! -f "$ALERT_FILE" ]]; then
  echo "error: alert rules not found: $ALERT_FILE" >&2
  exit 1
fi

echo "Checking metric references against $SRC_DIR..."
metrics="$(
  {
    grep -rhoE 'waf_[a-z0-9_]+' "$DASHBOARD_DIR" "$ALERT_FILE" || true
  } | sort -u
)"

if [[ -z "$metrics" ]]; then
  echo "error: no waf_* metrics found in dashboards or alerts" >&2
  exit 1
fi

while IFS= read -r metric; do
  [[ -z "$metric" ]] && continue
  base="$metric"
  case "$base" in
    *_bucket) base="${base%_bucket}" ;;
    *_sum) base="${base%_sum}" ;;
    *_count) base="${base%_count}" ;;
  esac

  if grep -rqF "$base" "$SRC_DIR"; then
    echo "  ok: $metric"
  else
    echo "  FAIL: $metric (base '$base') not found in $SRC_DIR" >&2
    fail=1
  fi
done <<< "$metrics"

if [[ $fail -ne 0 ]]; then
  echo "dashboard/alert validation failed" >&2
  exit 1
fi

echo "dashboard/alert validation passed"
