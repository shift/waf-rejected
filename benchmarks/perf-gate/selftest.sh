#!/usr/bin/env bash
# Verify the comparison gate on synthetic input: a copy of the baseline must
# pass, a +50% p50 row must fail under --enforce, and the same row must not fail
# without --enforce (the shared-runner default).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BASELINE="$ROOT/benchmarks/perf-gate/baseline.json"
COMPARE="$ROOT/benchmarks/perf-gate/compare.sh"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/perf-gate-selftest.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

[[ -f "$BASELINE" ]] || { echo "missing baseline: $BASELINE" >&2; exit 1; }

cp "$BASELINE" "$TMP/pass.json"
jq '(.rows[0].p50_ms) *= 1.5' "$BASELINE" >"$TMP/fail.json"
# Keep the 4k-sqli p50 unchanged but halve 4k-allow: the absolute rows do not
# regress, but the attack/allow ratio doubles and must trip the ratio gate.
jq '(.rows[] | select(.case == "4k-allow") | .p50_ms) *= 0.5' \
  "$BASELINE" >"$TMP/ratio-fail.json"

failures=0

if "$COMPARE" --enforce "$TMP/pass.json" >/dev/null; then
  echo "PASS: baseline copy passes under --enforce"
else
  echo "FAIL: baseline copy did not pass under --enforce" >&2
  failures=$((failures + 1))
fi

if "$COMPARE" --enforce "$TMP/fail.json" >/dev/null; then
  echo "FAIL: +50% p50 row passed under --enforce" >&2
  failures=$((failures + 1))
else
  echo "PASS: +50% p50 row fails under --enforce"
fi

if "$COMPARE" "$TMP/fail.json" >/dev/null; then
  echo "PASS: +50% p50 row does not fail without --enforce"
else
  echo "FAIL: +50% p50 row failed without --enforce" >&2
  failures=$((failures + 1))
fi

if "$COMPARE" --enforce "$TMP/ratio-fail.json" >/dev/null; then
  echo "FAIL: doubled 4k-sqli/4k-allow ratio passed under --enforce" >&2
  failures=$((failures + 1))
else
  echo "PASS: doubled 4k-sqli/4k-allow ratio fails under --enforce"
fi

if [[ "$failures" -ne 0 ]]; then
  echo "selftest: FAIL ($failures)" >&2
  exit 1
fi
echo "selftest: PASS"
