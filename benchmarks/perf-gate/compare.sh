#!/usr/bin/env bash
# Compare a perf-gate report against the committed baseline.
#
# The gate is deliberately opt-in: without `--enforce` it prints the comparison
# and always exits 0, so a shared or noisy CI runner cannot fail a build by
# accident. Pass `--enforce` (for example on a dedicated benchmark host) to make
# a p50 regression beyond the threshold a non-zero exit.
#
#   ./benchmarks/perf-gate/compare.sh benchmarks/perf-gate/results/latest.json
#   ./benchmarks/perf-gate/compare.sh --enforce --threshold 0.20 results.json
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BASELINE="$ROOT/benchmarks/perf-gate/baseline.json"
CURRENT=""
THRESHOLD="0.20"
ENFORCE=0

usage() {
  cat <<'EOF'
usage: benchmarks/perf-gate/compare.sh [options] <current.json>

  --baseline <path>   baseline report (default benchmarks/perf-gate/baseline.json)
  --threshold <f>     allowed p50 regression as a fraction (default 0.20 = +20%)
  --enforce           exit non-zero when a row regresses; without it the gate
                      only reports and exits 0 (safe for shared CI runners)
  -h, --help          this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --baseline) BASELINE="${2:?--baseline needs a path}"; shift 2 ;;
    --threshold) THRESHOLD="${2:?--threshold needs a number}"; shift 2 ;;
    --enforce) ENFORCE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    -*) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
    *) CURRENT="$1"; shift ;;
  esac
done

[[ -n "$CURRENT" ]] || { usage >&2; exit 2; }
[[ -f "$BASELINE" ]] || { echo "missing baseline: $BASELINE" >&2; exit 2; }
[[ -f "$CURRENT" ]] || { echo "missing report: $CURRENT" >&2; exit 2; }

declare -A BASE
while IFS=$'\t' read -r backend case p50; do
  BASE["$backend/$case"]="$p50"
done < <(jq -r '.rows[] | [.backend, .case, .p50_ms] | @tsv' "$BASELINE")

echo "baseline:  $BASELINE"
echo "current:   $CURRENT"
echo "threshold: +$(awk -v t="$THRESHOLD" 'BEGIN { printf "%.0f%%", t * 100 }') p50"
echo
printf '%-8s %-10s %12s %12s %10s %s\n' backend case baseline_ms current_ms delta status
printf '%-8s %-10s %12s %12s %10s %s\n' -------- ---------- ----------- ---------- ---------- ------

regressions=0
missing=0
while IFS=$'\t' read -r backend case p50; do
  key="$backend/$case"
  base="${BASE[$key]:-}"
  if [[ -z "$base" ]]; then
    printf '%-8s %-10s %12s %12s %10s %s\n' "$backend" "$case" "-" "$p50" "-" "NO-BASELINE"
    missing=$((missing + 1))
    continue
  fi
  delta="$(awk -v c="$p50" -v b="$base" 'BEGIN { if (b <= 0) print "0.0000"; else printf "%.4f", (c - b) / b }')"
  if awk -v c="$p50" -v b="$base" -v t="$THRESHOLD" 'BEGIN { exit !(c > b * (1 + t)) }'; then
    status="REGRESSION"
    regressions=$((regressions + 1))
  else
    status="ok"
  fi
  printf '%-8s %-10s %12.4f %12.4f %9.1f%% %s\n' \
    "$backend" "$case" "$base" "$p50" "$(awk -v d="$delta" 'BEGIN { print d * 100 }')" "$status"
done < <(jq -r '.rows[] | [.backend, .case, .p50_ms] | @tsv' "$CURRENT")

echo
if [[ "$regressions" -gt 0 ]]; then
  if [[ "$ENFORCE" == "1" ]]; then
    echo "gate: FAIL ($regressions regression(s) beyond +$(awk -v t="$THRESHOLD" 'BEGIN { printf "%.0f%%", t * 100 }') p50)"
    exit 1
  fi
  echo "gate: WOULD FAIL ($regressions regression(s)); not enforced (pass --enforce on a dedicated host)"
  exit 0
fi

if [[ "$missing" -gt 0 ]]; then
  echo "gate: PASS with $missing row(s) missing from the baseline"
else
  echo "gate: PASS"
fi
