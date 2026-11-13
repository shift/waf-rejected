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
declare -A CURP
while IFS=$'\t' read -r backend case p50; do
  CURP["$backend/$case"]="$p50"
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

# A CPU-frequency or host-load change scales every row together, so the
# absolute p50 check alone cannot tell an attack-path regression from a slower
# clock. Compare `4k-sqli / 4k-allow` in the same run: that ratio cancels the
# clock and isolates the attack/scoring path. A regression is a ratio above the
# baseline ratio (or 1.0 when the baseline was already faster on attack input)
# by more than the threshold.
echo
printf '%-8s %14s %14s %10s %s\n' backend baseline_ratio current_ratio delta status
printf '%-8s %14s %14s %10s %s\n' -------- -------------- ------------- ---------- ------
declare -A SEEN_BACKEND
ratio_regressions=0
for key in "${!CURP[@]}"; do
  backend="${key%%/*}"
  [[ -n "${SEEN_BACKEND[$backend]:-}" ]] && continue
  SEEN_BACKEND["$backend"]=1

  base_allow="${BASE[$backend/4k-allow]:-}"
  base_sqli="${BASE[$backend/4k-sqli]:-}"
  cur_allow="${CURP[$backend/4k-allow]:-}"
  cur_sqli="${CURP[$backend/4k-sqli]:-}"
  [[ -n "$base_allow" && -n "$base_sqli" && -n "$cur_allow" && -n "$cur_sqli" ]] || continue

  base_ratio="$(awk -v s="$base_sqli" -v a="$base_allow" 'BEGIN { if (a <= 0) print 0; else printf "%.4f", s / a }')"
  cur_ratio="$(awk -v s="$cur_sqli" -v a="$cur_allow" 'BEGIN { if (a <= 0) print 0; else printf "%.4f", s / a }')"
  limit="$(awk -v b="$base_ratio" -v t="$THRESHOLD" 'BEGIN { if (b < 1) b = 1; printf "%.6f", b * (1 + t) }')"

  status="ok"
  if awk -v c="$cur_ratio" -v l="$limit" 'BEGIN { exit !(c > l) }'; then
    status="REGRESSION"
    ratio_regressions=$((ratio_regressions + 1))
  fi
  printf '%-8s %14.4f %14.4f %9.1f%% %s\n' \
    "$backend" "$base_ratio" "$cur_ratio" \
    "$(awk -v c="$cur_ratio" -v b="$base_ratio" 'BEGIN { if (b <= 0) print 0; else printf "%.2f", (c - b) / b * 100 }')" \
    "$status"
done

echo
if [[ "$regressions" -gt 0 || "$ratio_regressions" -gt 0 ]]; then
  if [[ "$ENFORCE" == "1" ]]; then
    echo "gate: FAIL ($regressions p50 row(s), $ratio_regressions attack-ratio row(s) beyond +$(awk -v t="$THRESHOLD" 'BEGIN { printf "%.0f%%", t * 100 }'))"
    exit 1
  fi
  echo "gate: WOULD FAIL ($regressions p50 row(s), $ratio_regressions attack-ratio row(s)); not enforced (pass --enforce on a dedicated host)"
  exit 0
fi

if [[ "$missing" -gt 0 ]]; then
  echo "gate: PASS with $missing row(s) missing from the baseline"
else
  echo "gate: PASS"
fi
