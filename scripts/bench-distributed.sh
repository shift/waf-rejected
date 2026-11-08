#!/usr/bin/env bash
# Distributed fabric hot-path benchmark.
#
# Measures the real proxy over loopback (L2 proxy floor and L3 Rust-engine
# WAF) with the `distri-kv` feature compiled but the controller:
#
#   1. disabled (`waf.distributed.enabled = false`),
#   2. enabled with `fallback = "local_only"` and a refused endpoint,
#   3. enabled with a TCP endpoint that accepts and never speaks HTTP/2,
#      keeping a control-plane RPC in flight for the whole run.
#
# It also runs the request-side policy/reputation cache microbenchmark and
# writes JSON plus a Markdown summary. The endpoint is deliberately broken:
# the point is to prove the request path never waits on it.
#
#   nix develop -c ./scripts/bench-distributed.sh
#   nix develop -c ./scripts/bench-distributed.sh --quick
#   nix develop -c ./scripts/bench-distributed.sh --skip-build --cpus all
#
# See docs/operations/distributed-performance.md.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

OUT="${OUT:-$ROOT/target/bench-distributed/$(date -u +%Y%m%dT%H%M%SZ)}"
CPUS="${BENCH_CPUS:-2-3}"
SAMPLES="${BENCH_SAMPLES:-200}"
REQUESTS="${BENCH_REQUESTS:-200}"
WARMUP="${BENCH_WARMUP:-20}"
CONCURRENCY="${BENCH_CONCURRENCY:-16}"
PER_WORKER="${BENCH_PER_WORKER:-30}"
REPS="${BENCH_REPS:-3}"
SKIP_BUILD=0
BLACKHOLE=1
BASELINE=1

usage() {
  cat <<'EOF'
usage: scripts/bench-distributed.sh [options]

  --out <dir>        artefact directory (default target/bench-distributed/<utc>)
  --cpus <list>      taskset CPU list (default 2-3; "all" disables pinning)
  --samples <n>      timed samples per sequential cell (default 200)
  --requests <n>     sequential requests per cell (default 200)
  --warmup <n>       warm-up requests per cell (default 20)
  --concurrency <n>  closed-loop workers for the throughput cell (default 16)
  --per-worker <n>   requests per worker (default 30)
  --reps <n>         repetitions per scenario; the summary takes the median run (default 3)
  --skip-build       reuse target/release binaries
  --no-baseline      skip the build-without-distri-kv baseline scenario
  --no-blackhole     skip the accepted-but-silent endpoint scenario
  --quick            small sample counts for a smoke run
  -h, --help         this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --out) OUT="${2:?--out needs a path}"; shift 2 ;;
    --cpus) CPUS="${2:?--cpus needs a list}"; shift 2 ;;
    --samples) SAMPLES="${2:?--samples needs a number}"; shift 2 ;;
    --requests) REQUESTS="${2:?--requests needs a number}"; shift 2 ;;
    --warmup) WARMUP="${2:?--warmup needs a number}"; shift 2 ;;
    --concurrency) CONCURRENCY="${2:?--concurrency needs a number}"; shift 2 ;;
    --per-worker) PER_WORKER="${2:?--per-worker needs a number}"; shift 2 ;;
    --reps) REPS="${2:?--reps needs a number}"; shift 2 ;;
    --skip-build) SKIP_BUILD=1; shift ;;
    --no-baseline) BASELINE=0; shift ;;
    --no-blackhole) BLACKHOLE=0; shift ;;
    --quick) SAMPLES=40; REQUESTS=40; WARMUP=5; CONCURRENCY=8; PER_WORKER=10; REPS=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

mkdir -p "$OUT"

if [[ -n "${IN_NIX_SHELL:-}" ]]; then
  DEV=()
else
  DEV=(nix develop -c)
fi

PIN=()
if [[ "$CPUS" != "all" ]]; then
  command -v taskset >/dev/null 2>&1 || {
    echo "taskset not found; pass --cpus all to run unpinned" >&2
    exit 1
  }
  PIN=(taskset -c "$CPUS")
fi

BENCH="$ROOT/target/release/bench-subms"
BENCH_NOFEATURE="$ROOT/target/release/bench-subms-nofeature"
CACHE_BENCH="$ROOT/target/release/distributed-cache-bench"

if [[ "$SKIP_BUILD" != "1" ]]; then
  if [[ "$BASELINE" == "1" ]]; then
    echo "== build (no distri-kv baseline) =="
    "${DEV[@]}" cargo build --release --locked --features coraza-native --bin bench-subms
    cp "$BENCH" "$BENCH_NOFEATURE"
  fi
  echo "== build (distri-kv) =="
  "${DEV[@]}" cargo build --release --locked --features distri-kv,coraza-native \
    --bin bench-subms --bin distributed-cache-bench
fi

for bin in "$BENCH" "$CACHE_BENCH"; do
  [[ -x "$bin" ]] || { echo "missing $bin (run without --skip-build)" >&2; exit 1; }
done
if [[ "$BASELINE" == "1" && ! -x "$BENCH_NOFEATURE" ]]; then
  echo "warning: baseline binary missing; run without --skip-build or pass --no-baseline" >&2
  BASELINE=0
fi

BLACKHOLE_PID=""
cleanup() {
  if [[ -n "$BLACKHOLE_PID" ]]; then
    kill "$BLACKHOLE_PID" 2>/dev/null || true
    wait "$BLACKHOLE_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

BLACKHOLE_PORT=""
if [[ "$BLACKHOLE" == "1" ]] && command -v python3 >/dev/null 2>&1; then
  python3 - "$OUT/blackhole.port" <<'PY' &
import socket
import sys

sock = socket.socket()
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(("127.0.0.1", 0))
sock.listen(64)
with open(sys.argv[1], "w", encoding="ascii") as handle:
    handle.write(str(sock.getsockname()[1]))
    handle.flush()
held = []
while True:
    conn, _ = sock.accept()
    held.append(conn)
PY
  BLACKHOLE_PID=$!
  for _ in $(seq 1 100); do
    [[ -s "$OUT/blackhole.port" ]] && break
    sleep 0.05
  done
  BLACKHOLE_PORT="$(cat "$OUT/blackhole.port" 2>/dev/null || true)"
  if [[ -z "$BLACKHOLE_PORT" ]]; then
    echo "warning: blackhole listener did not start; skipping that scenario" >&2
    BLACKHOLE=0
  fi
fi

COMMON=(--only l2,l3 --no-wasm --samples "$SAMPLES" --requests "$REQUESTS"
        --warmup "$WARMUP" --concurrency "$CONCURRENCY" --per-worker "$PER_WORKER")

run_scenario() {
  local name="$1"
  local rep="$2"
  shift 2
  local bin="$BENCH"
  if [[ "$name" == "no-feature" ]]; then
    bin="$BENCH_NOFEATURE"
  fi
  echo "== $name (rep $rep/$REPS) =="
  "${PIN[@]}" "$bin" "${COMMON[@]}" --json-out "$OUT/$name.r$rep.json" "$@" \
    >"$OUT/$name.r$rep.txt" 2>&1
  echo "   $(grep -E 'process CPU time' "$OUT/$name.r$rep.txt" | tr '\n' ' ')"
}

for rep in $(seq 1 "$REPS"); do
  if [[ "$BASELINE" == "1" ]]; then
    run_scenario no-feature "$rep"
  fi
  run_scenario disabled "$rep"
  run_scenario enabled-refused "$rep" --distributed \
    --distributed-endpoint http://127.0.0.1:1
  if [[ "$BLACKHOLE" == "1" ]]; then
    run_scenario enabled-blackhole "$rep" --distributed \
      --distributed-endpoint "http://127.0.0.1:$BLACKHOLE_PORT"
  fi
done

echo "== cache microbenchmark =="
"${PIN[@]}" "$CACHE_BENCH" --json-out "$OUT/cache.json" \
  >"$OUT/cache.txt" 2>&1

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
CPU_MODEL="$(lscpu 2>/dev/null | awk -F: '/Model name/ {gsub(/^ +| +$/, "", $2); print $2; exit}')"
{
  echo "# Distributed hot-path benchmark — $COMMIT"
  echo
  echo "* host: ${CPU_MODEL:-unknown}, $(nproc) logical CPUs, affinity \`$CPUS\`"
  echo "* settings: samples=$SAMPLES requests=$REQUESTS warmup=$WARMUP c=$CONCURRENCY×$PER_WORKER reps=$REPS"
  echo "* scenarios: without the feature; feature compiled but disabled; enabled + local_only + refused endpoint; enabled + local_only + silent endpoint"
  echo

  for table in sequential concurrent; do
    echo "## L3 Rust WAF — $table (median rep of $REPS)"
    echo
    if [[ "$table" == "sequential" ]]; then
      echo "| scenario | size | p50 ms | p95 ms | p99 ms | allocs/op | alloc B/op | non-200 |"
      echo "|---|---|---:|---:|---:|---:|---:|---:|"
      condition='.throughput_rps == null'
      columns='| \($scenario) | \(.size) | \(.p50_ms) | \(.p95_ms) | \(.p99_ms) | \(.allocs_per_op // "-") | \(.alloc_bytes_per_op // "-") | \(.non_200) |'
    else
      echo "| scenario | size | p50 ms | p95 ms | p99 ms | throughput req/s | non-200 |"
      echo "|---|---|---:|---:|---:|---:|---:|"
      condition='.throughput_rps != null'
      columns='| \($scenario) | \(.size) | \(.p50_ms) | \(.p95_ms) | \(.p99_ms) | \(.throughput_rps | floor) | \(.non_200) |'
    fi
    for name in no-feature disabled enabled-refused enabled-blackhole; do
      files=("$OUT/$name".r*.json)
      [[ -e "${files[0]}" ]] || continue
      jq -s -r --arg scenario "$name" "
        [.[].rows[] | select(.layer == \"L3-proxy\" and .backend == \"rust\" and $condition)]
        | group_by(.size)
        | map(sort_by(.p50_ms)[length/2|floor])
        | sort_by(.size | if . == \"bodyless\" then 0 elif . == \"1 KiB\" then 1 elif . == \"4 KiB\" then 2 else 3 end)
        | .[]
        | \"$columns\"" \
        "${files[@]}"
    done
    echo
  done

  echo "## Process CPU (whole bench run, median of $REPS)"
  echo
  echo "| scenario | CPU ms |"
  echo "|---|---:|"
  for name in no-feature disabled enabled-refused enabled-blackhole; do
    files=("$OUT/$name".r*.json)
    [[ -e "${files[0]}" ]] || continue
    jq -s -r --arg scenario "$name" \
      '"| \($scenario) | \(map(.process_cpu_ms) | sort | .[length/2|floor] | floor) |"' \
      "${files[@]}"
  done
  echo

  echo "## Request-side cache"
  echo
  echo "| operation | median ns/op | p99 ns/op |"
  echo "|---|---:|---:|"
  jq -r '.rows[] | "| \(.operation) | \(.ns_per_op | . * 10 | round / 10) | \(.p99_ns | . * 10 | round / 10) |"' \
    "$OUT/cache.json" 2>/dev/null || true
  echo
  echo "## Artefacts"
  echo
  echo '```'
  ls -1 "$OUT"
  echo '```'
} >"$OUT/summary.md"

echo
echo "artefacts: $OUT"
echo "summary:   $OUT/summary.md"
