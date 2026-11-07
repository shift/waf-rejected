#!/usr/bin/env bash
# Reproducible engine-level performance run for the WAF regression gate.
#
# Runs the Coraza WASI reactor, the native Rust CRS engine and the experimental
# native kernel in separate processes so RSS is attributable, pins the CPU
# affinity mask, records hardware/kernel/toolchain versions and merges the three
# reports into one JSON document under benchmarks/perf-gate/results/.
#
#   nix develop -c ./benchmarks/perf-gate/run.sh
#   nix develop -c ./benchmarks/perf-gate/run.sh --samples 100 --warmup 10
#   nix develop -c PERF_GATE_CPUS=0-3 ./benchmarks/perf-gate/run.sh --out /tmp/run.json
#
# Everything after `--` is forwarded to the benchmark binary. Run on a quiet
# host with a fixed governor and turbo disabled for comparable absolute values.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

OUT=""
SAMPLES=50
WARMUP=5
ALLOC_REPS=50
CPUS="${PERF_GATE_CPUS:-2-5}"
SKIP_BUILD=0
FORWARD=()

usage() {
  cat <<'EOF'
usage: benchmarks/perf-gate/run.sh [options] [-- <bench args>]

  --out <path>       report path (default benchmarks/perf-gate/results/<utc>.json)
  --samples <n>      timed samples per case (default 50)
  --warmup <n>       warm-up iterations per case (default 5)
  --alloc-reps <n>   iterations for the allocation counter (default 50)
  --skip-build       reuse target/release/perf-gate-bench
  -h, --help         this help

Environment:
  PERF_GATE_CPUS     taskset CPU list (default 2-5; set to "all" to skip pinning)
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --out) OUT="${2:?--out needs a path}"; shift 2 ;;
    --samples) SAMPLES="${2:?--samples needs a number}"; shift 2 ;;
    --warmup) WARMUP="${2:?--warmup needs a number}"; shift 2 ;;
    --alloc-reps) ALLOC_REPS="${2:?--alloc-reps needs a number}"; shift 2 ;;
    --skip-build) SKIP_BUILD=1; shift ;;
    -h|--help) usage; exit 0 ;;
    --) shift; FORWARD=("$@"); break ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ -n "${IN_NIX_SHELL:-}" ]]; then
  DEV=()
else
  DEV=(nix develop -c)
fi

PIN=()
if [[ "$CPUS" != "all" ]]; then
  if ! command -v taskset >/dev/null 2>&1; then
    echo "taskset not found; set PERF_GATE_CPUS=all to run unpinned" >&2
    exit 1
  fi
  PIN=(taskset -c "$CPUS")
fi

BIN="$ROOT/target/release/perf-gate-bench"
if [[ "$SKIP_BUILD" != "1" ]]; then
  echo "== build =="
  "${DEV[@]}" cargo build --release \
    --features wasm-reactor,rust-engine,engine-kernel \
    --bin perf-gate-bench
fi
[[ -x "$BIN" ]] || { echo "missing $BIN (run without --skip-build)" >&2; exit 1; }

if [[ -z "$OUT" ]]; then
  mkdir -p "$ROOT/benchmarks/perf-gate/results"
  OUT="$ROOT/benchmarks/perf-gate/results/perf-gate-$(date -u +%Y%m%dT%H%M%SZ).json"
fi
mkdir -p "$(dirname "$OUT")"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/perf-gate.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

echo "== environment =="
HOST="$(uname -srm)"
KERNEL="$(uname -r)"
CPU_MODEL="$(lscpu 2>/dev/null | awk -F: '/Model name/ {gsub(/^ +| +$/, "", $2); print $2; exit}')"
CPU_COUNT="$(nproc 2>/dev/null || echo unknown)"
GOVERNOR="$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo unknown)"
TURBO="$(cat /sys/devices/system/cpu/intel_pstate/no_turbo 2>/dev/null || echo unknown)"
LOADAVG="$(awk '{print $1" "$2" "$3}' /proc/loadavg 2>/dev/null || echo unknown)"
RUSTC="$(rustc --version 2>/dev/null || echo unavailable)"
CARGO="$(cargo --version 2>/dev/null || echo unavailable)"
NIX="$(nix --version 2>/dev/null || echo unavailable)"
COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
DIRTY="$(git status --porcelain 2>/dev/null | wc -l | tr -d ' ')"
GENERATED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "host:       $HOST"
echo "cpu:        ${CPU_MODEL:-unknown} (${CPU_COUNT} logical)"
echo "affinity:   $CPUS"
echo "governor:   $GOVERNOR  turbo_disabled: $TURBO  loadavg: $LOADAVG"
echo "toolchain:  $RUSTC | $CARGO | $NIX"
echo "commit:     $COMMIT (dirty files: $DIRTY)"
echo

run_backend() {
  local backend="$1"
  echo "== $backend =="
  "${PIN[@]}" "$BIN" \
    --only "$backend" \
    --samples "$SAMPLES" \
    --warmup "$WARMUP" \
    --alloc-reps "$ALLOC_REPS" \
    --json-out "$TMP/$backend.json" \
    "${FORWARD[@]}" >/dev/null
}

run_backend coraza
run_backend rust
run_backend kernel

jq -s \
  --arg generated "$GENERATED" \
  --arg commit "$COMMIT" \
  --arg dirty "$DIRTY" \
  --arg host "$HOST" \
  --arg kernel "$KERNEL" \
  --arg cpu_model "$CPU_MODEL" \
  --arg cpu_count "$CPU_COUNT" \
  --arg governor "$GOVERNOR" \
  --arg turbo "$TURBO" \
  --arg loadavg "$LOADAVG" \
  --arg rustc "$RUSTC" \
  --arg cargo "$CARGO" \
  --arg nix "$NIX" \
  --arg cpus "$CPUS" \
  --argjson samples "$SAMPLES" \
  --argjson warmup "$WARMUP" \
  --argjson alloc_reps "$ALLOC_REPS" \
  '
  {
    schema: 1,
    generated_at: $generated,
    commit: $commit,
    dirty_files: ($dirty | tonumber),
    environment: {
      host: $host,
      kernel: $kernel,
      cpu_model: $cpu_model,
      cpu_count: $cpu_count,
      cpu_affinity: $cpus,
      scaling_governor: $governor,
      turbo_disabled: $turbo,
      loadavg_at_start: $loadavg,
      rustc: $rustc,
      cargo: $cargo,
      nix: $nix
    },
    settings: {
      samples: $samples,
      warmup: $warmup,
      alloc_reps: $alloc_reps,
      cases: ["bodyless", "4k-allow", "4k-sqli"],
      latency_metric: "process CPU time (CLOCK_PROCESS_CPUTIME_ID)",
      throughput_metric: "wall-clock samples per second",
      coraza_scope: "WasmReactor::evaluate on a prebuilt JSON payload; payload construction excluded"
    },
    process: (map({(.backend): .meta}) | add),
    rows: (map(.rows[]) | sort_by(.backend, .case))
  }
  ' "$TMP/coraza.json" "$TMP/rust.json" "$TMP/kernel.json" >"$OUT"

echo "wrote $OUT"
