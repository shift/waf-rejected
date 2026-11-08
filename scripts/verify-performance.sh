#!/usr/bin/env bash
# Reproducible post-merge performance verification.
#
# Runs the layered sub-millisecond budget harness, the engine regression gate,
# the CRS detection corpus for every backend, and (optionally) the feature
# matrix on a pinned host. Writes raw JSON/text artefacts plus a Markdown
# summary.
#
#   nix develop -c ./scripts/verify-performance.sh
#   nix develop -c ./scripts/verify-performance.sh --out target/perf-verify/run1
#   nix develop -c ./scripts/verify-performance.sh --cpus 0-3 --samples 50
#   nix develop -c ./scripts/verify-performance.sh --skip-build --with-matrix
#
# The host is recorded, never tuned: set the governor and turbo state yourself
# (see docs/operations/performance-verification.md) so the run stays observable.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

OUT=""
CPUS="${VERIFY_CPUS:-2-5}"
SAMPLES="${VERIFY_SAMPLES:-100}"
REQUESTS="${VERIFY_REQUESTS:-100}"
WARMUP="${VERIFY_WARMUP:-10}"
REPS="${VERIFY_REPS:-100}"
SKIP_BUILD=0
WITH_MATRIX=0
FAST=0

usage() {
  cat <<'EOF'
usage: scripts/verify-performance.sh [options]

  --out <dir>        artefact directory (default target/perf-verify/<utc>)
  --cpus <list>      taskset CPU list (default 2-5; "all" disables pinning)
  --samples <n>      samples per bench-subms/perf-gate row (default 100)
  --requests <n>     sequential proxy requests per L2/L3 row (default 100)
  --warmup <n>       warm-up iterations (default 10)
  --reps <n>         repetitions per Rust-engine latency row (default 100)
  --skip-build       reuse target/release binaries and target/native sidecar
  --with-matrix      also run scripts/ci-feature-matrix.sh --quick
  --fast             small sample counts for a smoke run
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
    --reps) REPS="${2:?--reps needs a number}"; shift 2 ;;
    --skip-build) SKIP_BUILD=1; shift ;;
    --with-matrix) WITH_MATRIX=1; shift ;;
    --fast) FAST=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ "$FAST" == "1" ]]; then
  SAMPLES=20
  REQUESTS=20
  WARMUP=5
  REPS=30
fi

OUT="${OUT:-$ROOT/target/perf-verify/$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "$OUT"
SOCKET="$OUT/coraza.sock"
SIDECAR_LOG="$OUT/sidecar.log"

if [[ -n "${IN_NIX_SHELL:-}" ]]; then
  DEV=()
else
  DEV=(nix develop -c)
fi

PIN=()
if [[ "$CPUS" == "all" ]]; then
  PIN=()
else
  command -v taskset >/dev/null 2>&1 || {
    echo "taskset not found; pass --cpus all to run unpinned" >&2
    exit 1
  }
  PIN=(taskset -c "$CPUS")
fi

# Run a command and record its peak RSS. GNU time is not in the Nix shell, so
# poll VmHWM; the kernel keeps the high-water mark, so a coarse interval is
# enough and the sampler stays off the measured cores.
run_tracked() {
  local rss_file="$1"
  shift
  "$@" &
  local pid=$!
  local peak=0
  while kill -0 "$pid" 2>/dev/null; do
    local value
    value="$(awk '/VmHWM:/ {print $2}' "/proc/$pid/status" 2>/dev/null || true)"
    if [[ -n "$value" ]]; then peak="$value"; fi
    sleep 0.2
  done
  wait "$pid"
  local status=$?
  printf '%s\n' "$peak" >"$rss_file"
  return "$status"
}

BENCH_SUBMS="$ROOT/target/release/bench-subms"
BODYLESS_BENCH="$ROOT/target/release/bodyless-bench"
PERF_GATE="$ROOT/target/release/perf-gate-bench"
RUST_PARITY="$ROOT/target/release/rust-engine-parity"
CRS_CORPUS="$ROOT/target/release/crs_corpus"
SIDECAR="$ROOT/target/native/coraza-sidecar"

# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------
CPU_MODEL="$(lscpu 2>/dev/null | awk -F: '/Model name/ {gsub(/^ +| +$/, "", $2); print $2; exit}')"
GOVERNOR="$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo unknown)"
CUR_FREQ_KHZ="$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq 2>/dev/null || echo 0)"
TURBO="$(cat /sys/devices/system/cpu/intel_pstate/no_turbo 2>/dev/null || echo unknown)"
LOADAVG="$(awk '{print $1" "$2" "$3}' /proc/loadavg 2>/dev/null || echo unknown)"
COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
DIRTY="$(git status --porcelain 2>/dev/null | wc -l | tr -d ' ')"
STARTED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

echo "== environment =="
echo "host:      $(uname -srm)"
echo "cpu:       ${CPU_MODEL:-unknown} ($(nproc) logical)"
echo "affinity:  $CPUS"
echo "governor:  $GOVERNOR  turbo_disabled: $TURBO  cpu0_freq: $((CUR_FREQ_KHZ / 1000)) MHz"
echo "loadavg:   $LOADAVG"
echo "commit:    $COMMIT (dirty files: $DIRTY)"
echo "artefacts: $OUT"
echo

if awk -v l="${LOADAVG%% *}" 'BEGIN { exit !(l > 1.0) }'; then
  echo "warning: 1-minute load average is ${LOADAVG%% *}; timings will be noisy." >&2
  echo "         Stop background builds/tests before recording a baseline." >&2
fi

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
if [[ "$SKIP_BUILD" != "1" ]]; then
  echo "== build =="
  "${DEV[@]}" cargo build --release --locked \
    --features wasm-reactor,coraza-native --bin bench-subms --bin bodyless-bench
  "${DEV[@]}" cargo build --release --locked \
    --features wasm-reactor,coraza-native,native-engine,rust-engine,engine-kernel,fastpath \
    --bin crs_corpus --bin rust-engine-parity --bin perf-gate-bench
  if [[ ! -x "$SIDECAR" ]] || ! command -v go >/dev/null 2>&1; then
    echo "building native Coraza sidecar"
    "${DEV[@]}" "$ROOT/scripts/build-coraza-sidecar.sh" "$SIDECAR"
  fi
  echo
fi

for bin in "$BENCH_SUBMS" "$BODYLESS_BENCH" "$PERF_GATE" "$RUST_PARITY" "$CRS_CORPUS"; do
  [[ -x "$bin" ]] || { echo "missing $bin (run without --skip-build)" >&2; exit 1; }
done

# ---------------------------------------------------------------------------
# Sidecar
# ---------------------------------------------------------------------------
sidecar_pid=""
cleanup() {
  if [[ -n "$sidecar_pid" ]]; then
    kill "$sidecar_pid" 2>/dev/null || true
    wait "$sidecar_pid" 2>/dev/null || true
  fi
}
trap cleanup EXIT

if [[ -x "$SIDECAR" ]]; then
  rm -f "$SOCKET"
  "${PIN[@]}" "$SIDECAR" \
    --socket "$SOCKET" \
    --rules "$ROOT/wasm/coraza_reactor/rules/crs/crs.conf" \
    --max-body 65536 --max-headers 100 --max-header-bytes 65536 \
    --max-conns 128 --timeout 120s --grace 10s \
    >"$SIDECAR_LOG" 2>&1 &
  sidecar_pid=$!
  for _ in $(seq 1 200); do
    if "$SIDECAR" --probe --socket "$SOCKET" >/dev/null 2>&1; then
      break
    fi
    kill -0 "$sidecar_pid" 2>/dev/null || {
      echo "sidecar exited before readiness; see $SIDECAR_LOG" >&2
      exit 1
    }
    sleep 0.1
  done
  echo "sidecar ready (pid $sidecar_pid)"
else
  echo "warning: no native sidecar binary; native rows will be skipped" >&2
fi

# ---------------------------------------------------------------------------
# 1. Layered budget: wasm + native sidecar, bodyless/1/4/8 KiB
# ---------------------------------------------------------------------------
echo
echo "== bench-subms =="
SUBMS_ARGS=(--samples "$SAMPLES" --requests "$REQUESTS" --warmup "$WARMUP"
            --json-out "$OUT/bench-subms.json")
if [[ -n "$sidecar_pid" ]]; then
  SUBMS_ARGS+=(--native-socket "$SOCKET")
fi
run_tracked "$OUT/bench-subms.rss" \
  "${PIN[@]}" "$BENCH_SUBMS" "${SUBMS_ARGS[@]}" >"$OUT/bench-subms.txt" 2>&1

# ---------------------------------------------------------------------------
# 2. Engine regression gate: coraza / rust / kernel, own process each
# ---------------------------------------------------------------------------
echo
echo "== perf-gate =="
PERF_GATE_CPUS="$CPUS" "${DEV[@]}" "$ROOT/benchmarks/perf-gate/run.sh" \
  --skip-build --samples "$SAMPLES" --warmup "$WARMUP" --alloc-reps "$SAMPLES" \
  --out "$OUT/perf-gate.json" >"$OUT/perf-gate.txt" 2>&1 || {
    echo "perf-gate failed; see $OUT/perf-gate.txt" >&2
  }

# ---------------------------------------------------------------------------
# 3. Component profile and fast-path timings
# ---------------------------------------------------------------------------
echo
echo "== bodyless-bench =="
"${PIN[@]}" "$BODYLESS_BENCH" --profile --samples 5000 --warmup 1000 \
  >"$OUT/bodyless-bench.txt" 2>&1 || true

# ---------------------------------------------------------------------------
# 4. Rust engine latency table: bodyless/1/4/8 KiB vs Coraza reactor
# ---------------------------------------------------------------------------
echo
echo "== rust-engine-parity --bench =="
"${PIN[@]}" "$RUST_PARITY" --bench --reps "$REPS" \
  >"$OUT/rust-engine-bench.txt" 2>&1 || true

# ---------------------------------------------------------------------------
# 5. Full 2,112-case CRS corpus: wasm, native sidecar, rust engine
# ---------------------------------------------------------------------------
echo
echo "== CRS corpus =="
"${DEV[@]}" "$CRS_CORPUS" --engine wasm --json "$OUT/corpus-wasm.json" \
  >"$OUT/corpus-wasm.txt" 2>&1 || echo "wasm corpus failed" >&2

if [[ -n "$sidecar_pid" ]]; then
  "${DEV[@]}" "$CRS_CORPUS" --engine native --native-socket "$SOCKET" \
    --json "$OUT/corpus-native.json" >"$OUT/corpus-native.txt" 2>&1 || \
    echo "native corpus failed" >&2
  "${DEV[@]}" "$CRS_CORPUS" --engine both --native-socket "$SOCKET" \
    --json "$OUT/corpus-parity.json" >"$OUT/corpus-parity.txt" 2>&1 || \
    echo "wasm/native parity failed" >&2
fi

"${DEV[@]}" "$CRS_CORPUS" --engine rust --require-engine \
  --json "$OUT/corpus-rust.json" >"$OUT/corpus-rust.txt" 2>&1 || \
  echo "rust corpus failed" >&2

"${DEV[@]}" "$RUST_PARITY" --engine both --json "$OUT/rust-parity.json" \
  >"$OUT/rust-parity.txt" 2>&1 || echo "rust parity failed" >&2

# ---------------------------------------------------------------------------
# 6. Optional feature matrix
# ---------------------------------------------------------------------------
MATRIX_STATUS="skipped"
MATRIX_SECONDS=0
if [[ "$WITH_MATRIX" == "1" ]]; then
  echo
  echo "== feature matrix (quick) =="
  matrix_start=$SECONDS
  if "${DEV[@]}" "$ROOT/scripts/ci-feature-matrix.sh" --quick \
      >"$OUT/feature-matrix.txt" 2>&1; then
    MATRIX_STATUS="pass"
  else
    MATRIX_STATUS="fail"
  fi
  MATRIX_SECONDS=$((SECONDS - matrix_start))
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
SIDECAR_RSS="null"
if [[ -n "$sidecar_pid" ]] && [[ -r "/proc/$sidecar_pid/status" ]]; then
  SIDECAR_RSS="$(awk '/VmHWM:/ {print $2}' "/proc/$sidecar_pid/status" 2>/dev/null || echo null)"
fi

jq -n \
  --arg generated "$STARTED" \
  --arg commit "$COMMIT" \
  --arg dirty "$DIRTY" \
  --arg host "$(uname -srm)" \
  --arg cpu_model "$CPU_MODEL" \
  --arg cpu_count "$(nproc)" \
  --arg cpus "$CPUS" \
  --arg governor "$GOVERNOR" \
  --arg turbo "$TURBO" \
  --arg cpu0_freq_mhz "$((CUR_FREQ_KHZ / 1000))" \
  --arg loadavg "$LOADAVG" \
  --argjson samples "$SAMPLES" \
  --argjson requests "$REQUESTS" \
  --argjson warmup "$WARMUP" \
  --argjson reps "$REPS" \
  --argjson sidecar_rss_kb "${SIDECAR_RSS:-null}" \
  --arg matrix_status "$MATRIX_STATUS" \
  --argjson matrix_seconds "$MATRIX_SECONDS" \
  '{
    schema: 1,
    generated_at: $generated,
    commit: $commit,
    dirty_files: ($dirty | tonumber),
    environment: {
      host: $host, cpu_model: $cpu_model, cpu_count: $cpu_count,
      cpu_affinity: $cpus, scaling_governor: $governor,
      turbo_disabled: $turbo, cpu0_freq_mhz: $cpu0_freq_mhz,
      loadavg_at_start: $loadavg
    },
    settings: {samples: $samples, requests: $requests, warmup: $warmup, reps: $reps},
    sidecar_rss_peak_kb: $sidecar_rss_kb,
    feature_matrix: {status: $matrix_status, seconds: $matrix_seconds}
  }' >"$OUT/environment.json"

# Copy the layer rows next to the environment block for a single-file summary.
jq -s '.[0] * {bench_subms: .[1], perf_gate: (.[2] // null)}' \
  "$OUT/environment.json" "$OUT/bench-subms.json" "$OUT/perf-gate.json" \
  >"$OUT/summary.json" 2>/dev/null || cp "$OUT/environment.json" "$OUT/summary.json"

{
  echo "# Performance verification — $COMMIT"
  echo
  echo "* generated: $STARTED UTC"
  echo "* host: ${CPU_MODEL:-unknown}, $(nproc) logical CPUs, affinity \`$CPUS\`, governor \`$GOVERNOR\`, turbo_disabled \`$TURBO\`"
  echo "* cpu0 frequency at start: $((CUR_FREQ_KHZ / 1000)) MHz; loadavg: \`$LOADAVG\`; dirty files: $DIRTY"
  echo "* bench-subms peak RSS: $(cat "$OUT/bench-subms.rss" 2>/dev/null || echo unknown) kB; sidecar peak RSS: ${SIDECAR_RSS:-unknown} kB"
  echo "* samples/requests/warmup: $SAMPLES/$REQUESTS/$WARMUP"
  echo
  echo "## Layered budget (bench-subms)"
  echo
  echo "| layer | backend | size | p50 ms | p95 ms | p99 ms | allocs/op | alloc B/op | non-200 |"
  echo "|---|---|---|---:|---:|---:|---:|---:|---:|"
  jq -r '.rows[] | "| \(.layer) | \(.backend) | \(.size) | \(.p50_ms) | \(.p95_ms) | \(.p99_ms) | \(.allocs_per_op // "-") | \(.alloc_bytes_per_op // "-") | \(.non_200) |"' \
    "$OUT/bench-subms.json" 2>/dev/null || true
  echo
  echo "## Engine gate (perf-gate, process CPU time)"
  echo
  echo "| backend | case | p50 ms | p95 ms | p99 ms | throughput rps | allocs/op |"
  echo "|---|---|---:|---:|---:|---:|---:|"
  jq -r '(.rows // [])[] | "| \(.backend) | \(.case) | \(.p50_ms) | \(.p95_ms) | \(.p99_ms) | \(.throughput_rps) | \(.allocs_per_op) |"' \
    "$OUT/perf-gate.json" 2>/dev/null || true
  echo
  echo "Process peak RSS (perf-gate):"
  jq -r '(.process // {}) | to_entries[] | "- \(.key): \(.value.rss_peak_kb) KiB"' \
    "$OUT/perf-gate.json" 2>/dev/null || true
  echo
  echo "## CRS corpus"
  echo
  for engine in wasm native rust; do
    file="$OUT/corpus-$engine.json"
    [[ -f "$file" ]] || continue
    jq -r --arg e "$engine" '.engines[$e] | "- \($e): total=\(.total) passed=\(.passed) false_negatives=\(.false_negatives) false_positives=\(.false_positives) errors=\(.errors) detection_rate=\(.detection_rate)"' \
      "$file" 2>/dev/null || true
  done
  if [[ -f "$OUT/corpus-parity.json" ]]; then
    jq -r '.parity | "- wasm/native parity: agree=\(.agree) disagree=\(.disagree) unsupported=\(.unsupported)"' \
      "$OUT/corpus-parity.json" 2>/dev/null || true
  fi
  if [[ -f "$OUT/rust-parity.json" ]]; then
    jq -r '"- rust/coraza parity: agree=\(.agree) disagree=\(.disagree) rust_false_negatives=\(.rust_false_negatives) coraza_false_negatives=\(.coraza_false_negatives)"' \
      "$OUT/rust-parity.json" 2>/dev/null || true
  fi
  echo
  echo "## Feature matrix"
  echo
  echo "* status: $MATRIX_STATUS, wall time: ${MATRIX_SECONDS}s"
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
