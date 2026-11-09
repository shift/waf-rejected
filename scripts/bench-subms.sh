#!/usr/bin/env bash
# Layered sub-millisecond WAF budget benchmark.
#
# Builds the release benchmark (and, by default, the native Coraza sidecar),
# starts the sidecar on a private Unix socket, runs the in-process loopback
# harness and writes a JSON report. No external network is used.
#
#   nix develop -c ./scripts/bench-subms.sh
#   nix develop -c ./scripts/bench-subms.sh --no-native -- --samples 30
#   nix develop -c ./scripts/bench-subms.sh --pin 2-5 -- --requests 200
#
# Everything after `--` is passed to the benchmark binary. See
# docs/operations/subms-budget.md for the layer model and the gates.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

STATE_DIR="${STATE_DIR:-/tmp/opencode/bench-subms}"
SOCKET="$STATE_DIR/coraza.sock"
SIDECAR_BIN="$ROOT/target/native/coraza-sidecar"
BENCH_BIN="$ROOT/target/release/bench-subms"
REPORT="$ROOT/target/bench-subms/report.json"

RUN_NATIVE=1
SKIP_BUILD=0
PIN_CPUS=""
PASSTHROUGH=()

usage() {
  cat <<'EOF'
usage: scripts/bench-subms.sh [options] [-- <bench-subms args>]

  --no-native       skip the native sidecar rows
  --skip-build      use existing target/release/bench-subms and sidecar
  --pin <cpulist>   taskset CPU list for the sidecar and benchmark (e.g. 2-5)
  --socket <path>   sidecar socket path (default /tmp/opencode/bench-subms)
  -h, --help        this help

Benchmark options after `--` include --samples, --requests, --warmup,
--concurrency, --per-worker, --only and --json-out.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-native) RUN_NATIVE=0; shift ;;
    --skip-build) SKIP_BUILD=1; shift ;;
    --pin)
      PIN_CPUS="${2:?--pin needs a CPU list}"
      shift 2
      ;;
    --socket)
      SOCKET="${2:?--socket needs a path}"
      shift 2
      ;;
    -h|--help) usage; exit 0 ;;
    --) shift; PASSTHROUGH=("$@"); break ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

mkdir -p "$STATE_DIR" "$(dirname "$REPORT")"

# Prefer the active development shell; fall back to `nix develop -c` so the
# script also works from a plain shell.
if [[ -n "${IN_NIX_SHELL:-}" ]]; then
  DEV=()
else
  DEV=(nix develop -c)
fi

PIN=()
if [[ -n "$PIN_CPUS" ]]; then
  if ! command -v taskset >/dev/null 2>&1; then
    echo "taskset is not available; ignoring --pin" >&2
  else
    PIN=(taskset -c "$PIN_CPUS")
  fi
fi

echo "== host =="
uname -srm
if command -v lscpu >/dev/null 2>&1; then
  lscpu | grep -E 'Model name|CPU\(s\)|MHz' || true
fi
if [[ -r /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor ]]; then
  echo "governor: $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor)"
fi
if [[ -r /sys/devices/system/cpu/intel_pstate/no_turbo ]]; then
  echo "turbo disabled: $(cat /sys/devices/system/cpu/intel_pstate/no_turbo)"
fi
grep -m1 'cpu MHz' /proc/cpuinfo || true
echo

if [[ "$SKIP_BUILD" != "1" ]]; then
  echo "== build =="
  "${DEV[@]}" cargo build --release --features wasm-reactor,coraza-native --bin bench-subms
  if [[ "$RUN_NATIVE" == "1" ]]; then
    if command -v go >/dev/null 2>&1; then
      "${DEV[@]}" "$ROOT/scripts/build-coraza-sidecar.sh" "$SIDECAR_BIN"
    else
      echo "go not found; native rows will be skipped" >&2
      RUN_NATIVE=0
    fi
  fi
fi

[[ -x "$BENCH_BIN" ]] || { echo "missing $BENCH_BIN (run without --skip-build)" >&2; exit 1; }

sidecar_pid=""
cleanup() {
  if [[ -n "$sidecar_pid" ]]; then
    kill "$sidecar_pid" 2>/dev/null || true
    wait "$sidecar_pid" 2>/dev/null || true
  fi
}
trap cleanup EXIT

NATIVE_ARGS=()
if [[ "$RUN_NATIVE" == "1" ]]; then
  [[ -x "$SIDECAR_BIN" ]] || { echo "missing $SIDECAR_BIN (run without --skip-build)" >&2; exit 1; }
  rm -f "$SOCKET"
  echo "== native sidecar =="
  "${PIN[@]}" "$SIDECAR_BIN" \
    --socket "$SOCKET" \
    --rules "$ROOT/wasm/coraza_reactor/rules/crs/crs.conf" \
    --max-body 65536 \
    --max-headers 100 \
    --max-header-bytes 65536 \
    --max-conns 128 \
    --timeout 120s \
    --grace 10s \
    >"$STATE_DIR/sidecar.log" 2>&1 &
  sidecar_pid=$!

  ready=0
  for _ in $(seq 1 200); do
    if "$SIDECAR_BIN" --probe --socket "$SOCKET" >/dev/null 2>&1; then
      ready=1
      break
    fi
    kill -0 "$sidecar_pid" 2>/dev/null || {
      echo "sidecar exited before readiness; see $STATE_DIR/sidecar.log" >&2
      exit 1
    }
    sleep 0.1
  done
  [[ "$ready" == "1" ]] || { echo "sidecar socket did not become ready" >&2; exit 1; }
  echo "sidecar ready on $SOCKET (pid $sidecar_pid)"
  NATIVE_ARGS=(--native-socket "$SOCKET")
fi

echo
echo "== benchmark =="
"${PIN[@]}" "$BENCH_BIN" "${NATIVE_ARGS[@]}" --json-out "$REPORT" "${PASSTHROUGH[@]}"

echo
echo "report: $REPORT"
echo "sidecar log: $STATE_DIR/sidecar.log"
echo
echo "Re-run on a quiet host: stop other builds, set the performance governor,"
echo "disable turbo if permitted, pin with --pin, and compare the same commit."
