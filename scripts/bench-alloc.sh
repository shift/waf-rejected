#!/usr/bin/env bash
# Allocator and scheduling benchmark harness for the WAF proxy.
#
# Compares the system allocator against the optional `mimalloc` and `jemalloc`
# global allocators, then measures the effect of worker-thread pinning and
# Tokio runtime tuning. Results are written to a JSON report so the numbers in
# docs/suggestions_from_agents/alloc-tuning.md can be reproduced.
#
#   nix develop -c ./scripts/bench-alloc.sh
#   nix develop -c ./scripts/bench-alloc.sh --skip-build --pin 2-5
#   nix develop -c ./scripts/bench-alloc.sh -- --samples 30
#
# Everything after `--` is passed to the benchmark binaries.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

REPORT_DIR="${REPORT_DIR:-$ROOT/target/bench-alloc}"
BENCH_SUBMS="$ROOT/target/release/bench-subms"
BODYLESS_BENCH="$ROOT/target/release/bodyless-bench"
PIN_CPUS=""
SKIP_BUILD=0
PASSTHROUGH=()

usage() {
  cat <<'EOF'
usage: scripts/bench-alloc.sh [options] [-- <bench args>]

  --skip-build      use existing release binaries
  --pin <cpulist>   taskset CPU list for every run (e.g. 2-5)
  --report-dir <d>  output directory (default target/bench-alloc)
  -h, --help        this help

Allocators: system (default), mimalloc (--features alloc-mimalloc),
jemalloc (--features alloc-jemalloc). The script builds each variant in turn
and runs the same workload so p50/p99, RSS and allocation counts are directly
comparable.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-build) SKIP_BUILD=1; shift ;;
    --pin) PIN_CPUS="${2:?--pin needs a CPU list}"; shift 2 ;;
    --report-dir) REPORT_DIR="${2:?--report-dir needs a path}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    --) shift; PASSTHROUGH=("$@"); break ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

mkdir -p "$REPORT_DIR"

run_bench() {
  local label="$1"
  local bin="$2"
  shift 2
  local out="$REPORT_DIR/$label.txt"
  echo "==> $label"
  local prefix=()
  if [[ -n "$PIN_CPUS" ]]; then
    prefix=(taskset -c "$PIN_CPUS")
  fi
  # /usr/bin/time -v reports peak RSS on stderr.
  /usr/bin/time -v "${prefix[@]}" "$bin" "$@" >"$out" 2>"$out.time"
  grep -E "Maximum resident set size|Elapsed \(wall clock\)" "$out.time" >>"$out" || true
}

build_variant() {
  local features="$1"
  local out_dir="$2"
  echo "==> building ($features)"
  if [[ -n "$features" ]]; then
    # jemalloc's configure script needs _GNU_SOURCE to detect strerror_r on
    # glibc >= 2.40; harmless for the other variants.
    CFLAGS="${CFLAGS:-} -D_GNU_SOURCE" CPPFLAGS="${CPPFLAGS:-} -D_GNU_SOURCE" \
      cargo build --release --features "$features" --bin bench-subms --bin bodyless-bench
  else
    cargo build --release --bin bench-subms --bin bodyless-bench
  fi
  mkdir -p "$out_dir"
  cp "$BENCH_SUBMS" "$out_dir/" 2>/dev/null || true
  cp "$BODYLESS_BENCH" "$out_dir/" 2>/dev/null || true
}

if [[ "$SKIP_BUILD" -eq 0 ]]; then
  build_variant "" "$REPORT_DIR/system"
  build_variant "alloc-mimalloc" "$REPORT_DIR/mimalloc"
  build_variant "alloc-jemalloc" "$REPORT_DIR/jemalloc"
fi

for variant in system mimalloc jemalloc; do
  dir="$REPORT_DIR/$variant"
  [[ -x "$dir/bench-subms" ]] || continue
  run_bench "$variant-subms" "$dir/bench-subms" --samples 30 --requests 200 "${PASSTHROUGH[@]}"
  run_bench "$variant-bodyless" "$dir/bodyless-bench" --concurrency 1,16,64 "${PASSTHROUGH[@]}"
done

# Pinning comparison at c=1/16/64 using the default build.
if [[ -x "$REPORT_DIR/system/bodyless-bench" ]]; then
  echo "==> pinning comparison"
  WAF_RUNTIME__ENABLE_CPU_PINNING=false \
    run_bench "pin-off-bodyless" "$REPORT_DIR/system/bodyless-bench" --concurrency 1,16,64
  if [[ -n "$PIN_CPUS" ]]; then
    WAF_RUNTIME__ENABLE_CPU_PINNING=true \
      run_bench "pin-on-bodyless" "$REPORT_DIR/system/bodyless-bench" --concurrency 1,16,64
  fi
fi

echo "reports written to $REPORT_DIR"
