#!/usr/bin/env bash
#
# Cross-feature compile/test matrix for WAF-Rejected.
#
# Guards against feature-combination regressions: a test or binary that only
# compiles with the default feature set can hide breakage in optional
# combinations (for example the `coraza-native` test import that the default
# set did not catch). Runs entirely through `nix develop -c`, so it works
# without GitHub Actions.
#
# Usage:
#   ./scripts/ci-feature-matrix.sh
#   ./scripts/ci-feature-matrix.sh --quick      # skip all-targets checks
#   ./scripts/ci-feature-matrix.sh --jobs 4
#   just ci-feature-matrix
#
# Options:
#   --quick     Skip the slow `cargo check --all-targets` stages.
#   --jobs N    Limit parallel compile jobs (exported as CARGO_BUILD_JOBS).
#   -h, --help  Show this help.
#
# Environment:
#   CI_FEATURE_MATRIX_NIX=0  Run cargo directly instead of via `nix develop -c`.
#   CARGO_TARGET_DIR=...     Shared target directory (useful for local runs).

set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

QUICK=0
JOBS=""

usage() {
  awk 'NR == 1 { next } /^#/ { sub(/^# ?/, ""); print; next } { exit }' \
    "${BASH_SOURCE[0]}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --quick)
      QUICK=1
      shift
      ;;
    --jobs)
      if [[ $# -lt 2 || ! "$2" =~ ^[1-9][0-9]*$ ]]; then
        printf 'error: --jobs requires a positive integer\n' >&2
        exit 2
      fi
      JOBS="$2"
      shift 2
      ;;
    --jobs=*)
      JOBS="${1#--jobs=}"
      if [[ ! "$JOBS" =~ ^[1-9][0-9]*$ ]]; then
        printf 'error: --jobs requires a positive integer\n' >&2
        exit 2
      fi
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'error: unknown argument: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -n "$JOBS" ]]; then
  export CARGO_BUILD_JOBS="$JOBS"
fi

if [[ "${CI_FEATURE_MATRIX_NIX:-1}" == "0" ]]; then
  CARGO_RUNNER=(cargo)
else
  if ! command -v nix >/dev/null 2>&1; then
    printf 'error: nix is not installed or not on PATH (set CI_FEATURE_MATRIX_NIX=0 to run cargo directly)\n' >&2
    exit 1
  fi
  CARGO_RUNNER=(nix develop -c cargo)
fi

if [[ -t 1 ]]; then
  COLOR_PASS=$'\033[32m'
  COLOR_FAIL=$'\033[31m'
  COLOR_SKIP=$'\033[33m'
  COLOR_BOLD=$'\033[1m'
  COLOR_RESET=$'\033[0m'
else
  COLOR_PASS=""
  COLOR_FAIL=""
  COLOR_SKIP=""
  COLOR_BOLD=""
  COLOR_RESET=""
fi

# name|description|cargo arguments
STAGES=(
  "fmt|cargo fmt -- --check|fmt -- --check"
  "clippy-default|cargo clippy --lib (default features)|clippy --lib -- --deny warnings"
  "test-default|cargo test --lib (default features)|test --lib"
  "config-files|shipped configs load through Config::load|test --test config_files"
  "test-wasm-reactor|cargo test --lib --features wasm-reactor|test --lib --features wasm-reactor"
  "test-wasm-reactor+coraza-native|cargo test --lib --features wasm-reactor,coraza-native|test --lib --features wasm-reactor,coraza-native"
  "test-no-default-features|cargo test --lib --no-default-features|test --lib --no-default-features"
  "test-no-default-features+wasm-reactor|cargo test --lib --no-default-features --features wasm-reactor|test --lib --no-default-features --features wasm-reactor"
  "check-all-targets+coraza-native|cargo check --all-targets --features wasm-reactor,coraza-native|check --all-targets --features wasm-reactor,coraza-native"
  "check-all-targets+http3+webtransport|cargo check --all-targets --features http3,webtransport,wasm-reactor|check --all-targets --features http3,webtransport,wasm-reactor"
  "check-all-targets+ai-threat-detection|cargo check --all-targets --features ai-threat-detection|check --all-targets --features ai-threat-detection"
  "check-bin-graphql-allowlist|cargo check --bin graphql-allowlist --features wasm-reactor|check --bin graphql-allowlist --features wasm-reactor"
  "check-bin-grpc-allowlist|cargo check --bin grpc-allowlist --features wasm-reactor|check --bin grpc-allowlist --features wasm-reactor"
)

is_skipped() {
  local name="$1"
  [[ "$QUICK" == "1" && "$name" == check-all-targets* ]]
}

TOTAL=0
for stage in "${STAGES[@]}"; do
  IFS='|' read -r name _ _ <<<"$stage"
  is_skipped "$name" || TOTAL=$((TOTAL + 1))
done

INDEX=0
PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
FIRST_FAILURE=""
FAILED_COMMAND=""
FAILED_ARGS=""
declare -a RESULTS=()

run_stage() {
  local name="$1"
  local description="$2"
  local cargo_args="$3"

  INDEX=$((INDEX + 1))
  printf '\n%s==> [%d/%d] %s%s\n' \
    "$COLOR_BOLD" "$INDEX" "$TOTAL" "$description" "$COLOR_RESET"

  local -a cmd=("${CARGO_RUNNER[@]}")
  # shellcheck disable=SC2206 # deliberate word splitting of the fixed arg list
  cmd+=($cargo_args)

  local start=$SECONDS
  local status=0
  "${cmd[@]}" || status=$?
  local elapsed=$((SECONDS - start))

  if [[ $status -eq 0 ]]; then
    PASS_COUNT=$((PASS_COUNT + 1))
    RESULTS+=("PASS|$name|$description|${elapsed}s")
    printf '%sPASS%s %s (%ss)\n' \
      "$COLOR_PASS" "$COLOR_RESET" "$description" "$elapsed"
  else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    RESULTS+=("FAIL|$name|$description|exit $status, ${elapsed}s")
    if [[ -z "$FIRST_FAILURE" ]]; then
      FIRST_FAILURE="$name"
      FAILED_COMMAND="$description"
      FAILED_ARGS="$cargo_args"
    fi
    printf '%sFAIL%s %s (exit %d, %ss)\n' \
      "$COLOR_FAIL" "$COLOR_RESET" "$description" "$status" "$elapsed"
  fi

  return 0
}

skip_stage() {
  local name="$1"
  local description="$2"

  INDEX=$((INDEX + 1))
  SKIP_COUNT=$((SKIP_COUNT + 1))
  RESULTS+=("SKIP|$name|$description|--quick")
  printf '\n%s==> [%d/%d] %s%s\n' \
    "$COLOR_BOLD" "$INDEX" "$TOTAL" "$description" "$COLOR_RESET"
  printf '%sSKIP%s %s (--quick)\n' \
    "$COLOR_SKIP" "$COLOR_RESET" "$description"
}

print_summary() {
  printf '\n==========================================\n'
  printf ' Feature matrix summary%s\n' "$([[ "$QUICK" == "1" ]] && printf ' (quick)')"
  printf '==========================================\n'
  local result status name description detail
  for result in "${RESULTS[@]}"; do
    IFS='|' read -r status name description detail <<<"$result"
    case "$status" in
      PASS) printf ' %sPASS%s  %-50s %s\n' "$COLOR_PASS" "$COLOR_RESET" "$name" "$detail" ;;
      FAIL) printf ' %sFAIL%s  %-50s %s\n' "$COLOR_FAIL" "$COLOR_RESET" "$name" "$detail" ;;
      SKIP) printf ' %sSKIP%s  %-50s %s\n' "$COLOR_SKIP" "$COLOR_RESET" "$name" "$detail" ;;
    esac
  done
  printf '%s\n' '------------------------------------------'
  printf ' Passed: %d  Failed: %d  Skipped: %d\n' \
    "$PASS_COUNT" "$FAIL_COUNT" "$SKIP_COUNT"
}

printf 'WAF-Rejected feature matrix\n'
printf 'Repository: %s\n' "$ROOT_DIR"
printf 'Runner:     %s\n' "${CARGO_RUNNER[*]}"
printf 'Mode:       %s\n' "$([[ "$QUICK" == "1" ]] && printf 'quick (all-targets checks skipped)' || printf 'full')"
printf 'Stages:     %d\n' "$TOTAL"

for stage in "${STAGES[@]}"; do
  IFS='|' read -r name description cargo_args <<<"$stage"
  if is_skipped "$name"; then
    skip_stage "$name" "$description"
    continue
  fi

  run_stage "$name" "$description" "$cargo_args"

  if [[ $FAIL_COUNT -gt 0 ]]; then
    print_summary
    printf '\n%sFAIL%s combination: %s\n' \
      "$COLOR_FAIL" "$COLOR_RESET" "$FIRST_FAILURE"
    printf '      command: %s\n' "$FAILED_COMMAND"
    printf '      rerun:   %s %s\n' "${CARGO_RUNNER[*]}" "$FAILED_ARGS"
    printf ' %sRESULT: FAIL%s (stopped at first failing combination)\n' \
      "$COLOR_FAIL" "$COLOR_RESET"
    exit 1
  fi
done

print_summary
printf ' %sRESULT: PASS%s\n' "$COLOR_PASS" "$COLOR_RESET"
