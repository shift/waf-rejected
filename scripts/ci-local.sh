#!/usr/bin/env bash
#
# Billing-independent local CI runner for WAF-Rejected.
#
# Runs the same format, lint, check and test stages as CI, plus optional
# dependency auditing, supply-chain policy checks (cargo-deny), Helm chart
# validation and container image build.
#
# Usage:
#   ./scripts/ci-local.sh
#   just ci-local
#
# Environment:
#   SKIP_AUDIT=1         Skip `cargo audit` even when cargo-audit is installed.
#   SKIP_DENY=1          Skip `cargo deny check` even when cargo-deny is installed.
#   BUILD_IMAGE=1        Also build the container image (docker by default).
#   CONTAINER_ENGINE=... Container engine for BUILD_IMAGE (default: docker).

set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

SKIP_AUDIT="${SKIP_AUDIT:-0}"
SKIP_DENY="${SKIP_DENY:-0}"
BUILD_IMAGE="${BUILD_IMAGE:-0}"
CONTAINER_ENGINE="${CONTAINER_ENGINE:-docker}"

NIX_DEVELOP=(nix develop -c)

STAGE_INDEX=0
STAGE_TOTAL=0
PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
FIRST_FAILURE=""
declare -a RESULTS=()

if [[ -t 1 ]]; then
  COLOR_PASS=$'\033[32m'
  COLOR_FAIL=$'\033[31m'
  COLOR_SKIP=$'\033[33m'
  COLOR_RESET=$'\033[0m'
else
  COLOR_PASS=""
  COLOR_FAIL=""
  COLOR_SKIP=""
  COLOR_RESET=""
fi

run_stage() {
  local name="$1"
  shift

  STAGE_INDEX=$((STAGE_INDEX + 1))
  printf '\n==> [%d/%d] %s\n' "$STAGE_INDEX" "$STAGE_TOTAL" "$name"

  local start=$SECONDS
  local status=0
  "$@" || status=$?
  local elapsed=$((SECONDS - start))

  if [[ $status -eq 0 ]]; then
    PASS_COUNT=$((PASS_COUNT + 1))
    RESULTS+=("PASS|$name|${elapsed}s")
    printf '%sPASS%s %s (%ss)\n' "$COLOR_PASS" "$COLOR_RESET" "$name" "$elapsed"
  else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    RESULTS+=("FAIL|$name|${elapsed}s")
    if [[ -z "$FIRST_FAILURE" ]]; then
      FIRST_FAILURE="$name"
    fi
    printf '%sFAIL%s %s (exit %d, %ss)\n' \
      "$COLOR_FAIL" "$COLOR_RESET" "$name" "$status" "$elapsed"
  fi

  return 0
}

skip_stage() {
  local name="$1"
  local reason="$2"

  STAGE_INDEX=$((STAGE_INDEX + 1))
  SKIP_COUNT=$((SKIP_COUNT + 1))
  RESULTS+=("SKIP|$name|$reason")
  printf '\n==> [%d/%d] %s\n' "$STAGE_INDEX" "$STAGE_TOTAL" "$name"
  printf '%sSKIP%s %s (%s)\n' "$COLOR_SKIP" "$COLOR_RESET" "$name" "$reason"
}

cargo_stage() {
  local name="$1"
  shift
  run_stage "$name" "${NIX_DEVELOP[@]}" cargo "$@"
}

if ! command -v nix >/dev/null 2>&1; then
  printf '%sFAIL%s nix is not installed or not on PATH\n' \
    "$COLOR_FAIL" "$COLOR_RESET" >&2
  exit 1
fi

helm_available=0
if command -v helm >/dev/null 2>&1; then
  helm_available=1
fi

audit_available=0
if [[ "$SKIP_AUDIT" != "1" ]] &&
  "${NIX_DEVELOP[@]}" cargo audit --version >/dev/null 2>&1; then
  audit_available=1
fi

deny_available=0
if [[ "$SKIP_DENY" != "1" ]] &&
  "${NIX_DEVELOP[@]}" cargo deny --version >/dev/null 2>&1; then
  deny_available=1
fi

STAGE_TOTAL=13
# Fixed cargo stages: fmt, 3x clippy, 2x check, 3x lib tests, 2x integration tests,
# plus cargo audit and cargo deny (either of which may be skipped).
if [[ $helm_available -eq 1 ]]; then
  STAGE_TOTAL=$((STAGE_TOTAL + 2))
fi
if [[ "$BUILD_IMAGE" == "1" ]]; then
  STAGE_TOTAL=$((STAGE_TOTAL + 1))
fi

printf 'WAF-Rejected local CI\n'
printf 'Repository: %s\n' "$ROOT_DIR"
printf 'Stages:     %d\n' "$STAGE_TOTAL"

cargo_stage "cargo fmt -- --check" fmt -- --check
cargo_stage "cargo clippy --lib (default features)" \
  clippy --lib -- --deny warnings
cargo_stage "cargo clippy --lib --features compliance" \
  clippy --lib --features compliance -- --deny warnings
cargo_stage "cargo clippy --lib --features http3" \
  clippy --lib --features http3 -- --deny warnings
cargo_stage "cargo check --all-targets" check --all-targets
cargo_stage "cargo check --features http3 --all-targets" \
  check --features http3 --all-targets
cargo_stage "cargo test --lib" test --lib
cargo_stage "cargo test --lib --features compliance" \
  test --lib --features compliance
cargo_stage "cargo test --lib --features http3" \
  test --lib --features http3
cargo_stage "cargo test --test integration" test --test integration
cargo_stage "cargo test --test integration --features http3" \
  test --test integration --features http3

if [[ "$SKIP_AUDIT" == "1" ]]; then
  skip_stage "cargo audit" "SKIP_AUDIT=1"
elif [[ $audit_available -eq 1 ]]; then
  cargo_stage "cargo audit" audit
else
  skip_stage "cargo audit" "cargo-audit is not available in the dev shell"
  printf '%sWARNING%s cargo-audit not found; install it in the dev shell to enable the audit stage.\n' \
    "$COLOR_SKIP" "$COLOR_RESET"
fi

if [[ "$SKIP_DENY" == "1" ]]; then
  skip_stage "cargo deny check" "SKIP_DENY=1"
elif [[ $deny_available -eq 1 ]]; then
  cargo_stage "cargo deny check" deny check
else
  skip_stage "cargo deny check" "cargo-deny is not available in the dev shell"
  printf '%sWARNING%s cargo-deny not found; install it (nix shell nixpkgs#cargo-deny nixpkgs#cargo) to enforce the supply-chain policy.\n' \
    "$COLOR_SKIP" "$COLOR_RESET"
fi

if [[ $helm_available -eq 1 ]]; then
  run_stage "helm lint infrastructure/helm" \
    helm lint infrastructure/helm
  run_stage "helm template infrastructure/helm" \
    bash -c 'helm template waf-rejected infrastructure/helm >/dev/null'
else
  printf '\n%sWARNING%s helm not found; skipping Helm lint/template stages.\n' \
    "$COLOR_SKIP" "$COLOR_RESET"
fi

if [[ "$BUILD_IMAGE" == "1" ]]; then
  if command -v "$CONTAINER_ENGINE" >/dev/null 2>&1; then
    run_stage "container build ($CONTAINER_ENGINE)" \
      "$CONTAINER_ENGINE" build -t waf-rejected:local-ci .
  else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    STAGE_INDEX=$((STAGE_INDEX + 1))
    RESULTS+=("FAIL|container build|$CONTAINER_ENGINE not found")
    if [[ -z "$FIRST_FAILURE" ]]; then
      FIRST_FAILURE="container build"
    fi
    printf '\n==> [%d/%d] container build (%s)\n' \
      "$STAGE_INDEX" "$STAGE_TOTAL" "$CONTAINER_ENGINE"
    printf '%sFAIL%s container build (%s not found)\n' \
      "$COLOR_FAIL" "$COLOR_RESET" "$CONTAINER_ENGINE"
  fi
fi

printf '\n==========================================\n'
printf ' Local CI summary\n'
printf '==========================================\n'
for result in "${RESULTS[@]}"; do
  IFS='|' read -r status name detail <<<"$result"
  case "$status" in
    PASS) printf ' %sPASS%s  %-55s %s\n' "$COLOR_PASS" "$COLOR_RESET" "$name" "$detail" ;;
    FAIL) printf ' %sFAIL%s  %-55s %s\n' "$COLOR_FAIL" "$COLOR_RESET" "$name" "$detail" ;;
    SKIP) printf ' %sSKIP%s  %-55s %s\n' "$COLOR_SKIP" "$COLOR_RESET" "$name" "$detail" ;;
  esac
done
printf '%s\n' '------------------------------------------'
printf ' Passed: %d  Failed: %d  Skipped: %d\n' \
  "$PASS_COUNT" "$FAIL_COUNT" "$SKIP_COUNT"

if [[ $FAIL_COUNT -gt 0 ]]; then
  printf ' First failing stage: %s\n' "$FIRST_FAILURE"
  printf ' %sRESULT: FAIL%s\n' "$COLOR_FAIL" "$COLOR_RESET"
  exit 1
fi

printf ' %sRESULT: PASS%s\n' "$COLOR_PASS" "$COLOR_RESET"
