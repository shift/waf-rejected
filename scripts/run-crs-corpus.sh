#!/usr/bin/env bash
# Run the pinned OWASP CRS detection corpus through the Coraza backends.
#
# Usage:
#   ./scripts/run-crs-corpus.sh [harness options]
#
# Examples:
#   ./scripts/run-crs-corpus.sh --engine wasm
#   ./scripts/run-crs-corpus.sh --engine both --json target/crs-corpus.json
#   ./scripts/run-crs-corpus.sh --filter sqli --verbose
#
# The script always builds the harness with `wasm-reactor,coraza-native`. For
# `--engine native` or `--engine both` it starts the Go sidecar on a temporary
# Unix socket unless `--native-socket` is supplied, and stops it on exit.
#
# This is an optional check: it is not part of the default feature matrix or
# the required CI jobs. See docs/operations/detection-corpus.md.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

ENGINE="wasm"
NATIVE_SOCKET=""
ARGS=("$@")

previous=""
for arg in "$@"; do
  case "$arg" in
    --engine=*)
      ENGINE="${arg#*=}"
      previous=""
      ;;
    --engine)
      previous="engine"
      ;;
    --native-socket=*)
      NATIVE_SOCKET="${arg#*=}"
      previous=""
      ;;
    --native-socket)
      previous="socket"
      ;;
    *)
      if [[ "$previous" == "engine" ]]; then
        ENGINE="$arg"
      elif [[ "$previous" == "socket" ]]; then
        NATIVE_SOCKET="$arg"
      fi
      previous=""
      ;;
  esac
done

case "$ENGINE" in
  wasm|native|both|rust|fastpath) ;;
  *)
    echo "error: --engine must be wasm, native, both, rust, or fastpath (got '$ENGINE')" >&2
    exit 2
    ;;
esac

FEATURES="wasm-reactor,coraza-native"
if [[ "$ENGINE" == "rust" || "${ENGINE_FEATURE:-0}" == "1" ]]; then
  FEATURES="$FEATURES,native-engine"
fi
if [[ "$ENGINE" == "fastpath" ]]; then
  FEATURES="$FEATURES,fastpath"
fi

SIDECAR_PID=""
SOCKET_DIR=""
cleanup() {
  if [[ -n "$SIDECAR_PID" ]]; then
    kill "$SIDECAR_PID" 2>/dev/null || true
    wait "$SIDECAR_PID" 2>/dev/null || true
  fi
  if [[ -n "$SOCKET_DIR" ]]; then
    rm -rf "$SOCKET_DIR"
  fi
}
trap cleanup EXIT

if [[ ("$ENGINE" == "native" || "$ENGINE" == "both") && -z "$NATIVE_SOCKET" ]]; then
  if ! command -v nix >/dev/null 2>&1; then
    echo "error: nix is required to build the native sidecar" >&2
    exit 1
  fi
  echo "building native Coraza sidecar"
  nix develop -c ./scripts/build-coraza-sidecar.sh >/dev/null

  SOCKET_DIR="$(mktemp -d)"
  NATIVE_SOCKET="$SOCKET_DIR/coraza.sock"
  "$ROOT/target/native/coraza-sidecar" \
    --socket "$NATIVE_SOCKET" \
    --rules "$ROOT/wasm/coraza_reactor/rules/crs/crs.conf" \
    >"$SOCKET_DIR/sidecar.log" 2>&1 &
  SIDECAR_PID=$!

  for _ in $(seq 1 120); do
    if [[ -S "$NATIVE_SOCKET" ]]; then
      break
    fi
    if ! kill -0 "$SIDECAR_PID" 2>/dev/null; then
      echo "error: native sidecar exited during start-up" >&2
      cat "$SOCKET_DIR/sidecar.log" >&2 || true
      exit 1
    fi
    sleep 0.25
  done
  if [[ ! -S "$NATIVE_SOCKET" ]]; then
    echo "error: native sidecar socket did not appear" >&2
    cat "$SOCKET_DIR/sidecar.log" >&2 || true
    exit 1
  fi
  ARGS+=("--native-socket" "$NATIVE_SOCKET")
fi

echo "running CRS detection corpus (engine=$ENGINE)"
nix develop -c cargo run --quiet --bin crs_corpus \
  --features "$FEATURES" -- "${ARGS[@]}"
