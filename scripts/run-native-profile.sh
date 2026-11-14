#!/usr/bin/env bash
# Run the native Coraza high-throughput profile locally.
#
# Builds the sidecar, the native-capable proxy and a tiny echo upstream, starts
# them with isolated state under /tmp/opencode, waits for readiness, runs a
# benign/SQLi/XSS/gRPC smoke test and tears everything down.
#
# Usage:
#   scripts/run-native-profile.sh            # build + smoke
#   scripts/run-native-profile.sh --load     # build + smoke + capacity matrix
#   scripts/run-native-profile.sh --no-build # reuse target/ binaries
#   scripts/run-native-profile.sh --keep     # leave the stack running
#
# Environment:
#   WAF_NATIVE_STATE_DIR    state root (default /tmp/opencode/native-profile)
#   WAF_NATIVE_PROXY_PORT   default 18080
#   WAF_NATIVE_HEALTH_PORT  default 18081
#   WAF_NATIVE_UPSTREAM_PORT default 13000
#   WAF_NATIVE_LOAD_SECS    measurement seconds per load cell (default 8)
#   WAF_NATIVE_WARMUP_SECS  warm-up seconds per load cell (default 2)
#
# The profile config is config/performance-native.toml. Ports, the upstream and
# the socket path are overridden through WAF_* environment variables so the
# checked-in config keeps its deployment defaults.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
STATE_DIR="${WAF_NATIVE_STATE_DIR:-/tmp/opencode/native-profile}"
PROXY_PORT="${WAF_NATIVE_PROXY_PORT:-18080}"
HEALTH_PORT="${WAF_NATIVE_HEALTH_PORT:-18081}"
UPSTREAM_PORT="${WAF_NATIVE_UPSTREAM_PORT:-13000}"
LOAD_SECS="${WAF_NATIVE_LOAD_SECS:-8}"
WARMUP_SECS="${WAF_NATIVE_WARMUP_SECS:-2}"

RUN_LOAD=0
DO_BUILD=1
KEEP=0
for arg in "$@"; do
  case "$arg" in
    --load) RUN_LOAD=1 ;;
    --no-build) DO_BUILD=0 ;;
    --keep) KEEP=1 ;;
    -h|--help)
      sed -n '2,30p' "$0"
      exit 0
      ;;
    *)
      echo "unknown argument: $arg" >&2
      exit 2
      ;;
  esac
done

SOCKET="$STATE_DIR/run/coraza.sock"
SIDECAR_BIN="$STATE_DIR/bin/coraza-sidecar"
PROXY_BIN="$ROOT/target/release/waf-ingress"
UPSTREAM_BIN="$ROOT/target/release/echo_backend"
LOAD_BIN="$ROOT/target/release/load-validate"
RULES="$ROOT/wasm/coraza_reactor/rules/crs/crs.conf"

mkdir -p "$STATE_DIR/bin" "$STATE_DIR/run" "$STATE_DIR/logs" "$STATE_DIR/load"
# Match the deployment contract: socket directory 0750, socket 0660.
chmod 750 "$STATE_DIR/run"
rm -f "$SOCKET"

# Use the flake toolchain unless the caller already entered `nix develop`.
if [[ -n "${IN_NIX_SHELL:-}" ]]; then
  DEV=()
else
  DEV=(nix develop -c)
fi

sidecar_pid=""
proxy_pid=""
upstream_pid=""

cleanup() {
  local code=$?
  trap - EXIT INT TERM
  if [[ "$KEEP" == "1" ]]; then
    echo "keeping stack running (proxy pid $proxy_pid, sidecar pid $sidecar_pid, upstream pid $upstream_pid)"
    exit "$code"
  fi
  for pid in "$proxy_pid" "$sidecar_pid" "$upstream_pid"; do
    [[ -n "$pid" ]] && kill -TERM "$pid" 2>/dev/null || true
  done
  for pid in "$proxy_pid" "$sidecar_pid" "$upstream_pid"; do
    [[ -n "$pid" ]] && wait "$pid" 2>/dev/null || true
  done
  rm -f "$SOCKET"
  exit "$code"
}
trap cleanup EXIT INT TERM

fail() {
  echo "FAIL: $*" >&2
  echo "logs: $STATE_DIR/logs" >&2
  exit 1
}

if [[ "$DO_BUILD" == "1" ]]; then
  echo "building sidecar and proxy (features wasm-reactor,coraza-native)"
  "${DEV[@]}" "$ROOT/scripts/build-coraza-sidecar.sh" "$SIDECAR_BIN"
  bins=(--bin waf-ingress --bin echo_backend)
  if [[ "$RUN_LOAD" == "1" ]]; then
    bins+=(--bin load-validate)
  fi
  "${DEV[@]}" cargo build --release --features wasm-reactor,coraza-native "${bins[@]}"
fi

[[ -x "$SIDECAR_BIN" ]] || fail "missing $SIDECAR_BIN (run without --no-build)"
[[ -x "$PROXY_BIN" ]] || fail "missing $PROXY_BIN (run without --no-build)"
[[ -x "$UPSTREAM_BIN" ]] || fail "missing $UPSTREAM_BIN (run without --no-build)"
[[ "$RUN_LOAD" == "0" || -x "$LOAD_BIN" ]] || fail "missing $LOAD_BIN (run without --no-build)"

echo "starting mock upstream on 127.0.0.1:$UPSTREAM_PORT"
BACKEND_PORT="$UPSTREAM_PORT" "$UPSTREAM_BIN" \
  >"$STATE_DIR/logs/upstream.log" 2>&1 &
upstream_pid=$!

echo "starting coraza sidecar on $SOCKET"
"$SIDECAR_BIN" \
  --socket "$SOCKET" \
  --rules "$RULES" \
  --max-body 65536 \
  --max-headers 100 \
  --max-header-bytes 65536 \
  --max-conns 128 \
  --timeout 5s \
  --grace 10s \
  >"$STATE_DIR/logs/sidecar.log" 2>&1 &
sidecar_pid=$!

for _ in $(seq 1 200); do
  if "$SIDECAR_BIN" --probe --socket "$SOCKET" >/dev/null 2>&1; then
    break
  fi
  kill -0 "$sidecar_pid" 2>/dev/null || fail "sidecar exited before readiness (see logs/sidecar.log)"
  sleep 0.1
done
"$SIDECAR_BIN" --probe --socket "$SOCKET" >/dev/null 2>&1 \
  || fail "sidecar socket $SOCKET did not become ready"

echo "starting proxy on 127.0.0.1:$PROXY_PORT (health $HEALTH_PORT)"
WAF_CONFIG_FILE="$ROOT/config/performance-native.toml" \
WAF_BIND_ADDR="127.0.0.1:$PROXY_PORT" \
WAF_HEALTH_BIND_ADDR="127.0.0.1:$HEALTH_PORT" \
WAF_UPSTREAM_URI="http://127.0.0.1:$UPSTREAM_PORT" \
WAF_WAF__CORAZA__NATIVE_SOCKET_PATH="$SOCKET" \
WAF_WAF__RATE_LIMIT__PER_IP_ENABLED=false \
WAF_WAF__RATE_LIMIT__GLOBAL_ENABLED=false \
  "$PROXY_BIN" >"$STATE_DIR/logs/proxy.log" 2>&1 &
proxy_pid=$!

ready=0
for _ in $(seq 1 600); do
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 \
    "http://127.0.0.1:$HEALTH_PORT/health/ready" || true)"
  if [[ "$code" == "200" ]]; then
    ready=1
    break
  fi
  kill -0 "$proxy_pid" 2>/dev/null || fail "proxy exited before readiness (see logs/proxy.log)"
  sleep 0.2
done
[[ "$ready" == "1" ]] || fail "proxy did not become ready at http://127.0.0.1:$HEALTH_PORT/health/ready"

check_status() {
  local name="$1" expected="$2" actual="$3"
  if [[ "$actual" != "$expected" ]]; then
    fail "$name: expected HTTP $expected, got $actual"
  fi
  printf '  %-10s %s\n' "$name" "$actual"
}

echo "smoke test"
status="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
  "http://127.0.0.1:$PROXY_PORT/hello?id=42")"
check_status benign 200 "$status"

status="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
  "http://127.0.0.1:$PROXY_PORT/?id=1%20UNION%20SELECT%20*%20FROM%20users")"
check_status sqli 403 "$status"

status="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
  -X POST -H 'content-type: application/x-www-form-urlencoded' \
  --data-binary '<script>alert(1)</script>' \
  "http://127.0.0.1:$PROXY_PORT/comment")"
check_status xss 403 "$status"

# A NUL byte cannot live in a shell argument, so write the unary frame first.
printf '\0\0\0\0\5hello' >"$STATE_DIR/grpc.bin"
status="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
  -X POST -H 'content-type: application/grpc+proto' -H 'te: trailers' \
  --data-binary @"$STATE_DIR/grpc.bin" \
  "http://127.0.0.1:$PROXY_PORT/helloworld.Greeter/SayHello")"
check_status grpc 200 "$status"

echo "smoke test passed"

if [[ "$RUN_LOAD" == "1" ]]; then
  echo "running capacity matrix (1/4/8/16/60 KiB + gRPC, c=1,4,16,64)"
  "$LOAD_BIN" \
    --target "http://127.0.0.1:$PROXY_PORT" \
    --no-upstream \
    --waf-pid "$proxy_pid" \
    --profiles form-1k,form-4k,form-8k,form-16k,form-60k,grpc-1k \
    --concurrency 1,4,16,64 \
    --warmup-secs "$WARMUP_SECS" \
    --duration-secs "$LOAD_SECS" \
    --output-dir "$STATE_DIR/load"
  echo "results: $STATE_DIR/load/summary.md"
fi

echo "native profile OK (state: $STATE_DIR)"
