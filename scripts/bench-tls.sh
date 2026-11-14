#!/usr/bin/env bash
# Isolate TLS/connection cost from WAF cost.
#
# Measures, against a local waf-ingress listener with the WAF disabled:
#   * full TLS handshake (new connection per probe)
#   * resumed TLS handshake (openssl s_time -reconnect)
#   * request latency over a reused HTTP/2 connection
#   * request latency over a reused HTTP/1.1 keep-alive connection
# and reports p50/p99 plus the proxy process CPU time consumed.
#
# Requires: openssl, curl, python3, and a built waf-ingress binary.
#
#   nix develop -c ./scripts/bench-tls.sh
#   nix develop -c ./scripts/bench-tls.sh --requests 500 --warmup 50
#   nix develop -c ./scripts/bench-tls.sh --skip-build
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

STATE_DIR="${STATE_DIR:-/tmp/opencode/bench-tls}"
CERT="$STATE_DIR/server.crt"
KEY="$STATE_DIR/server.key"
CONFIG="$STATE_DIR/config.toml"
BIN="${BIN:-$ROOT/target/release/waf-ingress}"
PORT="${PORT:-18443}"
HEALTH_PORT="${HEALTH_PORT:-18444}"
BACKEND_PORT="${BACKEND_PORT:-18080}"
REQUESTS="${REQUESTS:-200}"
WARMUP="${WARMUP:-20}"
SKIP_BUILD=0

usage() {
  cat <<'EOF'
usage: scripts/bench-tls.sh [options]

  --requests <n>   measured requests per scenario (default 200)
  --warmup <n>     discarded warmup requests (default 20)
  --skip-build     reuse an existing target/release/waf-ingress
  -h, --help       this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --requests) REQUESTS="${2:?--requests needs a value}"; shift 2 ;;
    --warmup) WARMUP="${2:?--warmup needs a value}"; shift 2 ;;
    --skip-build) SKIP_BUILD=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

mkdir -p "$STATE_DIR"

cleanup() {
  if [[ -n "${PROXY_PID:-}" ]] && kill -0 "$PROXY_PID" 2>/dev/null; then
    kill "$PROXY_PID" 2>/dev/null || true
    wait "$PROXY_PID" 2>/dev/null || true
  fi
  if [[ -n "${BACKEND_PID:-}" ]] && kill -0 "$BACKEND_PID" 2>/dev/null; then
    kill "$BACKEND_PID" 2>/dev/null || true
    wait "$BACKEND_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

if [[ ! -x "$BIN" ]]; then
  if [[ "$SKIP_BUILD" == "1" ]]; then
    echo "missing binary $BIN; rerun without --skip-build" >&2
    exit 1
  fi
  echo "building waf-ingress (release)…"
  nix develop -c cargo build --release --bin waf-ingress
fi

if [[ ! -f "$CERT" || ! -f "$KEY" ]]; then
  echo "generating self-signed certificate…"
  openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -keyout "$KEY" -out "$CERT" -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1
fi

echo "starting loopback backend on :$BACKEND_PORT"
cat >"$STATE_DIR/backend.sh" <<'BACKEND'
#!/usr/bin/env bash
# Minimal keep-alive HTTP/1.1 backend for the TLS benchmark.
while true; do
  while IFS= read -r line; do
    line=${line%$'\r'}
    [[ -z "$line" ]] && break
  done
  printf 'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: text/plain\r\nConnection: keep-alive\r\n\r\nOK'
done
BACKEND
chmod +x "$STATE_DIR/backend.sh"
socat "TCP-LISTEN:$BACKEND_PORT,bind=127.0.0.1,reuseaddr,fork,nodelay" "EXEC:$STATE_DIR/backend.sh" >/dev/null 2>&1 &
BACKEND_PID=$!

sed \
  -e "s|^bind_addr = .*|bind_addr = \"127.0.0.1:$PORT\"|" \
  -e "s|^health_bind_addr = .*|health_bind_addr = \"127.0.0.1:$HEALTH_PORT\"|" \
  -e "s|^upstream_uri = .*|upstream_uri = \"http://127.0.0.1:$BACKEND_PORT\"|" \
  config.toml >"$CONFIG"
# Keep the WAF out of the measurement and enable the TLS fast path.
awk -v cert="$CERT" -v key="$KEY" '
  /^\[waf\]$/ { in_waf=1; print; next }
  /^\[server\.tls\]$/ { in_tls=1; print; next }
  /^\[/ { in_waf=0; in_tls=0; print; next }
  in_waf && /^enabled = true/ { print "enabled = false"; next }
  in_tls && /^enabled = false/ { print "enabled = true"; next }
  /^cert_path = / { print "cert_path = \"" cert "\""; next }
  /^key_path = / { print "key_path = \"" key "\""; next }
  in_tls && /^require_client_cert = false$/ {
    print
    print "session_resumption = true"
    print "tcp_nodelay = true"
    print "tcp_keepalive_secs = 30"
    print "tcp_keepalive_interval_secs = 10"
    next
  }
  { print }
' "$CONFIG" >"$CONFIG.tmp" && mv "$CONFIG.tmp" "$CONFIG"

echo "starting waf-ingress on :$PORT (TLS, WAF disabled)"
WAF_CONFIG_FILE="$CONFIG" "$BIN" >"$STATE_DIR/proxy.log" 2>&1 &
PROXY_PID=$!

for _ in $(seq 1 100); do
  if curl -sk --max-time 1 "https://127.0.0.1:$PORT/" -o /dev/null 2>/dev/null; then
    break
  fi
  sleep 0.1
done
if ! kill -0 "$PROXY_PID" 2>/dev/null; then
  echo "proxy failed to start; see $STATE_DIR/proxy.log" >&2
  exit 1
fi

cpu_ticks() {
  awk '{print $14 + $15}' "/proc/$PROXY_PID/stat"
}

percentiles() {
  # Reads one float per line, prints "p50 p99 n".
  sort -n | awk '
    {v[NR]=$1}
    END {
      if (NR == 0) {print "0 0 0"; exit}
      p50=int((NR-1)*0.50)+1; p99=int((NR-1)*0.99)+1;
      printf "%.3f %.3f %d\n", v[p50]*1000, v[p99]*1000, NR
    }'
}

run_curl_latency() {
  local label="$1" slug="$2"; shift 2
  local tmp="$STATE_DIR/$slug.txt"
  : >"$tmp"
  # Warmup: discarded.
  for _ in $(seq 1 "$WARMUP"); do
    curl -sk "$@" -o /dev/null "https://127.0.0.1:$PORT/" || true
  done
  local before after
  before=$(cpu_ticks)
  for _ in $(seq 1 "$REQUESTS"); do
    curl -sk "$@" -o /dev/null -w '%{time_total}\n' "https://127.0.0.1:$PORT/" >>"$tmp" || true
  done
  after=$(cpu_ticks)
  local cpu_ms
  cpu_ms=$(awk -v d="$((after - before))" -v hz="$(getconf CLK_TCK)" 'BEGIN{printf "%.1f", d*1000/hz}')
  local p50 p99 n
  read -r p50 p99 n < <(percentiles <"$tmp")
  printf '%-22s p50=%7s ms p99=%7s ms n=%s cpu=%s ms\n' "$label" "$p50" "$p99" "$n" "$cpu_ms"
}

run_curl_reuse() {
  local label="$1" slug="$2"; shift 2
  local tmp="$STATE_DIR/$slug.txt"
  : >"$tmp"
  local args=()
  for _ in $(seq 1 "$REQUESTS"); do
    args+=(-o /dev/null -w '%{time_total}\n' "https://127.0.0.1:$PORT/")
  done
  # Warmup on a throwaway connection.
  curl -sk "$@" -o /dev/null "https://127.0.0.1:$PORT/" >/dev/null 2>&1 || true
  local before after
  before=$(cpu_ticks)
  curl -sk "$@" "${args[@]}" >>"$tmp" 2>/dev/null || true
  after=$(cpu_ticks)
  local cpu_ms
  cpu_ms=$(awk -v d="$((after - before))" -v hz="$(getconf CLK_TCK)" 'BEGIN{printf "%.1f", d*1000/hz}')
  local p50 p99 n
  read -r p50 p99 n < <(percentiles <"$tmp")
  printf '%-22s p50=%7s ms p99=%7s ms n=%s cpu=%s ms\n' "$label" "$p50" "$p99" "$n" "$cpu_ms"
}

echo
echo "== TLS handshake (openssl s_time, 5s each) =="
if command -v openssl >/dev/null 2>&1; then
  openssl s_time -connect "127.0.0.1:$PORT" -new -time 5 2>&1 \
    | tr '\r' '\n' | grep -E 'connections in .*s;' | tail -1 \
    | sed 's/^/full handshake:   /' || true
  openssl s_time -connect "127.0.0.1:$PORT" -reuse -time 5 2>&1 \
    | tr '\r' '\n' | grep -E 'connections in .*s;' | tail -1 \
    | sed 's/^/resumed handshake:/' || true
else
  echo "openssl not available; skipping handshake rows"
fi

echo
echo "== Request latency (isolated from WAF) =="
run_curl_latency "full handshake" "full-handshake" --http2
run_curl_reuse "h2 reused" "h2-reused" --http2
run_curl_reuse "http/1.1 keepalive" "http1-keepalive" --http1.1

echo
echo "report written under $STATE_DIR"
