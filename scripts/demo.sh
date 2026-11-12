#!/usr/bin/env bash
#
# Runnable WAF demo: mock upstream + minimal default-engine WAF.
#
# Starts both processes on throwaway loopback ports, sends benign, SQL
# injection, XSS and gRPC requests, prints the result of each and cleans up.
# Artifacts (config, logs, protobuf frame) live under /tmp/opencode/waf-demo-*.
#
# Usage:
#   ./scripts/demo.sh
#   WAF_BIN=./result/bin/waf-ingress ./scripts/demo.sh
#
# Environment:
#   WAF_BIN  Path to a waf-ingress binary. Defaults to ./result/bin/waf-ingress,
#            then builds one with `nix develop -c cargo build --bin waf-ingress`.

set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

TMP_BASE="${TMPDIR:-/tmp/opencode}"
mkdir -p "$TMP_BASE"
DEMO_DIR="$(mktemp -d "$TMP_BASE/waf-demo-XXXXXX")"

WAF_PID=""
UPSTREAM_PID=""

cleanup() {
  local status=$?
  trap - EXIT INT TERM
  if [[ -n "$WAF_PID" ]] && kill -0 "$WAF_PID" 2>/dev/null; then
    kill -TERM "$WAF_PID" 2>/dev/null || true
    wait "$WAF_PID" 2>/dev/null || true
  fi
  if [[ -n "$UPSTREAM_PID" ]] && kill -0 "$UPSTREAM_PID" 2>/dev/null; then
    kill -TERM "$UPSTREAM_PID" 2>/dev/null || true
    wait "$UPSTREAM_PID" 2>/dev/null || true
  fi
  printf '\nArtifacts: %s\n' "$DEMO_DIR"
  exit "$status"
}
trap cleanup EXIT INT TERM

pick_port() {
  local port
  for _ in $(seq 1 200); do
    port=$(( 20000 + RANDOM % 20000 ))
    if ! nc -z 127.0.0.1 "$port" >/dev/null 2>&1; then
      printf '%s' "$port"
      return 0
    fi
  done
  printf 'error: could not find a free port\n' >&2
  return 1
}

WAF_PORT="$(pick_port)"
HEALTH_PORT="$(pick_port)"
UPSTREAM_PORT="$(pick_port)"

if [[ -n "${WAF_BIN:-}" ]]; then
  :
elif [[ -x ./result/bin/waf-ingress ]]; then
  WAF_BIN=./result/bin/waf-ingress
else
  printf 'No waf-ingress binary found; building one...\n'
  nix develop -c cargo build --bin waf-ingress
  WAF_BIN=./target/debug/waf-ingress
fi

if [[ ! -x "$WAF_BIN" ]]; then
  printf 'error: WAF binary is not executable: %s\n' "$WAF_BIN" >&2
  exit 1
fi

UPSTREAM_IMPL=""
if command -v perl >/dev/null 2>&1; then
  UPSTREAM_IMPL=perl
elif command -v python3 >/dev/null 2>&1; then
  UPSTREAM_IMPL=python3
else
  printf 'error: need perl or python3 for the mock upstream\n' >&2
  exit 1
fi

cat >"$DEMO_DIR/upstream.pl" <<'PERL'
use strict;
use warnings;
use IO::Socket::INET;

my $port = shift or die "usage: upstream.pl PORT\n";
my $server = IO::Socket::INET->new(
    LocalAddr => '127.0.0.1',
    LocalPort => $port,
    Listen    => 64,
    ReuseAddr => 1,
    Proto     => 'tcp',
) or die "listen: $!\n";

while (my $client = $server->accept) {
    $client->autoflush(1);
    my $line = <$client>;
    my $content_length = 0;
    while (my $header = <$client>) {
        last if $header =~ /^\r?\n$/;
        $content_length = $1 if $header =~ /^Content-Length:\s*(\d+)/i;
    }
    if ($content_length > 0) {
        my $body = '';
        read($client, $body, $content_length);
    }
    print $client "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nok\n";
    close $client;
}
PERL

cat >"$DEMO_DIR/upstream.py" <<'PY'
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

class Handler(BaseHTTPRequestHandler):
    def _respond(self):
        length = int(self.headers.get("Content-Length", "0") or 0)
        if length:
            self.rfile.read(length)
        self.send_response(200)
        self.send_header("Content-Length", "3")
        self.end_headers()
        self.wfile.write(b"ok\n")

    do_GET = _respond
    do_POST = _respond

    def log_message(self, *args):
        pass

ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), Handler).serve_forever()
PY

cat >"$DEMO_DIR/config.toml" <<EOF
bind_addr = "127.0.0.1:$WAF_PORT"
health_bind_addr = "127.0.0.1:$HEALTH_PORT"
upstream_uri = "http://127.0.0.1:$UPSTREAM_PORT"

[proxy]
upstream_url = "http://127.0.0.1:$UPSTREAM_PORT"
bind_addr = "127.0.0.1:$WAF_PORT"
timeout_seconds = 10
max_request_size = 1048576

[server]
request_timeout_secs = 10
keep_alive_timeout_secs = 30
enable_http2 = true
enable_http3 = false
supported_http_versions = ["1.0", "1.1", "2"]
max_body_size = 1048576

[logging]
level = "info"
json_format = false

[waf]
enabled = true
fail_mode = "closed"

[waf.rate_limit]
per_ip_enabled = false
global_enabled = false

[waf.content_inspection]
enabled = true
inspect_headers = true
inspect_body = true
max_body_size = 1048576

[waf.security_events]
enabled = true
min_threat_level = "medium"
enable_cef = false
enable_otel = false

[storage]
enabled = false
EOF

if [[ "$UPSTREAM_IMPL" == "perl" ]]; then
  perl "$DEMO_DIR/upstream.pl" "$UPSTREAM_PORT" >"$DEMO_DIR/upstream.log" 2>&1 &
else
  python3 "$DEMO_DIR/upstream.py" "$UPSTREAM_PORT" >"$DEMO_DIR/upstream.log" 2>&1 &
fi
UPSTREAM_PID=$!

WAF_CONFIG_FILE="$DEMO_DIR/config.toml" "$WAF_BIN" >"$DEMO_DIR/waf.log" 2>&1 &
WAF_PID=$!

printf 'WAF:      %s (proxy 127.0.0.1:%s, health 127.0.0.1:%s)\n' "$WAF_BIN" "$WAF_PORT" "$HEALTH_PORT"
printf 'Upstream: 127.0.0.1:%s (%s)\n\n' "$UPSTREAM_PORT" "$UPSTREAM_IMPL"

ready=0
for _ in $(seq 1 150); do
  if ! kill -0 "$WAF_PID" 2>/dev/null; then
    printf 'error: WAF exited during startup\n' >&2
    cat "$DEMO_DIR/waf.log" >&2
    exit 1
  fi
  if curl --noproxy '*' -fsS --max-time 1 \
      "http://127.0.0.1:$HEALTH_PORT/health/ready" >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 0.2
done

if [[ "$ready" != "1" ]]; then
  printf 'error: WAF did not become ready\n' >&2
  cat "$DEMO_DIR/waf.log" >&2
  exit 1
fi

status() {
  curl --noproxy '*' -sS -o /dev/null -w '%{http_code}' --max-time 10 "$@"
}

GRPC_FRAME="$DEMO_DIR/empty-message.bin"
printf '\x00\x00\x00\x00\x00' >"$GRPC_FRAME"

benign="$(status "http://127.0.0.1:$WAF_PORT/hello")"
sqli="$(status "http://127.0.0.1:$WAF_PORT/?id=1%20UNION%20SELECT%20*%20FROM%20users")"
xss="$(status -X POST --data '<script>alert(1)</script>' "http://127.0.0.1:$WAF_PORT/login")"
grpc="$(status -X POST \
  -H 'content-type: application/grpc' \
  -H 'te: trailers' \
  --data-binary "@$GRPC_FRAME" \
  "http://127.0.0.1:$WAF_PORT/demo.Echo/Say")"

fail=0
report() {
  local label="$1" actual="$2" expected="$3" verdict="$4"
  local result="ok"
  if [[ "$actual" != "$expected" ]]; then
    result="FAIL"
    fail=1
  fi
  printf '%-40s %s (expected %s, %s) [%s]\n' "$label" "$actual" "$expected" "$verdict" "$result"
}

report "benign GET /hello" "$benign" "200" "allowed"
report "sqli query string" "$sqli" "403" "blocked"
report "xss request body" "$xss" "403" "blocked"
if [[ "$grpc" == "403" ]]; then
  printf '%-40s %s (unexpected WAF block) [FAIL]\n' "grpc envelope" "$grpc"
  fail=1
else
  printf '%-40s %s (forwarded, envelope-only) [ok]\n' "grpc envelope" "$grpc"
fi

printf '\nWAF log: %s\n' "$DEMO_DIR/waf.log"
if [[ "$fail" != "0" ]]; then
  printf 'Demo FAILED\n' >&2
  exit 1
fi
printf 'Demo PASSED\n'
