#!/usr/bin/env bash
# Reproducible end-to-end load validation for waf-ingress.
#
# Builds release binaries with the Nix toolchain, writes a throwaway config
# under /tmp/opencode, then runs the load-validate harness. The harness owns
# the mock upstream and starts/stops one waf-ingress child around the whole
# matrix, so every cell sees the same warm reactor pool.
#
# Usage:
#   scripts/load-validate.sh                 # full default matrix
#   scripts/load-validate.sh --duration-secs 3 --warmup-secs 1 \
#       --profiles bodyless,form-1k --concurrency 1,4   # smoke
#
# Environment:
#   OUT_DIR        result directory (default /tmp/opencode/load-validation)
#   WAF_PORT       ingress port (default 39080)
#   HEALTH_PORT    health port (default 39081)
#   UPSTREAM_PORT  mock upstream port (default 39000)
#   CARGO_TARGET_DIR  optional shared target directory
#   ADMISSION_ENABLED  heavy-inspection admission control (default true; false
#                      reproduces the pre-fix bypass for A/B validation)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${OUT_DIR:-/tmp/opencode/load-validation}"
WAF_PORT="${WAF_PORT:-39080}"
HEALTH_PORT="${HEALTH_PORT:-39081}"
UPSTREAM_PORT="${UPSTREAM_PORT:-39000}"
# A/B switch for validation: `false` reproduces the pre-fix behaviour where
# protocol content scans bypassed the heavy pool.
ADMISSION_ENABLED="${ADMISSION_ENABLED:-true}"

mkdir -p "$OUT_DIR"
rm -f "$OUT_DIR"/results.json "$OUT_DIR"/fixture.json "$OUT_DIR"/summary.md \
      "$OUT_DIR"/waf-ingress.log "$OUT_DIR"/config.toml \
      "$OUT_DIR"/grpc-allowlist.json

# Minimal IR v2 artifact: only `/acme.Content/Scan` has descriptor metadata,
# so only that load profile triggers the Coraza gRPC content scan. Unknown
# methods keep the envelope-only path used by the other gRPC profiles.
cat >"$OUT_DIR/grpc-allowlist.json" <<'EOF'
{
  "ir_version": 2,
  "source": {"kind": "protobuf", "sha256": "0000000000000000000000000000000000000000000000000000000000000000"},
  "methods": [
    {"path": "/acme.Content/Scan", "client_streaming": false, "server_streaming": false,
     "input": "acme.Request", "output": "acme.Response", "max_message_bytes": 4194304}
  ],
  "messages": [
    {"message": "acme.Request", "fields": [
      {"name": "name", "number": 1, "type": "string"}
    ]}
  ],
  "unknown_method_action": "allow"
}
EOF

cat >"$OUT_DIR/config.toml" <<EOF
# Throwaway load-validation config. Not a production configuration.
bind_addr = "127.0.0.1:${WAF_PORT}"
health_bind_addr = "127.0.0.1:${HEALTH_PORT}"
upstream_uri = "http://127.0.0.1:${UPSTREAM_PORT}"

[proxy]
upstream_url = "http://127.0.0.1:${UPSTREAM_PORT}"
bind_addr = "127.0.0.1:${WAF_PORT}"
timeout_seconds = 120
max_request_size = 10485760

[server]
max_connections = 4096
trusted_proxies = []
request_timeout_secs = 120
keep_alive_timeout_secs = 90
enable_http2 = false
enable_http3 = false
supported_http_versions = ["1.0", "1.1"]
max_body_size = 10485760

[server.tls]
enabled = false

[logging]
level = "warn"
json_format = false

[waf]
enabled = true
fail_mode = "closed"
upstream_timeout_ms = 120000

[waf.rate_limit]
# Disabled so the matrix measures inspection capacity, not the default
# 100 req/min per-IP limiter. Production keeps rate limits enabled.
per_ip_enabled = false
global_enabled = false

[waf.security_events]
# Keep the run reproducible and avoid sled I/O in the latency path.
enabled = false
enable_cef = false
enable_otel = false
enable_sled = false

[waf.content_inspection]
enabled = true
inspect_headers = true
inspect_body = true
max_body_size = 10485760
threat_patterns = ["sql_injection", "xss", "command_injection", "path_traversal"]

[waf.geo_blocking]
enabled = false
blocked_countries = []

[waf.coraza]
enabled = true
# Defaults are deliberately unchanged: 64 KiB payload cap, 5 s eval timeout,
# auto pool (cores clamped to 8).
max_payload_bytes = 65536
memory_limit_bytes = 268435456
eval_timeout_ms = 5000
pool_size = 0

[waf.grpc]
enabled = true
method_allowlist = []
allowlist_file = "${OUT_DIR}/grpc-allowlist.json"
content_scan = "strings"
max_message_bytes = 4194304
max_frames = 64

[waf.admission]
enabled = ${ADMISSION_ENABLED}

[security.auth]
enabled = false
api_keys = []

[security.ai]
enabled = false

[security.compliance]
enabled = false
EOF

if [[ "${SKIP_BUILD:-0}" == "1" ]]; then
  echo "==> SKIP_BUILD=1: using existing release binaries"
  cd "$ROOT"
else
  echo "==> Building release binaries (nix develop -c cargo build --release)"
  cd "$ROOT"
  nix develop -c cargo build --release --bin waf-ingress --bin load-validate
fi

TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
WAF_BIN="$TARGET_DIR/release/waf-ingress"
LOAD_BIN="$TARGET_DIR/release/load-validate"
test -x "$WAF_BIN"
test -x "$LOAD_BIN"

echo "==> Config: $OUT_DIR/config.toml"
echo "==> WAF: $WAF_BIN"
echo "==> Mock upstream: 127.0.0.1:${UPSTREAM_PORT}"

OUTPUT_ARGS=()
if [[ " $* " != *" --output-dir "* ]]; then
  OUTPUT_ARGS=(--output-dir "$OUT_DIR")
fi

if [[ -z "${LOAD_VALIDATE_RUSTC:-}" ]]; then
  LOAD_VALIDATE_RUSTC="$(
    nix develop -c rustc --version 2>/dev/null | grep -E '^rustc ' | tail -1 || true
  )"
  LOAD_VALIDATE_RUSTC="${LOAD_VALIDATE_RUSTC:-unknown}"
fi
export LOAD_VALIDATE_RUSTC

set +e
"$LOAD_BIN" \
  --waf-bin "$WAF_BIN" \
  --config "$OUT_DIR/config.toml" \
  --health-url "http://127.0.0.1:${HEALTH_PORT}/health" \
  --upstream-port "$UPSTREAM_PORT" \
  "${OUTPUT_ARGS[@]}" \
  "$@"
STATUS=$?
set -e

if [[ -f "$OUT_DIR/summary.md" ]]; then
  echo
  echo "==> Summary: $OUT_DIR/summary.md"
  echo "==> JSON:    $OUT_DIR/results.json (fixture: $OUT_DIR/fixture.json)"
  echo "==> WAF log: $OUT_DIR/waf-ingress.log"
fi

exit "$STATUS"
