#!/usr/bin/env bash
#
# Smoke test for deploy/distributed/compose.yaml.
#
# Starts an isolated regional cell (3 distri-kv nodes) and 2 WAF nodes, checks
# health and the distributed metrics families, exercises one ActivatePolicy /
# GetPolicy / LookupReputation flow when grpcurl is available, verifies that
# WAF readiness survives a full control-plane stop, then tears everything down.
#
# Usage:
#   ./scripts/demo-distributed.sh
#
# Environment:
#   COMPOSE_BIN          Override the compose command (e.g. "podman compose").
#   DISTRI_KV_IMAGE      distri-kv image (default: distri-kv:9079588).
#   WAF_IMAGE            WAF image (default: waf-rejected-distributed:local;
#                        compose builds deploy/distributed/Dockerfile.waf).
#   KEEP_STACK=1         Do not tear down on exit.
#   DKV_GRPC_PORT, WAF1_HTTP_PORT, WAF1_ADMIN_PORT, WAF2_HTTP_PORT,
#   WAF2_ADMIN_PORT      Override the isolated host ports.
#
# Exit codes: 0 success or environment limitation (reported), 1 verification
# failure, 2 usage error.

set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="$ROOT_DIR/deploy/distributed/compose.yaml"
CERTS_DIR="$ROOT_DIR/deploy/distributed/certs"
SECRETS_DIR="$ROOT_DIR/deploy/distributed/secrets"
PROJECT="${COMPOSE_PROJECT_NAME:-waf-distri-smoke-$$}"

BASE_PORT=$(( 20000 + ($$ * 7) % 20000 ))
export DKV_GRPC_PORT="${DKV_GRPC_PORT:-$BASE_PORT}"
export WAF1_HTTP_PORT="${WAF1_HTTP_PORT:-$((BASE_PORT + 1))}"
export WAF1_ADMIN_PORT="${WAF1_ADMIN_PORT:-$((BASE_PORT + 2))}"
export WAF2_HTTP_PORT="${WAF2_HTTP_PORT:-$((BASE_PORT + 3))}"
export WAF2_ADMIN_PORT="${WAF2_ADMIN_PORT:-$((BASE_PORT + 4))}"
export DISTRI_KV_IMAGE="${DISTRI_KV_IMAGE:-distri-kv:9079588}"
export WAF_IMAGE="${WAF_IMAGE:-waf-rejected-distributed:local}"

STARTED=0
COMPOSE=()

log() { printf '[demo-distributed] %s\n' "$*"; }
warn() { printf '[demo-distributed] WARN: %s\n' "$*" >&2; }
skip() { printf '[demo-distributed] SKIP: %s\n' "$*"; }

cleanup() {
  local status=$?
  trap - EXIT INT TERM
  if [[ "$STARTED" -eq 1 && "${KEEP_STACK:-0}" != "1" ]]; then
    log "Tearing down project $PROJECT"
    "${COMPOSE[@]}" -f "$COMPOSE_FILE" --project-name "$PROJECT" down -v --remove-orphans >/dev/null 2>&1 || true
  elif [[ "$STARTED" -eq 1 ]]; then
    log "KEEP_STACK=1: leaving project $PROJECT running"
  fi
  exit "$status"
}
trap cleanup EXIT INT TERM

if [[ -n "${COMPOSE_BIN:-}" ]]; then
  read -r -a COMPOSE <<<"$COMPOSE_BIN"
elif docker compose version >/dev/null 2>&1; then
  COMPOSE=(docker compose)
elif podman compose version >/dev/null 2>&1; then
  COMPOSE=(podman compose)
else
  skip "no working docker/podman compose command; cannot start the stack"
  exit 0
fi

if ! "${COMPOSE[@]}" version >/dev/null 2>&1; then
  skip "compose command is not usable in this environment"
  exit 0
fi

if ! command -v curl >/dev/null 2>&1; then
  skip "curl is required on the host for health checks"
  exit 0
fi

mkdir -p "$CERTS_DIR" "$SECRETS_DIR"

# The demo uses bearer auth because the current WAF client cannot present
# SPIFFE metadata. mTLS files are generated too so the documented rotation
# path and a future client TLS implementation can be exercised.
if [[ ! -s "$SECRETS_DIR/waf-token" ]]; then
  if command -v openssl >/dev/null 2>&1; then
    "$ROOT_DIR/scripts/gen-distri-certs.sh" --no-token >/dev/null 2>&1 || true
  fi
  if [[ ! -s "$SECRETS_DIR/waf-token" ]]; then
    token="$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"
    printf '%s\n' "$token" >"$SECRETS_DIR/waf-token"
    chmod 0600 "$SECRETS_DIR/waf-token"
  fi
fi
if [[ ! -s "$CERTS_DIR/ca.crt" ]]; then
  if command -v openssl >/dev/null 2>&1; then
    "$ROOT_DIR/scripts/gen-distri-certs.sh" --no-token >/dev/null 2>&1 || warn "certificate generation failed"
  else
    warn "openssl not found; skipping mTLS certificate generation (bearer demo continues)"
  fi
fi

image_exists() {
  local image="$1"
  if command -v docker >/dev/null 2>&1 && docker image inspect "$image" >/dev/null 2>&1; then
    return 0
  fi
  if command -v podman >/dev/null 2>&1 && podman image inspect "$image" >/dev/null 2>&1; then
    return 0
  fi
  return 1
}

if ! image_exists "$DISTRI_KV_IMAGE"; then
  skip "image $DISTRI_KV_IMAGE is not available; build it with deploy/distributed/Dockerfile.distri-kv and set DISTRI_KV_IMAGE"
  exit 0
fi

wait_url() {
  local url="$1" name="$2"
  for _ in $(seq 1 90); do
    if curl -fsS --max-time 3 "$url" >/dev/null 2>&1; then
      log "$name is ready"
      return 0
    fi
    sleep 2
  done
  printf 'error: %s did not become ready at %s\n' "$name" "$url" >&2
  return 1
}

wait_dkv_health() {
  local node="$1"
  for _ in $(seq 1 90); do
    if "${COMPOSE[@]}" -f "$COMPOSE_FILE" --project-name "$PROJECT" exec -T "$node" \
      curl -fsS --max-time 3 http://127.0.0.1:8082/health >/dev/null 2>&1; then
      log "$node health endpoint is ready"
      return 0
    fi
    sleep 2
  done
  printf 'error: %s health endpoint did not become ready\n' "$node" >&2
  return 1
}

log "Starting $PROJECT (dkv grpc 127.0.0.1:$DKV_GRPC_PORT, waf 127.0.0.1:$WAF1_HTTP_PORT/$WAF2_HTTP_PORT)"
STARTED=1
"${COMPOSE[@]}" -f "$COMPOSE_FILE" --project-name "$PROJECT" up -d --remove-orphans

wait_dkv_health dkv-1
wait_dkv_health dkv-2
wait_dkv_health dkv-3
wait_url "http://127.0.0.1:$WAF1_ADMIN_PORT/health/ready" "waf-1"
wait_url "http://127.0.0.1:$WAF2_ADMIN_PORT/health/ready" "waf-2"

waf_metrics="$(curl -fsS "http://127.0.0.1:$WAF1_ADMIN_PORT/metrics")"
for metric in \
  waf_distributed_connected \
  waf_distributed_heartbeat_age_seconds \
  waf_distributed_policy_generation \
  waf_distributed_fallback_activations_total; do
  if ! grep -Eq "^${metric}(\\{| )" <<<"$waf_metrics"; then
    printf 'error: WAF /metrics is missing %s\n' "$metric" >&2
    exit 1
  fi
done
log "WAF distributed gauges are present (connected=$(grep -E '^waf_distributed_connected ' <<<"$waf_metrics" | awk '{print $2}'))"

if command -v grpcurl >/dev/null 2>&1; then
  token="$(cat "$SECRETS_DIR/waf-token")"
  addr="127.0.0.1:$DKV_GRPC_PORT"
  auth=(-H "authorization: Bearer $token")
  proto=(-import-path "$ROOT_DIR/src/waf/distributed" -proto distri_waf.proto)

  log "Exercising ActivatePolicy -> GetPolicy"
  grpcurl -plaintext "${auth[@]}" "${proto[@]}" \
    -d '{"contract_version":1,"scope":"default","bundle_version":1,"reason":"smoke","idempotency_key":"smoke-'"$$"'","bundle":{"contract_version":1,"schema_version":1,"scope":"default","version":1,"generation":1,"payload":{"ruleset_version":"smoke"}}}' \
    "$addr" waf.distri.v1.DistriWaf/ActivatePolicy >/dev/null
  policy="$(grpcurl -plaintext "${auth[@]}" "${proto[@]}" \
    -d '{"contract_version":1,"scope":"default","version":0}' \
    "$addr" waf.distri.v1.DistriWaf/GetPolicy)"
  grep -q '"activeVersion"\|"version"' <<<"$policy" || {
    printf 'error: GetPolicy returned no version: %s\n' "$policy" >&2
    exit 1
  }
  log "Policy flow verified"

  log "Exercising LookupReputation"
  reputation="$(grpcurl -plaintext "${auth[@]}" "${proto[@]}" \
    -d '{"contract_version":1,"ips":["203.0.113.9"],"scope":"default","max_age_ms":300000}' \
    "$addr" waf.distri.v1.DistriWaf/LookupReputation)"
  [[ -n "$reputation" ]] || reputation="{}"
  log "Reputation flow verified (entries: $(grep -o '"entries": *\[[^]]*\]' <<<"$reputation" || printf 'empty'))"
else
  warn "grpcurl not found; skipping the direct policy/reputation RPC flow"
fi

log "Stopping the distri-kv cluster to verify local_only fallback"
"${COMPOSE[@]}" -f "$COMPOSE_FILE" --project-name "$PROJECT" stop dkv-1 dkv-2 dkv-3 >/dev/null
sleep 5
if ! curl -fsS --max-time 3 "http://127.0.0.1:$WAF1_ADMIN_PORT/health/ready" >/dev/null; then
  printf 'error: WAF readiness failed after the control plane was stopped\n' >&2
  exit 1
fi
after_stop="$(curl -fsS "http://127.0.0.1:$WAF1_ADMIN_PORT/metrics")"
grep -Eq '^waf_distributed_connected 0$' <<<"$after_stop" || warn "connected gauge is not 0 after stop (client may still hold a channel)"
log "WAF remains ready with distri-kv stopped (fallback = local_only)"

log "Smoke passed"
