#!/usr/bin/env bash
# Build and run the real WAF-Rejected <-> shift/distri-kv end-to-end tests.
#
# The distri-kv server is built from the pinned contract revision into
# /tmp/opencode/dkv-lease-e2e (override with DISTRI_KV_DIR). The server
# checkout is never modified. The WAF is built from this worktree with the
# non-default `distri-kv` feature plus `export-sled` for the reputation
# fixture writer.
#
# The suite covers node registration/heartbeats, policy generations and
# signatures, reputation, telemetry, and the Raft-backed shared-budget lease
# contract: grant/deny, idempotent retry, expiry fail-closed, release refund,
# cluster restart, two WAF instances sharing one bucket, and local_only
# fallback.
#
# Usage:
#   scripts/test-distri-e2e.sh
#
# Environment:
#   DISTRI_KV_DIR       server checkout (default /tmp/opencode/dkv-lease-e2e)
#   DISTRI_KV_SERVER_BIN overrides the server binary path (skips the build)
#   PROTOC              protoc binary if not available in PATH

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DISTRI_KV_DIR="${DISTRI_KV_DIR:-/tmp/opencode/dkv-lease-e2e}"
DISTRI_KV_REV="69af979a0b377486aa8290142f7cfaae7a5d4586"
DISTRI_KV_REMOTE="${DISTRI_KV_REMOTE:-https://github.com/shift/distri-kv.git}"
DISTRI_KV_SERVER_BIN="${DISTRI_KV_SERVER_BIN:-${DISTRI_KV_DIR}/target/debug/distri-kv-server}"

if [[ ! -x "${DISTRI_KV_SERVER_BIN}" ]]; then
    if [[ ! -d "${DISTRI_KV_DIR}/.git" ]]; then
        echo "==> cloning ${DISTRI_KV_REMOTE} to ${DISTRI_KV_DIR}"
        git clone "${DISTRI_KV_REMOTE}" "${DISTRI_KV_DIR}"
    fi

    echo "==> checking out distri-kv ${DISTRI_KV_REV}"
    if ! git -C "${DISTRI_KV_DIR}" cat-file -e "${DISTRI_KV_REV}^{commit}" 2>/dev/null; then
        git -C "${DISTRI_KV_DIR}" fetch origin "${DISTRI_KV_REV}" || git -C "${DISTRI_KV_DIR}" fetch origin
    fi
    git -C "${DISTRI_KV_DIR}" checkout --detach "${DISTRI_KV_REV}"

    # distri-kv's proto build needs protoc; the WAF devShell deliberately does
    # not ship it because the WAF vendors the generated bindings.
    protoc_bin="${PROTOC:-$(command -v protoc || true)}"
    if [[ -z "${protoc_bin}" ]]; then
        protoc_bin="$(nix build --no-link --print-out-paths 'nixpkgs#protobuf')/bin/protoc"
    fi

    echo "==> building distri-kv-server (${DISTRI_KV_REV})"
    (
        cd "${ROOT}"
        PATH="$(dirname "${protoc_bin}"):${PATH}" \
            nix develop -c cargo build \
                --manifest-path "${DISTRI_KV_DIR}/Cargo.toml" \
                -p distri-kv --bin distri-kv-server
    )
fi

export DISTRI_KV_SERVER_BIN

cd "${ROOT}"

echo "==> focused fallback semantics"
nix develop -c cargo test --features distri-kv,export-sled --test integration \
    distri_e2e::fallback_modes_are_explicit -- --exact

echo "==> shared-budget lease end-to-end tests"
LEASE_TESTS=(
    distri_e2e::two_waf_instances_share_one_bucket_budget
    distri_e2e::lease_grant_deny_and_idempotent_retry
    distri_e2e::lease_expiry_fails_closed_and_release_refunds
    distri_e2e::lease_state_survives_cluster_restart
    distri_e2e::policy_signature_verification_uses_real_server_key
    distri_e2e::local_only_lease_fallback_keeps_serving_when_server_dies
)
for test in "${LEASE_TESTS[@]}"; do
    nix develop -c cargo test --features distri-kv,export-sled --test integration \
        "${test}" -- --ignored --exact --test-threads=1
done

echo "==> real distri-kv end-to-end tests (server: ${DISTRI_KV_SERVER_BIN})"
nix develop -c cargo test --features distri-kv,export-sled --test integration \
    distri_e2e -- --ignored --test-threads=1
