#!/usr/bin/env bash
# Build and run the real WAF-Rejected <-> shift/distri-kv end-to-end tests.
#
# The distri-kv server is built from the pinned contract revision into
# /tmp/opencode/dkv-e2e (override with DISTRI_KV_DIR). The server checkout is
# never modified. The WAF is built from this worktree with the non-default
# `distri-kv` feature plus `export-sled` for the reputation fixture writer.
#
# Usage:
#   scripts/test-distri-e2e.sh
#
# Environment:
#   DISTRI_KV_DIR       server checkout (default /tmp/opencode/dkv-e2e)
#   DISTRI_KV_SERVER_BIN overrides the server binary path (skips the build)
#   PROTOC              protoc binary if not available in PATH

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DISTRI_KV_DIR="${DISTRI_KV_DIR:-/tmp/opencode/dkv-e2e}"
DISTRI_KV_REV="9079588bb9eb8e5fe15014e0b7af51fb20c2aecf"
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

echo "==> real distri-kv end-to-end tests (server: ${DISTRI_KV_SERVER_BIN})"
nix develop -c cargo test --features distri-kv,export-sled --test integration \
    distri_e2e -- --ignored --test-threads=1
