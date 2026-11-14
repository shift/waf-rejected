#!/usr/bin/env bash
#
# Validate every shipped TOML configuration with the real loader.
#
# Loads config.toml, config.docker.toml, the root test configs,
# config/*.toml, config/examples/*.toml and deploy/compose/config.native.toml
# through `Config::load` (the same
# file + environment + `Config::validate` path used by `waf-ingress`). The test
# fails on unknown top-level or nested keys, malformed TOML, wrong types,
# unknown enum variants, feature-dependent settings, cross-field limit
# violations and unreadable allowlist artifacts.
#
# Unknown keys are a hard error: the config structs set
# `serde(deny_unknown_fields)`, and errors name the file, section/key path and
# source location. The test also covers env overrides and typo rejection.
#
# Usage:
#   ./scripts/validate-configs.sh
#   CONFIG_VALIDATE_NIX=0 ./scripts/validate-configs.sh   # run cargo directly
#
# Environment:
#   CONFIG_VALIDATE_NIX=0  Run cargo directly instead of via `nix develop -c`.

set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ "${CONFIG_VALIDATE_NIX:-1}" == "0" ]]; then
  CARGO_RUNNER=(cargo)
else
  if ! command -v nix >/dev/null 2>&1; then
    printf 'error: nix is not installed or not on PATH (set CONFIG_VALIDATE_NIX=0 to run cargo directly)\n' >&2
    exit 1
  fi
  CARGO_RUNNER=(nix develop -c cargo)
fi

printf 'Validating shipped configuration files with the real loader\n'
printf 'Repository: %s\n\n' "$ROOT_DIR"

"${CARGO_RUNNER[@]}" test --test config_files -- --nocapture
