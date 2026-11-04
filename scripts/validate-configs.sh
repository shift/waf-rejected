#!/usr/bin/env bash
#
# Validate every shipped TOML configuration with the real loader.
#
# Loads config.toml, config.docker.toml, config/*.toml and
# config/examples/*.toml through `Config::load` (the same file + environment +
# `Config::validate` path used by `waf-ingress`). The test fails on malformed
# TOML, wrong types, unknown enum variants, feature-dependent settings,
# cross-field limit violations and unreadable allowlist artifacts.
#
# Unknown keys are NOT rejected: the config structs do not use serde's
# `deny_unknown_fields`, so a misspelled or obsolete key is silently ignored.
# The test prints every file it loads so reviewers can spot that class by eye.
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
