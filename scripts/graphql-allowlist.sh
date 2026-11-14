#!/usr/bin/env bash
# Generate a deterministic GraphQL persisted-query allowlist.
#
# Usage:
#   ./scripts/graphql-allowlist.sh --manifest persisted-queries.json \
#       --output graphql/allowlist.json
#   ./scripts/graphql-allowlist.sh --dir client/build/graphql \
#       --allow-mutations --output graphql/allowlist.json
#
# The manifest is a JSON list of {name, query} or {name, sha256} objects. A
# directory input reads every .graphql file and names the operation after the
# file stem. Queries are normalised (comments removed, commas and whitespace
# collapsed outside strings) before hashing.
#
# All arguments are forwarded to the graphql-allowlist binary; see
# `./scripts/graphql-allowlist.sh --help` and docs/graphql-inspection.md.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

exec cargo run --quiet --features wasm-reactor --bin graphql-allowlist -- "$@"
