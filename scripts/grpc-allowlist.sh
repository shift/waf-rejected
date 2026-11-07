#!/usr/bin/env bash
# Generate a gRPC method allowlist from a protobuf FileDescriptorSet.
#
# Usage:
#   ./scripts/grpc-allowlist.sh --descriptor descriptor.binpb \
#       --output grpc-allowlist.json
#
# The descriptor must be compiled with --include_imports so that every request
# and response type (including google.protobuf.* well-known types) is present
# in the descriptor set:
#
#   protoc --descriptor_set_out=descriptor.binpb --include_imports \
#       -I proto proto/acme/billing.proto
#
# All arguments are forwarded to the grpc-allowlist binary; see
# `./scripts/grpc-allowlist.sh --help` and docs/grpc-inspection.md.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

exec cargo run --quiet --bin grpc-allowlist -- "$@"
