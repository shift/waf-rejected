#!/usr/bin/env bash
# Run the real HTTP/2 gRPC end-to-end tests through the WAF proxy.
#
# The tests start a TLS HTTP/2 gRPC upstream, a TLS/HTTP2 WafProxyService and
# real ALPN h2 / HTTP/1.1 clients. They are ignored by default because they
# bind local ports and generate certificates.
#
# Usage:
#   ./scripts/test-grpc-e2e.sh
#   ./scripts/test-grpc-e2e.sh unary_grpc_over_h2
#
# Any argument is passed to cargo test as a test-name filter.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

FILTER="${1:-grpc_h2_e2e}"

exec nix develop -c cargo test --test integration "$FILTER" -- --ignored --nocapture
