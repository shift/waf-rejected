#!/usr/bin/env bash
# Generate the release CycloneDX SBOM and its checksum.
#
# Usage:
#   ./scripts/generate-sbom.sh [VERSION] [OUTPUT_DIR]
#
# VERSION defaults to the version in Cargo.toml. OUTPUT_DIR defaults to the
# repository root. The script always writes:
#   waf-rejected-<version>.cdx.json
#   waf-rejected-<version>.cdx.json.sha256
#
# cargo-cyclonedx is part of the Nix dev shell. When the script is run outside
# the dev shell it falls back to a pinned nixpkgs invocation, so release
# generation does not depend on a globally installed cargo subcommand.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

VERSION="${1:-$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n1)}"
OUT_DIR="${2:-$ROOT}"

if [[ -z "$VERSION" ]]; then
    echo "error: could not determine version from Cargo.toml" >&2
    exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
    echo "error: jq is required to add the Coraza reactor component" >&2
    echo "       run this script from 'nix develop' or install jq" >&2
    exit 1
fi

mkdir -p "$OUT_DIR"

# cargo-cyclonedx honours SOURCE_DATE_EPOCH. Use the commit timestamp so the
# SBOM metadata is stable for a given source revision.
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}"

if command -v cargo-cyclonedx >/dev/null 2>&1 && command -v cargo >/dev/null 2>&1; then
    CARGO=(cargo)
else
    echo "cargo-cyclonedx not found in PATH; using pinned nixpkgs invocation" >&2
    CARGO=(nix shell nixpkgs#cargo-cyclonedx nixpkgs#cargo -c cargo)
fi

RAW="waf-rejected-${VERSION}.json"
OUT="${OUT_DIR}/waf-rejected-${VERSION}.cdx.json"

echo "Generating CycloneDX SBOM for waf-ingress ${VERSION}..."
"${CARGO[@]}" cyclonedx \
    --format json \
    --spec-version 1.5 \
    --all \
    --override-filename "waf-rejected-${VERSION}"

if [[ ! -s "$RAW" ]]; then
    echo "error: cargo-cyclonedx did not produce $RAW" >&2
    exit 1
fi

# cargo-cyclonedx only inventories Rust crates. Record the shipped WASI
# reactor explicitly so the SBOM names the module digest and the Apache-2.0
# Coraza/CRS licensing obligation.
REACTOR_SHA="$(sha256sum wasm/coraza_reactor/coraza_reactor.wasm | awk '{print $1}')"
jq --arg sha "$REACTOR_SHA" \
    '.components += [{
      "type": "file",
      "name": "coraza_reactor.wasm",
      "version": "coraza-3.3.3",
      "hashes": [{"alg": "SHA-256", "content": $sha}],
      "licenses": [{"license": {"id": "Apache-2.0"}}],
      "properties": [
        {"name": "waf:component", "value": "Coraza WASI reactor built with Go 1.24 and Coraza v3.3.3"},
        {"name": "waf:license-note", "value": "Coraza and referenced OWASP CRS material are Apache-2.0; see wasm/coraza_reactor/LICENSE-CRS"},
        {"name": "waf:source", "value": "wasm/coraza_reactor/main.go"}
      ]
    }]' "$RAW" > "${OUT}.tmp"
mv "${OUT}.tmp" "$OUT"
rm -f "$RAW"

test -s "$OUT"
(
    cd "$OUT_DIR"
    sha256sum "waf-rejected-${VERSION}.cdx.json" > "waf-rejected-${VERSION}.cdx.json.sha256"
)

echo "ok: $OUT"
echo "ok: ${OUT}.sha256"
