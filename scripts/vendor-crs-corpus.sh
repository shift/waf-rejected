#!/usr/bin/env bash
# Vendor the pinned OWASP CRS request regression suite as a decision corpus.
#
# Usage: ./scripts/vendor-crs-corpus.sh
#
# Downloads the official CRS source at the commit pinned by the Coraza reactor,
# converts the request-phase regression tests to the corpus format documented
# in docs/operations/detection-corpus.md, and writes provenance next to the
# corpus. Only request-phase cases are read; response-phase suites are ignored.
#
# The conversion needs `yq` (kislyuk yq or mikefarah yq) and `python3`. When
# they are not on PATH the script re-executes itself through `nix shell`.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="$ROOT/tests/corpus/crs"
CRS_VERSION="4.14.0"
CRS_COMMIT="b5b788b5bc50e68836e17995b191f72e848fed75"
CRS_URL="https://codeload.github.com/coreruleset/coreruleset/tar.gz/${CRS_COMMIT}"
CRS_TARBALL_SHA256="c970605a62ae2dc9213d5de775fc5fbbed9423bf0435ce5456d2ffc769702123"
MAX_PAYLOAD_BYTES="${CRS_CORPUS_MAX_PAYLOAD_BYTES:-61440}"

if ! command -v yq >/dev/null 2>&1 || ! command -v python3 >/dev/null 2>&1; then
  if [[ "${CRS_CORPUS_NIX_REEXEC:-0}" == "1" ]]; then
    echo "error: yq and python3 are required" >&2
    exit 1
  fi
  if ! command -v nix >/dev/null 2>&1; then
    echo "error: install yq and python3, or run this script through nix develop" >&2
    exit 1
  fi
  export CRS_CORPUS_NIX_REEXEC=1
  exec nix shell nixpkgs#yq nixpkgs#python3 -c bash "$0" "$@"
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "downloading CRS ${CRS_VERSION} (${CRS_COMMIT})"
curl -sSL --fail --max-time 180 "$CRS_URL" -o "$WORK/crs.tar.gz"

ACTUAL_SHA256="$(sha256sum "$WORK/crs.tar.gz" | awk '{print $1}')"
if [[ "$ACTUAL_SHA256" != "$CRS_TARBALL_SHA256" ]]; then
  echo "error: CRS tarball SHA-256 mismatch" >&2
  echo "  expected: $CRS_TARBALL_SHA256" >&2
  echo "  actual:   $ACTUAL_SHA256" >&2
  echo "  The pinned commit tarball changed; review the upstream source before updating the pin." >&2
  exit 1
fi

mkdir -p "$WORK/src"
tar xzf "$WORK/crs.tar.gz" -C "$WORK/src" --strip-components=1
SRC="$WORK/src"
YAML_ROOT="$SRC/tests/regression/tests"

if [[ ! -d "$YAML_ROOT" ]]; then
  echo "error: upstream regression tests not found in the tarball" >&2
  exit 1
fi

mkdir -p "$WORK/json"
while IFS= read -r file; do
  relative="${file#"$YAML_ROOT"/}"
  mkdir -p "$WORK/json/$(dirname "$relative")"
  if yq --version 2>/dev/null | grep -q 'mikefarah'; then
    yq -o=json '.' "$file" > "$WORK/json/$relative.json"
  else
    yq . "$file" > "$WORK/json/$relative.json"
  fi
done < <(find "$YAML_ROOT" -path '*/REQUEST-*/*.yaml' -type f | sort)

rm -rf "$DEST"
mkdir -p "$DEST"
cp "$SRC/LICENSE" "$DEST/LICENSE"

python3 "$ROOT/scripts/convert-crs-corpus.py" \
  --json-root "$WORK/json" \
  --yaml-root "$YAML_ROOT" \
  --rules-dir "$ROOT/wasm/coraza_reactor/rules/crs/rules" \
  --out "$DEST/corpus.json" \
  --smoke-out "$DEST/smoke.json" \
  --crs-version "$CRS_VERSION" \
  --crs-commit "$CRS_COMMIT" \
  --crs-url "$CRS_URL" \
  --tarball-sha256 "$CRS_TARBALL_SHA256" \
  --max-payload-bytes "$MAX_PAYLOAD_BYTES"

# Audit manifest: every upstream YAML that contributed to the corpus.
{
  echo "# SHA-256 manifest of the upstream CRS request regression files"
  echo "# Source: $CRS_URL"
  find "$YAML_ROOT" -path '*/REQUEST-*/*.yaml' -type f | sort | while IFS= read -r file; do
    relative="${file#"$YAML_ROOT"/}"
    printf '%s  %s\n' "$(sha256sum "$file" | awk '{print $1}')" "$relative"
  done
} > "$DEST/SOURCE_MANIFEST.txt"

EXCLUSIONS="$(python3 - "$DEST/corpus.json" <<'PY'
import json, sys
corpus = json.load(open(sys.argv[1], encoding="utf-8"))
for reason, count in corpus["source"].get("exclusions", {}).items():
    print(f"- {reason}: {count}")
PY
)"

cat > "$DEST/PROVENANCE.md" <<EOF
# OWASP Core Rule Set regression corpus provenance

- Project: OWASP Core Rule Set (CRS)
- Version: ${CRS_VERSION}
- Commit: \`${CRS_COMMIT}\`
- Source: ${CRS_URL}
- Source archive SHA-256: \`${CRS_TARBALL_SHA256}\`
- License: Apache License 2.0, see \`LICENSE\` in this directory.
- Upstream path: \`tests/regression/tests/REQUEST-*\`
- Converter: \`scripts/convert-crs-corpus.py\`
- Regenerate: \`./scripts/vendor-crs-corpus.sh\`

## What is included

Every case in \`corpus.json\` is a request-phase regression test copied from the
upstream YAML. No payloads were authored for this corpus. Each case records its
upstream file and test ID in the \`source\` object.

Request construction follows the upstream client: the converter adds the
\`application/x-www-form-urlencoded\` Content-Type and \`Content-Length\` defaults
that ftw applies to bodies, applies ftw's form re-encoding, and expands the
go-ftw \`{{ "x" | repeat N }}\` template. No other payload bytes are changed.

The upstream suite is a log-level suite. This corpus is a decision-level
projection for the default PL1 rule bundle:

- a case expecting a PL1 critical rule that contributes the critical inbound
  anomaly score (or a disruptive \`deny\`/\`drop\` rule) is \`block\`;
- a case expecting a PL1 warning/notice rule is \`allow\` and tagged
  \`detection-only\`, because the default inbound anomaly threshold is not met;
- a \`no_expect_ids\` case for a PL1 rule is \`allow\`.

## What is excluded

${EXCLUSIONS}

The largest exclusion is rule coverage above paranoia level 1: the vendored
reactor runs at the CRS default PL1 and this corpus does not change detection
defaults. Response-phase suites (\`RESPONSE-*\`) are not read at all. Cases that
only assert an HTTP status (without a CRS rule expectation) are excluded
because the status can come from the web server rather than CRS. Cases using
\`encoded_request\`, \`raw_request\`, \`autocomplete_headers\`, \`match_regex\`,
\`no_match_regex\`, \`expect_error\`, or multiple stages are excluded because they
cannot be represented by the request/decision envelope without changing the
test. Cases whose serialised payload exceeds the reactor's 60 KiB safety limit
are excluded and reported above.

## Integrity

\`SOURCE_MANIFEST.txt\` lists the SHA-256 of every upstream YAML that
contributed to the corpus. \`corpus.json\` records the source archive SHA-256
and the SHA-256 of the sorted \`<file-sha>  <path>\` manifest lines in
\`source.source_manifest_sha256\`.
EOF

echo "wrote ${DEST}/corpus.json"
echo "wrote ${DEST}/smoke.json"
echo "wrote ${DEST}/PROVENANCE.md"
echo "wrote ${DEST}/SOURCE_MANIFEST.txt"
