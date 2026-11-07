#!/usr/bin/env bash
# Regenerates the transform differential fixtures from the *vendored* Coraza
# Go sources, so the Rust implementation is compared against the exact code the
# WASI reactor runs.
#
# Usage (from the repository root):
#   nix develop -c scripts/gen-transform-fixture.sh
#
# Outputs:
#   tests/fixtures/transform_parity.json
#   src/waf/transforms/entities.rs
#   src/waf/transforms/case_tables.rs
#
# The script copies the vendored sources into target/transformgen (never into
# the source tree), renames their package, and runs the generator offline.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"

vendor=wasm/coraza_reactor/vendor
work=target/transformgen
rm -rf "$work"
mkdir -p "$work/internal/strings" "$work/html"

if ! command -v go >/dev/null 2>&1; then
    echo "gen-transform-fixture: go toolchain not found (run via nix develop)" >&2
    exit 1
fi

# Coraza's internal string helpers used by the transform sources.
cp "$vendor/github.com/corazawaf/coraza/v3/internal/strings/strings.go" \
    "$work/internal/strings/strings.go"

# The transforms themselves. Only the files needed by the transforms under
# test are copied; the registry (transformations.go) drags in plugintypes.
transform_files=(
    base64decode.go
    cmd_line.go
    compress_whitespace.go
    css_decode.go
    escape_seq_decode.go
    html_entity_decode.go
    js_decode.go
    lowercase.go
    normalise_path.go
    normalise_path_win.go
    remove_nulls.go
    remove_whitespace.go
    replace_comments.go
    replace_nulls.go
    trim.go
    trim_left.go
    trim_right.go
    uppercase.go
    url_decode.go
    url_decode_uni.go
)
for file in "${transform_files[@]}"; do
    src="$vendor/github.com/corazawaf/coraza/v3/internal/transformations/$file"
    sed 's/^package transformations$/package main/' "$src" > "$work/$file"
done
# Point htmlEntityDecode at the local copy of the Go HTML package.
sed -i 's#"golang.org/x/net/html"#"github.com/corazawaf/coraza/v3/html"#' \
    "$work/html_entity_decode.go"

# Minimal copy of golang.org/x/net/html: UnescapeString, its entity tables and
# the writer interface the unused escape helpers reference.
cp "$vendor/golang.org/x/net/html/entity.go" "$work/html/entity.go"
cp "$vendor/golang.org/x/net/html/escape.go" "$work/html/escape.go"
cat > "$work/html/writer.go" <<'EOF'
package html

import "io"

// writer is defined in render.go upstream; only the interface is needed to
// compile the escape helpers that UnescapeString shares a file with.
type writer interface {
	io.Writer
	WriteString(string) (int, error)
}
EOF

cat > "$work/go.mod" <<'EOF'
module github.com/corazawaf/coraza/v3

go 1.24
EOF

cp scripts/transformgen/main.go "$work/main.go"

mkdir -p tests/fixtures src/waf/transforms
# The dev shell exports GOOS=js GOARCH=wasm for the reactor build; the fixture
# generator is a host program.
(cd "$work" && GOOS=linux GOARCH=amd64 go run . \
    "$root/tests/fixtures/transform_parity.json" \
    "$root/src/waf/transforms/entities.rs" \
    "$root/src/waf/transforms/case_tables.rs")

echo "wrote tests/fixtures/transform_parity.json"
echo "wrote src/waf/transforms/entities.rs"
echo "wrote src/waf/transforms/case_tables.rs"
