#!/usr/bin/env bash
# Regenerates the static tables in src/waf/native_detect/ from the vendored
# libinjection-go source. Run from the repository root.
set -euo pipefail

GO_DIR=native/coraza-sidecar/vendor/github.com/corazawaf/libinjection-go
OUT_DIR=src/waf/native_detect
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# ---------------------------------------------------------------------------
# SQLi: keyword table + fingerprint blacklist
# ---------------------------------------------------------------------------
sed -n "s/^\t\"\([^\"]*\)\": *'\(.\)',\$/\1\t\2/p" "$GO_DIR/sqli_data.go" > "$TMP/all.tsv"
awk -F'\t' '$2=="F"' "$TMP/all.tsv" | cut -f1 | LC_ALL=C sort > "$TMP/fp.txt"
awk -F'\t' '$2!="F"' "$TMP/all.tsv" | LC_ALL=C sort > "$TMP/kw.txt"

{
  cat <<'HEADER'
//! Generated from `libinjection-go` v0.2.2 (`sqli_data.go`). Do not edit.
//!
//! Upstream: <https://github.com/corazawaf/libinjection-go> (BSD-3-Clause),
//! itself a port of libinjection (C) by Nick Galbreath. The keyword table and
//! the fingerprint blacklist are data, not logic; `scripts/gen-native-detect-data.sh`
//! regenerates this file from the vendored Go source.
HEADER
  echo
  echo '/// SQL keywords and operators: `(uppercase token, libinjection category byte)`.'
  echo '///'
  echo '/// Sorted by token so lookups can binary-search without allocating.'
  echo 'pub(crate) static KEYWORDS: &[(&str, u8)] = &['
  awk -F'\t' -v q="'" '{ printf "    (\"%s\", b%s%s%s),\n", $1, q, $2, q }' "$TMP/kw.txt"
  echo '];'
  echo
  echo '/// Fingerprint blacklist: `0`-prefixed token-category strings that libinjection'
  echo '/// classifies as SQL injection. Sorted for binary search.'
  echo 'pub(crate) static FINGERPRINTS: &[&str] = &['
  awk '{ printf "    \"%s\",\n", $0 }' "$TMP/fp.txt"
  echo '];'
} > "$OUT_DIR/sqli_data.rs"

# ---------------------------------------------------------------------------
# XSS: black tags, event handlers, attributes
# ---------------------------------------------------------------------------
LC_ALL=C awk '/^var blackEvents/,/^}/' "$GO_DIR/xss_decls.go" \
  | sed -n 's/^\t{"\([A-Z0-9:-]*\)", *attributeType\([A-Za-z]*\)},.*$/\1\t\2/p' \
  | LC_ALL=C sort > "$TMP/events.tsv"
LC_ALL=C awk '/^var blacks/,/^}/' "$GO_DIR/xss_decls.go" \
  | sed -n 's/^\t{"\([A-Z0-9:-]*\)", *attributeType\([A-Za-z]*\)},.*$/\1\t\2/p' \
  | LC_ALL=C sort > "$TMP/attrs.tsv"
LC_ALL=C awk '/^var blackTags/,/^}/' "$GO_DIR/xss_decls.go" \
  | sed -n 's/^\t"\([A-Z0-9]*\)",.*$/\1/p' \
  | LC_ALL=C sort > "$TMP/tags.txt"

{
  cat <<'HEADER'
//! Generated from `libinjection-go` v0.2.2 (`xss_decls.go`). Do not edit.
//!
//! Upstream: <https://github.com/corazawaf/libinjection-go> (BSD-3-Clause),
//! itself a port of libinjection (C) by Nick Galbreath.
HEADER
  echo
  echo '/// Tags whose mere presence is XSS (`isBlackTag`). Sorted.'
  echo 'pub(crate) static BLACK_TAGS: &[&str] = &['
  awk '{ printf "    \"%s\",\n", $0 }' "$TMP/tags.txt"
  echo '];'
  echo
  echo '/// JavaScript event handler names accepted after `on` (`isBlackAttr`).'
  echo '/// Upstream maps every entry to `attributeTypeBlack`; sorted.'
  echo 'pub(crate) static BLACK_EVENTS: &[&str] = &['
  cut -f1 "$TMP/events.tsv" | awk '{ printf "    \"%s\",\n", $0 }'
  echo '];'
  echo
  echo '/// Black attributes and their handling: `(name, attribute type)`. Sorted.'
  echo 'pub(crate) static BLACK_ATTRS: &[(&str, u8)] = &['
  awk -F'\t' '{ t=$2; if (t=="Black") v=1; else if (t=="AttrURL") v=2; else if (t=="Style") v=3; else if (t=="AttrIndirect") v=4; else v=0; printf "    (\"%s\", %d),\n", $1, v }' "$TMP/attrs.tsv"
  echo '];'
} > "$OUT_DIR/xss_data.rs"

echo "wrote $OUT_DIR/sqli_data.rs ($(wc -l < "$TMP/kw.txt") keywords, $(wc -l < "$TMP/fp.txt") fingerprints)"
echo "run \`cargo fmt\` to normalize the generated files"
echo "wrote $OUT_DIR/xss_data.rs ($(wc -l < "$TMP/tags.txt") tags, $(wc -l < "$TMP/events.tsv") events, $(wc -l < "$TMP/attrs.tsv") attributes)"
