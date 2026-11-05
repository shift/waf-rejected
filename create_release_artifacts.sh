#!/usr/bin/env bash
# Create release artifacts for distribution

set -euo pipefail

VERSION="${1:-}"
if [[ -z "$VERSION" ]]; then
    echo "Usage: $0 <version>"
    echo "Example: $0 0.1.0"
    exit 1
fi

echo "📦 Creating release artifacts for WAF-Rejected v$VERSION"
echo "======================================================="

# Ensure we have a release build with the same feature set as the Nix package
# and container image. `coraza-native` enables the opt-in native sidecar
# backend; the default `waf.coraza.backend` remains "rust". Cargo is
# incremental, so this is cheap when the tree is already built.
echo "🏗️  Building release binary..."
if [[ "${SKIP_BUILD:-0}" == "1" ]]; then
    echo "⏭️  SKIP_BUILD=1; using existing target/release/waf-ingress"
else
    cargo build --release --bin waf-ingress \
        --features http3,webtransport,wasm-reactor,coraza-native,rust-engine
fi
test -x target/release/waf-ingress || {
    echo "❌ target/release/waf-ingress is missing; run without SKIP_BUILD=1"
    exit 1
}

# Create release directory (replace any previous run).
RELEASE_DIR="waf-rejected-v$VERSION"
rm -rf "$RELEASE_DIR"
mkdir -p "$RELEASE_DIR"

echo "📁 Preparing release directory: $RELEASE_DIR"

# Copy main binary
cp target/release/waf-ingress "$RELEASE_DIR/"
echo "✅ Added main binary ($(ls -lh target/release/waf-ingress | awk '{print $5}'))"

# Copy enterprise test binaries if they exist
for binary in enterprise_performance_test enterprise_security_test enterprise_compliance_test enterprise_availability_test; do
    if [[ -f "target/release/$binary" ]]; then
        cp "target/release/$binary" "$RELEASE_DIR/"
        echo "✅ Added $binary"
    fi
done

# Copy other utility binaries
for binary in waf-events-query create_sample_db; do
    if [[ -f "target/release/$binary" ]]; then
        cp "target/release/$binary" "$RELEASE_DIR/"
        echo "✅ Added $binary"
    fi
done

# Copy documentation
echo "📚 Adding documentation..."
cp README.md "$RELEASE_DIR/"
cp CHANGELOG.md "$RELEASE_DIR/"
cp SECURITY.md "$RELEASE_DIR/"
cp LICENSE-* "$RELEASE_DIR/"

# Copy configuration examples
if [[ -d "config" ]]; then
    cp -r config "$RELEASE_DIR/"
    echo "✅ Added configuration examples"
fi

# Copy essential documentation
mkdir -p "$RELEASE_DIR/docs"
if [[ -d "docs" ]]; then
    cp -r docs/operations "$RELEASE_DIR/docs/" 2>/dev/null || true
    cp docs/ai-context.md "$RELEASE_DIR/docs/" 2>/dev/null || true
    cp docs/PERFORMANCE_API.md "$RELEASE_DIR/docs/" 2>/dev/null || true
    echo "✅ Added essential documentation"
fi

# Copy rules directory if it exists
if [[ -d "rules" ]]; then
    cp -r rules "$RELEASE_DIR/"
    echo "✅ Added security rules"
fi

# Coraza WASI reactor: shipped at the same stable relative path as the Nix
# package and container image, with digest, licence and provenance.
./scripts/check-coraza-reactor-size.sh
install -Dm644 wasm/coraza_reactor/coraza_reactor.wasm \
    "$RELEASE_DIR/wasm/coraza_reactor.wasm"
install -Dm644 wasm/coraza_reactor/LICENSE-CRS "$RELEASE_DIR/wasm/LICENSE-CRS"
install -Dm644 wasm/coraza_reactor/PROVENANCE.md "$RELEASE_DIR/wasm/PROVENANCE.md"
install -Dm644 wasm/coraza_reactor/SHA256SUMS "$RELEASE_DIR/wasm/SHA256SUMS"

# Installed layout used by the binary's CRS resolver. The tarball keeps the
# legacy `wasm/` paths above for compatibility, but the default Rust engine
# needs the full CRS bundle next to the executable.
install -Dm644 wasm/coraza_reactor/coraza_reactor.wasm \
    "$RELEASE_DIR/share/waf/wasm/coraza_reactor.wasm"
install -Dm644 wasm/coraza_reactor/LICENSE-CRS "$RELEASE_DIR/share/waf/wasm/LICENSE-CRS"
install -Dm644 wasm/coraza_reactor/PROVENANCE.md "$RELEASE_DIR/share/waf/wasm/PROVENANCE.md"
install -Dm644 wasm/coraza_reactor/SHA256SUMS "$RELEASE_DIR/share/waf/wasm/SHA256SUMS"
mkdir -p "$RELEASE_DIR/share/waf/rules"
cp -r wasm/coraza_reactor/rules/crs "$RELEASE_DIR/share/waf/rules/crs"
echo "✅ Added Coraza reactor ($(stat -c%s wasm/coraza_reactor/coraza_reactor.wasm) bytes)"

# Native Coraza sidecar: binary plus the shared read-only CRS bundle. The
# high-throughput profile (config/performance-native.toml) needs both.
if [[ ! -x "target/native/coraza-sidecar" ]]; then
    echo "🏗️  Building native Coraza sidecar..."
    ./scripts/build-coraza-sidecar.sh
fi
install -Dm755 target/native/coraza-sidecar "$RELEASE_DIR/native/coraza-sidecar"
mkdir -p "$RELEASE_DIR/native/coraza"
cp -r wasm/coraza_reactor/rules/crs "$RELEASE_DIR/native/coraza/crs"
install -Dm644 wasm/coraza_reactor/LICENSE-CRS "$RELEASE_DIR/native/coraza/LICENSE-CRS"
install -Dm644 wasm/coraza_reactor/PROVENANCE.md "$RELEASE_DIR/native/coraza/PROVENANCE.md"
echo "✅ Added native Coraza sidecar and CRS rules"

# Standalone sidecar tarball, matching the Release workflow layout.
SIDECAR_ARCHIVE="waf-rejected-v$VERSION-coraza-sidecar-x86_64-linux.tar.gz"
SIDECAR_STAGE="$(mktemp -d "${TMPDIR:-/tmp}/waf-sidecar.XXXXXX")"
trap 'rm -rf "$SIDECAR_STAGE"' EXIT
mkdir -p "$SIDECAR_STAGE/bin" "$SIDECAR_STAGE/share/waf/coraza"
install -m755 target/native/coraza-sidecar "$SIDECAR_STAGE/bin/coraza-sidecar"
cp -r wasm/coraza_reactor/rules/crs "$SIDECAR_STAGE/share/waf/coraza/crs"
install -m644 wasm/coraza_reactor/LICENSE-CRS "$SIDECAR_STAGE/share/waf/coraza/LICENSE-CRS"
install -m644 wasm/coraza_reactor/PROVENANCE.md "$SIDECAR_STAGE/share/waf/coraza/PROVENANCE.md"
tar -czf "$SIDECAR_ARCHIVE" -C "$SIDECAR_STAGE" bin share
rm -rf "$SIDECAR_STAGE"
trap - EXIT
echo "✅ Added standalone sidecar archive: $SIDECAR_ARCHIVE"

# Standalone Coraza module, licence and provenance assets.
cp wasm/coraza_reactor/coraza_reactor.wasm \
    "waf-rejected-$VERSION-coraza_reactor.wasm"
cp wasm/coraza_reactor/LICENSE-CRS "waf-rejected-$VERSION-coraza-LICENSE"
cp wasm/coraza_reactor/PROVENANCE.md "waf-rejected-$VERSION-coraza-PROVENANCE.md"
echo "✅ Added standalone Coraza module, licence and provenance"

# CycloneDX SBOM. The script uses the dev-shell cargo-cyclonedx or a pinned
# nixpkgs fallback, and always writes the .cdx.json plus its .sha256.
./scripts/generate-sbom.sh "$VERSION" .
cp "waf-rejected-$VERSION.cdx.json" "$RELEASE_DIR/"
echo "✅ Added CycloneDX SBOM"

# The image is built separately (see docs/operations/container.md). Attach an
# existing tarball when one is available; never fail the binary release just
# because a container engine is unavailable.
IMAGE_ARCHIVE="waf-rejected-$VERSION-image.tar.gz"
if [[ -f "$IMAGE_ARCHIVE" ]]; then
    echo "✅ Using existing image archive: $IMAGE_ARCHIVE"
elif [[ -f ".release-assets/$IMAGE_ARCHIVE" ]]; then
    cp ".release-assets/$IMAGE_ARCHIVE" .
    echo "✅ Copied image archive from .release-assets/"
else
    echo "⚠️  No $IMAGE_ARCHIVE found; build/export it separately and attach it"
fi

# Create startup script
cat > "$RELEASE_DIR/start_waf.sh" << 'EOF'
#!/usr/bin/env bash
# WAF-Rejected startup script

CONFIG_FILE="${1:-config.toml}"

if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "❌ Configuration file not found: $CONFIG_FILE"
    echo "Usage: $0 [config_file]"
    echo "Example: $0 config/enterprise.toml"
    exit 1
fi

echo "🚀 Starting WAF-Rejected..."
echo "📝 Config: $CONFIG_FILE"

export WAF_CONFIG_FILE="$CONFIG_FILE"
exec ./waf-ingress
EOF

chmod +x "$RELEASE_DIR/start_waf.sh"
echo "✅ Added startup script"

# Create quick start guide
cat > "$RELEASE_DIR/QUICKSTART.md" << 'EOF'
# WAF-Rejected v@VERSION@ - Quick Start

## Installation

1. Extract the archive:
   ```bash
   tar -xzf waf-rejected-v@VERSION@-*.tar.gz
   cd @RELEASE_DIR@
   ```

2. Review and customize configuration:
   ```bash
   # Use one of the provided configurations
   cp config/enterprise.toml config.toml

   # Or create your own based on examples
   vim config.toml
   ```

3. Start the WAF:
   ```bash
   ./start_waf.sh config.toml
   ```

## Configuration

- **Basic setup**: Use `config/development-production.toml`
- **Enterprise**: Use `config/enterprise.toml`
- **High performance**: Use `benchmarks/performance_testing.toml`

See `docs/operations/deployment.md` for detailed configuration options.

## Testing

Test the WAF is working:

```bash
# Health check (health/metrics run on 8081)
curl http://localhost:8081/health

# Test security detection (should be blocked)
curl "http://localhost:8080/test?id=1%20UNION%20SELECT%20*%20FROM%20users"
```

## Documentation

- **Full documentation**: See the `README.md` and `docs/` directory
- **Deployment**: `docs/operations/deployment.md`
- **Monitoring**: `docs/operations/monitoring.md`
- **Backup/DR**: `docs/operations/backup-recovery.md`

## Support

- **Issues**: https://github.com/shift/waf-rejected/issues
- **Discussions**: https://github.com/shift/waf-rejected/discussions

## Performance

This release achieves:
- **Latency**: Sub-5ms processing (4.26ms measured)
- **Throughput**: 500-1200+ RPS on laptop hardware
- **Memory**: <100MB idle, <512MB under load
- **Security**: 96.2% attack detection accuracy
EOF
sed -i "s|@VERSION@|$VERSION|g; s|@RELEASE_DIR@|$RELEASE_DIR|g" "$RELEASE_DIR/QUICKSTART.md"

echo "✅ Added quick start guide"

# Create checksums for the unpacked tree
echo "🔐 Creating checksums..."
cd "$RELEASE_DIR"
find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
cd ..
echo "✅ Added checksums"

# Create archive
ARCHIVE_NAME="waf-rejected-v$VERSION-x86_64-linux.tar.gz"
echo "📦 Creating archive: $ARCHIVE_NAME"
tar -czf "$ARCHIVE_NAME" "$RELEASE_DIR"

# Create zip for Windows users when the zip tool is available. The release
# workflow publishes the tarball only; the zip is a convenience extra.
ZIP_NAME="waf-rejected-v$VERSION-x86_64-linux.zip"
if command -v zip >/dev/null 2>&1; then
    echo "📦 Creating zip archive: $ZIP_NAME"
    zip -r "$ZIP_NAME" "$RELEASE_DIR" >/dev/null
else
    echo "⚠️  zip not installed; skipping $ZIP_NAME"
    ZIP_NAME=""
fi

# Per-asset checksums, matching the Release workflow and verify-release.sh.
echo "🔐 Creating per-asset checksums..."
for asset in \
    "$ARCHIVE_NAME" \
    ${ZIP_NAME:+"$ZIP_NAME"} \
    "$SIDECAR_ARCHIVE" \
    "waf-rejected-$VERSION.cdx.json" \
    "waf-rejected-$VERSION-coraza_reactor.wasm" \
    "waf-rejected-$VERSION-coraza-LICENSE" \
    "waf-rejected-$VERSION-coraza-PROVENANCE.md" \
    "$IMAGE_ARCHIVE"; do
    if [[ -f "$asset" ]]; then
        sha256sum "$asset" > "$asset.sha256"
        sha256sum --check "$asset.sha256"
    fi
done
echo "✅ Added per-asset checksums"

# Show results
echo ""
echo "✅ Release artifacts created successfully!"
echo "========================================"
echo ""
echo "📁 Directory: $RELEASE_DIR/"
echo "📦 Archive: $ARCHIVE_NAME ($(ls -lh "$ARCHIVE_NAME" | awk '{print $5}'))"
if [[ -n "$ZIP_NAME" ]]; then
    echo "🗜️  Zip: $ZIP_NAME ($(ls -lh "$ZIP_NAME" | awk '{print $5}'))"
fi
echo ""

# Show contents
echo "📋 Archive contents:"
echo "==================="
ARCHIVE_LIST="$(mktemp "${TMPDIR:-/tmp}/waf-archive-list.XXXXXX")"
tar -tzf "$ARCHIVE_NAME" > "$ARCHIVE_LIST"
head -20 "$ARCHIVE_LIST"
TOTAL_FILES=$(wc -l < "$ARCHIVE_LIST")
if [[ "$TOTAL_FILES" -gt 20 ]]; then
    echo "... and $((TOTAL_FILES - 20)) more files"
fi
rm -f "$ARCHIVE_LIST"

echo ""
echo "🎯 Ready for release!"
echo "===================="
echo ""
echo "Upload these files to your release:"
echo "- $ARCHIVE_NAME (+ .sha256)"
if [[ -n "$ZIP_NAME" ]]; then
    echo "- $ZIP_NAME (+ .sha256)"
fi
echo "- $SIDECAR_ARCHIVE (+ .sha256)"
echo "- waf-rejected-$VERSION.cdx.json (+ .sha256)"
echo "- waf-rejected-$VERSION-coraza_reactor.wasm (+ .sha256)"
echo "- waf-rejected-$VERSION-coraza-LICENSE (+ .sha256)"
echo "- waf-rejected-$VERSION-coraza-PROVENANCE.md (+ .sha256)"
if [[ -f "$IMAGE_ARCHIVE" ]]; then
    echo "- $IMAGE_ARCHIVE (+ .sha256)"
fi
echo "- $RELEASE_DIR/SHA256SUMS"
