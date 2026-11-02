#!/bin/bash
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

# Ensure we have a release build. `coraza-native` enables the opt-in native
# sidecar backend; the default `waf.coraza.backend` remains "wasm". Cargo is
# incremental, so this is cheap when the tree is already built.
echo "🏗️  Building release binary..."
cargo build --release --features wasm-reactor,coraza-native

# Create release directory
RELEASE_DIR="waf-rejected-v$VERSION"
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

# Create startup script
cat > "$RELEASE_DIR/start_waf.sh" << 'EOF'
#!/bin/bash
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
cat > "$RELEASE_DIR/QUICKSTART.md" << EOF
# WAF-Rejected v$VERSION - Quick Start

## Installation

1. Extract the archive:
   \`\`\`bash
   tar -xzf waf-rejected-v$VERSION-*.tar.gz
   cd $RELEASE_DIR
   \`\`\`

2. Review and customize configuration:
   \`\`\`bash
   # Use one of the provided configurations
   cp config/enterprise.toml config.toml
   
   # Or create your own based on examples
   vim config.toml
   \`\`\`

3. Start the WAF:
   \`\`\`bash
   ./start_waf.sh config.toml
   \`\`\`

## Configuration

- **Basic setup**: Use \`config/development-production.toml\`
- **Enterprise**: Use \`config/enterprise.toml\`
- **High performance**: Use \`config/performance_testing.toml\`

See \`docs/CONFIGURATION.md\` for detailed configuration options.

## Testing

Test the WAF is working:

\`\`\`bash
# Health check (health/metrics run on 8081)
curl http://localhost:8081/health

# Test security detection (should be blocked)
curl "http://localhost:8080/test?id=1%20UNION%20SELECT%20*%20FROM%20users"
\`\`\`

## Documentation

- **Full documentation**: See the `README.md` and `docs/` directory
- **Deployment**: `docs/operations/deployment.md`
- **Monitoring**: `docs/operations/monitoring.md`
- **Backup/DR**: `docs/operations/backup-recovery.md`

## Support

- **Issues**: https://github.com/your-org/waf-rejected/issues
- **Discussions**: https://github.com/your-org/waf-rejected/discussions

## Performance

This release achieves:
- **Latency**: Sub-5ms processing (4.26ms measured)
- **Throughput**: 500-1200+ RPS on laptop hardware
- **Memory**: <100MB idle, <512MB under load
- **Security**: 96.2% attack detection accuracy
EOF

echo "✅ Added quick start guide"

# Create checksums
echo "🔐 Creating checksums..."
cd "$RELEASE_DIR"
find . -type f -exec sha256sum {} \; > SHA256SUMS
cd ..
echo "✅ Added checksums"

# Create archive
ARCHIVE_NAME="waf-rejected-v$VERSION-linux-x64.tar.gz"
echo "📦 Creating archive: $ARCHIVE_NAME"
tar -czf "$ARCHIVE_NAME" "$RELEASE_DIR"

# Create zip for Windows users
ZIP_NAME="waf-rejected-v$VERSION-linux-x64.zip"
echo "📦 Creating zip archive: $ZIP_NAME"
zip -r "$ZIP_NAME" "$RELEASE_DIR" >/dev/null

# Show results
echo ""
echo "✅ Release artifacts created successfully!"
echo "========================================"
echo ""
echo "📁 Directory: $RELEASE_DIR/"
echo "📦 Archive: $ARCHIVE_NAME ($(ls -lh "$ARCHIVE_NAME" | awk '{print $5}'))"
echo "🗜️  Zip: $ZIP_NAME ($(ls -lh "$ZIP_NAME" | awk '{print $5}'))"
echo ""

# Show contents
echo "📋 Archive contents:"
echo "==================="
tar -tzf "$ARCHIVE_NAME" | head -20
if [[ $(tar -tzf "$ARCHIVE_NAME" | wc -l) -gt 20 ]]; then
    echo "... and $(($(tar -tzf "$ARCHIVE_NAME" | wc -l) - 20)) more files"
fi

echo ""
echo "🎯 Ready for release!"
echo "===================="
echo ""
echo "Upload these files to your release:"
echo "- $ARCHIVE_NAME"
echo "- $ZIP_NAME"
echo "- $RELEASE_DIR/SHA256SUMS"
