#!/usr/bin/env bash
# Release preparation script for WAF-Rejected

set -euo pipefail

VERSION="${1:-}"
if [[ -z "$VERSION" ]]; then
    echo "Usage: $0 <version>"
    echo "Example: $0 0.1.0"
    exit 1
fi

echo "🚀 Preparing WAF-Rejected release v$VERSION"
echo "============================================"

# Validate version format
if [[ ! $VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
    echo "❌ Invalid version format. Use semantic versioning (e.g., 1.0.0 or 0.1.0-beta.1)"
    exit 1
fi

# Check if working directory is clean
if [[ -n $(git status --porcelain) ]]; then
    echo "❌ Working directory is not clean. Commit or stash changes first."
    git status --short
    exit 1
fi

# Check if we're on the main branch
CURRENT_BRANCH=$(git branch --show-current)
if [[ "$CURRENT_BRANCH" != "main" && "$CURRENT_BRANCH" != "master" ]]; then
    echo "⚠️  Warning: Not on main/master branch (currently on: $CURRENT_BRANCH)"
    read -p "Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

echo ""
echo "📋 Pre-release validation"
echo "========================="

# Run the test suite that is actually wired into the pipeline.
echo "🧪 Running test suite..."
if ! cargo test --lib --quiet; then
    echo "❌ Unit tests failed"
    exit 1
fi
if ! cargo test --test integration --quiet; then
    echo "❌ Integration tests failed"
    exit 1
fi
echo "✅ All tests passed"

# Check code formatting
echo "🎨 Checking code formatting..."
if ! cargo fmt --all -- --check; then
    echo "❌ Code formatting issues found. Run 'cargo fmt' to fix."
    exit 1
fi
echo "✅ Code formatting is correct"

# Run linting on the library (the live request path).
echo "🔍 Running linter..."
if ! cargo clippy --lib -- -D warnings; then
    echo "❌ Linting issues found"
    exit 1
fi
echo "✅ Linting passed"

# Security audit (cargo-audit is optional in local environments).
echo "🔒 Running security audit..."
if command -v cargo-audit >/dev/null 2>&1; then
    if ! cargo audit; then
        echo "❌ Security vulnerabilities found"
        exit 1
    fi
    echo "✅ Security audit passed"
else
    echo "⚠️  cargo-audit not installed; skipping local audit (CI still runs it)"
fi

# Build release binary with the same feature set as the Nix package and image.
echo "🏗️  Building release binary..."
if ! cargo build --release --bin waf-ingress \
    --features http3,webtransport,wasm-reactor,coraza-native,rust-engine --quiet; then
    echo "❌ Release build failed"
    exit 1
fi
echo "✅ Release binary built successfully"

# Run enterprise validation if available
if [[ -f "./enterprise_waf_test.sh" ]]; then
    echo "🏢 Running enterprise validation..."
    if ! ./enterprise_waf_test.sh; then
        echo "❌ Enterprise validation failed"
        exit 1
    fi
    echo "✅ Enterprise validation passed"
fi

echo ""
echo "📝 Updating release files"
echo "========================="

# Update version in Cargo.toml
echo "📦 Updating Cargo.toml version..."
sed -i.bak "s/^version = \".*\"/version = \"$VERSION\"/" Cargo.toml
rm -f Cargo.toml.bak
echo "✅ Cargo.toml updated"

# Update changelog
echo "📄 Please update CHANGELOG.md manually with release notes for v$VERSION"
echo "   - Add release date: $(date +%Y-%m-%d)"
echo "   - Move unreleased changes to the new version section"
echo "   - Add any missing changes or improvements"
echo ""
read -p "Press Enter after updating CHANGELOG.md..."

# Validate changelog was updated
if ! grep -q "\[${VERSION}\]" CHANGELOG.md; then
    echo "❌ CHANGELOG.md doesn't contain version $VERSION"
    exit 1
fi
echo "✅ CHANGELOG.md updated"

echo ""
echo "🎯 Final validation"
echo "=================="

# Build again to ensure version changes don't break anything
echo "🏗️  Final build validation..."
if ! cargo build --release --bin waf-ingress \
    --features http3,webtransport,wasm-reactor,coraza-native,rust-engine --quiet; then
    echo "❌ Final build failed"
    exit 1
fi
echo "✅ Final build successful"

# Show binary info and confirm the embedded version matches the release.
BINARY_SIZE=$(ls -lh target/release/waf-ingress | awk '{print $5}')
echo "📊 Release binary size: $BINARY_SIZE"
BINARY_VERSION=$(target/release/waf-ingress --version)
if [[ "$BINARY_VERSION" != "waf-ingress $VERSION" ]]; then
    echo "❌ Binary reports '$BINARY_VERSION', expected 'waf-ingress $VERSION'"
    exit 1
fi
echo "✅ Binary version: $BINARY_VERSION"

echo ""
echo "✅ Release v$VERSION is ready!"
echo "=============================="
echo ""
echo "Next steps:"
echo "1. Review the changes:"
echo "   git diff"
echo ""
echo "2. Commit the changes:"
echo "   git add Cargo.toml Cargo.lock CHANGELOG.md"
echo "   git commit -m \"chore: prepare v$VERSION release\""
echo ""
echo "3. Create and push the tag:"
echo "   git tag -a v$VERSION -m \"Release v$VERSION\""
echo "   git push origin v$VERSION"
echo "   git push origin $CURRENT_BRANCH"
echo ""
echo "4. Create release artifacts:"
echo "   ./create_release_artifacts.sh $VERSION"
echo ""
echo "5. Create GitHub release with changelog and artifacts"
echo ""
echo "🎉 Happy releasing!"
