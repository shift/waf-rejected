# Release Checklist

Use this checklist when preparing a new release of WAF-Rejected.

## Pre-Release Checklist

### Code Quality & Testing
- [ ] All tests pass: `cargo test`
- [ ] All benchmarks run successfully: `cargo bench`
- [ ] Code formatting is correct: `cargo fmt --check`
- [ ] Linting passes: `cargo clippy -- -D warnings`
- [ ] Security audit passes: `cargo audit`
- [ ] Enterprise validation tests pass: `./enterprise_waf_test.sh`

### Documentation
- [ ] `CHANGELOG.md` updated with new version and changes
- [ ] Version number updated in `Cargo.toml`
- [ ] Version number updated in `README.md` examples
- [ ] Documentation builds without warnings: `cargo doc --no-deps`
- [ ] All example configurations validated

### Performance & Security
- [ ] Performance benchmarks meet targets (sub-5ms processing)
- [ ] Memory usage within acceptable limits (<512MB under load)
- [ ] Security tests validate all attack detection scenarios
- [ ] Geographic IP blocking tests pass
- [ ] Rate limiting functionality validated

## Release Process

### 1. Version Bump
```bash
# Update version in Cargo.toml
# Update version references in README.md and docs/
# Update CHANGELOG.md with release date
```

### 2. Final Validation
```bash
# Clean build from scratch
cargo clean
cargo build --release

# Run comprehensive test suite
./verification_test.sh
./comprehensive_test_report.sh

# Validate enterprise features
cargo run --bin enterprise_security_test
cargo run --bin enterprise_performance_test
cargo run --bin enterprise_compliance_test
```

### 3. Git Release
```bash
# Commit all changes
git add -A
git commit -m "chore: prepare v${VERSION} release"

# Create and push tag
git tag -a v${VERSION} -m "Release v${VERSION}"
git push origin v${VERSION}
git push origin main
```

### 4. Build Release Artifacts
```bash
# Build optimized binary
cargo build --release

# Create distribution archive
tar -czf waf-rejected-v${VERSION}-linux-x64.tar.gz \
    target/release/waf-ingress \
    README.md \
    CHANGELOG.md \
    LICENSE-* \
    config/ \
    docs/

# Build Docker image
docker build -t waf-rejected:v${VERSION} .
docker tag waf-rejected:v${VERSION} waf-rejected:latest
```

### 5. Publish Release
```bash
# Publish to crates.io (if public)
cargo publish

# Push Docker image (if applicable)
docker push waf-rejected:v${VERSION}
docker push waf-rejected:latest
```

### 6. Post-Release
- [ ] Update GitHub release with changelog and artifacts
- [ ] Update documentation website
- [ ] Announce release on relevant channels
- [ ] Update deployment documentation with new version
- [ ] Monitor for any immediate issues

## Release Automation

For automated releases, ensure:
- CI/CD pipeline validates all quality gates
- Automated security scanning enabled
- Performance regression testing included
- Docker image security scanning configured
- Release notes generated from CHANGELOG.md

## Rollback Plan

If issues are discovered after release:
1. Investigate and assess severity
2. If critical: revert git tag and pull artifacts
3. If non-critical: prepare hotfix release
4. Update documentation and notify users

## Version Strategy

WAF-Rejected follows [Semantic Versioning](https://semver.org/):
- **MAJOR**: Breaking changes (e.g., API changes, config format changes)
- **MINOR**: New features, backward compatible (e.g., new security modules)
- **PATCH**: Bug fixes, security patches, backward compatible

## Support Matrix

| Version | Support Status | End of Life |
|---------|---------------|-------------|
| 0.1.x   | Current       | TBD         |
| Future  | Planned       | TBD         |
