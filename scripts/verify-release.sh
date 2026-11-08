#!/usr/bin/env bash
# Verify a WAF-Rejected release's assets.
#
# Usage:
#   ./scripts/verify-release.sh --dir .release-assets --version 0.1.0-beta.13
#   ./scripts/verify-release.sh --tag v0.1.0-beta.13
#   ./scripts/verify-release.sh --dir dist --version 0.1.0-beta.13 --no-smoke
#   ./scripts/verify-release.sh --dir dist --version 0.1.0-beta.13 \
#       --verify-registry
#
# With --tag/--version and no --dir, the assets are downloaded with
# `gh release download`. With --dir, the script validates a local artifact
# directory (for example the output of create_release_artifacts.sh).
#
# --verify-registry checks the immutable container reference recorded in
# image-digest.txt (or supplied with --image-digest) against the registry. It
# is optional because it needs network access and a container CLI. Use
# --registry-image to verify a mirror instead of the canonical
# ghcr.io/shift/waf-rejected-waf package.
#
# Checks:
#   - every required asset and its .sha256 file is present and matches;
#   - the CycloneDX SBOM is valid, names the release version and contains the
#     Coraza reactor file component with the module digest and Apache-2.0;
#   - the standalone module digest matches the SBOM and the tarball SHA256SUMS;
#   - the binary tarball contains the binary, CRS bundle, reactor, licences,
#     provenance and native sidecar;
#   - the sidecar tarball contains the binary and CRS bundle;
#   - the image tarball is a valid gzip archive with a Docker manifest;
#   - with --verify-registry, the image-digest.txt reference resolves in the
#     registry and names the canonical package;
#   - the binary reports the expected --version and answers /health.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO="${RELEASE_REPO:-shift/waf-rejected}"
DIR=""
VERSION=""
SMOKE=1
DEEP_IMAGE=0
ATTESTATIONS=0
VERIFY_REGISTRY=0
REGISTRY_IMAGE="ghcr.io/shift/waf-rejected-waf"
IMAGE_DIGEST=""
KEEP=0
TMP=""
WAF_PID=""

usage() {
    sed -n '2,31p' "$0" | sed 's/^# \{0,1\}//'
}

cleanup() {
    if [[ -n "$WAF_PID" ]] && kill -0 "$WAF_PID" 2>/dev/null; then
        kill "$WAF_PID" 2>/dev/null || true
        wait "$WAF_PID" 2>/dev/null || true
    fi
    if [[ -n "$TMP" && "$KEEP" -eq 0 ]]; then
        # Release tarballs preserve read-only directories from the Nix store.
        chmod -R u+w "$TMP" 2>/dev/null || true
        rm -rf "$TMP" || true
    fi
}
trap cleanup EXIT

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

ok() {
    echo "ok: $*"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dir) DIR="${2:?--dir needs a path}"; shift 2 ;;
        --version) VERSION="${2#v}"; shift 2 ;;
        --tag) VERSION="${2#v}"; shift 2 ;;
        --repo) REPO="${2:?--repo needs owner/name}"; shift 2 ;;
        --no-smoke) SMOKE=0; shift ;;
        --deep-image) DEEP_IMAGE=1; shift ;;
        --attestations) ATTESTATIONS=1; shift ;;
        --verify-registry) VERIFY_REGISTRY=1; shift ;;
        --registry-image) REGISTRY_IMAGE="${2:?--registry-image needs ghcr.io/owner/name}"; shift 2 ;;
        --image-digest) IMAGE_DIGEST="${2:?--image-digest needs sha256:<64 hex> or ghcr.io/owner/name@sha256:<64 hex>}"; shift 2 ;;
        --keep) KEEP=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) fail "unknown argument: $1 (try --help)" ;;
    esac
done

if [[ -z "$DIR" ]]; then
    if [[ -z "$VERSION" ]]; then
        if [[ -d "$ROOT/.release-assets" ]]; then
            DIR="$ROOT/.release-assets"
        else
            fail "specify --dir or --version/--tag"
        fi
    else
        command -v gh >/dev/null 2>&1 || fail "gh is required to download release assets"
        TMP="$(mktemp -d "${TMPDIR:-/tmp}/waf-release.XXXXXX")"
        echo "Downloading release v${VERSION} from ${REPO}..."
        gh release download "v${VERSION}" --repo "$REPO" --dir "$TMP"
        DIR="$TMP"
    fi
fi

[[ -d "$DIR" ]] || fail "artifact directory not found: $DIR"
DIR="$(cd "$DIR" && pwd)"

if [[ -z "$VERSION" ]]; then
    mapfile -t versions < <(
        find "$DIR" -maxdepth 1 -name 'waf-rejected-v*-x86_64-linux.tar.gz' -printf '%f\n' \
            | sed -E 's/^waf-rejected-v(.*)-x86_64-linux\.tar\.gz$/\1/' | sort -u
    )
    if [[ ${#versions[@]} -eq 1 ]]; then
        VERSION="${versions[0]}"
    elif [[ ${#versions[@]} -eq 0 ]]; then
        fail "could not infer version from $DIR; pass --version"
    else
        fail "multiple versions in $DIR (${versions[*]}); pass --version"
    fi
fi

BIN_TAR="waf-rejected-v${VERSION}-x86_64-linux.tar.gz"
SIDECAR_TAR="waf-rejected-v${VERSION}-coraza-sidecar-x86_64-linux.tar.gz"
IMAGE_TAR="waf-rejected-${VERSION}-image.tar.gz"
SBOM="waf-rejected-${VERSION}.cdx.json"
MODULE="waf-rejected-${VERSION}-coraza_reactor.wasm"
LICENSE="waf-rejected-${VERSION}-coraza-LICENSE"
PROVENANCE="waf-rejected-${VERSION}-coraza-PROVENANCE.md"

REQUIRED=("$BIN_TAR" "$SIDECAR_TAR" "$IMAGE_TAR" "$SBOM" "$MODULE" "$LICENSE" "$PROVENANCE")

echo "Verifying WAF-Rejected ${VERSION} in ${DIR}"
echo "=================================================="

for asset in "${REQUIRED[@]}"; do
    [[ -s "$DIR/$asset" ]] || fail "missing or empty asset: $asset"
    [[ -s "$DIR/$asset.sha256" ]] || fail "missing checksum: $asset.sha256"
    (cd "$DIR" && sha256sum --check "$asset.sha256" >/dev/null) \
        || fail "checksum mismatch: $asset"
    ok "checksum $asset"
done

# --- SBOM -----------------------------------------------------------------
jq -e '.bomFormat == "CycloneDX"' "$DIR/$SBOM" >/dev/null \
    || fail "SBOM is not CycloneDX"
jq -e '.specVersion == "1.5"' "$DIR/$SBOM" >/dev/null \
    || fail "SBOM specVersion is not 1.5"
jq -e --arg v "$VERSION" '.metadata.component.version == $v' "$DIR/$SBOM" >/dev/null \
    || fail "SBOM metadata component version does not match $VERSION"

MODULE_SHA="$(sha256sum "$DIR/$MODULE" | awk '{print $1}')"
jq -e --arg sha "$MODULE_SHA" '
    .components[]
    | select(.name == "coraza_reactor.wasm")
    | .hashes[]
    | select(.alg == "SHA-256" and .content == $sha)
' "$DIR/$SBOM" >/dev/null || fail "SBOM reactor digest does not match $MODULE"

jq -e '
    .components[]
    | select(.name == "coraza_reactor.wasm")
    | .licenses[]
    | select(.license.id == "Apache-2.0")
' "$DIR/$SBOM" >/dev/null || fail "SBOM reactor component lacks Apache-2.0"
ok "SBOM structure, version, reactor digest and licence"

MODULE_SIZE="$(stat -c%s "$DIR/$MODULE")"
(( MODULE_SIZE <= 32 * 1024 * 1024 )) \
    || fail "reactor module is $MODULE_SIZE bytes; budget is 32 MiB"
ok "reactor module size ${MODULE_SIZE} bytes (budget 32 MiB)"

# --- binary tarball -------------------------------------------------------
TMP="${TMP:-$(mktemp -d "${TMPDIR:-/tmp}/waf-release.XXXXXX")}"
EXTRACT="$TMP/extract"
mkdir -p "$EXTRACT"
tar -xzf "$DIR/$BIN_TAR" -C "$EXTRACT"
BUNDLE="$EXTRACT/waf-rejected-v${VERSION}"
[[ -d "$BUNDLE" ]] || fail "binary tarball does not contain waf-rejected-v${VERSION}/"

for path in \
    waf-ingress README.md CHANGELOG.md SECURITY.md LICENSE-APACHE LICENSE-MIT \
    wasm/coraza_reactor.wasm wasm/LICENSE-CRS wasm/PROVENANCE.md wasm/SHA256SUMS \
    share/waf/wasm/coraza_reactor.wasm share/waf/wasm/LICENSE-CRS \
    share/waf/wasm/PROVENANCE.md share/waf/wasm/SHA256SUMS \
    share/waf/rules/crs/crs.conf \
    native/coraza-sidecar native/coraza/crs/crs.conf \
    native/coraza/LICENSE-CRS native/coraza/PROVENANCE.md; do
    [[ -e "$BUNDLE/$path" ]] || fail "binary tarball missing $path"
done
[[ -x "$BUNDLE/waf-ingress" ]] || fail "waf-ingress is not executable"
[[ -x "$BUNDLE/native/coraza-sidecar" ]] || fail "native sidecar is not executable"
(cd "$BUNDLE/wasm" && sha256sum --check SHA256SUMS >/dev/null) \
    || fail "binary tarball wasm/SHA256SUMS does not match"
(cd "$BUNDLE/share/waf/wasm" && sha256sum --check SHA256SUMS >/dev/null) \
    || fail "binary tarball share/waf/wasm/SHA256SUMS does not match"
ok "binary tarball contents and reactor digests"

# --- sidecar tarball ------------------------------------------------------
SIDECAR_EXTRACT="$TMP/sidecar"
mkdir -p "$SIDECAR_EXTRACT"
tar -xzf "$DIR/$SIDECAR_TAR" -C "$SIDECAR_EXTRACT"
for path in \
    bin/coraza-sidecar share/waf/coraza/crs/crs.conf \
    share/waf/coraza/LICENSE-CRS share/waf/coraza/PROVENANCE.md; do
    [[ -e "$SIDECAR_EXTRACT/$path" ]] || fail "sidecar tarball missing $path"
done
[[ -x "$SIDECAR_EXTRACT/bin/coraza-sidecar" ]] || fail "sidecar binary is not executable"
ok "sidecar tarball contents"

# --- image tarball --------------------------------------------------------
gzip -t "$DIR/$IMAGE_TAR" || fail "image tarball is not valid gzip"
tar -tzf "$DIR/$IMAGE_TAR" > "$TMP/image-list.txt"
grep -qx 'manifest.json' "$TMP/image-list.txt" \
    || fail "image tarball has no manifest.json"
jq -e 'type == "array" and length > 0 and (.[0].Layers | length > 0)' \
    < <(tar -xOf "$DIR/$IMAGE_TAR" manifest.json) >/dev/null \
    || fail "image manifest is not a Docker save manifest"
ok "image tarball gzip and manifest"

# --- optional registry digest ---------------------------------------------
if [[ "$VERIFY_REGISTRY" -eq 1 ]]; then
    command -v docker >/dev/null 2>&1 \
        || fail "docker is required for --verify-registry"
    if [[ -z "$IMAGE_DIGEST" ]]; then
        [[ -s "$DIR/image-digest.txt" ]] \
            || fail "--verify-registry needs image-digest.txt or --image-digest"
        IMAGE_DIGEST="$(grep -E '^ghcr\.io/[^[:space:]]+@sha256:[0-9a-f]{64}$' \
            "$DIR/image-digest.txt" | head -n1 || true)"
        [[ -n "$IMAGE_DIGEST" ]] \
            || fail "image-digest.txt does not contain a ghcr.io digest reference"
    fi
    case "$IMAGE_DIGEST" in
        sha256:*) IMAGE_DIGEST="${REGISTRY_IMAGE}@${IMAGE_DIGEST}" ;;
    esac
    [[ "$IMAGE_DIGEST" =~ ^[^[:space:]]+@sha256:[0-9a-f]{64}$ ]] \
        || fail "image digest is not a registry reference: $IMAGE_DIGEST"
    if [[ -n "$REGISTRY_IMAGE" && "$IMAGE_DIGEST" != "${REGISTRY_IMAGE}@"* ]]; then
        fail "image digest $IMAGE_DIGEST does not use ${REGISTRY_IMAGE}"
    fi
    docker manifest inspect "$IMAGE_DIGEST" >/dev/null \
        || fail "registry image does not resolve: $IMAGE_DIGEST"
    ok "registry image $IMAGE_DIGEST"
fi

if [[ "$DEEP_IMAGE" -eq 1 ]]; then
    MANIFEST="$(tar -xOf "$DIR/$IMAGE_TAR" manifest.json)"
    mapfile -t layers < <(jq -r '.[0].Layers[]' <<<"$MANIFEST")
    found=0
    for layer in "${layers[@]}"; do
        layer_list="$(tar -xOf "$DIR/$IMAGE_TAR" "$layer" | tar -tf - 2>/dev/null || true)"
        if grep -qx 'usr/share/waf/wasm/coraza_reactor.wasm' <<<"$layer_list"; then
            image_sha="$(tar -xOf "$DIR/$IMAGE_TAR" "$layer" \
                | tar -xOf - 'usr/share/waf/wasm/coraza_reactor.wasm' \
                | sha256sum | awk '{print $1}')"
            [[ "$image_sha" == "$MODULE_SHA" ]] \
                || fail "image reactor digest $image_sha does not match $MODULE_SHA"
            found=1
            break
        fi
    done
    [[ "$found" -eq 1 ]] || fail "image does not contain usr/share/waf/wasm/coraza_reactor.wasm"
    ok "image reactor digest matches standalone module"
fi

# --- binary version and health smoke -------------------------------------
VERSION_OUTPUT="$("$BUNDLE/waf-ingress" --version 2>&1)" \
    || fail "waf-ingress --version failed: $VERSION_OUTPUT"
[[ "$VERSION_OUTPUT" == "waf-ingress $VERSION" ]] \
    || fail "waf-ingress --version reported '$VERSION_OUTPUT', expected 'waf-ingress $VERSION'"
ok "waf-ingress --version"

if [[ "$SMOKE" -eq 1 ]]; then
    command -v curl >/dev/null 2>&1 || fail "curl is required for the health smoke test"
    PORT=$((20000 + RANDOM % 20000))
    HEALTH_PORT=$((PORT + 1))
    cat > "$TMP/config.toml" <<EOF
bind_addr = "127.0.0.1:${PORT}"
health_bind_addr = "127.0.0.1:${HEALTH_PORT}"
upstream_uri = "http://127.0.0.1:9"

[server]
max_body_size = 1048576

[logging]
level = "error"
EOF
    WAF_CONFIG_FILE="$TMP/config.toml" "$BUNDLE/waf-ingress" \
        > "$TMP/waf.log" 2>&1 &
    WAF_PID=$!
    ready=0
    for _ in $(seq 1 40); do
        if ! kill -0 "$WAF_PID" 2>/dev/null; then
            break
        fi
        if curl -fsS "http://127.0.0.1:${HEALTH_PORT}/health" >/dev/null 2>&1; then
            ready=1
            break
        fi
        sleep 0.25
    done
    if [[ "$ready" -ne 1 ]]; then
        cat "$TMP/waf.log" >&2 || true
        fail "health smoke test did not become ready"
    fi
    curl -fsS "http://127.0.0.1:${HEALTH_PORT}/health" >/dev/null \
        || fail "health endpoint failed"
    ok "health smoke test on 127.0.0.1:${HEALTH_PORT}"
fi

# --- optional attestations ------------------------------------------------
if [[ "$ATTESTATIONS" -eq 1 ]]; then
    command -v gh >/dev/null 2>&1 || fail "gh is required for --attestations"
    for asset in "${REQUIRED[@]}"; do
        gh attestation verify "$DIR/$asset" --repo "$REPO" >/dev/null \
            || fail "attestation verification failed: $asset"
        ok "attestation $asset"
    done
fi

echo "=================================================="
echo "PASS: WAF-Rejected ${VERSION} assets verified"
