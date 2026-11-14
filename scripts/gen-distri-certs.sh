#!/usr/bin/env bash
#
# Generate a local CA, distri-kv server certificate and WAF client certificate
# for the distributed demo stack, plus a bearer token for the demo control
# plane. The output directory is gitignored.
#
# Usage:
#   ./scripts/gen-distri-certs.sh [--out DIR] [--force] [--no-token]
#
# Environment:
#   OPENSSL       openssl binary (default: openssl)
#   TRUST_DOMAIN  SPIFFE trust domain (default: waf.example)
#   REGION        region in the SPIFFE path (default: eu-west-1)
#
# The generated server certificate is valid for the compose and Kubernetes
# service names (dkv-1..3, dkv-client, dkv-headless, localhost, 127.0.0.1).
# The client certificate carries the SPIFFE URI SAN
# spiffe://<trust-domain>/region/<region>/node/waf-1.
#
# The current distri-kv build uses the auth configuration only as an identity
# hook; TLS termination still belongs in front of the gRPC listener. The files
# are produced so a sidecar or a future client TLS implementation can use them.

set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="$ROOT_DIR/deploy/distributed/certs"
SECRETS_DIR="$ROOT_DIR/deploy/distributed/secrets"
FORCE=0
WRITE_TOKEN=1
TRUST_DOMAIN="${TRUST_DOMAIN:-waf.example}"
REGION="${REGION:-eu-west-1}"
OPENSSL="${OPENSSL:-openssl}"

usage() {
  sed -n '2,28p' "$0" | sed 's/^# \{0,1\}//'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --out)
      OUT_DIR="${2:?--out requires a directory}"
      shift 2
      ;;
    --force)
      FORCE=1
      shift
      ;;
    --no-token)
      WRITE_TOKEN=0
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'error: unknown argument: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if ! command -v "$OPENSSL" >/dev/null 2>&1; then
  printf 'error: openssl not found (%s). Install openssl or set OPENSSL.\n' "$OPENSSL" >&2
  exit 3
fi

umask 077
mkdir -p "$OUT_DIR" "$SECRETS_DIR"
chmod 0700 "$OUT_DIR" "$SECRETS_DIR"

tmp_dir="$(mktemp -d "$OUT_DIR/.tmp.XXXXXX")"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT INT TERM

present=0
for file in ca.key ca.crt server.key server.crt client.key client.crt; do
  [[ -e "$OUT_DIR/$file" ]] && present=1
done
if [[ "$present" -eq 1 && "$FORCE" -eq 0 ]]; then
  printf 'Certificates already exist in %s; use --force to replace them.\n' "$OUT_DIR"
else
  printf 'Generating CA and leaf certificates in %s\n' "$OUT_DIR"

  "$OPENSSL" genrsa -out "$tmp_dir/ca.key" 4096 >/dev/null 2>&1
  "$OPENSSL" req -x509 -new -nodes -key "$tmp_dir/ca.key" -sha256 -days 3650 \
    -subj "/CN=WAF distri-kv local CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -out "$tmp_dir/ca.crt" >/dev/null 2>&1

  cat >"$tmp_dir/server.ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:dkv-1,DNS:dkv-2,DNS:dkv-3,DNS:dkv-client,DNS:dkv-headless,DNS:localhost,IP:127.0.0.1
EOF

  "$OPENSSL" genrsa -out "$tmp_dir/server.key" 4096 >/dev/null 2>&1
  "$OPENSSL" req -new -key "$tmp_dir/server.key" \
    -subj "/CN=dkv-client" -out "$tmp_dir/server.csr" >/dev/null 2>&1
  "$OPENSSL" x509 -req -in "$tmp_dir/server.csr" -CA "$tmp_dir/ca.crt" \
    -CAkey "$tmp_dir/ca.key" -CAcreateserial -days 825 -sha256 \
    -extfile "$tmp_dir/server.ext" -out "$tmp_dir/server.crt" >/dev/null 2>&1

  cat >"$tmp_dir/client.ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
subjectAltName=URI:spiffe://$TRUST_DOMAIN/region/$REGION/node/waf-1
EOF

  "$OPENSSL" genrsa -out "$tmp_dir/client.key" 4096 >/dev/null 2>&1
  "$OPENSSL" req -new -key "$tmp_dir/client.key" \
    -subj "/CN=waf-1" -out "$tmp_dir/client.csr" >/dev/null 2>&1
  "$OPENSSL" x509 -req -in "$tmp_dir/client.csr" -CA "$tmp_dir/ca.crt" \
    -CAkey "$tmp_dir/ca.key" -CAcreateserial -days 825 -sha256 \
    -extfile "$tmp_dir/client.ext" -out "$tmp_dir/client.crt" >/dev/null 2>&1

  install -m 0600 "$tmp_dir/ca.key" "$OUT_DIR/ca.key"
  install -m 0644 "$tmp_dir/ca.crt" "$OUT_DIR/ca.crt"
  install -m 0600 "$tmp_dir/server.key" "$OUT_DIR/server.key"
  install -m 0644 "$tmp_dir/server.crt" "$OUT_DIR/server.crt"
  install -m 0600 "$tmp_dir/client.key" "$OUT_DIR/client.key"
  install -m 0644 "$tmp_dir/client.crt" "$OUT_DIR/client.crt"
  printf 'Wrote CA, server and client certificates.\n'
fi

if [[ "$WRITE_TOKEN" -eq 1 ]]; then
  token_file="$SECRETS_DIR/waf-token"
  if [[ -s "$token_file" && "$FORCE" -eq 0 ]]; then
    printf 'Bearer token already exists at %s; use --force to rotate it.\n' "$token_file"
  else
    token="$("$OPENSSL" rand -hex 32)"
    printf '%s\n' "$token" >"$token_file"
    chmod 0600 "$token_file"
    printf 'Wrote bearer token to %s\n' "$token_file"
  fi
fi

printf 'Certificate directory: %s\n' "$OUT_DIR"
printf 'SPIFFE identity:       spiffe://%s/region/%s/node/waf-1\n' "$TRUST_DOMAIN" "$REGION"
