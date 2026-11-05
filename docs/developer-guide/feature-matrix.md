# Feature matrix

Optional features (`coraza-native`, `http3`, `webtransport`,
`ai-threat-detection`, `geoip`, `export-otel`, `export-redb`, `export-sled`,
`io-uring`) are not all exercised by the default build. A test module or
binary can therefore break in a feature combination that CI never compiles.
The `coraza-native` test import regression was one such case: the default
feature set did not enable the module, so the missing import only surfaced
with `cargo test --features coraza-native`.

`scripts/ci-feature-matrix.sh` and `.github/workflows/feature-matrix.yml` run
the same combinations so the gap cannot reopen.

## Running locally

```bash
# Full matrix (default)
./scripts/ci-feature-matrix.sh
just ci-feature-matrix

# Fast subset: skips the slow `cargo check --all-targets` stages
./scripts/ci-feature-matrix.sh --quick
just ci-feature-matrix --quick

# Limit parallel compile jobs
./scripts/ci-feature-matrix.sh --jobs 4
```

Every stage runs through `nix develop -c`, so the local run matches CI. Set
`CI_FEATURE_MATRIX_NIX=0` to invoke `cargo` directly from an already-active
dev shell. The script stops at the first failure and prints a summary naming
the failing combination plus the exact command to rerun it.

## Covered combinations

| Stage | Command | What it covers |
| --- | --- | --- |
| `fmt` | `cargo fmt -- --check` | Formatting across the whole crate. |
| `clippy-default` | `cargo clippy --lib -- --deny warnings` | Lints with the default features (`export-system`, `websocket`, `wasm-reactor`). |
| `test-default` | `cargo test --lib` | Unit tests with the default features, including the WASM reactor host. |
| `test-wasm-reactor` | `cargo test --lib --features wasm-reactor` | The reactor ABI explicitly, so a future default change cannot silently drop it. |
| `test-wasm-reactor+coraza-native` | `cargo test --lib --features wasm-reactor,coraza-native` | The native Go Coraza sidecar client next to the reactor. This is the combination that caught the missing `build_payload` import. |
| `test-no-default-features` | `cargo test --lib --no-default-features` | Builds with every optional feature off; catches unconditional uses of `sled`, `wasmtime` or `websocket` code. |
| `test-no-default-features+wasm-reactor` | `cargo test --lib --no-default-features --features wasm-reactor` | The minimal supported deployment: reactor only, no sled/websocket/export stack. |
| `check-all-targets+coraza-native` | `cargo check --all-targets --features wasm-reactor,coraza-native` | Tests, benches and binaries with the native backend; catches test-only imports and `required-features` mistakes. |
| `check-all-targets+http3+webtransport` | `cargo check --all-targets --features http3,webtransport,wasm-reactor` | QUIC/HTTP3 and WebTransport listeners together with the reactor, across all targets. |
| `check-bin-graphql-allowlist` | `cargo check --bin graphql-allowlist --features wasm-reactor` | The GraphQL allowlist tool that requires `wasm-reactor`. |
| `check-bin-grpc-allowlist` | `cargo check --bin grpc-allowlist --features wasm-reactor` | The gRPC allowlist tool compiled against the reactor feature set. |

`--quick` skips both `check-all-targets` rows. The binary checks still run.

## gRPC transport support

| Case | Classification | Body inspection | Notes |
| --- | --- | --- | --- |
| Unary gRPC with `content-length` | One complete frame | Yes | Buffered up to `server.max_body_size` |
| Unary gRPC without `content-length` (HTTP/2) | One complete frame + end-of-stream/trailers | Yes | The P0 gap: no longer inferred from HTTP framing |
| gRPC-Web binary/text | Buffered | Yes | Text framing is base64-decoded before frame validation |
| Streaming, `grpc_streaming_policy = "transport-only"` | More than one frame / open stream | No (explicit policy) | Start-up warning; header/URI rules still run |
| Streaming, `grpc_streaming_policy = "reject"` | More than one frame / open stream | N/A | `403` or `grpc-status: 7`; upstream not called |
| `grpc-encoding: gzip` | Any | Yes | Bounded by `waf.grpc.max_decompressed_bytes`; original bytes forwarded |
| Unsupported `grpc-encoding` | Any | N/A | `400` |

## Adding a combination

Add a row to the `STAGES` array in `scripts/ci-feature-matrix.sh` and the
matching entry to the `lib-tests` or `compile` matrix in
`.github/workflows/feature-matrix.yml`. Keep the local script and the
workflow in sync; the script is the source of truth when Actions is
unavailable.
