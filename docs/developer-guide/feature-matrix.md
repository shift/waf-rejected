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

GitHub Actions is currently billing-blocked. The local gate is
`./scripts/ci-local.sh`; it runs fmt, clippy (including all targets), tests,
this feature matrix, shipped-config validation, the 16-case CRS smoke corpus
and `nix build .#waf-ingress`. The `workflow_dispatch` inputs in
`.github/workflows/feature-matrix.yml` map to the optional local scripts
`scripts/run-crs-corpus.sh` and `scripts/check-engine-guarantees.sh`.

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
| `check-all-targets+ai-threat-detection` | `cargo check --all-targets --features ai-threat-detection` | The heuristic AI threat-detection module across all targets. |
| `check-bin-graphql-allowlist` | `cargo check --bin graphql-allowlist --features wasm-reactor` | The GraphQL allowlist tool that requires `wasm-reactor`. |
| `check-bin-grpc-allowlist` | `cargo check --bin grpc-allowlist --features wasm-reactor` | The gRPC allowlist tool compiled against the reactor feature set. |

`--quick` skips both `check-all-targets` rows. The binary checks still run.

## All-targets clippy

The blocking lint gate is:

```bash
nix develop -c cargo clippy --all-targets \
  --features wasm-reactor,coraza-native -- --deny warnings
```

This covers the library, every binary, tests, benches and examples. It is a
stage in `scripts/ci-local.sh`.

`cargo clippy --all-targets --all-features -- --deny warnings` is **not** a
supported gate. Two features are mutually exclusive or environment-specific:

| Feature | Why it is excluded from `--all-features` |
| --- | --- |
| `alloc-jemalloc` | `tikv-jemalloc-sys`'s configure step cannot determine `strerror_r` in the sandboxed Nix dev shell. It also defines a second `#[global_allocator]` alongside `alloc-mimalloc`. |
| `alloc-mimalloc` | Defines a second `#[global_allocator]` when combined with `alloc-jemalloc`. |

Use one allocator feature at a time, for example
`--features wasm-reactor,coraza-native,alloc-mimalloc`. The `hyperscan-eval`
feature additionally links the system `libhs` provided by the dev shell; it is
covered by its own benchmark/test targets rather than the default matrix.

## Feature status

`wasm-waf` is a legacy, intentionally empty feature retained for older
configuration files. It is **not supported and does not compile** (the
historical `wasm` module is not built); it is not part of the advertised
matrix. The live WASM path is `wasm-reactor`. `ai-threat-detection` is a
heuristic module that compiles and is exercised by the library tests.

## gRPC transport support

| Case | Classification | Body inspection | Notes |
| --- | --- | --- | --- |
| Unary gRPC with `content-length` | One complete frame | Yes | Buffered up to `server.max_body_size` |
| Unary gRPC without `content-length` (HTTP/2) | One complete frame + end-of-stream/trailers | Yes | The P0 gap: no longer inferred from HTTP framing |
| gRPC-Web binary/text | Buffered | Yes | Text framing is base64-decoded before frame validation |
| Streaming, `grpc_streaming_policy = "transport-only"` | More than one frame / additional bytes after the first complete message | Yes, per message | Explicit opt-out; every message inspected before forwarding; start-up warning |
| Streaming, `grpc_streaming_policy = "reject"` (default) | More than one frame / additional bytes after the first complete message | N/A | `403` or `grpc-status: 7`; upstream not called |
| `grpc-encoding: gzip` | Any | Yes | Bounded by `waf.grpc.max_decompressed_bytes`; original bytes forwarded |
| Unsupported `grpc-encoding` | Any | N/A | `400` |

## Adding a combination

Add a row to the `STAGES` array in `scripts/ci-feature-matrix.sh` and the
matching entry to the `lib-tests` or `compile` matrix in
`.github/workflows/feature-matrix.yml`. Keep the local script and the
workflow in sync; the script is the source of truth when Actions is
unavailable.
