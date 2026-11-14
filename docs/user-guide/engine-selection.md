# Choosing the Inspection Engine

WAF-Rejected has three request-inspection backends behind the same proxy and
configuration surface. They evaluate the same pinned OWASP CRS 4.14 bundle and
differ in implementation, deployment shape and cost.

| Backend | `waf.coraza.backend` | Build feature | Status |
| --- | --- | --- | --- |
| Native Rust CRS engine | `"rust"` | `rust-engine` (default) | **Default** in default builds |
| Coraza WASI reactor | `"wasm"` | `wasm-reactor` (default) | Reference implementation and differential oracle |
| Native Coraza sidecar | `"native"` | `coraza-native` (opt-in) + `wasm-reactor` | Opt-in high-throughput profile |

The backend resolves at start-up. A build without `rust-engine` keeps
`wasm` as the compiled default, so an old binary or a `--no-default-features`
build behaves as it did before the Rust engine shipped.

## Default: native Rust engine

The default feature set (`export-system`, `websocket`, `wasm-reactor`,
`rust-engine`) compiles the Rust engine and selects it automatically. No
configuration is required.

```toml
[waf]
enabled = true
fail_mode = "closed"

[waf.coraza]
# backend = "rust"   # explicit pin, same as the compiled default
fallback = "none"    # runtime error => fail-closed block
```

At start-up the engine parses the pinned CRS bundle once, compiles it into IR
and logs the rule count. Strict loading aborts start-up (fail closed) if the
bundle cannot be loaded. On the reference host this is ~210 ms of compile time,
~276 ms to readiness and ~30 MiB RSS.

Measured end-to-end proxy p50 on the reference 6-core host:

| Body | Rust engine | Coraza wasm |
| --- | ---: | ---: |
| bodyless | 0.315 ms | 4.47 ms |
| 1 KiB | 0.454 ms | 40.13 ms |
| 4 KiB | 0.810 ms | 169.56 ms |
| 8 KiB | 1.234 ms | 354.09 ms |

These are capacity floors on a shared host, not guarantees. Sub-millisecond
figures apply to bodyless requests, allow-cache hits (0.56–0.96 µs), fast-allow
(0.38 µs) and the engine request path. The engine's own request path is
~566–591 µs at 4 KiB and ~992 µs at 8 KiB; the proxy adds forwarding and I/O.
Response inspection is opt-in (`waf.response_inspection.enabled = true`) and
wired for the native Rust engine.

Corpus parity with Coraza is 2,112/2,112 cases; the former two oracle
differences are resolved. All 505 shipped rules execute.

## Reference / switch-back: Coraza WASI reactor

Set `backend = "wasm"` to return to the reference implementation. This is the
compatibility path and the differential oracle; it is slower and needs a
larger memory budget.

```toml
[waf.coraza]
enabled = true
backend = "wasm"
fallback = "none"
pool_size = 0            # auto: cores, clamped to 1..=8
max_payload_bytes = 65536
```

```bash
WAF_CONFIG_FILE=config/examples/coraza-reference.toml ./result/bin/waf-ingress
```

The reactor is compiled from the embedded ~20 MiB module (or
`module_path`) and pre-warmed before readiness. On the reference host start-up
is ~4.9 s and steady-state RSS is ~801 MiB; the reactor is **not** instantiated
when `backend = "rust"` and `fallback = "none"`, so that footprint does not
apply to the default path.

Coraza remains a default **build** feature. It is available in the released
binary without rebuilding; only the request-path selection changed.

## Opt-in: native Coraza sidecar

`backend = "native"` sends inspection to a separate `coraza-sidecar` process
over a Unix domain socket. It is about 6× faster than wasm on body inspection
but adds a process, a socket, a shared uid/gid requirement and a separate
upgrade lifecycle.

```toml
[waf.coraza]
enabled = true
backend = "native"
native_socket_path = "/run/waf/coraza.sock"
max_payload_bytes = 65536
max_inspect_bytes = 65536
oversize_action = "reject"
pool_size = 8
```

```bash
# Requires a build with --features wasm-reactor,coraza-native
WAF_CONFIG_FILE=config/examples/native-sidecar.toml ./result/bin/waf-ingress
```

`native_socket_path` is mandatory for this backend; otherwise start-up fails.
A sidecar outage returns `503` under `fail_mode = "closed"`, never a silent
allow. See
[native performance profile](../operations/native-performance-profile.md) for
capacity sizing and socket permissions.

## Fail-closed and fallback semantics

- `waf.coraza.fallback = "none"` (default): a Rust-engine runtime error is a
  fail-closed block. Lowest memory; a bug or budget overflow rejects the
  request.
- `waf.coraza.fallback = "wasm"`: after a Rust-engine runtime error the request
  is re-evaluated by the Coraza reactor. If Coraza also errors, the request is
  still blocked. Requires `wasm-reactor`. This doubles engine memory and adds
  re-inspection cost on the error path only.
- `waf.fail_mode = "closed"` (default) applies to inspection failures at the WAF
  layer. Keep it closed. `"open"` is available for emergency availability
  trade-offs and forwards on failure.
- Admission saturation is not an error and is never bypassed: it returns
  `503 + Retry-After`.
- The wasm payload cap is a hard contract. Above it, `inspect-all` fails closed;
  `reject` returns `413`; `forward-uninspected` forwards an explicitly
  partially inspected body.

## Migration and verification

Switching backends does not require a rules rewrite: all three consume the same
vendored CRS bundle and configuration. To verify a switch:

```bash
# Build and test the default-only path
nix develop -c cargo test --lib

# Coraza parity on the CLI
nix develop -c cargo run --features rust-engine --bin rust-engine-parity -- \
  --engine both

# Native profile smoke test (build + sidecar + requests)
./scripts/run-native-profile.sh
```

Check `/metrics` and the start-up log for the selected backend. Roll out to a
canary first: the Rust engine and Coraza agree on the corpus, but backend
changes can alter which rule reports first for a multi-rule payload.

## Opt-in features that are not defaults

- **Hyperscan/Vectorscan candidate pass** (`hyperscan-eval`): x86-64/AVX2 only,
  bounded and falls back to the pure-Rust path.
- **CRS required-literal prefilter** (`crs-prefilter`): `waf.coraza.prefilter`
  `off` by default; `gated` removes only provably absent rules.
- **io_uring listener** (`io-uring`): `server.io_backend = "io_uring"`;
  unsupported hosts fall back to tokio with a warning.
- **Allow cache** (`allow-cache`): `waf.allow_cache.enabled = true`.
- **Fast-allow**: `waf.fast_allow.enabled = true` plus explicit routes; only
  bodyless, query-free requests match.
- **CPU pinning** (`cpu-pinning`): `runtime.enable_cpu_pinning = true`.
