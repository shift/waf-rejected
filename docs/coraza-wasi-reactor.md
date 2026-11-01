# Coraza WASI Reactor

**Status:** experimental, behind the non-default `wasm-reactor` feature
**Module:** `wasm/coraza_reactor/coraza_reactor.wasm`
**Source:** `wasm/coraza_reactor/main.go`

This reactor replaces the historical `GOOS=js GOARCH=wasm` demo with a real
[Coraza](https://github.com/corazawaf/coraza) engine compiled as a Go 1.24
WASI reactor. It has no `syscall/js` imports and no runtime dependency on
`rules/coraza.conf`: a pinned OWASP Core Rule Set (CRS) bundle is embedded in
the binary.

The reactor is **not** enabled by default and does not replace the built-in
heuristic rules. It ships the full **request-side** CRS 4.14.0 rule set
(anomaly scoring, paranoia level 1); response inspection is disabled because
the host does not forward response bodies.

## Toolchain

Verified in the project Nix development shell:

| Component | Version |
| --- | --- |
| Go | `go1.24.5 linux/amd64` |
| Coraza | `github.com/corazawaf/coraza/v3 v3.3.3` |
| Target | `GOOS=wasip1 GOARCH=wasm` |

Go 1.24 `//go:wasmexport` and `-buildmode=c-shared` are required (the latter
also enables the reactor's `_initialize` export).

## Build

The reactor is built from the committed vendor tree
(`wasm/coraza_reactor/vendor`, populated with `go mod vendor`), so the build
needs no network access or module cache. `scripts/build-coraza-reactor.sh`
enforces the pinned toolchain and flags:

```sh
nix develop
./scripts/build-coraza-reactor.sh            # build + export/checksum verification
./scripts/build-coraza-reactor.sh --verify   # rebuild and compare to checksum
```

The script requires Go 1.24.x (`GOTOOLCHAIN=local`), sets
`GOOS=wasip1 GOARCH=wasm`, `CGO_ENABLED=0`, `GOFLAGS=-mod=vendor` and
`GOPROXY=off`, and builds with `-buildmode=c-shared -trimpath -buildvcs=false
-ldflags="-s -w -buildid="`. Equivalent manual command:

```sh
cd wasm/coraza_reactor
GOOS=wasip1 GOARCH=wasm CGO_ENABLED=0 GOFLAGS=-mod=vendor GOPROXY=off \
GOTOOLCHAIN=local go build \
  -tags no_fs_access \
  -buildmode=c-shared \
  -trimpath \
  -buildvcs=false \
  -ldflags="-s -w -buildid=" \
  -o coraza_reactor.wasm .
```

`no_fs_access` prevents Coraza from probing the filesystem at start-up; the
CRS `@pmFromFile` data files are resolved through an embedded `fs.FS`. The
output is about 20 MiB because it contains the Go runtime, Coraza and the CRS
rule/data bundle.

### Reproducibility and checksum

Go's Wasm builds are byte-reproducible with the flags above: the build ID is
empty, paths are trimmed, VCS metadata is excluded, and all inputs come from
the committed `go.mod`, `go.sum` and `vendor/` tree. Two clean builds on the
same `linux/amd64` host with Go 1.24.5 produce identical bytes.

The build writes `wasm/coraza_reactor/coraza_reactor.wasm.sha256` next to the
artifact. `--verify` rebuilds from scratch and fails if the SHA-256 differs
from that sidecar, which makes toolchain or dependency drift explicit:

```sh
(cd wasm/coraza_reactor && sha256sum -c coraza_reactor.wasm.sha256)
```

Reproducibility is across the pinned Go toolchain and host architecture, not
across different Go patch releases; changing Go or `go.mod` requires
regenerating the module and checksum in the same commit.

### Verify exports

`wasm-tools` is not installed in the dev shell; `wasm-objdump` (wabt) and
`wasmtime` are:

```sh
wasm-objdump -x wasm/coraza_reactor/coraza_reactor.wasm \
  | grep -A10 '^Export'
wasmtime run --invoke init wasm/coraza_reactor/coraza_reactor.wasm
```

Expected exports:

| Export | Signature | Notes |
| --- | --- | --- |
| `memory` | linear memory | Imported by the host. |
| `_initialize` | `() -> ()` | Go reactor initialiser; must run before any other export. |
| `input_base` | `() -> i32` | Address of the static request buffer. |
| `init` | `() -> i32` | `0` = ready, non-zero = WAF construction failed. |
| `eval` | `(i32, i32) -> i32` | `0` allow, `1` block, negative protocol error. |
| `free` | `(i32, i32) -> ()` | No-op; the input buffer is static. |

### Imports and WASI shim

Go emits imports from `wasi_snapshot_preview1` (`random_get`,
`clock_time_get`, `fd_write`, `poll_oneoff`, path/fd stubs). The host in
`src/waf/wasm_reactor.rs` links a deliberately capability-free preview1 shim:

- stdio writes are discarded (panic text is mirrored to stderr in test builds);
- `clock_time_get` returns a strictly increasing deterministic counter
  (Go aborts with `nanotime returning zero` otherwise);
- `random_get` returns deterministic bytes;
- all filesystem/path calls return `EBADF`;
- `proc_exit` traps.

The reactor therefore needs no pre-opened directories, no network and no
entropy source.

## ABI

The host calls, for every request:

1. instantiate the module with the WASI shim;
2. call `_initialize` (Go runtime start-up);
3. call `init`;
4. resolve `input_base`, copy the JSON payload there;
5. call `eval(base, len)`;
6. call `free(base, len)`;
7. discard the store (and its linear memory).

The historical spike modules without `_initialize` or `input_base` still work:
the host only calls them when exported and otherwise uses the fixed
`INPUT_BASE = 1024` offset.

### Payload

UTF-8 JSON, matching `build_payload` in `src/waf/wasm_reactor.rs`:

```json
{
  "method": "POST",
  "uri": "/login?next=/home",
  "http_version": "1.1",
  "headers": [["content-type", "application/x-www-form-urlencoded"]],
  "body_size": 38,
  "body": "username=admin&password=not-a-real-password"
}
```

`body` is `null` when no body was captured. Header pairs are the host's
current form; the module also accepts a `{"name": "value"}` object for manual
testing.

### Embedded rules

The reactor embeds OWASP CRS **4.14.0**, commit
`b5b788b5bc50e68836e17995b191f72e848fed75`, under
`wasm/coraza_reactor/rules/crs/`. Provenance, the upstream Apache-2.0 license
and the exact file list are in `rules/crs/PROVENANCE.md` and
`rules/crs/LICENSE`. The bundle is generated by
`scripts/vendor-coraza-crs.sh`; do not edit `crs.conf` by hand.

Included request-side rule files:

| File | Coverage |
| --- | --- |
| `REQUEST-901` | Initialisation, anomaly-score defaults, PL handling |
| `REQUEST-905` | Common static-resource exceptions |
| `REQUEST-911` | Method enforcement |
| `REQUEST-913` | Scanner detection |
| `REQUEST-920` | Protocol enforcement |
| `REQUEST-921` | Protocol attacks |
| `REQUEST-922` | Multipart attacks |
| `REQUEST-930` | LFI / path traversal |
| `REQUEST-931` | RFI |
| `REQUEST-932` | RCE / command injection |
| `REQUEST-933` | PHP injection |
| `REQUEST-934` | Generic attack detection |
| `REQUEST-941` | XSS |
| `REQUEST-942` | SQLi |
| `REQUEST-943` | Session fixation |
| `REQUEST-944` | Java injection |
| `REQUEST-949` | Inbound anomaly-score blocking evaluation |

Default policy: anomaly scoring, inbound threshold `5`, blocking paranoia
level `1`, detection paranoia level `1`. `SecDefaultAction` is CRS `pass`,
and `REQUEST-949` denies with `403` when the inbound score reaches the
threshold.

`crs-setup.conf` is the upstream example configuration unmodified; the reactor
prepends the ModSecurity engine preamble (`SecRuleEngine On`,
`SecRequestBodyAccess On`, body limits, `SecResponseBodyAccess Off`).

**Not included:** response inspection rules (`RESPONSE-950`–`980`), the
deployment-specific example exclusion files (`REQUEST-900`, `REQUEST-999`),
CRS plugins, and the upstream regression corpus. Response bodies are not
available over the current host ABI, so response rule coverage is explicitly
out of scope.

## Live WAF integration

The reactor is wired into the live rule chain only when both the
`wasm-reactor` feature is compiled and `waf.coraza.enabled` is true. It is
registered **before** the heuristic rules so a Coraza block wins even if a
later rule would allow the request.

```toml
[waf]
fail_mode = "closed"      # "open" logs reactor failures and continues

[waf.coraza]
enabled = false           # opt-in; never enabled by default
# module_path = "/etc/waf/coraza_reactor.wasm"  # omit to use the embedded reactor
max_payload_bytes = 65536
memory_limit_bytes = 268435456
fuel = 2000000000
```

`module_path` is optional: when omitted the Coraza module is embedded in the
WAF binary. `Config::validate` rejects zero payload/fuel values, a memory limit
below 64 KiB, a payload limit larger than the memory limit, and an empty module
path.

If the reactor cannot be constructed at start-up, the engine adds a
fail-closed placeholder rule when `waf.fail_mode != "open"`; the placeholder
returns `503`. In `open` mode the failure is logged and the request continues
through the remaining rules. At request time any reactor error (trap, fuel
exhaustion, payload overflow) follows the same policy: `503` when closed,
log-and-allow when open.

## Memory and limits

Host-side limits for the Coraza reactor (`ReactorLimits::coraza`):

| Limit | Value | Enforcement |
| --- | --- | --- |
| `max_payload_bytes` | 64 KiB | Host rejects larger payloads; matches the module's static buffer. |
| `memory_limit_bytes` | 256 MiB | wasmi `StoreLimits`; Go starts near 10 MiB and grows. |
| `fuel` | 200,000,000,000 | Bounds `_initialize` + `init` + `eval`. |
| `max_recursion_depth` | 1024 | Bounds native interpreter stack usage. |

Module-side constants: `maxInputBytes = 64 * 1024`. The input buffer is a Go
global; `input_base` exposes its address so the host never writes over Go
runtime data at a fixed low offset.

## Observability

Attach the shared metrics registry when constructing the rule:

```rust
let metrics = Arc::new(Metrics::new());
let rule = WasmReactorRule::new("coraza", Arc::new(reactor)).with_metrics(metrics);
```

The rule then records, under the `wasm-reactor` feature:

| Metric | Type | Meaning |
| --- | --- | --- |
| `waf_coraza_evaluations_total` | counter | Reactor evaluations attempted (including failures) |
| `waf_coraza_blocks_total` | counter | Decisions returned as block |
| `waf_coraza_errors_total` | counter | Payload-encoding or evaluation failures |
| `waf_coraza_evaluation_duration_seconds` | histogram | End-to-end rule path duration, including payload encoding |

Recording is limited to relaxed atomic increments plus one `Instant` read per
evaluation; there is no allocation on the metrics path. Without
`with_metrics`, the rule performs no metric work.

Prometheus alert rules for the error rate and block spikes are defined in
`infrastructure/monitoring/alert_rules.yml` and documented in
`docs/operations/monitoring.md`.

## Testing

The host test builds on the module actually being executable, not just
parseable:

```sh
nix develop -c cargo test --release --lib --features wasm-reactor -- --ignored
```

`coraza_reactor_allows_benign_and_blocks_attacks` loads the committed module,
asserts that a benign request and two ordinary query/form bodies are allowed,
and asserts SQLi, XSS, path traversal (`../../etc/passwd`) and command
injection (`cmd=/bin/cat /etc/passwd`) payloads are blocked with `403`.

The test is ignored in debug builds: wasmi's unoptimised interpreter frames
are large enough to overflow a normal test-thread stack during Go runtime
start-up. Release builds pass. The production host should run reactor
evaluations on a dedicated thread with a large stack (see remaining work).

## Benchmarks

The reactor has a feature-gated Criterion benchmark:

```sh
nix develop
./scripts/bench-coraza.sh
# equivalent
cargo bench --features wasm-reactor --bench coraza
```

The benchmark loads the committed 18 MiB module once, then measures:

- `reactor_construction/compile_module`: wasmi validation/compilation of the
  module bytes;
- `reactor_construction/compile_instantiate_and_init`: compilation plus a cold
  `_initialize` + `init` + `eval`;
- `reactor_decision/{allow,block_sqli,block_xss}`: full `evaluate` calls on a
  pre-compiled reactor, including a fresh store, Go runtime `_initialize`,
  Coraza `init` and `eval`;
- `reactor_body/allow_body/{1kb,16kb,64kb}`: clean POST bodies of 1 KiB and
  16 KiB, plus the largest body that fits the ABI's fixed 64 KiB payload
  buffer (`64kb` row, about 65.4 KB after the JSON envelope). A literal 64 KiB
  body cannot be represented because the JSON envelope would exceed
  `CORAZA_MAX_PAYLOAD_BYTES`.

Recorded on 2026-11-01 in the Nix development shell:

| Component | Value |
| --- | --- |
| CPU | Intel Core i5-8400T (6 threads, 1.70 GHz base) |
| OS / kernel | Linux 6.18.36 x86_64 |
| Rust | 1.89.0 |
| Profile | Cargo `bench` (opt-level 3, LTO, codegen-units 1) |

| Benchmark | p50 | mean | Throughput |
| --- | ---: | ---: | ---: |
| compile module | 126.9 ms | 129.6 ms | — |
| compile + cold init + eval | 234.1 ms | 244.8 ms | — |
| allow decision | 63.1 ms | 66.3 ms | 15.1 ops/s |
| SQLi block | 60.6 ms | 61.4 ms | 16.3 ops/s |
| XSS block | 60.9 ms | 61.4 ms | 16.3 ops/s |
| 1 KiB body (allow) | 60.8 ms | 61.3 ms | 18.3 KiB/s |
| 16 KiB body (allow) | 63.7 ms | 64.3 ms | 250.8 KiB/s |
| 64 KiB body ceiling (allow) | 73.7 ms | 80.4 ms | 795.6 KiB/s |

These numbers are informational only; there are no latency assertions in the
benchmark. The dominant cost is the per-evaluation Go runtime and Coraza
engine start-up in `evaluate`, not rule matching or body size. Reusing a
single instance or pool, or moving to a compiled Wasm runtime, is required
before this reactor can be considered for the proxy hot path.

### Observed latency

`measure_coraza_reactor_latency` reports load and per-request cost without a
brittle assertion. Observed on the development machine in release mode:

| Measurement | Observed |
| --- | --- |
| Module compile/load | ~581 ms |
| Per request (benign, fresh Go runtime) | ~207 ms average over 5 runs |

The per-request figure is dominated by starting a fresh Go runtime and
compiling the embedded SecLang rules for every evaluation. This is why the
reactor remains opt-in and is not used for the fast path. Treat these numbers
as an order of magnitude, not a service-level guarantee.

## Remaining work

- **Response coverage:** enable `SecResponseBodyAccess` and the
  `RESPONSE-950`–`980` files once the ABI carries response bodies.
- **CRS tuning:** add deployment-specific exclusions (`REQUEST-900` /
  `REQUEST-999`) and raise the paranoia level only with application-specific
  false-positive testing.
- **Performance:** a fresh Go runtime start-up per evaluation is unacceptable
  for sub-millisecond proxying. Reuse a single instance (or a pool) behind a
  mutex, or replace the interpreter with a compiled Wasm runtime. Measure
  start-up, per-request latency and memory growth.
- **Native stack:** confirm a dedicated reactor thread with a known stack size
  in release, and remove the test-only `#[ignore]` once a debug-friendly
  runtime path exists.
- **Module size:** run `wasm-opt -Oz` and/or split unused Coraza features;
  18 MiB is large for an embedded security control.
- **Default enablement:** keep `wasm-reactor` non-default until CRS,
  performance and an explicit fail-open/fail-closed policy are agreed.
- **Body fidelity:** the ABI is UTF-8/lossy; binary-safe inspection needs a
  byte-oriented payload format.
