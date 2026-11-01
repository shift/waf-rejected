# Coraza WASI Reactor

**Status:** experimental, behind the non-default `wasm-reactor` feature
**Module:** `wasm/coraza_reactor/coraza_reactor.wasm`
**Source:** `wasm/coraza_reactor/main.go`

This reactor replaces the historical `GOOS=js GOARCH=wasm` demo with a real
[Coraza](https://github.com/corazawaf/coraza) engine compiled as a Go 1.24
WASI reactor. It has no `syscall/js` imports and no runtime dependency on
`rules/coraza.conf`: a pinned OWASP Core Rule Set (CRS) bundle is embedded in
the binary. The host embeds [wasmtime](https://wasmtime.dev) 49 (Cranelift)
and uses wasmtime-wasi's preview1 imports for the Go runtime.

The reactor is **not** enabled by default and does not replace the built-in
heuristic rules. It ships the full **request-side** CRS 4.14.0 rule set
(anomaly scoring, paranoia level 1); response inspection is disabled because
the host does not forward response bodies.

## Packaging and stable path

The module is a first-class release artifact. The Nix package and the release
container image install it, its Apache-2.0 licence (`LICENSE-CRS`), its
provenance (`PROVENANCE.md`) and its digest (`SHA256SUMS`) at:

```text
/usr/share/waf/wasm/coraza_reactor.wasm
/usr/share/waf/wasm/LICENSE-CRS
/usr/share/waf/wasm/PROVENANCE.md
/usr/share/waf/wasm/SHA256SUMS
```

The binary tarball ships `wasm/coraza_reactor.wasm` plus `wasm/LICENSE-CRS`,
`wasm/PROVENANCE.md` and `wasm/SHA256SUMS`. Tagged releases
also attach the module, licence and provenance as standalone assets with
`.sha256` checksums, and the CycloneDX SBOM records the module as a `file`
component with its SHA-256 and `Apache-2.0` licence. The current digest is
recorded in `wasm/coraza_reactor/SHA256SUMS`; do not update the module without
updating that file, `PROVENANCE.md` and the SBOM output in the release run.

### Size budget and the 18 MiB tradeoff

`wasm/coraza_reactor/coraza_reactor.wasm` is about 20 MiB because it embeds
the Go runtime and the Coraza engine. That is large for an embedded security
control, but it buys a self-contained, auditable module with no JavaScript
host, no filesystem access and no runtime dependency on `rules/coraza.conf`.
The release pipeline enforces a **32 MiB** ceiling
(`CORAZA_MAX_MODULE_BYTES`, 33,554,432 bytes) in the Nix package, the
container build, `scripts/check-coraza-reactor-size.sh` and the host loader.
Exceeding it fails the build or startup instead of silently shipping a debug
or unstripped binary. Shrinking the module with `wasm-opt -Oz` remains
desirable, but the budget leaves headroom for a pinned CRS bundle.

## Startup validation (fail closed)

With the `wasm-reactor` feature compiled in, `waf-ingress` validates the
reactor during startup, before it starts listening:

1. read the module from `WAF_CORAZA_REACTOR_PATH` (default
   `/usr/share/waf/wasm/coraza_reactor.wasm`);
2. reject a missing file, unreadable file, malformed module or module over the
   32 MiB budget;
3. require `memory`, `_initialize`, `input_base`, `init`, `eval` and `free`;
4. run `_initialize`/`init` and one benign evaluation.

Any failure is fatal and prints a `Coraza reactor startup validation failed
(fail-closed): ...` error. Set `WAF_CORAZA_REACTOR_ENABLED=false` only for
local experiments; disabling the check means the module is not validated at
startup. Feature builds without the module therefore fail closed rather than
serving traffic with an unvalidated Coraza control.

## Toolchain

Verified in the project Nix development shell:

| Component | Version |
| --- | --- |
| Rust | `rustc 1.99.1` (pinned in `flake.nix`) |
| Host runtime | `wasmtime` / `wasmtime-wasi` 49.0.5 |
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

Go emits imports from `wasi_snapshot_preview1` (`sched_yield`, `proc_exit`,
`args_*`, `environ_*`, `clock_time_get`, `random_get`, `fd_write`,
`poll_oneoff`, path/fd stubs). `src/waf/wasm_reactor.rs` builds the linker with
`wasmtime_wasi::p1::add_to_linker_sync` and a `WasiCtxBuilder` that has no
preopened directories, no arguments and no environment. stdout/stderr are
discarded.

wasmtime-wasi implements sync preview1 calls by driving async host functions on
an ambient Tokio runtime (`Handle::block_on`). The proxy evaluates rules from
inside its own Tokio workers, where that call panics with *"Cannot start a
runtime from within a runtime"*. The file/stdio imports are therefore shadowed
after the wasmtime-wasi linker is installed:

- `fd_write` discards bytes and reports the full length;
- `fd_read`, `fd_pread` report zero bytes;
- `fd_fdstat_get` reports a character device; other fd/path calls return
  `EBADF`;
- `poll_oneoff` reports zero ready events.

The WASI clock and entropy calls remain wasmtime-wasi's host implementations:
Go requires a monotonic clock (`nanotime returning zero` aborts start-up) and
`random_get` for runtime hash seeds. The reactor still needs no pre-opened
directories, no network, no arguments and no environment. `proc_exit` traps via
wasmtime-wasi.

## ABI

The host keeps one initialised instance per worker thread and reactor. On the
first evaluation on a thread it:

1. instantiates the module with the WASI shim;
2. calls `_initialize` (Go runtime start-up);
3. calls `init` (compiles the embedded SecLang rules);
4. resolves `input_base`.

Every request then only:

1. resets the fuel budget;
2. copies the JSON payload to `input_base`;
3. calls `eval(base, len)`;
4. calls `free(base, len)`.

The instance is reused for later requests on that thread; `eval` creates and
closes a Coraza transaction per request, so decisions do not leak between
requests. A failed evaluation (trap, fuel exhaustion, failed init) discards the
instance and the next request recreates it. Instances live in a thread-local
cache keyed by reactor identity (`WasmReactor::id`) with a small bounded
capacity, which is required because wasmtime `Store`/`Instance`/`Memory` are
not `Send`. One thread never shares its instance with another, and a re-entrant
call on the same thread is rejected rather than aliasing a live store.

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
| `memory_limit_bytes` | 256 MiB | wasmtime `StoreLimits` with `trap_on_grow_failure`; Go starts near 10 MiB and grows. |
| `fuel` | 200,000,000,000 | Bounds `_initialize` + `init` on first use; reset before every `eval`. |
| `max_wasm_stack` | 8 MiB | Bounds native stack used by compiled wasm frames; traps instead of overflowing the host thread. |
| `async_stack_size` | 8 MiB | Must be at least `max_wasm_stack`; required by wasmtime even for sync calls. |

Module-side constants: `maxInputBytes = 64 * 1024`. The input buffer is a Go
global; `input_base` exposes its address so the host never writes over Go
runtime data at a fixed low offset.

The thread-local instance cache holds at most two initialised reactors per
thread (roughly one production configuration plus headroom for rotation).
Because a Go reactor can grow to the 256 MiB memory limit, budget up to that
amount per worker thread that evaluates Coraza traffic. `clear_thread_cache()`
releases cached instances for the current thread.

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
`coraza_reactor_reuses_instance_without_leaking_state` interleaves
allow/block/allow/XSS decisions repeatedly on one reactor to prove the cached
instance does not carry state between evaluations, and
`coraza_reactor_isolated_per_thread` runs the same `Arc<WasmReactor>` on three
threads to prove each thread gets its own instance.

The tests are ignored in debug builds because Go runtime start-up and CRS
compilation are slow without optimisation. Release builds pass:
`cargo test --release --lib --features wasm-reactor -- --ignored` runs all five
Coraza tests.

## Benchmarks

The reactor has a feature-gated Criterion benchmark:

```sh
nix develop
./scripts/bench-coraza.sh
# equivalent
cargo bench --features wasm-reactor --bench coraza
```

The benchmark loads the committed 20 MiB module once, then measures:

- `reactor_construction/compile_module`: wasmtime/Cranelift compilation of the
  module bytes;
- `reactor_construction/compile_instantiate_and_init`: compilation plus a cold
  `_initialize` + `init` + `eval`;
- `reactor_decision/{allow,block_sqli,block_xss}`: full `evaluate` calls on a
  pre-compiled reactor, reusing the thread-local initialised instance (only
  `eval` runs after the first warm-up call);
- `reactor_body/allow_body/{1kb,16kb,64kb}`: clean POST bodies of 1 KiB and
  16 KiB, plus the largest body that fits the ABI's fixed 64 KiB payload
  buffer (`64kb` row, about 65.4 KB after the JSON envelope). A literal 64 KiB
  body cannot be represented because the JSON envelope would exceed
  `CORAZA_MAX_PAYLOAD_BYTES`.

Recorded on 2026-11-01 in the Nix development shell, after the thread-local
instance cache was introduced:

| Component | Value |
| --- | --- |
| CPU | Intel Core i5-8400T (6 threads, 1.70 GHz base) |
| OS / kernel | Linux 6.18.36 x86_64 |
| Rust | 1.99.1 |
| Profile | Cargo `bench` (opt-level 3, LTO, codegen-units 1) |

| Benchmark | p50 | mean | Throughput |
| --- | ---: | ---: | ---: |
| compile module (Cranelift) | 5.49 s | 5.57 s | — |
| compile + cold init + eval | 9.50 s | 9.70 s | — |
| allow decision (warm) | 8.42 ms | 7.02 ms | ~119 ops/s |
| SQLi block (warm) | 10.59 ms | 10.62 ms | ~94 ops/s |
| XSS block (warm) | not re-measured | — | — |
| 1 KiB body (warm) | not re-measured | — | — |
| 16 KiB body (warm) | not re-measured | — | — |
| 64 KiB body ceiling (warm) | not re-measured | — | — |

wasmtime is **5–8× faster than wasmi with the CRS module** (wasmi/CRS measured
40.4 ms allow and 75.3 ms SQLi). It is still not sub-millisecond: the Go/Coraza
transaction and full-payload JSON decoding dominate. The compiled module is
created once per process and shared across threads; each worker thread still
pays Go `_initialize`/CRS `init` once (~0.5 s after the shared 4.5 s compile),
so default enablement needs startup pre-warming.

### Observed latency

`measure_coraza_reactor_latency` reports load and per-request cost without a
brittle assertion. Observed on the development machine in release mode:

| Measurement | Observed |
| --- | --- |
| Module compile/load (Cranelift) | ~4.5 s |
| First evaluation on a thread (includes Go/CRS init) | ~0.49 s |
| Subsequent evaluations, CRS allow | ~8.4 ms p50 |
| Subsequent evaluations, CRS SQLi | ~10.6 ms p50 |

The per-request figure no longer includes Go runtime start-up or SecLang rule
compilation; those run once per thread and reactor. Treat these numbers as an
order of magnitude, not a service-level guarantee.

## Remaining work

- **Response coverage:** enable `SecResponseBodyAccess` and the
  `RESPONSE-950`–`980` files once the ABI carries response bodies.
- **CRS tuning:** add deployment-specific exclusions (`REQUEST-900` /
  `REQUEST-999`) and raise the paranoia level only with application-specific
  false-positive testing.
- **Performance:** wasmtime's compiled execution did not remove the dominant
  cost: the Go/Coraza transaction work and full-payload JSON decoding still
  dominate. Large bodies (16–64 KiB) remain in the low-millisecond range, so
  sub-millisecond proxying needs a byte-oriented, allocation-free ABI rather
  than a faster runtime.
- **Tokio interaction:** wasmtime-wasi's sync preview1 adapters cannot run
  inside the proxy's Tokio workers, hence the shadowed stdio/path imports. If
  a future wasmtime-wasi release offers a runtime-free sync surface, the shims
  can be removed.
- **Native stack:** the 8 MiB wasm stack is validated by the release test
  suite. The thread-local cache keeps initialisation on whichever worker
  thread first evaluates Coraza traffic; confirm worker stack size before
  enabling the reactor on a small-stack executor.
- **Module size:** run `wasm-opt -Oz` and/or split unused Coraza features;
  20 MiB is large for an embedded security control.
- **Default enablement:** keep `wasm-reactor` non-default until CRS,
  performance and an explicit fail-open/fail-closed policy are agreed.
- **Body fidelity:** the ABI is UTF-8/lossy; binary-safe inspection needs a
  byte-oriented payload format.
