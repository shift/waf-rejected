# Coraza WASI Reactor

**Status:** experimental, behind the non-default `wasm-reactor` feature
**Module:** `wasm/coraza_reactor/coraza_reactor.wasm`
**Source:** `wasm/coraza_reactor/main.go`

This reactor replaces the historical `GOOS=js GOARCH=wasm` demo with a real
[Coraza](https://github.com/corazawaf/coraza) engine compiled as a Go 1.24
WASI reactor. It has no `syscall/js` imports and no runtime dependency on
`rules/coraza.conf`: the minimal rule set is embedded in the binary.

The reactor is **not** enabled by default, does not replace the built-in
heuristic rules, and does not yet ship OWASP CRS coverage.

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

```sh
nix develop
./scripts/build-coraza-reactor.sh
```

Equivalent manual command:

```sh
cd wasm/coraza_reactor
GOOS=wasip1 GOARCH=wasm go build \
  -tags no_fs_access \
  -buildmode=c-shared \
  -trimpath \
  -ldflags="-s -w" \
  -o coraza_reactor.wasm .
```

`no_fs_access` prevents Coraza from probing the filesystem at start-up. The
output is about 18 MiB because it contains the Go runtime and Coraza.

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

| ID | Phase | Detect |
| --- | --- | --- |
| 1001 | 2 | SQL injection (`union select`, `sleep(`, tautologies, ...) |
| 1002 | 2 | XSS (`<script`, `javascript:`, event handlers, `<iframe`, ...) |
| 1003 | 2 | Path traversal (`../`, `%2e%2e%2f`, double-encoded) |
| 1004 | 2 | Command injection in form fields (`cmd=;`, `exec=|`, ...) |

Rules are Coraza SecLang directives in `embeddedRules`; they are compiled once
per reactor instance (`init`).

## Memory and limits

Host-side limits for the Coraza reactor (`ReactorLimits::coraza`):

| Limit | Value | Enforcement |
| --- | --- | --- |
| `max_payload_bytes` | 64 KiB | Host rejects larger payloads; matches the module's static buffer. |
| `memory_limit_bytes` | 256 MiB | wasmi `StoreLimits`; Go starts near 10 MiB and grows. |
| `fuel` | 2,000,000,000 | Bounds `_initialize` + `init` + `eval`. |
| `max_recursion_depth` | 128 | Bounds native interpreter stack usage. |

Module-side constants: `maxInputBytes = 64 * 1024`. The input buffer is a Go
global; `input_base` exposes its address so the host never writes over Go
runtime data at a fixed low offset.

## Testing

The host test builds on the module actually being executable, not just
parseable:

```sh
nix develop -c cargo test --release --lib --features wasm-reactor -- --ignored
```

`coraza_reactor_allows_benign_and_blocks_attacks` loads the committed module,
asserts a benign request is allowed, and asserts SQLi, XSS and path traversal
payloads are blocked with `403`.

The test is ignored in debug builds: wasmi's unoptimised interpreter frames
are large enough to overflow a normal test-thread stack during Go runtime
start-up. Release builds pass. The production host should run reactor
evaluations on a dedicated thread with a large stack (see remaining work).

## Remaining work

- **OWASP CRS:** embed a pinned CRS bundle and raise the payload/body limits;
  the current four rules are explicitly a starter set.
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
