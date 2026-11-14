# WASM Reactor ABI Spike

**Status:** experimental, behind the non-default `wasm-reactor` feature
**Scope:** prove a clean request-in / decision-out WebAssembly boundary that a
real Coraza/TinyGo reactor can later implement without a JavaScript host.

This spike does **not** replace the built-in heuristic rules, is not wired into
the default proxy pipeline, and does not claim OWASP CRS coverage. It exists to
settle the host/module contract before investing in a Coraza/TinyGo build.

## Why the old Go-JS module cannot be used

The bundled `rules/coraza.wasm` (source in `wasm/main.go`) is a
`GOOS=js GOARCH=wasm` command module, not a reactor:

- it imports the `gojs` host ABI (about 20 functions: `syscall/js.*`, timers,
  `wasmWrite`, the JS value bridge) and needs `wasm_exec.js` semantics;
- it exports only `run`, `resume`, `getsp` and `mem`, so there is no
  `eval(ptr, len)` entry point;
- it drives the Go scheduler, GC and timers, which requires a JavaScript event
  loop;
- it never reads `rules/coraza.conf`.

A pure-Rust interpreter such as `wasmi` cannot satisfy `gojs` imports, and
embedding a JS runtime would add substantial memory and latency to a
sub-millisecond proxy. See `docs/wasm-integration-status.md` for the full
analysis. The replacement path is a purpose-built reactor that exports the ABI
below and has no JavaScript dependency.

## Host

`src/waf/wasm_reactor.rs` uses [`wasmi`](https://crates.io/crates/wasmi), a
pure-Rust WebAssembly interpreter, so no C/JS runtime or WASI host is required
for this ABI. `wasmi` is an optional dependency and is only compiled with:

```sh
nix develop -c cargo check --lib --features wasm-reactor
nix develop -c cargo test  --lib --features wasm-reactor
```

The compiled `wasmi::Module` and `Engine` are reused across requests. A fresh
`Store` (and therefore a fresh linear memory) is created per evaluation, which
isolates requests without sharing mutable state.

## ABI

The module must be a core Wasm module (not a component) with no imports.

| Export | Signature | Contract |
| --- | --- | --- |
| `memory` | linear memory | At least 1 page (64 KiB). The host reads/writes payload bytes here. |
| `init` | `() -> i32` | `0` = ready, non-zero = initialisation failure. Called once per fresh instance before `eval`. |
| `eval` | `(ptr: i32, len: i32) -> i32` | `0` = allow, `1` = block, negative = protocol/ABI error. |
| `free` | `(ptr: i32, len: i32) -> ()` | Releases the request region. The spike module is a no-op; real reactors may reclaim memory. |

### Payload layout

The host writes the JSON request payload at the fixed scratch offset
`INPUT_BASE = 1024` and passes `(1024, payload_len)` to `eval`. The spike
module does not allocate, so a fixed offset keeps the ABI minimal. The payload
is UTF-8 JSON:

```json
{
  "method": "GET",
  "uri": "/search?q=test",
  "http_version": "1.1",
  "headers": [["accept", "text/html"]],
  "body_size": 12,
  "body": "hello world"
}
```

`body` is `null` when no body was captured. Header values and body bytes are
lossily converted to UTF-8; the spike is not a binary-safe inspection API.

### Decision codes

| Code | Meaning |
| --- | --- |
| `0` | Allow |
| `1` | Block (`403`) |
| `< 0` | ABI error; the host reports `ReactorError::UnknownDecision` and the rule fails closed |

The spike module implements two hardcoded checks over the raw payload bytes:

- any `<` byte → block (XSS stand-in);
- the byte sequence `union ` → block (SQLi stand-in).

These are placeholders for demonstration and tests only.

## Memory and limits

`ReactorLimits` defaults:

| Limit | Default | Enforcement |
| --- | --- | --- |
| `max_payload_bytes` | 32 KiB | Host rejects larger payloads before touching Wasm memory. |
| `memory_limit_bytes` | 64 KiB | `wasmi::StoreLimits` rejects `memory.grow` beyond the limit. |
| `eval_timeout` | 5 s | wasmtime epoch interruption bounds wall-clock time per `eval`; `init` gets a fixed 60 s budget. |

The module itself declares `(memory 1 1)`; a real reactor that needs more
scratch space must raise both its minimum pages and `memory_limit_bytes`.
Because the payload is copied at `INPUT_BASE`, the maximum request payload is
also bounded by `memory_limit_bytes - INPUT_BASE`.

Additional hardening already in place:

- module export presence is checked at load time (`memory`, `init`, `eval`,
  `free`);
- negative and overflowing `(ptr, len)` values are rejected inside the module;
- traps, epoch timeouts and unknown decision codes surface as
  `ReactorError` rather than panics;
- the rule maps any reactor failure to `503` (fail closed), matching the
  project's fail-closed posture.

## Using the rule

```rust
use std::sync::Arc;
use waf_ingress::waf::wasm_reactor::{WasmReactor, WasmReactorRule};

let reactor = Arc::new(WasmReactor::spike()?);
let rule = WasmReactorRule::new("coraza-reactor", reactor);
// Register explicitly with WafEngine; nothing is registered automatically.
```

`WasmReactor::from_wat` / `from_bytes` accept a replacement module without
changing the host.

## Replacing the WAT with a real Coraza/TinyGo reactor

1. Build a reactor module with the same four exports and no imports.
   With TinyGo, export the entry points and compile for a reactor-style target,
   for example:

   ```go
   //go:wasmexport init
   func init() int32 { /* create Coraza WAF, load CRS */ return 0 }

   //go:wasmexport eval
   func eval(ptr, length int32) int32 { /* copy payload, inspect, return 0/1 */ }

   //go:wasmexport free
   func free(ptr, length int32) { /* release buffers */ }
   ```

   ```sh
   tinygo build -o coraza_reactor.wasm -target=wasi -buildmode=c-shared .
   ```

   TinyGo's `wasi` target imports `wasi_snapshot_preview1`. The current host
   intentionally rejects imports, so the follow-up must either:

   - add a `wasmi_wasi` host with a minimal preview1 implementation and an
     explicit allow-list, or
   - build the reactor with a target that does not import WASI (for example,
     `-target=wasm-unknown` / a custom target with `-scheduler=none` and no
     `os`/`fmt` use).

2. Keep the ABI fixed:
   - read exactly `(ptr, len)` from linear memory;
   - do not retain host pointers across calls;
   - return `0` or `1`; use negative values only for protocol errors;
   - release any allocation in `free`.

3. Load it from the host:

   ```rust
   let wasm = std::fs::read("coraza_reactor.wasm")?;
   let reactor = WasmReactor::from_bytes(&wasm, ReactorLimits::default())?;
   ```

4. Raise `memory_limit_bytes` and `eval_timeout` deliberately. Coraza rule
   loading and regex evaluation are heavier than the spike; measure before
   enabling it in the proxy pipeline.

5. Add parity tests: benign allow, SQLi/XSS block, oversized body, malformed
   module, trap, epoch timeout, and a request that exercises CRS rule IDs.

## Known limitations

- Not default; not registered by `WafEngine::add_default_rules`.
- The spike scans raw JSON bytes, so it does not decode percent-encoded input.
  A real reactor must parse the payload and inspect decoded parameters, headers
  and body.
- No WASI/import support yet, which blocks an unmodified TinyGo `wasi` build.
- One fresh `Store` per request keeps isolation simple but allocates a linear
  memory per evaluation; pooling can be added once the ABI is stable.
- The decision only carries a status and reason. Rule IDs, severity, tags and
  matched-data offsets are not part of the ABI yet.
- No hot reload, module signature verification, or per-tenant modules.
