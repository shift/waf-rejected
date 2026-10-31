# WASM / ModSecurity Integration Status

**Validated:** 2026-10-31

## Summary

The bundled `rules/coraza.wasm` is **not** a Coraza/ModSecurity engine and cannot
provide OWASP CRS coverage.

It is a Go `GOOS=js GOARCH=wasm` command module:

- imports the `gojs` host ABI (20 functions, including `runtime.scheduleTimeoutEvent`,
  `syscall/js.*`, `wasmWrite`, timers and the JS value bridge);
- exports only `run`, `resume`, `getsp` and linear `mem`;
- contains `main.*` and `regexp` code with a handful of hardcoded regex checks;
- never reads `rules/coraza.conf`.

`rules/coraza.wat` is a stale, unrelated toy module and does not describe this
binary.

## Why the current Rust host does not execute it

- `src/wasm/bindings.rs` assumes a WIT/component interface.
- `src/wasm/engine.rs` discards core modules and falls back to
  `evaluate_request_mock()`.
- The WASI linker cannot satisfy `gojs` imports.
- Driving the Go JS ABI would require a JS engine or a hand-written
  `wasm_exec.js` shim, plus Go runtime/GC memory and timer handling.

## Options

1. **Replace the artifact** with a purpose-built Coraza/TinyGo reactor exporting a
   clean `init` / `evaluate_request` / `free_result` ABI. Small-to-medium scope.
2. **Embed a JS runtime** and run `wasm_exec.js` semantics. Large scope and high
   memory/CPU cost for a sub-millisecond proxy.
3. **Keep the current built-in heuristic rules** (the Beta behavior) and do not
   advertise ModSecurity/CRS support.

## Beta decision

Beta builds do not compile or ship the WASM runtime. The historical module and
source remain in-tree for future work. Documentation must not claim Coraza,
ModSecurity or OWASP CRS support until option 1 is implemented and tested.
