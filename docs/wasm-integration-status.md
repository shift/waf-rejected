# WASM / ModSecurity Integration Status

**Validated:** 2026-11-05 (legacy component-ABI status; see the current-engine
note below)

## Current engine status (Beta 13+)

This page describes the **legacy component-ABI** `rules/coraza.wasm` module and
the old `src/wasm/` host. It is not the current inspection path.

- The default build compiles the **native Rust CRS engine** (`rust-engine`) and
  selects `waf.coraza.backend = "rust"`.
- The **Coraza 3.8.1 WASI reactor** (`wasm-reactor`, wasmtime 49) is compiled by
  default and is the reference implementation, the differential oracle and the
  explicit `waf.coraza.backend = "wasm"` switch-back.
- The legacy `wasm-waf` component-ABI stage is **not** compiled by default and
  is not the Coraza engine.
- See [`coraza-wasi-reactor.md`](coraza-wasi-reactor.md),
  [`user-guide/engine-selection.md`](user-guide/engine-selection.md) and the
  control matrix in
  [`architecture/security-model.md`](architecture/security-model.md#2-control-status-matrix).

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

The historical Go-JS module and the old `src/wasm/` host remain in-tree for
reference only. They are not the Coraza path. Beta builds ship the Coraza WASI
reactor and the native Rust engine; documentation must not describe
`rules/coraza.wasm` as a Coraza/ModSecurity engine. Any claim of Coraza/CRS
coverage must point at the reactor or the Rust engine, their tests and the
release that introduced them, per the maintenance practice in
[`architecture/security-model.md`](architecture/security-model.md#111-maintenance-practice-for-security-claims).
