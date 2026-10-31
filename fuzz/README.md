# Fuzz targets

`cargo-fuzz`/libFuzzer harnesses for the security-critical parsing and
inspection paths. This crate is an isolated workspace and is **not** part of
the root build, so `cargo build` and `nix build` at the repository root never
require a nightly toolchain.

## Prerequisites

- A nightly Rust toolchain (`rustup toolchain install nightly`).
- `cargo-fuzz` (`cargo install cargo-fuzz`).

The Nix dev shell provides the stable toolchain used by the normal build and
does not include `cargo-fuzz`; run fuzz targets outside the sandboxed build.

## Targets

| Target | Input | Property |
| --- | --- | --- |
| `content_inspection` | Arbitrary bytes as URI query and request body | `ContentInspectionRule::evaluate` must not panic, including percent-decoded and lossy-UTF-8 input. |
| `websocket_frame` | Arbitrary bytes interpreted as a text frame when valid UTF-8, otherwise a binary frame | The WebSocket frame inspection path (`WafEngine::fast_evaluate` with the handler's request context) must not panic. |
| `config_toml` | Arbitrary TOML | `Config` deserialization and `Config::validate` must not panic; invalid input may return an error. |

`WebSocketHandler::inspect_websocket_message` is private. The
`websocket_frame` harness reproduces the context it builds and evaluates it
through the same engine path. It also attaches the frame payload as a request
body so content inspection is exercised; the production helper currently
passes only the body length.

## Commands

```bash
cd fuzz

# List targets.
cargo +nightly fuzz list

# Build all harnesses without running them.
cargo +nightly fuzz build

# Short local smoke run (bounded).
cargo +nightly fuzz run content_inspection -- -runs=10000 -max_total_time=60
cargo +nightly fuzz run websocket_frame  -- -runs=10000 -max_total_time=60
cargo +nightly fuzz run config_toml      -- -runs=10000 -max_total_time=60
```

The seed corpus lives in `corpus/<target>/` and is picked up automatically.
libFuzzer appends newly discovered inputs to the same directory; do not commit
those unless they are intentionally promoted to seeds.

Crashes, timeouts and OOMs are written to `artifacts/<target>/`. Reproduce a
finding with:

```bash
cargo +nightly fuzz run <target> artifacts/<target>/<artifact>
```

## Limits and CI guidance

- Never run unbounded fuzzing on shared or CI runners.
- Pull requests: build the harnesses (`cargo +nightly fuzz build`) and run a
  bounded smoke pass per target, e.g. `-runs=1000 -max_total_time=30`.
- Scheduled jobs: run a longer bounded pass (for example
  `-max_total_time=600`) nightly, cache `fuzz/corpus/`, and upload
  `fuzz/artifacts/` on failure.
- Treat any crash, timeout or leak report as a release blocker for the
  affected path and add the minimised input to the seed corpus with a
  regression test in the main crate.
- Keep `-rss_limit_mb` at the default unless a target is known to need more;
  lowering it produces false OOM reports.
