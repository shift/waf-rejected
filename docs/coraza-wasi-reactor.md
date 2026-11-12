# Coraza WASI Reactor

**Status:** reference implementation; available in default builds. Since
`0.1.0-beta.13` the default request-inspection backend is the native Rust CRS
engine (`waf.coraza.backend = "rust"`); set `waf.coraza.backend = "wasm"` to use
this reactor.
**Module:** `wasm/coraza_reactor/coraza_reactor.wasm`
**Source:** `wasm/coraza_reactor/main.go`

This reactor replaces the historical `GOOS=js GOARCH=wasm` demo with a real
[Coraza](https://github.com/corazawaf/coraza) engine compiled as a Go 1.26
WASI reactor. It has no `syscall/js` imports and no runtime dependency on
`rules/coraza.conf`: a pinned OWASP Core Rule Set (CRS) bundle is embedded in
the binary. The host embeds [wasmtime](https://wasmtime.dev) 49 (Cranelift)
and uses wasmtime-wasi's preview1 imports for the Go runtime.

The reactor is **available in default builds**: the `wasm-reactor` Cargo
feature is part of `default`, and `WafCorazaConfig::default().enabled` is
`true`. It is **not** the default request-inspection backend: the Rust engine is
selected when compiled (`backend = "rust"`), and the reactor is only
instantiated when `backend = "wasm"` or when `fallback = "wasm"` needs it. When
selected it runs before the built-in heuristic rules, which remain as defence in
depth. It ships the full **request-side** CRS 4.14.0 rule set (anomaly scoring,
paranoia level 1); response inspection is disabled because the host does not
forward response bodies. To opt out, set `waf.coraza.enabled = false` (the
documented switch) or build with `--no-default-features`.

Measured cost when selected: about **4.5 s** to compile the ~20 MiB module once
at start-up, about **1.1 s** to warm the reactor pool before readiness, and
end-to-end proxy p50 **4.47 / 40.13 / 169.56 / 354.09 ms** for bodyless / 1 / 4
/ 8 KiB bodies on the reference host (versus 0.315 / 0.454 / 0.810 / 1.234 ms
for the default Rust engine).

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
or unstripped binary. `wasm-opt -O3` was evaluated as a size lever: it yields
a valid 18,975,699-byte module (−5.6%) with identical decisions, but it does
not change steady-state evaluation cost, so the committed artifact stays the
plain Go build (see [Runtime and module tuning](#runtime-and-module-tuning-measured)).
`-Oz` is smaller still (18,087,425 bytes) and no faster.

## Startup validation (fail closed)

With the `wasm-reactor` feature compiled in (the default), `waf-ingress`
validates the reactor module during startup, before it starts listening. This
happens even when the Rust engine is the selected backend, so a broken bundled
artifact is caught early; the reactor itself is only compiled and warmed when
`backend = "wasm"` (or `fallback = "wasm"` is armed):

1. `validate_startup(&config)` returns immediately when `waf.enabled` or
   `waf.coraza.enabled` is false;
2. otherwise it resolves the same module source the engine uses: the
   `waf.coraza.module_path` file when set, or the embedded reactor when
   `None`. It rejects a missing/unreadable file or a module over the 32 MiB
   budget;
3. When the wasm backend (or wasm fallback) is selected,
   `WafEngine::with_config` compiles that module once, requires
   `memory`, `_initialize`, `input_base`, `init`, `eval` and `free`, and warms
   the worker pool (`_initialize`/`init` on every worker);
4. `WafProxyService::new` treats any reactor compile, export-validation or
   warm-up failure as fatal and aborts start-up.

There is no environment-variable escape hatch: `waf.coraza.enabled = false`
is the documented switch, and it also skips module validation and pool
warm-up. `validate_startup` never builds a second reactor or pool, so the
module is compiled and warmed exactly once. Feature builds without a valid
module therefore fail closed rather than serving traffic with an unvalidated
Coraza control.

## Toolchain

Verified in the project Nix development shell:

| Component | Version |
| --- | --- |
| Rust | `rustc 1.99.1` (pinned in `flake.nix`) |
| Host runtime | `wasmtime` / `wasmtime-wasi` 49.0.5 |
| Go | `go1.26.10 linux/amd64` |
| Coraza | `github.com/corazawaf/coraza/v3 v3.8.1` |
| Target | `GOOS=wasip1 GOARCH=wasm` |

Go 1.26 `//go:wasmexport` and `-buildmode=c-shared` are required (the latter
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

The script requires Go 1.26.x (`GOTOOLCHAIN=local`), sets
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

The script deliberately does **not** run Binaryen. `wasm-opt -O3` was measured
(see [Runtime and module tuning](#runtime-and-module-tuning-measured)): it
shrinks the module by 5.6% with identical decisions but no measurable change
in evaluation cost, so it is not wired into the reproducible build.

### Reproducibility and checksum

Go's Wasm builds are byte-reproducible with the flags above: the build ID is
empty, paths are trimmed, VCS metadata is excluded, and all inputs come from
the committed `go.mod`, `go.sum` and `vendor/` tree. Two clean builds on the
same `linux/amd64` host with Go 1.26.10 produce identical bytes.

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
| `decision_base` | `() -> i32` | Optional address of the fixed 8-byte decision header. |
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

`WasmReactor::warm()` starts a fixed-size pool of dedicated OS threads and
blocks until every one of them has finished start-up. `warm_workers(n)` is the
explicit form: it pre-warms exactly `n` instances (clamped to `1..=8`) and is
what proxy start-up should call before marking readiness healthy. Any failure
aborts the pool and returns an error, so start-up fails closed.

1. instantiates the module with the WASI shim;
2. calls `_initialize` (Go runtime start-up);
3. calls `init` (compiles the embedded SecLang rules);
4. resolves `input_base` and, when exported, `decision_base`.

Every request then only:

1. hands the payload to an idle pool worker;
2. sets the wasmtime epoch deadline from `waf.coraza.eval_timeout_ms`;
3. writes the payload directly into the guest's static input buffer at
   `input_base` (no host-side JSON string is built for the binary ABI);
4. calls `eval(base, len)`;
5. reads the fixed decision header at `decision_base` (code + HTTP status);
6. calls `free(base, len)`.

`eval` creates and closes a Coraza transaction per request, so decisions do not
leak between requests. A failed evaluation (trap, epoch timeout, failed init)
discards that worker's instance, returns the error to the caller and the
worker's next job rebuilds it. Each worker owns one wasmtime
`Store`/`Instance`/`Memory`, which are not `Send`, so instances never migrate
between threads and no thread ever aliases another's store.

If `warm()` was never called, the first `evaluate` warms the pool lazily and
pays its cost; production callers should warm during start-up. Rule
construction (`WasmReactorRule::from_module`/`from_config`) calls `warm()`, so
engine start-up is the only place that pays Go/CRS initialisation.
`validate_startup()` only checks the module source and size budget; it
deliberately does not compile or warm a second reactor.

### Pool design

- **Size:** `std::thread::available_parallelism()` clamped to `1..=8`, or an
  explicit `waf.coraza.pool_size` (`0` selects auto). Each worker reserves a
  32 MiB native stack and may grow to the 256 MiB wasm memory limit.
- **Dispatch:** the pool keeps idle workers in a mutex-guarded stack with a
  condition variable. `evaluate` checks one out, sends the payload over a
  channel, waits for the decision and returns the worker. Contention beyond the
  pool size queues on the condition variable rather than blocking a Tokio
  worker inside Go.
- **Fail closed:** the guest runs under a wasmtime epoch deadline equal to
  `waf.coraza.eval_timeout_ms`; exceeding it traps and surfaces as
  `ReactorError::Timeout`. As a host-side backstop, `evaluate` also stops
  waiting `eval_timeout_ms + 5 s` after dispatch, discards the worker and
  returns an error instead of hanging. A worker that panics or exits drops its
  reply channel and is handled the same way. A replacement thread is started
  for the next job.
- **Idempotence:** `warm()` is serialised by a mutex and becomes a no-op after
  the pool exists. A failed warm-up leaves no pool installed, so start-up fails
  closed and a later call retries.

The historical spike modules without `_initialize` or `input_base` still work:
the host only calls them when exported and otherwise uses the fixed
`INPUT_BASE = 1024` offset.

### Capacity and admission control

A CRS body scan holds one reactor worker for the whole evaluation (about 3 s
for a 60 KiB form on the reference host), while a bodyless or gRPC/GraphQL
body-withheld request is ~2.5 ms. The pool is intentionally fixed; admission
control sits in front of it so expensive evaluations cannot occupy every
worker:

- **Classification.** After the gRPC/GraphQL pre-checks, a request is `heavy`
  when it still has a non-empty body and `cheap` otherwise. A body stripped by
  a pre-check is therefore cheap without a second parse. Classification is
  never used to skip or reduce inspection.
- **Heavy permits.** `waf.admission.heavy_permits` bounds concurrent body
  scans. `0` (default) resolves to about half the pool, capped at
  `pool_size - 1` (at least 1), so reactor workers remain available for cheap
  requests.
- **Bounded async queue.** When all heavy permits are held, a heavy request
  waits on a `tokio::sync::Semaphore` for at most
  `waf.admission.queue_timeout_ms` (default 250 ms). At most
  `waf.admission.max_queued` (default 64) requests may wait; `0` rejects
  immediately. Waiting never blocks a Tokio worker.
- **Fail closed.** A full queue or an expired wait returns `503` with
  `Retry-After: 1` and a reason naming admission control. It never returns
  `Allow`. Cheap requests bypass the heavy queue entirely.
- **Observability.** `waf_admission_queued_total`,
  `waf_admission_queue_depth`, `waf_admission_admitted_total`,
  `waf_admission_rejected_total{reason="queue_full|timeout"}`,
  `waf_admission_wait_duration_seconds` and
  `waf_admission_inflight{class="cheap|heavy"}` are exposed through
  `/metrics`. Prometheus alerts fire on sustained heavy rejections and a
  persistently non-empty queue.

Set `waf.admission.enabled = false` to restore the historical behaviour
(unbounded waiting on the reactor pool). The default is `true`.

### Payload

The default request envelope is a compact binary struct written directly into
the guest's static input buffer. It removes JSON parsing, base64 encoding and
the associated allocations from the per-request path. All integers are
little-endian:

```text
magic u32 = 0xCAFEBABE | version u16 = 1 | flags u16 (bit 0 = binary)
method_len u32 | uri_len u32 | http_version_len u32
body_len u32 | header_count u32 | remove_rule_count u32
method | uri | http_version | body (raw bytes)
header_count * (name_len u32 | name | value_len u32 | value)
remove_rule_count * u32
```

The body is raw bytes, so binary bodies (protobuf/gRPC, msgpack, compressed
payloads) are inspected without a base64 round trip. `remove_rule_count` is
bounded by 256 on both sides. The guest detects the envelope by the magic
number; anything else is parsed as the legacy JSON payload.

The legacy JSON envelope remains available behind `WAF_CORAZA_JSON_ABI=1`
(or `set_json_abi(Some(true))` in-process) for compatibility with older guest
modules and for A/B benchmarking:

```json
{
  "method": "POST",
  "uri": "/login?next=/home",
  "http_version": "1.1",
  "headers": [["content-type", "application/x-www-form-urlencoded"]],
  "body_size": 38,
  "body_encoding": "utf8",
  "body": "username=admin&password=not-a-real-password"
}
```

`body` is `null` when no body was captured. Header pairs are the host's
current form; the module also accepts a `{"name": "value"}` object for manual
testing.

gRPC requests are the exception: the protocol-aware pre-check in
`src/waf/grpc.rs` validates the frame envelope first and sets `body` to `null`
so CRS never scans protobuf bytes (header and URI rules still run). See
[`docs/grpc-inspection.md`](grpc-inspection.md).

`body_encoding` is a discriminator for the `body` string:

| Value | Meaning |
| --- | --- |
| `utf8` | `body` is the raw body and is valid UTF-8. This is the fast path. |
| `base64` | `body` is the raw body encoded with standard base64. |

The host chooses `base64` whenever the captured body is not valid UTF-8
(protobuf/gRPC frames, msgpack, compressed payloads), so invalid bytes are
never replaced with U+FFFD before inspection. The guest decodes base64 before
`WriteRequestBody`; if the encoding is unknown, the base64 is malformed, or the
decoded length disagrees with `body_size`, `eval` returns `-5`, which the host
surfaces as `ReactorError::InvalidBodyEncoding` (fail-closed `503` by default,
and the worker rebuilds its instance for the next request).

`body_size` is always the raw, unencoded byte length. Payloads that omit
`body_encoding` are treated as `utf8` for backwards compatibility.

Base64 costs four wire bytes per three raw bytes, so a 64 KiB payload budget
carries at most about 48 KiB of binary body once the JSON envelope and headers
are accounted for. The payload limit itself is unchanged
(`CORAZA_MAX_PAYLOAD_BYTES = 64 KiB`); `ReactorError::PayloadTooLarge` remains
the distinguishable error for exceeding it.

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
threshold. Phase-1 early blocking is **on** by default (see below).

`crs-setup.conf` is the upstream example configuration unmodified; the reactor
prepends the ModSecurity engine preamble (`SecRuleEngine On`,
`SecRequestBodyAccess On`, body limits, `SecResponseBodyAccess Off`).

The vendored `REQUEST-901-INITIALIZATION.conf` carries two documented patches
applied by `scripts/vendor-coraza-crs.sh`, so a regenerated bundle keeps them:
the gRPC media types added to `tx.allowed_request_content_type` (rule 920420),
and `tx.early_blocking=1` as the default (rule 901115). Both are recorded in
`rules/crs/PROVENANCE.md`.

### Early blocking (phase-1 anomaly evaluation)

The reactor enables CRS phase-1 early blocking (`tx.early_blocking=1`), the
same default as the native sidecar. When a request's phase-1 anomaly score
already reaches the blocking threshold (missing Host, scanner User-Agent,
protocol/header/cookie attack rules), CRS rule 949111 denies in phase 1 and the
request body is never scanned.

The patch flips the *default* in rule 901115 rather than uncommenting rule
900120 in `crs-setup.conf`. Rule 901115 only applies its default when
`tx.early_blocking` is unset, so the final value is deterministically `1`
regardless of rule order, while an explicit `0` from a caller still wins.
There is no runtime toggle: the rules are embedded in the module, so disabling
early blocking means rebuilding the module from the vendored tree with the
default restored (the vendor script is the single source of truth).

The block decision is unchanged: the phase-1 score is already over the
threshold, so the request would be denied in phase 2 as well. The documented
CRS tradeoff applies: phase-2 alerts for an already-blocked request are not
emitted, so the alert *set* for such a request is smaller. Benign traffic is
unaffected (no phase-1 score, so phase 2 still runs and the body is fully
scanned).

Measured on 2026-11-02 with a release build, a one-worker pre-warmed pool
pinned with `taskset -c 2`, and the old/new modules evaluated alternately in
one process (p50 of 5–9 evaluations). "Phase-1-blocked" is a scanner
User-Agent with a form body:

| Body | Before p50 | After p50 | Speedup |
| ---: | ---: | ---: | ---: |
| 1 KiB | 42–51 ms | 1.6–1.9 ms | ~27× |
| 8 KiB | 374–717 ms | 1.9 ms | 200–390× |
| 60 KiB | 3.2–7.6 s | 3.8 ms | 850–2 000× |

The development host throttles heavily, so the baseline for a given body size
varies by up to ~2.3× between runs; the post-change cost is flat because the
body is never scanned. Benign bodies are unchanged within that variance
(1 KiB p50 ≈ 41–43 ms on both modules; larger bodies remain dominated by the
full body scan). This also removes a timeout hazard: before the change a
60 KiB phase-1-blocked body could exceed the default 5 s `eval_timeout_ms` and
surface as a fail-closed `503`; it is now a `403` in a few milliseconds.

One observable ordering change: a malformed body (`body_encoding` error,
`body_size` mismatch) on a request that phase 1 already blocks now returns the
phase-1 `403` instead of `ReactorError::InvalidBodyEncoding`. The outcome is
still a deny; it is never an allow.

**Not included:** response inspection rules (`RESPONSE-950`–`980`), the
deployment-specific example exclusion files (`REQUEST-900`, `REQUEST-999`),
CRS plugins, and the upstream regression corpus. Response bodies are not
available over the current host ABI, so response rule coverage is explicitly
out of scope.

## Live WAF integration

The reactor is wired into the live rule chain only when the `wasm-reactor`
feature is compiled, `waf.coraza.enabled` is true **and**
`waf.coraza.backend = "wasm"` (or it is used as the `fallback = "wasm"`
engine). The feature and `enabled` are true by default, but the Rust engine is
the default backend. When selected, the reactor is registered **before** the
heuristic rules so a Coraza block wins even if a later rule would allow the
request.

```toml
[waf]
fail_mode = "closed"      # "open" logs request-time reactor failures and continues

[waf.coraza]
enabled = true            # default; set false to skip compilation/warm-up entirely
# module_path = "/etc/waf/coraza_reactor.wasm"  # omit to use the embedded reactor
max_payload_bytes = 65536
# Opt-in body-size policy. Defaults preserve full inspection.
# max_inspect_bytes = 0   # 0 = inspect the whole body (default)
# oversize_action = "inspect-all"  # "inspect-all" | "forward-uninspected" | "reject"
memory_limit_bytes = 268435456
eval_timeout_ms = 5000    # DoS bound per eval; init gets a fixed 60 s budget
pool_size = 0             # 0 = one worker per core, clamped to 1..=8
prefilter = "off"         # "off" | "dry-run" | "gated" (requires crs-prefilter)
```

### Per-rule CRS gating (`prefilter = "gated"`)

`gated` runs the host-side required-literal prefilter over the URI, query
string, header names/values, cookies and body, then removes only the gated CRS
rules whose proven mandatory literals are absent from every one of those
values. Ungated rules (`@detectSQLi`, `@detectXSS`, size/validation checks, the
obfuscation-tolerant 932 regexes) always run, so the decision is identical to
`off`; only evaluation work changes. The guest validates every id against the
embedded `rules/crs/prefilter.json` copy, so a forged payload cannot disable an
ungated or unknown rule.

The mode is opt-in and non-default because it requires the non-default
`crs-prefilter` feature. A build without the feature rejects the config at
validation time. `dry-run` measures the prefilter without sending removals.
On the stock CRS 4.14 bundle the host removes 57-58 of the 61 distinct gated
rules for benign requests; measured p50 improves by 1.3-1.6x (native sidecar).
See `docs/design/crs-prefilter.md` for the soundness argument
and measurements.

### Body-inspection size policy (opt-in)

CRS body inspection is byte-linear: on the WASI reactor a 1 KiB body costs
roughly 39 ms, 8 KiB roughly 350 ms and 60 KiB roughly 2.6 s. The native
sidecar is about 6x faster. Operators can bound that cost with
`max_inspect_bytes` and choose what happens above it with `oversize_action`.
The default (`max_inspect_bytes = 0`, `oversize_action = "inspect-all"`) is
unchanged: every body up to `max_payload_bytes` is fully inspected.

| `oversize_action` | Body above `max_inspect_bytes` | What is inspected | What is not |
| --- | --- | --- | --- |
| `inspect-all` (default) | Sent whole, up to `max_payload_bytes` | URI, headers, full body | Nothing within the cap; bodies above the cap fail closed with `503` |
| `forward-uninspected` | First `max_inspect_bytes` bytes sent as `body`; `body_size` is the prefix length and `body_original_size` keeps the full length | URI, headers, body prefix | **All body bytes after the prefix.** An attack placed only after the prefix is forwarded upstream |
| `reject` | Rejected before evaluation | URI and headers are not evaluated either; the request returns `413` | The whole request |

`forward-uninspected` is an explicit, documented inspection gap. It is useful
for large uploads or form posts where the first N bytes carry the meaningful
parameters, but it must not be used where an attacker can move a payload past
the prefix. `reject` is the fail-closed choice for endpoints that should never
receive large bodies. `max_inspect_bytes` must be non-zero and no larger than
`max_payload_bytes`; an unknown `oversize_action` is rejected at config load.

Sizing guidance: start from the largest legitimate body that must be fully
inspected. A 1 KiB prefix keeps the WASI cost near 40 ms per body; 8 KiB is
near 350 ms. Prefer `reject` for JSON/API endpoints with a known small body
limit, and `forward-uninspected` only for upload paths whose security does not
depend on the tail. The native sidecar can afford a larger prefix for the same
latency budget. Start-up logs a warning whenever `oversize_action` is not
`inspect-all`.

`module_path` is optional: when omitted the Coraza module is embedded in the
WAF binary. `Config::validate` rejects zero payload/timeout values, a memory
limit below 64 KiB, a payload limit larger than the memory limit, a
`max_inspect_bytes` larger than `max_payload_bytes`, an empty module path, and
a `pool_size` above 8. An unknown `oversize_action` fails TOML deserialisation.

`eval_timeout_ms` is a wall-clock denial-of-service bound, not a latency
target. It is generous because CRS body inspection is byte-linear and a 60 KiB
body can legitimately take seconds on modest hardware. Exceeding it traps the
guest through wasmtime epoch interruption (checked every 10 ms), discards the
instance, and follows the failure policy below. Go `_initialize` and Coraza
`init` use a separate fixed 60 s budget so slow start-up is never mistaken for
an attack.

If the reactor cannot be constructed at start-up, the engine adds a
fail-closed placeholder rule when `waf.fail_mode != "open"`; the placeholder
returns `503`. In `open` mode the failure is logged and the request continues
through the remaining rules. At request time any reactor error (trap, epoch
timeout, payload overflow) follows the same policy: `503` when closed,
log-and-allow when open.

## Memory and limits

Host-side limits for the Coraza reactor (`ReactorLimits::coraza`):

| Limit | Value | Enforcement |
| --- | --- | --- |
| `max_payload_bytes` | 64 KiB | Host rejects larger payloads; matches the module's static buffer. |
| `memory_limit_bytes` | 256 MiB | wasmtime `StoreLimits` with `trap_on_grow_failure`; Go starts near 10 MiB and grows. |
| `eval_timeout_ms` | 5,000 ms | wasmtime epoch deadline per `eval`; a ticker advances the epoch every 10 ms. Exceeding it traps as `ReactorError::Timeout`. |
| init timeout | 60 s (fixed) | Larger epoch deadline for `_initialize` + `init`, so slow Go/CRS start-up is not treated as an attack. |
| `max_wasm_stack` | 8 MiB | Bounds native stack used by compiled wasm frames; traps instead of overflowing the host thread. |
| `async_stack_size` | 8 MiB | Must be at least `max_wasm_stack`; required by wasmtime even for sync calls. |
| `pool_size` | cores clamped to `1..=8` (`0` = auto) | Number of pre-warmed reactor instances, one dedicated OS thread each. Each reserves a 32 MiB native stack. |

Module-side constants: `maxInputBytes = 64 * 1024`. The input buffer is a Go
global; `input_base` exposes its address so the host never writes over Go
runtime data at a fixed low offset.

Because Go's wasm linear memory only grows, `waf.coraza.memory_limit_bytes`
(256 MiB) is a trap ceiling, not a residency target. Size the pool from the
measured plateau instead of from that ceiling:

```text
budget MiB ≈ 370 (host: wasmtime engine, module, thread stacks, channels)
           + pool_size × 80 (guest linear memory per worker at the 64 MiB GC bound)
```

A conservative planning rule is one worker per 96 MiB of available memory
after reserving ~384 MiB for the host: `pool_size ≈ (available_MiB - 384) / 96`,
clamped to `1..=8`. For example 1 GiB available supports 6 workers, 512 MiB
supports 1, and 2 GiB or more supports the 8-worker cap. Keep each worker's
`memory_limit_bytes` at or above ~96 MiB so the Go runtime has room for
non-heap linear memory (`waf.coraza.memory_limit_bytes` below ~96 MiB is not a
supported sizing).

### Guest GC tuning and measured memory plateau

At startup the reactor calls `debug.SetGCPercent(600)` and
`debug.SetMemoryLimit(64 MiB)` in `wasm/coraza_reactor/main.go`. With the Go
default (`GOGC=100`) a collection lands every ~10 MiB of allocation; CRS
evaluation allocates ~0.5–1 MiB per 8 KiB body, so early requests can pay a
collection mid-evaluation and roughly double that request's latency. The 600 %
growth target amortises collections across requests, while the 64 MiB soft
limit bounds the retained heap before linear memory grows without bound.

The limit matters because wasm memory cannot be returned to the OS. Measured
with `memory-soak` (6 workers, 6 client threads, 90 s, mixed bodyless/1 KiB/
8 KiB plus a 60 KiB body every 20 s) on the reference 6-core laptop:

| `SetMemoryLimit` | peak RSS | linear memory | p50 bodyless / 1 KiB / 8 KiB / 60 KiB |
| ---: | ---: | ---: | --- |
| 64 MiB | 797–842 MiB | 456–528 MiB | 3.0 / 49.5 / 440 / 3 390 ms (GC 600) |
| 128 MiB | 1 029–1 191 MiB | 720–888 MiB | 3.8–4.8 / 90–95 / 610–1 190 / 3 510–10 100 ms |
| 192 MiB | 1 084–1 404 MiB | 784–1 116 MiB | 2.8–3.6 / 47–89 / 420–610 / 3 510–4 130 ms |

A 10-minute soak at the chosen GC 600 / 64 MiB setting held **837.6 MiB peak
RSS** and **480 MiB linear memory** across 24 112 evaluations; after the
midpoint growth was 0.0 %, so this is a plateau rather than a slow leak. The
same 6-worker pool with the previous 192 MiB limit was still climbing at
1.4 GiB. At the 64 MiB bound, GC 200/400/600 all plateaued; 600 kept the
lowest 8 KiB/60 KiB p50 and is retained.

Pool-size scaling at GC 600 / 64 MiB (same 90 s workload) is linear, with a
fixed ~370 MiB host cost:

| `pool_size` | baseline RSS | 90 s RSS | linear memory |
| ---: | ---: | ---: | ---: |
| 1 | 435 MiB | 445 MiB | 80 MiB |
| 2 | 492 MiB | 512 MiB | 160 MiB |
| 4 | 619 MiB | 661 MiB | 320 MiB |
| 6 | 759 MiB | 819 MiB | 480 MiB |

Calling `debug.FreeOSMemory()` every 256 evaluations was also measured: it
produced the same 815 MiB plateau and indistinguishable p50 (per-evaluation
counter plus forced collection), because wasm linear memory cannot shrink.
It is not enabled. A worker could be recycled to bound a pathological workload,
but dropping and re-running Go/CRS init costs about a second per worker, and
the 64 MiB GC bound already plateaus on the mixed workload tested here.

The tradeoff of the tighter limit is slightly higher GC frequency; measured
p50 for bodyless, 1 KiB and 8 KiB traffic stayed at or below the 192 MiB
setting, so no latency regression was observed. The size-dependent cost is
still dominated by CRS scanning, not collection. The 8–16 KiB GC tail
described in earlier measurements was the reason for 600 %; that remains.

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
| `waf_coraza_body_truncated_total` | counter | Bodies truncated to `max_inspect_bytes` by `forward-uninspected` |
| `waf_coraza_body_rejected_total` | counter | Bodies rejected with `413` by the `reject` policy before evaluation |
| `waf_coraza_body_inspected_bytes` | histogram | Body bytes actually handed to Coraza per evaluation |
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
allow/block/allow/XSS decisions repeatedly on one reactor to prove a warmed
instance does not carry state between evaluations, and
`coraza_reactor_isolated_per_thread` runs the same `Arc<WasmReactor>` on three
threads to prove concurrent dispatch is safe.

Fast tests cover the pool itself: `warm_prepares_pool_and_keeps_decisions_correct`
warms twice and checks allow/block/allow, `warm_fails_closed_when_a_worker_cannot_init`
asserts a failed worker aborts warm-up, `concurrent_evaluations_return_correct_decisions`
runs eight threads against a two-worker pool, and
`worker_trap_discards_instance_without_hanging_or_corrupting` interleaves
trapping and clean payloads to prove a failed instance is rebuilt and later
evaluations stay correct, and
`evaluation_timeout_discards_instance_and_next_evaluation_recovers` does the
same for an evaluation that exceeds `eval_timeout_ms` and must surface as
`ReactorError::Timeout`.

The tests are ignored in debug builds because Go runtime start-up and CRS
compilation are slow without optimisation. Release builds pass:
`cargo test --release --lib --features wasm-reactor -- --ignored` runs all five
Coraza tests.

## Memory soak

`memory-soak` (`src/bin/memory_soak.rs`) drives a warm pool directly with the
mixed workload described above and samples `/proc/self/status` RSS plus the
reactor's published linear-memory total once per second. It fails when RSS
exceeds `--max-rss-mib`, when RSS after the midpoint grows more than
`--max-growth-pct`, or when any evaluation errors. Defaults are 5 minutes,
6 workers and the automatic pool ceiling; use `--duration-secs 1800` for a
30-minute run and `--module <path>` to test a candidate build. A zero
`--max-rss-mib` (the default) selects the documented `370 + 96 × pool_size`
MiB ceiling.

```sh
nix develop -c cargo build --release --features wasm-reactor --bin memory-soak
./target/release/memory-soak --duration-secs 600 --pool-size 6 \
  --concurrency 6 --large-body-interval-secs 30 \
  --max-rss-mib 1024 --max-growth-pct 5 \
  --output /tmp/opencode/coraza-soak.csv
```

For the 6-worker pool on the reference host the operational gate is **peak
RSS < 1024 MiB and < 5 % growth after the midpoint**. The chosen GC 600 /
64 MiB module measured 838 MiB peak after 10 minutes. Scale the ceiling with
the pool: `370 + 96 × pool_size` MiB is a conservative cap (1/2/4/6/8 workers
→ 466/562/754/946/1138 MiB). Also run the end-to-end `load-validate` matrix,
whose `rss-peak` and `rss-growth` gates cover host and proxy buffers.

## Benchmarks

### Binary ABI vs JSON and pre-warm (measured)

`src/bin/coraza_abi_bench.rs` compares the two envelopes and a cold pool
against a pre-warmed pool on the same host:

```sh
CORAZA_BENCH_REPS=120 \
  nix develop -c cargo run --release --bin coraza_abi_bench --features wasm-reactor
```

Reference host, 2-worker pool, p50/p99 in ms:

| case | binary warm | JSON warm | binary cold first call |
| --- | --- | --- | --- |
| allow | 3.18 / 3.99 | 3.17 / 3.76 | 1677 ms |
| SQLi | 4.16 / 8.94 | 4.17 / 7.80 | 6.6 ms |
| 4 KiB body | 397 / 502 | 392 / 546 | 185 ms |

The binary envelope is neutral on p50 because CRS evaluation dominates the
request (roughly 95 % of the time); it removes JSON/base64 work and improves
the 4 KiB body p99 (502 vs 546 ms). The absolute p50 is about 2.6× below the
historical 8.4 ms allow / 10.6 ms SQLi baseline on this host, but that gain is
host/toolchain, not the envelope alone. Pre-warming is the large win: the first
allow request drops from ~1.3–1.7 s (Go runtime + CRS compilation) to ~3.7 ms
once `warm_workers(n)` has completed.

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
  pre-compiled, warmed reactor (dispatch plus `eval`; no initialisation);
- `reactor_body/allow_body/{1kb,16kb,64kb}`: clean POST bodies of 1 KiB and
  16 KiB, plus the largest body that fits the ABI's fixed 64 KiB payload
  buffer (`64kb` row, about 65.4 KB after the JSON envelope). A literal 64 KiB
  body cannot be represented because the JSON envelope would exceed
  `CORAZA_MAX_PAYLOAD_BYTES`.

Recorded on 2026-11-01 in the Nix development shell, after the reactor moved to
wasmtime; dispatch now goes through the pre-warmed pool, which adds ~15 µs per
evaluation to these figures:

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
| body sizes (warm) | see request-body table below | — | — |

wasmtime is **5–8× faster than wasmi with the CRS module** (wasmi/CRS measured
40.4 ms allow and 75.3 ms SQLi). It is still not sub-millisecond: the Go/Coraza
transaction and full-payload JSON decoding dominate. The compiled module is
created once per process and shared across threads; each pool worker pays Go
`_initialize`/CRS `init` during `warm()` (about 0.6 s per worker, run in
parallel), so start-up pays the cost and requests do not.

### Observed latency

`measure_coraza_reactor_latency` warms a two-worker pool, then reports load,
warm-up, the first post-warm evaluation and steady state without a brittle
assertion. Two runs on the development machine in release mode:

| Measurement | Run 1 (cold page cache) | Run 2 (warm page cache) |
| --- | ---: | ---: |
| Module compile/load (Cranelift) | 46.9 s | 10.4 s |
| `warm()` for 2 workers (Go `_initialize` + CRS `init`) | 3.62 s | 1.14 s |
| First evaluation after warm | 23.0 ms | 3.3 ms |
| Steady-state evaluation, CRS allow (avg of 5) | 7.38 ms | 2.72 ms |
| Pool dispatch overhead (trivial reactor, 10k avg) | — | 15 µs |

The previous first-request path paid Go/CRS initialisation inside the request
(~0.49 s on a warm page cache). After pre-warming, the first request only pays
the normal `eval` cost; observed first-evaluation overhead over steady state
ranged from ~0.5 ms to ~16 ms across runs, depending on allocator/page-cache
warm-up inside the worker. The pool hand-off itself adds ~15 µs per evaluation,
well under the 1 ms budget. Warm-up itself is a start-up cost: with the default
pool size it runs one Go/CRS init per core (at most eight), in parallel. Treat
these numbers as an order of magnitude, not a service-level guarantee.

### Request-body latency after wasm tuning

Epoch interruption and guest GC tuning were measured on 2026-11-01 with a
release build (`cargo build --release`), a one-worker pre-warmed pool pinned
with `taskset -c 2`, and form-urlencoded `data=AAA…` bodies. Each row is seven
evaluations after one warm-up; p50 and mean are milliseconds. The module was
the rebuilt 20 MiB reactor with `SetGCPercent(600)` and the then-current
192 MiB soft memory limit (later reduced to 64 MiB to bound RSS, see the
memory section above).

| Body | Payload bytes | Before p50 | Before mean | After p50 | After mean |
| --- | ---: | ---: | ---: | ---: | ---: |
| none (GET) | 173 | 2.2 | 2.2 | 2.3 | 2.3 |
| 1 KiB | 1,283 | 38.6 | 38.7 | 39.1 | 39.3 |
| 4 KiB | 4,355 | 163.8 | 163.7 | 167.5 | 169.3 |
| 8 KiB | 8,451 | 832.6 | 804.2 | 351.4 | 353.6 |
| 16 KiB | 16,645 | 1,754.4 | 1,677.9 | 707.1 | 708.2 |
| 60 KiB | 61,701 | 2,624.5 | 2,689.4 | 2,650.2 | 2,652.1 |

The 8–16 KiB improvement is the GC tail disappearing: before tuning the same
8 KiB workload alternated between a ~347 ms steady state and ~830 ms p50 when a
collection landed mid-request. Body cost remains linear in inspected bytes and
is dominated by Go→wasm CRS operator scanning, so 60 KiB is still ~2.6 s on
this hardware; a 60 KiB request can approach the default 5 s
`eval_timeout_ms` when the laptop is throttled to 1.7 GHz.

The development laptop throttles between 1.7 and 3.3 GHz, so the same workload
varies by up to ~2.6× between runs. For example a 4 KiB body measured 164 ms in
one run and 375 ms in another. A/B runs were therefore interleaved and pinned;
treat these numbers as relative guidance, not an SLO. On the same machine a
forced `eval_timeout_ms = 20` made an 8 KiB evaluation return
`ReactorError::Timeout` in 19 ms; the next (fast) evaluation succeeded on a
freshly created instance, and the rule maps the timeout to `503` when
`fail_mode = "closed"`.

### Runtime and module tuning (measured)

A second tuning pass on 2026-11-02 re-measured the wasmtime `Config`, the
compiled module and the pool against the same form-body workload. The headline
result is that **no runtime or module knob moved steady-state cost**: the body
cost is inherent Go→wasm CRS scanning, not a tuning artefact. The measurements
are recorded here so the options are not re-litigated.

Method: release build, one pre-warmed worker, `data=AAA…` bodies, variants
interleaved round-robin on a shared host. Because wall-clock time was dominated
by preemption, the comparison used per-`eval` **thread CPU time** (measured
around the guest call) as well as wall p50; both agreed. A 4 KiB body was
169–170 ms p50 for every variant below (1 KiB 39.7 ms, 8 KiB 353 ms, 16 KiB
727 ms, 60 KiB 2.74 s), matching the table above.

| Experiment | Result | Kept |
| --- | --- | --- |
| `wasm-opt -O3` module (20,112,739 → 18,975,699 bytes) | 0% (±2%) on 1/4/8/16/60 KiB | No |
| `wasm-opt -Oz` module (18,087,425 bytes) | 0% vs `-O3` on every size | No |
| `memory_may_move(false)` (static memory base) | 0% | No |
| `native_unwind_info(false)` | 0% | No |
| `cranelift_regalloc_algorithm(SinglePass)` (control) | 1.17–1.85× **slower** | No |
| `wasm_backtrace_max_frames(None)` + no debug info | no steady-state change; less work per trap | Yes |
| `cranelift_debug_verifier`, `nan_canonicalization`, `memory_init_cow` | already the release defaults | n/a |
| `pooling_allocator` | not applicable: needs the non-enabled `pooling-allocator` feature and forbids memory growth; the pre-warmed pool already removes per-request instantiation | No |
| `async_stack_size` / `max_wasm_stack` | address-space reservation only; 8 MiB is the validated Go start-up requirement | unchanged |

The SinglePass control is the important row: it changes codegen quality and
costs 1.17–1.85×, so the method can see codegen effects. `-O3` therefore
genuinely adds nothing on top of Cranelift's own optimiser for this workload —
the module only gets 5.6% smaller. Disabling backtraces is kept because every
fail-closed timeout (an attacker-influenced path) otherwise walks frames and
retains guest debug info; it does not change steady-state latency.

**Precompiled modules.** Serialising the compiled module with
`Engine::precompile_module` and reloading it with `Module::deserialize_file`
cuts module compile plus pool warm-up from ~5.6 s to ~1.3 s (cache-hit runs
measured 1.26 s and 1.68 s on a loaded host). It is not shipped: the artifact
is ~40 MB, is tied to the exact wasmtime version, CPU and host configuration,
and `deserialize_file` is `unsafe`, so a writable cache path would be a
code-execution boundary. A deployment that wants the ~4 s of start-up back
should generate the cache at install time under a root-owned path.

**Pool memory.** Peak RSS grows by ~65 MiB per pre-warmed worker: 434 MiB at
`pool_size = 1`, 501 MiB at 2, 626 MiB at 4 and 756 MiB at 6 on the reference
laptop (the first worker includes the ~20 MiB module plus its compiled code).
The default (one worker per core, at most 8) therefore costs roughly
`cores × 65 MiB` on top of that shared footprint. Body scans are CPU-bound and
admission control already caps concurrent heavy scans, so an explicit smaller
`pool_size` trades throughput for memory roughly linearly; the default is
unchanged because lowering it would cut cheap (bodyless) throughput without a
measured memory-pressure signal.

## Remaining work

- **Response coverage:** enable `SecResponseBodyAccess` and the
  `RESPONSE-950`–`980` files once the ABI carries response bodies.
- **CRS tuning:** add deployment-specific exclusions (`REQUEST-900` /
  `REQUEST-999`) and raise the paranoia level only with application-specific
  false-positive testing.
- **Performance:** wasmtime's compiled execution did not remove the dominant
  cost: CRS operators scan the whole body byte-for-byte and Go→wasm adds a
  ~5× constant factor. Epoch interruption and GC tuning help the tail, but an
  8 KiB body still costs ~350 ms and 60 KiB ~2.6 s on the reference laptop.
  Runtime and module tuning (`wasm-opt`, memory style, unwind info, stack
  sizing, allocator) was measured and does not move steady-state cost; see
  [Runtime and module tuning](#runtime-and-module-tuning-measured).
  Sub-second large-body inspection needs a body-size policy or native Coraza,
  not a faster runtime.
- **Tokio interaction:** wasmtime-wasi's sync preview1 adapters cannot run
  inside the proxy's Tokio workers, hence the shadowed stdio/path imports. If
  a future wasmtime-wasi release offers a runtime-free sync surface, the shims
  can be removed.
- **Native stack:** the 8 MiB wasm stack is validated by the release test
  suite. Pool threads are created by the host with an explicit 32 MiB native
  stack, so initialisation no longer depends on the stack size of the calling
  Tokio worker.
- **Module size:** `wasm-opt -O3` (−5.6%) and `-Oz` (−10%) were measured as
  size levers: both produce valid modules with identical decisions and no
  latency change, so neither is wired into the build. Splitting unused Coraza
  features or a lighter CRS profile remains the way to shrink the 20 MiB
  artifact.
- **Availability:** `wasm-reactor` is default-on, but the Rust engine is the
  default request backend. When `backend = "wasm"` is selected, watch the
  ~4.5 s compile + ~1.1 s pool warm at start-up and the body-size-dependent
  per-request cost (4.47 ms bodyless, 169.56 ms at 4 KiB, 354.09 ms at 8 KiB on
  the reference host); provide a
  lighter CRS profile or a body-size policy if that is too expensive for edge
  deployments.
- **Body fidelity:** binary bodies are now carried losslessly as base64 in the
  ABI; the remaining gap is response-body inspection (the reactor still only
  sees request bodies) and the ~33 % wire overhead for binary payloads.
