# QuicCrunch Evaluation

**Subject:** [`shift/quiccrunch`](https://github.com/shift/quiccrunch) at `4ee1ec4` ("Clean up repo for open-source release", 2026-08-06)
**Question:** Can QuicCrunch replace tonic on the DistriWaf control plane?
**Verdict:** **Reject** as a transport replacement. Individual ideas (SO_REUSEPORT worker model) are worth borrowing; the code is not.
**Evaluated:** 2026-11-09, Rust 1.89.0 (nix devShell), Linux 6.18.36, Intel i5-8400T (6C/6T, 1.7 GHz base), governor `performance`.

---

## 1. Executive summary

| Area | Result |
| --- | --- |
| Workspace build | `cargo check --workspace` **fails** in `quiccrunch-ffi` (E0432) |
| Workspace tests | `cargo test --workspace` **does not compile** (`quiccrunch-core` lib test, E0063 ×2) |
| Four-worker throughput | **19.8k msg/s median** (5,083–26,472 across 5 runs) vs README **31,629** |
| One-worker throughput | **4.8k msg/s median** (3,710–6,085), 32–64 stream timeouts per run |
| Real p99 RTT (1 in-flight/conn, 16 conn, 1 KiB) | **4.5 ms @ 1 worker, 35–36 ms @ 4 workers** vs README **194 µs / 32 µs** |
| README latency metric | Not a percentile: `p99 == 1 / throughput` exactly (see §4.3). The benchmark never measures per-request latency |
| TLS client authentication | **Absent by default.** No `set_verify(true)`, no CA load; `verify_cert`/`ca_cert_file` are dead fields |
| Auth / RBAC / rate limiting / metrics | Implemented as standalone structs, **never wired into `RpcServer`**; JWTs cannot cross the wire (metadata is never serialised) |
| Dependency audit | **12 vulnerabilities** (incl. `rustls 0.21.12`, `rustls-webpki 0.101.7`, `capnp 0.23.0`, `bytes 1.10.1`) + 19 warnings |
| Fit for DistriWaf | No mTLS/SPIFFE, no watch resume, no backpressure, no reconnect/discovery, no schema contract negotiation |
| Estimated parity effort | **10–16 engineer-weeks** and a rewritten security layer; residual risk remains high |

The project is a benchmark harness whose README describes a product. The benchmark path is a raw
length-prefixed echo server; the RPC/Cap'n Proto/auth/metrics paths are separate, mostly unwired code.

---

## 2. Repository state

- Workspace members: `quiccrunch-core`, `quiccrunch-macros`, `quiccrunch-cli`, `quiccrunch-ffi`.
- `quiccrunch-security/` exists on disk but is **not a workspace member**, so it is never built
  (its `rustls 0.22` would also conflict with core's `rustls 0.21`). `bindings/python` and
  `tquic_example` are likewise outside the workspace.
- Core dependencies of note: `tquic 1.6.0` (BoringSSL), `capnp 0.23`, `rustls 0.21`, `jsonwebtoken 9.3`.
- ~29k lines of Rust across 139 files and 182 `#[test]`/`#[tokio::test]` functions.
- `.cargo/config.toml` forces `target-cpu=native -C target-feature=+avx2,+fma,+sse4.2`, so release
  artefacts are not portable across x86-64 hosts.
- CI declares `RUSTFLAGS=-Dwarnings`. The tree emits **48 warnings from `quiccrunch-core` alone**,
  so CI cannot be green at this commit even after the FFI break is fixed.

### 2.1 Modules disabled in `lib.rs`

`client`, `server`, `connection_pool`, `crypto_accel`, `congestion`, `metrics`, `power`,
`test_utils`, and `rpc::discovery` are commented out. That removes the high-level client/server API,
hardware-crypto acceleration (the README's "AES-NI/AVX/SHA-NI auto detection"), the connection pool,
and service discovery from the compiled library. Several are still imported by tests and by
`quiccrunch-ffi`, which is why the workspace does not build.

---

## 3. Build and test results

All commands run with `CARGO_TARGET_DIR=/run/media/shift/.../code/.cargo-target-quiccrunch`
(external to the repo; the previous run exhausted the root filesystem).

### 3.1 `cargo check --workspace`

```
error[E0432]: unresolved imports `quiccrunch_core::QuicClient`, `quiccrunch_core::QuicConnection`
 --> quiccrunch-ffi/src/client.rs:5:23
error[E0432]: unresolved imports `quiccrunch_core::QuicServer`, `QuicListener`,
               `MessageHandler`, `EchoHandler`
 --> quiccrunch-ffi/src/server.rs:4:9
error: could not compile `quiccrunch-ffi` (lib) due to 2 previous errors
```

`quiccrunch-core`, all its binaries (including `multi_worker_server`, `pipelined_benchmark`) and
`quiccrunch-cli` **do** compile — with 48 warnings in core and 1–4 per binary.

### 3.2 `cargo check --workspace --all-targets` / `cargo test --workspace`

Additionally fails on the core lib-test:

```
error[E0063]: missing fields `ca_cert_file` and `verify_cert` in initializer of
               `messages::WorkerConfig`   (src/transport/test_worker_pool.rs:18)
error[E0063]: missing field `connection_id` in initializer of
               `messages::TquicCommand`   (src/transport/test_worker_pool.rs:59)
error: could not compile `quiccrunch-core` (lib test) due to 2 previous errors
```

Consequences:

- **No test in `quiccrunch-core` can run.** Unit tests, integration tests and BDD suites are all
  unreachable because the lib-test target does not compile.
- `cargo test -p quiccrunch-macros` passes: 1 integration test + 2 doctests, 0 unit tests.
- Many integration tests are additionally stale: e.g. `tests/rpc_tests.rs` imports
  `rpc::discovery` (disabled module) and implements `RpcService::{name, call_method, methods}`,
  none of which exist on the current trait. `tests/certs.rs`, `interop.rs`,
  `integration_transport.rs` contain zero test functions.
- The project ships **no fuzzing target** (`cargo-fuzz` absent; only one `proptest` covers a
  Cap'n Proto frame length round-trip).

Net: the advertised 30k msg/s framework has **no compiling test suite**.

---

## 4. Real API map and measured behaviour

### 4.1 Server / client

- Runnable binaries are **raw echo servers**, not RPC servers:
  - `bin/multi_worker_server.rs`: N OS threads, one `TquicRuntime` each, `SO_REUSEPORT` UDP
    socket, accepts streams, parses `u32` big-endian length prefixes, echoes bytes.
  - `bin/server.rs`, `bin/mt_server.rs`, `bin/quic_server.rs`: same idea, single/multi-worker.
  - **No binary registers or serves an `RpcServer`.**
- `QuicServer`/`QuicClient` (the ergonomic API in `src/server.rs` / `src/client.rs`) are commented
  out of `lib.rs`. Their test-cert helper is a stub:
  `generate_self_signed_cert()` returns `TlsConfig::default()`; `generate_node_cert()` also returns
  the default. Using them would not produce a certificate at all.
- `RpcClient` is bound to a single `QuicStream` (not a connection) and serialises one request at a
  time on that stream; callers must build their own pool (`RpcConnectionPool` is a `Vec<QuicStream>`
  round-robin with no health checks, reconnect, or in-flight limits).

### 4.2 Service registration

- `RpcServer::register_service(name: String, Arc<dyn RpcService>)` — a `HashMap<String, Arc<dyn …>>`
  behind a `tokio::RwLock`; dispatch is by service and method **string** on every call.
- There are **two incompatible `RpcService` traits and two `RpcContext` types**:
  `rpc::RpcService { call(&self, &RpcContext, &str, Bytes) }` is the one used by `RpcServer`;
  `rpc::service::RpcService { definition(), call(RpcContext, MethodId, Bytes) }` is used by the
  unused `ServiceRegistry`/reflection path. The public re-export points at the former.
- The `#[rpc_service]` macro is scaffolding: it generates a handler wrapper and an **empty client
  struct with no methods** (`// TODO: Add RPC client field once core integration is ready`).
  The README/Rustdoc examples (`CalculatorClient::new(client).add(5, 3)`) do not exist.
- Reflection (`rpc::reflection`) is implemented but not attached to `RpcServer`.

### 4.3 Cap'n Proto and the benchmark's latency claim

- The real RPC path uses `capnp` with `schema/rpc.capnp`: `RpcMessage` union, `RpcRequest`,
  `RpcResponse`, `RpcStreamChunk/End/Error`, `ErrorCode`, `KeyValue` metadata, `StreamingType`.
  This part is genuine and is the strongest technical piece in the repo.
- `rpc/message.rs` is dead legacy code that hand-rolls a binary header and *claims* to be Cap'n
  Proto ("For now, we'll use a simple binary format as a placeholder"); it is not referenced by
  `rpc.rs`.
- **The benchmark does not use Cap'n Proto.** `multi_worker_server` and `pipelined_benchmark` use a
  4-byte length prefix + repeated `b'x'` payload. There is no serialisation, no service dispatch,
  no auth, no metrics, no rate limiting on the measured path.
- The benchmark reports `Avg latency: duration / messages_sent`. There is **no timestamping and no
  percentile bucket anywhere**. The README table is therefore arithmetically derived:

  | README | implied throughput | reciprocal |
  | --- | --- | --- |
  | 5,000 msg/s, p99 194 µs | 1 / 194 µs = 5,154 msg/s | ✔ |
  | 31,629 msg/s, p99 32 µs | 1 / 32 µs = 31,250 msg/s | ✔ |

  `p99` is `1/throughput` rounded. It is not a measured tail latency.
- The benchmark counts **messages sent**, not completed. In one 1-worker run each connection logged
  `sent=1800, received=59` (and similar), yet the tool still printed a 5,088 msg/s throughput figure;
  throughput is therefore overstated whenever streams stall, and the "Errors: 64" line is the only
  hint that completions were lost.

### 4.4 Benchmark results (this hardware)

Command (as published in README):
`pipelined_benchmark <addr> 1800 1800 16 1024 4` → 28,800 × 1 KiB messages, 16 connections,
4 streams/connection, pipeline depth 1800, client and server on the same host over loopback.

| Workers | Runs (msg/s) | Median | Best | README | Errors |
| --- | --- | --- | --- | --- | --- |
| 1 | 4,773 / 5,088 / 3,710 | **4,773** | 5,088 | 5,000 | 64 / 64 / 32 |
| 4 | 19,782 / 15,631 / 5,083 / 19,773 / 26,472 | **19,773** | 26,472 | 31,629 | 0 / 0 / 3 / 0 / 0 |

- One worker roughly matches the README (4.8k vs 5k) but is unreliable: in two of three runs **all
  64 streams (16 conn × 4) hit the 5 s receive timeout** (the third lost 32), and at pipeline depth
  10 the same workload collapses to 417 msg/s.
- Four workers reach 19.8k median, **~37 % below** the claimed 31.6k, with one run collapsing to
  5.1k. Some of the gap is hardware (6 low-power cores, co-located client), but the variance and
   the 1-worker stalls are correctness problems, not tuning.
- `Avg latency` tracks `1/throughput` to the microsecond (e.g. 1/21,735 = 46.0 µs reported as
  "46.01 µs"), confirming §4.3.

#### Real per-request latency

Because the shipped tool cannot produce percentiles, an out-of-tree probe (`latency_probe`, one
in-flight request per connection, 16 connections, 500 × 1 KiB requests, 8,000 samples) was used:

| Workers | p50 | p90 | p99 | p99.9 | max | req/s |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | 2,166 µs | 2,297 µs | **4,463 µs** | 57,131 µs | 57,626 µs | 4,341 |
| 4 | 2,175 µs | — | **35,260–36,216 µs** | 59,272 µs | — | 3,916 |

Against the README's 194 µs / 32 µs, real p99 is **23× / 1,100× higher**. The ~2 ms p50 floor is
inherent to the runtime's channel/event-loop design, and the 4-worker p99 is ~35 ms.

### 4.5 Multi-worker

Genuine: each worker owns a UDP socket created with `socket2` + `set_reuse_port(true)` and its own
`TquicRuntime` thread with a `mio::Poll` loop, so the kernel spreads 4-tuples across workers. This
is the one design element worth reusing. Caveats:

- `TquicRuntime::new` hard-codes `worker_id: 0` in `WorkerConfig`; logging/metrics cannot attribute
  work to a worker.
- The runtime thread `expect()`s on adapter creation, so a bad cert path panics a worker thread.
- There is no worker health reporting, no graceful drain, no per-worker metrics, and no wakeup
  batching: the poll timeout is 0 and the loop busy-polls, with a 1 ms condvar sleep only when idle.

### 4.6 TLS / certificate handling

- QUIC + TLS 1.3 via BoringSSL (`tquic`), ALPN `h3` / `http/0.9`. Server requires `cert_file` and
  `key_file`; that part works.
- **Client verification is not enabled.** `TlsConfig::new_client_config(...)` in tquic 1.6 sets ALPN
  and early data only; BoringSSL's default verify mode is `SSL_VERIFY_NONE`. QuicCrunch never calls
  `set_verify(true)` or `load_verify_locations`. `WorkerConfig.verify_cert` and `ca_cert_file` are
  populated but **never read** (`grep set_verify|verify_cert` finds only struct fields/initialisers).
  Any server certificate is accepted → trivial MITM on an otherwise encrypted channel.
- Server name for the handshake is the **IP literal** (`server_addr.ip().to_string()`), not a DNS
  name; SPIFFE/DNS SAN verification is impossible without changes.
- **No mTLS**: no client certificate/key API on the client side, no client-auth configuration on the
  server side. SPIFFE IDs (the DistriWaf requirement) have no representation.
- `production::CertificateRotator` exists but is not connected to any transport. The
  `TlsConfig` helper in `test_utils/certs.rs` is a stub.

### 4.7 Authn/authz, rate limiting, metrics

- **JWT auth** (`AuthInterceptor`, HS256/RS256, roles, permissions, per-method requirements) and
  **RBAC** structures exist in `quiccrunch-core/src/interceptor/auth.rs`.
- **They are not wired in.** `RpcServer` has no interceptor field or chain; `InterceptorChain` is
  constructed nowhere outside docs/tests. There is no way for the server to require auth.
- **Tokens cannot cross the wire.** `create_streaming_request` writes service/method/parameters/
  streaming type but **never writes `context.metadata`**, and `parse_request` never reads it. The
  schema has `metadata :List(KeyValue)`; the implementation ignores it. So even a manually invoked
  `AuthInterceptor` has no bearer token to verify.
- **Rate limiting** (`TokenBucketRateLimiter`, per-client, per-service, `DdosProtection`) is a
  standalone library, also unwired. Implementation nit: refill is `(elapsed * rate) as u64`, so any
  rate below 1 token/s never refills; `available_tokens` ignores elapsed time.
- **Metrics** (`MetricsCollector`, `RpcMetrics`, Prometheus text, tracing spans) are in-memory and
  unwired. `MetricsInterceptor` is never added to a chain. The older `src/metrics.rs` module is
  disabled. There is no `/metrics` listener; `production.rs` can format `/health/live` and
  `/health/ready` payloads but nothing serves them over HTTP/QUIC.
- The separate `quiccrunch-security` crate (OAuth2, Casbin RBAC, audit logging, compliance) is not
  built at all.

### 4.8 Streaming

- Four modes are defined in the schema and in `RpcServer`/`RpcClient`, using one bidirectional QUIC
  stream per call: unary request/response; server streaming; client streaming; bidirectional.
- Chunks are real Cap'n Proto `StreamChunk`/`StreamEnd` messages.
- Gaps: no application-level flow control/backpressure (relies on QUIC windows), no per-chunk
  deadlines, no reset/cancel propagation, no resume/sequence replay, no max-message-size guard,
  and the server does not enforce `RpcRequest.timeout` for unary calls.
- `RpcStreamSink::send`/`finish` are not idempotent and there is no half-close for client streaming
  beyond closing the QUIC stream.
- Streaming tests exist but, per §3.2, cannot run.

---

## 5. Security review

### 5.1 Defaults

| Item | Finding |
| --- | --- |
| Server identity verification | **Off** (BoringSSL default, never enabled) |
| CA trust store | Never loaded; config fields unused |
| mTLS / client certs | Not implemented |
| SPIFFE / workload identity | Not implemented |
| Certificate rotation | Struct exists, unwired |
| Authn on RPC hot path | No enforcement point |
| Authz (RBAC) | Struct exists, unwired; `quiccrunch-security` unbuilt |
| Rate limiting / DDoS | Library only, unwired; integer-refill bug |
| Bounded input | Echo server buffers an attacker-declared `u32` length without a cap → memory DoS |
| Panics | `expect()` in runtime thread on adapter init; `unwrap()` on poll registration |
| Secret handling | `Debug` on TLS session values exposed by `rustls 0.21.12` (RUSTSEC-2026-0346) |

TLS 1.3 + AEAD + forward secrecy from BoringSSL is sound as cryptography; the problem is that the
peer is never authenticated and the framework provides no identity layer.

### 5.2 Dependency audit (`cargo-audit 0.22.2`, 484 crates)

**12 vulnerabilities**, notably:

| Crate | Ver | Advisory | Issue |
| --- | --- | --- | --- |
| `rustls` | 0.21.12 | RUSTSEC-2026-0346 | `Debug` impls expose TLS secrets (medium 4.0) |
| `rustls` | 0.21.12 | RUSTSEC-2026-0349 | Unauthenticated ServerHello can downgrade KEX |
| `rustls-webpki` | 0.101.7 | 2026-0104 / 0098 / 0099 / 0382 | CRL panic, name-constraint bypass, distrusted intermediates |
| `capnp` | 0.23.0 / 0.18.13 | RUSTSEC-2025-0143 | Unsound `constant::Reader` / `StructSchema` APIs |
| `bytes` | 1.10.1 | RUSTSEC-2026-0007 | Integer overflow in `BytesMut::reserve` |
| `h2` | 0.3.27 | RUSTSEC-2026-0258 | Unbounded empty DATA frames (via optional tonic path) |
| `thrift` | 0.17.0 | RUSTSEC-2026-0435 | Unbounded allocation (severity 7.5) |
| `crossbeam-epoch` | 0.9.18 | RUSTSEC-2026-0204 | Invalid pointer dereference in `fmt::Pointer` |

Plus 19 allowed warnings (unmaintained/unsound: `atty`, `lru` ×2, `rand` ×2, `tokio 1.47.1`,
`aesni`, `paste`, `fxhash`, `instant`, …). Note `capnp` — the serialiser on the RPC path — is
itself flagged unsound.

### 5.3 Assurance

- CI nominally runs `cargo clippy --all-targets --all-features -- -D warnings` and
  `cargo test --all-features`, both of which fail at this commit (warnings + E0432/E0063).
- No fuzzing, no malformed-frame corpus, no adversarial TLS tests, no auth bypass tests that run.
- `cargo deny` configuration is absent.

---

## 6. Integration fit for the DistriWaf control plane

DistriWaf (`src/waf/distributed/distri_waf.proto`, ADR-0007) needs 12 RPCs: unary
Register/Heartbeat/Discover/GetPolicy/ActivatePolicy/LookupReputation/AcquireLease/ReleaseLease,
server-streaming Watch, client-streaming IngestEvents, unary IngestCounterDeltas. The tonic client
already implements mTLS, bearer tokens, SPIFFE metadata, CA/server-name pinning, retry/backoff and
watch resume.

### 6.1 Capability matrix

| Requirement | QuicCrunch | Verdict |
| --- | --- | --- |
| QUIC + TLS 1.3 transport | Yes (tquic/BoringSSL) | adopt idea |
| Multiplexed streams | Yes | adopt |
| Multi-worker SO_REUSEPORT | Yes, genuine | adopt design |
| Unary RPC + binary schema | Yes (Cap'n Proto) | prototype |
| Server-streaming Watch | API exists; no resume token, no chunking, no flow control | reject |
| Client-streaming IngestEvents | API exists; no backpressure, no at-least-once/dedup | reject |
| mTLS (client certs) | Absent | reject |
| SPIFFE / workload identity | Absent | reject |
| Bearer-token metadata on wire | Metadata never serialised/parsed | reject |
| Server certificate verification / CA pinning | Absent by default | reject |
| Policy bundle signing | Transport-agnostic; can keep current code | n/a |
| Lease acquire/release latency | p99 35 ms measured | reject |
| Schema evolution / `contract_version` | Cap'n Proto is extensible, but no version negotiation, no v1→v2 policy | prototype |
| Reconnect / discovery / LB | `discovery` disabled; retry types unused; no health-aware pool | reject |
| Observability (Prometheus/OTel) | In-memory only, no exporter/listener; OTel optional & unwired | reject |
| Health/readiness endpoints | Formatters only; nothing serves them | reject |
| Ops tooling (grpcurl, Envoy, L7 LB, mTLS proxies) | None (custom UDP protocol) | reject |
| Fuzzing / compiling tests | None / broken | reject |
| Portable release binary | `target-cpu=native` + AVX2 required | prototype |
| License | MIT/Apache-2.0 (compatible) | adopt |

### 6.2 Effort to reach parity

| Work item | Estimate |
| --- | --- |
| Fix build, warnings, FFI, test compile; restore CI | 1–2 weeks |
| TLS verification, CA loading, SNI, mTLS, certificate rotation | 2–3 weeks (tquic custom `SSL_CTX` via `new_with_ssl_ctx`) |
| Metadata on the wire + auth interceptor enforcement + SPIFFE | 2 weeks |
| Watch resume/versioning, 4 MiB chunking, flow control | 2–3 weeks |
| Reconnect/backoff, discovery, health-aware pooling, deadline propagation | 2 weeks |
| Metrics/health endpoints + OTel, per-worker observability | 1–2 weeks |
| Test suite, fuzz targets, dependency upgrades (rustls 0.23+, capnp fix) | 2 weeks |
| **Total** | **10–16 engineer-weeks**, plus ongoing security ownership of a bespoke RPC stack |

The measured 2 ms p50 / 35 ms p99 also means the control plane would need its own latency work
(wakeup batching, avoiding the per-call mpsc round-trip) before lease/heartbeat RPCs are safe.

### 6.3 Per-interface recommendation

| DistriWaf link | Recommendation | Reason |
| --- | --- | --- |
| Register | **Reject** | Needs authenticated identity; none exists |
| Heartbeat | **Reject** | p99 tens of ms and no deadline enforcement; tonic is fine at 10 s cadence |
| Discover | **Reject** | No discovery/LB implementation (module disabled) |
| Watch (server streaming) | **Reject** | No resume token / RESET / chunking / backpressure |
| GetPolicy / ActivatePolicy | **Prototype** (app-layer only) | Unary + signed blob works, but transport auth still blocks production |
| LookupReputation | **Prototype** | Same unary caveat; background only |
| IngestEvents (client streaming) | **Reject** | No at-least-once semantics, dedup, or backpressure |
| IngestCounterDeltas | **Reject** | Batching/retry logic absent |
| AcquireLease / ReleaseLease | **Reject** | Tail latency 35 ms p99 vs permit-style budget |

---

## 7. Recommendation

**Reject** QuicCrunch as the DistriWaf control-plane transport. Do **not** prototype it behind the
existing `PolicySource`/`NodeRegistry`/`EventSink` traits as a tonic replacement: the missing
identity layer (mTLS/SPIFFE), wire-level metadata, watch resume and backpressure are architectural,
not incremental, and the 10–16 week estimate carries a bespoke security-stack maintenance burden.

What is worth taking:

1. **Adopt the SO_REUSEPORT multi-worker pattern as a design reference** if a future data-plane
   transport needs kernel-level fan-out; the implementation is ~150 lines and is the only part that
   behaved as advertised.
2. **Adopt Cap'n Proto as a schema option** if zero-copy payloads become a hard requirement, but use
   the maintained `capnp` crate directly rather than this wrapper.
3. **Do not adopt** the p99/throughput claims; any internal performance comparison must use a
   benchmark that timestamps individual requests and counts completed responses.

If a QUIC control plane is still desired later, evaluate `quinn` + `tonic`-style codegen, or
`h3`/`quinn` with a maintained IDL layer, and require: certificate verification on by default,
mTLS, SPIFFE, per-RPC deadlines, flow-controlled streaming, and a fuzzed decoder as acceptance
criteria.

---

## 8. Evidence and reproduction

```bash
# external target dir (root fs is tight)
export CARGO_TARGET_DIR=/run/media/shift/.../code/.cargo-target-quiccrunch

nix develop -c cargo check --workspace            # fails: quiccrunch-ffi E0432
nix develop -c cargo test  --workspace            # fails: core lib test E0063 x2
nix develop -c cargo test  -p quiccrunch-macros   # 1 pass, 2 doctests pass

nix develop -c cargo build --release \
  --bin multi_worker_server --bin pipelined_benchmark

# infrastructure
nix develop -c openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
  -keyout key.pem -out cert.pem -subj '/CN=localhost'

# server (repeat with 4 workers)
multi_worker_server 127.0.0.1:4433 cert.pem key.pem 1
# published benchmark
pipelined_benchmark 127.0.0.1:4433 1800 1800 16 1024 4
# real percentiles (out-of-tree probe, 1 in-flight per connection)
latency_probe 127.0.0.1:4433 16 500 1024

cargo audit    # 12 vulnerabilities, 19 warnings
```

**Raw numbers.** 1 worker: 4,773 / 5,088 / 3,710 msg/s; 4 workers: 19,782 / 15,631 / 5,083 /
19,773 / 26,472 msg/s. Probe p99: 4,463 µs (1w), 35,260–36,216 µs (4w). Hardware: i5-8400T, 6C/6T,
1.7 GHz, Linux 6.18.36, Rust 1.89.0, client and server co-located on loopback.

---

## 9. Update — 2026-11-10: after the performance and backend workstreams

The evaluation above is left as written, because its measurements were correct **for the code that
existed then**. Two workstreams have since changed the picture. Evidence lives in the QuicCrunch
repository: `docs/PERFORMANCE_RELEASE.md`, `docs/BACKEND_MESSAGING.md`, `scripts/bench.sh`, merged as
`98f26b0` (`perf/wait-free`); the messaging prototype is draft PR #2 (`feat/backend-messaging`,
`7039737`), deliberately **not** merged into `main`.

### 9.1 The original numbers were also partly a logging artefact

One intermediate run reported `p99 = 1,616,904 µs`. That run had `RUST_LOG=debug`, and the transport
emitted a `debug!` per packet, frame and `written N bytes` write. Two conclusions follow:

- the published 194 µs / 32 µs claims were never reproducible: the shipped benchmark had no latency
  instrumentation and reported `1 / throughput`;
- but the early "35 ms p99" measurements were also pessimistic, because the hot path is only quiet
  when debug logging is disabled.

Fixed in the merged work: per-packet events moved to `trace!` with guarded field construction,
`release_max_level_info` on the transport crates, and `scripts/bench.sh` forces and prints
`RUST_LOG=warn` so a stray debug environment cannot silently invalidate a run.

### 9.2 Measured after the transport rewrite

Push-based reads and bounded wait-free sends removed the two command-channel handoffs per send and
receive. Measured at 1 KiB, 4 streams/connection, `RUST_LOG=warn`:

| Workers | Connections | Pipeline | msg/s | RTT p50 | RTT p99 | Errors / timeouts |
|---:|---:|---:|---:|---:|---:|---:|
| 4 | 16 | 1 | **51,350** | 1.09 ms | 3.40 ms | 0 / 0 |
| 4 | 16 | 64 | 33,000–42,000 | — | 0.46–0.59 ms | 0 / 0 |
| 6 | 16 | 64 | 39,700 | — | — | 0 / 0 |
| 1 | 16 | 64 | 21,800 | — | — | 0 / 0 |

Zero errors and zero timeouts across all 36 measured cells. The earlier saturation cliff (88 errors
and 44 timeouts per 64k samples) was traced to an experimental `SO_ATTACH_REUSEPORT_CBPF` program
reordering flows plus lost `on_stream_readable` events when no reader was parked; both are fixed, and
partial writes now return an error instead of silently dropping bytes.

**What is still not met:** a reliable 40k+ msg/s at depth 64 (median is ~35k; only the depth-1 cell
clears it comfortably), and a p99 below 200 µs is **not achievable** with the current TLS and
one-runtime-thread-per-worker design — the floor is a p50 of roughly 0.85–1.1 ms with 16 in flight.
Anyone quoting a sub-200 µs p99 for this code is quoting an artefact.

### 9.3 Security and shape of the code changed too

The backend workstream fixed what §5 criticised: `cargo check/test --workspace` pass, TLS peer
verification defaults on (insecure mode must be opted into explicitly), CA/SNI and client
certificate/key support exist, request metadata is actually serialized, the interceptor chain invokes
auth/RBAC, rate limiting and metrics, and `cargo audit` reports 0 vulnerabilities (13 informational
warnings). A v1 Cap'n Proto contract (`LeaseAcquire/Release`, `PolicyGet/Watch` with `sinceVersion`,
`EventIngest`, `Heartbeat`), a server dispatch path, a Rust client and loopback tests exist.

### 9.4 Revised verdict

Still **not adopted** for the DistriWaf control plane, but no longer "reject the code". The honest
position is:

- **Transport performance is now adequate** for policy/IOC/lease/heartbeat control traffic. gRPC is
  also adequate, so performance alone does not justify a migration.
- **The blocker is identity.** tQUIC 1.6 exposes no peer certificate, so SPIFFE-bound mTLS identity —
  a hard requirement in the distributed WAF design — cannot be derived at the transport layer. The
  workarounds are patching tQUIC or carrying a signed application-layer identity assertion, both of
  which add bespoke security code on the critical path.
- **Remaining work is 10–16 engineer-weeks** (reconnect/pooling, watch resume retention, flow
  control, exporter endpoints, fuzzing, tail-latency work), for a capability gRPC already provides.

Recommendation: keep the prototype on its branch as an evaluated option, keep distri-kv on tonic, and
revisit only if peer-certificate access lands upstream (or if a future data-plane transport needs the
SO_REUSEPORT worker model). Any re-evaluation must reuse `scripts/bench.sh` with `RUST_LOG=warn` and
the queueing-separated latency instrumentation.