# io_uring network backend

Status: **implemented behind the non-default `io-uring` feature**, opt-in only.
The default epoll/tokio path is unchanged and remains the fallback.

## What was built

`src/waf/io/uring.rs` is a small, self-contained raw FFI layer (no external
crate) over the stable kernel ABI:

- `io_uring_setup` + `mmap` of the SQ ring, CQ ring and SQE array.
- Bounded submission queue (`Uring::push` refuses when the ring is full;
  `Uring::submit` calls `io_uring_enter`). The ring depth is derived from
  `IoConfig::concurrency` (`max(concurrency, 64) * 2`), so the queue cannot grow
  without bound.
- `IORING_OP_READ` / `IORING_OP_WRITE` shared with registered-buffer support
  via `io_uring_register(IORING_REGISTER_BUFFERS)` (`Uring::register_buffers`).
- `IORING_OP_ACCEPT` for single accept and `IORING_ACCEPT_MULTISHOT` for a
  dedicated multishot accept thread.

`src/waf/io/network.rs` adds `IoUringNetworkHandler`:

- A dedicated ring thread owns each `Uring`; async calls send a command over a
  bounded channel and await a `oneshot` reply, so no tokio worker is blocked.
- `read_fd`, `write_fd` (loops over partial writes), `accept_fd`,
  `start_multishot_accept` and `shutdown` form the fd-based fast path used by
  the connection layer.
- The `NetworkIo` trait is still implemented, delegating to the tokio fallback:
  the trait takes `&mut dyn AsyncRead`, which cannot expose a raw fd. A caller
  that owns the socket fd should use the `*_fd` methods directly.

`src/waf/io/mod.rs` exposes `create_network_io_handler`, which tries io_uring
and **falls back to `NetworkIoHandler` with a `tracing::warn!`** if setup fails.
`create_io_handler` (file I/O) is unchanged; file I/O still uses the tokio
backend. This change is scoped to the network path.

## Kernel / runtime requirements

| Capability | Minimum kernel |
| --- | --- |
| Ring setup, read/write | 5.1 |
| `IORING_OP_ACCEPT` | 5.6 |
| `IORING_ACCEPT_MULTISHOT` | 5.19 |
| `IORING_REGISTER_BUFFERS` | 5.1 |
| Best-tested | 6.x |

Additional operational caveats:

- `io_uring` may be disabled by `kernel.io_uring_disabled=2` (or `1` for
  unprivileged processes). Setup then returns `ENOSYS`/`EPERM` and the handler
  falls back automatically.
- Container seccomp profiles (Docker default, some Kubernetes runtimes) block
  `io_uring_setup` without an explicit allow rule. Allow syscalls 425/426/427
  if the backend should be used in a container.
- Each ring consumes locked/shmem memory; `RLIMIT_MEMLOCK` and
  `vm.overcommit_memory` matter at high ring counts.
- A ring thread is pinned to the handler; ring teardown happens when the
  handler is dropped (channel closes). `shutdown()` provides an explicit stop.

## Graceful fallback

- `IoUringNetworkHandler::new` returns `Err` on setup failure; it never panics.
- `create_network_io_handler` logs `io_uring unavailable; falling back to tokio
  network I/O` and returns the standard handler.
- Tests skip (with an `eprintln!`) when the ring cannot be created, so CI on
  locked-down kernels still passes.

## Integration note (connection layer)

`src/proxy/service.rs` is owned by another task and was not modified. The
intended integration is: the accept loop obtains the listener fd, calls
`start_multishot_accept`, and for each accepted fd uses `read_fd`/`write_fd`
instead of the tokio stream. The WAF still receives exactly the same bytes;
only the transport path changes. Because the existing `NetworkIo` trait is
stream-oriented, the fd fast path is additive and opt-in.

## Benchmark

Run (release, requires the feature):

```sh
nix develop -c cargo run --release --features io-uring \
  --bin io-uring-network-bench
```

The benchmark measures loopback echo round-trips for bodyless (16-byte header)
and 1 KiB body requests at concurrency 1, 16 and 64, reporting req/s and
p50/p99 latency for the default tokio path and the io_uring fd path.

### Measured results

Loopback echo, 2000 round-trips per connection, this host (kernel 6.18.36,
release build). `bodyless` = 16-byte request header, `1 KiB` = header + 1024 B.
CPU is process user+sys seconds for the whole case.

| body | c | path | req/s | p50 | p99 | CPU (s) |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| 0 B | 1 | tokio | 51,039 | 19 µs | 23 µs | 0.03 |
| 0 B | 1 | io_uring | 31,466 | 27 µs | 79 µs | 0.09 |
| 0 B | 16 | tokio | 79,889 | 168 µs | 335 µs | 0.43 |
| 0 B | 16 | io_uring | 86,446 | 184 µs | 253 µs | 0.79 |
| 0 B | 64 | tokio | 99,487 | 506 µs | 1218 µs | 1.72 |
| 0 B | 64 | io_uring | 87,374 | 745 µs | 890 µs | 3.14 |
| 1 KiB | 1 | tokio | 48,589 | 20 µs | 24 µs | 0.03 |
| 1 KiB | 1 | io_uring | 31,355 | 27 µs | 71 µs | 0.09 |
| 1 KiB | 16 | tokio | 77,427 | 174 µs | 341 µs | 0.44 |
| 1 KiB | 16 | io_uring | 83,548 | 189 µs | 251 µs | 0.88 |
| 1 KiB | 64 | tokio | 94,025 | 553 µs | 1251 µs | 1.76 |
| 1 KiB | 64 | io_uring | 86,382 | 763 µs | 919 µs | 3.08 |

Interpretation:

- **c=1**: io_uring is ~38% slower. Each request costs a channel hop to the
  ring thread plus a wakeup, while tokio's epoll path is already very cheap
  for a single connection.
- **c=16**: the only clear win: ~8% higher req/s and a better tail (p99 253 µs
  vs 335 µs bodyless) because multishot accept avoids per-accept syscalls and
  epoll registration churn. CPU is ~1.8x.
- **c=64**: tokio wins again. One ring thread per handler serialises all
  read/write completions, so latency grows and CPU roughly doubles.
- Body size barely moves the needle: this echo path is dominated by
  syscall/channel overhead, not payload copying.

Where the gain comes from today: **multishot accept** (one SQE services many
connections) and avoiding per-connection epoll registration, visible at c=16.
The classic io_uring wins are not realised yet because the hot path submits and
waits one operation at a time, allocates a fresh `Vec` per read, and does not
use batched submission, a registered buffer pool, or `IORING_SETUP_SQPOLL`.
Those are the documented follow-ups below, not hidden in the numbers.

## Tests

`cargo test --lib --features io-uring` covers:

- ring setup success/clean fallback (`uring::tests::setup_or_fallback`),
- buffer registration (`uring::tests::register_buffers_or_fallback`),
- read/write round-trip including partial/large write looping,
- graceful `shutdown()`,
- single and multishot accept (skips when unsupported).

## Follow-ups (not implemented)

- Batch submissions and drain completions out of order.
- Buffer pool + `IORING_REGISTER_BUFFERS` on the hot path.
- `IORING_SETUP_SQPOLL` mode.
- Wire the fd fast path into `src/proxy/service.rs` (owned elsewhere).
- File I/O backend (`IoUringHandler` in `backend.rs`) is still the optimized
  tokio fallback.
