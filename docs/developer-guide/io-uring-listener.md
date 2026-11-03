# io_uring listener

The proxy listener can accept connections through a Linux io_uring multishot
accept ring instead of the default epoll/tokio accept path. The feature is
opt-in and defaults to the existing tokio backend.

## Configuration

```toml
[server]
# "tokio" (default) or "io_uring"
io_backend = "io_uring"
```

`io_uring` requires:

- Linux with the `io-uring` Cargo feature enabled (`--features io-uring`).
- Kernel >= 5.19 for `IORING_ACCEPT_MULTISHOT`; older kernels fall back.
- Permission for `io_uring_setup` (not blocked by seccomp or
  `kernel.io_uring_disabled`).

If the ring cannot be created, the listener logs a warning and continues with
the tokio backend. The WAF, TLS, HTTP/2 and request pipeline are unchanged: only
the accept path differs, and accepted connections are handed to hyper as normal
tokio `TcpStream`s.

## What changed in the backend

- **Batched submission.** The ring thread drains up to half of the ring depth
  worth of commands and submits them with a single `io_uring_enter`. Commands
  may complete out of order and are matched by `user_data`.
- **Multiple in-flight operations.** A single ring no longer serialises one
  read/write/accept at a time. This removes the c=64 regression caused by one
  completed operation per round trip.
- **Read buffer pool.** Fixed-size read buffers are recycled after the
  completion is copied out, so the hot path stops allocating and zeroing a
  fresh `Vec` for every read. Oversized reads use a one-off allocation.
- **Partial writes without repeated copies.** `write_fd` copies the payload
  once into a ref-counted `Bytes` value and slices it for each retry.
- **Deterministic accept shutdown.** The multishot accept thread sleeps in
  `poll(2)` on the CQ ring fd with a 25 ms bound and checks a stop flag, so
  listener shutdown does not hang.
- **SQPOLL is opt-in only.** `WAF_IO_URING_SQPOLL=1` tries
  `IORING_SETUP_SQPOLL` and falls back to a normal ring when the kernel
  refuses. It is not enabled by default.

## Benchmark

The end-to-end benchmark drives the real proxy with TLS 1.3, ALPN `h2` and the
WAF/Coraza enabled over loopback:

```sh
nix develop -c cargo test --release --test integration --features io-uring,coraza-native \
  io_uring_proxy_bench -- --ignored --nocapture
```

It reports req/s, p50/p99 and process CPU seconds for bodyless and 1 KiB
requests at concurrency 1/16/64. Results for this host are recorded below.

| backend | body | c | req/s | p50 (µs) | p99 (µs) | CPU (s) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| tokio | 0 B | 1 | 354 | 2,566 | 4,155 | 1.09 |
| io_uring | 0 B | 1 | 359 | 2,505 | 4,202 | 1.08 |
| tokio | 0 B | 16 | 1,617 | 8,737 | 26,906 | 17.64 |
| io_uring | 0 B | 16 | 1,611 | 8,524 | 41,344 | 17.48 |
| tokio | 0 B | 64 | 1,653 | 33,147 | 129,439 | 72.83 |
| io_uring | 0 B | 64 | 1,662 | 32,948 | 124,249 | 72.85 |
| tokio | 1 KiB | 1 | 15 | 64,349 | 78,073 | 4.28 |
| io_uring | 1 KiB | 1 | 13 | 77,050 | 78,426 | 3.30 |
| tokio | 1 KiB | 16 | 66 | 221,616 | 432,304 | 57.68 |
| io_uring | 1 KiB | 16 | 68 | 206,607 | 368,936 | 56.23 |
| tokio | 1 KiB | 64 | 64 | 986,382 | 1,461,705 | 238.41 |
| io_uring | 1 KiB | 64 | 65 | 943,782 | 1,455,051 | 235.16 |

Host: Linux 6.18, release build, 8 worker threads, one process for
client+proxy+upstream. Bodyless rows are listener/concurrency limited; the
1 KiB rows are dominated by the Coraza body-scan permit pool, so throughput is
near-identical and latency is high for both backends.

Interpretation: batching removed the c=64 regression seen in the earlier
one-op-at-a-time ring (bodyless 1,653 → 1,662 req/s, 1 KiB 64 → 65 req/s, CPU
unchanged). At c=1 the listener is not the bottleneck for bodyless traffic
(359 vs 354 req/s); with a heavy body the single-request path is still slightly
slower (13 vs 15 req/s), so the backend stays opt-in.

The accept-only integration cannot show the full data-path gain of io_uring
because hyper still performs reads/writes on tokio streams. It measures the
listener fast path plus the same WAF and TLS work for both backends.

## Tests

```sh
nix develop -c cargo test --lib --features io-uring
nix develop -c cargo test --test integration --features io-uring,coraza-native
```

Covered:

- listener enable/disable and post-setup backend reporting,
- simulated `io_uring_setup` failure → tokio fallback without panic,
- graceful accept-thread shutdown,
- partial/large writes and partial reads,
- concurrent read/write correctness through one pipelined ring,
- config parsing (`"tokio"`, `"io_uring"`, invalid value rejected).
