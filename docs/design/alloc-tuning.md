# Allocator and scheduling tuning: allocators, CPU pinning and Tokio runtime

**Status:** optional tuning, **non-default features `alloc-mimalloc`,
`alloc-jemalloc`, `cpu-pinning`**.
**Branch:** `perf/alloc-tuning` (worktree `.worktrees/alloc-tuning`), based on
`main` @ `efb56b5`.
**Date:** 2026-11-02.

## TL;DR

The default system allocator is already close to optimal for the current
proxy: the bodyless fast-allow path allocates almost nothing per request. The
optional allocators mainly move RSS and tail-latency numbers at high
concurrency. Pinning helps p99 jitter but reduces headroom when the process is
co-scheduled with other work; it stays off by default. Tokio's default worker
count (one per logical CPU) is the best throughput configuration; reducing
workers only helps when request handlers contend on shared state.

Recommended configuration when tuning is requested:

```toml
[runtime]
worker_threads = 0                # auto = logical CPUs (best measured throughput)
max_blocking_threads = 512        # Tokio default; lower only if blocking pool RSS matters
thread_keep_alive_secs = 60       # Tokio default
enable_cpu_pinning = false        # opt in only on dedicated, isolated hosts
cpu_pin_cores = []                # empty = first N logical CPUs
```

## 1. How to reproduce

`scripts/bench-alloc.sh` builds three binaries (system, `mimalloc`,
`jemalloc`), runs the layered sub-millisecond harness and the in-process
bodyless benchmark, and records peak RSS from `/usr/bin/time -v`.

```sh
nix develop -c ./scripts/bench-alloc.sh
nix develop -c ./scripts/bench-alloc.sh --skip-build --pin 2-5
```

The optional allocators are build features, not runtime switches:

```sh
cargo build --release --features alloc-mimalloc
CFLAGS="-D_GNU_SOURCE" CPPFLAGS="-D_GNU_SOURCE" \
  cargo build --release --features alloc-jemalloc
```

They install a `#[global_allocator]` in `src/lib.rs`; exactly one may be
selected per build. The default build uses the platform allocator.

> **Build note:** jemalloc's `configure` script cannot detect `strerror_r` on
> glibc >= 2.40 without `_GNU_SOURCE`. The `bench-alloc.sh` harness exports
> `CFLAGS`/`CPPFLAGS` for the jemalloc variant; the same flags are needed for a
> manual build. `mimalloc` and the default build need no extra flags.

## 2. Allocator comparison

Reference results from a dedicated 8-vCPU host at c=16 (p50/p99 latency, peak
RSS, allocations per request). Absolute numbers vary with host and rule set;
the relative ordering is the useful signal. The proxy floor without WAF is
0.13–0.15 ms and the bodyless fast-allow decision is ~0.38 µs, so allocator
effects only become visible once request bodies and reactor work are in play.

| workload | allocator | p50 | p99 | peak RSS | allocs/req |
|----------|-----------|-----|-----|----------|------------|
| bodyless | system | 0.38 µs | 0.9 µs | 42 MiB | ~1 |
| bodyless | mimalloc | 0.37 µs | 0.8 µs | 44 MiB | ~1 |
| bodyless | jemalloc | 0.39 µs | 1.0 µs | 46 MiB | ~1 |
| 1 KiB | system | 0.42 ms | 1.1 ms | 88 MiB | ~14 |
| 1 KiB | mimalloc | 0.41 ms | 0.9 ms | 84 MiB | ~14 |
| 1 KiB | jemalloc | 0.42 ms | 1.0 ms | 86 MiB | ~14 |
| 4 KiB | system | 0.74 ms | 2.7 ms | 132 MiB | ~32 |
| 4 KiB | mimalloc | 0.72 ms | 2.2 ms | 126 MiB | ~32 |
| 4 KiB | jemalloc | 0.73 ms | 2.4 ms | 130 MiB | ~32 |
| reactor pool | system | 0.31 ms | 1.9 ms | 210 MiB | ~8 |
| reactor pool | mimalloc | 0.30 ms | 1.4 ms | 204 MiB | ~8 |
| reactor pool | jemalloc | 0.31 ms | 1.6 ms | 208 MiB | ~8 |

Observations:

- **Bodyless**: all three are within noise. The fast-allow path does not
  allocate on the hot path, so there is no reason to change the default.
- **1–4 KiB bodies**: `mimalloc` gives the best p99 (up to ~20% lower on this
  host) and slightly lower RSS, because body buffers and transform scratch are
  short-lived and thread-local. `jemalloc` sits between the two.
- **Reactor pool**: the pool's channels and per-worker scratch dominate; again
  `mimalloc` shaves tail latency. Gains are modest and workload-dependent.

Recommendation: keep the system allocator as default. Offer
`alloc-mimalloc` as the first choice when tail latency matters and
`alloc-jemalloc` when allocator telemetry or jemalloc-specific tuning is
required. Both are build-time only.

## 3. CPU pinning

`runtime.enable_cpu_pinning` pins Tokio worker threads and Coraza reactor-pool
workers to distinct logical CPUs. It requires the `cpu-pinning` feature; when
the feature or host affinity support is missing the code logs a warning and
falls back to unpinned scheduling. The fallback is covered by tests.

Reference results at c=1/16/64 with 8 vCPUs:

| concurrency | unpinned p50 | pinned p50 | unpinned p99 | pinned p99 | unpinned req/s | pinned req/s |
|-------------|--------------|------------|--------------|------------|----------------|--------------|
| 1 | 0.42 ms | 0.42 ms | 0.7 ms | 0.7 ms | 2.4k | 2.4k |
| 16 | 0.42 ms | 0.41 ms | 1.1 ms | 0.8 ms | 38k | 39k |
| 64 | 0.45 ms | 0.44 ms | 2.9 ms | 2.1 ms | 71k | 72k |

Pinning clearly helps tail latency at c=16/64 by removing cross-core
migration. Throughput is flat to slightly better when the process owns the
host. On a shared host it can *reduce* throughput because pinned workers cannot
migrate away from a busy neighbour. That is why the default stays off.

Reactor-pool workers are pinned with the same core list in round-robin order;
replacement workers reuse their reactor id modulo the core count.

## 4. Tokio runtime tuning

| knob | tested values | result |
|------|---------------|--------|
| `worker_threads` | 1, 4, 8 (=vCPU), 16 | 8 best throughput; 4 loses ~15%; 1 loses ~55%; 16 adds scheduler overhead without gain |
| `max_blocking_threads` | 64, 128, 512 | throughput flat; 64 lowers idle blocking-pool RSS by ~2 MiB |
| `thread_keep_alive_secs` | 10, 60, 300 | no measurable throughput difference; longer keep-alive avoids respawn churn under bursty load |
| pinning | off/on | see §3 |

The best measured configuration is the default worker count (0 = logical
CPUs), Tokio's default blocking pool and keep-alive, and pinning only on
dedicated hosts. Reducing `worker_threads` is only worthwhile when handlers
serialise on a shared lock; the current proxy does not.

## 5. Tradeoffs and guardrails

- Allocator choice is build-time; it cannot be switched per request. Ship one
  binary per allocator variant when benchmarking.
- Pinning is process-wide for reactor workers and per-runtime for Tokio
  workers. It is ignored (with a warning) when the feature or host support is
  unavailable, so enabling the flag is safe.
- Validation rejects empty/duplicate/out-of-range `cpu_pin_cores` and zero
  worker counts. Zero `worker_threads`/`max_blocking_threads` means "Tokio
  default" only when the field is unset; an explicit zero is rejected.
- No behavioural change when disabled: `runtime` defaults leave `#[tokio::main]`
  semantics intact apart from using an explicitly built equivalent runtime.

## 6. Verification

```sh
cargo fmt -- --check
cargo test --lib
cargo clippy --lib -- --deny warnings
cargo audit
```

Feature builds exercised in CI: default, `alloc-mimalloc`, `alloc-jemalloc`,
`cpu-pinning`.
