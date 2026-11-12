# Soak and Fault-Injection Testing

This document describes the long-running soak harness and the deterministic
fault-injection suite added for the WAF ingress. The harness is intentionally
quarantined behind the `experimental` feature, matching the other ad-hoc load
and test tools in [`module-scope.md`](module-scope.md).

> **A short CI run is not a soak.** The default 60-second run is a smoke test
> that proves the harness, the proxy and the verdict logic work. It cannot
> detect slow leaks, multi-hour degradation, or rare protocol wedges. A real
> soak is an operator task measured in hours, run on a quiet host.

## What is covered

`scripts/soak.sh` starts a fixture upstream and the real `waf-ingress` binary,
then drives a configurable mixed workload through the proxy:

| Traffic class | What it exercises |
| --- | --- |
| `benign` | JSON request/response path, body buffering, upstream pool |
| `blocked` | Canonical SQLi, XSS and path-traversal payloads; must return `403` |
| `oversized` | Body above `server.max_body_size`; must return `413` |
| `malformed` | Invalid chunked framing; must be rejected or closed, never forwarded |
| `grpc` | Unary gRPC framing and gRPC-aware inspection path |
| `websocket` | Upgrade, frame inspection, tunnel lifecycle |

During the run the harness samples the proxy process from `/proc/<pid>`:

- RSS (`VmRSS`)
- open file descriptors (`/proc/<pid>/fd`)
- thread count (`/proc/<pid>/status`)
- TCP connections owned by the process (socket inodes matched against
  `/proc/net/tcp` and `/proc/net/tcp6`)

It reports per-minute throughput, p50/p95/p99 latency, status-code
distribution, block rate and errors. At the end it re-sends the canonical
SQLi, XSS and path-traversal payloads. If any of them is not blocked, the run
fails even if every other metric is healthy.

## Thresholds

The verdict is fail-closed. Defaults (all overridable through `SOAK_*`
environment variables):

| Check | Default | Meaning |
| --- | --- | --- |
| RSS growth slope after warm-up | `<= 2.0 MiB/min` | Linear regression over post-warm-up samples |
| FD growth | `<= 32` | Max FD count after warm-up minus the first post-warm-up sample |
| Connection growth | `<= 32` | Same, for process-owned TCP connections |
| Error rate | `< 1%` | Unexpected status, connection failure or failed WebSocket session |
| Block rate | `>= 99%` | Blocked-class requests that returned `403` |
| Canonical payloads | all blocked | SQLi, XSS and path traversal must still return `403` at the end |

A run with zero blocked attempts also fails the block-rate check, so a broken
traffic mix cannot silently pass.

## How to run

Short CI-friendly smoke (default 60 seconds):

```bash
SOAK_DURATION=60s ./scripts/soak.sh
```

Fault scenarios only:

```bash
./scripts/soak.sh faults
```

Long operator soak (not a CI run):

```bash
SOAK_DURATION=2h \
SOAK_WARMUP=10m \
SOAK_CONCURRENCY=64 \
SOAK_MIX=benign=50,blocked=15,oversized=5,malformed=5,grpc=10,websocket=15 \
./scripts/soak.sh
```

The script builds `soak-load` and `waf-ingress` with the `experimental`
feature, writes a temporary config under `$CARGO_TARGET_DIR/soak-work`, starts
the fixture and proxy, runs the workload, writes a JSON report to
`$CARGO_TARGET_DIR/soak-report.json`, and exits non-zero on any failed
threshold.

Useful overrides:

```bash
SOAK_PROFILE=release          # default; use debug for a faster local build
SOAK_CONCURRENCY=16
SOAK_BODY_SIZE=4096
SOAK_OVERSIZED_BYTES=1572864
SOAK_SAMPLE_INTERVAL=2s
SOAK_MAX_RSS_SLOPE_MB_PER_MIN=2.0
SOAK_MAX_FD_GROWTH=32
SOAK_MAX_CONN_GROWTH=32
SOAK_MAX_ERROR_RATE=0.01
SOAK_MIN_BLOCK_RATE=0.99
SOAK_REPORT=/path/to/report.json
```

## Fault scenarios

`./scripts/soak.sh faults` runs each scenario once, process-level and without
root or `tc netem`:

1. **Upstream unavailable mid-run** — the fixture is killed while load is
   running. The proxy must return `502`/`503`, then recover to `200` after the
   fixture restarts, without restarting the proxy.
2. **Slow upstream** — a userspace delay fixture sleeps past
   `proxy.timeout_seconds`. Requests must return `504`, connections must not
   leak, and the proxy must stay responsive.
3. **Malformed upstream responses** — malformed status line, truncated body,
   bad chunked framing and a 128 KiB header. The proxy must not panic and
   inspection must still block canonical payloads.
4. **WAF restart under load** — the proxy is killed and restarted while a
   client loop is running. Clients reconnect, post-restart requests succeed,
   and inspection still blocks.
5. **Connection flood** — `server.max_connections` is set to 8 and held
   connections are opened. Excess connections must be rejected with `503`,
   the health listener must stay responsive, and the proxy must recover after
   the flood is released.
6. **Abandoned WebSocket tunnels** — `max_concurrent_tunnels = 4` and a
   2-second idle timeout. Four tunnels are admitted, the rest are rejected,
   and abandoned tunnels are reaped so a new tunnel succeeds.

## Measured short run on this host

These are **provisional** results from a 30-second debug-build smoke run on a
shared host while a release gate was also running. They are not a soak and
must not be used as a capacity claim.

- Host: Intel Core i5-8400T, 6 logical CPUs, 15.8 GiB RAM, NixOS
- Load average at the start of the session: `17.24, 9.22, 6.11`
- Build: `debug` (`SOAK_PROFILE=debug`), default feature set plus `experimental`
- Duration: 30 s, warm-up 5 s, concurrency 8
- Mix: `benign=40,blocked=20,oversized=5,malformed=5,grpc=15,websocket=15`
- Requests: 10,004; errors: 0; error rate: 0.00%
- Block rate: 100.00% (2,005/2,005); canonical payloads blocked at end: yes
- Latency: p50 20 ms, p95 100 ms, p99 200 ms (debug build, shared host)
- RSS: 58.7 -> 77.6 MiB; post-warm-up slope: -3.18 MiB/min
- FDs: 11 -> 22 (max growth 4 over baseline); connections: 0 -> 4 (growth 5)
- Verdict: **PASS**

Fault suite on the same host: all six scenarios passed. The connection-flood
scenario observed 4/20 excess connections rejected with `503` and the health
endpoint stayed responsive; the remaining connections sat in the accept
backlog under the loaded debug build. The WebSocket scenario admitted 4
tunnels, rejected 6 at the cap, and reaped the abandoned tunnels after the
idle timeout.

## Long soak procedure

1. Run on a quiet host (or record the load average and treat results as
   provisional).
2. Use a release build: `SOAK_PROFILE=release`.
3. Choose a duration of at least 1 hour, preferably 4-8 hours, with a warm-up
   of at least 10 minutes.
4. Keep the JSON report and the proxy log for the whole run.
5. Investigate any positive RSS slope, FD/connection growth, error rate above
   the ceiling, or any canonical payload that is not blocked.
6. Do not run the long soak in CI. The manual workflow only runs the short
   smoke and fault suite.
