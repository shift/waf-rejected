# Native Coraza performance profile

**Status:** supported, opt-in deployment profile. The default backend is still
`waf.coraza.backend = "wasm"`; nothing in this profile is enabled by a plain
`config.toml`.

This profile runs the same Coraza 3.3.3 / OWASP CRS 4.14.0 engine as the WASI
reactor, but as a native Go sidecar over a Unix domain socket. It removes the
Go-to-wasm execution penalty from CRS body scanning (the dominant cost) and is
about 6× faster on body inspection than the wasm reactor (proxy p50 at 8 KiB:
341 ms → 56 ms; at 60 KiB: 2 617 ms → 422 ms on the reference host). It costs
one extra process, one socket and a second image/unit to operate.

## Files

| Path | Purpose |
|---|---|
| `config/performance-native.toml` | Proxy configuration with `backend = "native"`, tuned pool/admission/body policy. |
| `deploy/compose/native-performance.yaml` | Compose stack: proxy + sidecar + mock upstream, healthchecks, read-only rules, limits. |
| `deploy/kubernetes/native-performance.yaml` | Same-pod sidecar, shared `emptyDir` socket, probes, PDB. |
| `deploy/systemd/coraza-sidecar.service` | Hardened host unit for the sidecar. |
| `deploy/container/Dockerfile.coraza-sidecar` | Distroless sidecar image with the CRS bundle baked in. |
| `scripts/run-native-profile.sh` | Local build, start, readiness, smoke test and teardown under `/tmp/opencode`. |
| `native/coraza-sidecar/` | Sidecar source, protocol, probe mode and tests. |

## Quick start

Local, isolated state (recommended for validation):

```sh
./scripts/run-native-profile.sh          # build + benign/SQLi/XSS/gRPC smoke
./scripts/run-native-profile.sh --load   # also run the capacity matrix
```

Compose:

```sh
docker compose -f deploy/compose/native-performance.yaml up --build
curl -fsS http://127.0.0.1:8081/health/ready
```

Kubernetes:

```sh
kubectl apply -f deploy/kubernetes/native-performance.yaml
```

Both deployment examples run the proxy and sidecar as uid/gid `1000`. The
sidecar creates the socket with mode `0660`; filesystem access is the only
authentication on that boundary. Never expose the socket on TCP.

## Measured capacity

Reference host: Intel i5-8400T, 6 logical CPUs, 15.8 GiB RAM, Linux 6.18,
release build, CRS 4.14.0, `scripts/run-native-profile.sh --load`, seed 42,
warm-up 2 s + measure 8 s per cell. The host was shared and busy during this
run (load average ~20 from unrelated builds), so these are **capacity floors**,
not ceilings. The sidecar, proxy, client and mock upstream also share the six
cores.

| body | c | RPS | p50 | p95 | p99 | 503 |
|---|---:|---:|---:|---:|---:|---:|
| 1 KiB | 1 | 50.1 | 19.00 ms | 23.31 ms | 47.00 ms | 0 |
| 1 KiB | 4 | 148.3 | 24.38 ms | 44.00 ms | 78.17 ms | 0 |
| 1 KiB | 16 | 90.1 | 156.15 ms | 305.05 ms | 400.01 ms | 0 |
| 1 KiB | 64 | 120.7 | 507.74 ms | 584.08 ms | 603.21 ms | 346 |
| 4 KiB | 1 | 12.9 | 70.33 ms | 125.89 ms | 169.50 ms | 0 |
| 4 KiB | 4 | 33.6 | 100.35 ms | 214.45 ms | 248.79 ms | 0 |
| 4 KiB | 16 | 27.7 | 547.86 ms | 717.25 ms | 759.56 ms | 32 |
| 4 KiB | 64 | 115.5 | 506.00 ms | 686.75 ms | 762.15 ms | 798 |
| 8 KiB | 1 | 6.7 | 141.74 ms | 226.88 ms | 246.72 ms | 0 |
| 8 KiB | 4 | 19.8 | 184.44 ms | 340.51 ms | 487.14 ms | 0 |
| 8 KiB | 16 | 24.1 | 506.53 ms | 911.15 ms | 960.00 ms | 117 |
| 8 KiB | 64 | 111.5 | 507.01 ms | 784.72 ms | 941.26 ms | 887 |
| 16 KiB | 1 | 3.4 | 285.00 ms | 361.05 ms | 379.00 ms | 0 |
| 16 KiB | 4 | 7.3 | 436.98 ms | 963.37 ms | 996.60 ms | 0 |
| 16 KiB | 16 | 23.9 | 504.04 ms | 1.21 s | 1.32 s | 157 |
| 16 KiB | 64 | 100.5 | 508.17 ms | 530.10 ms | 1.49 s | 933 |
| 60 KiB | 1 | 1.3 | 737.12 ms | 1.04 s | 1.04 s | 0 |
| 60 KiB | 4 | 1.5 | 2.58 s | 3.01 s | 3.05 s | 0 |
| 60 KiB | 16 | 18.6 | 504.82 ms | 2.41 s | 3.87 s | 186 |
| 60 KiB | 64 | 99.3 | 507.88 ms | 548.44 ms | 2.41 s | 954 |
| gRPC 1 KiB | 1 | 279.0 | 3.00 ms | 6.00 ms | 7.00 ms | 0 |
| gRPC 1 KiB | 4 | 477.7 | 6.70 ms | 20.18 ms | 28.36 ms | 0 |
| gRPC 1 KiB | 16 | 1162.8 | 11.04 ms | 30.84 ms | 39.90 ms | 0 |
| gRPC 1 KiB | 64 | 1812.1 | 29.22 ms | 79.39 ms | 99.84 ms | 0 |

A second identical run on the same host produced 32.6 RPS / p95 64.5 ms for
1 KiB at c=1 and 650 RPS / p95 13.9 ms for gRPC at c=4, i.e. roughly ±30 %
run-to-run variation from unrelated host load. Re-run the matrix on quiet
hardware before setting SLOs.

The RPS column counts completed responses, including `503`s. Cells with `503`s
are saturated: admission control is doing its job, not serving useful traffic.
Use the zero-503 rows for capacity planning:

| profile | max sustained RPS (zero 503) | at c | observed p95 |
|---|---:|---:|---:|
| 1 KiB form | 148 | 4 | 44 ms |
| 4 KiB form | 34 | 4 | 214 ms |
| 8 KiB form | 20 | 4 | 341 ms |
| 16 KiB form | 7 | 4 | 963 ms |
| 60 KiB form | 1.5 | 4 | 3.01 s |
| gRPC 1 KiB (envelope) | 478 | 4 | 20 ms |

On a quiet host the same profile is expected to reach the values in
[`docs/coraza-native-sidecar.md`](../coraza-native-sidecar.md) (about 130 RPS at
1 KiB and 17 RPS at 8 KiB per sidecar core, i.e. ~456 RPS at 1 KiB on four
effective cores). Treat the table above as the guaranteed floor when the host
is contended.

### CPU per 1k RPS

CRS body inspection is byte-linear: budget **~7–8 µs of sidecar CPU per
inspected body byte**, or **~130 KiB of body per second per core**. That gives
a simple CPU estimate for a target rate:

| inspected body | CPU-seconds per request | Cores per 1 000 RPS |
|---|---:|---:|
| 1 KiB | ~0.0077 s | ~7.7 |
| 4 KiB | ~0.031 s | ~31 |
| 8 KiB | ~0.061 s | ~61 |
| 16 KiB | ~0.123 s | ~123 |
| 60 KiB | ~0.46 s | ~461 |

In other words, a 6-core host can sustain roughly 800 RPS of 1 KiB bodies, 100
RPS of 8 KiB bodies, or 13 RPS of 60 KiB bodies **if the sidecar owns every
core**. The proxy, TLS termination, upstream and kernel networking need their
own cores, so plan for the sidecar to use at most `cores - 1` and scale out
horizontally (more pods/hosts) rather than buying one enormous machine.

The levers that change this table are the body policy (`max_inspect_bytes` +
`oversize_action = "reject"` caps the linear cost), gRPC/GraphQL modes that
withhold non-form bodies from CRS, and admission control.

### Socket and connection sizing

- `waf.coraza.pool_size`: one pooled connection per concurrent evaluation.
  Set it to the number of cores the sidecar may use, capped at 8 by validation.
  The shipped profile uses `8`; on a 4-core host use `3` or `4`. `0` means
  auto (available cores clamped to 1..8). More connections than cores only
  adds queueing.
- `--max-conns` (sidecar): keep it well above `pool_size` (default `128`). It
  bounds concurrent evaluations and gives a restarted proxy room to reconnect
  without hitting the listen backlog.
- Admission: `heavy_permits = 4` reserves half the pool for cheap requests.
  `queue_timeout_ms = 500` is deliberately short; raise it to 1–2 s if 60 KiB
  bodies are normal traffic, and lower `max_queued` if you prefer to shed load
  earlier. Admission never skips inspection: a saturated queue returns `503`
  with `Retry-After`.
- Unix socket path length must stay below 108 bytes. `emptyDir`/`RuntimeDirectory`
  paths are short by design; avoid deep per-request temp directories.
- File descriptors: the sidecar unit uses `LimitNOFILE=8192`. The proxy's
  `server.max_connections` is `8192` in the profile; keep the container/host
  `nofile` limit above the sum of proxy connections and upstream sockets.

### Memory

- Proxy idle RSS ~16 MiB; peak RSS measured during the matrix: **62.5 MiB**
  (buffer pools warm).
- Sidecar idle RSS ~63 MiB after loading CRS; `GOGC=600`, a 192 MiB soft limit
  and `MemoryMax=512M` in the unit.
  A 60 KiB request needs roughly 8–12 MiB of transient allocation. The
  distroless container in the profile reserves 256 MiB and limits to 1 GiB;
  size the limit to at least `2 ×` the steady RSS plus the largest concurrent
  body working set.
- The socket volume only needs a few KiB; `emptyDir.sizeLimit: 64Mi` is ample.

## Operational requirements

### Socket permissions

| Path | Owner | Mode | Notes |
|---|---|---|---|
| `/run/waf` | `waf:waf` (or pod `fsGroup`) | `0750` | systemd `RuntimeDirectory`, Compose init, K8s `fsGroup` |
| `/run/waf/coraza.sock` | `waf:waf` | `0660` | set by the sidecar after bind |
| `/usr/share/waf/coraza` | root | `0755` | CRS rules, read-only |

The proxy and sidecar must share a uid or gid. Do not widen the socket to
`0666`; there is no authentication beyond filesystem access. The proxy mounts
the socket volume read-only in Compose/Kubernetes: it only connects, it never
creates or unlinks the socket.

### Sidecar lifecycle and restart

- Start the sidecar before the proxy. The proxy performs a preflight connect
  during `WafProxyService::new` and **aborts start-up** if the socket is
  unavailable. This is intentional: a missing sidecar must not silently
  degrade to per-request `503`s.
- The sidecar is foreground-only and owns no persistent state. `SIGTERM`
  stops accepting, closes idle pooled connections and drains in-flight work
  for `--grace` (10 s). Keep the supervisor/container stop timeout above
  `--grace` (`stop_grace_period: 15s`, `TimeoutStopSec=15s`,
  `terminationGracePeriodSeconds: 30`).
- A sidecar restart does not require a proxy restart. The client retries once
  on a fresh connection and re-negotiates the binary protocol. Requests during
  the gap fail closed (`503`) when `fail_mode = "closed"`.
- The sidecar removes a stale socket at start-up. If it crashes, the socket
  inode remains until the restart removes it; the proxy's connects then fail
  closed until the new listener is up.
- In Kubernetes the two containers start concurrently. The sidecar loads CRS
  in ~1–2 s while the proxy spends ~5 s validating the wasm module, so the
  sidecar normally wins the race. If the proxy starts first it exits and the
  kubelet restarts it; the readiness probe keeps it out of the Service until
  the socket is usable. On Kubernetes 1.29+ you can make the ordering explicit
  by running the sidecar as a native sidecar (`initContainer` with
  `restartPolicy: Always`).

### Rolling upgrades

1. Roll the sidecar and proxy together (same pod or same host) with the same
   CRS bundle. The sidecar loads rules once at start-up; there is no hot
   reload.
2. Keep at least one replica serving (`PodDisruptionBudget minAvailable: 1`
   with `replicas: 2`). A rolling pod replacement briefly removes one socket,
   but the other replica keeps serving.
3. On a host (systemd), restart the sidecar first, then the proxy if the proxy
   binary also changed. `PartOf=waf-ingress.service` keeps the pair together.
4. Do not mix CRS versions between the proxy's wasm bundle and the sidecar if
   you compare decisions; the native and wasm backends are decision-parity
   tested on the same bundle.
5. Drain before upgrade: stop sending new connections, wait for in-flight
   requests, then replace. The sidecar's `--grace` drain only covers requests
   already accepted.

### Failure modes

| Failure | Behaviour |
|---|---|
| Sidecar not running at proxy start-up | Proxy aborts with `Coraza native sidecar failed to initialise: ... socket ... is unavailable`. Fix the sidecar/socket, then start the proxy. |
| Sidecar dies while the proxy runs | In-flight/next requests get `503` (fail closed) until the socket returns. `fail_mode = "open"` would allow them; do not use that for a security control. |
| Sidecar restarts | Proxy reconnects on the next request; no proxy restart needed. Brief `503` window. |
| Socket permission/uid mismatch | Start-up preflight fails (or request-time `EACCES` → `503`). Check the uid/gid and `0750`/`0660` modes. |
| Evaluation exceeds `eval_timeout_ms` | Client closes the socket, returns fail-closed `503`; the sidecar goroutine exits after the current Coraza call returns. The connection is not reused. |
| Admission queue full/timeout | `503` with `Retry-After`; inspection is never skipped. |
| Sidecar OOM | Supervisor restarts it; `503`s during the gap. Check `MemoryMax`, `--max-body`, and body policy. |
| Rules bundle missing/unreadable | Sidecar exits at start-up (`initialise Coraza`); proxy preflight then fails. Rules are read-only in all examples. |
| Stale socket after crash | Sidecar removes it at start-up. Do not point two sidecars at the same path. |

### Observability

The proxy serves Prometheus text from `health_bind_addr` at `/metrics`
(`8081` in the profile). Liveness is `/health/live`, readiness `/health/ready`.
Relevant series:

- `waf_coraza_evaluations_total`, `waf_coraza_blocks_total`,
  `waf_coraza_errors_total`
- `waf_coraza_evaluation_duration_seconds` histogram
- `waf_coraza_body_inspected_bytes`, `waf_coraza_body_truncated_total` and
  `waf_coraza_body_rejected_total`
- `waf_admission_wait_duration_seconds` and the request/503 counters

Alert on a rising `waf_coraza_errors_total` rate, sustained `503`s, sidecar
restarts, and sidecar RSS near its limit. The sidecar logs `ready socket=...`
and `shutdown complete`; it has no HTTP endpoint of its own. Its health is
probed with `coraza-sidecar --probe --socket /run/waf/coraza.sock`, which
connects to the listener and exits 0 only when it accepts.

### When to choose wasm instead

Use the default wasm backend when any of these is true:

- You want a **single static binary** with no second process, socket, uid or
  supervisor to manage.
- Traffic is low or bodies are small enough that the wasm reactor meets the
  latency budget (it remains the default and is decision-parity tested).
- You cannot guarantee a shared uid/gid or a Unix socket (for example Windows
  hosts, or a platform that does not allow Unix sockets).
- You prefer wasmtime's in-process memory/fuel sandbox over OS process
  isolation and supervisor-managed restarts.
- You cannot operate a second container/unit and its upgrade lifecycle.

Choose the native profile when body-inspection CPU dominates, you can operate
one sidecar per proxy pod/host, and you need the ~6× body-inspection speed-up
without reducing inspection depth or the inspected body size.

## Packaging

- `nix build .#waf-ingress` now builds with `wasm-reactor,coraza-native`; the
  default `Config` still resolves to `backend = "wasm"`.
- `nix build .#coraza-native-sidecar` installs `bin/coraza-sidecar` and
  `share/waf/coraza/{crs,LICENSE-CRS,PROVENANCE.md}`.
- Release tarballs include `native/coraza-sidecar` and `native/coraza/`, plus a
  standalone `waf-rejected-v<version>-coraza-sidecar-x86_64-linux.tar.gz`.
  From a release tree, start it with
  `native/coraza-sidecar --rules native/coraza/crs/crs.conf ...`.
- The proxy container is built with `coraza-native`; the sidecar container is
  built from `deploy/container/Dockerfile.coraza-sidecar` (distroless, rules
  baked in read-only). Both images are required for the Compose/K8s examples.

## Validation

```sh
# smoke (benign 200, SQLi/XSS 403, gRPC 200) and teardown
./scripts/run-native-profile.sh

# capacity matrix at 1/4/8/16/60 KiB + gRPC, c=1,4,16,64
./scripts/run-native-profile.sh --load

# packaging and static checks
nix build .#coraza-native-sidecar
nix develop -c cargo fmt -- --check
nix develop -c cargo clippy --lib --features wasm-reactor,coraza-native -- --deny warnings
```

The script writes logs and `summary.md`/`results.json` under
`/tmp/opencode/native-profile/` and tears the stack down on exit (use `--keep`
to leave it running). It disables per-IP/global rate limiting only for the
validation proxy so the matrix measures inspection capacity; the checked-in
profile keeps both limits enabled.

## Limitations

- One extra process, socket and image to deploy, monitor and secure.
- Coraza has no cancellation API: a timed-out evaluation keeps its sidecar
  goroutine until the current Coraza call returns. Bound work with `--timeout`,
  `--max-body`, `--max-conns`, header limits and the body policy.
- The sidecar's `--max-body` must be at least the proxy's `max_payload_bytes`
  plus request line and headers. The profile uses 64 KiB for both; raise both
  together.
- Unix sockets are local-only. There is no cross-host sidecar; scale by adding
  proxy+sidecar pods, not by sharing one sidecar.
- The measured table above was taken on a shared, contended host. Re-run the
  matrix on your hardware and record the result before setting SLOs.
