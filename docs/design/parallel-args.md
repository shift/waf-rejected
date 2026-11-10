# Parallel ARGS candidate evaluation: model, semantics and measurements

**Status:** experimental, non-default feature `parallel-args`; **not enabled**.
**Branch:** `perf/parallel-args` (worktree `.worktrees/parallel-args`).
**Scope:** evaluate whether the per-rule candidate loop over `ARGS` can be
split across a small worker set without changing decisions, anomaly order or
capture variables, and whether it pays off at 1/4/8 KiB. No production
default, rule, proxy or Coraza-reactor behaviour changed.

## Model

A rule's resolved candidates are independent values. The operator scan is the
only side-effect-free part of the current loop; everything else (`budget`
charges, captures, `MATCHED_VARS`, `setvar`/`ctl` actions) mutates `TxState`
and must stay ordered.

The prototype therefore splits evaluation into two deterministic phases:

1. **Evaluate** each candidate on a worker. The worker gets its own
   thread-local `Scratch` (transform cache, gate mask cache, capture
   locations) and a local `Budget`; it returns an immutable
   `CandidateEval { matched, transformed_len, captures, recorded }`.
2. **Reduce** the results in candidate-index order on the request thread. The
   reduction charges the budget, restores `TX:0..9`, records `MATCHED_VAR*`,
   and runs non-disruptive actions exactly where the serial loop would.

`map_ordered` owns the reduction order: thread scheduling can only change
which worker computed an index, never the order of results.

### Safety gate

A rule is routed to the parallel path only when `candidate_local` proves that
no candidate can observe another candidate's actions:

- targets are `ARGS*` collections only;
- the operator is regex/phrase/native-detect/validation (no `%{...}` macro
  operator arguments, so no candidate reads TX the rule itself writes);
- no `ctl:` action (a `ruleRemoveTarget*` cannot change which later candidates
  are evaluated);
- `multiMatch` is excluded.

Captures use one fresh array per candidate. `copy_captures` only copies
non-empty slots, which is identical to the serial rule-level array because a
match overwrites all slots and a later non-capturing match could not have
changed the serial array either.

Worker panics are converted to `EngineError::Internal` (request blocked).
Release builds use `panic = "abort"`, where a worker panic aborts the process
rather than allowing the request.

## Thread model

The prototype uses `std::thread::scope` per call: it is a measurement vehicle,
not the production pool. Thread creation is included in every row. The
production checklist (bounded process-wide pool, reused workers, no allocation
on submit, shared thread budget with the reactor) was deliberately **not**
built: the model already fails the performance gate, and the per-rule
synchronisation cost it would remove is only ~29–58 µs of a 0.9–1.5 ms loss.
Building a pooled dispatcher would add shared state and lifetime hazards to a
path that cannot be enabled. Panic handling is implemented in the prototype
(`catch_unwind` → `EngineError::Internal`, request blocked; release builds use
`panic = "abort"`, which fails closed at process level).

## Measurements

Host: 6 logical CPUs, shared build host (other builds active), release build
(`panic=abort`, LTO). 60 samples per row after 10 warm-ups. `p50/p99` are wall
latency; `cpu` is `CLOCK_PROCESS_CPUTIME_ID` per request across all threads.
Thread creation is included. Source: `--bin parallel-args-bench`.

| body / args | path | threads | p50 µs | p99 µs | cpu µs | vs serial |
|---|---|---:|---:|---:|---:|---:|
| 4 KiB / 1 | serial | 1 | 1204.1 | 1264.5 | 1199.1 | 1.00 |
| 4 KiB / 1 | parallel | 2 | 1201.6 | 1222.6 | 1195.5 | 1.00 |
| 4 KiB / 1 | parallel | 3 | 1198.4 | 1483.7 | 1193.8 | 1.00 |
| 4 KiB / 1 | parallel | 4 | 1200.2 | 1311.3 | 1195.2 | 1.00 |
| 8 KiB / 1 | serial | 1 | 2176.5 | 2304.0 | 2169.1 | 1.00 |
| 8 KiB / 1 | parallel | 2 | 2119.1 | 2352.4 | 2110.4 | 1.03 |
| 8 KiB / 1 | parallel | 3 | 2149.9 | 2401.6 | 2134.9 | 1.01 |
| 8 KiB / 1 | parallel | 4 | 2131.1 | 2229.8 | 2119.2 | 1.02 |
| 4 KiB / 16 | serial | 1 | 1409.9 | 1522.8 | 1403.1 | 1.00 |
| 4 KiB / 16 | parallel | 2 | 2613.2 | 2834.7 | 3369.3 | 0.54 |
| 4 KiB / 16 | parallel | 3 | 2488.3 | 4843.3 | 3781.1 | 0.57 |
| 4 KiB / 16 | parallel | 4 | 2497.4 | 2985.8 | 4116.8 | 0.56 |
| 8 KiB / 16 | serial | 1 | 2502.8 | 2678.9 | 2492.4 | 1.00 |
| 8 KiB / 16 | parallel | 2 | 4061.7 | 4309.2 | 5172.0 | 0.62 |
| 8 KiB / 16 | parallel | 3 | 3993.2 | 4186.7 | 5841.8 | 0.63 |
| 8 KiB / 16 | parallel | 4 | 3914.6 | 12032.0 | 6143.7 | 0.64 |
| 8 KiB / 64 | serial | 1 | 1706.7 | 1758.9 | 1701.2 | 1.00 |
| 8 KiB / 64 | parallel | 2 | 3003.9 | 3091.5 | 3951.2 | 0.57 |
| 8 KiB / 64 | parallel | 3 | 2836.3 | 2969.5 | 4391.3 | 0.60 |
| 8 KiB / 64 | parallel | 4 | 2734.0 | 3062.9 | 4717.4 | 0.62 |

Empty scoped-thread dispatch cost on the same host: ~29 µs (2 threads),
~46 µs (3), ~58 µs (4) per `evaluate` call.

### Interpretation

1. **The gate workload has exactly one ARGS candidate.** The 4/8 KiB rows are
   `data=<payload>` bodies: one decoded argument, so `candidates.len() == 1`
   and the parallel path never activates. The measured 0–3% difference is
   noise. Parallel ARGS inspection is structurally unable to change the
   `4k-allow`/`4k-sqli` gate rows.
2. **Multi-argument bodies get slower, not faster.** Per-rule scoped dispatch
   costs more than the per-candidate work it moves off the calling thread.
   Even at 64 arguments the parallel path is 0.57–0.64× serial and burns
   1.5–2.5× the CPU: each worker re-warms its own transform/gate cache and
   the rule-level reductions still run serially.
3. The prototype already includes thread creation in the comparison, so a
   persistent pool could remove ~29–58 µs per call. That is not enough: the
   multi-arg rows lose 0.9–1.5 ms. The dominant cost is the per-rule
   synchronisation and duplicated cache work, not spawn.

## Decision

**Rejected; not enabled.** The model preserves semantics (2,112/2,112 corpus
cases and 60 generated multi-argument bodies produce identical decisions,
rule order, anomaly scores, early-block flag, operator counts and gate skips),
but it fails the acceptance gate: best 8 KiB gain is ~2.6% (single-arg, within
noise) and best 4 KiB gain ~1.3%, against the required 25% / 15%. Multi-arg
workloads regress. The engine keeps the serial candidate loop; no config or
default selects the parallel path.

If this is revisited, the viable direction is not per-rule dispatch but a
process-wide bounded pool with (a) one work submission per *phase*, (b) a
per-worker transform/gate cache keyed by `(value, pipeline)` that is shared or
partitioned once per request, and (c) a single ordered reduction. That is a
different execution-model change, not a local optimisation.
