# Operations Runbook

Per-alert triage for the WAF-Rejected monitoring stack. Every alert in
`infrastructure/monitoring/alert_rules.yml` links to a section here. The
dashboard is `infrastructure/monitoring/dashboards/waf-overview.json`.

## General triage order

1. Confirm the alert is real: check the dashboard panels for the same window
   and compare with `waf_requests_total` so a low-traffic artefact is not
   mistaken for an incident.
2. Check recent changes: config rollout, rule/allowlist update, image tag,
   `waf.coraza` policy, `waf.admission` limits.
3. Prefer reversible mitigations (raise limits, switch backend, roll back the
   config) over disabling inspection. Never disable Coraza or admission
   control to clear an alert.
4. Record the observed values and the mitigation in the incident ticket.

## Capacity guidance

The reference capacity numbers and acceptance gates are in
[`performance-validation.md`](performance-validation.md). Key points for
on-call:

- The reference laptop (6 logical CPUs, reactor pool auto = 6) is beta-ready
  for bodyless and gRPC traffic up to roughly 16 concurrent connections /
  ~1.5 kRPS. It is **not** beta-ready for untrusted 8–60 KiB bodies at c=64,
  for 16 KiB bodies at c=16, or for 60 KiB bodies mixed with latency-sensitive
  traffic.
- The 60 KiB isolation gate is the canary: 10% maximum-size bodies at c=64
  pushed bodyless p95 to 6.5 s on the reference host. If that pattern appears
  in production, treat it as a capacity incident, not a tuning nuisance.
- Peak RSS on the reference run was 1803 MiB with 95.8% growth, both above the
  beta gates. Size memory from the target host's measured RSS, not from the
  reference laptop.
- Capacity claims must state the body policy (`inspect-all`,
  `forward-uninspected` + `max_inspect_bytes`, or `reject` +
  `max_inspect_bytes`). A smaller prefix or `reject` changes which rows of the
  capacity table are meaningful.
- For per-layer latency (raw reactor, engine, payload, proxy with and without
  the WAF) and the sub-millisecond gates, see
  [`subms-budget.md`](subms-budget.md). Use it before attributing a latency
  regression to the rule engine or to the proxy.
- The native Coraza sidecar removes the ~5–6× Go-to-wasm body-inspection
  penalty (8 KiB p50 358 → 61 ms, 60 KiB 2779 → 457 ms on the research
  laptop). It is the first mitigation for sustained heavy-body latency.

## CorazaAdmissionHeavyRejections

**Symptom:** `waf_admission_rejected_total` is a sustained fraction of
`waf_coraza_evaluations_total`; clients see `503` with `Retry-After`.

**Likely cause:** heavy (CRS body) inspections exceed `heavy_permits` or wait
longer than `queue_timeout_ms`; a burst of large bodies, a slow upstream, or a
pool that is too small for the body mix.

**Immediate mitigation:**

1. Check `waf_admission_queue_depth`, `waf_admission_inflight{class="heavy"}`
   and `waf_admission_wait_duration_seconds` on the dashboard.
2. Raise `waf.admission.heavy_permits` (bounded by `pool_size - 1`) and/or
   `max_queued`/`queue_timeout_ms` if the host has headroom.
3. If the body mix is the problem, switch to the native Coraza backend
   (`waf.coraza.backend = "native"`) or apply a documented body policy
   (`max_inspect_bytes` + `oversize_action`) after confirming the security
   tradeoff.
4. Scale out replicas if the host is CPU-saturated.

**Escalation:** security architecture if the only fix is to reduce inspection
coverage; platform/SRE if the host is out of CPU or memory.

## CorazaAdmissionQueueSaturated

**Symptom:** `waf_admission_queue_depth > 0` for 2 minutes.

**Likely cause:** all heavy permits are busy and new heavy requests are
waiting; usually the same trigger as heavy rejections, one step earlier.

**Immediate mitigation:** same as
[CorazaAdmissionHeavyRejections](#corazaadmissionheavyrejections). If queue
depth is rising and rejections are not yet visible, act now: raise
`heavy_permits`, shed non-critical heavy traffic at the edge, or move to the
native backend.

**Escalation:** platform/SRE for capacity; security architecture for any
inspection-coverage change.

## CorazaBodyTruncationSpike

**Symptom:** `waf_coraza_body_truncated_total` rises above 1/s for 5 minutes.

**Likely cause:** `waf.coraza.max_inspect_bytes` is smaller than the normal
request-body size, so a large share of bodies is only partially scanned. This
is expected only when the policy was deliberately chosen.

**Immediate mitigation:**

1. Confirm the active policy from the config and the start-up warning.
2. If truncation is unintended, raise `max_inspect_bytes` or return to
   `inspect-all` (default `0`).
3. If truncation is intentional, verify the documented coverage gap is
   accepted and that the alert threshold matches the expected traffic mix.
4. Do not silently switch to `forward-uninspected` to clear the alert.

**Escalation:** security architecture for any decision that leaves part of a
body uninspected.

## CorazaBodyRejectionSpike

**Symptom:** `waf_coraza_body_rejected_total` rises above 0.5/s for 5 minutes;
clients receive `413`.

**Likely cause:** `oversize_action = "reject"` with a `max_inspect_bytes`
below the body sizes clients send, or a client sending unexpectedly large
payloads.

**Immediate mitigation:**

1. Identify the affected routes/clients from logs and the body-size
   distribution panel.
2. If the limit is too low, raise `max_inspect_bytes` or switch to
   `forward-uninspected` after accepting the documented gap.
3. If the traffic is abusive, keep `reject` and block/rate-limit the source.
4. Verify the `413` is intentional and documented for the API contract.

**Escalation:** security architecture for policy changes; application owner
for client payload changes.

## CorazaEvaluationDurationSLOBurn

**Symptom:** Coraza p99 evaluation duration is above 0.5 s for 10 minutes.

**Likely cause:** large bodies under `inspect-all`, reactor contention, a
small pool, or the wasm backend's body-inspection penalty.

**Immediate mitigation:**

1. Check the Coraza duration heatmap and the body-size distribution.
2. Raise the reactor pool size if CPU headroom exists (`waf.coraza.pool_size`,
   auto = cores clamped to 8).
3. Switch to the native Coraza backend for heavy-body workloads.
4. Apply a documented body policy if the latency budget cannot be met with
   full inspection.
5. Scale out replicas if a single host is saturated.

**Escalation:** platform/SRE for capacity; security architecture for
inspection-coverage tradeoffs.

## GrpcBlockRateAnomaly

**Symptom:** more than 20% of gRPC protocol decisions are blocks for 5
minutes, with at least 0.1 decisions/s.

**Likely cause:** a bad allowlist/descriptor rollout, tightened field limits
(`max_string_bytes`, `max_bytes_len`, `max_repeated`, `max_depth`,
`reject_unknown_fields`), or an active attack against gRPC methods.

**Immediate mitigation:**

1. Compare the block reason in security events with the last allowlist or
   descriptor change.
2. Roll back the allowlist/descriptor artifact if the change is the trigger.
3. If the traffic is malicious, keep blocking and rate-limit the source.
4. Do not switch gRPC inspection off; the raw protobuf body is deliberately
   withheld from CRS.

**Escalation:** service owner for the gRPC contract; security architecture for
allowlist/limit changes.

## GraphqlBlockRateAnomaly

**Symptom:** more than 20% of GraphQL protocol decisions are blocks for 5
minutes, with at least 0.1 decisions/s.

**Likely cause:** an operation allowlist change, tightened depth/alias/field
limits, a mutation/subscription policy change, or an attack.

**Immediate mitigation:**

1. Check the block reason and operation name/hash in security events.
2. Roll back the allowlist or limit change if it is the trigger.
3. If the traffic is malicious, keep blocking and rate-limit the source.
4. In `graphql-only` mode, remember the raw body is withheld from CRS; do not
   disable the GraphQL pre-check to "restore" body scanning.

**Escalation:** service owner for the GraphQL schema/operations; security
architecture for allowlist/limit changes.

## ReactorPoolExhaustion

**Symptom:** heavy inspections are queued while heavy in-flight work is
non-zero for 5 minutes. Direct reactor pool/worker gauges are not exported;
admission queue depth is the available pool-pressure signal.

**Likely cause:** the reactor pool is fully occupied by heavy body scans, a
worker is wedged, or the pool is undersized for the body mix.

**Immediate mitigation:**

1. Check `waf_admission_inflight{class="heavy"}`, queue depth and Coraza
   errors. A rising error count with queue depth suggests a wedged worker.
2. Raise `waf.coraza.pool_size` if CPU headroom exists, and raise
   `waf.admission.heavy_permits` only up to `pool_size - 1`.
3. Switch to the native Coraza backend for heavy-body workloads.
4. Restart the pod only if workers are wedged and the queue does not drain;
   capture `/metrics` and logs first.
5. Scale out replicas if the host is saturated.

**Escalation:** platform/SRE for capacity and restarts; security architecture
for any inspection-coverage change.

## CorazaEvaluationErrorRate

**Symptom:** more than 5% of Coraza evaluations fail for 2 minutes; with
`fail_mode = closed` clients receive `503`.

**Likely cause:** reactor trap/timeout, module or rule load failure, payload
that exceeds reactor limits, or a wedged worker.

**Immediate mitigation:**

1. Check Coraza errors, evaluation duration and admission queue depth.
2. If the error started after a rule/module change, roll it back.
3. If workers are wedged, restart the pod after capturing diagnostics.
4. Switch to the native backend if the wasm reactor is the failing component.
5. Do not set `fail_mode = open` to clear the alert.

**Escalation:** security architecture for rule/module changes; platform/SRE
for restarts and capacity.

## CorazaBlockSpike

**Symptom:** Coraza blocks more than 10 requests/s for 2 minutes.

**Likely cause:** an active attack, a new/tightened rule, or a false-positive
rule rollout.

**Immediate mitigation:**

1. Inspect the top rule IDs and client sources in security events.
2. If a recent rule change caused it, roll back the rule.
3. If it is an attack, keep blocking and consider edge rate limiting.
4. Do not disable Coraza to clear the alert.

**Escalation:** security operations for attack confirmation; security
architecture for rule changes.

## HighRequestLatency

**Symptom:** request p95 is above 0.5 s for 5 minutes.

**Likely cause:** heavy body inspection, reactor/admission contention, upstream
slowness, or host saturation.

**Immediate mitigation:**

1. Split the latency by checking Coraza duration, admission wait and upstream
   error panels.
2. If Coraza/admission is the cause, follow
   [CorazaEvaluationDurationSLOBurn](#corazaevaluationdurationsloburn).
3. If upstream is the cause, escalate to the upstream owner.
4. Scale out if the host is saturated.

**Escalation:** platform/SRE for capacity; upstream owner for upstream
latency.

## Metric gaps

The following are **not** exported by the WAF `/metrics` endpoint and must not
be invented in dashboards or alerts:

- reactor pool size, idle workers, busy workers, worker restarts;
- process RSS / working set.

Use admission queue depth, heavy in-flight and Coraza errors as pool-pressure
proxies, and scrape container RSS from cAdvisor/kubelet
(`container_memory_working_set_bytes`). Adding direct pool gauges would be a
small, bounded-cardinality follow-up (one series per pool, not per worker).
