# Distributed deployment (WAF + distri-kv)

Operational guide for the regional distributed security fabric. The design and
threat model are in
[ADR-0007](../design/distributed-waf-architecture.md); the WAF-side client
contract is in [distributed.md](distributed.md). This page covers the
deployment artifacts in [`deploy/distributed`](../../deploy/distributed).

> **Read this first — current integration limits.**
>
> 1. The WAF client in this revision does **not** attach bearer or SPIFFE
>    metadata. `distri-kv` fails closed with `UNAUTHENTICATED` unless a trusted
>    sidecar injects credentials. The WAF nodes therefore stay in
>    `fallback = "local_only"` and report `waf_distributed_connected 0`. This
>    is expected, and is the exact fallback path the smoke test verifies.
> 2. `DistriWaf` policy/registry/reputation state in `distri-kv` `9079588`
>    uses the node-local storage adapter. The Raft proposal path for these
>    objects is still a prerequisite in the ADR. Until it lands, a
>    load-balanced `dkv-client` Service can expose different views from
>    different pods. Pin one authoritative endpoint per regional cell, or
>    route consistently, and do not treat the cell as a strongly consistent
>    shared store.
> 3. The published `ghcr.io/shift/waf-rejected-waf` image does not include the
>    non-default `distri-kv` feature. Build
>    [`Dockerfile.waf`](../../deploy/distributed/Dockerfile.waf) or use an
>    internal image built with `--features ...,distri-kv`.

## Topology

| Component | Count | Ports | Notes |
| --- | --- | --- | --- |
| distri-kv regional cell | 3 | gRPC `7443`, Raft `8443`, health `8082`, metrics `9091` | Raft transport is always `gRPC port + 1000`. Health/metrics bind `127.0.0.1`, so probe with `exec`. |
| WAF nodes | 2 | proxy `8080`, health/metrics `8081` | `[waf.distributed]` enabled, `fallback = "local_only"`, `shadow = true`. |
| Upstream | 1 | `3000` | Demo only (`hashicorp/http-echo`). |

Compose publishes only loopback ports, uses project-scoped networks/volumes
and is safe to run next to a development WAF. The Kubernetes manifests use a
3-replica StatefulSet, stable headless Service DNS, a client Service, two WAF
replicas, PDBs and required pod anti-affinity.

## Prerequisites

- A distri-kv image built from a checkout at contract commit `9079588` or
  later:

  ```bash
  docker build -f deploy/distributed/Dockerfile.distri-kv \
    -t distri-kv:9079588 /path/to/distri-kv
  ```

  The image must contain `/bin/sh` and `curl`; the manifests use them for node
  identity and local health probes.
- A WAF image with the feature:

  ```bash
  docker build -f deploy/distributed/Dockerfile.waf \
    -t waf-rejected-distributed:local .
  ```

  The release image does not include `distri-kv`.
- OpenSSL for local certificates and the bearer token.

## Compose quick start

```bash
./scripts/gen-distri-certs.sh

export DISTRI_KV_IMAGE=distri-kv:9079588
export WAF_IMAGE=waf-rejected-distributed:local
docker compose -f deploy/distributed/compose.yaml up -d

curl -fsS http://127.0.0.1:18081/health/ready
curl -fsS http://127.0.0.1:18081/metrics | grep waf_distributed_
```

The script writes `deploy/distributed/certs/` (CA, server, client) and
`deploy/distributed/secrets/waf-token` (bearer token). Both directories are
gitignored. `--force` replaces them; `--no-token` leaves the token alone.

Use `./scripts/demo-distributed.sh` for an automated start, verification and
teardown. It derives isolated host ports and a unique Compose project name,
so two runs do not share volumes or listeners.

## Bootstrap the cluster and register nodes

1. **Start the regional cell.** Wait for all three distri-kv nodes to report
   healthy. Because health binds loopback, probe from inside the container:

   ```bash
   for n in dkv-1 dkv-2 dkv-3; do
     docker compose -f deploy/distributed/compose.yaml exec -T "$n" \
       curl -fsS http://127.0.0.1:8082/health
   done
   ```

2. **Verify the WAF nodes loaded the distributed block.** The gauges are
   emitted even while disconnected:

   ```bash
   curl -fsS http://127.0.0.1:18081/metrics \
     | grep -E 'waf_distributed_(connected|heartbeat_age_seconds|policy_generation|fallback_activations_total)'
   ```

   `connected 0` is expected until WAF-side auth metadata is available; WAF
   readiness must remain `200`.

3. **Register WAF nodes (direct control-plane verification).** The current
   WAF client cannot authenticate, so use `grpcurl` with the bearer token to
   validate the registry path:

   ```bash
   TOKEN="$(cat deploy/distributed/secrets/waf-token)"
   ADDR=127.0.0.1:17443
   PROTO=(-import-path src/waf/distributed -proto distri_waf.proto)

   grpcurl -plaintext -H "authorization: Bearer $TOKEN" "${PROTO[@]}" \
     -d '{"contract_version":1,"request_id":"waf-1","lease_ttl_secs":30,
          "node":{"node_id":"waf-1","region":"eu-west-1",
                  "endpoint":"https://waf-1.example:8443",
                  "capabilities":["waf"],"epoch":1}}' \
     "$ADDR" waf.distri.v1.DistriWaf/Register
   ```

   Repeat for `waf-2`. The lease is 30 s; the WAF controller would refresh it
   once client auth is wired. `Discover` lists live nodes in the region.

4. **Exercise policy and reputation.**

   ```bash
   grpcurl -plaintext -H "authorization: Bearer $TOKEN" "${PROTO[@]}" \
     -d '{"contract_version":1,"scope":"default","bundle_version":1,
          "reason":"bootstrap","idempotency_key":"bootstrap-1",
          "bundle":{"contract_version":1,"schema_version":1,
                    "scope":"default","version":1,"generation":1,
                    "payload":{"ruleset_version":"bootstrap"}}}' \
     "$ADDR" waf.distri.v1.DistriWaf/ActivatePolicy

   grpcurl -plaintext -H "authorization: Bearer $TOKEN" "${PROTO[@]}" \
     -d '{"contract_version":1,"scope":"default","version":0}' \
     "$ADDR" waf.distri.v1.DistriWaf/GetPolicy

   grpcurl -plaintext -H "authorization: Bearer $TOKEN" "${PROTO[@]}" \
     -d '{"contract_version":1,"ips":["203.0.113.9"],"scope":"default",
          "max_age_ms":300000}' \
     "$ADDR" waf.distri.v1.DistriWaf/LookupReputation
   ```

   Reputation upsert is a server API for the correlator, not a WAF RPC; a
   fresh cell returns an empty `entries` list. That is a successful lookup.

5. **Test fallback.** Stop the cell and confirm the WAF still serves:

   ```bash
   docker compose -f deploy/distributed/compose.yaml stop dkv-1 dkv-2 dkv-3
   curl -fsS http://127.0.0.1:18081/health/ready
   curl -fsS http://127.0.0.1:18081/metrics | grep waf_distributed_connected
   docker compose -f deploy/distributed/compose.yaml start dkv-1 dkv-2 dkv-3
   ```

   Readiness must stay `200`; the request path never waits on the cluster.
   `waf_distributed_fallback_activations_total` (after a lookup requires
   fallback) and queue-drop counters show degradation, not failure.

## Kubernetes

1. Build and push the two images to your registry, then update the image
   references in `deploy/distributed/kubernetes/10-distri-kv.yaml` and
   `20-waf.yaml`. Nothing in this repository pushes images.
2. Replace the Secret placeholders in `10-distri-kv.yaml`:

   ```bash
   kubectl create namespace waf-distributed --dry-run=client -o yaml | kubectl apply -f -
   kubectl -n waf-distributed create secret generic distri-waf-auth \
     --from-file=waf-token=deploy/distributed/secrets/waf-token \
     --dry-run=client -o yaml | kubectl apply -f -
   kubectl -n waf-distributed create secret generic distri-waf-tls \
     --from-file=ca.crt=deploy/distributed/certs/ca.crt \
     --from-file=server.crt=deploy/distributed/certs/server.crt \
     --from-file=server.key=deploy/distributed/certs/server.key \
     --from-file=client.crt=deploy/distributed/certs/client.crt \
     --from-file=client.key=deploy/distributed/certs/client.key \
     --dry-run=client -o yaml | kubectl apply -f -
   ```

3. Apply and verify:

   ```bash
   kubectl apply -k deploy/distributed/kubernetes
   kubectl -n waf-distributed rollout status statefulset/distri-kv
   kubectl -n waf-distributed rollout status deployment/waf-rejected
   kubectl -n waf-distributed exec distri-kv-0 -- \
     curl -fsS http://127.0.0.1:8082/health
   kubectl -n waf-distributed port-forward svc/waf 8081:8081
   curl -fsS http://127.0.0.1:8081/metrics | grep waf_distributed_
   ```

   The StatefulSet sets `--node-id "$((ordinal + 1))"` and peers
   `1..3` at `dkv-{0,1,2}.dkv-headless:8443`; the Raft port is the gRPC port
   plus 1000. The PDB keeps two distri-kv pods available during voluntary
   disruption; required anti-affinity keeps one pod per node.

4. Before production, verify that the cluster's WAF-object replication story
   matches the ADR. As noted above, `9079588` stores `DistriWaf` state per
   node. Do not scale the WAF fleet against a load-balanced Service until
   either the Raft proposal path lands or you pin an authoritative endpoint.

## Rotate tokens and certificates

`--force` replaces the existing files. `--no-token` leaves the token alone;
without it, a `--force` run rotates both the certificates and the bearer
token. Restart distri-kv after either change so the new files are read:

```bash
./scripts/gen-distri-certs.sh --force
docker compose -f deploy/distributed/compose.yaml restart dkv-1 dkv-2 dkv-3
# Kubernetes: update distri-waf-auth as well, then:
kubectl -n waf-distributed create secret generic distri-waf-tls \
  --from-file=ca.crt=deploy/distributed/certs/ca.crt \
  --from-file=server.crt=deploy/distributed/certs/server.crt \
  --from-file=server.key=deploy/distributed/certs/server.key \
  --from-file=client.crt=deploy/distributed/certs/client.crt \
  --from-file=client.key=deploy/distributed/certs/client.key \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl -n waf-distributed rollout restart statefulset/distri-kv
```

The generated server certificate covers `dkv-1..3`, `dkv-client`,
`dkv-headless`, `localhost` and `127.0.0.1`. The client certificate carries a
SPIFFE URI SAN. Re-run the script with `TRUST_DOMAIN`/`REGION` set if your
identity namespace differs.

## Metrics and alerts

WAF (`8081/metrics`): the families in [distributed.md](distributed.md#metrics).
Key signals:

- `waf_distributed_connected` should be `1` once client auth is wired; `0`
  while the stack is intentionally in local-only fallback.
- `waf_distributed_heartbeat_age_seconds` growing past the lease interval.
- `waf_distributed_fallback_activations_total` and
  `waf_distributed_reconnects_total` rate.
- `waf_distributed_queue_dropped_total` for telemetry pressure; requests are
  never blocked.
- `waf_distributed_policy_rejected_total`, `waf_distributed_stale_policy_total`.

distri-kv (`9091/metrics`, loopback inside the pod/container) exposes the
`distri_waf_*` families, including registry/policy/reputation counters and
the local event/counter queues. Scrape through a sidecar or pod annotation;
a remote Service target cannot reach a loopback listener.

## Troubleshooting

| Symptom | Likely cause | Action |
| --- | --- | --- |
| WAF `connected 0`, logs `Unauthenticated` | WAF client cannot attach bearer/SPIFFE metadata | Expected in this revision; keep `local_only` and verify the control plane with `grpcurl`, or terminate auth in a sidecar. |
| distri-kv pod crashes at startup | Missing token file or invalid cert path with `tls_enabled = true` | Create the Secret/cert volume; keep `tls_enabled = false` for the bearer demo. |
| `GetPolicy` returns an old version from one pod | Node-local DistriWaf storage / load-balanced client Service | Pin one endpoint; see the integration limit above. |
| Health probe fails in Kubernetes | Health binds `127.0.0.1` | Use `exec` probes (the manifests do) or a sidecar. |
| `dkv-client` cannot resolve peers | Headless Service DNS or ordinal command | Check `dkv-{0,1,2}.dkv-headless` and the `--peers` argument. |
| WAF cannot start with `distri-kv` config | Release image lacks the feature | Build `Dockerfile.waf` or use an internal image with the feature. |

## Related

- [Distributed client operations](distributed.md)
- [ADR-0007](../design/distributed-waf-architecture.md)
- [distri-kv capability audit](../design/distri-kv-audit.md)
- [Security model](../architecture/security-model.md)
- [Support matrix](support-matrix.md)
