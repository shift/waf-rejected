# QuicCrunch transport (optional, not production-ready)

**Status:** seam landed, dependency not vendored, transport stubbed.
**Feature:** `quiccrunch-transport` (non-default, implies `distri-kv`).
**Default:** `waf.distributed.transport = "grpc"` — unchanged.

The distributed client now has one transport seam
(`src/waf/distributed/transport.rs`). The controller, policy/reputation caches,
lease pool, policy verification and `fallback = "local_only"` only see the
`TransportClient` trait, so selecting QuicCrunch is a configuration switch, not
a controller rewrite.

## Enablement

```toml
[waf.distributed]
enabled = true
transport = "quiccrunch"
node_id = "waf-eu-1"
region = "eu-west-1"
fallback = "local_only"

[waf.distributed.quiccrunch]
endpoint = "quic://dkv-eu.example:7443"
server_name = "dkv-eu.example"
ca_cert_path = "/etc/waf/certs/ca.pem"
client_cert_path = "/etc/waf/certs/waf.pem"
client_key_path = "/etc/waf/certs/waf-key.pem"
```

There is **no insecure mode**. All five QuicCrunch fields are required once
`enabled = true` and `transport = "quiccrunch"`; a missing CA, client cert or
client key is a startup error. The client must present the configured client
certificate/key and verify the server against the configured CA.

Selecting `transport = "quiccrunch"` in a build without the feature is rejected
during config validation, even when `enabled = false`. It never silently falls
back to gRPC.

## What is implemented today

| Piece | State |
| --- | --- |
| Transport trait seam | Landed (`TransportClient`, `TransportRoles`, `split_transport`) |
| gRPC (tonic) implementation | Landed behind the seam, behaviour unchanged |
| Config enum + `[waf.distributed.quiccrunch]` | Landed with strict validation |
| `FakeQuicCrunchTransport` for controller tests | Landed |
| Real `quiccrunch-core` dependency | **Not vendored** |
| Real QuicCrunch client | **Stub**: construction fails closed with an actionable error |

Enabling `--features quiccrunch-transport` compiles, but controller startup
fails with an error pointing here until the dependency is vendored. This is
intentional: a stub must not ship control-plane traffic over an unverified
transport.

## Dependency / vendoring step

`quiccrunch-core` is **not published on crates.io** (checked 2026-11-10), so
the dependency must come from git, pinned to a rev. The Nix build resolves the
Cargo graph offline, so the lock file and Nix vendor derivation must be updated
in the same commit.

1. Add the optional dependency to the root `Cargo.toml` (repository
   `shift/quiccrunch`, pinned to `main` at `e64e86f`; the 2026-11-09 evaluation
   in [`docs/design/quiccrunch-evaluation.md`](../design/quiccrunch-evaluation.md)
   was at `4ee1ec4`):

   ```toml
   quiccrunch-core = { git = "https://github.com/shift/quiccrunch", rev = "e64e86f", optional = true, default-features = false }
   ```

2. Wire it into the feature:

   ```toml
   quiccrunch-transport = ["distri-kv", "dep:quiccrunch-core"]
   ```

3. `nix develop -c cargo update -p quiccrunch-core` and commit `Cargo.lock`.
4. Update the Nix Cargo vendoring input/hash used by `craneLib.buildDepsOnly`
   in `flake.nix` (this repository currently lets crane resolve `Cargo.lock`
   during the fixed-output dependency derivation; changing the lock changes
   that derivation). Re-run `nix build .#waf-ingress` before committing.
5. Replace `src/waf/distributed/quiccrunch.rs::build` with the real client:
   map the same RPCs, present `client_cert_path`/`client_key_path`, verify
   against `ca_cert_path` and `server_name`, and never enable an insecure
   verification mode.

## Known blockers (do not treat as production-ready)

- **tQUIC peer-certificate access.** The tQUIC 1.6 client exposed no peer
  certificate at evaluation time, so SPIFFE-bound mTLS identity cannot be
  derived at the transport layer. Any workaround (patching tQUIC or carrying a
  signed application-layer identity assertion) adds bespoke security code to
  the control plane.
- **Client verification was disabled by default.** `TlsConfig::new_client_config`
  never called `set_verify(true)` or loaded the CA; `verify_cert`/`ca_cert_file`
  were dead fields. A real client must prove verification is on, with tests.
- **No SPIFFE representation.** The DistriWaf design requires mTLS + a SPIFFE
  identity assertion; QuicCrunch has no client-certificate or SPIFFE surface.
- **Raft surface.** QuicCrunch is a transport, not a consensus implementation.
  The WAF is a client only; it still depends on distri-kv's Raft-backed
  `DistriWaf` semantics (`GetPolicy`, watch resume, reputation TTL, leases).
  QuicCrunch does not supply those, and distri-kv's Raft endpoints
  (`ChangeConfig`, etc.) are not a WAF-facing contract.
- **No watch resume/backpressure** parity with the gRPC streaming path.
- The evaluation measured 10–16 engineer-weeks of remaining work for parity on
  a capability gRPC already provides.

## Rollback switch

Set `waf.distributed.transport = "grpc"` and restart. No other config changes
are needed: the gRPC implementation, endpoints, mTLS and `local_only` fallback
are unchanged. If a QuicCrunch build is rolled back to a binary without the
feature, the config validator fails closed until the transport is switched
back to `grpc`.

## Tests

Transport-agnostic controller tests run the same set of operations (register,
heartbeat, policy watch/refresh, reputation, counters, event ingest, reconnect,
deadline expiry, `local_only` fallback activation) against the mock tonic
server and `FakeQuicCrunchTransport`. Config tests pin the gRPC default, reject
unknown transport values and prove `quiccrunch` without the feature fails
closed with an actionable message.