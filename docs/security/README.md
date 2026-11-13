# Security Documentation

This directory holds the material an external reviewer, penetration tester or
downstream manufacturer needs in order to evaluate WAF-Rejected. It indexes the
security documents that live elsewhere in the repository; it is not a second
source of truth for any control.

## Penetration-test readiness

- [**Penetration-test readiness pack**](pen-test-scope.md) — the entry point for
  an external engagement. System description, trust boundaries, in-scope
  components, out-of-scope boundary, threat model, 86 concrete test cases,
  stand-up commands, the comparable baseline config
  ([`config/pentest.toml`](../../config/pentest.toml)), known limitations and
  the remediation process.
- [Security architecture and threat model](../architecture/security-model.md) —
  the authoritative control-status matrix (code, test and release for every
  claim), request lifecycle, bypass classes and residual risks. The pen-test
  pack is subordinate to this document; where they differ, this one wins.

## Policy and process

- [`SECURITY.md`](../../SECURITY.md) — supported versions, private disclosure
  channels, response commitments, CRA Article 14 alignment and scope.
- [Support policy](../operations/support-policy.md) — support period, patch
  targets and end of life.
- [Supply-chain policy](../operations/supply-chain.md) — advisories, SBOM,
  provenance, Trivy policy.
- [Release checklist](../operations/release-checklist.md) — gates a release
  must pass, including security-model re-verification.

## Boundary and operations

- [Module scope and quarantine boundary](../operations/module-scope.md) —
  which features are inside the review boundary and which are quarantined.
- [Deployment guide](../operations/deployment.md) — the deployment shapes the
  security model assumes.
- [Container operations](../operations/container.md) — image, ports, digest
  pinning.
- [Monitoring](../operations/monitoring.md) — metrics, alerts and evidence.
- [Soak and fault-injection testing](../operations/soak-testing.md) — the
  stability harness referenced by the pen-test pack.
- [Distributed deployment](../operations/distributed-deployment.md) — the
  optional distri-kv client and why the server is out of scope.

## Regulatory context

- [EU regulatory status](../compliance/eu-regulatory-status.md) — CRA, NIS2 and
  the limits of the compliance evidence packs. Nothing here is a
  certification.

## Related audit material

- [Security audit, November 2026](../audit/security-audit-2026-11.md) — the
  request-path audit that preceded this pack. It is a source-review snapshot;
  later commits added regression tests for its findings. The pen-test pack
  exists because that audit examined documentation and source, not a running
  target.
