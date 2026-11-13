# Support Policy

This policy states how long WAF-Rejected releases are supported, what a security
patch can be expected to contain, and when a release reaches end of life. It is
the project's own commitment; it does not by itself satisfy any regulatory
obligation of a party that distributes WAF-Rejected as part of a product.

## Current support matrix

| Release line | Status | Security fixes | Support ends |
|---|---|---|---|
| `0.1.0-beta.x` (latest beta) | Supported | Yes | When superseded, plus 90 days |
| Previous beta | Limited | Critical and high only | 90 days after the successor ships |
| Older pre-releases | End of life | No | Already ended |
| `main` (unreleased) | Development | Fixes land here first | Not a release |

The project is in beta. Beta releases are not covered by a multi-year support
period. Each beta is superseded by the next beta, and the superseded beta keeps
receiving critical and high severity fixes for 90 days so that operators have a
realistic upgrade window.

## Planned support period after 1.0

Once a stable `1.0` line exists, the intent is:

- **Support period:** 3 years from the release date of a minor version, with
  security updates for the full period.
- **Overlap:** at least 6 months of overlap between consecutive minor versions,
  so an upgrade never forces an immediate cut-over.
- **Long-term line:** if an LTS line is published, its support period is stated
  in the release notes at publication time, not retroactively.

These are planning targets, not a contractual SLA. Any change is announced in
`CHANGELOG.md` before the affected release, and shortening a support period for
an already published release requires a security advisory explaining the
reason.

## What a security patch contains

| Severity | Target | Content |
|---|---|---|
| Critical (remote bypass, RCE, auth bypass) | Fix release within 14 days of triage | Minimal patch, advisory, updated SBOM, container image, backport to the supported previous beta |
| High (DoS, information disclosure, TLS/proxy weakness) | Fix release within 30 days | Patch, advisory, updated SBOM, container image |
| Medium | Next scheduled release | Patch and changelog entry |
| Low / hardening | Best effort | Changelog entry, may be batched |

A security release always includes:

- A GitHub security advisory describing affected versions, impact, CVSS where
  assigned, and mitigations that work before upgrading.
- A new container image tag plus the immutable digest in the release notes.
- A CycloneDX SBOM attached to the release, regenerated from the fixed
  dependency graph.
- An entry in `CHANGELOG.md` under the release version.

There is no guarantee of a CVE identifier for every issue; the project requests
one for issues that affect downstream products or are publicly known.

## Upgrade expectations

- Configuration remains backward compatible within a minor line. New options
  default to the previous behaviour; a removed or renamed option is called out
  in `CHANGELOG.md` with a migration note.
- The Sled event store and on-disk layout remain readable across patch and minor
  upgrades. If a format change is unavoidable, the release notes state the
  migration step and whether rollback preserves events.
- Rolling back to the previous image digest is supported for the duration of the
  overlap window. See [`container.md`](container.md) for the procedure.

## End of life

A release is end of life when its support window closes. At that point:

1. The support matrix above and the release notes are updated.
2. A final advisory states the end-of-life date, the last supported version and
   the recommended upgrade target.
3. No further fixes, images or SBOMs are published for that line. Existing
   images and advisories stay available, but are not maintained.
4. Operators still running an end-of-life release are expected to treat
   vulnerability reports against it as unfixed.

End-of-life is announced at least 90 days in advance, except where a critical
security issue forces an earlier retirement of a line that cannot be patched
safely.

## How this maps to CRA manufacturer expectations

Regulation (EU) 2024/2847 places duties on the manufacturer of a product with
digital elements. When WAF-Rejected is integrated into such a product, this
policy is intended to give the manufacturer the inputs it needs:

| CRA expectation | Where it is addressed |
|---|---|
| Determine and publish a support period | Support matrix and the planned 1.0 support period above |
| Provide security updates for the support period | Patch targets, security release contents |
| Identify and document vulnerabilities and components | CycloneDX SBOM on every release, dependency inventory from `Cargo.lock` |
| Address vulnerabilities without delay | Triage and fix targets, private advisory workflow |
| Apply effective and regular security testing | CI checks, integration tests, release checklist |
| Coordinated vulnerability disclosure policy | [`SECURITY.md`](../../SECURITY.md) |
| Report actively exploited vulnerabilities and severe incidents | Article 14 timeline in [`SECURITY.md`](../../SECURITY.md) |
| Inform users about end of support | End-of-life process above |
| Provide security information to users | Advisories, `CHANGELOG.md`, release notes, this policy |

The manufacturer remains responsible for conformity assessment, CE marking,
technical documentation, the actual support-period commitment in its own
declaration, and submission of Article 14 reports to ENISA and its CSIRT. This
repository supplies evidence and process, not a certificate. See
[`docs/compliance/eu-regulatory-status.md`](../compliance/eu-regulatory-status.md).

## Contact

Security reports: see [`SECURITY.md`](../../SECURITY.md).
Support questions and non-security bugs: open a GitHub issue.
