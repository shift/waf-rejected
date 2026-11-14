# Governance

WAF-Rejected is a maintainer-led open-source project. This document describes
how decisions are made and how maintainers are added or removed.

## Roles

- **Users** — deploy the project, report bugs, propose features.
- **Contributors** — submit issues, documentation, tests, or code.
- **Reviewers** — contributors trusted to review pull requests in a subsystem.
- **Maintainers** — reviewers with merge rights and responsibility for
  releases, security response, and project direction.

The current maintainers are listed in [`MAINTAINERS.md`](MAINTAINERS.md).

## Decision making

- Day-to-day changes are decided by lazy consensus in the relevant issue or
  pull request.
- A maintainer must approve every pull request. Security-sensitive changes
  (inspection logic, TLS, authentication, fail-mode behaviour, rule handling)
  require approval from two maintainers.
- Larger changes (new engines, protocol support, default-behaviour changes,
  licensing changes) require an issue with a design proposal and explicit
  maintainer approval before implementation.
- If consensus cannot be reached, maintainers decide by simple majority; the
  rationale is recorded in the issue or advisory.

## Adding maintainers

A contributor may be nominated by an existing maintainer after sustained,
high-quality contributions and demonstrated judgement on security-sensitive
changes. Nomination requires approval from all current maintainers.

## Removing maintainers

A maintainer may step down at any time. Inactive maintainers (no review or
release activity for six months) may be moved to emeritus status by consensus
of the remaining maintainers. Maintainer access may be revoked immediately for
Code of Conduct violations or security negligence.

## Releases

Releases follow the support policy in
[`docs/operations/support-policy.md`](docs/operations/support-policy.md).
- While the project is in beta, only the latest pre-release is fully supported.
- Release notes, checksums, SBOMs and provenance attestations are published
  with every release where tooling permits.

## Security

Security reports follow [`SECURITY.md`](SECURITY.md). Maintainers coordinate
disclosure and credit. Do not discuss suspected vulnerabilities in public
issues.

## Changes to this document

Changes require approval from all current maintainers.
