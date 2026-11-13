# Security Policy

WAF-Rejected is a security component: it inspects and forwards production
traffic. We take reports about it seriously and welcome coordinated disclosure.

**WAF-Rejected is not certified.** This policy describes how the project
handles vulnerabilities and how it supports downstream manufacturers. It does
not make the project, or any deployment of it, CRA-conformant, CE-marked or
"NIS2 compliant". See
[`docs/compliance/eu-regulatory-status.md`](docs/compliance/eu-regulatory-status.md)
for the regulatory status and the limits of the compliance evidence packs.

## Supported versions

| Version | Supported | Notes |
|---|---|---|
| `0.1.0-beta.x` (latest beta) | Yes | Security fixes and regressions |
| `0.1.0-beta.x` (previous beta) | Best effort, 90 days after a successor | Security fixes only |
| `< 0.1.0-beta.6` | No | Superseded pre-releases |
| Unreleased `main` | Yes | Fixes land here first |

Only the latest pre-release receives full support while the project is in beta.
The support period, patch targets and end-of-life rules are defined in
[`docs/operations/support-policy.md`](docs/operations/support-policy.md).

## Reporting a vulnerability

**Do not open a public issue, pull request or discussion for a suspected
vulnerability.**

Preferred channel: GitHub private vulnerability reporting
(`Security` tab -> `Report a vulnerability`) on
`https://github.com/shift/waf-rejected/security/advisories/new`.

Fallback channel: `security@waf-rejected.com` (monitored security mailbox).

Encrypt sensitive material if the fallback mailbox publishes a PGP key. Never
send production credentials, customer payloads or full packet captures; redact
them and describe the shape of the data instead.

### What to include

- Affected version or commit, and how it was built (Nix, Cargo, container
  digest).
- Configuration relevant to the issue (`fail_mode`, inspection toggles,
  authentication, trusted proxies). Redact secrets.
- A minimal reproduction: request, upstream behaviour, expected and observed
  result.
- Impact assessment: bypass of inspection, request smuggling, denial of
  service, information disclosure, privilege escalation.
- Whether you believe the issue is being exploited in the wild.

### Our commitments

- Acknowledge receipt within 3 business days.
- Provide an initial triage (severity, affected versions, whether a fix is
  planned) within 10 business days.
- Keep you informed at least every 10 business days until closure.
- Credit you in the advisory unless you ask to stay anonymous.
- Coordinate publication: we aim to publish an advisory and fixed release
  within 90 days of the report, sooner for actively exploited issues.

We do not operate a paid bounty programme. We will not pursue legal action
against researchers who act in good faith, stay within the scope above, avoid
privacy violations and data destruction, and give us reasonable time to fix the
issue before disclosure.

## CRA Article 14 alignment

Regulation (EU) 2024/2847 (Cyber Resilience Act) Article 14 reporting
obligations have applied since 11 September 2026. Where WAF-Rejected is placed
on the EU market as a product with digital elements, the party distributing it
is normally the manufacturer and owns the reporting duty. The project supports
that duty as follows.

| Stage | Deadline | Project action |
|---|---|---|
| Early warning | 24 hours after awareness of an actively exploited vulnerability | Confirm receipt, state whether the report is credible, share known affected versions and indicators, open a private advisory |
| Notification | 72 hours after awareness | Publish severity, affected versions, exploitation status, mitigations and the remediation plan in the private advisory |
| Final report | 14 days after a corrective measure is available (actively exploited vulnerability) | Release the fix, advisory, updated SBOM and remediation guidance |
| Final report | 1 month after notification (severe incident) | Publish root cause, corrective and preventive measures, and residual risk |

Notes:

- Submission to the ENISA Single Reporting Platform (SRP) and the relevant
  CSIRT is **manual** and performed by the manufacturer. The project does not
  submit reports on a deployer's behalf and does not automate SRP submission.
- A GitHub advisory is not a regulatory notification. Downstream manufacturers
  must still meet their own 24h/72h/final-report deadlines, so watch the
  repository security advisories and release feed.
- Reports about a *deployment* (misconfiguration, exposed admin surface,
  upstream compromise) are incident response for the operator, not a product
  vulnerability. The project can supply log and event evidence.

## NIS2 awareness

Directive (EU) 2022/2555 (NIS2) obligations fall on essential and important
entities, not on this repository. If you operate WAF-Rejected as part of a NIS2
in-scope service:

- Your incident cascade is typically an early warning within 24 hours, an
  incident notification within 72 hours and a final report within one month.
  Confirm the exact channel and deadlines with your national CSIRT; national
  transposition is uneven.
- Security events and blocking decisions produced by the WAF (JSON/CEF events,
  Sled store, Prometheus counters) are detection evidence only. They do not by
  themselves satisfy NIS2, and no compliance report generated by the
  `compliance` feature is a certification.
- Report supply-chain issues you find in WAF-Rejected to us through the private
  channel above so that other operators can be warned.
- Release filesystems and container images are scanned with Trivy; any
  `HIGH` or `CRITICAL` finding blocks the release. The scan policy and local
  reproduction steps are documented in
  [`docs/operations/supply-chain.md`](docs/operations/supply-chain.md).

## Verifying release provenance

Tagged releases publish a GitHub build provenance attestation for the binary
tarball, the container image tarball and the CycloneDX SBOM. The attestation is
signed by the Release workflow's OIDC identity and records the repository, the
workflow and the source commit that produced the artifact.

```bash
gh attestation verify waf-rejected-v<version>-x86_64-linux.tar.gz --repo shift/waf-rejected
gh attestation verify waf-rejected-<version>-image.tar.gz --repo shift/waf-rejected
gh attestation verify waf-rejected-<version>.cdx.json --repo shift/waf-rejected
```

Verify provenance before deploying a downloaded artifact. A failed verification
means the file did not come from this repository's release pipeline; do not
deploy it and report it through the private channel above. The published
`<asset>.sha256` files remain useful for corruption checks but are not a
substitute for the signed attestation.

## Scope

In scope: the `waf-ingress` binary, the container image published from this
repository, bundled configuration and rules, and the release workflow.

Out of scope: findings that require a deliberately insecure configuration
(for example authentication disabled and the proxy exposed to the internet),
vulnerabilities in an operator's upstream service, missing OWASP CRS coverage
(the bundled `rules/coraza.wasm` is a demo module, see
[`docs/wasm-integration-status.md`](docs/wasm-integration-status.md)), and
issues already fixed on `main` and released.

## Related documents

- [Penetration-test readiness pack](docs/security/pen-test-scope.md) — scope,
  stand-up, test cases and known limitations for an external engagement.
- [Security documentation index](docs/security/README.md)

- [Security architecture and threat model](docs/architecture/security-model.md)
- [Support policy](docs/operations/support-policy.md)
- [Supply-chain policy](docs/operations/supply-chain.md)
- [Container usage](docs/operations/container.md)
- [EU regulatory status](docs/compliance/eu-regulatory-status.md)
- [Release checklist](docs/operations/release-checklist.md)
