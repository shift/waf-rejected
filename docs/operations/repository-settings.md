# Repository settings

This document records the intended GitHub settings for
[`shift/waf-rejected`](https://github.com/shift/waf-rejected) and the commands
used to reproduce them. It covers repository metadata, security features and
the `main` branch ruleset. It does not describe application configuration.

## Metadata

| Setting | Value |
|---|---|
| Visibility | Public |
| Description | Rust reverse-proxy WAF with a native OWASP CRS engine, Coraza reference backend, gRPC/GraphQL inspection and sub-millisecond fast paths |
| Homepage | <https://github.com/shift/waf-rejected#readme> (canonical project page until a dedicated site exists) |
| Topics | `coraza`, `crs`, `graphql`, `grpc`, `reverse-proxy`, `rust`, `security`, `waf`, `web-application-firewall`, `modsecurity` |
| Default branch | `main` |
| Issues | Enabled |
| Discussions | Disabled |
| Wiki | Enabled (not used as a source of truth) |

Reproduce:

```bash
gh repo edit shift/waf-rejected \
  --description "Rust reverse-proxy WAF with a native OWASP CRS engine, Coraza reference backend, gRPC/GraphQL inspection and sub-millisecond fast paths" \
  --homepage "https://github.com/shift/waf-rejected#readme" \
  --add-topic coraza --add-topic crs --add-topic graphql --add-topic grpc \
  --add-topic reverse-proxy --add-topic rust --add-topic security \
  --add-topic waf --add-topic web-application-firewall --add-topic modsecurity
```

## Security features

| Feature | State | Notes |
|---|---|---|
| Dependabot alerts | Enabled | Free for public repositories. |
| Dependabot security updates | Enabled | Opens fix PRs for vulnerable dependencies. |
| Secret scanning | Enabled | Free for public repositories. |
| Secret scanning push protection | Enabled | Blocks pushes containing supported secrets. |
| Private vulnerability reporting | Enabled | `Security` tab -> `Report a vulnerability`. |
| CodeQL default setup | Configured | Analysis runs only when GitHub Actions is available. |
| Secret scanning non-provider patterns | Unavailable | Not offered on this repository's current plan. |
| Secret scanning validity checks | Unavailable | Not offered on this repository's current plan. |

Reproduce:

```bash
gh api -X PUT repos/shift/waf-rejected/vulnerability-alerts
gh api -X PUT repos/shift/waf-rejected/automated-security-fixes
gh api -X PATCH repos/shift/waf-rejected --input - <<'JSON'
{"security_and_analysis":{
  "secret_scanning":{"status":"enabled"},
  "secret_scanning_push_protection":{"status":"enabled"}
}}
JSON
gh api -X PATCH repos/shift/waf-rejected/code-scanning/default-setup \
  --input - <<'JSON'
{"state":"configured","query_suite":"default"}
JSON
```

Read back:

```bash
gh api repos/shift/waf-rejected --jq '.security_and_analysis'
gh api repos/shift/waf-rejected/private-vulnerability-reporting
gh api repos/shift/waf-rejected/code-scanning/default-setup
```

## `main` branch ruleset

The active ruleset `main-protection` targets `refs/heads/main` and enforces:

- Changes must arrive through a pull request.
- Linear history (no merge commits).
- Force pushes are blocked.
- Branch deletion is blocked.
- Review conversations must be resolved before merge.
- Stale approvals are dismissed on new pushes.
- No required approving reviews, so a sole maintainer can still merge.
- No required status checks while GitHub Actions is billing-blocked. Add them
  once CI is restored; otherwise every PR would be unmergeable.

Reproduce:

```bash
gh api -X POST repos/shift/waf-rejected/rulesets --input - <<'JSON'
{
  "name": "main-protection",
  "target": "branch",
  "enforcement": "active",
  "conditions": {"ref_name": {"include": ["refs/heads/main"], "exclude": []}},
  "rules": [
    {"type": "deletion"},
    {"type": "non_fast_forward"},
    {"type": "required_linear_history"},
    {"type": "pull_request", "parameters": {
      "required_approving_review_count": 0,
      "dismiss_stale_reviews_on_push": true,
      "require_code_owner_review": false,
      "require_last_push_approval": false,
      "required_review_thread_resolution": true
    }}
  ]
}
JSON
```

When CI is available, add a `required_status_checks` rule with the job names
from `.github/workflows/` and re-check that the ruleset still allows the
maintainer to merge.

## Tags

A separate `release-tags` ruleset blocks deletion and force-updates of `v*`
tags. Release and tag conventions are in
[`release-policy.md`](release-policy.md).

## Ownership

`.github/CODEOWNERS` assigns the repository and security-sensitive paths to
`@shift`. Update it if the project moves to an organisation or gains
additional maintainers.

## Verification

```bash
gh api repos/shift/waf-rejected/rulesets
gh api repos/shift/waf-rejected/rulesets/<id>
gh api repos/shift/waf-rejected/branches/main/protection
git ls-remote --heads origin main
```

`branches/main/protection` returns `404 Branch not protected` when protection
is provided by a ruleset rather than classic branch protection. That is
expected for this repository.
