# GitHub Labels

This document defines all available GitHub labels for the WAF-Rejected project, their colors, and intended purposes.

## Type Labels

| Label | Color | Description |
|-------|-------|-------------|
| `type:feat` | `#a2eeef` | New feature or enhancement |
| `type:fix` | `#d73a4a` | Bug fix or error correction |
| `type:docs` | `#0075ca` | Documentation improvements or additions |
| `type:refactor` | `#fbca04` | Code refactoring without functionality changes |
| `type:test` | `#c5def5` | Test additions or improvements |
| `type:chore` | `#fef2c0` | Maintenance tasks, dependency updates |
| `type:perf` | `#0e8a16` | Performance improvements |

## Scope Labels

| Label | Color | Description |
|-------|-------|-------------|
| `scope:security` | `#b60205` | Security-related changes (content inspection, threat detection) |
| `scope:wasm` | `#e99695` | WASM ModSecurity integration |
| `scope:proxy` | `#d4c5f9` | Proxy service and middleware |
| `scope:config` | `#c2e0c6` | Configuration management |
| `scope:export` | `#bfd4f2` | Security event export systems |
| `scope:geo` | `#f9d0c4` | Geographic blocking functionality |
| `scope:websocket` | `#ededed` | WebSocket protocol support |
| `scope:http3` | `#bfe5bf` | HTTP/3 and QUIC support |
| `scope:ai` | `#5319e7` | AI/ML threat detection |
| `scope:monitoring` | `#0052cc` | Observability and metrics |

## Priority Labels

| Label | Color | Description |
|-------|-------|-------------|
| `priority:high` | `#b60205` | Critical issues requiring immediate attention |
| `priority:medium` | `#fbca04` | Important issues for next release |
| `priority:low` | `#0e8a16` | Nice-to-have improvements |

## Status Labels

| Label | Color | Description |
|-------|-------|-------------|
| `status:blocked` | `#e4e669` | Blocked by dependencies or external factors |
| `status:needs-review` | `#ff9500` | Ready for code review |
| `status:in-progress` | `#1d76db` | Currently being worked on |
| `status:ready` | `#0e8a16` | Ready for implementation |

## Special Labels

| Label | Color | Description |
|-------|-------|-------------|
| `good-first-issue` | `#7057ff` | Good for newcomers to the project |
| `help-wanted` | `#008672` | Extra attention or expertise needed |
| `security-review` | `#b60205` | Requires security team review |
| `breaking-change` | `#d73a4a` | Contains breaking API changes |
| `enterprise` | `#5319e7` | Enterprise-specific features |
| `compliance` | `#0052cc` | Compliance and audit related |

## Size Labels

| Label | Color | Description |
|-------|-------|-------------|
| `size:xs` | `#c2e0c6` | Very small change (1-10 lines) |
| `size:s` | `#bfd4f2` | Small change (11-50 lines) |
| `size:m` | `#fbca04` | Medium change (51-200 lines) |
| `size:l` | `#ff9500` | Large change (201-500 lines) |
| `size:xl` | `#d73a4a` | Extra large change (500+ lines) |

## Usage Guidelines

1. **Required Labels**: All PRs must have at least one `type:` and one `scope:` label
2. **Priority Assignment**: Use priority labels for issues, typically not needed for PRs
3. **Status Tracking**: Update status labels as work progresses
4. **Security Focus**: Use `security-review` label for any security-related changes
5. **Breaking Changes**: Always use `breaking-change` label when API changes occur

## Label Creation Commands

Use these commands to create labels programmatically:

```bash
# Type labels
gh label create "type:feat" --color "a2eeef" --description "New feature or enhancement"
gh label create "type:fix" --color "d73a4a" --description "Bug fix or error correction"
# ... (see individual sections above for complete commands)
```