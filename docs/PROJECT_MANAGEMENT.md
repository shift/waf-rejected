# WAF Project Management

This document explains how to maintain the GitHub Project board for the WAF-Rejected development project.

## Project Overview

**Project URL**: https://github.com/users/shift/projects/3
**Project Title**: WAF-Rejected Development

## Project Structure

### Custom Fields

| Field | Type | Options |
|-------|------|---------|
| **Status** | Single Select | Todo, In Progress, Done |
| **Priority** | Single Select | High, Medium, Low |
| **Component** | Single Select | Security, WASM, Proxy, Config, Export, Geo, WebSocket, HTTP3, AI, Monitoring, Core |
| **Size** | Single Select | XS, S, M, L, XL |

### Labels Integration

The project integrates with GitHub issue labels:
- **Type labels**: `type:feat`, `type:fix`, `type:docs`, `type:refactor`, `type:test`, `type:chore`, `type:perf`
- **Scope labels**: `scope:security`, `scope:wasm`, `scope:proxy`, etc.
- **Priority labels**: `priority:high`, `priority:medium`, `priority:low`
- **Size labels**: `size:xs`, `size:s`, `size:m`, `size:l`, `size:xl`

## Task Management Workflow

### 1. Creating New Tasks

When creating new issues for the WAF project:

```bash
# Create issue with proper labels
gh issue create --title "Your task title" \
  --body "Detailed description with acceptance criteria" \
  --label "type:feat,scope:security,priority:high,size:m"

# Add to project
gh project item-add 3 --owner "@me" --url "https://github.com/shift/waf-rejected/issues/N"
```

### 2. Managing Task Status

Use the project management script to update task status:

```bash
# Show current project status
./scripts/project_management.sh status

# Move task to in-progress
./scripts/project_management.sh status ITEM_ID in-progress

# Mark task as done
./scripts/project_management.sh status ITEM_ID done

# Set priority
./scripts/project_management.sh priority ITEM_ID high

# Set component
./scripts/project_management.sh component ITEM_ID Security

# Set size estimate
./scripts/project_management.sh size ITEM_ID L
```

### 3. Status Change Protocol

Follow this protocol when changing task status:

#### **Moving to "In Progress"**
- Assign yourself to the issue
- Update the project status to "In Progress"
- Create a feature branch for the work
- Document your approach in the issue comments

```bash
# Example workflow
ITEM_ID="PVTI_lAHNBnXOAQPAJM4Hc7r0"
./scripts/project_management.sh status $ITEM_ID in-progress
gh issue edit 1 --add-assignee "@me"
git checkout -b type/short-description
```

#### **Moving to "Done"**
- Ensure all acceptance criteria are met
- Create and merge pull request
- Update project status to "Done"
- Close the issue

```bash
# After PR is merged
./scripts/project_management.sh status $ITEM_ID done
gh issue close 1 --comment "Completed in PR #X"
```

## Current Active Issues

The project currently tracks these key areas:

1. **Documentation** (`scope:config`)
   - AGENTS.md consistency fixes
   - API documentation updates

2. **Security Features** (`scope:security`)
   - Enhanced geographic blocking
   - WASM ModSecurity optimization
   - Security event export system

3. **Monitoring** (`scope:monitoring`)
   - Performance dashboard implementation
   - OpenTelemetry integration

4. **Performance** (`type:perf`)
   - WASM processing optimization
   - Request latency improvements

## Project Maintenance Guidelines

### Regular Updates

1. **Daily**: Update task status as work progresses
2. **Weekly**: Review and prioritize backlog items
3. **Monthly**: Clean up completed items and plan next iteration

### Field Usage Guidelines

#### **Priority Assignment**
- **High**: Critical security issues, major performance problems, blocking issues
- **Medium**: New features, enhancements, non-critical bugs
- **Low**: Nice-to-have improvements, documentation updates

#### **Component Classification**
- **Security**: Content inspection, threat detection, attack prevention
- **WASM**: ModSecurity integration, WASM runtime optimization
- **Proxy**: HTTP/HTTPS proxy functionality, middleware
- **Config**: Configuration management, hot reloading
- **Export**: Security event exports, SIEM integration
- **Geo**: Geographic blocking, IP geolocation
- **WebSocket**: WebSocket protocol support
- **HTTP3**: QUIC/HTTP3 implementation
- **AI**: Machine learning threat detection
- **Monitoring**: Metrics, observability, dashboards
- **Core**: Core WAF functionality, libraries

#### **Size Estimation**
- **XS**: 1-10 lines of code, simple config changes
- **S**: 11-50 lines, small feature additions
- **M**: 51-200 lines, moderate features
- **L**: 201-500 lines, significant features
- **XL**: 500+ lines, major features or refactoring

## Integration with AGENTS.md Workflow

This project board integrates with the three-phase workflow defined in AGENTS.md:

1. **Research Phase**: Issues should be well-defined with clear requirements
2. **Planning Phase**: Size and component fields help with planning
3. **Implementation Phase**: Status tracking ensures visibility

## Automation Opportunities

Future enhancements could include:
- GitHub Actions to auto-update project fields based on labels
- Status synchronization with PR states
- Automated size estimation based on code changes
- Integration with commit status for automatic completion

## Quick Reference Commands

```bash
# Common project management tasks
./scripts/project_management.sh status                    # Show project overview
./scripts/project_management.sh add <issue-url>          # Add new issue
./scripts/project_management.sh item-id <issue-url>      # Get item ID
./scripts/project_management.sh status <item-id> todo    # Reset to todo
./scripts/project_management.sh priority <item-id> high  # Set high priority
```