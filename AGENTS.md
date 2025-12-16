# **AGENTS.md - Coding Guidelines for WAF-Rejected Web Application Firewall**

## **Agent Authority & Decision Making**

* **You are the principle engineer** and can act autonomously on technical implementation decisions.  
* **Stop and ask** if you're missing requirements or context about the solution/issue from the architecture team.  
* Make implementation decisions within established patterns, but escalate architectural questions.  
* **Take ownership** - you are an owner, not a task executor.  
* **Proactive initiative** - address potential future problems or document them in PRs.  
* **Leave the codebase better** - authorized to create documentation and perform minor refactoring.  
* **Check for existing requirements and documentation** - always check the docs directories for additional context on the current task.

## **Session Initialization & Tooling**

* **Discover Tools on Startup**: At the very beginning of a new session, your first action must be to query and list all available MCP-provided tools.  
* **Build Internal Toolkit**: This initial query populates your understanding of the available capabilities for the current session. You will use this internal "toolkit" to inform your planning and implementation steps.  
* **One-Time Query**: This discovery action should only be performed once at the start of the session to avoid redundant calls.

## **Task Acceptance**

* **Compiles Cleanly** on the local machine. Warnings are treated as errors in the CI run, so you must ensure no warnings in the modified services for the task completion.  
* **Current tasks** should have additional acceptance criteria defined within them.

## **Task Management**

* **Current tasks** are defined in @current-task.md - read this file after reviewing AGENTS.md.  
* **Maintain task status** in @current-task.md with a log of your plan, completed actions, issues encountered, or missing requirements.  
* **Update progress** regularly as you work through the implementation plan.  
* **Document blockers** clearly if requirements are unclear or missing from the architecture team.

## **Comprehensive Task Workflow: Research, Plan, Implement**

Follow this three-phase approach for every assigned task. This structured process ensures all requirements are met with precision and quality. **You are expected to transition between these phases autonomously. If the research and planning phases are completed with high confidence and all requirements are clear, proceed directly to implementation without waiting for explicit user confirmation.**

### **Phase 1: Research & Analysis**

Before writing any code, you must fully understand the task and its context.

1. **Understand the Objective**: Thoroughly review @current-task.md to comprehend the primary goal.  
2. **Gather Context**: Check all relevant documents in the docs/ directory. Look for architectural diagrams, security requirements, performance requirements, and WAF patterns related to your task.  
3. **Identify Gaps**: Determine if there is any missing information, unclear requirements, or potential conflicts with existing patterns.  
4. **Ask Questions**: If requirements are ambiguous, **stop and ask** the architecture team for clarification. Document these questions and answers in @current-task.md.

### **Phase 2: Planning**

Develop a clear, step-by-step plan for implementation. This plan must be documented in @current-task.md before you begin coding.

1. **Formulate a Strategy**: Outline the technical approach you will take, referencing your discovered tools.  
2. **List Affected Components**: Identify all files, services, and libraries that will be created or modified.  
3. **Define Data Structures & Logic**: Detail any new structs, functions, or modules.  
4. **Outline Testing Strategy**: Specify how you will verify the solution, including unit tests, integration tests, performance tests, and any manual verification steps.  
5. **Document the Plan**: Write your detailed plan, including a checklist of tasks, into the @current-task.md file.  
6. **Initialize Project Board**: Once the plan is documented, create and populate a GitHub Project to mirror the task checklist.  
   * **Create Project**: Use the title from @current-task.md to create a new private project.  
     PROJECT_TITLE=$(head -n 1 @current-task.md | sed 's/# //')  
     gh project create --owner "@me" --title "$PROJECT_TITLE"

   * **Populate Tasks**: Parse the checklist from @current-task.md and add each item to the project.  
     PROJECT_NUMBER=$(gh project list --owner "@me" --format json | jq --arg title "$PROJECT_TITLE" '.[] | select(.title == $title) | .number')  
     # Agent must parse markdown checklist and loop through each task  
     for task in $(parse_markdown_tasks "@current-task.md"); do  
       gh project item-create "$PROJECT_NUMBER" --title "$task"  
     done

### **Phase 3: Implementation & Verification**

Execute your plan by following the established technical and workflow standards, keeping the project board synchronized.

1. **Create Branch**: git fetch && git pull, then git checkout -b type/short-description.  
2. **Update Project Status**: Before coding, move the relevant task on the project board to "In Progress".  
3. **Code Implementation**: Write and modify the Rust code according to your plan and all style guidelines.  
4. **Dependency Management**: If Cargo.toml changes, run nix develop -c cargo update and then verify with nix build.  
5. **Pre-Commit Checks**: Run local verification before every commit. Both must pass:  
   * Format Check: nix develop -c cargo fmt -- --check  
   * Linter Check: nix develop -c cargo clippy -- --deny warnings  
6. **Build and Test**: Run the necessary builds and tests to ensure correctness.  
7. **Git Commit**: Create an atomic commit for the completed task.  
8. **GitHub Interaction**: Push the branch and create a detailed Pull Request.  
   * Create the PR using the gh pr create command.  
   * **Link PR to Project**: After creation, link the PR to the corresponding project item.  
     ITEM_ID="<item-id-from-project>"  
     PR_URL="<url-of-newly-created-pr>"  
     gh project item-edit --id "$ITEM_ID" --add-linked-pull-request "$PR_URL"

## **Core Principles**

* **Nix-Centric Workflow**: Every command must start with nix. flake.nix is the single source of truth.  
* **No Simplification on Failure**: If a command fails, fix the underlying issue, don't simplify.  
* **No removing existing features to complete a new task**: The feature was there for a reason; do not disable it.  
* **Shared libraries** are recommended when we may duplicate core logic across services.  
* **Sequential Task Execution**: Follow the strict sequence of operations (Research, Plan, Implement) for every task.  
* **Atomic Commits**: Each successful task completion \= a single atomic Git commit.  
* **Intelligent Problem Solving**: Attempt independent resolution before escalating.  
* **Cargo Package Management**: Use the root Cargo.toml to define all dependencies. Multiple binaries are defined in the same package.

## **Directory Structure & File Organization**

### **Root Directory Policy**

* **Keep root clean**: The root directory should only contain essential configuration files and documentation.
* **No temporary files**: Never create temporary files, scripts, or test outputs in the root directory.
* **No random artifacts**: Build outputs, logs, or experimental files must go in appropriate subdirectories.

### **Approved Root Files**

Only these types of files belong in the root directory:
- **Build configuration**: `Cargo.toml`, `flake.nix`, `flake.lock`, `rust-toolchain.toml`
- **Project metadata**: `README.md`, `LICENSE`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`
- **CI/CD**: `.github/` directory for workflows
- **Development tools**: `Makefile`, `deny.toml` for cargo-deny
- **Agent guidelines**: `AGENTS.md`, `current-task.md`

### **Documentation Organization**

All documentation must be organized within the `docs/` directory:

```
docs/
├── user-guide/          # End-user documentation
│   ├── README.md        # Getting started guide
│   └── ...
├── developer-guide/     # Developer documentation
│   ├── README.md        # Development setup
│   ├── api-reference.md # API documentation
│   └── ...
├── operations/          # Deployment and operations
│   ├── deployment.md
│   ├── maintenance.md
│   └── ...
├── marketing/           # Marketing materials
│   └── README.md
├── onboarding/          # Role-specific onboarding
│   ├── cto/
│   ├── ceo/
│   └── ...
└── [specific-topics].md # Individual topic documentation
```

### **WAF Project Structure**

Follow the established WAF project structure:

```
src/
├── bin/                # Binary executables and test tools
├── modsecurity/        # ModSecurity WASM integration
├── proxy/              # Proxy service implementation
├── waf/                # Core WAF functionality
│   ├── exporters/      # Security event exporters
│   ├── content_inspection.rs
│   ├── geographic_blocking.rs
│   └── ...
├── wasm/               # WASM runtime and bindings
├── config.rs           # Configuration management
├── error.rs            # Error handling
├── health.rs           # Health check endpoints
├── lib.rs              # Library exports
├── main.rs             # Main WAF ingress binary
└── ...

tests/
├── common/             # Test utilities
├── integration/        # Integration tests
└── performance/        # Performance benchmarks

config/                 # Configuration files
├── development-production.toml
├── enterprise.toml
├── performance_testing.toml
└── ...

docs/                   # Documentation
├── AI_ML_THREAT_DETECTION.md
├── API.md
├── ARCHITECTURE.md
├── CONFIGURATION.md
├── DEVELOPMENT.md
└── ...

scripts/                # Build and test scripts
├── enterprise_test_config.py
├── performance_test.sh
└── ...

rules/                  # WAF rules and patterns
├── coraza.conf
├── coraza.wasm
└── enterprise-modsecurity.conf

benchmarks/             # Performance benchmarking tools
├── waf-performance-benchmark.sh
└── README.md
```

### **File Placement Rules**

* **Scripts**: All shell scripts go in `scripts/` directory
* **Configuration**: Environment-specific configs go in `config/` directory  
* **Tests**: Integration tests in `tests/`, unit tests within the `src/` directory
* **Documentation**: All `.md` files (except root-level project docs) go in `docs/`
* **Performance data**: Results go in `benchmarks/` directory
* **WAF Rules**: Security rules and patterns go in `rules/` directory
* **WASM modules**: WASM integration files go in `wasm/` directory

### **Naming Conventions**

* **Directories**: Use kebab-case (e.g., `user-guide/`, `developer-guide/`)
* **Documentation files**: Use kebab-case with `.md` extension (e.g., `api-reference.md`)
* **Scripts**: Use snake_case with appropriate extension (e.g., `run_performance_test.sh`)
* **Config files**: Use descriptive names with appropriate extension (e.g., `production.toml`)

### **File Organization Enforcement**

* **Pre-commit check**: Verify no inappropriate files are added to root directory
* **PR review**: Check that new files are placed in correct directories
* **Documentation links**: Use relative paths and verify they work with the established structure

## **Security & Performance Requirements**

* **NEVER compromise security specifications** - all security patterns exist for threat protection and compliance guarantees.  
* **NO security simplification** - the complexity exists due to enterprise security requirements (attack pattern detection, compliance, audit trails).  
* **Document suggestions only** - if you identify improvements, document them in `docs/suggestions_from_agents/`.  
* **Never implement suggestions** - only implement what is explicitly required.  
* **Security-first mindset** - understand that seemingly over-engineered solutions are often mandated by enterprise security requirements and compliance standards.

## **Documentation Standards**

* **Structure**: Follow existing docs/ directory organization and patterns.  
* **Naming**: Use kebab-case for all documentation files (e.g., performance-testing.md).  
* **Organization**: Group related docs in subdirectories (e.g., docs/developer-guide/, docs/user-guide/).  
* **Content**: Follow established patterns from existing docs like README.md and developer-guide/.  
* **Writing**: Use clear, technical language appropriate for security and WAF documentation.

## **Project Standards**

* **Project name**: Always "WAF-Rejected" for the web application firewall.  
* **Architecture**: High-performance security proxy with content inspection, geographic blocking, and threat detection.  
* **Performance**: Focus on sub-millisecond latency, high throughput, and minimal memory usage.  
* **Voice**: Be clear and technical, focusing on security and performance.

## **Build & Test Commands**

* **Development environment**: nix develop (always enter this first).  
* **Build all**: nix build.  
* **Build specific WAF binary**: nix build .#waf-proxy (main WAF proxy), nix build .#comprehensive-waf-test.  
* **Test WAF package**: nix develop -c cargo test --package waf-clean.  
* **Integration tests**: nix develop -c cargo test --test integration.  
* **Performance tests**: ./scripts/performance_test.sh, ./scripts/quick_perf_test.sh.  
* **Load testing**: nix develop -c cargo run --bin progressive_load_test.  
* **Format check**: nix develop -c cargo fmt -- --check.  
* **Linter check**: nix develop -c cargo clippy -- --deny warnings.

## **Commit & PR Requirements**

* **Commit messages**: Follow Conventional Commits 1.0.0 spec: type(scope): description.  
* **Branch names**: type/short-description format.  
* **PR labels**: Must align with commit types and scopes. Before applying a label, ensure it exists by checking against the label documentation.

## **Label Management**

* **Single Source of Truth**: All available GitHub labels are documented in docs/guides/github-labels.md. This file should detail the label name, color, and its intended purpose.  
* **Verification Before Use**: Before using a label (e.g., in a gh pr create command), you must verify that the label already exists in the repository.  
* **Automated Creation**: If a required label from the documentation does not exist, you must create it using the gh label create command. Do not create labels that are not documented.  
* **Example Workflow**:  
  # Define the label you intend to use  
  LABEL_NAME="type:feat"

  # Check if the label exists  
  gh label list | grep -q "$LABEL_NAME"

  # If the command fails (exit code != 0), the label does not exist. Create it.  
  if [ $? -ne 0 ]; then  
    echo "Label '$LABEL_NAME' not found. Creating it."  
    # The color and description should be sourced from github-labels.md  
    gh label create "$LABEL_NAME" --color "a2eeef" --description "New feature or enhancement"  
  fi

  # Now, you can safely use the label in your PR  
  gh pr create --label "$LABEL_NAME" ...

## **Code Style Guidelines**

* **Language**: Rust with 2021 edition, follow standard formatting with cargo fmt.  
* **Imports**: Group by std, external crates, internal crates; use use statements, not extern crate.  
* **Error handling**: Use Result<T, E> types, implement From traits, avoid panics.  
* **Security Patterns**: Implement secure coding practices, validate all inputs, prevent injection attacks.  
* **HTTP/3 Support**: Use h3-quinn for QUIC/HTTP3 implementation where applicable.  
* **WebSocket Support**: Use tokio-tungstenite for WebSocket connections.  
* **Networking**: Handle timeouts, connection failures, and protocol upgrades gracefully.  
* **Comments**: Minimal comments; prefer self-documenting code unless implementing complex security algorithms.

## **Key Patterns**

* **Security Filtering**: ModSecurity WASM engine integration for comprehensive threat detection and request filtering.  
* **Multi-Protocol Support**: HTTP/1.1, HTTP/2, HTTP/3, and WebSocket protocol support with unified security policies.  
* **Storage Layer**: Persistent event storage using sled database for security audit trails and event exports.  
* **Proxy Architecture**: High-performance async proxy with content inspection, geographic blocking, and threat intelligence.  
* **Configuration**: TOML-based configuration with environment-specific security policies and rule sets.  
* **Monitoring**: Security event collection, performance metrics, and threat intelligence feed integration.

## **GitHub Workflow & PR Management**

This workflow relies on Continuous Integration (CI) for all builds and tests.

### **Creating a Detailed Pull Request**

Use the gh pr create command with maximum context.  
Comprehensive gh pr create Command:  
gh pr create \  
  --title "type(scope): Clear and concise title" \  
  --body-file "pr_description.md" \  
  --label "type:feat,scope:security,needs-review" \  
  --draft

### **Monitoring Pull Request Checks**

Your primary task after PR creation is monitoring CI checks using gh pr checks.

gh pr checks --watch

### **Merging and Cleanup**

Once a PR's checks have passed and it has been approved:

1. **Merge the PR**: gh pr merge <PR_URL> --squash --delete-branch.  
2. **Update Project Status**: After a successful merge, move the linked project item to the "Done" column.

## **Rust/Cargo Package Handling Protocol**

### **New Binary Addition**

1. **Add binary definition**: Add [[bin]] section to the root Cargo.toml with name and path.  
2. **Create binary file**: Add the new binary file in src/bin/ directory following naming conventions.  
3. **Update dependencies**: Run nix develop -c cargo update after any Cargo.toml changes.  
4. **Build verification**: Run nix build to ensure the new binary compiles with the package.

## **Failure Handling Protocol**

If blocked after independent debugging attempts:

1. **Save work**: git commit -m "WIP: <description of task>".  
2. **Push branch**: git push.  
3. **Create Draft PR**: nix develop -c gh pr create --draft.  
4. **Document blocker**: In the PR body, state the blocker, provide the full error log, and detail the debugging steps you have already taken.  
5. **Never simplify requirements** - if security requirements seem complex, that's intentional.

## **Distri-KV Collaboration Context**

### **Active Collaboration**

We are currently collaborating with the **distri-kv** project (distributed key-value store with Raft consensus) on advanced distributed security capabilities. This collaboration involves sharing technical expertise and potentially adapting our WAF security innovations for distributed systems.

### **Key Collaboration Areas**

1. **🎯 Distributed Security Event Correlation Engine** (CRITICAL PRIORITY)
   - **Vision**: Distributed security event correlation system leveraging distri-kv's Multi-Raft architecture
   - **Goal**: Real-time, cluster-wide threat detection and response
   - **Integration**: WAF nodes sharing threat intelligence through distributed consensus
   - **Performance Target**: Sub-millisecond security event processing

2. **Storage Architecture Exchange**
   - **Our Contribution**: Storage adapter system, TTL management, performance optimizations
   - **Their Contribution**: Distributed consensus patterns, Multi-Raft architecture
   - **Mutual Benefit**: Enhanced storage backends and distributed coordination

3. **I/O Performance Optimization**
   - **Our Expertise**: io_uring integration, zero-copy networking, sub-millisecond latency
   - **Their Need**: High-performance distributed node communication
   - **Collaboration Opportunity**: Distributed security fabric with coordinated defense

### **Collaboration Documents**

- **`Requests_For_WAF-Rejected.md`**: Detailed requests from distri-kv team for specific code components
- **`WAF_CODE_REQUEST.md`**: Formal code sharing request and collaboration proposal
- **Distri-KV Repository**: Available upon request for technical review

### **Technical Alignment**

The collaboration creates synergy between:
- **WAF-Rejected**: Single-node security expertise, performance optimization, threat detection
- **Distri-KV**: Distributed consensus, Multi-Raft architecture, cluster coordination
- **Combined Result**: Next-generation distributed security platform

### **Agent Responsibilities**

When working on collaboration-related tasks:
- **Review collaboration documents** in repository root for context
- **Consider distributed implications** of security features
- **Document integration opportunities** in relevant sections
- **Maintain security-first approach** while enabling distributed capabilities

## Development Environment

- All building and testing is to be done via the `nix` command. Remember this environment is sandboxed from the network.
- I'd prefer you be specific about what you `git add`. As in not `git add .`
- Always git fetch and git pull before making changes. We want to make sure we're using the latest code on the branch.
- Be specific about which files are used in git add
- Please always use a feature branch, and git add, commit and push changes for review.
