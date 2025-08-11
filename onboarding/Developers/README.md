# WAF-Rejected: Developer Onboarding Guide

## 1. Welcome to the Team

Welcome to the `waf-rejected` project! This guide provides a structured reading list to get you up to speed on our architecture, strategy, and current development goals. 

Our project is ambitious, so we follow a disciplined, phased approach. Please read these documents in order to understand how we build and what we're focused on right now.

---

## 2. The Reading List

### Step 1: Understand the Vision & Strategy

**Goal:** Understand the project's high-level goals, what we are building first, and how we plan to get there.

*   **Must Read #1: `../../STRATEGIC_ROADMAP.md`**
    *   **Why:** This is the most important document for understanding our current direction. It explains our phased integration strategy and long-term vision.

*   **Must Read #2: `../../MVP_DEFINITION.md`**
    *   **Why:** This defines the specific, focused goal of our initial release (`v0.1`). It clarifies what is in scope and, just as importantly, what is out of scope for our current work.

### Step 2: Understand the Current State

**Goal:** Get familiar with the project's structure and the gaps we are actively working to fill.

*   **Must Read #3: `../../README.md`**
    *   **Why:** The main project README gives a great overview of all the features and technologies we envision for the final product. 
    *   **Note:** Keep in mind that this document describes the *target state* of the project. Refer to the `STRATEGIC_ROADMAP.md` for the current implementation phase.

*   **Must Read #4: `../../GAP_ANALYSIS.md`**
    *   **Why:** This document provides crucial context on the project's current state versus where we want to be. It will help you understand the "why" behind many of our immediate engineering tasks.

### Step 3: Deep Dive into Technical Areas (As Needed)

**Goal:** Once you understand the strategy and current state, you can explore the documentation for the specific components you'll be working on.

*   **For Core Proxy & WAF Engine Development:**
    *   `../../docs/ARCHITECTURE.md`: For the high-level system design.
    *   `../../specs/`: For the TLA+ formal specifications of the core proxy logic.

*   **For AI/ML Development:**
    *   `../../docs/AI_ML_THREAT_DETECTION.md`: For the design of the AI/ML systems.
    *   `../../docs/TRAINING_NODE_DEPLOYMENT_PLAN.md`: For the plan to deploy and manage the training environment.

*   **For Extensibility & Exporting:**
    *   `../../docs/WASM_INTEGRATION_DOCUMENTATION.md`: For the WebAssembly runtime design.
    *   `../../docs/SECURITY_EVENT_EXPORTS.md`: For the design of the CEF and OpenTelemetry exporters.

---

## 3. Next Steps

After completing this reading list, your next step should be to set up your local development environment. The instructions for this will be in the `DEVELOPMENT_QUICKSTART.md` file (currently in development).
