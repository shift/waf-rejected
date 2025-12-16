# Minimum Viable Product (MVP) Definition

## 1. Introduction

This document defines the scope and requirements for the Minimum Viable Product (MVP) of the `waf-rejected` project. The purpose of the MVP is to deliver a focused, stable, and valuable core product that solves a primary problem for a specific user. This allows us to launch faster, gather feedback, and build momentum for future development.

---

## 2. Core Problem Statement

Traditional WAFs like ModSecurity are powerful but can be complex to manage and may struggle with performance under high load. Developers and security teams need a simpler, faster alternative that provides effective protection against the most common threats without a significant performance penalty or operational overhead.

## 3. Target User

A DevOps engineer or platform engineering team at a mid- to large-sized tech company with responsibility for application security.

## 4. Value Proposition

> WAF-Rejected MVP is a high-performance WAF that offers essential protection against common web threats with a simplified configuration and lower latency than traditional solutions.

---

## 5. Scope of the MVP

To achieve our focused goal, the scope of the MVP is strictly limited. 

### IN SCOPE:

*   **Core Function:** A single, statically-compiled binary that runs as a reverse proxy for one upstream web application.
*   **WASM Runtime:** A WebAssembly runtime integrated into the request pipeline, capable of executing WASM modules.
*   **Rule Engine:** The WAF will load and run the **Coraza rule engine** as its primary WASM module.
*   **Rule Set:** The Coraza module will be configured to load a defined subset of the OWASP Core Rule Set (CRS) from a local file.
    *   The WAF will support the SQLi and XSS rules from the OWASP Core Rule Set at Paranoia Level 1 (PL1).
*   **Logging:** Logs all blocked requests to `stdout`. Log entries must be in a simple, machine-readable JSON format.
*   **Configuration:** All configuration will be managed through a single `config.toml` file with parameters for the proxy and the rule engine.

### OUT OF SCOPE:

*   **All AI/ML Features:** No training, no inference, no `threat_intelligence` module.
*   **Multiple Data Exporters:** Only `stdout` logging is required. OpenTelemetry, CEF, etc., are not part of the MVP.
*   **High Availability / Distributed Deployment:** The MVP will run as a single node with no external state sharing.
*   **User Interface:** No GUI, dashboard, or API for configuration.
*   **TLS/SSL Termination:** The MVP will not handle HTTPS. It is assumed to run behind a load balancer or another proxy (like Nginx) that terminates TLS.
*   **Advanced Features:** No rate limiting, geo-blocking, or behavioral analysis outside of the loaded Coraza rules.

---

## 6. Key Technologies

*   **Language:** Rust
*   **Core Libraries:** Tokio, Hyper
*   **WASM Runtime:** Wasmtime
*   **Rule Engine:** Coraza (via WASM)
*   **Build System:** Cargo, Nix

---

## 7. Acceptance Criteria

The MVP will be considered "done" when the following criteria are met:

1.  The application compiles into a single, self-contained binary via `cargo build --release`.
2.  The application successfully proxies HTTP traffic to a configured upstream service.
3.  The WAF, running the Coraza WASM module, correctly blocks a standard OWASP ZAP test suite for SQL Injection and logs the blocked events to `stdout`.
4.  The application can sustain a baseline performance of 50,000 RPS on a specific, documented hardware configuration.
5.  The application adds less than **5ms** of latency to proxied requests under the baseline load.
6.  The core library code has a unit test coverage of at least **85%**.