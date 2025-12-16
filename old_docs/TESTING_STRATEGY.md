# Testing Strategy

## 1. Introduction & Guiding Principles

This document outlines the testing strategy for the `waf-rejected` project. Our goal is to produce a high-quality, reliable, and performant application. This is achieved through a multi-layered testing approach where every component is validated through automated tests.

Our strategy is guided by these principles:

*   **The Test Pyramid:** We follow the standard test pyramid model: a large base of fast unit tests, a smaller layer of more complex integration tests, and a peak of end-to-end and formal verification.
*   **Full Automation:** All tests must be runnable from a single command (`cargo test`) and will be executed automatically by our Continuous Integration (CI) pipeline on every commit and pull request.
*   **Clarity and Maintainability:** Tests are first-class citizens of the codebase. They must be clear, readable, and well-maintained.

---

## 2. Types of Tests

### Layer 1: Unit Tests

*   **Purpose:** To test a single function, method, or data structure in complete isolation from the rest of the system. These tests are fast, simple, and have no external dependencies (like files or networks).
*   **Location:** Inside the same file as the code they are testing, within a `#[cfg(test)]` module.
    ```rust
    // src/some_module.rs
    pub fn my_function() -> bool { true }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_my_function() {
            assert_eq!(my_function(), true);
        }
    }
    ```
*   **When to Write:** Every time you write a new public function or a piece of complex internal logic.

### Layer 2: Integration Tests

*   **Purpose:** To test the interaction between different components of the system or the behavior of a complete binary. These tests are slower as they often involve file I/O or running subprocesses.
*   **Location:** In the `/tests` directory at the root of the repository.
*   **Example:** An integration test might:
    1.  Start the `waf-ingress` binary as a subprocess.
    2.  Send it a series of real HTTP requests using an HTTP client.
    3.  Assert that the WAF returns the correct HTTP responses and prints the expected logs to its stdout/stderr.

### Layer 3: Formal Verification

*   **Purpose:** To mathematically prove the correctness of the most critical, complex, and high-risk parts of the system, specifically the core state machine of the reverse proxy.
*   **Location:** The TLA+ specifications are located in the `/specs` directory.
*   **Process:**
    1.  The TLA+ model is verified using the TLC model checker.
    2.  The properties and invariants from the TLA+ spec (e.g., "the proxy never drops a request without logging it") are used as a guide to write specific integration tests that check if the Rust implementation upholds those guarantees.

### Layer 4: Performance Benchmarks

*   **Purpose:** To track and prevent regressions in the performance of critical code paths.
*   **Location:** The `/benches` directory.
*   **Process:** Benchmarks are defined using the `criterion` crate and run via `cargo bench`. The results should be monitored over time to catch performance degradation before it becomes a problem.

---

## 3. Continuous Integration (CI)

Our CI pipeline (e.g., GitHub Actions) is the ultimate guardian of code quality. On every pull request and merge to the `main` branch, the CI server will automatically perform the following checks:

1.  **Formatting:** `cargo fmt --check`
2.  **Linting:** `cargo clippy -- -D warnings`
3.  **Build:** `cargo build --all-features`
4.  **Testing:** `cargo test --all-features`

A pull request cannot be merged unless all of these checks pass successfully.
