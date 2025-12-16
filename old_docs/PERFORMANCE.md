# Performance Benchmark Analysis

## 1. Introduction

This document provides the detailed environment, workload, and configuration used to generate the performance metrics for `waf-rejected`. The goal is to provide a transparent and reproducible account of the WAF's performance characteristics.

---

## 2. Summary of Results

These results were generated on **[TODO: Date of benchmark run]** against git commit **[TODO: Git commit hash]**.

| Metric | Value |
| :--- | :--- |
| **Throughput (RPS)** | **[TODO: From benchmark run]** |
| **99th Percentile Latency** | **[TODO: From benchmark run]** |
| **Mean Latency** | **[TODO: From benchmark run]** |

---

## 3. Test Environment

*   **Hardware:**
    *   **CPU:** `[TODO: CPU Model, Cores, Clock Speed]`
    *   **Memory:** `[TODO: Amount of RAM]`
    *   **Network:** `[TODO: NIC Capacity, e.g., 25 Gbps]`
*   **Software:**
    *   **Operating System:** The exact OS, kernel, and libraries are defined in the project's `flake.nix` to ensure reproducibility.
    *   **Rust Version:** As defined in `flake.nix`.

---

## 4. Test Workload & Methodology

*   **Load Generator:** `[TODO: Specify tool, e.g., wrk2, k6, h2load]`
*   **Traffic Profile:**
    *   **Request Mix:** `[TODO: e.g., 80% GET, 20% POST]`
    *   **Request Size:** `[TODO: e.g., Average 512-byte headers, 4KB POST bodies]`
*   **Test Duration:** `[TODO: e.g., 10 minutes]`

---

## 5. WAF Configuration Under Test

*   **WAF Version:** `[TODO: Git commit hash]`
*   **Rule Set:** `[TODO: e.g., OWASP Core Rule Set v3.3.2 at Paranoia Level 1]`
*   **Features Enabled:** `[TODO: e.g., stdout logging, basic metrics]`

---

## 6. Raw Benchmark Output

```
[TODO: Paste the raw, unedited output from the benchmark tool here]
```
