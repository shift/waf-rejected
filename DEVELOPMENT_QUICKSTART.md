# Developer Quickstart Guide

## 1. Introduction

This guide provides the essential, step-by-step instructions to get a local development environment for `waf-rejected` set up and running. The goal is to enable you to build the application, run the core MVP functionality, and execute the test suite.

---

## 2. Prerequisites

This project uses the Nix package manager to ensure a completely reproducible development environment. All required tools (Rust, Cargo, etc.) are provided by the Nix flake.

*   **Required:** You must have [Nix installed](https://nixos.org/download.html) on your system (Linux or macOS).
*   **Required:** `git` for cloning the repository.

---

## 3. Step-by-Step Setup

### Step 1: Clone the Repository

First, clone the project from our Git repository:

```bash
git clone https://github.com/your-org/waf-rejected.git
cd waf-rejected
```

### Step 2: Enter the Development Environment

Once inside the project directory, use the `nix develop` command. This will automatically install all the correct versions of the tools specified in our `flake.nix` file and drop you into a development shell.

```bash
nix develop
```

> **Note:** The first time you run this command, it may take several minutes to download and build the dependencies. Subsequent runs will be much faster.

### Step 3: Build the Application

Now that you are inside the Nix shell, you can build the entire project using the standard Cargo command. This will build the core library and all binaries in `src/bin/`.

```bash
cargo build
```

For a release build (which is slower to compile but much faster to run), use:

```bash
cargo build --release
```

### Step 4: Run the MVP Locally

To test the WAF, you need two components: a backend application for the WAF to protect, and the WAF itself. We use our `justfile` to manage this.

1.  **Start the Test Backend:**
    In your first terminal (already inside the `nix develop` shell), run the following command. This will start a simple web server on `localhost:3000` that echoes requests.

    ```bash
    # TODO: This command needs to be created in the justfile
    just run-test-backend
    ```

2.  **Start the WAF:**
    Open a **second terminal**, navigate to the project directory, and enter the Nix shell again (`nix develop`). Then, run the command to start the WAF MVP. It will be configured by default to protect the test backend.

    ```bash
    # TODO: This command needs to be created in the justfile
    just run-waf-mvp
    ```

The WAF should now be running and listening on `localhost:8080`.

### Step 5: Verify the Setup

You can now send requests to the WAF to verify it's working.

1.  **Send a normal request:** This should pass through the WAF and be echoed back by the backend server.

    ```bash
    curl http://localhost:8080/
    ```

2.  **Send a malicious request:** This should be blocked by the WAF, which will print a JSON log to its `stdout` and return an error to you.

    ```bash
    curl http://localhost:8080/?q="' OR 1=1 --"
    ```

### Step 6: Run the Test Suite

To run all automated tests, simply use the standard Cargo command:

```bash
cargo test --all-features
```

This will run all unit and integration tests for the entire project.
