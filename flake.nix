{
  description = "WAF Rejected - Enterprise Web Application Firewall";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay.url = "github:oxalica/rust-overlay";
    crane = {
      url = "github:ipetkov/crane";
    };
  };

  nixConfig = {
    extra-substituters = [
      "https://cache.garnix.io"
      "https://shift.cachix.org"
    ];
    extra-trusted-public-keys = [
      "cache.garnix.io:CTFPyKSLcx5RMJKfLo5EEPUObbA78b0YQ2DTCJXqr9g="
      "shift.cachix.org-1:GfqZjV2WglCFobSSZ+l+IH2ojrY8LyJVA6cMmgVVBgk="
    ];
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay, crane }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };

        rustVersion = pkgs.rust-bin.stable.latest.default.override {
          extensions = [ "rust-src" "rustfmt" "clippy" ];
        };

        # Crane library instantiated with pkgs
        craneLib = crane.mkLib pkgs;

        # Filter source files
        src = craneLib.cleanCargoSource ./.;

        # Common arguments for all derivations
        commonArgs = {
          inherit src;
          strictDeps = true;
          
          nativeBuildInputs = with pkgs; [
            rustVersion
            pkg-config
            cmake
          ];

          buildInputs = with pkgs; [
            openssl
            zlib
            zstd
          ] ++ lib.optionals stdenv.isDarwin [
            # macOS specific dependencies
            pkgs.libiconv
            pkgs.darwin.apple_sdk.frameworks.Security
            pkgs.darwin.apple_sdk.frameworks.SystemConfiguration
          ];

          # Environment variables
          PKG_CONFIG_PATH = "${pkgs.openssl.dev}/lib/pkgconfig:${pkgs.zlib.dev}/lib/pkgconfig";
        };

        # Build *just* the cargo dependencies, so we can reuse all of that work between builds
        cargoArtifacts = craneLib.buildDepsOnly commonArgs;

        # Individual package builds
        waf-ingress = craneLib.buildPackage (commonArgs // {
          inherit cargoArtifacts;
          pname = "waf-ingress";
          
          # Build main binary
          cargoBuildCommand = "cargo build --release --bin waf-ingress";
          cargoCheckCommand = "cargo check --release --bin waf-ingress";
          # Tests run in the dedicated CI/test jobs; keeping them out of the
          # package build avoids compiling every test utility binary twice.
          doCheck = false;
          
          meta = with pkgs.lib; {
            description = "High-Performance Rust-Based WAF Ingress";
            homepage = "https://github.com/shift/waf-rejected";
            license = with licenses; [ mit asl20 ];
            maintainers = [ ];
          };
        });

        # Enterprise test binaries
        enterprise-performance-test = craneLib.buildPackage (commonArgs // {
          inherit cargoArtifacts;
          pname = "enterprise-performance-test";
          cargoBuildCommand = "cargo build --release --bin enterprise_performance_test";
          cargoCheckCommand = "cargo check --release --bin enterprise_performance_test";
        });

        enterprise-security-test = craneLib.buildPackage (commonArgs // {
          inherit cargoArtifacts;
          pname = "enterprise-security-test";
          cargoBuildCommand = "cargo build --release --bin enterprise_security_test";
          cargoCheckCommand = "cargo check --release --bin enterprise_security_test";
        });

        enterprise-compliance-test = craneLib.buildPackage (commonArgs // {
          inherit cargoArtifacts;
          pname = "enterprise-compliance-test";
          cargoBuildCommand = "cargo build --release --bin enterprise_compliance_test";
          cargoCheckCommand = "cargo check --release --bin enterprise_compliance_test";
        });

        enterprise-availability-test = craneLib.buildPackage (commonArgs // {
          inherit cargoArtifacts;
          pname = "enterprise-availability-test";
          cargoBuildCommand = "cargo build --release --bin enterprise_availability_test";
          cargoCheckCommand = "cargo check --release --bin enterprise_availability_test";
        });

        enterprise-modsecurity-test = craneLib.buildPackage (commonArgs // {
          inherit cargoArtifacts;
          pname = "enterprise-modsecurity-test";
          cargoBuildCommand = "cargo build --release --bin enterprise_modsecurity_test";
          cargoCheckCommand = "cargo check --release --bin enterprise_modsecurity_test";
        });

        # Test and utility binaries
        progressive-load-test = craneLib.buildPackage (commonArgs // {
          inherit cargoArtifacts;
          pname = "progressive-load-test";
          cargoBuildCommand = "cargo build --release --bin progressive_load_test";
          cargoCheckCommand = "cargo check --release --bin progressive_load_test";
        });

        echo-backend = craneLib.buildPackage (commonArgs // {
          inherit cargoArtifacts;
          pname = "echo-backend";
          cargoBuildCommand = "cargo build --release --bin echo_backend";
          cargoCheckCommand = "cargo check --release --bin echo_backend";
        });

        simple-multi-protocol-test = craneLib.buildPackage (commonArgs // {
          inherit cargoArtifacts;
          pname = "simple-multi-protocol-test";
          cargoBuildCommand = "cargo build --release --bin simple_multi_protocol_test";
          cargoCheckCommand = "cargo check --release --bin simple_multi_protocol_test";
        });

        websocket-performance-test = craneLib.buildPackage (commonArgs // {
          inherit cargoArtifacts;
          pname = "websocket-performance-test";
          cargoBuildCommand = "cargo build --release --bin websocket_performance_test";
          cargoCheckCommand = "cargo check --release --bin websocket_performance_test";
        });

        # WASM-enabled binaries (conditional)
        test-wasm-integration = craneLib.buildPackage (commonArgs // {
          inherit cargoArtifacts;
          pname = "test-wasm-integration";
          cargoBuildCommand = "cargo build --release --bin test_wasm_integration --features wasm-waf";
          cargoCheckCommand = "cargo check --release --bin test_wasm_integration --features wasm-waf";
          
          # Additional WASM runtime tools for building
          nativeBuildInputs = commonArgs.nativeBuildInputs ++ (with pkgs; [
            wasmtime
            binaryen
            wabt
          ]);
        });

        # WebTransport binaries (conditional on feature)
        webtransport-waf-proxy = craneLib.buildPackage (commonArgs // {
          inherit cargoArtifacts;
          pname = "webtransport-waf-proxy";
          cargoBuildCommand = "cargo build --release --bin webtransport_waf_proxy --features webtransport";
          cargoCheckCommand = "cargo check --release --bin webtransport_waf_proxy --features webtransport";
        });

        webtransport-echo-backend = craneLib.buildPackage (commonArgs // {
          inherit cargoArtifacts;
          pname = "webtransport-echo-backend";
          cargoBuildCommand = "cargo build --release --bin webtransport_echo_backend --features webtransport";
          cargoCheckCommand = "cargo check --release --bin webtransport_echo_backend --features webtransport";
        });

        # Export system binaries  
        waf-events-query = craneLib.buildPackage (commonArgs // {
          inherit cargoArtifacts;
          pname = "waf-events-query";
          cargoBuildCommand = "cargo build --release --bin waf-events-query --features export-sled";
          cargoCheckCommand = "cargo check --release --bin waf-events-query --features export-sled";
        });

        create-sample-db = craneLib.buildPackage (commonArgs // {
          inherit cargoArtifacts;
          pname = "create-sample-db";
          cargoBuildCommand = "cargo build --release --bin create_sample_db --features export-sled";
          cargoCheckCommand = "cargo check --release --bin create_sample_db --features export-sled";
        });

        # All binaries package - builds everything at once
        all-binaries = craneLib.buildPackage (commonArgs // {
          inherit cargoArtifacts;
          pname = "waf-all-binaries";
          cargoBuildCommand = "cargo build --release --all-targets";
          cargoCheckCommand = "cargo check --release --all-targets";
        });
      in
      {
        packages = {
          # Main WAF binary
          default = waf-ingress;
          waf-ingress = waf-ingress;

          # Enterprise test suite
          enterprise-performance-test = enterprise-performance-test;
          enterprise-security-test = enterprise-security-test;
          enterprise-compliance-test = enterprise-compliance-test;
          enterprise-availability-test = enterprise-availability-test;
          enterprise-modsecurity-test = enterprise-modsecurity-test;

          # Test and utility binaries
          progressive-load-test = progressive-load-test;
          echo-backend = echo-backend;
          simple-multi-protocol-test = simple-multi-protocol-test;
          websocket-performance-test = websocket-performance-test;

          # WASM integration
          test-wasm-integration = test-wasm-integration;

          # WebTransport (experimental)
          webtransport-waf-proxy = webtransport-waf-proxy;
          webtransport-echo-backend = webtransport-echo-backend;

          # Export system tools
          waf-events-query = waf-events-query;
          create-sample-db = create-sample-db;

          # Convenience package that builds all binaries
          all = all-binaries;
        };
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            # Rust toolchain
            rustVersion
            rust-analyzer

            # Go toolchain for WASM compilation
            go
            binaryen  # WASM optimization tools (wasm-opt)
            wabt  # WebAssembly Binary Toolkit (wat2wasm, wasm2wat)
            
            # WASM runtime tools
            wasmtime  # WASM runtime for testing

            # C/C++ build tools
            gcc
            clang
            cmake
            pkg-config

            # System libraries
            openssl
            zlib
            zstd

            # Development tools
            git
            just
            
            # Testing and benchmarking
            wrk
            curl
            jq
            gnuplot  # Added for Criterion benchmark plotting
            
            # Monitoring and observability
            prometheus
            grafana
            
            # Database tools
            sqlite
            postgresql
          ];

          shellHook = ''
            echo "🏢 WAF Rejected Development Environment (Nix)"
            echo "==========================================="
            echo "✅ Rust $(rustc --version)"
            echo "✅ Go $(go version)"
            echo "✅ WASM Runtime $(wasmtime --version)"
            echo "✅ GCC $(gcc --version | head -n1)"
            echo "✅ Clang $(clang --version | head -n1)"
            echo ""
            echo "🚀 Use nix to run all commands:"
            echo "   nix develop -c cargo build --release            # Build optimized WAF"
            echo "   nix develop -c cargo test --all --release       # Run test suite"
            echo "   nix develop -c ./target/release/simple_multi_protocol_test"
            echo "   nix develop -c ./target/release/progressive_load_test"
            echo "   nix develop -c ./target/release/websocket_performance_test"
            echo "   nix develop -c just bench                       # Run benchmarks"
            echo ""
            echo "🔧 WASM Development:"
            echo "   nix develop -c just build-modsec-wasm           # Build ModSecurity WASM module"
            echo "   nix develop -c wasmtime --version               # Test WASM runtime"
            echo "   nix develop -c wasm-opt --help                  # WASM optimization"
            echo ""
            echo "📦 Build individual packages:"
            echo "   nix build                                      # Build main WAF"
            echo "   nix build .#enterprise-performance-test       # Build enterprise tests"
            echo "   nix build .#all                                # Build all binaries"
            echo ""
          '';

          # Environment variables
          RUST_SRC_PATH = "${rustVersion}/lib/rustlib/src/rust/src";
          PKG_CONFIG_PATH = "${pkgs.openssl.dev}/lib/pkgconfig:${pkgs.zlib.dev}/lib/pkgconfig";
          
          # Go and WASM environment
          GOOS = "js";
          GOARCH = "wasm";
          CGO_ENABLED = "0";
          
          # WASM build tools
          WASMTIME_PATH = "${pkgs.wasmtime}/bin/wasmtime";
          WASM_OPT_PATH = "${pkgs.binaryen}/bin/wasm-opt";
        };
      });
}
