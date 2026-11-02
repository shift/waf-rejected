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

        # Pinned Rust toolchain. wasmtime 49 requires Rust >= 1.96; 1.99.1 is
        # the newest stable published by the locked rust-overlay input.
        rustVersion = pkgs.rust-bin.stable."1.99.1".default.override {
          extensions = [ "rust-src" "rustfmt" "clippy" ];
        };

        # Crane library instantiated with pkgs
        craneLib = crane.mkLib pkgs;

        # Filter source files
        # `cleanCargoSource` keeps only Cargo inputs, which drops the reactor
        # modules that are embedded with `include_bytes!`/`include_str!`.
        # Keep `wasm/` as well or the package build fails to compile.
        src = pkgs.lib.cleanSourceWith {
          src = ./.;
          filter =
            path: type:
            (craneLib.filterCargoSources path type)
            || (builtins.match ".*/wasm/.*" path != null);
        };

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
          # `coraza-native` enables the opt-in native sidecar backend only; the
          # default `waf.coraza.backend` stays "wasm".
          cargoBuildCommand = "cargo build --release --bin waf-ingress --features http3,webtransport,wasm-reactor,coraza-native";
          cargoCheckCommand = "cargo check --release --bin waf-ingress --features http3,webtransport,wasm-reactor,coraza-native";
          # Tests run in the dedicated CI/test jobs; keeping them out of the
          # package build avoids compiling every test utility binary twice.
          doCheck = false;

          # Ship the Coraza reactor at a stable, read-only path next to the
          # binary. Fail the package build if the digest or size budget drifts.
          postInstall = ''
            mkdir -p "$out/share/waf/wasm"
            install -m644 ${./wasm/coraza_reactor/coraza_reactor.wasm} \
              "$out/share/waf/wasm/coraza_reactor.wasm"
            install -m644 ${./wasm/coraza_reactor/LICENSE-CRS} \
              "$out/share/waf/wasm/LICENSE-CRS"
            install -m644 ${./wasm/coraza_reactor/PROVENANCE.md} \
              "$out/share/waf/wasm/PROVENANCE.md"
            install -m644 ${./wasm/coraza_reactor/SHA256SUMS} \
              "$out/share/waf/wasm/SHA256SUMS"
            (cd "$out/share/waf/wasm" && sha256sum --check SHA256SUMS)
            test "$(stat -c%s "$out/share/waf/wasm/coraza_reactor.wasm")" -le 33554432
          '';

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

        # Native Go Coraza sidecar (experimental, non-default backend). It
        # reuses the vendored Coraza module and CRS bundle from
        # wasm/coraza_reactor, so no rule material is duplicated.
        coraza-native-sidecar = pkgs.stdenv.mkDerivation {
          pname = "coraza-native-sidecar";
          version = "0.1.0";
          src = pkgs.lib.cleanSourceWith {
            src = ./.;
            filter = path: _:
              let p = toString path; in
              !(pkgs.lib.hasPrefix (toString ./target) p)
              && !(pkgs.lib.hasPrefix (toString ./.git) p)
              && !(pkgs.lib.hasPrefix (toString ./.worktrees) p);
          };
          nativeBuildInputs = [ pkgs.go ];
          dontConfigure = true;
          buildPhase = ''
            runHook preBuild
            cd native/coraza-sidecar
            export HOME="$NIX_BUILD_TOP"
            export GOCACHE="$TMPDIR/go-cache"
            export GOOS=linux
            export GOARCH=${if pkgs.stdenv.hostPlatform.isAarch64 then "arm64" else "amd64"}
            export CGO_ENABLED=0
            export GOFLAGS=-mod=vendor
            go build -trimpath -ldflags="-s -w" -o coraza-sidecar .
            runHook postBuild
          '';
          installPhase = ''
            runHook preInstall
            mkdir -p "$out/bin" "$out/share/waf/coraza"
            install -m755 coraza-sidecar "$out/bin/coraza-sidecar"
            cp -r ../../wasm/coraza_reactor/rules/crs "$out/share/waf/coraza/crs"
            install -m644 ../../wasm/coraza_reactor/LICENSE-CRS \
              "$out/share/waf/coraza/LICENSE-CRS"
            install -m644 ../../wasm/coraza_reactor/PROVENANCE.md \
              "$out/share/waf/coraza/PROVENANCE.md"
            runHook postInstall
          '';
          meta = with pkgs.lib; {
            description = "Native Go Coraza/OWASP CRS sidecar for WAF-Rejected";
            homepage = "https://github.com/shift/waf-rejected";
            license = with licenses; [ asl20 ];
            mainProgram = "coraza-sidecar";
          };
        };
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

          # Export system tools
          waf-events-query = waf-events-query;
          create-sample-db = create-sample-db;

          # Convenience package that builds all binaries
          all = all-binaries;

          # Experimental native Go Coraza sidecar (not part of default builds)
          coraza-native-sidecar = coraza-native-sidecar;
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
            cargo-audit  # Dependency vulnerability scan (cargo audit)
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
