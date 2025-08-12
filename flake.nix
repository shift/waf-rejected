{
  description = "WAF Rejected - Enterprise Web Application Firewall";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };

        rustVersion = pkgs.rust-bin.stable.latest.default.override {
          extensions = [ "rust-src" "rustfmt" "clippy" ];
        };
      in
      {
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
            echo "🏢 WAF Rejected Development Environment"
            echo "====================================="
            echo "✅ Rust $(rustc --version)"
            echo "✅ Go $(go version)"
            echo "✅ WASM Runtime $(wasmtime --version)"
            echo "✅ GCC $(gcc --version | head -n1)"
            echo "✅ Clang $(clang --version | head -n1)"
            echo ""
            echo "🚀 Ready for enterprise development with WASM support!"
            echo "📚 Available commands:"
            echo "   • cargo build --release         # Build optimized WAF"
            echo "   • cargo test                    # Run test suite"  
            echo "   • ./enterprise_waf_test.sh      # Enterprise validation"
            echo "   • just bench                    # Run benchmarks"
            echo ""
            echo "🔧 WASM Development:"
            echo "   • just build-modsec-wasm         # Build ModSecurity WASM module"
            echo "   • wasmtime --version             # Test WASM runtime"
            echo "   • wasm-opt --help                # WASM optimization"
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
