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
            echo "✅ GCC $(gcc --version | head -n1)"
            echo "✅ Clang $(clang --version | head -n1)"
            echo ""
            echo "🚀 Ready for enterprise development!"
            echo "📚 Available commands:"
            echo "   • cargo build --release         # Build optimized WAF"
            echo "   • cargo test                    # Run test suite"  
            echo "   • ./enterprise_waf_test.sh      # Enterprise validation"
            echo "   • just bench                    # Run benchmarks"
            echo ""
          '';

          # Environment variables
          RUST_SRC_PATH = "${rustVersion}/lib/rustlib/src/rust/src";
          PKG_CONFIG_PATH = "${pkgs.openssl.dev}/lib/pkgconfig:${pkgs.zlib.dev}/lib/pkgconfig";
        };
      });
}
