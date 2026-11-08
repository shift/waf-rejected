//! Build script for the experimental Vectorscan/Hyperscan evaluation target.
//!
//! The `hyperscan-eval` feature is non-default. It links the system
//! `libhs` (nixpkgs `vectorscan`) through a small hand-written FFI surface in
//! `src/waf/hyperscan.rs`; no crates.io binding is required. When the feature
//! is disabled this script emits nothing, so default builds do not need the
//! library at all.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    if std::env::var_os("CARGO_FEATURE_HYPERSCAN_EVAL").is_none() {
        return;
    }

    println!("cargo:rerun-if-env-changed=HS_LIB_DIR");
    if let Some(dir) = std::env::var_os("HS_LIB_DIR") {
        println!("cargo:rustc-link-search=native={}", dir.to_string_lossy());
    }

    // Best effort: Nix puts `libhs` on NIX_LDFLAGS through buildInputs, but a
    // plain `cargo build` in a dev shell can also discover it via pkg-config.
    if let Ok(output) = std::process::Command::new("pkg-config")
        .args(["--libs-only-L", "libhs"])
        .output()
    {
        if output.status.success() {
            for token in String::from_utf8_lossy(&output.stdout).split_whitespace() {
                if let Some(dir) = token.strip_prefix("-L") {
                    println!("cargo:rustc-link-search=native={dir}");
                }
            }
        }
    }

    println!("cargo:rustc-link-lib=hs");
}
