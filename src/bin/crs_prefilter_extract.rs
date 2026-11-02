//! Offline CRS required-literal extractor.
//!
//! Usage:
//!
//! ```text
//! cargo run --features crs-prefilter --bin crs-prefilter-extract -- \
//!     [--rules <crs.conf>] [--out <prefilter.json>] [--summary <summary.md>]
//! ```
//!
//! Defaults match the vendored bundle and the committed artifact locations.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use waf_ingress::waf::prefilter_extract::{
    default_artifact_path, default_summary_path, extract_from_path_with_paranoia, render_summary,
};

const DEFAULT_RULES: &str = "wasm/coraza_reactor/rules/crs/crs.conf";

fn main() -> ExitCode {
    let mut rules = PathBuf::from(DEFAULT_RULES);
    let mut out = default_artifact_path();
    let mut summary = default_summary_path();
    let mut paranoia_level = 1u32;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--rules" => {
                if let Some(value) = args.next() {
                    rules = PathBuf::from(value);
                }
            }
            "--paranoia-level" => {
                if let Some(value) = args.next() {
                    paranoia_level = value.parse().unwrap_or(1);
                }
            }
            "--out" => {
                if let Some(value) = args.next() {
                    out = PathBuf::from(value);
                }
            }
            "--summary" => {
                if let Some(value) = args.next() {
                    summary = PathBuf::from(value);
                }
            }
            "-h" | "--help" => {
                println!(
                    "crs-prefilter-extract [--rules <crs.conf>] [--paranoia-level N] [--out <prefilter.json>] [--summary <summary.md>]"
                );
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("unknown argument: {other}");
                return ExitCode::from(2);
            }
        }
    }

    match run(&rules, paranoia_level, &out, &summary) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("crs-prefilter-extract: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run(
    rules: &Path,
    paranoia_level: u32,
    out: &Path,
    summary: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let artifact = extract_from_path_with_paranoia(rules, paranoia_level)?;
    let json = serde_json::to_string_pretty(&artifact)?;
    write(out, json.as_bytes())?;
    write(summary, render_summary(&artifact).as_bytes())?;

    let cov = &artifact.coverage;
    println!(
        "parsed {} body-relevant entries: {} gated, {} ungated",
        cov.body_relevant_entries, cov.body_relevant_gated, cov.body_relevant_ungated
    );
    println!(
        "distinct literals: {} ({} members); all body rules gated: {}",
        cov.distinct_literals, cov.total_literals, cov.all_body_rules_gated
    );
    if !cov.ungated_by_family.is_empty() {
        let families: Vec<String> = cov
            .ungated_by_family
            .iter()
            .map(|(family, count)| format!("{family}:{count}"))
            .collect();
        println!("ungated by family: {}", families.join(", "));
    }
    println!("wrote {}", out.display());
    println!("wrote {}", summary.display());
    Ok(())
}

fn write(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    fs::write(path, bytes)
}
