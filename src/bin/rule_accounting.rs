//! Emits and verifies the pinned CRS rule-accounting manifest.
//!
//! ```text
//! cargo run --bin rule_accounting -- --check
//! cargo run --bin rule_accounting -- --support rules/crs/engine-support.json
//! cargo run --bin rule_accounting -- --emit-support rules/crs/engine-support.json
//! ```
//!
//! Exit codes: `0` success, `1` fatal error, `2` invalid invocation, `3` the
//! committed manifest drifted or the engine does not account for every rule.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Parser;
use waf_ingress::engine::accounting::{
    verify_complete, AccountingError, EngineSupport, Manifest, DEFAULT_MANIFEST_PATH,
    DEFAULT_RULES_PATH,
};

#[derive(Debug, Parser)]
#[command(
    name = "rule_accounting",
    about = "Emit and verify the pinned CRS rule-accounting manifest",
    version
)]
struct Args {
    /// Pinned CRS rule bundle.
    #[arg(long, default_value = DEFAULT_RULES_PATH)]
    source: PathBuf,

    /// Manifest path written by default and checked with `--check`.
    #[arg(long, default_value = DEFAULT_MANIFEST_PATH)]
    output: PathBuf,

    /// Verify that the committed manifest matches the rule bundle.
    #[arg(long)]
    check: bool,

    /// Verify an engine support declaration against the manifest.
    #[arg(long)]
    support: Option<PathBuf>,

    /// Write a full-support template the engine workstream can trim.
    #[arg(long)]
    emit_support: Option<PathBuf>,

    /// Print the manifest JSON to stdout instead of writing it.
    #[arg(long)]
    stdout: bool,
}

fn main() -> ExitCode {
    let args = Args::parse();
    match run(&args) {
        Ok(code) => code,
        Err(Fatal::Fatal(message)) => {
            eprintln!("error: {message}");
            ExitCode::from(1)
        }
    }
}

enum Fatal {
    Fatal(String),
}

fn run(args: &Args) -> Result<ExitCode, Fatal> {
    let manifest = Manifest::from_path(&args.source).map_err(|error| {
        Fatal::Fatal(format!(
            "failed to account for `{}`: {error}",
            args.source.display()
        ))
    })?;

    print_summary(&manifest, &args.source);

    if args.stdout {
        let json = manifest
            .to_json_pretty()
            .map_err(|error| Fatal::Fatal(error.to_string()))?;
        print!("{json}");
        return Ok(ExitCode::SUCCESS);
    }

    let mut code = ExitCode::SUCCESS;

    if args.check {
        code = check_manifest(&args.output, &manifest)?;
        if code != ExitCode::SUCCESS {
            return Ok(code);
        }
    } else if args.support.is_none() && args.emit_support.is_none() {
        manifest.write(&args.output).map_err(|error| {
            Fatal::Fatal(format!(
                "failed to write `{}`: {error}",
                args.output.display()
            ))
        })?;
        println!("manifest written to {}", args.output.display());
    }

    if let Some(path) = &args.emit_support {
        let support = EngineSupport::from_manifest(&manifest);
        let text = serde_json::to_string_pretty(&support)
            .map_err(|error| Fatal::Fatal(error.to_string()))?;
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|error| {
                    Fatal::Fatal(format!("failed to create `{}`: {error}", parent.display()))
                })?;
            }
        }
        std::fs::write(path, format!("{text}\n")).map_err(|error| {
            Fatal::Fatal(format!("failed to write `{}`: {error}", path.display()))
        })?;
        println!("support template written to {}", path.display());
    }

    if let Some(path) = &args.support {
        code = check_support(path, &manifest)?;
    }

    Ok(code)
}

fn print_summary(manifest: &Manifest, source: &Path) {
    println!(
        "rule accounting: {} entries, {} rule ids, {} chains ({} chained members) from {}",
        manifest.coverage.entries,
        manifest.coverage.rule_ids,
        manifest.coverage.chains,
        manifest.coverage.chain_members,
        source.display()
    );
    println!(
        "  directives: {}",
        join_counts(&manifest.coverage.directives)
    );
    println!(
        "  operators:  {}",
        join_counts(&manifest.coverage.operators)
    );
    println!(
        "  transforms: {}",
        join_counts(&manifest.coverage.transforms)
    );
    println!("  actions:    {}", join_counts(&manifest.coverage.actions));
    println!(
        "  constructs: {}",
        join_counts(&manifest.coverage.constructs)
    );
}

fn join_counts(counts: &std::collections::BTreeMap<String, usize>) -> String {
    counts
        .iter()
        .map(|(name, count)| format!("{name}={count}"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn check_manifest(path: &Path, manifest: &Manifest) -> Result<ExitCode, Fatal> {
    let committed = match Manifest::load(path) {
        Ok(committed) => committed,
        Err(AccountingError::Io { .. }) => {
            eprintln!(
                "error: no committed manifest at {}; run without --check to create it",
                path.display()
            );
            return Ok(ExitCode::from(3));
        }
        Err(error) => {
            return Err(Fatal::Fatal(format!(
                "failed to load `{}`: {error}",
                path.display()
            )));
        }
    };

    if committed == *manifest {
        println!("manifest is current: {}", path.display());
        return Ok(ExitCode::SUCCESS);
    }

    eprintln!("error: rule manifest drift detected at {}", path.display());
    if committed.source_sha256 != manifest.source_sha256 {
        eprintln!(
            "  source sha256: committed {}, current {}",
            committed.source_sha256, manifest.source_sha256
        );
    }
    if committed.entries.len() != manifest.entries.len() {
        eprintln!(
            "  entries: committed {}, current {}",
            committed.entries.len(),
            manifest.entries.len()
        );
    }
    if committed.coverage.rule_id_list != manifest.coverage.rule_id_list {
        let committed_ids: std::collections::BTreeSet<u32> =
            committed.coverage.rule_id_list.iter().copied().collect();
        let current_ids: std::collections::BTreeSet<u32> =
            manifest.coverage.rule_id_list.iter().copied().collect();
        let added: Vec<u32> = current_ids.difference(&committed_ids).copied().collect();
        let removed: Vec<u32> = committed_ids.difference(&current_ids).copied().collect();
        eprintln!("  rule ids added: {added:?}");
        eprintln!("  rule ids removed: {removed:?}");
    }
    if committed.coverage.operators != manifest.coverage.operators {
        eprintln!("  operators changed");
    }
    if committed.coverage.transforms != manifest.coverage.transforms {
        eprintln!("  transforms changed");
    }
    if committed.coverage.actions != manifest.coverage.actions {
        eprintln!("  actions changed");
    }
    if committed.coverage.constructs != manifest.coverage.constructs {
        eprintln!("  constructs changed");
    }
    eprintln!("run without --check to regenerate the manifest");
    Ok(ExitCode::from(3))
}

fn check_support(path: &Path, manifest: &Manifest) -> Result<ExitCode, Fatal> {
    let text = std::fs::read_to_string(path)
        .map_err(|error| Fatal::Fatal(format!("failed to read `{}`: {error}", path.display())))?;
    let support: EngineSupport = serde_json::from_str(&text).map_err(|error| {
        Fatal::Fatal(format!(
            "failed to parse engine support `{}`: {error}",
            path.display()
        ))
    })?;

    match verify_complete(manifest, &support) {
        Ok(verification) => {
            println!(
                "engine support complete: {} entries, {} rule ids, {} operators, {} transforms, {} actions, {} constructs",
                verification.entries,
                verification.rule_ids,
                verification.operators,
                verification.transforms,
                verification.actions,
                verification.constructs
            );
            Ok(ExitCode::SUCCESS)
        }
        Err(AccountingError::Incomplete { gaps }) => {
            eprintln!("error: engine does not account for every rule");
            let json = serde_json::to_string_pretty(&gaps)
                .map_err(|error| Fatal::Fatal(error.to_string()))?;
            eprintln!("{json}");
            Ok(ExitCode::from(3))
        }
        Err(error) => Err(Fatal::Fatal(error.to_string())),
    }
}
