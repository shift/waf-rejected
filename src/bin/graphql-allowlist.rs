//! Generate a deterministic GraphQL persisted-query allowlist.
//!
//! ```text
//! graphql-allowlist --manifest persisted-queries.json --output allowlist.json
//! graphql-allowlist --dir client/build/graphql --allow-mutations -o out.json
//! graphql-allowlist --manifest manifest.json --dir queries --max-query-bytes 65536
//! ```
//!
//! See `docs/graphql-inspection.md` for the ingestion workflow.

use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use waf_ingress::waf::graphql_allowlist::{
    build_allowlist, GenerateOptions, GraphqlAllowlistError,
};

const HELP: &str = "\
Generate a deterministic GraphQL persisted-query allowlist.

USAGE:
    graphql-allowlist (--manifest <PATH> | --dir <PATH>) [OPTIONS]

OPTIONS:
    -m, --manifest <PATH>            JSON list of {name, query} or {name, sha256}.
    -d, --dir <PATH>                 Directory of .graphql files (named by stem).
    -o, --output <PATH>              Write the artifact to PATH instead of stdout.
        --max-query-bytes <N>        Maximum raw query size (default 1048576).
        --allow-mutations            Allow mutation operations.
        --allow-subscriptions        Allow subscription operations.
        --unknown-operation-action <action>
                                     'allow' or 'block' (default block).
    -h, --help                       Print this help.

Queries are normalised (comments removed, commas and whitespace collapsed
outside strings) before hashing. The artifact records the SHA-256 of the
canonical inputs so reviewers can verify provenance and diff allowlists in CI.
Exit status is non-zero for malformed JSON, empty queries, duplicate names or
hashes, invalid hashes, and unsupported operation types.
";

#[derive(Debug, Default)]
struct Cli {
    manifest: Option<PathBuf>,
    directory: Option<PathBuf>,
    output: Option<PathBuf>,
    max_query_bytes: Option<usize>,
    allow_mutations: bool,
    allow_subscriptions: bool,
    unknown_operation_action: Option<String>,
}

fn main() -> ExitCode {
    match run(std::env::args().skip(1)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(HelpOrError::Help) => {
            print!("{HELP}");
            ExitCode::SUCCESS
        }
        Err(HelpOrError::Error(error)) => {
            eprintln!("graphql-allowlist: error: {error}");
            ExitCode::FAILURE
        }
    }
}

enum HelpOrError {
    Help,
    Error(GraphqlAllowlistError),
}

impl From<GraphqlAllowlistError> for HelpOrError {
    fn from(error: GraphqlAllowlistError) -> Self {
        Self::Error(error)
    }
}

fn run(args: impl Iterator<Item = String>) -> Result<(), HelpOrError> {
    let Some(cli) = parse_args(args)? else {
        return Err(HelpOrError::Help);
    };

    let mut options = GenerateOptions::default();
    if let Some(limit) = cli.max_query_bytes {
        options.max_query_bytes = limit;
    }
    options.allow_mutations = cli.allow_mutations;
    options.allow_subscriptions = cli.allow_subscriptions;
    if let Some(action) = cli.unknown_operation_action {
        options.unknown_operation_action = action;
    }

    let manifest = match cli.manifest.as_deref() {
        Some(path) => Some(fs::read(path).map_err(|error| GraphqlAllowlistError::Io {
            path: path.display().to_string(),
            source: error,
        })?),
        None => None,
    };
    let allowlist = build_allowlist(manifest.as_deref(), cli.directory.as_deref(), &options)?;
    let json = allowlist.to_canonical_json()?;
    match cli.output {
        Some(path) => fs::write(&path, json).map_err(|error| GraphqlAllowlistError::Io {
            path: path.display().to_string(),
            source: error,
        })?,
        None => print!("{json}"),
    }
    Ok(())
}

fn parse_args(
    mut args: impl Iterator<Item = String>,
) -> Result<Option<Cli>, GraphqlAllowlistError> {
    let mut cli = Cli::default();
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "-h" | "--help" => return Ok(None),
            "-m" | "--manifest" => {
                cli.manifest = Some(PathBuf::from(next_value(&mut args, &argument)?));
            }
            "-d" | "--dir" => {
                cli.directory = Some(PathBuf::from(next_value(&mut args, &argument)?));
            }
            "-o" | "--output" => {
                cli.output = Some(PathBuf::from(next_value(&mut args, &argument)?));
            }
            "--max-query-bytes" => {
                let value = next_value(&mut args, &argument)?;
                let limit = value.parse::<usize>().map_err(|_| {
                    GraphqlAllowlistError::Cli(format!(
                        "--max-query-bytes expects a positive integer, got '{value}'"
                    ))
                })?;
                if limit == 0 {
                    return Err(GraphqlAllowlistError::Cli(
                        "--max-query-bytes must be greater than zero".to_string(),
                    ));
                }
                cli.max_query_bytes = Some(limit);
            }
            "--allow-mutations" => cli.allow_mutations = true,
            "--allow-subscriptions" => cli.allow_subscriptions = true,
            "--unknown-operation-action" => {
                let value = next_value(&mut args, &argument)?;
                if value != "allow" && value != "block" {
                    return Err(GraphqlAllowlistError::Cli(format!(
                        "--unknown-operation-action must be 'allow' or 'block', got '{value}'"
                    )));
                }
                cli.unknown_operation_action = Some(value);
            }
            other => {
                return Err(GraphqlAllowlistError::Cli(format!(
                    "unexpected argument '{other}' (try --help)"
                )));
            }
        }
    }

    if cli.manifest.is_none() && cli.directory.is_none() {
        return Err(GraphqlAllowlistError::Cli(
            "missing required --manifest <PATH> or --dir <PATH> (try --help)".to_string(),
        ));
    }
    Ok(Some(cli))
}

fn next_value(
    args: &mut impl Iterator<Item = String>,
    flag: &str,
) -> Result<String, GraphqlAllowlistError> {
    args.next()
        .ok_or_else(|| GraphqlAllowlistError::Cli(format!("{flag} requires a value")))
}
