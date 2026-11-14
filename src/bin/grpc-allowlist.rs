//! Generate a gRPC method allowlist from a protobuf `FileDescriptorSet`.
//!
//! ```text
//! grpc-allowlist --descriptor descriptor.binpb --output grpc-allowlist.json
//! grpc-allowlist -d descriptor.json --max-message-bytes 1048576
//! grpc-allowlist -d descriptor.binpb --overrides grpc-allowlist.toml -o out.json
//! ```
//!
//! See `docs/grpc-inspection.md` for the ingestion workflow.

use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use waf_ingress::waf::grpc_allowlist::{
    build_allowlist, generate_from_descriptor_path, load_overrides, AllowlistOptions,
    DescriptorFormat, GrpcAllowlistError,
};

const HELP: &str = "\
Generate a deterministic gRPC method allowlist from a protobuf FileDescriptorSet.

USAGE:
    grpc-allowlist --descriptor <PATH> [OPTIONS]

OPTIONS:
    -d, --descriptor <PATH>          FileDescriptorSet to read (.binpb or .json).
    -f, --format <auto|binpb|json>   Descriptor format. Defaults to the extension.
    -o, --output <PATH>              Write the artifact to PATH instead of stdout.
        --max-message-bytes <N>      Default per-message limit (default 4194304).
        --overrides <PATH>           Optional TOML per-method override file.
        --unknown-method-action <action>
                                     'allow' or 'block' (default block).
    -h, --help                       Print this help.

The artifact records the SHA-256 of the descriptor bytes so reviewers can
verify provenance and diff allowlists in CI. Exit status is non-zero for any
malformed descriptor, duplicate method, unresolved type or invalid artifact.
";

#[derive(Debug, Default)]
struct Cli {
    descriptor: PathBuf,
    format: Option<DescriptorFormat>,
    output: Option<PathBuf>,
    max_message_bytes: Option<usize>,
    overrides: Option<PathBuf>,
    unknown_method_action: Option<String>,
}

fn main() -> ExitCode {
    match run(std::env::args().skip(1)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(HelpOrError::Help) => {
            print!("{HELP}");
            ExitCode::SUCCESS
        }
        Err(HelpOrError::Error(error)) => {
            eprintln!("grpc-allowlist: error: {error}");
            ExitCode::FAILURE
        }
    }
}

enum HelpOrError {
    Help,
    Error(GrpcAllowlistError),
}

impl From<GrpcAllowlistError> for HelpOrError {
    fn from(error: GrpcAllowlistError) -> Self {
        Self::Error(error)
    }
}

fn run(args: impl Iterator<Item = String>) -> Result<(), HelpOrError> {
    let Some(cli) = parse_args(args)? else {
        return Err(HelpOrError::Help);
    };

    let mut options = AllowlistOptions::default();
    if let Some(path) = &cli.overrides {
        options = load_overrides(path, options)?;
    }
    if let Some(limit) = cli.max_message_bytes {
        options.max_message_bytes = limit;
    }
    if let Some(action) = cli.unknown_method_action {
        options.unknown_method_action = action;
    }

    let allowlist = match cli.format {
        Some(format) => {
            let bytes = fs::read(&cli.descriptor).map_err(|error| GrpcAllowlistError::Io {
                path: cli.descriptor.display().to_string(),
                source: error,
            })?;
            build_allowlist(&bytes, format, &options)?
        }
        None => generate_from_descriptor_path(&cli.descriptor, &options)?,
    };

    let json = allowlist.to_canonical_json()?;
    match cli.output {
        Some(path) => fs::write(&path, json).map_err(|error| GrpcAllowlistError::Io {
            path: path.display().to_string(),
            source: error,
        })?,
        None => print!("{json}"),
    }
    Ok(())
}

fn parse_args(mut args: impl Iterator<Item = String>) -> Result<Option<Cli>, GrpcAllowlistError> {
    let mut cli = Cli::default();
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "-h" | "--help" => return Ok(None),
            "-d" | "--descriptor" => {
                cli.descriptor = PathBuf::from(next_value(&mut args, &argument)?);
            }
            "-f" | "--format" => {
                cli.format = Some(DescriptorFormat::parse(&next_value(&mut args, &argument)?)?);
            }
            "-o" | "--output" => {
                cli.output = Some(PathBuf::from(next_value(&mut args, &argument)?));
            }
            "--max-message-bytes" => {
                let value = next_value(&mut args, &argument)?;
                cli.max_message_bytes = Some(value.parse::<usize>().map_err(|_| {
                    GrpcAllowlistError::Cli(format!(
                        "--max-message-bytes expects a positive integer, got '{value}'"
                    ))
                })?);
                if cli.max_message_bytes == Some(0) {
                    return Err(GrpcAllowlistError::Cli(
                        "--max-message-bytes must be greater than zero".to_string(),
                    ));
                }
            }
            "--overrides" => {
                cli.overrides = Some(PathBuf::from(next_value(&mut args, &argument)?));
            }
            "--unknown-method-action" => {
                let value = next_value(&mut args, &argument)?;
                if value != "allow" && value != "block" {
                    return Err(GrpcAllowlistError::Cli(format!(
                        "--unknown-method-action must be 'allow' or 'block', got '{value}'"
                    )));
                }
                cli.unknown_method_action = Some(value);
            }
            other => {
                return Err(GrpcAllowlistError::Cli(format!(
                    "unexpected argument '{other}' (try --help)"
                )));
            }
        }
    }

    if cli.descriptor.as_os_str().is_empty() {
        return Err(GrpcAllowlistError::Cli(
            "missing required --descriptor <PATH> (try --help)".to_string(),
        ));
    }
    Ok(Some(cli))
}

fn next_value(
    args: &mut impl Iterator<Item = String>,
    flag: &str,
) -> Result<String, GrpcAllowlistError> {
    args.next()
        .ok_or_else(|| GrpcAllowlistError::Cli(format!("{flag} requires a value")))
}
