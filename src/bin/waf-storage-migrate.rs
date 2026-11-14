//! Migrate the security-event store between sled (legacy) and redb (default).
//!
//! See `docs/operations/migrating-event-store.md` for the runbook.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;
use waf_ingress::waf::storage::{
    legacy_event_trees, migrate, LegacySledTreeAdapter, MigrationError, MigrationOptions,
    ReadConsistency, RedbStorageAdapter, SledStorageAdapter, StorageAdapter,
};

use clap::{Parser, ValueEnum};

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum Backend {
    Sled,
    Redb,
}

impl Backend {
    fn as_str(self) -> &'static str {
        match self {
            Backend::Sled => "sled",
            Backend::Redb => "redb",
        }
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "waf-storage-migrate",
    version,
    about = "Copy and verify a WAF security-event store between sled and redb",
    long_about = "Copies every live event from one embedded store to another, then runs a \
verification pass that compares key counts and a SHA-256 digest over key/value/TTL-presence. \
Progress is checkpointed after every batch, so an interrupted run resumes where it stopped. \
A non-empty destination is refused unless --force is given. Use --reverse for the redb -> sled \
downgrade."
)]
struct Args {
    /// Source store path.
    #[arg(long)]
    from: Option<PathBuf>,

    /// Destination store path.
    #[arg(long)]
    to: Option<PathBuf>,

    /// Source backend.
    #[arg(long, value_enum, default_value_t = Backend::Sled)]
    from_backend: Backend,

    /// Destination backend.
    #[arg(long, value_enum, default_value_t = Backend::Redb)]
    to_backend: Backend,

    /// Downgrade: redb -> sled (swaps the default backends and paths).
    #[arg(long)]
    reverse: bool,

    /// Overwrite a non-empty destination (it is cleared first).
    #[arg(long)]
    force: bool,

    /// Keys copied and checkpointed per batch.
    #[arg(long, default_value_t = 1000)]
    batch_size: usize,

    /// Verify only the first N entries instead of a full digest.
    #[arg(long)]
    sample: Option<usize>,

    /// Checkpoint file (default: `<destination>.migrate-state.json`).
    #[arg(long)]
    state_file: Option<PathBuf>,

    /// Legacy sled tree to read from. Defaults to the only non-adapter tree
    /// (normally `security_events`); the adapter `data` tree is used when no
    /// legacy tree exists.
    #[arg(long)]
    from_tree: Option<String>,

    /// Legacy sled tree to write to for `--reverse`.
    #[arg(long, default_value = "security_events")]
    to_tree: String,

    /// Do not print per-batch progress.
    #[arg(long)]
    quiet: bool,
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = Args::parse();

    let (from_backend, to_backend) = if args.reverse {
        (Backend::Redb, Backend::Sled)
    } else {
        (args.from_backend, args.to_backend)
    };

    let from = args.from.unwrap_or_else(|| {
        if args.reverse {
            PathBuf::from("./data/waf.redb")
        } else {
            PathBuf::from("./data/waf_security_events.sled")
        }
    });
    let to = args.to.unwrap_or_else(|| {
        if args.reverse {
            PathBuf::from("./data/waf_security_events.sled")
        } else {
            PathBuf::from("./data/waf.redb")
        }
    });

    if from == to {
        eprintln!(
            "error: source and destination are the same path: {}",
            from.display()
        );
        return ExitCode::from(2);
    }

    let state_path = args
        .state_file
        .unwrap_or_else(|| PathBuf::from(format!("{}.migrate-state.json", to.display())));

    eprintln!(
        "waf-storage-migrate: {} ({}) -> {} ({})",
        from.display(),
        from_backend.as_str(),
        to.display(),
        to_backend.as_str()
    );

    let (source, source_id) =
        match open_source(from_backend, &from, args.from_tree.as_deref()).await {
            Ok(opened) => opened,
            Err(e) => {
                eprintln!("error: cannot open source {}: {}", from.display(), e);
                return ExitCode::from(4);
            }
        };
    let destination = match open_destination(to_backend, &to, &args.to_tree).await {
        Ok(adapter) => adapter,
        Err(e) => {
            eprintln!("error: cannot open destination {}: {}", to.display(), e);
            return ExitCode::from(4);
        }
    };

    let options = MigrationOptions {
        batch_size: args.batch_size,
        force: args.force,
        sample: args.sample,
        state_path: Some(state_path),
        quiet: args.quiet,
        source_id,
        destination_id: format!("{}:{}", to_backend.as_str(), to.display()),
    };

    match migrate(source.as_ref(), destination.as_ref(), &options).await {
        Ok(summary) => {
            if let Some(resumed) = summary.resumed_from {
                eprintln!("resumed after key {}", String::from_utf8_lossy(&resumed));
            }
            eprintln!(
                "migration verified: copied={} skipped_expired={} source_keys={} \
destination_keys={} digest={} elapsed={:.2}s",
                summary.copied,
                summary.skipped_expired,
                summary.source_keys,
                summary.destination_keys,
                summary.source_digest,
                summary.elapsed.as_secs_f64()
            );
            ExitCode::SUCCESS
        }
        Err(MigrationError::DestinationNotEmpty { keys }) => {
            eprintln!(
                "error: destination {} already contains {} keys; pass --force to overwrite",
                to.display(),
                keys
            );
            ExitCode::from(3)
        }
        Err(MigrationError::Verification(message)) => {
            eprintln!("error: verification failed: {}", message);
            ExitCode::from(5)
        }
        Err(e @ MigrationError::SameStore) | Err(e @ MigrationError::StateMismatch(_)) => {
            eprintln!("error: {}", e);
            ExitCode::from(2)
        }
        Err(e) => {
            eprintln!("error: {}", e);
            ExitCode::from(4)
        }
    }
}

async fn open(
    backend: Backend,
    path: &Path,
) -> Result<Box<dyn StorageAdapter>, Box<dyn std::error::Error + Send + Sync>> {
    // The migration tool never uses the background cleanup task; a long
    // interval avoids it touching entries while the copy is in flight.
    let interval = Duration::from_secs(24 * 60 * 60);

    let adapter: Box<dyn StorageAdapter> = match backend {
        Backend::Sled => Box::new(SledStorageAdapter::new(path, false, interval, false).await?),
        Backend::Redb => Box::new(RedbStorageAdapter::new(path, None, interval, false).await?),
    };

    // Fail early if the adapter cannot read (e.g. a corrupt store).
    adapter
        .get(b"__migration_probe__", ReadConsistency::Strong)
        .await?;
    Ok(adapter)
}

/// Open the sled source, preferring the legacy exporter tree when present.
async fn open_source(
    backend: Backend,
    path: &Path,
    tree: Option<&str>,
) -> Result<(Box<dyn StorageAdapter>, String), Box<dyn std::error::Error + Send + Sync>> {
    if !path.exists() {
        return Err(format!("source store does not exist: {}", path.display()).into());
    }

    if backend == Backend::Sled {
        let legacy_tree = match tree {
            Some("data") | Some("ttl") | Some("meta") => None,
            Some(name) => Some(name.to_string()),
            None if path.exists() => legacy_event_trees(path)?.into_iter().next(),
            None => None,
        };

        if let Some(tree_name) = legacy_tree {
            let adapter = LegacySledTreeAdapter::new(path, &tree_name)?;
            return Ok((
                Box::new(adapter),
                format!("sled-legacy:{}:{}", path.display(), tree_name),
            ));
        }
    }

    let adapter = open(backend, path).await?;
    Ok((adapter, format!("{}:{}", backend.as_str(), path.display())))
}

async fn open_destination(
    backend: Backend,
    path: &Path,
    tree: &str,
) -> Result<Box<dyn StorageAdapter>, Box<dyn std::error::Error + Send + Sync>> {
    if backend == Backend::Sled {
        // Downgrade target: write the legacy exporter layout so the old binary
        // can read the store after a rollback.
        return Ok(Box::new(LegacySledTreeAdapter::new(path, tree)?));
    }
    open(backend, path).await
}
