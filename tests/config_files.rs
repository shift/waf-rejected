//! Load every shipped configuration file through the real `Config::load`
//! path (file source + environment overrides + `Config::validate`).
//!
//! The `config` crate deserialises into structs that do **not** set
//! `deny_unknown_fields`, so an unknown key is silently ignored rather than
//! rejected. What this test *does* catch is everything the loader and
//! `Config::validate` enforce: malformed TOML, wrong types, unknown enum
//! variants, feature-dependent settings, cross-field limits and referenced
//! allowlist artifacts.
//!
//! Run it directly or through `./scripts/validate-configs.sh`.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use waf_ingress::config::Config;

static ENV_LOCK: Mutex<()> = Mutex::new(());

fn config_files() -> Vec<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();

    for path in [root.join("config.toml"), root.join("config.docker.toml")] {
        if path.is_file() {
            files.push(path);
        }
    }

    for dir in [root.join("config"), root.join("config/examples")] {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) == Some("toml") {
                files.push(path);
            }
        }
    }

    files.sort();
    files.dedup();
    files
}

#[test]
fn every_shipped_config_loads_through_the_real_loader() {
    let _guard = ENV_LOCK.lock().expect("config test env lock");
    let previous = std::env::var_os("WAF_CONFIG_FILE");

    let files = config_files();
    assert!(
        !files.is_empty(),
        "no config files discovered under config/ or config/examples/"
    );

    let mut failures = Vec::new();
    for path in &files {
        std::env::set_var("WAF_CONFIG_FILE", path);
        match Config::load() {
            Ok(_) => println!("ok   {}", path.display()),
            Err(error) => {
                println!("FAIL {}: {error:#}", path.display());
                failures.push(format!("{}: {error:#}", path.display()));
            }
        }
    }

    match previous {
        Some(value) => std::env::set_var("WAF_CONFIG_FILE", value),
        None => std::env::remove_var("WAF_CONFIG_FILE"),
    }

    assert!(
        failures.is_empty(),
        "{} config file(s) failed to load:\n{}",
        failures.len(),
        failures.join("\n")
    );
    println!("validated {} config file(s)", files.len());
}
