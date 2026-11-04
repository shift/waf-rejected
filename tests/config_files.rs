//! Load every shipped configuration file through the real `Config::load`
//! path (file source + environment overrides + `Config::validate`).
//!
//! Since the config structs use `serde(deny_unknown_fields)`, a misspelled or
//! obsolete key is a hard error. Errors name the file, section/key path and
//! source location. This test also pins the strict-failure cases and checks
//! that `WAF_*` environment overrides still work.
//!
//! Run it directly or through `./scripts/validate-configs.sh`.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use waf_ingress::config::Config;

static ENV_LOCK: Mutex<()> = Mutex::new(());

fn config_files() -> Vec<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();

    // Root configs: the default, the container variant and the test configs
    // used by the test binaries.
    for name in [
        "config.toml",
        "config.docker.toml",
        "config-test.toml",
        "config-test-fail-open.toml",
        "config-with-exports.toml",
        "test_config.toml",
        "deploy/compose/config.native.toml",
    ] {
        let path = root.join(name);
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

/// Load `contents` as `WAF_CONFIG_FILE`, restoring the environment afterwards.
fn load_contents(contents: &str) -> anyhow::Result<Config> {
    let _guard = ENV_LOCK.lock().expect("config test env lock");
    let directory = tempfile::tempdir().expect("temporary config directory");
    let path = directory.path().join("config.toml");
    std::fs::write(&path, contents).expect("write temporary config");

    let previous = std::env::var_os("WAF_CONFIG_FILE");
    std::env::set_var("WAF_CONFIG_FILE", &path);
    let result = Config::load();
    match previous {
        Some(value) => std::env::set_var("WAF_CONFIG_FILE", value),
        None => std::env::remove_var("WAF_CONFIG_FILE"),
    }
    result
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

#[test]
fn unknown_top_level_key_is_rejected_with_file_and_key() {
    let error = load_contents("bind_addr_typo = \"0.0.0.0:8080\"\n")
        .expect_err("unknown top-level key must fail");
    let message = format!("{error:#}");

    assert!(message.contains("config.toml"), "{message}");
    assert!(message.contains("top-level.bind_addr_typo"), "{message}");
    assert!(message.contains("unknown key"), "{message}");
}

#[test]
fn unknown_nested_key_is_rejected_with_section_path() {
    let error = load_contents("[waf.coraza]\nbackedn = \"wasm\"\n")
        .expect_err("unknown nested key must fail");
    let message = format!("{error:#}");

    assert!(message.contains("config.toml"), "{message}");
    assert!(message.contains("waf.coraza.backedn"), "{message}");
    assert!(message.contains("unknown key"), "{message}");
}

#[test]
fn typo_in_waf_coraza_backend_key_fails() {
    let error = load_contents("[waf.coraza]\nbackedn = \"rust\"\n[waf]\nenabled = true\n")
        .expect_err("misspelled backend key must fail");

    assert!(
        format!("{error:#}").contains("waf.coraza.backedn"),
        "{error:#}"
    );
}

#[test]
fn env_overrides_still_apply() {
    let _guard = ENV_LOCK.lock().expect("config test env lock");
    let directory = tempfile::tempdir().expect("temporary config directory");
    let path = directory.path().join("config.toml");
    std::fs::write(&path, "[server]\nmax_connections = 1000\n").expect("write config");

    let previous_file = std::env::var_os("WAF_CONFIG_FILE");
    let previous_value = std::env::var_os("WAF_SERVER__MAX_CONNECTIONS");
    std::env::set_var("WAF_CONFIG_FILE", &path);
    std::env::set_var("WAF_SERVER__MAX_CONNECTIONS", "2345");
    let result = Config::load();
    match previous_file {
        Some(value) => std::env::set_var("WAF_CONFIG_FILE", value),
        None => std::env::remove_var("WAF_CONFIG_FILE"),
    }
    match previous_value {
        Some(value) => std::env::set_var("WAF_SERVER__MAX_CONNECTIONS", value),
        None => std::env::remove_var("WAF_SERVER__MAX_CONNECTIONS"),
    }

    let config = result.expect("environment override must load");
    assert_eq!(config.server.max_connections, 2345);
}
