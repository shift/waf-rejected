use notify::{self, Event, EventKind, RecursiveMode, Watcher};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use tracing::{debug, error, info, warn};

use super::{ModSecurityConfig, ModSecurityError, Result, RuleSet};

/// Thread-safe ModSecurity engine wrapper
///
/// This provides the core interface to libmodsecurity with proper memory management
/// and Rust safety guarantees. The engine is designed to be shared across multiple
/// worker threads using Arc<RwLock<>> for rule hot-reloading.
#[derive(Debug)]
pub struct ModSecurityEngine {
    config: ModSecurityConfig,
    rules: Arc<RwLock<RuleSet>>,
    metrics: Arc<RwLock<super::ModSecurityMetrics>>,
    _rule_watcher: Option<notify::RecommendedWatcher>,
}

impl ModSecurityEngine {
    /// Create a new ModSecurity engine instance
    pub fn new(config: ModSecurityConfig) -> Result<Self> {
        info!("Initializing ModSecurity engine with config: {:?}", config);

        // Validate configuration
        if !Path::new(&config.rules_path).exists() {
            return Err(ModSecurityError::EngineInit(format!(
                "Rules path does not exist: {}",
                config.rules_path
            )));
        }

        // Initialize empty rule set - rules loaded separately
        let rules = Arc::new(RwLock::new(RuleSet::new()));
        let metrics = Arc::new(RwLock::new(super::ModSecurityMetrics::default()));

        let mut engine = Self {
            config: config.clone(),
            rules,
            metrics,
            _rule_watcher: None,
        };

        // Load initial rules
        engine.load_rules()?;

        // Setup file watcher for hot reloading
        if config.watch_rules {
            engine.setup_rule_watcher()?;
        }

        info!("ModSecurity engine initialized successfully");
        Ok(engine)
    }

    /// Load ModSecurity rules from the configured directory
    pub fn load_rules(&mut self) -> Result<()> {
        let rules_path = Path::new(&self.config.rules_path);
        info!("Loading ModSecurity rules from: {:?}", rules_path);

        let mut rule_files = Vec::new();
        Self::collect_rule_files(rules_path, &mut rule_files)?;

        let mut new_ruleset = RuleSet::new();
        let mut loaded_count = 0;
        let mut error_count = 0;

        for rule_file in rule_files {
            let rule_file_str = rule_file.to_string_lossy();
            match new_ruleset.load_from_file(&rule_file_str) {
                Ok(count) => {
                    loaded_count += count;
                    debug!("Loaded {} rules from {:?}", count, rule_file);
                }
                Err(e) => {
                    error_count += 1;
                    warn!("Failed to load rules from {:?}: {}", rule_file, e);
                }
            }
        }

        // Atomically replace the current rule set
        {
            let mut rules = self.rules.write().unwrap();
            *rules = new_ruleset;
        }

        info!(
            "Rule loading complete: {} rules loaded, {} files had errors",
            loaded_count, error_count
        );

        Ok(())
    }

    /// Create a new transaction for processing a request
    pub fn create_transaction(&self) -> Result<super::Transaction> {
        let rules = self.rules.read().unwrap();
        super::Transaction::new(Arc::clone(&rules.get_engine()), self.config.clone())
    }

    /// Get current processing metrics
    pub fn metrics(&self) -> super::ModSecurityMetrics {
        self.metrics.read().unwrap().clone()
    }

    /// Update metrics (called by transactions)
    pub fn update_metrics<F>(&self, updater: F)
    where
        F: FnOnce(&mut super::ModSecurityMetrics),
    {
        let mut metrics = self.metrics.write().unwrap();
        updater(&mut *metrics);
    }

    /// Get the number of loaded rules
    pub fn rule_count(&self) -> usize {
        self.rules.read().unwrap().rule_count()
    }

    /// Check if engine is properly initialized
    pub fn is_initialized(&self) -> bool {
        !self.rules.read().unwrap().is_empty()
    }

    // Private helper methods

    fn collect_rule_files(dir: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
        if !dir.is_dir() {
            return Ok(());
        }

        let entries = std::fs::read_dir(dir).map_err(|e| {
            ModSecurityError::EngineInit(format!("Failed to read rules directory: {}", e))
        })?;
        for entry in entries {
            let entry = entry.map_err(|e| {
                ModSecurityError::EngineInit(format!("Failed to read directory entry: {}", e))
            })?;
            let path = entry.path();

            if path.is_file() {
                if let Some(ext) = path.extension() {
                    if ext == "conf" || ext == "rules" {
                        files.push(path);
                    }
                }
            } else if path.is_dir() {
                // Recursively process subdirectories
                Self::collect_rule_files(&path, files)?;
            }
        }

        // Sort for consistent loading order
        files.sort();
        Ok(())
    }

    fn setup_rule_watcher(&mut self) -> Result<()> {
        use std::sync::mpsc;
        use std::thread;

        let (tx, rx) = mpsc::channel();
        let rules_path = self.config.rules_path.clone();
        let rules_arc = Arc::clone(&self.rules);
        let config = self.config.clone();

        let mut watcher = notify::recommended_watcher(tx).map_err(|e| {
            ModSecurityError::EngineInit(format!("Failed to create file watcher: {}", e))
        })?;

        watcher
            .watch(Path::new(&rules_path), RecursiveMode::Recursive)
            .map_err(|e| {
                ModSecurityError::EngineInit(format!("Failed to watch rules directory: {}", e))
            })?;

        // Spawn background thread to handle file events
        thread::spawn(move || {
            info!("ModSecurity rule file watcher started");

            while let Ok(event) = rx.recv() {
                match event {
                    Ok(Event {
                        kind: EventKind::Modify(_),
                        ..
                    })
                    | Ok(Event {
                        kind: EventKind::Create(_),
                        ..
                    })
                    | Ok(Event {
                        kind: EventKind::Remove(_),
                        ..
                    }) => {
                        info!("Rule file change detected, reloading rules...");

                        // Simple reload strategy - in production you'd want more sophisticated
                        // change detection to avoid unnecessary reloads
                        match RuleSet::load_from_directory(&rules_path) {
                            Ok(new_rules) => {
                                let mut rules = rules_arc.write().unwrap();
                                *rules = new_rules;
                                info!("Rules reloaded successfully");
                            }
                            Err(e) => {
                                error!("Failed to reload rules: {}", e);
                            }
                        }
                    }
                    Ok(_) => {} // Ignore other events
                    Err(e) => {
                        warn!("File watcher error: {}", e);
                    }
                }
            }
        });

        self._rule_watcher = Some(watcher);
        Ok(())
    }
}

impl Drop for ModSecurityEngine {
    fn drop(&mut self) {
        debug!("Dropping ModSecurity engine");
    }
}

// Thread safety
unsafe impl Send for ModSecurityEngine {}
unsafe impl Sync for ModSecurityEngine {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn create_test_config(rules_dir: &Path) -> ModSecurityConfig {
        ModSecurityConfig {
            enabled: true,
            rules_path: rules_dir.to_string_lossy().to_string(),
            watch_rules: false, // Disable for tests
            ..Default::default()
        }
    }

    #[test]
    fn test_engine_creation_with_missing_rules_dir() {
        let config = ModSecurityConfig {
            rules_path: "/nonexistent/path".to_string(),
            ..Default::default()
        };

        let result = ModSecurityEngine::new(config);
        assert!(result.is_err());

        if let Err(ModSecurityError::EngineInit(msg)) = result {
            assert!(msg.contains("does not exist"));
        }
    }

    #[test]
    fn test_engine_creation_with_empty_rules_dir() -> Result<()> {
        let temp_dir = TempDir::new().unwrap();
        let config = create_test_config(temp_dir.path());

        let engine = ModSecurityEngine::new(config)?;
        assert_eq!(engine.rule_count(), 0);

        Ok(())
    }

    #[test]
    fn test_rule_file_collection() -> Result<()> {
        let temp_dir = TempDir::new().unwrap();
        let rules_dir = temp_dir.path();

        // Create test rule files
        fs::write(rules_dir.join("test1.conf"), "# Test rule file 1")?;
        fs::write(rules_dir.join("test2.rules"), "# Test rule file 2")?;
        fs::write(rules_dir.join("readme.txt"), "# Not a rule file")?;

        // Create subdirectory with rules
        let sub_dir = rules_dir.join("subdir");
        fs::create_dir(&sub_dir)?;
        fs::write(sub_dir.join("test3.conf"), "# Test rule file 3")?;

        let mut files = Vec::new();
        ModSecurityEngine::collect_rule_files(rules_dir, &mut files)?;

        assert_eq!(files.len(), 3);
        assert!(files.iter().any(|f| f.file_name().unwrap() == "test1.conf"));
        assert!(files
            .iter()
            .any(|f| f.file_name().unwrap() == "test2.rules"));
        assert!(files.iter().any(|f| f.file_name().unwrap() == "test3.conf"));
        assert!(!files.iter().any(|f| f.file_name().unwrap() == "readme.txt"));

        Ok(())
    }
}
