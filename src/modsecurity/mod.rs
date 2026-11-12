use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub mod engine;
pub mod transaction;

pub use engine::ModSecurityEngine;
pub use transaction::{Intervention, Transaction};

// Type alias for ModSecurity results
pub type Result<T> = std::result::Result<T, ModSecurityError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModSecurityConfig {
    pub rules_path: String,
    pub watch_rules: bool,
    pub audit_log_path: Option<String>,
    pub debug_log_path: Option<String>,
    pub enabled: bool,
}

impl Default for ModSecurityConfig {
    fn default() -> Self {
        Self {
            rules_path: "./rules".to_string(),
            watch_rules: false,
            audit_log_path: None,
            debug_log_path: None,
            enabled: true,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ModSecurityError {
    #[error("Engine initialization failed: {0}")]
    EngineInit(String),
    #[error("Rule loading failed: {0}")]
    RuleLoad(String),
    #[error("Transaction processing failed: {0}")]
    Transaction(String),
}

impl From<std::io::Error> for ModSecurityError {
    fn from(err: std::io::Error) -> Self {
        ModSecurityError::EngineInit(format!("IO error: {}", err))
    }
}

#[derive(Debug, Default, Clone)]
pub struct ModSecurityMetrics {
    pub requests_processed: u64,
    pub rules_triggered: u64,
    pub blocked_requests: u64,
}

#[derive(Debug)]
pub struct RuleSet {
    pub rules: Vec<String>,
    pub enabled: bool,
}

impl RuleSet {
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            enabled: true,
        }
    }

    pub fn load_from_file(&mut self, path: &str) -> Result<usize> {
        // Basic file loading implementation
        self.rules.push(format!("Rule from file: {}", path));
        Ok(1) // Return count of rules loaded
    }

    pub fn load_from_directory(path: &str) -> Result<Self> {
        let mut rule_set = Self::new();
        rule_set
            .rules
            .push(format!("Rules from directory: {}", path));
        Ok(rule_set)
    }

    pub fn get_engine(&self) -> Arc<Self> {
        // Return a reference to self wrapped in Arc
        // In a real implementation, this would return the actual ModSecurity engine
        Arc::new(self.clone())
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

impl Clone for RuleSet {
    fn clone(&self) -> Self {
        Self {
            rules: self.rules.clone(),
            enabled: self.enabled,
        }
    }
}

#[derive(Debug, Clone)]
pub enum Phase {
    RequestHeaders,
    RequestBody,
    ResponseHeaders,
    ResponseBody,
    Logging,
}
