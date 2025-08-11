use std::fmt;
use std::error::Error as StdError;

/// WAF error types
#[derive(Debug, Clone)]
pub enum WafError {
    /// Configuration error
    ConfigError(String),
    /// Rule evaluation error
    RuleError(String),
    /// Rate limiting error
    RateLimitError(String),
    /// Network/IO error
    NetworkError(String),
    /// Database error
    DatabaseError(String),
    /// Authentication error
    AuthError(String),
    /// Validation error
    ValidationError(String),
    /// Internal error
    InternalError(String),
}

impl fmt::Display for WafError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WafError::ConfigError(msg) => write!(f, "Configuration error: {}", msg),
            WafError::RuleError(msg) => write!(f, "Rule error: {}", msg),
            WafError::RateLimitError(msg) => write!(f, "Rate limit error: {}", msg),
            WafError::NetworkError(msg) => write!(f, "Network error: {}", msg),
            WafError::DatabaseError(msg) => write!(f, "Database error: {}", msg),
            WafError::AuthError(msg) => write!(f, "Authentication error: {}", msg),
            WafError::ValidationError(msg) => write!(f, "Validation error: {}", msg),
            WafError::InternalError(msg) => write!(f, "Internal error: {}", msg),
        }
    }
}

impl StdError for WafError {}

/// WAF result type
pub type Result<T> = std::result::Result<T, WafError>;

/// WAF result type (alternative name for compatibility)
pub type WafResult<T> = std::result::Result<T, WafError>;

impl From<std::io::Error> for WafError {
    fn from(err: std::io::Error) -> Self {
        WafError::NetworkError(err.to_string())
    }
}

impl From<serde_json::Error> for WafError {
    fn from(err: serde_json::Error) -> Self {
        WafError::ValidationError(err.to_string())
    }
}

impl From<toml::de::Error> for WafError {
    fn from(err: toml::de::Error) -> Self {
        WafError::ConfigError(err.to_string())
    }
}

impl From<anyhow::Error> for WafError {
    fn from(err: anyhow::Error) -> Self {
        WafError::InternalError(err.to_string())
    }
}