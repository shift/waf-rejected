use std::error::Error as StdError;
use std::fmt;

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
    /// Authentication error (HTTPS requirement and other generic failures)
    AuthError(String),
    /// The presented API key is missing.
    AuthMissingKey,
    /// The presented API key was not recognised.
    AuthInvalidKey,
    /// The presented API key matched but has expired.
    AuthExpiredKey,
    /// The authentication failure budget (temporary lockout) was exhausted.
    AuthFailureLimited(String),
    /// Validation error
    ValidationError(String),
    /// Internal error
    InternalError(String),
    /// Upstream connection error
    Upstream(String),
    /// Request blocked by WAF rule
    Blocked { rule_id: String },
    /// Configuration error (standardized)
    Configuration(String),
    /// TLS handshake error
    TlsHandshake(String),
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
            WafError::AuthMissingKey => write!(f, "Authentication error: missing API key"),
            WafError::AuthInvalidKey => write!(f, "Authentication error: invalid API key"),
            WafError::AuthExpiredKey => write!(f, "Authentication error: expired API key"),
            WafError::AuthFailureLimited(msg) => {
                write!(f, "Authentication failure lockout: {}", msg)
            }
            WafError::ValidationError(msg) => write!(f, "Validation error: {}", msg),
            WafError::InternalError(msg) => write!(f, "Internal error: {}", msg),
            WafError::Upstream(msg) => write!(f, "Upstream error: {}", msg),
            WafError::Blocked { rule_id } => write!(f, "Request blocked by rule: {}", rule_id),
            WafError::Configuration(msg) => write!(f, "Configuration error: {}", msg),
            WafError::TlsHandshake(msg) => write!(f, "TLS handshake error: {}", msg),
        }
    }
}

impl WafError {
    /// Create an internal error
    pub fn internal<T: Into<String>>(msg: T) -> Self {
        WafError::InternalError(msg.into())
    }

    /// Create an HTTP error
    pub fn http<T: Into<String>>(msg: T) -> Self {
        WafError::NetworkError(msg.into())
    }

    /// Create an upstream connection error
    pub fn upstream_connection<T: Into<String>>(msg: T) -> Self {
        WafError::NetworkError(format!("Upstream connection error: {}", msg.into()))
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
