//! Trait boundaries between the WAF data plane and the distri-kv control plane.
//!
//! The request path never calls these traits. Only the background controller
//! does, which is why every method is `async` and fallible. The `local`
//! module provides implementations that preserve single-process behaviour, so
//! the feature can be enabled without a cluster.

use std::fmt;
use std::net::IpAddr;
use std::time::{Duration, SystemTime};

use async_trait::async_trait;

/// Failure of a control-plane operation. These are always recoverable by the
/// controller: the data plane keeps serving from local state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DistributedError {
    pub kind: DistributedErrorKind,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DistributedErrorKind {
    /// The cluster cannot be reached (connect/timeout/transport).
    Unavailable,
    /// The request was authenticated but not authorised.
    PermissionDenied,
    /// The payload failed validation or signature/version checks.
    Invalid,
    /// The server is overloaded; back off and retry.
    ResourceExhausted,
    /// Any other failure.
    Other,
}

impl DistributedError {
    pub fn unavailable(message: impl Into<String>) -> Self {
        Self {
            kind: DistributedErrorKind::Unavailable,
            message: message.into(),
        }
    }

    pub fn invalid(message: impl Into<String>) -> Self {
        Self {
            kind: DistributedErrorKind::Invalid,
            message: message.into(),
        }
    }

    pub fn other(message: impl Into<String>) -> Self {
        Self {
            kind: DistributedErrorKind::Other,
            message: message.into(),
        }
    }

    /// Whether the controller should retry with backoff.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self.kind,
            DistributedErrorKind::Unavailable | DistributedErrorKind::ResourceExhausted
        )
    }
}

impl fmt::Display for DistributedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.kind, self.message)
    }
}

impl std::error::Error for DistributedError {}

/// A versioned policy/allowlist snapshot.
///
/// `generation` is monotonic per scope and drives generation-based cache
/// invalidation: a higher generation invalidates every cached verdict that
/// was derived from the previous one.
#[derive(Debug, Clone, PartialEq)]
pub struct PolicySnapshot {
    pub generation: u64,
    pub ruleset_version: String,
    /// Explicit allow entries (`pol/allow`), already normalised to CIDR or
    /// exact address strings by the control plane.
    pub allowlist: Vec<String>,
    /// Explicit block entries (`pol/block`).
    pub blocklist: Vec<String>,
    /// Rate-limit feedback multiplier published by the correlator. `1.0`
    /// means no change. Kept as data; enforcement stays local.
    pub rate_limit_multiplier: f32,
    pub issued_at: SystemTime,
}

impl PolicySnapshot {
    /// The local, in-process policy: generation 0 and no shared entries.
    pub fn local() -> Self {
        Self {
            generation: 0,
            ruleset_version: "local".to_string(),
            allowlist: Vec::new(),
            blocklist: Vec::new(),
            rate_limit_multiplier: 1.0,
            issued_at: SystemTime::UNIX_EPOCH,
        }
    }

    pub fn is_shadow_only(&self) -> bool {
        false
    }
}

/// A single IP reputation observation.
#[derive(Debug, Clone, PartialEq)]
pub struct ReputationEntry {
    pub ip: IpAddr,
    /// 0.0 (benign) .. 1.0 (malicious).
    pub score: f32,
    /// 0.0 .. 1.0.
    pub confidence: f32,
    pub labels: Vec<String>,
    /// Absolute expiry. `None` means the entry never expires locally.
    pub expires_at: Option<SystemTime>,
    pub version: u64,
}

impl ReputationEntry {
    pub fn is_expired(&self, now: SystemTime) -> bool {
        self.expires_at.is_some_and(|expiry| now >= expiry)
    }
}

/// One rate-limit accounting delta. Enforcement stays in the local token
/// buckets; this is observation only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CounterDelta {
    pub policy_id: String,
    pub window_start_unix: u64,
    pub shard: u32,
    pub key_hash: [u8; 16],
    pub consumed: u64,
    pub rejected: u64,
    pub clock_offset_ms: i32,
}

/// Body-free security event summary for event egress.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityEventRecord {
    pub event_id: String,
    pub node_id: String,
    pub observed_at_unix_ms: u64,
    pub rule_ids: Vec<String>,
    pub decision: EventDecision,
    pub threat_level: EventThreatLevel,
    /// Optional hashed client address; raw addresses are only included when
    /// the operator opts in. Never a body, credential or header value.
    pub ip_hash: Option<[u8; 16]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventDecision {
    Allow,
    Block,
    RateLimit,
    Challenge,
    Monitor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventThreatLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// This node's registration record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeInfo {
    pub node_id: String,
    pub region: String,
    pub version: String,
    pub epoch: u64,
}

/// Result of a register/heartbeat call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeartbeatAck {
    pub connected: bool,
    pub server_time_unix_ms: u64,
    pub policy_generation: Option<u64>,
}

/// Versioned policy and allowlist source.
#[async_trait]
pub trait PolicySource: Send + Sync {
    /// Fetch the current snapshot. The controller applies it only when
    /// `generation` advances.
    async fn current_policy(&self) -> Result<PolicySnapshot, DistributedError>;

    /// Fetch a specific generation (cold start / resync).
    async fn policy_at(&self, generation: u64) -> Result<PolicySnapshot, DistributedError> {
        let snapshot = self.current_policy().await?;
        if snapshot.generation != generation {
            return Err(DistributedError::invalid(format!(
                "requested generation {generation}, source has {}",
                snapshot.generation
            )));
        }
        Ok(snapshot)
    }
}

/// IP reputation read path.
#[async_trait]
pub trait ReputationSource: Send + Sync {
    /// `Ok(None)` means "unknown", which falls back to the local default.
    async fn lookup(&self, ip: IpAddr) -> Result<Option<ReputationEntry>, DistributedError>;

    /// Maximum age the caller accepts before treating the result as stale.
    fn max_age(&self) -> Duration {
        Duration::from_secs(300)
    }
}

/// Rate-limit counter-delta flush path.
#[async_trait]
pub trait RateLimitSync: Send + Sync {
    async fn flush(&self, deltas: &[CounterDelta]) -> Result<(), DistributedError>;
}

/// Security event egress path.
#[async_trait]
pub trait EventSink: Send + Sync {
    async fn export(&self, events: &[SecurityEventRecord]) -> Result<(), DistributedError>;
}

/// Node registration and liveness.
#[async_trait]
pub trait NodeRegistry: Send + Sync {
    async fn register(&self, node: &NodeInfo) -> Result<HeartbeatAck, DistributedError>;

    async fn heartbeat(&self, node: &NodeInfo) -> Result<HeartbeatAck, DistributedError>;
}
