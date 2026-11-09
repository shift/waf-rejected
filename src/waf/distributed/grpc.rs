//! Minimal tonic client for the `waf.distri.v1.DistriWaf` contract.
//!
//! The contract is owned by shift/distri-kv (`proto/distri_waf.proto`); the
//! checked-in bindings in [`super::distri_waf`] are generated from that file
//! with `tonic-build 0.11`. This module maps the five WAF-side traits onto the
//! contract and keeps every failure recoverable: a transport error becomes a
//! [`DistributedError`], the channel is discarded, and the controller retries
//! with backoff. Nothing here is called on the request path.
//!
//! `local_only` remains the default; constructing this client requires at
//! least one configured endpoint.

use std::future::Future;
use std::net::IpAddr;
use std::path::Path;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex as StdMutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use tokio::sync::Mutex;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};
use tonic::{Code, Request, Status};

use crate::config::DistributedConfig;

use super::distri_waf::distri_waf_client::DistriWafClient as WafGrpcClient;
use super::distri_waf::{
    self, AcquireLeaseRequest, AcquireLeaseResponse, CounterDelta as ProtoCounterDelta,
    CounterDeltas, GetPolicyRequest, HeartbeatRequest, HeartbeatResponse, LookupReputationRequest,
    NodeHealth, NodeMetadata, PolicyBundle, RegisterRequest, ReleaseLeaseRequest,
    ReleaseLeaseResponse, ReputationResponse, SecurityEvent,
};
use super::leases::{LeaseGrant, LeaseKey, LeaseRequest};
use super::policy_verify::{PolicyVerificationState, PolicyVerifier};
use super::traits::{
    CounterDelta, DistributedError, DistributedErrorKind, EventDecision, EventSink,
    EventThreatLevel, HeartbeatAck, LeaseSource, NodeInfo, NodeRegistry, PolicySnapshot,
    PolicySource, RateLimitSync, ReputationEntry, ReputationSource, SecurityEventRecord,
};

/// Wire contract version implemented by shift/distri-kv.
pub const CONTRACT_VERSION: u32 = 1;

/// Default policy scope when the operator does not set one.
const DEFAULT_POLICY_SCOPE: &str = "default";

/// A tonic gRPC client implementing every distributed source trait.
///
/// A single instance is shared by the controller as `PolicySource`,
/// `ReputationSource`, `RateLimitSync`, `EventSink` and `NodeRegistry`. The
/// channel is established lazily and dropped on retryable failures so the
/// next call rediscovers an endpoint.
#[derive(Debug)]
pub struct DistriWafClient {
    endpoints: Vec<String>,
    next_endpoint: AtomicUsize,
    request_timeout: Duration,
    connect_timeout: Duration,
    node_id: String,
    region: String,
    policy_scope: String,
    advertise_endpoint: String,
    auth_token: Option<tonic::metadata::MetadataValue<tonic::metadata::Ascii>>,
    spiffe_key: Option<tonic::metadata::MetadataKey<tonic::metadata::Ascii>>,
    spiffe_value: Option<tonic::metadata::MetadataValue<tonic::metadata::Ascii>>,
    tls_ca_cert: Option<Vec<u8>>,
    tls_client_cert: Option<Vec<u8>>,
    tls_client_key: Option<Vec<u8>>,
    tls_server_name: Option<String>,
    allow_insecure_transport: bool,
    lease_ttl: Duration,
    verifier: PolicyVerifier,
    policy_state: StdMutex<PolicyVerificationState>,
    epoch: AtomicU64,
    sequence: AtomicU64,
    policy_generation: AtomicU64,
    channel: Mutex<Option<Channel>>,
}

impl DistriWafClient {
    /// Build a client from `[waf.distributed]`. Fails if no endpoints are
    /// configured; callers that want local behaviour should not construct it.
    pub fn new(config: &DistributedConfig) -> Result<Self, DistributedError> {
        if config.endpoints.is_empty() {
            return Err(DistributedError::unavailable(
                "distri-kv client requires at least one endpoint",
            ));
        }
        let request_timeout = Duration::from_millis(config.request_timeout_ms.max(1));
        let policy_scope = if config.policy_scope.trim().is_empty() {
            DEFAULT_POLICY_SCOPE.to_string()
        } else {
            config.policy_scope.clone()
        };
        let advertise_endpoint = if config.advertise_endpoint.trim().is_empty() {
            config.endpoints.first().cloned().unwrap_or_default()
        } else {
            config.advertise_endpoint.clone()
        };
        if !config.allow_insecure_transport
            && config
                .endpoints
                .iter()
                .any(|endpoint| endpoint.starts_with("http://"))
        {
            return Err(DistributedError::invalid(
                "http:// distri-kv endpoints require allow_insecure_transport = true",
            ));
        }
        if no_credential(config) {
            tracing::warn!(
                "distri-kv client has no bearer token, SPIFFE identity or client certificate; \
                 configure mTLS/SPIFFE for production"
            );
        }
        let auth_token = if !config.auth_token.is_empty() {
            Some(format!("Bearer {}", config.auth_token))
        } else if !config.spiffe_jwt.is_empty() {
            Some(format!("Bearer {}", config.spiffe_jwt))
        } else {
            None
        };
        let auth_token = auth_token
            .map(|value| {
                tonic::metadata::MetadataValue::try_from(value).map_err(|error| {
                    DistributedError::invalid(format!(
                        "invalid waf.distributed bearer token: {error}"
                    ))
                })
            })
            .transpose()?;
        let (spiffe_key, spiffe_value) = if config.spiffe_id.trim().is_empty() {
            (None, None)
        } else {
            let key =
                tonic::metadata::MetadataKey::from_bytes(config.spiffe_metadata_key.as_bytes())
                    .map_err(|error| {
                        DistributedError::invalid(format!(
                            "invalid waf.distributed.spiffe_metadata_key: {error}"
                        ))
                    })?;
            let value = tonic::metadata::MetadataValue::try_from(config.spiffe_id.as_str())
                .map_err(|error| {
                    DistributedError::invalid(format!(
                        "invalid waf.distributed.spiffe_id value: {error}"
                    ))
                })?;
            (Some(key), Some(value))
        };
        let tls_ca_cert = read_optional_pem(&config.tls_ca_cert_path, "tls_ca_cert_path")?;
        let tls_client_cert =
            read_optional_pem(&config.tls_client_cert_path, "tls_client_cert_path")?;
        let tls_client_key = read_optional_pem(&config.tls_client_key_path, "tls_client_key_path")?;
        let tls_server_name = (!config.tls_server_name.trim().is_empty())
            .then(|| config.tls_server_name.trim().to_string());
        let verifier = PolicyVerifier::from_config(config)?;
        Ok(Self {
            endpoints: config.endpoints.clone(),
            next_endpoint: AtomicUsize::new(0),
            request_timeout,
            connect_timeout: request_timeout,
            node_id: config.node_id.clone(),
            region: config.region.clone(),
            policy_scope,
            advertise_endpoint,
            auth_token,
            spiffe_key,
            spiffe_value,
            tls_ca_cert,
            tls_client_cert,
            tls_client_key,
            tls_server_name,
            allow_insecure_transport: config.allow_insecure_transport,
            lease_ttl: Duration::from_millis(config.lease_ttl_ms.max(1)),
            verifier,
            policy_state: StdMutex::new(PolicyVerificationState::default()),
            epoch: AtomicU64::new(1),
            sequence: AtomicU64::new(0),
            policy_generation: AtomicU64::new(0),
            channel: Mutex::new(None),
        })
    }

    /// Update the generation reported on the next heartbeat. The controller
    /// calls this after applying a policy snapshot.
    pub fn set_policy_generation(&self, generation: u64) {
        self.policy_generation.store(generation, Ordering::Release);
    }

    pub fn policy_scope(&self) -> &str {
        &self.policy_scope
    }

    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    /// Drop the cached channel so the next call reconnects. Called on
    /// retryable transport failures.
    async fn invalidate_channel(&self) {
        *self.channel.lock().await = None;
    }

    /// Build a client TLS configuration for `https://` endpoints. Plaintext
    /// is only permitted when `allow_insecure_transport` was explicitly set.
    fn tls_config_for(&self, endpoint: &str) -> Result<Option<ClientTlsConfig>, DistributedError> {
        if let Some(host) = endpoint.strip_prefix("http://") {
            let _ = host;
            if !self.allow_insecure_transport {
                return Err(DistributedError::invalid(
                    "plaintext distri-kv endpoint rejected",
                ));
            }
            return Ok(None);
        }
        if !endpoint.starts_with("https://") {
            return Err(DistributedError::invalid(format!(
                "unsupported distri-kv endpoint scheme: {endpoint}"
            )));
        }
        let mut tls = ClientTlsConfig::new();
        if let Some(ca) = &self.tls_ca_cert {
            tls = tls.ca_certificate(Certificate::from_pem(ca));
        }
        if let (Some(cert), Some(key)) = (&self.tls_client_cert, &self.tls_client_key) {
            tls = tls.identity(Identity::from_pem(cert, key));
        }
        if let Some(name) = &self.tls_server_name {
            tls = tls.domain_name(name.clone());
        }
        Ok(Some(tls))
    }

    async fn channel(&self) -> Result<Channel, DistributedError> {
        let mut guard = self.channel.lock().await;
        if let Some(channel) = guard.as_ref() {
            return Ok(channel.clone());
        }

        let start = self.next_endpoint.fetch_add(1, Ordering::Relaxed);
        let mut last_error = None;
        for offset in 0..self.endpoints.len() {
            let index = (start + offset) % self.endpoints.len();
            let endpoint = &self.endpoints[index];
            let parsed = match Endpoint::from_shared(endpoint.clone()) {
                Ok(parsed) => parsed,
                Err(error) => {
                    last_error = Some(format!("{endpoint}: {error}"));
                    continue;
                }
            };
            let parsed = parsed
                .connect_timeout(self.connect_timeout)
                .timeout(self.request_timeout);
            let parsed = match self.tls_config_for(endpoint) {
                Ok(Some(tls)) => match parsed.tls_config(tls) {
                    Ok(parsed) => parsed,
                    Err(error) => {
                        last_error = Some(format!("{endpoint}: {error}"));
                        continue;
                    }
                },
                Ok(None) => parsed,
                Err(error) => {
                    last_error = Some(format!("{endpoint}: {error}"));
                    continue;
                }
            };
            match tokio::time::timeout(self.connect_timeout, parsed.connect()).await {
                Ok(Ok(channel)) => {
                    *guard = Some(channel.clone());
                    return Ok(channel);
                }
                Ok(Err(error)) => last_error = Some(format!("{endpoint}: {error}")),
                Err(_) => last_error = Some(format!("{endpoint}: connect timed out")),
            }
        }

        Err(DistributedError::unavailable(format!(
            "no distri-kv endpoint reachable ({})",
            last_error.unwrap_or_else(|| "no endpoints configured".to_string())
        )))
    }

    async fn client(&self) -> Result<WafGrpcClient<Channel>, DistributedError> {
        Ok(WafGrpcClient::new(self.channel().await?))
    }

    pub(crate) fn request<T>(&self, message: T) -> Request<T> {
        let mut request = Request::new(message);
        request.set_timeout(self.request_timeout);
        if let Some(token) = &self.auth_token {
            request
                .metadata_mut()
                .insert("authorization", token.clone());
        }
        if let (Some(key), Some(value)) = (&self.spiffe_key, &self.spiffe_value) {
            request.metadata_mut().insert(key.clone(), value.clone());
        }
        request
    }

    async fn finish<T>(
        &self,
        result: Result<tonic::Response<T>, Status>,
    ) -> Result<T, DistributedError> {
        match result {
            Ok(response) => Ok(response.into_inner()),
            Err(status) => {
                let error = map_status(status);
                if error.is_retryable() {
                    self.invalidate_channel().await;
                }
                Err(error)
            }
        }
    }

    async fn register_node(&self, node: &NodeInfo) -> Result<HeartbeatAck, DistributedError> {
        let epoch = if node.epoch > 0 {
            node.epoch
        } else {
            self.epoch.load(Ordering::Acquire).max(1)
        };
        let metadata = NodeMetadata {
            node_id: if node.node_id.is_empty() {
                self.node_id.clone()
            } else {
                node.node_id.clone()
            },
            region: if node.region.is_empty() {
                self.region.clone()
            } else {
                node.region.clone()
            },
            zone: String::new(),
            cluster_id: String::new(),
            version: node.version.clone(),
            build_commit: String::new(),
            capabilities: vec!["waf".to_string()],
            endpoint: self.advertise_endpoint.clone(),
            labels: Default::default(),
            epoch,
            policy_generation: self.policy_generation.load(Ordering::Acquire),
            ruleset_version: String::new(),
            health: NodeHealth::Healthy as i32,
            queue_depth: 0,
            lease_expires_at_unix_ms: 0,
        };
        let request_id = metadata.node_id.clone();
        let request = self.request(RegisterRequest {
            contract_version: CONTRACT_VERSION,
            node: Some(metadata),
            request_id,
            lease_ttl_secs: 30,
        });
        let response = self.client().await?.register(request).await;
        let response = self.finish(response).await?;
        if response.accepted {
            self.epoch
                .store(response.epoch.max(epoch), Ordering::Release);
        }
        Ok(HeartbeatAck {
            connected: response.accepted,
            server_time_unix_ms: response.server_time_unix_ms,
            policy_generation: None,
        })
    }

    // A `tonic::Status` is large, but this is a private helper and boxing it
    // would obscure the `NotFound` re-register path.
    #[allow(clippy::result_large_err)]
    async fn heartbeat_once(&self, node: &NodeInfo) -> Result<HeartbeatResponse, Status> {
        let epoch = self.epoch.load(Ordering::Acquire).max(1);
        let sequence = self.sequence.fetch_add(1, Ordering::AcqRel) + 1;
        let request = self.request(HeartbeatRequest {
            contract_version: CONTRACT_VERSION,
            node_id: if node.node_id.is_empty() {
                self.node_id.clone()
            } else {
                node.node_id.clone()
            },
            epoch,
            policy_generation: self.policy_generation.load(Ordering::Acquire),
            ruleset_version: String::new(),
            queue_depth: 0,
            health: NodeHealth::Healthy as i32,
            sequence,
        });
        let mut client = match self.client().await {
            Ok(client) => client,
            Err(error) => {
                return Err(Status::unavailable(error.message));
            }
        };
        client
            .heartbeat(request)
            .await
            .map(|response| response.into_inner())
    }
}

/// Map a tonic status onto the controller's closed error vocabulary.
pub fn map_status(status: Status) -> DistributedError {
    let kind = match status.code() {
        Code::Unavailable | Code::DeadlineExceeded | Code::Unknown | Code::Cancelled => {
            DistributedErrorKind::Unavailable
        }
        Code::ResourceExhausted | Code::Aborted => DistributedErrorKind::ResourceExhausted,
        Code::PermissionDenied | Code::Unauthenticated => DistributedErrorKind::PermissionDenied,
        Code::InvalidArgument
        | Code::FailedPrecondition
        | Code::OutOfRange
        | Code::AlreadyExists
        | Code::NotFound => DistributedErrorKind::Invalid,
        _ => DistributedErrorKind::Other,
    };
    DistributedError {
        kind,
        message: format!("{:?}: {}", status.code(), status.message()),
    }
}

fn from_unix_millis(millis: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_millis(millis)
}

fn policy_from_bundle(bundle: PolicyBundle) -> PolicySnapshot {
    let payload = bundle.payload.unwrap_or_default();
    let ruleset_version = if payload.ruleset_version.is_empty() {
        format!("distri-v{}", bundle.version)
    } else {
        payload.ruleset_version
    };
    PolicySnapshot {
        generation: bundle.generation.max(bundle.version),
        ruleset_version,
        // The v1 contract carries a compiled artifact, not explicit allow/block
        // lists. Those stay local until a later contract adds them.
        allowlist: Vec::new(),
        blocklist: Vec::new(),
        rate_limit_multiplier: 1.0,
        issued_at: from_unix_millis(bundle.created_at_unix_ms),
    }
}

fn reputation_from_proto(entry: distri_waf::ReputationEntry) -> Option<ReputationEntry> {
    let ip: IpAddr = entry.ip.parse().ok()?;
    Some(ReputationEntry {
        ip,
        score: entry.score.clamp(0.0, 1.0),
        confidence: entry.confidence.clamp(0.0, 1.0),
        labels: entry.labels,
        expires_at: (entry.expires_at_unix_ms > 0)
            .then(|| from_unix_millis(entry.expires_at_unix_ms)),
        version: entry.version,
    })
}

fn event_decision(action: &str) -> EventDecision {
    match action.to_ascii_lowercase().as_str() {
        "allow" => EventDecision::Allow,
        "block" | "deny" => EventDecision::Block,
        "rate_limit" | "rate-limit" => EventDecision::RateLimit,
        "challenge" => EventDecision::Challenge,
        _ => EventDecision::Monitor,
    }
}

fn decision_action(decision: EventDecision) -> &'static str {
    match decision {
        EventDecision::Allow => "allow",
        EventDecision::Block => "block",
        EventDecision::RateLimit => "rate_limit",
        EventDecision::Challenge => "challenge",
        EventDecision::Monitor => "monitor",
    }
}

fn threat_severity(level: EventThreatLevel) -> u32 {
    match level {
        EventThreatLevel::Low => 1,
        EventThreatLevel::Medium => 2,
        EventThreatLevel::High => 3,
        EventThreatLevel::Critical => 4,
    }
}

fn event_to_proto(record: SecurityEventRecord, region: &str) -> SecurityEvent {
    SecurityEvent {
        event_id: record.event_id,
        node_id: record.node_id,
        region: region.to_string(),
        event_type: "waf".to_string(),
        rule_id: record.rule_ids.first().cloned().unwrap_or_default(),
        action: decision_action(record.decision).to_string(),
        client_ip_hash: record.ip_hash.map(hex::encode).unwrap_or_default(),
        timestamp_unix_ms: record.observed_at_unix_ms,
        severity: threat_severity(record.threat_level),
        payload_hash: Vec::new(),
        metadata: record
            .rule_ids
            .into_iter()
            .enumerate()
            .map(|(index, rule)| (format!("rule_{index}"), rule))
            .collect(),
    }
}

#[async_trait]
impl PolicySource for DistriWafClient {
    async fn current_policy(&self) -> Result<PolicySnapshot, DistributedError> {
        let request = self.request(GetPolicyRequest {
            contract_version: CONTRACT_VERSION,
            scope: self.policy_scope.clone(),
            version: 0,
        });
        let response = self.client().await?.get_policy(request).await;
        let bundle = self.finish(response).await?;
        {
            let mut state = self
                .policy_state
                .lock()
                .map_err(|_| DistributedError::other("policy verification state lock poisoned"))?;
            self.verifier.verify(&bundle, &mut state)?;
        }
        Ok(policy_from_bundle(bundle))
    }
}

#[async_trait]
impl ReputationSource for DistriWafClient {
    async fn lookup(&self, ip: IpAddr) -> Result<Option<ReputationEntry>, DistributedError> {
        let request = self.request(LookupReputationRequest {
            contract_version: CONTRACT_VERSION,
            ips: vec![ip.to_string()],
            scope: self.policy_scope.clone(),
            max_age_ms: self.max_age().as_millis().min(u32::MAX as u128) as u32,
        });
        let response = self.client().await?.lookup_reputation(request).await;
        let response: ReputationResponse = self.finish(response).await?;
        Ok(response
            .entries
            .into_iter()
            .next()
            .and_then(reputation_from_proto))
    }

    fn max_age(&self) -> Duration {
        // A stale server entry is still useful to the controller; the cache's
        // own TTL and max_stale decide when the value stops being servable.
        Duration::from_secs(300)
    }
}

#[async_trait]
impl RateLimitSync for DistriWafClient {
    async fn flush(&self, deltas: &[CounterDelta]) -> Result<(), DistributedError> {
        if deltas.is_empty() {
            return Ok(());
        }
        let batch = CounterDeltas {
            contract_version: CONTRACT_VERSION,
            node_id: self.node_id.clone(),
            epoch: self.epoch.load(Ordering::Acquire),
            deltas: deltas
                .iter()
                .map(|delta| ProtoCounterDelta {
                    policy_id: delta.policy_id.clone(),
                    window_start_unix: delta.window_start_unix.min(u32::MAX as u64) as u32,
                    shard: delta.shard,
                    key_hash: delta.key_hash.to_vec(),
                    consumed: delta.consumed,
                    rejected: delta.rejected,
                    clock_offset_ms: delta.clock_offset_ms,
                })
                .collect(),
            batch_id: counter_batch_id(
                self.node_id.as_str(),
                self.epoch.load(Ordering::Acquire),
                deltas,
            ),
        };
        let request = self.request(batch);
        let response = self.client().await?.ingest_counter_deltas(request).await;
        let ack = self.finish(response).await?;
        if ack.retry_after_ms > 0 {
            return Err(DistributedError {
                kind: DistributedErrorKind::ResourceExhausted,
                message: format!("distri-kv asked to retry after {}ms", ack.retry_after_ms),
            });
        }
        Ok(())
    }
}

#[async_trait]
impl EventSink for DistriWafClient {
    async fn export(&self, events: &[SecurityEventRecord]) -> Result<(), DistributedError> {
        if events.is_empty() {
            return Ok(());
        }
        let region = self.region.clone();
        let messages: Vec<SecurityEvent> = events
            .iter()
            .cloned()
            .map(|event| event_to_proto(event, &region))
            .collect();
        let stream = futures::stream::iter(messages);
        let request = self.request(stream);
        let response = self.client().await?.ingest_events(request).await;
        let summary = self.finish(response).await?;
        if summary.retry_after_ms > 0 {
            return Err(DistributedError {
                kind: DistributedErrorKind::ResourceExhausted,
                message: format!(
                    "distri-kv asked to retry after {}ms",
                    summary.retry_after_ms
                ),
            });
        }
        Ok(())
    }
}

#[async_trait]
impl NodeRegistry for DistriWafClient {
    async fn register(&self, node: &NodeInfo) -> Result<HeartbeatAck, DistributedError> {
        self.register_node(node).await
    }

    async fn heartbeat(&self, node: &NodeInfo) -> Result<HeartbeatAck, DistributedError> {
        let result = self.heartbeat_once(node).await;
        let response: HeartbeatResponse = match result {
            Ok(response) => response,
            Err(status) if status.code() == Code::NotFound => {
                // A lease can expire during an outage. Re-register once, then
                // retry the heartbeat; the controller only sees one error.
                self.register_node(node).await?;
                self.heartbeat_once(node).await.map_err(map_status)?
            }
            Err(status) => {
                let error = map_status(status);
                if error.is_retryable() {
                    self.invalidate_channel().await;
                }
                return Err(error);
            }
        };
        Ok(HeartbeatAck {
            connected: !response.drain,
            server_time_unix_ms: response.server_time_unix_ms,
            policy_generation: None,
        })
    }
}

#[async_trait]
impl LeaseSource for DistriWafClient {
    async fn acquire_leases(
        &self,
        requests: &[LeaseRequest],
    ) -> Result<Vec<LeaseGrant>, DistributedError> {
        if requests.is_empty() {
            return Ok(Vec::new());
        }
        let mut client = self.client().await?;
        let mut grants = Vec::with_capacity(requests.len());
        for request in requests {
            let rpc = self.request(AcquireLeaseRequest {
                contract_version: CONTRACT_VERSION,
                node_id: self.node_id.clone(),
                bucket_key: request.bucket_key(),
                requested_tokens: request.requested.min(u32::MAX as u64) as u32,
                ttl_ms: self.lease_ttl_ms(),
                idempotency_key: uuid::Uuid::new_v4().to_string(),
            });
            let response = match client.acquire_lease(rpc).await {
                Ok(response) => response.into_inner(),
                Err(status) => {
                    let error = map_status(status);
                    if error.is_retryable() {
                        self.invalidate_channel().await;
                    }
                    return Err(error);
                }
            };
            grants.push(lease_from_response(self, request, response));
        }
        Ok(grants)
    }
}

impl DistriWafClient {
    fn lease_ttl_ms(&self) -> u32 {
        self.lease_ttl.as_millis().clamp(100, 60_000) as u32
    }

    /// Return unused tokens to a shared bucket. The controller currently lets
    /// the server reap unused grants at expiry; this entry point exists for
    /// callers that want an immediate refund and for contract tests.
    pub async fn release_lease(
        &self,
        bucket_key: &str,
        remaining_tokens: u32,
        idempotency_key: &str,
    ) -> Result<ReleaseLeaseResponse, DistributedError> {
        let mut client = self.client().await?;
        let rpc = self.request(ReleaseLeaseRequest {
            contract_version: CONTRACT_VERSION,
            node_id: self.node_id.clone(),
            bucket_key: bucket_key.to_string(),
            remaining_tokens,
            idempotency_key: idempotency_key.to_string(),
        });
        match client.release_lease(rpc).await {
            Ok(response) => Ok(response.into_inner()),
            Err(status) => {
                let error = map_status(status);
                if error.is_retryable() {
                    self.invalidate_channel().await;
                }
                Err(error)
            }
        }
    }
}

fn lease_from_response(
    client: &DistriWafClient,
    request: &LeaseRequest,
    response: AcquireLeaseResponse,
) -> LeaseGrant {
    let expires_in = if response.expires_at_unix_ms > 0 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        Duration::from_millis(response.expires_at_unix_ms.saturating_sub(now))
            .min(client.lease_ttl.saturating_mul(2))
    } else {
        client.lease_ttl
    };
    let granted = u64::from(response.granted_tokens);
    LeaseGrant {
        lease_id: response.idempotency_key,
        key: LeaseKey::new(&request.policy_id, request.shard, request.key_hash),
        granted,
        remaining: granted,
        expires_in: expires_in.max(Duration::from_millis(1)),
        denied: !response.granted || granted == 0,
    }
}

fn counter_batch_id(node_id: &str, epoch: u64, deltas: &[CounterDelta]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(node_id.as_bytes());
    hasher.update(epoch.to_le_bytes());
    for delta in deltas {
        hasher.update((delta.policy_id.len() as u64).to_le_bytes());
        hasher.update(delta.policy_id.as_bytes());
        hasher.update(delta.window_start_unix.to_le_bytes());
        hasher.update(delta.shard.to_le_bytes());
        hasher.update(delta.key_hash);
        hasher.update(delta.consumed.to_le_bytes());
        hasher.update(delta.rejected.to_le_bytes());
    }
    // UUIDv5 over a stable SHA-256 digest makes retries of the same batch
    // idempotent at the server without persisting a mapping.
    uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_OID, &hasher.finalize()).to_string()
}

fn read_optional_pem(path: &str, name: &str) -> Result<Option<Vec<u8>>, DistributedError> {
    let path = path.trim();
    if path.is_empty() {
        return Ok(None);
    }
    std::fs::read(Path::new(path)).map(Some).map_err(|error| {
        DistributedError::invalid(format!(
            "cannot read waf.distributed.{name} '{path}': {error}"
        ))
    })
}

fn no_credential(config: &DistributedConfig) -> bool {
    config.auth_token.is_empty()
        && config.spiffe_jwt.is_empty()
        && config.spiffe_id.is_empty()
        && config.tls_client_cert_path.is_empty()
}

/// Wait for a future with the configured deadline. Exposed for tests and for
/// callers that build the client manually.
pub async fn with_deadline<F, T>(timeout: Duration, future: F) -> Result<T, DistributedError>
where
    F: Future<Output = Result<T, DistributedError>>,
{
    match tokio::time::timeout(timeout, future).await {
        Ok(result) => result,
        Err(_) => Err(DistributedError::unavailable("distri-kv request timed out")),
    }
}
