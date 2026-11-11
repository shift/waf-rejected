//! Transport seam for the distributed client.
//!
//! The controller, cache, lease pool, policy verification and `local_only`
//! fallback only ever see the trait objects in [`TransportRoles`]. A transport
//! implements [`TransportClient`], which is the union of the five existing
//! source traits plus lease acquisition and an explicit shutdown hook. The
//! gRPC (tonic) client is one implementation; QuicCrunch is another.
//!
//! Adding a transport must not change request decisions. Both implementations
//! map transport failures onto [`DistributedError`]; only the controller's
//! reconnect/backoff and the configured `fallback` decide what happens next.

use std::sync::Arc;

use async_trait::async_trait;

use super::leases::{LeaseGrant, LeaseRequest};
use super::traits::{
    DistributedError, EventSink, LeaseSource, NodeRegistry, PolicySource, RateLimitSync,
    ReputationSource,
};
use crate::config::{DistributedConfig, DistributedTransportKind};

/// Construct the configured transport.
///
/// `transport = "grpc"` always builds the tonic client. `quiccrunch` is only
/// compiled in with the `quiccrunch-transport` feature; without it this fails
/// closed instead of falling back to gRPC.
pub fn build_transport(
    config: &DistributedConfig,
) -> Result<Arc<dyn TransportClient>, DistributedError> {
    match config.transport {
        DistributedTransportKind::Grpc => Ok(Arc::new(super::grpc::DistriWafClient::new(config)?)),
        DistributedTransportKind::QuicCrunch => build_quiccrunch(config),
    }
}

#[cfg(feature = "quiccrunch-transport")]
fn build_quiccrunch(
    config: &DistributedConfig,
) -> Result<Arc<dyn TransportClient>, DistributedError> {
    super::quiccrunch::build(config)
}

#[cfg(not(feature = "quiccrunch-transport"))]
fn build_quiccrunch(
    _config: &DistributedConfig,
) -> Result<Arc<dyn TransportClient>, DistributedError> {
    Err(DistributedError::invalid(
        "waf.distributed.transport = \"quiccrunch\" requires a build with the non-default \
         `quiccrunch-transport` feature; rebuild with --features quiccrunch-transport or select \
         transport = \"grpc\"",
    ))
}

/// Everything the distributed controller needs from a control-plane transport.
///
/// This deliberately mirrors the already-vendored `DistriWaf` RPC surface:
/// register/heartbeat ([`NodeRegistry`]), policy get ([`PolicySource`]),
/// reputation get ([`ReputationSource`]), counter flush ([`RateLimitSync`]),
/// event ingest ([`EventSink`]) and lease acquisition ([`LeaseSource`]).
/// `shutdown` lets a transport close its connection pool without changing the
/// controller's drain semantics.
#[async_trait]
pub trait TransportClient:
    PolicySource
    + ReputationSource
    + RateLimitSync
    + EventSink
    + NodeRegistry
    + LeaseSource
    + Send
    + Sync
{
    /// Stable name used in logs and diagnostics, for example `grpc`.
    fn transport_name(&self) -> &'static str;

    /// Release transport resources. Called once after the controller has
    /// drained its queues. The default is a no-op, which is correct for the
    /// stateless tonic channel wrapper.
    async fn shutdown(&self) -> Result<(), DistributedError> {
        Ok(())
    }
}

/// Individual trait objects handed to [`super::controller::DistributedController`].
///
/// The controller stores five separate `Arc<dyn Trait>` handles so it stays
/// unaware of the concrete transport. [`TransportRoles::lease`] is attached
/// only when the transport supplies one.
pub struct TransportRoles {
    pub policy: Arc<dyn PolicySource>,
    pub reputation: Arc<dyn ReputationSource>,
    pub rate_limit_sync: Arc<dyn RateLimitSync>,
    pub event_sink: Arc<dyn EventSink>,
    pub registry: Arc<dyn NodeRegistry>,
    pub lease: Arc<dyn LeaseSource>,
}

/// Split one transport into the controller's individual source handles.
pub fn split_transport(transport: Arc<dyn TransportClient>) -> TransportRoles {
    let adapter = Arc::new(RoleAdapter(transport));
    TransportRoles {
        policy: Arc::clone(&adapter) as Arc<dyn PolicySource>,
        reputation: Arc::clone(&adapter) as Arc<dyn ReputationSource>,
        rate_limit_sync: Arc::clone(&adapter) as Arc<dyn RateLimitSync>,
        event_sink: Arc::clone(&adapter) as Arc<dyn EventSink>,
        registry: Arc::clone(&adapter) as Arc<dyn NodeRegistry>,
        lease: adapter as Arc<dyn LeaseSource>,
    }
}

/// Forwards each source trait to the underlying transport. Trait-object
/// upcasting is still unstable, so the split uses this thin adapter instead.
struct RoleAdapter(Arc<dyn TransportClient>);

#[async_trait]
impl PolicySource for RoleAdapter {
    async fn current_policy(&self) -> Result<super::traits::PolicySnapshot, DistributedError> {
        self.0.current_policy().await
    }

    async fn policy_at(
        &self,
        generation: u64,
    ) -> Result<super::traits::PolicySnapshot, DistributedError> {
        self.0.policy_at(generation).await
    }
}

#[async_trait]
impl ReputationSource for RoleAdapter {
    async fn lookup(
        &self,
        ip: std::net::IpAddr,
    ) -> Result<Option<super::traits::ReputationEntry>, DistributedError> {
        self.0.lookup(ip).await
    }

    fn max_age(&self) -> std::time::Duration {
        self.0.max_age()
    }
}

#[async_trait]
impl RateLimitSync for RoleAdapter {
    async fn flush(&self, deltas: &[super::traits::CounterDelta]) -> Result<(), DistributedError> {
        self.0.flush(deltas).await
    }
}

#[async_trait]
impl EventSink for RoleAdapter {
    async fn export(
        &self,
        events: &[super::traits::SecurityEventRecord],
    ) -> Result<(), DistributedError> {
        self.0.export(events).await
    }
}

#[async_trait]
impl NodeRegistry for RoleAdapter {
    async fn register(
        &self,
        node: &super::traits::NodeInfo,
    ) -> Result<super::traits::HeartbeatAck, DistributedError> {
        self.0.register(node).await
    }

    async fn heartbeat(
        &self,
        node: &super::traits::NodeInfo,
    ) -> Result<super::traits::HeartbeatAck, DistributedError> {
        self.0.heartbeat(node).await
    }
}

#[async_trait]
impl LeaseSource for RoleAdapter {
    async fn acquire_leases(
        &self,
        requests: &[LeaseRequest],
    ) -> Result<Vec<LeaseGrant>, DistributedError> {
        self.0.acquire_leases(requests).await
    }
}
