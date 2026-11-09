//! Tests for the distributed scaffold. Compiled only with `--features distri-kv`.

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;

use super::cache::{CacheLookup, CacheState, VersionedCache};
use super::controller::{
    next_backoff, BoundedQueue, DistributedController, DropPolicy, PushOutcome,
};
use super::local::{
    LocalEventSink, LocalNodeRegistry, LocalPolicySource, LocalRateLimitSync, LocalReputationSource,
};
use super::state::{DistributedState, UnavailableDecision};
use super::traits::{
    DistributedError, EventSink, HeartbeatAck, NodeInfo, NodeRegistry, PolicySnapshot,
    PolicySource, RateLimitSync, ReputationSource, SecurityEventRecord,
};
use crate::config::{DistributedConfig, DistributedFallbackMode};
use crate::waf::{Decision, RequestContext, WafEngine};

fn enabled_config() -> DistributedConfig {
    DistributedConfig {
        enabled: true,
        node_id: "node-a".to_string(),
        region: "eu-west-1".to_string(),
        endpoints: vec!["https://dkv-eu.example:7443".to_string()],
        heartbeat_interval_secs: 1,
        reconnect_initial_backoff_ms: 1,
        reconnect_max_backoff_ms: 4,
        event_queue_capacity: 4,
        counter_queue_capacity: 4,
        allow_insecure_transport: true,
        require_policy_signature: false,
        ..DistributedConfig::default()
    }
}

#[test]
fn local_only_sources_preserve_single_process_behaviour() {
    let config = enabled_config();
    let state = DistributedState::from_config(&config);

    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let policy = LocalPolicySource.current_policy().await.unwrap();
        assert_eq!(policy.generation, 0);
        assert_eq!(policy.ruleset_version, "local");
        assert!(policy.allowlist.is_empty());
        assert!(policy.blocklist.is_empty());
        assert_eq!(policy.rate_limit_multiplier, 1.0);

        let reputation = LocalReputationSource
            .lookup("203.0.113.7".parse().unwrap())
            .await
            .unwrap();
        assert!(reputation.is_none(), "local reputation is always unknown");

        let sink = LocalEventSink::default();
        sink.export(&[]).await.unwrap();
        assert_eq!(sink.exported(), 0);

        let sync = LocalRateLimitSync::default();
        sync.flush(&[]).await.unwrap();
        assert_eq!(sync.flushed(), 0);

        let ack = LocalNodeRegistry
            .heartbeat(&NodeInfo {
                node_id: "node-a".to_string(),
                region: "eu-west-1".to_string(),
                version: "test".to_string(),
                epoch: 0,
            })
            .await
            .unwrap();
        assert!(!ack.connected);
    });

    assert_eq!(state.fallback(), DistributedFallbackMode::LocalOnly);
    assert_eq!(state.unavailable_decision(), UnavailableDecision::LocalOnly);
    assert!(!state.should_block_without_cluster());
    assert!(!state.allows_without_cluster());
}

#[test]
fn fallback_modes_have_explicit_unavailable_decisions() {
    let mut config = enabled_config();

    config.fallback = DistributedFallbackMode::LocalOnly;
    let state = DistributedState::from_config(&config);
    assert_eq!(state.unavailable_decision(), UnavailableDecision::LocalOnly);
    assert!(!state.should_block_without_cluster());

    config.fallback = DistributedFallbackMode::FailOpen;
    let state = DistributedState::from_config(&config);
    assert_eq!(state.unavailable_decision(), UnavailableDecision::Allow);
    assert!(state.allows_without_cluster());
    assert!(!state.should_block_without_cluster());

    config.fallback = DistributedFallbackMode::FailClosed;
    let state = DistributedState::from_config(&config);
    assert_eq!(state.unavailable_decision(), UnavailableDecision::Block);
    assert!(state.should_block_without_cluster());
}

#[tokio::test]
async fn enabling_the_feature_does_not_change_decisions_without_a_cluster() {
    let mut off = crate::config::Config::default();
    off.waf.rate_limit.per_ip_enabled = false;
    off.waf.rate_limit.global_enabled = false;
    off.waf.distributed.enabled = false;

    let mut on = off.clone();
    on.waf.distributed = enabled_config();

    let off_engine = WafEngine::with_config(&off);
    let on_engine = WafEngine::with_config(&on);
    assert!(off_engine.distributed_state().is_none());
    let state = on_engine
        .distributed_state()
        .expect("enabled config exposes a state handle");
    assert_eq!(state.unavailable_decision(), UnavailableDecision::LocalOnly);

    let cases: Vec<(hyper::Method, &str)> = vec![
        (hyper::Method::GET, "/health"),
        (hyper::Method::GET, "/?id=1%20UNION%20SELECT%201"),
        (hyper::Method::POST, "/api/items"),
    ];
    for (method, uri) in cases {
        let ctx = RequestContext::new(
            IpAddr::from([127, 0, 0, 1]),
            method,
            uri.parse().unwrap(),
            hyper::HeaderMap::new(),
            None,
        );
        let off_decision = off_engine.evaluate(&ctx).await;
        let on_decision = on_engine.evaluate(&ctx).await;
        assert_eq!(
            on_decision, off_decision,
            "distributed enabled changed the decision for {uri}"
        );
        assert!(matches!(
            on_decision,
            Decision::Allow | Decision::Block { .. }
        ));
    }
}

#[test]
fn cache_ttl_stale_and_generation_invalidation() {
    let ttl = Duration::from_secs(10);
    let max_stale = Duration::from_secs(30);
    let cache: VersionedCache<String, u64> = VersionedCache::new(ttl, max_stale, 8);
    let start = Instant::now();
    cache.insert_at("k".to_string(), 7, 0, start, false);

    assert_eq!(
        cache.get_at(&"k".to_string(), start + Duration::from_secs(5)),
        CacheLookup::Hit {
            value: 7,
            state: CacheState::Fresh
        }
    );
    assert_eq!(
        cache.get_at(&"k".to_string(), start + Duration::from_secs(20)),
        CacheLookup::Hit {
            value: 7,
            state: CacheState::Stale
        }
    );
    assert_eq!(
        cache.get_at(&"k".to_string(), start + Duration::from_secs(41)),
        CacheLookup::Miss
    );

    cache.insert_at("k".to_string(), 8, 0, start, false);
    assert!(cache.set_generation(1));
    assert_eq!(
        cache.get_at(&"k".to_string(), start + Duration::from_secs(1)),
        CacheLookup::Miss,
        "a new generation must invalidate older entries"
    );
    assert!(!cache.set_generation(1), "same generation is a no-op");
    assert_eq!(cache.metrics().cache_invalidations(), 1);
}

#[test]
fn cache_reports_explicit_blocked_entries() {
    let cache: VersionedCache<String, u64> =
        VersionedCache::new(Duration::from_secs(10), Duration::from_secs(10), 4);
    cache.block("bad".to_string(), 99);
    assert_eq!(
        cache.get(&"bad".to_string()),
        CacheLookup::Hit {
            value: 99,
            state: CacheState::Blocked
        }
    );
    assert_eq!(cache.metrics().cache_blocked(), 1);
}

#[test]
fn bounded_queue_drops_oldest_and_accounts_for_backpressure() {
    let queue = BoundedQueue::new(2, DropPolicy::DropOldest);
    assert_eq!(queue.try_push(1), PushOutcome::Enqueued);
    assert_eq!(queue.try_push(2), PushOutcome::Enqueued);
    assert_eq!(queue.try_push(3), PushOutcome::DroppedOldest);
    assert_eq!(queue.len(), 2);
    assert_eq!(queue.dropped(), 1);
    assert_eq!(queue.enqueued(), 3);
    assert_eq!(queue.drain_batch(10), vec![2, 3]);

    queue.close();
    assert_eq!(queue.try_push(4), PushOutcome::Closed);
}

#[test]
fn bounded_queue_drop_newest_keeps_the_oldest_items() {
    let queue = BoundedQueue::new(2, DropPolicy::DropNewest);
    assert_eq!(queue.try_push(1), PushOutcome::Enqueued);
    assert_eq!(queue.try_push(2), PushOutcome::Enqueued);
    assert_eq!(queue.try_push(3), PushOutcome::DroppedNewest);
    assert_eq!(queue.drain_batch(10), vec![1, 2]);
    assert_eq!(queue.dropped(), 1);
}

#[test]
fn queue_pressure_under_failure_stays_bounded() {
    let mut config = enabled_config();
    config.event_queue_capacity = 8;
    config.counter_queue_capacity = 8;
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let state = Arc::new(DistributedState::from_config(&config));
        let controller = DistributedController::with_sources(
            &config,
            Arc::clone(&state),
            Arc::new(LocalPolicySource),
            Arc::new(LocalReputationSource),
            Arc::new(LocalRateLimitSync::default()),
            Arc::new(LocalEventSink::default()),
            Arc::new(CountingRegistry {
                calls: Arc::new(AtomicU64::new(0)),
                fail: true,
            }),
        );
        // Do not spawn: the consumer is unavailable, so every push exercises
        // the full-queue path while the control plane is down.
        let handle = controller.handle();
        for index in 0..10_000 {
            handle.enqueue_event(sample_event_with_id(index));
            handle.enqueue_counter(super::traits::CounterDelta {
                policy_id: "per_ip".to_string(),
                window_start_unix: 0,
                shard: 0,
                key_hash: [0; 16],
                consumed: 1,
                rejected: 0,
                clock_offset_ms: 0,
            });
        }
        for (name, depth) in handle.queue_depths() {
            assert!(depth <= 8, "{name} queue grew past its bound: {depth}");
        }
        assert_eq!(state.metrics().queue_dropped(), 20_000 - 16);
        assert!(
            state.metrics().reconnects() == 0,
            "controller was not spawned"
        );
    });
}

#[test]
fn reconnect_backoff_doubles_and_caps() {
    let mut backoff = Duration::from_millis(100);
    let max = Duration::from_secs(1);
    let expected = [200, 400, 800, 1000, 1000];
    for want in expected {
        backoff = next_backoff(backoff, max);
        assert_eq!(backoff, Duration::from_millis(want));
    }
}

struct CountingRegistry {
    calls: Arc<AtomicU64>,
    fail: bool,
}

#[async_trait]
impl NodeRegistry for CountingRegistry {
    async fn register(&self, _node: &NodeInfo) -> Result<HeartbeatAck, DistributedError> {
        Ok(HeartbeatAck {
            connected: !self.fail,
            server_time_unix_ms: 0,
            policy_generation: None,
        })
    }

    async fn heartbeat(&self, _node: &NodeInfo) -> Result<HeartbeatAck, DistributedError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        if self.fail {
            Err(DistributedError::unavailable("cluster down"))
        } else {
            Ok(HeartbeatAck {
                connected: true,
                server_time_unix_ms: 1,
                policy_generation: Some(1),
            })
        }
    }
}

struct GeneratingPolicy {
    generation: u64,
}

#[async_trait]
impl PolicySource for GeneratingPolicy {
    async fn current_policy(&self) -> Result<PolicySnapshot, DistributedError> {
        Ok(PolicySnapshot {
            generation: self.generation,
            ruleset_version: "test".to_string(),
            allowlist: Vec::new(),
            blocklist: Vec::new(),
            rate_limit_multiplier: 0.5,
            issued_at: std::time::SystemTime::now(),
        })
    }
}

#[test]
fn controller_applies_generation_and_exposes_metrics() {
    let config = enabled_config();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let state = Arc::new(DistributedState::from_config(&config));
        let controller = DistributedController::with_sources(
            &config,
            Arc::clone(&state),
            Arc::new(GeneratingPolicy { generation: 5 }),
            Arc::new(LocalReputationSource),
            Arc::new(LocalRateLimitSync::default()),
            Arc::new(LocalEventSink::default()),
            Arc::new(CountingRegistry {
                calls: Arc::new(AtomicU64::new(0)),
                fail: false,
            }),
        );
        let handle = controller.spawn();

        tokio::time::sleep(Duration::from_millis(120)).await;
        assert_eq!(state.policy_generation(), 5);
        assert!(state.connected());
        assert!(state.heartbeat_age().is_some());

        // Shadow mode (default true) never applies the feedback multiplier.
        assert_eq!(state.rate_limit_multiplier(), 1.0);

        handle.shutdown().await;
        assert_eq!(handle.enqueue_event(sample_event()), PushOutcome::Closed);
    });
}

#[test]
fn controller_backs_off_and_activates_fallback_on_failure() {
    let config = enabled_config();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let state = Arc::new(DistributedState::from_config(&config));
        let calls = Arc::new(AtomicU64::new(0));
        let controller = DistributedController::with_sources(
            &config,
            Arc::clone(&state),
            Arc::new(LocalPolicySource),
            Arc::new(LocalReputationSource),
            Arc::new(LocalRateLimitSync::default()),
            Arc::new(LocalEventSink::default()),
            Arc::new(CountingRegistry {
                calls: Arc::clone(&calls),
                fail: true,
            }),
        );
        let handle = controller.spawn();
        tokio::time::sleep(Duration::from_millis(120)).await;

        assert!(!state.connected());
        assert!(calls.load(Ordering::Relaxed) >= 1);
        assert!(state.metrics().reconnects() >= 1);
        assert_eq!(state.metrics().fallback_activations(), 1);
        // local_only must not turn the outage into a block decision.
        assert!(!state.should_block_without_cluster());

        handle.shutdown().await;
    });
}

#[test]
fn queues_are_drained_and_closed_on_shutdown() {
    let config = enabled_config();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let state = Arc::new(DistributedState::from_config(&config));
        let controller = DistributedController::with_sources(
            &config,
            Arc::clone(&state),
            Arc::new(LocalPolicySource),
            Arc::new(LocalReputationSource),
            Arc::new(LocalRateLimitSync::default()),
            Arc::new(LocalEventSink::default()),
            Arc::new(LocalNodeRegistry),
        );
        let handle = controller.spawn();
        for index in 0..6 {
            handle.enqueue_event(sample_event_with_id(index));
        }
        let depths = handle.queue_depths();
        assert!(depths
            .iter()
            .any(|(_, depth)| *depth <= config.event_queue_capacity));

        handle.shutdown().await;
        assert!(handle.queue_depths().iter().all(|(_, depth)| *depth == 0));
        assert!(state.metrics().queue_dropped() >= 1);
    });
}

fn sample_event() -> SecurityEventRecord {
    sample_event_with_id(0)
}

fn sample_event_with_id(index: u64) -> SecurityEventRecord {
    SecurityEventRecord {
        event_id: format!("event-{index}"),
        node_id: "node-a".to_string(),
        observed_at_unix_ms: 0,
        rule_ids: vec!["942100".to_string()],
        decision: super::traits::EventDecision::Block,
        threat_level: super::traits::EventThreatLevel::High,
        ip_hash: None,
    }
}

// ---------------------------------------------------------------------------
// gRPC contract (mock in-process server)
// ---------------------------------------------------------------------------

use super::distri_waf::distri_waf_server::{DistriWaf as DistriWafService, DistriWafServer};
use super::distri_waf::{
    PolicyBundle, PolicyPayload, RegisterRequest, RegisterResponse, ReputationEntry as ProtoRep,
    ReputationResponse,
};
use super::grpc::DistriWafClient;

#[derive(Default)]
struct MockWaf {
    events: AtomicU64,
    counters: AtomicU64,
    /// Deliberate control-plane stall for the non-blocking request-path test.
    rpc_delay_ms: u64,
    lease_budget: AtomicU64,
    spiffe_seen: std::sync::Mutex<Option<String>>,
}

impl MockWaf {
    async fn stall(&self) {
        if self.rpc_delay_ms > 0 {
            tokio::time::sleep(Duration::from_millis(self.rpc_delay_ms)).await;
        }
    }
}

#[tonic::async_trait]
impl DistriWafService for MockWaf {
    type WatchStream = futures::stream::Empty<Result<super::distri_waf::WatchEvent, tonic::Status>>;

    async fn register(
        &self,
        request: tonic::Request<RegisterRequest>,
    ) -> Result<tonic::Response<RegisterResponse>, tonic::Status> {
        self.stall().await;
        let node = request
            .into_inner()
            .node
            .ok_or_else(|| tonic::Status::invalid_argument("node required"))?;
        Ok(tonic::Response::new(RegisterResponse {
            contract_version: 1,
            accepted: true,
            epoch: node.epoch.max(1),
            lease_ttl_secs: 30,
            server_time_unix_ms: 1_700_000_000_000,
        }))
    }

    async fn heartbeat(
        &self,
        request: tonic::Request<super::distri_waf::HeartbeatRequest>,
    ) -> Result<tonic::Response<super::distri_waf::HeartbeatResponse>, tonic::Status> {
        self.stall().await;
        let spiffe = request
            .metadata()
            .get("x-spiffe-id")
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        *self.spiffe_seen.lock().unwrap() = spiffe;
        let request = request.into_inner();
        if request.node_id != "node-a" {
            return Err(tonic::Status::not_found("unknown node"));
        }
        Ok(tonic::Response::new(super::distri_waf::HeartbeatResponse {
            contract_version: 1,
            lease_ttl_secs: 30,
            server_time_unix_ms: 1_700_000_000_000,
            drain: false,
        }))
    }

    async fn discover(
        &self,
        _request: tonic::Request<super::distri_waf::DiscoverRequest>,
    ) -> Result<tonic::Response<super::distri_waf::DiscoverResponse>, tonic::Status> {
        Ok(tonic::Response::new(Default::default()))
    }

    async fn watch(
        &self,
        _request: tonic::Request<super::distri_waf::WatchRequest>,
    ) -> Result<tonic::Response<Self::WatchStream>, tonic::Status> {
        Ok(tonic::Response::new(futures::stream::empty()))
    }

    async fn get_policy(
        &self,
        request: tonic::Request<super::distri_waf::GetPolicyRequest>,
    ) -> Result<tonic::Response<PolicyBundle>, tonic::Status> {
        let request = request.into_inner();
        if request.scope != "waf" {
            return Err(tonic::Status::not_found("unknown scope"));
        }
        Ok(tonic::Response::new(PolicyBundle {
            contract_version: 1,
            schema_version: 1,
            scope: "waf".to_string(),
            version: 3,
            generation: 7,
            created_at_unix_ms: 1_700_000_000_000,
            content_hash: {
                let payload = PolicyPayload {
                    ruleset_version: "crs-4.0".to_string(),
                    ..Default::default()
                };
                super::policy_verify::payload_hash(&payload).to_vec()
            },
            payload: Some(PolicyPayload {
                ruleset_version: "crs-4.0".to_string(),
                ..Default::default()
            }),
            ..Default::default()
        }))
    }

    async fn activate_policy(
        &self,
        _request: tonic::Request<super::distri_waf::ActivatePolicyRequest>,
    ) -> Result<tonic::Response<super::distri_waf::ActivatePolicyResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("not used by the WAF client"))
    }

    async fn lookup_reputation(
        &self,
        request: tonic::Request<super::distri_waf::LookupReputationRequest>,
    ) -> Result<tonic::Response<ReputationResponse>, tonic::Status> {
        let request = request.into_inner();
        let entries = request
            .ips
            .iter()
            .filter(|ip| ip.as_str() == "203.0.113.7")
            .map(|ip| ProtoRep {
                ip: ip.clone(),
                score: 0.93,
                confidence: 0.8,
                labels: vec!["scanner".to_string()],
                expires_at_unix_ms: 1_800_000_000_000,
                version: 9,
                ..Default::default()
            })
            .collect();
        Ok(tonic::Response::new(ReputationResponse {
            contract_version: 1,
            entries,
            as_of_version: 9,
            stale: false,
        }))
    }

    async fn ingest_events(
        &self,
        request: tonic::Request<tonic::Streaming<super::distri_waf::SecurityEvent>>,
    ) -> Result<tonic::Response<super::distri_waf::IngestSummary>, tonic::Status> {
        let mut stream = request.into_inner();
        let mut accepted = 0;
        while stream.message().await?.is_some() {
            accepted += 1;
        }
        self.events.fetch_add(accepted, Ordering::Relaxed);
        Ok(tonic::Response::new(super::distri_waf::IngestSummary {
            contract_version: 1,
            node_id: "node-a".to_string(),
            accepted,
            ..Default::default()
        }))
    }

    async fn ingest_counter_deltas(
        &self,
        request: tonic::Request<super::distri_waf::CounterDeltas>,
    ) -> Result<tonic::Response<super::distri_waf::CounterAck>, tonic::Status> {
        let request = request.into_inner();
        let accepted = request.deltas.len() as u64;
        self.counters.fetch_add(accepted, Ordering::Relaxed);
        Ok(tonic::Response::new(super::distri_waf::CounterAck {
            contract_version: 1,
            accepted,
            ..Default::default()
        }))
    }

    async fn acquire_lease(
        &self,
        request: tonic::Request<super::distri_waf::AcquireLeaseRequest>,
    ) -> Result<tonic::Response<super::distri_waf::AcquireLeaseResponse>, tonic::Status> {
        let request = request.into_inner();
        let mut budget = self.lease_budget.load(Ordering::Relaxed);
        let granted = loop {
            if budget == 0 {
                break 0;
            }
            let grant = budget.min(u64::from(request.requested_tokens.max(1)));
            match self.lease_budget.compare_exchange_weak(
                budget,
                budget - grant,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => break grant,
                Err(actual) => budget = actual,
            }
        };
        let expires = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
            + 30_000;
        Ok(tonic::Response::new(
            super::distri_waf::AcquireLeaseResponse {
                contract_version: 1,
                granted: granted > 0,
                granted_tokens: granted as u32,
                remaining_tokens: self.lease_budget.load(Ordering::Relaxed) as u32,
                lease_tokens: granted as u32,
                expires_at_unix_ms: expires,
                bucket_key: request.bucket_key,
                idempotency_key: request.idempotency_key,
                retry_after_ms: 0,
                expired_leases: 0,
            },
        ))
    }

    async fn release_lease(
        &self,
        request: tonic::Request<super::distri_waf::ReleaseLeaseRequest>,
    ) -> Result<tonic::Response<super::distri_waf::ReleaseLeaseResponse>, tonic::Status> {
        let request = request.into_inner();
        let released = u64::from(request.remaining_tokens);
        self.lease_budget.fetch_add(released, Ordering::Relaxed);
        Ok(tonic::Response::new(
            super::distri_waf::ReleaseLeaseResponse {
                contract_version: 1,
                released_tokens: request.remaining_tokens,
                remaining_tokens: self.lease_budget.load(Ordering::Relaxed) as u32,
                bucket_key: request.bucket_key,
                expired_leases: 0,
            },
        ))
    }
}

/// A deliberately slow control plane must not add latency to request
/// evaluation. The controller is stuck in a 750 ms registration RPC while the
/// engine evaluates requests; the request path only reads atomics.
#[test]
fn slow_endpoint_does_not_block_request_evaluation() {
    use tonic::transport::Server;

    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            Server::builder()
                .add_service(DistriWafServer::new(MockWaf {
                    rpc_delay_ms: 750,
                    ..Default::default()
                }))
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
                .await
                .unwrap();
        });

        let mut off = crate::config::Config::default();
        off.waf.rate_limit.per_ip_enabled = false;
        off.waf.rate_limit.global_enabled = false;

        let mut on = off.clone();
        on.waf.distributed = DistributedConfig {
            enabled: true,
            node_id: "node-slow".to_string(),
            region: "eu-west-1".to_string(),
            endpoints: vec![format!("http://{address}")],
            heartbeat_interval_secs: 1,
            request_timeout_ms: 2_000,
            allow_insecure_transport: true,
            require_policy_signature: false,
            ..DistributedConfig::default()
        };

        let off_engine = WafEngine::with_config(&off);
        let on_engine = WafEngine::with_config(&on);
        let state = on_engine
            .distributed_state()
            .expect("enabled config exposes a state handle")
            .clone();
        let handle =
            DistributedController::from_config_with_state(&on.waf.distributed, Arc::clone(&state))
                .unwrap()
                .spawn();

        // Let the controller enter the slow registration RPC.
        tokio::time::sleep(Duration::from_millis(50)).await;

        let ctx = RequestContext::new(
            IpAddr::from([127, 0, 0, 1]),
            hyper::Method::GET,
            "/health".parse().unwrap(),
            hyper::HeaderMap::new(),
            None,
        );

        let started = Instant::now();
        let mut slowest = Duration::ZERO;
        for _ in 0..10 {
            let sample = Instant::now();
            let on_decision = on_engine.evaluate(&ctx).await;
            slowest = slowest.max(sample.elapsed());
            let off_decision = off_engine.evaluate(&ctx).await;
            assert_eq!(on_decision, off_decision);
        }
        let total = started.elapsed();

        assert!(
            slowest < Duration::from_millis(100),
            "request evaluation waited on the control plane: slowest {slowest:?}"
        );
        assert!(
            total < Duration::from_millis(500),
            "10 request evaluations took {total:?} while the endpoint stalled"
        );

        handle.shutdown().await;
        server.abort();
    });
}

#[test]
fn grpc_client_round_trips_register_heartbeat_policy_and_reputation() {
    use super::traits::{CounterDelta, EventDecision, EventThreatLevel};
    use tonic::transport::Server;

    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            Server::builder()
                .add_service(DistriWafServer::new(MockWaf::default()))
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
                .await
                .unwrap();
        });

        let config = DistributedConfig {
            enabled: true,
            node_id: "node-a".to_string(),
            region: "eu-west-1".to_string(),
            policy_scope: "waf".to_string(),
            endpoints: vec![format!("http://{address}")],
            allow_insecure_transport: true,
            require_policy_signature: false,
            ..DistributedConfig::default()
        };
        let client = DistriWafClient::new(&config).unwrap();
        let node = NodeInfo {
            node_id: "node-a".to_string(),
            region: "eu-west-1".to_string(),
            version: "test".to_string(),
            epoch: 3,
        };

        let ack = client.register(&node).await.unwrap();
        assert!(ack.connected);
        let ack = client.heartbeat(&node).await.unwrap();
        assert!(ack.connected);

        let policy = client.current_policy().await.unwrap();
        assert_eq!(policy.generation, 7);
        assert_eq!(policy.ruleset_version, "crs-4.0");

        let reputation = client
            .lookup("203.0.113.7".parse().unwrap())
            .await
            .unwrap()
            .expect("reputation entry");
        assert!((reputation.score - 0.93).abs() < f32::EPSILON);
        assert_eq!(reputation.version, 9);

        client
            .export(&[SecurityEventRecord {
                event_id: "event-1".to_string(),
                node_id: "node-a".to_string(),
                observed_at_unix_ms: 1,
                rule_ids: vec!["942100".to_string()],
                decision: EventDecision::Block,
                threat_level: EventThreatLevel::High,
                ip_hash: None,
            }])
            .await
            .unwrap();
        client
            .flush(&[CounterDelta {
                policy_id: "per_ip".to_string(),
                window_start_unix: 1,
                shard: 0,
                key_hash: [1; 16],
                consumed: 2,
                rejected: 1,
                clock_offset_ms: 0,
            }])
            .await
            .unwrap();

        server.abort();
    });
}

// ---------------------------------------------------------------------------
// Auth, policy integrity and leases
// ---------------------------------------------------------------------------

#[test]
fn auth_config_requires_explicit_insecure_transport_and_tls_pairing() {
    let mut config = DistributedConfig {
        enabled: true,
        node_id: "node-a".to_string(),
        region: "eu-west-1".to_string(),
        endpoints: vec!["http://dkv:7443".to_string()],
        ..DistributedConfig::default()
    };
    assert!(config.validate().is_err(), "plaintext must be explicit");
    config.allow_insecure_transport = true;
    assert!(config.validate().is_ok());

    config.endpoints = vec!["https://dkv:7443".to_string()];
    config.tls_client_cert_path = "/tmp/client.pem".to_string();
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("tls_client_key_path"), "{error}");

    config.tls_client_key_path = "/tmp/client.key".to_string();
    config.spiffe_id = "not-a-spiffe-id".to_string();
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("spiffe_id"), "{error}");
    config.spiffe_id = "spiffe://example.org/waf/node-a".to_string();
    assert!(config.validate().is_ok());
}

#[test]
fn spiffe_and_bearer_metadata_are_attached_without_network() {
    let config = DistributedConfig {
        enabled: true,
        node_id: "node-a".to_string(),
        region: "eu-west-1".to_string(),
        endpoints: vec!["https://dkv.example:7443".to_string()],
        auth_token: "secret-token".to_string(),
        spiffe_id: "spiffe://example.org/waf/node-a".to_string(),
        require_policy_signature: false,
        ..DistributedConfig::default()
    };
    let client = DistriWafClient::new(&config).unwrap();
    let request = client.request(());
    assert_eq!(
        request.metadata().get("authorization").unwrap(),
        "Bearer secret-token"
    );
    assert_eq!(
        request.metadata().get("x-spiffe-id").unwrap(),
        "spiffe://example.org/waf/node-a"
    );
}

fn policy_keypair() -> (ring::signature::Ed25519KeyPair, String) {
    use ring::signature::KeyPair as _;
    let seed = [7u8; 32];
    let pair = ring::signature::Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
    let public = hex::encode(pair.public_key().as_ref());
    (pair, public)
}

fn signed_bundle(
    pair: &ring::signature::Ed25519KeyPair,
    generation: u64,
    previous_hash: Vec<u8>,
) -> PolicyBundle {
    let payload = PolicyPayload {
        ruleset_version: format!("crs-{generation}"),
        ..Default::default()
    };
    let content_hash = super::policy_verify::payload_hash(&payload).to_vec();
    let signature = pair.sign(&content_hash).as_ref().to_vec();
    PolicyBundle {
        contract_version: 1,
        schema_version: 1,
        scope: "waf".to_string(),
        version: generation,
        generation,
        created_at_unix_ms: 1,
        previous_hash,
        content_hash,
        signature,
        key_id: "key-1".to_string(),
        payload: Some(payload),
        ..Default::default()
    }
}

#[test]
fn policy_signature_chain_and_generation_are_enforced() {
    let (pair, public_key) = policy_keypair();
    let config = DistributedConfig {
        require_policy_signature: true,
        policy_signing_public_key: public_key,
        policy_signing_key_id: "key-1".to_string(),
        ..DistributedConfig::default()
    };
    let verifier = super::policy_verify::PolicyVerifier::from_config(&config).unwrap();
    let mut state = super::policy_verify::PolicyVerificationState::default();

    let first = signed_bundle(&pair, 1, Vec::new());
    assert!(verifier.verify(&first, &mut state).is_ok());

    let mut tampered = signed_bundle(&pair, 2, first.content_hash.clone());
    tampered.payload.as_mut().unwrap().ruleset_version = "evil".to_string();
    assert!(verifier.verify(&tampered, &mut state).is_err());

    let mut unsigned = signed_bundle(&pair, 2, first.content_hash.clone());
    unsigned.signature.clear();
    assert!(verifier.verify(&unsigned, &mut state).is_err());

    let mut bad_chain = signed_bundle(&pair, 2, vec![9u8; 32]);
    assert!(verifier.verify(&bad_chain, &mut state).is_err());

    bad_chain.previous_hash = first.content_hash.clone();
    assert!(verifier.verify(&bad_chain, &mut state).is_ok());
    assert_eq!(state.generation(), 2);

    let replay = signed_bundle(&pair, 2, first.content_hash.clone());
    assert!(verifier.verify(&replay, &mut state).is_ok());

    let older = signed_bundle(&pair, 1, Vec::new());
    assert!(verifier.verify(&older, &mut state).is_err());
}

fn lease_config() -> DistributedConfig {
    DistributedConfig {
        enabled: true,
        node_id: "node-a".to_string(),
        region: "eu-west-1".to_string(),
        endpoints: vec!["https://dkv.example:7443".to_string()],
        leases_enabled: true,
        shadow: false,
        require_policy_signature: false,
        lease_queue_capacity: 4,
        ..DistributedConfig::default()
    }
}

fn grant(key: &super::leases::LeaseKey, units: u64) -> super::leases::LeaseGrant {
    super::leases::LeaseGrant {
        lease_id: "lease".to_string(),
        key: *key,
        granted: units,
        remaining: units,
        expires_in: Duration::from_secs(30),
        denied: false,
    }
}

#[test]
fn lease_exhaustion_is_shared_across_two_waf_instances() {
    use crate::waf::WafRule as _;
    let config = lease_config();
    let state_a = Arc::new(DistributedState::from_config(&config));
    let state_b = Arc::new(DistributedState::from_config(&config));
    let ip: IpAddr = "198.51.100.7".parse().unwrap();
    let key = super::leases::LeaseKey::new("per_ip_rate_limit", 0, {
        use sha2::Digest as _;
        let digest = sha2::Sha256::digest(match ip {
            IpAddr::V4(v4) => v4.octets().to_vec(),
            IpAddr::V6(v6) => v6.octets().to_vec(),
        });
        let mut hash = [0u8; 16];
        hash.copy_from_slice(&digest[..16]);
        hash
    });

    // The broker grants two units total, one per node, and nothing more.
    state_a.apply_lease(grant(&key, 1));
    state_b.apply_lease(grant(&key, 1));

    let limiter_a = super::super::rate_limit::RateLimiter::new(
        "per_ip_rate_limit",
        1,
        0,
        Duration::from_secs(60),
    )
    .with_distributed_state(Arc::clone(&state_a));
    let limiter_b = super::super::rate_limit::RateLimiter::new(
        "per_ip_rate_limit",
        1,
        0,
        Duration::from_secs(60),
    )
    .with_distributed_state(Arc::clone(&state_b));
    let ctx = RequestContext::new(
        ip,
        hyper::Method::GET,
        "/".parse().unwrap(),
        hyper::HeaderMap::new(),
        None,
    );

    assert!(matches!(limiter_a.evaluate(&ctx), Decision::Allow));
    assert!(
        matches!(limiter_a.evaluate(&ctx), Decision::Allow),
        "lease unit"
    );
    assert!(matches!(
        limiter_a.evaluate(&ctx),
        Decision::RateLimit { .. }
    ));
    assert!(matches!(limiter_b.evaluate(&ctx), Decision::Allow));
    assert!(
        matches!(limiter_b.evaluate(&ctx), Decision::Allow),
        "lease unit"
    );
    assert!(matches!(
        limiter_b.evaluate(&ctx),
        Decision::RateLimit { .. }
    ));
    assert!(state_a.metrics().lease_granted() >= 1);
    assert!(state_b.metrics().lease_granted() >= 1);
}

#[test]
fn expired_lease_fails_closed_but_keeps_local_behaviour() {
    let config = lease_config();
    let state = DistributedState::from_config(&config);
    let key = super::leases::LeaseKey::new("per_ip_rate_limit", 0, [1u8; 16]);
    state.apply_lease(super::leases::LeaseGrant {
        lease_id: "lease".to_string(),
        key,
        granted: 5,
        remaining: 5,
        expires_in: Duration::from_millis(1),
        denied: false,
    });
    std::thread::sleep(Duration::from_millis(5));
    assert_eq!(
        state.try_consume_lease(&key),
        super::leases::LeaseConsume::Expired
    );
    assert_eq!(state.metrics().lease_expired(), 1);
    assert!(state.metrics().lease_fallbacks() >= 1);
}

#[test]
fn lease_request_queue_is_bounded_and_accounts_drops() {
    let requests = super::leases::LeaseRequests::new(2);
    for shard in 0..3 {
        requests.try_push(super::leases::LeaseRequest {
            policy_id: "per_ip".to_string(),
            window_start_unix: 0,
            shard,
            key_hash: [shard as u8; 16],
            requested: 1,
        });
    }
    assert_eq!(requests.len(), 2);
    assert_eq!(requests.dropped(), 1);
    let drained = requests.drain_batch(10);
    assert_eq!(drained.len(), 2);
    assert_eq!(drained[0].shard, 1, "oldest request was evicted");
}
