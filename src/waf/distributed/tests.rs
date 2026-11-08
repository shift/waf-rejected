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
}

#[tonic::async_trait]
impl DistriWafService for MockWaf {
    type WatchStream = futures::stream::Empty<Result<super::distri_waf::WatchEvent, tonic::Status>>;

    async fn register(
        &self,
        request: tonic::Request<RegisterRequest>,
    ) -> Result<tonic::Response<RegisterResponse>, tonic::Status> {
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
