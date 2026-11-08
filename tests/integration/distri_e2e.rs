//! End-to-end tests against a real `shift/distri-kv` server.
//!
//! The tests are `#[ignore]`d because they need a built `distri-kv-server`
//! binary. Run them with `scripts/test-distri-e2e.sh`, which builds the server
//! from the pinned revision, builds `waf-ingress` with the `distri-kv` feature
//! and executes this module.
//!
//! Nothing in this module weakens production authentication: the server is
//! started with its real bearer-token mode and the WAF client presents the
//! configured `waf.distributed.auth_token`.
//!
//! Coverage:
//!
//! - node registration and heartbeats are visible through `Discover` and the
//!   server's `distri_waf_connected_nodes` gauge,
//! - policy fetch and generation changes invalidate the WAF policy cache,
//! - reputation lookups round-trip a seeded entry,
//! - security events and counter deltas are accepted by the server,
//! - the real proxy keeps serving with `fallback = "local_only"` during an
//!   outage, and the fallback decision matrix is explicit for `fail_open` and
//!   `fail_closed`.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use waf_ingress::config::{DistributedConfig, DistributedFallbackMode};
use waf_ingress::waf::distributed::distri_waf::distri_waf_client::DistriWafClient as RawWafClient;
use waf_ingress::waf::distributed::distri_waf::{
    ActivatePolicyRequest, CounterDelta as ProtoCounterDelta, CounterDeltas, DiscoverRequest,
    LookupReputationRequest, PolicyBundle, PolicyPayload, ReputationEntry as ProtoReputationEntry,
};
use waf_ingress::waf::distributed::{
    CounterDelta, DistriWafClient, DistributedController, DistributedState, EventDecision,
    EventSink, EventThreatLevel, NodeInfo, NodeRegistry, PolicySource, RateLimitSync,
    ReputationSource, SecurityEventRecord, UnavailableDecision,
};

const REGION: &str = "e2e-region";
const NODE_ID: &str = "waf-e2e-1";
const SCOPE: &str = "default";
const REPUTATION_IP: &str = "198.51.100.77";

fn server_binary() -> PathBuf {
    std::env::var_os("DISTRI_KV_SERVER_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp/opencode/dkv-e2e/target/debug/distri-kv-server"))
}

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().expect("ephemeral addr").port()
}

/// A gRPC port whose `port + 1000` sibling (the Raft listener) is also free.
fn free_grpc_port() -> u16 {
    for _ in 0..64 {
        let port = free_port();
        if port > 55_000 {
            continue;
        }
        if std::net::TcpListener::bind(("127.0.0.1", port + 1000)).is_ok() {
            return port;
        }
    }
    panic!("could not find a free gRPC + Raft port pair");
}

fn wait_bounded<F>(mut predicate: F, timeout: Duration, what: &str)
where
    F: FnMut() -> bool,
{
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if predicate() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("timed out after {timeout:?} waiting for {what}");
}

async fn wait_until<F, Fut>(mut check: F, timeout: Duration, what: &str)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if check().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out after {timeout:?} waiting for {what}");
}

async fn http_get(addr: SocketAddr, path: &str) -> String {
    let mut stream = TcpStream::connect(addr)
        .await
        .expect("connect to HTTP server");
    let request = format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write HTTP request");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .expect("read HTTP response");
    String::from_utf8_lossy(&response).into_owned()
}

fn metric_value(text: &str, name: &str) -> Option<f64> {
    text.lines().find_map(|line| {
        let rest = line.strip_prefix(name)?;
        if !(rest.starts_with(' ') || rest.starts_with('{')) {
            return None;
        }
        let rest = rest.trim_start();
        let value = match rest.strip_prefix('{') {
            Some(labelled) => labelled.split_once('}')?.1,
            None => rest,
        };
        value.split_whitespace().next()?.parse().ok()
    })
}

async fn wait_for_metric<F>(addr: SocketAddr, name: &str, predicate: F, what: &str) -> String
where
    F: Fn(f64) -> bool + Copy,
{
    let mut last = String::new();
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        last = http_get(addr, "/metrics").await;
        if metric_value(&last, name).is_some_and(predicate) {
            return last;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("timed out waiting for {what} ({name}); last metrics:\n{last}");
}

struct DkvServer {
    child: Child,
    dir: tempfile::TempDir,
    grpc: SocketAddr,
    metrics: SocketAddr,
    token: String,
}

impl DkvServer {
    /// Start a single-node server on ephemeral ports. When `seed_ip` is set a
    /// reputation entry is written into the service's sled database before the
    /// server opens it (the contract has no WAF-node reputation write RPC).
    async fn start(seed_ip: Option<&str>) -> Self {
        let binary = server_binary();
        assert!(
            binary.is_file(),
            "distri-kv-server not found at {}; run scripts/test-distri-e2e.sh or set DISTRI_KV_SERVER_BIN",
            binary.display()
        );

        let dir = tempfile::tempdir().expect("temp dir");
        let data_dir = dir.path().join("data");
        std::fs::create_dir_all(&data_dir).expect("create data dir");
        let token = format!("e2e-token-{}", std::process::id());
        let token_path = dir.path().join("token");
        std::fs::write(&token_path, format!("{token}\n")).expect("write token");

        if let Some(ip) = seed_ip {
            seed_reputation(&data_dir, ip);
        }

        let grpc_port = free_grpc_port();
        let grpc: SocketAddr = format!("127.0.0.1:{grpc_port}").parse().unwrap();
        let metrics: SocketAddr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
        let health: SocketAddr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
        let config_path = dir.path().join("distri-kv.toml");
        std::fs::write(
            &config_path,
            format!(
                r#"[server]
bind_address = "{grpc}"
admin_address = "127.0.0.1:{admin_port}"
data_dir = "{data_dir}"
log_level = "info"
json_logging = false

[cluster]
node_id = 1
initial_cluster_size = 1
election_timeout_ms = 300
heartbeat_interval_ms = 50
max_log_entries_per_batch = 1000
snapshot_threshold = 10000
enable_pre_vote = true
jurisdictions = []

[storage]
backend = "Sled"
sync_writes = false
compression = "None"
max_db_size_gb = 1
auto_compaction = false
compaction_schedule = "0 2 * * *"

[multi_raft]
initial_partitions = 1
replication_factor = 1
split_threshold_ops_per_sec = 10000
merge_threshold_keys = 1000
virtual_nodes_per_partition = 10
auto_rebalancing = false
rebalancing_interval_sec = 300

[network]
max_message_size_mb = 16
connection_timeout_ms = 5000
keep_alive_interval_ms = 30000
concurrent_streams = 100
enable_compression = false
tcp_nodelay = true
connection_pool_size = 1

[monitoring]
metrics_enabled = true
metrics_port = {metrics_port}
health_check_port = {health_port}
profiling_enabled = false
metrics_interval_sec = 15
enable_tracing = false
trace_sampling_rate = 0.0

[security]
tls_enabled = false
cert_file = "{cert}"
key_file = "{key}"
mutual_tls = false
auth_enabled = true
auth_provider = "ApiKey"
api_key_file = "{token_path}"
"#,
                grpc = grpc,
                admin_port = free_port(),
                data_dir = data_dir.display(),
                metrics_port = metrics.port(),
                health_port = health.port(),
                cert = dir.path().join("none.crt").display(),
                key = dir.path().join("none.key").display(),
                token_path = token_path.display(),
            ),
        )
        .expect("write server config");

        let log = std::fs::File::create(dir.path().join("distri-kv.log")).expect("create log");
        let child = Command::new(&binary)
            .arg("--config")
            .arg(&config_path)
            .stdout(Stdio::from(log.try_clone().expect("clone log")))
            .stderr(Stdio::from(log))
            .spawn()
            .unwrap_or_else(|error| panic!("failed to start {}: {error}", binary.display()));

        let mut server = Self {
            child,
            dir,
            grpc,
            metrics,
            token,
        };

        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if let Some(status) = server.child.try_wait().expect("poll server") {
                panic!(
                    "distri-kv-server exited early ({status}); log:\n{}",
                    server.log()
                );
            }
            let grpc_ready = std::net::TcpStream::connect(server.grpc).is_ok();
            let metrics_ready = std::net::TcpStream::connect(server.metrics).is_ok();
            if grpc_ready && metrics_ready {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(
            std::net::TcpStream::connect(server.grpc).is_ok(),
            "distri-kv-server did not listen on {}; log:\n{}",
            server.grpc,
            server.log()
        );
        server
    }

    fn endpoint(&self) -> String {
        format!("http://{}", self.grpc)
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("distri-kv.log")).unwrap_or_default()
    }

    fn config(&self, fallback: DistributedFallbackMode) -> DistributedConfig {
        DistributedConfig {
            enabled: true,
            node_id: NODE_ID.to_string(),
            region: REGION.to_string(),
            policy_scope: SCOPE.to_string(),
            endpoints: vec![self.endpoint()],
            auth_token: self.token.clone(),
            advertise_endpoint: "http://waf-e2e.invalid:9443".to_string(),
            fallback,
            heartbeat_interval_secs: 1,
            request_timeout_ms: 1_000,
            reconnect_initial_backoff_ms: 100,
            reconnect_max_backoff_ms: 500,
            ..DistributedConfig::default()
        }
    }
}

impl Drop for DkvServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn seed_reputation(data_dir: &Path, ip: &str) {
    use prost::Message;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let entry = ProtoReputationEntry {
        ip: ip.to_string(),
        score: 0.93,
        confidence: 0.87,
        labels: vec!["scanner".to_string()],
        sources: vec!["e2e-fixture".to_string()],
        first_seen_unix_ms: now,
        last_seen_unix_ms: now,
        expires_at_unix_ms: now + 3_600_000,
        version: 1,
        review_state: 1, // AUTO
    };
    // distri-kv stores per-node state under `<data_dir>/node-<id>` and keeps
    // the DistriWaf service in the `distri-waf` namespace.
    let db =
        sled::open(data_dir.join("node-1").join("distri-waf")).expect("open distri-waf sled db");
    db.insert(format!("intel/ip/{ip}").as_bytes(), entry.encode_to_vec())
        .expect("insert reputation fixture");
    db.flush().expect("flush reputation fixture");
}

async fn raw_client(server: &DkvServer) -> RawWafClient<tonic::transport::Channel> {
    RawWafClient::connect(server.endpoint())
        .await
        .expect("connect raw DistriWaf client")
}

fn authed<T>(message: T, token: &str) -> tonic::Request<T> {
    let mut request = tonic::Request::new(message);
    request.metadata_mut().insert(
        "authorization",
        format!("Bearer {token}").parse().expect("valid token"),
    );
    request
}

async fn activate_policy(server: &DkvServer, version: u64) {
    let mut client = raw_client(server).await;
    let bundle = PolicyBundle {
        contract_version: 1,
        schema_version: 1,
        scope: SCOPE.to_string(),
        version,
        generation: version,
        created_at_unix_ms: 0,
        author: "e2e".to_string(),
        previous_hash: Vec::new(),
        content_hash: Vec::new(),
        signature: Vec::new(),
        key_id: String::new(),
        payload: Some(PolicyPayload {
            ruleset_uri: "file:///e2e/rules".to_string(),
            ruleset_version: format!("e2e-v{version}"),
            compiled_artifact: String::new(),
            features: Default::default(),
        }),
        stale_after_unix_ms: 0,
    };
    let response = client
        .activate_policy(authed(
            ActivatePolicyRequest {
                contract_version: 1,
                scope: SCOPE.to_string(),
                bundle_version: version,
                expected_current: None,
                reason: "e2e".to_string(),
                approval_id: "e2e".to_string(),
                idempotency_key: format!("e2e-{SCOPE}-{version}"),
                bundle: Some(bundle),
            },
            &server.token,
        ))
        .await
        .expect("activate policy")
        .into_inner();
    assert_eq!(response.active_version, version);
    assert_eq!(response.generation, version);
}

// ---------------------------------------------------------------------------
// WAF client against a real server
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires a built distri-kv-server; run scripts/test-distri-e2e.sh"]
async fn waf_client_registers_heartbeats_and_ingests() {
    let server = DkvServer::start(Some(REPUTATION_IP)).await;
    let config = server.config(DistributedFallbackMode::LocalOnly);
    let client = DistriWafClient::new(&config).expect("build WAF client");
    let node = NodeInfo {
        node_id: NODE_ID.to_string(),
        region: REGION.to_string(),
        version: "e2e".to_string(),
        epoch: 0,
    };

    let ack = client.register(&node).await.expect("register");
    assert!(ack.connected);
    assert!(ack.server_time_unix_ms > 0);
    let ack = client.heartbeat(&node).await.expect("heartbeat");
    assert!(ack.connected);

    let mut raw = raw_client(&server).await;
    let discovered = raw
        .discover(authed(
            DiscoverRequest {
                contract_version: 1,
                region: REGION.to_string(),
                capabilities: vec!["waf".to_string()],
                page_size: 10,
                page_token: String::new(),
            },
            &server.token,
        ))
        .await
        .expect("discover")
        .into_inner();
    let record = discovered
        .nodes
        .iter()
        .find(|node| node.node_id == NODE_ID)
        .expect("registered node is discoverable");
    assert_eq!(record.region, REGION);
    assert!(record.capabilities.iter().any(|cap| cap == "waf"));

    let reputation = client
        .lookup(REPUTATION_IP.parse().unwrap())
        .await
        .expect("reputation lookup")
        .expect("seeded reputation entry");
    assert!(reputation.score > 0.9);
    assert_eq!(reputation.labels, vec!["scanner".to_string()]);
    assert!(client
        .lookup("203.0.113.250".parse().unwrap())
        .await
        .expect("unknown reputation lookup")
        .is_none());

    let event = SecurityEventRecord {
        event_id: "0192f0a0-0000-7000-8000-000000000001".to_string(),
        node_id: NODE_ID.to_string(),
        observed_at_unix_ms: 1_700_000_000_000,
        rule_ids: vec!["942100".to_string()],
        decision: EventDecision::Block,
        threat_level: EventThreatLevel::High,
        ip_hash: Some([0xab; 16]),
    };
    client.export(&[event]).await.expect("export event");
    wait_for_metric(
        server.metrics,
        "distri_waf_event_queue_depth",
        |depth| depth >= 1.0,
        "server to accept the security event",
    )
    .await;

    let delta = CounterDelta {
        policy_id: "e2e-policy".to_string(),
        window_start_unix: 1_700_000_000,
        shard: 1,
        key_hash: [7u8; 16],
        consumed: 42,
        rejected: 3,
        clock_offset_ms: 0,
    };
    client.flush(&[delta]).await.expect("flush counter delta");

    // The contract deduplicates counter batches by `batch_id`; prove the
    // server really applied the WAF predicate by replaying the batch id.
    let batch = CounterDeltas {
        contract_version: 1,
        node_id: NODE_ID.to_string(),
        epoch: 1,
        deltas: vec![ProtoCounterDelta {
            policy_id: "e2e-policy".to_string(),
            window_start_unix: 1_700_000_000,
            shard: 1,
            key_hash: vec![7u8; 16],
            consumed: 1,
            rejected: 0,
            clock_offset_ms: 0,
        }],
        batch_id: "e2e-batch-1".to_string(),
    };
    let first = raw
        .ingest_counter_deltas(authed(batch.clone(), &server.token))
        .await
        .expect("ingest counter delta")
        .into_inner();
    assert_eq!(first.accepted, 1);
    let replay = raw
        .ingest_counter_deltas(authed(batch, &server.token))
        .await
        .expect("replay counter delta")
        .into_inner();
    assert_eq!(replay.duplicate, 1);

    let lookup = raw
        .lookup_reputation(authed(
            LookupReputationRequest {
                contract_version: 1,
                ips: vec![REPUTATION_IP.to_string()],
                scope: SCOPE.to_string(),
                max_age_ms: 300_000,
            },
            &server.token,
        ))
        .await
        .expect("raw reputation lookup")
        .into_inner();
    assert_eq!(lookup.entries.len(), 1);

    let policy = client.current_policy().await;
    assert!(
        policy.is_err(),
        "no policy should be active before ActivatePolicy"
    );
}

// ---------------------------------------------------------------------------
// Policy generation invalidates the WAF cache
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a built distri-kv-server; run scripts/test-distri-e2e.sh"]
async fn policy_generation_change_invalidates_waf_cache() {
    let server = DkvServer::start(None).await;
    activate_policy(&server, 1).await;

    let config = server.config(DistributedFallbackMode::LocalOnly);
    let controller = DistributedController::from_config(&config).expect("build controller");
    let cache = Arc::clone(controller.policy_cache());
    let state = Arc::clone(controller.state());
    let handle = controller.spawn();

    wait_until(
        || async { state.connected() && state.policy_generation() == 1 && !cache.is_empty() },
        Duration::from_secs(20),
        "controller to apply generation 1",
    )
    .await;

    let client = DistriWafClient::new(&config).expect("build WAF client");
    let policy = client.current_policy().await.expect("fetch policy");
    assert_eq!(policy.generation, 1);
    assert_eq!(policy.ruleset_version, "e2e-v1");

    let invalidations_before = cache.metrics().cache_invalidations();
    activate_policy(&server, 2).await;

    wait_until(
        || async { state.policy_generation() == 2 && cache.generation() == 2 },
        Duration::from_secs(20),
        "controller to apply generation 2",
    )
    .await;
    assert!(
        cache.metrics().cache_invalidations() > invalidations_before,
        "generation change must invalidate the versioned cache"
    );

    let policy = client
        .current_policy()
        .await
        .expect("fetch generation 2 policy");
    assert_eq!(policy.generation, 2);
    assert_eq!(policy.ruleset_version, "e2e-v2");

    handle.shutdown().await;
}

// ---------------------------------------------------------------------------
// Real proxy process
// ---------------------------------------------------------------------------

struct WafProxy {
    child: Child,
    dir: tempfile::TempDir,
    addr: SocketAddr,
    metrics: SocketAddr,
}

impl WafProxy {
    fn start(upstream: SocketAddr, endpoint: &str, fallback: &str, token: &str) -> Self {
        assert!(
            std::path::Path::new(env!("CARGO_BIN_EXE_waf-ingress")).is_file(),
            "waf-ingress binary is missing"
        );
        let dir = tempfile::tempdir().expect("temp dir");
        let addr: SocketAddr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
        let metrics: SocketAddr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
        let config_path = dir.path().join("waf.toml");
        std::fs::write(
            &config_path,
            format!(
                r#"bind_addr = "{addr}"
health_bind_addr = "{metrics}"
upstream_uri = "http://{upstream}"

[waf]
enabled = true

[waf.coraza]
enabled = false

[waf.security_events]
enable_sled = false

[waf.distributed]
enabled = true
node_id = "{NODE_ID}"
region = "{REGION}"
policy_scope = "{SCOPE}"
endpoints = ["{endpoint}"]
auth_token = "{token}"
advertise_endpoint = "http://waf-e2e.invalid:9443"
fallback = "{fallback}"
heartbeat_interval_secs = 1
request_timeout_ms = 1000
policy_cache_ttl_secs = 300
reputation_cache_ttl_secs = 300
max_stale_secs = 900
reconnect_initial_backoff_ms = 100
reconnect_max_backoff_ms = 500
shadow = false
"#,
            ),
        )
        .expect("write WAF config");

        let log = std::fs::File::create(dir.path().join("waf.log")).expect("create log");
        let child = Command::new(env!("CARGO_BIN_EXE_waf-ingress"))
            .env("WAF_CONFIG_FILE", &config_path)
            .env("RUST_LOG", "info")
            .stdout(Stdio::from(log.try_clone().expect("clone log")))
            .stderr(Stdio::from(log))
            .spawn()
            .expect("start waf-ingress");

        wait_bounded(
            || {
                std::net::TcpStream::connect(addr).is_ok()
                    && std::net::TcpStream::connect(metrics).is_ok()
            },
            Duration::from_secs(30),
            "waf-ingress listeners",
        );

        Self {
            child,
            dir,
            addr,
            metrics,
        }
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("waf.log")).unwrap_or_default()
    }
}

impl Drop for WafProxy {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

async fn start_upstream() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream");
    let addr = listener.local_addr().expect("upstream addr");
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buffer = [0u8; 1024];
                let _ = stream.read(&mut buffer).await;
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .await;
            });
        }
    });
    (addr, handle)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a built distri-kv-server; run scripts/test-distri-e2e.sh"]
async fn proxy_registers_and_applies_policy_generations() {
    let server = DkvServer::start(None).await;
    activate_policy(&server, 1).await;
    let (upstream, upstream_task) = start_upstream().await;

    let proxy = WafProxy::start(upstream, &server.endpoint(), "local_only", &server.token);

    wait_for_metric(
        proxy.metrics,
        "waf_distributed_connected",
        |value| value == 1.0,
        "proxy to connect to distri-kv",
    )
    .await;
    wait_for_metric(
        proxy.metrics,
        "waf_distributed_policy_generation",
        |value| value == 1.0,
        "proxy to apply generation 1",
    )
    .await;
    wait_for_metric(
        server.metrics,
        "distri_waf_connected_nodes",
        |value| value >= 1.0,
        "cluster to observe the registered WAF node",
    )
    .await;

    let response = http_get(proxy.addr, "/health?id=42").await;
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "proxy returned: {response}\nproxy log:\n{}",
        proxy.log()
    );

    activate_policy(&server, 2).await;
    wait_for_metric(
        proxy.metrics,
        "waf_distributed_policy_generation",
        |value| value == 2.0,
        "proxy to apply generation 2",
    )
    .await;

    let response = http_get(proxy.addr, "/still-serving").await;
    assert!(response.starts_with("HTTP/1.1 200"));
    assert!(response.ends_with("ok"));

    upstream_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a built distri-kv-server; run scripts/test-distri-e2e.sh"]
async fn local_only_keeps_serving_while_cluster_is_down() {
    // Reserve and release a port so the endpoint is definitely closed.
    let dead_port = free_port();
    let endpoint = format!("http://127.0.0.1:{dead_port}");
    let (upstream, upstream_task) = start_upstream().await;

    let proxy = WafProxy::start(upstream, &endpoint, "local_only", "");
    wait_for_metric(
        proxy.metrics,
        "waf_distributed_fallback_activations_total",
        |value| value >= 1.0,
        "local_only fallback activation",
    )
    .await;
    let metrics = http_get(proxy.metrics, "/metrics").await;
    assert_eq!(
        metric_value(&metrics, "waf_distributed_connected"),
        Some(0.0)
    );

    let response = http_get(proxy.addr, "/during-outage").await;
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "local_only must keep serving: {response}\nproxy log:\n{}",
        proxy.log()
    );

    upstream_task.abort();
}

// ---------------------------------------------------------------------------
// Focused fallback semantics (no cluster required)
// ---------------------------------------------------------------------------

#[test]
fn fallback_modes_are_explicit() {
    let cases = [
        (
            DistributedFallbackMode::LocalOnly,
            UnavailableDecision::LocalOnly,
            false,
            false,
        ),
        (
            DistributedFallbackMode::FailOpen,
            UnavailableDecision::Allow,
            false,
            true,
        ),
        (
            DistributedFallbackMode::FailClosed,
            UnavailableDecision::Block,
            true,
            false,
        ),
    ];
    for (fallback, expected, blocks, allows) in cases {
        let config = DistributedConfig {
            enabled: true,
            node_id: NODE_ID.to_string(),
            region: REGION.to_string(),
            endpoints: vec!["http://127.0.0.1:1".to_string()],
            fallback,
            ..DistributedConfig::default()
        };
        config.validate().expect("valid distributed config");
        let state = DistributedState::from_config(&config);
        assert_eq!(state.unavailable_decision(), expected);
        assert_eq!(state.should_block_without_cluster(), blocks);
        assert_eq!(state.allows_without_cluster(), allows);
    }
}
