//! Native Go Coraza sidecar backend (experimental, non-default).
//!
//! This module talks to `native/coraza-sidecar` over a Unix domain socket. It
//! is enabled with the `coraza-native` feature and selected with
//! `waf.coraza.backend = "native"`. The wire envelope is the same JSON payload
//! used by [`crate::waf::wasm_reactor`], framed with a 4-byte big-endian length
//! prefix in each direction.
//!
//! The sync [`WafRule`] trait cannot `.await`, so requests are handed to a
//! dedicated Tokio runtime thread. That keeps all I/O off the proxy's async
//! workers and gives connection pooling, reconnect and timeouts without
//! blocking a shared runtime.

use std::path::{Path, PathBuf};
use std::sync::mpsc as std_mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::{mpsc, Mutex, Semaphore};
use tracing::{info, warn};

use crate::metrics::Metrics;
use crate::waf::coraza_payload::{build_payload_with_policy, BodyInspectionPolicy, PayloadBuild};
use crate::waf::{Decision, RequestContext, WafRule};

/// Maximum response frame the client will accept from the sidecar.
const MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// Default number of concurrent sidecar connections when config says `0`.
const DEFAULT_POOL_SIZE: usize = 8;

/// How long to wait for a Unix socket connect outside the evaluation budget.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

/// Extra time the sync caller waits for the runtime thread, on top of the
/// async evaluation timeout, so the async path reports the real error first.
const REPLY_MARGIN: Duration = Duration::from_secs(1);

/// Errors returned by the native backend.
#[derive(Debug, thiserror::Error)]
pub enum NativeCorazaError {
    /// The configured socket could not be reached.
    #[error("native Coraza sidecar socket `{path}` is unavailable: {detail}")]
    Unavailable { path: String, detail: String },
    /// The sidecar did not answer within the configured budget.
    #[error("native Coraza sidecar request exceeded the configured timeout")]
    Timeout,
    /// The bounded request queue is full.
    #[error("native Coraza sidecar request queue is full")]
    QueueFull,
    /// The payload exceeds the configured limit.
    #[error("request payload of {size} bytes exceeds the {limit} byte limit")]
    PayloadTooLarge { size: usize, limit: usize },
    /// Framing or socket I/O failed.
    #[error("native Coraza sidecar I/O failed: {0}")]
    Io(String),
    /// The sidecar returned a malformed or oversized response.
    #[error("native Coraza sidecar protocol error: {0}")]
    Protocol(String),
    /// The sidecar returned a decision the client does not understand.
    #[error("native Coraza sidecar returned unknown decision `{0}`")]
    UnknownDecision(String),
    /// The background runtime could not be started or has stopped.
    #[error("native Coraza sidecar client is not running: {0}")]
    Client(String),
}

#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub socket_path: PathBuf,
    pub pool_size: usize,
    pub timeout: Duration,
    pub max_payload_bytes: usize,
}

impl From<&crate::config::WafCorazaConfig> for ClientConfig {
    fn from(config: &crate::config::WafCorazaConfig) -> Self {
        Self {
            socket_path: PathBuf::from(
                config
                    .native_socket_path
                    .clone()
                    .unwrap_or_else(|| "/run/waf/coraza.sock".to_string()),
            ),
            pool_size: if config.pool_size == 0 {
                DEFAULT_POOL_SIZE
            } else {
                config.pool_size
            },
            timeout: Duration::from_millis(config.eval_timeout_ms),
            max_payload_bytes: config.max_payload_bytes,
        }
    }
}

#[derive(Debug, Deserialize)]
struct SidecarResponse {
    decision: String,
    #[serde(default)]
    status: Option<u16>,
    #[serde(default)]
    reason: Option<String>,
}

struct Job {
    payload: Vec<u8>,
    reply: std_mpsc::Sender<Result<SidecarResponse, NativeCorazaError>>,
}

struct ConnectionPool {
    pub socket_path: PathBuf,
    pub timeout: Duration,
    semaphore: Semaphore,
    idle: Mutex<Vec<UnixStream>>,
}

impl ConnectionPool {
    fn new(config: &ClientConfig) -> Self {
        Self {
            socket_path: config.socket_path.clone(),
            timeout: config.timeout,
            semaphore: Semaphore::new(config.pool_size.max(1)),
            idle: Mutex::new(Vec::new()),
        }
    }

    async fn take_idle(&self) -> Option<UnixStream> {
        self.idle.lock().await.pop()
    }

    async fn release(&self, conn: UnixStream) {
        self.idle.lock().await.push(conn);
    }

    async fn connect(&self) -> Result<UnixStream, NativeCorazaError> {
        match tokio::time::timeout(CONNECT_TIMEOUT, UnixStream::connect(&self.socket_path)).await {
            Ok(Ok(stream)) => Ok(stream),
            Ok(Err(err)) => Err(NativeCorazaError::Unavailable {
                path: self.socket_path.display().to_string(),
                detail: err.to_string(),
            }),
            Err(_) => Err(NativeCorazaError::Timeout),
        }
    }

    async fn evaluate(&self, payload: &[u8]) -> Result<SidecarResponse, NativeCorazaError> {
        let _permit = self
            .semaphore
            .acquire()
            .await
            .map_err(|_| NativeCorazaError::Client("connection pool closed".to_string()))?;

        let mut last_error = None;
        // One retry with a fresh connection covers a sidecar restart and a
        // pooled connection that was closed while idle.
        for attempt in 0..2 {
            let mut conn = if attempt == 0 {
                match self.take_idle().await {
                    Some(conn) => conn,
                    None => self.connect_bounded().await?,
                }
            } else {
                self.connect_bounded().await?
            };

            // The deadline is enforced here, at the client, because Coraza has
            // no cancellation API. On expiry the connection is dropped rather
            // than returned to the pool, which closes the socket and lets the
            // sidecar's per-connection goroutine exit as soon as its current
            // evaluation finishes. The sidecar must still bound its own work.
            match tokio::time::timeout(self.timeout, round_trip(&mut conn, payload)).await {
                Ok(Ok(response)) => {
                    self.release(conn).await;
                    return Ok(response);
                }
                Ok(Err(err)) => {
                    last_error = Some(err);
                }
                Err(_) => return Err(NativeCorazaError::Timeout),
            }
        }
        Err(last_error.unwrap_or_else(|| NativeCorazaError::Io("no attempt made".to_string())))
    }

    async fn connect_bounded(&self) -> Result<UnixStream, NativeCorazaError> {
        match tokio::time::timeout(self.timeout, self.connect()).await {
            Ok(result) => result,
            Err(_) => Err(NativeCorazaError::Timeout),
        }
    }
}

async fn round_trip(
    conn: &mut UnixStream,
    payload: &[u8],
) -> Result<SidecarResponse, NativeCorazaError> {
    let len = u32::try_from(payload.len())
        .map_err(|_| NativeCorazaError::Protocol("payload too large to frame".to_string()))?;
    conn.write_all(&len.to_be_bytes()).await.map_err(io_error)?;
    conn.write_all(payload).await.map_err(io_error)?;
    conn.flush().await.map_err(io_error)?;

    let mut header = [0u8; 4];
    conn.read_exact(&mut header).await.map_err(io_error)?;
    let response_len = u32::from_be_bytes(header) as usize;
    if response_len == 0 || response_len > MAX_RESPONSE_BYTES {
        return Err(NativeCorazaError::Protocol(format!(
            "response frame of {response_len} bytes is invalid"
        )));
    }
    let mut body = vec![0u8; response_len];
    conn.read_exact(&mut body).await.map_err(io_error)?;
    serde_json::from_slice(&body)
        .map_err(|err| NativeCorazaError::Protocol(format!("invalid response JSON: {err}")))
}

fn io_error(err: std::io::Error) -> NativeCorazaError {
    NativeCorazaError::Io(err.to_string())
}

fn response_to_decision(resp: SidecarResponse) -> Result<Decision, NativeCorazaError> {
    match resp.decision.as_str() {
        "allow" => Ok(Decision::Allow),
        "block" => Ok(Decision::Block {
            status: resp.status.filter(|s| *s != 0).unwrap_or(403),
            reason: resp
                .reason
                .filter(|r| !r.is_empty())
                .unwrap_or_else(|| "request blocked by native Coraza".to_string()),
        }),
        other => Err(NativeCorazaError::UnknownDecision(other.to_string())),
    }
}

/// A pooled, async Unix-socket client driven by a dedicated runtime thread.
pub struct NativeCorazaClient {
    tx: mpsc::Sender<Job>,
    pub timeout: Duration,
    pub max_payload_bytes: usize,
    _thread: std::thread::JoinHandle<()>,
}

impl NativeCorazaClient {
    /// Creates a client and verifies that the sidecar socket accepts
    /// connections. This is the start-up check: a missing sidecar is reported
    /// immediately rather than surfacing as per-request 503s.
    pub fn new(config: &ClientConfig) -> Result<Self, NativeCorazaError> {
        preflight(&config.socket_path)?;

        let queue_capacity = config.pool_size.saturating_mul(2).max(8);
        let (tx, mut rx) = mpsc::channel::<Job>(queue_capacity);
        let thread_config = config.clone();
        let thread = std::thread::Builder::new()
            .name("coraza-native-client".to_string())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(err) => {
                        warn!(error = %err, "failed to start native Coraza client runtime");
                        return;
                    }
                };
                runtime.block_on(async move {
                    let pool = Arc::new(ConnectionPool::new(&thread_config));
                    while let Some(job) = rx.recv().await {
                        let pool = Arc::clone(&pool);
                        tokio::spawn(async move {
                            let result = tokio::time::timeout(
                                thread_config.timeout,
                                pool.evaluate(&job.payload),
                            )
                            .await
                            .unwrap_or(Err(NativeCorazaError::Timeout));
                            let _ = job.reply.send(result);
                        });
                    }
                });
            })
            .map_err(|err| NativeCorazaError::Client(err.to_string()))?;

        info!(
            socket = %config.socket_path.display(),
            pool_size = config.pool_size,
            timeout_ms = config.timeout.as_millis(),
            "Coraza native sidecar client ready"
        );
        Ok(Self {
            tx,
            timeout: config.timeout,
            max_payload_bytes: config.max_payload_bytes,
            _thread: thread,
        })
    }

    /// Sends one payload and waits for the decision. Called only from the sync
    /// rule; the actual I/O runs on the dedicated runtime thread.
    pub fn evaluate(&self, payload: &[u8]) -> Result<Decision, NativeCorazaError> {
        if payload.len() > self.max_payload_bytes {
            return Err(NativeCorazaError::PayloadTooLarge {
                size: payload.len(),
                limit: self.max_payload_bytes,
            });
        }
        let (reply_tx, reply_rx) = std_mpsc::channel();
        self.tx
            .try_send(Job {
                payload: payload.to_vec(),
                reply: reply_tx,
            })
            .map_err(|err| match err {
                mpsc::error::TrySendError::Full(_) => NativeCorazaError::QueueFull,
                mpsc::error::TrySendError::Closed(_) => {
                    NativeCorazaError::Client("runtime thread stopped".to_string())
                }
            })?;

        match reply_rx.recv_timeout(self.timeout + REPLY_MARGIN) {
            Ok(result) => result.and_then(response_to_decision),
            Err(std_mpsc::RecvTimeoutError::Timeout) => Err(NativeCorazaError::Timeout),
            Err(std_mpsc::RecvTimeoutError::Disconnected) => Err(NativeCorazaError::Client(
                "runtime thread stopped".to_string(),
            )),
        }
    }
}

fn preflight(path: &Path) -> Result<(), NativeCorazaError> {
    std::os::unix::net::UnixStream::connect(path)
        .map(|_| ())
        .map_err(|err| NativeCorazaError::Unavailable {
            path: path.display().to_string(),
            detail: err.to_string(),
        })
}

/// A [`WafRule`] backed by the native Go sidecar.
///
/// Semantics mirror [`crate::waf::wasm_reactor::WasmReactorRule`]: the rule is
/// registered explicitly, blocks with the sidecar's status/reason, and fails
/// closed with `503` when evaluation cannot be completed.
pub struct NativeCorazaRule {
    name: String,
    client: NativeCorazaClient,
    metrics: Option<Arc<Metrics>>,
    fail_closed: bool,
    body_policy: BodyInspectionPolicy,
}

impl NativeCorazaRule {
    /// Creates a rule from a running sidecar client.
    pub fn new(name: impl Into<String>, client: NativeCorazaClient) -> Self {
        Self {
            name: name.into(),
            client,
            metrics: None,
            fail_closed: true,
            body_policy: BodyInspectionPolicy::default(),
        }
    }

    /// Attaches process metrics so sidecar evaluations are observable.
    pub fn with_metrics(mut self, metrics: Arc<Metrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Applies an explicit body-size inspection policy.
    pub fn with_body_policy(mut self, policy: BodyInspectionPolicy) -> Self {
        self.body_policy = policy;
        self
    }

    /// Sets the failure policy. `true` maps failures to `503`.
    pub fn with_fail_closed(mut self, fail_closed: bool) -> Self {
        self.fail_closed = fail_closed;
        self
    }

    /// Builds a rule from `waf.coraza` configuration, verifying the socket.
    pub fn from_config(
        config: &crate::config::WafCorazaConfig,
        fail_closed: bool,
    ) -> Result<Self, NativeCorazaError> {
        let client = NativeCorazaClient::new(&ClientConfig::from(config))?;
        Ok(Self::new("coraza-native-sidecar", client)
            .with_fail_closed(fail_closed)
            .with_body_policy(BodyInspectionPolicy::from(config)))
    }

    fn failure_decision(&self, reason: String) -> Decision {
        if self.fail_closed {
            Decision::Block {
                status: 503,
                reason: format!("native Coraza sidecar failure: {reason}"),
            }
        } else {
            warn!(
                rule = %self.name,
                reason = %reason,
                "native Coraza sidecar failed; continuing because fail_mode is open"
            );
            Decision::Allow
        }
    }
}

impl WafRule for NativeCorazaRule {
    fn name(&self) -> &str {
        &self.name
    }

    fn evaluate(&self, ctx: &RequestContext) -> Decision {
        let started = Instant::now();
        let (payload, inspected_bytes, truncated) = match build_payload_with_policy(
            ctx,
            &self.body_policy,
        ) {
            Ok(PayloadBuild::Built {
                payload,
                inspected_bytes,
                truncated,
            }) => (payload, inspected_bytes, truncated),
            Ok(PayloadBuild::Reject { size, limit }) => {
                if let Some(metrics) = &self.metrics {
                    metrics.record_coraza_body_rejected();
                }
                return Decision::Block {
                        status: 413,
                        reason: format!(
                            "request body of {size} bytes exceeds the {limit} byte Coraza inspection limit"
                        ),
                    };
            }
            Err(err) => {
                warn!(rule = %self.name, error = %err, "failed to encode native Coraza payload");
                if let Some(metrics) = &self.metrics {
                    metrics.record_coraza_evaluation(started.elapsed());
                    metrics.record_coraza_error();
                }
                return self.failure_decision(err.to_string());
            }
        };

        if let Some(metrics) = &self.metrics {
            metrics.record_coraza_body_inspected_bytes(inspected_bytes);
            if truncated {
                metrics.record_coraza_body_truncated();
            }
        }

        let result = self.client.evaluate(&payload);
        if let Some(metrics) = &self.metrics {
            metrics.record_coraza_evaluation(started.elapsed());
        }

        match result {
            Ok(Decision::Allow) => Decision::Allow,
            Ok(decision @ Decision::Block { .. }) => {
                if let Some(metrics) = &self.metrics {
                    metrics.record_coraza_block();
                }
                decision
            }
            Ok(other) => {
                warn!(rule = %self.name, ?other, "native sidecar returned unexpected decision");
                if let Some(metrics) = &self.metrics {
                    metrics.record_coraza_error();
                }
                self.failure_decision("unexpected decision variant".to_string())
            }
            Err(err) => {
                warn!(rule = %self.name, error = %err, "native Coraza sidecar evaluation failed");
                if let Some(metrics) = &self.metrics {
                    metrics.record_coraza_error();
                }
                self.failure_decision(err.to_string())
            }
        }
    }
}

/// Returns true when the given socket path currently accepts connections.
pub fn socket_available(path: &Path) -> bool {
    preflight(path).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use hyper::{HeaderMap, Method, Uri};
    use std::io::{Read as _, Write as _};
    use std::net::IpAddr;
    use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

    static SOCKET_SEQ: AtomicU64 = AtomicU64::new(0);

    struct TestSidecar {
        path: PathBuf,
        stop: Arc<AtomicU32>,
        handle: Option<std::thread::JoinHandle<()>>,
    }

    impl TestSidecar {
        fn start(mode: &'static str) -> Self {
            let seq = SOCKET_SEQ.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "coraza-native-test-{}-{seq}.sock",
                std::process::id()
            ));
            let _ = std::fs::remove_file(&path);
            let listener = std::os::unix::net::UnixListener::bind(&path).expect("bind test socket");
            let stop = Arc::new(AtomicU32::new(0));
            let stop_thread = Arc::clone(&stop);
            let handle = std::thread::spawn(move || {
                for stream in listener.incoming() {
                    if stop_thread.load(Ordering::Relaxed) != 0 {
                        break;
                    }
                    let Ok(mut stream) = stream else { break };
                    std::thread::spawn(move || serve_test_connection(&mut stream, mode));
                }
            });
            Self {
                path,
                stop,
                handle: Some(handle),
            }
        }
    }

    impl Drop for TestSidecar {
        fn drop(&mut self) {
            self.stop.store(1, Ordering::Relaxed);
            // Wake the accept loop.
            let _ = std::os::unix::net::UnixStream::connect(&self.path);
            if let Some(handle) = self.handle.take() {
                let _ = handle.join();
            }
            let _ = std::fs::remove_file(&self.path);
        }
    }

    fn serve_test_connection(stream: &mut std::os::unix::net::UnixStream, mode: &str) {
        loop {
            let mut header = [0u8; 4];
            if stream.read_exact(&mut header).is_err() {
                return;
            }
            let len = u32::from_be_bytes(header) as usize;
            let mut payload = vec![0u8; len];
            if stream.read_exact(&mut payload).is_err() {
                return;
            }
            if mode == "close" {
                return;
            }
            if mode == "timeout" {
                std::thread::sleep(Duration::from_millis(500));
            }
            let body = if mode == "malformed" {
                b"not json".to_vec()
            } else if let Ok(req) = serde_json::from_slice::<serde_json::Value>(&payload) {
                let uri = req["uri"].as_str().unwrap_or("/");
                if uri.contains("attack") {
                    br#"{"decision":"block","status":403,"reason":"test block"}"#.to_vec()
                } else {
                    br#"{"decision":"allow"}"#.to_vec()
                }
            } else {
                br#"{"decision":"block","status":400,"reason":"malformed"}"#.to_vec()
            };
            let mut out = Vec::with_capacity(4 + body.len());
            out.extend_from_slice(&(body.len() as u32).to_be_bytes());
            out.extend_from_slice(&body);
            if stream.write_all(&out).is_err() {
                return;
            }
        }
    }

    fn context(uri: &str, body: Option<&[u8]>) -> RequestContext {
        let mut headers = HeaderMap::new();
        headers.insert("host", "example.test".parse().unwrap());
        RequestContext::new(
            "127.0.0.1".parse::<IpAddr>().unwrap(),
            Method::POST,
            uri.parse::<Uri>().unwrap(),
            headers,
            body.map(<[u8]>::len),
        )
        .with_body(body.map(|b| Bytes::copy_from_slice(b)))
    }

    fn client(path: &Path, timeout: Duration) -> NativeCorazaClient {
        NativeCorazaClient::new(&ClientConfig {
            socket_path: path.to_path_buf(),
            pool_size: 2,
            timeout,
            max_payload_bytes: 64 * 1024,
        })
        .expect("client must start against test sidecar")
    }

    #[test]
    fn allows_benign_and_blocks_attack() {
        let sidecar = TestSidecar::start("ok");
        let client = client(&sidecar.path, Duration::from_secs(2));
        assert_eq!(
            client
                .evaluate(&build_payload(&context("/hello", Some(b"a=b"))).unwrap())
                .unwrap(),
            Decision::Allow
        );
        match client
            .evaluate(&build_payload(&context("/attack", Some(b"x=1"))).unwrap())
            .unwrap()
        {
            Decision::Block { status, reason } => {
                assert_eq!(status, 403);
                assert_eq!(reason, "test block");
            }
            other => panic!("expected block, got {other:?}"),
        }
    }

    #[test]
    fn malformed_response_fails_closed() {
        let sidecar = TestSidecar::start("malformed");
        let client = client(&sidecar.path, Duration::from_secs(2));
        let err = client
            .evaluate(&build_payload(&context("/hello", None)).unwrap())
            .unwrap_err();
        assert!(matches!(err, NativeCorazaError::Protocol(_)), "{err}");
    }

    #[test]
    fn timeout_is_reported() {
        let sidecar = TestSidecar::start("timeout");
        let client = client(&sidecar.path, Duration::from_millis(80));
        let err = client
            .evaluate(&build_payload(&context("/hello", None)).unwrap())
            .unwrap_err();
        assert!(matches!(err, NativeCorazaError::Timeout), "{err}");
    }

    #[test]
    fn reconnects_after_sidecar_closes_connection() {
        let sidecar = TestSidecar::start("close");
        let client = client(&sidecar.path, Duration::from_secs(2));
        // First call uses the preflight/initial connection, which the test
        // server closes. The retry must establish a fresh connection.
        let err = client
            .evaluate(&build_payload(&context("/hello", None)).unwrap())
            .unwrap_err();
        assert!(matches!(err, NativeCorazaError::Io(_)), "{err}");
    }

    #[test]
    fn missing_socket_is_a_startup_error() {
        let path = std::env::temp_dir().join("coraza-native-missing.sock");
        let _ = std::fs::remove_file(&path);
        let err = NativeCorazaClient::new(&ClientConfig {
            socket_path: path,
            pool_size: 1,
            timeout: Duration::from_millis(100),
            max_payload_bytes: 1024,
        })
        .err()
        .expect("missing socket must fail");
        assert!(
            matches!(err, NativeCorazaError::Unavailable { .. }),
            "{err}"
        );
    }

    #[test]
    fn payload_limit_is_enforced() {
        let sidecar = TestSidecar::start("ok");
        let client = NativeCorazaClient::new(&ClientConfig {
            socket_path: sidecar.path.clone(),
            pool_size: 1,
            timeout: Duration::from_secs(1),
            max_payload_bytes: 8,
        })
        .unwrap();
        let err = client.evaluate(b"0123456789").unwrap_err();
        assert!(matches!(err, NativeCorazaError::PayloadTooLarge { .. }));
    }

    #[test]
    fn timeout_closes_the_connection() {
        let seq = SOCKET_SEQ.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "coraza-native-timeout-{}-{seq}.sock",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let (tx, rx) = std_mpsc::channel();
        let handle = std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let mut header = [0u8; 4];
                // The preflight connection sends no frame and closes.
                if stream.read_exact(&mut header).is_err() {
                    continue;
                }
                let len = u32::from_be_bytes(header) as usize;
                let mut payload = vec![0u8; len];
                if stream.read_exact(&mut payload).is_err() {
                    continue;
                }
                tx.send(true).unwrap();
                // The client deadline must drop the connection, so this read
                // observes EOF instead of blocking forever.
                let mut byte = [0u8; 1];
                let closed = matches!(stream.read(&mut byte), Ok(0));
                tx.send(closed).unwrap();
                return;
            }
        });

        let client = client(&path, Duration::from_millis(50));
        let err = client.evaluate(b"{}").unwrap_err();
        assert!(matches!(err, NativeCorazaError::Timeout), "{err}");
        rx.recv_timeout(Duration::from_secs(2))
            .expect("sidecar should receive the request");
        assert!(
            rx.recv_timeout(Duration::from_secs(2))
                .expect("sidecar should observe the closed connection"),
            "client timeout must close the socket"
        );
        handle.join().unwrap();
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn native_rule_records_coraza_metrics() {
        let sidecar = TestSidecar::start("ok");
        let metrics = Arc::new(Metrics::new());
        let rule = NativeCorazaRule::new(
            "coraza-native-sidecar",
            client(&sidecar.path, Duration::from_secs(2)),
        )
        .with_metrics(Arc::clone(&metrics));

        assert_eq!(
            rule.evaluate(&context("/hello", Some(b"a=b"))),
            Decision::Allow
        );
        assert!(matches!(
            rule.evaluate(&context("/attack", Some(b"x=1"))),
            Decision::Block { status: 403, .. }
        ));

        let rendered = metrics.render_prometheus();
        assert!(rendered.contains("waf_coraza_evaluations_total 2"));
        assert!(rendered.contains("waf_coraza_blocks_total 1"));
        assert!(rendered.contains("waf_coraza_errors_total 0"));
        assert!(rendered.contains("waf_coraza_evaluation_duration_seconds_count 2"));

        let malformed = TestSidecar::start("malformed");
        let error_metrics = Arc::new(Metrics::new());
        let error_rule = NativeCorazaRule::new(
            "coraza-native-sidecar",
            client(&malformed.path, Duration::from_secs(2)),
        )
        .with_metrics(Arc::clone(&error_metrics));
        assert!(matches!(
            error_rule.evaluate(&context("/hello", None)),
            Decision::Block { status: 503, .. }
        ));
        let rendered = error_metrics.render_prometheus();
        assert!(rendered.contains("waf_coraza_evaluations_total 1"));
        assert!(rendered.contains("waf_coraza_errors_total 1"));
    }
}
