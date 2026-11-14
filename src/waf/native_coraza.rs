//! Native Go Coraza sidecar backend (experimental, non-default).
//!
//! This module talks to `native/coraza-sidecar` over a Unix domain socket. It
//! is enabled with the `coraza-native` feature and selected with
//! `waf.coraza.backend = "native"`.
//!
//! Two wire encodings are supported on the same framing:
//!
//! * **binary v1** ([`crate::waf::coraza_wire`]) — length-prefixed fixed
//!   header, request line and headers, then the raw body bytes. No JSON
//!   escaping, no base64, one `writev` per request and a reused response
//!   buffer.
//! * **legacy JSON** — the envelope shared with the WASI reactor, kept for
//!   compatibility with sidecars that predate binary v1.
//!
//! A new client sends a handshake frame when it opens a connection. A sidecar
//! that understands binary v1 answers with an ack; a legacy sidecar answers
//! with a JSON `400` block, which the client reads as "use JSON on this
//! connection". The decision is remembered for the process lifetime, so the
//! handshake costs one round trip per connection at start-up and nothing after
//! that.
//!
//! The sync [`WafRule`] trait cannot `.await`, so evaluations use a bounded
//! pool of blocking connections: a caller checks a connection out, writes the
//! request, reads the decision and returns it. Socket send/receive timeouts
//! plus a post-read deadline check enforce `eval_timeout_ms`; a connection that
//! times out or errors is dropped instead of reused. This is the same
//! fail-closed contract as before, without a dedicated runtime thread, a job
//! channel or a task spawn per request.

use std::io::{self, IoSlice, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use serde::Deserialize;
use tracing::{info, warn};

#[cfg(feature = "crs-prefilter")]
use tracing::debug;

#[cfg(feature = "crs-prefilter")]
use crate::waf::prefilter::{Prefilter, PrefilterError, PrefilterMode};

use crate::metrics::Metrics;
use crate::waf::coraza_payload::BodyInspectionPolicy;
use crate::waf::coraza_wire::{
    decode_handshake, decode_handshake_capabilities, decode_response, encode_request_with_rules,
    handshake_frame, BinaryRequest, WireBuild, CAP_REMOVE_RULES, DECISION_ALLOW,
    FRAME_MAGIC_BINARY, WIRE_VERSION,
};
use crate::waf::{Decision, RequestContext, WafRule};

/// Maximum response frame the client will accept from the sidecar.
const MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// Default number of pooled sidecar connections when config says `0`.
const DEFAULT_POOL_SIZE: usize = 8;

/// Negotiation state shared by the pool.
const NEGOTIATION_UNKNOWN: u8 = 0;
const NEGOTIATION_BINARY: u8 = 1;
const NEGOTIATION_JSON: u8 = 2;

/// Errors returned by the native backend.
#[derive(Debug, thiserror::Error)]
pub enum NativeCorazaError {
    /// The configured socket could not be reached.
    #[error("native Coraza sidecar socket `{path}` is unavailable: {detail}")]
    Unavailable { path: String, detail: String },
    /// The sidecar did not answer within the configured budget.
    #[error("native Coraza sidecar request exceeded the configured timeout")]
    Timeout,
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
    /// The experimental CRS prefilter artifact could not be loaded.
    #[cfg(feature = "crs-prefilter")]
    #[error("CRS prefilter: {0}")]
    Prefilter(String),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WireProtocol {
    Binary,
    Json,
}

struct Conn {
    stream: UnixStream,
    /// Socket send/receive timeout set at connect time.
    timeout: Duration,
    read_buf: Vec<u8>,
}

struct PoolState {
    idle: Vec<Conn>,
    /// Connections that are open or being opened (idle + checked out).
    open: usize,
}

/// Bounded pool of blocking sidecar connections.
///
/// `pool_size` is the maximum number of simultaneous evaluations; a caller that
/// finds the pool exhausted waits on the condvar until a connection is
/// returned or its deadline expires.
struct Pool {
    socket_path: PathBuf,
    timeout: Duration,
    max: usize,
    negotiated: AtomicU8,
    /// True when the sidecar advertised [`CAP_REMOVE_RULES`].
    remove_rules: AtomicBool,
    state: Mutex<PoolState>,
    available: Condvar,
}

impl Pool {
    fn new(config: &ClientConfig) -> Self {
        Self {
            socket_path: config.socket_path.clone(),
            timeout: config.timeout,
            max: config.pool_size.max(1),
            negotiated: AtomicU8::new(NEGOTIATION_UNKNOWN),
            remove_rules: AtomicBool::new(false),
            state: Mutex::new(PoolState {
                idle: Vec::new(),
                open: 0,
            }),
            available: Condvar::new(),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, PoolState> {
        // A panic in a request must not poison the pool: the state is a plain
        // counter plus a list of connections.
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn acquire(&self, deadline: Instant) -> Result<Conn, NativeCorazaError> {
        let mut state = self.lock();
        loop {
            if let Some(conn) = state.idle.pop() {
                return Ok(conn);
            }
            if state.open < self.max {
                state.open += 1;
                drop(state);
                return match self.connect() {
                    Ok(conn) => Ok(conn),
                    Err(err) => {
                        let mut state = self.lock();
                        state.open -= 1;
                        self.available.notify_one();
                        Err(err)
                    }
                };
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(NativeCorazaError::Timeout);
            }
            let (guard, _) = self
                .available
                .wait_timeout(state, deadline - now)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state = guard;
        }
    }

    fn release(&self, conn: Conn) {
        let mut state = self.lock();
        state.idle.push(conn);
        drop(state);
        self.available.notify_one();
    }

    /// Drops a connection whose stream state is unknown (error or timeout).
    fn discard(&self) {
        let mut state = self.lock();
        state.open = state.open.saturating_sub(1);
        drop(state);
        self.available.notify_one();
    }

    fn connect(&self) -> Result<Conn, NativeCorazaError> {
        let stream = UnixStream::connect(&self.socket_path).map_err(|err| {
            NativeCorazaError::Unavailable {
                path: self.socket_path.display().to_string(),
                detail: err.to_string(),
            }
        })?;
        stream
            .set_write_timeout(Some(self.timeout))
            .map_err(io_error)?;
        stream
            .set_read_timeout(Some(self.timeout))
            .map_err(io_error)?;
        let mut conn = Conn {
            stream,
            timeout: self.timeout,
            read_buf: Vec::new(),
        };
        match self.negotiated.load(Ordering::Relaxed) {
            NEGOTIATION_BINARY | NEGOTIATION_JSON => {}
            _ => match conn.negotiate() {
                Ok((protocol, capabilities)) => {
                    self.negotiated.store(
                        if protocol == WireProtocol::Binary {
                            NEGOTIATION_BINARY
                        } else {
                            NEGOTIATION_JSON
                        },
                        Ordering::Relaxed,
                    );
                    self.remove_rules
                        .store(capabilities & CAP_REMOVE_RULES != 0, Ordering::Relaxed);
                }
                Err(err) => {
                    // A legacy sidecar answers the handshake with a JSON block
                    // or closes the connection. Either way, fall back to JSON
                    // for every future connection; the connection itself is
                    // kept because the failure may have been the handshake
                    // only.
                    info!(
                        error = %err,
                        "native Coraza sidecar did not negotiate the binary protocol; using JSON"
                    );
                    self.negotiated.store(NEGOTIATION_JSON, Ordering::Relaxed);
                }
            },
        }
        Ok(conn)
    }

    /// Opens one connection so the negotiated protocol is known before the
    /// first evaluation.
    fn warm(&self, deadline: Instant) -> Result<(), NativeCorazaError> {
        let conn = self.acquire(deadline)?;
        self.release(conn);
        Ok(())
    }

    fn uses_binary(&self) -> bool {
        self.negotiated.load(Ordering::Relaxed) == NEGOTIATION_BINARY
    }

    fn supports_remove_rules(&self) -> bool {
        self.uses_binary() && self.remove_rules.load(Ordering::Relaxed)
    }
}

impl Conn {
    /// Sends the handshake frame and reads the ack.
    fn negotiate(&mut self) -> Result<(WireProtocol, u8), NativeCorazaError> {
        self.stream
            .write_all(&handshake_frame())
            .map_err(io_error)?;
        let n = self.read_len()?;
        self.fill(n)?;
        let frame = &self.read_buf[..n];
        let capabilities = decode_handshake_capabilities(frame);
        Ok(match decode_handshake(frame) {
            Some(version) if version >= WIRE_VERSION => (WireProtocol::Binary, capabilities),
            _ => (WireProtocol::Json, 0),
        })
    }

    fn read_len(&mut self) -> Result<usize, NativeCorazaError> {
        let mut header = [0u8; 4];
        self.stream.read_exact(&mut header).map_err(read_error)?;
        let n = u32::from_be_bytes(header) as usize;
        if n == 0 || n > MAX_RESPONSE_BYTES {
            return Err(NativeCorazaError::Protocol(format!(
                "response frame of {n} bytes is invalid"
            )));
        }
        Ok(n)
    }

    fn fill(&mut self, n: usize) -> Result<(), NativeCorazaError> {
        if self.read_buf.len() < n {
            self.read_buf.resize(n, 0);
        }
        self.stream
            .read_exact(&mut self.read_buf[..n])
            .map_err(read_error)
    }

    /// Writes a binary request and reads its decision.
    fn round_trip_binary(
        &mut self,
        request: &BinaryRequest,
        deadline: Instant,
    ) -> Result<Decision, NativeCorazaError> {
        self.apply_deadline(deadline)?;
        write_frame(&mut self.stream, request.head(), request.body()).map_err(io_error)?;
        let decision = self.read_decision()?;
        check_deadline(deadline)?;
        Ok(decision)
    }

    /// Writes a legacy JSON payload and reads its decision.
    fn round_trip_json(
        &mut self,
        payload: &[u8],
        deadline: Instant,
    ) -> Result<Decision, NativeCorazaError> {
        self.apply_deadline(deadline)?;
        let len = u32::try_from(payload.len())
            .map_err(|_| NativeCorazaError::Protocol("payload too large to frame".to_string()))?;
        write_frame(&mut self.stream, &len.to_be_bytes(), Some(payload)).map_err(io_error)?;
        let decision = self.read_decision()?;
        check_deadline(deadline)?;
        Ok(decision)
    }

    /// Tightens the socket timeouts when a retry has less budget left. The
    /// common path keeps the timeouts set at connect time and pays no syscall.
    fn apply_deadline(&mut self, deadline: Instant) -> Result<(), NativeCorazaError> {
        let now = Instant::now();
        if now >= deadline {
            return Err(NativeCorazaError::Timeout);
        }
        let remaining = deadline - now;
        if remaining + Duration::from_millis(1) < self.timeout {
            self.stream
                .set_write_timeout(Some(remaining))
                .map_err(io_error)?;
            self.stream
                .set_read_timeout(Some(remaining))
                .map_err(io_error)?;
        }
        Ok(())
    }

    fn read_decision(&mut self) -> Result<Decision, NativeCorazaError> {
        let n = self.read_len()?;
        self.fill(n)?;
        let frame = &self.read_buf[..n];
        // The response encoding is self-describing: the sidecar answers in the
        // encoding of the request frame it received, so dispatch on the magic
        // rather than on connection state.
        if frame.first() == Some(&FRAME_MAGIC_BINARY) {
            let view = decode_response(frame)
                .map_err(|err| NativeCorazaError::Protocol(err.to_string()))?;
            if view.decision == DECISION_ALLOW {
                return Ok(Decision::Allow);
            }
            let status = if view.status == 0 { 403 } else { view.status };
            let reason = if view.reason.is_empty() {
                "request blocked by native Coraza".to_string()
            } else {
                String::from_utf8_lossy(view.reason).into_owned()
            };
            Ok(Decision::Block { status, reason })
        } else {
            let response: SidecarResponse = serde_json::from_slice(frame).map_err(|err| {
                NativeCorazaError::Protocol(format!("invalid response JSON: {err}"))
            })?;
            response_to_decision(response)
        }
    }
}

/// Writes the frame head and the body with a single `writev` when possible.
fn write_frame(stream: &mut UnixStream, head: &[u8], body: Option<&[u8]>) -> io::Result<()> {
    let mut slices = [IoSlice::new(head), IoSlice::new(body.unwrap_or(&[]))];
    let count = if body.is_some() { 2 } else { 1 };
    let mut bufs = &mut slices[..count];
    while !bufs.is_empty() {
        match stream.write_vectored(bufs) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "native Coraza sidecar closed the connection",
                ))
            }
            Ok(n) => IoSlice::advance_slices(&mut bufs, n),
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(err) => return Err(err),
        }
    }
    Ok(())
}

fn check_deadline(deadline: Instant) -> Result<(), NativeCorazaError> {
    if Instant::now() > deadline {
        Err(NativeCorazaError::Timeout)
    } else {
        Ok(())
    }
}

fn io_error(err: io::Error) -> NativeCorazaError {
    NativeCorazaError::Io(err.to_string())
}

fn read_error(err: io::Error) -> NativeCorazaError {
    match err.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => NativeCorazaError::Timeout,
        _ => NativeCorazaError::Io(err.to_string()),
    }
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

/// A pooled, blocking Unix-socket client.
pub struct NativeCorazaClient {
    pool: Pool,
    pub timeout: Duration,
    pub max_payload_bytes: usize,
}

/// Outcome of a request-context evaluation.
#[derive(Debug)]
pub enum Evaluation {
    /// The sidecar returned a decision.
    Decided {
        decision: Decision,
        /// Number of body bytes actually handed to Coraza.
        inspected_bytes: usize,
        /// Whether the body was truncated to the inspection prefix.
        truncated: bool,
    },
    /// The body-size policy rejected the request before evaluation.
    BodyRejected { size: usize, limit: usize },
}

/// A request encoded in whichever wire format the sidecar negotiated.
enum Encoded<'a> {
    Binary(BinaryRequest),
    Json(std::borrow::Cow<'a, [u8]>),
}

impl Encoded<'_> {
    fn body_len(&self) -> usize {
        match self {
            Self::Binary(request) => request.body_len(),
            Self::Json(payload) => payload.len(),
        }
    }
}

impl NativeCorazaClient {
    /// Creates a client and verifies that the sidecar socket accepts
    /// connections. This is the start-up check: a missing sidecar is reported
    /// immediately rather than surfacing as per-request 503s.
    ///
    /// The first connection also negotiates the wire protocol, so every
    /// evaluation knows whether to use binary v1 or the legacy JSON envelope.
    pub fn new(config: &ClientConfig) -> Result<Self, NativeCorazaError> {
        preflight(&config.socket_path)?;
        let client = Self {
            pool: Pool::new(config),
            timeout: config.timeout,
            max_payload_bytes: config.max_payload_bytes,
        };
        client.pool.warm(Instant::now() + config.timeout)?;
        info!(
            socket = %config.socket_path.display(),
            pool_size = config.pool_size,
            timeout_ms = config.timeout.as_millis(),
            binary_protocol = client.uses_binary(),
            "Coraza native sidecar client ready"
        );
        Ok(client)
    }

    /// True when the sidecar negotiated binary v1 for this process.
    pub fn uses_binary(&self) -> bool {
        self.pool.uses_binary()
    }

    /// True when the sidecar can apply a per-request removal list.
    pub fn supports_remove_rules(&self) -> bool {
        self.pool.supports_remove_rules()
    }

    /// Encodes the request in the negotiated format, applies the body-size
    /// policy and evaluates it.
    pub fn evaluate_context(
        &self,
        ctx: &RequestContext,
        policy: &BodyInspectionPolicy,
    ) -> Result<Evaluation, NativeCorazaError> {
        self.evaluate_context_with_rules(ctx, policy, &[])
    }

    /// Evaluates a request with an explicit per-rule removal list.
    ///
    /// Removals are only sent when the sidecar advertised the capability. A
    /// legacy sidecar therefore evaluates every rule, which is slower but
    /// never changes a decision.
    pub fn evaluate_context_with_rules(
        &self,
        ctx: &RequestContext,
        policy: &BodyInspectionPolicy,
        remove_rule_ids: &[u32],
    ) -> Result<Evaluation, NativeCorazaError> {
        let remove_rule_ids = if self.supports_remove_rules() {
            remove_rule_ids
        } else {
            &[]
        };
        let (encoded, inspected_bytes, truncated) = if self.uses_binary() {
            match encode_request_with_rules(ctx, policy, remove_rule_ids) {
                Ok(WireBuild::Built {
                    request,
                    inspected_bytes,
                    truncated,
                }) => (Encoded::Binary(request), inspected_bytes, truncated),
                Ok(WireBuild::Reject { size, limit }) => {
                    return Ok(Evaluation::BodyRejected { size, limit });
                }
                Err(err) => {
                    return Err(NativeCorazaError::Protocol(format!(
                        "failed to encode binary request: {err}"
                    )));
                }
            }
        } else {
            match crate::waf::coraza_payload::build_payload_with_policy_and_rules(
                ctx,
                policy,
                remove_rule_ids,
            ) {
                Ok(crate::waf::coraza_payload::PayloadBuild::Built {
                    payload,
                    inspected_bytes,
                    truncated,
                }) => (
                    Encoded::Json(std::borrow::Cow::Owned(payload)),
                    inspected_bytes,
                    truncated,
                ),
                Ok(crate::waf::coraza_payload::PayloadBuild::Reject { size, limit }) => {
                    return Ok(Evaluation::BodyRejected { size, limit });
                }
                Err(err) => {
                    return Err(NativeCorazaError::Protocol(format!(
                        "failed to encode JSON request: {err}"
                    )));
                }
            }
        };

        if encoded.body_len() > self.max_payload_bytes {
            return Err(NativeCorazaError::PayloadTooLarge {
                size: encoded.body_len(),
                limit: self.max_payload_bytes,
            });
        }

        let decision = self.execute(&encoded)?;
        Ok(Evaluation::Decided {
            decision,
            inspected_bytes,
            truncated,
        })
    }

    /// Evaluates a pre-encoded legacy JSON payload. Kept for callers that build
    /// the shared envelope (the gRPC content scanner and tests).
    pub fn evaluate(&self, payload: &[u8]) -> Result<Decision, NativeCorazaError> {
        if payload.len() > self.max_payload_bytes {
            return Err(NativeCorazaError::PayloadTooLarge {
                size: payload.len(),
                limit: self.max_payload_bytes,
            });
        }
        self.execute(&Encoded::Json(std::borrow::Cow::Borrowed(payload)))
    }

    /// Evaluates a pre-encoded binary v1 request frame.
    pub fn evaluate_binary(&self, request: BinaryRequest) -> Result<Decision, NativeCorazaError> {
        if !self.uses_binary() {
            return Err(NativeCorazaError::Protocol(
                "sidecar negotiated the JSON protocol".to_string(),
            ));
        }
        if request.body_len() > self.max_payload_bytes {
            return Err(NativeCorazaError::PayloadTooLarge {
                size: request.body_len(),
                limit: self.max_payload_bytes,
            });
        }
        self.execute(&Encoded::Binary(request))
    }

    /// Runs one evaluation, retrying once on a fresh connection so a sidecar
    /// restart or a pooled connection closed while idle is transparent.
    ///
    /// The deadline is enforced at the client because Coraza has no
    /// cancellation API. On expiry the connection is dropped rather than
    /// returned to the pool, which closes the socket and lets the sidecar's
    /// per-connection goroutine exit as soon as its current evaluation
    /// finishes. The sidecar must still bound its own work.
    fn execute(&self, encoded: &Encoded<'_>) -> Result<Decision, NativeCorazaError> {
        let deadline = Instant::now() + self.timeout;
        let mut last_error = None;
        for _ in 0..2 {
            let mut conn = self.pool.acquire(deadline)?;
            let result = match encoded {
                Encoded::Binary(request) => conn.round_trip_binary(request, deadline),
                Encoded::Json(payload) => conn.round_trip_json(payload, deadline),
            };
            match result {
                Ok(decision) => {
                    self.pool.release(conn);
                    return Ok(decision);
                }
                Err(NativeCorazaError::Timeout) => {
                    self.pool.discard();
                    return Err(NativeCorazaError::Timeout);
                }
                Err(err) => {
                    self.pool.discard();
                    last_error = Some(err);
                }
            }
        }
        Err(last_error.unwrap_or_else(|| NativeCorazaError::Io("no attempt made".to_string())))
    }
}

impl crate::waf::grpc::GrpcContentScanner for NativeCorazaClient {
    fn scan(&self, payload: &[u8]) -> Result<Decision, String> {
        self.evaluate(payload).map_err(|error| error.to_string())
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
    client: Arc<NativeCorazaClient>,
    metrics: Option<Arc<Metrics>>,
    fail_closed: bool,
    body_policy: BodyInspectionPolicy,
    /// Experimental CRS literal prefilter (non-default `crs-prefilter` feature).
    #[cfg(feature = "crs-prefilter")]
    prefilter: Option<Arc<Prefilter>>,
    #[cfg(feature = "crs-prefilter")]
    prefilter_mode: PrefilterMode,
}

impl NativeCorazaRule {
    /// Creates a rule from a running sidecar client.
    pub fn new(name: impl Into<String>, client: NativeCorazaClient) -> Self {
        Self {
            name: name.into(),
            client: Arc::new(client),
            metrics: None,
            fail_closed: true,
            body_policy: BodyInspectionPolicy::default(),
            #[cfg(feature = "crs-prefilter")]
            prefilter: None,
            #[cfg(feature = "crs-prefilter")]
            prefilter_mode: PrefilterMode::Off,
        }
    }

    /// Returns the shared sidecar client, for direct (non-recursive)
    /// evaluations such as gRPC field-content scanning.
    pub fn client(&self) -> Arc<NativeCorazaClient> {
        Arc::clone(&self.client)
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

    /// Enables the experimental CRS literal prefilter.
    ///
    /// `PrefilterMode::DryRun` only measures; `PrefilterMode::BodyWithhold`
    /// additionally withholds the body when the prefilter is clean **and** the
    /// artifact proves every body-relevant rule is gated. On the stock CRS
    /// bundle the latter condition is false (see the coverage report), so the
    /// mode is a no-op there by construction. This is opt-in and non-default.
    #[cfg(feature = "crs-prefilter")]
    pub fn with_prefilter(mut self, mode: PrefilterMode) -> Result<Self, PrefilterError> {
        self.prefilter_mode = mode;
        if mode != PrefilterMode::Off {
            let prefilter = Prefilter::from_json(crate::waf::prefilter::EMBEDDED_ARTIFACT)?;
            self.prefilter = Some(Arc::new(prefilter));
        }
        Ok(self)
    }

    /// The loaded prefilter, when the mode is enabled.
    #[cfg(feature = "crs-prefilter")]
    pub fn prefilter(&self) -> Option<&Prefilter> {
        self.prefilter.as_deref()
    }

    /// Builds a rule from `waf.coraza` configuration, verifying the socket.
    pub fn from_config(
        config: &crate::config::WafCorazaConfig,
        fail_closed: bool,
    ) -> Result<Self, NativeCorazaError> {
        let client = NativeCorazaClient::new(&ClientConfig::from(config))?;
        #[allow(unused_mut)]
        let mut rule = Self::new("coraza-native-sidecar", client)
            .with_fail_closed(fail_closed)
            .with_body_policy(BodyInspectionPolicy::from(config));
        #[cfg(feature = "crs-prefilter")]
        {
            rule = rule
                .with_prefilter(PrefilterMode::from(config.prefilter))
                .map_err(|err| NativeCorazaError::Prefilter(err.to_string()))?;
        }
        Ok(rule)
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

    fn cacheable(&self) -> bool {
        true
    }

    fn fast_allow_policy(&self) -> crate::waf::fast_allow::FastAllowPolicy {
        crate::waf::fast_allow::FastAllowPolicy::Skip
    }

    fn evaluate(&self, ctx: &RequestContext) -> Decision {
        #[allow(unused_mut)]
        let mut evaluation_ctx = ctx;
        // Keeps a body-withheld clone alive for the duration of the call.
        #[cfg(feature = "crs-prefilter")]
        let mut scrubbed: Option<RequestContext> = None;
        #[cfg(feature = "crs-prefilter")]
        let mut remove_rule_ids: Vec<u32> = Vec::new();

        #[cfg(feature = "crs-prefilter")]
        if let (Some(prefilter), mode) = (self.prefilter.as_deref(), self.prefilter_mode) {
            if mode != PrefilterMode::Off {
                let prefilter_started = Instant::now();
                let gate = prefilter.evaluate_request(ctx);
                let hit = gate.forced_reason.is_some() || !gate.matched_rules.is_empty();
                let mut withheld = false;

                match mode {
                    PrefilterMode::Gated => {
                        remove_rule_ids = gate.removable_rule_ids.clone();
                        if !remove_rule_ids.is_empty() {
                            debug!(
                                rule = %self.name,
                                removed = remove_rule_ids.len(),
                                matched = ?gate.matched_rules,
                                forced = ?gate.forced_reason,
                                "CRS prefilter gated rules for this transaction"
                            );
                        }
                    }
                    PrefilterMode::BodyWithhold => {
                        if !hit && prefilter.all_body_rules_gated() {
                            let mut stripped = ctx.clone();
                            stripped.body = None;
                            scrubbed = Some(stripped);
                            withheld = true;
                            debug!(
                                rule = %self.name,
                                body_bytes = ctx.body.as_deref().map_or(0, <[u8]>::len),
                                representations = gate.scanned_bytes,
                                "CRS prefilter clean and all body rules gated; withholding body"
                            );
                        }
                    }
                    PrefilterMode::DryRun => {
                        if hit {
                            debug!(
                                rule = %self.name,
                                rules = ?gate.matched_rules,
                                forced = ?gate.forced_reason,
                                "CRS prefilter found an indicator; running full evaluation"
                            );
                        }
                    }
                    PrefilterMode::Off => {}
                }

                if let Some(metrics) = &self.metrics {
                    metrics.record_crs_prefilter(prefilter_started.elapsed(), hit, withheld);
                }
                if withheld {
                    evaluation_ctx = scrubbed.as_ref().expect("scrubbed context");
                }
            }
        }

        let started = Instant::now();
        #[cfg(feature = "crs-prefilter")]
        let result = self.client.evaluate_context_with_rules(
            evaluation_ctx,
            &self.body_policy,
            &remove_rule_ids,
        );
        #[cfg(not(feature = "crs-prefilter"))]
        let result = self
            .client
            .evaluate_context(evaluation_ctx, &self.body_policy);
        if let Some(metrics) = &self.metrics {
            metrics.record_coraza_evaluation(started.elapsed());
        }

        match result {
            Ok(Evaluation::Decided {
                decision,
                inspected_bytes,
                truncated,
            }) => {
                if let Some(metrics) = &self.metrics {
                    metrics.record_coraza_body_inspected_bytes(inspected_bytes);
                    if truncated {
                        metrics.record_coraza_body_truncated();
                    }
                }
                match decision {
                    Decision::Allow => Decision::Allow,
                    decision @ Decision::Block { .. } => {
                        if let Some(metrics) = &self.metrics {
                            metrics.record_coraza_block();
                        }
                        decision
                    }
                    other => {
                        warn!(rule = %self.name, ?other, "native sidecar returned unexpected decision");
                        if let Some(metrics) = &self.metrics {
                            metrics.record_coraza_error();
                        }
                        self.failure_decision("unexpected decision variant".to_string())
                    }
                }
            }
            Ok(Evaluation::BodyRejected { size, limit }) => {
                if let Some(metrics) = &self.metrics {
                    metrics.record_coraza_body_rejected();
                }
                Decision::Block {
                    status: 413,
                    reason: format!(
                        "request body of {size} bytes exceeds the {limit} byte Coraza inspection limit"
                    ),
                }
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
    use crate::waf::coraza_payload::build_payload;
    use crate::waf::coraza_wire::{encode_request, FRAME_MAGIC_BINARY, FRAME_MAGIC_HANDSHAKE};
    use bytes::Bytes;
    use hyper::{HeaderMap, Method, Uri};
    use std::net::IpAddr;
    use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize};

    static SOCKET_SEQ: AtomicU64 = AtomicU64::new(0);

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum TestProtocol {
        /// Pre-binary sidecar: answers the handshake with a JSON block.
        JsonOnly,
        /// Binary v1 sidecar: acks the handshake and answers in binary.
        Binary,
    }

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum Behaviour {
        Ok,
        /// Close the connection after the first frame.
        Close,
        /// Delay past the client deadline.
        Timeout,
        /// Answer with an undecodable payload.
        Malformed,
        /// Write the response in two chunks with a pause between them.
        SlowChunks,
    }

    struct TestSidecar {
        path: PathBuf,
        stop: Arc<AtomicU32>,
        handshakes: Arc<AtomicUsize>,
        requests: Arc<AtomicUsize>,
        handle: Option<std::thread::JoinHandle<()>>,
    }

    impl TestSidecar {
        fn start(protocol: TestProtocol, behaviour: Behaviour) -> Self {
            let seq = SOCKET_SEQ.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "coraza-native-test-{}-{seq}.sock",
                std::process::id()
            ));
            let _ = std::fs::remove_file(&path);
            let listener = std::os::unix::net::UnixListener::bind(&path).expect("bind test socket");
            let stop = Arc::new(AtomicU32::new(0));
            let handshakes = Arc::new(AtomicUsize::new(0));
            let requests = Arc::new(AtomicUsize::new(0));
            let stop_thread = Arc::clone(&stop);
            let handshakes_thread = Arc::clone(&handshakes);
            let requests_thread = Arc::clone(&requests);
            let handle = std::thread::spawn(move || {
                for stream in listener.incoming() {
                    if stop_thread.load(Ordering::Relaxed) != 0 {
                        break;
                    }
                    let Ok(mut stream) = stream else { break };
                    let handshakes = Arc::clone(&handshakes_thread);
                    let requests = Arc::clone(&requests_thread);
                    std::thread::spawn(move || {
                        serve_test_connection(
                            &mut stream,
                            protocol,
                            behaviour,
                            &handshakes,
                            &requests,
                        )
                    });
                }
            });
            Self {
                path,
                stop,
                handshakes,
                requests,
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

    fn write_framed(stream: &mut std::os::unix::net::UnixStream, body: &[u8]) {
        let mut out = Vec::with_capacity(4 + body.len());
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        out.extend_from_slice(body);
        let _ = stream.write_all(&out);
    }

    fn binary_response(decision: u8, status: u16, reason: &[u8]) -> Vec<u8> {
        let mut body = vec![0u8; 8];
        body[0] = FRAME_MAGIC_BINARY;
        body[1] = WIRE_VERSION;
        body[2] = decision;
        body[4..6].copy_from_slice(&status.to_be_bytes());
        body[6..8].copy_from_slice(&(reason.len() as u16).to_be_bytes());
        body.extend_from_slice(reason);
        body
    }

    fn serve_test_connection(
        stream: &mut std::os::unix::net::UnixStream,
        protocol: TestProtocol,
        behaviour: Behaviour,
        handshakes: &AtomicUsize,
        requests: &AtomicUsize,
    ) {
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
            if payload.first() == Some(&FRAME_MAGIC_HANDSHAKE) {
                handshakes.fetch_add(1, Ordering::Relaxed);
                if protocol == TestProtocol::Binary {
                    write_framed(stream, &[FRAME_MAGIC_HANDSHAKE, WIRE_VERSION, 1]);
                } else {
                    write_framed(
                        stream,
                        br#"{"decision":"block","status":400,"reason":"malformed request payload"}"#,
                    );
                }
                continue;
            }
            requests.fetch_add(1, Ordering::Relaxed);
            if behaviour == Behaviour::Close {
                return;
            }
            if behaviour == Behaviour::Timeout {
                std::thread::sleep(Duration::from_millis(500));
            }
            let attack = payload.windows(6).any(|w| w == b"attack");
            let body = match behaviour {
                Behaviour::Malformed => {
                    if protocol == TestProtocol::Binary {
                        // Magic and version are valid, the reason length is not.
                        let mut body = binary_response(0, 0, b"");
                        body[6..8].copy_from_slice(&9u16.to_be_bytes());
                        body
                    } else {
                        b"not json".to_vec()
                    }
                }
                _ => match protocol {
                    TestProtocol::Binary => {
                        if attack {
                            binary_response(1, 403, b"test block")
                        } else {
                            binary_response(0, 0, b"")
                        }
                    }
                    TestProtocol::JsonOnly => {
                        if attack {
                            br#"{"decision":"block","status":403,"reason":"test block"}"#.to_vec()
                        } else {
                            br#"{"decision":"allow"}"#.to_vec()
                        }
                    }
                },
            };
            if behaviour == Behaviour::SlowChunks {
                let (first, rest) = body.split_at(body.len() / 2);
                let mut framed = Vec::with_capacity(4 + body.len());
                framed.extend_from_slice(&(body.len() as u32).to_be_bytes());
                if stream.write_all(&framed).is_err() || stream.write_all(first).is_err() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(5));
                if stream.write_all(rest).is_err() {
                    return;
                }
            } else {
                write_framed(stream, &body);
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
        .with_body(body.map(Bytes::copy_from_slice))
    }

    fn client(path: &Path, timeout: Duration) -> NativeCorazaClient {
        client_with_pool(path, timeout, 2)
    }

    fn client_with_pool(path: &Path, timeout: Duration, pool_size: usize) -> NativeCorazaClient {
        NativeCorazaClient::new(&ClientConfig {
            socket_path: path.to_path_buf(),
            pool_size,
            timeout,
            max_payload_bytes: 64 * 1024,
        })
        .expect("client must start against test sidecar")
    }

    fn rule(path: &Path) -> NativeCorazaRule {
        NativeCorazaRule::new(
            "coraza-native-sidecar",
            client(path, Duration::from_secs(2)),
        )
    }

    #[test]
    fn binary_protocol_allows_benign_and_blocks_attack() {
        let sidecar = TestSidecar::start(TestProtocol::Binary, Behaviour::Ok);
        let rule = rule(&sidecar.path);
        assert_eq!(
            rule.evaluate(&context("/hello", Some(b"a=b"))),
            Decision::Allow
        );
        match rule.evaluate(&context("/attack", Some(b"x=1"))) {
            Decision::Block { status, reason } => {
                assert_eq!(status, 403);
                assert_eq!(reason, "test block");
            }
            other => panic!("expected block, got {other:?}"),
        }
        assert_eq!(
            sidecar.handshakes.load(Ordering::Relaxed),
            1,
            "the handshake must run once per connection"
        );
        assert_eq!(sidecar.requests.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn legacy_json_sidecar_still_works() {
        let sidecar = TestSidecar::start(TestProtocol::JsonOnly, Behaviour::Ok);
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
        assert_eq!(
            sidecar.handshakes.load(Ordering::Relaxed),
            1,
            "negotiation must be remembered for the process"
        );
    }

    #[test]
    fn legacy_json_sidecar_decisions_match_binary() {
        let binary = TestSidecar::start(TestProtocol::Binary, Behaviour::Ok);
        let json = TestSidecar::start(TestProtocol::JsonOnly, Behaviour::Ok);
        let binary_rule = rule(&binary.path);
        let json_rule = rule(&json.path);
        for (uri, body) in [
            ("/hello", Some(&b"a=b"[..])),
            ("/attack", Some(&b"x=1"[..])),
            ("/hello", None),
        ] {
            let ctx = context(uri, body);
            assert_eq!(
                binary_rule.evaluate(&ctx),
                json_rule.evaluate(&ctx),
                "decision parity for {uri}"
            );
        }
    }

    #[test]
    fn partial_response_reads_are_reassembled() {
        let sidecar = TestSidecar::start(TestProtocol::Binary, Behaviour::SlowChunks);
        let client = client(&sidecar.path, Duration::from_secs(2));
        for _ in 0..3 {
            let request = match encode_request(
                &context("/hello", Some(b"a=b")),
                &BodyInspectionPolicy::default(),
            )
            .unwrap()
            {
                WireBuild::Built { request, .. } => request,
                WireBuild::Reject { .. } => panic!("default policy must not reject"),
            };
            assert_eq!(client.evaluate_binary(request).unwrap(), Decision::Allow);
        }
    }

    #[test]
    fn malformed_binary_response_fails_closed() {
        let sidecar = TestSidecar::start(TestProtocol::Binary, Behaviour::Malformed);
        let client = client(&sidecar.path, Duration::from_secs(2));
        let request =
            match encode_request(&context("/hello", None), &BodyInspectionPolicy::default())
                .unwrap()
            {
                WireBuild::Built { request, .. } => request,
                WireBuild::Reject { .. } => panic!("default policy must not reject"),
            };
        let err = client.evaluate_binary(request).unwrap_err();
        assert!(
            matches!(err, NativeCorazaError::Protocol(_)),
            "unexpected error: {err}"
        );

        // The rule must turn that into a fail-closed 503, not an allow.
        assert!(matches!(
            rule(&sidecar.path).evaluate(&context("/hello", None)),
            Decision::Block { status: 503, .. }
        ));
    }

    #[test]
    fn timeout_is_reported() {
        let sidecar = TestSidecar::start(TestProtocol::Binary, Behaviour::Timeout);
        let client = client(&sidecar.path, Duration::from_millis(80));
        let err = client
            .evaluate(&build_payload(&context("/hello", None)).unwrap())
            .unwrap_err();
        assert!(matches!(err, NativeCorazaError::Timeout), "{err}");
    }

    #[test]
    fn reconnects_after_sidecar_closes_connection() {
        let sidecar = TestSidecar::start(TestProtocol::Binary, Behaviour::Close);
        let client = client(&sidecar.path, Duration::from_secs(2));
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
        let sidecar = TestSidecar::start(TestProtocol::Binary, Behaviour::Ok);
        let client = NativeCorazaClient::new(&ClientConfig {
            socket_path: sidecar.path.clone(),
            pool_size: 1,
            timeout: Duration::from_secs(1),
            max_payload_bytes: 8,
        })
        .unwrap();
        let err = client.evaluate(b"0123456789").unwrap_err();
        assert!(matches!(err, NativeCorazaError::PayloadTooLarge { .. }));

        let request = match encode_request(
            &context("/hello", Some(b"0123456789")),
            &BodyInspectionPolicy::default(),
        )
        .unwrap()
        {
            WireBuild::Built { request, .. } => request,
            WireBuild::Reject { .. } => panic!("default policy must not reject"),
        };
        let err = client.evaluate_binary(request).unwrap_err();
        assert!(matches!(err, NativeCorazaError::PayloadTooLarge { .. }));
    }

    #[test]
    fn pool_serves_more_callers_than_connections() {
        let sidecar = TestSidecar::start(TestProtocol::Binary, Behaviour::Ok);
        let client = Arc::new(client_with_pool(&sidecar.path, Duration::from_secs(5), 2));
        std::thread::scope(|scope| {
            for _ in 0..8 {
                let client = Arc::clone(&client);
                scope.spawn(move || {
                    for _ in 0..5 {
                        let request = match encode_request(
                            &context("/hello", Some(b"a=b")),
                            &BodyInspectionPolicy::default(),
                        )
                        .unwrap()
                        {
                            WireBuild::Built { request, .. } => request,
                            WireBuild::Reject { .. } => panic!("default policy must not reject"),
                        };
                        assert_eq!(client.evaluate_binary(request).unwrap(), Decision::Allow);
                    }
                });
            }
        });
        assert_eq!(sidecar.requests.load(Ordering::Relaxed), 40);
    }

    #[test]
    fn pool_recovers_after_timeouts() {
        let sidecar = TestSidecar::start(TestProtocol::Binary, Behaviour::Timeout);
        let client = client_with_pool(&sidecar.path, Duration::from_millis(50), 1);
        let request = || match encode_request(
            &context("/hello", Some(b"a=b")),
            &BodyInspectionPolicy::default(),
        )
        .unwrap()
        {
            WireBuild::Built { request, .. } => request,
            WireBuild::Reject { .. } => panic!("default policy must not reject"),
        };
        for _ in 0..3 {
            assert!(matches!(
                client.evaluate_binary(request()).unwrap_err(),
                NativeCorazaError::Timeout
            ));
        }

        // A healthy sidecar must be usable again after the timeouts dropped
        // every pooled connection.
        let healthy = TestSidecar::start(TestProtocol::Binary, Behaviour::Ok);
        let client = client_with_pool(&healthy.path, Duration::from_secs(2), 1);
        assert_eq!(client.evaluate_binary(request()).unwrap(), Decision::Allow);
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
        let (tx, rx) = std::sync::mpsc::channel();
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
                if payload.first() == Some(&FRAME_MAGIC_HANDSHAKE) {
                    write_framed(&mut stream, &[FRAME_MAGIC_HANDSHAKE, WIRE_VERSION, 1]);
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
        let sidecar = TestSidecar::start(TestProtocol::Binary, Behaviour::Ok);
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

        let malformed = TestSidecar::start(TestProtocol::Binary, Behaviour::Malformed);
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
