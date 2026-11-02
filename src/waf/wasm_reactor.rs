//! Request-in/decision-out WebAssembly reactor ABI.
//!
//! This module is compiled with the `wasm-reactor` feature, which is enabled
//! by default. It hosts the Go/Coraza WASI reactor with
//! [wasmtime](https://wasmtime.dev), using wasmtime's WASI preview1
//! implementation for the reactor's imports. It runs before the built-in
//! heuristic rules and can be disabled with `waf.coraza.enabled = false`.
//!
//! See `docs/coraza-wasi-reactor.md` for the ABI, limits and benchmark notes.

use std::borrow::Cow;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Condvar, Mutex, OnceLock, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use tracing::{info, warn};
use wasmtime::{
    Caller, Config, Engine, Extern, Linker, Memory, Module, OptLevel, Store, StoreLimits,
    StoreLimitsBuilder, TypedFunc, WasmBacktraceDetails,
};
use wasmtime_wasi::p1::{self, WasiP1Ctx};
use wasmtime_wasi::p2::pipe::SinkOutputStream;
use wasmtime_wasi::WasiCtxBuilder;

use crate::metrics::Metrics;
use crate::waf::coraza_payload::{
    build_payload_with_policy_and_rules, BodyInspectionPolicy, PayloadBuild,
};
use crate::waf::{Decision, RequestContext, WafRule};

/// Decision code returned by the reactor for "allow".
pub const DECISION_ALLOW: i32 = 0;
/// Decision code returned by the reactor for "block".
pub const DECISION_BLOCK: i32 = 1;

/// Guest error code for invalid base64, an unknown `body_encoding`, or a
/// `body` whose decoded length does not match `body_size`.
pub const GUEST_ERROR_BODY_ENCODING: i32 = -5;

/// Payload `body_encoding` value for a body that is valid UTF-8.
pub const BODY_ENCODING_UTF8: &str = "utf8";
/// Payload `body_encoding` value for a base64-encoded binary body.
pub const BODY_ENCODING_BASE64: &str = "base64";

/// Offset in linear memory where the host writes the request payload.
pub const INPUT_BASE: usize = 1024;

/// Maximum request payload accepted by the spike host.
pub const DEFAULT_MAX_PAYLOAD_BYTES: usize = 32 * 1024;

/// Maximum linear memory the reactor is allowed to grow to.
pub const DEFAULT_MEMORY_LIMIT_BYTES: usize = 64 * 1024;

/// Default wall-clock budget for one `eval`. This is a denial-of-service
/// bound, not a normal-latency target: CRS body inspection is byte-linear and
/// a 60 KiB body can legitimately take seconds on modest hardware.
pub const DEFAULT_EVAL_TIMEOUT: Duration = Duration::from_secs(5);

/// Wall-clock budget for Go `_initialize` + Coraza `init` on a fresh instance.
/// Rule compilation is a start-up cost and gets a much larger bound.
pub const INIT_TIMEOUT: Duration = Duration::from_secs(60);

/// Maximum payload accepted by the Coraza reactor (its static input buffer).
pub const CORAZA_MAX_PAYLOAD_BYTES: usize = 64 * 1024;

/// Linear-memory ceiling for the Go/Coraza reactor. The Go runtime starts at
/// roughly 10 MiB and grows during WAF compilation and request parsing.
pub const CORAZA_MEMORY_LIMIT_BYTES: usize = 256 * 1024 * 1024;

/// Shared engine epoch tick period. A store deadline set to N ticks therefore
/// expires after roughly `N * 10 ms` of guest execution.
const EPOCH_TICK_INTERVAL: Duration = Duration::from_millis(10);

/// Margin added to the guest `eval` timeout for the host-side channel wait, so
/// a wedged worker is discarded shortly after the epoch deadline fires.
const HOST_REPLY_MARGIN: Duration = Duration::from_secs(5);

/// Size budget for the shipped Coraza reactor. The current module is about
/// 18 MiB; the budget leaves room for a pinned rule bundle while still
/// catching accidental debug builds or unstripped payloads.
pub const CORAZA_MAX_MODULE_BYTES: usize = 32 * 1024 * 1024;

/// Stable path where release packages install the reactor module.
pub const CORAZA_RELEASE_MODULE_PATH: &str = "/usr/share/waf/wasm/coraza_reactor.wasm";

/// Upper bound on the number of pre-warmed reactor instances. Each instance
/// owns a Go runtime and may grow to the configured memory limit, so the pool
/// is deliberately small even on large machines.
pub const MAX_REACTOR_POOL_SIZE: usize = 8;

/// Native stack reserved for every pool thread. The Go runtime's start-up
/// frames need substantially more than a default 2 MiB thread stack; this
/// leaves four times the 8 MiB wasm stack limit for host frames.
const REACTOR_THREAD_STACK_BYTES: usize = 32 * 1024 * 1024;

/// Default pool size: one worker per available core, clamped to a sane range.
fn default_pool_size() -> usize {
    thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(1)
        .clamp(1, MAX_REACTOR_POOL_SIZE)
}

const SPIKE_WAT: &str = include_str!("../../wasm/reactor_spike.wat");

/// Coraza reactor embedded in the binary. Used when
/// `waf.coraza.module_path` is not set, so deployments need only the WAF
/// binary.
pub const EMBEDDED_CORAZA_REACTOR: &[u8] =
    include_bytes!("../../wasm/coraza_reactor/coraza_reactor.wasm");

/// Resource limits applied to every reactor instance.
#[derive(Debug, Clone)]
pub struct ReactorLimits {
    /// Maximum number of payload bytes accepted by the host.
    pub max_payload_bytes: usize,
    /// Maximum linear-memory size in bytes.
    pub memory_limit_bytes: usize,
    /// Wall-clock budget for one `eval`. Enforced by wasmtime epoch
    /// interruption; exceeding it traps and surfaces as
    /// [`ReactorError::Timeout`].
    pub eval_timeout: Duration,
    /// Number of pre-warmed reactor instances (one OS thread each). Clamped to
    /// `1..=MAX_REACTOR_POOL_SIZE` when the reactor is built.
    pub pool_size: usize,
}

impl Default for ReactorLimits {
    fn default() -> Self {
        Self {
            max_payload_bytes: DEFAULT_MAX_PAYLOAD_BYTES,
            memory_limit_bytes: DEFAULT_MEMORY_LIMIT_BYTES,
            eval_timeout: DEFAULT_EVAL_TIMEOUT,
            pool_size: default_pool_size(),
        }
    }
}

impl ReactorLimits {
    /// Limits suitable for the Go/Coraza reactor and its larger linear memory.
    pub fn coraza() -> Self {
        Self {
            max_payload_bytes: CORAZA_MAX_PAYLOAD_BYTES,
            memory_limit_bytes: CORAZA_MEMORY_LIMIT_BYTES,
            eval_timeout: DEFAULT_EVAL_TIMEOUT,
            pool_size: default_pool_size(),
        }
    }
}

/// Decision produced by a reactor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReactorDecision {
    /// The request is allowed.
    Allow,
    /// The request is blocked with an HTTP status and a human-readable reason.
    Block { status: u16, reason: String },
}

/// Errors raised by the reactor host.
#[derive(Debug, thiserror::Error)]
pub enum ReactorError {
    /// The module could not be parsed, validated or instantiated.
    #[error("failed to load reactor module: {0}")]
    Compile(String),
    /// The configured module file could not be read.
    #[error("failed to read reactor module `{path}`: {detail}")]
    Io { path: String, detail: String },
    /// The module exceeds the release size budget.
    #[error("reactor module is {size} bytes, exceeding the {limit} byte budget")]
    ModuleTooLarge { size: usize, limit: usize },
    /// A required ABI export is missing or has the wrong signature.
    #[error("reactor module is missing required export `{0}`")]
    MissingExport(&'static str),
    /// `init` returned a non-zero code.
    #[error("reactor initialisation failed with code {0}")]
    Init(i32),
    /// The payload exceeds the configured limit.
    #[error("request payload of {size} bytes exceeds the {limit} byte limit")]
    PayloadTooLarge { size: usize, limit: usize },
    /// The payload does not fit in the reactor's linear memory.
    #[error("request payload does not fit in reactor linear memory")]
    PayloadOutOfBounds,
    /// The reactor trapped or otherwise failed while running.
    #[error("reactor execution failed: {0}")]
    Trap(String),
    /// The reactor exceeded its wall-clock execution budget.
    #[error("reactor execution exceeded the configured timeout")]
    Timeout,
    /// The reactor returned a decision code the host does not understand.
    #[error("reactor returned unknown decision code {0}")]
    UnknownDecision(i32),
    /// The guest rejected the payload body: invalid base64, an unknown
    /// `body_encoding`, or a decoded length that disagrees with `body_size`.
    #[error("reactor rejected request body encoding: {0}")]
    InvalidBodyEncoding(&'static str),
    /// The experimental CRS prefilter artifact could not be loaded.
    #[cfg(feature = "crs-prefilter")]
    #[error("CRS prefilter: {0}")]
    Prefilter(String),
}

/// Per-`Store` state. `WasiP1Ctx` supplies the preview1 imports the Go
/// runtime needs; `StoreLimits` caps linear memory.
struct ReactorState {
    wasi: WasiP1Ctx,
    limits: StoreLimits,
}

const WASI_SUCCESS: i32 = 0;
const WASI_BADF: i32 = 8;
const WASI_INVAL: i32 = 28;

/// Builds the preview1 linker for the reactor.
///
/// The context inherits no preopened directories, no arguments and no
/// environment, so the reactor cannot read or write files, spawn processes or
/// observe host configuration. Wall-clock and entropy calls come from
/// wasmtime-wasi; the Go runtime requires both to make progress.
///
/// wasmtime-wasi's synchronous preview1 adapters drive async host functions
/// through an ambient Tokio runtime (`Handle::block_on`). The proxy evaluates
/// rules from inside its own Tokio workers, where that call panics with
/// "Cannot start a runtime from within a runtime". The file/stdio imports are
/// therefore shadowed with deterministic, authority-free shims. They are the
/// same imports the previous hand-written shim implemented: stdio is
/// discarded, descriptors are invalid, and directory/path operations return
/// `EBADF`. Nothing in the WAF rules needs those capabilities.
fn wasi_linker(engine: &Engine) -> Result<Linker<ReactorState>, ReactorError> {
    let mut linker: Linker<ReactorState> = Linker::new(engine);
    linker.allow_shadowing(true);
    p1::add_to_linker_sync(&mut linker, |state: &mut ReactorState| &mut state.wasi)
        .map_err(|err| ReactorError::Compile(err.to_string()))?;
    install_sync_shims(&mut linker)?;
    Ok(linker)
}

fn install_sync_shims(linker: &mut Linker<ReactorState>) -> Result<(), ReactorError> {
    let compile = |err: wasmtime::Error| ReactorError::Compile(err.to_string());

    linker
        .func_wrap(
            "wasi_snapshot_preview1",
            "fd_write",
            |mut caller: Caller<'_, ReactorState>,
             _fd: i32,
             iovs: i32,
             iovs_len: i32,
             nwritten: i32|
             -> i32 {
                let mut total: u32 = 0;
                for index in 0..iovs_len.max(0) {
                    let offset = iovs.saturating_add(index.saturating_mul(8));
                    let Some((_ptr, len)) = wasi_read_pair(&mut caller, offset) else {
                        return WASI_INVAL;
                    };
                    total = total.saturating_add(len);
                }
                wasi_write_u32(&mut caller, nwritten, total)
            },
        )
        .map_err(compile)?;
    linker
        .func_wrap(
            "wasi_snapshot_preview1",
            "fd_read",
            |mut caller: Caller<'_, ReactorState>,
             _fd: i32,
             _iovs: i32,
             _iovs_len: i32,
             nread: i32|
             -> i32 { wasi_write_u32(&mut caller, nread, 0) },
        )
        .map_err(compile)?;
    linker
        .func_wrap(
            "wasi_snapshot_preview1",
            "fd_pread",
            |mut caller: Caller<'_, ReactorState>,
             _fd: i32,
             _iovs: i32,
             _iovs_len: i32,
             _offset: i64,
             nread: i32|
             -> i32 { wasi_write_u32(&mut caller, nread, 0) },
        )
        .map_err(compile)?;
    linker
        .func_wrap("wasi_snapshot_preview1", "fd_close", |_fd: i32| -> i32 {
            WASI_SUCCESS
        })
        .map_err(compile)?;
    linker
        .func_wrap(
            "wasi_snapshot_preview1",
            "fd_fdstat_get",
            |mut caller: Caller<'_, ReactorState>, _fd: i32, out: i32| -> i32 {
                let Some(memory) = wasi_memory(&mut caller) else {
                    return WASI_INVAL;
                };
                let Ok(start) = usize::try_from(out) else {
                    return WASI_INVAL;
                };
                let Some(end) = start.checked_add(24) else {
                    return WASI_INVAL;
                };
                let data = memory.data_mut(&mut caller);
                if end > data.len() {
                    return WASI_INVAL;
                }
                data[start..end].fill(0);
                data[start] = 2; // filetype: character_device
                data[start + 8..start + 16].fill(0xff);
                data[start + 16..start + 24].fill(0xff);
                WASI_SUCCESS
            },
        )
        .map_err(compile)?;
    linker
        .func_wrap(
            "wasi_snapshot_preview1",
            "fd_prestat_get",
            |_fd: i32, _out: i32| -> i32 { WASI_BADF },
        )
        .map_err(compile)?;
    linker
        .func_wrap(
            "wasi_snapshot_preview1",
            "fd_prestat_dir_name",
            |_fd: i32, _path: i32, _len: i32| -> i32 { WASI_BADF },
        )
        .map_err(compile)?;
    linker
        .func_wrap(
            "wasi_snapshot_preview1",
            "fd_readdir",
            |_fd: i32, _buf: i32, _len: i32, _cookie: i64, _used: i32| -> i32 { WASI_BADF },
        )
        .map_err(compile)?;
    linker
        .func_wrap(
            "wasi_snapshot_preview1",
            "fd_filestat_get",
            |_fd: i32, _out: i32| -> i32 { WASI_BADF },
        )
        .map_err(compile)?;
    linker
        .func_wrap(
            "wasi_snapshot_preview1",
            "poll_oneoff",
            |mut caller: Caller<'_, ReactorState>,
             _in: i32,
             _out: i32,
             _nsubscriptions: i32,
             nevents: i32|
             -> i32 { wasi_write_u32(&mut caller, nevents, 0) },
        )
        .map_err(compile)?;
    linker
        .func_wrap(
            "wasi_snapshot_preview1",
            "path_filestat_get",
            |_fd: i32, _flags: i32, _path: i32, _len: i32, _out: i32| -> i32 { WASI_BADF },
        )
        .map_err(compile)?;
    linker
        .func_wrap(
            "wasi_snapshot_preview1",
            "path_readlink",
            |_fd: i32, _path: i32, _path_len: i32, _buf: i32, _buf_len: i32, _used: i32| -> i32 {
                WASI_BADF
            },
        )
        .map_err(compile)?;
    linker
        .func_wrap(
            "wasi_snapshot_preview1",
            "path_remove_directory",
            |_fd: i32, _path: i32, _len: i32| -> i32 { WASI_BADF },
        )
        .map_err(compile)?;
    linker
        .func_wrap(
            "wasi_snapshot_preview1",
            "path_unlink_file",
            |_fd: i32, _path: i32, _len: i32| -> i32 { WASI_BADF },
        )
        .map_err(compile)?;
    linker
        .func_wrap(
            "wasi_snapshot_preview1",
            "path_open",
            |_fd: i32,
             _dirflags: i32,
             _path: i32,
             _path_len: i32,
             _oflags: i32,
             _rights: i64,
             _inheriting: i64,
             _fdflags: i32,
             _out: i32|
             -> i32 { WASI_BADF },
        )
        .map_err(compile)?;

    Ok(())
}

fn wasi_memory(caller: &mut Caller<'_, ReactorState>) -> Option<Memory> {
    match caller.get_export("memory") {
        Some(Extern::Memory(memory)) => Some(memory),
        _ => None,
    }
}

fn wasi_write_u32(caller: &mut Caller<'_, ReactorState>, ptr: i32, value: u32) -> i32 {
    let Some(memory) = wasi_memory(caller) else {
        return WASI_INVAL;
    };
    let Ok(ptr) = usize::try_from(ptr) else {
        return WASI_INVAL;
    };
    match memory.write(caller, ptr, &value.to_le_bytes()) {
        Ok(()) => WASI_SUCCESS,
        Err(_) => WASI_INVAL,
    }
}

fn wasi_read_pair(caller: &mut Caller<'_, ReactorState>, ptr: i32) -> Option<(u32, u32)> {
    let memory = wasi_memory(caller)?;
    let ptr = usize::try_from(ptr).ok()?;
    let mut bytes = [0u8; 8];
    memory.read(caller, ptr, &mut bytes).ok()?;
    Some((
        u32::from_le_bytes(bytes[0..4].try_into().ok()?),
        u32::from_le_bytes(bytes[4..8].try_into().ok()?),
    ))
}

/// A compiled, reusable reactor module.
///
/// The compiled [`Module`] and [`Engine`] are shared across calls. Evaluations
/// are dispatched to a small pool of dedicated OS threads, each owning one
/// initialised [`Store`] and instance (wasmtime stores are not `Send`). The
/// expensive Go runtime `_initialize` and Coraza `init` therefore run once per
/// pool worker during [`WasmReactor::warm`] instead of on the first production
/// request. A worker only ever touches its own instance, so evaluations never
/// share mutable state; a failed instance is discarded and the worker
/// recreates it on its next job.
pub struct WasmReactor {
    id: u64,
    engine: Engine,
    module: Module,
    linker: Linker<ReactorState>,
    limits: ReactorLimits,
    pool_size: usize,
    pool: OnceLock<Arc<ReactorPool>>,
    warm_lock: Mutex<()>,
    /// Sum of the linear-memory sizes currently published by live workers.
    /// Guest Go heaps live inside this memory, so it separates wasm growth
    /// from host-side RSS. Updated by workers at most once per evaluation.
    linear_memory_bytes: Arc<AtomicU64>,
    /// Keeps the engine epoch advancing while the reactor is alive. Dropping
    /// the reactor stops and joins the ticker.
    _epoch: EpochTicker,
}

impl std::fmt::Debug for WasmReactor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WasmReactor")
            .field("id", &self.id)
            .field("limits", &self.limits)
            .field("pool_size", &self.pool_size)
            .field("warm", &self.pool.get().is_some())
            .finish_non_exhaustive()
    }
}

static NEXT_REACTOR_ID: AtomicU64 = AtomicU64::new(1);

/// Advances a reactor engine's epoch on a fixed interval.
///
/// wasmtime checks the deadline only at epoch boundaries, so this replaces the
/// per-basic-block fuel instrumentation with one wakeup per tick per reactor.
/// The thread stops and joins when the reactor (and therefore this handle) is
/// dropped, so reactors created and discarded by tests do not leak threads.
struct EpochTicker {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl EpochTicker {
    fn start(engine: Engine) -> Result<Self, ReactorError> {
        let stop = Arc::new(AtomicBool::new(false));
        let stop_flag = Arc::clone(&stop);
        let handle = thread::Builder::new()
            .name("coraza-epoch-ticker".to_string())
            .spawn(move || {
                while !stop_flag.load(Ordering::Relaxed) {
                    thread::sleep(EPOCH_TICK_INTERVAL);
                    engine.increment_epoch();
                }
            })
            .map_err(|err| ReactorError::Compile(format!("failed to spawn epoch ticker: {err}")))?;
        Ok(Self {
            stop,
            handle: Some(handle),
        })
    }
}

impl Drop for EpochTicker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Converts a wall-clock budget to wasmtime epoch ticks, rounding up so a
/// non-zero timeout always allows at least one tick.
fn epoch_deadline_ticks(timeout: Duration) -> u64 {
    let tick = EPOCH_TICK_INTERVAL.as_millis().max(1);
    let millis = timeout.as_millis();
    let ticks = millis.div_ceil(tick).max(1);
    u64::try_from(ticks).unwrap_or(u64::MAX)
}

/// Maps a guest trap caused by the epoch deadline to [`ReactorError::Timeout`].
fn map_guest_error(err: wasmtime::Error) -> ReactorError {
    if err.downcast_ref::<wasmtime::Trap>() == Some(&wasmtime::Trap::Interrupt) {
        ReactorError::Timeout
    } else {
        ReactorError::Trap(err.to_string())
    }
}

/// One initialised reactor instance, owned by a single worker thread.
struct CachedInstance {
    store: Store<ReactorState>,
    memory: Memory,
    eval: TypedFunc<(i32, i32), i32>,
    free: TypedFunc<(i32, i32), ()>,
    input_base: usize,
}

impl CachedInstance {
    fn linear_memory_bytes(&self) -> u64 {
        self.memory.data_size(&self.store) as u64
    }
}

/// Immutable data each pool worker needs to build and drive its own instance.
///
/// `Engine`, `Module` and `Linker` are cheap to clone (`Arc` inside) and
/// `Send + Sync`; the `Store` created from them stays on the worker thread.
#[derive(Clone)]
struct WorkerConfig {
    id: u64,
    engine: Engine,
    module: Module,
    linker: Linker<ReactorState>,
    limits: ReactorLimits,
    /// Aggregate linear-memory counter shared with the owning reactor.
    linear_memory_bytes: Arc<AtomicU64>,
}

/// One request dispatched to a pool worker. The payload is copied because the
/// channel and worker outlive the caller's borrow.
struct Job {
    payload: Vec<u8>,
    reply: mpsc::Sender<Result<ReactorDecision, ReactorError>>,
}

/// Handle to a worker thread. Dropping the handle detaches the thread; the
/// worker exits once its job sender is dropped.
struct Worker {
    tx: mpsc::Sender<Job>,
    _join: JoinHandle<()>,
}

/// Fixed-size pool of pre-warmed, per-thread reactor instances.
struct ReactorPool {
    config: WorkerConfig,
    size: usize,
    idle: Mutex<IdleState>,
    released: Condvar,
}

struct IdleState {
    workers: Vec<Worker>,
    /// Workers that exist (idle, busy, or starting). Guards `acquire` against
    /// leaving a failed/replaced worker's slot empty forever.
    total: usize,
}

impl ReactorPool {
    /// Spawns `size` workers and blocks until every one has finished
    /// `_initialize` + `init`. Any failure aborts the whole pool so start-up
    /// can fail closed instead of serving with a partially ready pool.
    fn start(config: WorkerConfig, size: usize) -> Result<Self, ReactorError> {
        let size = size.clamp(1, MAX_REACTOR_POOL_SIZE);
        let mut workers = Vec::with_capacity(size);
        let mut readies = Vec::with_capacity(size);

        for index in 0..size {
            let (tx, rx) = mpsc::channel();
            let (ready_tx, ready_rx) = mpsc::channel();
            let worker_config = config.clone();
            let join = thread::Builder::new()
                .name(format!("coraza-reactor-{}-{index}", config.id))
                .stack_size(REACTOR_THREAD_STACK_BYTES)
                .spawn(move || {
                    #[cfg(feature = "cpu-pinning")]
                    if crate::affinity::reactor_pinning_enabled() {
                        let cores = crate::affinity::available_cores();
                        if let Some(core) = crate::affinity::core_for_index(&cores, index) {
                            let _ = crate::affinity::pin_current_thread(core);
                        }
                    }
                    worker_loop(worker_config, rx, Some(ready_tx))
                })
                .map_err(|err| {
                    ReactorError::Compile(format!("failed to spawn reactor worker: {err}"))
                })?;
            workers.push(Worker { tx, _join: join });
            readies.push(ready_rx);
        }

        let mut failure = None;
        for ready in &readies {
            match ready.recv() {
                Ok(Ok(())) => {}
                Ok(Err(err)) => {
                    failure.get_or_insert(err);
                }
                Err(_) => {
                    failure.get_or_insert_with(|| {
                        ReactorError::Trap("reactor worker exited during warm-up".to_string())
                    });
                }
            }
        }
        if let Some(err) = failure {
            // Dropping the senders makes every worker leave its receive loop.
            drop(workers);
            return Err(err);
        }

        Ok(Self {
            config,
            size,
            idle: Mutex::new(IdleState {
                workers,
                total: size,
            }),
            released: Condvar::new(),
        })
    }

    /// Waits for an idle worker, spawning a replacement when a previous worker
    /// failed, then dispatches the payload and waits for its decision.
    fn evaluate(&self, payload: &[u8]) -> Result<ReactorDecision, ReactorError> {
        let worker = self.acquire()?;
        let (reply_tx, reply_rx) = mpsc::channel();
        let job = Job {
            payload: payload.to_vec(),
            reply: reply_tx,
        };

        if worker.tx.send(job).is_err() {
            self.discard(worker);
            return Err(ReactorError::Trap(
                "reactor worker is unavailable".to_string(),
            ));
        }

        // The guest epoch deadline is the primary bound; this host-side wait is
        // a backstop for a worker wedged outside guest code. It is only a small
        // margin longer so a stuck worker cannot pin a request for a minute.
        let host_timeout = self
            .config
            .limits
            .eval_timeout
            .saturating_add(HOST_REPLY_MARGIN);
        match reply_rx.recv_timeout(host_timeout) {
            Ok(result) => {
                self.release(worker);
                result
            }
            Err(RecvTimeoutError::Timeout) => {
                // The worker may still be running; dropping it detaches the
                // thread and closes its job channel so it exits afterwards.
                self.discard(worker);
                Err(ReactorError::Timeout)
            }
            Err(RecvTimeoutError::Disconnected) => {
                // The worker panicked or exited without replying.
                self.discard(worker);
                Err(ReactorError::Trap(
                    "reactor worker exited during evaluation".to_string(),
                ))
            }
        }
    }

    fn acquire(&self) -> Result<Worker, ReactorError> {
        loop {
            let mut state = self.idle.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some(worker) = state.workers.pop() {
                return Ok(worker);
            }
            if state.total < self.size {
                state.total += 1;
                drop(state);
                match self.spawn_worker() {
                    Ok(worker) => return Ok(worker),
                    Err(err) => {
                        let mut state = self.idle.lock().unwrap_or_else(PoisonError::into_inner);
                        state.total = state.total.saturating_sub(1);
                        self.released.notify_all();
                        return Err(err);
                    }
                }
            }
            state = self
                .released
                .wait(state)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }

    /// Starts a replacement worker. Warm-up is eager, but the worker is
    /// returned to the pool immediately; a job that arrives first waits for
    /// the same `_initialize` + `init` the failed worker had already done.
    fn spawn_worker(&self) -> Result<Worker, ReactorError> {
        let (tx, rx) = mpsc::channel();
        let config = self.config.clone();
        let join = thread::Builder::new()
            .name(format!("coraza-reactor-{}", config.id))
            .stack_size(REACTOR_THREAD_STACK_BYTES)
            .spawn(move || {
                #[cfg(feature = "cpu-pinning")]
                if crate::affinity::reactor_pinning_enabled() {
                    let cores = crate::affinity::available_cores();
                    let index = crate::affinity::next_pin_index();
                    if let Some(core) = crate::affinity::core_for_index(&cores, index) {
                        let _ = crate::affinity::pin_current_thread(core);
                    }
                }
                worker_loop(config, rx, None)
            })
            .map_err(|err| {
                ReactorError::Compile(format!("failed to spawn reactor worker: {err}"))
            })?;
        Ok(Worker { tx, _join: join })
    }

    fn release(&self, worker: Worker) {
        let mut state = self.idle.lock().unwrap_or_else(PoisonError::into_inner);
        state.workers.push(worker);
        self.released.notify_one();
    }

    fn discard(&self, worker: Worker) {
        drop(worker);
        let mut state = self.idle.lock().unwrap_or_else(PoisonError::into_inner);
        state.total = state.total.saturating_sub(1);
        // A waiter may now be able to spawn the replacement itself.
        self.released.notify_all();
    }
}

/// Worker main loop. The instance is created before the loop (so `warm` can
/// report readiness) and recreated lazily after a failure.
fn worker_loop(
    config: WorkerConfig,
    jobs: mpsc::Receiver<Job>,
    ready: Option<mpsc::Sender<Result<(), ReactorError>>>,
) {
    let mut reported_memory = 0u64;
    let mut cached = match config.instantiate() {
        Ok(instance) => {
            publish_memory(&config, &mut reported_memory, &instance);
            if let Some(ready) = ready {
                let _ = ready.send(Ok(()));
            }
            Some(instance)
        }
        Err(err) => {
            if let Some(ready) = ready {
                let _ = ready.send(Err(err));
            }
            return;
        }
    };

    while let Ok(job) = jobs.recv() {
        let instance = match cached.take() {
            Some(instance) => instance,
            None => match config.instantiate() {
                Ok(instance) => {
                    publish_memory(&config, &mut reported_memory, &instance);
                    instance
                }
                Err(err) => {
                    let _ = job.reply.send(Err(err));
                    continue;
                }
            },
        };

        match config.evaluate_on(instance, &job.payload) {
            Ok((decision, instance)) => {
                publish_memory(&config, &mut reported_memory, &instance);
                cached = Some(instance);
                let _ = job.reply.send(Ok(decision));
            }
            // The failed instance was already dropped; the next job builds a
            // fresh one.
            Err(err) => {
                clear_memory(&config, &mut reported_memory);
                let _ = job.reply.send(Err(err));
            }
        }
    }
}

fn publish_memory(config: &WorkerConfig, reported: &mut u64, instance: &CachedInstance) {
    let current = instance.linear_memory_bytes();
    if current >= *reported {
        config
            .linear_memory_bytes
            .fetch_add(current - *reported, Ordering::Relaxed);
    } else {
        config
            .linear_memory_bytes
            .fetch_sub(*reported - current, Ordering::Relaxed);
    }
    *reported = current;
}

fn clear_memory(config: &WorkerConfig, reported: &mut u64) {
    if *reported != 0 {
        config
            .linear_memory_bytes
            .fetch_sub(*reported, Ordering::Relaxed);
        *reported = 0;
    }
}

impl WorkerConfig {
    /// Creates and fully initialises a fresh instance on the calling thread.
    fn instantiate(&self) -> Result<CachedInstance, ReactorError> {
        let store_limits = StoreLimitsBuilder::new()
            .memory_size(self.limits.memory_limit_bytes)
            .trap_on_grow_failure(true)
            .build();
        // No preopens, arguments or environment: the reactor has no filesystem
        // or configuration authority. stdout/stderr are discarded so reactor
        // logging cannot be used to flood host output.
        let mut wasi = WasiCtxBuilder::new();
        wasi.stdout(SinkOutputStream).stderr(SinkOutputStream);
        let mut store = Store::new(
            &self.engine,
            ReactorState {
                wasi: wasi.build_p1(),
                limits: store_limits,
            },
        );
        store.limiter(|state: &mut ReactorState| &mut state.limits);
        // Go runtime start-up and CRS compilation get the larger
        // initialisation budget; `evaluate_on` sets a fresh deadline per eval.
        store.set_epoch_deadline(epoch_deadline_ticks(INIT_TIMEOUT));

        let instance = self
            .linker
            .instantiate(&mut store, &self.module)
            .map_err(|err| ReactorError::Compile(err.to_string()))?;

        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or(ReactorError::MissingExport("memory"))?;
        let init = instance
            .get_typed_func::<(), i32>(&mut store, "init")
            .map_err(|_| ReactorError::MissingExport("init"))?;
        let eval = instance
            .get_typed_func::<(i32, i32), i32>(&mut store, "eval")
            .map_err(|_| ReactorError::MissingExport("eval"))?;
        let free = instance
            .get_typed_func::<(i32, i32), ()>(&mut store, "free")
            .map_err(|_| ReactorError::MissingExport("free"))?;

        // Go's `-buildmode=c-shared` reactor exports `_initialize`, which must
        // run before any `//go:wasmexport` function. Modules without it (the
        // WAT spike) simply skip this step.
        if let Ok(initialize) = instance.get_typed_func::<(), ()>(&mut store, "_initialize") {
            initialize.call(&mut store, ()).map_err(map_guest_error)?;
        }

        let init_code = init.call(&mut store, ()).map_err(map_guest_error)?;
        if init_code != 0 {
            return Err(ReactorError::Init(init_code));
        }

        // Reactors whose runtime owns low linear memory advertise a safe
        // write offset through `input_base`; the WAT spike keeps the historical
        // fixed offset.
        let input_base = match instance.get_typed_func::<(), i32>(&mut store, "input_base") {
            Ok(func) => {
                let base = func.call(&mut store, ()).map_err(map_guest_error)?;
                if base < 0 {
                    return Err(ReactorError::PayloadOutOfBounds);
                }
                base as usize
            }
            Err(_) => INPUT_BASE,
        };

        Ok(CachedInstance {
            store,
            memory,
            eval,
            free,
            input_base,
        })
    }

    /// Runs one `eval` against an initialised instance and returns it for
    /// reuse on success. The epoch deadline is reset per request so one
    /// evaluation cannot consume the next one's budget.
    fn evaluate_on(
        &self,
        mut cached: CachedInstance,
        payload: &[u8],
    ) -> Result<(ReactorDecision, CachedInstance), ReactorError> {
        cached
            .store
            .set_epoch_deadline(epoch_deadline_ticks(self.limits.eval_timeout));

        let input_base = cached.input_base;
        let end = input_base
            .checked_add(payload.len())
            .ok_or(ReactorError::PayloadOutOfBounds)?;
        if end > cached.memory.data_size(&cached.store) {
            return Err(ReactorError::PayloadOutOfBounds);
        }
        let base_i32 = i32::try_from(input_base).map_err(|_| ReactorError::PayloadOutOfBounds)?;
        let len_i32 = i32::try_from(payload.len()).map_err(|_| ReactorError::PayloadOutOfBounds)?;
        cached
            .memory
            .write(&mut cached.store, input_base, payload)
            .map_err(|err| ReactorError::Trap(err.to_string()))?;

        let code = cached
            .eval
            .call(&mut cached.store, (base_i32, len_i32))
            .map_err(map_guest_error)?;

        // `free` is part of the ABI even though the reactors do not allocate
        // per request. A failure here does not invalidate the instance.
        let _ = cached.free.call(&mut cached.store, (base_i32, len_i32));

        let decision = match code {
            DECISION_ALLOW => ReactorDecision::Allow,
            DECISION_BLOCK => ReactorDecision::Block {
                status: 403,
                reason: "blocked by wasm reactor".to_string(),
            },
            GUEST_ERROR_BODY_ENCODING => {
                return Err(ReactorError::InvalidBodyEncoding(
                    "guest rejected base64 body or body_size mismatch",
                ))
            }
            other => return Err(ReactorError::UnknownDecision(other)),
        };
        Ok((decision, cached))
    }
}

/// Builds the wasmtime engine configuration for the reactor.
///
/// Only settings that change measured behaviour are set explicitly; the rest
/// are wasmtime defaults (Cranelift `Speed`, no IR verifier or NaN
/// canonicalisation in release, copy-on-write data segments). See
/// `docs/coraza-wasi-reactor.md` for the tuning measurements behind this list.
fn reactor_engine_config() -> Config {
    let mut config = Config::new();
    // Epoch interruption bounds wall-clock execution without the per-block
    // instrumentation cost of fuel metering. The ticker below advances the
    // epoch; stores set a deadline before each guest call.
    config.epoch_interruption(true);
    config.cranelift_opt_level(OptLevel::Speed);
    // A trapped reactor is discarded and reported as an error, and the host
    // never symbolises guest frames. Disabling backtraces keeps the
    // fail-closed timeout path (the DoS-facing path) from walking frames and
    // retaining debug info. This does not affect steady-state `eval`.
    config.wasm_backtrace_max_frames(None);
    config.wasm_backtrace_details(WasmBacktraceDetails::Disable);
    // The Go runtime uses more wasm stack than a typical Rust/C guest.
    // Exceeding this limit traps in wasm instead of overflowing the host
    // thread stack. wasmtime requires `max_wasm_stack` to fit inside the
    // async stack, even for synchronous calls. Both only reserve address
    // space, so they do not affect steady-state throughput.
    config.async_stack_size(8 * 1024 * 1024);
    config.max_wasm_stack(8 * 1024 * 1024);
    config
}

impl WasmReactor {
    /// Compiles a reactor from WAT or Wasm bytes.
    pub fn from_wat(wat: &str, limits: ReactorLimits) -> Result<Self, ReactorError> {
        Self::from_bytes(wat.as_bytes(), limits)
    }

    /// Compiles a reactor from Wasm bytes. WAT text is accepted as well.
    pub fn from_bytes(bytes: &[u8], limits: ReactorLimits) -> Result<Self, ReactorError> {
        let config = reactor_engine_config();
        let engine = Engine::new(&config).map_err(|err| ReactorError::Compile(err.to_string()))?;
        let module =
            Module::new(&engine, bytes).map_err(|err| ReactorError::Compile(err.to_string()))?;
        let linker = wasi_linker(&engine)?;
        let epoch = EpochTicker::start(engine.clone())?;
        let pool_size = limits.pool_size.clamp(1, MAX_REACTOR_POOL_SIZE);
        let reactor = Self {
            id: NEXT_REACTOR_ID.fetch_add(1, Ordering::Relaxed),
            engine,
            module,
            linker,
            limits,
            pool_size,
            pool: OnceLock::new(),
            warm_lock: Mutex::new(()),
            linear_memory_bytes: Arc::new(AtomicU64::new(0)),
            _epoch: epoch,
        };
        reactor.validate_exports()?;
        Ok(reactor)
    }

    /// Builds the reactor from the embedded hardcoded-rule spike module.
    pub fn spike() -> Result<Self, ReactorError> {
        Self::from_wat(SPIKE_WAT, ReactorLimits::default())
    }

    /// Loads the shipped Coraza reactor from a file, enforcing the size budget
    /// and the full Coraza export set.
    pub fn from_coraza_file(path: impl AsRef<Path>) -> Result<Self, ReactorError> {
        let path = path.as_ref();
        let bytes = load_coraza_module(Some(path.to_string_lossy().as_ref()))?;
        Self::from_coraza_bytes_with_limits(&bytes, ReactorLimits::coraza())
    }

    /// Compiles the Coraza reactor from bytes and requires its full ABI.
    pub fn from_coraza_bytes(bytes: &[u8]) -> Result<Self, ReactorError> {
        Self::from_coraza_bytes_with_limits(bytes, ReactorLimits::coraza())
    }

    /// Compiles the Coraza reactor from bytes with explicit limits.
    ///
    /// Callers that need a non-default pool size or memory ceiling use this;
    /// [`WasmReactor::from_coraza_bytes`] applies [`ReactorLimits::coraza`].
    pub fn from_coraza_bytes_with_limits(
        bytes: &[u8],
        limits: ReactorLimits,
    ) -> Result<Self, ReactorError> {
        if bytes.len() > CORAZA_MAX_MODULE_BYTES {
            return Err(ReactorError::ModuleTooLarge {
                size: bytes.len(),
                limit: CORAZA_MAX_MODULE_BYTES,
            });
        }
        let reactor = Self::from_bytes(bytes, limits)?;
        for name in ["_initialize", "input_base"] {
            if reactor.module.get_export(name).is_none() {
                return Err(ReactorError::MissingExport(name));
            }
        }
        Ok(reactor)
    }

    /// Returns the configured limits.
    pub fn limits(&self) -> &ReactorLimits {
        &self.limits
    }

    /// Sum of linear-memory sizes currently published by live pool workers.
    ///
    /// The Go heap and Coraza allocations live inside this memory, so the
    /// value separates guest/wasm growth from host-side RSS (stacks, wasmtime
    /// stores and channels). Workers refresh it once per evaluation; it is a
    /// diagnostic, not a security limit.
    pub fn linear_memory_bytes(&self) -> u64 {
        self.linear_memory_bytes.load(Ordering::Relaxed)
    }

    /// Checks the module's export section before the first evaluation so that
    /// configuration errors surface at load time rather than per request.
    fn validate_exports(&self) -> Result<(), ReactorError> {
        for name in ["memory", "init", "eval", "free"] {
            if self.module.get_export(name).is_none() {
                return Err(ReactorError::MissingExport(name));
            }
        }
        Ok(())
    }

    /// Creates every pool worker and blocks until each one has completed
    /// `_initialize` + `init`. Call this during start-up so no production
    /// request pays initialisation cost.
    ///
    /// The call is idempotent and thread-safe. A failed worker aborts the whole
    /// warm-up so start-up can fail closed; later calls retry from scratch.
    pub fn warm(&self) -> Result<(), ReactorError> {
        if self.pool.get().is_some() {
            return Ok(());
        }

        let _guard = self
            .warm_lock
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if self.pool.get().is_some() {
            return Ok(());
        }

        let pool = ReactorPool::start(
            WorkerConfig {
                id: self.id,
                engine: self.engine.clone(),
                module: self.module.clone(),
                linker: self.linker.clone(),
                limits: self.limits.clone(),
                linear_memory_bytes: Arc::clone(&self.linear_memory_bytes),
            },
            self.pool_size,
        )?;
        let _ = self.pool.set(Arc::new(pool));
        info!(
            reactor = self.id,
            pool_size = self.pool_size,
            "Coraza WASI reactor pool warmed"
        );
        Ok(())
    }

    /// Returns the warmed pool, warming it on first use when the caller did
    /// not call [`WasmReactor::warm`] during start-up.
    fn pool(&self) -> Result<&Arc<ReactorPool>, ReactorError> {
        self.warm()?;
        self.pool
            .get()
            .ok_or_else(|| ReactorError::Trap("reactor pool is unavailable".to_string()))
    }

    /// Runs `eval` for one request payload on a pool worker.
    ///
    /// The Go runtime and Coraza start-up run during [`WasmReactor::warm`]. If
    /// warm-up never ran, the first call performs it (and pays its cost) before
    /// dispatching. Payload limits are enforced before any dispatch.
    pub fn evaluate(&self, payload: &[u8]) -> Result<ReactorDecision, ReactorError> {
        if payload.len() > self.limits.max_payload_bytes {
            return Err(ReactorError::PayloadTooLarge {
                size: payload.len(),
                limit: self.limits.max_payload_bytes,
            });
        }

        self.pool()?.evaluate(payload)
    }
}

impl crate::waf::grpc::GrpcContentScanner for WasmReactor {
    fn scan(&self, payload: &[u8]) -> Result<Decision, String> {
        match self.evaluate(payload) {
            Ok(ReactorDecision::Allow) => Ok(Decision::Allow),
            Ok(ReactorDecision::Block { status, reason }) => Ok(Decision::Block { status, reason }),
            Err(error) => Err(error.to_string()),
        }
    }
}

/// Loads the configured Coraza module bytes. `module_path` selects a file;
/// `None` uses the module embedded in the binary, mirroring engine start-up.
fn load_coraza_module(module_path: Option<&str>) -> Result<Cow<'static, [u8]>, ReactorError> {
    match module_path {
        Some(path) => {
            let metadata = std::fs::metadata(path).map_err(|err| ReactorError::Io {
                path: path.to_string(),
                detail: err.to_string(),
            })?;
            let size = usize::try_from(metadata.len()).unwrap_or(usize::MAX);
            if size > CORAZA_MAX_MODULE_BYTES {
                return Err(ReactorError::ModuleTooLarge {
                    size,
                    limit: CORAZA_MAX_MODULE_BYTES,
                });
            }
            let bytes = std::fs::read(path).map_err(|err| ReactorError::Io {
                path: path.to_string(),
                detail: err.to_string(),
            })?;
            Ok(Cow::Owned(bytes))
        }
        None => Ok(Cow::Borrowed(EMBEDDED_CORAZA_REACTOR)),
    }
}

/// Validates the configured Coraza module source at startup when the
/// `wasm-reactor` feature is enabled.
///
/// This only resolves the configured source (file or embedded module) and
/// enforces the size budget; it deliberately does not compile or warm a
/// reactor. [`WafEngine`](crate::waf::WafEngine) construction owns the single
/// compile and pool warm-up, and its failure is fatal in
/// [`WafProxyService::new`](crate::proxy::WafProxyService::new).
pub fn validate_startup(config: &crate::config::Config) -> Result<(), ReactorError> {
    if !config.waf.enabled || !config.waf.coraza.enabled {
        return Ok(());
    }

    let module = match config.waf.coraza.module_path.as_deref() {
        Some(path) => path.to_string(),
        None => "embedded coraza_reactor.wasm".to_string(),
    };
    // Checks readability and the 32 MiB budget without paying the ~4.5 s
    // compile; the engine construction below performs full ABI validation.
    let bytes = load_coraza_module(config.waf.coraza.module_path.as_deref())?;
    info!(
        module = %module,
        bytes = bytes.len(),
        "Coraza reactor module validated at startup"
    );
    Ok(())
}

/// A [`WafRule`] backed by a reactor.
///
/// The rule is experimental and must be registered explicitly; it never
/// replaces the built-in heuristic rules. Reactor failures fail closed with a
/// `503` because a security control that cannot evaluate must not silently
/// allow traffic.
pub struct WasmReactorRule {
    name: String,
    reactor: Arc<WasmReactor>,
    metrics: Option<Arc<Metrics>>,
    fail_closed: bool,
    body_policy: BodyInspectionPolicy,
    /// Experimental CRS literal prefilter (non-default `crs-prefilter` feature).
    #[cfg(feature = "crs-prefilter")]
    prefilter: Option<Arc<crate::waf::prefilter::Prefilter>>,
    #[cfg(feature = "crs-prefilter")]
    prefilter_mode: crate::waf::prefilter::PrefilterMode,
}

impl WasmReactorRule {
    /// Creates a rule from a compiled reactor.
    pub fn new(name: impl Into<String>, reactor: Arc<WasmReactor>) -> Self {
        Self {
            name: name.into(),
            reactor,
            metrics: None,
            fail_closed: true,
            body_policy: BodyInspectionPolicy::default(),
            #[cfg(feature = "crs-prefilter")]
            prefilter: None,
            #[cfg(feature = "crs-prefilter")]
            prefilter_mode: crate::waf::prefilter::PrefilterMode::Off,
        }
    }

    /// Returns the shared reactor, for direct (non-recursive) evaluations
    /// such as gRPC field-content scanning.
    pub fn reactor(&self) -> Arc<WasmReactor> {
        Arc::clone(&self.reactor)
    }

    /// Attaches the process metrics registry so reactor evaluations are
    /// observable through `/metrics`.
    pub fn with_metrics(mut self, metrics: Arc<Metrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Applies an explicit body-size inspection policy.
    pub fn with_body_policy(mut self, policy: BodyInspectionPolicy) -> Self {
        self.body_policy = policy;
        self
    }

    /// Sets the failure policy for reactor errors. `true` maps failures to
    /// `503`; `false` logs and allows the request to continue.
    pub fn with_fail_closed(mut self, fail_closed: bool) -> Self {
        self.fail_closed = fail_closed;
        self
    }

    /// Enables host-side CRS required-literal gating.
    ///
    /// `Gated` removes only the rules whose mandatory literals are absent from
    /// the request; ungated rules always run. This is opt-in and non-default.
    #[cfg(feature = "crs-prefilter")]
    pub fn with_prefilter(
        mut self,
        mode: crate::waf::prefilter::PrefilterMode,
    ) -> Result<Self, crate::waf::prefilter::PrefilterError> {
        self.prefilter_mode = mode;
        if mode != crate::waf::prefilter::PrefilterMode::Off {
            self.prefilter = Some(Arc::new(crate::waf::prefilter::Prefilter::from_json(
                crate::waf::prefilter::EMBEDDED_ARTIFACT,
            )?));
        }
        Ok(self)
    }

    /// The loaded prefilter, when the mode is enabled.
    #[cfg(feature = "crs-prefilter")]
    pub fn prefilter(&self) -> Option<&crate::waf::prefilter::Prefilter> {
        self.prefilter.as_deref()
    }

    /// Creates a Coraza rule from either an explicit module file or the
    /// embedded reactor, together with the configured limits.
    pub fn from_module(
        module_path: Option<&str>,
        limits: ReactorLimits,
        fail_closed: bool,
    ) -> Result<Self, ReactorError> {
        // Same source selection as `validate_startup`: an explicit
        // `waf.coraza.module_path` file, otherwise the embedded module. Both
        // paths enforce the release size budget and required Coraza exports.
        let bytes = load_coraza_module(module_path)?;
        let reactor = WasmReactor::from_coraza_bytes_with_limits(&bytes, limits)?;
        // Rule construction happens during engine start-up; warming here keeps
        // the first proxied request free of Go/CRS initialisation.
        reactor.warm()?;

        Ok(Self::new("coraza-wasi-reactor", Arc::new(reactor)).with_fail_closed(fail_closed))
    }

    /// Creates a Coraza rule from `waf.coraza` configuration.
    pub fn from_config(
        config: &crate::config::WafCorazaConfig,
        fail_closed: bool,
    ) -> Result<Self, ReactorError> {
        let rule = Self::from_module(
            config.module_path.as_deref(),
            ReactorLimits::from(config),
            fail_closed,
        )?
        .with_body_policy(BodyInspectionPolicy::from(config));
        #[cfg(feature = "crs-prefilter")]
        let rule = rule
            .with_prefilter(crate::waf::prefilter::PrefilterMode::from(config.prefilter))
            .map_err(|err| ReactorError::Prefilter(err.to_string()))?;
        Ok(rule)
    }

    /// Creates a rule backed by the embedded spike module.
    pub fn spike() -> Result<Self, ReactorError> {
        Ok(Self::new(
            "wasm-reactor-spike",
            Arc::new(WasmReactor::spike()?),
        ))
    }
}

impl From<&crate::config::WafCorazaConfig> for ReactorLimits {
    fn from(config: &crate::config::WafCorazaConfig) -> Self {
        Self {
            max_payload_bytes: config.max_payload_bytes,
            memory_limit_bytes: config.memory_limit_bytes,
            eval_timeout: Duration::from_millis(config.eval_timeout_ms),
            pool_size: if config.pool_size == 0 {
                default_pool_size()
            } else {
                config.pool_size
            },
        }
    }
}

impl WafRule for WasmReactorRule {
    fn name(&self) -> &str {
        &self.name
    }

    fn cacheable(&self) -> bool {
        true
    }

    fn fast_allow_policy(&self) -> crate::waf::fast_allow::FastAllowPolicy {
        // Coraza is per-request inspection; an explicitly allowlisted route
        // opts out of it.
        crate::waf::fast_allow::FastAllowPolicy::Skip
    }

    fn evaluate(&self, ctx: &RequestContext) -> Decision {
        let started = Instant::now();
        #[cfg(feature = "crs-prefilter")]
        let mut remove_rule_ids: Vec<u32> = Vec::new();
        #[cfg(feature = "crs-prefilter")]
        if let (Some(prefilter), mode) = (self.prefilter.as_deref(), self.prefilter_mode) {
            if mode != crate::waf::prefilter::PrefilterMode::Off {
                let prefilter_started = Instant::now();
                let gate = prefilter.evaluate_request(ctx);
                let hit = gate.forced_reason.is_some() || !gate.matched_rules.is_empty();
                if mode == crate::waf::prefilter::PrefilterMode::Gated {
                    remove_rule_ids = gate.removable_rule_ids.clone();
                }
                if let Some(metrics) = &self.metrics {
                    metrics.record_crs_prefilter(prefilter_started.elapsed(), hit, false);
                }
            }
        }
        #[cfg(not(feature = "crs-prefilter"))]
        let remove_rule_ids: Vec<u32> = Vec::new();
        let payload_result =
            build_payload_with_policy_and_rules(ctx, &self.body_policy, &remove_rule_ids);
        let (payload, inspected_bytes, truncated) = match payload_result {
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
                warn!(rule = %self.name, error = %err, "failed to encode wasm reactor payload");
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

        let result = self.reactor.evaluate(&payload);
        if let Some(metrics) = &self.metrics {
            metrics.record_coraza_evaluation(started.elapsed());
        }

        match result {
            Ok(ReactorDecision::Allow) => Decision::Allow,
            Ok(ReactorDecision::Block { status, reason }) => {
                if let Some(metrics) = &self.metrics {
                    metrics.record_coraza_block();
                }
                Decision::Block { status, reason }
            }
            Err(err) => {
                warn!(rule = %self.name, error = %err, "wasm reactor evaluation failed");
                if let Some(metrics) = &self.metrics {
                    metrics.record_coraza_error();
                }
                self.failure_decision(err.to_string())
            }
        }
    }
}

impl WasmReactorRule {
    fn failure_decision(&self, reason: String) -> Decision {
        if self.fail_closed {
            Decision::Block {
                status: 503,
                reason: format!("wasm reactor failure: {reason}"),
            }
        } else {
            warn!(
                rule = %self.name,
                reason = %reason,
                "wasm reactor failed; continuing because fail_mode is open"
            );
            Decision::Allow
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::waf::coraza_payload::build_payload;
    use crate::waf::coraza_payload::build_payload_with_policy;
    use bytes::Bytes;
    use hyper::{HeaderMap, Method, Uri};
    use std::net::{IpAddr, Ipv4Addr};

    fn payload(value: &serde_json::Value) -> Vec<u8> {
        serde_json::to_vec(value).expect("test payload must serialise")
    }

    fn benign_payload() -> Vec<u8> {
        payload(&serde_json::json!({
            "method": "GET",
            "uri": "/index.html",
            "headers": [["host", "example.com"], ["accept", "text/html"]],
            "body": null,
        }))
    }

    fn form_payload(uri: &str, body: &str) -> Vec<u8> {
        payload(&serde_json::json!({
            "method": "POST",
            "uri": uri,
            "headers": [
                ["host", "example.com"],
                ["content-type", "application/x-www-form-urlencoded"],
                ["content-length", body.len().to_string()],
            ],
            "body": body,
        }))
    }

    /// Context with an arbitrary raw body, used to exercise binary payloads.
    fn binary_context(uri: &str, body: &[u8]) -> RequestContext {
        let mut headers = HeaderMap::new();
        headers.insert("host", "example.com".parse().unwrap());
        headers.insert(
            "content-type",
            "application/x-www-form-urlencoded".parse().unwrap(),
        );
        headers.insert("content-length", body.len().to_string().parse().unwrap());
        RequestContext::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            Method::POST,
            uri.parse::<Uri>().unwrap(),
            headers,
            Some(body.len()),
        )
        .with_body(Some(Bytes::copy_from_slice(body)))
    }

    fn context(uri: &str, body: Option<&str>) -> RequestContext {
        let mut headers = HeaderMap::new();
        headers.insert("user-agent", "spike-test".parse().unwrap());
        let mut ctx = RequestContext::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            Method::GET,
            uri.parse::<Uri>().unwrap(),
            headers,
            body.map(str::len),
        );
        if let Some(body) = body {
            ctx = ctx.with_body(Some(Bytes::from(body.to_string())));
        }
        ctx
    }

    #[test]
    fn build_payload_keeps_utf8_bodies_on_the_fast_path() {
        let body = "<script>alert(1)</script>";
        let encoded = build_payload(&context("/search", Some(body))).expect("payload must encode");
        let value: serde_json::Value =
            serde_json::from_slice(&encoded).expect("payload must be JSON");

        assert_eq!(value["body_encoding"], BODY_ENCODING_UTF8);
        assert_eq!(value["body"], body);
        assert_eq!(value["body_size"].as_u64(), Some(body.len() as u64));
    }

    #[test]
    fn build_payload_base64_encodes_binary_bodies_losslessly() {
        use base64::Engine as _;

        // Leading invalid UTF-8 bytes model a protobuf/gRPC frame prefix; the
        // attack follows so the test covers both the preserved framing bytes
        // and the inspected payload.
        let raw: &[u8] = b"\xff\xfe\x00\x01q=<script>alert(1)</script>";
        let encoded = build_payload(&binary_context("/search", raw)).expect("payload must encode");
        let value: serde_json::Value =
            serde_json::from_slice(&encoded).expect("payload must be JSON");

        assert_eq!(value["body_encoding"], BODY_ENCODING_BASE64);
        assert_eq!(value["body_size"].as_u64(), Some(raw.len() as u64));
        let text = value["body"].as_str().expect("body must be a string");
        assert!(
            !text.contains('\u{FFFD}'),
            "binary body must not contain replacement characters"
        );
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(text)
                .expect("body must be valid base64"),
            raw
        );
    }

    #[test]
    fn default_body_policy_inspects_the_whole_body() {
        let body = "a".repeat(8 * 1024);
        let built = build_payload_with_policy(
            &context("/search", Some(&body)),
            &BodyInspectionPolicy::default(),
        )
        .expect("payload must encode");
        let PayloadBuild::Built {
            payload,
            inspected_bytes,
            truncated,
        } = built
        else {
            panic!("inspect-all must never reject");
        };
        assert_eq!(inspected_bytes, body.len());
        assert!(!truncated);
        let value: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(value["body"], body);
        assert_eq!(value["body_size"].as_u64(), Some(body.len() as u64));
        assert_eq!(
            value["body_original_size"].as_u64(),
            Some(body.len() as u64)
        );
    }

    #[test]
    fn forward_uninspected_sends_only_the_inspection_prefix() {
        let body = "a".repeat(8 * 1024);
        let policy = BodyInspectionPolicy {
            max_inspect_bytes: 1024,
            oversize_action: crate::config::CorazaOversizeAction::ForwardUninspected,
        };
        let built = build_payload_with_policy(&context("/search", Some(&body)), &policy)
            .expect("payload must encode");
        let PayloadBuild::Built {
            payload,
            inspected_bytes,
            truncated,
        } = built
        else {
            panic!("forward-uninspected must not reject");
        };
        assert_eq!(inspected_bytes, 1024);
        assert!(truncated);
        let value: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(value["body"], "a".repeat(1024));
        // The guest requires body_size to match the decoded body; the original
        // length is retained separately for observability.
        assert_eq!(value["body_size"].as_u64(), Some(1024));
        assert_eq!(
            value["body_original_size"].as_u64(),
            Some(body.len() as u64)
        );
    }

    #[test]
    fn reject_policy_returns_a_rejection_without_building_a_payload() {
        let body = "a".repeat(8 * 1024);
        let policy = BodyInspectionPolicy {
            max_inspect_bytes: 1024,
            oversize_action: crate::config::CorazaOversizeAction::Reject,
        };
        let built = build_payload_with_policy(&context("/search", Some(&body)), &policy)
            .expect("policy decision must not be an encoding error");
        assert!(matches!(
            built,
            PayloadBuild::Reject {
                size: 8192,
                limit: 1024
            }
        ));
    }

    #[test]
    fn reject_policy_returns_413_and_does_not_evaluate_the_reactor() {
        let metrics = Arc::new(Metrics::new());
        let rule = WasmReactorRule::spike()
            .expect("spike module must load")
            .with_metrics(Arc::clone(&metrics))
            .with_body_policy(BodyInspectionPolicy {
                max_inspect_bytes: 1024,
                oversize_action: crate::config::CorazaOversizeAction::Reject,
            });
        let body = "a".repeat(8 * 1024);
        let decision = rule.evaluate(&context("/search", Some(&body)));
        assert!(matches!(decision, Decision::Block { status: 413, .. }));
        let rendered = metrics.render_prometheus();
        assert!(rendered.contains("waf_coraza_body_rejected_total 1"));
        assert!(rendered.contains("waf_coraza_evaluations_total 0"));
    }

    #[test]
    fn default_policy_still_fails_closed_at_the_payload_cap() {
        let limits = ReactorLimits {
            max_payload_bytes: 8,
            ..ReactorLimits::default()
        };
        let reactor = WasmReactor::from_wat(SPIKE_WAT, limits).expect("spike module must load");
        let rule = WasmReactorRule::new("spike", Arc::new(reactor));
        assert!(matches!(
            rule.evaluate(&context("/search", Some("0123456789"))),
            Decision::Block { status: 503, .. }
        ));
    }

    #[test]
    fn forward_uninspected_records_truncation_and_inspected_bytes() {
        let metrics = Arc::new(Metrics::new());
        let rule = WasmReactorRule::spike()
            .expect("spike module must load")
            .with_metrics(Arc::clone(&metrics))
            .with_body_policy(BodyInspectionPolicy {
                max_inspect_bytes: 1024,
                oversize_action: crate::config::CorazaOversizeAction::ForwardUninspected,
            });
        let body = "a".repeat(8 * 1024);
        assert_eq!(
            rule.evaluate(&context("/search", Some(&body))),
            Decision::Allow
        );
        let rendered = metrics.render_prometheus();
        assert!(rendered.contains("waf_coraza_body_truncated_total 1"));
        assert!(rendered.contains("waf_coraza_body_inspected_bytes_count 1"));
        assert!(rendered.contains("waf_coraza_body_inspected_bytes_sum 1024"));
    }

    #[test]
    fn startup_validation_is_a_noop_when_coraza_is_disabled() {
        let mut config = crate::config::Config::default();
        config.waf.coraza.enabled = false;
        config.waf.coraza.module_path = Some("/nonexistent/coraza.wasm".to_string());
        assert!(validate_startup(&config).is_ok());
    }

    #[test]
    fn startup_validation_is_a_noop_when_waf_is_disabled() {
        let mut config = crate::config::Config::default();
        config.waf.enabled = false;
        config.waf.coraza.module_path = Some("/nonexistent/coraza.wasm".to_string());
        assert!(validate_startup(&config).is_ok());
    }

    #[test]
    fn startup_validation_rejects_a_missing_module_file() {
        let mut config = crate::config::Config::default();
        config.waf.coraza.module_path = Some("/nonexistent/coraza.wasm".to_string());
        assert!(validate_startup(&config).is_err());
    }

    #[test]
    fn allows_benign_payload() {
        let reactor = WasmReactor::spike().expect("spike module must load");
        assert_eq!(
            reactor.evaluate(&benign_payload()).unwrap(),
            ReactorDecision::Allow
        );
    }

    #[test]
    fn blocks_xss_payload() {
        let reactor = WasmReactor::spike().expect("spike module must load");
        let body = payload(&serde_json::json!({
            "method": "GET",
            "uri": "/search?q=<script>alert(1)</script>",
        }));
        assert_eq!(
            reactor.evaluate(&body).unwrap(),
            ReactorDecision::Block {
                status: 403,
                reason: "blocked by wasm reactor".to_string(),
            }
        );
    }

    #[test]
    fn blocks_sql_injection_payload() {
        let reactor = WasmReactor::spike().expect("spike module must load");
        let body = payload(&serde_json::json!({
            "method": "POST",
            "uri": "/login",
            "body": "username=admin&password=x union select password from users",
        }));
        assert!(matches!(
            reactor.evaluate(&body).unwrap(),
            ReactorDecision::Block { status: 403, .. }
        ));
    }

    #[test]
    fn rejects_malformed_module() {
        let err = WasmReactor::from_wat("(module (func", ReactorLimits::default())
            .expect_err("malformed WAT must not load");
        assert!(matches!(err, ReactorError::Compile(_)));
    }

    #[test]
    fn rejects_module_without_required_exports() {
        let err = WasmReactor::from_wat(
            "(module (memory (export \"memory\") 1))",
            ReactorLimits::default(),
        )
        .expect_err("module without ABI exports must not load");
        assert!(matches!(err, ReactorError::MissingExport(_)));
    }

    #[test]
    fn coraza_requires_reactor_exports() {
        let wat = r#"
            (module
              (memory (export "memory") 1)
              (func (export "init") (result i32) i32.const 0)
              (func (export "eval") (param i32 i32) (result i32) i32.const 0)
              (func (export "free") (param i32 i32)))
        "#;
        let err = WasmReactor::from_coraza_bytes(wat.as_bytes())
            .expect_err("module without _initialize/input_base must not load");
        assert!(matches!(err, ReactorError::MissingExport(_)));
    }

    #[test]
    fn reports_init_failure() {
        let wat = r#"
            (module
              (memory (export "memory") 1)
              (func (export "init") (result i32) i32.const 7)
              (func (export "eval") (param i32 i32) (result i32) i32.const 0)
              (func (export "free") (param i32 i32)))
        "#;
        let reactor =
            WasmReactor::from_wat(wat, ReactorLimits::default()).expect("module must load");
        assert!(matches!(
            reactor.evaluate(b"{}"),
            Err(ReactorError::Init(7))
        ));
    }

    #[test]
    fn reports_trap_as_error() {
        let wat = r#"
            (module
              (memory (export "memory") 1)
              (func (export "init") (result i32) i32.const 0)
              (func (export "eval") (param i32 i32) (result i32) unreachable)
              (func (export "free") (param i32 i32)))
        "#;
        let reactor =
            WasmReactor::from_wat(wat, ReactorLimits::default()).expect("module must load");
        assert!(matches!(
            reactor.evaluate(b"{}"),
            Err(ReactorError::Trap(_))
        ));
    }

    #[test]
    fn warm_prepares_pool_and_keeps_decisions_correct() {
        let limits = ReactorLimits {
            pool_size: 2,
            ..ReactorLimits::default()
        };
        let reactor = WasmReactor::from_wat(SPIKE_WAT, limits).expect("spike module must load");

        reactor.warm().expect("warm-up must succeed");
        // Idempotent and cheap: the pool is only built once.
        reactor.warm().expect("second warm-up must succeed");
        assert!(
            reactor.linear_memory_bytes() > 0,
            "warm workers must publish their linear-memory size"
        );

        assert_eq!(
            reactor.evaluate(&benign_payload()).unwrap(),
            ReactorDecision::Allow
        );
        let xss = payload(&serde_json::json!({
            "method": "GET",
            "uri": "/search?q=<script>alert(1)</script>",
        }));
        assert!(matches!(
            reactor.evaluate(&xss).unwrap(),
            ReactorDecision::Block { status: 403, .. }
        ));
        assert_eq!(
            reactor.evaluate(&benign_payload()).unwrap(),
            ReactorDecision::Allow
        );
    }

    #[test]
    fn warm_fails_closed_when_a_worker_cannot_init() {
        let wat = r#"
            (module
              (memory (export "memory") 1)
              (func (export "init") (result i32) i32.const 7)
              (func (export "eval") (param i32 i32) (result i32) i32.const 0)
              (func (export "free") (param i32 i32)))
        "#;
        let limits = ReactorLimits {
            pool_size: 2,
            ..ReactorLimits::default()
        };
        let reactor = WasmReactor::from_wat(wat, limits).expect("module must load");
        assert!(matches!(reactor.warm(), Err(ReactorError::Init(7))));
        // A failed warm-up must not poison later attempts.
        assert!(matches!(
            reactor.evaluate(b"{}"),
            Err(ReactorError::Init(7))
        ));
    }

    #[test]
    fn concurrent_evaluations_return_correct_decisions() {
        let limits = ReactorLimits {
            pool_size: 2,
            ..ReactorLimits::default()
        };
        let reactor =
            Arc::new(WasmReactor::from_wat(SPIKE_WAT, limits).expect("spike module must load"));
        reactor.warm().expect("warm-up must succeed");

        let benign = Arc::new(benign_payload());
        let xss = Arc::new(payload(&serde_json::json!({
            "method": "GET",
            "uri": "/search?q=<script>alert(1)</script>",
        })));

        let handles: Vec<_> = (0..8)
            .map(|_| {
                let reactor = Arc::clone(&reactor);
                let benign = Arc::clone(&benign);
                let xss = Arc::clone(&xss);
                std::thread::spawn(move || {
                    for _ in 0..20 {
                        assert_eq!(reactor.evaluate(&benign).unwrap(), ReactorDecision::Allow);
                        assert!(matches!(
                            reactor.evaluate(&xss).unwrap(),
                            ReactorDecision::Block { status: 403, .. }
                        ));
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().expect("evaluation thread must not panic");
        }
    }

    #[test]
    fn worker_trap_discards_instance_without_hanging_or_corrupting() {
        // `eval` traps when the payload starts with '1' and allows otherwise,
        // so a failure can be interleaved with successful evaluations.
        let wat = r#"
            (module
              (memory (export "memory") 1)
              (func (export "init") (result i32) i32.const 0)
              (func (export "eval") (param $ptr i32) (param $len i32) (result i32)
                (if (i32.and (i32.gt_s (local.get $len) (i32.const 0))
                             (i32.eq (i32.load8_u (local.get $ptr)) (i32.const 49)))
                  (then unreachable))
                i32.const 0)
              (func (export "free") (param i32 i32)))
        "#;
        let limits = ReactorLimits {
            pool_size: 1,
            ..ReactorLimits::default()
        };
        let reactor = WasmReactor::from_wat(wat, limits).expect("module must load");
        reactor.warm().expect("warm-up must succeed");

        for _ in 0..3 {
            assert!(matches!(reactor.evaluate(b"1"), Err(ReactorError::Trap(_))));
            // The failed instance is discarded and rebuilt; decisions stay
            // correct and the call returns instead of hanging.
            assert_eq!(reactor.evaluate(b"0").unwrap(), ReactorDecision::Allow);
        }
    }

    #[test]
    fn evaluation_timeout_discards_instance_and_next_evaluation_recovers() {
        // `eval` spins forever when the payload starts with '1' and allows
        // otherwise, so the timeout path can be exercised without a real hang.
        let wat = r#"
            (module
              (memory (export "memory") 1)
              (func (export "init") (result i32) i32.const 0)
              (func (export "eval") (param $ptr i32) (param $len i32) (result i32)
                (if (i32.and (i32.gt_s (local.get $len) (i32.const 0))
                             (i32.eq (i32.load8_u (local.get $ptr)) (i32.const 49)))
                  (then (loop $spin (br $spin))))
                i32.const 0)
              (func (export "free") (param i32 i32)))
        "#;
        let limits = ReactorLimits {
            pool_size: 1,
            eval_timeout: Duration::from_millis(30),
            ..ReactorLimits::default()
        };
        let reactor = WasmReactor::from_wat(wat, limits).expect("module must load");
        reactor.warm().expect("warm-up must succeed");

        let started = Instant::now();
        assert!(matches!(reactor.evaluate(b"1"), Err(ReactorError::Timeout)));
        // The epoch deadline, not the host-side backstop, ended the call.
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "timeout should fire near the 30 ms budget, took {:?}",
            started.elapsed()
        );

        // The timed-out instance was discarded; the next evaluation builds a
        // fresh one and succeeds.
        assert_eq!(reactor.evaluate(b"0").unwrap(), ReactorDecision::Allow);
    }

    #[test]
    fn rejects_oversized_payload() {
        let limits = ReactorLimits {
            max_payload_bytes: 8,
            ..ReactorLimits::default()
        };
        let reactor = WasmReactor::from_wat(SPIKE_WAT, limits).expect("spike module must load");
        assert!(matches!(
            reactor.evaluate(b"0123456789"),
            Err(ReactorError::PayloadTooLarge { .. })
        ));
    }

    // Initialising the Go runtime and compiling CRS is slow in debug builds,
    // so this test is kept out of the default run. Run it with:
    //   cargo test --release --lib --features wasm-reactor -- --ignored
    #[test]
    #[ignore = "Go/WASI reactor is exercised in release mode"]
    #[cfg(feature = "crs-prefilter")]
    fn gated_prefilter_preserves_wasm_decisions() {
        use crate::waf::prefilter::PrefilterMode;

        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/wasm/coraza_reactor/coraza_reactor.wasm"
        );
        let rule = WasmReactorRule::from_module(Some(path), ReactorLimits::coraza(), true)
            .expect("reactor must load")
            .with_prefilter(PrefilterMode::Gated)
            .expect("prefilter artifact must load");

        std::thread::Builder::new()
            .stack_size(256 * 1024 * 1024)
            .spawn(move || {
                let benign = context(
                    "/login",
                    Some("username=alice&password=CorrectHorseBattery123&remember=1"),
                );
                let gate = rule
                    .prefilter()
                    .expect("prefilter enabled")
                    .evaluate_request(&benign);
                assert!(
                    !gate.removable_rule_ids.is_empty(),
                    "a benign form must gate some rules"
                );
                // @detectSQLi (942100) is ungated and must never be offered.
                assert!(!gate.removable_rule_ids.contains(&942100));
                assert_eq!(rule.evaluate(&benign), Decision::Allow);

                for (kind, body) in [
                    ("SQLi", "username=admin' OR '1'='1"),
                    ("XSS", "q=<script>alert(1)</script>"),
                    ("RCE", "cmd=/bin/cat /etc/passwd"),
                ] {
                    let decision = rule.evaluate(&context("/check", Some(body)));
                    assert!(
                        matches!(decision, Decision::Block { status: 403, .. }),
                        "gated mode must still block {kind}: {body}"
                    );
                }
            })
            .expect("reactor test thread")
            .join()
            .expect("reactor test thread panicked");
    }

    #[test]
    #[ignore = "Go/WASI reactor is exercised in release mode"]
    fn coraza_reactor_allows_benign_and_blocks_attacks() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/wasm/coraza_reactor/coraza_reactor.wasm"
        );
        let bytes = std::fs::read(path).expect("built Coraza reactor must exist");
        let reactor =
            WasmReactor::from_bytes(&bytes, ReactorLimits::coraza()).expect("reactor must load");

        std::thread::Builder::new()
            // Give the interpreter enough native stack for Go runtime
            // initialisation; the reactor is not run on a proxy worker thread.
            .stack_size(256 * 1024 * 1024)
            .spawn(move || {
                assert_eq!(
                    reactor.evaluate(&benign_payload()).unwrap(),
                    ReactorDecision::Allow
                );

                // gRPC media types must be allowed by the CRS content-type
                // policy (920420); the protocol-aware pre-check validates the
                // envelope and strips the protobuf body before this point.
                let grpc = payload(&serde_json::json!({
                    "method": "POST",
                    "uri": "/acme.Echo/Echo",
                    "http_version": "2.0",
                    "headers": [
                        ["content-type", "application/grpc+proto"],
                        ["te", "trailers"],
                    ],
                    "body": null,
                    "body_size": 0,
                }));
                assert_eq!(
                    reactor.evaluate(&grpc).unwrap(),
                    ReactorDecision::Allow,
                    "gRPC content-type must not trip CRS 920420"
                );

                // False-positive checks: ordinary query strings and form bodies
                // must not trip CRS at the default paranoia level.
                let benign_cases = [
                    (
                        "plain search query",
                        payload(&serde_json::json!({
                            "method": "GET",
                            "uri": "/search?q=wireless+keyboard&page=2&sort=price",
                            "headers": [["host", "example.com"], ["accept", "text/html"]],
                            "body": null,
                        })),
                    ),
                    (
                        "login form body",
                        form_payload(
                            "/login",
                            "username=alice&password=CorrectHorseBattery123&remember=1",
                        ),
                    ),
                ];
                for (kind, payload_bytes) in benign_cases {
                    assert_eq!(
                        reactor.evaluate(&payload_bytes).unwrap(),
                        ReactorDecision::Allow,
                        "expected benign {kind} to be allowed"
                    );
                }

                let attacks = [
                    ("SQLi", "/login", "username=admin' OR '1'='1"),
                    ("XSS", "/search", "<script>alert(1)</script>"),
                    ("path traversal", "/download", "../../etc/passwd"),
                    ("command injection", "/run", "cmd=/bin/cat /etc/passwd"),
                ];
                for (kind, uri, body) in attacks {
                    let payload = form_payload(uri, body);
                    assert!(
                        matches!(
                            reactor.evaluate(&payload).unwrap(),
                            ReactorDecision::Block { status: 403, .. }
                        ),
                        "expected Coraza CRS to block {kind} payload: {body}"
                    );
                }
            })
            .expect("spawn reactor thread")
            .join()
            .expect("reactor thread must not panic");
    }

    #[test]
    #[ignore = "Go/WASI reactor is exercised in release mode"]
    fn coraza_forward_uninspected_blocks_prefix_attack_but_not_suffix_attack() {
        let reactor = WasmReactor::from_bytes(EMBEDDED_CORAZA_REACTOR, ReactorLimits::coraza())
            .expect("embedded reactor must load");
        let rule = WasmReactorRule::new("coraza", Arc::new(reactor)).with_body_policy(
            BodyInspectionPolicy {
                max_inspect_bytes: 1024,
                oversize_action: crate::config::CorazaOversizeAction::ForwardUninspected,
            },
        );

        let benign = format!("q={}", "a".repeat(8 * 1024));
        let prefix_attack = format!("q=<script>alert(1)</script>&pad={}", "a".repeat(8 * 1024));
        // The attack starts after the 1 KiB inspection prefix. This is the
        // documented gap of forward-uninspected and is asserted explicitly.
        let suffix_attack = format!("q={}&x=<script>alert(1)</script>", "a".repeat(1024));

        std::thread::Builder::new()
            .stack_size(256 * 1024 * 1024)
            .spawn(move || {
                assert_eq!(
                    rule.evaluate(&binary_context("/search", benign.as_bytes())),
                    Decision::Allow,
                    "benign 8 KiB body must be allowed"
                );
                assert!(
                    matches!(
                        rule.evaluate(&binary_context("/search", prefix_attack.as_bytes())),
                        Decision::Block { status: 403, .. }
                    ),
                    "an attack inside the inspection prefix must still be blocked"
                );
                assert_eq!(
                    rule.evaluate(&binary_context("/search", suffix_attack.as_bytes())),
                    Decision::Allow,
                    "an attack after the inspection prefix is not inspected (documented gap)"
                );
            })
            .expect("spawn reactor thread")
            .join()
            .expect("reactor thread must not panic");
    }

    #[test]
    #[ignore = "Go/WASI reactor is exercised in release mode"]
    fn coraza_reactor_inspects_binary_bodies_after_invalid_utf8() {
        let reactor = WasmReactor::from_bytes(EMBEDDED_CORAZA_REACTOR, ReactorLimits::coraza())
            .expect("embedded reactor must load");

        // Invalid UTF-8 prefix (as found in protobuf/gRPC or compressed
        // bodies) followed by the attack payload. With the old lossy host the
        // prefix became U+FFFD bytes before the guest ever saw the body.
        let benign = build_payload(&binary_context("/search", b"\xff\xfeq=wireless+keyboard"))
            .expect("payload must encode");
        let xss = build_payload(&binary_context(
            "/search",
            b"\xff\xfeq=<script>alert(1)</script>",
        ))
        .expect("payload must encode");
        let sqli = build_payload(&binary_context("/login", b"\xff\xfeq=admin' OR '1'='1"))
            .expect("payload must encode");

        let wire: serde_json::Value = serde_json::from_slice(&xss).expect("payload must be JSON");
        assert_eq!(wire["body_encoding"], BODY_ENCODING_BASE64);

        std::thread::Builder::new()
            .stack_size(256 * 1024 * 1024)
            .spawn(move || {
                assert_eq!(
                    reactor.evaluate(&benign).unwrap(),
                    ReactorDecision::Allow,
                    "benign binary body must not be blocked"
                );
                assert!(
                    matches!(
                        reactor.evaluate(&xss).unwrap(),
                        ReactorDecision::Block { status: 403, .. }
                    ),
                    "Coraza must inspect the binary body and block the embedded XSS"
                );
                assert!(
                    matches!(
                        reactor.evaluate(&sqli).unwrap(),
                        ReactorDecision::Block { status: 403, .. }
                    ),
                    "Coraza must inspect the binary body and block the embedded SQLi"
                );
            })
            .expect("spawn reactor thread")
            .join()
            .expect("reactor thread must not panic");
    }

    #[test]
    #[ignore = "Go/WASI reactor is exercised in release mode"]
    fn coraza_reactor_rejects_invalid_body_encoding_and_recovers() {
        use base64::Engine as _;

        let reactor = WasmReactor::from_bytes(EMBEDDED_CORAZA_REACTOR, ReactorLimits::coraza())
            .expect("embedded reactor must load");
        // A malformed body must surface as an encoding error, so these
        // payloads must not also trip a phase-1 rule: with early blocking on,
        // a phase-1 deny happens before the body is decoded. A missing Host
        // header alone scores 5 (rule 920280) and would shadow the error.
        let headers = serde_json::json!([
            ["host", "example.com"],
            ["content-type", "application/x-www-form-urlencoded"],
        ]);

        let invalid_base64 = payload(&serde_json::json!({
            "method": "POST",
            "uri": "/search",
            "headers": headers.clone(),
            "body_encoding": "base64",
            "body": "!!!not-base64!!!",
            "body_size": 4,
        }));
        let mismatched_size = payload(&serde_json::json!({
            "method": "POST",
            "uri": "/search",
            "headers": headers.clone(),
            "body_encoding": "base64",
            "body": base64::engine::general_purpose::STANDARD
                .encode(b"q=<script>alert(1)</script>"),
            "body_size": 1,
        }));
        let unknown_encoding = payload(&serde_json::json!({
            "method": "POST",
            "uri": "/search",
            "headers": headers.clone(),
            "body_encoding": "latin1",
            "body": "abc",
            "body_size": 3,
        }));
        let valid_binary = build_payload(&binary_context(
            "/search",
            b"\xff\xfeq=<script>alert(1)</script>",
        ))
        .expect("payload must encode");
        let benign = benign_payload();

        std::thread::Builder::new()
            .stack_size(256 * 1024 * 1024)
            .spawn(move || {
                for (kind, bad) in [
                    ("invalid base64", invalid_base64),
                    ("mismatched body_size", mismatched_size),
                    ("unknown body_encoding", unknown_encoding),
                ] {
                    assert!(
                        matches!(
                            reactor.evaluate(&bad),
                            Err(ReactorError::InvalidBodyEncoding(_))
                        ),
                        "expected {kind} to be rejected with a body-encoding error"
                    );
                    // The failed worker instance is discarded, so the next
                    // evaluation rebuilds and must still produce decisions.
                    assert_eq!(
                        reactor.evaluate(&benign).unwrap(),
                        ReactorDecision::Allow,
                        "reactor must recover after {kind}"
                    );
                }

                assert!(
                    matches!(
                        reactor.evaluate(&valid_binary).unwrap(),
                        ReactorDecision::Block { status: 403, .. }
                    ),
                    "valid base64 bodies must still be inspected and blocked"
                );

                // A malformed body on a request that phase 1 already blocks is
                // denied before the body is decoded. The outcome is still a
                // deny (403), never an allow.
                let phase1_blocked_bad_encoding = payload(&serde_json::json!({
                    "method": "POST",
                    "uri": "/search",
                    "headers": [["content-type", "application/x-www-form-urlencoded"]],
                    "body_encoding": "base64",
                    "body": "!!!not-base64!!!",
                    "body_size": 4,
                }));
                assert!(
                    matches!(
                        reactor.evaluate(&phase1_blocked_bad_encoding).unwrap(),
                        ReactorDecision::Block { status: 403, .. }
                    ),
                    "a phase-1 deny must fail closed even with a malformed body"
                );
            })
            .expect("spawn reactor thread")
            .join()
            .expect("reactor thread must not panic");
    }

    #[test]
    #[ignore = "Go/WASI reactor is exercised in release mode"]
    fn coraza_reactor_reuses_instance_without_leaking_state() {
        let reactor = WasmReactor::from_bytes(EMBEDDED_CORAZA_REACTOR, ReactorLimits::coraza())
            .expect("embedded reactor must load");

        let benign = benign_payload();
        let sqli = payload(&serde_json::json!({
            "method": "POST",
            "uri": "/login",
            "headers": [["content-type", "application/x-www-form-urlencoded"]],
            "body": "username=admin&password=x union select password from users",
        }));
        let xss = payload(&serde_json::json!({
            "method": "GET",
            "uri": "/search?q=<script>alert(1)</script>",
            "headers": [["accept", "text/html"]],
            "body": null,
        }));

        std::thread::Builder::new()
            .stack_size(256 * 1024 * 1024)
            .spawn(move || {
                // The first call initialises the Go runtime and Coraza; the
                // rest must reuse that instance. Interleaving decisions proves
                // a block does not poison or leak into later evaluations.
                for _ in 0..3 {
                    assert_eq!(reactor.evaluate(&benign).unwrap(), ReactorDecision::Allow);
                    assert!(matches!(
                        reactor.evaluate(&sqli).unwrap(),
                        ReactorDecision::Block { status: 403, .. }
                    ));
                    assert_eq!(reactor.evaluate(&benign).unwrap(), ReactorDecision::Allow);
                    assert!(matches!(
                        reactor.evaluate(&xss).unwrap(),
                        ReactorDecision::Block { status: 403, .. }
                    ));
                }
            })
            .expect("spawn reactor thread")
            .join()
            .expect("reactor thread must not panic");
    }

    #[test]
    #[ignore = "Go/WASI reactor is exercised in release mode"]
    fn coraza_reactor_isolated_per_thread() {
        let reactor = Arc::new(
            WasmReactor::from_bytes(EMBEDDED_CORAZA_REACTOR, ReactorLimits::coraza())
                .expect("embedded reactor must load"),
        );
        let benign = Arc::new(benign_payload());
        let sqli = Arc::new(payload(&serde_json::json!({
            "method": "POST",
            "uri": "/login",
            "headers": [["content-type", "application/x-www-form-urlencoded"]],
            "body": "username=admin&password=x union select password from users",
        })));

        let handles: Vec<_> = (0..3)
            .map(|_| {
                let reactor = Arc::clone(&reactor);
                let benign = Arc::clone(&benign);
                let sqli = Arc::clone(&sqli);
                std::thread::Builder::new()
                    .stack_size(256 * 1024 * 1024)
                    .spawn(move || {
                        for _ in 0..2 {
                            assert_eq!(reactor.evaluate(&benign).unwrap(), ReactorDecision::Allow);
                            assert!(matches!(
                                reactor.evaluate(&sqli).unwrap(),
                                ReactorDecision::Block { status: 403, .. }
                            ));
                        }
                    })
                    .expect("spawn reactor thread")
            })
            .collect();

        for handle in handles {
            handle.join().expect("reactor thread must not panic");
        }
    }

    fn trapping_reactor() -> Arc<WasmReactor> {
        let wat = r#"
            (module
              (memory (export "memory") 1)
              (func (export "init") (result i32) i32.const 0)
              (func (export "eval") (param i32 i32) (result i32) unreachable)
              (func (export "free") (param i32 i32)))
        "#;
        Arc::new(WasmReactor::from_wat(wat, ReactorLimits::default()).expect("module must load"))
    }

    #[test]
    #[ignore = "Go/WASI reactor latency measurement runs in release mode"]
    fn measure_coraza_reactor_latency() {
        let limits = ReactorLimits {
            pool_size: 2,
            ..ReactorLimits::coraza()
        };
        let load_start = std::time::Instant::now();
        let reactor =
            WasmReactor::from_bytes(EMBEDDED_CORAZA_REACTOR, limits).expect("reactor must load");
        let load_elapsed = load_start.elapsed();

        // Warming runs Go `_initialize` + Coraza `init` on every pool worker.
        let warm_start = std::time::Instant::now();
        reactor.warm().expect("warm-up must succeed");
        let warm_elapsed = warm_start.elapsed();

        // After warm-up no request pays initialisation; report the first
        // post-warm evaluation separately from steady state.
        let payload = benign_payload();
        let first_start = std::time::Instant::now();
        reactor.evaluate(&payload).expect("benign payload");
        let first_elapsed = first_start.elapsed();

        let iterations = 5;
        let start = std::time::Instant::now();
        for _ in 0..iterations {
            reactor.evaluate(&payload).expect("benign payload");
        }
        let elapsed = start.elapsed();
        eprintln!(
            "coraza-wasi-reactor: load={load_elapsed:?}, warm={warm_elapsed:?}, \
             first_eval_after_warm={first_elapsed:?}, evaluations={iterations}, \
             steady_total={elapsed:?}, steady_avg={:?}, pool_size={}",
            elapsed / iterations,
            reactor.pool_size
        );

        // Dispatch overhead: the trivial WAT reactor returns immediately, so
        // this isolates the channel round trip and pool hand-off.
        let spike_limits = ReactorLimits {
            pool_size: 2,
            ..ReactorLimits::default()
        };
        let spike = WasmReactor::from_wat(SPIKE_WAT, spike_limits).expect("spike module must load");
        spike.warm().expect("spike warm-up must succeed");
        let dispatch_iterations = 10_000;
        let dispatch_start = std::time::Instant::now();
        for _ in 0..dispatch_iterations {
            spike.evaluate(&payload).expect("spike payload");
        }
        let dispatch_elapsed = dispatch_start.elapsed();
        eprintln!(
            "coraza-wasi-reactor: dispatch_evaluations={dispatch_iterations}, \
             dispatch_total={dispatch_elapsed:?}, dispatch_avg={:?}",
            dispatch_elapsed / dispatch_iterations
        );
    }

    #[test]
    fn rule_fails_closed_on_reactor_error() {
        let rule = WasmReactorRule::new("trapping", trapping_reactor()).with_fail_closed(true);
        assert!(matches!(
            rule.evaluate(&context("/", None)),
            Decision::Block { status: 503, .. }
        ));
    }

    #[test]
    fn rule_fails_open_when_configured() {
        let rule = WasmReactorRule::new("trapping", trapping_reactor()).with_fail_closed(false);
        assert_eq!(rule.evaluate(&context("/", None)), Decision::Allow);
    }

    #[test]
    fn rule_maps_allow_and_block_decisions() {
        let rule = WasmReactorRule::spike().expect("spike module must load");

        assert_eq!(rule.name(), "wasm-reactor-spike");
        assert_eq!(
            rule.evaluate(&context("/index.html", None)),
            Decision::Allow
        );

        let decision = rule.evaluate(&context("/search", Some("<script>alert(1)</script>")));
        assert!(matches!(decision, Decision::Block { status: 403, .. }));

        let decision = rule.evaluate(&context("/login", Some("union select 1")));
        assert!(matches!(decision, Decision::Block { status: 403, .. }));
    }
}
