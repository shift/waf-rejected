//! Experimental request-in/decision-out WebAssembly reactor ABI.
//!
//! This module is compiled only with the non-default `wasm-reactor` feature.
//! It is a spike: it proves the host/module boundary with a pure-Rust
//! interpreter ([`wasmi`]) so that a real Coraza/TinyGo reactor can later be
//! dropped in without the historical Go-JS host. It does not replace any of
//! the built-in heuristic rules and is never enabled by default.
//!
//! See `docs/wasm-reactor-spike.md` for the ABI and migration notes.

use std::sync::Arc;
use std::time::Instant;

use tracing::warn;
use wasmi::{
    Caller, Config, Engine, Extern, Linker, Memory, Module, Store, StoreLimits, StoreLimitsBuilder,
};

use crate::metrics::Metrics;
use crate::waf::{Decision, RequestContext, WafRule};

/// Decision code returned by the reactor for "allow".
pub const DECISION_ALLOW: i32 = 0;
/// Decision code returned by the reactor for "block".
pub const DECISION_BLOCK: i32 = 1;

/// Offset in linear memory where the host writes the request payload.
pub const INPUT_BASE: usize = 1024;

/// Maximum request payload accepted by the spike host.
pub const DEFAULT_MAX_PAYLOAD_BYTES: usize = 32 * 1024;

/// Maximum linear memory the reactor is allowed to grow to.
pub const DEFAULT_MEMORY_LIMIT_BYTES: usize = 64 * 1024;

/// Fuel budget for one `init` + `eval` round trip.
pub const DEFAULT_FUEL: u64 = 1_000_000;

/// Maximum payload accepted by the Coraza reactor (its static input buffer).
pub const CORAZA_MAX_PAYLOAD_BYTES: usize = 64 * 1024;

/// Linear-memory ceiling for the Go/Coraza reactor. The Go runtime starts at
/// roughly 10 MiB and grows during WAF compilation and request parsing.
pub const CORAZA_MEMORY_LIMIT_BYTES: usize = 256 * 1024 * 1024;

/// Fuel budget for one Coraza `_initialize` + `init` + `eval` round trip.
/// Go runtime start-up dominates this budget; see the performance notes in
/// `docs/coraza-wasi-reactor.md`.
pub const CORAZA_FUEL: u64 = 2_000_000_000;

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
    /// Instruction budget for one evaluation.
    pub fuel: u64,
}

impl Default for ReactorLimits {
    fn default() -> Self {
        Self {
            max_payload_bytes: DEFAULT_MAX_PAYLOAD_BYTES,
            memory_limit_bytes: DEFAULT_MEMORY_LIMIT_BYTES,
            fuel: DEFAULT_FUEL,
        }
    }
}

impl ReactorLimits {
    /// Limits suitable for the Go/Coraza reactor and its larger linear memory.
    pub fn coraza() -> Self {
        Self {
            max_payload_bytes: CORAZA_MAX_PAYLOAD_BYTES,
            memory_limit_bytes: CORAZA_MEMORY_LIMIT_BYTES,
            fuel: CORAZA_FUEL,
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
    /// The reactor trapped, ran out of fuel, or otherwise failed while running.
    #[error("reactor execution failed: {0}")]
    Trap(String),
    /// The reactor returned a decision code the host does not understand.
    #[error("reactor returned unknown decision code {0}")]
    UnknownDecision(i32),
}

const WASI_SUCCESS: i32 = 0;
const WASI_BADF: i32 = 8;
const WASI_INVAL: i32 = 28;

/// Minimal WASI preview1 shim for Go's `wasip1` runtime.
///
/// The Coraza reactor is a Go `-buildmode=c-shared` module, so it imports the
/// handful of preview1 calls the Go runtime needs for start-up and allocation.
/// This shim deliberately provides no filesystem, clock or entropy authority:
/// stdio is discarded, clocks read zero, random bytes are deterministic, and
/// path operations return `EBADF`. Nothing in the WAF rules needs those
/// capabilities.
fn wasi_linker(engine: &Engine) -> Linker<StoreLimits> {
    let mut linker = Linker::new(engine);

    linker
        .func_wrap("wasi_snapshot_preview1", "sched_yield", || -> i32 {
            WASI_SUCCESS
        })
        .expect("unique WASI import");
    linker
        .func_wrap(
            "wasi_snapshot_preview1",
            "proc_exit",
            |_code: i32| -> Result<(), wasmi::Error> {
                Err(wasmi::Error::new("WASI proc_exit called"))
            },
        )
        .expect("unique WASI import");
    linker
        .func_wrap(
            "wasi_snapshot_preview1",
            "args_sizes_get",
            |mut caller: Caller<'_, StoreLimits>, argc: i32, argv_buf: i32| -> i32 {
                wasi_write_u32(&mut caller, argc, 0).max(wasi_write_u32(&mut caller, argv_buf, 0))
            },
        )
        .expect("unique WASI import");
    linker
        .func_wrap(
            "wasi_snapshot_preview1",
            "args_get",
            |_argc: i32, _argv: i32| -> i32 { WASI_SUCCESS },
        )
        .expect("unique WASI import");
    linker
        .func_wrap(
            "wasi_snapshot_preview1",
            "environ_sizes_get",
            |mut caller: Caller<'_, StoreLimits>, count: i32, size: i32| -> i32 {
                wasi_write_u32(&mut caller, count, 0).max(wasi_write_u32(&mut caller, size, 0))
            },
        )
        .expect("unique WASI import");
    linker
        .func_wrap(
            "wasi_snapshot_preview1",
            "environ_get",
            |_environ: i32, _buf: i32| -> i32 { WASI_SUCCESS },
        )
        .expect("unique WASI import");
    linker
        .func_wrap(
            "wasi_snapshot_preview1",
            "clock_time_get",
            |mut caller: Caller<'_, StoreLimits>, _clock: i32, _precision: i64, out: i32| -> i32 {
                // Go's runtime throws "nanotime returning zero" if the
                // monotonic clock never advances. A deterministic, strictly
                // increasing counter is sufficient for scheduling timeouts.
                use std::sync::atomic::{AtomicU64, Ordering};
                static NOW: AtomicU64 = AtomicU64::new(1);
                let now = NOW.fetch_add(1_000_000, Ordering::Relaxed);
                wasi_write_u64(&mut caller, out, now)
            },
        )
        .expect("unique WASI import");
    linker
        .func_wrap(
            "wasi_snapshot_preview1",
            "random_get",
            |mut caller: Caller<'_, StoreLimits>, ptr: i32, len: i32| -> i32 {
                let Some(memory) = wasi_memory(&mut caller) else {
                    return WASI_INVAL;
                };
                let Ok(start) = usize::try_from(ptr) else {
                    return WASI_INVAL;
                };
                let Ok(len) = usize::try_from(len) else {
                    return WASI_INVAL;
                };
                let Some(end) = start.checked_add(len) else {
                    return WASI_INVAL;
                };
                let data = memory.data_mut(&mut caller);
                if end > data.len() {
                    return WASI_INVAL;
                }
                let mut state = 0x9e37_79b9_u32 ^ len as u32;
                for byte in &mut data[start..end] {
                    state ^= state << 13;
                    state ^= state >> 17;
                    state ^= state << 5;
                    *byte = state as u8;
                }
                WASI_SUCCESS
            },
        )
        .expect("unique WASI import");
    linker
        .func_wrap(
            "wasi_snapshot_preview1",
            "fd_write",
            |mut caller: Caller<'_, StoreLimits>,
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
                    #[cfg(test)]
                    if _fd == 2 {
                        if let Some(memory) = wasi_memory(&mut caller) {
                            let mut bytes = vec![0u8; len as usize];
                            if memory.read(&caller, _ptr as usize, &mut bytes).is_ok() {
                                eprint!("{}", String::from_utf8_lossy(&bytes));
                            }
                        }
                    }
                    total = total.saturating_add(len);
                }
                wasi_write_u32(&mut caller, nwritten, total)
            },
        )
        .expect("unique WASI import");
    linker
        .func_wrap(
            "wasi_snapshot_preview1",
            "fd_read",
            |mut caller: Caller<'_, StoreLimits>,
             _fd: i32,
             _iovs: i32,
             _iovs_len: i32,
             nread: i32|
             -> i32 { wasi_write_u32(&mut caller, nread, 0) },
        )
        .expect("unique WASI import");
    linker
        .func_wrap(
            "wasi_snapshot_preview1",
            "fd_pread",
            |mut caller: Caller<'_, StoreLimits>,
             _fd: i32,
             _iovs: i32,
             _iovs_len: i32,
             _offset: i64,
             nread: i32|
             -> i32 { wasi_write_u32(&mut caller, nread, 0) },
        )
        .expect("unique WASI import");
    linker
        .func_wrap("wasi_snapshot_preview1", "fd_close", |_fd: i32| -> i32 {
            WASI_SUCCESS
        })
        .expect("unique WASI import");
    linker
        .func_wrap(
            "wasi_snapshot_preview1",
            "fd_fdstat_get",
            |mut caller: Caller<'_, StoreLimits>, _fd: i32, out: i32| -> i32 {
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
        .expect("unique WASI import");
    linker
        .func_wrap(
            "wasi_snapshot_preview1",
            "fd_fdstat_set_flags",
            |_fd: i32, _flags: i32| -> i32 { WASI_SUCCESS },
        )
        .expect("unique WASI import");
    linker
        .func_wrap(
            "wasi_snapshot_preview1",
            "fd_prestat_get",
            |_fd: i32, _out: i32| -> i32 { WASI_BADF },
        )
        .expect("unique WASI import");
    linker
        .func_wrap(
            "wasi_snapshot_preview1",
            "fd_prestat_dir_name",
            |_fd: i32, _path: i32, _len: i32| -> i32 { WASI_BADF },
        )
        .expect("unique WASI import");
    linker
        .func_wrap(
            "wasi_snapshot_preview1",
            "fd_readdir",
            |_fd: i32, _buf: i32, _len: i32, _cookie: i64, _used: i32| -> i32 { WASI_BADF },
        )
        .expect("unique WASI import");
    linker
        .func_wrap(
            "wasi_snapshot_preview1",
            "fd_filestat_get",
            |_fd: i32, _out: i32| -> i32 { WASI_BADF },
        )
        .expect("unique WASI import");
    linker
        .func_wrap(
            "wasi_snapshot_preview1",
            "poll_oneoff",
            |mut caller: Caller<'_, StoreLimits>,
             _in: i32,
             _out: i32,
             _nsubscriptions: i32,
             nevents: i32|
             -> i32 { wasi_write_u32(&mut caller, nevents, 0) },
        )
        .expect("unique WASI import");
    linker
        .func_wrap(
            "wasi_snapshot_preview1",
            "path_filestat_get",
            |_fd: i32, _flags: i32, _path: i32, _len: i32, _out: i32| -> i32 { WASI_BADF },
        )
        .expect("unique WASI import");
    linker
        .func_wrap(
            "wasi_snapshot_preview1",
            "path_readlink",
            |_fd: i32, _path: i32, _path_len: i32, _buf: i32, _buf_len: i32, _used: i32| -> i32 {
                WASI_BADF
            },
        )
        .expect("unique WASI import");
    linker
        .func_wrap(
            "wasi_snapshot_preview1",
            "path_remove_directory",
            |_fd: i32, _path: i32, _len: i32| -> i32 { WASI_BADF },
        )
        .expect("unique WASI import");
    linker
        .func_wrap(
            "wasi_snapshot_preview1",
            "path_unlink_file",
            |_fd: i32, _path: i32, _len: i32| -> i32 { WASI_BADF },
        )
        .expect("unique WASI import");
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
        .expect("unique WASI import");

    // Unused but listed for clarity; keeps the shim honest if the Go runtime
    // starts importing them in a future toolchain.

    linker
}

fn wasi_memory(caller: &mut Caller<'_, StoreLimits>) -> Option<Memory> {
    match caller.get_export("memory") {
        Some(Extern::Memory(memory)) => Some(memory),
        _ => None,
    }
}

fn wasi_write_u32(caller: &mut Caller<'_, StoreLimits>, ptr: i32, value: u32) -> i32 {
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

fn wasi_write_u64(caller: &mut Caller<'_, StoreLimits>, ptr: i32, value: u64) -> i32 {
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

fn wasi_read_pair(caller: &mut Caller<'_, StoreLimits>, ptr: i32) -> Option<(u32, u32)> {
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
/// The compiled [`Module`] and [`Engine`] are shared across calls; a fresh
/// [`Store`] (and therefore a fresh linear memory) is created per evaluation,
/// which keeps evaluations isolated without sharing mutable state.
pub struct WasmReactor {
    engine: Engine,
    module: Module,
    limits: ReactorLimits,
}

impl std::fmt::Debug for WasmReactor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WasmReactor")
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl WasmReactor {
    /// Compiles a reactor from WAT or Wasm bytes.
    pub fn from_wat(wat: &str, limits: ReactorLimits) -> Result<Self, ReactorError> {
        Self::from_bytes(wat.as_bytes(), limits)
    }

    /// Compiles a reactor from Wasm bytes. WAT text is also accepted when the
    /// `wat` feature of `wasmi` is enabled (it is, for this spike).
    pub fn from_bytes(bytes: &[u8], limits: ReactorLimits) -> Result<Self, ReactorError> {
        let mut config = Config::default();
        config.consume_fuel(true);
        // Bound native stack use per call frame. The Go runtime start-up is
        // shallow, but an unbounded interpreter stack can overflow the host
        // thread before wasmi reports a trap.
        config.set_max_recursion_depth(128);
        let engine = Engine::new(&config);
        let module =
            Module::new(&engine, bytes).map_err(|err| ReactorError::Compile(err.to_string()))?;
        let reactor = Self {
            engine,
            module,
            limits,
        };
        reactor.validate_exports()?;
        Ok(reactor)
    }

    /// Builds the reactor from the embedded hardcoded-rule spike module.
    pub fn spike() -> Result<Self, ReactorError> {
        Self::from_wat(SPIKE_WAT, ReactorLimits::default())
    }

    /// Returns the configured limits.
    pub fn limits(&self) -> &ReactorLimits {
        &self.limits
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

    /// Runs `init` and `eval` for one request payload.
    pub fn evaluate(&self, payload: &[u8]) -> Result<ReactorDecision, ReactorError> {
        if payload.len() > self.limits.max_payload_bytes {
            return Err(ReactorError::PayloadTooLarge {
                size: payload.len(),
                limit: self.limits.max_payload_bytes,
            });
        }

        let store_limits = StoreLimitsBuilder::new()
            .memory_size(self.limits.memory_limit_bytes)
            .build();
        let mut store = Store::new(&self.engine, store_limits);
        store.limiter(|limits: &mut StoreLimits| limits);
        store
            .set_fuel(self.limits.fuel)
            .map_err(|err| ReactorError::Trap(err.to_string()))?;

        let linker = wasi_linker(&self.engine);
        let instance = linker
            .instantiate_and_start(&mut store, &self.module)
            .map_err(|err| ReactorError::Compile(err.to_string()))?;

        let memory = instance
            .get_memory(&store, "memory")
            .ok_or(ReactorError::MissingExport("memory"))?;
        let init = instance
            .get_typed_func::<(), i32>(&store, "init")
            .map_err(|_| ReactorError::MissingExport("init"))?;
        let eval = instance
            .get_typed_func::<(i32, i32), i32>(&store, "eval")
            .map_err(|_| ReactorError::MissingExport("eval"))?;
        let free = instance
            .get_typed_func::<(i32, i32), ()>(&store, "free")
            .map_err(|_| ReactorError::MissingExport("free"))?;

        // Go's `-buildmode=c-shared` reactor exports `_initialize`, which must
        // run before any `//go:wasmexport` function. Modules without it (the
        // WAT spike) simply skip this step.
        if let Ok(initialize) = instance.get_typed_func::<(), ()>(&store, "_initialize") {
            initialize
                .call(&mut store, ())
                .map_err(|err| ReactorError::Trap(err.to_string()))?;
        }

        let init_code = init
            .call(&mut store, ())
            .map_err(|err| ReactorError::Trap(err.to_string()))?;
        if init_code != 0 {
            return Err(ReactorError::Init(init_code));
        }

        // Reactors whose runtime owns low linear memory advertise a safe
        // write offset through `input_base`; the WAT spike keeps the historical
        // fixed offset.
        let input_base = match instance.get_typed_func::<(), i32>(&store, "input_base") {
            Ok(func) => {
                let base = func
                    .call(&mut store, ())
                    .map_err(|err| ReactorError::Trap(err.to_string()))?;
                if base < 0 {
                    return Err(ReactorError::PayloadOutOfBounds);
                }
                base as usize
            }
            Err(_) => INPUT_BASE,
        };

        let end = input_base
            .checked_add(payload.len())
            .ok_or(ReactorError::PayloadOutOfBounds)?;
        if end > memory.data_size(&store) {
            return Err(ReactorError::PayloadOutOfBounds);
        }
        memory
            .write(&mut store, input_base, payload)
            .map_err(|err| ReactorError::Trap(err.to_string()))?;

        let code = eval
            .call(&mut store, (input_base as i32, payload.len() as i32))
            .map_err(|err| ReactorError::Trap(err.to_string()))?;

        // `free` is part of the ABI even though the spike does not allocate.
        // Ignore failures here: the store is discarded immediately afterwards.
        let _ = free.call(&mut store, (input_base as i32, payload.len() as i32));

        match code {
            DECISION_ALLOW => Ok(ReactorDecision::Allow),
            DECISION_BLOCK => Ok(ReactorDecision::Block {
                status: 403,
                reason: "blocked by wasm reactor".to_string(),
            }),
            other => Err(ReactorError::UnknownDecision(other)),
        }
    }
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
}

impl WasmReactorRule {
    /// Creates a rule from a compiled reactor.
    pub fn new(name: impl Into<String>, reactor: Arc<WasmReactor>) -> Self {
        Self {
            name: name.into(),
            reactor,
            metrics: None,
            fail_closed: true,
        }
    }

    /// Attaches the process metrics registry so reactor evaluations are
    /// observable through `/metrics`.
    pub fn with_metrics(mut self, metrics: Arc<Metrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Sets the failure policy for reactor errors. `true` maps failures to
    /// `503`; `false` logs and allows the request to continue.
    pub fn with_fail_closed(mut self, fail_closed: bool) -> Self {
        self.fail_closed = fail_closed;
        self
    }

    /// Creates a Coraza rule from either an explicit module file or the
    /// embedded reactor, together with the configured limits.
    pub fn from_module(
        module_path: Option<&str>,
        limits: ReactorLimits,
        fail_closed: bool,
    ) -> Result<Self, ReactorError> {
        let reactor = match module_path {
            Some(path) => {
                let bytes = std::fs::read(path).map_err(|err| ReactorError::Io {
                    path: path.to_string(),
                    detail: err.to_string(),
                })?;
                WasmReactor::from_bytes(&bytes, limits)
            }
            None => WasmReactor::from_bytes(EMBEDDED_CORAZA_REACTOR, limits),
        }?;

        Ok(Self::new("coraza-wasi-reactor", Arc::new(reactor)).with_fail_closed(fail_closed))
    }

    /// Creates a Coraza rule from `waf.coraza` configuration.
    pub fn from_config(
        config: &crate::config::WafCorazaConfig,
        fail_closed: bool,
    ) -> Result<Self, ReactorError> {
        Self::from_module(
            config.module_path.as_deref(),
            ReactorLimits::from(config),
            fail_closed,
        )
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
            fuel: config.fuel,
        }
    }
}

impl WafRule for WasmReactorRule {
    fn name(&self) -> &str {
        &self.name
    }

    fn evaluate(&self, ctx: &RequestContext) -> Decision {
        let started = Instant::now();
        let payload = match build_payload(ctx) {
            Ok(payload) => payload,
            Err(err) => {
                warn!(rule = %self.name, error = %err, "failed to encode wasm reactor payload");
                if let Some(metrics) = &self.metrics {
                    metrics.record_coraza_evaluation(started.elapsed());
                    metrics.record_coraza_error();
                }
                return self.failure_decision(err.to_string());
            }
        };

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

/// Serialises the request context into the reactor's JSON payload.
fn build_payload(ctx: &RequestContext) -> Result<Vec<u8>, serde_json::Error> {
    let headers: Vec<(String, String)> = ctx
        .headers
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_string(),
                String::from_utf8_lossy(value.as_bytes()).into_owned(),
            )
        })
        .collect();

    let body = ctx
        .body
        .as_deref()
        .map(|bytes| String::from_utf8_lossy(bytes).into_owned());

    serde_json::to_vec(&serde_json::json!({
        "method": ctx.method.as_str(),
        "uri": ctx.uri.to_string(),
        "http_version": ctx.http_version,
        "headers": headers,
        "body_size": ctx.body_size,
        "body": body,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
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
            "headers": [["accept", "text/html"]],
            "body": null,
        }))
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

    // Debug-build wasmi interpreter frames are too large to initialise the Go
    // runtime reliably; the same test passes in release. Run it with:
    //   cargo test --release --lib --features wasm-reactor -- --ignored
    #[test]
    #[ignore = "Go/WASI reactor requires the release wasmi profile"]
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

                for body in [
                    "username=admin&password=x union select password from users",
                    "<script>alert(1)</script>",
                    "../../etc/passwd",
                ] {
                    let payload = payload(&serde_json::json!({
                        "method": "POST",
                        "uri": "/login",
                        "headers": [["content-type", "application/x-www-form-urlencoded"]],
                        "body": body,
                    }));
                    assert!(
                        matches!(
                            reactor.evaluate(&payload).unwrap(),
                            ReactorDecision::Block { status: 403, .. }
                        ),
                        "expected Coraza to block payload: {body}"
                    );
                }
            })
            .expect("spawn reactor thread")
            .join()
            .expect("reactor thread must not panic");
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
    #[ignore = "Go/WASI reactor latency measurement requires the release wasmi profile"]
    fn measure_coraza_reactor_latency() {
        let load_start = std::time::Instant::now();
        let reactor = WasmReactor::from_bytes(EMBEDDED_CORAZA_REACTOR, ReactorLimits::coraza())
            .expect("embedded reactor must load");
        let load_elapsed = load_start.elapsed();

        // A fresh Go runtime starts for every evaluation, so latency is
        // reported, not asserted. This keeps the check robust on shared CI.
        std::thread::Builder::new()
            .stack_size(256 * 1024 * 1024)
            .spawn(move || {
                let payload = benign_payload();
                let iterations = 5;
                let start = std::time::Instant::now();
                for _ in 0..iterations {
                    reactor.evaluate(&payload).expect("benign payload");
                }
                let elapsed = start.elapsed();
                eprintln!(
                    "coraza-wasi-reactor: load={:?}, evaluations={}, total={:?}, avg={:?}",
                    load_elapsed,
                    iterations,
                    elapsed,
                    elapsed / iterations
                );
            })
            .expect("spawn reactor thread")
            .join()
            .expect("reactor thread must not panic");
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
