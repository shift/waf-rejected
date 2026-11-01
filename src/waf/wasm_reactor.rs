//! Experimental request-in/decision-out WebAssembly reactor ABI.
//!
//! This module is compiled only with the non-default `wasm-reactor` feature.
//! It hosts the Go/Coraza WASI reactor with [wasmtime](https://wasmtime.dev),
//! using wasmtime's WASI preview1 implementation for the reactor's imports. It
//! does not replace any of the built-in heuristic rules and is never enabled
//! by default.
//!
//! See `docs/coraza-wasi-reactor.md` for the ABI, limits and benchmark notes.

use std::cell::RefCell;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use tracing::{info, warn};
use wasmtime::{
    Caller, Config, Engine, Extern, Linker, Memory, Module, OptLevel, Store, StoreLimits,
    StoreLimitsBuilder, TypedFunc,
};
use wasmtime_wasi::p1::{self, WasiP1Ctx};
use wasmtime_wasi::p2::pipe::SinkOutputStream;
use wasmtime_wasi::WasiCtxBuilder;

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
/// Go runtime start-up and compilation of the CRS directive bundle dominate
/// this budget; see the performance notes in `docs/coraza-wasi-reactor.md`.
pub const CORAZA_FUEL: u64 = 200_000_000_000;

/// Size budget for the shipped Coraza reactor. The current module is about
/// 18 MiB; the budget leaves room for a pinned rule bundle while still
/// catching accidental debug builds or unstripped payloads.
pub const CORAZA_MAX_MODULE_BYTES: usize = 32 * 1024 * 1024;

/// Stable path where release packages install the reactor module.
pub const CORAZA_RELEASE_MODULE_PATH: &str = "/usr/share/waf/wasm/coraza_reactor.wasm";

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
    /// The reactor trapped, ran out of fuel, or otherwise failed while running.
    #[error("reactor execution failed: {0}")]
    Trap(String),
    /// The reactor returned a decision code the host does not understand.
    #[error("reactor returned unknown decision code {0}")]
    UnknownDecision(i32),
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
/// The compiled [`Module`] and [`Engine`] are shared across calls. Each
/// worker thread keeps its own initialised [`Store`] and instance (wasmtime
/// stores are not `Send`), so the expensive Go runtime `_initialize` and
/// Coraza `init` run once per thread and reactor instead of once per request.
/// A thread only ever borrows its own instance, so evaluations never share
/// mutable state; a failed instance is discarded and recreated on the next
/// call.
pub struct WasmReactor {
    id: u64,
    engine: Engine,
    module: Module,
    linker: Linker<ReactorState>,
    limits: ReactorLimits,
}

impl std::fmt::Debug for WasmReactor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WasmReactor")
            .field("id", &self.id)
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

static NEXT_REACTOR_ID: AtomicU64 = AtomicU64::new(1);

/// Maximum number of initialised reactors cached per thread. Bounds memory
/// when a process rotates through more than one reactor configuration while
/// keeping the common single-reactor case allocation-free after warm-up.
const THREAD_CACHE_CAPACITY: usize = 2;

/// One initialised reactor instance, owned by a single worker thread.
struct CachedInstance {
    reactor_id: u64,
    store: Store<ReactorState>,
    memory: Memory,
    eval: TypedFunc<(i32, i32), i32>,
    free: TypedFunc<(i32, i32), ()>,
    input_base: usize,
}

thread_local! {
    /// Thread-local, identity-keyed cache of initialised reactor instances.
    /// `Store`/`Memory`/`TypedFunc` are not `Send`, so this is the only place
    /// they live.
    static INSTANCE_CACHE: RefCell<Vec<CachedInstance>> = const { RefCell::new(Vec::new()) };
}

/// Drops every cached instance on the current thread. Primarily useful for
/// tests and for releasing Go heap memory after a configuration change.
pub fn clear_thread_cache() {
    INSTANCE_CACHE.with(|cache| cache.borrow_mut().clear());
}

impl WasmReactor {
    /// Compiles a reactor from WAT or Wasm bytes.
    pub fn from_wat(wat: &str, limits: ReactorLimits) -> Result<Self, ReactorError> {
        Self::from_bytes(wat.as_bytes(), limits)
    }

    /// Compiles a reactor from Wasm bytes. WAT text is accepted as well.
    pub fn from_bytes(bytes: &[u8], limits: ReactorLimits) -> Result<Self, ReactorError> {
        let mut config = Config::new();
        config.consume_fuel(true);
        config.cranelift_opt_level(OptLevel::Speed);
        // The Go runtime uses more wasm stack than a typical Rust/C guest.
        // Exceeding this limit traps in wasm instead of overflowing the host
        // thread stack. wasmtime requires `max_wasm_stack` to fit inside the
        // async stack, even for synchronous calls.
        config.async_stack_size(8 * 1024 * 1024);
        config.max_wasm_stack(8 * 1024 * 1024);
        let engine = Engine::new(&config).map_err(|err| ReactorError::Compile(err.to_string()))?;
        let module =
            Module::new(&engine, bytes).map_err(|err| ReactorError::Compile(err.to_string()))?;
        let linker = wasi_linker(&engine)?;
        let reactor = Self {
            id: NEXT_REACTOR_ID.fetch_add(1, Ordering::Relaxed),
            engine,
            module,
            linker,
            limits,
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
        let metadata = std::fs::metadata(path).map_err(|err| {
            ReactorError::Compile(format!("cannot read module {}: {err}", path.display()))
        })?;
        let size = usize::try_from(metadata.len()).unwrap_or(usize::MAX);
        if size > CORAZA_MAX_MODULE_BYTES {
            return Err(ReactorError::ModuleTooLarge {
                size,
                limit: CORAZA_MAX_MODULE_BYTES,
            });
        }
        let bytes = std::fs::read(path).map_err(|err| {
            ReactorError::Compile(format!("cannot read module {}: {err}", path.display()))
        })?;
        Self::from_coraza_bytes(&bytes)
    }

    /// Compiles the Coraza reactor from bytes and requires its full ABI.
    pub fn from_coraza_bytes(bytes: &[u8]) -> Result<Self, ReactorError> {
        if bytes.len() > CORAZA_MAX_MODULE_BYTES {
            return Err(ReactorError::ModuleTooLarge {
                size: bytes.len(),
                limit: CORAZA_MAX_MODULE_BYTES,
            });
        }
        let reactor = Self::from_bytes(bytes, ReactorLimits::coraza())?;
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
    ///
    /// The first call on a thread (for a given reactor) pays the Go runtime
    /// and Coraza start-up cost; later calls reuse the initialised instance.
    /// If an evaluation fails, the instance is evicted so the next call starts
    /// from a clean store.
    pub fn evaluate(&self, payload: &[u8]) -> Result<ReactorDecision, ReactorError> {
        if payload.len() > self.limits.max_payload_bytes {
            return Err(ReactorError::PayloadTooLarge {
                size: payload.len(),
                limit: self.limits.max_payload_bytes,
            });
        }

        INSTANCE_CACHE.with(|cell| {
            let mut cache = cell.try_borrow_mut().map_err(|_| {
                ReactorError::Trap("reactor instance is already in use".to_string())
            })?;

            let cached = match cache.iter().position(|entry| entry.reactor_id == self.id) {
                Some(index) => cache.swap_remove(index),
                None => self.instantiate()?,
            };

            match self.evaluate_on(cached, payload) {
                Ok((decision, cached)) => {
                    if cache.len() >= THREAD_CACHE_CAPACITY {
                        cache.pop();
                    }
                    cache.push(cached);
                    Ok(decision)
                }
                // Drop the instance on any failure: a trap, fuel exhaustion
                // or failed init may leave the runtime inconsistent.
                Err(err) => Err(err),
            }
        })
    }

    /// Creates and fully initialises a fresh instance for this thread.
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
        store
            .set_fuel(self.limits.fuel)
            .map_err(|err| ReactorError::Trap(err.to_string()))?;

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
        let input_base = match instance.get_typed_func::<(), i32>(&mut store, "input_base") {
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

        Ok(CachedInstance {
            reactor_id: self.id,
            store,
            memory,
            eval,
            free,
            input_base,
        })
    }

    /// Runs one `eval` against an initialised instance and returns it for
    /// reuse on success. Fuel is reset per request so one evaluation cannot
    /// starve the next.
    fn evaluate_on(
        &self,
        mut cached: CachedInstance,
        payload: &[u8],
    ) -> Result<(ReactorDecision, CachedInstance), ReactorError> {
        cached
            .store
            .set_fuel(self.limits.fuel)
            .map_err(|err| ReactorError::Trap(err.to_string()))?;

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
            .map_err(|err| ReactorError::Trap(err.to_string()))?;

        // `free` is part of the ABI even though the reactors do not allocate
        // per request. A failure here does not invalidate the instance.
        let _ = cached.free.call(&mut cached.store, (base_i32, len_i32));

        let decision = match code {
            DECISION_ALLOW => ReactorDecision::Allow,
            DECISION_BLOCK => ReactorDecision::Block {
                status: 403,
                reason: "blocked by wasm reactor".to_string(),
            },
            other => return Err(ReactorError::UnknownDecision(other)),
        };
        Ok((decision, cached))
    }
}

/// Validates the packaged Coraza reactor at startup when the `wasm-reactor`
/// feature is enabled. Any load, export, initialisation, size or execution
/// failure is fatal so the process fails closed instead of serving traffic
/// without the configured WAF engine.
pub fn validate_startup() -> Result<(), ReactorError> {
    let enabled = std::env::var("WAF_CORAZA_REACTOR_ENABLED")
        .map(|value| {
            !matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "0" | "false" | "no" | "off"
            )
        })
        .unwrap_or(true);
    if !enabled {
        warn!("Coraza reactor startup validation disabled by WAF_CORAZA_REACTOR_ENABLED");
        return Ok(());
    }

    let path = std::env::var("WAF_CORAZA_REACTOR_PATH")
        .unwrap_or_else(|_| CORAZA_RELEASE_MODULE_PATH.to_string());
    let reactor = WasmReactor::from_coraza_file(&path)?;

    // `_initialize` and `init` run as part of the first evaluation, so this
    // also proves the Go runtime and Coraza engine construct successfully.
    let probe = br#"{"method":"GET","uri":"/","http_version":"1.1","headers":[],"body":null,"body_size":0}"#;
    reactor.evaluate(probe)?;

    info!(module = %path, "Coraza reactor startup validation passed");
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
        let load_start = std::time::Instant::now();
        let reactor = WasmReactor::from_bytes(EMBEDDED_CORAZA_REACTOR, ReactorLimits::coraza())
            .expect("embedded reactor must load");
        let load_elapsed = load_start.elapsed();

        // The first evaluation initialises the Go runtime and Coraza; later
        // ones reuse the thread-local instance. Latency is reported, not
        // asserted, to stay robust on shared CI.
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
