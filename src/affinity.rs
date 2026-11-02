//! Optional CPU affinity helpers for proxy worker and reactor-pool threads.
//!
//! Pinning is strictly opt-in: without the `cpu-pinning` build feature these
//! functions are no-ops and report `false`, so default deployments keep the
//! scheduler's own placement decisions. See
//! `docs/suggestions_from_agents/alloc-tuning.md` for the measurement results
//! and tradeoffs.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// Process-wide switch for reactor-pool pinning. Set once at start-up from
/// `runtime.enable_cpu_pinning`; the pool reads it when spawning workers so
/// individual `WasmReactor` constructors do not need a new parameter.
static PIN_REACTOR_POOL: AtomicBool = AtomicBool::new(false);

/// Monotonic index used to spread replacement reactor workers across cores.
static NEXT_PIN_INDEX: AtomicUsize = AtomicUsize::new(0);

/// Record whether reactor-pool workers should be pinned. No-op without the
/// `cpu-pinning` feature (the flag is still stored so tests can observe it).
pub fn set_reactor_pinning(enabled: bool) {
    PIN_REACTOR_POOL.store(enabled, Ordering::Relaxed);
}

/// Whether reactor-pool workers should attempt CPU pinning.
pub fn reactor_pinning_enabled() -> bool {
    PIN_REACTOR_POOL.load(Ordering::Relaxed)
}

/// Next round-robin index for a replacement reactor worker.
pub fn next_pin_index() -> usize {
    NEXT_PIN_INDEX.fetch_add(1, Ordering::Relaxed)
}

/// Return the logical CPUs available to this process, in ascending order.
///
/// With the `cpu-pinning` feature this asks the OS for the current affinity
/// mask; otherwise it falls back to `num_cpus`.
pub fn available_cores() -> Vec<usize> {
    #[cfg(feature = "cpu-pinning")]
    {
        if let Some(ids) = core_affinity::get_core_ids() {
            if !ids.is_empty() {
                return ids.into_iter().map(|id| id.id).collect();
            }
        }
    }
    (0..num_cpus::get()).collect()
}

/// Pin the calling thread to `core_id`. Returns `true` when the affinity was
/// applied, `false` when the feature is disabled or the platform refused it.
///
/// Failure is never fatal: callers keep running on the scheduler's chosen CPU.
pub fn pin_current_thread(core_id: usize) -> bool {
    #[cfg(feature = "cpu-pinning")]
    {
        return core_affinity::set_for_current(core_affinity::CoreId { id: core_id });
    }
    #[cfg(not(feature = "cpu-pinning"))]
    {
        let _ = core_id;
        false
    }
}

/// Pick the core for the `index`-th worker from `cores`, wrapping when there
/// are more workers than cores. Returns `None` for an empty list.
pub fn core_for_index(cores: &[usize], index: usize) -> Option<usize> {
    if cores.is_empty() {
        None
    } else {
        Some(cores[index % cores.len()])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn core_for_index_wraps() {
        assert_eq!(core_for_index(&[2, 4], 0), Some(2));
        assert_eq!(core_for_index(&[2, 4], 1), Some(4));
        assert_eq!(core_for_index(&[2, 4], 2), Some(2));
        assert_eq!(core_for_index(&[], 0), None);
    }

    #[test]
    fn available_cores_is_non_empty_and_sorted() {
        let cores = available_cores();
        assert!(!cores.is_empty());
        let mut sorted = cores.clone();
        sorted.sort_unstable();
        assert_eq!(cores, sorted);
    }

    #[test]
    fn pinning_falls_back_when_disabled() {
        // Without the feature the helper must report failure rather than panic;
        // with the feature this simply exercises the platform call.
        let _ = pin_current_thread(0);
    }
}
