//! Experimental per-argument parallelism for the native CRS engine.
//!
//! This module is compiled only with the non-default `parallel-args` feature
//! and is **not** part of the default request path. It provides the execution
//! scaffolding for evaluating the candidates of one `ARGS`-shaped rule on a
//! small scoped thread set while preserving serial semantics:
//!
//! * every candidate is evaluated independently and produces an immutable
//!   [`super::engine`] outcome;
//! * results are reduced in candidate order, so captures, `MATCHED_VARS`
//!   bookkeeping, anomaly score updates and `setvar` actions run in exactly
//!   the same order as the serial loop;
//! * the caller validates that a rule is *candidate-local* before using the
//!   parallel path (see `RustEngine::candidate_local`), so no candidate can
//!   observe an action applied by an earlier candidate.
//!
//! Worker panics are converted to [`EngineError::Internal`] so the caller
//! blocks the request. Release builds use `panic = "abort"`, where a panic
//! terminates the process instead of allowing the request through.
//!
//! The thread set is scoped to one call. This prototype is used to measure the
//! ceiling of the model; a production version would replace [`map_ordered`]
//! with a bounded process-wide worker pool. See
//! `docs/design/parallel-args.md`.

use std::panic::AssertUnwindSafe;

use super::error::EngineError;

/// Configuration for the experimental parallel ARGS path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArgsParallelConfig {
    /// Maximum worker threads per evaluation (including the calling thread's
    /// share of the work).
    pub threads: usize,
    /// Minimum number of resolved candidates before the path is considered.
    pub min_candidates: usize,
}

impl Default for ArgsParallelConfig {
    fn default() -> Self {
        Self {
            threads: default_threads(),
            min_candidates: 8,
        }
    }
}

impl ArgsParallelConfig {
    /// Returns true when the path can run at all.
    pub fn enabled(&self) -> bool {
        self.threads > 1
    }

    /// True when `count` candidates are enough to amortise the thread set.
    pub fn applies(&self, count: usize) -> bool {
        self.enabled() && count >= self.min_candidates
    }
}

/// Worker count bounded by the process CPU count minus the reactor's share,
/// never more than four. The default is deliberately conservative so the
/// prototype cannot oversubscribe a reactor pool.
pub fn default_threads() -> usize {
    let available = std::thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(1);
    // Leave at least one core for the reactor/proxy and cap the fan-out.
    available.saturating_sub(1).clamp(1, 4)
}

/// Evaluates `f` for every index in `0..count` and returns the results in
/// index order, regardless of which worker produced them.
///
/// This is the deterministic reduction primitive: thread scheduling cannot
/// reorder results, and a worker failure is reported at its candidate index.
pub(crate) fn map_ordered<T, F>(count: usize, threads: usize, f: F) -> Vec<Result<T, EngineError>>
where
    T: Send,
    F: Fn(usize) -> Result<T, EngineError> + Sync,
{
    if count == 0 {
        return Vec::new();
    }
    let threads = threads.clamp(1, count);
    if threads == 1 {
        return (0..count).map(|index| catch_worker(|| f(index))).collect();
    }

    let chunk = count.div_ceil(threads);
    let mut slots: Vec<Option<Result<T, EngineError>>> = (0..count).map(|_| None).collect();
    std::thread::scope(|scope| {
        for (chunk_index, window) in slots.chunks_mut(chunk).enumerate() {
            let worker = &f;
            let base = chunk_index * chunk;
            scope.spawn(move || {
                for (offset, slot) in window.iter_mut().enumerate() {
                    let index = base + offset;
                    *slot = Some(catch_worker(|| worker(index)));
                }
            });
        }
    });

    slots
        .into_iter()
        .map(|slot| slot.unwrap_or(Err(EngineError::Internal("parallel worker lost a slot"))))
        .collect()
}

fn catch_worker<T, F>(f: F) -> Result<T, EngineError>
where
    F: FnOnce() -> Result<T, EngineError>,
{
    match std::panic::catch_unwind(AssertUnwindSafe(f)) {
        Ok(result) => result,
        Err(_) => Err(EngineError::Internal("parallel worker panicked")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_ordered_preserves_index_order() {
        let values = map_ordered(100, 4, |index| Ok(index * 2));
        let values: Vec<usize> = values.into_iter().map(Result::unwrap).collect();
        assert_eq!(values, (0..100).map(|index| index * 2).collect::<Vec<_>>());
    }

    #[test]
    fn map_ordered_reports_failure_at_its_index() {
        let results = map_ordered(16, 4, |index| {
            if index == 7 {
                Err(EngineError::Budget("test"))
            } else {
                Ok(index)
            }
        });
        assert!(results[0].is_ok());
        assert!(results[7].is_err());
        assert!(results[15].is_ok());
    }

    #[test]
    fn map_ordered_single_thread_is_serial() {
        let values = map_ordered(8, 1, |index| Ok(index));
        assert_eq!(
            values.into_iter().map(Result::unwrap).collect::<Vec<_>>(),
            (0..8).collect::<Vec<_>>()
        );
    }
}
