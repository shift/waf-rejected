//! Hot-loop instrumentation for the native CRS engine.
//!
//! Non-default (`engine-profile`) and compiled out otherwise. The profiler is
//! thread-local and allocation-free; a counting allocator in the benchmark
//! binary increments [`ALLOCATIONS`] so every category reports both time and
//! allocation events. See `docs/design/engine-hotloop.md`.
//!
//! Production builds do not enable this feature and contain no timers in the
//! request path.

use std::cell::RefCell;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

/// Allocation events observed by the benchmark's counting allocator.
pub static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

/// One measured hot-loop category.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    Parse,
    Transforms,
    Candidates,
    Gate,
    Operators,
    Scoring,
    Captures,
    Tx,
    MatchedVars,
}

const CATEGORIES: usize = 9;

/// Per-request profile, normalised to one request by the caller.
#[derive(Debug, Clone, Default)]
pub struct Report {
    pub parse_ns: u64,
    pub transforms_ns: u64,
    pub candidates_ns: u64,
    pub gate_ns: u64,
    pub operators_ns: u64,
    pub scoring_ns: u64,
    pub captures_ns: u64,
    pub tx_ns: u64,
    pub matched_ns: u64,
    pub parse_allocs: u64,
    pub transforms_allocs: u64,
    pub candidates_allocs: u64,
    pub gate_allocs: u64,
    pub operators_allocs: u64,
    pub scoring_allocs: u64,
    pub captures_allocs: u64,
    pub tx_allocs: u64,
    pub matched_allocs: u64,
    pub regex_evaluations: u64,
    pub regex_skipped: u64,
    /// Operator time attributed to each rule id, descending. Evaluations with
    /// no rule id are reported under `u32::MAX`. Diagnostics only.
    pub rule_ns: Vec<(u32, u64)>,
    /// Operator evaluation count per rule id (`u32::MAX` = no id).
    pub rule_runs: Vec<(u32, u64)>,
    /// All allocation events between `begin` and `finish`, including work not
    /// attributed to a category (rule scaffolding, match bookkeeping).
    pub total_allocs: u64,
}

#[derive(Default)]
struct State {
    active: bool,
    start_allocs: usize,
    ns: [u64; CATEGORIES],
    allocs: [u64; CATEGORIES],
    regex_evaluations: u64,
    regex_skipped: u64,
    rule_ns: Vec<(u32, u64)>,
    rule_runs: Vec<(u32, u64)>,
}

thread_local! {
    static STATE: RefCell<State> = RefCell::new(State::default());
}

/// Allocation counter value, used for per-category deltas.
#[inline]
pub fn allocations() -> usize {
    ALLOCATIONS.load(Ordering::Relaxed)
}

/// Starts a profile. Nested calls are ignored.
pub fn begin() {
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        *state = State {
            active: true,
            start_allocs: allocations(),
            ..State::default()
        };
    });
}

/// Stops a profile and returns the accumulated counters.
pub fn finish() -> Report {
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.active = false;
        Report {
            parse_ns: state.ns[Category::Parse as usize],
            transforms_ns: state.ns[Category::Transforms as usize],
            candidates_ns: state.ns[Category::Candidates as usize],
            gate_ns: state.ns[Category::Gate as usize],
            operators_ns: state.ns[Category::Operators as usize],
            scoring_ns: state.ns[Category::Scoring as usize],
            captures_ns: state.ns[Category::Captures as usize],
            tx_ns: state.ns[Category::Tx as usize],
            matched_ns: state.ns[Category::MatchedVars as usize],
            parse_allocs: state.allocs[Category::Parse as usize],
            transforms_allocs: state.allocs[Category::Transforms as usize],
            candidates_allocs: state.allocs[Category::Candidates as usize],
            gate_allocs: state.allocs[Category::Gate as usize],
            operators_allocs: state.allocs[Category::Operators as usize],
            scoring_allocs: state.allocs[Category::Scoring as usize],
            captures_allocs: state.allocs[Category::Captures as usize],
            tx_allocs: state.allocs[Category::Tx as usize],
            matched_allocs: state.allocs[Category::MatchedVars as usize],
            regex_evaluations: state.regex_evaluations,
            regex_skipped: state.regex_skipped,
            rule_ns: {
                let mut rules = state.rule_ns.clone();
                rules.sort_unstable_by(|a, b| b.1.cmp(&a.1));
                rules
            },
            rule_runs: state.rule_runs.clone(),
            total_allocs: allocations().saturating_sub(state.start_allocs) as u64,
        }
        .normalize()
    })
}

impl Report {
    /// Sorts per-rule diagnostics so callers can print a stable top list.
    fn normalize(mut self) -> Self {
        self.rule_runs.sort_unstable_by(|a, b| b.1.cmp(&a.1));
        self
    }
}

/// Records elapsed time and allocation events for one category.
#[inline]
pub fn record(category: Category, started: Instant, allocations_before: usize) {
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        if !state.active {
            return;
        }
        state.ns[category as usize] += started.elapsed().as_nanos() as u64;
        state.allocs[category as usize] += ALLOCATIONS
            .load(Ordering::Relaxed)
            .saturating_sub(allocations_before) as u64;
    });
}

/// Records one executed regex.
#[inline]
pub fn regex_run() {
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        if state.active {
            state.regex_evaluations += 1;
        }
    });
}

/// Records one regex skipped by a mandatory-literal gate.
#[inline]
pub fn regex_skip() {
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        if state.active {
            state.regex_skipped += 1;
        }
    });
}

/// Attributes one operator execution to a rule id (diagnostics only).
#[inline]
pub fn record_rule(rule_id: Option<u32>, elapsed: std::time::Duration) {
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        if !state.active {
            return;
        }
        let id = rule_id.unwrap_or(u32::MAX);
        let ns = elapsed.as_nanos() as u64;
        if let Some((_, total)) = state.rule_ns.iter_mut().find(|(rule, _)| *rule == id) {
            *total += ns;
        } else {
            state.rule_ns.push((id, ns));
        }
        if let Some((_, runs)) = state.rule_runs.iter_mut().find(|(rule, _)| *rule == id) {
            *runs += 1;
        } else {
            state.rule_runs.push((id, 1));
        }
    });
}

/// Convenience: a timestamp plus allocation baseline for one category.
#[inline]
pub fn sample() -> (Instant, usize) {
    (Instant::now(), allocations())
}
