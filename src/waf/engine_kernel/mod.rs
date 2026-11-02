//! Experimental native Rust evaluation kernel.
//!
//! This module is a **prototype, not the production engine**. It exists to
//! demonstrate and measure the execution model that a future Coraza
//! replacement needs:
//!
//! 1. parse the request once into zero-copy spans ([`state`]);
//! 2. cache every transform pipeline per value ([`state::Arena`]);
//! 3. evaluate a compiled DAG of cheap predicates, shared Aho-Corasick
//!    literals and precompiled regex DFAs ([`matcher`]);
//! 4. gate regex groups with the sound CRS literal prefilter ([`prefilter`]);
//! 5. accumulate CRS anomaly scores and stop as soon as the threshold is
//!    reached.
//!
//! The rule set is a hand-written slice of OWASP CRS 4.14.0 ([`rules`]). It is
//! intentionally incomplete: libinjection, multipart, XML and base64-based
//! rules are absent. See `docs/suggestions_from_agents/engine-kernel.md`.

pub mod corpus;
pub mod matcher;
pub mod prefilter;
pub mod rules;
pub mod state;
pub mod transform;

use matcher::{CompiledRules, Phase, RuleMeta};
use prefilter::Prefilter;
use state::{Arena, RequestInput};

/// CRS PL1 inbound anomaly threshold.
pub const DEFAULT_THRESHOLD: u16 = 5;

/// Kernel decision. It carries ids and scores, never a heap-allocated string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Block { rule_id: u32, phase: u8, score: u16 },
}

impl Decision {
    pub fn is_block(self) -> bool {
        matches!(self, Self::Block { .. })
    }
}

/// One evaluation result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EvalOutcome {
    pub decision: Decision,
    pub score: u16,
}

/// A compiled kernel instance. It is immutable and can be shared by all worker
/// threads; each worker owns one [`Arena`].
pub struct KernelEngine {
    compiled: CompiledRules,
    prefilter: Prefilter,
    threshold: u16,
}

impl std::fmt::Debug for KernelEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KernelEngine")
            .field("rules", &self.compiled.rule_ids.len())
            .field("pipelines", &self.compiled.pipeline_count())
            .field("literal_groups", &self.compiled.literal_groups.len())
            .field("regex_groups", &self.compiled.regex_groups.len())
            .field("gates", &self.prefilter.gate_count())
            .field("threshold", &self.threshold)
            .finish()
    }
}

impl KernelEngine {
    /// Compiles the hand-written rule set and the prefilter layer.
    pub fn new() -> Result<Self, String> {
        Self::with_threshold(DEFAULT_THRESHOLD)
    }

    /// Compiles with a custom anomaly threshold.
    pub fn with_threshold(threshold: u16) -> Result<Self, String> {
        let implemented = rules::implemented_rule_ids();
        let mut prefilter = Prefilter::build(&implemented)?;
        let extra_pipelines = prefilter.pipelines();
        let compiled = CompiledRules::compile(
            rules::RULES,
            prefilter.gate_for_rule().clone(),
            extra_pipelines,
        )?;
        prefilter.bind(&compiled.pipelines)?;
        Ok(Self {
            compiled,
            prefilter,
            threshold,
        })
    }

    /// Evaluates one request. The arena is reused across calls.
    pub fn evaluate(&self, request: &RequestInput<'_>, arena: &mut Arena) -> Decision {
        self.evaluate_outcome(request, arena).decision
    }

    /// Evaluates one request and returns the anomaly score.
    pub fn evaluate_outcome(&self, request: &RequestInput<'_>, arena: &mut Arena) -> EvalOutcome {
        arena.begin(self.compiled.pipeline_count());
        arena.parse(request);
        self.prefilter
            .scan(request, arena, &self.compiled.pipelines);

        let mut score = 0u16;
        for phase in [Phase::One, Phase::Two] {
            if let Some(rule) = self.evaluate_phase(phase, request, arena, &mut score) {
                return EvalOutcome {
                    decision: Decision::Block {
                        rule_id: rule.id,
                        phase: match phase {
                            Phase::One => 1,
                            Phase::Two => 2,
                        },
                        score,
                    },
                    score,
                };
            }
        }
        EvalOutcome {
            decision: Decision::Allow,
            score,
        }
    }

    fn evaluate_phase(
        &self,
        phase: Phase,
        request: &RequestInput<'_>,
        arena: &mut Arena,
        score: &mut u16,
    ) -> Option<RuleMeta> {
        if let Some(rule) = self.compiled.match_request_predicate(phase, request) {
            if self.accumulate(score, rule.score) {
                return Some(rule);
            }
        }
        if let Some(rule) = self.compiled.match_value_predicate(phase, request, arena) {
            if self.accumulate(score, rule.score) {
                return Some(rule);
            }
        }
        if let Some(rule) = self.compiled.match_literal_group(phase, request, arena) {
            if self.accumulate(score, rule.score) {
                return Some(rule);
            }
        }
        if let Some(rule) = self.compiled.match_regex_group(phase, request, arena) {
            if self.accumulate(score, rule.score) {
                return Some(rule);
            }
        }
        None
    }

    fn accumulate(&self, score: &mut u16, increment: u16) -> bool {
        *score = score.saturating_add(increment);
        *score >= self.threshold
    }

    /// Number of compiled rules.
    pub fn rule_count(&self) -> usize {
        self.compiled.rule_ids.len()
    }

    /// Rule ids implemented by this kernel.
    pub fn rule_ids(&self) -> &[u32] {
        &self.compiled.rule_ids
    }

    /// Number of cached transform pipelines.
    pub fn pipeline_count(&self) -> usize {
        self.compiled.pipeline_count()
    }

    /// Number of prefilter gates.
    pub fn gate_count(&self) -> usize {
        self.prefilter.gate_count()
    }
}

/// Convenience for tests and tools: evaluate one request with a fresh arena.
pub fn evaluate_once(engine: &KernelEngine, request: &RequestInput<'_>) -> Decision {
    let mut arena = Arena::new();
    engine.evaluate(request, &mut arena)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eval(
        engine: &KernelEngine,
        method: &str,
        uri: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Decision {
        let (path, query) = uri.split_once('?').unwrap_or((uri, ""));
        let request = RequestInput::new(method, path, query, headers, body);
        evaluate_once(engine, &request)
    }

    #[test]
    fn benign_request_is_allowed() {
        let engine = KernelEngine::new().expect("engine");
        let headers = [
            ("Host", "example.test"),
            ("User-Agent", "Mozilla/5.0"),
            ("Accept", "text/html"),
        ];
        assert_eq!(
            eval(&engine, "GET", "/index.html", &headers, b""),
            Decision::Allow
        );
    }

    #[test]
    fn disallowed_method_is_blocked() {
        let engine = KernelEngine::new().expect("engine");
        let headers = [("Host", "example.test")];
        assert!(eval(&engine, "DELETE", "/x", &headers, b"").is_block());
    }

    #[test]
    fn scanner_user_agent_is_blocked() {
        let engine = KernelEngine::new().expect("engine");
        let headers = [("User-Agent", "nuclei")];
        assert!(eval(&engine, "GET", "/", &headers, b"").is_block());
    }

    #[test]
    fn path_traversal_is_blocked() {
        let engine = KernelEngine::new().expect("engine");
        let headers = [("Host", "example.test")];
        assert!(eval(
            &engine,
            "GET",
            "/download?file=../../etc/passwd",
            &headers,
            b""
        )
        .is_block());
    }

    #[test]
    fn xss_and_sqli_are_blocked() {
        let engine = KernelEngine::new().expect("engine");
        let headers = [("Content-Type", "application/x-www-form-urlencoded")];
        assert!(eval(
            &engine,
            "POST",
            "/comment",
            &headers,
            b"c=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
        )
        .is_block());
        assert!(eval(
            &engine,
            "POST",
            "/login",
            &headers,
            b"q=information_schema.tables"
        )
        .is_block());
    }

    #[test]
    fn json_sql_injection_in_path_is_blocked() {
        let engine = KernelEngine::new().expect("engine");
        let headers = [("Host", "localhost")];
        let uri = "/get/OR%20%27%7B%22b%22%3A2%7D%27%3A%3Ajsonb%20%3C%40%20%27%7B%22a%22%3A1%2C%20%22b%22%3A2%7D%27%3A%3Ajsonb";
        let decision = eval(&engine, "GET", uri, &headers, b"");
        println!("json sqli decision: {decision:?}");
        assert!(decision.is_block());
    }

    #[test]
    fn java_class_is_blocked() {
        let engine = KernelEngine::new().expect("engine");
        let headers = [("Content-Type", "application/x-www-form-urlencoded")];
        assert!(eval(&engine, "POST", "/", &headers, b"x=java.lang.Runtime").is_block());
    }

    #[test]
    fn transform_cache_is_shared_per_value() {
        let engine = KernelEngine::new().expect("engine");
        let headers = [("Content-Type", "application/x-www-form-urlencoded")];
        let request = RequestInput::new("POST", "/", "", &headers, b"a=%3Cscript%3E");
        let mut arena = Arena::new();
        let first = engine.evaluate(&request, &mut arena);
        let second = engine.evaluate(&request, &mut arena);
        assert_eq!(first, second);
        assert!(first.is_block());
    }
}
