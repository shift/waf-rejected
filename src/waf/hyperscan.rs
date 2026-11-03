//! Experimental Vectorscan/Hyperscan multi-pattern scanner.
//!
//! This module is a deliberately small, hand-written FFI surface over
//! `libhs` (Vectorscan on x86-64, Hyperscan-compatible API). It exists to
//! evaluate whether a multi-pattern hardware-accelerated matcher can replace
//! the per-group Aho-Corasick passes in the experimental CRS prefilter.
//!
//! It is **not** part of the default build. Enable it with
//! `--features hyperscan-eval`, which also enables the `crs-prefilter`
//! artifact/transform machinery this scanner consumes. The system library is
//! provided by `nixpkgs#vectorscan`; see
//! `docs/suggestions_from_agents/hyperscan-evaluation.md`.
//!
//! Design constraints:
//!
//! * Block mode only. CRS bodies are bounded (`--max-body 1 MiB`), so a
//!   one-shot scan is the right primitive.
//! * One scratch region per scanner; [`HsScanner`] is `Send` but not `Sync`.
//! * Literals are escaped before compilation, so a literal that contains a
//!   regex metacharacter is still matched literally.
//! * Matching is boolean-first: the callback terminates on the first match.
//!   The returned rule ids are diagnostic, not a complete match set.

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_uint, c_void};
use std::ptr;
use std::sync::{Arc, Mutex};

/// `HS_SUCCESS`.
const HS_SUCCESS: c_int = 0;
/// `HS_SCAN_TERMINATED`.
const HS_SCAN_TERMINATED: c_int = -3;
/// `HS_MODE_BLOCK`.
const HS_MODE_BLOCK: c_uint = 1;
/// `HS_FLAG_CASELESS`.
const HS_FLAG_CASELESS: c_uint = 1;
/// `HS_FLAG_DOTALL` (`.` matches newline, mirroring `(?s)`).
const HS_FLAG_DOTALL: c_uint = 2;
/// `HS_FLAG_MULTILINE` (anchors match at line boundaries, mirroring `(?m)`).
const HS_FLAG_MULTILINE: c_uint = 4;
/// `HS_FLAG_SINGLEMATCH`.
const HS_FLAG_SINGLEMATCH: c_uint = 8;

#[repr(C)]
struct HsDatabase {
    _private: [u8; 0],
}

#[repr(C)]
struct HsScratch {
    _private: [u8; 0],
}

#[repr(C)]
struct HsPlatformInfo {
    _private: [u8; 0],
}

#[repr(C)]
struct HsCompileError {
    message: *mut c_char,
    expression: c_int,
}

type MatchEventHandler = unsafe extern "C" fn(
    id: c_uint,
    from: u64,
    to: u64,
    flags: c_uint,
    context: *mut c_void,
) -> c_int;

#[link(name = "hs")]
extern "C" {
    fn hs_version() -> *const c_char;
    fn hs_valid_platform() -> c_int;
    fn hs_compile_multi(
        expressions: *const *const c_char,
        flags: *const c_uint,
        ids: *const c_uint,
        elements: c_uint,
        mode: c_uint,
        platform: *const HsPlatformInfo,
        db: *mut *mut HsDatabase,
        error: *mut *mut HsCompileError,
    ) -> c_int;
    fn hs_free_compile_error(error: *mut HsCompileError) -> c_int;
    fn hs_alloc_scratch(db: *const HsDatabase, scratch: *mut *mut HsScratch) -> c_int;
    fn hs_free_scratch(scratch: *mut HsScratch) -> c_int;
    fn hs_free_database(db: *mut HsDatabase) -> c_int;
    fn hs_database_size(db: *const HsDatabase, size: *mut usize) -> c_int;
    fn hs_scan(
        db: *const HsDatabase,
        data: *const c_char,
        length: c_uint,
        flags: c_uint,
        scratch: *mut HsScratch,
        on_event: Option<MatchEventHandler>,
        context: *mut c_void,
    ) -> c_int;
}

/// One literal and the CRS rules that require it.
#[derive(Debug, Clone)]
pub struct LiteralPattern {
    /// The literal bytes, as UTF-8 text. Regex metacharacters are escaped at
    /// compile time.
    pub literal: String,
    /// Match ASCII case-insensitively (`HS_FLAG_CASELESS`).
    pub caseless: bool,
    /// Rule ids that share this literal.
    pub rule_ids: Vec<u32>,
}

/// One regular expression and the rules that share it.
///
/// Unlike [`LiteralPattern`] the expression is passed to the compiler
/// verbatim. Callers must only supply patterns that are exactly representable
/// for the intended match direction; compilation failures are reported per
/// expression so a caller can drop the pattern and keep the rule on the
/// existing path. Expressions are compiled in exact (non-prefilter) mode;
/// callers are responsible for excluding constructs whose byte semantics could
/// differ from the reference engine.
#[derive(Debug, Clone)]
pub struct RegexPattern {
    /// PCRE-syntax expression (no delimiters).
    pub expression: String,
    /// Match ASCII case-insensitively (`HS_FLAG_CASELESS`).
    pub caseless: bool,
    /// Mirror `(?s)`: `.` also matches a newline.
    pub dotall: bool,
    /// Mirror `(?m)`: `^`/`$` also match at line boundaries.
    pub multiline: bool,
    /// Rule ids that share this expression.
    pub rule_ids: Vec<u32>,
}

/// Result of one block scan.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HsMatch {
    /// True when at least one pattern matched.
    pub hit: bool,
    /// Rule ids reached through the first matching pattern (diagnostic).
    pub matched_rule_ids: Vec<u32>,
}

/// Errors returned by the scanner.
#[derive(Debug, thiserror::Error)]
pub enum HsError {
    #[error("vectorscan rejected literal {index}: {message}")]
    Compile { index: usize, message: String },
    #[error("vectorscan compile failed: {0}")]
    CompileGeneral(String),
    #[error("vectorscan runtime error {0}")]
    Runtime(c_int),
    #[error("literal contains an interior NUL byte: {0:?}")]
    InteriorNul(String),
    #[error("vectorscan platform check failed: this CPU is not supported")]
    UnsupportedPlatform,
    #[error("body length {0} exceeds the vectorscan block API limit")]
    BodyTooLarge(usize),
}

/// A compiled block-mode database and its scratch region.
///
/// This is the single-threaded convenience type used by the evaluation
/// benchmark. Production callers should use [`SharedHsDatabase`], which shares
/// the compiled database across threads and pools scratch regions.
pub struct HsScanner {
    db: *mut HsDatabase,
    scratch: *mut HsScratch,
    /// Pattern index -> rule ids. Indexed by the `id` passed to
    /// `hs_compile_multi`, which is the pattern's position.
    pattern_rules: Vec<Vec<u32>>,
}

// The database and scratch are heap allocations owned by this value. Hyperscan
// explicitly permits a database to be shared across threads, but a scratch
// region must not be used concurrently. We therefore expose `Send` only.
unsafe impl Send for HsScanner {}

impl Drop for HsScanner {
    fn drop(&mut self) {
        unsafe {
            if !self.scratch.is_null() {
                hs_free_scratch(self.scratch);
            }
            if !self.db.is_null() {
                hs_free_database(self.db);
            }
        }
    }
}

/// Owned, reference-counted Hyperscan database.
///
/// Hyperscan documents that a compiled database is immutable and may be used
/// concurrently from multiple threads. The scratch region is the only mutable
/// state, so it is pooled separately in [`SharedHsDatabase`].
struct DatabaseHandle {
    db: *mut HsDatabase,
}

// SAFETY: the database is immutable after compilation and Hyperscan permits
// concurrent `hs_scan` calls against one database.
unsafe impl Send for DatabaseHandle {}
unsafe impl Sync for DatabaseHandle {}

impl Drop for DatabaseHandle {
    fn drop(&mut self) {
        unsafe {
            if !self.db.is_null() {
                hs_free_database(self.db);
            }
        }
    }
}

/// Owned scratch region. Not `Sync`: a scratch region must not be used by two
/// scans at once. The pool hands it to exactly one caller at a time.
struct ScratchHandle {
    scratch: *mut HsScratch,
}

unsafe impl Send for ScratchHandle {}

impl Drop for ScratchHandle {
    fn drop(&mut self) {
        unsafe {
            if !self.scratch.is_null() {
                hs_free_scratch(self.scratch);
            }
        }
    }
}

/// A process-shareable compiled database with a bounded scratch pool.
///
/// The database is compiled once and wrapped in an `Arc`; every scan borrows a
/// scratch region from the pool, so concurrent workers do not serialise on the
/// matcher itself. The pool is capped so a burst of threads cannot grow memory
/// without bound; excess scratches are dropped when returned.
pub struct SharedHsDatabase {
    // Field order matters: the pool (scratch regions) must drop before the
    // database they were allocated against.
    pool: Mutex<Vec<ScratchHandle>>,
    pattern_rules: Vec<Vec<u32>>,
    db: Arc<DatabaseHandle>,
}

// SAFETY: the database is immutable and shared; the pool is a `Mutex`.
unsafe impl Send for SharedHsDatabase {}
unsafe impl Sync for SharedHsDatabase {}

/// Maximum number of idle scratch regions kept per database.
const MAX_POOLED_SCRATCH: usize = 64;

impl SharedHsDatabase {
    /// Compiles a database once. The returned value is cheap to share via
    /// `Arc` and safe to scan from multiple threads.
    pub fn compile(patterns: &[LiteralPattern]) -> Result<Self, HsError> {
        let raw = compile_raw(patterns)?;
        Ok(Self::from_raw(
            raw,
            patterns.iter().map(|p| p.rule_ids.clone()),
        ))
    }

    /// Compiles a regex database in over-approximate (`HS_FLAG_PREFILTER`)
    /// mode. Every expression is compiled exactly as supplied; on failure the
    /// error carries the offending index so the caller can drop that pattern
    /// and retry without losing the rest of the group.
    pub fn compile_regex(patterns: &[RegexPattern]) -> Result<Self, HsError> {
        let expressions: Vec<(String, c_uint)> = patterns
            .iter()
            .map(|pattern| {
                let mut flags = HS_FLAG_SINGLEMATCH;
                if pattern.caseless {
                    flags |= HS_FLAG_CASELESS;
                }
                if pattern.dotall {
                    flags |= HS_FLAG_DOTALL;
                }
                if pattern.multiline {
                    flags |= HS_FLAG_MULTILINE;
                }
                (pattern.expression.clone(), flags)
            })
            .collect();
        let refs: Vec<(&str, c_uint)> = expressions
            .iter()
            .map(|(expression, flags)| (expression.as_str(), *flags))
            .collect();
        let raw = compile_expressions(&refs)?;
        Ok(Self::from_raw(
            raw,
            patterns.iter().map(|p| p.rule_ids.clone()),
        ))
    }

    fn from_raw(raw: RawCompiled, pattern_rules: impl IntoIterator<Item = Vec<u32>>) -> Self {
        let db = Arc::new(DatabaseHandle { db: raw.db });
        let pool = Mutex::new(vec![ScratchHandle {
            scratch: raw.scratch,
        }]);
        let pattern_rules: Vec<Vec<u32>> = pattern_rules.into_iter().collect();
        Self {
            pool,
            pattern_rules,
            db,
        }
    }

    fn take_scratch(&self) -> Result<ScratchHandle, HsError> {
        if let Ok(mut pool) = self.pool.lock() {
            if let Some(scratch) = pool.pop() {
                return Ok(scratch);
            }
        }
        let mut scratch: *mut HsScratch = ptr::null_mut();
        let rc = unsafe { hs_alloc_scratch(self.db.db, &mut scratch) };
        if rc != HS_SUCCESS {
            return Err(HsError::Runtime(rc));
        }
        Ok(ScratchHandle { scratch })
    }

    fn return_scratch(&self, scratch: ScratchHandle) {
        let mut scratch = Some(scratch);
        if let Ok(mut pool) = self.pool.lock() {
            if pool.len() < MAX_POOLED_SCRATCH {
                if let Some(scratch) = scratch.take() {
                    pool.push(scratch);
                }
            }
        }
        // `scratch` is dropped here when the pool is full.
    }

    /// Scans one body. When `first_only` is true the callback terminates on the
    /// first match (boolean prefilter); otherwise every matching pattern is
    /// reported so per-rule removal stays sound.
    pub fn scan(&self, body: &[u8], first_only: bool) -> Result<HsMatch, HsError> {
        if body.len() > c_uint::MAX as usize {
            return Err(HsError::BodyTooLarge(body.len()));
        }
        let scratch = self.take_scratch()?;
        let mut context = ScanContext {
            pattern_rules: &self.pattern_rules,
            hit: false,
            first_only,
            matched_rule_ids: Vec::new(),
        };
        let rc = unsafe {
            hs_scan(
                self.db.db,
                body.as_ptr() as *const c_char,
                body.len() as c_uint,
                0,
                scratch.scratch,
                Some(on_match),
                &mut context as *mut ScanContext<'_> as *mut c_void,
            )
        };
        self.return_scratch(scratch);
        if rc != HS_SUCCESS && rc != HS_SCAN_TERMINATED {
            return Err(HsError::Runtime(rc));
        }
        context.matched_rule_ids.sort_unstable();
        context.matched_rule_ids.dedup();
        Ok(HsMatch {
            hit: context.hit,
            matched_rule_ids: context.matched_rule_ids,
        })
    }

    /// Scans one body and visits every rule id reached by a matching pattern.
    ///
    /// Allocation-free: the caller accumulates into its own bitset. Returns
    /// `true` when at least one pattern matched. Any runtime error must be
    /// treated by the caller as "unknown" and must not suppress a rule.
    pub fn scan_visit<F>(&self, body: &[u8], visit: F) -> Result<bool, HsError>
    where
        F: FnMut(u32),
    {
        if body.len() > c_uint::MAX as usize {
            return Err(HsError::BodyTooLarge(body.len()));
        }
        let scratch = self.take_scratch()?;
        let mut context = VisitContext {
            pattern_rules: &self.pattern_rules,
            hit: false,
            visit,
        };
        let rc = unsafe {
            hs_scan(
                self.db.db,
                body.as_ptr() as *const c_char,
                body.len() as c_uint,
                0,
                scratch.scratch,
                Some(on_visit::<F>),
                &mut context as *mut VisitContext<'_, F> as *mut c_void,
            )
        };
        self.return_scratch(scratch);
        if rc != HS_SUCCESS && rc != HS_SCAN_TERMINATED {
            return Err(HsError::Runtime(rc));
        }
        Ok(context.hit)
    }

    /// Number of compiled patterns.
    pub fn pattern_count(&self) -> usize {
        self.pattern_rules.len()
    }

    /// Size of the compiled database in bytes, if the library reports it.
    pub fn database_size(&self) -> Option<usize> {
        let mut size = 0usize;
        let rc = unsafe { hs_database_size(self.db.db, &mut size) };
        (rc == HS_SUCCESS).then_some(size)
    }
}

struct VisitContext<'a, F> {
    pattern_rules: &'a [Vec<u32>],
    hit: bool,
    visit: F,
}

unsafe extern "C" fn on_visit<F>(
    id: c_uint,
    _from: u64,
    _to: u64,
    _flags: c_uint,
    context: *mut c_void,
) -> c_int
where
    F: FnMut(u32),
{
    let context = &mut *(context as *mut VisitContext<'_, F>);
    context.hit = true;
    if let Some(rules) = context.pattern_rules.get(id as usize) {
        for rule in rules {
            (context.visit)(*rule);
        }
    }
    0
}

struct RawCompiled {
    db: *mut HsDatabase,
    scratch: *mut HsScratch,
}

/// Compiles a block-mode database from literal patterns.
fn compile_raw(patterns: &[LiteralPattern]) -> Result<RawCompiled, HsError> {
    let escaped: Vec<String> = patterns
        .iter()
        .map(|pattern| escape_literal(&pattern.literal))
        .collect();
    let expressions: Vec<(&str, c_uint)> = patterns
        .iter()
        .zip(escaped.iter())
        .map(|(pattern, expression)| {
            let mut flags = HS_FLAG_SINGLEMATCH;
            if pattern.caseless {
                flags |= HS_FLAG_CASELESS;
            }
            (expression.as_str(), flags)
        })
        .collect();
    compile_expressions(&expressions)
}

/// Compiles a block-mode database and allocates one scratch region.
fn compile_expressions(expressions: &[(&str, c_uint)]) -> Result<RawCompiled, HsError> {
    if expressions.is_empty() {
        return Err(HsError::CompileGeneral("empty pattern set".to_string()));
    }
    if unsafe { hs_valid_platform() } != HS_SUCCESS {
        return Err(HsError::UnsupportedPlatform);
    }

    let mut pointers = Vec::with_capacity(expressions.len());
    let mut cstrings = Vec::with_capacity(expressions.len());
    let mut flags = Vec::with_capacity(expressions.len());
    let mut ids = Vec::with_capacity(expressions.len());
    for (index, (expression, flag)) in expressions.iter().enumerate() {
        let cstring = CString::new(*expression)
            .map_err(|_| HsError::InteriorNul((*expression).to_string()))?;
        pointers.push(cstring.as_ptr());
        cstrings.push(cstring);
        flags.push(*flag);
        ids.push(index as c_uint);
    }

    let mut db: *mut HsDatabase = ptr::null_mut();
    let mut error: *mut HsCompileError = ptr::null_mut();
    let rc = unsafe {
        hs_compile_multi(
            pointers.as_ptr(),
            flags.as_ptr(),
            ids.as_ptr(),
            expressions.len() as c_uint,
            HS_MODE_BLOCK,
            ptr::null(),
            &mut db,
            &mut error,
        )
    };

    if rc != HS_SUCCESS {
        let (index, message) = if error.is_null() {
            (usize::MAX, format!("hs_compile_multi returned {rc}"))
        } else {
            let message = unsafe {
                if (*error).message.is_null() {
                    "unknown compile error".to_string()
                } else {
                    CStr::from_ptr((*error).message)
                        .to_string_lossy()
                        .into_owned()
                }
            };
            let index = unsafe { (*error).expression };
            unsafe {
                hs_free_compile_error(error);
            }
            (
                if index < 0 {
                    usize::MAX
                } else {
                    index as usize
                },
                message,
            )
        };
        if index == usize::MAX {
            return Err(HsError::CompileGeneral(message));
        }
        return Err(HsError::Compile { index, message });
    }

    let mut scratch: *mut HsScratch = ptr::null_mut();
    let rc = unsafe { hs_alloc_scratch(db, &mut scratch) };
    if rc != HS_SUCCESS {
        unsafe {
            hs_free_database(db);
        }
        return Err(HsError::Runtime(rc));
    }

    // Keep the CString allocations alive until after compilation. The
    // compiler copies the expressions, so they can be dropped here.
    drop(cstrings);

    Ok(RawCompiled { db, scratch })
}

struct ScanContext<'a> {
    pattern_rules: &'a [Vec<u32>],
    hit: bool,
    first_only: bool,
    matched_rule_ids: Vec<u32>,
}

unsafe extern "C" fn on_match(
    id: c_uint,
    _from: u64,
    _to: u64,
    _flags: c_uint,
    context: *mut c_void,
) -> c_int {
    // `context` always points at a live `ScanContext` for the duration of
    // `hs_scan`. Boolean callers terminate on the first hit; removal callers
    // keep scanning so every matching rule is reported.
    let context = &mut *(context as *mut ScanContext<'_>);
    context.hit = true;
    if let Some(rules) = context.pattern_rules.get(id as usize) {
        context.matched_rule_ids.extend_from_slice(rules);
    }
    if context.first_only {
        1
    } else {
        0
    }
}

/// Vectorscan runtime version, for diagnostics.
pub fn version() -> String {
    unsafe {
        let ptr = hs_version();
        if ptr.is_null() {
            return "unknown".to_string();
        }
        CStr::from_ptr(ptr).to_string_lossy().into_owned()
    }
}

/// Escape PCRE metacharacters so a literal is compiled as a literal.
fn escape_literal(literal: &str) -> String {
    let mut escaped = String::with_capacity(literal.len());
    for ch in literal.chars() {
        if matches!(
            ch,
            '\\' | '.' | '^' | '$' | '*' | '+' | '?' | '(' | ')' | '[' | ']' | '{' | '}' | '|'
        ) {
            escaped.push('\\');
        }
        escaped.push(ch);
    }
    escaped
}

impl HsScanner {
    /// Compile a block-mode database from literals.
    ///
    /// An empty pattern list is rejected because Hyperscan has nothing to
    /// compile; callers should skip groups without literals.
    pub fn compile(patterns: &[LiteralPattern]) -> Result<Self, HsError> {
        let raw = compile_raw(patterns)?;
        Ok(Self {
            db: raw.db,
            scratch: raw.scratch,
            pattern_rules: patterns.iter().map(|p| p.rule_ids.clone()).collect(),
        })
    }

    /// Scan one body. Returns on the first match.
    pub fn scan(&self, body: &[u8]) -> Result<HsMatch, HsError> {
        if body.len() > c_uint::MAX as usize {
            return Err(HsError::BodyTooLarge(body.len()));
        }
        let mut context = ScanContext {
            pattern_rules: &self.pattern_rules,
            hit: false,
            first_only: true,
            matched_rule_ids: Vec::new(),
        };
        let rc = unsafe {
            hs_scan(
                self.db,
                body.as_ptr() as *const c_char,
                body.len() as c_uint,
                0,
                self.scratch,
                Some(on_match),
                &mut context as *mut ScanContext<'_> as *mut c_void,
            )
        };
        if rc != HS_SUCCESS && rc != HS_SCAN_TERMINATED {
            return Err(HsError::Runtime(rc));
        }
        context.matched_rule_ids.sort_unstable();
        context.matched_rule_ids.dedup();
        Ok(HsMatch {
            hit: context.hit,
            matched_rule_ids: context.matched_rule_ids,
        })
    }

    /// Number of compiled patterns.
    pub fn pattern_count(&self) -> usize {
        self.pattern_rules.len()
    }

    /// Size of the compiled database in bytes, if the library reports it.
    pub fn database_size(&self) -> Option<usize> {
        let mut size = 0usize;
        let rc = unsafe { hs_database_size(self.db, &mut size) };
        (rc == HS_SUCCESS).then_some(size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn patterns(literals: &[(&str, bool, u32)]) -> Vec<LiteralPattern> {
        literals
            .iter()
            .map(|(literal, caseless, rule)| LiteralPattern {
                literal: (*literal).to_string(),
                caseless: *caseless,
                rule_ids: vec![*rule],
            })
            .collect()
    }

    #[test]
    fn shared_database_matches_literals() {
        let db = SharedHsDatabase::compile(&patterns(&[
            ("select", true, 942100),
            ("<script", false, 941100),
        ]))
        .expect("compile");
        assert_eq!(db.pattern_count(), 2);
        assert!(db.database_size().is_some());

        assert!(db.scan(b"q=1 SELECT password", true).expect("scan").hit);
        assert!(db.scan(b"x=<script>", true).expect("scan").hit);
        assert!(!db.scan(b"name=alice", true).expect("scan").hit);
        // Empty input is a no-op, not an error.
        assert!(!db.scan(b"", true).expect("scan").hit);
    }

    #[test]
    fn shared_database_reports_all_matches_when_requested() {
        let db = SharedHsDatabase::compile(&patterns(&[
            ("select", true, 942100),
            ("union", true, 942101),
        ]))
        .expect("compile");
        let first = db.scan(b"union select", true).expect("scan");
        assert!(first.hit);
        assert_eq!(first.matched_rule_ids.len(), 1);

        let all = db.scan(b"union select", false).expect("scan");
        assert!(all.hit);
        assert_eq!(all.matched_rule_ids, vec![942100, 942101]);
    }

    #[test]
    fn shared_database_handles_unicode_and_large_input() {
        let db = SharedHsDatabase::compile(&patterns(&[("café", false, 1)])).expect("compile");
        assert!(db.scan("café".as_bytes(), true).expect("scan").hit);
        assert!(!db.scan("cafe".as_bytes(), true).expect("scan").hit);

        let large = vec![b'z'; 1024 * 1024];
        assert!(!db.scan(&large, true).expect("scan").hit);
    }

    #[test]
    fn shared_database_is_safe_to_scan_from_multiple_threads() {
        let db = Arc::new(
            SharedHsDatabase::compile(&patterns(&[("select", true, 942100)])).expect("compile"),
        );
        let mut handles = Vec::new();
        for _ in 0..4 {
            let db = Arc::clone(&db);
            handles.push(std::thread::spawn(move || {
                for _ in 0..64 {
                    assert!(db.scan(b"SELECT 1", true).expect("scan").hit);
                    assert!(!db.scan(b"benign", true).expect("scan").hit);
                }
            }));
        }
        for handle in handles {
            handle.join().expect("thread");
        }
    }

    #[test]
    fn empty_pattern_set_is_rejected() {
        assert!(SharedHsDatabase::compile(&[]).is_err());
    }

    #[test]
    fn regex_database_scan_visits_every_hit() {
        let patterns = vec![
            RegexPattern {
                expression: r"union\s+select".to_string(),
                caseless: true,
                dotall: true,
                multiline: true,
                rule_ids: vec![1],
            },
            RegexPattern {
                expression: r"<script".to_string(),
                caseless: true,
                dotall: true,
                multiline: true,
                rule_ids: vec![2],
            },
        ];
        let db = SharedHsDatabase::compile_regex(&patterns).expect("compile");
        let mut hits = Vec::new();
        assert!(db
            .scan_visit(b"id=1 UNION SELECT x", |rule| hits.push(rule))
            .expect("scan"));
        assert_eq!(hits, vec![1]);
        let mut hits = Vec::new();
        db.scan_visit(b"<SCRIPT>alert(1)</SCRIPT>", |rule| hits.push(rule))
            .expect("scan");
        assert_eq!(hits, vec![2]);
        assert!(!db.scan_visit(b"benign", |_| {}).expect("scan"));
    }

    #[test]
    fn regex_database_reports_the_unsupported_expression_index() {
        let patterns = vec![
            RegexPattern {
                expression: "a(?=b)".to_string(),
                caseless: false,
                dotall: true,
                multiline: true,
                rule_ids: vec![1],
            },
            RegexPattern {
                expression: "select".to_string(),
                caseless: false,
                dotall: true,
                multiline: true,
                rule_ids: vec![2],
            },
        ];
        match SharedHsDatabase::compile_regex(&patterns) {
            Err(HsError::Compile { index, .. }) => assert_eq!(index, 0),
            other => panic!("expected a compile error, got {:?}", other.err()),
        }
    }
}
