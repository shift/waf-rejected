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

/// `HS_SUCCESS`.
const HS_SUCCESS: c_int = 0;
/// `HS_SCAN_TERMINATED`.
const HS_SCAN_TERMINATED: c_int = -3;
/// `HS_MODE_BLOCK`.
const HS_MODE_BLOCK: c_uint = 1;
/// `HS_FLAG_CASELESS`.
const HS_FLAG_CASELESS: c_uint = 1;
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

struct ScanContext<'a> {
    pattern_rules: &'a [Vec<u32>],
    hit: bool,
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
    // `hs_scan`. Terminate on the first hit: the prefilter only needs a
    // boolean, and early termination keeps attack bodies cheap.
    let context = &mut *(context as *mut ScanContext<'_>);
    context.hit = true;
    if let Some(rules) = context.pattern_rules.get(id as usize) {
        context.matched_rule_ids.extend_from_slice(rules);
    }
    1
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
        if patterns.is_empty() {
            return Err(HsError::CompileGeneral("empty pattern set".to_string()));
        }
        if unsafe { hs_valid_platform() } != HS_SUCCESS {
            return Err(HsError::UnsupportedPlatform);
        }

        let mut expressions = Vec::with_capacity(patterns.len());
        let mut cstrings = Vec::with_capacity(patterns.len());
        let mut flags = Vec::with_capacity(patterns.len());
        let mut ids = Vec::with_capacity(patterns.len());
        for (index, pattern) in patterns.iter().enumerate() {
            let escaped = escape_literal(&pattern.literal);
            let cstring = CString::new(escaped.clone())
                .map_err(|_| HsError::InteriorNul(pattern.literal.clone()))?;
            expressions.push(cstring.as_ptr());
            cstrings.push(cstring);
            let mut flag = HS_FLAG_SINGLEMATCH;
            if pattern.caseless {
                flag |= HS_FLAG_CASELESS;
            }
            flags.push(flag);
            ids.push(index as c_uint);
        }

        let mut db: *mut HsDatabase = ptr::null_mut();
        let mut error: *mut HsCompileError = ptr::null_mut();
        let rc = unsafe {
            hs_compile_multi(
                expressions.as_ptr(),
                flags.as_ptr(),
                ids.as_ptr(),
                patterns.len() as c_uint,
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

        Ok(Self {
            db,
            scratch,
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
