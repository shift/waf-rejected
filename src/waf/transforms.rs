//! Shared, bounded, allocation-free transform pipeline.
//!
//! The CRS prefilter must see every representation a rule can see before it may
//! remove a rule. Recomputing a rule's transform chain for every rule and every
//! input turns a 4 KiB body into dozens of fresh `Vec` allocations and repeated
//! percent-decodes. This module provides one pipeline that
//!
//! * writes every intermediate value into a reusable arena (no per-request
//!   allocation after the arena reaches its high-water mark),
//! * memoises each *chain prefix* for the lifetime of a request, so rules that
//!   share `urlDecodeUni → htmlEntityDecode → jsDecode` pay for it once, and
//! * fails closed when an intermediate value or the arena exceeds its bound.
//!
//! Transform semantics are byte-for-byte ports of the vendored Coraza
//! `internal/transformations` package (`wasm/coraza_reactor/vendor`). The
//! `coraza_parity` test compares every transform against
//! `tests/fixtures/transform_parity.json`, which is generated from that Go code
//! by `scripts/gen-transform-fixture.sh`. Known deliberate differences are
//! listed in `docs/design/transform-pipeline.md`.
//!
//! The module is compiled with the non-default `crs-prefilter` feature. It is
//! also compiled for unit tests so `cargo test --lib` exercises parity without
//! changing the default feature set.

mod case_tables;
mod entities;

use std::ops::Range;

use memchr::{memchr, memchr2, memchr3};

/// Hard cap for one intermediate value. A value larger than this makes the
/// pipeline fail closed (the caller must run full evaluation).
pub const MAX_VALUE_BYTES: usize = 1 << 18;

/// Hard cap for the per-request arena. Reaching it makes the pipeline fail
/// closed instead of growing without bound.
pub const MAX_ARENA_BYTES: usize = 8 << 20;

/// Transform overflow / bound violations. Both variants are fail-closed: the
/// caller must not use a partial result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TransformError {
    #[error("transform output exceeded the per-value bound")]
    OutputOverflow,
    #[error("transform arena exceeded its bound")]
    ArenaOverflow,
}

/// One step in a transform chain.
///
/// `Identity` and `JsonUnescape` model body-processor extraction variants
/// rather than named Coraza transforms; the rest match Coraza names exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Transform {
    Identity,
    Lowercase,
    Uppercase,
    UrlDecode,
    UrlDecodeUni,
    RemoveNulls,
    ReplaceNulls,
    CompressWhitespace,
    RemoveWhitespace,
    Trim,
    TrimLeft,
    TrimRight,
    NormalizePath,
    NormalizePathWin,
    EscapeSeqDecode,
    ReplaceComments,
    JsDecode,
    CssDecode,
    HtmlEntityDecode,
    CmdLine,
    Base64Decode,
    JsonUnescape,
    /// Coraza `utf8ToUnicode` (not an identity; see [`Self::is_noop_name`]).
    Utf8ToUnicode,
    /// Coraza `sha1`.
    Sha1,
    /// Coraza `hexEncode`.
    HexEncode,
    /// Coraza `removeCommentsChar`.
    RemoveCommentsChar,
    /// Coraza `length`.
    Length,
}

/// A pipeline step: byte transform plus a conservative identity pre-check.
///
/// [`TransformCache`] is generic over this trait so the native engine can reuse
/// the arena, prefix memoisation and aliasing while keeping its own transform
/// implementations. The shared [`Transform`] is the only implementation used by
/// the CRS prefilter.
pub trait Step: Copy + PartialEq + Eq + std::hash::Hash + std::fmt::Debug {
    /// Applies the step to `input`, replacing `output`.
    fn apply_into(self, input: &[u8], output: &mut Vec<u8>);
    /// True only when the step is provably the identity on `input`.
    ///
    /// Callers still compare the result, so returning `false` is always safe.
    fn is_identity(self, input: &[u8]) -> bool;
}

impl Transform {
    /// Resolves a SecRule transform name (already trimmed and lowercased).
    ///
    /// Returns `None` for `none`/`utf8tounicode` (no-ops here) and for unknown
    /// names; callers that need to distinguish the two use
    /// [`Self::is_noop_name`].
    pub fn from_rule_name(name: &str) -> Option<Self> {
        Some(match name {
            "lowercase" => Self::Lowercase,
            "uppercase" => Self::Uppercase,
            "urldecode" => Self::UrlDecode,
            "urldecodeuni" => Self::UrlDecodeUni,
            "removenulls" => Self::RemoveNulls,
            "replacenulls" => Self::ReplaceNulls,
            "compresswhitespace" => Self::CompressWhitespace,
            "removewhitespace" => Self::RemoveWhitespace,
            "trim" => Self::Trim,
            "trimleft" => Self::TrimLeft,
            "trimright" => Self::TrimRight,
            "normalizepath" | "normalisepath" => Self::NormalizePath,
            "normalizepathwin" | "normalisepathwin" => Self::NormalizePathWin,
            "escapeseqdecode" => Self::EscapeSeqDecode,
            "replacecomments" => Self::ReplaceComments,
            "jsdecode" => Self::JsDecode,
            "cssdecode" => Self::CssDecode,
            "htmlentitydecode" => Self::HtmlEntityDecode,
            "cmdline" => Self::CmdLine,
            "base64decode" => Self::Base64Decode,
            _ => return None,
        })
    }

    /// True for transform names that are an identity in this pipeline.
    pub fn is_noop_name(name: &str) -> bool {
        matches!(name, "none" | "utf8tounicode")
    }

    /// True when this step is provably the identity on `input`.
    ///
    /// This is a cheap pre-check: it avoids copying and comparing a value that
    /// the transform would return unchanged. It is conservative — `false` only
    /// means "run the transform and compare".
    pub fn is_identity_on(self, input: &[u8]) -> bool {
        match self {
            Self::Identity => true,
            Self::Lowercase => !input
                .iter()
                .any(|byte| byte.is_ascii_uppercase() || *byte >= 0x80),
            Self::Uppercase => !input
                .iter()
                .any(|byte| byte.is_ascii_lowercase() || *byte >= 0x80),
            Self::UrlDecode | Self::UrlDecodeUni => memchr2(b'%', b'+', input).is_none(),
            Self::RemoveNulls | Self::ReplaceNulls => memchr(0, input).is_none(),
            Self::CompressWhitespace => whitespace_is_compressed(input),
            Self::RemoveWhitespace => {
                if input.is_ascii() {
                    memchr3(b' ', b'\t', b'\n', input).is_none()
                        && memchr3(0x0b, 0x0c, b'\r', input).is_none()
                } else {
                    !input.iter().any(|byte| {
                        matches!(
                            byte,
                            b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r' | 0x85 | 0xa0
                        )
                    })
                }
            }
            Self::Trim | Self::TrimLeft | Self::TrimRight => {
                let left = matches!(
                    input.first(),
                    Some(b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)
                );
                let right = matches!(
                    input.last(),
                    Some(b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)
                );
                let trim_left = matches!(self, Self::Trim | Self::TrimLeft);
                let trim_right = matches!(self, Self::Trim | Self::TrimRight);
                !((trim_left && left) || (trim_right && right))
            }
            Self::NormalizePath => memchr2(b'/', b'.', input).is_none(),
            Self::NormalizePathWin => memchr3(b'/', b'.', b'\\', input).is_none(),
            Self::EscapeSeqDecode | Self::JsDecode | Self::CssDecode | Self::JsonUnescape => {
                memchr(b'\\', input).is_none()
            }
            Self::ReplaceComments => memchr(b'/', input).is_none(),
            Self::HtmlEntityDecode => memchr(b'&', input).is_none(),
            Self::CmdLine => cmd_line_is_identity(input),
            Self::Base64Decode => false,
            Self::Utf8ToUnicode => !input.is_ascii(),
            Self::Sha1 | Self::HexEncode | Self::Length => false,
            Self::RemoveCommentsChar => remove_comments_char_is_identity(input),
        }
    }

    /// Convenience wrapper around [`Self::apply_into`] for callers that want an
    /// owned result (tests, the hyperscan comparison harness). The request path
    /// uses [`TransformCache`] and never calls this.
    pub fn apply(self, input: &[u8]) -> Vec<u8> {
        let mut output = Vec::new();
        self.apply_into(input, &mut output);
        output
    }

    /// Applies this step to `input`, replacing `output`.
    ///
    /// The caller owns the bound checks; [`TransformCache`] enforces them.
    pub fn apply_into(self, input: &[u8], output: &mut Vec<u8>) {
        output.clear();
        match self {
            Self::Identity => output.extend_from_slice(input),
            Self::Lowercase => map_case(input, output, case_tables::LOWER, true),
            Self::Uppercase => map_case(input, output, case_tables::UPPER, false),
            Self::UrlDecode => url_decode_into(input, output, false),
            Self::UrlDecodeUni => url_decode_into(input, output, true),
            Self::RemoveNulls => {
                output.reserve(input.len());
                output.extend(input.iter().copied().filter(|byte| *byte != 0));
            }
            Self::ReplaceNulls => {
                output.reserve(input.len());
                output.extend(
                    input
                        .iter()
                        .map(|byte| if *byte == 0 { b' ' } else { *byte }),
                );
            }
            Self::CompressWhitespace => compress_whitespace_into(input, output),
            Self::RemoveWhitespace => remove_whitespace_into(input, output),
            Self::Trim => trim_into(input, output, true, true),
            Self::TrimLeft => trim_into(input, output, true, false),
            Self::TrimRight => trim_into(input, output, false, true),
            Self::NormalizePath => normalize_path_into(input, output),
            Self::NormalizePathWin => normalize_path_win_into(input, output),
            Self::EscapeSeqDecode => escape_seq_decode_into(input, output),
            Self::ReplaceComments => replace_comments_into(input, output),
            Self::JsDecode => js_decode_into(input, output),
            Self::CssDecode => css_decode_into(input, output),
            Self::HtmlEntityDecode => html_entity_decode_into(input, output),
            Self::CmdLine => cmd_line_into(input, output),
            Self::Base64Decode => base64_decode_into(input, output),
            Self::JsonUnescape => json_unescape_into(input, output),
            Self::Utf8ToUnicode => utf8_to_unicode_into(input, output),
            Self::Sha1 => {
                use sha1::{Digest, Sha1};
                let mut hasher = Sha1::new();
                hasher.update(input);
                output.extend_from_slice(&hasher.finalize());
            }
            Self::HexEncode => hex_encode_into(input, output),
            Self::RemoveCommentsChar => remove_comments_char_into(input, output),
            Self::Length => push_decimal(output, input.len()),
        }
    }
}

impl Step for Transform {
    fn apply_into(self, input: &[u8], output: &mut Vec<u8>) {
        Transform::apply_into(self, input, output);
    }

    fn is_identity(self, input: &[u8]) -> bool {
        self.is_identity_on(input)
    }
}

// ---------------------------------------------------------------------------
// Request-scoped cache
// ---------------------------------------------------------------------------

/// Identity of one input value within a request.
///
/// The value must stay alive (and unmodified) until the next
/// [`TransformCache::begin_request`]. The cache never dereferences the pointer:
/// it is only used to tell values apart, so equal contents in different
/// buffers are distinct values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValueId(u32);

#[derive(Debug, Clone, Copy)]
struct ValueKey {
    ptr: usize,
    len: usize,
}

#[derive(Debug, Clone, Copy)]
struct Entry {
    start: u32,
    end: u32,
    hash: u64,
}

/// Fast, sampled, non-cryptographic hash used only to bucket content-dedup
/// candidates. Every candidate is verified with a byte comparison, so a
/// collision or a skipped sample can only cost a comparison, never correctness.
fn hash_bytes(bytes: &[u8]) -> u64 {
    let mut hash = (bytes.len() as u64).wrapping_mul(0xcbf2_9ce4_8422_2325);
    let sample = |hash: &mut u64, byte: u8| {
        *hash = (*hash ^ u64::from(byte)).wrapping_mul(0x100_0000_01b3);
        *hash ^= *hash >> 29;
    };
    for &byte in bytes.iter().take(16) {
        sample(&mut hash, byte);
    }
    let step = (bytes.len() / 16).max(1);
    for index in (0..bytes.len()).step_by(step) {
        sample(&mut hash, bytes[index]);
    }
    for &byte in bytes.iter().rev().take(16) {
        sample(&mut hash, byte);
    }
    hash | 1
}

/// Per-request transform arena and prefix cache.
///
/// Usage:
/// 1. [`begin_request`](Self::begin_request) with the number of registered
///    chain prefixes.
/// 2. [`begin_value`](Self::begin_value) once per distinct input.
/// 3. [`resolve`](Self::resolve) for every chain, sharing prefixes across
///    chains.
///
/// Steady state allocates nothing: `begin_request` only clears the arena, the
/// value table and the slot table, all of which keep their capacity.
#[derive(Debug)]
pub struct TransformCache<S = Transform> {
    arena: Vec<u8>,
    scratch: Vec<u8>,
    values: Vec<ValueKey>,
    /// `values.len() * prefix_count` entries, 1-based index into `entries`
    /// (0 means "not computed for this value").
    slots: Vec<u32>,
    entries: Vec<Entry>,
    /// `(parent slot, step) -> result slot` memo shared by every chain. Two
    /// prefixes that reach equal bytes and apply the same step reuse it.
    memo: Vec<(u32, S, u32)>,
    prefix_count: usize,
    value_limit: usize,
    arena_limit: usize,
    /// When set, `value_limit` is the only per-value cap (no `3 * input` guess).
    explicit_limit: bool,
    transform_bytes: u64,
}

impl<S: Step> Default for TransformCache<S> {
    fn default() -> Self {
        Self {
            arena: Vec::new(),
            scratch: Vec::new(),
            values: Vec::new(),
            slots: Vec::new(),
            entries: Vec::new(),
            memo: Vec::new(),
            prefix_count: 1,
            value_limit: MAX_VALUE_BYTES,
            arena_limit: MAX_ARENA_BYTES,
            explicit_limit: false,
            transform_bytes: 0,
        }
    }
}

impl<S: Step> TransformCache<S> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a cache with an explicit arena bound (tests and benchmarks).
    pub fn with_arena_limit(arena_limit: usize) -> Self {
        let mut cache = Self::new();
        cache.arena_limit = arena_limit;
        cache
    }

    /// Sets explicit per-value and per-request arena bounds.
    ///
    /// This also replaces the prefilter's `3 * input` expansion estimate with
    /// `value_limit`, which engine callers need because some transform chains
    /// legitimately expand (for example `utf8ToUnicode` and `hexEncode`).
    pub fn set_bounds(&mut self, value_limit: usize, arena_limit: usize) {
        self.value_limit = value_limit;
        self.arena_limit = arena_limit;
        self.explicit_limit = true;
    }

    /// Starts a new request. `prefix_count` is the number of registered chain
    /// prefixes, including the empty prefix (id 0).
    pub fn begin_request(&mut self, prefix_count: usize) {
        self.prefix_count = prefix_count.max(1);
        self.arena.clear();
        self.values.clear();
        self.slots.clear();
        self.entries.clear();
        self.memo.clear();
    }

    /// Registers an input value and stores its raw form as prefix 0.
    pub fn begin_value(&mut self, value: &[u8]) -> Result<ValueId, TransformError> {
        if value.len() > self.value_limit {
            return Err(TransformError::OutputOverflow);
        }
        let id = u32::try_from(self.values.len()).map_err(|_| TransformError::ArenaOverflow)?;
        let slot_base = self.values.len() * self.prefix_count;
        let needed = slot_base + self.prefix_count;
        if self.slots.len() < needed {
            self.slots.resize(needed, 0);
        }
        // The step memo is only meaningful within one value; clearing it here
        // keeps its length bounded by the prefix count instead of growing with
        // every value in the request.
        self.memo.clear();
        let start = self.arena.len();
        self.arena.extend_from_slice(value);
        if self.arena.len() > self.arena_limit {
            return Err(TransformError::ArenaOverflow);
        }
        let end = self.arena.len();
        self.entries.push(Entry {
            start: start as u32,
            end: end as u32,
            hash: hash_bytes(value),
        });
        self.slots[slot_base] = self.entries.len() as u32;
        self.values.push(ValueKey {
            ptr: value.as_ptr() as usize,
            len: value.len(),
        });
        Ok(ValueId(id))
    }

    /// Applies `plan` (a list of prefix ids) to `value` and returns the final
    /// output range. Prefixes already computed for this value are reused.
    ///
    /// `prefixes[prefix_id]` is the full step list ending at that prefix;
    /// prefix 0 must be the empty list.
    pub fn resolve(
        &mut self,
        value: ValueId,
        input: &[u8],
        plan: &[u32],
        prefixes: &[Vec<S>],
    ) -> Result<Range<usize>, TransformError> {
        let value_index = value.0 as usize;
        if let Some(key) = self.values.get(value_index) {
            // Cheap identity check: the cache is scoped to one request, so a
            // mismatched pointer/length means the caller reused a ValueId for
            // a different buffer. Fail closed rather than return wrong bytes.
            if key.ptr != input.as_ptr() as usize || key.len != input.len() {
                return Err(TransformError::OutputOverflow);
            }
        } else {
            return Err(TransformError::OutputOverflow);
        }

        let slot_base = value_index * self.prefix_count;
        let mut current_slot = self.slots[slot_base];
        let mut current = {
            let entry = self.entries[current_slot as usize - 1];
            entry.start as usize..entry.end as usize
        };
        // Fast path: the plan's final prefix is already resolved for this value,
        // so a repeated `(value, chain)` lookup does not walk the plan.
        if let Some(&last) = plan.last() {
            let last = last as usize;
            if last < self.prefix_count {
                let slot = self.slots[slot_base + last];
                if slot != 0 {
                    return Ok(self.entry_range(slot));
                }
            }
        }
        let limit = self.step_limit(input);
        for &prefix in plan {
            let prefix_index = prefix as usize;
            if prefix_index >= self.prefix_count {
                return Err(TransformError::ArenaOverflow);
            }
            let slot = self.slots[slot_base + prefix_index];
            if slot != 0 {
                current_slot = slot;
                let entry = self.entries[slot as usize - 1];
                current = entry.start as usize..entry.end as usize;
                continue;
            }
            let steps = prefixes
                .get(prefix_index)
                .ok_or(TransformError::ArenaOverflow)?;
            let step = *steps.last().ok_or(TransformError::ArenaOverflow)?;
            // Cheap identity pre-check: no copy, no compare, no scan.
            if step.is_identity(&self.arena[current.clone()]) {
                self.slots[slot_base + prefix_index] = current_slot;
                continue;
            }
            current_slot = self.push_step(current_slot, step, limit)?;
            let entry = self.entries[current_slot as usize - 1];
            current = entry.start as usize..entry.end as usize;
            self.slots[slot_base + prefix_index] = current_slot;
        }
        Ok(current)
    }

    /// Computes every registered chain prefix for one value exactly once.
    ///
    /// `parents[i]` is the prefix id of `steps[..i]` (the immediate parent of
    /// prefix `i`); the prefix table is built parent-before-child, so a single
    /// forward pass resolves the whole DAG. Groups then read their final
    /// prefix without re-walking their plan.
    pub fn resolve_all(
        &mut self,
        value: ValueId,
        input: &[u8],
        steps: &[S],
        parents: &[u32],
    ) -> Result<(), TransformError> {
        self.check_value(value, input)?;
        let value_index = value.0 as usize;
        let slot_base = value_index * self.prefix_count;
        let limit = self.step_limit(input);
        let count = self.prefix_count.min(steps.len()).min(parents.len());
        for prefix in 1..count {
            if self.slots[slot_base + prefix] != 0 {
                continue;
            }
            let parent = parents[prefix] as usize;
            if parent >= prefix {
                return Err(TransformError::ArenaOverflow);
            }
            let parent_slot = self.slots[slot_base + parent];
            if parent_slot == 0 {
                return Err(TransformError::ArenaOverflow);
            }
            let step = steps[prefix];
            let slot = if let Some((_, _, slot)) = self
                .memo
                .iter()
                .find(|(parent, cached, _)| *parent == parent_slot && *cached == step)
            {
                *slot
            } else {
                let current = self.entry_range(parent_slot);
                let slot = if step.is_identity(&self.arena[current]) {
                    parent_slot
                } else {
                    self.push_step(parent_slot, step, limit)?
                };
                self.memo.push((parent_slot, step, slot));
                slot
            };
            self.slots[slot_base + prefix] = slot;
        }
        Ok(())
    }

    /// Borrows the cached range for one (value, prefix) pair.
    pub fn prefix_range(&self, value: ValueId, prefix: usize) -> Option<Range<usize>> {
        let slot = *self
            .slots
            .get(value.0 as usize * self.prefix_count + prefix)?;
        if slot == 0 {
            None
        } else {
            Some(self.entry_range(slot))
        }
    }

    fn check_value(&self, value: ValueId, input: &[u8]) -> Result<(), TransformError> {
        match self.values.get(value.0 as usize) {
            Some(key) if key.ptr == input.as_ptr() as usize && key.len == input.len() => Ok(()),
            _ => Err(TransformError::OutputOverflow),
        }
    }

    /// True when `id` still refers to `input`.
    pub fn value_matches(&self, value: ValueId, input: &[u8]) -> bool {
        self.check_value(value, input).is_ok()
    }

    /// Total bytes written for transform outputs (raw values excluded).
    ///
    /// Callers use deltas of this counter to charge a work budget without
    /// re-charging aliased or memoised representations.
    pub fn transform_bytes(&self) -> u64 {
        self.transform_bytes
    }

    /// Per-value output cap for `input`.
    fn step_limit(&self, input: &[u8]) -> usize {
        if self.explicit_limit {
            self.value_limit
        } else {
            input
                .len()
                .saturating_mul(3)
                .saturating_add(64)
                .min(self.value_limit)
        }
    }

    fn entry_range(&self, slot: u32) -> Range<usize> {
        let entry = self.entries[slot as usize - 1];
        entry.start as usize..entry.end as usize
    }

    /// Applies one step to the representation in `parent_slot` and returns the
    /// slot of the result. Unchanged output aliases the parent (no arena copy);
    /// equal output aliases an existing entry so the scan is shared too.
    fn push_step(
        &mut self,
        parent_slot: u32,
        step: S,
        limit: usize,
    ) -> Result<u32, TransformError> {
        let current = self.entry_range(parent_slot);
        let arena_limit = self.arena_limit;
        let TransformCache {
            arena,
            scratch,
            entries,
            transform_bytes,
            ..
        } = self;
        step.apply_into(&arena[current.clone()], scratch);
        if scratch.len() > limit {
            return Err(TransformError::OutputOverflow);
        }
        let hash = hash_bytes(scratch);
        let parent = entries[parent_slot as usize - 1];
        if hash == parent.hash
            && (parent.end - parent.start) as usize == scratch.len()
            && scratch.as_slice() == &arena[current]
        {
            return Ok(parent_slot);
        }
        if let Some(index) = entries.iter().position(|entry| {
            entry.hash == hash
                && (entry.end - entry.start) as usize == scratch.len()
                && &arena[entry.start as usize..entry.end as usize] == scratch.as_slice()
        }) {
            return Ok((index + 1) as u32);
        }
        let start = arena.len();
        arena.extend_from_slice(scratch);
        if arena.len() > arena_limit {
            return Err(TransformError::ArenaOverflow);
        }
        *transform_bytes = transform_bytes.saturating_add(scratch.len() as u64);
        entries.push(Entry {
            start: start as u32,
            end: arena.len() as u32,
            hash,
        });
        Ok(entries.len() as u32)
    }

    /// Borrows a previously resolved range.
    pub fn bytes(&self, range: Range<usize>) -> &[u8] {
        &self.arena[range]
    }

    /// Number of stored intermediate values (diagnostics / benchmarks).
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }
}

// ---------------------------------------------------------------------------
// Prefix table
// ---------------------------------------------------------------------------

/// Deduplicated transform prefix DAG for a set of interned chains.
///
/// `from_chains` builds one entry per distinct chain prefix, so `N` rules that
/// share `urlDecodeUni -> htmlEntityDecode` pay for that prefix once per value.
/// `plan(i)` is the list of prefix ids to pass to [`TransformCache::resolve`].
#[derive(Debug, Clone)]
pub struct PrefixTable<S> {
    prefixes: Vec<Vec<S>>,
    plans: Vec<Vec<u32>>,
}

impl<S> Default for PrefixTable<S> {
    fn default() -> Self {
        Self {
            prefixes: vec![Vec::new()],
            plans: Vec::new(),
        }
    }
}

impl<S: Copy + PartialEq> PrefixTable<S> {
    /// Builds the prefix table for `chains` (chain order is preserved).
    pub fn from_chains(chains: &[Vec<S>]) -> Self {
        let mut prefixes: Vec<Vec<S>> = vec![Vec::new()];
        let mut plans = Vec::with_capacity(chains.len());
        for chain in chains {
            let mut plan = Vec::with_capacity(chain.len());
            let mut sequence: Vec<S> = Vec::with_capacity(chain.len());
            for &step in chain {
                sequence.push(step);
                let id = match prefixes.iter().position(|prefix| prefix == &sequence) {
                    Some(id) => id,
                    None => {
                        prefixes.push(sequence.clone());
                        prefixes.len() - 1
                    }
                };
                plan.push(id as u32);
            }
            plans.push(plan);
        }
        Self { prefixes, plans }
    }

    /// Number of registered prefixes, including the empty prefix 0.
    pub fn len(&self) -> usize {
        self.prefixes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.prefixes.len() <= 1
    }

    pub fn prefixes(&self) -> &[Vec<S>] {
        &self.prefixes
    }

    pub fn plans(&self) -> &[Vec<u32>] {
        &self.plans
    }

    /// Plan for chain `index`; an unknown index resolves to the empty plan.
    pub fn plan(&self, index: usize) -> &[u32] {
        self.plans.get(index).map_or(&[], Vec::as_slice)
    }
}

// ---------------------------------------------------------------------------
// Byte transforms
// ---------------------------------------------------------------------------

/// Appends the decimal representation of `value`.
fn push_decimal(output: &mut Vec<u8>, value: usize) {
    let mut buffer = [0u8; 20];
    let mut cursor = buffer.len();
    let mut value = value;
    loop {
        cursor -= 1;
        buffer[cursor] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    output.extend_from_slice(&buffer[cursor..]);
}

/// Appends `value` as lowercase hexadecimal digits without allocation.
fn push_hex_lower(output: &mut Vec<u8>, value: u32) {
    let mut buffer = [0u8; 8];
    let mut cursor = buffer.len();
    let mut value = value;
    loop {
        cursor -= 1;
        let digit = (value & 0xf) as u8;
        buffer[cursor] = if digit < 10 {
            b'0' + digit
        } else {
            b'a' + digit - 10
        };
        value >>= 4;
        if value == 0 {
            break;
        }
    }
    output.extend_from_slice(&buffer[cursor..]);
}

/// Coraza `hexEncode` (`encoding/hex.EncodeToString`).
fn hex_encode_into(input: &[u8], output: &mut Vec<u8>) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    output.reserve(input.len() * 2);
    for &byte in input {
        output.push(HEX[usize::from(byte >> 4)]);
        output.push(HEX[usize::from(byte & 0x0f)]);
    }
}

/// Coraza `removeCommentsChar`: drops comment delimiters but keeps the text.
fn remove_comments_char_into(input: &[u8], output: &mut Vec<u8>) {
    output.reserve(input.len());
    let mut index = 0usize;
    let len = input.len();
    while index < len {
        if input[index] == b'/' && index + 1 < len && input[index + 1] == b'*' {
            index += 2;
        } else if input[index] == b'*' && index + 1 < len && input[index + 1] == b'/' {
            index += 2;
        } else if input[index] == b'<'
            && index + 3 < len
            && input[index + 1] == b'!'
            && input[index + 2] == b'-'
            && input[index + 3] == b'-'
        {
            index += 4;
        } else if input[index] == b'-'
            && index + 2 < len
            && input[index + 1] == b'-'
            && input[index + 2] == b'>'
        {
            index += 3;
        } else if input[index] == b'-' && index + 1 < len && input[index + 1] == b'-' {
            index += 2;
        } else if input[index] == b'#' {
            index += 1;
        } else {
            output.push(input[index]);
            index += 1;
        }
    }
}

/// Conservative identity check for `removeCommentsChar`.
fn remove_comments_char_is_identity(input: &[u8]) -> bool {
    !input
        .iter()
        .any(|byte| matches!(byte, b'/' | b'*' | b'<' | b'!' | b'-' | b'#'))
}

/// Coraza `utf8ToUnicode`: non-ASCII runes become `%uXXXX`.
fn utf8_to_unicode_into(input: &[u8], output: &mut Vec<u8>) {
    output.reserve(input.len());
    let mut index = 0usize;
    while index < input.len() {
        let byte = input[index];
        if byte < 0x80 {
            output.push(byte);
            index += 1;
            continue;
        }
        match decode_utf8(&input[index..]) {
            Some((rune, len)) => {
                output.extend_from_slice(b"%u");
                let digits = match rune {
                    0x0..=0xf => 1,
                    0x10..=0xff => 2,
                    0x100..=0xfff => 3,
                    _ => 4,
                };
                for _ in digits..4 {
                    output.push(b'0');
                }
                push_hex_lower(output, rune);
                index += len;
            }
            // Go's `range` over a string yields U+FFFD for each invalid byte.
            None => {
                output.extend_from_slice(b"%ufffd");
                index += 1;
            }
        }
    }
}

/// True when `compressWhitespace` would return `input` unchanged.
fn whitespace_is_compressed(input: &[u8]) -> bool {
    if input.is_ascii() {
        if memchr3(b'\t', b'\n', b'\r', input).is_some() || memchr2(0x0b, 0x0c, input).is_some() {
            return false;
        }
        let mut start = 0usize;
        while let Some(offset) = memchr(b' ', &input[start..]) {
            let at = start + offset;
            if input.get(at + 1) == Some(&b' ') {
                return false;
            }
            start = at + 1;
        }
        return true;
    }
    let mut previous_space = false;
    for &byte in input {
        if is_latin_space(byte) {
            if byte != b' ' || previous_space {
                return false;
            }
            previous_space = true;
        } else {
            previous_space = false;
        }
    }
    true
}

/// True when `cmdLine` has work beyond ASCII case folding.
fn cmd_line_has_special(input: &[u8]) -> bool {
    if memchr3(b'"', b'\'', b'\\', input).is_some()
        || memchr3(b'^', b',', b';', input).is_some()
        || memchr3(b'\t', b'\r', b'\n', input).is_some()
        || memchr2(b'/', b'(', input).is_some()
    {
        return true;
    }
    let mut start = 0usize;
    while let Some(offset) = memchr(b' ', &input[start..]) {
        let at = start + offset;
        if input.get(at + 1) == Some(&b' ') {
            return true;
        }
        start = at + 1;
    }
    false
}

/// True when `cmdLine` would return `input` unchanged.
fn cmd_line_is_identity(input: &[u8]) -> bool {
    !cmd_line_has_special(input) && !input.iter().any(|byte| byte.is_ascii_uppercase())
}

fn output_push_rune(output: &mut Vec<u8>, rune: u32) {
    match char::from_u32(rune) {
        Some(ch) => {
            let mut buf = [0u8; 4];
            output.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
        }
        None => output.extend_from_slice("\u{FFFD}".as_bytes()),
    }
}

/// Decodes one UTF-8 scalar with Go's `utf8.DecodeRune` semantics.
///
/// Returns `None` for an invalid or truncated sequence; Go advances one byte
/// and emits U+FFFD in that case, which callers replicate.
fn decode_utf8(input: &[u8]) -> Option<(u32, usize)> {
    let first = *input.first()?;
    let len = match first {
        0x00..=0x7f => 1,
        0xc2..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf4 => 4,
        _ => return None,
    };
    let slice = input.get(..len)?;
    let text = std::str::from_utf8(slice).ok()?;
    Some((text.chars().next()? as u32, len))
}

fn table_lookup(table: &[(u32, u32)], rune: u32) -> Option<u32> {
    table
        .binary_search_by_key(&rune, |(from, _)| *from)
        .ok()
        .map(|index| table[index].1)
}

/// Go's `strings.ToLower`/`ToUpper` (simple, context-free case mapping).
///
/// Invalid UTF-8 bytes become U+FFFD, one per byte, exactly like ranging over a
/// Go string.
fn map_case(input: &[u8], output: &mut Vec<u8>, table: &[(u32, u32)], lower: bool) {
    output.reserve(input.len());
    if input.is_ascii() {
        let start = output.len();
        output.extend_from_slice(input);
        if lower {
            output[start..].make_ascii_lowercase();
        } else {
            output[start..].make_ascii_uppercase();
        }
        return;
    }
    let mut index = 0usize;
    while index < input.len() {
        let byte = input[index];
        if byte < 0x80 {
            output.push(if lower {
                byte.to_ascii_lowercase()
            } else {
                byte.to_ascii_uppercase()
            });
            index += 1;
            continue;
        }
        match decode_utf8(&input[index..]) {
            Some((rune, len)) => {
                output_push_rune(output, table_lookup(table, rune).unwrap_or(rune));
                index += len;
            }
            None => {
                output.extend_from_slice("\u{FFFD}".as_bytes());
                index += 1;
            }
        }
    }
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn hex_pair(input: &[u8], at: usize) -> Option<u8> {
    let hi = hex_value(*input.get(at)?)?;
    let lo = hex_value(*input.get(at + 1)?)?;
    Some((hi << 4) | lo)
}

/// Coraza `urlDecode` / `urlDecodeUni`.
fn url_decode_into(input: &[u8], output: &mut Vec<u8>, uni: bool) {
    output.reserve(input.len());
    let mut index = 0usize;
    while index < input.len() {
        let Some(offset) = memchr2(b'%', b'+', &input[index..]) else {
            output.extend_from_slice(&input[index..]);
            break;
        };
        if offset > 0 {
            output.extend_from_slice(&input[index..index + offset]);
            index += offset;
        }
        match input[index] {
            b'%' => {
                if uni
                    && index + 1 < input.len()
                    && matches!(input[index + 1], b'u' | b'U')
                    && index + 5 < input.len()
                {
                    if let (Some(hi), Some(lo)) =
                        (hex_pair(input, index + 2), hex_pair(input, index + 4))
                    {
                        let mut byte = lo;
                        if hi == 0xff && byte > 0x00 && byte < 0x5f {
                            byte = byte.wrapping_add(0x20);
                        }
                        output.push(byte);
                        index += 6;
                        continue;
                    }
                }
                if let Some(byte) = hex_pair(input, index + 1) {
                    output.push(byte);
                    index += 3;
                } else {
                    output.push(b'%');
                    index += 1;
                }
            }
            _ => {
                output.push(b' ');
                index += 1;
            }
        }
    }
}

/// Coraza's `isLatinSpace`.
fn is_latin_space(byte: u8) -> bool {
    matches!(
        byte,
        b'\t' | b'\n' | 0x0b | 0x0c | b'\r' | b' ' | 0x85 | 0xa0
    )
}

fn compress_whitespace_into(input: &[u8], output: &mut Vec<u8>) {
    output.reserve(input.len());
    if input.is_ascii() {
        let start = output.len();
        output.extend_from_slice(input);
        let mut write = start;
        let mut in_space = false;
        for read in start..output.len() {
            let byte = output[read];
            if is_latin_space(byte) {
                if !in_space {
                    output[write] = b' ';
                    write += 1;
                    in_space = true;
                }
            } else {
                output[write] = byte;
                write += 1;
                in_space = false;
            }
        }
        output.truncate(write);
        return;
    }
    let mut in_space = false;
    for &byte in input {
        if is_latin_space(byte) {
            if !in_space {
                output.push(b' ');
                in_space = true;
            }
        } else {
            output.push(byte);
            in_space = false;
        }
    }
}

/// Go's `unicode.IsSpace`, applied through `strings.Map`.
fn remove_whitespace_into(input: &[u8], output: &mut Vec<u8>) {
    output.reserve(input.len());
    if input.is_ascii() {
        // Spaces dominate real bodies. When the other five ASCII whitespace
        // bytes are absent, copy whole spans between spaces instead of
        // branching per byte.
        let rare =
            memchr3(b'\t', b'\n', b'\r', input).is_some() || memchr2(0x0b, 0x0c, input).is_some();
        if !rare {
            let mut start = 0usize;
            while let Some(offset) = memchr(b' ', &input[start..]) {
                output.extend_from_slice(&input[start..start + offset]);
                start += offset + 1;
            }
            output.extend_from_slice(&input[start..]);
            return;
        }
        let start = output.len();
        output.extend_from_slice(input);
        let mut write = start;
        for read in start..output.len() {
            let byte = output[read];
            if !matches!(byte, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r') {
                output[write] = byte;
                write += 1;
            }
        }
        output.truncate(write);
        return;
    }
    let mut index = 0usize;
    while index < input.len() {
        let byte = input[index];
        if byte < 0x80 {
            if !matches!(byte, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r') {
                output.push(byte);
            }
            index += 1;
            continue;
        }
        match decode_utf8(&input[index..]) {
            Some((rune, len)) => {
                if !char::from_u32(rune).is_some_and(char::is_whitespace) {
                    output_push_rune(output, rune);
                }
                index += len;
            }
            None => {
                output.extend_from_slice("\u{FFFD}".as_bytes());
                index += 1;
            }
        }
    }
}

fn trim_into(input: &[u8], output: &mut Vec<u8>, left: bool, right: bool) {
    let is_trim = |byte: u8| matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | 0x0c | 0x0b);
    let mut start = 0usize;
    let mut end = input.len();
    if left {
        while start < end && is_trim(input[start]) {
            start += 1;
        }
    }
    if right {
        while end > start && is_trim(input[end - 1]) {
            end -= 1;
        }
    }
    output.extend_from_slice(&input[start..end]);
}

/// Go's `filepath.Clean` on Unix, written directly into `output`.
///
/// `win` treats `\` as a separator and normalises it to `/`, matching
/// Coraza's `normalisePathWin` (which replaces backslashes first).
fn clean_path_into(path: &[u8], output: &mut Vec<u8>, win: bool) {
    let is_sep = |byte: u8| byte == b'/' || (win && byte == b'\\');
    if path.is_empty() {
        output.push(b'.');
        return;
    }
    let rooted = is_sep(path[0]);
    let mut read = 0usize;
    let mut dotdot = 0usize;
    if rooted {
        output.push(b'/');
        read = 1;
        dotdot = 1;
    }
    let len = path.len();
    while read < len {
        if is_sep(path[read]) {
            read += 1;
        } else if path[read] == b'.' && (read + 1 == len || is_sep(path[read + 1])) {
            read += 1;
        } else if path[read] == b'.'
            && read + 1 < len
            && path[read + 1] == b'.'
            && (read + 2 == len || is_sep(path[read + 2]))
        {
            read += 2;
            if output.len() > dotdot {
                output.pop();
                while output.len() > dotdot && !is_sep(*output.last().expect("non-empty")) {
                    output.pop();
                }
                // The separator before the removed element is excluded from
                // Go's write index, so drop it too.
                if output.len() > dotdot && is_sep(*output.last().expect("non-empty")) {
                    output.pop();
                }
            } else if !rooted {
                if !output.is_empty() {
                    output.push(b'/');
                }
                output.push(b'.');
                output.push(b'.');
                dotdot = output.len();
            }
        } else {
            if (rooted && output.len() != 1) || (!rooted && !output.is_empty()) {
                output.push(b'/');
            }
            while read < len && !is_sep(path[read]) {
                output.push(if win && path[read] == b'\\' {
                    b'/'
                } else {
                    path[read]
                });
                read += 1;
            }
        }
    }
    if output.is_empty() {
        output.push(b'.');
    }
}

/// Coraza `normalisePath`, including its trailing-slash and `.` quirks.
fn normalize_path_into(input: &[u8], output: &mut Vec<u8>) {
    if input.is_empty() {
        return;
    }
    clean_path_into(input, output, false);
    if output == b"." {
        output.clear();
        return;
    }
    if input.last() == Some(&b'/') {
        output.push(b'/');
    }
}

fn normalize_path_win_into(input: &[u8], output: &mut Vec<u8>) {
    if input.is_empty() {
        return;
    }
    clean_path_into(input, output, true);
    if output == b"." {
        output.clear();
        return;
    }
    // Coraza re-appends the slash based on the backslash-replaced string.
    if matches!(input.last(), Some(b'/') | Some(b'\\')) {
        output.push(b'/');
    }
}

/// Coraza's `escapeSeqDecode`.
fn escape_seq_decode_into(input: &[u8], output: &mut Vec<u8>) {
    output.reserve(input.len());
    let mut index = 0usize;
    let len = input.len();
    while index < len {
        let Some(offset) = memchr(b'\\', &input[index..]) else {
            output.extend_from_slice(&input[index..]);
            break;
        };
        if offset > 0 {
            output.extend_from_slice(&input[index..index + offset]);
            index += offset;
        }
        if index + 1 < len {
            let next = input[index + 1];
            let simple = match next {
                b'a' => Some(0x07),
                b'b' => Some(0x08),
                b'f' => Some(0x0c),
                b'n' => Some(b'\n'),
                b'r' => Some(b'\r'),
                b't' => Some(b'\t'),
                b'v' => Some(0x0b),
                b'\\' => Some(b'\\'),
                b'?' => Some(b'?'),
                b'\'' => Some(b'\''),
                b'"' => Some(b'"'),
                _ => None,
            };
            if let Some(byte) = simple {
                output.push(byte);
                index += 2;
                continue;
            }
            if matches!(next, b'x' | b'X')
                && index + 3 < input.len()
                && input[index + 2].is_ascii_hexdigit()
                && input[index + 3].is_ascii_hexdigit()
            {
                output.push(hex_pair(input, index + 2).unwrap_or(0));
                index += 4;
                continue;
            }
            if (b'0'..=b'7').contains(&next) {
                let mut width = 2usize;
                while width < 4
                    && index + width < input.len()
                    && (b'0'..=b'7').contains(&input[index + width])
                {
                    width += 1;
                }
                // Coraza uses strconv.ParseUint(..., 8, 8), which saturates at
                // 255 on range errors rather than wrapping.
                let mut value = 0u32;
                for &digit in &input[index + 1..index + width] {
                    value = (value * 8 + u32::from(digit - b'0')).min(255);
                }
                output.push(value as u8);
                index += width;
                continue;
            }
            output.push(next);
            index += 2;
        } else {
            output.push(input[index]);
            index += 1;
        }
    }
}

/// Coraza's `replaceComments`.
fn replace_comments_into(input: &[u8], output: &mut Vec<u8>) {
    output.reserve(input.len());
    let mut index = 0usize;
    let mut in_comment = false;
    while index < input.len() {
        if !in_comment {
            if input[index] == b'/' && input.get(index + 1) == Some(&b'*') {
                in_comment = true;
                index += 2;
            } else {
                output.push(input[index]);
                index += 1;
            }
        } else if input[index] == b'*' && input.get(index + 1) == Some(&b'/') {
            in_comment = false;
            index += 2;
            output.push(b' ');
        } else {
            index += 1;
        }
    }
    if in_comment {
        output.push(b' ');
    }
}

fn is_octal(byte: u8) -> bool {
    (b'0'..=b'7').contains(&byte)
}

/// Coraza's `jsDecode`.
///
/// This reproduces the upstream octal branch exactly, including its use of the
/// backslash byte as the first parsed digit (which makes octal escapes decode
/// to NUL). Deviating would make the prefilter see a different value than
/// Coraza and could hide a literal.
fn js_decode_into(input: &[u8], output: &mut Vec<u8>) {
    output.reserve(input.len());
    let mut index = 0usize;
    let len = input.len();
    while index < len {
        let Some(offset) = memchr(b'\\', &input[index..]) else {
            output.extend_from_slice(&input[index..]);
            break;
        };
        if offset > 0 {
            output.extend_from_slice(&input[index..index + offset]);
            index += offset;
        }
        if index + 5 < len
            && input[index + 1] == b'u'
            && input[index + 2].is_ascii_hexdigit()
            && input[index + 3].is_ascii_hexdigit()
            && input[index + 4].is_ascii_hexdigit()
            && input[index + 5].is_ascii_hexdigit()
        {
            let mut byte = hex_pair(input, index + 4).unwrap_or(0);
            if byte > 0
                && byte < 0x5f
                && matches!(input[index + 2], b'f' | b'F')
                && matches!(input[index + 3], b'f' | b'F')
            {
                byte = byte.wrapping_add(0x20);
            }
            output.push(byte);
            index += 6;
            continue;
        }
        if index + 3 < len
            && input[index + 1] == b'x'
            && input[index + 2].is_ascii_hexdigit()
            && input[index + 3].is_ascii_hexdigit()
        {
            output.push(hex_pair(input, index + 2).unwrap_or(0));
            index += 4;
            continue;
        }
        if index + 1 < len && is_octal(input[index + 1]) {
            let mut buf = [0u8; 3];
            let mut width = 0usize;
            while index + 1 + width < len && width < 3 {
                buf[width] = input[index + width];
                width += 1;
                if !is_octal(input[index + width]) {
                    break;
                }
            }
            if width > 0 {
                if width == 3 && buf[0] > b'3' {
                    width = 2;
                }
                let mut value = 0u32;
                let mut valid = true;
                for &digit in &buf[..width] {
                    if !is_octal(digit) {
                        valid = false;
                        break;
                    }
                    value = value * 8 + u32::from(digit - b'0');
                }
                // Coraza's ParseInt error path yields 0.
                output.push(if valid { value as u8 } else { 0 });
                index += 1 + width;
            }
            continue;
        }
        if index + 1 < len {
            let decoded = match input[index + 1] {
                b'a' => 0x07,
                b'b' => 0x08,
                b'f' => 0x0c,
                b'n' => b'\n',
                b'r' => b'\r',
                b't' => b'\t',
                b'v' => 0x0b,
                other => other,
            };
            output.push(decoded);
            index += 2;
            continue;
        }
        output.extend_from_slice(&input[index..]);
        break;
    }
}

fn is_css_space(byte: u8) -> bool {
    matches!(byte, b' ' | 0x0c | b'\n' | b'\t' | b'\r' | 0x0b)
}

fn single_hex_value(byte: u8) -> u8 {
    if byte >= b'A' {
        ((byte & 0xdf) - b'A') + 10
    } else {
        byte - b'0'
    }
}

/// Coraza's `cssDecode`.
fn css_decode_into(input: &[u8], output: &mut Vec<u8>) {
    output.reserve(input.len());
    let mut index = 0usize;
    let len = input.len();
    while index < len {
        let Some(offset) = memchr(b'\\', &input[index..]) else {
            output.extend_from_slice(&input[index..]);
            break;
        };
        if offset > 0 {
            output.extend_from_slice(&input[index..index + offset]);
            index += offset;
        }
        if index + 1 >= len {
            index += 1;
            continue;
        }
        index += 1;
        let mut width = 0usize;
        while width < 6 && index + width < len && input[index + width].is_ascii_hexdigit() {
            width += 1;
        }
        if width > 0 {
            let mut full_check = false;
            let mut byte = match width {
                1 => single_hex_value(input[index]),
                2 | 3 => hex_pair(input, index + width - 2).unwrap_or(0),
                4 => {
                    full_check = true;
                    hex_pair(input, index + width - 2).unwrap_or(0)
                }
                5 => {
                    let byte = hex_pair(input, index + width - 2).unwrap_or(0);
                    if input[index] == b'0' {
                        full_check = true;
                        byte
                    } else {
                        output.push(byte);
                        index += width;
                        continue;
                    }
                }
                _ => {
                    let byte = hex_pair(input, index + width - 2).unwrap_or(0);
                    if input[index] == b'0' && input[index + 1] == b'0' {
                        full_check = true;
                        byte
                    } else {
                        output.push(byte);
                        index += width;
                        continue;
                    }
                }
            };
            if full_check
                && byte > 0
                && byte < 0x5f
                && width >= 4
                && matches!(input[index + width - 3], b'f' | b'F')
                && matches!(input[index + width - 4], b'f' | b'F')
            {
                byte = byte.wrapping_add(0x20);
            }
            output.push(byte);
            if index + width < len && is_css_space(input[index + width]) {
                width += 1;
            }
            index += width;
        } else if input[index] == b'\n' {
            index += 1;
        } else {
            output.push(input[index]);
            index += 1;
        }
    }
}

/// Windows-1252 replacements for numeric entities in `0x80..=0x9f`.
const HTML_REPLACEMENT_TABLE: [u32; 32] = [
    0x20AC, 0x0081, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021, 0x02C6, 0x2030, 0x0160, 0x2039,
    0x0152, 0x008D, 0x017D, 0x008F, 0x0090, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014,
    0x02DC, 0x2122, 0x0161, 0x203A, 0x0153, 0x009D, 0x017E, 0x0178,
];

/// Open-addressed index over the HTML5 entity table. Entity names are short
/// ASCII keys; four failed binary searches per `&` in a form body cost more
/// than the decode itself, so the hot path hashes the bytes once instead.
struct EntityIndex {
    entries: Vec<(&'static str, [u32; 2])>,
    /// Open-addressed slots; 0 is empty, otherwise `entry index + 1`.
    slots: Vec<u32>,
}

impl EntityIndex {
    fn new(entries: Vec<(&'static str, [u32; 2])>) -> Self {
        let capacity = (entries.len() * 2).next_power_of_two().max(16);
        let mut index = Self {
            entries,
            slots: vec![0; capacity],
        };
        for (entry, (name, _)) in index.entries.iter().enumerate() {
            let mut slot = entity_hash(name.as_bytes()) & (capacity - 1);
            while index.slots[slot] != 0 {
                slot = (slot + 1) & (capacity - 1);
            }
            index.slots[slot] = entry as u32 + 1;
        }
        index
    }

    fn lookup(&self, name: &[u8]) -> Option<[u32; 2]> {
        let mask = self.slots.len() - 1;
        let mut slot = entity_hash(name) & mask;
        loop {
            match self.slots[slot] {
                0 => return None,
                entry => {
                    let (candidate, value) = self.entries[entry as usize - 1];
                    if candidate.as_bytes() == name {
                        return Some(value);
                    }
                }
            }
            slot = (slot + 1) & mask;
        }
    }
}

fn entity_hash(name: &[u8]) -> usize {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for &byte in name {
        hash = (hash ^ u64::from(byte)).wrapping_mul(0x100_0000_01b3);
    }
    hash as usize
}

fn entity_lookup(name: &[u8]) -> Option<[u32; 2]> {
    static INDEX: std::sync::OnceLock<EntityIndex> = std::sync::OnceLock::new();
    INDEX
        .get_or_init(|| EntityIndex::new(entities::ENTITIES.to_vec()))
        .lookup(name)
}

/// Entity names that do not require a trailing `;`. A no-semicolon reference
/// can only match one of these, so the common `&key=value` form searches ~100
/// entries instead of the full 2,231-entry HTML5 table.
fn legacy_entity_lookup(name: &[u8]) -> Option<[u32; 2]> {
    static INDEX: std::sync::OnceLock<EntityIndex> = std::sync::OnceLock::new();
    INDEX
        .get_or_init(|| {
            EntityIndex::new(
                entities::ENTITIES
                    .iter()
                    .copied()
                    .filter(|(name, _)| !name.ends_with(';'))
                    .collect(),
            )
        })
        .lookup(name)
}

/// Go's `html.UnescapeString` entity reader (non-attribute context).
///
/// Returns the number of input bytes consumed starting at `s[0] == b'&'`.
fn unescape_entity(s: &[u8], output: &mut Vec<u8>) -> usize {
    if s.len() <= 1 {
        output.push(b'&');
        return 1;
    }
    if s[1] == b'#' {
        if s.len() <= 3 {
            output.push(b'&');
            return 1;
        }
        let mut index = 2usize;
        let hex = matches!(s[index], b'x' | b'X');
        if hex {
            index += 1;
        }
        let mut value: i32 = 0;
        while index < s.len() {
            let byte = s[index];
            index += 1;
            let digit = if hex {
                hex_value(byte).map(u32::from)
            } else if byte.is_ascii_digit() {
                Some(u32::from(byte - b'0'))
            } else {
                None
            };
            if let Some(digit) = digit {
                value = value
                    .wrapping_mul(if hex { 16 } else { 10 })
                    .wrapping_add(digit as i32);
                continue;
            }
            if byte != b';' {
                index -= 1;
            }
            break;
        }
        if index <= 3 {
            output.push(b'&');
            return 1;
        }
        if (0x80..=0x9f).contains(&value) {
            value = HTML_REPLACEMENT_TABLE[(value - 0x80) as usize] as i32;
        } else if value == 0 || (0xd800..=0xdfff).contains(&value) || value > 0x10ffff || value < 0
        {
            value = 0xfffd;
        }
        output_push_rune(output, value as u32);
        return index;
    }

    let mut index = 1usize;
    let mut semicolon = false;
    while index < s.len() {
        let byte = s[index];
        index += 1;
        if byte.is_ascii_alphanumeric() {
            continue;
        }
        if byte == b';' {
            semicolon = true;
        } else {
            index -= 1;
        }
        break;
    }
    let lookup = if semicolon {
        entity_lookup
    } else {
        legacy_entity_lookup
    };
    let name = &s[1..index];
    if !name.is_empty() {
        if let Some(value) = lookup(name) {
            output_push_rune(output, value[0]);
            if value[1] != 0 {
                output_push_rune(output, value[1]);
            }
            return index;
        }
        let max_len = name.len().saturating_sub(1).min(6);
        for length in (2..=max_len).rev() {
            if let Some(value) = lookup(&name[..length]) {
                output_push_rune(output, value[0]);
                return length + 1;
            }
        }
    }
    output.extend_from_slice(&s[..index]);
    index
}

/// Go's `html.UnescapeString`.
fn html_entity_decode_into(input: &[u8], output: &mut Vec<u8>) {
    output.reserve(input.len());
    let mut index = 0usize;
    while index < input.len() {
        let Some(offset) = memchr(b'&', &input[index..]) else {
            output.extend_from_slice(&input[index..]);
            break;
        };
        if offset > 0 {
            output.extend_from_slice(&input[index..index + offset]);
            index += offset;
        }
        index += unescape_entity(&input[index..], output);
    }
}

/// Coraza's `cmdLine`.
/// True when `cmdLine` only needs case folding: no quote/escape/comma/semicolon
/// or separator characters and no whitespace run to collapse.
fn cmd_line_needs_only_case_fold(input: &[u8]) -> bool {
    !cmd_line_has_special(input)
}

fn cmd_line_into(input: &[u8], output: &mut Vec<u8>) {
    output.reserve(input.len());
    if input.is_ascii() && cmd_line_needs_only_case_fold(input) {
        let start = output.len();
        output.extend_from_slice(input);
        output[start..].make_ascii_lowercase();
        return;
    }
    let mut space = false;
    for &byte in input {
        match byte {
            b'"' | b'\'' | b'\\' | b'^' => {}
            b' ' | b',' | b';' | b'\t' | b'\r' | b'\n' => {
                if !space {
                    output.push(b' ');
                    space = true;
                }
            }
            b'/' | b'(' => {
                if space {
                    output.pop();
                }
                space = false;
                output.push(byte);
            }
            other => {
                output.push(other.to_ascii_lowercase());
                space = false;
            }
        }
    }
}

/// Coraza's `base64Decode`: padding is optional, decoding stops at the first
/// invalid character, CR/LF are ignored.
fn base64_decode_into(input: &[u8], output: &mut Vec<u8>) {
    output.reserve(input.len() / 4 * 3 + 3);
    if input.is_empty() {
        return;
    }
    let mut n = 0u32;
    let mut x: u32 = 0;
    for &byte in input {
        if byte == b'\r' || byte == b'\n' {
            continue;
        }
        // Coraza's table covers all 128 ASCII bytes; 127 means "invalid".
        if byte == b'=' || byte == b' ' || byte > 127 {
            break;
        }
        let decoded = BASE64_DECODE_MAP[byte as usize];
        if decoded == 127 {
            break;
        }
        x = (x << 6) | u32::from(decoded & 0x3f);
        n += 1;
        if n == 4 {
            output.push((x >> 16) as u8);
            output.push((x >> 8) as u8);
            output.push(x as u8);
            n = 0;
            x = 0;
        }
    }
    if n == 2 {
        x <<= 12;
        output.push((x >> 16) as u8);
    } else if n == 3 {
        x <<= 6;
        output.push((x >> 16) as u8);
        output.push((x >> 8) as u8);
    }
}

#[rustfmt::skip]
const BASE64_DECODE_MAP: [u8; 128] = [
    127, 127, 127, 127, 127, 127, 127, 127, 127, 127,
    127, 127, 127, 127, 127, 127, 127, 127, 127, 127,
    127, 127, 127, 127, 127, 127, 127, 127, 127, 127,
    127, 127, 127, 127, 127, 127, 127, 127, 127, 127,
    127, 127, 127, 62, 127, 127, 127, 63, 52, 53,
    54, 55, 56, 57, 58, 59, 60, 61, 127, 127,
    127, 64, 127, 127, 127, 0, 1, 2, 3, 4,
    5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
    25, 127, 127, 127, 127, 127, 127, 26, 27, 28,
    29, 30, 31, 32, 33, 34, 35, 36, 37, 38,
    39, 40, 41, 42, 43, 44, 45, 46, 47, 48,
    49, 50, 51, 127, 127, 127, 127, 127,
];

/// JSON string unescaping used by the JSON body-processor representation.
fn json_unescape_into(input: &[u8], output: &mut Vec<u8>) {
    output.reserve(input.len());
    let mut index = 0usize;
    while index < input.len() {
        if input[index] != b'\\' || index + 1 >= input.len() {
            output.push(input[index]);
            index += 1;
            continue;
        }
        let escape = input[index + 1];
        match escape {
            b'"' | b'\\' | b'/' => {
                output.push(escape);
                index += 2;
            }
            b'b' => {
                output.push(0x08);
                index += 2;
            }
            b'f' => {
                output.push(0x0c);
                index += 2;
            }
            b'n' => {
                output.push(b'\n');
                index += 2;
            }
            b'r' => {
                output.push(b'\r');
                index += 2;
            }
            b't' => {
                output.push(b'\t');
                index += 2;
            }
            b'u' => {
                if let Some((decoded, consumed)) = decode_json_unicode(&input[index..]) {
                    let mut buf = [0u8; 4];
                    output.extend_from_slice(decoded.encode_utf8(&mut buf).as_bytes());
                    index += consumed;
                } else {
                    output.push(b'\\');
                    output.push(escape);
                    index += 2;
                }
            }
            _ => {
                output.push(b'\\');
                output.push(escape);
                index += 2;
            }
        }
    }
}

fn decode_json_unicode(input: &[u8]) -> Option<(char, usize)> {
    let first = u32::from(hex_pair(input, 2)?) << 8 | u32::from(hex_pair(input, 4)?);
    if (0xd800..=0xdbff).contains(&first) {
        if input.get(6) == Some(&b'\\') && input.get(7) == Some(&b'u') {
            let second = u32::from(hex_pair(input, 8)?) << 8 | u32::from(hex_pair(input, 10)?);
            if (0xdc00..=0xdfff).contains(&second) {
                let code = 0x10000 + ((first - 0xd800) << 10) + (second - 0xdc00);
                return char::from_u32(code).map(|ch| (ch, 12));
            }
        }
        return None;
    }
    char::from_u32(first).map(|ch| (ch, 6))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(serde::Deserialize)]
    struct Fixture {
        engine: String,
        transforms: Vec<String>,
        inputs: Vec<String>,
        outputs: Vec<Vec<String>>,
    }

    #[test]
    fn coraza_parity() {
        let raw = include_str!("../../tests/fixtures/transform_parity.json");
        let fixture: Fixture = serde_json::from_str(raw).expect("fixture parses");
        assert!(
            fixture.engine.contains("coraza"),
            "unexpected fixture engine"
        );
        assert_eq!(fixture.inputs.len(), fixture.outputs.len());

        let mut failures = Vec::new();
        let mut checked = 0usize;
        for (row, input_hex) in fixture.inputs.iter().enumerate() {
            let input = hex::decode(input_hex).expect("input hex");
            for (column, name) in fixture.transforms.iter().enumerate() {
                let rule_name = name.to_ascii_lowercase();
                let step = Transform::from_rule_name(&rule_name)
                    .unwrap_or_else(|| panic!("unknown fixture transform {name}"));
                let mut output = Vec::new();
                step.apply_into(&input, &mut output);
                let expected = hex::decode(&fixture.outputs[row][column]).expect("output hex");
                checked += 1;
                if output != expected {
                    failures.push(format!(
                        "{name}({}): got {} want {}",
                        input_hex,
                        hex::encode(&output),
                        fixture.outputs[row][column]
                    ));
                }
            }
        }
        assert!(checked > 1000, "fixture is too small ({checked} cases)");
        assert!(
            failures.is_empty(),
            "{} of {checked} transform cases differ from Coraza:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }

    fn chain(steps: &[Transform]) -> (Vec<u32>, Vec<Vec<Transform>>) {
        let mut prefixes = vec![Vec::new()];
        let mut plan = Vec::new();
        for step in steps {
            let mut next = prefixes.last().expect("prefix").clone();
            next.push(*step);
            prefixes.push(next);
            plan.push((prefixes.len() - 1) as u32);
        }
        (plan, prefixes)
    }

    #[test]
    fn cache_reuses_prefixes_and_matches_direct_application() {
        let mut cache = TransformCache::<Transform>::new();
        let input = b"q=1%20UNION%20SELECT%20password";
        let (plan, prefixes) = chain(&[
            Transform::UrlDecode,
            Transform::Lowercase,
            Transform::CompressWhitespace,
        ]);
        cache.begin_request(prefixes.len());
        let value = cache.begin_value(input).expect("value fits");
        let first = cache
            .resolve(value, input, &plan, &prefixes)
            .expect("resolves");
        let first_bytes = cache.bytes(first.clone()).to_vec();
        let after_first = cache.entry_count();

        let second = cache
            .resolve(value, input, &plan, &prefixes)
            .expect("resolves");
        assert_eq!(cache.bytes(second), first_bytes.as_slice());
        assert_eq!(
            cache.entry_count(),
            after_first,
            "second call must be a cache hit"
        );

        let mut direct = Vec::new();
        Transform::UrlDecode.apply_into(input, &mut direct);
        let mut lower = Vec::new();
        Transform::Lowercase.apply_into(&direct, &mut lower);
        let mut compressed = Vec::new();
        Transform::CompressWhitespace.apply_into(&lower, &mut compressed);
        assert_eq!(first_bytes, compressed);
        assert_eq!(first_bytes, b"q=1 union select password");
    }

    #[test]
    fn shared_prefix_is_computed_once_across_chains() {
        let mut cache = TransformCache::<Transform>::new();
        let input = b"%41%42%43";
        let (short_plan, prefixes) = chain(&[Transform::UrlDecode]);
        // Extend the same registry with a longer chain that shares the prefix.
        let mut prefixes = prefixes;
        let mut long_steps = prefixes.last().expect("prefix").clone();
        long_steps.push(Transform::Lowercase);
        prefixes.push(long_steps);
        let long_plan = vec![1u32, 2];

        cache.begin_request(prefixes.len());
        let value = cache.begin_value(input).expect("value fits");
        cache
            .resolve(value, input, &short_plan, &prefixes)
            .expect("short");
        let entries_after_short = cache.entry_count();
        cache
            .resolve(value, input, &long_plan, &prefixes)
            .expect("long");
        assert_eq!(
            cache.entry_count(),
            entries_after_short + 1,
            "the shared urlDecode prefix must not be recomputed"
        );
    }

    #[test]
    fn output_overflow_fails_closed() {
        // The raw value fits (6 bytes) but the decoded copy would exceed the
        // 7-byte arena.
        let mut cache = TransformCache::<Transform>::with_arena_limit(7);
        cache.begin_request(2);
        let value = cache.begin_value(b"%41%42").expect("fits");
        let (plan, prefixes) = chain(&[Transform::UrlDecode]);
        let error = cache
            .resolve(value, b"%41%42", &plan, &prefixes)
            .expect_err("arena bound");
        assert_eq!(error, TransformError::ArenaOverflow);
    }

    #[test]
    fn oversized_value_fails_closed() {
        let mut cache = TransformCache::<Transform>::new();
        cache.begin_request(1);
        let big = vec![b'a'; MAX_VALUE_BYTES + 1];
        assert_eq!(
            cache.begin_value(&big).expect_err("bound"),
            TransformError::OutputOverflow
        );
    }

    #[test]
    fn value_id_must_match_the_buffer() {
        let mut cache = TransformCache::<Transform>::new();
        let (plan, prefixes) = chain(&[Transform::Identity]);
        cache.begin_request(prefixes.len());
        let value = cache.begin_value(b"abc").expect("fits");
        let other = b"abd";
        assert_eq!(
            cache
                .resolve(value, other, &plan, &prefixes)
                .expect_err("mismatched value id"),
            TransformError::OutputOverflow
        );
    }

    #[test]
    fn extended_transforms_match_coraza() {
        let apply = |step: Transform, input: &[u8]| {
            let mut output = Vec::new();
            step.apply_into(input, &mut output);
            output
        };
        assert_eq!(apply(Transform::Length, b"abcd"), b"4");
        assert_eq!(apply(Transform::Length, b""), b"0");
        assert_eq!(apply(Transform::HexEncode, b"a\xff"), b"61ff");
        assert_eq!(
            hex::encode(apply(Transform::Sha1, b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            apply(Transform::RemoveCommentsChar, b"a/*x*/b<!--c-->#d"),
            b"axbcd"
        );
        assert_eq!(apply(Transform::Utf8ToUnicode, b"abc"), b"abc");
        assert_eq!(
            apply(Transform::Utf8ToUnicode, "aäb".as_bytes()),
            b"a%u00e4b"
        );
        assert_eq!(apply(Transform::Utf8ToUnicode, b"a\xffb"), b"a%ufffdb");
        assert_eq!(apply(Transform::Utf8ToUnicode, "😀".as_bytes()), b"%u1f600");
    }

    #[test]
    fn prefix_table_dedups_shared_prefixes() {
        let chains = vec![
            vec![Transform::UrlDecode],
            vec![Transform::UrlDecode, Transform::Lowercase],
            vec![Transform::Lowercase],
        ];
        let table = PrefixTable::from_chains(&chains);
        assert_eq!(table.plan(0), &[1]);
        assert_eq!(table.plan(1), &[1, 2]);
        assert_eq!(table.plan(2), &[3]);
        assert_eq!(table.len(), 4);
        assert!(table.plan(99).is_empty());
    }
}
