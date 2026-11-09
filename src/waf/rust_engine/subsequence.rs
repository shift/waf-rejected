//! Ordered-subsequence prerequisites extracted from `@rx` patterns.
//!
//! A set of CRS regexes (the RCE command families) deliberately allows shell
//! filler between every character of a command word, so no contiguous literal
//! survives extraction. What does survive is an **ordered subsequence**: every
//! string that matches `c[\"'0-9]*a[\"'0-9]*t` must contain `c`, then `a`, then
//! `t`. Proving the subsequence absent proves the regex cannot match, which is
//! exactly the contract the per-rule gate needs.
//!
//! The extractor is deliberately conservative:
//!
//! * only patterns that are pure ASCII, use no Unicode classes/escapes and no
//!   scoped inline flags are considered (Unicode case folding could match a
//!   byte sequence the ASCII folding here would miss);
//! * only literal atoms and fully understood character classes become
//!   *steps*; dots, anchors, word boundaries, back-references and unknown
//!   constructs are ignored. Ignoring an atom is always sound: it only makes
//!   the prerequisite weaker, never wrong;
//! * optional atoms (`?`, `*`, `{0,n}`) contribute no step, because a match may
//!   skip them;
//! * alternation is modelled as a disjunction (at least one branch must be
//!   satisfied) and concatenation as a conjunction, so the result is an
//!   OR-of-AND-of-OR of sequences. When combining would exceed [`MAX_ALTS`] the
//!   weaker side is dropped, which is a sound weakening;
//! * anything the parser cannot prove is returned as [`Req::trivial`], and the
//!   caller leaves the rule ungated.
//!
//! Matching is a greedy subsequence scan. Each step is a 256-bit byte set
//! (case-folded when the pattern is case-insensitive) with an optional maximum
//! gap in bytes. A one-byte step uses `memchr`; class steps use a byte-set
//! lookup. A per-value presence bitmap rejects most sequences without scanning
//! the value.

use memchr::memchr;

/// Maximum number of disjunctive alternatives kept for one rule. Exceeding the
/// cap drops the requirement instead of truncating it: truncating an OR would
/// be unsound.
const MAX_ALTS: usize = 256;

/// Regexes in this set are the RCE command families. They are the only rules
/// analysed: each has identity transforms and filler between command letters,
/// and together they dominate the residual regex time.
const SUBSEQUENCE_RULES: [u32; 7] = [932125, 932230, 932235, 932250, 932260, 932370, 932380];

/// Unlimited gap between two matched steps.
pub(crate) const GAP_UNLIMITED: u32 = u32::MAX;

/// One required byte position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Step {
    mask: [u64; 4],
    /// The single accepted byte, when the set has exactly one member.
    byte: Option<u8>,
    /// Maximum number of bytes between the end of the previous step and the
    /// start of this one. [`GAP_UNLIMITED`] means "any distance".
    max_gap: u32,
}

impl Step {
    fn new(mask: [u64; 4]) -> Self {
        let mut byte = None;
        let mut count = 0u32;
        let mut single = 0u8;
        for (word_index, word) in mask.iter().enumerate() {
            let mut word = *word;
            while word != 0 {
                let bit = word.trailing_zeros() as usize;
                let value = (word_index * 64 + bit) as u8;
                single = value;
                count += 1;
                word &= word - 1;
            }
        }
        if count == 1 {
            byte = Some(single);
        }
        Self {
            mask,
            byte,
            max_gap: GAP_UNLIMITED,
        }
    }

    #[inline]
    fn contains(&self, byte: u8) -> bool {
        self.mask[usize::from(byte) >> 6] & (1u64 << (byte & 63)) != 0
    }

    /// True when at least one accepted byte occurs in the value at all.
    #[inline]
    fn present(&self, present: &[u64; 4]) -> bool {
        self.mask
            .iter()
            .zip(present)
            .any(|(required, seen)| required & seen != 0)
    }

    #[cfg(test)]
    fn from_bytes(bytes: &[u8], max_gap: u32) -> Self {
        let mut step = Self::new(byte_set(bytes));
        step.max_gap = max_gap;
        step
    }
}

/// One ordered subsequence requirement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Sequence {
    steps: Vec<Step>,
}

impl Sequence {
    fn new(steps: Vec<Step>) -> Self {
        Self { steps }
    }

    /// True when `bytes` contains this sequence in order.
    pub(crate) fn matches(&self, bytes: &[u8], present: &[u64; 4]) -> bool {
        let mut position = 0usize;
        for step in &self.steps {
            // Cheap rejection: a byte the step needs does not occur anywhere.
            if !step.present(present) {
                return false;
            }
            let limit = if step.max_gap == GAP_UNLIMITED {
                bytes.len()
            } else {
                position
                    .saturating_add(usize::try_from(step.max_gap).unwrap_or(usize::MAX))
                    .saturating_add(1)
                    .min(bytes.len())
            };
            if position >= limit {
                return false;
            }
            let found = match step.byte {
                Some(byte) => memchr(byte, &bytes[position..limit]),
                None => bytes[position..limit]
                    .iter()
                    .position(|&byte| step.contains(byte)),
            };
            let Some(offset) = found else {
                return false;
            };
            position += offset + 1;
        }
        true
    }
}

/// A disjunction of sequences: at least one member must match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Clause {
    sequences: Vec<Sequence>,
}

impl Clause {
    fn matches(&self, bytes: &[u8], present: &[u64; 4]) -> bool {
        self.sequences
            .iter()
            .any(|sequence| sequence.matches(bytes, present))
    }
}

/// Sound prerequisite for one regex: at least one alternative (an AND of
/// clauses) must be satisfied. An empty alternative list means "no
/// requirement"; an empty alternative means "always satisfied".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Req {
    /// Clause ids per alternative. All ids must be satisfied.
    alts: Vec<Vec<u16>>,
    clauses: Vec<Clause>,
}

impl Req {
    fn trivial() -> Self {
        Self {
            alts: vec![Vec::new()],
            clauses: Vec::new(),
        }
    }

    fn atom(step: Step) -> Self {
        let mut req = Self::default();
        req.clauses.push(Clause {
            sequences: vec![Sequence::new(vec![step])],
        });
        req.alts.push(vec![0]);
        req
    }

    /// True when the requirement proves nothing.
    fn is_trivial(&self) -> bool {
        self.alts.is_empty() || self.alts.iter().any(Vec::is_empty)
    }

    /// Number of alternatives, used to choose the cheaper side on overflow.
    fn alternative_count(&self) -> usize {
        self.alts.len()
    }

    /// Total number of steps across every stored sequence.
    fn step_count(&self) -> usize {
        self.clauses
            .iter()
            .flat_map(|clause| &clause.sequences)
            .map(|sequence| sequence.steps.len())
            .sum()
    }

    /// Concatenation: the match must satisfy both requirements.
    fn concat(mut self, other: Self) -> Self {
        if self.is_trivial() {
            return other;
        }
        if other.is_trivial() {
            return self;
        }
        if self.alts.len().saturating_mul(other.alts.len()) > MAX_ALTS {
            // Dropping one conjunct is a sound weakening. Keep the side with
            // fewer alternatives (cheaper to evaluate); break ties on total
            // step count, then on the larger set for selectivity.
            return if (self.alternative_count(), self.step_count())
                <= (other.alternative_count(), other.step_count())
            {
                self
            } else {
                other
            };
        }

        let offset = self.clauses.len();
        self.clauses.extend(other.clauses);
        let mut alts = Vec::with_capacity(self.alts.len() * other.alts.len());
        for left in &self.alts {
            for right in &other.alts {
                let mut combined = left.clone();
                combined.extend(right.iter().map(|id| *id + offset as u16));
                alts.push(combined);
            }
        }
        self.alts = alts;
        self.minimise();
        self
    }

    /// Alternation: the match must satisfy at least one branch.
    fn union(mut self, other: Self) -> Self {
        if self.is_trivial() || other.is_trivial() {
            return Self::trivial();
        }
        let offset = self.clauses.len();
        self.clauses.extend(other.clauses);
        for alt in other.alts {
            self.alts
                .push(alt.into_iter().map(|id| id + offset as u16).collect());
        }
        if self.alts.len() > MAX_ALTS {
            return Self::trivial();
        }
        self.minimise();
        self
    }

    /// Removes duplicate alternatives and alternatives that are strict
    /// supersets of another one. If A's clauses are a subset of B's, A is
    /// easier to satisfy, so B adds nothing (OR).
    #[allow(clippy::needless_range_loop)]
    fn minimise(&mut self) {
        self.alts.sort();
        self.alts.dedup();
        if self.alts.len() <= 1 {
            return;
        }
        let mut keep = vec![true; self.alts.len()];
        for index in 0..self.alts.len() {
            if !keep[index] {
                continue;
            }
            for other in 0..self.alts.len() {
                if index == other || !keep[other] {
                    continue;
                }
                let (left, right) = (&self.alts[index], &self.alts[other]);
                if left.len() < right.len() && is_subset(left, right) {
                    keep[other] = false;
                }
            }
        }
        let mut index = 0;
        self.alts.retain(|_| {
            let keep_this = keep[index];
            index += 1;
            keep_this
        });
    }

    /// Evaluates the prerequisite against one candidate value.
    #[inline]
    pub(crate) fn satisfied(&self, bytes: &[u8], present: &[u64; 4]) -> bool {
        self.alts.iter().any(|alt| {
            alt.iter().all(|id| {
                self.clauses
                    .get(usize::from(*id))
                    .is_some_and(|clause| clause.matches(bytes, present))
            })
        })
    }

    /// True when this requirement is worth attaching as a gate: non-trivial
    /// and containing at least two steps somewhere.
    pub(crate) fn useful(&self) -> bool {
        !self.is_trivial() && self.step_count() >= 2
    }

    /// Number of disjunctive alternatives (diagnostics).
    pub fn alternatives(&self) -> usize {
        self.alts.len()
    }

    /// Total stored steps (diagnostics).
    pub fn steps(&self) -> usize {
        self.step_count()
    }
}

fn is_subset(left: &[u16], right: &[u16]) -> bool {
    left.iter().all(|id| right.contains(id))
}

fn byte_set(bytes: &[u8]) -> [u64; 4] {
    let mut mask = [0u64; 4];
    for &byte in bytes {
        mask[usize::from(byte) >> 6] |= 1u64 << (byte & 63);
    }
    mask
}

fn escape_set(escape: u8) -> Option<[u64; 4]> {
    let set: &[u8] = match escape {
        b'd' => b"0123456789",
        b'w' => b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz",
        b's' => b"\t\n\x0b\x0c\r ",
        _ => return None,
    };
    Some(byte_set(set))
}

fn complement(mask: [u64; 4]) -> [u64; 4] {
    [!mask[0], !mask[1], !mask[2], !mask[3]]
}

/// True when `id` belongs to the RCE command families this gate targets.
/// These are the filler-heavy rules named by the performance task; every other
/// family is left to the literal/`pm` gates.
pub(crate) fn is_target_rule(id: u32) -> bool {
    SUBSEQUENCE_RULES.contains(&id)
}

/// Extraction result: `None` means the pattern could not be proven, so the
/// rule must stay ungated.
pub(crate) fn extract(pattern: &str) -> Option<Req> {
    if !pattern.is_ascii()
        || pattern.contains("\\x{")
        || pattern.contains("\\p")
        || pattern.contains("\\P")
    {
        return None;
    }
    let mut parser = Parser {
        source: pattern.as_bytes(),
        position: 0,
        case_insensitive: false,
    };
    parser.parse_flags()?;
    let node = parser.parse_alternation()?;
    if parser.position != parser.source.len() {
        return None;
    }
    let requirement = derive(&node);
    requirement.useful().then_some(requirement)
}

#[derive(Debug, Clone)]
enum Node {
    /// Contributes no requirement (anchor, dot, opaque atom, empty sequence).
    Empty,
    Step(Step),
    Seq(Vec<Node>),
    Alt(Vec<Node>),
    /// `min` occurrences are mandatory; `max` is informational only.
    Repeat(Box<Node>, u32, Option<u32>),
}

fn derive(node: &Node) -> Req {
    match node {
        Node::Empty => Req::trivial(),
        Node::Step(step) => Req::atom(step.clone()),
        Node::Seq(nodes) => nodes
            .iter()
            .map(derive)
            .fold(Req::trivial(), |left, right| left.concat(right)),
        Node::Alt(nodes) => {
            let mut iter = nodes.iter();
            let Some(first) = iter.next() else {
                return Req::trivial();
            };
            let mut req = derive(first);
            for node in iter {
                req = req.union(derive(node));
            }
            req
        }
        Node::Repeat(node, min, _) => {
            if *min == 0 {
                Req::trivial()
            } else {
                derive(node)
            }
        }
    }
}

struct Parser<'a> {
    source: &'a [u8],
    position: usize,
    case_insensitive: bool,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.source.get(self.position).copied()
    }

    fn peek_at(&self, offset: usize) -> Option<u8> {
        self.source.get(self.position + offset).copied()
    }

    fn starts_with(&self, prefix: &[u8]) -> bool {
        self.source[self.position..].starts_with(prefix)
    }

    /// Consumes leading global inline flag groups such as `(?i)` or `(?im)`.
    fn parse_flags(&mut self) -> Option<()> {
        loop {
            if !self.starts_with(b"(?") {
                return Some(());
            }
            let mut offset = 2;
            let mut saw_flag = false;
            let mut case_insensitive = self.case_insensitive;
            loop {
                match self.peek_at(offset) {
                    Some(b')') => break,
                    Some(b'i') => {
                        case_insensitive = true;
                        saw_flag = true;
                        offset += 1;
                    }
                    Some(b'm' | b's' | b'x' | b'U' | b'n' | b'a') => {
                        saw_flag = true;
                        offset += 1;
                    }
                    // Scoped flags, `-` resets, lookarounds and named groups are
                    // not global flag groups: let the normal parser reject or
                    // handle them.
                    _ => return Some(()),
                }
            }
            if !saw_flag {
                return Some(());
            }
            self.case_insensitive = case_insensitive;
            self.position += offset + 1;
        }
    }

    fn parse_alternation(&mut self) -> Option<Node> {
        let mut branches = vec![self.parse_sequence()?];
        while self.peek() == Some(b'|') {
            self.position += 1;
            branches.push(self.parse_sequence()?);
        }
        if branches.len() == 1 {
            branches.pop()
        } else {
            Some(Node::Alt(branches))
        }
    }

    fn parse_sequence(&mut self) -> Option<Node> {
        let mut nodes = Vec::new();
        while let Some(byte) = self.peek() {
            if matches!(byte, b')' | b'|') {
                break;
            }
            nodes.push(self.parse_term()?);
        }
        match nodes.len() {
            0 => Some(Node::Empty),
            1 => nodes.pop(),
            _ => Some(Node::Seq(nodes)),
        }
    }

    fn parse_term(&mut self) -> Option<Node> {
        let atom = self.parse_atom()?;
        let Some((min, max)) = self.parse_quantifier() else {
            return Some(atom);
        };
        Some(Node::Repeat(Box::new(atom), min, max))
    }

    /// Parses a quantifier if one starts here. Returns `None` when the next
    /// byte is not a quantifier; a `{` that is not a valid counted repeat is
    /// left in place and read as a literal by the caller.
    fn parse_quantifier(&mut self) -> Option<(u32, Option<u32>)> {
        let result = match self.peek()? {
            b'*' => {
                self.position += 1;
                (0, None)
            }
            b'+' => {
                self.position += 1;
                (1, None)
            }
            b'?' => {
                self.position += 1;
                (0, Some(1))
            }
            b'{' => {
                let start = self.position;
                self.position += 1;
                let Some(min) = self.parse_number() else {
                    self.position = start;
                    return None;
                };
                let max = match self.peek() {
                    Some(b'}') => Some(min),
                    Some(b',') => {
                        self.position += 1;
                        if self.peek() == Some(b'}') {
                            None
                        } else {
                            let value = self.parse_number()?;
                            Some(value)
                        }
                    }
                    _ => {
                        self.position = start;
                        return None;
                    }
                };
                if self.peek() != Some(b'}') {
                    self.position = start;
                    return None;
                }
                self.position += 1;
                (min, max)
            }
            _ => return None,
        };
        // Lazy / possessive suffix.
        if matches!(self.peek(), Some(b'?' | b'+')) {
            self.position += 1;
        }
        Some(result)
    }

    fn parse_number(&mut self) -> Option<u32> {
        let start = self.position;
        let mut value: u32 = 0;
        while let Some(byte @ b'0'..=b'9') = self.peek() {
            value = value
                .saturating_mul(10)
                .saturating_add(u32::from(byte - b'0'));
            self.position += 1;
        }
        (self.position > start).then_some(value)
    }

    fn parse_atom(&mut self) -> Option<Node> {
        match self.peek()? {
            b'(' => self.parse_group(),
            b'[' => self.parse_class(),
            b'\\' => self.parse_escape(),
            b'.' | b'^' | b'$' => {
                self.position += 1;
                Some(Node::Empty)
            }
            byte => {
                self.position += 1;
                Some(self.literal(byte))
            }
        }
    }

    fn parse_group(&mut self) -> Option<Node> {
        if self.starts_with(b"(?:") {
            self.position += 3;
        } else if self.starts_with(b"(?P<") {
            let end = self.source[self.position..]
                .iter()
                .position(|&byte| byte == b'>')?;
            self.position += end + 1;
        } else {
            // Lookarounds, scoped flags, conditionals, atomic groups and named
            // groups with unsupported syntax: refuse to prove anything.
            return None;
        }
        let node = self.parse_alternation()?;
        if self.peek() != Some(b')') {
            return None;
        }
        self.position += 1;
        Some(node)
    }

    fn literal(&self, byte: u8) -> Node {
        let mut mask = byte_set(&[byte]);
        if self.case_insensitive && byte.is_ascii_alphabetic() {
            mask = byte_set(&[byte, byte.to_ascii_lowercase(), byte.to_ascii_uppercase()]);
        }
        Node::Step(Step::new(mask))
    }

    fn step_from_mask(&self, mut mask: [u64; 4]) -> Node {
        if self.case_insensitive {
            for byte in b'a'..=b'z' {
                let upper = byte.to_ascii_uppercase();
                if mask[usize::from(byte) >> 6] & (1u64 << (byte & 63)) != 0 {
                    mask[usize::from(upper) >> 6] |= 1u64 << (upper & 63);
                }
                if mask[usize::from(upper) >> 6] & (1u64 << (upper & 63)) != 0 {
                    mask[usize::from(byte) >> 6] |= 1u64 << (byte & 63);
                }
            }
        }
        if mask.iter().all(|word| *word == 0) {
            Node::Empty
        } else {
            Node::Step(Step::new(mask))
        }
    }

    fn parse_escape(&mut self) -> Option<Node> {
        self.position += 1; // '\'
        let byte = self.peek()?;
        self.position += 1;
        match byte {
            b'x' => {
                if self.peek() == Some(b'{') {
                    return None; // Unicode escape: extraction is unsupported.
                }
                let high = self.peek()?.to_ascii_uppercase();
                let low = self.peek_at(1)?.to_ascii_uppercase();
                let value = (hex(high)? << 4) | hex(low)?;
                self.position += 2;
                Some(self.literal(value))
            }
            b'0'..=b'9' => {
                // Octal escape or back-reference: variable width, ignore.
                while self.peek().is_some_and(|next| next.is_ascii_digit()) {
                    self.position += 1;
                }
                Some(Node::Empty)
            }
            b'd' | b'w' | b's' => {
                let mask = escape_set(byte)?;
                Some(self.step_from_mask(mask))
            }
            b'D' | b'W' | b'S' => {
                let mask = escape_set(byte.to_ascii_lowercase())?;
                Some(self.step_from_mask(complement(mask)))
            }
            b'v' | b'V' => Some(Node::Empty),
            b'b' | b'B' | b'A' | b'z' | b'Z' | b'C' => Some(Node::Empty),
            b'n' => Some(self.literal(b'\n')),
            b'r' => Some(self.literal(b'\r')),
            b't' => Some(self.literal(b'\t')),
            b'f' => Some(self.literal(0x0c)),
            b'a' => Some(self.literal(0x07)),
            b'e' => Some(self.literal(0x1b)),
            // Back-references, quoted literals, Unicode properties and other
            // unknown escapes: never prove a step from them.
            b'k' | b'g' | b'p' | b'P' | b'Q' | b'E' | b'h' | b'H' | b'R' | b'X' => {
                Some(Node::Empty)
            }
            other if other.is_ascii_alphanumeric() => Some(Node::Empty),
            other => Some(self.literal(other)),
        }
    }

    fn parse_class(&mut self) -> Option<Node> {
        self.position += 1; // '['
        let negated = if self.peek() == Some(b'^') {
            self.position += 1;
            true
        } else {
            false
        };
        let mut set = [0u64; 4];
        let mut understood = true;
        let mut first = true;
        loop {
            let byte = self.peek()?;
            if byte == b']' && !first {
                self.position += 1;
                break;
            }
            first = false;
            if byte == b'[' && self.peek_at(1) == Some(b':') {
                // POSIX class: consume it but do not interpret it.
                let rest = &self.source[self.position..];
                let end = rest.windows(2).position(|window| window == b":]")?;
                self.position += end + 2;
                understood = false;
                continue;
            }
            let element = self.parse_class_element()?;
            match element {
                ClassElement::Byte(low) => {
                    if self.peek() == Some(b'-') && !matches!(self.peek_at(1), Some(b']') | None) {
                        self.position += 1;
                        match self.parse_class_element()? {
                            ClassElement::Byte(high) if low <= high => {
                                for value in low..=high {
                                    add_byte(&mut set, value);
                                }
                            }
                            ClassElement::Byte(_)
                            | ClassElement::Set(_)
                            | ClassElement::Invalid => {
                                // Ambiguous range: keep the class opaque.
                                understood = false;
                            }
                        }
                    } else {
                        add_byte(&mut set, low);
                    }
                }
                ClassElement::Set(extra) => {
                    for (word, extra) in set.iter_mut().zip(extra) {
                        *word |= extra;
                    }
                }
                ClassElement::Invalid => understood = false,
            }
        }
        if !understood {
            return Some(Node::Empty);
        }
        if negated {
            set = complement(set);
        }
        Some(self.step_from_mask(set))
    }

    fn parse_class_element(&mut self) -> Option<ClassElement> {
        let byte = self.peek()?;
        if byte != b'\\' {
            self.position += 1;
            return Some(ClassElement::Byte(byte));
        }
        self.position += 1;
        let escaped = self.peek()?;
        self.position += 1;
        match escaped {
            b'x' => {
                let high = hex(self.peek()?.to_ascii_uppercase())?;
                let low = hex(self.peek_at(1)?.to_ascii_uppercase())?;
                self.position += 2;
                Some(ClassElement::Byte((high << 4) | low))
            }
            b'd' | b'w' | b's' => escape_set(escaped).map(ClassElement::Set),
            b'D' | b'W' | b'S' => escape_set(escaped.to_ascii_lowercase())
                .map(|mask| ClassElement::Set(complement(mask))),
            b'v' | b'V' => Some(ClassElement::Invalid),
            b'n' => Some(ClassElement::Byte(b'\n')),
            b'r' => Some(ClassElement::Byte(b'\r')),
            b't' => Some(ClassElement::Byte(b'\t')),
            b'f' => Some(ClassElement::Byte(0x0c)),
            b'b' => Some(ClassElement::Byte(0x08)),
            b'a' => Some(ClassElement::Byte(0x07)),
            b'e' => Some(ClassElement::Byte(0x1b)),
            b'p' | b'P' | b'Q' | b'E' | b'h' | b'H' | b'R' | b'X' | b'k' => {
                Some(ClassElement::Invalid)
            }
            other if other.is_ascii_alphanumeric() => Some(ClassElement::Invalid),
            other => Some(ClassElement::Byte(other)),
        }
    }
}

enum ClassElement {
    Byte(u8),
    Set([u64; 4]),
    Invalid,
}

fn add_byte(set: &mut [u64; 4], byte: u8) {
    set[usize::from(byte) >> 6] |= 1u64 << (byte & 63);
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{extract, Req, Step, GAP_UNLIMITED};
    use regex::bytes::Regex;

    fn present(bytes: &[u8]) -> [u64; 4] {
        let mut present = [0u64; 4];
        for &byte in bytes {
            present[usize::from(byte) >> 6] |= 1u64 << (byte & 63);
        }
        present
    }

    #[test]
    fn bounded_gap_is_honoured() {
        let step_a = Step::from_bytes(b"a", 0);
        let step_b = Step::from_bytes(b"b", 2);
        let sequence = super::Sequence::new(vec![step_a, step_b]);
        let seen = present(b"a__b");
        assert!(sequence.matches(b"a__b", &seen));
        let seen = present(b"a___b");
        assert!(!sequence.matches(b"a___b", &seen));
        let unlimited = super::Sequence::new(vec![
            Step::from_bytes(b"a", GAP_UNLIMITED),
            Step::from_bytes(b"b", GAP_UNLIMITED),
        ]);
        assert!(unlimited.matches(b"a______________b", &seen));
    }

    #[test]
    fn separates_filler_from_contiguous_literal() {
        // Every character may be separated by shell filler, so a contiguous
        // "watch" gate would miss the attack. The subsequence gate must not.
        let pattern = r#"(?i)w[\"'0-9]*a[\"'0-9]*t[\"'0-9]*c[\"'0-9]*h"#;
        let requirement = extract(pattern).expect("extracted");
        let regex = Regex::new(pattern).expect("regex");
        for payload in [b"watch".as_slice(), b"w'1'a'2't'3'c'4'h"] {
            assert!(regex.is_match(payload));
            assert!(requirement.satisfied(payload, &present(payload)));
        }
        // Subsequence present, regex absent: this is a permitted false
        // positive (the rule simply runs); it must not be reported as a miss.
        let payload = b"w a t c h";
        assert!(requirement.satisfied(payload, &present(payload)));
    }

    #[test]
    fn alternation_is_a_disjunction() {
        let requirement = extract(r"(?i)cat|dog").expect("extracted");
        assert!(requirement.satisfied(b"dog", &present(b"dog")));
        assert!(requirement.satisfied(b"c-a-t", &present(b"c-a-t")));
        assert!(!requirement.satisfied(b"bird", &present(b"bird")));
        assert_eq!(requirement.alternatives(), 2);
    }

    #[test]
    fn optional_atoms_are_not_required() {
        let requirement = extract(r"(?i)c(?:a)?t").expect("extracted");
        assert!(requirement.satisfied(b"ct", &present(b"ct")));
        assert!(!requirement.satisfied(b"cx", &present(b"cx")));
    }

    #[test]
    fn no_requirement_is_never_gated() {
        for pattern in [
            r"(?i).*",
            r"(?i)(?:cat)?",
            r"(?i)^$",
            r"(?i)\p{L}",
            r"(?i)(?=cat)",
        ] {
            assert!(
                extract(pattern).is_none(),
                "pattern must stay ungated: {pattern}"
            );
        }
    }

    /// Property: over every short string from a small alphabet, a regex match
    /// implies the extracted prerequisite is satisfied. This is the
    /// no-false-negative contract in miniature.
    #[test]
    fn extraction_is_a_sound_prerequisite() {
        let patterns = [
            r#"(?i)b[\"'\)\[\x5c]*(?:\$[\w]*)?u[\"'\)\[\x5c]*(?:\$[\w]*)?s[\"'\)\[\x5c]*(?:\$[\w]*)?y"#,
            r#"(?i)c[0-9]*a[0-9]*t|e[0-9]*v[0-9]*a[0-9]*l"#,
            r#"(?i)(?:[\n\r;`\{]|\|\|?|&&?)[\s]*[a-z]+"#,
            r#"(?i)w[^a]*a[^t]*t[^c]*c[^h]*h"#,
            r#"(?i)[ls][0-9]*t[0-9]*r[0-9]*a[0-9]*c[0-9]*e"#,
        ];
        let alphabet = b"abcdehlstw019|&;";
        for pattern in patterns {
            let requirement = extract(pattern).expect(pattern);
            let regex = Regex::new(pattern).expect(pattern);
            let mut buffer = Vec::new();
            for length in 0..=4 {
                enumerate(&mut buffer, alphabet, length, &mut |candidate| {
                    if regex.is_match(candidate) {
                        assert!(
                            requirement.satisfied(candidate, &present(candidate)),
                            "false negative for {pattern:?} on {:?}",
                            String::from_utf8_lossy(candidate)
                        );
                    }
                });
            }
        }
    }

    fn enumerate(
        buffer: &mut Vec<u8>,
        alphabet: &[u8],
        remaining: usize,
        visit: &mut impl FnMut(&[u8]),
    ) {
        if remaining == 0 {
            visit(buffer);
            return;
        }
        for &byte in alphabet {
            buffer.push(byte);
            enumerate(buffer, alphabet, remaining - 1, visit);
            buffer.pop();
        }
    }

    #[test]
    fn requirement_type_is_debug_clone() {
        // Keep the public surface honest: the gate clones requirements into
        // the compiled `GateSet`.
        fn assert_traits<T: std::fmt::Debug + Clone>() {}
        assert_traits::<Req>();
    }
}
