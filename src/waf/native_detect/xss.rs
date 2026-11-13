//! Byte-for-byte port of libinjection's XSS detector (HTML5 tokenizer + black
//! lists).
//!
//! Transcription of `libinjection-go` v0.2.2 (`xss.go`, `xss_helpers.go`,
//! `html5.go`), which Coraza v3.3.3 uses for `@detectXSS`. The tokenizer is
//! the HTML5 spec state machine reduced to what the detector needs; the
//! classifier checks document types, black tags, black attributes, URL
//! attributes, inline styles, indirect attributes and IE conditional comments.
//!
//! The port is allocation-free: attribute/tag/URL comparisons fold case and
//! skip embedded NULs on the fly, and the HTML-entity decode used for URL
//! attributes streams through a fixed ring buffer instead of building a string.

use super::xss_data::{BLACK_ATTRS, BLACK_EVENTS, BLACK_TAGS};

pub(crate) const ATTR_NONE: u8 = 0;
pub(crate) const ATTR_BLACK: u8 = 1;
pub(crate) const ATTR_URL: u8 = 2;
pub(crate) const ATTR_STYLE: u8 = 3;
pub(crate) const ATTR_INDIRECT: u8 = 4;

const T_DATA_TEXT: u8 = 0;
const T_TAG_NAME_OPEN: u8 = 1;
const T_TAG_NAME_CLOSE: u8 = 2;
const T_TAG_NAME_SELF_CLOSE: u8 = 3;

const T_TAG_CLOSE: u8 = 5;
const T_ATTR_NAME: u8 = 6;
const T_ATTR_VALUE: u8 = 7;
const T_TAG_COMMENT: u8 = 8;
const T_DOC_TYPE: u8 = 9;

const FLAG_DATA_STATE: u8 = 0;
const FLAG_VALUE_NO_QUOTE: u8 = 1;
const FLAG_VALUE_SINGLE_QUOTE: u8 = 2;
const FLAG_VALUE_DOUBLE_QUOTE: u8 = 3;
const FLAG_VALUE_BACK_QUOTE: u8 = 4;

const BYTE_EOF: i32 = -1;
const BYTE_BANG: u8 = 33;
const BYTE_PERCENT: u8 = 37;
const BYTE_DASH: u8 = 45;
const BYTE_SLASH: u8 = 47;
const BYTE_LT: u8 = 60;
const BYTE_EQUALS: u8 = 61;
const BYTE_GT: u8 = 62;
const BYTE_QUESTION: u8 = 63;
const BYTE_RIGHT_B: u8 = 93;
const BYTE_NULL: u8 = 0;
const BYTE_SINGLE: u8 = b'\'';
const BYTE_DOUBLE: u8 = b'"';
const BYTE_TICK: u8 = b'`';

fn is_h5_white(ch: u8) -> bool {
    matches!(ch, b'\n' | b'\t' | 0x0b | 0x0c | b'\r' | b' ')
}

/// ASCII-uppercase, NUL-stripped equality against an already-uppercase literal.
fn eq_upper_no_null(candidate: &str, raw: &[u8]) -> bool {
    let candidate = candidate.as_bytes();
    let mut i = 0;
    for &b in raw {
        if b == BYTE_NULL {
            continue;
        }
        if i >= candidate.len() || candidate[i] != b.to_ascii_uppercase() {
            return false;
        }
        i += 1;
    }
    i == candidate.len()
}

/// Number of bytes left after stripping NULs.
fn len_no_null(raw: &[u8]) -> usize {
    raw.iter().filter(|&&b| b != BYTE_NULL).count()
}

/// Case-insensitive prefix match that skips NULs in `raw`, returning the
/// remainder of `raw` after the prefix (NULs preserved).
fn strip_prefix_no_null<'a>(raw: &'a [u8], prefix: &str) -> Option<&'a [u8]> {
    let prefix = prefix.as_bytes();
    let mut i = 0;
    for (pos, &b) in raw.iter().enumerate() {
        if b == BYTE_NULL {
            continue;
        }
        if i >= prefix.len() {
            return Some(&raw[pos..]);
        }
        if prefix[i] != b.to_ascii_uppercase() {
            return None;
        }
        i += 1;
    }
    if i == prefix.len() {
        Some(&raw[raw.len()..])
    } else {
        None
    }
}

fn is_black_tag(tag: &[u8]) -> bool {
    if tag.len() < 3 {
        return false;
    }
    if BLACK_TAGS.iter().any(|name| eq_upper_no_null(name, tag)) {
        return true;
    }
    // Anything SVG or XSL(t) related.
    eq_upper_no_null("SVT", tag) || eq_upper_no_null("XSL", tag)
}

fn is_black_attr(attr: &[u8]) -> u8 {
    let length = len_no_null(attr);
    if length < 2 {
        return ATTR_NONE;
    }
    if length >= 5 {
        if eq_upper_no_null("XMLNS", attr) || eq_upper_no_null("XLINK", attr) {
            return ATTR_BLACK;
        }
        // JavaScript `on*` event handlers.
        if let Some(event_name) = strip_prefix_no_null(attr, "ON") {
            if BLACK_EVENTS
                .iter()
                .any(|name| eq_upper_no_null(name, event_name))
            {
                return ATTR_BLACK;
            }
        }
    }
    BLACK_ATTRS
        .iter()
        .find(|(name, _)| eq_upper_no_null(name, attr))
        .map(|(_, ty)| *ty)
        .unwrap_or(ATTR_NONE)
}

fn hex_val(b: u8) -> u32 {
    match b {
        b'0'..=b'9' => (b - b'0') as u32,
        b'a'..=b'f' => (b - b'a' + 10) as u32,
        b'A'..=b'F' => (b - b'A' + 10) as u32,
        _ => 256,
    }
}

/// Decode one HTML entity at the start of `s`, returning `(value, consumed)`.
fn html_decode_byte_at(s: &[u8]) -> (i32, usize) {
    let length = s.len();
    if length == 0 {
        return (BYTE_EOF, 0);
    }
    if s[0] != b'&' || length < 2 {
        return (s[0] as i32, 1);
    }
    if s[1] != b'#' || length < 3 {
        return (b'&' as i32, 1);
    }

    if s[2] == b'x' || s[2] == b'X' {
        if length < 4 {
            return (b'&' as i32, 1);
        }
        let mut val = hex_val(s[3]);
        if val == 256 {
            return (b'&' as i32, 1);
        }
        let mut i = 4;
        while i < length {
            if s[i] == b';' {
                return (val as i32, i + 1);
            }
            let ch = hex_val(s[i]);
            if ch == 256 {
                return (val as i32, i);
            }
            val = val * 16 + ch;
            if val > 0x1000FF {
                return (b'&' as i32, 1);
            }
            i += 1;
        }
        return (val as i32, i);
    }

    let mut i = 2;
    if s[i] < b'0' || s[i] > b'9' {
        return (b'&' as i32, 1);
    }
    let mut val = (s[i] - b'0') as u32;
    i += 1;
    while i < length {
        if s[i] == b';' {
            return (val as i32, i + 1);
        }
        if s[i] < b'0' || s[i] > b'9' {
            return (val as i32, i);
        }
        val = val * 10 + (s[i] - b'0') as u32;
        if val > 0x1000FF {
            return (b'&' as i32, 1);
        }
        i += 1;
    }
    (val as i32, i)
}

/// `Contains(html_decode_upper(b), a)`, streamed through a fixed ring buffer.
fn html_encode_starts_with(needle: &str, hay: &[u8]) -> bool {
    let needle = needle.as_bytes();
    let n = needle.len();
    if n == 0 {
        return true;
    }
    let mut window = [0u8; 16];
    let mut filled = 0usize;
    let mut first = true;
    let mut pos = 0usize;

    while pos < hay.len() {
        let (cb, consumed) = html_decode_byte_at(&hay[pos..]);
        pos += consumed.max(1);

        if first && cb <= 32 {
            // Ignore leading whitespace and control characters.
            continue;
        }
        first = false;

        if cb == 0 || cb == 10 {
            // Ignore NULs and vertical tabs.
            continue;
        }
        let mut byte = cb as u8;
        if byte.is_ascii_lowercase() {
            byte -= 0x20;
        }

        if filled < n {
            window[filled] = byte;
            filled += 1;
            if filled == n && &window[..n] == needle {
                return true;
            }
        } else {
            window.copy_within(1..n, 0);
            window[n - 1] = byte;
            if &window[..n] == needle {
                return true;
            }
        }
    }
    false
}

fn is_black_url(url: &[u8]) -> bool {
    // Skip leading controls and high-bit bytes (Opera/EUC-JP quirks).
    let mut start = 0;
    while start < url.len() && (url[start] <= 32 || url[start] >= 127) {
        start += 1;
    }
    let url = &url[start..];

    ["DATA", "VIEW-SOURCE", "VBSCRIPT", "JAVA"]
        .iter()
        .any(|needle| html_encode_starts_with(needle, url))
}

struct H5<'a> {
    s: &'a [u8],
    len: usize,
    pos: usize,
    is_close: bool,
    state: State,
    token_start: usize,
    token_len: usize,
    token_type: u8,
}

/// HTML5 tokenizer states reachable from the detector.
#[derive(Clone, Copy)]
enum State {
    Eof,
    BogusComment,
    BogusComment2,
    Comment,
    CData,
    Doctype,
    MarkupDeclarationOpen,
    SelfClosingStartTag,
    TagNameClose,
    TagName,
    EndTagOpen,
    TagOpen,
    Data,
    AttrValueNoQuote,
    BeforeAttrValue,
    AfterAttrName,
    AttrName,
    BeforeAttrName,
    AfterAttrValueQuoted,
    AttrValueSingleQuote,
    AttrValueDoubleQuote,
    AttrValueBackQuote,
}

impl<'a> H5<'a> {
    fn init(input: &'a [u8], flags: u8) -> Self {
        let mut h5 = Self {
            s: input,
            len: input.len(),
            pos: 0,
            is_close: false,
            state: State::Data,
            token_start: 0,
            token_len: 0,
            token_type: T_DATA_TEXT,
        };
        h5.state = match flags {
            FLAG_DATA_STATE => State::Data,
            FLAG_VALUE_NO_QUOTE => State::BeforeAttrName,
            FLAG_VALUE_SINGLE_QUOTE => State::AttrValueSingleQuote,
            FLAG_VALUE_DOUBLE_QUOTE => State::AttrValueDoubleQuote,
            FLAG_VALUE_BACK_QUOTE => State::AttrValueBackQuote,
            _ => State::Data,
        };
        h5
    }

    fn token(&self) -> &'a [u8] {
        let end = (self.token_start + self.token_len).min(self.len);
        &self.s[self.token_start.min(self.len)..end]
    }

    fn next(&mut self) -> bool {
        self.step()
    }

    fn step(&mut self) -> bool {
        match self.state {
            State::Eof => self.state_eof(),
            State::BogusComment => self.state_bogus_comment(),
            State::BogusComment2 => self.state_bogus_comment2(),
            State::Comment => self.state_comment(),
            State::CData => self.state_cdata(),
            State::Doctype => self.state_doctype(),
            State::MarkupDeclarationOpen => self.state_markup_declaration_open(),
            State::SelfClosingStartTag => self.state_self_closing_start_tag(),
            State::TagNameClose => self.state_tag_name_close(),
            State::TagName => self.state_tag_name(),
            State::EndTagOpen => self.state_end_tag_open(),
            State::TagOpen => self.state_tag_open(),
            State::Data => self.state_data(),
            State::AttrValueNoQuote => self.state_attribute_value_no_quote(),
            State::BeforeAttrValue => self.state_before_attribute_value(),
            State::AfterAttrName => self.state_after_attribute_name(),
            State::AttrName => self.state_attribute_name(),
            State::BeforeAttrName => self.state_before_attribute_name(),
            State::AfterAttrValueQuoted => self.state_after_attribute_value_quoted(),
            State::AttrValueSingleQuote => self.state_attribute_value_single_quote(),
            State::AttrValueDoubleQuote => self.state_attribute_value_double_quote(),
            State::AttrValueBackQuote => self.state_attribute_value_back_quote(),
        }
    }

    fn skip_white(&mut self) -> i32 {
        while self.pos < self.len {
            match self.s[self.pos] {
                0x00 | 0x20 | 0x09 | 0x0a | 0x0b | 0x0c | 0x0d => self.pos += 1,
                ch => return ch as i32,
            }
        }
        BYTE_EOF
    }

    fn state_eof(&mut self) -> bool {
        false
    }

    fn state_bogus_comment(&mut self) -> bool {
        let index = self.s[self.pos..].iter().position(|&b| b == BYTE_GT);
        match index {
            None => {
                self.token_start = self.pos;
                self.token_len = self.len - self.pos;
                self.pos = self.len;
                self.state = State::Eof;
            }
            Some(index) => {
                self.token_start = self.pos;
                self.token_len = index;
                self.pos += index + 1;
                self.state = State::Data;
            }
        }
        self.token_type = T_TAG_COMMENT;
        true
    }

    fn state_bogus_comment2(&mut self) -> bool {
        let mut pos = self.pos;
        loop {
            let index = self.s[pos..].iter().position(|&b| b == BYTE_PERCENT);
            // Upstream indexes from `h.pos`, not the local cursor, so both
            // bounds have to hold before dereferencing.
            let index = match index {
                Some(index) if pos + index + 1 < self.len && self.pos + index + 1 < self.len => {
                    index
                }
                _ => {
                    self.token_start = self.pos;
                    self.token_len = self.len - self.pos;
                    self.pos = self.len;
                    self.token_type = T_TAG_COMMENT;
                    self.state = State::Eof;
                    return true;
                }
            };

            // Upstream indexes from `h.pos`, not the local cursor.
            if self.s[self.pos + index + 1] != BYTE_GT {
                pos += index + 1;
                continue;
            }

            self.token_start = self.pos;
            self.token_len = index;
            self.pos = pos + index + 2;
            self.state = State::Data;
            self.token_type = T_TAG_COMMENT;
            return true;
        }
    }

    fn state_comment(&mut self) -> bool {
        let mut pos = self.pos;
        loop {
            let index = self.s[pos..].iter().position(|&b| b == BYTE_DASH);
            let index = match index {
                Some(index) if pos + index + 3 <= self.len => index,
                _ => {
                    self.state = State::Eof;
                    self.token_start = self.pos;
                    self.token_len = self.len - self.pos;
                    self.token_type = T_TAG_COMMENT;
                    return true;
                }
            };

            let mut offset = 1;
            while pos + index + offset < self.len && self.s[pos + index + offset] == 0x00 {
                offset += 1;
            }
            if pos + index + offset == self.len {
                self.state = State::Eof;
                self.token_start = self.pos;
                self.token_len = self.len - self.pos;
                self.token_type = T_TAG_COMMENT;
                return true;
            }

            let ch = self.s[pos + index + offset];
            if ch != BYTE_DASH && ch != BYTE_BANG {
                pos += index + 1;
                continue;
            }
            offset += 1;

            if pos + index + offset == self.len {
                self.state = State::Eof;
                self.token_start = self.pos;
                self.token_len = self.len - self.pos;
                self.token_type = T_TAG_COMMENT;
                return true;
            }
            if self.s[pos + index + offset] != BYTE_GT {
                pos += index + 1;
                continue;
            }
            offset += 1;

            self.token_start = self.pos;
            self.token_len = index + pos - self.pos;
            self.pos = pos + index + offset;
            self.state = State::Data;
            self.token_type = T_TAG_COMMENT;
            return true;
        }
    }

    fn state_cdata(&mut self) -> bool {
        let mut pos = self.pos;
        loop {
            let index = self.s[pos..].iter().position(|&b| b == BYTE_RIGHT_B);
            match index {
                None => {
                    self.state = State::Eof;
                    self.token_start = self.pos;
                    self.token_len = self.len - self.pos;
                    self.token_type = T_DATA_TEXT;
                    return true;
                }
                Some(index) if self.pos + index + 3 > self.len => {
                    self.state = State::Eof;
                    self.token_start = self.pos;
                    self.token_len = self.len - self.pos;
                    self.token_type = T_DATA_TEXT;
                    return true;
                }
                Some(index)
                    if pos + index + 2 < self.len
                        && self.s[pos + index + 1] == BYTE_RIGHT_B
                        && self.s[pos + index + 2] == BYTE_GT =>
                {
                    self.state = State::Data;
                    self.token_start = self.pos;
                    self.token_len = pos + index - self.pos;
                    self.pos = pos + index + 3;
                    self.token_type = T_DATA_TEXT;
                    return true;
                }
                Some(index) => pos += index + 1,
            }
        }
    }

    fn state_doctype(&mut self) -> bool {
        self.token_start = self.pos;
        self.token_type = T_DOC_TYPE;
        let index = self.s[self.pos..].iter().position(|&b| b == BYTE_GT);
        match index {
            None => {
                self.state = State::Eof;
                self.token_len = self.len - self.pos;
            }
            Some(index) => {
                self.state = State::Data;
                self.token_len = index;
                self.pos += index + 1;
            }
        }
        true
    }

    fn state_markup_declaration_open(&mut self) -> bool {
        let remaining = self.len - self.pos;
        if remaining >= 7 && self.s[self.pos..self.pos + 7].eq_ignore_ascii_case(b"doctype") {
            return self.state_doctype();
        }
        if remaining >= 7 && &self.s[self.pos..self.pos + 7] == b"[CDATA[" {
            self.pos += 7;
            return self.state_cdata();
        }
        if remaining >= 2 && &self.s[self.pos..self.pos + 2] == b"--" {
            self.pos += 2;
            return self.state_comment();
        }
        self.state_bogus_comment()
    }

    fn state_self_closing_start_tag(&mut self) -> bool {
        if self.pos >= self.len {
            return false;
        }
        if self.s[self.pos] == BYTE_GT {
            self.token_start = self.pos - 1;
            self.token_len = 2;
            self.token_type = T_TAG_NAME_SELF_CLOSE;
            self.state = State::Data;
            self.pos += 1;
            return true;
        }
        self.state_before_attribute_name()
    }

    fn state_tag_name_close(&mut self) -> bool {
        self.is_close = false;
        self.token_start = self.pos;
        self.token_len = 1;
        self.token_type = T_TAG_NAME_CLOSE;
        self.pos += 1;
        if self.pos < self.len {
            self.state = State::Data;
        } else {
            self.state = State::Eof;
        }
        true
    }

    fn state_tag_name(&mut self) -> bool {
        let mut pos = self.pos;
        while pos < self.len {
            let ch = self.s[pos];
            if ch == 0 {
                pos += 1;
            } else if is_h5_white(ch) {
                self.token_start = self.pos;
                self.token_len = pos - self.pos;
                self.token_type = T_TAG_NAME_OPEN;
                self.pos = pos + 1;
                self.state = State::BeforeAttrName;
                return true;
            } else if ch == BYTE_SLASH {
                self.token_start = self.pos;
                self.token_len = pos - self.pos;
                self.token_type = T_TAG_NAME_OPEN;
                self.pos = pos + 1;
                self.state = State::SelfClosingStartTag;
                return true;
            } else if ch == BYTE_GT {
                self.token_start = self.pos;
                self.token_len = pos - self.pos;
                if self.is_close {
                    self.pos = pos + 1;
                    self.is_close = false;
                    self.token_type = T_TAG_CLOSE;
                    self.state = State::Data;
                } else {
                    self.pos = pos;
                    self.token_type = T_TAG_NAME_OPEN;
                    self.state = State::TagNameClose;
                }
                return true;
            } else {
                pos += 1;
            }
        }

        self.token_start = self.pos;
        self.token_len = self.len - self.pos;
        self.token_type = T_TAG_NAME_OPEN;
        self.state = State::Eof;
        true
    }

    fn state_end_tag_open(&mut self) -> bool {
        if self.pos >= self.len {
            return false;
        }
        let ch = self.s[self.pos];
        if ch == BYTE_GT {
            self.state_data()
        } else if ch.is_ascii_alphabetic() {
            self.state_tag_name()
        } else {
            self.is_close = false;
            self.state_bogus_comment()
        }
    }

    fn state_tag_open(&mut self) -> bool {
        if self.pos >= self.len {
            return false;
        }
        let ch = self.s[self.pos];
        match ch {
            BYTE_BANG => {
                self.pos += 1;
                self.state_markup_declaration_open()
            }
            BYTE_SLASH => {
                self.pos += 1;
                self.is_close = true;
                self.state_end_tag_open()
            }
            BYTE_QUESTION => {
                self.pos += 1;
                self.state_bogus_comment()
            }
            BYTE_PERCENT => {
                self.pos += 1;
                self.state_bogus_comment2()
            }
            _ if ch.is_ascii_alphabetic() => self.state_tag_name(),
            BYTE_NULL => self.state_tag_name(),
            _ => {
                if self.pos == 0 {
                    return self.state_data();
                }
                self.token_start = self.pos - 1;
                self.token_len = 1;
                self.token_type = T_DATA_TEXT;
                self.state = State::Data;
                true
            }
        }
    }

    fn state_data(&mut self) -> bool {
        let index = self.s[self.pos..].iter().position(|&b| b == BYTE_LT);
        match index {
            None => {
                self.token_start = self.pos;
                self.token_len = self.len - self.pos;
                self.token_type = T_DATA_TEXT;
                self.state = State::Eof;
                if self.token_len == 0 {
                    return false;
                }
            }
            Some(index) => {
                self.token_start = self.pos;
                self.token_type = T_DATA_TEXT;
                self.token_len = index;
                self.pos += index + 1;
                self.state = State::TagOpen;
                if self.token_len == 0 {
                    return self.state_tag_open();
                }
            }
        }
        true
    }

    fn state_attribute_value_no_quote(&mut self) -> bool {
        let mut pos = self.pos;
        while pos < self.len {
            let ch = self.s[pos];
            if is_h5_white(ch) {
                self.token_type = T_ATTR_VALUE;
                self.token_start = self.pos;
                self.token_len = pos - self.pos;
                self.pos = pos + 1;
                self.state = State::BeforeAttrName;
                return true;
            } else if ch == BYTE_GT {
                self.token_type = T_ATTR_VALUE;
                self.token_start = self.pos;
                self.token_len = pos - self.pos;
                self.pos = pos;
                self.state = State::TagNameClose;
                return true;
            }
            pos += 1;
        }
        self.state = State::Eof;
        self.token_start = self.pos;
        self.token_len = self.len - self.pos;
        self.token_type = T_ATTR_VALUE;
        true
    }

    fn state_before_attribute_value(&mut self) -> bool {
        let ch = self.skip_white();
        if ch == BYTE_EOF {
            self.state = State::Eof;
            return false;
        }
        match ch as u8 {
            BYTE_DOUBLE => self.state_attribute_value_double_quote(),
            BYTE_SINGLE => self.state_attribute_value_single_quote(),
            BYTE_TICK => self.state_attribute_value_back_quote(),
            _ => self.state_attribute_value_no_quote(),
        }
    }

    fn state_after_attribute_name(&mut self) -> bool {
        let ch = self.skip_white();
        if ch == BYTE_EOF {
            return false;
        }
        match ch as u8 {
            BYTE_SLASH => {
                self.pos += 1;
                self.state_self_closing_start_tag()
            }
            BYTE_EQUALS => {
                self.pos += 1;
                self.state_before_attribute_value()
            }
            BYTE_GT => self.state_tag_name_close(),
            _ => self.state_attribute_name(),
        }
    }

    fn state_attribute_name(&mut self) -> bool {
        let mut pos = self.pos + 1;
        while pos < self.len {
            let ch = self.s[pos];
            if is_h5_white(ch) {
                self.token_start = self.pos;
                self.token_len = pos - self.pos;
                self.token_type = T_ATTR_NAME;
                self.state = State::AfterAttrName;
                self.pos = pos + 1;
                return true;
            } else if ch == BYTE_SLASH {
                self.token_start = self.pos;
                self.token_len = pos - self.pos;
                self.token_type = T_ATTR_NAME;
                self.state = State::SelfClosingStartTag;
                self.pos = pos + 1;
                return true;
            } else if ch == BYTE_EQUALS {
                self.token_start = self.pos;
                self.token_len = pos - self.pos;
                self.token_type = T_ATTR_NAME;
                self.state = State::BeforeAttrValue;
                self.pos = pos + 1;
                return true;
            } else if ch == BYTE_GT {
                self.token_start = self.pos;
                self.token_len = pos - self.pos;
                self.token_type = T_ATTR_NAME;
                self.state = State::TagNameClose;
                self.pos = pos;
                return true;
            }
            pos += 1;
        }

        self.token_start = self.pos;
        self.token_len = self.len - self.pos;
        self.token_type = T_ATTR_NAME;
        self.state = State::Eof;
        self.pos = self.len;
        true
    }

    fn state_before_attribute_name(&mut self) -> bool {
        while self.pos < self.len {
            let ch = self.skip_white();
            if ch == BYTE_EOF {
                return false;
            }
            match ch as u8 {
                BYTE_SLASH => {
                    self.pos += 1;
                    // Inline the self-closing transition to avoid recursion.
                    if self.pos < self.len && self.s[self.pos] != BYTE_GT {
                        continue;
                    }
                    return self.state_self_closing_start_tag();
                }
                BYTE_GT => {
                    self.state = State::Data;
                    self.token_start = self.pos;
                    self.token_len = 1;
                    self.token_type = T_TAG_NAME_CLOSE;
                    self.pos += 1;
                    return true;
                }
                _ => return self.state_attribute_name(),
            }
        }
        false
    }

    fn state_after_attribute_value_quoted(&mut self) -> bool {
        if self.pos >= self.len {
            return false;
        }
        let ch = self.s[self.pos];
        if is_h5_white(ch) {
            self.pos += 1;
            self.state_before_attribute_name()
        } else if ch == BYTE_SLASH {
            self.pos += 1;
            self.state_self_closing_start_tag()
        } else if ch == BYTE_GT {
            self.token_start = self.pos;
            self.token_len = 1;
            self.token_type = T_TAG_NAME_CLOSE;
            self.pos += 1;
            self.state = State::Data;
            true
        } else {
            self.state_before_attribute_name()
        }
    }

    fn state_attribute_value_quote(&mut self, ch: u8) -> bool {
        if self.pos > 0 {
            self.pos += 1;
        }
        let index = self.s[self.pos..].iter().position(|&b| b == ch);
        match index {
            None => {
                self.token_start = self.pos;
                self.token_len = self.len - self.pos;
                self.token_type = T_ATTR_VALUE;
                self.state = State::Eof;
            }
            Some(index) => {
                self.token_start = self.pos;
                self.token_len = index;
                self.token_type = T_ATTR_VALUE;
                self.state = State::AfterAttrValueQuoted;
                self.pos += index + 1;
            }
        }
        true
    }

    fn state_attribute_value_single_quote(&mut self) -> bool {
        self.state_attribute_value_quote(BYTE_SINGLE)
    }

    fn state_attribute_value_double_quote(&mut self) -> bool {
        self.state_attribute_value_quote(BYTE_DOUBLE)
    }

    fn state_attribute_value_back_quote(&mut self) -> bool {
        self.state_attribute_value_quote(BYTE_TICK)
    }
}

fn is_xss(input: &[u8], flags: u8) -> bool {
    let mut h5 = H5::init(input, flags);
    let mut attr = ATTR_NONE;

    while h5.next() {
        if h5.token_type != T_ATTR_VALUE {
            attr = ATTR_NONE;
        }

        match h5.token_type {
            T_DOC_TYPE => return true,
            T_TAG_NAME_OPEN => {
                if is_black_tag(h5.token()) {
                    return true;
                }
            }
            T_ATTR_NAME => attr = is_black_attr(h5.token()),
            T_ATTR_VALUE => {
                match attr {
                    ATTR_NONE => {}
                    ATTR_BLACK => return true,
                    ATTR_URL => {
                        if is_black_url(h5.token()) {
                            return true;
                        }
                    }
                    ATTR_STYLE => return true,
                    ATTR_INDIRECT if is_black_attr(h5.token()) == ATTR_BLACK => return true,
                    ATTR_INDIRECT => {}
                    _ => {}
                }
                attr = ATTR_NONE;
            }
            T_TAG_COMMENT => {
                let token = h5.token();
                // IE uses "`" as a tag ending byte.
                if token.contains(&BYTE_TICK) {
                    return true;
                }
                if token.len() > 3 {
                    if token[0] == b'[' && token[1..3].eq_ignore_ascii_case(b"IF") {
                        return true;
                    }
                    if token.len() >= 4 && token[1..4].eq_ignore_ascii_case(b"XML") {
                        return true;
                    }
                }
                if token.len() > 5 {
                    let mut upper = [0u8; 6];
                    let mut n = 0;
                    for &b in &token[..6] {
                        if b == BYTE_NULL {
                            continue;
                        }
                        upper[n] = b.to_ascii_uppercase();
                        n += 1;
                    }
                    if &upper[..n] == b"IMPORT" || &upper[..n] == b"ENTITY" {
                        return true;
                    }
                }
            }
            _ => {}
        }
    }

    false
}

/// Returns `true` when libinjection classifies `input` as XSS.
pub(crate) fn is_xss_detect(input: &[u8]) -> bool {
    is_xss(input, FLAG_DATA_STATE)
        || is_xss(input, FLAG_VALUE_NO_QUOTE)
        || is_xss(input, FLAG_VALUE_SINGLE_QUOTE)
        || is_xss(input, FLAG_VALUE_DOUBLE_QUOTE)
        || is_xss(input, FLAG_VALUE_BACK_QUOTE)
}
