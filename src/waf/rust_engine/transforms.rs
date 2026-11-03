//! CRS transform implementations.
//!
//! These follow the Coraza/ModSecurity byte-oriented semantics closely enough
//! for differential testing. Values are byte strings, not UTF-8, because
//! URL/JS/CSS decoding can produce arbitrary bytes.
//!
//! Every transform writes into a caller-owned buffer
//! ([`Transform::apply_into`]). The engine's transform cache and pipeline
//! runner reuse two scratch buffers, so a steady-state request performs no
//! transform allocations. [`Transform::apply`] remains as an allocating
//! convenience wrapper for tests and one-shot callers.

use super::budget::Budget;
use super::error::EngineError;

/// A SecLang transform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Transform {
    None,
    Lowercase,
    Uppercase,
    UrlDecode,
    UrlDecodeUni,
    HtmlEntityDecode,
    JsDecode,
    CssDecode,
    CmdLine,
    ReplaceComments,
    EscapeSeqDecode,
    RemoveWhitespace,
    NormalizePath,
    NormalizePathWin,
    CompressWhitespace,
    RemoveNulls,
    Base64Decode,
    Sha1,
    HexEncode,
    RemoveCommentsChar,
    Length,
    Utf8ToUnicode,
    Trim,
    TrimLeft,
    TrimRight,
}

impl Transform {
    /// Parses a `t:` argument. Returns `None` for unknown transforms so the
    /// caller can report an unsupported construct.
    pub fn parse(name: &str) -> Option<Self> {
        let lower = name.to_ascii_lowercase();
        Some(match lower.as_str() {
            "none" => Self::None,
            "lowercase" => Self::Lowercase,
            "uppercase" => Self::Uppercase,
            "urldecode" => Self::UrlDecode,
            "urldecodeuni" => Self::UrlDecodeUni,
            "htmlentitydecode" => Self::HtmlEntityDecode,
            "jsdecode" => Self::JsDecode,
            "cssdecode" => Self::CssDecode,
            "cmdline" => Self::CmdLine,
            "replacecomments" => Self::ReplaceComments,
            "escapeseqdecode" => Self::EscapeSeqDecode,
            "removewhitespace" => Self::RemoveWhitespace,
            "normalizepath" | "normalisepath" => Self::NormalizePath,
            "normalizepathwin" | "normalisepathwin" => Self::NormalizePathWin,
            "compresswhitespace" => Self::CompressWhitespace,
            "removenulls" => Self::RemoveNulls,
            "base64decode" => Self::Base64Decode,
            "sha1" => Self::Sha1,
            "hexencode" => Self::HexEncode,
            "removecommentschar" => Self::RemoveCommentsChar,
            "length" => Self::Length,
            "utf8tounicode" => Self::Utf8ToUnicode,
            "trim" => Self::Trim,
            "trimleft" => Self::TrimLeft,
            "trimright" => Self::TrimRight,
            _ => return None,
        })
    }

    /// Applies the transform, charging the request budget.
    ///
    /// Allocating convenience wrapper. The request path uses
    /// [`Self::apply_into`] with reused buffers.
    pub fn apply(self, input: &[u8], budget: &mut Budget) -> Result<Vec<u8>, EngineError> {
        let mut out = Vec::new();
        self.apply_into(input, &mut out, budget)?;
        Ok(out)
    }

    /// Applies the transform into `out`. `out` is cleared first and keeps its
    /// capacity across calls.
    pub fn apply_into(
        self,
        input: &[u8],
        out: &mut Vec<u8>,
        budget: &mut Budget,
    ) -> Result<(), EngineError> {
        out.clear();
        match self {
            Self::None => out.extend_from_slice(input),
            Self::Lowercase => lowercase_into(input, out),
            Self::Uppercase => uppercase_into(input, out),
            Self::UrlDecode => url_decode_into(input, false, out),
            Self::UrlDecodeUni => url_decode_into(input, true, out),
            Self::HtmlEntityDecode => html_entity_decode_into(input, out),
            Self::JsDecode => js_decode_into(input, out),
            Self::CssDecode => css_decode_into(input, out),
            Self::CmdLine => cmd_line_into(input, out),
            Self::ReplaceComments => replace_comments_into(input, out),
            Self::EscapeSeqDecode => escape_seq_decode_into(input, out),
            Self::RemoveWhitespace => remove_whitespace_into(input, out),
            Self::NormalizePath => normalize_path_into(input, out),
            Self::NormalizePathWin => normalize_path_win_into(input, out),
            Self::CompressWhitespace => compress_whitespace_into(input, out),
            Self::RemoveNulls => out.extend(input.iter().copied().filter(|b| *b != 0)),
            Self::Base64Decode => base64_decode_into(input, out),
            Self::Sha1 => {
                use sha1::{Digest, Sha1};
                let mut hasher = Sha1::new();
                hasher.update(input);
                out.extend_from_slice(&hasher.finalize());
            }
            Self::HexEncode => hex_encode_into(input, out),
            Self::RemoveCommentsChar => remove_comments_char_into(input, out),
            Self::Length => push_u64(out, input.len() as u64),
            Self::Utf8ToUnicode => utf8_to_unicode_into(input, out),
            Self::Trim => {
                let (start, end) = trim_bounds(input);
                out.extend_from_slice(&input[start..end]);
            }
            Self::TrimLeft => {
                let start = input
                    .iter()
                    .position(|byte| !is_latin_space(*byte))
                    .unwrap_or(input.len());
                out.extend_from_slice(&input[start..]);
            }
            Self::TrimRight => {
                let end = input
                    .iter()
                    .rposition(|byte| !is_latin_space(*byte))
                    .map_or(0, |pos| pos + 1);
                out.extend_from_slice(&input[..end]);
            }
        }
        budget.bytes(out.len())?;
        Ok(())
    }
}

fn is_hex(byte: u8) -> bool {
    byte.is_ascii_hexdigit()
}

fn hex_value(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => 0,
    }
}

fn x2c(bytes: &[u8]) -> u8 {
    (hex_value(bytes[0]) << 4) | hex_value(bytes[1])
}

fn lowercase_into(input: &[u8], out: &mut Vec<u8>) {
    out.reserve(input.len());
    if input.is_ascii() {
        out.extend(input.iter().map(u8::to_ascii_lowercase));
        return;
    }
    let text = String::from_utf8_lossy(input);
    for ch in text.chars() {
        for lower in ch.to_lowercase() {
            push_char(out, lower);
        }
    }
}

fn uppercase_into(input: &[u8], out: &mut Vec<u8>) {
    out.reserve(input.len());
    if input.is_ascii() {
        out.extend(input.iter().map(u8::to_ascii_uppercase));
        return;
    }
    let text = String::from_utf8_lossy(input);
    for ch in text.chars() {
        for upper in ch.to_uppercase() {
            push_char(out, upper);
        }
    }
}

fn push_char(out: &mut Vec<u8>, ch: char) {
    let mut buffer = [0u8; 4];
    out.extend_from_slice(ch.encode_utf8(&mut buffer).as_bytes());
}

fn push_u64(out: &mut Vec<u8>, value: u64) {
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
    out.extend_from_slice(&buffer[cursor..]);
}

fn url_decode_into(input: &[u8], uni: bool, out: &mut Vec<u8>) {
    out.reserve(input.len());
    let mut i = 0;
    while i < input.len() {
        let byte = input[i];
        if byte == b'%' {
            if uni && i + 1 < input.len() && (input[i + 1] == b'u' || input[i + 1] == b'U') {
                if i + 5 < input.len()
                    && is_hex(input[i + 2])
                    && is_hex(input[i + 3])
                    && is_hex(input[i + 4])
                    && is_hex(input[i + 5])
                {
                    let mut value = x2c(&input[i + 4..i + 6]);
                    if value > 0
                        && value < 0x5f
                        && (input[i + 2] | 0x20) == b'f'
                        && (input[i + 3] | 0x20) == b'f'
                    {
                        value = value.wrapping_add(0x20);
                    }
                    out.push(value);
                    i += 6;
                    continue;
                }
                out.push(b'%');
                i += 1;
                continue;
            }
            if i + 2 < input.len() && is_hex(input[i + 1]) && is_hex(input[i + 2]) {
                out.push(x2c(&input[i + 1..i + 3]));
                i += 3;
                continue;
            }
            out.push(b'%');
            i += 1;
            continue;
        }
        if byte == b'+' {
            out.push(b' ');
        } else {
            out.push(byte);
        }
        i += 1;
    }
}

fn html_entity_decode_into(input: &[u8], out: &mut Vec<u8>) {
    out.reserve(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] != b'&' {
            out.push(input[i]);
            i += 1;
            continue;
        }
        let start = i;
        let mut j = i + 1;
        while j < input.len() && j - start <= 32 && input[j] != b';' {
            j += 1;
        }
        if j >= input.len() || input[j] != b';' {
            out.push(b'&');
            i += 1;
            continue;
        }
        let entity = &input[start + 1..j];
        if write_entity(entity, out) {
            i = j + 1;
        } else {
            out.push(b'&');
            i += 1;
        }
    }
}

/// Decodes one entity name/value and appends it to `out`.
fn write_entity(entity: &[u8], out: &mut Vec<u8>) -> bool {
    if entity.is_empty() {
        return false;
    }
    if entity[0] == b'#' {
        let (digits, radix) = if entity.len() > 1 && (entity[1] | 0x20) == b'x' {
            (&entity[2..], 16)
        } else {
            (&entity[1..], 10)
        };
        if digits.is_empty() {
            return false;
        }
        let mut value: u32 = 0;
        for digit in digits {
            let d = match radix {
                16 if is_hex(*digit) => hex_value(*digit),
                10 if digit.is_ascii_digit() => digit - b'0',
                _ => return false,
            };
            value = value.saturating_mul(radix).saturating_add(u32::from(d));
        }
        if value == 0 || value > 0x10ffff {
            return false;
        }
        let Some(ch) = char::from_u32(value) else {
            return false;
        };
        push_char(out, ch);
        return true;
    }
    let Ok(name) = std::str::from_utf8(entity) else {
        return false;
    };
    let value = match name {
        "amp" => "&",
        "lt" => "<",
        "gt" => ">",
        "quot" => "\"",
        "apos" => "'",
        "nbsp" => "\u{a0}",
        "colon" => ":",
        "tab" => "\t",
        "newline" => "\n",
        "sol" => "/",
        "comma" => ",",
        "period" => ".",
        "lpar" => "(",
        "rpar" => ")",
        "lsqb" | "lbrack" => "[",
        "rsqb" | "rbrack" => "]",
        "lcub" | "lbrace" => "{",
        "rcub" | "rbrace" => "}",
        "semi" => ";",
        "equals" => "=",
        "plus" => "+",
        "ast" => "*",
        "percnt" => "%",
        "quest" => "?",
        "commat" => "@",
        "dollar" => "$",
        "excl" => "!",
        "num" => "#",
        "grave" => "`",
        "Hat" => "^",
        "verbar" | "vert" => "|",
        "lowbar" => "_",
        "hyphen" | "dash" => "-",
        "hellip" => "\u{2026}",
        "mdash" => "\u{2014}",
        "ndash" => "\u{2013}",
        "lsquo" => "\u{2018}",
        "rsquo" => "\u{2019}",
        "ldquo" => "\u{201c}",
        "rdquo" => "\u{201d}",
        "bull" => "\u{2022}",
        "trade" => "\u{2122}",
        "reg" => "\u{ae}",
        "copy" => "\u{a9}",
        _ => return false,
    };
    out.extend_from_slice(value.as_bytes());
    true
}

fn js_decode_into(input: &[u8], out: &mut Vec<u8>) {
    out.reserve(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] != b'\\' || i + 1 >= input.len() {
            out.push(input[i]);
            i += 1;
            continue;
        }
        let next = input[i + 1];
        if (next | 0x20) == b'u'
            && i + 5 < input.len()
            && is_hex(input[i + 2])
            && is_hex(input[i + 3])
            && is_hex(input[i + 4])
            && is_hex(input[i + 5])
        {
            let mut value = x2c(&input[i + 4..i + 6]);
            if value > 0
                && value < 0x5f
                && (input[i + 2] | 0x20) == b'f'
                && (input[i + 3] | 0x20) == b'f'
            {
                value = value.wrapping_add(0x20);
            }
            out.push(value);
            i += 6;
            continue;
        }
        if (next | 0x20) == b'x'
            && i + 3 < input.len()
            && is_hex(input[i + 2])
            && is_hex(input[i + 3])
        {
            out.push(x2c(&input[i + 2..i + 4]));
            i += 4;
            continue;
        }
        if (b'0'..=b'7').contains(&next) {
            let mut j = 1;
            while j < 4 && i + j < input.len() && (b'0'..=b'7').contains(&input[i + j]) {
                j += 1;
            }
            let mut value: u32 = 0;
            for digit in &input[i + 1..i + j] {
                value = value * 8 + u32::from(digit - b'0');
            }
            out.push(value as u8);
            i += j;
            continue;
        }
        let escaped = match next {
            b'a' => 0x07,
            b'b' => 0x08,
            b'f' => 0x0c,
            b'n' => b'\n',
            b'r' => b'\r',
            b't' => b'\t',
            b'v' => 0x0b,
            other => other,
        };
        out.push(escaped);
        i += 2;
    }
}

fn css_decode_into(input: &[u8], out: &mut Vec<u8>) {
    out.reserve(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] != b'\\' {
            out.push(input[i]);
            i += 1;
            continue;
        }
        if i + 1 >= input.len() {
            break;
        }
        i += 1;
        let mut j = 0;
        while j < 6 && i + j < input.len() && is_hex(input[i + j]) {
            j += 1;
        }
        if j == 0 {
            if input[i] == b'\n' {
                i += 1;
                continue;
            }
            out.push(input[i]);
            i += 1;
            continue;
        }
        let mut full_check = false;
        let mut value = match j {
            1 => {
                let d = hex_value(input[i]);
                full_check = false;
                d
            }
            2 | 3 => x2c(&input[i + j - 2..i + j]),
            4 => {
                full_check = true;
                x2c(&input[i + j - 2..i + j])
            }
            5 => {
                if input[i] == b'0' {
                    full_check = true;
                }
                x2c(&input[i + j - 2..i + j])
            }
            _ => {
                if input[i] == b'0' && input[i + 1] == b'0' {
                    full_check = true;
                }
                x2c(&input[i + j - 2..i + j])
            }
        };
        if full_check
            && value > 0
            && value < 0x5f
            && j >= 4
            && (input[i + j - 3] | 0x20) == b'f'
            && (input[i + j - 4] | 0x20) == b'f'
        {
            value = value.wrapping_add(0x20);
        }
        out.push(value);
        i += j;
        if i < input.len() && is_latin_space(input[i]) {
            i += 1;
        }
    }
}

fn cmd_line_into(input: &[u8], out: &mut Vec<u8>) {
    out.reserve(input.len());
    let mut space = false;
    for &byte in input {
        match byte {
            b'"' | b'\'' | b'\\' | b'^' => {}
            b' ' | b',' | b';' | b'\t' | b'\r' | b'\n' => {
                if !space {
                    out.push(b' ');
                    space = true;
                }
            }
            b'/' | b'(' => {
                if space {
                    out.pop();
                }
                space = false;
                out.push(byte);
            }
            _ => {
                out.push(byte.to_ascii_lowercase());
                space = false;
            }
        }
    }
}

fn replace_comments_into(input: &[u8], out: &mut Vec<u8>) {
    out.reserve(input.len());
    let mut i = 0;
    let mut in_comment = false;
    while i < input.len() {
        if !in_comment {
            if input[i] == b'/' && i + 1 < input.len() && input[i + 1] == b'*' {
                in_comment = true;
                i += 2;
            } else {
                out.push(input[i]);
                i += 1;
            }
        } else if input[i] == b'*' && i + 1 < input.len() && input[i + 1] == b'/' {
            in_comment = false;
            i += 2;
            out.push(b' ');
        } else {
            i += 1;
        }
    }
    if in_comment {
        out.push(b' ');
    }
}

fn escape_seq_decode_into(input: &[u8], out: &mut Vec<u8>) {
    out.reserve(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] != b'\\' || i + 1 >= input.len() {
            out.push(input[i]);
            i += 1;
            continue;
        }
        let next = input[i + 1];
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
            out.push(byte);
            i += 2;
            continue;
        }
        if (next | 0x20) == b'x'
            && i + 3 < input.len()
            && is_hex(input[i + 2])
            && is_hex(input[i + 3])
        {
            out.push(x2c(&input[i + 2..i + 4]));
            i += 4;
            continue;
        }
        if (b'0'..=b'7').contains(&next) {
            let mut j = 2;
            while j < 4 && i + j < input.len() && (b'0'..=b'7').contains(&input[i + j]) {
                j += 1;
            }
            let mut value: u32 = 0;
            for digit in &input[i + 1..i + j] {
                value = value * 8 + u32::from(digit - b'0');
            }
            out.push(value as u8);
            i += j;
            continue;
        }
        out.push(next);
        i += 2;
    }
}

fn remove_whitespace_into(input: &[u8], out: &mut Vec<u8>) {
    out.reserve(input.len());
    out.extend(input.iter().copied().filter(|byte| !is_latin_space(*byte)));
}

fn compress_whitespace_into(input: &[u8], out: &mut Vec<u8>) {
    out.reserve(input.len());
    let mut in_space = false;
    for &byte in input {
        if is_latin_space(byte) {
            if !in_space {
                out.push(b' ');
                in_space = true;
            }
        } else {
            out.push(byte);
            in_space = false;
        }
    }
}

fn is_latin_space(byte: u8) -> bool {
    matches!(
        byte,
        b'\t' | b'\n' | 0x0b | 0x0c | b'\r' | b' ' | 0x85 | 0xa0
    )
}

fn normalize_path_into(input: &[u8], out: &mut Vec<u8>) {
    if input.is_empty() {
        return;
    }
    clean_path_into(input, false, out);
    if out.as_slice() == b"." {
        out.clear();
        return;
    }
    if input.last() == Some(&b'/') && out.last() != Some(&b'/') {
        out.push(b'/');
    }
}

fn normalize_path_win_into(input: &[u8], out: &mut Vec<u8>) {
    if input.is_empty() {
        return;
    }
    clean_path_into(input, true, out);
    if out.as_slice() == b"." {
        out.clear();
        return;
    }
    if matches!(input.last(), Some(b'/') | Some(b'\\')) && out.last() != Some(&b'/') {
        out.push(b'/');
    }
}

/// A zero-allocation `path.Clean` equivalent for the byte strings seen in CRS
/// rules. `win` treats `\` as a path separator as well as `/`.
fn clean_path_into(input: &[u8], win: bool, out: &mut Vec<u8>) {
    let is_sep = |byte: u8| byte == b'/' || (win && byte == b'\\');
    let rooted = input.first().is_some_and(|byte| is_sep(*byte));
    let rooted_len = usize::from(rooted);
    let mut starts = [0usize; 32];
    let mut depth = 0usize;
    let mut spilled: Option<Vec<usize>> = None;

    if rooted {
        out.push(b'/');
    }
    let mut i = 0;
    while i < input.len() {
        while i < input.len() && is_sep(input[i]) {
            i += 1;
        }
        let start = i;
        while i < input.len() && !is_sep(input[i]) {
            i += 1;
        }
        let segment = &input[start..i];
        match segment {
            b"" | b"." => {}
            b".." => {
                let last = if let Some(stack) = &spilled {
                    stack.last().copied()
                } else if depth > 0 {
                    Some(starts[depth - 1])
                } else {
                    None
                };
                if let Some(position) = last {
                    out.truncate(position);
                    if position > rooted_len && out.last() == Some(&b'/') {
                        out.pop();
                    }
                    depth -= 1;
                    if let Some(stack) = &mut spilled {
                        stack.pop();
                    }
                } else if !rooted {
                    let position = next_segment_start(out, rooted_len);
                    push_path_segment(out, b"..", rooted_len);
                    record_segment(&mut starts, &mut spilled, &mut depth, position);
                }
            }
            other => {
                let position = next_segment_start(out, rooted_len);
                push_path_segment(out, other, rooted_len);
                record_segment(&mut starts, &mut spilled, &mut depth, position);
            }
        }
    }
    if out.is_empty() {
        if rooted {
            out.push(b'/');
        } else {
            out.push(b'.');
        }
    }
}

fn push_path_segment(out: &mut Vec<u8>, segment: &[u8], rooted_len: usize) {
    if out.len() > rooted_len && out.last() != Some(&b'/') {
        out.push(b'/');
    }
    out.extend_from_slice(segment);
}

fn next_segment_start(out: &[u8], rooted_len: usize) -> usize {
    if out.len() > rooted_len && out.last() != Some(&b'/') {
        out.len() + 1
    } else {
        out.len()
    }
}

fn record_segment(
    starts: &mut [usize; 32],
    spilled: &mut Option<Vec<usize>>,
    depth: &mut usize,
    position: usize,
) {
    if let Some(stack) = spilled {
        stack.push(position);
    } else if *depth < starts.len() {
        starts[*depth] = position;
    } else {
        let mut stack: Vec<usize> = starts.to_vec();
        stack.push(position);
        *spilled = Some(stack);
    }
    *depth += 1;
}

fn base64_decode_into(input: &[u8], out: &mut Vec<u8>) {
    out.reserve(input.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut count = 0;
    for &byte in input {
        if byte == b'\r' || byte == b'\n' {
            continue;
        }
        if byte == b'=' || byte == b' ' || byte > 127 {
            break;
        }
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => break,
        };
        acc = (acc << 6) | u32::from(value);
        count += 1;
        if count == 4 {
            out.push((acc >> 16) as u8);
            out.push((acc >> 8) as u8);
            out.push(acc as u8);
            acc = 0;
            count = 0;
        }
    }
    if count == 2 {
        acc <<= 12;
        out.push((acc >> 16) as u8);
    } else if count == 3 {
        acc <<= 6;
        out.push((acc >> 16) as u8);
        out.push((acc >> 8) as u8);
    }
}

fn hex_encode_into(input: &[u8], out: &mut Vec<u8>) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.reserve(input.len() * 2);
    for &byte in input {
        out.push(HEX[usize::from(byte >> 4)]);
        out.push(HEX[usize::from(byte & 0x0f)]);
    }
}

fn remove_comments_char_into(input: &[u8], out: &mut Vec<u8>) {
    out.reserve(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] == b'/' && i + 1 < input.len() && input[i + 1] == b'*' {
            i += 2;
        } else if input[i] == b'*' && i + 1 < input.len() && input[i + 1] == b'/' {
            i += 2;
        } else if input[i] == b'<'
            && i + 3 < input.len()
            && input[i + 1] == b'!'
            && input[i + 2] == b'-'
            && input[i + 3] == b'-'
        {
            i += 4;
        } else if input[i] == b'-'
            && i + 2 < input.len()
            && input[i + 1] == b'-'
            && input[i + 2] == b'>'
        {
            i += 3;
        } else if input[i] == b'-' && i + 1 < input.len() && input[i + 1] == b'-' {
            i += 2;
        } else if input[i] == b'#' {
            i += 1;
        } else {
            out.push(input[i]);
            i += 1;
        }
    }
}

fn utf8_to_unicode_into(input: &[u8], out: &mut Vec<u8>) {
    out.reserve(input.len());
    let mut i = 0;
    while i < input.len() {
        let byte = input[i];
        if byte < 0x80 {
            out.push(byte);
            i += 1;
            continue;
        }
        let width = match byte {
            0xc0..=0xdf => 2,
            0xe0..=0xef => 3,
            0xf0..=0xf7 => 4,
            _ => {
                out.push(byte);
                i += 1;
                continue;
            }
        };
        if i + width > input.len() {
            out.push(byte);
            i += 1;
            continue;
        }
        let slice = &input[i..i + width];
        if let Ok(text) = std::str::from_utf8(slice) {
            if let Some(ch) = text.chars().next() {
                out.extend_from_slice(b"%u");
                let code = ch as u32;
                for shift in [12u32, 8, 4, 0] {
                    let digit = ((code >> shift) & 0xf) as u8;
                    out.push(if digit < 10 {
                        b'0' + digit
                    } else {
                        b'a' + digit - 10
                    });
                }
                i += width;
                continue;
            }
        }
        out.push(byte);
        i += 1;
    }
}

fn trim_bounds(input: &[u8]) -> (usize, usize) {
    let start = input
        .iter()
        .position(|byte| !is_latin_space(*byte))
        .unwrap_or(input.len());
    let end = input
        .iter()
        .rposition(|byte| !is_latin_space(*byte))
        .map_or(start, |pos| pos + 1);
    (start, end)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn apply(transform: Transform, input: &[u8]) -> Vec<u8> {
        let mut budget = Budget::new(crate::waf::rust_engine::budget::Limits::default());
        transform.apply(input, &mut budget).expect("transform")
    }

    #[test]
    fn url_decode_uni_handles_iis_encoding() {
        assert_eq!(apply(Transform::UrlDecodeUni, b"a%u0041b"), b"aAb");
        assert_eq!(apply(Transform::UrlDecodeUni, b"a%41b"), b"aAb");
        assert_eq!(apply(Transform::UrlDecodeUni, b"a+b"), b"a b");
    }

    #[test]
    fn js_decode_handles_unicode_and_hex() {
        assert_eq!(apply(Transform::JsDecode, b"\\u0041\\x42"), b"AB");
        assert_eq!(apply(Transform::JsDecode, b"\\141"), b"a");
    }

    #[test]
    fn html_entities_decode() {
        assert_eq!(
            apply(Transform::HtmlEntityDecode, b"&lt;script&gt;&#x41;"),
            b"<script>A"
        );
    }

    #[test]
    fn base64_decode_stops_at_padding() {
        assert_eq!(apply(Transform::Base64Decode, b"YWJjZA=="), b"abcd");
    }

    #[test]
    fn normalize_path_collapses_segments() {
        assert_eq!(apply(Transform::NormalizePath, b"/a/./b/../c/"), b"/a/c/");
        assert_eq!(apply(Transform::NormalizePathWin, b"\\a\\..\\b"), b"/b");
        assert_eq!(apply(Transform::NormalizePath, b".."), b"..");
        assert_eq!(apply(Transform::NormalizePath, b"a/../../b"), b"../b");
    }

    #[test]
    fn cmd_line_matches_modsecurity() {
        assert_eq!(apply(Transform::CmdLine, b"a ; b/c"), b"a b/c");
    }

    #[test]
    fn uppercase_and_lowercase_are_unicode_aware() {
        assert_eq!(
            apply(Transform::Lowercase, "ÄÖÜ".as_bytes()),
            "äöü".as_bytes()
        );
        assert_eq!(
            apply(Transform::Uppercase, "äöü".as_bytes()),
            "ÄÖÜ".as_bytes()
        );
    }
}
