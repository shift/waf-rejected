//! CRS transform implementations.
//!
//! These follow the Coraza/ModSecurity byte-oriented semantics closely enough
//! for differential testing. Values are byte strings, not UTF-8, because
//! URL/JS/CSS decoding can produce arbitrary bytes.

use super::budget::Budget;
use super::error::EngineError;

/// A SecLang transform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    pub fn apply(self, input: &[u8], budget: &mut Budget) -> Result<Vec<u8>, EngineError> {
        let out = match self {
            Self::None => input.to_vec(),
            Self::Lowercase => lowercase(input),
            Self::Uppercase => uppercase(input),
            Self::UrlDecode => url_decode(input, false),
            Self::UrlDecodeUni => url_decode(input, true),
            Self::HtmlEntityDecode => html_entity_decode(input),
            Self::JsDecode => js_decode(input),
            Self::CssDecode => css_decode(input),
            Self::CmdLine => cmd_line(input),
            Self::ReplaceComments => replace_comments(input),
            Self::EscapeSeqDecode => escape_seq_decode(input),
            Self::RemoveWhitespace => remove_whitespace(input),
            Self::NormalizePath => normalize_path(input),
            Self::NormalizePathWin => normalize_path_win(input),
            Self::CompressWhitespace => compress_whitespace(input),
            Self::RemoveNulls => input.iter().copied().filter(|b| *b != 0).collect(),
            Self::Base64Decode => base64_decode(input),
            Self::Sha1 => {
                use sha1::{Digest, Sha1};
                let mut hasher = Sha1::new();
                hasher.update(input);
                hasher.finalize().to_vec()
            }
            Self::HexEncode => hex::encode(input).into_bytes(),
            Self::RemoveCommentsChar => remove_comments_char(input),
            Self::Length => input.len().to_string().into_bytes(),
            Self::Utf8ToUnicode => utf8_to_unicode(input),
            Self::Trim => trim(input),
            Self::TrimLeft => trim_left(input),
            Self::TrimRight => trim_right(input),
        };
        budget.bytes(out.len())?;
        Ok(out)
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

fn lowercase(input: &[u8]) -> Vec<u8> {
    if input.is_ascii() {
        return input.to_ascii_lowercase();
    }
    String::from_utf8_lossy(input).to_lowercase().into_bytes()
}

fn uppercase(input: &[u8]) -> Vec<u8> {
    if input.is_ascii() {
        return input.to_ascii_uppercase();
    }
    String::from_utf8_lossy(input).to_uppercase().into_bytes()
}

fn url_decode(input: &[u8], uni: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
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
    out
}

fn html_entity_decode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
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
        if let Some(decoded) = decode_entity(entity) {
            out.extend_from_slice(&decoded);
            i = j + 1;
        } else {
            out.push(b'&');
            i += 1;
        }
    }
    out
}

fn decode_entity(entity: &[u8]) -> Option<Vec<u8>> {
    if entity.is_empty() {
        return None;
    }
    if entity[0] == b'#' {
        let (digits, radix) = if entity.len() > 1 && (entity[1] | 0x20) == b'x' {
            (&entity[2..], 16)
        } else {
            (&entity[1..], 10)
        };
        if digits.is_empty() {
            return None;
        }
        let mut value: u32 = 0;
        for digit in digits {
            let d = match radix {
                16 if is_hex(*digit) => hex_value(*digit),
                10 if digit.is_ascii_digit() => digit - b'0',
                _ => return None,
            };
            value = value.saturating_mul(radix).saturating_add(u32::from(d));
        }
        if value == 0 || value > 0x10ffff {
            return None;
        }
        let ch = char::from_u32(value)?;
        return Some(ch.to_string().into_bytes());
    }
    let name = std::str::from_utf8(entity).ok()?;
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
        _ => return None,
    };
    Some(value.as_bytes().to_vec())
}

fn js_decode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
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
    out
}

fn css_decode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
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
    out
}

fn cmd_line(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
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
    out
}

fn replace_comments(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
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
    out
}

fn escape_seq_decode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
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
    out
}

fn remove_whitespace(input: &[u8]) -> Vec<u8> {
    input
        .iter()
        .copied()
        .filter(|byte| !is_latin_space(*byte))
        .collect()
}

fn compress_whitespace(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
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
    out
}

fn is_latin_space(byte: u8) -> bool {
    matches!(
        byte,
        b'\t' | b'\n' | 0x0b | 0x0c | b'\r' | b' ' | 0x85 | 0xa0
    )
}

fn normalize_path(input: &[u8]) -> Vec<u8> {
    if input.is_empty() {
        return Vec::new();
    }
    let text = String::from_utf8_lossy(input);
    let clean = clean_path(&text);
    if clean == "." {
        return Vec::new();
    }
    let mut out = clean.into_bytes();
    if input.last() == Some(&b'/') && out.last() != Some(&b'/') {
        out.push(b'/');
    }
    out
}

fn normalize_path_win(input: &[u8]) -> Vec<u8> {
    let replaced: Vec<u8> = input
        .iter()
        .map(|byte| if *byte == b'\\' { b'/' } else { *byte })
        .collect();
    normalize_path(&replaced)
}

/// A small `path.Clean` equivalent for the byte strings seen in CRS rules.
fn clean_path(input: &str) -> String {
    let rooted = input.starts_with('/');
    let mut parts: Vec<&str> = Vec::new();
    for part in input.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if parts.last().is_some_and(|last| *last != "..") {
                    parts.pop();
                } else if !rooted {
                    parts.push("..");
                }
            }
            other => parts.push(other),
        }
    }
    let mut out = String::new();
    if rooted {
        out.push('/');
    }
    out.push_str(&parts.join("/"));
    if out.is_empty() {
        out.push('.');
    }
    out
}

fn base64_decode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
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
    out
}

fn remove_comments_char(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
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
    out
}

fn utf8_to_unicode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
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
                out.extend_from_slice(format!("%u{:04x}", ch as u32).as_bytes());
                i += width;
                continue;
            }
        }
        out.push(byte);
        i += 1;
    }
    out
}

fn trim(input: &[u8]) -> Vec<u8> {
    let start = input
        .iter()
        .position(|byte| !is_latin_space(*byte))
        .unwrap_or(input.len());
    let end = input
        .iter()
        .rposition(|byte| !is_latin_space(*byte))
        .map_or(start, |pos| pos + 1);
    input[start..end].to_vec()
}

fn trim_left(input: &[u8]) -> Vec<u8> {
    let start = input
        .iter()
        .position(|byte| !is_latin_space(*byte))
        .unwrap_or(input.len());
    input[start..].to_vec()
}

fn trim_right(input: &[u8]) -> Vec<u8> {
    let end = input
        .iter()
        .rposition(|byte| !is_latin_space(*byte))
        .map_or(0, |pos| pos + 1);
    input[..end].to_vec()
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
    }

    #[test]
    fn cmd_line_matches_modsecurity() {
        assert_eq!(apply(Transform::CmdLine, b"a ; b/c"), b"a b/c");
    }
}
