//! Byte transforms used by the engine-kernel prototype.
//!
//! These mirror the Coraza/ModSecurity transforms that the hand-written rule
//! subset needs. They write into caller-owned buffers so a request can be
//! evaluated without per-rule allocation. The transform *pipeline* result is
//! cached per value by [`crate::waf::engine_kernel::state::Arena`], not per
//! rule.

/// One Coraza-compatible transform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Transform {
    Lowercase,
    Utf8ToUnicode,
    UrlDecodeUni,
    HtmlEntityDecode,
    RemoveNulls,
    CompressWhitespace,
    RemoveWhitespace,
    CmdLine,
    NormalizePath,
    JsDecode,
    CssDecode,
    Base64Decode,
    ReplaceComments,
    RemoveCommentsChar,
}

impl Transform {
    /// Parses a transform name from the prefilter artifact.
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "none" => None,
            "utf8tounicode" => Some(Self::Utf8ToUnicode),
            "lowercase" => Some(Self::Lowercase),
            "urldecode" | "urldecodeuni" => Some(Self::UrlDecodeUni),
            "htmlentitydecode" => Some(Self::HtmlEntityDecode),
            "removenulls" => Some(Self::RemoveNulls),
            "compresswhitespace" => Some(Self::CompressWhitespace),
            "removewhitespace" => Some(Self::RemoveWhitespace),
            "cmdline" => Some(Self::CmdLine),
            "normalizepath" | "normalisepath" => Some(Self::NormalizePath),
            "jsdecode" => Some(Self::JsDecode),
            "cssdecode" => Some(Self::CssDecode),
            "base64decode" => Some(Self::Base64Decode),
            "replacecomments" => Some(Self::ReplaceComments),
            "removecommentschar" => Some(Self::RemoveCommentsChar),
            _ => None,
        }
    }

    /// Applies the transform, appending the result to `out`.
    ///
    /// `out` is cleared first. Callers may pass an empty slice as `input`.
    pub fn apply_into(self, input: &[u8], out: &mut Vec<u8>) {
        out.clear();
        match self {
            Self::Lowercase => lowercase_into(input, out),
            Self::Utf8ToUnicode => utf8_to_unicode_into(input, out),
            Self::UrlDecodeUni => url_decode_uni_into(input, out),
            Self::HtmlEntityDecode => html_entity_decode_into(input, out),
            Self::RemoveNulls => out.extend(input.iter().copied().filter(|b| *b != 0)),
            Self::CompressWhitespace => compress_whitespace_into(input, out),
            Self::RemoveWhitespace => {
                out.extend(input.iter().copied().filter(|b| !is_latin_space(*b)));
            }
            Self::CmdLine => cmd_line_into(input, out),
            Self::NormalizePath => normalize_path_into(input, out),
            Self::JsDecode => js_decode_into(input, out),
            Self::CssDecode => css_decode_into(input, out),
            Self::Base64Decode => base64_decode_into(input, out),
            Self::ReplaceComments => replace_comments_into(input, out),
            Self::RemoveCommentsChar => remove_comments_char_into(input, out),
        }
    }
}

/// Applies a pipeline. The result is appended to `out`.
///
/// `scratch` provides two reusable intermediate buffers. An empty pipeline is
/// the identity and is handled without touching the scratch buffers.
pub fn apply_pipeline(
    input: &[u8],
    pipeline: &[Transform],
    scratch: &mut [Vec<u8>; 2],
    out: &mut Vec<u8>,
) {
    out.clear();
    if pipeline.is_empty() {
        out.extend_from_slice(input);
        return;
    }
    scratch[0].clear();
    scratch[0].extend_from_slice(input);
    let mut source = 0usize;
    for transform in pipeline {
        let destination = 1 - source;
        let (left, right) = scratch.split_at_mut(1);
        if source == 0 {
            transform.apply_into(&left[0], &mut right[0]);
        } else {
            transform.apply_into(&right[0], &mut left[0]);
        }
        source = destination;
    }
    out.extend_from_slice(&scratch[source]);
}

fn is_latin_space(byte: u8) -> bool {
    matches!(
        byte,
        b'\t' | b'\n' | 0x0b | 0x0c | b'\r' | b' ' | 0x85 | 0xa0
    )
}

fn lowercase_into(input: &[u8], out: &mut Vec<u8>) {
    out.reserve(input.len());
    // Fast path: ASCII-only values dominate WAF traffic. Non-ASCII bytes are
    // copied unchanged; the prototype's rule subset only uses ASCII literals.
    out.extend(input.iter().map(u8::to_ascii_lowercase));
}

/// Coraza's `utf8toUnicode`: non-ASCII runes become `%uXXXX` escapes, which
/// `urlDecodeUni` then maps back (including the fullwidth-to-ASCII range).
fn utf8_to_unicode_into(input: &[u8], out: &mut Vec<u8>) {
    out.reserve(input.len());
    let mut rest = input;
    loop {
        match std::str::from_utf8(rest) {
            Ok(text) => {
                for ch in text.chars() {
                    push_utf8_to_unicode(ch, out);
                }
                break;
            }
            Err(error) => {
                let valid = error.valid_up_to();
                if valid > 0 {
                    let text = std::str::from_utf8(&rest[..valid]).expect("valid prefix");
                    for ch in text.chars() {
                        push_utf8_to_unicode(ch, out);
                    }
                }
                match error.error_len() {
                    Some(len) => {
                        out.extend_from_slice(&rest[valid..valid + len]);
                        rest = &rest[valid + len..];
                    }
                    None => {
                        out.extend_from_slice(&rest[valid..]);
                        break;
                    }
                }
            }
        }
    }
}

fn push_utf8_to_unicode(ch: char, out: &mut Vec<u8>) {
    if ch.is_ascii() {
        out.push(ch as u8);
        return;
    }
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
    Some((hex_value(*input.get(at)?)? << 4) | hex_value(*input.get(at + 1)?)?)
}

fn url_decode_uni_into(input: &[u8], out: &mut Vec<u8>) {
    out.reserve(input.len());
    let mut index = 0usize;
    while index < input.len() {
        match input[index] {
            b'%' => {
                if index + 5 < input.len() && matches!(input[index + 1], b'u' | b'U') {
                    if let (Some(high), Some(low)) =
                        (hex_pair(input, index + 2), hex_pair(input, index + 4))
                    {
                        let mut byte = low;
                        if high == 0xff && (1..=0x5e).contains(&byte) {
                            byte = byte.wrapping_add(0x20);
                        }
                        out.push(byte);
                        index += 6;
                        continue;
                    }
                }
                if let Some(byte) = hex_pair(input, index + 1) {
                    out.push(byte);
                    index += 3;
                } else {
                    out.push(b'%');
                    index += 1;
                }
            }
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
}

fn push_code_point(out: &mut Vec<u8>, code: u32) {
    if let Some(ch) = char::from_u32(code) {
        let mut buffer = [0u8; 4];
        out.extend_from_slice(ch.encode_utf8(&mut buffer).as_bytes());
    }
}

fn html_entity_decode_into(input: &[u8], out: &mut Vec<u8>) {
    out.reserve(input.len());
    let mut index = 0usize;
    while index < input.len() {
        if input[index] != b'&' {
            out.push(input[index]);
            index += 1;
            continue;
        }
        if let Some((decoded, consumed)) = decode_entity(&input[index..]) {
            match decoded {
                DecodedEntity::Bytes(bytes) => out.extend_from_slice(bytes),
                DecodedEntity::Code(code) => push_code_point(out, code),
            }
            index += consumed;
        } else {
            out.push(b'&');
            index += 1;
        }
    }
}

enum DecodedEntity {
    Bytes(&'static [u8]),
    Code(u32),
}

fn decode_entity(input: &[u8]) -> Option<(DecodedEntity, usize)> {
    debug_assert_eq!(input.first(), Some(&b'&'));
    if input.get(1) == Some(&b'#') {
        let (radix, start) = match input.get(2).copied() {
            Some(b'x') | Some(b'X') => (16u32, 3usize),
            _ => (10u32, 2usize),
        };
        let mut end = start;
        while end < input.len() {
            let valid = if radix == 16 {
                input[end].is_ascii_hexdigit()
            } else {
                input[end].is_ascii_digit()
            };
            if !valid {
                break;
            }
            end += 1;
        }
        if end == start {
            return None;
        }
        let digits = std::str::from_utf8(&input[start..end]).ok()?;
        let code = u32::from_str_radix(digits, radix).ok()?;
        let consumed = if input.get(end) == Some(&b';') {
            end + 1
        } else {
            end
        };
        return Some((DecodedEntity::Code(code), consumed));
    }

    let mut end = 1usize;
    while end < input.len() && input[end].is_ascii_alphanumeric() {
        end += 1;
    }
    if end == 1 {
        return None;
    }
    let run = std::str::from_utf8(&input[1..end]).ok()?;
    let lower = run.to_ascii_lowercase();
    if input.get(end) == Some(&b';') {
        if let Some(bytes) = named_entity(&lower) {
            return Some((DecodedEntity::Bytes(bytes), end + 1));
        }
    }
    let max_len = lower.len().min(6);
    for len in (2..=max_len).rev() {
        if let Some(bytes) = legacy_entity(&lower[..len]) {
            return Some((DecodedEntity::Bytes(bytes), 1 + len));
        }
    }
    None
}

fn legacy_entity(name: &str) -> Option<&'static [u8]> {
    match name {
        "lt" => Some(b"<"),
        "gt" => Some(b">"),
        "amp" => Some(b"&"),
        "quot" => Some(b"\""),
        "nbsp" => Some(b"\xc2\xa0"),
        _ => None,
    }
}

fn named_entity(name: &str) -> Option<&'static [u8]> {
    let decoded: &'static [u8] = match name {
        "lt" => b"<",
        "gt" => b">",
        "amp" => b"&",
        "quot" => b"\"",
        "apos" => b"'",
        "nbsp" => b"\xc2\xa0",
        "colon" => b":",
        "sol" => b"/",
        "bsol" => b"\\",
        "lpar" => b"(",
        "rpar" => b")",
        "period" => b".",
        "comma" => b",",
        "semi" => b";",
        "num" => b"#",
        "percnt" => b"%",
        "equals" => b"=",
        "quest" => b"?",
        "plus" => b"+",
        "lowbar" | "underbar" => b"_",
        "ast" | "midast" => b"*",
        "verbar" | "vert" | "verticalline" => b"|",
        "grave" | "diacriticalgrave" => b"`",
        "hat" => b"^",
        "excl" => b"!",
        "dollar" => b"$",
        "commat" => b"@",
        "lsqb" | "lbrack" => b"[",
        "rsqb" | "rbrack" => b"]",
        "lcub" | "lbrace" => b"{",
        "rcub" | "rbrace" => b"}",
        "tab" => b"\t",
        "newline" => b"\n",
        _ => return None,
    };
    Some(decoded)
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

/// Coraza's `cmdLine` (ModSecurity `cmd_line`).
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
            other => {
                out.push(other.to_ascii_lowercase());
                space = false;
            }
        }
    }
}

/// Mirrors Go's `filepath.Clean` on Unix without allocating.
fn normalize_path_into(input: &[u8], out: &mut Vec<u8>) {
    out.clear();
    if input.is_empty() {
        out.push(b'.');
        return;
    }
    let rooted = input[0] == b'/';
    if rooted {
        out.push(b'/');
    }
    let mut wrote_part = false;
    for part in input.split(|byte| *byte == b'/') {
        if part.is_empty() || part == b"." {
            continue;
        }
        if part == b".." {
            if out.len() > usize::from(rooted) {
                if let Some(position) = out.iter().rposition(|byte| *byte == b'/') {
                    if position >= usize::from(rooted) {
                        out.truncate(position);
                    } else {
                        out.truncate(usize::from(rooted));
                    }
                } else {
                    out.truncate(usize::from(rooted));
                }
                wrote_part = out.len() > usize::from(rooted);
            } else if !rooted {
                if wrote_part {
                    out.push(b'/');
                }
                out.extend_from_slice(part);
                wrote_part = true;
            }
            continue;
        }
        if wrote_part {
            out.push(b'/');
        }
        out.extend_from_slice(part);
        wrote_part = true;
    }
    if out.is_empty() {
        out.push(b'.');
    }
}

fn js_decode_into(input: &[u8], out: &mut Vec<u8>) {
    out.reserve(input.len());
    let mut index = 0usize;
    while index < input.len() {
        if input[index] != b'\\' || index + 1 >= input.len() {
            out.push(input[index]);
            index += 1;
            continue;
        }
        let escape = input[index + 1];
        match escape {
            b'u' if index + 5 < input.len() => {
                if let Some(byte) = hex_pair(input, index + 4) {
                    let mut byte = byte;
                    if byte > 0
                        && byte < 0x5f
                        && matches!(input[index + 2], b'f' | b'F')
                        && matches!(input[index + 3], b'f' | b'F')
                    {
                        byte = byte.wrapping_add(0x20);
                    }
                    out.push(byte);
                    index += 6;
                } else {
                    out.push(escape);
                    index += 2;
                }
            }
            b'x' if index + 3 < input.len() => {
                if let Some(byte) = hex_pair(input, index + 2) {
                    out.push(byte);
                    index += 4;
                } else {
                    out.push(escape);
                    index += 2;
                }
            }
            b'n' => {
                out.push(b'\n');
                index += 2;
            }
            b'r' => {
                out.push(b'\r');
                index += 2;
            }
            b't' => {
                out.push(b'\t');
                index += 2;
            }
            b'b' => {
                out.push(0x08);
                index += 2;
            }
            b'f' => {
                out.push(0x0c);
                index += 2;
            }
            b'0' => {
                out.push(0);
                index += 2;
            }
            b'\\' | b'"' | b'\'' | b'/' => {
                out.push(escape);
                index += 2;
            }
            _ => {
                out.push(escape);
                index += 2;
            }
        }
    }
}

fn css_decode_into(input: &[u8], out: &mut Vec<u8>) {
    out.reserve(input.len());
    let mut index = 0usize;
    while index < input.len() {
        if input[index] != b'\\' || index + 1 >= input.len() {
            out.push(input[index]);
            index += 1;
            continue;
        }
        let mut end = index + 1;
        while end < input.len() && end < index + 7 && input[end].is_ascii_hexdigit() {
            end += 1;
        }
        if end == index + 1 {
            out.push(input[index + 1]);
            index += 2;
            continue;
        }
        if let Ok(digits) = std::str::from_utf8(&input[index + 1..end]) {
            if let Ok(code) = u32::from_str_radix(digits, 16) {
                push_code_point(out, code);
                index = if input.get(end) == Some(&b' ') {
                    end + 1
                } else {
                    end
                };
                continue;
            }
        }
        out.push(input[index]);
        index += 1;
    }
}

fn base64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Coraza-compatible `base64decode` with a conservative guard for the
/// prototype: short or non-printable decodes are treated as identity. Coraza
/// decodes partial input, which would corrupt ordinary words such as `eval`;
/// the guard keeps plaintext rules working while still decoding the base64
/// corpus payloads.
fn base64_decode_into(input: &[u8], out: &mut Vec<u8>) {
    out.reserve(input.len());
    let mut valid = 0usize;
    for &byte in input {
        if byte == b'\r' || byte == b'\n' || byte == b'=' {
            continue;
        }
        if base64_value(byte).is_none() {
            out.extend_from_slice(input);
            return;
        }
        valid += 1;
    }
    if valid < 8 {
        out.extend_from_slice(input);
        return;
    }
    let start = out.len();
    let mut accumulator = 0u32;
    let mut count = 0usize;
    for &byte in input {
        if byte == b'\r' || byte == b'\n' {
            continue;
        }
        if byte == b'=' {
            break;
        }
        let value = base64_value(byte).expect("validated");
        accumulator = (accumulator << 6) | u32::from(value);
        count += 1;
        if count == 4 {
            out.push((accumulator >> 16) as u8);
            out.push((accumulator >> 8) as u8);
            out.push(accumulator as u8);
            count = 0;
            accumulator = 0;
        }
    }
    if count == 2 {
        accumulator <<= 12;
        out.push((accumulator >> 16) as u8);
    } else if count == 3 {
        accumulator <<= 6;
        out.push((accumulator >> 16) as u8);
        out.push((accumulator >> 8) as u8);
    }
    let printable = out[start..]
        .iter()
        .all(|byte| matches!(*byte, b'\t' | b'\n' | b'\r' | 0x20..=0x7e));
    if !printable || out.len() == start {
        out.clear();
        out.extend_from_slice(input);
    }
}

fn replace_comments_into(input: &[u8], out: &mut Vec<u8>) {
    out.reserve(input.len());
    let mut index = 0usize;
    let mut in_comment = false;
    while index < input.len() {
        if !in_comment {
            if input[index] == b'/' && input.get(index + 1) == Some(&b'*') {
                in_comment = true;
                index += 2;
            } else {
                out.push(input[index]);
                index += 1;
            }
        } else if input[index] == b'*' && input.get(index + 1) == Some(&b'/') {
            in_comment = false;
            index += 2;
            out.push(b' ');
        } else {
            index += 1;
        }
    }
    if in_comment {
        out.push(b' ');
    }
}

fn remove_comments_char_into(input: &[u8], out: &mut Vec<u8>) {
    out.reserve(input.len());
    let mut index = 0usize;
    while index < input.len() {
        if input[index] == b'/' && input.get(index + 1) == Some(&b'*') {
            index += 2;
        } else if input[index] == b'*' && input.get(index + 1) == Some(&b'/') {
            index += 2;
        } else if input[index] == b'-' && input.get(index + 1) == Some(&b'-') {
            index += 2;
        } else if input[index] == b'#' {
            index += 1;
        } else {
            out.push(input[index]);
            index += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn apply(transform: Transform, input: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        transform.apply_into(input, &mut out);
        out
    }

    #[test]
    fn url_decode_uni_decodes_percent_and_plus() {
        assert_eq!(apply(Transform::UrlDecodeUni, b"a%2fb+c"), b"a/b c");
        assert_eq!(apply(Transform::UrlDecodeUni, b"%u0041"), b"A");
        assert_eq!(apply(Transform::UrlDecodeUni, b"%zz"), b"%zz");
    }

    #[test]
    fn html_entity_decode_decodes_named_and_numeric() {
        assert_eq!(
            apply(Transform::HtmlEntityDecode, b"&lt;script&gt;"),
            b"<script>"
        );
        assert_eq!(apply(Transform::HtmlEntityDecode, b"&#x41;&#66;"), b"AB");
    }

    #[test]
    fn cmd_line_normalizes_quotes_and_spaces() {
        // Coraza's cmdLine removes spaces immediately before `/` and `(`.
        assert_eq!(
            apply(Transform::CmdLine, b"cat  '/etc/passwd'"),
            b"cat/etc/passwd"
        );
    }

    #[test]
    fn normalize_path_collapses_dot_segments() {
        assert_eq!(apply(Transform::NormalizePath, b"/a/b/../c"), b"/a/c");
        assert_eq!(apply(Transform::NormalizePath, b"a/../../b"), b"../b");
        assert_eq!(apply(Transform::NormalizePath, b"/"), b"/");
        assert_eq!(apply(Transform::NormalizePath, b""), b".");
    }

    #[test]
    fn utf8_to_unicode_maps_fullwidth_to_ascii_via_url_decode() {
        let mut scratch = [Vec::new(), Vec::new()];
        let mut out = Vec::new();
        apply_pipeline(
            "\u{ff1c}script\u{ff1e}".as_bytes(),
            &[Transform::Utf8ToUnicode, Transform::UrlDecodeUni],
            &mut scratch,
            &mut out,
        );
        assert_eq!(out, b"<script>");
    }

    #[test]
    fn base64_decodes_printable_payloads_and_guards_plaintext() {
        assert_eq!(
            apply(Transform::Base64Decode, b"XyQkTkRfRlVOQyQkX2Z1bmN0aW9uKCkK"),
            b"_$$ND_FUNC$$_function()\n"
        );
        assert_eq!(apply(Transform::Base64Decode, b"eval"), b"eval");
    }

    #[test]
    fn pipeline_applies_in_order() {
        let mut scratch = [Vec::new(), Vec::new()];
        let mut out = Vec::new();
        apply_pipeline(
            b"%3CSCRIPT%3E",
            &[Transform::UrlDecodeUni, Transform::Lowercase],
            &mut scratch,
            &mut out,
        );
        assert_eq!(out, b"<script>");
    }
}
