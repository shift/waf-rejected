//! XML body processor.
//!
//! The collection shape matches the vendored Coraza v3.3.3
//! `internal/bodyprocessors/xml.go`:
//!
//! * `XML://@*` holds every attribute value, in document order;
//! * `XML:/*` holds every non-empty, trimmed run of character data (including
//!   CDATA), in document order.
//!
//! Coraza uses Go's `encoding/xml` with `Strict=false`, `AutoClose` for HTML
//! elements and the HTML entity table. The native scanner is deliberately
//! non-validating and **never resolves external DTDs, external entities or
//! namespaces**. Documented deviations from Go:
//!
//! * only XML predefined entities, numeric character references and a small
//!   HTML entity subset are decoded; unknown entities are passed through
//!   literally (Go's `HTMLEntity` table is complete);
//! * malformed nesting is reported as an error (the request body processor
//!   then leaves `XML` empty, as Coraza does after `generateRequestBodyError`);
//! * the HTML auto-close rules are a compact subset (void elements and the
//!   common optional-end-tag elements).

use super::ProcessorError;

/// Values collected from a well-formed XML body.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct XmlValues {
    /// Attribute values, exposed as `XML://@*`.
    pub attributes: Vec<Vec<u8>>,
    /// Trimmed character data, exposed as `XML:/*`.
    pub content: Vec<Vec<u8>>,
}

/// Elements that never get an end tag.
const VOID_ELEMENTS: &[&str] = &[
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source",
    "track", "wbr",
];

/// Elements that implicitly close a currently open element of the same kind.
const AUTO_CLOSE: &[&str] = &[
    "dd", "dt", "li", "option", "p", "td", "th", "tr", "thead", "tbody", "tfoot",
];

/// Parses `body`, returning the attribute and character-data collections.
pub fn process(body: &[u8]) -> Result<XmlValues, ProcessorError> {
    let text = std::str::from_utf8(body)
        .map_err(|_| ProcessorError::Malformed("xml body is not valid UTF-8"))?;
    let bytes = text.as_bytes();
    let mut values = XmlValues::default();
    let mut stack: Vec<String> = Vec::new();
    let mut cursor = 0usize;

    while cursor < bytes.len() {
        if bytes[cursor] != b'<' {
            let start = cursor;
            while cursor < bytes.len() && bytes[cursor] != b'<' {
                cursor += 1;
            }
            push_text(&text[start..cursor], &mut values.content);
            continue;
        }

        if text[cursor..].starts_with("<!--") {
            cursor = skip_past(text, cursor + 4, "-->")?;
        } else if text[cursor..].starts_with("<![CDATA[") {
            let start = cursor + 9;
            let end = text[start..]
                .find("]]>")
                .map(|offset| start + offset)
                .ok_or(ProcessorError::Malformed("unterminated CDATA"))?;
            push_text(&text[start..end], &mut values.content);
            cursor = end + 3;
        } else if text[cursor..].starts_with("<?") {
            cursor = skip_past(text, cursor + 2, "?>")?;
        } else if text[cursor..].starts_with("<!") {
            cursor = skip_declaration(text, cursor)?;
        } else {
            cursor = parse_tag(text, cursor, &mut stack, &mut values)?;
        }
    }

    if !stack.is_empty() {
        return Err(ProcessorError::Malformed("unclosed xml element"));
    }
    Ok(values)
}

fn push_text(raw: &str, content: &mut Vec<Vec<u8>>) {
    let decoded = decode_entities(raw);
    let trimmed = decoded.trim();
    if !trimmed.is_empty() {
        content.push(trimmed.as_bytes().to_vec());
    }
}

fn skip_past(text: &str, from: usize, marker: &str) -> Result<usize, ProcessorError> {
    text[from..]
        .find(marker)
        .map(|offset| from + offset + marker.len())
        .ok_or(ProcessorError::Malformed("unterminated xml construct"))
}

fn skip_declaration(text: &str, start: usize) -> Result<usize, ProcessorError> {
    let bytes = text.as_bytes();
    let mut cursor = start + 2;
    let mut depth = 0usize;
    while cursor < bytes.len() {
        match bytes[cursor] {
            b'[' => depth += 1,
            b']' => depth = depth.saturating_sub(1),
            b'>' if depth == 0 => return Ok(cursor + 1),
            _ => {}
        }
        cursor += 1;
    }
    Err(ProcessorError::Malformed("unterminated xml declaration"))
}

fn parse_tag(
    text: &str,
    start: usize,
    stack: &mut Vec<String>,
    values: &mut XmlValues,
) -> Result<usize, ProcessorError> {
    let bytes = text.as_bytes();
    let mut cursor = start + 1;
    let mut quote: Option<u8> = None;
    while cursor < bytes.len() {
        let byte = bytes[cursor];
        match quote {
            Some(active) => {
                if byte == active {
                    quote = None;
                }
            }
            None => match byte {
                b'"' | b'\'' => quote = Some(byte),
                b'>' => break,
                _ => {}
            },
        }
        cursor += 1;
    }
    if cursor >= bytes.len() {
        return Err(ProcessorError::Malformed("unterminated xml tag"));
    }
    let inner = &text[start + 1..cursor];
    let next = cursor + 1;

    if let Some(name) = inner.strip_prefix('/') {
        let name = name.trim();
        let open = stack
            .pop()
            .ok_or(ProcessorError::Malformed("xml end tag without a start tag"))?;
        if !open.eq_ignore_ascii_case(name) {
            return Err(ProcessorError::Malformed("mismatched xml end tag"));
        }
        return Ok(next);
    }

    let self_closing = inner.trim_end().ends_with('/');
    let inner = if self_closing {
        inner.trim_end().trim_end_matches('/')
    } else {
        inner
    };
    let mut tokens = AttributeScanner::new(inner);
    let name = tokens
        .name()
        .ok_or(ProcessorError::Malformed("xml tag without a name"))?;

    if !self_closing
        && !VOID_ELEMENTS
            .iter()
            .any(|void| void.eq_ignore_ascii_case(name))
    {
        if AUTO_CLOSE.iter().any(|tag| tag.eq_ignore_ascii_case(name))
            && stack
                .last()
                .is_some_and(|open| open.eq_ignore_ascii_case(name))
        {
            stack.pop();
        }
        stack.push(name.to_string());
    }

    while let Some((_name, value)) = tokens.attribute()? {
        values.attributes.push(decode_entities(&value).into_bytes());
    }
    Ok(next)
}

struct AttributeScanner<'a> {
    text: &'a str,
    cursor: usize,
}

impl<'a> AttributeScanner<'a> {
    fn new(text: &'a str) -> Self {
        Self { text, cursor: 0 }
    }

    fn name(&mut self) -> Option<&'a str> {
        self.skip_whitespace();
        let start = self.cursor;
        while let Some(byte) = self.text.as_bytes().get(self.cursor) {
            if byte.is_ascii_whitespace() || *byte == b'=' || *byte == b'/' {
                break;
            }
            self.cursor += 1;
        }
        (self.cursor > start).then(|| &self.text[start..self.cursor])
    }

    fn attribute(&mut self) -> Result<Option<(String, String)>, ProcessorError> {
        self.skip_whitespace();
        if self.cursor >= self.text.len() {
            return Ok(None);
        }
        let Some(name) = self.name() else {
            return Ok(None);
        };
        self.skip_whitespace();
        if self.text.as_bytes().get(self.cursor) != Some(&b'=') {
            return Err(ProcessorError::Malformed("xml attribute without a value"));
        }
        self.cursor += 1;
        self.skip_whitespace();
        let Some(quote) = self.text.as_bytes().get(self.cursor).copied() else {
            return Err(ProcessorError::Malformed("xml attribute without a value"));
        };
        let value = if quote == b'"' || quote == b'\'' {
            self.cursor += 1;
            let start = self.cursor;
            while self.text.as_bytes().get(self.cursor) != Some(&quote) {
                if self.cursor >= self.text.len() {
                    return Err(ProcessorError::Malformed("unterminated xml attribute"));
                }
                self.cursor += 1;
            }
            let value = &self.text[start..self.cursor];
            self.cursor += 1;
            value
        } else {
            let start = self.cursor;
            while let Some(byte) = self.text.as_bytes().get(self.cursor) {
                if byte.is_ascii_whitespace() {
                    break;
                }
                self.cursor += 1;
            }
            &self.text[start..self.cursor]
        };
        Ok(Some((name.to_string(), value.to_string())))
    }

    fn skip_whitespace(&mut self) {
        while self
            .text
            .as_bytes()
            .get(self.cursor)
            .is_some_and(|byte| byte.is_ascii_whitespace())
        {
            self.cursor += 1;
        }
    }
}

/// Decodes XML predefined entities, numeric references and a compact HTML
/// subset. Unknown entities are preserved literally.
fn decode_entities(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let bytes = raw.as_bytes();
    let mut cursor = 0usize;
    while cursor < bytes.len() {
        if bytes[cursor] != b'&' {
            let start = cursor;
            while cursor < bytes.len() && bytes[cursor] != b'&' {
                cursor += 1;
            }
            out.push_str(&raw[start..cursor]);
            continue;
        }
        let Some(relative_end) = raw[cursor..].find(';') else {
            out.push('&');
            cursor += 1;
            continue;
        };
        let end = cursor + relative_end;
        let name = &raw[cursor + 1..end];
        if name.is_empty() || name.len() > 32 {
            out.push('&');
            cursor += 1;
            continue;
        }
        match decode_entity(name) {
            Some(decoded) => {
                out.push(decoded);
                cursor = end + 1;
            }
            None => {
                out.push('&');
                cursor += 1;
            }
        }
    }
    out
}

fn decode_entity(name: &str) -> Option<char> {
    if let Some(number) = name.strip_prefix("#x").or_else(|| name.strip_prefix("#X")) {
        return u32::from_str_radix(number, 16)
            .ok()
            .and_then(char::from_u32);
    }
    if let Some(number) = name.strip_prefix('#') {
        return number.parse::<u32>().ok().and_then(char::from_u32);
    }
    Some(match name {
        "amp" => '&',
        "lt" => '<',
        "gt" => '>',
        "quot" => '"',
        "apos" => '\'',
        "nbsp" => '\u{a0}',
        "copy" => '\u{a9}',
        "reg" => '\u{ae}',
        "hellip" => '\u{2026}',
        "mdash" => '\u{2014}',
        "ndash" => '\u{2013}',
        "lsquo" => '\u{2018}',
        "rsquo" => '\u{2019}',
        "ldquo" => '\u{201c}',
        "rdquo" => '\u{201d}',
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collects_attributes_and_content_like_coraza() {
        let xml = br#"<?xml version="1.0"?>
            <root xmlns="urn:test" id="1">
                <child name="value"> hello </child>
                <empty/>
            </root>"#;
        let values = process(xml).expect("xml");
        assert_eq!(
            values.attributes,
            vec![b"urn:test".to_vec(), b"1".to_vec(), b"value".to_vec()]
        );
        assert_eq!(values.content, vec![b"hello".to_vec()]);
    }

    #[test]
    fn cdata_is_character_data() {
        let values = process(b"<a><![CDATA[  <script>alert(1)</script>  ]]></a>").expect("xml");
        assert_eq!(values.content, vec![b"<script>alert(1)</script>".to_vec()]);
    }

    #[test]
    fn entities_are_decoded_without_network_access() {
        let values = process(b"<a x=\"&lt;&amp;&#65;\">&quot;x&quot;</a>").expect("xml");
        assert_eq!(values.attributes, vec![b"<&A".to_vec()]);
        assert_eq!(values.content, vec![b"\"x\"".to_vec()]);
    }

    #[test]
    fn doctype_is_ignored_and_never_fetched() {
        let values =
            process(b"<!DOCTYPE foo SYSTEM \"http://127.0.0.1/evil.dtd\"><foo a=\"b\">c</foo>")
                .expect("xml");
        assert_eq!(values.attributes, vec![b"b".to_vec()]);
        assert_eq!(values.content, vec![b"c".to_vec()]);
    }

    #[test]
    fn malformed_xml_is_an_error() {
        assert!(process(b"<a><b></a>").is_err());
        assert!(process(b"<a>").is_err());
        assert!(process(b"<a x=>1</a>").is_err());
    }
}
