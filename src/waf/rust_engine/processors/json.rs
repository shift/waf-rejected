//! JSON body processor.
//!
//! Semantics are copied from the vendored Coraza v3.3.3
//! `internal/bodyprocessors/json.go`:
//!
//! * every scalar is written to `ARGS_POST` with the `json.` prefix;
//! * object keys are joined with `.`; array elements use their index;
//! * an array also writes its length at the array path (`json.items` = `3`);
//! * strings are decoded, `null` becomes the empty value and numbers/booleans
//!   keep their raw JSON spelling;
//! * duplicate object keys overwrite the previous flattened value.
//!
//! Coraza parses with gjson, which returns an empty result (not an error) for
//! malformed input. The native parser behaves the same way for malformed
//! documents: the collection is left empty. The only difference is an explicit
//! depth/value bound, which Coraza documents as a missing anti-DOS guard.

use std::collections::HashMap;

use super::{ProcessorError, ProcessorLimits};

/// Flattens `body` into `(key, value)` pairs in first-seen order.
pub fn process(
    body: &[u8],
    limits: &ProcessorLimits,
) -> Result<Vec<(String, Vec<u8>)>, ProcessorError> {
    let Some(value) = Parser::new(body, *limits).parse_root()? else {
        return Ok(Vec::new());
    };
    if !matches!(value, Value::Object(_) | Value::Array(_)) {
        return Ok(Vec::new());
    }

    let mut output = Output {
        entries: Vec::new(),
        index: HashMap::new(),
        limits: *limits,
    };
    output.flatten(&value, "json", 1)?;
    Ok(output.entries)
}

#[derive(Debug)]
enum Value {
    Object(Vec<(String, Value)>),
    Array(Vec<Value>),
    String(String),
    Raw(Vec<u8>),
    Null,
}

impl Value {
    fn is_container(&self) -> bool {
        matches!(self, Self::Object(_) | Self::Array(_))
    }

    fn scalar_bytes(&self) -> Vec<u8> {
        match self {
            Self::String(value) => value.as_bytes().to_vec(),
            Self::Raw(value) => value.clone(),
            Self::Null => Vec::new(),
            Self::Object(_) | Self::Array(_) => Vec::new(),
        }
    }
}

struct Output {
    entries: Vec<(String, Vec<u8>)>,
    index: HashMap<String, usize>,
    limits: ProcessorLimits,
}

impl Output {
    fn insert(&mut self, key: String, value: Vec<u8>) -> Result<(), ProcessorError> {
        if value.len() > self.limits.max_value_bytes {
            return Err(ProcessorError::Limit("json value exceeds the byte cap"));
        }
        if let Some(&index) = self.index.get(&key) {
            // Coraza stores flattened values in a Go map, so the last
            // duplicate key wins.
            self.entries[index].1 = value;
            return Ok(());
        }
        if self.entries.len() >= self.limits.max_values {
            return Err(ProcessorError::Limit("json value count exceeds the cap"));
        }
        self.index.insert(key.clone(), self.entries.len());
        self.entries.push((key, value));
        Ok(())
    }

    fn flatten(&mut self, value: &Value, prefix: &str, depth: usize) -> Result<(), ProcessorError> {
        if depth > self.limits.max_depth {
            return Err(ProcessorError::Limit("json nesting exceeds the depth cap"));
        }
        match value {
            Value::Object(pairs) => {
                for (key, value) in pairs {
                    let path = format!("{prefix}.{key}");
                    if value.is_container() {
                        self.flatten(value, &path, depth + 1)?;
                    } else {
                        self.insert(path, value.scalar_bytes())?;
                    }
                }
            }
            Value::Array(items) => {
                let mut length = 0usize;
                for (index, value) in items.iter().enumerate() {
                    length += 1;
                    let path = format!("{prefix}.{index}");
                    if value.is_container() {
                        self.flatten(value, &path, depth + 1)?;
                    } else {
                        self.insert(path, value.scalar_bytes())?;
                    }
                }
                // gjson's readItems writes the number of array elements at the
                // array's own path; an empty array writes nothing.
                if length > 0 {
                    self.insert(prefix.to_string(), length.to_string().into_bytes())?;
                }
            }
            Value::String(_) | Value::Raw(_) | Value::Null => {}
        }
        Ok(())
    }
}

struct Parser<'a> {
    bytes: &'a [u8],
    cursor: usize,
    limits: ProcessorLimits,
}

impl<'a> Parser<'a> {
    fn new(bytes: &'a [u8], limits: ProcessorLimits) -> Self {
        Self {
            bytes,
            cursor: 0,
            limits,
        }
    }

    /// Parses the first JSON value, ignoring trailing bytes like gjson.
    fn parse_root(mut self) -> Result<Option<Value>, ProcessorError> {
        self.skip_whitespace();
        if self.cursor >= self.bytes.len() {
            return Ok(None);
        }
        self.parse_value(1)
    }

    fn parse_value(&mut self, depth: usize) -> Result<Option<Value>, ProcessorError> {
        if depth > self.limits.max_depth {
            return Err(ProcessorError::Limit("json nesting exceeds the depth cap"));
        }
        let Some(byte) = self.peek() else {
            return Ok(None);
        };
        match byte {
            b'{' => self.parse_object(depth),
            b'[' => self.parse_array(depth),
            b'"' => Ok(self.parse_string()?.map(Value::String)),
            b't' => Ok(self.literal(b"true").then(|| Value::Raw(b"true".to_vec()))),
            b'f' => Ok(self
                .literal(b"false")
                .then(|| Value::Raw(b"false".to_vec()))),
            b'n' => Ok(self.literal(b"null").then_some(Value::Null)),
            _ => self.parse_number(),
        }
    }

    fn parse_object(&mut self, depth: usize) -> Result<Option<Value>, ProcessorError> {
        self.cursor += 1; // '{'
        let mut pairs = Vec::new();
        self.skip_whitespace();
        if self.consume(b'}') {
            return Ok(Some(Value::Object(pairs)));
        }
        loop {
            self.skip_whitespace();
            let Some(key) = self.parse_string()? else {
                return Ok(None);
            };
            self.skip_whitespace();
            if !self.consume(b':') {
                return Ok(None);
            }
            self.skip_whitespace();
            let Some(value) = self.parse_value(depth + 1)? else {
                return Ok(None);
            };
            pairs.push((key, value));
            self.skip_whitespace();
            if self.consume(b',') {
                continue;
            }
            if self.consume(b'}') {
                return Ok(Some(Value::Object(pairs)));
            }
            return Ok(None);
        }
    }

    fn parse_array(&mut self, depth: usize) -> Result<Option<Value>, ProcessorError> {
        self.cursor += 1; // '['
        let mut items = Vec::new();
        self.skip_whitespace();
        if self.consume(b']') {
            return Ok(Some(Value::Array(items)));
        }
        loop {
            self.skip_whitespace();
            let Some(value) = self.parse_value(depth + 1)? else {
                return Ok(None);
            };
            items.push(value);
            self.skip_whitespace();
            if self.consume(b',') {
                continue;
            }
            if self.consume(b']') {
                return Ok(Some(Value::Array(items)));
            }
            return Ok(None);
        }
    }

    fn parse_string(&mut self) -> Result<Option<String>, ProcessorError> {
        if !self.consume(b'"') {
            return Ok(None);
        }
        let mut out: Vec<u8> = Vec::new();
        while let Some(byte) = self.peek() {
            self.cursor += 1;
            match byte {
                b'"' => {
                    return Ok(String::from_utf8(out).ok());
                }
                b'\\' => {
                    let Some(escape) = self.peek() else {
                        return Ok(None);
                    };
                    self.cursor += 1;
                    match escape {
                        b'"' => out.push(b'"'),
                        b'\\' => out.push(b'\\'),
                        b'/' => out.push(b'/'),
                        b'b' => out.push(0x08),
                        b'f' => out.push(0x0c),
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'u' => {
                            let Some(codepoint) = self.hex4() else {
                                return Ok(None);
                            };
                            let codepoint = if (0xd800..=0xdbff).contains(&codepoint) {
                                // Surrogate pair.
                                if !(self.consume(b'\\') && self.consume(b'u')) {
                                    return Ok(None);
                                }
                                let Some(low) = self.hex4() else {
                                    return Ok(None);
                                };
                                if !(0xdc00..=0xdfff).contains(&low) {
                                    return Ok(None);
                                }
                                0x10000
                                    + ((u32::from(codepoint) - 0xd800) << 10)
                                    + (u32::from(low) - 0xdc00)
                            } else {
                                u32::from(codepoint)
                            };
                            let Some(ch) = char::from_u32(codepoint) else {
                                return Ok(None);
                            };
                            let mut buffer = [0u8; 4];
                            out.extend_from_slice(ch.encode_utf8(&mut buffer).as_bytes());
                        }
                        _ => return Ok(None),
                    }
                }
                byte if byte < 0x20 => return Ok(None),
                byte => out.push(byte),
            }
        }
        Ok(None)
    }

    fn hex4(&mut self) -> Option<u16> {
        let slice = self.bytes.get(self.cursor..self.cursor + 4)?;
        let mut value = 0u16;
        for byte in slice {
            value = (value << 4) | u16::from(hex_value(*byte)?);
        }
        self.cursor += 4;
        Some(value)
    }

    fn parse_number(&mut self) -> Result<Option<Value>, ProcessorError> {
        let start = self.cursor;
        if self.peek() == Some(b'-') {
            self.cursor += 1;
        }
        let digits = self.take_digits();
        if digits == 0 {
            return Ok(None);
        }
        if self.peek() == Some(b'.') {
            self.cursor += 1;
            if self.take_digits() == 0 {
                return Ok(None);
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.cursor += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.cursor += 1;
            }
            if self.take_digits() == 0 {
                return Ok(None);
            }
        }
        Ok(Some(Value::Raw(self.bytes[start..self.cursor].to_vec())))
    }

    fn take_digits(&mut self) -> usize {
        let start = self.cursor;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.cursor += 1;
        }
        self.cursor - start
    }

    fn literal(&mut self, expected: &[u8]) -> bool {
        if self.bytes.get(self.cursor..self.cursor + expected.len()) == Some(expected) {
            self.cursor += expected.len();
            true
        } else {
            false
        }
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.cursor += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.cursor).copied()
    }

    fn consume(&mut self, byte: u8) -> bool {
        if self.peek() == Some(byte) {
            self.cursor += 1;
            true
        } else {
            false
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

#[cfg(test)]
mod tests {
    use super::*;

    fn flatten(body: &str) -> Vec<(String, Vec<u8>)> {
        process(body.as_bytes(), &ProcessorLimits::default()).expect("process")
    }

    fn map(body: &str) -> HashMap<String, String> {
        flatten(body)
            .into_iter()
            .map(|(key, value)| (key, String::from_utf8_lossy(&value).into_owned()))
            .collect()
    }

    #[test]
    fn matches_coraza_flattening_example() {
        let values =
            map(r#"{"data":{"name":"John","age":30},"items":[1,2,3],"ok":true,"none":null}"#);
        assert_eq!(values["json.data.name"], "John");
        assert_eq!(values["json.data.age"], "30");
        assert_eq!(values["json.items.0"], "1");
        assert_eq!(values["json.items.1"], "2");
        assert_eq!(values["json.items.2"], "3");
        assert_eq!(values["json.items"], "3");
        assert_eq!(values["json.ok"], "true");
        assert_eq!(values["json.none"], "");
    }

    #[test]
    fn root_array_writes_length() {
        let values = map(r#"[{"a":1},2]"#);
        assert_eq!(values["json.0.a"], "1");
        assert_eq!(values["json.1"], "2");
        assert_eq!(values["json"], "2");
    }

    #[test]
    fn duplicate_keys_last_wins() {
        let values = flatten(r#"{"a":1,"a":2}"#);
        assert_eq!(values.len(), 1);
        assert_eq!(values[0].1, b"2");
    }

    #[test]
    fn malformed_input_is_empty_like_gjson() {
        assert!(flatten("{").is_empty());
        assert!(flatten("not json").is_empty());
        assert!(flatten("").is_empty());
        assert!(flatten(r#""scalar""#).is_empty());
    }

    #[test]
    fn numbers_keep_their_raw_spelling() {
        let values = map(r#"{"a":1.50,"b":1e3,"c":-0}"#);
        assert_eq!(values["json.a"], "1.50");
        assert_eq!(values["json.b"], "1e3");
        assert_eq!(values["json.c"], "-0");
    }

    #[test]
    fn depth_bound_fails_closed() {
        let limits = ProcessorLimits {
            max_depth: 2,
            ..ProcessorLimits::default()
        };
        let err = process(br#"{"a":{"b":{"c":1}}}"#, &limits).expect_err("depth");
        assert!(matches!(err, ProcessorError::Limit(_)));
    }
}
