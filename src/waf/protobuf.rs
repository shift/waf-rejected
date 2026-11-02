//! Minimal, allocation-light protobuf wire decoder for gRPC field policy.
//!
//! This module only needs to understand enough of the wire format to walk a
//! message against descriptor metadata. It does not materialise values: scalar
//! content is checked in place (string length/bytes/UTF-8, enum membership),
//! unknown fields are skipped, and nested messages are recursed with a depth
//! limit. No generated code or heavyweight protobuf runtime is required.

use std::collections::HashMap;

use super::grpc_allowlist::{GrpcMessage, GrpcMessageField};

const WIRE_VARINT: u8 = 0;
const WIRE_64BIT: u8 = 1;
const WIRE_LENGTH_DELIMITED: u8 = 2;
const WIRE_32BIT: u8 = 5;

/// Per-field decoding policy derived from `[waf.grpc]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodeLimits {
    /// Maximum length of one `string` value.
    pub max_string_bytes: usize,
    /// Maximum length of one `bytes` value.
    pub max_bytes_len: usize,
    /// Maximum number of values for one repeated field.
    pub max_repeated: usize,
    /// Maximum nested message depth (the request message is depth 0).
    pub max_depth: usize,
    /// Maximum number of wire fields decoded in one message tree.
    pub max_decoded_fields: usize,
    /// Reject field numbers that are absent from the descriptor.
    pub reject_unknown_fields: bool,
    /// Validate string values (UTF-8, NUL and control characters).
    pub validate_strings: bool,
}

/// Field-level decoding failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// The wire data is structurally invalid.
    Malformed { path: String, reason: String },
    /// A configured field limit was exceeded.
    Limit { path: String, reason: String },
    /// A field number is not in the descriptor and unknowns are rejected.
    UnknownField { path: String },
    /// An enum value is not declared in the descriptor.
    InvalidEnum { path: String, value: i32 },
    /// A string is not valid UTF-8 or contains forbidden characters.
    InvalidString { path: String, reason: String },
}

impl DecodeError {
    /// HTTP status for a request rejected by this error.
    pub fn status(&self) -> u16 {
        match self {
            Self::Limit { .. } => 413,
            _ => 400,
        }
    }
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed { path, reason } => {
                write!(formatter, "malformed protobuf at field '{path}': {reason}")
            }
            Self::Limit { path, reason } => {
                write!(formatter, "protobuf field '{path}' {reason}")
            }
            Self::UnknownField { path } => {
                write!(
                    formatter,
                    "protobuf field '{path}' is not defined by the descriptor"
                )
            }
            Self::InvalidEnum { path, value } => write!(
                formatter,
                "protobuf enum field '{path}' has undeclared value {value}"
            ),
            Self::InvalidString { path, reason } => {
                write!(formatter, "protobuf string field '{path}' {reason}")
            }
        }
    }
}

impl std::error::Error for DecodeError {}

/// Decodes `payload` as `input_type` and enforces field policy.
///
/// Callers must only invoke this when the descriptor contains `input_type`;
/// missing metadata falls back to envelope-only inspection before this point.
pub fn decode_message(
    payload: &[u8],
    input_type: &str,
    messages: &HashMap<String, GrpcMessage>,
    limits: &DecodeLimits,
) -> Result<(), DecodeError> {
    let Some(message) = messages.get(input_type) else {
        return Ok(());
    };
    let mut decoder = Decoder {
        cursor: Cursor::new(payload),
        messages,
        limits,
        decoded_fields: 0,
    };
    decoder.decode_at(message, input_type, 0)
}

struct Decoder<'a> {
    cursor: Cursor<'a>,
    messages: &'a HashMap<String, GrpcMessage>,
    limits: &'a DecodeLimits,
    decoded_fields: usize,
}

impl<'a> Decoder<'a> {
    fn decode_at(
        &mut self,
        message: &GrpcMessage,
        path: &str,
        depth: usize,
    ) -> Result<(), DecodeError> {
        if depth > self.limits.max_depth {
            return Err(DecodeError::Limit {
                path: path.to_string(),
                reason: format!(
                    "exceeds the maximum nesting depth of {}",
                    self.limits.max_depth
                ),
            });
        }

        let mut repeated_counts: HashMap<u32, usize> = HashMap::new();
        while let Some(tag) = self
            .cursor
            .read_tag()
            .map_err(|error| DecodeError::Malformed {
                path: path.to_string(),
                reason: error.reason,
            })?
        {
            let (number, wire) = tag;
            self.decoded_fields += 1;
            if self.decoded_fields > self.limits.max_decoded_fields {
                return Err(DecodeError::Limit {
                    path: path.to_string(),
                    reason: format!(
                        "exceeds the maximum decoded field count of {}",
                        self.limits.max_decoded_fields
                    ),
                });
            }

            let Some(field) = message.fields.iter().find(|field| field.number == number) else {
                if self.limits.reject_unknown_fields {
                    return Err(DecodeError::UnknownField {
                        path: format!("{path}.<field {number}>"),
                    });
                }
                self.cursor
                    .skip(wire)
                    .map_err(|error| DecodeError::Malformed {
                        path: format!("{path}.<field {number}>"),
                        reason: error.reason,
                    })?;
                continue;
            };

            let field_path = format!("{path}.{}", field.name);
            self.decode_field(field, wire, &field_path, depth, &mut repeated_counts)?;
        }
        Ok(())
    }

    fn decode_field(
        &mut self,
        field: &GrpcMessageField,
        wire: u8,
        path: &str,
        depth: usize,
        repeated_counts: &mut HashMap<u32, usize>,
    ) -> Result<(), DecodeError> {
        if field.repeated && wire == WIRE_LENGTH_DELIMITED && is_packable(&field.field_type) {
            let payload = self.length_delimited(path)?;
            let count = packed_count(&field.field_type, payload).map_err(|reason| {
                DecodeError::Malformed {
                    path: path.to_string(),
                    reason,
                }
            })?;
            if count > self.limits.max_repeated {
                return Err(DecodeError::Limit {
                    path: path.to_string(),
                    reason: format!(
                        "exceeds the maximum repeated count of {}",
                        self.limits.max_repeated
                    ),
                });
            }
            let entry = repeated_counts.entry(field.number).or_default();
            *entry = entry.saturating_add(count);
            if *entry > self.limits.max_repeated {
                return Err(DecodeError::Limit {
                    path: path.to_string(),
                    reason: format!(
                        "exceeds the maximum repeated count of {}",
                        self.limits.max_repeated
                    ),
                });
            }
            if field.field_type == "enum" {
                if let Some(values) = &field.enum_values {
                    validate_packed_enum(values, payload, path)?;
                }
            }
            return Ok(());
        }

        if field.repeated {
            let entry = repeated_counts.entry(field.number).or_default();
            *entry = entry.saturating_add(1);
            if *entry > self.limits.max_repeated {
                return Err(DecodeError::Limit {
                    path: path.to_string(),
                    reason: format!(
                        "exceeds the maximum repeated count of {}",
                        self.limits.max_repeated
                    ),
                });
            }
        }

        let expected = expected_wire(&field.field_type);
        if wire != expected {
            return Err(DecodeError::Malformed {
                path: path.to_string(),
                reason: format!(
                    "wire type {wire} does not match {} (expected {expected})",
                    field.field_type
                ),
            });
        }

        match field.field_type.as_str() {
            "string" => {
                let value = self.length_delimited(path)?;
                if value.len() > self.limits.max_string_bytes {
                    return Err(DecodeError::Limit {
                        path: path.to_string(),
                        reason: format!(
                            "is {} bytes, exceeding the {}-byte string limit",
                            value.len(),
                            self.limits.max_string_bytes
                        ),
                    });
                }
                if self.limits.validate_strings {
                    validate_string(value, path)?;
                }
            }
            "bytes" => {
                let value = self.length_delimited(path)?;
                if value.len() > self.limits.max_bytes_len {
                    return Err(DecodeError::Limit {
                        path: path.to_string(),
                        reason: format!(
                            "is {} bytes, exceeding the {}-byte bytes limit",
                            value.len(),
                            self.limits.max_bytes_len
                        ),
                    });
                }
            }
            "message" => {
                let payload = self.length_delimited(path)?;
                if let Some(target) = field.message_type.as_deref() {
                    if let Some(nested) = self.messages.get(target) {
                        let child_path = if field.repeated {
                            let index = repeated_counts
                                .get(&field.number)
                                .copied()
                                .unwrap_or(1)
                                .saturating_sub(1);
                            format!("{path}[{index}]")
                        } else {
                            path.to_string()
                        };
                        let mut child = Decoder {
                            cursor: Cursor::new(payload),
                            messages: self.messages,
                            limits: self.limits,
                            decoded_fields: self.decoded_fields,
                        };
                        let result = child.decode_at(nested, &child_path, depth + 1);
                        self.decoded_fields = child.decoded_fields;
                        return result;
                    }
                }
            }
            "enum" => {
                let value = self
                    .cursor
                    .read_varint()
                    .map_err(|error| DecodeError::Malformed {
                        path: path.to_string(),
                        reason: error.reason,
                    })? as i32;
                if let Some(values) = &field.enum_values {
                    if !values.contains(&value) {
                        return Err(DecodeError::InvalidEnum {
                            path: path.to_string(),
                            value,
                        });
                    }
                }
            }
            _ => {
                self.cursor
                    .skip(wire)
                    .map_err(|error| DecodeError::Malformed {
                        path: path.to_string(),
                        reason: error.reason,
                    })?;
            }
        }
        Ok(())
    }

    fn length_delimited(&mut self, path: &str) -> Result<&'a [u8], DecodeError> {
        self.cursor
            .read_length_delimited()
            .map_err(|error| DecodeError::Malformed {
                path: path.to_string(),
                reason: error.reason,
            })
    }
}

fn expected_wire(field_type: &str) -> u8 {
    match field_type {
        "double" | "fixed64" => WIRE_64BIT,
        "float" | "fixed32" => WIRE_32BIT,
        "string" | "bytes" | "message" => WIRE_LENGTH_DELIMITED,
        _ => WIRE_VARINT,
    }
}

fn is_packable(field_type: &str) -> bool {
    !matches!(field_type, "string" | "bytes" | "message")
}

fn packed_count(field_type: &str, payload: &[u8]) -> Result<usize, String> {
    match field_type {
        "double" | "fixed64" => {
            if payload.len().is_multiple_of(8) {
                Ok(payload.len() / 8)
            } else {
                Err("packed fixed64 field has a length that is not a multiple of 8".to_string())
            }
        }
        "float" | "fixed32" => {
            if payload.len().is_multiple_of(4) {
                Ok(payload.len() / 4)
            } else {
                Err("packed fixed32 field has a length that is not a multiple of 4".to_string())
            }
        }
        _ => {
            let mut cursor = Cursor::new(payload);
            let mut count = 0;
            while cursor.remaining() > 0 {
                cursor.read_varint().map_err(|error| error.reason)?;
                count += 1;
            }
            Ok(count)
        }
    }
}

fn validate_packed_enum(values: &[i32], payload: &[u8], path: &str) -> Result<(), DecodeError> {
    let mut cursor = Cursor::new(payload);
    while cursor.remaining() > 0 {
        let value = cursor
            .read_varint()
            .map_err(|error| DecodeError::Malformed {
                path: path.to_string(),
                reason: error.reason,
            })? as i32;
        if !values.contains(&value) {
            return Err(DecodeError::InvalidEnum {
                path: path.to_string(),
                value,
            });
        }
    }
    Ok(())
}

fn validate_string(value: &[u8], path: &str) -> Result<(), DecodeError> {
    let text = std::str::from_utf8(value).map_err(|_| DecodeError::InvalidString {
        path: path.to_string(),
        reason: "is not valid UTF-8".to_string(),
    })?;
    for byte in text.bytes() {
        if byte == 0 {
            return Err(DecodeError::InvalidString {
                path: path.to_string(),
                reason: "contains a NUL byte".to_string(),
            });
        }
        if (byte < 0x20 && byte != b'\t' && byte != b'\n' && byte != b'\r') || byte == 0x7f {
            return Err(DecodeError::InvalidString {
                path: path.to_string(),
                reason: format!("contains control byte 0x{byte:02x}"),
            });
        }
    }
    Ok(())
}

#[derive(Debug)]
struct WireError {
    reason: String,
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }

    fn read_varint(&mut self) -> Result<u64, WireError> {
        let mut value = 0u64;
        for shift in 0..10 {
            let byte = *self.bytes.get(self.offset).ok_or_else(|| WireError {
                reason: format!("truncated varint at offset {}", self.offset),
            })?;
            self.offset += 1;
            value |= u64::from(byte & 0x7f) << (shift * 7);
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(WireError {
            reason: format!("varint longer than 10 bytes at offset {}", self.offset),
        })
    }

    fn read_tag(&mut self) -> Result<Option<(u32, u8)>, WireError> {
        if self.offset >= self.bytes.len() {
            return Ok(None);
        }
        let tag = self.read_varint()?;
        let number = u32::try_from(tag >> 3)
            .ok()
            .filter(|number| *number != 0)
            .ok_or_else(|| WireError {
                reason: format!("invalid field number in tag at offset {}", self.offset),
            })?;
        Ok(Some((number, (tag & 0x07) as u8)))
    }

    fn read_length_delimited(&mut self) -> Result<&'a [u8], WireError> {
        let length = usize::try_from(self.read_varint()?).map_err(|_| WireError {
            reason: format!("length prefix too large at offset {}", self.offset),
        })?;
        let end = self.offset.checked_add(length).ok_or_else(|| WireError {
            reason: format!("length prefix overflows at offset {}", self.offset),
        })?;
        if end > self.bytes.len() {
            return Err(WireError {
                reason: format!(
                    "truncated length-delimited field at offset {} (need {length} bytes, {} available)",
                    self.offset,
                    self.remaining()
                ),
            });
        }
        let slice = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(slice)
    }

    fn skip(&mut self, wire: u8) -> Result<(), WireError> {
        match wire {
            WIRE_VARINT => {
                self.read_varint()?;
            }
            WIRE_64BIT => self.advance(8)?,
            WIRE_LENGTH_DELIMITED => {
                self.read_length_delimited()?;
            }
            WIRE_32BIT => self.advance(4)?,
            other => {
                return Err(WireError {
                    reason: format!("unsupported wire type {other} at offset {}", self.offset),
                });
            }
        }
        Ok(())
    }

    fn advance(&mut self, amount: usize) -> Result<(), WireError> {
        let end = self.offset.checked_add(amount).ok_or_else(|| WireError {
            reason: format!("offset overflow at {}", self.offset),
        })?;
        if end > self.bytes.len() {
            return Err(WireError {
                reason: format!("truncated field at offset {}", self.offset),
            });
        }
        self.offset = end;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(name: &str, number: u32, field_type: &str, repeated: bool) -> GrpcMessageField {
        GrpcMessageField {
            name: name.to_string(),
            number,
            field_type: field_type.to_string(),
            repeated,
            required: false,
            message_type: None,
            enum_values: None,
        }
    }

    fn message(name: &str, fields: Vec<GrpcMessageField>) -> GrpcMessage {
        GrpcMessage {
            message: name.to_string(),
            fields,
        }
    }

    fn registry(messages: Vec<GrpcMessage>) -> HashMap<String, GrpcMessage> {
        messages
            .into_iter()
            .map(|message| (message.message.clone(), message))
            .collect()
    }

    fn limits() -> DecodeLimits {
        DecodeLimits {
            max_string_bytes: 64,
            max_bytes_len: 64,
            max_repeated: 4,
            max_depth: 4,
            max_decoded_fields: 64,
            reject_unknown_fields: false,
            validate_strings: true,
        }
    }

    fn put_varint(mut value: u64, out: &mut Vec<u8>) {
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if value == 0 {
                return;
            }
        }
    }

    fn put_tag(number: u32, wire: u8, out: &mut Vec<u8>) {
        put_varint((u64::from(number) << 3) | u64::from(wire), out);
    }

    fn put_string(number: u32, value: &str, out: &mut Vec<u8>) {
        put_tag(number, WIRE_LENGTH_DELIMITED, out);
        put_varint(value.len() as u64, out);
        out.extend_from_slice(value.as_bytes());
    }

    #[test]
    fn valid_message_decodes() {
        let messages = registry(vec![message(
            "pkg.Request",
            vec![field("name", 1, "string", false)],
        )]);
        let mut payload = Vec::new();
        put_string(1, "alice", &mut payload);
        decode_message(&payload, "pkg.Request", &messages, &limits()).unwrap();
    }

    #[test]
    fn unknown_fields_are_skipped_or_rejected() {
        let messages = registry(vec![message("pkg.Request", vec![])]);
        let mut payload = Vec::new();
        put_string(99, "value", &mut payload);
        decode_message(&payload, "pkg.Request", &messages, &limits()).unwrap();

        let mut limits = limits();
        limits.reject_unknown_fields = true;
        let error = decode_message(&payload, "pkg.Request", &messages, &limits).unwrap_err();
        assert!(error.to_string().contains("<field 99>"), "{error}");
    }

    #[test]
    fn oversized_string_is_rejected_with_path() {
        let messages = registry(vec![message(
            "pkg.Request",
            vec![field("name", 1, "string", false)],
        )]);
        let mut payload = Vec::new();
        put_string(1, "abcdefgh", &mut payload);
        let mut limits = limits();
        limits.max_string_bytes = 4;
        let error = decode_message(&payload, "pkg.Request", &messages, &limits).unwrap_err();
        assert_eq!(error.status(), 413);
        assert!(error.to_string().contains("pkg.Request.name"), "{error}");
    }

    #[test]
    fn malformed_wire_data_is_rejected() {
        let messages = registry(vec![message(
            "pkg.Request",
            vec![field("name", 1, "string", false)],
        )]);
        let payload = vec![0x0a, 0x05, 0x01];
        let error = decode_message(&payload, "pkg.Request", &messages, &limits()).unwrap_err();
        assert_eq!(error.status(), 400);
        assert!(error.to_string().contains("pkg.Request.name"), "{error}");
    }

    #[test]
    fn nested_depth_is_bounded() {
        let mut child = field("leaf", 1, "string", false);
        child.message_type = None;
        let mut parent = field("child", 1, "message", false);
        parent.message_type = Some("pkg.Child".to_string());
        let messages = registry(vec![
            message("pkg.Parent", vec![parent]),
            message("pkg.Child", vec![child]),
        ]);
        let mut inner = Vec::new();
        put_string(1, "leaf", &mut inner);
        let mut payload = Vec::new();
        put_tag(1, WIRE_LENGTH_DELIMITED, &mut payload);
        put_varint(inner.len() as u64, &mut payload);
        payload.extend_from_slice(&inner);

        let mut limits = limits();
        limits.max_depth = 0;
        let error = decode_message(&payload, "pkg.Parent", &messages, &limits).unwrap_err();
        assert_eq!(error.status(), 413);
        assert!(error.to_string().contains("pkg.Parent.child"), "{error}");
    }

    #[test]
    fn enum_values_are_validated() {
        let mut field = field("state", 1, "enum", false);
        field.enum_values = Some(vec![0, 1]);
        let messages = registry(vec![message("pkg.Request", vec![field])]);
        let mut payload = Vec::new();
        put_tag(1, WIRE_VARINT, &mut payload);
        put_varint(2, &mut payload);
        let error = decode_message(&payload, "pkg.Request", &messages, &limits()).unwrap_err();
        assert!(error.to_string().contains("pkg.Request.state"), "{error}");
    }

    #[test]
    fn control_characters_are_rejected() {
        let messages = registry(vec![message(
            "pkg.Request",
            vec![field("name", 1, "string", false)],
        )]);
        let mut payload = Vec::new();
        put_tag(1, WIRE_LENGTH_DELIMITED, &mut payload);
        put_varint(2, &mut payload);
        payload.extend_from_slice(b"a\0");
        let error = decode_message(&payload, "pkg.Request", &messages, &limits()).unwrap_err();
        assert!(error.to_string().contains("NUL"), "{error}");
    }

    #[test]
    fn packed_repeated_values_count_toward_the_limit() {
        let messages = registry(vec![message(
            "pkg.Request",
            vec![field("ids", 1, "int32", true)],
        )]);
        let mut payload = Vec::new();
        put_tag(1, WIRE_LENGTH_DELIMITED, &mut payload);
        put_varint(3, &mut payload);
        for value in 1..=3 {
            put_varint(value, &mut payload);
        }
        let mut limits = limits();
        limits.max_repeated = 2;
        let error = decode_message(&payload, "pkg.Request", &messages, &limits).unwrap_err();
        assert_eq!(error.status(), 413);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    fn field(name: &str, number: u32, field_type: &str, repeated: bool) -> GrpcMessageField {
        GrpcMessageField {
            name: name.to_string(),
            number,
            field_type: field_type.to_string(),
            repeated,
            required: false,
            message_type: None,
            enum_values: None,
        }
    }

    fn sample_registry() -> HashMap<String, GrpcMessage> {
        let mut child = field("child", 6, "message", false);
        child.message_type = Some("pkg.Node".to_string());
        let mut state = field("state", 2, "enum", false);
        state.enum_values = Some(vec![0, 1, 2]);
        let messages = vec![
            GrpcMessage {
                message: "pkg.Request".to_string(),
                fields: vec![
                    field("name", 1, "string", false),
                    field("blob", 2, "bytes", false),
                    field("count", 3, "int32", false),
                    field("ids", 4, "int32", true),
                    state,
                    child.clone(),
                ],
            },
            GrpcMessage {
                message: "pkg.Node".to_string(),
                fields: vec![field("value", 1, "string", false), child],
            },
        ];
        messages
            .into_iter()
            .map(|message| (message.message.clone(), message))
            .collect()
    }

    fn limits() -> DecodeLimits {
        DecodeLimits {
            max_string_bytes: 64,
            max_bytes_len: 64,
            max_repeated: 4,
            max_depth: 4,
            max_decoded_fields: 64,
            reject_unknown_fields: false,
            validate_strings: true,
        }
    }

    fn put_varint(mut value: u64, out: &mut Vec<u8>) {
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if value == 0 {
                return;
            }
        }
    }

    fn put_tag(number: u32, wire: u8, out: &mut Vec<u8>) {
        put_varint((u64::from(number) << 3) | u64::from(wire), out);
    }

    fn put_len(number: u32, value: &[u8], out: &mut Vec<u8>) {
        put_tag(number, WIRE_LENGTH_DELIMITED, out);
        put_varint(value.len() as u64, out);
        out.extend_from_slice(value);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        #[test]
        fn arbitrary_bytes_never_panic(payload in proptest::collection::vec(any::<u8>(), 0..2048)) {
            let messages = sample_registry();
            let _ = decode_message(&payload, "pkg.Request", &messages, &limits());
        }

        #[test]
        fn valid_string_round_trips(value in "[ -~]{0,64}") {
            let messages = sample_registry();
            let mut payload = Vec::new();
            put_len(1, value.as_bytes(), &mut payload);
            prop_assert!(decode_message(&payload, "pkg.Request", &messages, &limits()).is_ok());
        }

        #[test]
        fn string_length_limit_is_enforced(value in proptest::collection::vec(any::<u8>(), 0..128)) {
            let messages = sample_registry();
            let mut payload = Vec::new();
            put_len(1, &value, &mut payload);
            let result = decode_message(&payload, "pkg.Request", &messages, &limits());
            if value.len() > 64 {
                let is_limit = matches!(result, Err(DecodeError::Limit { .. }));
                prop_assert!(is_limit);
            }
        }

        #[test]
        fn nested_depth_is_bounded(depth in 0usize..20) {
            let messages = sample_registry();
            let mut payload = Vec::new();
            for _ in 0..depth {
                let mut wrapped = Vec::new();
                put_len(6, &payload, &mut wrapped);
                payload = wrapped;
            }
            let result = decode_message(&payload, "pkg.Request", &messages, &limits());
            if depth > 4 {
                let is_limit = matches!(result, Err(DecodeError::Limit { .. }));
                prop_assert!(is_limit);
            } else {
                prop_assert!(result.is_ok());
            }
        }

        #[test]
        fn repeated_count_is_bounded(count in 0usize..16) {
            let messages = sample_registry();
            let mut payload = Vec::new();
            for value in 0..count {
                put_tag(4, WIRE_VARINT, &mut payload);
                put_varint(value as u64, &mut payload);
            }
            let result = decode_message(&payload, "pkg.Request", &messages, &limits());
            if count > 4 {
                let is_limit = matches!(result, Err(DecodeError::Limit { .. }));
                prop_assert!(is_limit);
            } else {
                prop_assert!(result.is_ok());
            }
        }
    }
}
