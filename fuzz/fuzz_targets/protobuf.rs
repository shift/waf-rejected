#![no_main]

use std::collections::HashMap;
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use waf_ingress::waf::grpc_allowlist::{GrpcMessage, GrpcMessageField};
use waf_ingress::waf::protobuf::{decode_message, DecodeLimits};

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

fn registry() -> &'static HashMap<String, GrpcMessage> {
    static REGISTRY: OnceLock<HashMap<String, GrpcMessage>> = OnceLock::new();
    REGISTRY.get_or_init(|| {
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
    })
}

fn limits() -> DecodeLimits {
    DecodeLimits {
        max_string_bytes: 1024,
        max_bytes_len: 1024,
        max_repeated: 64,
        max_depth: 8,
        max_decoded_fields: 1024,
        reject_unknown_fields: false,
        validate_strings: true,
    }
}

fuzz_target!(|data: &[u8]| {
    let _ = decode_message(data, "pkg.Request", registry(), &limits());
});
