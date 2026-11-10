#![no_main]

use std::net::{IpAddr, Ipv4Addr};
use std::sync::OnceLock;

use bytes::Bytes;
use http::{HeaderMap, Method, Uri};
use libfuzzer_sys::fuzz_target;
use waf_ingress::waf::content_inspection::{ContentInspectionRule, ContentInspectionRuleFactory};
use waf_ingress::waf::{RequestContext, WafRule};

const CLIENT_IP: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

fn inspection_rule() -> &'static ContentInspectionRule {
    static RULE: OnceLock<ContentInspectionRule> = OnceLock::new();
    RULE.get_or_init(ContentInspectionRuleFactory::all_attacks_rule)
}

fn is_hex(byte: u8) -> bool {
    byte.is_ascii_hexdigit()
}

/// Encode arbitrary bytes so they form a valid URI query while preserving
/// characters that the inspection rules care about (quotes, plus, percent
/// escapes). Invalid percent escapes are encoded as `%25`.
fn encode_query(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 3);
    let mut index = 0;
    while index < data.len() {
        let byte = data[index];
        let safe = matches!(
            byte,
            b'A'..=b'Z'
                | b'a'..=b'z'
                | b'0'..=b'9'
                | b'-'
                | b'.'
                | b'_'
                | b'~'
                | b'!'
                | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
                | b':'
                | b'@'
                | b'/'
                | b'?'
        );

        if safe {
            out.push(byte as char);
        } else if byte == b'%'
            && index + 2 < data.len()
            && is_hex(data[index + 1])
            && is_hex(data[index + 2])
        {
            out.push('%');
        } else {
            const HEX: &[u8; 16] = b"0123456789ABCDEF";
            out.push('%');
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
        index += 1;
    }
    out
}

fn query_uri(data: &[u8]) -> Uri {
    let candidate = format!("/fuzz?{}", encode_query(data));
    candidate
        .parse()
        .unwrap_or_else(|_| Uri::from_static("/fuzz"))
}

fuzz_target!(|data: &[u8]| {
    let rule = inspection_rule();

    // Query-string inspection, including percent-decoding of encoded payloads.
    let query_ctx = RequestContext::new(
        CLIENT_IP,
        Method::GET,
        query_uri(data),
        HeaderMap::new(),
        None,
    );
    let _ = rule.evaluate(&query_ctx);

    // Body inspection, including the lossy UTF-8 and percent-decoding paths.
    let body_ctx = RequestContext::new(
        CLIENT_IP,
        Method::POST,
        Uri::from_static("/fuzz"),
        HeaderMap::new(),
        Some(data.len()),
    )
    .with_body(Some(Bytes::copy_from_slice(data)));
    let _ = rule.evaluate(&body_ctx);
});
