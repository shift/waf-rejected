//! Property-based security regression tests.
//!
//! These tests exercise attacker-controlled input paths that are easy to get
//! wrong (UTF-8 truncation, oversized URIs, WebSocket frames and header
//! parsing) without opening sockets or depending on external services.

use std::net::IpAddr;
use std::str::FromStr;

use bytes::Bytes;
use hyper::{HeaderMap, Method, Uri};
use proptest::prelude::*;

use waf_ingress::waf::content_inspection::{ContentInspectionRule, ContentInspectionRuleFactory};
use waf_ingress::waf::rules::RequestSizeRule;
use waf_ingress::waf::WafRule;
use waf_ingress::{Decision, RequestContext, WafEngine};

const CASES: u32 = 128;

/// Maximum size accepted for a single WebSocket frame in these tests.
const WS_MAX_BODY_SIZE: usize = 1024;

fn proptest_config() -> ProptestConfig {
    ProptestConfig::with_cases(CASES)
}

/// Arbitrary UTF-8 text, bounded so each case stays fast.
fn utf8_text(max_chars: usize) -> impl Strategy<Value = String> {
    proptest::collection::vec(any::<char>(), 0..=max_chars)
        .prop_map(|chars| chars.into_iter().collect())
}

/// Arbitrary bytes, bounded to keep regex work reasonable.
fn arbitrary_bytes(max_len: usize) -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(any::<u8>(), 0..=max_len)
}

/// Replace bytes that are not legal in a URI path/query. Non-ASCII characters
/// are kept so multibyte UTF-8 reaches the rules unchanged.
fn sanitize_uri_component(input: &str) -> String {
    input
        .chars()
        .map(|ch| {
            let valid_ascii = ch.is_ascii_alphanumeric() || "-._~!$&'()*+,;=:@/%".contains(ch);
            if ch.is_ascii() && !valid_ascii {
                'a'
            } else {
                ch
            }
        })
        .collect()
}

fn build_uri(path_input: &str, query_input: &str) -> Uri {
    let path = sanitize_uri_component(path_input);
    let query = sanitize_uri_component(query_input);

    let mut uri = String::with_capacity(path.len() + query.len() + 2);
    uri.push('/');
    uri.push_str(&path);
    if !query.is_empty() {
        uri.push('?');
        uri.push_str(&query);
    }

    Uri::from_str(&uri).expect("sanitized URI must always parse")
}

fn request_context(uri: Uri, body: Option<Bytes>) -> RequestContext {
    let body_size = body.as_ref().map(Bytes::len);
    RequestContext::new(
        IpAddr::from([192, 0, 2, 10]),
        Method::POST,
        uri,
        HeaderMap::new(),
        body_size,
    )
    .with_body(body)
}

fn websocket_engine() -> WafEngine {
    let mut engine = WafEngine::new();
    engine.add_rule(RequestSizeRule::new(
        "websocket_frame_size",
        WS_MAX_BODY_SIZE,
    ));
    engine.add_rule(ContentInspectionRuleFactory::all_attacks_rule());
    engine
}

fn websocket_context(payload: &[u8]) -> RequestContext {
    let mut headers = HeaderMap::new();
    headers.insert("content-type", "application/octet-stream".parse().unwrap());
    headers.insert("x-websocket-message-type", "binary".parse().unwrap());

    RequestContext::new(
        IpAddr::from([127, 0, 0, 1]),
        Method::POST,
        Uri::from_static("/websocket/binary"),
        headers,
        Some(payload.len()),
    )
    .with_body(Some(Bytes::copy_from_slice(payload)))
}

fn assert_blocked_with_414(decision: &Decision, context: &str) {
    match decision {
        Decision::Block { status: 414, .. } => {}
        other => panic!("expected 414 block for {context}, got {other:?}"),
    }
}

proptest! {
    #![proptest_config(proptest_config())]

    /// Arbitrary UTF-8 in path, query and body must never panic the rule.
    #[test]
    fn content_inspection_never_panics_on_arbitrary_utf8(
        path in utf8_text(256),
        query in utf8_text(256),
        body in utf8_text(2048),
    ) {
        let rule = ContentInspectionRuleFactory::all_attacks_rule();
        let ctx = request_context(build_uri(&path, &query), Some(Bytes::from(body)));
        let _ = rule.evaluate(&ctx);
    }

    /// Arbitrary bytes (including invalid UTF-8) must never panic body inspection.
    #[test]
    fn content_inspection_never_panics_on_arbitrary_bytes(
        path in utf8_text(128),
        query in utf8_text(128),
        body in arbitrary_bytes(4096),
    ) {
        let rule = ContentInspectionRule::new("arbitrary bytes");
        let ctx = request_context(build_uri(&path, &query), Some(Bytes::from(body)));
        let _ = rule.evaluate(&ctx);
    }

    /// A regex match longer than the 100-character truncation limit must be cut
    /// on a UTF-8 boundary for both body and percent-decoded query/path input.
    #[test]
    fn multibyte_matches_are_truncated_on_a_char_boundary(
        filler_len in 90usize..=140,
        filler in prop::sample::select(vec!['é', 'ß', '世', '漢', '😀']),
        suffix in "[a-zA-Z0-9]{0,16}",
    ) {
        let filler: String = std::iter::repeat_n(filler, filler_len).collect();
        let payload = format!("<script{filler}>{suffix}");

        let rule = ContentInspectionRuleFactory::xss_rule();
        let body_ctx = request_context(
            Uri::from_static("/inspect"),
            Some(Bytes::from(payload.clone())),
        );
        let body_decision = rule.evaluate(&body_ctx);
        let body_blocked = matches!(body_decision, Decision::Block { .. });
        prop_assert!(body_blocked, "body payload was not blocked");

        // Percent-encoded angle brackets plus raw multibyte text: the decoded
        // form is what gets truncated by the rule.
        let encoded_query = format!("%3Cscript{filler}%3E{suffix}");
        let query_ctx = request_context(
            build_uri("", &encoded_query),
            None,
        );
        let query_decision = rule.evaluate(&query_ctx);
        let query_blocked = matches!(query_decision, Decision::Block { .. });
        prop_assert!(query_blocked, "query payload was not blocked");
    }

    /// Padding a URI path beyond the inspection limit must always be rejected
    /// with 414, regardless of length or filler character.
    #[test]
    fn overlong_uri_path_always_blocks_414(
        path_chars in 8193usize..=20_000,
        filler in prop::sample::select(vec!['a', 'é', '世']),
    ) {
        let path: String = std::iter::repeat_n(filler, path_chars).collect();
        // Keep an attack payload after the padding so a length check that only
        // inspects the prefix cannot silently allow it.
        let uri =
            Uri::from_str(&format!("/{path}UNION+SELECT+1")).expect("path must be a valid URI");

        let rule = ContentInspectionRuleFactory::all_attacks_rule();
        let decision = rule.evaluate(&request_context(uri, None));
        assert_blocked_with_414(&decision, "overlong URI path");
    }

    /// Padding a query string beyond the inspection limit must always be
    /// rejected with 414, regardless of length or filler character.
    #[test]
    fn overlong_query_always_blocks_414(
        query_chars in 8193usize..=20_000,
        filler in prop::sample::select(vec!['a', 'é', '世']),
    ) {
        let query: String = std::iter::repeat_n(filler, query_chars).collect();
        // Keep an attack payload after the padding so a length check that only
        // inspects the prefix cannot silently allow it.
        let uri = Uri::from_str(&format!("/?q={query}+UNION+SELECT+1"))
            .expect("query must be a valid URI");

        let rule = ContentInspectionRuleFactory::all_attacks_rule();
        let decision = rule.evaluate(&request_context(uri, None));
        assert_blocked_with_414(&decision, "overlong query string");
    }

    /// Arbitrary WebSocket text/binary payloads must not panic WAF evaluation.
    #[test]
    fn websocket_frame_payload_never_panics(
        payload in prop_oneof![
            utf8_text(2048).prop_map(String::into_bytes),
            arbitrary_bytes(4096),
        ],
    ) {
        let engine = websocket_engine();
        let ctx = websocket_context(&payload);
        let _ = futures::executor::block_on(engine.evaluate(&ctx));
    }

    /// Any frame larger than the configured body limit must be blocked.
    #[test]
    fn websocket_frame_over_max_body_size_blocks(
        payload in arbitrary_bytes(WS_MAX_BODY_SIZE + 4096),
    ) {
        prop_assume!(payload.len() > WS_MAX_BODY_SIZE);

        let engine = websocket_engine();
        let ctx = websocket_context(&payload);
        let decision = futures::executor::block_on(engine.evaluate(&ctx));

        match decision {
            Decision::Block { status: 413, .. } => {}
            other => prop_assert!(
                false,
                "expected 413 block for {} byte frame, got {:?}",
                payload.len(),
                other
            ),
        }
    }

    /// Every factory-produced rule must tolerate arbitrary path/query/body input.
    #[test]
    fn factory_rules_never_panic_on_arbitrary_input(
        path in utf8_text(256),
        query in utf8_text(256),
        body in arbitrary_bytes(4096),
        header_value in any::<String>(),
    ) {
        let mut headers = HeaderMap::new();
        if let Ok(value) = header_value.parse() {
            headers.insert("x-proptest", value);
        }

        let ctx = RequestContext::new(
            IpAddr::from([198, 51, 100, 7]),
            Method::POST,
            build_uri(&path, &query),
            headers,
            Some(body.len()),
        )
        .with_body(Some(Bytes::from(body)));

        let rules = [
            ContentInspectionRuleFactory::sql_injection_rule(),
            ContentInspectionRuleFactory::xss_rule(),
            ContentInspectionRuleFactory::command_injection_rule(),
            ContentInspectionRuleFactory::path_traversal_rule(),
            ContentInspectionRuleFactory::all_attacks_rule(),
            ContentInspectionRuleFactory::create_threat_rule("unknown"),
        ];

        for rule in &rules {
            let _ = rule.evaluate(&ctx);
        }
    }
}
