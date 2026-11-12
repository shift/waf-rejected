#![no_main]

use std::net::{IpAddr, Ipv4Addr};
use std::sync::OnceLock;

use bytes::Bytes;
use http::{HeaderMap, Method, Uri};
use libfuzzer_sys::fuzz_target;
use tokio::runtime::Runtime;
use waf_ingress::waf::content_inspection::ContentInspectionRuleFactory;
use waf_ingress::waf::{RequestContext, WafEngine};

const CLIENT_IP: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// `WebSocketHandler::inspect_websocket_message` is private, so the harness
/// reproduces the request context it builds and evaluates it through the same
/// `WafEngine::fast_evaluate` path. The frame payload is also attached as the
/// request body because the production helper currently passes only the body
/// length; this exercises content inspection as defence in depth.
fn engine() -> &'static WafEngine {
    static ENGINE: OnceLock<WafEngine> = OnceLock::new();
    ENGINE.get_or_init(|| {
        let mut engine = WafEngine::new();
        engine.add_rule(ContentInspectionRuleFactory::all_attacks_rule());
        engine
    })
}

fn runtime() -> &'static Runtime {
    static RUNTIME: OnceLock<Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("failed to build tokio runtime")
    })
}

fn inspect(
    engine: &WafEngine,
    uri: Uri,
    content_type: &'static str,
    kind: &'static str,
    payload: &[u8],
) {
    let mut headers = HeaderMap::with_capacity(2);
    headers.insert(
        "content-type",
        content_type.parse().expect("static header value"),
    );
    headers.insert(
        "x-websocket-message-type",
        kind.parse().expect("static header value"),
    );

    // Exact shape used by the WebSocket handler: body length only.
    let frame_ctx = RequestContext::new(
        CLIENT_IP,
        Method::POST,
        uri.clone(),
        headers.clone(),
        Some(payload.len()),
    );
    let _ = runtime().block_on(engine.fast_evaluate(&frame_ctx));

    // Defence in depth: inspect the payload bytes as a request body.
    let body_ctx = RequestContext::new(CLIENT_IP, Method::POST, uri, headers, Some(payload.len()))
        .with_body(Some(Bytes::copy_from_slice(payload)));
    let _ = runtime().block_on(engine.fast_evaluate(&body_ctx));
}

fuzz_target!(|data: &[u8]| {
    let engine = engine();

    match std::str::from_utf8(data) {
        Ok(text) => inspect(
            engine,
            Uri::from_static("/websocket/message"),
            "text/plain",
            "text",
            text.as_bytes(),
        ),
        Err(_) => inspect(
            engine,
            Uri::from_static("/websocket/binary"),
            "application/octet-stream",
            "binary",
            data,
        ),
    }
});
