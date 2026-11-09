#![no_main]

use std::net::{IpAddr, Ipv4Addr};

use bytes::Bytes;
use hyper::{HeaderMap, Method, Uri};
use libfuzzer_sys::fuzz_target;
use waf_ingress::config::WafGraphqlConfig;
use waf_ingress::waf::graphql::GraphqlInspector;
use waf_ingress::waf::RequestContext;

fuzz_target!(|data: &[u8]| {
    let inspector = GraphqlInspector::from_config(&WafGraphqlConfig::default());
    let mut headers = HeaderMap::new();
    headers.insert(
        hyper::header::CONTENT_TYPE,
        hyper::header::HeaderValue::from_static("application/json"),
    );
    let ctx = RequestContext::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        Method::POST,
        Uri::from_static("/graphql"),
        headers,
        Some(data.len()),
    )
    .with_body(Some(Bytes::copy_from_slice(data)));
    let _ = inspector.inspect(&ctx);
});
