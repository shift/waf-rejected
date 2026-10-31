use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

use bytes::Bytes;
use hyper::{HeaderMap, Method, Uri};

use waf_ingress::waf::content_inspection::ContentInspectionRuleFactory;
use waf_ingress::waf::geoip::{GeoBlockingRuleFactory, GeoIpService};
use waf_ingress::waf::{Decision, RequestContext, WafEngine, WafRule};
use waf_ingress::Config;

fn request(uri: &str, body: Option<&str>) -> RequestContext {
    let mut ctx = RequestContext::new(
        IpAddr::from_str("203.0.113.10").unwrap(),
        Method::POST,
        Uri::from_str(uri).unwrap(),
        HeaderMap::new(),
        body.map(str::len),
    );
    if let Some(body) = body {
        ctx = ctx.with_body(Some(Bytes::copy_from_slice(body.as_bytes())));
    }
    ctx
}

async fn assert_blocked(engine: &WafEngine, ctx: &RequestContext, label: &str) {
    match engine.evaluate(ctx).await {
        Decision::Block { .. } | Decision::RateLimit { .. } => {}
        Decision::Allow => panic!("{} was unexpectedly allowed", label),
    }
}

#[tokio::test]
async fn test_comprehensive_waf_protection() {
    let config = Config::default();
    let engine = WafEngine::with_config(&config);

    assert_blocked(
        &engine,
        &request(
            "http://example.com/?id=1%20UNION%20SELECT%20*%20FROM%20users",
            None,
        ),
        "sql injection query",
    )
    .await;
    assert_blocked(
        &engine,
        &request(
            "http://example.com/?q=%3Cscript%3Ealert(1)%3C/script%3E",
            None,
        ),
        "xss query",
    )
    .await;
    assert_blocked(
        &engine,
        &request(
            "http://example.com/login",
            Some("id=1 UNION SELECT * FROM users"),
        ),
        "sql injection body",
    )
    .await;
    assert_blocked(
        &engine,
        &request(
            "http://example.com/login",
            Some("<script>alert(1)</script>"),
        ),
        "xss body",
    )
    .await;
    assert_blocked(
        &engine,
        &request("http://example.com/exec?cmd=test;cat+/etc/passwd", None),
        "command injection",
    )
    .await;
    assert_blocked(
        &engine,
        &request("http://example.com/file?path=../../../etc/passwd", None),
        "path traversal",
    )
    .await;

    let clean = request("http://example.com/health?id=42", None);
    assert_eq!(engine.evaluate(&clean).await, Decision::Allow);
}

#[tokio::test]
async fn test_security_event_logging() {
    use waf_ingress::waf::security_events::SecurityEventLogger;

    let logger = SecurityEventLogger::new(Default::default());
    let ctx = request("http://example.com/?id=1%20UNION%20SELECT%201", None);
    logger
        .log_event(
            &ctx,
            &Decision::Block {
                status: 403,
                reason: "test".to_string(),
            },
            vec!["sql_injection".to_string()],
        )
        .await;
}

#[test]
fn test_geo_blocking() {
    let geoip_service = Arc::new(GeoIpService::new());
    let rule = GeoBlockingRuleFactory::create_country_rule("US", Arc::clone(&geoip_service));

    let ctx = RequestContext::new(
        "8.8.8.8".parse().unwrap(),
        Method::GET,
        Uri::from_str("http://example.com/").unwrap(),
        HeaderMap::new(),
        None,
    );
    assert!(matches!(rule.evaluate(&ctx), Decision::Block { .. }));
}

#[test]
fn test_content_inspection_factory() {
    let rule = ContentInspectionRuleFactory::create_threat_rule("sql_injection");
    let ctx = request("http://example.com/?id=1%20UNION%20SELECT%201", None);
    assert!(matches!(rule.evaluate(&ctx), Decision::Block { .. }));
}
