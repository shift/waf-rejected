//! Borrowed request view shared by the proxy and the WAF encoders.
//!
//! The proxy already owns the parsed hyper request head and the buffered body.
//! Building an owned [`crate::waf::RequestContext`] for every evaluation used
//! to clone the method, URI and header map. [`RequestView`] borrows those
//! fields instead, so the binary Coraza encoder can write the wire frame
//! directly from the request without an intermediate owned copy or a JSON
//! re-serialisation.

use hyper::{HeaderMap, Method, Uri};

use crate::waf::RequestContext;

/// A borrowed view of the request fields the WAF needs.
#[derive(Debug, Clone, Copy)]
pub struct RequestView<'a> {
    /// Client address used by policy rules.
    pub client_ip: std::net::IpAddr,
    /// Request method.
    pub method: &'a Method,
    /// Request URI.
    pub uri: &'a Uri,
    /// Request headers.
    pub headers: &'a HeaderMap,
    /// Buffered request body, if any.
    pub body: Option<&'a [u8]>,
    /// Refcounted body backing store, when the caller has one. Keeping this
    /// lets the binary encoder slice the body without copying it.
    pub body_bytes: Option<&'a bytes::Bytes>,
    /// Full body length before any inspection truncation.
    pub body_size: Option<usize>,
    /// HTTP version string (`"1.1"`, `"2"`, ...).
    pub http_version: &'a str,
}

impl<'a> RequestView<'a> {
    /// Builds a view over an owned request context.
    pub fn from_context(ctx: &'a RequestContext) -> Self {
        Self {
            client_ip: ctx.client_ip,
            method: &ctx.method,
            uri: &ctx.uri,
            headers: &ctx.headers,
            body: ctx.body.as_deref(),
            body_bytes: ctx.body.as_ref(),
            body_size: ctx.body_size,
            http_version: &ctx.http_version,
        }
    }
}

impl RequestContext {
    /// Borrows this context as a [`RequestView`].
    pub fn view(&self) -> RequestView<'_> {
        RequestView::from_context(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use std::net::IpAddr;

    #[test]
    fn view_borrows_context_fields() {
        let mut headers = HeaderMap::new();
        headers.insert("host", "example.test".parse().unwrap());
        let ctx = RequestContext::new(
            "127.0.0.1".parse::<IpAddr>().unwrap(),
            Method::POST,
            "/submit?q=1".parse::<Uri>().unwrap(),
            headers,
            Some(3),
        )
        .with_body(Some(Bytes::from_static(b"a=1")));

        let view = ctx.view();
        assert_eq!(view.method, &Method::POST);
        assert_eq!(view.uri.path(), "/submit");
        assert_eq!(view.headers.get("host").unwrap(), "example.test");
        assert_eq!(view.body, Some(&b"a=1"[..]));
        assert_eq!(view.body_bytes.map(Bytes::as_ref), Some(&b"a=1"[..]));
        assert_eq!(view.body_size, Some(3));
        assert_eq!(view.http_version, "1.1");
    }
}
