//! Shared request state and the per-request arena.
//!
//! The request is parsed **once** into compact spans. Every span is a
//! zero-copy view into the caller's method/path/query/header/body buffers.
//! Transform pipelines are cached per (value, pipeline) in the arena, so two
//! rules that need the same decoded value pay for the decode once.

use memchr::memchr;

/// A parsed request. The caller owns the bytes; the kernel only borrows them.
#[derive(Debug, Clone, Copy)]
pub struct RequestInput<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub query: &'a str,
    pub headers: &'a [(&'a str, &'a str)],
    pub body: &'a [u8],
    /// Raw `Cookie` header, if present. Derived by [`RequestInput::new`].
    pub cookie_header: Option<&'a str>,
}

impl<'a> RequestInput<'a> {
    /// Builds a request view and locates the `Cookie` header once.
    pub fn new(
        method: &'a str,
        path: &'a str,
        query: &'a str,
        headers: &'a [(&'a str, &'a str)],
        body: &'a [u8],
    ) -> Self {
        let cookie_header = headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("cookie"))
            .map(|(_, value)| *value);
        Self {
            method,
            path,
            query,
            headers,
            body,
            cookie_header,
        }
    }
}

/// A value kind, used by the compiled target masks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueKind {
    Method,
    Path,
    PathDecoded,
    Query,
    Body,
    ArgName,
    ArgValue,
    HeaderName,
    HeaderValue,
    CookieName,
    CookieValue,
}

/// Distinguishes the handful of headers that CRS rules target directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderKind {
    Other,
    UserAgent,
    Referer,
    ContentType,
    Cookie,
}

/// Where a span's bytes live.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Method,
    Path,
    Query,
    Body,
    Header(u16),
    CookieHeader,
    /// A parser-decoded argument/cookie/JSON token. ModSecurity decodes these
    /// before rule transforms run, so the kernel must too.
    Decoded,
}

/// A zero-copy byte range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    pub source: Source,
    pub start: u32,
    pub len: u32,
}

impl Span {
    fn new(source: Source, start: usize, len: usize) -> Self {
        Self {
            source,
            start: start as u32,
            len: len as u32,
        }
    }
}

/// One parsed value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValueRef {
    pub span: Span,
    pub kind: ValueKind,
    pub header: HeaderKind,
}

/// A compact target mask. This is the "which values does this rule read?"
/// edge of the matcher DAG.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TargetMask(pub u16);

impl TargetMask {
    pub const METHOD: Self = Self(1 << 0);
    pub const PATH: Self = Self(1 << 1);
    pub const QUERY: Self = Self(1 << 2);
    pub const BODY: Self = Self(1 << 3);
    pub const ARG_NAME: Self = Self(1 << 4);
    pub const ARG_VALUE: Self = Self(1 << 5);
    pub const HEADER_NAME: Self = Self(1 << 6);
    pub const HEADER_VALUE: Self = Self(1 << 7);
    pub const USER_AGENT: Self = Self(1 << 8);
    pub const REFERER: Self = Self(1 << 9);
    pub const COOKIE_NAME: Self = Self(1 << 10);
    pub const COOKIE_VALUE: Self = Self(1 << 11);
    pub const CONTENT_TYPE: Self = Self(1 << 12);
    /// `REQUEST_FILENAME`: the URL-decoded path.
    pub const FILENAME: Self = Self(1 << 13);

    /// Union used by rules that target several variables.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// True when this value is in the mask.
    pub fn matches(self, value: ValueRef) -> bool {
        let bit = match value.kind {
            ValueKind::Method => Self::METHOD,
            ValueKind::Path => Self::PATH,
            ValueKind::PathDecoded => Self::FILENAME,
            ValueKind::Query => Self::QUERY,
            ValueKind::Body => Self::BODY,
            ValueKind::ArgName => Self::ARG_NAME,
            ValueKind::ArgValue => Self::ARG_VALUE,
            ValueKind::HeaderName => Self::HEADER_NAME,
            ValueKind::HeaderValue => {
                // `REQUEST_HEADERS` includes every header; the specific masks
                // select one header.
                if self.0 & Self::HEADER_VALUE.0 != 0 {
                    return true;
                }
                match value.header {
                    HeaderKind::UserAgent => Self::USER_AGENT,
                    HeaderKind::Referer => Self::REFERER,
                    HeaderKind::ContentType => Self::CONTENT_TYPE,
                    HeaderKind::Other | HeaderKind::Cookie => return false,
                }
            }
            ValueKind::CookieName => Self::COOKIE_NAME,
            ValueKind::CookieValue => Self::COOKIE_VALUE,
        };
        self.0 & bit.0 != 0
    }

    /// The common CRS `ARGS` target: query and body argument values.
    pub const fn args() -> Self {
        Self(Self::ARG_VALUE.0 | Self::QUERY.0)
    }

    /// `REQUEST_URI_RAW`: path plus query string.
    pub const fn uri() -> Self {
        Self(Self::PATH.0 | Self::QUERY.0)
    }

    /// Everything that request-phase content rules normally inspect.
    pub const fn all_request() -> Self {
        Self(
            Self::METHOD.0
                | Self::PATH.0
                | Self::QUERY.0
                | Self::BODY.0
                | Self::ARG_NAME.0
                | Self::ARG_VALUE.0
                | Self::HEADER_NAME.0
                | Self::HEADER_VALUE.0
                | Self::USER_AGENT.0
                | Self::REFERER.0
                | Self::COOKIE_NAME.0
                | Self::COOKIE_VALUE.0
                | Self::CONTENT_TYPE.0
                | Self::FILENAME.0,
        )
    }
}

/// One cached transform-pipeline result.
#[derive(Debug, Clone, Copy, Default)]
struct CacheEntry {
    generation: u32,
    start: u32,
    len: u32,
}

/// Per-request scratch space. Reuse one arena per worker thread; after the
/// first request the hot path performs no allocation.
#[derive(Debug, Default)]
pub struct Arena {
    values: Vec<ValueRef>,
    cache: Vec<CacheEntry>,
    buf: Vec<u8>,
    decoded: Vec<u8>,
    scratch: [Vec<u8>; 2],
    staging: Vec<u8>,
    generation: u32,
    pipeline_count: usize,
    gate_hits: u64,
}

impl Arena {
    pub fn new() -> Self {
        Self {
            generation: 1,
            ..Self::default()
        }
    }

    /// Starts a new request. Keeps all buffers.
    pub fn begin(&mut self, pipeline_count: usize) {
        self.values.clear();
        self.buf.clear();
        self.decoded.clear();
        self.pipeline_count = pipeline_count;
        self.gate_hits = 0;
        self.generation = self.generation.wrapping_add(1);
        if self.generation == 0 {
            for entry in &mut self.cache {
                entry.generation = 0;
            }
            self.generation = 1;
        }
    }

    /// Parses the request into spans. Must be called after [`Arena::begin`].
    pub fn parse(&mut self, request: &RequestInput<'_>) {
        self.push(
            Source::Method,
            0,
            request.method.len(),
            ValueKind::Method,
            HeaderKind::Other,
        );
        self.push(
            Source::Path,
            0,
            request.path.len(),
            ValueKind::Path,
            HeaderKind::Other,
        );
        self.push_decoded(
            request.path.as_bytes(),
            ValueKind::PathDecoded,
            HeaderKind::Other,
            crate::waf::engine_kernel::transform::Transform::UrlDecodeUni,
        );
        if !request.query.is_empty() {
            self.push(
                Source::Query,
                0,
                request.query.len(),
                ValueKind::Query,
                HeaderKind::Other,
            );
            self.parse_pairs(request.query.as_bytes());
        }
        let content_type = request
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
            .map(|(_, value)| *value)
            .unwrap_or("");
        // Coraza's XML processor does not expose the raw document as
        // REQUEST_BODY. Keeping it out avoids false positives on XML-only
        // rules whose corpus expectations are "allow".
        let is_xml = ["text/xml", "application/xml", "application/soap+xml"]
            .iter()
            .any(|mime| {
                content_type
                    .as_bytes()
                    .windows(mime.len())
                    .any(|window| window.eq_ignore_ascii_case(mime.as_bytes()))
            });
        if !request.body.is_empty() && !is_xml {
            self.push(
                Source::Body,
                0,
                request.body.len(),
                ValueKind::Body,
                HeaderKind::Other,
            );
        }

        if !request.body.is_empty() {
            if is_xml {
                self.parse_xml_values(request.body);
            } else if content_type
                .as_bytes()
                .windows(33)
                .any(|window| window.eq_ignore_ascii_case(b"application/x-www-form-urlencoded"))
            {
                self.parse_pairs(request.body);
            } else if content_type
                .as_bytes()
                .windows(16)
                .any(|window| window.eq_ignore_ascii_case(b"application/json"))
                || content_type
                    .as_bytes()
                    .windows(5)
                    .any(|window| window.eq_ignore_ascii_case(b"+json"))
            {
                self.parse_json_strings(request.body);
            }
        }

        for (index, (name, value)) in request.headers.iter().enumerate() {
            let header = header_kind(name);
            let index = index as u16;
            self.push(
                Source::Header(index),
                0,
                name.len(),
                ValueKind::HeaderName,
                header,
            );
            self.push(
                Source::Header(index),
                0,
                value.len(),
                ValueKind::HeaderValue,
                header,
            );
            if header == HeaderKind::Cookie {
                self.parse_cookie_pairs(value.as_bytes());
            }
        }

        self.ensure_cache();
    }

    fn push(
        &mut self,
        source: Source,
        start: usize,
        len: usize,
        kind: ValueKind,
        header: HeaderKind,
    ) {
        self.values.push(ValueRef {
            span: Span::new(source, start, len),
            kind,
            header,
        });
    }

    fn ensure_cache(&mut self) {
        let needed = self.values.len().saturating_mul(self.pipeline_count);
        if self.cache.len() < needed {
            self.cache.resize(
                needed,
                CacheEntry {
                    generation: 0,
                    start: 0,
                    len: 0,
                },
            );
        }
    }

    /// Number of parsed values.
    pub fn len(&self) -> usize {
        self.values.len()
    }

    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Iterates the parsed values.
    pub fn values(&self) -> impl Iterator<Item = ValueRef> + '_ {
        self.values.iter().copied()
    }

    /// Returns one parsed value by index.
    pub fn value_at(&self, index: usize) -> ValueRef {
        self.values[index]
    }

    /// Resolves one value's bytes.
    pub fn value<'a>(&'a self, request: &'a RequestInput<'a>, value: ValueRef) -> &'a [u8] {
        resolve(request, &self.decoded, value)
    }

    /// Returns the cached pipeline result for one value, computing it once.
    ///
    /// Pipeline 0 is the identity and returns the raw span directly.
    pub fn transformed<'a>(
        &'a mut self,
        request: &'a RequestInput<'a>,
        value_index: usize,
        pipeline_index: usize,
        pipeline: &[crate::waf::engine_kernel::transform::Transform],
    ) -> &'a [u8] {
        let value = self.values[value_index];
        if pipeline_index == 0 || pipeline.is_empty() {
            return resolve(request, &self.decoded, value);
        }
        let cache_index = value_index * self.pipeline_count + pipeline_index;
        let entry = self.cache[cache_index];
        if entry.generation == self.generation {
            let start = entry.start as usize;
            let end = start + entry.len as usize;
            return &self.buf[start..end];
        }
        let raw = resolve(request, &self.decoded, value);
        crate::waf::engine_kernel::transform::apply_pipeline(
            raw,
            pipeline,
            &mut self.scratch,
            &mut self.staging,
        );
        let start = self.buf.len();
        self.buf.extend_from_slice(&self.staging);
        let len = self.buf.len() - start;
        self.cache[cache_index] = CacheEntry {
            generation: self.generation,
            start: start as u32,
            len: len as u32,
        };
        &self.buf[start..start + len]
    }

    fn push_decoded(
        &mut self,
        input: &[u8],
        kind: ValueKind,
        header: HeaderKind,
        transform: crate::waf::engine_kernel::transform::Transform,
    ) {
        transform.apply_into(input, &mut self.staging);
        let start = self.decoded.len();
        self.decoded.extend_from_slice(&self.staging);
        let len = self.decoded.len() - start;
        self.values.push(ValueRef {
            span: Span::new(Source::Decoded, start, len),
            kind,
            header,
        });
    }

    fn parse_pairs(&mut self, input: &[u8]) {
        use crate::waf::engine_kernel::transform::Transform;
        let mut start = 0usize;
        while start <= input.len() {
            let end = memchr(b'&', &input[start..])
                .map(|offset| start + offset)
                .unwrap_or(input.len());
            let pair = &input[start..end];
            if !pair.is_empty() {
                let equals = memchr(b'=', pair).unwrap_or(pair.len());
                self.push_decoded(
                    &pair[..equals],
                    ValueKind::ArgName,
                    HeaderKind::Other,
                    Transform::UrlDecodeUni,
                );
                if equals < pair.len() {
                    self.push_decoded(
                        &pair[equals + 1..],
                        ValueKind::ArgValue,
                        HeaderKind::Other,
                        Transform::UrlDecodeUni,
                    );
                }
            }
            if end == input.len() {
                break;
            }
            start = end + 1;
        }
    }

    fn parse_cookie_pairs(&mut self, input: &[u8]) {
        use crate::waf::engine_kernel::transform::Transform;
        let mut start = 0usize;
        while start <= input.len() {
            let end = memchr(b';', &input[start..])
                .map(|offset| start + offset)
                .unwrap_or(input.len());
            let mut pair = &input[start..end];
            while let [b' ', rest @ ..] = pair {
                pair = rest;
            }
            if !pair.is_empty() {
                let equals = memchr(b'=', pair).unwrap_or(pair.len());
                self.push_decoded(
                    &pair[..equals],
                    ValueKind::CookieName,
                    HeaderKind::Cookie,
                    Transform::UrlDecodeUni,
                );
                if equals < pair.len() {
                    self.push_decoded(
                        &pair[equals + 1..],
                        ValueKind::CookieValue,
                        HeaderKind::Cookie,
                        Transform::UrlDecodeUni,
                    );
                }
            }
            if end == input.len() {
                break;
            }
            start = end + 1;
        }
    }

    /// Extracts XML attribute values and text nodes. Element names are
    /// deliberately excluded: Coraza's `XML:/*` does not expose them, and the
    /// corpus has negative cases whose payload is only an element name.
    fn parse_xml_values(&mut self, input: &[u8]) {
        use crate::waf::engine_kernel::transform::Transform;
        let mut index = 0usize;
        while index < input.len() {
            match input[index] {
                b'=' => {
                    let mut quote_at = index + 1;
                    while quote_at < input.len() && input[quote_at].is_ascii_whitespace() {
                        quote_at += 1;
                    }
                    let Some(&quote) = input.get(quote_at) else {
                        break;
                    };
                    if quote != b'"' && quote != b'\'' {
                        index += 1;
                        continue;
                    }
                    let start = quote_at + 1;
                    let mut end = start;
                    while end < input.len() && input[end] != quote {
                        end += 1;
                    }
                    if end > start {
                        self.push_decoded(
                            &input[start..end],
                            ValueKind::ArgValue,
                            HeaderKind::Other,
                            Transform::HtmlEntityDecode,
                        );
                    }
                    index = end.saturating_add(1);
                }
                b'>' => {
                    let start = index + 1;
                    let mut end = start;
                    while end < input.len() && input[end] != b'<' {
                        end += 1;
                    }
                    let text = trim_ascii(&input[start..end]);
                    if !text.is_empty() {
                        self.push_decoded(
                            text,
                            ValueKind::ArgValue,
                            HeaderKind::Other,
                            Transform::HtmlEntityDecode,
                        );
                    }
                    index = end;
                }
                _ => index += 1,
            }
        }
    }

    /// Extracts JSON string tokens as argument values/names. This is a token
    /// scanner, not a JSON parser: it never allocates beyond the arena and it
    /// treats every string as a candidate argument.
    fn parse_json_strings(&mut self, input: &[u8]) {
        use crate::waf::engine_kernel::transform::Transform;
        let mut index = 0usize;
        while index < input.len() {
            if input[index] != b'"' {
                index += 1;
                continue;
            }
            let start = index + 1;
            index = start;
            let mut escaped = false;
            while index < input.len() {
                match input[index] {
                    b'\\' if !escaped => {
                        escaped = true;
                        index += 1;
                    }
                    b'"' if !escaped => break,
                    _ => {
                        escaped = false;
                        index += 1;
                    }
                }
            }
            if index > start {
                let mut lookahead = index + 1;
                while lookahead < input.len() && input[lookahead].is_ascii_whitespace() {
                    lookahead += 1;
                }
                let kind = if input.get(lookahead) == Some(&b':') {
                    ValueKind::ArgName
                } else {
                    ValueKind::ArgValue
                };
                self.push_decoded(
                    &input[start..index],
                    kind,
                    HeaderKind::Other,
                    Transform::JsDecode,
                );
            }
            index += 1;
        }
    }

    /// Records prefilter gate hits.
    pub fn add_gates(&mut self, gates: u64) {
        self.gate_hits |= gates;
    }

    /// True when the prefilter proved the rule's literals are present.
    pub fn gate_hit(&self, gate: usize) -> bool {
        gate < 64 && self.gate_hits & (1u64 << gate) != 0
    }
}

fn header_kind(name: &str) -> HeaderKind {
    if name.eq_ignore_ascii_case("user-agent") {
        HeaderKind::UserAgent
    } else if name.eq_ignore_ascii_case("referer") {
        HeaderKind::Referer
    } else if name.eq_ignore_ascii_case("content-type") {
        HeaderKind::ContentType
    } else if name.eq_ignore_ascii_case("cookie") {
        HeaderKind::Cookie
    } else {
        HeaderKind::Other
    }
}

fn trim_ascii(mut bytes: &[u8]) -> &[u8] {
    while let [first, rest @ ..] = bytes {
        if first.is_ascii_whitespace() {
            bytes = rest;
        } else {
            break;
        }
    }
    while let [rest @ .., last] = bytes {
        if last.is_ascii_whitespace() {
            bytes = rest;
        } else {
            break;
        }
    }
    bytes
}

fn resolve<'a>(request: &'a RequestInput<'a>, decoded: &'a [u8], value: ValueRef) -> &'a [u8] {
    let bytes: &'a [u8] = match value.span.source {
        Source::Method => request.method.as_bytes(),
        Source::Path => request.path.as_bytes(),
        Source::Query => request.query.as_bytes(),
        Source::Body => request.body,
        Source::Header(index) => {
            let (name, header_value) = request.headers[index as usize];
            if value.kind == ValueKind::HeaderName {
                name.as_bytes()
            } else {
                header_value.as_bytes()
            }
        }
        Source::CookieHeader => request.cookie_header.unwrap_or("").as_bytes(),
        Source::Decoded => decoded,
    };
    let start = value.span.start as usize;
    let end = start + value.span.len as usize;
    &bytes[start..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_query_and_form_body() {
        let headers = [("Content-Type", "application/x-www-form-urlencoded")];
        let request = RequestInput::new("POST", "/submit", "a=1&b=two", &headers, b"c=3&d=four");
        let mut arena = Arena::new();
        arena.begin(1);
        arena.parse(&request);
        let values: Vec<&[u8]> = arena
            .values()
            .map(|value| arena.value(&request, value))
            .collect();
        assert!(values.contains(&b"a".as_slice()));
        assert!(values.contains(&b"two".as_slice()));
        assert!(values.contains(&b"four".as_slice()));
    }

    #[test]
    fn parses_cookies() {
        let headers = [("Cookie", "session=abc; theme=dark")];
        let request = RequestInput::new("GET", "/", "", &headers, b"");
        let mut arena = Arena::new();
        arena.begin(1);
        arena.parse(&request);
        let values: Vec<&[u8]> = arena
            .values()
            .map(|value| arena.value(&request, value))
            .collect();
        assert!(values.contains(&b"abc".as_slice()));
        assert!(values.contains(&b"dark".as_slice()));
    }

    #[test]
    fn xml_attributes_are_values_but_element_names_are_not() {
        let headers = [("Content-Type", "application/xml")];
        let body = b"<?xml version=\"1.0\"?><xml><java.lang.Runtime attribute=\"safe\">value</java.lang.Runtime></xml>";
        let request = RequestInput::new("POST", "/post", "", &headers, body);
        let mut arena = Arena::new();
        arena.begin(1);
        arena.parse(&request);
        let values: Vec<&[u8]> = arena
            .values()
            .map(|value| arena.value(&request, value))
            .collect();
        assert!(values.contains(&b"safe".as_slice()));
        assert!(values.contains(&b"value".as_slice()));
        assert!(!values.contains(&b"java.lang.Runtime".as_slice()));
    }

    #[test]
    fn target_masks_select_values() {
        let value = ValueRef {
            span: Span::new(Source::Method, 0, 3),
            kind: ValueKind::Method,
            header: HeaderKind::Other,
        };
        assert!(TargetMask::METHOD.matches(value));
        assert!(!TargetMask::PATH.matches(value));
    }
}
