//! Request collections and macro expansion.
//!
//! The collection model mirrors the subset of Coraza that the pinned CRS uses
//! when driven by the WASI reactor: `ProcessURI`, request headers, cookies and
//! the body processors selected by `Content-Type`. `REMOTE_ADDR` and
//! `UNIQUE_ID` are intentionally empty because the reactor never calls
//! `ProcessConnection` and the host does not supply them.

use std::borrow::Cow;
use std::collections::HashMap;

use super::budget::Budget;
use super::error::EngineError;
use super::ir::{Collection, Selector, VariableSpec};
use super::operators::MacroResolver;
use super::processors::{self, ProcessorLimits};

/// One key/value pair in a keyed collection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry<'a> {
    pub key: Cow<'a, str>,
    pub value: Cow<'a, [u8]>,
}

/// A request as seen by the engine.
#[derive(Debug, Clone, Copy)]
pub struct EngineRequest<'a> {
    pub method: &'a str,
    pub uri: &'a str,
    pub http_version: &'a str,
    pub headers: &'a [(String, String)],
    pub body: Option<&'a [u8]>,
}

/// A resolved variable value.
///
/// Values from the immutable request data are borrowed (zero-copy); values
/// that only exist in the mutable transaction state (TX, MATCHED_VARS) are
/// owned. `cache_id` is a stable identity for the transform cache and is
/// `None` for values that can change during a phase.
#[derive(Debug, Clone)]
pub struct Candidate<'a> {
    pub collection: Collection,
    pub key: Option<Cow<'a, str>>,
    pub value: Cow<'a, [u8]>,
    pub cache_id: Option<u32>,
}

impl<'a> Candidate<'a> {
    /// Name used by `MATCHED_VAR_NAME`, e.g. `ARGS:id` or `REQUEST_URI`.
    pub fn matched_name(&self) -> String {
        match &self.key {
            Some(key) => format!("{}:{}", self.collection.name(), key),
            None => self.collection.name().to_string(),
        }
    }
}

/// Backwards-compatible alias for the old owned resolved value.
pub type ResolvedValue<'a> = Candidate<'a>;

/// Immutable request data, parsed once per transaction.
#[derive(Debug, Clone)]
pub struct RequestData<'a> {
    args_get: Vec<Entry<'a>>,
    args_post: Vec<Entry<'a>>,
    headers: Vec<Entry<'a>>,
    cookies: Vec<Entry<'a>>,
    files: Vec<Entry<'a>>,
    files_names: Vec<Entry<'a>>,
    files_sizes: Vec<Entry<'a>>,
    multipart_part_headers: Vec<Entry<'a>>,
    xml: Vec<Entry<'a>>,

    // Response phases (3–5). Populated only by `attach_response`.
    response_attached: bool,
    response_status: String,
    response_protocol: String,
    response_headers: Vec<Entry<'a>>,
    response_body: Option<Vec<u8>>,
    response_body_length: usize,
    response_content_type: String,
    response_content_length: String,
    response_args: Vec<Entry<'a>>,
    response_xml: Vec<Entry<'a>>,
    outbound_data_error: bool,

    request_uri: Cow<'a, [u8]>,
    request_uri_raw: Cow<'a, [u8]>,
    request_method: Cow<'a, [u8]>,
    request_body: Option<Cow<'a, [u8]>>,
    request_filename: Cow<'a, [u8]>,
    request_basename: Cow<'a, [u8]>,
    request_line: Cow<'a, [u8]>,
    request_protocol: Cow<'a, [u8]>,
    query_string: Cow<'a, [u8]>,
    files_combined_size: usize,

    reqbody_processor: String,
}

/// Mutable per-transaction state.
#[derive(Debug, Clone)]
pub struct TxState {
    tx: HashMap<String, (String, Vec<u8>)>,
    /// Recycled `(lower name, original name, value buffer)` triples. Keeping
    /// them across requests makes repeated `setvar`/anomaly updates
    /// allocation-free after the first request.
    spare: Vec<(String, String, Vec<u8>)>,
    pub(crate) request_body_processor_override: Option<String>,
    pub(crate) force_request_body_variable: bool,
    body_processed: bool,

    captures: [Vec<u8>; super::operators::MAX_CAPTURES],
    matched_var: Vec<u8>,
    matched_var_name: Vec<u8>,
    /// Arena-backed match records for `MATCHED_VARS`: `(name start, name end,
    /// value start, value end)` into `matched_names` / `matched_values`.
    matched_vars: Vec<(usize, usize, usize, usize)>,
    matched_names: Vec<u8>,
    matched_values: Vec<u8>,
}

impl Default for TxState {
    fn default() -> Self {
        Self {
            tx: HashMap::new(),
            spare: Vec::new(),
            request_body_processor_override: None,
            force_request_body_variable: false,
            body_processed: false,
            captures: std::array::from_fn(|_| Vec::new()),
            matched_var: Vec::new(),
            matched_var_name: Vec::new(),
            matched_vars: Vec::new(),
            matched_names: Vec::new(),
            matched_values: Vec::new(),
        }
    }
}

impl TxState {
    /// Prepares a recycled state for a new request while keeping the key and
    /// value allocations for reuse.
    pub fn reset(&mut self) {
        const MAX_SPARE: usize = 256;
        for (lower, (original, value)) in self.tx.drain() {
            if self.spare.len() < MAX_SPARE {
                self.spare.push((lower, original, value));
            }
        }
        self.request_body_processor_override = None;
        self.force_request_body_variable = false;
        self.body_processed = false;
        for slot in &mut self.captures {
            slot.clear();
        }
        self.matched_var.clear();
        self.matched_var_name.clear();
        self.matched_vars.clear();
    }
}

/// Request state for one transaction.
#[derive(Debug, Clone)]
pub struct Collections<'a> {
    data: RequestData<'a>,
    state: TxState,
}

impl<'a> Collections<'a> {
    /// Builds the phase-1 collection view from the request line and headers.
    pub fn new(request: &EngineRequest<'a>, budget: &mut Budget) -> Result<Self, EngineError> {
        Self::new_with_state(request, budget, TxState::default())
    }

    /// Builds a collection view around a recycled transaction state.
    pub fn new_with_state(
        request: &EngineRequest<'a>,
        budget: &mut Budget,
        state: TxState,
    ) -> Result<Self, EngineError> {
        let parsed = ParsedUri::parse(request.uri);
        let mut headers = Vec::with_capacity(request.headers.len());
        let mut reqbody_processor = String::new();
        for (name, value) in request.headers {
            headers.push(Entry {
                key: Cow::Borrowed(name.as_str()),
                value: Cow::Borrowed(value.as_bytes()),
            });
            if name.eq_ignore_ascii_case("content-type") {
                if value.eq_ignore_ascii_case("application/x-www-form-urlencoded") {
                    reqbody_processor = "URLENCODED".to_string();
                } else if value
                    .get(..19)
                    .is_some_and(|prefix| prefix.eq_ignore_ascii_case("multipart/form-data"))
                {
                    reqbody_processor = "MULTIPART".to_string();
                }
            }
        }
        for header in &headers {
            budget.bytes(header.key.len() + header.value.len())?;
        }

        let mut cookies = Vec::new();
        for header in &headers {
            if header.key.eq_ignore_ascii_case("cookie") {
                parse_cookies(&header.value, &mut cookies);
            }
        }

        let args_get = if parsed.valid {
            parse_query(parsed.query.as_ref(), b'&')
                .into_iter()
                .map(|entry| Entry {
                    key: Cow::Owned(entry.key.into_owned()),
                    value: Cow::Owned(entry.value.into_owned()),
                })
                .collect()
        } else {
            Vec::new()
        };

        let data = RequestData {
            args_get,
            args_post: Vec::new(),
            headers,
            cookies,
            files: Vec::new(),
            files_names: Vec::new(),
            files_sizes: Vec::new(),
            multipart_part_headers: Vec::new(),
            xml: Vec::new(),
            response_attached: false,
            response_status: String::new(),
            response_protocol: String::new(),
            response_headers: Vec::new(),
            response_body: None,
            response_body_length: 0,
            response_content_type: String::new(),
            response_content_length: String::new(),
            response_args: Vec::new(),
            response_xml: Vec::new(),
            outbound_data_error: false,
            request_uri: parsed.request_uri,
            request_uri_raw: Cow::Borrowed(request.uri.as_bytes()),
            request_method: Cow::Borrowed(request.method.as_bytes()),
            request_body: None,
            request_filename: parsed.path,
            request_basename: parsed.basename,
            request_line: Cow::Owned(
                format!(
                    "{} {} {}",
                    request.method, request.uri, request.http_version
                )
                .into_bytes(),
            ),
            request_protocol: Cow::Borrowed(request.http_version.as_bytes()),
            query_string: parsed.query,
            files_combined_size: 0,
            reqbody_processor,
        };
        budget.bytes(
            data.request_uri.len()
                + data.request_uri_raw.len()
                + data.request_method.len()
                + data.request_filename.len()
                + data.request_basename.len()
                + data.request_line.len()
                + data.request_protocol.len()
                + data.query_string.len(),
        )?;
        Ok(Self { data, state })
    }

    /// Consumes the collections and returns the recyclable transaction state.
    pub fn into_state(self) -> TxState {
        self.state
    }

    /// Splits the immutable request data from the mutable transaction state.
    ///
    /// This is what lets the engine hold zero-copy candidate spans while it
    /// mutates TX scores and captures.
    pub fn split(&mut self) -> (&RequestData<'a>, &mut TxState) {
        (&self.data, &mut self.state)
    }

    /// Immutable request data.
    pub fn data(&self) -> &RequestData<'a> {
        &self.data
    }

    /// Mutable transaction state.
    pub fn state_mut(&mut self) -> &mut TxState {
        &mut self.state
    }

    /// Runs the body processor selected by `Content-Type` (and by `ctl` during
    /// phase 1), exactly like `Transaction::ProcessRequestBody`.
    pub fn process_body(
        &mut self,
        request: &EngineRequest<'a>,
        budget: &mut Budget,
    ) -> Result<(), EngineError> {
        if self.state.body_processed {
            return Ok(());
        }
        self.state.body_processed = true;
        let Some(body) = request.body else {
            return Ok(());
        };
        if body.is_empty() {
            return Ok(());
        }

        let mut processor = self.state.request_body_processor_override.take();
        if self.state.force_request_body_variable
            && processor
                .as_deref()
                .unwrap_or(&self.data.reqbody_processor)
                .is_empty()
        {
            processor = Some("URLENCODED".to_string());
        }
        let processor_name = processor.as_deref().unwrap_or(&self.data.reqbody_processor);
        let urlencoded = processor_name.eq_ignore_ascii_case("urlencoded");
        let multipart = processor_name.eq_ignore_ascii_case("multipart");
        let json = processor_name.eq_ignore_ascii_case("json");
        let xml = processor_name.eq_ignore_ascii_case("xml");
        budget.bytes(body.len())?;

        if let Some(processor) = processor {
            self.data.reqbody_processor = processor;
        }
        if urlencoded {
            self.data.args_post = parse_query(body, b'&');
            self.data.request_body = Some(Cow::Borrowed(body));
        } else if multipart {
            self.parse_multipart(body, budget)?;
        } else if json {
            // Coraza's JSON processor writes only ARGS_POST; it does not set
            // REQUEST_BODY. Malformed input produces no arguments.
            if let Ok(values) = processors::json::process(body, &ProcessorLimits::default()) {
                for (key, value) in values {
                    self.data.args_post.push(Entry {
                        key: Cow::Owned(key),
                        value: Cow::Owned(value),
                    });
                }
            }
        } else if xml {
            // `XML://@*` holds attributes, `XML:/*` character data. No
            // external DTD/entity resolution happens in the processor.
            if let Ok(values) = processors::xml::process(body) {
                for value in values.attributes {
                    self.data.xml.push(Entry {
                        key: Cow::Borrowed("//@*"),
                        value: Cow::Owned(value),
                    });
                }
                for value in values.content {
                    self.data.xml.push(Entry {
                        key: Cow::Borrowed("/*"),
                        value: Cow::Owned(value),
                    });
                }
            }
        }
        Ok(())
    }

    fn parse_multipart(&mut self, body: &'a [u8], budget: &mut Budget) -> Result<(), EngineError> {
        let boundary = self
            .data
            .headers
            .iter()
            .find(|header| header.key.eq_ignore_ascii_case("content-type"))
            .and_then(|header| content_type_boundary(&header.value));
        let Some(boundary) = boundary else {
            return Ok(());
        };
        let delimiter = format!("--{boundary}").into_bytes();
        let mut cursor = 0usize;
        while let Some(start) = find_bytes(&body[cursor..], &delimiter) {
            let part_start = cursor + start + delimiter.len();
            if body.get(part_start..part_start + 2) == Some(b"--") {
                break;
            }
            let part_start = part_start
                + if body.get(part_start..part_start + 2) == Some(b"\r\n") {
                    2
                } else if body.get(part_start..part_start + 1) == Some(b"\n") {
                    1
                } else {
                    0
                };
            let Some(end) = find_bytes(&body[part_start..], &delimiter) else {
                break;
            };
            let part = &body[part_start..part_start + end];
            let part = trim_trailing_crlf(part);
            cursor = part_start + end;
            if part.is_empty() {
                continue;
            }
            let (header_bytes, value) = split_part_headers(part);
            let headers = parse_part_headers(header_bytes);
            let (name, filename) = disposition_fields(&headers);
            let Some(name) = name else {
                continue;
            };
            for (header_name, header_value) in &headers {
                self.data.multipart_part_headers.push(Entry {
                    key: Cow::Owned(name.clone()),
                    value: Cow::Owned(format!("{header_name}: {header_value}").into_bytes()),
                });
            }
            if let Some(filename) = filename {
                self.data.files.push(Entry {
                    key: Cow::Borrowed(""),
                    value: Cow::Owned(filename.clone().into_bytes()),
                });
                self.data.files_names.push(Entry {
                    key: Cow::Borrowed(""),
                    value: Cow::Owned(name.clone().into_bytes()),
                });
                self.data.files_sizes.push(Entry {
                    key: Cow::Owned(filename),
                    value: Cow::Owned(value.len().to_string().into_bytes()),
                });
                self.data.files_combined_size += value.len();
            } else {
                self.data.args_post.push(Entry {
                    key: Cow::Owned(name),
                    value: Cow::Owned(value.to_vec()),
                });
            }
            budget.bytes(value.len())?;
        }
        Ok(())
    }

    /// Returns the TX value, case-insensitive.
    pub fn tx_get(&self, name: &str) -> Option<&[u8]> {
        self.state.tx_get(name)
    }

    /// Sets a TX value.
    pub fn tx_set(&mut self, name: &str, value: Vec<u8>) {
        self.state.tx_set(name, value);
    }

    /// Adds to a TX value. Numeric values are added numerically; otherwise the
    /// new value is appended, matching ModSecurity's `+` setvar semantics.
    pub fn tx_add(&mut self, name: &str, value: &[u8]) {
        self.state.tx_add(name, value);
    }

    /// Subtracts from a TX value.
    pub fn tx_sub(&mut self, name: &str, value: &[u8]) {
        self.state.tx_sub(name, value);
    }

    /// Removes a TX value.
    pub fn tx_remove(&mut self, name: &str) {
        self.state.tx_remove(name);
    }

    /// Stores a regex capture in `TX:n` and the capture array.
    pub fn set_capture(&mut self, index: usize, value: &[u8]) {
        self.state.set_capture(index, value);
    }

    /// Clears capture slots.
    pub fn clear_captures(&mut self) {
        self.state.clear_captures();
    }

    /// Records a matched variable for `MATCHED_VAR*`.
    pub fn record_match(&mut self, collection: Collection, key: Option<&str>, value: &[u8]) {
        self.state.record_match(collection, key, value);
    }

    /// Clears the per-rule matched-variable state.
    pub fn clear_matches(&mut self) {
        self.state.clear_matches();
    }

    /// Returns the body processor name exposed as `REQBODY_PROCESSOR`.
    pub fn reqbody_processor(&self) -> &str {
        &self.data.reqbody_processor
    }

    /// Applies a `ctl:requestBodyProcessor=...` override.
    pub fn set_request_body_processor(&mut self, processor: String) {
        self.state.request_body_processor_override = Some(processor);
    }

    /// Applies `ctl:forceRequestBodyVariable=...`.
    pub fn set_force_request_body_variable(&mut self, force: bool) {
        self.state.force_request_body_variable = force;
    }

    /// Attaches the upstream response for phases 3–5.
    ///
    /// Header values are exposed as `RESPONSE_HEADERS`, the status as
    /// `RESPONSE_STATUS`, and (when [`ResponseConfig::inspect_body`] is set)
    /// the body as `RESPONSE_BODY` or through the configured body processor.
    pub fn attach_response(
        &mut self,
        response: &super::response::EngineResponse<'_>,
        config: &super::response::ResponseConfig,
    ) {
        self.data.response_attached = true;
        self.data.response_status = response.status.to_string();
        self.data.response_protocol = response.protocol.to_string();
        self.data.response_headers.clear();
        for (name, value) in response.headers {
            if name.eq_ignore_ascii_case("content-type") {
                self.data.response_content_type =
                    value.split(';').next().unwrap_or(value).trim().to_string();
            }
            if name.eq_ignore_ascii_case("content-length") {
                self.data.response_content_length = value.trim().to_string();
            }
            self.data.response_headers.push(Entry {
                key: Cow::Owned(name.clone()),
                value: Cow::Owned(value.as_bytes().to_vec()),
            });
        }
        if self.data.response_content_length.is_empty() {
            if let Some(body) = response.body {
                self.data.response_content_length = body.len().to_string();
            }
        }

        let values = super::response::process_body(response, config);
        self.data.response_body = values.raw;
        self.data.response_body_length = response.body.map_or(0, <[u8]>::len);
        self.data.response_args.clear();
        for (key, value) in values.entries {
            let entry = Entry {
                key: Cow::Owned(key),
                value: Cow::Owned(value),
            };
            if config
                .body_processor
                .as_deref()
                .is_some_and(|processor| processor.eq_ignore_ascii_case("xml"))
            {
                self.data.response_xml.push(entry);
            } else {
                self.data.response_args.push(entry);
            }
        }
    }

    /// Resolves one variable spec into values.
    pub fn resolve<'r>(
        &'r self,
        spec: &VariableSpec,
        budget: &mut Budget,
    ) -> Result<Vec<Candidate<'r>>, EngineError> {
        let mut values = Vec::new();
        self.resolve_into(spec, budget, &mut values)?;
        Ok(values)
    }

    /// Resolves one variable spec, appending to a reusable candidate buffer.
    pub fn resolve_into<'r>(
        &'r self,
        spec: &VariableSpec,
        budget: &mut Budget,
        out: &mut Vec<Candidate<'r>>,
    ) -> Result<(), EngineError> {
        self.data.resolve_into(spec, &self.state, budget, out)
    }
}

impl<'a> RequestData<'a> {
    /// Dynamic collection presence bits for the current phase.
    ///
    /// `CompiledRule::presence` is an OR of these bits; when it does not
    /// intersect this mask (and the rule has no static target or count target)
    /// the rule cannot match, so candidate resolution and regex work are
    /// skipped entirely.
    pub(crate) fn dynamic_present(&self, state: &TxState) -> u64 {
        let mut mask = 0u64;
        let mut bit = |collection: Collection| mask |= 1u64 << (collection as u32);
        if !self.args_get.is_empty() || !self.args_post.is_empty() {
            bit(Collection::Args);
        }
        if !self.args_get.is_empty() {
            bit(Collection::ArgsGet);
            bit(Collection::ArgsGetNames);
            bit(Collection::ArgsNames);
        }
        if !self.args_post.is_empty() {
            bit(Collection::ArgsPost);
            bit(Collection::ArgsPostNames);
            bit(Collection::ArgsNames);
        }
        if !self.headers.is_empty() {
            bit(Collection::RequestHeaders);
            bit(Collection::RequestHeadersNames);
        }
        if !self.cookies.is_empty() {
            bit(Collection::RequestCookies);
            bit(Collection::RequestCookiesNames);
        }
        if self
            .request_body
            .as_ref()
            .is_some_and(|body| !body.is_empty())
        {
            bit(Collection::RequestBody);
        }
        if !self.files.is_empty() {
            bit(Collection::Files);
        }
        if !self.files_names.is_empty() {
            bit(Collection::FilesNames);
        }
        if !self.files_sizes.is_empty() {
            bit(Collection::FilesSizes);
        }
        if !self.multipart_part_headers.is_empty() {
            bit(Collection::MultipartPartHeaders);
        }
        if !state.tx_is_empty() {
            bit(Collection::Tx);
        }
        if state.matched_len() > 0 {
            bit(Collection::MatchedVars);
            bit(Collection::MatchedVarsNames);
        }
        mask
    }

    pub(crate) fn resolve_into<'r>(
        &'r self,
        spec: &VariableSpec,
        state: &TxState,
        budget: &mut Budget,
        out: &mut Vec<Candidate<'r>>,
    ) -> Result<(), EngineError> {
        let start = out.len();
        match spec.collection {
            Collection::Args => self.keyed(
                Collection::Args,
                &self.args_get,
                &self.args_post,
                &spec.selector,
                budget,
                out,
            )?,
            Collection::ArgsGet => self.keyed(
                Collection::ArgsGet,
                &self.args_get,
                &[],
                &spec.selector,
                budget,
                out,
            )?,
            Collection::ArgsPost => self.keyed(
                Collection::ArgsPost,
                &self.args_post,
                &[],
                &spec.selector,
                budget,
                out,
            )?,
            Collection::ArgsNames => self.names(
                Collection::ArgsNames,
                &self.args_get,
                &self.args_post,
                &spec.selector,
                budget,
                out,
            )?,
            Collection::ArgsGetNames => self.names(
                Collection::ArgsGetNames,
                &self.args_get,
                &[],
                &spec.selector,
                budget,
                out,
            )?,
            Collection::ArgsPostNames => self.names(
                Collection::ArgsPostNames,
                &self.args_post,
                &[],
                &spec.selector,
                budget,
                out,
            )?,
            Collection::ArgsCombinedSize => {
                let size = self
                    .args_get
                    .iter()
                    .chain(self.args_post.iter())
                    .map(|entry| entry.key.len() + entry.value.len())
                    .sum::<usize>();
                self.single(
                    Collection::ArgsCombinedSize,
                    Cow::Owned(size.to_string().into_bytes()),
                    budget,
                    out,
                )?;
            }
            Collection::RequestHeaders => self.keyed(
                Collection::RequestHeaders,
                &self.headers,
                &[],
                &spec.selector,
                budget,
                out,
            )?,
            Collection::RequestHeadersNames => self.names(
                Collection::RequestHeadersNames,
                &self.headers,
                &[],
                &spec.selector,
                budget,
                out,
            )?,
            Collection::RequestCookies => self.keyed(
                Collection::RequestCookies,
                &self.cookies,
                &[],
                &spec.selector,
                budget,
                out,
            )?,
            Collection::RequestCookiesNames => self.names(
                Collection::RequestCookiesNames,
                &self.cookies,
                &[],
                &spec.selector,
                budget,
                out,
            )?,
            Collection::RequestUri => self.single(
                Collection::RequestUri,
                self.request_uri.clone(),
                budget,
                out,
            )?,
            Collection::RequestUriRaw => self.single(
                Collection::RequestUriRaw,
                self.request_uri_raw.clone(),
                budget,
                out,
            )?,
            Collection::RequestMethod => self.single(
                Collection::RequestMethod,
                self.request_method.clone(),
                budget,
                out,
            )?,
            Collection::RequestBody => self.single(
                Collection::RequestBody,
                self.request_body.clone().unwrap_or(Cow::Borrowed(&[])),
                budget,
                out,
            )?,
            Collection::RequestBodyLength => {
                let length = self.request_body.as_ref().map_or(0, |body| body.len());
                self.single(
                    Collection::RequestBodyLength,
                    Cow::Owned(length.to_string().into_bytes()),
                    budget,
                    out,
                )?;
            }
            Collection::RequestFilename => self.single(
                Collection::RequestFilename,
                self.request_filename.clone(),
                budget,
                out,
            )?,
            Collection::RequestBasename => self.single(
                Collection::RequestBasename,
                self.request_basename.clone(),
                budget,
                out,
            )?,
            Collection::RequestLine => self.single(
                Collection::RequestLine,
                self.request_line.clone(),
                budget,
                out,
            )?,
            Collection::RequestProtocol => self.single(
                Collection::RequestProtocol,
                self.request_protocol.clone(),
                budget,
                out,
            )?,
            Collection::QueryString => self.single(
                Collection::QueryString,
                self.query_string.clone(),
                budget,
                out,
            )?,
            Collection::Tx => state.tx_values(&spec.selector, budget, out)?,
            Collection::MatchedVars => state.matched_values(false, budget, out)?,
            Collection::MatchedVarsNames => state.matched_values(true, budget, out)?,
            Collection::Xml => {
                self.keyed(Collection::Xml, &self.xml, &[], &spec.selector, budget, out)?
            }
            Collection::Files => self.keyed(
                Collection::Files,
                &self.files,
                &[],
                &spec.selector,
                budget,
                out,
            )?,
            Collection::FilesNames => self.keyed(
                Collection::FilesNames,
                &self.files_names,
                &[],
                &spec.selector,
                budget,
                out,
            )?,
            Collection::FilesSizes => self.keyed(
                Collection::FilesSizes,
                &self.files_sizes,
                &[],
                &spec.selector,
                budget,
                out,
            )?,
            Collection::FilesCombinedSize => self.single(
                Collection::FilesCombinedSize,
                Cow::Owned(self.files_combined_size.to_string().into_bytes()),
                budget,
                out,
            )?,
            Collection::MultipartPartHeaders => self.keyed(
                Collection::MultipartPartHeaders,
                &self.multipart_part_headers,
                &[],
                &spec.selector,
                budget,
                out,
            )?,
            Collection::ReqbodyProcessor => self.single(
                Collection::ReqbodyProcessor,
                Cow::Owned(self.reqbody_processor.clone().into_bytes()),
                budget,
                out,
            )?,
            Collection::RemoteAddr => {
                self.single(Collection::RemoteAddr, Cow::Borrowed(&[]), budget, out)?
            }
            Collection::UniqueId => {
                self.single(Collection::UniqueId, Cow::Borrowed(&[]), budget, out)?
            }
            Collection::OutboundDataError => self.single(
                Collection::OutboundDataError,
                Cow::Owned(if self.outbound_data_error { b"1" } else { b"0" }.to_vec()),
                budget,
                out,
            )?,
            Collection::ResponseStatus => self.single(
                Collection::ResponseStatus,
                Cow::Owned(self.response_status.clone().into_bytes()),
                budget,
                out,
            )?,
            Collection::ResponseProtocol => self.single(
                Collection::ResponseProtocol,
                Cow::Owned(self.response_protocol.clone().into_bytes()),
                budget,
                out,
            )?,
            Collection::ResponseHeaders => self.keyed(
                Collection::ResponseHeaders,
                &self.response_headers,
                &[],
                &spec.selector,
                budget,
                out,
            )?,
            Collection::ResponseHeadersNames => self.names(
                Collection::ResponseHeadersNames,
                &self.response_headers,
                &[],
                &spec.selector,
                budget,
                out,
            )?,
            Collection::ResponseBody => self.single(
                Collection::ResponseBody,
                Cow::Owned(self.response_body.clone().unwrap_or_default()),
                budget,
                out,
            )?,
            Collection::ResponseBodyLength => self.single(
                Collection::ResponseBodyLength,
                Cow::Owned(
                    if self.response_body_length > 0 {
                        self.response_body_length.to_string()
                    } else {
                        self.response_content_length.clone()
                    }
                    .into_bytes(),
                ),
                budget,
                out,
            )?,
            Collection::ResponseContentType => self.single(
                Collection::ResponseContentType,
                Cow::Owned(self.response_content_type.clone().into_bytes()),
                budget,
                out,
            )?,
            Collection::ResponseContentLength => self.single(
                Collection::ResponseContentLength,
                Cow::Owned(self.response_content_length.clone().into_bytes()),
                budget,
                out,
            )?,
            Collection::ResponseArgs => self.keyed(
                Collection::ResponseArgs,
                &self.response_args,
                &[],
                &spec.selector,
                budget,
                out,
            )?,
            Collection::ResponseXml => self.keyed(
                Collection::ResponseXml,
                &self.response_xml,
                &[],
                &spec.selector,
                budget,
                out,
            )?,
            Collection::Rule | Collection::Global | Collection::Ip => {}
        }

        if spec.count {
            let count = (out.len() - start).to_string().into_bytes();
            out.truncate(start);
            budget.value()?;
            budget.bytes(count.len())?;
            out.push(Candidate {
                collection: spec.collection,
                key: None,
                value: Cow::Owned(count),
                cache_id: None,
            });
        }
        Ok(())
    }

    fn single<'r>(
        &'r self,
        collection: Collection,
        value: Cow<'a, [u8]>,
        budget: &mut Budget,
        out: &mut Vec<Candidate<'r>>,
    ) -> Result<(), EngineError> {
        budget.value()?;
        budget.bytes(value.len())?;
        out.push(Candidate {
            collection,
            key: None,
            value,
            cache_id: None,
        });
        Ok(())
    }

    fn keyed<'r>(
        &'r self,
        collection: Collection,
        first: &'r [Entry<'a>],
        second: &'r [Entry<'a>],
        selector: &Selector,
        budget: &mut Budget,
        out: &mut Vec<Candidate<'r>>,
    ) -> Result<(), EngineError> {
        for (index, entry) in first.iter().chain(second.iter()).enumerate() {
            if !selector_matches(selector, &entry.key) {
                continue;
            }
            budget.value()?;
            budget.bytes(entry.value.len())?;
            out.push(Candidate {
                collection,
                key: Some(Cow::Borrowed(entry.key.as_ref())),
                value: Cow::Borrowed(entry.value.as_ref()),
                cache_id: Some(entry_cache_id(collection, index)),
            });
        }
        Ok(())
    }

    fn names<'r>(
        &'r self,
        collection: Collection,
        first: &'r [Entry<'a>],
        second: &'r [Entry<'a>],
        selector: &Selector,
        budget: &mut Budget,
        out: &mut Vec<Candidate<'r>>,
    ) -> Result<(), EngineError> {
        for (index, entry) in first.iter().chain(second.iter()).enumerate() {
            if !selector_matches(selector, &entry.key) {
                continue;
            }
            budget.value()?;
            budget.bytes(entry.key.len())?;
            out.push(Candidate {
                collection,
                key: Some(Cow::Borrowed(entry.key.as_ref())),
                value: Cow::Borrowed(entry.key.as_ref().as_bytes()),
                cache_id: Some(entry_cache_id(collection, index)),
            });
        }
        Ok(())
    }
}

impl TxState {
    /// True when no TX variable is currently defined.
    pub(crate) fn tx_is_empty(&self) -> bool {
        self.tx.is_empty()
    }

    /// Returns the TX value, case-insensitive.
    pub fn tx_get(&self, name: &str) -> Option<&[u8]> {
        if let Some((_, value)) = self.tx.get(name) {
            return Some(value.as_slice());
        }
        // Names are stored lowercased at parse time; only macro-expanded or
        // caller-supplied names can arrive with different case.
        if name.bytes().any(|byte| byte.is_ascii_uppercase()) {
            return self
                .tx
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case(name))
                .map(|(_, (_, value))| value.as_slice());
        }
        None
    }

    /// Sets a TX value from owned bytes.
    pub fn tx_set(&mut self, name: &str, value: Vec<u8>) {
        self.tx_set_bytes(name, &value);
    }

    /// Sets a TX value from a borrowed slice. The slot is reused when the
    /// variable already exists, so repeated `setvar` actions do not allocate.
    pub fn tx_set_bytes(&mut self, name: &str, value: &[u8]) {
        let lower = lower_name(name);
        if let Some((_, slot)) = self.tx.get_mut(lower.as_ref()) {
            slot.clear();
            slot.extend_from_slice(value);
            return;
        }
        let (key, original, mut slot) = self.take_slot(lower.as_ref(), name);
        slot.clear();
        slot.extend_from_slice(value);
        self.tx.insert(key, (original, slot));
    }

    /// Takes a recycled `(key, original name, value)` triple, or allocates one
    /// on the first request that uses this name.
    fn take_slot(&mut self, lower: &str, name: &str) -> (String, String, Vec<u8>) {
        if let Some(index) = self.spare.iter().position(|(key, _, _)| key == lower) {
            return self.spare.swap_remove(index);
        }
        (lower.to_string(), name.to_string(), Vec::new())
    }

    /// Adds to a TX value. Numeric values are added numerically; otherwise the
    /// new value is appended, matching ModSecurity's `+` setvar semantics.
    pub fn tx_add(&mut self, name: &str, value: &[u8]) {
        let lower = lower_name(name);
        if let Some((_, slot)) = self.tx.get_mut(lower.as_ref()) {
            if let (Some(left), Some(right)) = (parse_i64(slot), parse_i64(value)) {
                slot.clear();
                push_i64(slot, left.saturating_add(right));
            } else {
                slot.extend_from_slice(value);
            }
            return;
        }
        let (key, original, mut slot) = self.take_slot(lower.as_ref(), name);
        slot.clear();
        slot.extend_from_slice(value);
        self.tx.insert(key, (original, slot));
    }

    /// Subtracts from a TX value.
    pub fn tx_sub(&mut self, name: &str, value: &[u8]) {
        let lower = lower_name(name);
        let result = self
            .tx
            .get(lower.as_ref())
            .and_then(|(_, current)| parse_i64(current))
            .unwrap_or(0)
            .saturating_sub(parse_i64(value).unwrap_or(0));
        if let Some((_, slot)) = self.tx.get_mut(lower.as_ref()) {
            slot.clear();
            push_i64(slot, result);
            return;
        }
        let (key, original, mut slot) = self.take_slot(lower.as_ref(), name);
        slot.clear();
        push_i64(&mut slot, result);
        self.tx.insert(key, (original, slot));
    }

    /// Removes a TX value.
    pub fn tx_remove(&mut self, name: &str) {
        if let Some((lower, entry)) = self.tx.remove_entry(name) {
            self.recycle(lower, entry);
            return;
        }
        if let Some(key) = self
            .tx
            .keys()
            .find(|key| key.eq_ignore_ascii_case(name))
            .cloned()
        {
            if let Some((lower, entry)) = self.tx.remove_entry(&key) {
                self.recycle(lower, entry);
            }
        }
    }

    fn recycle(&mut self, lower: String, (original, value): (String, Vec<u8>)) {
        const MAX_SPARE: usize = 256;
        if self.spare.len() < MAX_SPARE {
            self.spare.push((lower, original, value));
        }
    }

    /// Stores a regex capture in `TX:n` and the capture array.
    pub fn set_capture(&mut self, index: usize, value: &[u8]) {
        if index < self.captures.len() {
            if let Some(name) = capture_name(index) {
                self.tx_set_bytes(name, value);
            }
            let slot = &mut self.captures[index];
            slot.clear();
            slot.extend_from_slice(value);
        }
    }

    /// Clears capture slots.
    pub fn clear_captures(&mut self) {
        for slot in &mut self.captures {
            slot.clear();
        }
    }

    /// Records a matched variable for `MATCHED_VAR*`.
    ///
    /// The collection/key/value are appended to reused byte arenas, so a match
    /// does not allocate after the first request that needs the same capacity.
    pub fn record_match(&mut self, collection: Collection, key: Option<&str>, value: &[u8]) {
        let name_start = self.matched_names.len();
        self.matched_names
            .extend_from_slice(collection.name().as_bytes());
        if let Some(key) = key {
            self.matched_names.push(b':');
            self.matched_names.extend_from_slice(key.as_bytes());
        }
        let name_end = self.matched_names.len();
        let value_start = self.matched_values.len();
        self.matched_values.extend_from_slice(value);
        let value_end = self.matched_values.len();

        self.matched_var.clear();
        self.matched_var.extend_from_slice(value);
        self.matched_var_name.clear();
        self.matched_var_name
            .extend_from_slice(&self.matched_names[name_start..name_end]);
        self.matched_vars
            .push((name_start, name_end, value_start, value_end));
    }

    /// Clears the per-rule matched-variable state.
    pub fn clear_matches(&mut self) {
        self.matched_var.clear();
        self.matched_var_name.clear();
        self.matched_vars.clear();
        self.matched_names.clear();
        self.matched_values.clear();
    }

    /// Number of values in `MATCHED_VARS` for the current rule group.
    pub fn matched_len(&self) -> usize {
        self.matched_vars.len()
    }

    /// One `MATCHED_VARS` entry as `(name, value)`.
    pub fn matched_at(&self, index: usize) -> Option<(&str, &[u8])> {
        let (name_start, name_end, value_start, value_end) = *self.matched_vars.get(index)?;
        let name = std::str::from_utf8(&self.matched_names[name_start..name_end]).ok()?;
        Some((name, &self.matched_values[value_start..value_end]))
    }

    /// Borrowed `(name, value)` iterator over active TX entries matching
    /// `selector`. Used for allocation-free pre-checks.
    pub(crate) fn tx_entries_matching<'s>(
        &'s self,
        selector: &'s Selector,
    ) -> impl Iterator<Item = (&'s str, &'s [u8])> + 's {
        self.tx.values().filter_map(move |(original, value)| {
            selector_matches(selector, original).then_some((original.as_str(), value.as_slice()))
        })
    }

    fn tx_values<'a>(
        &self,
        selector: &Selector,
        budget: &mut Budget,
        out: &mut Vec<Candidate<'a>>,
    ) -> Result<(), EngineError> {
        for (original, value) in self.tx.values() {
            if !selector_matches(selector, original) {
                continue;
            }
            budget.value()?;
            budget.bytes(value.len())?;
            out.push(Candidate {
                collection: Collection::Tx,
                key: Some(Cow::Owned(original.clone())),
                value: Cow::Owned(value.clone()),
                cache_id: None,
            });
        }
        Ok(())
    }

    fn matched_values<'a>(
        &self,
        names_only: bool,
        budget: &mut Budget,
        out: &mut Vec<Candidate<'a>>,
    ) -> Result<(), EngineError> {
        let collection = if names_only {
            Collection::MatchedVarsNames
        } else {
            Collection::MatchedVars
        };
        for index in 0..self.matched_vars.len() {
            let Some((name, value)) = self.matched_at(index) else {
                continue;
            };
            let value = if names_only {
                name.as_bytes().to_vec()
            } else {
                value.to_vec()
            };
            budget.value()?;
            budget.bytes(value.len())?;
            out.push(Candidate {
                collection,
                key: Some(Cow::Owned(name.to_string())),
                value: Cow::Owned(value),
                cache_id: None,
            });
        }
        Ok(())
    }
}

/// Stable cache id for an entry in a keyed collection.
fn entry_cache_id(collection: Collection, index: usize) -> u32 {
    let base = match collection {
        Collection::Args | Collection::ArgsGet => 0,
        Collection::ArgsPost => 1_000,
        Collection::ArgsNames => 2_000,
        Collection::ArgsGetNames => 2_100,
        Collection::ArgsPostNames => 2_200,
        Collection::RequestHeaders => 3_000,
        Collection::RequestHeadersNames => 3_100,
        Collection::RequestCookies => 4_000,
        Collection::RequestCookiesNames => 4_100,
        Collection::Files => 5_000,
        Collection::FilesNames => 5_100,
        Collection::FilesSizes => 5_200,
        Collection::MultipartPartHeaders => 5_300,
        _ => 6_000,
    };
    base + index as u32
}

fn lower_name(name: &str) -> Cow<'_, str> {
    if name.bytes().any(|byte| byte.is_ascii_uppercase()) {
        Cow::Owned(name.to_ascii_lowercase())
    } else {
        Cow::Borrowed(name)
    }
}

/// Expands `%{...}` macros against immutable request data and TX state.
pub fn expand_macros(data: &RequestData<'_>, state: &TxState, template: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(template.len());
    expand_macros_into(data, state, template, &mut out);
    out
}

/// [`expand_macros`] with a caller-owned, reused buffer.
pub fn expand_macros_into(
    data: &RequestData<'_>,
    state: &TxState,
    template: &str,
    out: &mut Vec<u8>,
) {
    out.clear();
    let bytes = template.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 1 < bytes.len() && bytes[i + 1] == b'{' {
            if let Some(end) = template[i + 2..].find('}') {
                let name = &template[i + 2..i + 2 + end];
                out.extend_from_slice(&expand_macro_name(data, state, name));
                i += 2 + end + 1;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
}

impl MacroResolver for Collections<'_> {
    fn expand_into(&self, template: &str, out: &mut Vec<u8>) {
        expand_macros_into(&self.data, &self.state, template, out);
    }
}

impl MacroResolver for (&RequestData<'_>, &TxState) {
    fn expand_into(&self, template: &str, out: &mut Vec<u8>) {
        expand_macros_into(self.0, self.1, template, out);
    }
}

fn expand_macro_name<'r, 'a>(
    data: &'r RequestData<'a>,
    state: &'r TxState,
    name: &str,
) -> Cow<'r, [u8]> {
    let lower = lower_name(name);
    if let Some(key) = lower.strip_prefix("tx.") {
        return state.tx_get(key).map(Cow::Borrowed).unwrap_or_default();
    }
    if lower == "matched_var" {
        return Cow::Borrowed(state.matched_var.as_slice());
    }
    if lower == "matched_var_name" {
        return Cow::Borrowed(state.matched_var_name.as_slice());
    }
    if let Some((collection, key)) = name.split_once('.') {
        if collection.eq_ignore_ascii_case("args") {
            return find_entry(&data.args_get, key)
                .or_else(|| find_entry(&data.args_post, key))
                .map(|entry| Cow::Borrowed(entry.value.as_ref()))
                .unwrap_or_default();
        }
        if collection.eq_ignore_ascii_case("args_get") {
            return find_entry(&data.args_get, key)
                .map(|entry| Cow::Borrowed(entry.value.as_ref()))
                .unwrap_or_default();
        }
        if collection.eq_ignore_ascii_case("args_post") {
            return find_entry(&data.args_post, key)
                .map(|entry| Cow::Borrowed(entry.value.as_ref()))
                .unwrap_or_default();
        }
        if collection.eq_ignore_ascii_case("request_headers") {
            return data
                .headers
                .iter()
                .find(|header| header.key.eq_ignore_ascii_case(key))
                .map(|header| Cow::Borrowed(header.value.as_ref()))
                .unwrap_or_default();
        }
        if collection.eq_ignore_ascii_case("request_cookies") {
            return find_entry(&data.cookies, key)
                .map(|entry| Cow::Borrowed(entry.value.as_ref()))
                .unwrap_or_default();
        }
        if collection.eq_ignore_ascii_case("rule") {
            return Cow::Borrowed(&[]);
        }
    }
    match lower.as_ref() {
        "request_uri" => Cow::Borrowed(data.request_uri.as_ref()),
        "request_uri_raw" => Cow::Borrowed(data.request_uri_raw.as_ref()),
        "request_method" => Cow::Borrowed(data.request_method.as_ref()),
        "request_body" => data
            .request_body
            .as_ref()
            .map(|body| Cow::Borrowed(body.as_ref()))
            .unwrap_or_default(),
        "request_filename" => Cow::Borrowed(data.request_filename.as_ref()),
        "request_basename" => Cow::Borrowed(data.request_basename.as_ref()),
        "request_line" => Cow::Borrowed(data.request_line.as_ref()),
        "request_protocol" => Cow::Borrowed(data.request_protocol.as_ref()),
        "query_string" => Cow::Borrowed(data.query_string.as_ref()),
        "remote_addr" | "unique_id" => Cow::Borrowed(&[]),
        "response_status" => Cow::Owned(data.response_status.clone().into_bytes()),
        "response_protocol" => Cow::Owned(data.response_protocol.clone().into_bytes()),
        "response_body" => Cow::Owned(data.response_body.clone().unwrap_or_default()),
        "response_content_type" => Cow::Owned(data.response_content_type.clone().into_bytes()),
        "response_content_length" => Cow::Owned(data.response_content_length.clone().into_bytes()),
        _ => Cow::Borrowed(&[]),
    }
}

fn find_entry<'r, 'a>(entries: &'r [Entry<'a>], key: &str) -> Option<&'r Entry<'a>> {
    entries
        .iter()
        .find(|entry| entry.key.eq_ignore_ascii_case(key))
}

fn selector_matches(selector: &Selector, key: &str) -> bool {
    match selector {
        Selector::All => true,
        Selector::Key(expected) => key.eq_ignore_ascii_case(expected),
        Selector::Regex(regex) => regex.is_match(lower_name(key).as_ref()),
    }
}

fn parse_i64(value: &[u8]) -> Option<i64> {
    std::str::from_utf8(value).ok()?.trim().parse().ok()
}

fn push_i64(out: &mut Vec<u8>, value: i64) {
    let mut buffer = [0u8; 20];
    let mut cursor = buffer.len();
    let negative = value < 0;
    let mut magnitude = value.unsigned_abs();
    loop {
        cursor -= 1;
        buffer[cursor] = b'0' + (magnitude % 10) as u8;
        magnitude /= 10;
        if magnitude == 0 {
            break;
        }
    }
    if negative {
        cursor -= 1;
        buffer[cursor] = b'-';
    }
    out.extend_from_slice(&buffer[cursor..]);
}

/// Static names for the ten capture slots, avoiding `to_string` per match.
fn capture_name(index: usize) -> Option<&'static str> {
    const NAMES: [&str; 10] = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"];
    NAMES.get(index).copied()
}

fn parse_cookies<'a>(value: &[u8], out: &mut Vec<Entry<'a>>) {
    let text = String::from_utf8_lossy(value);
    for part in split_quoted(&text, ';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (key, value) = part.split_once('=').unwrap_or((part, ""));
        out.push(Entry {
            key: Cow::Owned(key.trim().to_string()),
            value: Cow::Owned(value.trim().as_bytes().to_vec()),
        });
    }
}

/// Parses `application/x-www-form-urlencoded` data with Coraza's forgiving
/// rules (invalid escapes are preserved). Values borrow from `query` when no
/// percent-decoding is needed.
pub fn parse_query<'a>(query: &'a [u8], separator: u8) -> Vec<Entry<'a>> {
    let mut out = Vec::new();
    for field in query.split(|byte| *byte == separator) {
        if field.is_empty() {
            continue;
        }
        let (key, value) = match field.iter().position(|byte| *byte == b'=') {
            Some(index) => (&field[..index], &field[index + 1..]),
            None => (field, &[][..]),
        };
        let key = percent_decode(key, true);
        let value = percent_decode(value, true);
        if key.is_empty() {
            continue;
        }
        let key = match key {
            Cow::Borrowed(bytes) => match std::str::from_utf8(bytes) {
                Ok(text) => Cow::Borrowed(text),
                Err(_) => Cow::Owned(String::from_utf8_lossy(bytes).into_owned()),
            },
            Cow::Owned(bytes) => Cow::Owned(String::from_utf8_lossy(&bytes).into_owned()),
        };
        out.push(Entry { key, value });
    }
    out
}

/// Percent-decodes `input`, borrowing the original bytes when no escape or
/// plus-sign rewrite is required.
fn percent_decode(input: &[u8], plus_as_space: bool) -> Cow<'_, [u8]> {
    let needs_decode = input
        .iter()
        .any(|byte| *byte == b'%' || (plus_as_space && *byte == b'+'));
    if !needs_decode {
        return Cow::Borrowed(input);
    }
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        let byte = input[i];
        if byte == b'%' {
            if i + 2 < input.len()
                && input[i + 1].is_ascii_hexdigit()
                && input[i + 2].is_ascii_hexdigit()
            {
                out.push((hex_value(input[i + 1]) << 4) | hex_value(input[i + 2]));
                i += 3;
                continue;
            }
            out.push(byte);
            i += 1;
            continue;
        }
        if plus_as_space && byte == b'+' {
            out.push(b' ');
        } else {
            out.push(byte);
        }
        i += 1;
    }
    Cow::Owned(out)
}

fn hex_value(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => 0,
    }
}

fn content_type_boundary(value: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(value);
    for part in split_quoted(&text, ';') {
        let part = part.trim();
        if let Some((name, value)) = part.split_once('=') {
            if name.trim().eq_ignore_ascii_case("boundary") {
                let value = value.trim();
                let value = value
                    .strip_prefix('"')
                    .and_then(|value| value.strip_suffix('"'))
                    .unwrap_or(value);
                return Some(value.to_string());
            }
        }
    }
    None
}

/// Splits on `separator` while ignoring separators inside quoted strings.
fn split_quoted(text: &str, separator: char) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for ch in text.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
            continue;
        }
        if ch == '\\' {
            current.push(ch);
            escaped = true;
            continue;
        }
        match quote {
            Some(active) => {
                current.push(ch);
                if ch == active {
                    quote = None;
                }
            }
            None => {
                if ch == '"' || ch == '\'' {
                    quote = Some(ch);
                    current.push(ch);
                } else if ch == separator {
                    out.push(std::mem::take(&mut current));
                } else {
                    current.push(ch);
                }
            }
        }
    }
    out.push(current);
    out
}

fn split_part_headers(part: &[u8]) -> (&[u8], &[u8]) {
    if let Some(index) = find_bytes(part, b"\r\n\r\n") {
        return (&part[..index], &part[index + 4..]);
    }
    if let Some(index) = find_bytes(part, b"\n\n") {
        return (&part[..index], &part[index + 2..]);
    }
    (&[], part)
}

fn parse_part_headers(header_bytes: &[u8]) -> Vec<(String, String)> {
    let text = String::from_utf8_lossy(header_bytes);
    let mut headers = Vec::new();
    for line in text.split('\n') {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_string(), value.trim().to_string()));
        }
    }
    headers
}

fn disposition_fields(headers: &[(String, String)]) -> (Option<String>, Option<String>) {
    let Some((_, value)) = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-disposition"))
    else {
        return (None, None);
    };
    let mut name = None;
    let mut filename = None;
    for part in split_quoted(value, ';') {
        let part = part.trim();
        if let Some((key, value)) = part.split_once('=') {
            let value = value.trim().trim_matches('"');
            if key.trim().eq_ignore_ascii_case("name") {
                name = Some(value.to_string());
            } else if key.trim().eq_ignore_ascii_case("filename") {
                filename = Some(value.to_string());
            }
        }
    }
    (name, filename)
}

fn trim_trailing_crlf(part: &[u8]) -> &[u8] {
    if let Some(stripped) = part.strip_suffix(b"\r\n") {
        stripped
    } else if let Some(stripped) = part.strip_suffix(b"\n") {
        stripped
    } else {
        part
    }
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

struct ParsedUri<'a> {
    request_uri: Cow<'a, [u8]>,
    path: Cow<'a, [u8]>,
    basename: Cow<'a, [u8]>,
    query: Cow<'a, [u8]>,
    valid: bool,
}

impl<'a> ParsedUri<'a> {
    /// Mirrors `net/url.ParseRequestURI` + `(*url.URL).String()` for the parts
    /// Coraza exposes as `REQUEST_URI`, `REQUEST_FILENAME` and `QUERY_STRING`.
    fn parse(uri: &'a str) -> Self {
        let without_fragment = match uri.find('#') {
            Some(index) => &uri[..index],
            None => uri,
        };
        if without_fragment.is_empty()
            || without_fragment
                .bytes()
                .any(|byte| byte < 0x20 || byte == 0x7f)
        {
            return Self::invalid(without_fragment);
        }
        if without_fragment == "*" {
            return Self {
                request_uri: Cow::Borrowed(b"*"),
                path: Cow::Borrowed(b"*"),
                basename: Cow::Borrowed(b"*"),
                query: Cow::Borrowed(&[]),
                valid: true,
            };
        }

        let (scheme, rest) = split_scheme(without_fragment);
        let scheme = scheme.to_ascii_lowercase();
        let (rest, query, force_query) = split_query(rest);

        if !rest.starts_with('/') {
            if !scheme.is_empty() {
                // RFC 3986 opaque path, e.g. `mailto:x` / `host:80`.
                let mut request_uri = String::with_capacity(scheme.len() + 1 + rest.len());
                request_uri.push_str(&scheme);
                request_uri.push(':');
                request_uri.push_str(rest);
                append_query(&mut request_uri, query, force_query);
                return Self {
                    request_uri: Cow::Owned(request_uri.into_bytes()),
                    path: Cow::Borrowed(&[]),
                    basename: Cow::Borrowed(&[]),
                    query: Cow::Borrowed(query.as_bytes()),
                    valid: true,
                };
            }
            return Self::invalid(without_fragment);
        }

        // A scheme plus `//` is an authority; without a scheme, `//foo` is a
        // path for request URIs (`viaRequest` in net/url).
        let (host, path_raw) = if !scheme.is_empty() && rest.starts_with("//") {
            let rest = &rest[2..];
            match rest.find('/') {
                Some(index) => (&rest[..index], &rest[index..]),
                None => (rest, ""),
            }
        } else {
            ("", rest)
        };

        let Some(path) = decode_path(path_raw.as_bytes()) else {
            return Self::invalid(without_fragment);
        };
        let escaped = if encoded_path_is_valid(path_raw.as_bytes()) {
            path_raw.to_string()
        } else {
            escape_path(&path)
        };

        let path: Cow<'a, [u8]> = Cow::Owned(path);
        let basename = basename_cow(path.clone());
        let request_uri = if scheme.is_empty() && escaped == path_raw && !force_query {
            // The common origin-form case: Go's String() is byte-identical to
            // the wire request target, so keep it zero-copy.
            Cow::Borrowed(without_fragment.as_bytes())
        } else {
            let mut request_uri =
                String::with_capacity(scheme.len() + host.len() + escaped.len() + 2);
            if !scheme.is_empty() {
                request_uri.push_str(&scheme);
                request_uri.push_str("://");
                request_uri.push_str(host);
            }
            request_uri.push_str(&escaped);
            append_query(&mut request_uri, query, force_query);
            Cow::Owned(request_uri.into_bytes())
        };
        Self {
            request_uri,
            path,
            basename,
            query: Cow::Borrowed(query.as_bytes()),
            valid: true,
        }
    }

    fn invalid(raw: &'a str) -> Self {
        let bytes = raw.as_bytes();
        Self {
            request_uri: Cow::Borrowed(bytes),
            path: Cow::Borrowed(bytes),
            basename: basename(bytes),
            query: Cow::Borrowed(&[]),
            valid: false,
        }
    }
}

/// Splits the leading RFC 3986 scheme (`alpha *( alpha / digit / "+" / "-" /
/// "." )`) when it is followed by `:`. Returns `("", uri)` otherwise.
fn split_scheme(uri: &str) -> (&str, &str) {
    let bytes = uri.as_bytes();
    if !bytes.first().is_some_and(u8::is_ascii_alphabetic) {
        return ("", uri);
    }
    let mut index = 1;
    while index < bytes.len()
        && (bytes[index].is_ascii_alphanumeric() || matches!(bytes[index], b'+' | b'-' | b'.'))
    {
        index += 1;
    }
    if bytes.get(index) == Some(&b':') {
        (&uri[..index], &uri[index + 1..])
    } else {
        ("", uri)
    }
}

/// Go splits a lone trailing `?` into `ForceQuery`.
fn split_query(rest: &str) -> (&str, &str, bool) {
    if rest.ends_with('?') && rest.bytes().filter(|byte| *byte == b'?').count() == 1 {
        return (&rest[..rest.len() - 1], "", true);
    }
    match rest.find('?') {
        Some(index) => (&rest[..index], &rest[index + 1..], false),
        None => (rest, "", false),
    }
}

fn append_query(out: &mut String, query: &str, force: bool) {
    if force || !query.is_empty() {
        out.push('?');
        out.push_str(query);
    }
}

/// Strict path unescape: invalid `%` escapes make `ParseRequestURI` fail.
fn decode_path(raw: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(raw.len());
    let mut index = 0;
    while index < raw.len() {
        if raw[index] == b'%' {
            let high = *raw.get(index + 1)?;
            let low = *raw.get(index + 2)?;
            if !high.is_ascii_hexdigit() || !low.is_ascii_hexdigit() {
                return None;
            }
            out.push((hex_value(high) << 4) | hex_value(low));
            index += 3;
            continue;
        }
        out.push(raw[index]);
        index += 1;
    }
    Some(out)
}

/// True when `raw` is already a valid `encodePath` encoding: every byte is
/// permitted and every `%` is followed by two hex digits. This is the
/// condition under which Go's `URL.String()` keeps `RawPath` verbatim.
fn encoded_path_is_valid(raw: &[u8]) -> bool {
    let mut index = 0;
    while index < raw.len() {
        if raw[index] == b'%' {
            if index + 2 >= raw.len()
                || !raw[index + 1].is_ascii_hexdigit()
                || !raw[index + 2].is_ascii_hexdigit()
            {
                return false;
            }
            index += 3;
            continue;
        }
        if !path_byte_allowed(raw[index]) {
            return false;
        }
        index += 1;
    }
    true
}

/// Bytes Go leaves unescaped under `encodePath`.
fn path_byte_allowed(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'-' | b'_'
                | b'.'
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
                | b'/'
                | b':'
                | b';'
                | b'='
                | b'@'
        )
}

fn escape_path(path: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(path.len());
    for byte in path {
        if path_byte_allowed(*byte) {
            out.push(*byte as char);
        } else {
            out.push('%');
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
    }
    out
}

fn basename(path: &[u8]) -> Cow<'_, [u8]> {
    let index = path
        .iter()
        .rposition(|byte| *byte == b'/' || *byte == b'\\');
    match index {
        Some(index) if index + 1 < path.len() => Cow::Borrowed(&path[index + 1..]),
        _ => Cow::Borrowed(path),
    }
}

fn basename_cow<'a>(path: Cow<'a, [u8]>) -> Cow<'a, [u8]> {
    let index = path
        .iter()
        .rposition(|byte| *byte == b'/' || *byte == b'\\');
    let start = match index {
        Some(index) if index + 1 < path.len() => index + 1,
        _ => 0,
    };
    match path {
        Cow::Borrowed(bytes) => Cow::Borrowed(&bytes[start..]),
        Cow::Owned(bytes) => Cow::Owned(bytes[start..].to_vec()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_parsing_is_forgiving() {
        let entries = parse_query(b"a=1&b=hello+world&c=%zz", b'&');
        assert_eq!(entries[0].key, "a");
        assert_eq!(entries[0].value.as_ref(), b"1");
        assert_eq!(entries[1].value.as_ref(), b"hello world");
        assert_eq!(entries[2].value.as_ref(), b"%zz");
    }

    #[test]
    fn uri_parsing_matches_coraza_url_string() {
        let parsed = ParsedUri::parse("/get/demo.php?x=1");
        assert!(parsed.valid);
        assert_eq!(parsed.path.as_ref(), b"/get/demo.php");
        assert_eq!(parsed.basename.as_ref(), b"demo.php");
        assert_eq!(parsed.query.as_ref(), b"x=1");
        assert_eq!(parsed.request_uri.as_ref(), b"/get/demo.php?x=1");

        let spaced = ParsedUri::parse("/get with space?x=1");
        assert!(spaced.valid);
        assert_eq!(spaced.path.as_ref(), b"/get with space");
        assert_eq!(spaced.query.as_ref(), b"x=1");
        // Go's URL.String() re-encodes a raw space in the path.
        assert_eq!(spaced.request_uri.as_ref(), b"/get%20with%20space?x=1");

        let escaped = ParsedUri::parse("/get/%41%2f%5c?x=1");
        assert_eq!(escaped.path.as_ref(), b"/get/A/\\");
        // A valid RawPath is preserved verbatim.
        assert_eq!(escaped.request_uri.as_ref(), b"/get/%41%2f%5c?x=1");

        let invalid = ParsedUri::parse("CONNECT");
        assert!(!invalid.valid);
        assert_eq!(invalid.path.as_ref(), b"CONNECT");

        let absolute = ParsedUri::parse("http://Example.COM/a%20b?q=1");
        assert_eq!(absolute.path.as_ref(), b"/a b");
        assert_eq!(
            absolute.request_uri.as_ref(),
            b"http://Example.COM/a%20b?q=1"
        );

        let opaque = ParsedUri::parse("www.coreruleset.org:80");
        assert!(opaque.valid);
        assert_eq!(opaque.path.as_ref(), b"");
        assert_eq!(opaque.request_uri.as_ref(), b"www.coreruleset.org:80");

        let authority = ParsedUri::parse("http://localhost");
        assert_eq!(authority.path.as_ref(), b"");
        assert_eq!(authority.request_uri.as_ref(), b"http://localhost");

        let double_slash = ParsedUri::parse("//host/path");
        assert_eq!(double_slash.path.as_ref(), b"//host/path");

        let broken_escape = ParsedUri::parse("/a%zz");
        assert!(!broken_escape.valid);
        assert_eq!(broken_escape.path.as_ref(), b"/a%zz");
    }

    #[test]
    fn macros_expand_tx_and_matched_values() {
        let request = EngineRequest {
            method: "GET",
            uri: "/",
            http_version: "HTTP/1.1",
            headers: &[],
            body: None,
        };
        let mut budget = Budget::new(super::super::budget::Limits::default());
        let mut collections = Collections::new(&request, &mut budget).expect("collections");
        collections.tx_set("foo", b"bar".to_vec());
        collections.record_match(Collection::Args, Some("x"), b"value");
        let mut out = Vec::new();
        collections.expand_into("%{tx.foo}", &mut out);
        assert_eq!(out.as_slice(), b"bar");
        collections.expand_into("%{MATCHED_VAR}", &mut out);
        assert_eq!(out.as_slice(), b"value");
        collections.expand_into("%{matched_var_name}", &mut out);
        assert_eq!(out.as_slice(), b"ARGS:x");
    }
}
