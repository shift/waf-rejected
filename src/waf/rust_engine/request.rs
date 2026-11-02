//! Request collections and macro expansion.
//!
//! The collection model mirrors the subset of Coraza that the pinned CRS uses
//! when driven by the WASI reactor: `ProcessURI`, request headers, cookies and
//! the body processors selected by `Content-Type`. `REMOTE_ADDR` and
//! `UNIQUE_ID` are intentionally empty because the reactor never calls
//! `ProcessConnection` and the host does not supply them.

use std::collections::BTreeMap;

use super::budget::Budget;
use super::error::EngineError;
use super::ir::{Collection, Selector, VariableSpec};
use super::operators::MacroResolver;

/// One key/value pair in a keyed collection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub key: String,
    pub value: Vec<u8>,
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
#[derive(Debug, Clone)]
pub struct ResolvedValue {
    pub collection: Collection,
    pub key: Option<String>,
    pub value: Vec<u8>,
}

impl ResolvedValue {
    fn new(collection: Collection, key: Option<String>, value: Vec<u8>) -> Self {
        Self {
            collection,
            key,
            value,
        }
    }

    /// Name used by `MATCHED_VAR_NAME`, e.g. `ARGS:id` or `REQUEST_URI`.
    pub fn matched_name(&self) -> String {
        match &self.key {
            Some(key) => format!("{}:{}", self.collection.name(), key),
            None => self.collection.name().to_string(),
        }
    }
}

/// Request state for one transaction.
#[derive(Debug, Clone)]
pub struct Collections {
    tx: BTreeMap<String, (String, Vec<u8>)>,
    args_get: Vec<Entry>,
    args_post: Vec<Entry>,
    headers: Vec<Entry>,
    cookies: Vec<Entry>,
    files: Vec<Entry>,
    files_names: Vec<Entry>,
    files_sizes: Vec<Entry>,
    multipart_part_headers: Vec<Entry>,

    request_uri: Vec<u8>,
    request_uri_raw: Vec<u8>,
    request_method: Vec<u8>,
    request_body: Option<Vec<u8>>,
    request_filename: Vec<u8>,
    request_basename: Vec<u8>,
    request_line: Vec<u8>,
    request_protocol: Vec<u8>,
    query_string: Vec<u8>,
    files_combined_size: usize,

    reqbody_processor: String,
    request_body_processor_override: Option<String>,
    force_request_body_variable: bool,
    body_processed: bool,

    captures: [Vec<u8>; super::operators::MAX_CAPTURES],
    matched_var: Vec<u8>,
    matched_var_name: Vec<u8>,
    matched_vars: Vec<(String, Vec<u8>)>,
}

impl Collections {
    /// Builds the phase-1 collection view from the request line and headers.
    pub fn new(request: &EngineRequest<'_>, budget: &mut Budget) -> Result<Self, EngineError> {
        let parsed = ParsedUri::parse(request.uri);
        let mut headers = Vec::with_capacity(request.headers.len());
        let mut reqbody_processor = String::new();
        for (name, value) in request.headers {
            headers.push(Entry {
                key: name.clone(),
                value: value.as_bytes().to_vec(),
            });
            if name.eq_ignore_ascii_case("content-type") {
                let lower = value.to_ascii_lowercase();
                if lower == "application/x-www-form-urlencoded" {
                    reqbody_processor = "URLENCODED".to_string();
                } else if lower.starts_with("multipart/form-data") {
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
            parse_query(&parsed.query, b'&')
        } else {
            Vec::new()
        };

        let collections = Self {
            tx: BTreeMap::new(),
            args_get,
            args_post: Vec::new(),
            headers,
            cookies,
            files: Vec::new(),
            files_names: Vec::new(),
            files_sizes: Vec::new(),
            multipart_part_headers: Vec::new(),
            request_uri: parsed.request_uri,
            request_uri_raw: request.uri.as_bytes().to_vec(),
            request_method: request.method.as_bytes().to_vec(),
            request_body: None,
            request_filename: parsed.path,
            request_basename: parsed.basename,
            request_line: format!(
                "{} {} {}",
                request.method, request.uri, request.http_version
            )
            .into_bytes(),
            request_protocol: request.http_version.as_bytes().to_vec(),
            query_string: parsed.query,
            files_combined_size: 0,
            reqbody_processor,
            request_body_processor_override: None,
            force_request_body_variable: false,
            body_processed: false,
            captures: std::array::from_fn(|_| Vec::new()),
            matched_var: Vec::new(),
            matched_var_name: Vec::new(),
            matched_vars: Vec::new(),
        };
        budget.bytes(
            collections.request_uri.len()
                + collections.request_uri_raw.len()
                + collections.request_method.len()
                + collections.request_filename.len()
                + collections.request_basename.len()
                + collections.request_line.len()
                + collections.request_protocol.len()
                + collections.query_string.len(),
        )?;
        Ok(collections)
    }

    /// Runs the body processor selected by `Content-Type` (and by `ctl` during
    /// phase 1), exactly like `Transaction::ProcessRequestBody`.
    pub fn process_body(
        &mut self,
        request: &EngineRequest<'_>,
        budget: &mut Budget,
    ) -> Result<(), EngineError> {
        if self.body_processed {
            return Ok(());
        }
        self.body_processed = true;
        let Some(body) = request.body else {
            return Ok(());
        };
        if body.is_empty() {
            return Ok(());
        }

        let mut processor = self
            .request_body_processor_override
            .take()
            .unwrap_or_else(|| self.reqbody_processor.clone());
        if self.force_request_body_variable && processor.is_empty() {
            processor = "URLENCODED".to_string();
        }
        self.reqbody_processor = processor.clone();
        budget.bytes(body.len())?;

        match processor.to_ascii_lowercase().as_str() {
            "urlencoded" => {
                self.args_post = parse_query(body, b'&');
                self.request_body = Some(body.to_vec());
            }
            "multipart" => {
                self.parse_multipart(body, budget)?;
            }
            _ => {}
        }
        Ok(())
    }

    fn parse_multipart(&mut self, body: &[u8], budget: &mut Budget) -> Result<(), EngineError> {
        let boundary = self
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
                self.multipart_part_headers.push(Entry {
                    key: name.clone(),
                    value: format!("{header_name}: {header_value}").into_bytes(),
                });
            }
            if let Some(filename) = filename {
                self.files.push(Entry {
                    key: String::new(),
                    value: filename.clone().into_bytes(),
                });
                self.files_names.push(Entry {
                    key: String::new(),
                    value: name.clone().into_bytes(),
                });
                self.files_sizes.push(Entry {
                    key: filename,
                    value: value.len().to_string().into_bytes(),
                });
                self.files_combined_size += value.len();
            } else {
                self.args_post.push(Entry {
                    key: name,
                    value: value.to_vec(),
                });
            }
            budget.bytes(value.len())?;
        }
        Ok(())
    }

    /// Returns the TX value, case-insensitive.
    pub fn tx_get(&self, name: &str) -> Option<&[u8]> {
        self.tx
            .get(&name.to_ascii_lowercase())
            .map(|(_, value)| value.as_slice())
    }

    /// Sets a TX value.
    pub fn tx_set(&mut self, name: &str, value: Vec<u8>) {
        let lower = name.to_ascii_lowercase();
        self.tx.insert(lower, (name.to_string(), value));
    }

    /// Adds to a TX value. Numeric values are added numerically; otherwise the
    /// new value is appended, matching ModSecurity's `+` setvar semantics.
    pub fn tx_add(&mut self, name: &str, value: &[u8]) {
        let existing = self.tx_get(name).map(ToOwned::to_owned);
        let next = match existing {
            None => value.to_vec(),
            Some(current) => {
                if let (Some(left), Some(right)) = (parse_i64(&current), parse_i64(value)) {
                    left.saturating_add(right).to_string().into_bytes()
                } else {
                    let mut combined = current;
                    combined.extend_from_slice(value);
                    combined
                }
            }
        };
        self.tx_set(name, next);
    }

    /// Subtracts from a TX value.
    pub fn tx_sub(&mut self, name: &str, value: &[u8]) {
        let existing = self.tx_get(name).map(ToOwned::to_owned).unwrap_or_default();
        let left = parse_i64(&existing).unwrap_or(0);
        let right = parse_i64(value).unwrap_or(0);
        self.tx_set(name, left.saturating_sub(right).to_string().into_bytes());
    }

    /// Removes a TX value.
    pub fn tx_remove(&mut self, name: &str) {
        self.tx.remove(&name.to_ascii_lowercase());
    }

    /// Stores a regex capture in `TX:n` and the capture array.
    pub fn set_capture(&mut self, index: usize, value: Vec<u8>) {
        if index < self.captures.len() {
            self.tx_set(&index.to_string(), value.clone());
            self.captures[index] = value;
        }
    }

    /// Clears capture slots.
    pub fn clear_captures(&mut self) {
        for slot in &mut self.captures {
            slot.clear();
        }
    }

    /// Records a matched variable for `MATCHED_VAR*`.
    pub fn record_match(&mut self, name: String, value: Vec<u8>) {
        self.matched_var = value.clone();
        self.matched_var_name = name.as_bytes().to_vec();
        self.matched_vars.push((name, value));
    }

    /// Clears the per-rule matched-variable state.
    pub fn clear_matches(&mut self) {
        self.matched_var.clear();
        self.matched_var_name.clear();
        self.matched_vars.clear();
    }

    /// Returns the body processor name exposed as `REQBODY_PROCESSOR`.
    pub fn reqbody_processor(&self) -> &str {
        &self.reqbody_processor
    }

    /// Applies a `ctl:requestBodyProcessor=...` override.
    pub fn set_request_body_processor(&mut self, processor: String) {
        self.request_body_processor_override = Some(processor);
    }

    /// Applies `ctl:forceRequestBodyVariable=...`.
    pub fn set_force_request_body_variable(&mut self, force: bool) {
        self.force_request_body_variable = force;
    }

    /// Resolves one variable spec into values.
    pub fn resolve(
        &self,
        spec: &VariableSpec,
        budget: &mut Budget,
    ) -> Result<Vec<ResolvedValue>, EngineError> {
        let mut values = match spec.collection {
            Collection::Args => self.keyed(
                Collection::Args,
                &self.args_get,
                &self.args_post,
                &spec.selector,
                budget,
            )?,
            Collection::ArgsGet => self.keyed(
                Collection::ArgsGet,
                &self.args_get,
                &[],
                &spec.selector,
                budget,
            )?,
            Collection::ArgsPost => self.keyed(
                Collection::ArgsPost,
                &self.args_post,
                &[],
                &spec.selector,
                budget,
            )?,
            Collection::ArgsNames => self.names(
                Collection::ArgsNames,
                &self.args_get,
                &self.args_post,
                &spec.selector,
                budget,
            )?,
            Collection::ArgsGetNames => self.names(
                Collection::ArgsGetNames,
                &self.args_get,
                &[],
                &spec.selector,
                budget,
            )?,
            Collection::ArgsPostNames => self.names(
                Collection::ArgsPostNames,
                &self.args_post,
                &[],
                &spec.selector,
                budget,
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
                    size.to_string().into_bytes(),
                    budget,
                )?
            }
            Collection::RequestHeaders => self.keyed(
                Collection::RequestHeaders,
                &self.headers,
                &[],
                &spec.selector,
                budget,
            )?,
            Collection::RequestHeadersNames => self.names(
                Collection::RequestHeadersNames,
                &self.headers,
                &[],
                &spec.selector,
                budget,
            )?,
            Collection::RequestCookies => self.keyed(
                Collection::RequestCookies,
                &self.cookies,
                &[],
                &spec.selector,
                budget,
            )?,
            Collection::RequestCookiesNames => self.names(
                Collection::RequestCookiesNames,
                &self.cookies,
                &[],
                &spec.selector,
                budget,
            )?,
            Collection::RequestUri => {
                self.single(Collection::RequestUri, self.request_uri.clone(), budget)?
            }
            Collection::RequestUriRaw => self.single(
                Collection::RequestUriRaw,
                self.request_uri_raw.clone(),
                budget,
            )?,
            Collection::RequestMethod => self.single(
                Collection::RequestMethod,
                self.request_method.clone(),
                budget,
            )?,
            Collection::RequestBody => self.single(
                Collection::RequestBody,
                self.request_body.clone().unwrap_or_default(),
                budget,
            )?,
            Collection::RequestBodyLength => {
                let length = self.request_body.as_ref().map_or(0, Vec::len);
                self.single(
                    Collection::RequestBodyLength,
                    length.to_string().into_bytes(),
                    budget,
                )?
            }
            Collection::RequestFilename => self.single(
                Collection::RequestFilename,
                self.request_filename.clone(),
                budget,
            )?,
            Collection::RequestBasename => self.single(
                Collection::RequestBasename,
                self.request_basename.clone(),
                budget,
            )?,
            Collection::RequestLine => {
                self.single(Collection::RequestLine, self.request_line.clone(), budget)?
            }
            Collection::RequestProtocol => self.single(
                Collection::RequestProtocol,
                self.request_protocol.clone(),
                budget,
            )?,
            Collection::QueryString => {
                self.single(Collection::QueryString, self.query_string.clone(), budget)?
            }
            Collection::Tx => self.tx_values(&spec.selector, budget)?,
            Collection::MatchedVars => self.matched_values(false, budget)?,
            Collection::MatchedVarsNames => self.matched_values(true, budget)?,
            Collection::Xml => Vec::new(),
            Collection::Files => {
                self.keyed(Collection::Files, &self.files, &[], &spec.selector, budget)?
            }
            Collection::FilesNames => self.keyed(
                Collection::FilesNames,
                &self.files_names,
                &[],
                &spec.selector,
                budget,
            )?,
            Collection::FilesSizes => self.keyed(
                Collection::FilesSizes,
                &self.files_sizes,
                &[],
                &spec.selector,
                budget,
            )?,
            Collection::FilesCombinedSize => self.single(
                Collection::FilesCombinedSize,
                self.files_combined_size.to_string().into_bytes(),
                budget,
            )?,
            Collection::MultipartPartHeaders => self.keyed(
                Collection::MultipartPartHeaders,
                &self.multipart_part_headers,
                &[],
                &spec.selector,
                budget,
            )?,
            Collection::ReqbodyProcessor => self.single(
                Collection::ReqbodyProcessor,
                self.reqbody_processor.clone().into_bytes(),
                budget,
            )?,
            Collection::RemoteAddr => self.single(Collection::RemoteAddr, Vec::new(), budget)?,
            Collection::UniqueId => self.single(Collection::UniqueId, Vec::new(), budget)?,
            Collection::Rule | Collection::Global | Collection::Ip => Vec::new(),
        };

        if spec.count {
            let count = values.len().to_string().into_bytes();
            budget.value()?;
            budget.bytes(count.len())?;
            values = vec![ResolvedValue::new(spec.collection, None, count)];
        }
        Ok(values)
    }

    fn single(
        &self,
        collection: Collection,
        value: Vec<u8>,
        budget: &mut Budget,
    ) -> Result<Vec<ResolvedValue>, EngineError> {
        budget.value()?;
        budget.bytes(value.len())?;
        Ok(vec![ResolvedValue::new(collection, None, value)])
    }

    fn keyed(
        &self,
        collection: Collection,
        first: &[Entry],
        second: &[Entry],
        selector: &Selector,
        budget: &mut Budget,
    ) -> Result<Vec<ResolvedValue>, EngineError> {
        let mut values = Vec::new();
        for entry in first.iter().chain(second.iter()) {
            if !selector_matches(selector, &entry.key) {
                continue;
            }
            budget.value()?;
            budget.bytes(entry.value.len())?;
            values.push(ResolvedValue::new(
                collection,
                Some(entry.key.clone()),
                entry.value.clone(),
            ));
        }
        Ok(values)
    }

    fn names(
        &self,
        collection: Collection,
        first: &[Entry],
        second: &[Entry],
        selector: &Selector,
        budget: &mut Budget,
    ) -> Result<Vec<ResolvedValue>, EngineError> {
        let mut values = Vec::new();
        for entry in first.iter().chain(second.iter()) {
            if !selector_matches(selector, &entry.key) {
                continue;
            }
            budget.value()?;
            budget.bytes(entry.key.len())?;
            values.push(ResolvedValue::new(
                collection,
                Some(entry.key.clone()),
                entry.key.as_bytes().to_vec(),
            ));
        }
        Ok(values)
    }

    fn tx_values(
        &self,
        selector: &Selector,
        budget: &mut Budget,
    ) -> Result<Vec<ResolvedValue>, EngineError> {
        let mut values = Vec::new();
        for (original, value) in self.tx.values() {
            if !selector_matches(selector, original) {
                continue;
            }
            budget.value()?;
            budget.bytes(value.len())?;
            values.push(ResolvedValue::new(
                Collection::Tx,
                Some(original.clone()),
                value.clone(),
            ));
        }
        Ok(values)
    }

    fn matched_values(
        &self,
        names_only: bool,
        budget: &mut Budget,
    ) -> Result<Vec<ResolvedValue>, EngineError> {
        let collection = if names_only {
            Collection::MatchedVarsNames
        } else {
            Collection::MatchedVars
        };
        let mut values = Vec::new();
        for (name, value) in &self.matched_vars {
            let value = if names_only {
                name.as_bytes().to_vec()
            } else {
                value.clone()
            };
            budget.value()?;
            budget.bytes(value.len())?;
            values.push(ResolvedValue::new(collection, Some(name.clone()), value));
        }
        Ok(values)
    }
}

impl MacroResolver for Collections {
    fn expand(&self, template: &str) -> Vec<u8> {
        let mut out = Vec::with_capacity(template.len());
        let bytes = template.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%' && i + 1 < bytes.len() && bytes[i + 1] == b'{' {
                if let Some(end) = template[i + 2..].find('}') {
                    let name = &template[i + 2..i + 2 + end];
                    out.extend_from_slice(&self.expand_macro_name(name));
                    i += 2 + end + 1;
                    continue;
                }
            }
            out.push(bytes[i]);
            i += 1;
        }
        out
    }
}

impl Collections {
    fn expand_macro_name(&self, name: &str) -> Vec<u8> {
        let lower = name.to_ascii_lowercase();
        if let Some(key) = lower.strip_prefix("tx.") {
            return self.tx_get(key).map(ToOwned::to_owned).unwrap_or_default();
        }
        if lower == "matched_var" {
            return self.matched_var.clone();
        }
        if lower == "matched_var_name" {
            return self.matched_var_name.clone();
        }
        if let Some((collection, key)) = name.split_once('.') {
            match collection.to_ascii_lowercase().as_str() {
                "args" => {
                    return find_entry(&self.args_get, key)
                        .or_else(|| find_entry(&self.args_post, key))
                        .map(|entry| entry.value.clone())
                        .unwrap_or_default();
                }
                "args_get" => {
                    return find_entry(&self.args_get, key)
                        .map(|entry| entry.value.clone())
                        .unwrap_or_default();
                }
                "args_post" => {
                    return find_entry(&self.args_post, key)
                        .map(|entry| entry.value.clone())
                        .unwrap_or_default();
                }
                "request_headers" => {
                    return self
                        .headers
                        .iter()
                        .find(|header| header.key.eq_ignore_ascii_case(key))
                        .map(|header| header.value.clone())
                        .unwrap_or_default();
                }
                "request_cookies" => {
                    return find_entry(&self.cookies, key)
                        .map(|entry| entry.value.clone())
                        .unwrap_or_default();
                }
                "rule" => {
                    return Vec::new();
                }
                _ => {}
            }
        }
        match lower.as_str() {
            "request_uri" => self.request_uri.clone(),
            "request_uri_raw" => self.request_uri_raw.clone(),
            "request_method" => self.request_method.clone(),
            "request_body" => self.request_body.clone().unwrap_or_default(),
            "request_filename" => self.request_filename.clone(),
            "request_basename" => self.request_basename.clone(),
            "request_line" => self.request_line.clone(),
            "request_protocol" => self.request_protocol.clone(),
            "query_string" => self.query_string.clone(),
            "remote_addr" | "unique_id" => Vec::new(),
            _ => Vec::new(),
        }
    }
}

fn find_entry<'a>(entries: &'a [Entry], key: &str) -> Option<&'a Entry> {
    entries
        .iter()
        .find(|entry| entry.key.eq_ignore_ascii_case(key))
}

fn selector_matches(selector: &Selector, key: &str) -> bool {
    match selector {
        Selector::All => true,
        Selector::Key(expected) => key.eq_ignore_ascii_case(expected),
        Selector::Regex(regex) => regex.is_match(&key.to_ascii_lowercase()),
    }
}

fn parse_i64(value: &[u8]) -> Option<i64> {
    std::str::from_utf8(value).ok()?.trim().parse().ok()
}

fn parse_cookies(value: &[u8], out: &mut Vec<Entry>) {
    let text = String::from_utf8_lossy(value);
    for part in split_quoted(&text, ';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (key, value) = part.split_once('=').unwrap_or((part, ""));
        out.push(Entry {
            key: key.trim().to_string(),
            value: value.trim().as_bytes().to_vec(),
        });
    }
}

/// Parses `application/x-www-form-urlencoded` data with Coraza's forgiving
/// rules (invalid escapes are preserved).
pub fn parse_query(query: &[u8], separator: u8) -> Vec<Entry> {
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
        out.push(Entry {
            key: String::from_utf8_lossy(&key).into_owned(),
            value,
        });
    }
    out
}

fn percent_decode(input: &[u8], plus_as_space: bool) -> Vec<u8> {
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
    out
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

struct ParsedUri {
    request_uri: Vec<u8>,
    path: Vec<u8>,
    basename: Vec<u8>,
    query: Vec<u8>,
    valid: bool,
}

impl ParsedUri {
    fn parse(uri: &str) -> Self {
        let without_fragment = match uri.find('#') {
            Some(index) => &uri[..index],
            None => uri,
        };
        if !is_valid_request_uri(without_fragment) {
            return Self {
                request_uri: without_fragment.as_bytes().to_vec(),
                path: without_fragment.as_bytes().to_vec(),
                basename: basename(without_fragment.as_bytes()),
                query: Vec::new(),
                valid: false,
            };
        }
        let target = request_target(without_fragment);
        let (path_raw, query_raw) = match target.find('?') {
            Some(index) => (&target[..index], &target[index + 1..]),
            None => (target, ""),
        };
        let path = percent_decode(path_raw.as_bytes(), false);
        Self {
            request_uri: without_fragment.as_bytes().to_vec(),
            basename: basename(&path),
            path,
            query: query_raw.as_bytes().to_vec(),
            valid: true,
        }
    }
}

/// Mirrors the parts of `net/url.ParseRequestURI` that change Coraza's
/// collection values: control bytes and invalid path escapes are rejected;
/// spaces, backslashes and invalid query escapes are accepted.
fn is_valid_request_uri(uri: &str) -> bool {
    if uri.bytes().any(|byte| byte < 0x20 || byte == 0x7f) {
        return false;
    }
    if uri.is_empty() {
        return false;
    }
    if !(uri.starts_with('/') || uri == "*" || uri.starts_with("//") || has_scheme(uri)) {
        return false;
    }
    let target = request_target(uri);
    let path = target.split('?').next().unwrap_or(target);
    valid_percent_escapes(path.as_bytes())
}

/// Returns the request target after a leading scheme+authority or `//`
/// authority. A `://` later in the query is not a scheme.
fn request_target(uri: &str) -> &str {
    if let Some(rest) = uri.strip_prefix("//") {
        return match rest.find('/') {
            Some(slash) => &rest[slash..],
            None => "/",
        };
    }
    if has_scheme(uri) {
        let index = uri.find("://").unwrap_or(0);
        let after_scheme = &uri[index + 3..];
        return match after_scheme.find('/') {
            Some(slash) => &after_scheme[slash..],
            None => "/",
        };
    }
    uri
}

fn has_scheme(uri: &str) -> bool {
    let Some(index) = uri.find("://") else {
        return false;
    };
    let scheme = &uri[..index];
    !scheme.is_empty()
        && scheme
            .chars()
            .next()
            .is_some_and(|ch| ch.is_ascii_alphabetic())
        && scheme
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '-' | '.'))
}

fn valid_percent_escapes(value: &[u8]) -> bool {
    let mut i = 0;
    while i < value.len() {
        if value[i] == b'%' {
            if i + 2 >= value.len()
                || !value[i + 1].is_ascii_hexdigit()
                || !value[i + 2].is_ascii_hexdigit()
            {
                return false;
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    true
}

fn basename(path: &[u8]) -> Vec<u8> {
    let index = path
        .iter()
        .rposition(|byte| *byte == b'/' || *byte == b'\\');
    match index {
        Some(index) if index + 1 < path.len() => path[index + 1..].to_vec(),
        _ => path.to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_parsing_is_forgiving() {
        let entries = parse_query(b"a=1&b=hello+world&c=%zz", b'&');
        assert_eq!(entries[0].key, "a");
        assert_eq!(entries[0].value, b"1");
        assert_eq!(entries[1].value, b"hello world");
        assert_eq!(entries[2].value, b"%zz");
    }

    #[test]
    fn uri_parsing_matches_reactor_shape() {
        let parsed = ParsedUri::parse("/get/demo.php?x=1");
        assert!(parsed.valid);
        assert_eq!(parsed.path, b"/get/demo.php");
        assert_eq!(parsed.basename, b"demo.php");
        assert_eq!(parsed.query, b"x=1");

        let invalid = ParsedUri::parse("/get with space?x=1");
        assert!(invalid.valid);
        assert_eq!(invalid.path, b"/get with space");
        assert_eq!(invalid.query, b"x=1");

        let invalid = ParsedUri::parse("CONNECT");
        assert!(!invalid.valid);
        assert_eq!(invalid.path, b"CONNECT");
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
        collections.record_match("ARGS:x".to_string(), b"value".to_vec());
        assert_eq!(collections.expand("%{tx.foo}"), b"bar");
        assert_eq!(collections.expand("%{MATCHED_VAR}"), b"value");
        assert_eq!(collections.expand("%{matched_var_name}"), b"ARGS:x");
    }
}
