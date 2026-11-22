//! The egress fetch service: resolver, bounded fetcher, HTTP handler and
//! listener.
//!
//! This is intentionally *not* a CONNECT proxy. The service performs the
//! request itself, so it sees the plaintext response and can inspect it
//! without terminating TLS with a locally trusted CA.

use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::header::{CONTENT_TYPE, HOST, LOCATION, USER_AGENT};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;
use tracing::{error, info};

use super::rules::{
    check_content_type, check_ip, check_uri, effective_port, hidden_text_present, injection_marker,
    EgressPolicy, EG_BODY_TOO_LARGE, EG_INJECTION, HIDDEN_TEXT_MIN_CHARS,
};
use super::verdict::Verdict;
use crate::config::{Config, EgressConfig};
use crate::error::WafError;
use crate::metrics::Metrics;

/// Largest JSON request body accepted by the handler.
const MAX_REQUEST_BODY: usize = 64 * 1024;

/// Name resolution seam. Production uses [`SystemResolver`]; tests inject a
/// deterministic resolver so no SSRF test performs a real request.
#[async_trait]
pub trait EgressResolver: Send + Sync {
    async fn resolve(&self, host: &str, port: u16) -> std::io::Result<Vec<IpAddr>>;
}

/// Resolver backed by the OS (`tokio::net::lookup_host`).
pub struct SystemResolver;

#[async_trait]
impl EgressResolver for SystemResolver {
    async fn resolve(&self, host: &str, port: u16) -> std::io::Result<Vec<IpAddr>> {
        let addresses = tokio::net::lookup_host((host, port)).await?;
        Ok(addresses.map(|address| address.ip()).collect())
    }
}

/// One parsed fetch request.
#[derive(Debug, serde::Deserialize)]
struct FetchRequest {
    url: String,
    max_bytes: Option<usize>,
    timeout_ms: Option<u64>,
}

/// Result of one HTTP exchange (headers plus a bounded body).
struct Exchange {
    status: u16,
    location: Option<String>,
    content_type: Option<String>,
    body: Vec<u8>,
    truncated: bool,
}

/// Local fetch service. The TLS config is built once per service.
pub struct EgressService {
    policy: EgressPolicy,
    metrics: Arc<Metrics>,
    resolver: Arc<dyn EgressResolver>,
    tls: Arc<ClientConfig>,
}

impl std::fmt::Debug for EgressService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EgressService")
            .field("mode", &self.policy.mode)
            .field("max_bytes", &self.policy.max_bytes)
            .field("max_redirects", &self.policy.max_redirects)
            .finish()
    }
}

impl EgressService {
    /// Build the service from the full configuration.
    ///
    /// Returns `None` when `[egress].enabled` is false, so the server wiring
    /// leaves the edge listener untouched.
    pub fn maybe_from_config(config: &Config, metrics: Arc<Metrics>) -> Option<Self> {
        if !config.egress.enabled {
            return None;
        }
        Some(Self::from_egress_config(config.egress.clone(), metrics))
    }

    /// Build an enabled service from just the `[egress]` section.
    pub fn from_egress_config(egress: EgressConfig, metrics: Arc<Metrics>) -> Self {
        Self::with_parts(egress, metrics, Arc::new(SystemResolver), false)
    }

    /// Test-only constructor: resolves through `resolver` and permits loopback
    /// addresses so a local hyper server can stand in for the internet. Nothing
    /// else about the rule set changes.
    #[doc(hidden)]
    pub fn new_permissive_for_tests(
        egress: EgressConfig,
        metrics: Arc<Metrics>,
        resolver: Arc<dyn EgressResolver>,
    ) -> Self {
        Self::with_parts(egress, metrics, resolver, true)
    }

    fn with_parts(
        egress: EgressConfig,
        metrics: Arc<Metrics>,
        resolver: Arc<dyn EgressResolver>,
        allow_loopback: bool,
    ) -> Self {
        let mut policy = EgressPolicy::from_config(&egress);
        policy.allow_loopback = allow_loopback;

        // Bundled webpki roots: the laptop needs no local CA and no
        // certificate configuration.
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut tls =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .expect("ring provider supports TLS 1.2/1.3")
                .with_root_certificates(roots)
                .with_no_client_auth();
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];

        Self {
            policy,
            metrics,
            resolver,
            tls: Arc::new(tls),
        }
    }

    pub fn policy(&self) -> &EgressPolicy {
        &self.policy
    }

    /// Fetch one URL and return the verdict. Never panics: transport failures
    /// become `failed` verdicts.
    pub async fn fetch(&self, url: &str, max_bytes: usize, timeout: Duration) -> Verdict {
        let cap = max_bytes.max(1).min(self.policy.max_bytes);
        let budget = timeout.min(self.policy.timeout);

        let verdict = match tokio::time::timeout(budget, self.fetch_inner(url, cap)).await {
            Ok(verdict) => verdict,
            Err(_) => Verdict::failed(format!("fetch timed out after {} ms", budget.as_millis())),
        };

        self.metrics.record_egress_outcome(verdict.outcome.as_str());
        for id in &verdict.rule_ids {
            self.metrics.record_egress_rule(id);
        }
        verdict
    }

    async fn fetch_inner(&self, url: &str, cap: usize) -> Verdict {
        let mut current: Uri = match url.parse() {
            Ok(uri) => uri,
            Err(error) => return Verdict::failed(format!("invalid URL '{url}': {error}")),
        };
        let mut redirects = 0usize;

        loop {
            // Static checks run on every hop, including redirect targets.
            if let Some(hit) = check_uri(&current, &self.policy) {
                return Verdict::blocked(vec![hit.id], hit.message(), 0, false);
            }

            let Some(host) = current.host().map(|host| {
                host.trim_start_matches('[')
                    .trim_end_matches(']')
                    .to_string()
            }) else {
                return Verdict::failed("URL has no host".to_string());
            };
            let Some(port) = effective_port(&current) else {
                return Verdict::failed("URL has no port".to_string());
            };

            let address = match self.resolve_checked(&host, port).await {
                Ok(address) => address,
                Err(verdict) => return verdict,
            };

            let exchange = match self.exchange(&current, &host, address, cap).await {
                Ok(exchange) => exchange,
                Err(message) => return Verdict::failed(message),
            };

            if is_redirect(exchange.status) {
                if redirects >= self.policy.max_redirects {
                    return Verdict::failed(format!(
                        "stopped after {} redirects (egress.max_redirects = {})",
                        redirects, self.policy.max_redirects
                    ));
                }
                let Some(location) = exchange.location else {
                    return Verdict::failed(format!(
                        "redirect {} has no Location header",
                        exchange.status
                    ));
                };
                let Some(next) = resolve_location(&current, &location) else {
                    return Verdict::failed(format!(
                        "redirect Location '{location}' cannot be resolved against {current}"
                    ));
                };
                // The next iteration re-checks scheme/port/domain/credentials
                // and resolves the new host before it connects.
                current = next;
                redirects += 1;
                continue;
            }

            return self.inspect_response(exchange, cap);
        }
    }

    /// Resolve `host` and check every returned address. Metadata wins over the
    /// generic private-address rule; one bad address refuses the whole name.
    async fn resolve_checked(&self, host: &str, port: u16) -> Result<SocketAddr, Verdict> {
        let ips: Vec<IpAddr> = if let Ok(ip) = host.parse::<IpAddr>() {
            vec![ip]
        } else {
            match self.resolver.resolve(host, port).await {
                Ok(ips) => ips,
                Err(error) => {
                    return Err(Verdict::failed(format!(
                        "DNS resolution failed for '{host}': {error}"
                    )))
                }
            }
        };

        if ips.is_empty() {
            return Err(Verdict::failed(format!(
                "DNS resolution for '{host}' returned no addresses"
            )));
        }

        let mut chosen: Option<IpAddr> = None;
        let mut ids: Vec<&'static str> = Vec::new();
        let mut first_message: Option<String> = None;

        for ip in ips {
            match check_ip(ip, self.policy.allow_loopback) {
                Some(hit) => {
                    if !ids.contains(&hit.id) {
                        ids.push(hit.id);
                    }
                    if first_message.is_none() {
                        first_message = Some(hit.message());
                    }
                }
                None => {
                    if chosen.is_none() {
                        chosen = Some(ip);
                    }
                }
            }
        }

        if let Some(message) = first_message {
            return Err(Verdict::blocked(ids, message, 0, false));
        }

        let Some(ip) = chosen else {
            return Err(Verdict::failed(format!("no usable address for '{host}'")));
        };

        Ok(SocketAddr::new(ip, port))
    }

    /// Perform one HTTP/1.1 exchange against an already-checked address.
    async fn exchange(
        &self,
        uri: &Uri,
        host: &str,
        address: SocketAddr,
        cap: usize,
    ) -> Result<Exchange, String> {
        let tcp = TcpStream::connect(address)
            .await
            .map_err(|error| format!("connection to {address} failed: {error}"))?;

        if uri.scheme_str() == Some("https") {
            let server_name = ServerName::try_from(host.to_string())
                .map_err(|error| format!("invalid TLS server name '{host}': {error}"))?;
            let connector = TlsConnector::from(Arc::clone(&self.tls));
            let stream = connector
                .connect(server_name, tcp)
                .await
                .map_err(|error| format!("TLS handshake with '{host}' failed: {error}"))?;
            self.http1_exchange(TokioIo::new(stream), uri, cap).await
        } else {
            self.http1_exchange(TokioIo::new(tcp), uri, cap).await
        }
    }

    async fn http1_exchange<T>(&self, io: T, uri: &Uri, cap: usize) -> Result<Exchange, String>
    where
        T: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
    {
        let (mut sender, connection) = hyper::client::conn::http1::handshake(io)
            .await
            .map_err(|error| format!("HTTP/1.1 handshake failed: {error}"))?;
        tokio::task::spawn(async move {
            if let Err(error) = connection.await {
                tracing::debug!("egress connection closed: {error}");
            }
        });

        let path = uri
            .path_and_query()
            .map(|value| value.as_str())
            .unwrap_or("/");
        let authority = uri.authority().map(|value| value.as_str()).unwrap_or("");
        let request = Request::builder()
            .method(Method::GET)
            .uri(path)
            .header(HOST, authority)
            .header(USER_AGENT, "waf-ingress-egress/0.1")
            .header("accept", "*/*")
            .body(Empty::<Bytes>::new())
            .map_err(|error| format!("failed to build egress request: {error}"))?;

        let response = sender
            .send_request(request)
            .await
            .map_err(|error| format!("request to {uri} failed: {error}"))?;

        let status = response.status().as_u16();
        let location = header_value(response.headers(), LOCATION);
        let content_type = header_value(response.headers(), CONTENT_TYPE);

        let mut body = Vec::with_capacity(cap.min(64 * 1024));
        let mut truncated = false;
        let mut incoming = response.into_body();

        while let Some(frame) = incoming.frame().await {
            let frame = frame.map_err(|error| format!("reading response body failed: {error}"))?;
            if let Ok(data) = frame.into_data() {
                let room = cap.saturating_sub(body.len());
                if data.len() > room {
                    body.extend_from_slice(&data[..room]);
                    truncated = true;
                    break;
                }
                body.extend_from_slice(&data);
            }
        }

        Ok(Exchange {
            status,
            location,
            content_type,
            body,
            truncated,
        })
    }

    /// Apply `EG-2002`/`EG-2001`/`EG-2003` to a completed exchange.
    fn inspect_response(&self, exchange: Exchange, cap: usize) -> Verdict {
        let text = String::from_utf8_lossy(&exchange.body).into_owned();
        let mut ids: Vec<&'static str> = Vec::new();
        let mut messages: Vec<String> = Vec::new();
        let mut blocking: Option<(&'static str, String)> = None;

        if exchange.truncated {
            let detail = format!("response body exceeded the {cap} byte cap and was truncated");
            ids.push(EG_BODY_TOO_LARGE);
            messages.push(detail.clone());
            blocking = Some((
                EG_BODY_TOO_LARGE,
                format!("blocked by {EG_BODY_TOO_LARGE}: {detail}"),
            ));
        }

        let injection = injection_marker(&text)
            .map(|marker| format!("response text contains injection marker \"{marker}\""))
            .or_else(|| {
                hidden_text_present(&text).then(|| {
                    format!(
                        "response HTML contains hidden text (display:none or font-size:0) \
                         longer than {HIDDEN_TEXT_MIN_CHARS} characters"
                    )
                })
            });

        if let Some(detail) = injection {
            ids.push(EG_INJECTION);
            messages.push(detail.clone());
            if self.policy.refuses_injection() && blocking.is_none() {
                blocking = Some((EG_INJECTION, format!("blocked by {EG_INJECTION}: {detail}")));
            }
        }

        if let Some(hit) = check_content_type(exchange.content_type.as_deref(), &self.policy) {
            if !ids.contains(&hit.id) {
                ids.push(hit.id);
            }
            messages.push(hit.detail);
        }

        if let Some((id, message)) = blocking {
            if ids.first().copied() != Some(id) {
                ids.insert(0, id);
            }
            return Verdict::blocked(ids, message, exchange.body.len(), exchange.truncated);
        }

        if ids.is_empty() {
            Verdict::fetched(text, exchange.content_type, exchange.body.len())
        } else {
            Verdict::recorded(
                text,
                exchange.content_type,
                exchange.body.len(),
                ids,
                messages.join("; "),
            )
        }
    }

    /// Serve one request. `/metrics` is the same Prometheus rendering as the
    /// edge health service; `/egress/fetch` is the only data route.
    pub async fn handle(&self, request: Request<Incoming>) -> Response<Full<Bytes>> {
        let method = request.method().clone();
        let path = request.uri().path().to_string();

        if path == "/metrics" && method == Method::GET {
            Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, "text/plain; version=0.0.4")
                .body(Full::new(Bytes::from(self.metrics.render_prometheus())))
                .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())))
        } else if path == "/egress/fetch" {
            if method == Method::POST {
                self.handle_fetch(request).await
            } else {
                let verdict =
                    Verdict::failed("method not allowed; use POST /egress/fetch".to_string());
                let mut response = json_response(&verdict, StatusCode::METHOD_NOT_ALLOWED);
                response
                    .headers_mut()
                    .insert("allow", "POST".parse().expect("static header value"));
                response
            }
        } else {
            let verdict = Verdict::failed(format!("unknown egress route '{path}'"));
            json_response(&verdict, StatusCode::NOT_FOUND)
        }
    }

    async fn handle_fetch(&self, request: Request<Incoming>) -> Response<Full<Bytes>> {
        let mut request_body = request.into_body();
        let mut raw = Vec::with_capacity(1024);

        while let Some(frame) = request_body.frame().await {
            let frame = match frame {
                Ok(frame) => frame,
                Err(error) => {
                    return json_response(
                        &Verdict::failed(format!("failed to read request body: {error}")),
                        StatusCode::BAD_REQUEST,
                    )
                }
            };
            if let Ok(data) = frame.into_data() {
                if raw.len() + data.len() > MAX_REQUEST_BODY {
                    return json_response(
                        &Verdict::failed(format!("request body exceeds {MAX_REQUEST_BODY} bytes")),
                        StatusCode::PAYLOAD_TOO_LARGE,
                    );
                }
                raw.extend_from_slice(&data);
            }
        }

        let parsed: FetchRequest = match serde_json::from_slice(&raw) {
            Ok(parsed) => parsed,
            Err(error) => {
                return json_response(
                    &Verdict::failed(format!("invalid request JSON: {error}")),
                    StatusCode::BAD_REQUEST,
                )
            }
        };

        if parsed.url.trim().is_empty() {
            return json_response(
                &Verdict::failed("request field 'url' must not be empty".to_string()),
                StatusCode::BAD_REQUEST,
            );
        }

        let cap = parsed
            .max_bytes
            .unwrap_or(self.policy.max_bytes)
            .max(1)
            .min(self.policy.max_bytes);
        let budget = parsed
            .timeout_ms
            .map(Duration::from_millis)
            .unwrap_or(self.policy.timeout)
            .min(self.policy.timeout);

        let verdict = self.fetch(&parsed.url, cap, budget).await;
        let status = StatusCode::from_u16(verdict.outcome.status_code())
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        json_response(&verdict, status)
    }

    /// Bind `bind_addr` and serve until the task is cancelled.
    pub async fn start(self: Arc<Self>, bind_addr: SocketAddr) -> Result<(), WafError> {
        let listener = TcpListener::bind(bind_addr).await.map_err(|error| {
            WafError::internal(format!(
                "failed to bind egress service to {bind_addr}: {error}"
            ))
        })?;

        info!("Egress fetch service listening on http://{bind_addr}/egress/fetch");
        info!("Egress metrics available at http://{bind_addr}/metrics");

        loop {
            let (stream, _) = listener.accept().await.map_err(|error| {
                WafError::internal(format!("failed to accept egress connection: {error}"))
            })?;
            let service = Arc::clone(&self);
            tokio::task::spawn(async move {
                if let Err(error) = hyper::server::conn::http1::Builder::new()
                    .serve_connection(
                        TokioIo::new(stream),
                        service_fn(move |request| {
                            let service = Arc::clone(&service);
                            async move { Ok::<_, Infallible>(service.handle(request).await) }
                        }),
                    )
                    .await
                {
                    error!("error serving egress connection: {error}");
                }
            });
        }
    }
}

fn json_response(verdict: &Verdict, status: StatusCode) -> Response<Full<Bytes>> {
    let mut builder = Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json")
        .header("cache-control", "no-store");
    for (name, value) in verdict.headers() {
        builder = builder.header(name, value);
    }
    builder
        .body(Full::new(Bytes::from(verdict.to_json())))
        .unwrap_or_else(|_| {
            Response::new(Full::new(Bytes::from(
                "{\"outcome\":\"failed\",\"rule_ids\":[],\"message\":\"response build failed\"}",
            )))
        })
}

fn header_value(headers: &hyper::HeaderMap, name: hyper::header::HeaderName) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
}

fn is_redirect(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

/// Resolve a redirect target against the URI that produced it, without a URL
/// crate. Absolute targets win; `//host/path`, `/path` and relative paths are
/// supported because they are what real sites send.
pub fn resolve_location(base: &Uri, location: &str) -> Option<Uri> {
    let location = location.trim();
    if location.is_empty() {
        return None;
    }

    let absolute = if location.starts_with("http://") || location.starts_with("https://") {
        location.to_string()
    } else if location.starts_with("//") {
        format!("{}:{}", base.scheme_str()?, location)
    } else if location.starts_with('/') {
        format!(
            "{}://{}{}",
            base.scheme_str()?,
            base.authority()?.as_str(),
            location
        )
    } else if location.starts_with('?') {
        format!(
            "{}://{}{}{}",
            base.scheme_str()?,
            base.authority()?.as_str(),
            base.path(),
            location
        )
    } else {
        let path = base.path();
        let directory = match path.rfind('/') {
            Some(index) => &path[..=index],
            None => "/",
        };
        format!(
            "{}://{}{}{}",
            base.scheme_str()?,
            base.authority()?.as_str(),
            directory,
            location
        )
    };

    absolute.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absolute_location_is_used_as_is() {
        let base: Uri = "https://example.org/a/b".parse().unwrap();
        let next = resolve_location(&base, "https://other.org/x").unwrap();
        assert_eq!(next.to_string(), "https://other.org/x");
    }

    #[test]
    fn scheme_relative_location_keeps_the_scheme() {
        let base: Uri = "https://example.org/a/b".parse().unwrap();
        let next = resolve_location(&base, "//other.org/x").unwrap();
        assert_eq!(next.to_string(), "https://other.org/x");
    }

    #[test]
    fn relative_location_joins_the_directory() {
        let base: Uri = "https://example.org/a/b?c=1".parse().unwrap();
        let next = resolve_location(&base, "c").unwrap();
        assert_eq!(next.to_string(), "https://example.org/a/c");
    }

    #[test]
    fn query_only_location_joins_the_path() {
        let base: Uri = "https://example.org/a/b".parse().unwrap();
        let next = resolve_location(&base, "?x=1").unwrap();
        assert_eq!(next.to_string(), "https://example.org/a/b?x=1");
    }
}
