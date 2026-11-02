//! Reproducible end-to-end load-validation harness for `waf-ingress`.
//!
//! The harness owns a tiny in-process mock upstream, optionally spawns a
//! `waf-ingress` child with a throwaway config, and replays a deterministic
//! request matrix against the real proxy. It records closed-loop latency,
//! throughput, decision correctness, 503s and process RSS, then writes JSON,
//! a compact JSON fixture and a markdown report.
//!
//! See `scripts/load-validate.sh` and
//! `docs/operations/performance-validation.md` for the operating model.

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context as TaskContext, Poll};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use clap::Parser;
use http_body_util::{BodyExt, Full};
use hyper::body::{Body, Frame, Incoming, SizeHint};
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Barrier;
use tokio::time::timeout;
use tracing::warn;

const SCHEMA_VERSION: u32 = 1;
const HOST_HEADER: &str = "127.0.0.1";

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Debug, Parser)]
#[command(
    name = "load-validate",
    about = "End-to-end concurrent load validation for waf-ingress"
)]
struct Cli {
    /// Spawn this waf-ingress binary. Without it, --target must point at a
    /// running proxy and the harness starts only the mock upstream.
    #[arg(long)]
    waf_bin: Option<PathBuf>,

    /// Throwaway WAF config used with --waf-bin (exported as WAF_CONFIG_FILE).
    #[arg(long)]
    config: Option<PathBuf>,

    /// Running proxy address, e.g. http://127.0.0.1:39080.
    #[arg(long)]
    target: Option<String>,

    /// Health endpoint of the spawned proxy, e.g. http://127.0.0.1:39081/health.
    #[arg(long)]
    health_url: Option<String>,

    /// PID to sample for RSS when targeting an already-running proxy.
    #[arg(long)]
    waf_pid: Option<u32>,

    /// Local mock upstream port (the WAF config must point at it).
    #[arg(long, default_value_t = 39000)]
    upstream_port: u16,

    /// Do not start the in-process upstream (target already has one).
    #[arg(long)]
    no_upstream: bool,

    #[arg(long, default_value_t = 42)]
    seed: u64,

    /// Warm-up seconds per (profile, concurrency) cell. Excluded from stats.
    #[arg(long, default_value_t = 2)]
    warmup_secs: u64,

    /// Measurement seconds per cell.
    #[arg(long, default_value_t = 8)]
    duration_secs: u64,

    /// Comma-separated concurrency levels.
    #[arg(long, default_value = "1,4,16,64", value_delimiter = ',')]
    concurrency: Vec<usize>,

    /// Comma-separated profiles (default: all). See --list-profiles.
    #[arg(long, value_delimiter = ',')]
    profiles: Vec<String>,

    #[arg(long)]
    list_profiles: bool,

    /// Directory for config copy, WAF logs, results.json, fixture.json and
    /// summary.md.
    #[arg(long, default_value = "/tmp/opencode/load-validation")]
    output_dir: PathBuf,

    /// Start-up budget for the spawned proxy.
    #[arg(long, default_value_t = 180)]
    startup_timeout_secs: u64,

    /// Per-request client timeout (the WAF may legitimately spend seconds on a
    /// 60 KiB body; a hung request is still a harness error).
    #[arg(long, default_value_t = 120)]
    request_timeout_secs: u64,

    /// Emit a short machine-readable summary and exit (still runs the matrix).
    #[arg(long)]
    quiet: bool,
}

// ---------------------------------------------------------------------------
// Request model
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Expected {
    /// Clean traffic: correct decision is a 2xx from the upstream.
    Allow,
    /// Attack traffic: correct decision is a WAF block (403).
    Block,
}

#[derive(Debug, Clone)]
struct RequestTemplate {
    class: &'static str,
    method: &'static str,
    path: String,
    headers: Vec<(String, String)>,
    body: Bytes,
    expected: Expected,
    /// Hide the body length so hyper uses chunked transfer encoding. Real
    /// gRPC has no content-length; the WAF then treats the body as a stream.
    chunked: bool,
}

struct LoadBody {
    inner: Full<Bytes>,
    chunked: bool,
}

impl LoadBody {
    fn new(bytes: Bytes, chunked: bool) -> Self {
        Self {
            inner: Full::new(bytes),
            chunked,
        }
    }
}

impl Body for LoadBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Pin::new(&mut self.inner).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        if self.chunked {
            SizeHint::default()
        } else {
            self.inner.size_hint()
        }
    }
}

#[derive(Debug, Clone)]
struct Profile {
    name: &'static str,
    /// Weighted request classes. A single-entry profile is a constant stream.
    mix: Vec<(&'static str, u32)>,
    /// Honest latency target used only for capacity guidance and acceptance
    /// gates. `None` means "decision correctness only".
    p95_target_ms: Option<f64>,
    description: &'static str,
}

impl Profile {
    fn pick(&self, rng: &mut StdRng) -> &'static str {
        if self.mix.len() == 1 {
            return self.mix[0].0;
        }
        let total: u32 = self.mix.iter().map(|(_, w)| *w).sum();
        let mut n = rng.gen_range(0..total);
        for (class, weight) in &self.mix {
            if n < *weight {
                return class;
            }
            n -= *weight;
        }
        self.mix[0].0
    }
}

fn fill(seed: u64, len: usize) -> Vec<u8> {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = StdRng::seed_from_u64(seed);
    (0..len)
        .map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())])
        .collect()
}

fn form_body(seed: u64, total_len: usize) -> Bytes {
    let prefix = b"data=";
    let mut body = Vec::with_capacity(total_len);
    body.extend_from_slice(prefix);
    let pad = total_len.saturating_sub(prefix.len());
    body.extend_from_slice(&fill(seed.wrapping_add(total_len as u64), pad));
    Bytes::from(body)
}

fn graphql_body(seed: u64, total_len: usize) -> Bytes {
    let inner = format!(
        "{{\"query\":\"query Viewer($id: ID!) {{ viewer(id: $id) {{ id name email }}}}\",\"variables\":{{\"id\":\"{}\"}}}}",
        String::from_utf8_lossy(&fill(seed, 16))
    );
    let mut body = inner.into_bytes();
    if body.len() < total_len {
        body.resize(total_len, b' ');
    }
    Bytes::from(body)
}

fn grpc_frame(seed: u64, message_len: usize) -> Bytes {
    let mut body = Vec::with_capacity(message_len + 5);
    body.push(0);
    body.extend_from_slice(&(message_len as u32).to_be_bytes());
    let mut payload = fill(seed, message_len);
    // Keep the payload protobuf-ish (field 1, length-delimited) without
    // claiming any semantics; the inspector validates the frame envelope.
    if message_len >= 2 {
        payload[0] = 0x0a;
        payload[1] = 0x01;
    }
    body.extend_from_slice(&payload);
    Bytes::from(body)
}

/// A frame whose field 1 is a valid UTF-8 `string` of `value_len` bytes.
///
/// This is the shape a descriptor-backed artifact declares, so the gRPC
/// pre-check runs its Coraza field-content scan (unless `content_scan` is
/// off).
fn grpc_string_frame(seed: u64, value_len: usize) -> Bytes {
    let value = fill(seed, value_len);
    let mut payload = Vec::with_capacity(value_len + 10);
    payload.push(0x0a); // field 1, wire type 2
    let mut remaining = value_len as u64;
    loop {
        let mut byte = (remaining & 0x7f) as u8;
        remaining >>= 7;
        if remaining != 0 {
            byte |= 0x80;
        }
        payload.push(byte);
        if remaining == 0 {
            break;
        }
    }
    payload.extend_from_slice(&value);

    let mut body = Vec::with_capacity(payload.len() + 5);
    body.push(0);
    body.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    body.extend_from_slice(&payload);
    Bytes::from(body)
}

fn post_headers(content_type: &str, body_len: usize) -> Vec<(String, String)> {
    vec![
        ("content-type".into(), content_type.into()),
        ("content-length".into(), body_len.to_string()),
        ("user-agent".into(), "waf-rejected-load-validate/1.0".into()),
        ("accept".into(), "*/*".into()),
    ]
}

/// Real gRPC over HTTP/2 has no `Content-Length`; the WAF classifies a gRPC
/// request without one as a stream and relays the body without CRS scanning.
/// HTTP/1.1 transport therefore deliberately omits it as well.
fn grpc_headers() -> Vec<(String, String)> {
    vec![
        ("content-type".into(), "application/grpc+proto".into()),
        // gRPC over HTTP/1.1 requires TE: trailers.
        ("te".into(), "trailers".into()),
        ("user-agent".into(), "waf-rejected-load-validate/1.0".into()),
        ("accept".into(), "*/*".into()),
    ]
}

fn build_templates(seed: u64) -> Vec<RequestTemplate> {
    let mut templates = Vec::new();

    templates.push(RequestTemplate {
        class: "bodyless-get",
        method: "GET",
        path: "/".into(),
        headers: vec![("user-agent".into(), "waf-rejected-load-validate/1.0".into())],
        body: Bytes::new(),
        expected: Expected::Allow,
        chunked: false,
    });

    for (class, len) in [
        ("form-1k", 1024usize),
        ("form-8k", 8 * 1024),
        ("form-16k", 16 * 1024),
        ("form-60k", 60_000),
    ] {
        let body = form_body(seed.wrapping_add(len as u64), len);
        templates.push(RequestTemplate {
            class,
            method: "POST",
            path: "/upload".into(),
            headers: post_headers("application/x-www-form-urlencoded", body.len()),
            body,
            expected: Expected::Allow,
            chunked: false,
        });
    }

    for (class, len) in [("grpc-1k", 1024usize), ("grpc-256k", 256 * 1024)] {
        let body = grpc_frame(seed.wrapping_add(len as u64), len);
        templates.push(RequestTemplate {
            class,
            method: "POST",
            path: "/acme.Service/Method".into(),
            headers: grpc_headers(),
            body,
            expected: Expected::Allow,
            chunked: true,
        });
    }

    // Descriptor-backed gRPC method: the allowlist artifact declares field 1
    // as a string, so this request triggers the Coraza content scan. The body
    // is buffered (content-length, not chunked) so the pre-check can see it;
    // the streaming path never inspects frames.
    for (class, len) in [
        ("grpc-content-4k", 4 * 1024usize),
        ("grpc-content-16k", 16 * 1024),
    ] {
        let body = grpc_string_frame(seed.wrapping_add(len as u64), len);
        let mut headers = grpc_headers();
        headers.push(("content-length".into(), body.len().to_string()));
        templates.push(RequestTemplate {
            class,
            method: "POST",
            path: "/acme.Content/Scan".into(),
            headers,
            body,
            expected: Expected::Allow,
            chunked: false,
        });
    }

    for (class, len) in [("graphql-2k", 2048usize), ("graphql-8k", 8192)] {
        let body = graphql_body(seed.wrapping_add(len as u64), len);
        templates.push(RequestTemplate {
            class,
            method: "POST",
            path: "/graphql".into(),
            headers: post_headers("application/json", body.len()),
            body,
            expected: Expected::Allow,
            chunked: false,
        });
    }

    let sqli = b"username=admin%27%20OR%20%271%27%3D%271&password=notasecret".to_vec();
    templates.push(RequestTemplate {
        class: "sqli",
        method: "POST",
        path: "/login".into(),
        headers: post_headers("application/x-www-form-urlencoded", sqli.len()),
        body: Bytes::from(sqli),
        expected: Expected::Block,
        chunked: false,
    });

    templates.push(RequestTemplate {
        class: "xss",
        method: "GET",
        path: "/search?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E".into(),
        headers: vec![("user-agent".into(), "waf-rejected-load-validate/1.0".into())],
        body: Bytes::new(),
        expected: Expected::Block,
        chunked: false,
    });

    templates
}

fn profiles() -> Vec<Profile> {
    vec![
        Profile {
            name: "bodyless",
            mix: vec![("bodyless-get", 100)],
            p95_target_ms: Some(20.0),
            description: "bodyless GET through the proxy",
        },
        Profile {
            name: "form-1k",
            mix: vec![("form-1k", 100)],
            p95_target_ms: Some(250.0),
            description: "1 KiB urlencoded POST",
        },
        Profile {
            name: "form-8k",
            mix: vec![("form-8k", 100)],
            p95_target_ms: Some(1000.0),
            description: "8 KiB urlencoded POST (CRS body scan)",
        },
        Profile {
            name: "form-16k",
            mix: vec![("form-16k", 100)],
            p95_target_ms: Some(2000.0),
            description: "16 KiB urlencoded POST (CRS body scan)",
        },
        Profile {
            name: "form-60k",
            mix: vec![("form-60k", 100)],
            p95_target_ms: Some(5000.0),
            description: "60 KiB urlencoded POST (reactor DoS probe)",
        },
        Profile {
            name: "grpc-1k",
            mix: vec![("grpc-1k", 100)],
            p95_target_ms: Some(25.0),
            description: "valid unary gRPC frame, body withheld from CRS",
        },
        Profile {
            name: "grpc-256k",
            mix: vec![("grpc-256k", 100)],
            p95_target_ms: Some(30.0),
            description: "256 KiB valid gRPC frame, body withheld from CRS",
        },
        Profile {
            name: "grpc-content-4k",
            mix: vec![("grpc-content-4k", 100)],
            p95_target_ms: Some(1000.0),
            description: "4 KiB gRPC string field, Coraza content scan (admission-bounded)",
        },
        Profile {
            name: "grpc-content-16k",
            mix: vec![("grpc-content-16k", 100)],
            p95_target_ms: Some(2000.0),
            description: "16 KiB gRPC string field, Coraza content scan (admission-bounded)",
        },
        Profile {
            name: "graphql-2k",
            mix: vec![("graphql-2k", 100)],
            p95_target_ms: Some(500.0),
            description: "2 KiB GraphQL JSON POST",
        },
        Profile {
            name: "graphql-8k",
            mix: vec![("graphql-8k", 100)],
            p95_target_ms: Some(1500.0),
            description: "8 KiB GraphQL JSON POST",
        },
        Profile {
            name: "sqli",
            mix: vec![("sqli", 100)],
            p95_target_ms: None,
            description: "SQL-injection probe; 100% must be blocked",
        },
        Profile {
            name: "xss",
            mix: vec![("xss", 100)],
            p95_target_ms: None,
            description: "XSS probe; 100% must be blocked",
        },
        Profile {
            name: "mixed",
            mix: vec![
                ("bodyless-get", 60),
                ("form-1k", 20),
                ("sqli", 10),
                ("xss", 10),
            ],
            p95_target_ms: Some(250.0),
            description: "60% clean GET, 20% form, 20% attacks",
        },
        Profile {
            name: "mixed-dos",
            mix: vec![("bodyless-get", 90), ("form-60k", 10)],
            p95_target_ms: Some(200.0),
            description: "90% bodyless GET + 10% 60 KiB bodies (pool starvation)",
        },
        Profile {
            name: "mixed-grpc-dos",
            mix: vec![("bodyless-get", 90), ("grpc-content-4k", 10)],
            p95_target_ms: Some(200.0),
            description: "90% bodyless GET + 10% gRPC content scans (admission isolation)",
        },
    ]
}

// ---------------------------------------------------------------------------
// Results
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Clone, Serialize)]
struct Stats {
    count: u64,
    errors: u64,
    error_rate: f64,
    rps: f64,
    p50_ms: f64,
    p95_ms: f64,
    p99_ms: f64,
    max_ms: f64,
    mean_ms: f64,
    statuses: BTreeMap<String, u64>,
    s503: u64,
    false_allows: u64,
    false_blocks: u64,
    unexpected_statuses: u64,
}

#[derive(Debug, Clone, Serialize)]
struct ClassResult {
    expected: Expected,
    #[serde(flatten)]
    stats: Stats,
}

#[derive(Debug, Clone, Serialize)]
struct CellResult {
    profile: String,
    description: String,
    concurrency: usize,
    duration_secs: u64,
    wall_secs: f64,
    total: u64,
    #[serde(flatten)]
    stats: Stats,
    by_class: BTreeMap<String, ClassResult>,
    rss_start_mib: Option<f64>,
    rss_end_mib: Option<f64>,
    rss_peak_mib: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
struct RssSample {
    t_ms: u64,
    rss_kib: u64,
    cpu_max_mhz: Option<f64>,
    load1: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
struct Environment {
    hostname: String,
    os: String,
    kernel: String,
    cpu_model: String,
    logical_cpus: usize,
    reactor_pool_auto: usize,
    memory_total_mib: u64,
    rustc: String,
    git_commit: String,
    git_branch: String,
    git_dirty_tracked: bool,
    build_profile: String,
    target_arch: String,
    target_os: String,
    waf_binary: Option<String>,
    waf_binary_sha256: Option<String>,
    waf_binary_bytes: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
struct RunConfig {
    seed: u64,
    warmup_secs: u64,
    duration_secs: u64,
    concurrency: Vec<usize>,
    profiles: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct Gate {
    id: String,
    description: String,
    status: GateStatus,
    observed: String,
    cell: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
enum GateStatus {
    Pass,
    Fail,
    Skip,
}

#[derive(Debug, Clone, Serialize)]
struct CapacityRow {
    profile: String,
    p95_target_ms: Option<f64>,
    max_sustained_rps: f64,
    at_concurrency: usize,
    p95_ms: f64,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
struct Results {
    schema_version: u32,
    harness: &'static str,
    environment: Environment,
    config: RunConfig,
    reactor_pool_expected: usize,
    rss: RssSummary,
    cells: Vec<CellResult>,
    gates: Vec<Gate>,
    gates_passed: usize,
    gates_failed: usize,
    gates_skipped: usize,
    capacity: Vec<CapacityRow>,
}

#[derive(Debug, Clone, Serialize, Default)]
struct RssSummary {
    baseline_mib: Option<f64>,
    end_mib: Option<f64>,
    peak_mib: Option<f64>,
    growth_pct: Option<f64>,
    samples: Vec<RssSample>,
}

#[derive(Debug, Clone, Serialize)]
struct FixtureResults {
    schema_version: u32,
    harness: &'static str,
    environment: Environment,
    config: RunConfig,
    cells: Vec<FixtureCell>,
    gates: Vec<Gate>,
    gates_passed: usize,
    gates_failed: usize,
    gates_skipped: usize,
    capacity: Vec<CapacityRow>,
}

#[derive(Debug, Clone, Serialize)]
struct FixtureCell {
    profile: String,
    concurrency: usize,
    total: u64,
    rps: f64,
    p50_ms: f64,
    p95_ms: f64,
    p99_ms: f64,
    max_ms: f64,
    error_rate: f64,
    s503: u64,
    false_allows: u64,
    false_blocks: u64,
}

impl From<&CellResult> for FixtureCell {
    fn from(c: &CellResult) -> Self {
        Self {
            profile: c.profile.clone(),
            concurrency: c.concurrency,
            total: c.total,
            rps: c.stats.rps,
            p50_ms: c.stats.p50_ms,
            p95_ms: c.stats.p95_ms,
            p99_ms: c.stats.p99_ms,
            max_ms: c.stats.max_ms,
            error_rate: c.stats.error_rate,
            s503: c.stats.s503,
            false_allows: c.stats.false_allows,
            false_blocks: c.stats.false_blocks,
        }
    }
}

fn percentile(sorted_us: &[u64], p: f64) -> f64 {
    if sorted_us.is_empty() {
        return 0.0;
    }
    let rank = ((p / 100.0) * (sorted_us.len() as f64 - 1.0)).round() as usize;
    sorted_us[rank.min(sorted_us.len() - 1)] as f64 / 1000.0
}

#[derive(Debug)]
struct Outcome {
    class: &'static str,
    latency_us: u64,
    status: Option<u16>,
    error: Option<String>,
    expected: Expected,
}

fn aggregate(outcomes: &[Outcome], elapsed: Duration) -> Stats {
    let mut latencies: Vec<u64> = outcomes.iter().map(|o| o.latency_us).collect();
    latencies.sort_unstable();
    let total = outcomes.len() as u64;
    let mut statuses = BTreeMap::new();
    let mut errors = 0u64;
    let mut s503 = 0u64;
    let mut false_allows = 0u64;
    let mut false_blocks = 0u64;
    let mut unexpected = 0u64;

    for o in outcomes {
        match o.status {
            Some(code) => {
                *statuses.entry(code.to_string()).or_insert(0) += 1;
                if code == 503 {
                    s503 += 1;
                }
                match o.expected {
                    Expected::Allow => {
                        if (200..300).contains(&code) {
                        } else if code == 403 {
                            false_blocks += 1;
                        } else {
                            unexpected += 1;
                        }
                    }
                    Expected::Block => {
                        if code == 403 {
                        } else if (200..300).contains(&code) {
                            false_allows += 1;
                        } else {
                            unexpected += 1;
                        }
                    }
                }
                if code >= 500 || o.error.is_some() {
                    errors += 1;
                }
            }
            None => errors += 1,
        }
    }

    let count = total.max(1) as f64;
    Stats {
        count: total,
        errors,
        error_rate: errors as f64 / count,
        rps: total as f64 / elapsed.as_secs_f64().max(0.001),
        p50_ms: percentile(&latencies, 50.0),
        p95_ms: percentile(&latencies, 95.0),
        p99_ms: percentile(&latencies, 99.0),
        max_ms: latencies.last().copied().unwrap_or(0) as f64 / 1000.0,
        mean_ms: latencies.iter().sum::<u64>() as f64 / 1000.0 / count,
        statuses,
        s503,
        false_allows,
        false_blocks,
        unexpected_statuses: unexpected,
    }
}

// ---------------------------------------------------------------------------
// Mock upstream
// ---------------------------------------------------------------------------

async fn mock_upstream(listener: TcpListener) -> Result<()> {
    loop {
        let (stream, _) = listener.accept().await?;
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let service = service_fn(|req: Request<Incoming>| async move {
                let is_grpc = req
                    .headers()
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .map(|v| v.starts_with("application/grpc"))
                    .unwrap_or(false);
                // Drain the request body before responding.
                let _ = req.into_body().collect().await;
                let mut response = Response::new(Full::new(Bytes::from_static(b"ok")));
                if is_grpc {
                    response.headers_mut().insert(
                        "content-type",
                        "application/grpc".parse().expect("static header"),
                    );
                    // Empty unary response frame.
                    *response.body_mut() = Full::new(Bytes::from_static(&[0, 0, 0, 0, 0]));
                }
                Ok::<_, Infallible>(response)
            });
            if let Err(err) = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .await
            {
                warn!("mock upstream connection error: {err}");
            }
        });
    }
}

// ---------------------------------------------------------------------------
// Load workers
// ---------------------------------------------------------------------------

struct WorkerTarget {
    addr: SocketAddr,
    request_timeout: Duration,
}

struct WorkerContext {
    target: Arc<WorkerTarget>,
    templates: Arc<Vec<RequestTemplate>>,
    profile: Arc<Profile>,
    class_index: Arc<BTreeMap<&'static str, usize>>,
    seed: u64,
}

async fn load_worker(
    ctx: Arc<WorkerContext>,
    worker_id: usize,
    duration: Duration,
    barrier: Arc<Barrier>,
) -> Vec<Outcome> {
    let target = &ctx.target;
    let templates = &ctx.templates;
    let profile = &ctx.profile;
    let class_index = &ctx.class_index;
    let mut rng = StdRng::seed_from_u64(ctx.seed ^ ((worker_id as u64 + 1) * 0x9e37_79b9));
    let mut outcomes = Vec::new();

    // All workers release together so the measured window matches the
    // coordinator's wall clock.
    barrier.wait().await;
    let deadline = Instant::now() + duration;

    'reconnect: loop {
        if Instant::now() >= deadline {
            break;
        }
        let stream = match TcpStream::connect(target.addr).await {
            Ok(stream) => stream,
            Err(err) => {
                outcomes.push(Outcome {
                    class: "connect",
                    latency_us: 0,
                    status: None,
                    error: Some(format!("connect: {err}")),
                    expected: Expected::Allow,
                });
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let io = TokioIo::new(stream);
        let (mut sender, conn) = match hyper::client::conn::http1::handshake(io).await {
            Ok(pair) => pair,
            Err(err) => {
                outcomes.push(Outcome {
                    class: "handshake",
                    latency_us: 0,
                    status: None,
                    error: Some(format!("handshake: {err}")),
                    expected: Expected::Allow,
                });
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let conn_handle = tokio::spawn(async move {
            let _ = conn.await;
        });

        loop {
            if Instant::now() >= deadline {
                conn_handle.abort();
                break 'reconnect;
            }
            let class = profile.pick(&mut rng);
            let idx = *class_index
                .get(class)
                .expect("every profile class has a template");
            let template = &templates[idx];
            let mut builder = Request::builder()
                .method(template.method)
                .uri(template.path.as_str())
                .header("host", format!("{}:{}", HOST_HEADER, target.addr.port()));
            for (name, value) in &template.headers {
                builder = builder.header(name.as_str(), value.as_str());
            }
            let request = match builder.body(LoadBody::new(template.body.clone(), template.chunked))
            {
                Ok(request) => request,
                Err(err) => {
                    outcomes.push(Outcome {
                        class: template.class,
                        latency_us: 0,
                        status: None,
                        error: Some(format!("request build: {err}")),
                        expected: template.expected,
                    });
                    conn_handle.abort();
                    break 'reconnect;
                }
            };

            let start = Instant::now();
            let result = timeout(target.request_timeout, sender.send_request(request)).await;
            let latency_us = start.elapsed().as_micros() as u64;
            let now = Instant::now();
            match result {
                Ok(Ok(response)) => {
                    let status = response.status().as_u16();
                    let body_result = response.into_body().collect().await;
                    let body_error = body_result.err().map(|e| format!("body: {e}"));
                    outcomes.push(Outcome {
                        class: template.class,
                        latency_us,
                        status: Some(status),
                        error: body_error,
                        expected: template.expected,
                    });
                }
                Ok(Err(err)) => {
                    if now < deadline {
                        outcomes.push(Outcome {
                            class: template.class,
                            latency_us,
                            status: None,
                            error: Some(format!("send: {err}")),
                            expected: template.expected,
                        });
                    }
                    conn_handle.abort();
                    if now >= deadline {
                        break 'reconnect;
                    }
                    continue 'reconnect;
                }
                Err(_) => {
                    outcomes.push(Outcome {
                        class: template.class,
                        latency_us,
                        status: None,
                        error: Some("client timeout".into()),
                        expected: template.expected,
                    });
                    conn_handle.abort();
                    if now >= deadline {
                        break 'reconnect;
                    }
                    continue 'reconnect;
                }
            }
        }
    }
    outcomes
}

async fn run_phase(
    ctx: Arc<WorkerContext>,
    concurrency: usize,
    duration: Duration,
) -> (Vec<Outcome>, Duration) {
    let barrier = Arc::new(Barrier::new(concurrency + 1));
    let mut handles = Vec::with_capacity(concurrency);
    for worker_id in 0..concurrency {
        handles.push(tokio::spawn(load_worker(
            ctx.clone(),
            worker_id,
            duration,
            barrier.clone(),
        )));
    }
    barrier.wait().await;
    let started = Instant::now();
    let mut outcomes = Vec::new();
    for handle in handles {
        match handle.await {
            Ok(partial) => outcomes.extend(partial),
            Err(err) => outcomes.push(Outcome {
                class: "worker",
                latency_us: 0,
                status: None,
                error: Some(format!("worker join: {err}")),
                expected: Expected::Allow,
            }),
        }
    }
    (outcomes, started.elapsed())
}

fn split_by_class(outcomes: &[Outcome], elapsed: Duration) -> BTreeMap<String, ClassResult> {
    let mut grouped: BTreeMap<&'static str, Vec<&Outcome>> = BTreeMap::new();
    for outcome in outcomes {
        grouped.entry(outcome.class).or_default().push(outcome);
    }
    let mut result = BTreeMap::new();
    for (class, items) in grouped {
        let owned: Vec<Outcome> = items
            .into_iter()
            .map(|o| Outcome {
                class: o.class,
                latency_us: o.latency_us,
                status: o.status,
                error: o.error.clone(),
                expected: o.expected,
            })
            .collect();
        result.insert(
            class.to_string(),
            ClassResult {
                expected: owned.first().map(|o| o.expected).unwrap_or(Expected::Allow),
                stats: aggregate(&owned, elapsed),
            },
        );
    }
    result
}

// ---------------------------------------------------------------------------
// RSS sampling
// ---------------------------------------------------------------------------

fn read_rss_kib(pid: u32) -> Option<u64> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            return rest.split_whitespace().next().and_then(|v| v.parse().ok());
        }
    }
    None
}

fn read_load1() -> Option<f64> {
    std::fs::read_to_string("/proc/loadavg")
        .ok()?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

fn read_cpu_max_mhz() -> Option<f64> {
    let mut max = None::<f64>;
    for cpu in 0..32 {
        let path = format!("/sys/devices/system/cpu/cpu{cpu}/cpufreq/scaling_cur_freq");
        let Ok(raw) = std::fs::read_to_string(path) else {
            continue;
        };
        if let Ok(khz) = raw.trim().parse::<f64>() {
            let mhz = khz / 1000.0;
            max = Some(max.map_or(mhz, |m: f64| m.max(mhz)));
        }
    }
    max
}

struct RssMonitor {
    samples: Arc<Mutex<Vec<RssSample>>>,
    stop: Arc<AtomicBool>,
    handle: tokio::task::JoinHandle<()>,
}

fn start_rss_monitor(pid: u32, run_start: Instant) -> RssMonitor {
    let samples = Arc::new(Mutex::new(Vec::new()));
    let stop = Arc::new(AtomicBool::new(false));
    let samples_task = samples.clone();
    let stop_task = stop.clone();
    let handle = tokio::spawn(async move {
        while !stop_task.load(Ordering::Relaxed) {
            if let Some(rss_kib) = read_rss_kib(pid) {
                let sample = RssSample {
                    t_ms: run_start.elapsed().as_millis() as u64,
                    rss_kib,
                    cpu_max_mhz: read_cpu_max_mhz(),
                    load1: read_load1(),
                };
                if let Ok(mut guard) = samples_task.lock() {
                    guard.push(sample);
                }
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });
    RssMonitor {
        samples,
        stop,
        handle,
    }
}

impl RssMonitor {
    fn snapshot(&self) -> Vec<RssSample> {
        self.samples
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or_default()
    }

    async fn finish(self) -> Vec<RssSample> {
        let samples = self.samples.clone();
        self.stop.store(true, Ordering::Relaxed);
        let _ = timeout(Duration::from_secs(3), self.handle).await;
        samples
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or_default()
    }
}

fn rss_window(
    samples: &[RssSample],
    from_ms: u64,
    to_ms: u64,
) -> (Option<f64>, Option<f64>, Option<f64>) {
    let in_window: Vec<&RssSample> = samples
        .iter()
        .filter(|s| s.t_ms >= from_ms && s.t_ms <= to_ms)
        .collect();
    if in_window.is_empty() {
        return (None, None, None);
    }
    let start = in_window.first().map(|s| s.rss_kib as f64 / 1024.0);
    let end = in_window.last().map(|s| s.rss_kib as f64 / 1024.0);
    let peak = in_window
        .iter()
        .map(|s| s.rss_kib)
        .max()
        .map(|kib| kib as f64 / 1024.0);
    (start, end, peak)
}

fn nearest_rss(samples: &[RssSample], t_ms: u64) -> Option<f64> {
    samples
        .iter()
        .min_by_key(|s| s.t_ms.abs_diff(t_ms))
        .map(|s| s.rss_kib as f64 / 1024.0)
}

// ---------------------------------------------------------------------------
// Environment
// ---------------------------------------------------------------------------

fn command_output(program: &str, args: &[&str]) -> Option<String> {
    Command::new(program)
        .args(args)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
}

fn read_cpu_model() -> String {
    let Ok(cpuinfo) = std::fs::read_to_string("/proc/cpuinfo") else {
        return "unknown".into();
    };
    for line in cpuinfo.lines() {
        if let Some(rest) = line.strip_prefix("model name") {
            if let Some(value) = rest.split_once(':') {
                return value.1.trim().to_string();
            }
        }
    }
    "unknown".into()
}

fn read_mem_total_mib() -> u64 {
    let Ok(meminfo) = std::fs::read_to_string("/proc/meminfo") else {
        return 0;
    };
    for line in meminfo.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            if let Some(kib) = rest
                .split_whitespace()
                .next()
                .and_then(|v| v.parse::<u64>().ok())
            {
                return kib / 1024;
            }
        }
    }
    0
}

fn sha256_file(path: &Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Some(format!("{:x}", hasher.finalize()))
}

fn collect_environment(waf_bin: Option<&Path>) -> Environment {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let git = |args: &[&str]| {
        Command::new("git")
            .args(args)
            .current_dir(&cwd)
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
    };
    let status = git(&["status", "--porcelain", "--untracked-files=no"]).unwrap_or_default();
    Environment {
        hostname: std::fs::read_to_string("/proc/sys/kernel/hostname")
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "unknown".into()),
        os: std::env::consts::OS.into(),
        kernel: command_output("uname", &["-r"]).unwrap_or_else(|| "unknown".into()),
        cpu_model: read_cpu_model(),
        logical_cpus: num_cpus::get(),
        reactor_pool_auto: num_cpus::get().clamp(1, 8),
        memory_total_mib: read_mem_total_mib(),
        rustc: std::env::var("LOAD_VALIDATE_RUSTC")
            .ok()
            .or_else(|| command_output("rustc", &["--version"]))
            .unwrap_or_else(|| "unknown".into()),
        git_commit: git(&["rev-parse", "--short=12", "HEAD"]).unwrap_or_else(|| "unknown".into()),
        git_branch: git(&["rev-parse", "--abbrev-ref", "HEAD"]).unwrap_or_else(|| "unknown".into()),
        git_dirty_tracked: !status.is_empty(),
        build_profile: if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        }
        .into(),
        target_arch: std::env::consts::ARCH.into(),
        target_os: std::env::consts::OS.into(),
        waf_binary: waf_bin.map(|p| p.display().to_string()),
        waf_binary_sha256: waf_bin.and_then(sha256_file),
        waf_binary_bytes: waf_bin
            .and_then(|p| std::fs::metadata(p).ok())
            .map(|m| m.len()),
    }
}

// ---------------------------------------------------------------------------
// Gates and capacity
// ---------------------------------------------------------------------------

fn find_cell<'a>(cells: &'a [CellResult], profile: &str, c: usize) -> Option<&'a CellResult> {
    cells
        .iter()
        .find(|cell| cell.profile == profile && cell.concurrency == c)
}

fn gate_from_cell(
    cells: &[CellResult],
    id: &str,
    profile: &str,
    concurrency: usize,
    description: &str,
    test: impl Fn(&Stats, &CellResult) -> (bool, String),
) -> Gate {
    let label = format!("{profile}@{concurrency}");
    match find_cell(cells, profile, concurrency) {
        Some(cell) => {
            let (pass, observed) = test(&cell.stats, cell);
            Gate {
                id: id.into(),
                description: description.into(),
                status: if pass {
                    GateStatus::Pass
                } else {
                    GateStatus::Fail
                },
                observed,
                cell: Some(label),
            }
        }
        None => Gate {
            id: id.into(),
            description: description.into(),
            status: GateStatus::Skip,
            observed: "cell not run".into(),
            cell: Some(label),
        },
    }
}

fn build_gates(cells: &[CellResult], rss: &RssSummary) -> Vec<Gate> {
    let mut gates = Vec::new();

    gates.push(gate_from_cell(
        cells,
        "bodyless-p95-c64",
        "bodyless",
        64,
        "bodyless GET p95 < 20 ms at concurrency 64",
        |s, _| {
            (
                s.p95_ms < 20.0 && s.error_rate == 0.0 && s.false_blocks == 0,
                format!(
                    "p95={:.2} ms, errors={:.2}%",
                    s.p95_ms,
                    s.error_rate * 100.0
                ),
            )
        },
    ));
    gates.push(gate_from_cell(
        cells,
        "grpc-1k-p95-c64",
        "grpc-1k",
        64,
        "valid gRPC unary p95 < 25 ms at concurrency 64",
        |s, _| {
            (
                s.p95_ms < 25.0 && s.error_rate == 0.0 && s.false_blocks == 0,
                format!(
                    "p95={:.2} ms, errors={:.2}%",
                    s.p95_ms,
                    s.error_rate * 100.0
                ),
            )
        },
    ));
    gates.push(gate_from_cell(
        cells,
        "grpc-256k-p95-c64",
        "grpc-256k",
        64,
        "256 KiB gRPC (body withheld from CRS) p95 < 30 ms at concurrency 64",
        |s, _| {
            (
                s.p95_ms < 30.0 && s.error_rate == 0.0 && s.false_blocks == 0,
                format!(
                    "p95={:.2} ms, errors={:.2}%",
                    s.p95_ms,
                    s.error_rate * 100.0
                ),
            )
        },
    ));
    gates.push(gate_from_cell(
        cells,
        "form-1k-p95-c64",
        "form-1k",
        64,
        "1 KiB form p95 < 250 ms at concurrency 64",
        |s, _| {
            (
                s.p95_ms < 250.0 && s.error_rate == 0.0,
                format!(
                    "p95={:.2} ms, errors={:.2}%",
                    s.p95_ms,
                    s.error_rate * 100.0
                ),
            )
        },
    ));
    gates.push(gate_from_cell(
        cells,
        "form-8k-p95-c64",
        "form-8k",
        64,
        "8 KiB form p95 < 1000 ms at concurrency 64",
        |s, _| {
            (
                s.p95_ms < 1000.0 && s.error_rate == 0.0,
                format!(
                    "p95={:.2} ms, errors={:.2}%",
                    s.p95_ms,
                    s.error_rate * 100.0
                ),
            )
        },
    ));
    gates.push(gate_from_cell(
        cells,
        "form-16k-p95-c16",
        "form-16k",
        16,
        "16 KiB form p95 < 2000 ms at concurrency 16",
        |s, _| {
            (
                s.p95_ms < 2000.0 && s.error_rate == 0.0,
                format!(
                    "p95={:.2} ms, errors={:.2}%",
                    s.p95_ms,
                    s.error_rate * 100.0
                ),
            )
        },
    ));
    gates.push(gate_from_cell(
        cells,
        "form-60k-admitted-c1",
        "form-60k",
        1,
        "60 KiB form is inspected (no 503/timeout) at concurrency 1",
        |s, _| {
            (
                s.s503 == 0 && s.errors == 0 && s.false_blocks == 0 && s.p95_ms < 5000.0,
                format!(
                    "p95={:.2} ms, 503={}, errors={}",
                    s.p95_ms, s.s503, s.errors
                ),
            )
        },
    ));
    gates.push(gate_from_cell(
        cells,
        "form-60k-p95-c1",
        "form-60k",
        1,
        "60 KiB form p95 < 5000 ms (eval_timeout) at concurrency 1",
        |s, _| (s.p95_ms < 5000.0, format!("p95={:.2} ms", s.p95_ms)),
    ));
    gates.push(gate_from_cell(
        cells,
        "grpc-content-4k-admission-bounded",
        "grpc-content-4k",
        64,
        "gRPC content scans are admission-bounded at c=64 (p95 < 1000 ms, no non-503 errors)",
        |s, _| {
            (
                s.p95_ms < 1000.0 && s.errors.saturating_sub(s.s503) == 0,
                format!(
                    "p95={:.2} ms, 503={}, non-503 errors={}",
                    s.p95_ms,
                    s.s503,
                    s.errors.saturating_sub(s.s503)
                ),
            )
        },
    ));

    // No 503s once the offered rate is material (>= 20 RPS), including mixed
    // profiles. Heavy-body-only cells below that rate are covered separately.
    // Admission-bounded profiles (`form-60k`, `grpc-content-*`) and mixes that
    // include them (`mixed-dos`, `mixed-grpc-dos`) are expected to reject
    // excess heavy work with 503 by design and are excluded.
    {
        let mut failing = Vec::new();
        let mut evaluated = 0usize;
        for cell in cells {
            let admission_bounded = matches!(
                cell.profile.as_str(),
                "form-60k" | "mixed-dos" | "mixed-grpc-dos"
            ) || cell.profile.starts_with("grpc-content-");
            if cell.stats.rps >= 20.0 && !admission_bounded {
                evaluated += 1;
                if cell.stats.s503 > 0 {
                    failing.push(format!(
                        "{}@{}:{}",
                        cell.profile, cell.concurrency, cell.stats.s503
                    ));
                }
            }
        }
        gates.push(Gate {
            id: "zero-503-above-20rps".into(),
            description: "every cell offered >= 20 RPS has zero 503s".into(),
            status: if evaluated == 0 {
                GateStatus::Skip
            } else if failing.is_empty() {
                GateStatus::Pass
            } else {
                GateStatus::Fail
            },
            observed: if evaluated == 0 {
                "no cell reached 20 RPS".into()
            } else if failing.is_empty() {
                format!("{evaluated} cells inspected, zero 503s")
            } else {
                format!("503s: {}", failing.join(", "))
            },
            cell: None,
        });
    }

    // Availability for light profiles at or below 16 concurrency.
    {
        let light = [
            "bodyless",
            "form-1k",
            "form-8k",
            "grpc-1k",
            "grpc-256k",
            "graphql-2k",
            "graphql-8k",
        ];
        let mut bad = Vec::new();
        let mut evaluated = 0usize;
        for cell in cells {
            if light.contains(&cell.profile.as_str()) && cell.concurrency <= 16 {
                evaluated += 1;
                if cell.stats.error_rate > 0.0 || cell.stats.s503 > 0 {
                    bad.push(format!(
                        "{}@{}: err={:.2}% 503={}",
                        cell.profile,
                        cell.concurrency,
                        cell.stats.error_rate * 100.0,
                        cell.stats.s503
                    ));
                }
            }
        }
        gates.push(Gate {
            id: "light-availability-c16".into(),
            description: "light profiles have zero errors/503s at concurrency <= 16".into(),
            status: if evaluated == 0 {
                GateStatus::Skip
            } else if bad.is_empty() {
                GateStatus::Pass
            } else {
                GateStatus::Fail
            },
            observed: if bad.is_empty() {
                format!("{evaluated} cells clean")
            } else {
                bad.join("; ")
            },
            cell: None,
        });
    }

    // Decision correctness.
    {
        let mut attacks = 0u64;
        let mut false_allows = 0u64;
        let mut blocked = 0u64;
        for cell in cells {
            if cell.profile == "sqli" || cell.profile == "xss" {
                attacks += cell.stats.count;
                false_allows += cell.stats.false_allows;
                blocked += cell.stats.statuses.get("403").copied().unwrap_or(0);
            }
        }
        gates.push(Gate {
            id: "attack-block-rate".into(),
            description: "SQLi/XSS probes: 100% 403, zero false allows".into(),
            status: if attacks == 0 {
                GateStatus::Skip
            } else if false_allows == 0 && blocked == attacks {
                GateStatus::Pass
            } else {
                GateStatus::Fail
            },
            observed: format!("{blocked}/{attacks} blocked, {false_allows} false allows"),
            cell: None,
        });
    }
    {
        let mut found = false;
        let mut clean_false_allows = 0u64;
        let mut clean_false_blocks = 0u64;
        let mut attack_false_allows = 0u64;
        let mut attack_total = 0u64;
        let mut attack_blocked = 0u64;
        for cell in cells.iter().filter(|c| c.profile == "mixed") {
            found = true;
            for (class, result) in &cell.by_class {
                match result.expected {
                    Expected::Allow => {
                        clean_false_allows += 0;
                        clean_false_blocks += result.stats.false_blocks;
                    }
                    Expected::Block => {
                        attack_total += result.stats.count;
                        attack_false_allows += result.stats.false_allows;
                        attack_blocked += result.stats.statuses.get("403").copied().unwrap_or(0);
                    }
                }
                let _ = class;
            }
        }
        gates.push(Gate {
            id: "mixed-decision-correctness".into(),
            description: "mixed traffic: zero false allows for attacks, zero false blocks for clean".into(),
            status: if !found {
                GateStatus::Skip
            } else if attack_false_allows == 0 && attack_blocked == attack_total && clean_false_blocks == 0 {
                GateStatus::Pass
            } else {
                GateStatus::Fail
            },
            observed: format!(
                "attacks {attack_blocked}/{attack_total} blocked, attack false allows={attack_false_allows}, clean false blocks={clean_false_blocks}, clean false allows={clean_false_allows}"
            ),
            cell: None,
        });
    }
    {
        let clean = [
            "bodyless",
            "form-1k",
            "form-8k",
            "form-16k",
            "form-60k",
            "grpc-1k",
            "grpc-256k",
            "graphql-2k",
            "graphql-8k",
        ];
        let mut bad = Vec::new();
        let mut total = 0u64;
        for cell in cells.iter().filter(|c| clean.contains(&c.profile.as_str())) {
            total += cell.stats.count;
            if cell.stats.false_blocks > 0 {
                bad.push(format!(
                    "{}@{}:{}",
                    cell.profile, cell.concurrency, cell.stats.false_blocks
                ));
            }
        }
        gates.push(Gate {
            id: "clean-no-false-blocks".into(),
            description: "clean profiles never return 403".into(),
            status: if total == 0 {
                GateStatus::Skip
            } else if bad.is_empty() {
                GateStatus::Pass
            } else {
                GateStatus::Fail
            },
            observed: if bad.is_empty() {
                format!("{total} clean requests, zero false blocks")
            } else {
                format!("false blocks: {}", bad.join(", "))
            },
            cell: None,
        });
    }

    // DoS isolation: 60 KiB bodies must not starve bodyless traffic.
    {
        let mixed_dos = find_cell(cells, "mixed-dos", 64);
        let baseline = find_cell(cells, "bodyless", 64);
        match mixed_dos {
            Some(cell) => {
                let class = cell.by_class.get("bodyless-get");
                let bodyless_p95 = class.map(|c| c.stats.p95_ms).unwrap_or(f64::INFINITY);
                let base = baseline.map(|c| c.stats.p95_ms).unwrap_or(0.0);
                gates.push(Gate {
                    id: "dos-isolation-bodyless-c64".into(),
                    description:
                        "with 10% 60 KiB bodies at c=64, bodyless p95 stays < 100 ms".into(),
                    status: if bodyless_p95 < 100.0 {
                        GateStatus::Pass
                    } else {
                        GateStatus::Fail
                    },
                    observed: format!(
                        "bodyless p95={bodyless_p95:.2} ms (baseline {base:.2} ms), 60k p95={:.2} ms",
                        cell
                            .by_class
                            .get("form-60k")
                            .map(|c| c.stats.p95_ms)
                            .unwrap_or(0.0)
                    ),
                    cell: Some("mixed-dos@64".into()),
                });
            }
            None => gates.push(Gate {
                id: "dos-isolation-bodyless-c64".into(),
                description: "with 10% 60 KiB bodies at c=64, bodyless p95 stays < 100 ms".into(),
                status: GateStatus::Skip,
                observed: "cell not run".into(),
                cell: Some("mixed-dos@64".into()),
            }),
        }
    }

    gates.push(Gate {
        id: "rss-peak".into(),
        description: "WAF process peak RSS < 1536 MiB".into(),
        status: match rss.peak_mib {
            Some(peak) if peak < 1536.0 => GateStatus::Pass,
            Some(_) => GateStatus::Fail,
            None => GateStatus::Skip,
        },
        observed: rss
            .peak_mib
            .map(|p| format!("peak={p:.1} MiB"))
            .unwrap_or_else(|| "RSS not sampled".into()),
        cell: None,
    });
    gates.push(Gate {
        id: "rss-growth".into(),
        description: "WAF RSS growth over the matrix < 25% of baseline".into(),
        status: match rss.growth_pct {
            Some(growth) if growth < 25.0 => GateStatus::Pass,
            Some(_) => GateStatus::Fail,
            None => GateStatus::Skip,
        },
        observed: rss
            .growth_pct
            .map(|g| format!("growth={g:.1}%"))
            .unwrap_or_else(|| "RSS not sampled".into()),
        cell: None,
    });

    gates
}

fn build_capacity(cells: &[CellResult], profile_defs: &[Profile]) -> Vec<CapacityRow> {
    let mut rows = Vec::new();
    for profile in profile_defs {
        let Some(target) = profile.p95_target_ms else {
            continue;
        };
        let mut candidates: Vec<&CellResult> =
            cells.iter().filter(|c| c.profile == profile.name).collect();
        candidates.sort_by_key(|c| c.concurrency);
        let mut best: Option<&CellResult> = None;
        for cell in &candidates {
            let passes = cell.stats.p95_ms <= target
                && cell.stats.error_rate == 0.0
                && cell.stats.s503 == 0
                && cell.stats.false_blocks == 0;
            if passes && best.is_none_or(|b| cell.stats.rps > b.stats.rps) {
                best = Some(cell);
            }
        }
        let (rps, concurrency, p95, note) = match best {
            Some(cell) => (
                cell.stats.rps,
                cell.concurrency,
                cell.stats.p95_ms,
                format!(
                    "highest observed rate meeting p95 <= {target:.0} ms with zero errors/503s"
                ),
            ),
            None => {
                let lowest = candidates.iter().min_by_key(|c| c.concurrency);
                (
                    0.0,
                    lowest.map(|c| c.concurrency).unwrap_or(0),
                    lowest.map(|c| c.stats.p95_ms).unwrap_or(0.0),
                    format!("no cell met p95 <= {target:.0} ms with zero errors/503s"),
                )
            }
        };
        rows.push(CapacityRow {
            profile: profile.name.into(),
            p95_target_ms: Some(target),
            max_sustained_rps: rps,
            at_concurrency: concurrency,
            p95_ms: p95,
            note,
        });
    }
    rows
}

// ---------------------------------------------------------------------------
// WAF lifecycle
// ---------------------------------------------------------------------------

fn parse_host_port(url: &str) -> Result<SocketAddr> {
    let stripped = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or(url);
    let authority = stripped.split('/').next().unwrap_or(stripped);
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    authority
        .parse::<SocketAddr>()
        .with_context(|| format!("parse address from {url}"))
}

struct WafProcess {
    child: Child,
    log_path: PathBuf,
}

fn spawn_waf(bin: &Path, config: &Path, log_path: &Path) -> Result<WafProcess> {
    let stdout =
        File::create(log_path).with_context(|| format!("create WAF log {}", log_path.display()))?;
    let stderr = stdout
        .try_clone()
        .context("clone WAF log handle for stderr")?;
    let child = Command::new(bin)
        .env("WAF_CONFIG_FILE", config)
        // Block warnings would otherwise write one line per attack request on
        // the measured request path; that is I/O, not WAF inspection capacity.
        .env("RUST_LOG", "error")
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
        .with_context(|| format!("spawn {}", bin.display()))?;
    Ok(WafProcess {
        child,
        log_path: log_path.to_path_buf(),
    })
}

async fn wait_for_health(
    addr: SocketAddr,
    child: &mut Child,
    log_path: &Path,
    timeout_secs: u64,
) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        if let Some(status) = child.try_wait().context("poll WAF child")? {
            let log = std::fs::read_to_string(log_path).unwrap_or_default();
            bail!(
                "waf-ingress exited during start-up with {status}; log tail:\n{}",
                tail(&log, 40)
            );
        }
        if let Ok(Ok(stream)) = timeout(Duration::from_millis(500), TcpStream::connect(addr)).await
        {
            drop(stream);
            // Give the service a moment to finish wiring handlers.
            tokio::time::sleep(Duration::from_millis(250)).await;
            return Ok(());
        }
        if Instant::now() >= deadline {
            let log = std::fs::read_to_string(log_path).unwrap_or_default();
            bail!(
                "timed out after {timeout_secs}s waiting for WAF health at {addr}; log tail:\n{}",
                tail(&log, 40)
            );
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

fn tail(text: &str, lines: usize) -> String {
    let all: Vec<&str> = text.lines().collect();
    all[all.len().saturating_sub(lines)..].join("\n")
}

fn stop_waf(process: &mut WafProcess) {
    let pid = process.child.id();
    let _ = Command::new("kill")
        .args(["-TERM", &pid.to_string()])
        .status();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match process.child.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(100));
            }
            _ => {
                let _ = process.child.kill();
                let _ = process.child.wait();
                return;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

fn ms(value: f64) -> String {
    if value >= 1000.0 {
        format!("{:.2}s", value / 1000.0)
    } else {
        format!("{value:.2}ms")
    }
}

fn write_markdown(path: &Path, results: &Results) -> Result<()> {
    let mut out = String::new();
    out.push_str("# WAF load-validation summary\n\n");
    out.push_str(
        "Generated by `load-validate`. Timings are closed-loop client latency at the proxy.\n\n",
    );

    out.push_str("## Environment\n\n");
    out.push_str(&format!(
        "- Host: `{}` ({}, {} logical CPUs, {} MiB RAM)\n",
        results.environment.hostname,
        results.environment.cpu_model,
        results.environment.logical_cpus,
        results.environment.memory_total_mib
    ));
    out.push_str(&format!(
        "- Kernel: `{}`; rustc: `{}`; build: `{}`\n",
        results.environment.kernel, results.environment.rustc, results.environment.build_profile
    ));
    out.push_str(&format!(
        "- Commit: `{}` on `{}`{}; seed: `{}`\n",
        results.environment.git_commit,
        results.environment.git_branch,
        if results.environment.git_dirty_tracked {
            " (dirty tracked files)"
        } else {
            ""
        },
        results.config.seed
    ));
    if let Some(bin) = &results.environment.waf_binary {
        out.push_str(&format!(
            "- WAF binary: `{}` ({} bytes, sha256 `{}`)\n",
            bin,
            results.environment.waf_binary_bytes.unwrap_or(0),
            results
                .environment
                .waf_binary_sha256
                .clone()
                .unwrap_or_else(|| "unknown".into())
        ));
    }
    out.push_str(&format!(
        "- Reactor pool (auto = cores clamped to 8): expected `{}`\n",
        results.reactor_pool_expected
    ));
    out.push_str(&format!(
        "- Matrix: warm-up {}s + measure {}s; concurrency {:?}\n\n",
        results.config.warmup_secs, results.config.duration_secs, results.config.concurrency
    ));

    out.push_str("## Matrix\n\n");
    out.push_str("| profile | c | requests | RPS | p50 | p95 | p99 | max | err | 503 | false allow | false block |\n");
    out.push_str("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n");
    for cell in &results.cells {
        out.push_str(&format!(
            "| {} | {} | {} | {:.1} | {} | {} | {} | {} | {:.2}% | {} | {} | {} |\n",
            cell.profile,
            cell.concurrency,
            cell.total,
            cell.stats.rps,
            ms(cell.stats.p50_ms),
            ms(cell.stats.p95_ms),
            ms(cell.stats.p99_ms),
            ms(cell.stats.max_ms),
            cell.stats.error_rate * 100.0,
            cell.stats.s503,
            cell.stats.false_allows,
            cell.stats.false_blocks
        ));
    }

    out.push_str("\n## Acceptance gates\n\n");
    out.push_str("| gate | status | observed |\n|---|---|---|\n");
    for gate in &results.gates {
        out.push_str(&format!(
            "| `{}` — {} | {} | {} |\n",
            gate.id,
            gate.description,
            match gate.status {
                GateStatus::Pass => "PASS",
                GateStatus::Fail => "FAIL",
                GateStatus::Skip => "SKIP",
            },
            gate.observed
        ));
    }
    out.push_str(&format!(
        "\n**{} passed, {} failed, {} skipped.**\n",
        results.gates_passed, results.gates_failed, results.gates_skipped
    ));

    out.push_str("\n## Capacity guidance\n\n");
    out.push_str("| profile | p95 target | max sustained RPS | at c | observed p95 |\n");
    out.push_str("|---|---:|---:|---:|---:|\n");
    for row in &results.capacity {
        out.push_str(&format!(
            "| {} | {} | {:.1} | {} | {} |\n",
            row.profile,
            row.p95_target_ms.map(ms).unwrap_or_else(|| "n/a".into()),
            row.max_sustained_rps,
            row.at_concurrency,
            ms(row.p95_ms)
        ));
    }

    out.push_str("\n## A 60 KiB body can starve the reactor pool\n\n");
    if let Some(c1) = find_cell(&results.cells, "form-60k", 1) {
        out.push_str(&format!(
            "- One 60 KiB body at c=1: p50 {}, p95 {}, {:.2} RPS, {} 503s.\n",
            ms(c1.stats.p50_ms),
            ms(c1.stats.p95_ms),
            c1.stats.rps,
            c1.stats.s503
        ));
    }
    if let Some(c64) = find_cell(&results.cells, "form-60k", 64) {
        out.push_str(&format!(
            "- 64 concurrent 60 KiB bodies: p50 {}, p95 {}, {:.2} RPS, {} 503s.\n",
            ms(c64.stats.p50_ms),
            ms(c64.stats.p95_ms),
            c64.stats.rps,
            c64.stats.s503
        ));
    }
    if let Some(mixed) = find_cell(&results.cells, "mixed-dos", 64) {
        let bodyless = mixed.by_class.get("bodyless-get");
        out.push_str(&format!(
            "- At c=64 with 10% 60 KiB bodies, bodyless p95 is {} while the 60 KiB class has p95 {}. A single in-flight 60 KiB body occupies one reactor for seconds; `pool_size` concurrent large bodies saturate all reactors.\n",
            bodyless.map(|c| ms(c.stats.p95_ms)).unwrap_or_else(|| "n/a".into()),
            mixed
                .by_class
                .get("form-60k")
                .map(|c| ms(c.stats.p95_ms))
                .unwrap_or_else(|| "n/a".into())
        ));
    }

    out.push_str("\n## Memory\n\n");
    out.push_str(&format!(
        "- Baseline {}, end {}, peak {}, growth {}.\n",
        results
            .rss
            .baseline_mib
            .map(|v| format!("{v:.1} MiB"))
            .unwrap_or_else(|| "n/a".into()),
        results
            .rss
            .end_mib
            .map(|v| format!("{v:.1} MiB"))
            .unwrap_or_else(|| "n/a".into()),
        results
            .rss
            .peak_mib
            .map(|v| format!("{v:.1} MiB"))
            .unwrap_or_else(|| "n/a".into()),
        results
            .rss
            .growth_pct
            .map(|v| format!("{v:.1}%"))
            .unwrap_or_else(|| "n/a".into())
    ));
    if let Some(sample) = results
        .rss
        .samples
        .iter()
        .filter_map(|s| s.cpu_max_mhz)
        .next()
    {
        out.push_str(&format!(
            "- Highest sampled CPU clock during the run: {sample:.0} MHz. Laptop CPUs may throttle across the 1.7–3.3 GHz range; treat absolute RPS as host-specific.\n"
        ));
    }
    if let Some(max_load) = results
        .rss
        .samples
        .iter()
        .filter_map(|s| s.load1)
        .reduce(f64::max)
    {
        out.push_str(&format!(
            "- Highest 1-minute host load sample during the run: {max_load:.2} (other builds/agents share this host).\n"
        ));
    }

    out.push_str("\n## Caveats\n\n");
    out.push_str("- Closed-loop clients on the same host as the WAF and upstream compete for CPU; these are capacity floors, not ceilings.\n");
    out.push_str("- Plaintext ingress speaks HTTP/1.1 only. The gRPC profiles use valid unary frames with `application/grpc` over HTTP/1.1; `grpc-1k`/`grpc-256k` withhold the body from CRS, while `grpc-content-4k`/`grpc-content-16k` use the descriptor-backed `/acme.Content/Scan` method and therefore run the Coraza field-content scan under admission control.\n");
    out.push_str("- Rate limiting is disabled in the throwaway config so the matrix measures inspection capacity, not the default 100 req/min per-IP limiter.\n");
    out.push_str("- A p95 is only meaningful with enough samples; heavy 60 KiB cells at high concurrency complete few requests.\n");

    std::fs::write(path, out).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)
        .with_context(|| format!("create {}", path.display()))?;
    serde_json::to_writer_pretty(file, value)
        .with_context(|| format!("write JSON {}", path.display()))?;
    Ok(())
}

fn print_summary(results: &Results) {
    println!("\nprofile              c    req      RPS      p50      p95      p99      max    err   503  fAllow fBlock");
    println!("--------------------------------------------------------------------------------------------------------");
    for cell in &results.cells {
        println!(
            "{:<20} {:>2} {:>6} {:>8.1} {:>8} {:>8} {:>8} {:>8} {:>5.2}% {:>4} {:>6} {:>6}",
            cell.profile,
            cell.concurrency,
            cell.total,
            cell.stats.rps,
            ms(cell.stats.p50_ms),
            ms(cell.stats.p95_ms),
            ms(cell.stats.p99_ms),
            ms(cell.stats.max_ms),
            cell.stats.error_rate * 100.0,
            cell.stats.s503,
            cell.stats.false_allows,
            cell.stats.false_blocks
        );
    }
    println!(
        "\nGates: {} passed, {} failed, {} skipped",
        results.gates_passed, results.gates_failed, results.gates_skipped
    );
    for gate in results
        .gates
        .iter()
        .filter(|g| g.status != GateStatus::Pass)
    {
        println!("  {:?} {}: {}", gate.status, gate.id, gate.observed);
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    if cli.list_profiles {
        for profile in profiles() {
            println!("{:<14} {}", profile.name, profile.description);
        }
        return Ok(());
    }

    if cli.waf_bin.is_some() && cli.config.is_none() {
        bail!("--config is required with --waf-bin");
    }
    if cli.waf_bin.is_none() && cli.target.is_none() {
        bail!("provide --waf-bin/--config or --target");
    }

    std::fs::create_dir_all(&cli.output_dir)
        .with_context(|| format!("create {}", cli.output_dir.display()))?;

    let target_addr = match (&cli.target, &cli.waf_bin) {
        (Some(url), _) => parse_host_port(url)?,
        (None, Some(_)) => parse_host_port("http://127.0.0.1:39080")?,
        _ => unreachable!(),
    };

    // Mock upstream first: the WAF must be able to reach it at start-up.
    let upstream_addr: SocketAddr = format!("127.0.0.1:{}", cli.upstream_port)
        .parse()
        .context("parse upstream address")?;
    if !cli.no_upstream {
        let listener = TcpListener::bind(upstream_addr)
            .await
            .with_context(|| format!("bind mock upstream {upstream_addr}"))?;
        tokio::spawn(async move {
            if let Err(err) = mock_upstream(listener).await {
                eprintln!("mock upstream stopped: {err}");
            }
        });
    }

    let mut waf_process: Option<WafProcess> = None;
    let mut waf_pid = cli.waf_pid;

    if let Some(bin) = &cli.waf_bin {
        let config = cli.config.as_ref().expect("validated above");
        let log_path = cli.output_dir.join("waf-ingress.log");
        let mut process = spawn_waf(bin, config, &log_path)?;
        waf_pid = Some(process.child.id());
        let health_addr = cli
            .health_url
            .as_deref()
            .map(parse_host_port)
            .transpose()?
            .unwrap_or_else(|| "127.0.0.1:39081".parse().expect("static address"));
        wait_for_health(
            health_addr,
            &mut process.child,
            &process.log_path,
            cli.startup_timeout_secs,
        )
        .await?;
        waf_process = Some(process);
    }

    let templates = Arc::new(build_templates(cli.seed));
    let class_index: Arc<BTreeMap<&'static str, usize>> = Arc::new(
        templates
            .iter()
            .enumerate()
            .map(|(idx, t)| (t.class, idx))
            .collect(),
    );
    let all_profiles = profiles();
    let selected_profiles: Vec<Profile> = if cli.profiles.is_empty() {
        all_profiles.clone()
    } else {
        all_profiles
            .iter()
            .filter(|p| cli.profiles.iter().any(|name| name == p.name))
            .cloned()
            .collect()
    };
    if selected_profiles.is_empty() {
        bail!("no matching profiles; use --list-profiles");
    }

    let run_start = Instant::now();
    let monitor = waf_pid.map(|pid| start_rss_monitor(pid, run_start));

    // Settle the reactor pool and take a baseline before the matrix.
    tokio::time::sleep(Duration::from_secs(1)).await;

    let target = Arc::new(WorkerTarget {
        addr: target_addr,
        request_timeout: Duration::from_secs(cli.request_timeout_secs),
    });

    let mut cells: Vec<CellResult> = Vec::new();
    let mut concurrencies = cli.concurrency.clone();
    concurrencies.sort_unstable();
    concurrencies.dedup();

    for concurrency in &concurrencies {
        for profile in &selected_profiles {
            if !cli.quiet {
                print!(
                    "running {:<14} c={:<3} warm-up {}s, measure {}s ... ",
                    profile.name, concurrency, cli.warmup_secs, cli.duration_secs
                );
                std::io::stdout().flush().ok();
            }
            let worker_ctx = Arc::new(WorkerContext {
                target: target.clone(),
                templates: templates.clone(),
                profile: Arc::new(profile.clone()),
                class_index: class_index.clone(),
                seed: cli.seed,
            });
            let _ = run_phase(
                worker_ctx.clone(),
                *concurrency,
                Duration::from_secs(cli.warmup_secs),
            )
            .await;

            let cell_start_ms = run_start.elapsed().as_millis() as u64;
            let (outcomes, elapsed) = run_phase(
                worker_ctx.clone(),
                *concurrency,
                Duration::from_secs(cli.duration_secs),
            )
            .await;
            let cell_end_ms = run_start.elapsed().as_millis() as u64;
            let stats = aggregate(&outcomes, elapsed);
            let by_class = split_by_class(&outcomes, elapsed);

            let samples = monitor.as_ref().map(|m| m.snapshot()).unwrap_or_default();
            let (rss_start, rss_end, rss_peak) = if samples.is_empty() {
                (None, None, None)
            } else {
                let (start, end, _) = rss_window(&samples, cell_start_ms, cell_end_ms);
                (
                    start.or_else(|| nearest_rss(&samples, cell_start_ms)),
                    end.or_else(|| nearest_rss(&samples, cell_end_ms)),
                    rss_window(&samples, cell_start_ms, cell_end_ms).2,
                )
            };

            if !cli.quiet {
                println!(
                    "{:>7} req, {:>7.1} RPS, p95 {}, 503 {}",
                    stats.count,
                    stats.rps,
                    ms(stats.p95_ms),
                    stats.s503
                );
            }

            cells.push(CellResult {
                profile: profile.name.to_string(),
                description: profile.description.to_string(),
                concurrency: *concurrency,
                duration_secs: cli.duration_secs,
                wall_secs: elapsed.as_secs_f64(),
                total: stats.count,
                stats,
                by_class,
                rss_start_mib: rss_start,
                rss_end_mib: rss_end,
                rss_peak_mib: rss_peak,
            });
        }
    }

    let samples = match monitor {
        Some(monitor) => monitor.finish().await,
        None => Vec::new(),
    };

    let baseline_mib = samples.first().map(|s| s.rss_kib as f64 / 1024.0);
    let end_mib = samples.last().map(|s| s.rss_kib as f64 / 1024.0);
    let peak_mib = samples
        .iter()
        .map(|s| s.rss_kib)
        .max()
        .map(|kib| kib as f64 / 1024.0);
    let growth_pct = match (baseline_mib, end_mib) {
        (Some(base), Some(end)) if base > 0.0 => Some((end - base) / base * 100.0),
        _ => None,
    };
    let rss = RssSummary {
        baseline_mib,
        end_mib,
        peak_mib,
        growth_pct,
        samples,
    };

    let gates = build_gates(&cells, &rss);
    let gates_passed = gates
        .iter()
        .filter(|g| g.status == GateStatus::Pass)
        .count();
    let gates_failed = gates
        .iter()
        .filter(|g| g.status == GateStatus::Fail)
        .count();
    let gates_skipped = gates
        .iter()
        .filter(|g| g.status == GateStatus::Skip)
        .count();
    let capacity = build_capacity(&cells, &all_profiles);

    let environment = collect_environment(cli.waf_bin.as_deref());
    let reactor_pool_expected = environment.reactor_pool_auto;
    let config = RunConfig {
        seed: cli.seed,
        warmup_secs: cli.warmup_secs,
        duration_secs: cli.duration_secs,
        concurrency: concurrencies,
        profiles: selected_profiles
            .iter()
            .map(|p| p.name.to_string())
            .collect(),
    };

    let results = Results {
        schema_version: SCHEMA_VERSION,
        harness: "load-validate",
        environment: environment.clone(),
        config: config.clone(),
        reactor_pool_expected,
        rss: rss.clone(),
        cells: cells.clone(),
        gates: gates.clone(),
        gates_passed,
        gates_failed,
        gates_skipped,
        capacity: capacity.clone(),
    };

    let fixture = FixtureResults {
        schema_version: SCHEMA_VERSION,
        harness: "load-validate",
        environment,
        config,
        cells: cells.iter().map(FixtureCell::from).collect(),
        gates: gates.clone(),
        gates_passed,
        gates_failed,
        gates_skipped,
        capacity,
    };

    write_json(&cli.output_dir.join("results.json"), &results)?;
    write_json(&cli.output_dir.join("fixture.json"), &fixture)?;
    write_markdown(&cli.output_dir.join("summary.md"), &results)?;

    if let Some(mut process) = waf_process {
        stop_waf(&mut process);
    }

    print_summary(&results);
    println!(
        "\nWrote {}/results.json, {}/fixture.json, {}/summary.md",
        cli.output_dir.display(),
        cli.output_dir.display(),
        cli.output_dir.display()
    );
    if gates_failed > 0 {
        // Honest machine-readable failure without hiding the report.
        std::process::exit(2);
    }
    Ok(())
}
