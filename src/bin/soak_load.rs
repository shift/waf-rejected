//! Soak and deterministic fault-injection harness for the WAF ingress.
//!
//! This binary is quarantined behind the `experimental` feature, matching the
//! other ad-hoc load/test tools in `docs/operations/module-scope.md`. It is
//! driven by `scripts/soak.sh`.
//!
//! Subcommands:
//!   serve   - HTTP/WebSocket echo or deliberately broken upstream fixture
//!   soak    - mixed-traffic soak with /proc resource sampling and a verdict
//!   faults  - deterministic process-level fault scenarios
//!
//! The harness fails closed: a canonical SQLi/XSS/path-traversal payload must
//! still be blocked at the end of every soak and fault scenario.

use anyhow::{anyhow, bail, Context, Result};
use futures_util::{SinkExt, StreamExt};
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::TcpListener as StdTcpListener;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::{Child, Command};
use tokio::time::{sleep, timeout};
use tokio_tungstenite::tungstenite::Message;

const LATENCY_BOUNDS_US: [u64; 21] = [
    0,
    50,
    100,
    200,
    500,
    1_000,
    2_000,
    5_000,
    10_000,
    20_000,
    50_000,
    100_000,
    200_000,
    500_000,
    1_000_000,
    2_000_000,
    5_000_000,
    10_000_000,
    30_000_000,
    60_000_000,
    u64::MAX,
];

const SQLI: &str = "/api/users?id=1%27%20OR%20%271%27%3D%271";
const XSS: &str = "<script>alert('xss')</script>";
const TRAVERSAL: &str = "/api/file?path=../../../../etc/passwd";

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = args.first().map(String::as_str).unwrap_or("help");
    let rest = if args.is_empty() { &[][..] } else { &args[1..] };

    match command {
        "serve" => serve(rest).await,
        "soak" => soak(rest).await,
        "faults" => faults(rest).await,
        "help" | "--help" | "-h" => {
            println!(
                "soak-load <serve|soak|faults> [options]\n\
                 \n\
                 serve:  --port N [--mode echo|slow|malformed|truncated|bad-framing|huge-headers|close] [--delay-ms N]\n\
                 soak:   --waf-bin PATH --self-bin PATH [--duration 60s] [--warmup 10s] [--concurrency 16]\n\
                 \x20       [--mix benign=40,blocked=20,oversized=5,malformed=5,grpc=15,websocket=15]\n\
                 \x20       [--body-size 4096] [--oversized-bytes 1572864] [--sample-interval 2s]\n\
                 \x20       [--max-rss-slope-mb-per-min 2.0] [--max-fd-growth 32] [--max-conn-growth 32]\n\
                 \x20       [--max-error-rate 0.01] [--min-block-rate 0.99] [--report PATH] [--work-dir PATH]\n\
                 faults: --waf-bin PATH --self-bin PATH [--work-dir PATH]"
            );
            Ok(())
        }
        other => bail!("unknown subcommand {other:?}; try --help"),
    }
}

fn arg_map(args: &[String]) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let mut i = 0;
    while i < args.len() {
        let key = args[i].trim_start_matches("--").to_string();
        if i + 1 < args.len() && !args[i + 1].starts_with("--") {
            map.insert(key, args[i + 1].clone());
            i += 2;
        } else {
            map.insert(key, "true".to_string());
            i += 1;
        }
    }
    map
}

fn get<'a>(map: &'a HashMap<String, String>, key: &str, default: &'a str) -> &'a str {
    map.get(key).map(String::as_str).unwrap_or(default)
}

fn get_u64(map: &HashMap<String, String>, key: &str, default: u64) -> u64 {
    get(map, key, &default.to_string())
        .parse()
        .unwrap_or(default)
}

fn get_usize(map: &HashMap<String, String>, key: &str, default: usize) -> usize {
    get(map, key, &default.to_string())
        .parse()
        .unwrap_or(default)
}

fn get_f64(map: &HashMap<String, String>, key: &str, default: f64) -> f64 {
    get(map, key, &default.to_string())
        .parse()
        .unwrap_or(default)
}

fn parse_duration(value: &str) -> Result<Duration> {
    let value = value.trim();
    if value.is_empty() {
        bail!("empty duration");
    }
    let (number, unit) = value.split_at(value.len() - 1);
    let number: f64 = number
        .parse()
        .with_context(|| format!("invalid duration {value:?}"))?;
    let seconds = match unit {
        "s" => number,
        "m" => number * 60.0,
        "h" => number * 3600.0,
        _ => bail!("duration {value:?} must end in s, m or h"),
    };
    if seconds <= 0.0 {
        bail!("duration must be positive");
    }
    Ok(Duration::from_secs_f64(seconds))
}

fn free_port() -> Result<u16> {
    let listener = StdTcpListener::bind(("127.0.0.1", 0))?;
    Ok(listener.local_addr()?.port())
}

fn work_dir(map: &HashMap<String, String>) -> Result<PathBuf> {
    let dir = map
        .get("work-dir")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("target/soak-work"));
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

// ---------------------------------------------------------------------------
// Upstream fixture
// ---------------------------------------------------------------------------

async fn serve(args: &[String]) -> Result<()> {
    let map = arg_map(args);
    let port = get_u64(&map, "port", 0) as u16;
    if port == 0 {
        bail!("serve requires --port");
    }
    let mode = get(&map, "mode", "echo").to_string();
    let delay_ms = get_u64(&map, "delay-ms", 0);
    let listener = TcpListener::bind(("127.0.0.1", port)).await?;
    println!("soak-load fixture listening on 127.0.0.1:{port} mode={mode}");
    loop {
        let (stream, _) = listener.accept().await?;
        let mode = mode.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_fixture(stream, &mode, delay_ms).await {
                eprintln!("fixture connection ended: {error}");
            }
        });
    }
}

async fn handle_fixture(mut stream: TcpStream, mode: &str, delay_ms: u64) -> Result<()> {
    match mode {
        "malformed" => {
            stream.write_all(b"NOT-HTTP\r\n\r\n").await?;
            stream.shutdown().await?;
            return Ok(());
        }
        "truncated" => {
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort")
                .await?;
            stream.shutdown().await?;
            return Ok(());
        }
        "bad-framing" => {
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nZZ\r\n")
                .await?;
            stream.shutdown().await?;
            return Ok(());
        }
        "huge-headers" => {
            let mut response = String::from("HTTP/1.1 200 OK\r\nX-Huge: ");
            response.push_str(&"a".repeat(128 * 1024));
            response.push_str("\r\nContent-Length: 2\r\n\r\nok");
            stream.write_all(response.as_bytes()).await?;
            stream.shutdown().await?;
            return Ok(());
        }
        "close" => {
            stream.shutdown().await?;
            return Ok(());
        }
        _ => {}
    }

    let mut peek = [0u8; 2048];
    let peeked = timeout(Duration::from_secs(2), stream.peek(&mut peek)).await??;
    let head = String::from_utf8_lossy(&peek[..peeked]).to_ascii_lowercase();
    if head.contains("upgrade: websocket") {
        let mut ws = tokio_tungstenite::accept_async(stream).await?;
        while let Some(message) = ws.next().await {
            match message? {
                Message::Text(text) => ws.send(Message::Text(text)).await?,
                Message::Binary(bytes) => ws.send(Message::Binary(bytes)).await?,
                Message::Ping(bytes) => ws.send(Message::Pong(bytes)).await?,
                Message::Close(_) => break,
                _ => {}
            }
        }
        return Ok(());
    }

    let (request_head, body) = read_http_request(&mut stream).await?;
    if mode == "slow" && delay_ms > 0 {
        sleep(Duration::from_millis(delay_ms)).await;
    }
    let is_grpc = request_head
        .to_ascii_lowercase()
        .contains("content-type: application/grpc");
    let response = if is_grpc {
        let mut body = vec![0u8, 0, 0, 0, 2, b'o', b'k'];
        let mut response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/grpc\r\ngrpc-status: 0\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        response.append(&mut body);
        response
    } else {
        let payload = format!(
            "{{\"echo\":true,\"path\":\"/\",\"body_bytes\":{}}}",
            body.len()
        );
        format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            payload.len(),
            payload
        )
        .into_bytes()
    };
    stream.write_all(&response).await?;
    stream.shutdown().await?;
    Ok(())
}

async fn read_http_request(stream: &mut TcpStream) -> Result<(String, Vec<u8>)> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 8192];
    let header_end = loop {
        let read = timeout(Duration::from_secs(5), stream.read(&mut chunk)).await??;
        if read == 0 {
            bail!("client closed before request head");
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(position) = find_subslice(&buffer, b"\r\n\r\n") {
            break position + 4;
        }
        if buffer.len() > 256 * 1024 {
            bail!("request head too large");
        }
    };
    let head = String::from_utf8_lossy(&buffer[..header_end]).to_string();
    let content_length = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.eq_ignore_ascii_case("content-length") {
                value.trim().parse::<usize>().ok()
            } else {
                None
            }
        })
        .unwrap_or(0);
    let mut body = buffer[header_end..].to_vec();
    while body.len() < content_length {
        let read = timeout(Duration::from_secs(5), stream.read(&mut chunk)).await??;
        if read == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..read]);
    }
    body.truncate(content_length);
    Ok((head, body))
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

// ---------------------------------------------------------------------------
// Soak
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Benign,
    Blocked,
    Oversized,
    Malformed,
    Grpc,
    WebSocket,
}

#[derive(Clone, Debug)]
struct Mix {
    entries: Vec<(Kind, u32)>,
    total: u32,
}

impl Mix {
    fn parse(value: &str) -> Result<Self> {
        let mut entries = Vec::new();
        for part in value.split(',') {
            let (name, weight) = part
                .split_once('=')
                .ok_or_else(|| anyhow!("mix entry {part:?} must be name=weight"))?;
            let kind = match name.trim() {
                "benign" => Kind::Benign,
                "blocked" => Kind::Blocked,
                "oversized" => Kind::Oversized,
                "malformed" => Kind::Malformed,
                "grpc" => Kind::Grpc,
                "websocket" => Kind::WebSocket,
                other => bail!("unknown mix kind {other:?}"),
            };
            let weight: u32 = weight.trim().parse()?;
            if weight > 0 {
                entries.push((kind, weight));
            }
        }
        if entries.is_empty() {
            bail!("mix must contain at least one positive weight");
        }
        let total = entries.iter().map(|(_, weight)| weight).sum();
        Ok(Self { entries, total })
    }

    fn pick(&self, index: u64) -> Kind {
        let mut slot = (index % self.total as u64) as u32;
        for (kind, weight) in &self.entries {
            if slot < *weight {
                return *kind;
            }
            slot -= *weight;
        }
        Kind::Benign
    }
}

#[derive(Default)]
struct MinuteBucket {
    minute: u64,
    requests: u64,
    errors: u64,
    blocked_attempts: u64,
    blocked_ok: u64,
    statuses: HashMap<u16, u64>,
    latency: [u64; LATENCY_BOUNDS_US.len()],
}

struct Recorder {
    start: Instant,
    buckets: Mutex<Vec<MinuteBucket>>,
}

impl Recorder {
    fn new() -> Self {
        Self {
            start: Instant::now(),
            buckets: Mutex::new(vec![MinuteBucket::default()]),
        }
    }

    fn record(&self, kind: Kind, status: Option<u16>, latency: Duration, success: bool) {
        let minute = self.start.elapsed().as_secs() / 60;
        let mut buckets = self.buckets.lock().expect("recorder lock");
        if buckets.last().map(|bucket| bucket.minute) != Some(minute) {
            buckets.push(MinuteBucket {
                minute,
                ..MinuteBucket::default()
            });
        }
        let bucket = buckets.last_mut().expect("bucket");
        bucket.requests += 1;
        if !success {
            bucket.errors += 1;
        }
        if kind == Kind::Blocked {
            bucket.blocked_attempts += 1;
            if status == Some(403) {
                bucket.blocked_ok += 1;
            }
        }
        if let Some(status) = status {
            *bucket.statuses.entry(status).or_insert(0) += 1;
        }
        let micros = latency.as_micros().min(u64::MAX as u128) as u64;
        let index = LATENCY_BOUNDS_US
            .iter()
            .position(|bound| micros <= *bound)
            .unwrap_or(LATENCY_BOUNDS_US.len() - 1);
        bucket.latency[index] += 1;
    }

    fn snapshot(&self) -> Vec<MinuteBucket> {
        self.buckets
            .lock()
            .expect("recorder lock")
            .iter()
            .map(|bucket| MinuteBucket {
                minute: bucket.minute,
                requests: bucket.requests,
                errors: bucket.errors,
                blocked_attempts: bucket.blocked_attempts,
                blocked_ok: bucket.blocked_ok,
                statuses: bucket.statuses.clone(),
                latency: bucket.latency,
            })
            .collect()
    }
}

fn percentile(bucket: &MinuteBucket, percentile: f64) -> u64 {
    let total: u64 = bucket.latency.iter().sum();
    if total == 0 {
        return 0;
    }
    let target = ((total as f64) * percentile).ceil() as u64;
    let mut seen = 0;
    for (index, count) in bucket.latency.iter().enumerate() {
        seen += count;
        if seen >= target {
            return LATENCY_BOUNDS_US[index];
        }
    }
    u64::MAX
}

#[derive(Clone, Debug)]
struct Sample {
    elapsed_s: f64,
    rss_kb: u64,
    fds: usize,
    threads: usize,
    connections: usize,
}

fn read_proc_status(pid: u32) -> Result<(u64, usize)> {
    let status = fs::read_to_string(format!("/proc/{pid}/status"))?;
    let mut rss_kb = 0;
    let mut threads = 0;
    for line in status.lines() {
        if let Some(value) = line.strip_prefix("VmRSS:") {
            rss_kb = value
                .split_whitespace()
                .next()
                .and_then(|value| value.parse().ok())
                .unwrap_or(0);
        } else if let Some(value) = line.strip_prefix("Threads:") {
            threads = value.trim().parse().unwrap_or(0);
        }
    }
    Ok((rss_kb, threads))
}

fn process_socket_inodes(pid: u32) -> Result<HashSet<u64>> {
    let mut inodes = HashSet::new();
    for entry in fs::read_dir(format!("/proc/{pid}/fd"))? {
        let entry = entry?;
        if let Ok(target) = fs::read_link(entry.path()) {
            if let Some(value) = target.to_str() {
                if let Some(inode) = value
                    .strip_prefix("socket:[")
                    .and_then(|value| value.strip_suffix(']'))
                {
                    if let Ok(inode) = inode.parse() {
                        inodes.insert(inode);
                    }
                }
            }
        }
    }
    Ok(inodes)
}

fn count_connections(pid: u32) -> Result<usize> {
    let inodes = process_socket_inodes(pid)?;
    let mut count = 0;
    for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
        let Ok(table) = fs::read_to_string(path) else {
            continue;
        };
        for line in table.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 10 {
                continue;
            }
            let state = fields[3];
            let inode: u64 = fields[9].parse().unwrap_or(0);
            if state != "0A" && inodes.contains(&inode) {
                count += 1;
            }
        }
    }
    Ok(count)
}

fn sample_proc(pid: u32, start: Instant) -> Result<Sample> {
    let (rss_kb, threads) = read_proc_status(pid)?;
    let fds = fs::read_dir(format!("/proc/{pid}/fd"))?.count();
    let connections = count_connections(pid)?;
    Ok(Sample {
        elapsed_s: start.elapsed().as_secs_f64(),
        rss_kb,
        fds,
        threads,
        connections,
    })
}

fn rss_slope_mb_per_min(samples: &[Sample], warmup_s: f64) -> f64 {
    let points: Vec<(f64, f64)> = samples
        .iter()
        .filter(|sample| sample.elapsed_s >= warmup_s)
        .map(|sample| (sample.elapsed_s / 60.0, sample.rss_kb as f64 / 1024.0))
        .collect();
    if points.len() < 2 {
        return 0.0;
    }
    let n = points.len() as f64;
    let mean_x = points.iter().map(|(x, _)| x).sum::<f64>() / n;
    let mean_y = points.iter().map(|(_, y)| y).sum::<f64>() / n;
    let mut covariance = 0.0;
    let mut variance = 0.0;
    for (x, y) in &points {
        covariance += (x - mean_x) * (y - mean_y);
        variance += (x - mean_x) * (x - mean_x);
    }
    if variance == 0.0 {
        0.0
    } else {
        covariance / variance
    }
}

struct ProxyOptions {
    max_connections: usize,
    request_timeout_secs: u64,
    max_body_size: usize,
    ws_tunnels: usize,
    ws_idle_secs: u64,
    ws_lifetime_secs: u64,
    keep_alive_secs: u64,
}

impl Default for ProxyOptions {
    fn default() -> Self {
        Self {
            max_connections: 10_000,
            request_timeout_secs: 30,
            max_body_size: 1024 * 1024,
            ws_tunnels: 1024,
            ws_idle_secs: 300,
            ws_lifetime_secs: 3600,
            keep_alive_secs: 30,
        }
    }
}

fn write_config(
    path: &Path,
    proxy_port: u16,
    health_port: u16,
    upstream_port: u16,
    options: &ProxyOptions,
) -> Result<()> {
    let config = format!(
        r#"bind_addr = "127.0.0.1:{proxy_port}"
health_bind_addr = "127.0.0.1:{health_port}"
upstream_uri = "http://127.0.0.1:{upstream_port}"

[health]
dependency_checks = false

[proxy]
timeout_seconds = {request_timeout}
max_request_size = {max_body}

[server]
max_connections = {max_connections}
trusted_proxies = []
request_timeout_secs = {request_timeout}
keep_alive_timeout_secs = {keep_alive}
enable_http2 = true
enable_http3 = false
supported_http_versions = ["1.0", "1.1", "2"]
max_body_size = {max_body}
max_header_count = 200
max_header_bytes = 65536

[server.websocket]
max_concurrent_tunnels = {ws_tunnels}
idle_timeout_secs = {ws_idle}
max_lifetime_secs = {ws_lifetime}

[logging]
level = "warn"
json_format = false

[waf]
enabled = true
fail_mode = "closed"

[waf.rate_limit]
per_ip_enabled = false
global_enabled = false

[waf.security_events]
enabled = false

[waf.content_inspection]
enabled = true
inspect_headers = true
inspect_body = true
max_body_size = {max_body}
threat_patterns = ["sql_injection", "xss", "command_injection", "path_traversal"]

[waf.geo_blocking]
enabled = false

[waf.admission]
enabled = false

[storage]
enabled = false
"#,
        request_timeout = options.request_timeout_secs,
        max_body = options.max_body_size,
        max_connections = options.max_connections,
        keep_alive = options.keep_alive_secs,
        ws_tunnels = options.ws_tunnels,
        ws_idle = options.ws_idle_secs,
        ws_lifetime = options.ws_lifetime_secs,
    );
    fs::write(path, config)?;
    Ok(())
}

async fn wait_tcp(port: u16, duration: Duration) -> Result<()> {
    let deadline = Instant::now() + duration;
    loop {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!("timed out waiting for 127.0.0.1:{port}");
        }
        sleep(Duration::from_millis(100)).await;
    }
}

async fn spawn_backend(self_bin: &Path, port: u16, mode: &str, delay_ms: u64) -> Result<Child> {
    let child = Command::new(self_bin)
        .arg("serve")
        .arg("--port")
        .arg(port.to_string())
        .arg("--mode")
        .arg(mode)
        .arg("--delay-ms")
        .arg(delay_ms.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("spawn fixture {mode}"))?;
    wait_tcp(port, Duration::from_secs(10)).await?;
    Ok(child)
}

async fn spawn_proxy(waf_bin: &Path, config: &Path) -> Result<Child> {
    let child = Command::new(waf_bin)
        .env("WAF_CONFIG_FILE", config)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("spawn {}", waf_bin.display()))?;
    Ok(child)
}

async fn stop_child(child: &mut Option<Child>) {
    if let Some(mut child) = child.take() {
        let _ = child.start_kill();
        let _ = child.wait().await;
    }
}

fn child_alive(child: &mut Option<Child>) -> bool {
    match child {
        Some(child) => matches!(child.try_wait(), Ok(None)),
        None => false,
    }
}

async fn raw_http(port: u16, request: &[u8], read_timeout: Duration) -> Result<(u16, Vec<u8>)> {
    let mut stream = timeout(
        Duration::from_secs(5),
        TcpStream::connect(("127.0.0.1", port)),
    )
    .await
    .context("connect timeout")??;
    stream.write_all(request).await?;
    let mut response = Vec::new();
    let _ = timeout(read_timeout, stream.read_to_end(&mut response)).await;
    let status = parse_status(&response).ok_or_else(|| anyhow!("no HTTP status in response"))?;
    Ok((status, response))
}

fn parse_status(response: &[u8]) -> Option<u16> {
    let text = String::from_utf8_lossy(response);
    let first = text.lines().next()?;
    let mut parts = first.split_whitespace();
    let _version = parts.next()?;
    parts.next()?.parse().ok()
}

fn request_for(kind: Kind, body_size: usize, oversized_bytes: usize) -> Vec<u8> {
    match kind {
        Kind::Benign => {
            let body = format!("{{\"data\":\"{}\"}}", "x".repeat(body_size));
            format!(
                "POST /api/echo HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .into_bytes()
        }
        Kind::Blocked => match fastrand_index(3) {
            0 => format!(
                "GET {SQLI} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
            )
            .into_bytes(),
            1 => {
                let body = format!("{{\"comment\":\"{XSS}\"}}");
                format!(
                    "POST /api/comment HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                )
                .into_bytes()
            }
            _ => format!(
                "GET {TRAVERSAL} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
            )
            .into_bytes(),
        },
        Kind::Oversized => {
            let body = "A".repeat(oversized_bytes);
            format!(
                "POST /api/upload HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .into_bytes()
        }
        Kind::Malformed => {
            b"POST /api/echo HTTP/1.1\r\nHost: 127.0.0.1\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\nZZ\r\n".to_vec()
        }
        Kind::Grpc => {
            let mut body = vec![0u8, 0, 0, 0, 5];
            body.extend_from_slice(b"hello");
            let mut request = format!(
                "POST /grpc.health.v1.Health/Check HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/grpc\r\nTE: trailers\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .into_bytes();
            request.extend_from_slice(&body);
            request
        }
        Kind::WebSocket => Vec::new(),
    }
}

fn fastrand_index(modulus: u64) -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.subsec_nanos() as u64)
        .unwrap_or(0)
        % modulus
}

fn classify(kind: Kind, status: Option<u16>) -> bool {
    match kind {
        Kind::Benign | Kind::Grpc => matches!(status, Some(200..=399)),
        Kind::Blocked => status == Some(403),
        Kind::Oversized => status == Some(413),
        Kind::Malformed => matches!(status, Some(400 | 413 | 431)) || status.is_none(),
        Kind::WebSocket => status == Some(101),
    }
}

async fn websocket_session(port: u16) -> Result<u16> {
    let url = format!("ws://127.0.0.1:{port}/ws");
    let (mut socket, response) = timeout(
        Duration::from_secs(5),
        tokio_tungstenite::connect_async(url),
    )
    .await
    .context("websocket connect timeout")??;
    let status = response.status().as_u16();
    if status != 101 {
        return Ok(status);
    }
    socket.send(Message::Text("soak".into())).await?;
    let _ = timeout(Duration::from_secs(2), socket.next()).await;
    let _ = socket.close(None).await;
    Ok(101)
}

async fn run_one(
    port: u16,
    kind: Kind,
    body_size: usize,
    oversized_bytes: usize,
    read_timeout: Duration,
) -> (Option<u16>, Duration) {
    let start = Instant::now();
    let status = if kind == Kind::WebSocket {
        websocket_session(port).await.ok()
    } else {
        let request = request_for(kind, body_size, oversized_bytes);
        raw_http(port, &request, read_timeout)
            .await
            .ok()
            .map(|(status, _)| status)
    };
    (status, start.elapsed())
}

async fn soak(args: &[String]) -> Result<()> {
    let map = arg_map(args);
    let waf_bin = PathBuf::from(get(&map, "waf-bin", "target/release/waf-ingress"));
    let self_bin = PathBuf::from(get(&map, "self-bin", "target/release/soak-load"));
    let duration = parse_duration(get(&map, "duration", "60s"))?;
    let warmup = parse_duration(get(&map, "warmup", "10s"))?;
    let concurrency = get_usize(&map, "concurrency", 16).max(1);
    let mix = Mix::parse(get(
        &map,
        "mix",
        "benign=40,blocked=20,oversized=5,malformed=5,grpc=15,websocket=15",
    ))?;
    let body_size = get_usize(&map, "body-size", 4096);
    let oversized_bytes = get_usize(&map, "oversized-bytes", 1536 * 1024);
    let sample_interval = parse_duration(get(&map, "sample-interval", "2s"))?;
    let max_rss_slope = get_f64(&map, "max-rss-slope-mb-per-min", 2.0);
    let max_fd_growth = get_u64(&map, "max-fd-growth", 32) as i64;
    let max_conn_growth = get_u64(&map, "max-conn-growth", 32) as i64;
    let max_error_rate = get_f64(&map, "max-error-rate", 0.01);
    let min_block_rate = get_f64(&map, "min-block-rate", 0.99);
    let report_path = map.get("report").map(PathBuf::from);
    let dir = work_dir(&map)?;

    let backend_port = free_port()?;
    let proxy_port = free_port()?;
    let health_port = free_port()?;
    let config_path = dir.join("soak.toml");
    let options = ProxyOptions {
        max_body_size: 1024 * 1024,
        ..ProxyOptions::default()
    };
    write_config(
        &config_path,
        proxy_port,
        health_port,
        backend_port,
        &options,
    )?;

    println!(
        "soak: duration={}s warmup={}s concurrency={} mix={} body={}B oversized={}B",
        duration.as_secs(),
        warmup.as_secs(),
        concurrency,
        get(&map, "mix", "default"),
        body_size,
        oversized_bytes
    );

    let mut backend = Some(spawn_backend(&self_bin, backend_port, "echo", 0).await?);
    let mut proxy = Some(spawn_proxy(&waf_bin, &config_path).await?);
    wait_tcp(proxy_port, Duration::from_secs(20)).await?;
    let pid = proxy
        .as_ref()
        .and_then(Child::id)
        .ok_or_else(|| anyhow!("proxy pid"))?;

    let recorder = Arc::new(Recorder::new());
    let stop = Arc::new(AtomicBool::new(false));
    let start = Instant::now();
    let samples = Arc::new(Mutex::new(Vec::new()));
    let sampler = {
        let samples = Arc::clone(&samples);
        let stop = Arc::clone(&stop);
        tokio::spawn(async move {
            while !stop.load(Ordering::Relaxed) {
                if let Ok(sample) = sample_proc(pid, start) {
                    samples.lock().expect("samples lock").push(sample);
                }
                sleep(sample_interval).await;
            }
        })
    };

    let mut workers = Vec::new();
    for worker in 0..concurrency {
        let recorder = Arc::clone(&recorder);
        let stop = Arc::clone(&stop);
        let mix = mix.clone();
        workers.push(tokio::spawn(async move {
            let mut index = worker as u64;
            while !stop.load(Ordering::Relaxed) {
                let kind = mix.pick(index);
                index = index.wrapping_add(1);
                let (status, latency) = run_one(
                    proxy_port,
                    kind,
                    body_size,
                    oversized_bytes,
                    Duration::from_secs(5),
                )
                .await;
                recorder.record(kind, status, latency, classify(kind, status));
            }
        }));
    }

    sleep(duration).await;
    stop.store(true, Ordering::Relaxed);
    for worker in workers {
        let _ = worker.await;
    }
    sampler.abort();
    let _ = sampler.await;

    let canonical = canonical_check(proxy_port).await;
    let buckets = recorder.snapshot();
    let samples = samples.lock().expect("samples lock").clone();
    let total_requests: u64 = buckets.iter().map(|bucket| bucket.requests).sum();
    let total_errors: u64 = buckets.iter().map(|bucket| bucket.errors).sum();
    let blocked_attempts: u64 = buckets.iter().map(|bucket| bucket.blocked_attempts).sum();
    let blocked_ok: u64 = buckets.iter().map(|bucket| bucket.blocked_ok).sum();
    let error_rate = if total_requests == 0 {
        1.0
    } else {
        total_errors as f64 / total_requests as f64
    };
    let block_rate = if blocked_attempts == 0 {
        0.0
    } else {
        blocked_ok as f64 / blocked_attempts as f64
    };
    let slope = rss_slope_mb_per_min(&samples, warmup.as_secs_f64());
    let baseline = samples
        .iter()
        .find(|sample| sample.elapsed_s >= warmup.as_secs_f64())
        .or_else(|| samples.first());
    let fd_growth = baseline
        .map(|base| {
            samples
                .iter()
                .map(|sample| sample.fds)
                .max()
                .unwrap_or(base.fds) as i64
                - base.fds as i64
        })
        .unwrap_or(0);
    let conn_growth = baseline
        .map(|base| {
            samples
                .iter()
                .map(|sample| sample.connections)
                .max()
                .unwrap_or(base.connections) as i64
                - base.connections as i64
        })
        .unwrap_or(0);

    let mut failures = Vec::new();
    if slope > max_rss_slope {
        failures.push(format!(
            "RSS slope {slope:.2} MB/min exceeds {max_rss_slope:.2} MB/min"
        ));
    }
    if fd_growth > max_fd_growth {
        failures.push(format!("FD growth {fd_growth} exceeds {max_fd_growth}"));
    }
    if conn_growth > max_conn_growth {
        failures.push(format!(
            "connection growth {conn_growth} exceeds {max_conn_growth}"
        ));
    }
    if error_rate > max_error_rate {
        failures.push(format!(
            "error rate {:.2}% exceeds {:.2}%",
            error_rate * 100.0,
            max_error_rate * 100.0
        ));
    }
    if blocked_attempts > 0 && block_rate < min_block_rate {
        failures.push(format!(
            "block rate {:.2}% below {:.2}%",
            block_rate * 100.0,
            min_block_rate * 100.0
        ));
    }
    if !canonical {
        failures.push("canonical blocked payload was not blocked at end of run".to_string());
    }
    if total_requests == 0 {
        failures.push("no requests completed".to_string());
    }

    println!("\nper-minute steady state:");
    for bucket in &buckets {
        let statuses = bucket
            .statuses
            .iter()
            .map(|(status, count)| format!("{status}:{count}"))
            .collect::<Vec<_>>()
            .join(" ");
        println!(
            "  minute {}: req={} err={} p50={}us p95={}us p99={}us block={}/{} statuses=[{}]",
            bucket.minute,
            bucket.requests,
            bucket.errors,
            percentile(bucket, 0.50),
            percentile(bucket, 0.95),
            percentile(bucket, 0.99),
            bucket.blocked_ok,
            bucket.blocked_attempts,
            statuses
        );
    }
    if let (Some(first), Some(last)) = (samples.first(), samples.last()) {
        println!(
            "resources: rss {:.1}->{:.1} MiB, fds {}->{}, threads {}->{}, connections {}->{}",
            first.rss_kb as f64 / 1024.0,
            last.rss_kb as f64 / 1024.0,
            first.fds,
            last.fds,
            first.threads,
            last.threads,
            first.connections,
            last.connections
        );
    }
    println!(
        "summary: requests={total_requests} errors={total_errors} error_rate={:.2}% block_rate={:.2}% rss_slope={slope:.2}MB/min fd_growth={fd_growth} conn_growth={conn_growth} canonical_blocked={canonical}",
        error_rate * 100.0,
        block_rate * 100.0
    );

    if let Some(path) = report_path {
        let report = json!({
            "kind": "soak",
            "duration_secs": duration.as_secs(),
            "warmup_secs": warmup.as_secs(),
            "concurrency": concurrency,
            "mix": get(&map, "mix", "default"),
            "body_size": body_size,
            "oversized_bytes": oversized_bytes,
            "thresholds": {
                "max_rss_slope_mb_per_min": max_rss_slope,
                "max_fd_growth": max_fd_growth,
                "max_conn_growth": max_conn_growth,
                "max_error_rate": max_error_rate,
                "min_block_rate": min_block_rate,
            },
            "summary": {
                "requests": total_requests,
                "errors": total_errors,
                "error_rate": error_rate,
                "blocked_attempts": blocked_attempts,
                "blocked_ok": blocked_ok,
                "block_rate": block_rate,
                "rss_slope_mb_per_min": slope,
                "fd_growth": fd_growth,
                "connection_growth": conn_growth,
                "canonical_blocked": canonical,
            },
            "minutes": buckets.iter().map(|bucket| json!({
                "minute": bucket.minute,
                "requests": bucket.requests,
                "errors": bucket.errors,
                "p50_us": percentile(bucket, 0.50),
                "p95_us": percentile(bucket, 0.95),
                "p99_us": percentile(bucket, 0.99),
                "blocked_ok": bucket.blocked_ok,
                "blocked_attempts": bucket.blocked_attempts,
                "statuses": bucket.statuses,
            })).collect::<Vec<_>>(),
            "samples": samples.iter().map(|sample| json!({
                "elapsed_s": sample.elapsed_s,
                "rss_kb": sample.rss_kb,
                "fds": sample.fds,
                "threads": sample.threads,
                "connections": sample.connections,
            })).collect::<Vec<_>>(),
            "host": host_info(),
            "failures": failures,
            "passed": failures.is_empty(),
        });
        fs::write(path, serde_json::to_vec_pretty(&report)?)?;
    }

    stop_child(&mut proxy).await;
    stop_child(&mut backend).await;

    if failures.is_empty() {
        println!("VERDICT: PASS");
        Ok(())
    } else {
        for failure in &failures {
            eprintln!("FAIL: {failure}");
        }
        println!("VERDICT: FAIL");
        bail!("soak failed: {}", failures.join("; "))
    }
}

fn host_info() -> serde_json::Value {
    let load = fs::read_to_string("/proc/loadavg").unwrap_or_default();
    let cpu = fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|text| {
            text.lines()
                .find(|line| line.starts_with("model name"))
                .and_then(|line| line.split_once(':'))
                .map(|(_, value)| value.trim().to_string())
        })
        .unwrap_or_else(|| "unknown".to_string());
    let mem = fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|text| {
            text.lines()
                .find(|line| line.starts_with("MemTotal:"))
                .map(|line| line.to_string())
        })
        .unwrap_or_default();
    json!({
        "loadavg": load.trim(),
        "cpu": cpu,
        "meminfo": mem.trim(),
        "cpus": std::thread::available_parallelism().map(|value| value.get()).unwrap_or(0),
    })
}

async fn canonical_check(port: u16) -> bool {
    let payloads = [
        format!("GET {SQLI} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"),
        format!(
            "POST /api/comment HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{{\"comment\":\"{XSS}\"}}",
            format!("{{\"comment\":\"{XSS}\"}}").len()
        ),
        format!("GET {TRAVERSAL} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"),
    ];
    for payload in payloads {
        match raw_http(port, payload.as_bytes(), Duration::from_secs(5)).await {
            Ok((403, _)) => {}
            Ok((status, _)) => {
                eprintln!("canonical payload returned {status}, expected 403");
                return false;
            }
            Err(error) => {
                eprintln!("canonical payload failed: {error}");
                return false;
            }
        }
    }
    true
}

// ---------------------------------------------------------------------------
// Fault injection
// ---------------------------------------------------------------------------

struct ScenarioResult {
    name: &'static str,
    passed: bool,
    detail: String,
}

async fn faults(args: &[String]) -> Result<()> {
    let map = arg_map(args);
    let waf_bin = PathBuf::from(get(&map, "waf-bin", "target/release/waf-ingress"));
    let self_bin = PathBuf::from(get(&map, "self-bin", "target/release/soak-load"));
    let dir = work_dir(&map)?;
    let mut results = Vec::new();

    results.push(scenario_upstream_unavailable(&waf_bin, &self_bin, &dir).await);
    results.push(scenario_slow_upstream(&waf_bin, &self_bin, &dir).await);
    results.push(scenario_malformed_upstream(&waf_bin, &self_bin, &dir).await);
    results.push(scenario_waf_restart(&waf_bin, &self_bin, &dir).await);
    results.push(scenario_connection_flood(&waf_bin, &self_bin, &dir).await);
    results.push(scenario_websocket_abandon(&waf_bin, &self_bin, &dir).await);

    println!("\nfault scenarios:");
    let mut failed = 0;
    for result in &results {
        println!(
            "  {} {}: {}",
            if result.passed { "PASS" } else { "FAIL" },
            result.name,
            result.detail
        );
        if !result.passed {
            failed += 1;
        }
    }
    if failed == 0 {
        println!("VERDICT: PASS");
        Ok(())
    } else {
        println!("VERDICT: FAIL ({failed} scenario(s))");
        bail!("{failed} fault scenario(s) failed")
    }
}

async fn scenario_upstream_unavailable(
    waf_bin: &Path,
    self_bin: &Path,
    dir: &Path,
) -> ScenarioResult {
    let name = "upstream-unavailable-mid-run";
    let result = async {
        let backend_port = free_port()?;
        let proxy_port = free_port()?;
        let health_port = free_port()?;
        let config = dir.join("fault-unavailable.toml");
        write_config(
            &config,
            proxy_port,
            health_port,
            backend_port,
            &ProxyOptions::default(),
        )?;
        let mut backend = Some(spawn_backend(self_bin, backend_port, "echo", 0).await?);
        let mut proxy = Some(spawn_proxy(waf_bin, &config).await?);
        wait_tcp(proxy_port, Duration::from_secs(20)).await?;
        let (status, _) = raw_http(
            proxy_port,
            b"GET /api/echo HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
            Duration::from_secs(5),
        )
        .await?;
        if status != 200 {
            bail!("initial request returned {status}");
        }
        let load = tokio::spawn(load_loop(proxy_port, Duration::from_secs(8), 4));
        sleep(Duration::from_secs(2)).await;
        stop_child(&mut backend).await;
        sleep(Duration::from_secs(1)).await;
        let mut saw_unavailable = false;
        for _ in 0..5 {
            if let Ok((status, _)) = raw_http(
                proxy_port,
                b"GET /api/echo HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
                Duration::from_secs(5),
            )
            .await
            {
                if status == 502 || status == 503 {
                    saw_unavailable = true;
                }
            }
        }
        if !saw_unavailable {
            bail!("no 502/503 while upstream was down");
        }
        backend = Some(spawn_backend(self_bin, backend_port, "echo", 0).await?);
        sleep(Duration::from_secs(1)).await;
        let mut recovered = 0;
        for _ in 0..5 {
            if let Ok((200, _)) = raw_http(
                proxy_port,
                b"GET /api/echo HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
                Duration::from_secs(5),
            )
            .await
            {
                recovered += 1;
            }
        }
        load.abort();
        let _ = load.await;
        if recovered == 0 {
            bail!("proxy did not recover after upstream restart");
        }
        if !child_alive(&mut proxy) {
            bail!("proxy exited");
        }
        if !canonical_check(proxy_port).await {
            bail!("inspection bypass after recovery");
        }
        stop_child(&mut proxy).await;
        stop_child(&mut backend).await;
        Ok::<String, anyhow::Error>(format!(
            "saw 502/503 during outage, {recovered}/5 recovered without proxy restart"
        ))
    }
    .await;
    scenario_result(name, result)
}

async fn scenario_slow_upstream(waf_bin: &Path, self_bin: &Path, dir: &Path) -> ScenarioResult {
    let name = "slow-upstream-timeout";
    let result = async {
        let backend_port = free_port()?;
        let proxy_port = free_port()?;
        let health_port = free_port()?;
        let config = dir.join("fault-slow.toml");
        let options = ProxyOptions {
            request_timeout_secs: 2,
            ..ProxyOptions::default()
        };
        write_config(&config, proxy_port, health_port, backend_port, &options)?;
        let mut backend = Some(spawn_backend(self_bin, backend_port, "slow", 5000).await?);
        let mut proxy = Some(spawn_proxy(waf_bin, &config).await?);
        wait_tcp(proxy_port, Duration::from_secs(20)).await?;
        let pid = proxy
            .as_ref()
            .and_then(Child::id)
            .ok_or_else(|| anyhow!("proxy pid"))?;
        let before = count_connections(pid).unwrap_or(0);
        let mut tasks = Vec::new();
        for _ in 0..10 {
            tasks.push(tokio::spawn(async move {
                raw_http(
                    proxy_port,
                    b"GET /api/slow HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
                    Duration::from_secs(8),
                )
                .await
                .ok()
                .map(|(status, _)| status)
            }));
        }
        let mut timeouts = 0;
        for task in tasks {
            if let Ok(Some(status)) = task.await {
                if status == 504 {
                    timeouts += 1;
                }
            }
        }
        sleep(Duration::from_secs(1)).await;
        let after = count_connections(pid).unwrap_or(0);
        if timeouts < 8 {
            bail!("only {timeouts}/10 slow requests timed out with 504");
        }
        if after > before + 4 {
            bail!("connection leak after timeouts: {before} -> {after}");
        }
        if !child_alive(&mut proxy) {
            bail!("proxy exited");
        }
        if !canonical_check(proxy_port).await {
            bail!("inspection bypass after slow upstream");
        }
        stop_child(&mut proxy).await;
        stop_child(&mut backend).await;
        Ok::<String, anyhow::Error>(format!(
            "{timeouts}/10 timed out with 504, connections {before}->{after}"
        ))
    }
    .await;
    scenario_result(name, result)
}

async fn scenario_malformed_upstream(
    waf_bin: &Path,
    self_bin: &Path,
    dir: &Path,
) -> ScenarioResult {
    let name = "malformed-upstream-responses";
    let result = async {
        let backend_port = free_port()?;
        let proxy_port = free_port()?;
        let health_port = free_port()?;
        let config = dir.join("fault-malformed.toml");
        write_config(
            &config,
            proxy_port,
            health_port,
            backend_port,
            &ProxyOptions::default(),
        )?;
        let mut backend = Some(spawn_backend(self_bin, backend_port, "echo", 0).await?);
        let mut proxy = Some(spawn_proxy(waf_bin, &config).await?);
        wait_tcp(proxy_port, Duration::from_secs(20)).await?;
        let mut checked = Vec::new();
        for mode in ["malformed", "truncated", "bad-framing", "huge-headers"] {
            stop_child(&mut backend).await;
            backend = Some(spawn_backend(self_bin, backend_port, mode, 0).await?);
            sleep(Duration::from_millis(200)).await;
            let _ = raw_http(
                proxy_port,
                b"GET /api/echo HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
                Duration::from_secs(5),
            )
            .await;
            if !child_alive(&mut proxy) {
                bail!("proxy exited on {mode} upstream response");
            }
            if !canonical_check(proxy_port).await {
                bail!("inspection bypass with {mode} upstream response");
            }
            checked.push(mode);
        }
        stop_child(&mut proxy).await;
        stop_child(&mut backend).await;
        Ok::<String, anyhow::Error>(format!(
            "survived {} without panic or bypass",
            checked.join(", ")
        ))
    }
    .await;
    scenario_result(name, result)
}

async fn scenario_waf_restart(waf_bin: &Path, self_bin: &Path, dir: &Path) -> ScenarioResult {
    let name = "waf-restart-under-load";
    let result = async {
        let backend_port = free_port()?;
        let proxy_port = free_port()?;
        let health_port = free_port()?;
        let config = dir.join("fault-restart.toml");
        write_config(
            &config,
            proxy_port,
            health_port,
            backend_port,
            &ProxyOptions::default(),
        )?;
        let mut backend = Some(spawn_backend(self_bin, backend_port, "echo", 0).await?);
        let mut proxy = Some(spawn_proxy(waf_bin, &config).await?);
        wait_tcp(proxy_port, Duration::from_secs(20)).await?;
        let successes = Arc::new(AtomicU64::new(0));
        let errors = Arc::new(AtomicU64::new(0));
        let load = tokio::spawn(load_loop_counted(
            proxy_port,
            Duration::from_secs(10),
            4,
            Arc::clone(&successes),
            Arc::clone(&errors),
        ));
        sleep(Duration::from_secs(2)).await;
        stop_child(&mut proxy).await;
        sleep(Duration::from_secs(1)).await;
        proxy = Some(spawn_proxy(waf_bin, &config).await?);
        wait_tcp(proxy_port, Duration::from_secs(20)).await?;
        sleep(Duration::from_secs(2)).await;
        load.abort();
        let _ = load.await;
        if successes.load(Ordering::Relaxed) == 0 {
            bail!("no successful requests across restart");
        }
        if errors.load(Ordering::Relaxed) == 0 {
            bail!("load generator saw no downtime errors; restart was not exercised");
        }
        let mut ok = 0;
        for _ in 0..20 {
            if let Ok((200, _)) = raw_http(
                proxy_port,
                b"GET /api/echo HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
                Duration::from_secs(5),
            )
            .await
            {
                ok += 1;
            }
        }
        if ok < 20 {
            bail!("only {ok}/20 requests succeeded after restart");
        }
        if !canonical_check(proxy_port).await {
            bail!("inspection bypass after restart");
        }
        stop_child(&mut proxy).await;
        stop_child(&mut backend).await;
        Ok::<String, anyhow::Error>(format!(
            "{} successes, {} downtime errors, 20/20 after restart",
            successes.load(Ordering::Relaxed),
            errors.load(Ordering::Relaxed)
        ))
    }
    .await;
    scenario_result(name, result)
}

async fn scenario_connection_flood(waf_bin: &Path, self_bin: &Path, dir: &Path) -> ScenarioResult {
    let name = "connection-flood-limits";
    let result = async {
        let backend_port = free_port()?;
        let proxy_port = free_port()?;
        let health_port = free_port()?;
        let config = dir.join("fault-flood.toml");
        let options = ProxyOptions {
            max_connections: 8,
            ..ProxyOptions::default()
        };
        write_config(&config, proxy_port, health_port, backend_port, &options)?;
        let mut backend = Some(spawn_backend(self_bin, backend_port, "echo", 0).await?);
        let mut proxy = Some(spawn_proxy(waf_bin, &config).await?);
        wait_tcp(proxy_port, Duration::from_secs(20)).await?;
        let mut held = Vec::new();
        for _ in 0..8 {
            held.push(TcpStream::connect(("127.0.0.1", proxy_port)).await?);
        }
        sleep(Duration::from_millis(300)).await;
        let mut rejected = 0;
        for _ in 0..20 {
            if let Ok(mut stream) = TcpStream::connect(("127.0.0.1", proxy_port)).await {
                let mut buffer = Vec::new();
                let _ = timeout(Duration::from_secs(1), stream.read_to_end(&mut buffer)).await;
                if parse_status(&buffer) == Some(503) {
                    rejected += 1;
                }
            }
        }
        if rejected == 0 {
            bail!("no 503 rejections at max_connections=8");
        }
        let health = raw_http(
            health_port,
            b"GET /health/live HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
            Duration::from_secs(2),
        )
        .await;
        if !matches!(health, Ok((200, _))) {
            bail!("health endpoint unresponsive during flood");
        }
        drop(held);
        sleep(Duration::from_millis(500)).await;
        let (status, _) = raw_http(
            proxy_port,
            b"GET /api/echo HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
            Duration::from_secs(5),
        )
        .await?;
        if status != 200 {
            bail!("proxy did not recover after flood: {status}");
        }
        if !canonical_check(proxy_port).await {
            bail!("inspection bypass after flood");
        }
        stop_child(&mut proxy).await;
        stop_child(&mut backend).await;
        Ok::<String, anyhow::Error>(format!(
            "{rejected}/20 excess connections rejected with 503, health responsive"
        ))
    }
    .await;
    scenario_result(name, result)
}

async fn scenario_websocket_abandon(waf_bin: &Path, self_bin: &Path, dir: &Path) -> ScenarioResult {
    let name = "websocket-abandoned-tunnels";
    let result = async {
        let backend_port = free_port()?;
        let proxy_port = free_port()?;
        let health_port = free_port()?;
        let config = dir.join("fault-websocket.toml");
        let options = ProxyOptions {
            ws_tunnels: 4,
            ws_idle_secs: 2,
            ws_lifetime_secs: 10,
            ..ProxyOptions::default()
        };
        write_config(&config, proxy_port, health_port, backend_port, &options)?;
        let mut backend = Some(spawn_backend(self_bin, backend_port, "echo", 0).await?);
        let mut proxy = Some(spawn_proxy(waf_bin, &config).await?);
        wait_tcp(proxy_port, Duration::from_secs(20)).await?;
        let mut opened = Vec::new();
        let mut rejected = 0;
        for _ in 0..10 {
            match timeout(
                Duration::from_secs(5),
                tokio_tungstenite::connect_async(format!("ws://127.0.0.1:{proxy_port}/ws")),
            )
            .await
            {
                Ok(Ok((socket, response))) if response.status().as_u16() == 101 => {
                    opened.push(socket);
                }
                _ => rejected += 1,
            }
        }
        if opened.len() != 4 {
            bail!(
                "expected 4 admitted tunnels at cap, got {} (rejected {rejected})",
                opened.len()
            );
        }
        drop(opened);
        sleep(Duration::from_secs(4)).await;
        let reaped = timeout(
            Duration::from_secs(5),
            tokio_tungstenite::connect_async(format!("ws://127.0.0.1:{proxy_port}/ws")),
        )
        .await;
        match reaped {
            Ok(Ok((mut socket, response))) if response.status().as_u16() == 101 => {
                let _ = socket.close(None).await;
            }
            _ => bail!("abandoned tunnels were not reaped by idle timeout"),
        }
        if !canonical_check(proxy_port).await {
            bail!("inspection bypass after websocket churn");
        }
        stop_child(&mut proxy).await;
        stop_child(&mut backend).await;
        Ok::<String, anyhow::Error>(format!(
            "4 admitted, {rejected} rejected at cap, idle timeout reaped abandoned tunnels"
        ))
    }
    .await;
    scenario_result(name, result)
}

fn scenario_result(name: &'static str, result: Result<String>) -> ScenarioResult {
    match result {
        Ok(detail) => ScenarioResult {
            name,
            passed: true,
            detail,
        },
        Err(error) => ScenarioResult {
            name,
            passed: false,
            detail: format!("{error:#}"),
        },
    }
}

async fn load_loop(port: u16, duration: Duration, concurrency: usize) {
    let successes = Arc::new(AtomicU64::new(0));
    let errors = Arc::new(AtomicU64::new(0));
    load_loop_counted(port, duration, concurrency, successes, errors).await;
}

async fn load_loop_counted(
    port: u16,
    duration: Duration,
    concurrency: usize,
    successes: Arc<AtomicU64>,
    errors: Arc<AtomicU64>,
) {
    let deadline = Instant::now() + duration;
    let mut workers = Vec::new();
    for _ in 0..concurrency.max(1) {
        let successes = Arc::clone(&successes);
        let errors = Arc::clone(&errors);
        workers.push(tokio::spawn(async move {
            while Instant::now() < deadline {
                match raw_http(
                    port,
                    b"GET /api/echo HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
                    Duration::from_secs(3),
                )
                .await
                {
                    Ok((200, _)) => {
                        successes.fetch_add(1, Ordering::Relaxed);
                    }
                    _ => {
                        errors.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }));
    }
    for worker in workers {
        let _ = worker.await;
    }
}
