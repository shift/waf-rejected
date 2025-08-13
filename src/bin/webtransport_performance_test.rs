use anyhow::Result;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::error;
use url::Url;
use web_transport_quinn as wtq;

#[derive(Clone, Copy)]
enum Mode { Bidi, Datagram }

#[tokio::main]
async fn main() -> Result<()> {
    // Reduce harness logging overhead
    tracing_subscriber::fmt().with_max_level(tracing::Level::WARN).init();

    // Start backend and WAF proxy in-process for an end-to-end benchmark
    let backend_addr: SocketAddr = SocketAddr::from(("127.0.0.1".parse::<std::net::IpAddr>().unwrap(), find_free_udp_port()?));
    let waf_addr: SocketAddr = SocketAddr::from(("127.0.0.1".parse::<std::net::IpAddr>().unwrap(), find_free_udp_port()?));

    // Resolve sibling binaries from the current binary directory
    let bin_dir = std::env::current_exe()?.parent().unwrap().to_path_buf();
    let backend_bin = bin_dir.join("webtransport_echo_backend");
    let waf_bin = bin_dir.join("webtransport_waf_proxy");

    // Spawn backend within nix devShell
    let backend_child = std::process::Command::new("nix")
        .arg("develop")
        .arg("-c")
        .arg(&backend_bin)
        .env("WT_BACKEND_ADDR", backend_addr.to_string())
        .spawn()?;

    // Spawn WAF proxy within nix devShell
    let waf_child = std::process::Command::new("nix")
        .arg("develop")
        .arg("-c")
        .arg(&waf_bin)
        .env("WT_WAF_ADDR", waf_addr.to_string())
        .spawn()?;

    // Wait for WAF to be ready (attempt quick client connect retries)
    wait_ready(waf_addr, Duration::from_secs(5)).await;

    let scenarios = vec![
        ("WT-bidi-128B", Mode::Bidi, 100, 100, 128),
        ("WT-bidi-512B", Mode::Bidi, 100, 100, 512),
        ("WT-bidi-1KB", Mode::Bidi, 200, 100, 1024),
        ("WT-dgram-800B", Mode::Datagram, 100, 100, 800),
    ];

    // Warmup + median-of-3 for stability
    const RUNS: usize = 3;

    for (name, mode, conns, msgs, size) in scenarios {
        println!("\n🔥 Running {} via WAF ({} conns × {} msgs, {}B)", name, conns, msgs, size);

        // Warmup (not recorded)
        match mode {
            Mode::Bidi => { let _ = run_bidi_benchmark(waf_addr, conns, msgs, size).await?; }
            Mode::Datagram => { let _ = run_dgram_benchmark(waf_addr, conns, msgs, size).await?; }
        }

        // Recorded runs
        let mut mps_runs = Vec::with_capacity(RUNS);
        let mut ratio_runs = Vec::with_capacity(RUNS);
        for _ in 0..RUNS {
            let r = match mode {
                Mode::Bidi => run_bidi_benchmark(waf_addr, conns, msgs, size).await?,
                Mode::Datagram => run_dgram_benchmark(waf_addr, conns, msgs, size).await?,
            };
            print_result(&r);
            mps_runs.push(throughput(&r));
            ratio_runs.push(success_ratio(&r));
        }
        let med = median(&mut mps_runs);
        let med_ratio = median(&mut ratio_runs);
        println!("Median throughput: {:.1} msg/s", med);
        println!("Median success rate: {:.1}%", med_ratio * 100.0);
        println!(
            "10K threshold (median): {}",
            if med >= 10_000.0 && med_ratio >= 0.95 { "ACHIEVED" } else { "NOT MET" }
        );
    }

    // Cleanup children to avoid port conflicts in subsequent runs
    let _ = nix_kill_child(backend_child);
    let _ = nix_kill_child(waf_child);

    Ok(())
}

fn find_free_udp_port() -> std::io::Result<u16> {
    let sock = UdpSocket::bind("127.0.0.1:0")?;
    let port = sock.local_addr()?.port();
    // drop socket to free port for our server
    drop(sock);
    Ok(port)
}

async fn wait_ready(addr: SocketAddr, max_wait: Duration) {
    let url = Url::parse(&format!("https://{}/", addr)).unwrap();
    let client = unsafe { wtq::ClientBuilder::new().with_no_certificate_verification().unwrap() };
    let start = Instant::now();
    loop {
        if start.elapsed() > max_wait { break; }
        match client.connect(url.clone()).await {
            Ok(_session) => break,
            Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
}

#[cfg(unix)]
fn nix_kill_child(mut child: std::process::Child) -> std::io::Result<()> {
    use std::os::unix::process::CommandExt;
    // Try graceful kill first
    child.kill()?;
    let _ = child.wait();
    Ok(())
}

#[cfg(not(unix))]
fn nix_kill_child(mut child: std::process::Child) -> std::io::Result<()> {
    child.kill()?;
    let _ = child.wait();
    Ok(())
}

// Establish sessions up-front to exclude handshake time from the measurement window
async fn connect_sessions(addr: SocketAddr, conns: usize) -> Result<Vec<wtq::Session>> {
    let url = Url::parse(&format!("https://{}/", addr)).unwrap();
    let client = unsafe { wtq::ClientBuilder::new().with_no_certificate_verification()? };
    let client = Arc::new(client);

    let mut tasks = Vec::with_capacity(conns);
    for _ in 0..conns {
        let client = client.clone();
        let url = url.clone();
        tasks.push(tokio::spawn(async move { client.connect(url).await }));
    }
    let mut sessions = Vec::with_capacity(conns);
    for t in tasks {
        match t.await.unwrap() {
            Ok(s) => sessions.push(s),
            Err(e) => error!("connect error: {}", e),
        }
    }
    Ok(sessions)
}

async fn run_bidi_benchmark(addr: SocketAddr, conns: usize, msgs_per_conn: usize, size: usize) -> Result<ResultSet> {
    // Pre-connect all sessions
    let sessions = connect_sessions(addr, conns).await?;

    // Pre-open all bidirectional streams before timing
    let mut streams = Vec::with_capacity(conns);
    let mut open_tasks = Vec::with_capacity(conns);
    for s in sessions {
        open_tasks.push(tokio::spawn(async move { s.open_bi().await }));
    }
    for t in open_tasks { if let Ok(Ok(p)) = t.await { streams.push(p); } }

    let ok = Arc::new(AtomicU64::new(0));
    let sent = Arc::new(AtomicU64::new(0));

    let start = Instant::now();
    let mut tasks = Vec::with_capacity(streams.len());

    for (mut send, mut recv) in streams {
        let ok = ok.clone();
        let sent = sent.clone();
        // Pre-build payload once per connection
        let payload = vec![b'A'; size];

        tasks.push(tokio::spawn(async move {
            // Pipeline: send all messages first, read echoes concurrently
            let ok_rx = ok.clone();
            let payload_tx = payload.clone();
            let send_task = tokio::spawn(async move {
                for _ in 0..msgs_per_conn {
                    if send.write_all(&payload_tx).await.is_err() { break; }
                    sent.fetch_add(1, Ordering::Relaxed);
                }
                let _ = send.finish();
            });
            let recv_task = tokio::spawn(async move {
                let mut buf = vec![0u8; size];
                for _ in 0..msgs_per_conn {
                    if recv.read_exact(&mut buf).await.is_ok() {
                        ok_rx.fetch_add(1, Ordering::Relaxed);
                    } else {
                        break;
                    }
                }
            });
            let _ = tokio::join!(send_task, recv_task);
        }));
    }

    for t in tasks { let _ = t.await; }

    let dur = start.elapsed();
    Ok(ResultSet { conns, msgs: sent.load(Ordering::Relaxed), ok: ok.load(Ordering::Relaxed), dur })
}

async fn run_dgram_benchmark(addr: SocketAddr, conns: usize, msgs_per_conn: usize, size: usize) -> Result<ResultSet> {
    // Pre-connect all sessions
    let sessions = connect_sessions(addr, conns).await?;

    let ok = Arc::new(AtomicU64::new(0));
    let sent = Arc::new(AtomicU64::new(0));

    // Pre-build a static payload once to minimize cloning cost
    let payload = bytes::Bytes::from(vec![b'D'; size]);

    // Windowed flow control per connection (reduces drops vs. pure pacing)
    const WINDOW: usize = 32; // max in-flight datagrams per connection
    let recv_idle = Duration::from_millis(10); // short timeout slice when waiting

    let start = Instant::now();
    let mut tasks = Vec::with_capacity(sessions.len());

    for (idx, session) in sessions.into_iter().enumerate() {
        let ok_global = ok.clone();
        let sent_global = sent.clone();
        let payload = payload.clone();
        tasks.push(tokio::spawn(async move {
            let ok_conn = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let sent_conn = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let send_done = Arc::new(std::sync::atomic::AtomicBool::new(false));

            // Stagger start to de-synchronize bursts across connections
            let jitter_us = ((idx as u64) % 32) * 250; // 0..=7.75ms
            tokio::time::sleep(Duration::from_micros(jitter_us)).await;

            let s_clone = session.clone();
            let payload_tx = payload.clone();
            let ok_conn_tx = ok_conn.clone();
            let sent_conn_tx = sent_conn.clone();
            let send_done_tx = send_done.clone();
            let send_task = tokio::spawn(async move {
                let mut local_sent = 0usize;
                while local_sent < msgs_per_conn {
                    // Backpressure: wait while in-flight >= WINDOW
                    while local_sent.saturating_sub(ok_conn_tx.load(Ordering::Acquire)) >= WINDOW {
                        tokio::time::sleep(Duration::from_micros(50)).await;
                    }
                    // Bounded retry on congestion
                    let mut attempt: u32 = 0;
                    loop {
                        match s_clone.send_datagram(payload_tx.clone()) {
                            Ok(()) => {
                                local_sent += 1;
                                sent_global.fetch_add(1, Ordering::Relaxed);
                                sent_conn_tx.fetch_add(1, Ordering::Relaxed);
                                break;
                            }
                            Err(_) => {
                                attempt += 1;
                                if attempt >= 8 { break; }
                                tokio::time::sleep(Duration::from_micros(50 * attempt as u64)).await;
                            }
                        }
                    }
                }
                send_done_tx.store(true, Ordering::Release);
            });

            let ok_conn_rx = ok_conn.clone();
            let sent_conn_rx = sent_conn.clone();
            let send_done_rx = send_done.clone();
            let recv_task = tokio::spawn(async move {
                loop {
                    // Stop when sender finished and we've received all echoes for successful sends
                    if send_done_rx.load(Ordering::Relaxed) && ok_conn_rx.load(Ordering::Acquire) >= sent_conn_rx.load(Ordering::Acquire) { break; }
                    match tokio::time::timeout(recv_idle, session.read_datagram()).await {
                        Ok(Ok(_d)) => {
                            ok_global.fetch_add(1, Ordering::Relaxed);
                            ok_conn_rx.fetch_add(1, Ordering::Relaxed);
                        }
                        Ok(Err(_)) => break,
                        Err(_) => continue, // timeout slice; re-check condition
                    }
                }
            });

            let _ = tokio::join!(send_task, recv_task);
        }));
    }

    for t in tasks { let _ = t.await; }

    let dur = start.elapsed();
    Ok(ResultSet { conns, msgs: sent.load(Ordering::Relaxed), ok: ok.load(Ordering::Relaxed), dur })
}

struct ResultSet {
    conns: usize,
    msgs: u64,
    ok: u64,
    dur: Duration,
}

fn throughput(r: &ResultSet) -> f64 { r.ok as f64 / r.dur.as_secs_f64() }

fn success_ratio(r: &ResultSet) -> f64 {
    if r.msgs == 0 { 0.0 } else { r.ok as f64 / r.msgs as f64 }
}

fn median(v: &mut Vec<f64>) -> f64 {
    if v.is_empty() { return 0.0; }
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let mid = v.len() / 2;
    if v.len() % 2 == 0 { (v[mid - 1] + v[mid]) / 2.0 } else { v[mid] }
}

fn print_result(r: &ResultSet) {
    println!("Connections: {}", r.conns);
    println!("Messages: {} ok / {} total", r.ok, r.msgs);
    let mps = throughput(r);
    let ratio = success_ratio(r);
    println!("Throughput: {:.1} msg/s", mps);
    println!("Success rate: {:.1}%", ratio * 100.0);
    let pass = mps >= 10_000.0 && ratio >= 0.95;
    println!("10K threshold: {}", if pass { "ACHIEVED" } else { "NOT MET" });
}
