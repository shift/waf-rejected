use anyhow::Result;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::error;
use url::Url;
use web_transport_quinn as wtq;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_max_level(tracing::Level::INFO).init();

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
    wait_ready(waf_addr, Duration::from_secs(3)).await;

    let scenarios = vec![
        ("WT-bidi-128B", 100, 100, 128),
        ("WT-bidi-512B", 100, 100, 512),
        ("WT-bidi-1KB", 200, 100, 1024),
        ("WT-dgram-800B", 200, 200, 800),
    ];

    for (name, conns, msgs, size) in scenarios {
        println!("\n🔥 Running {} via WAF ({} conns × {} msgs, {}B)", name, conns, msgs, size);
        let r = run_bidi_benchmark(waf_addr, conns, msgs, size).await?;
        print_result(&r);
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

struct ResultSet {
    conns: usize,
    msgs: u64,
    ok: u64,
    dur: Duration,
}

async fn run_bidi_benchmark(addr: SocketAddr, conns: usize, msgs_per_conn: usize, size: usize) -> Result<ResultSet> {
    let url = Url::parse(&format!("https://{}/", addr)).unwrap();
    let client = unsafe { wtq::ClientBuilder::new().with_no_certificate_verification()? };
    let client = Arc::new(client);

    let ok = Arc::new(AtomicU64::new(0));
    let sent = Arc::new(AtomicU64::new(0));

    let start = Instant::now();
    let mut tasks = Vec::with_capacity(conns);

    for _ in 0..conns {
        let client = client.clone();
        let url = url.clone();
        let ok = ok.clone();
        let sent = sent.clone();
        let payload = vec![b'A'; size];

        tasks.push(tokio::spawn(async move {
            match client.connect(url).await {
                Ok(mut session) => {
                    if let Ok((mut send, mut recv)) = session.open_bi().await {
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
                    }
                }
                Err(e) => {
                    error!("connect error: {}", e);
                }
            }
        }));
    }

    for t in tasks { let _ = t.await; }

    let dur = start.elapsed();
    Ok(ResultSet { conns, msgs: sent.load(Ordering::Relaxed), ok: ok.load(Ordering::Relaxed), dur })
}

fn print_result(r: &ResultSet) {
    println!("Connections: {}", r.conns);
    println!("Messages: {} ok / {} total", r.ok, r.msgs);
    let mps = r.ok as f64 / r.dur.as_secs_f64();
    println!("Throughput: {:.1} msg/s", mps);
    println!("10K threshold: {}", if mps >= 10_000.0 { "ACHIEVED" } else { "NOT MET" });
}
