//! Loopback echo benchmark: default tokio path vs the io_uring fd path.
//!
//! Run with:
//!   nix develop -c cargo run --release --features io-uring \
//!     --bin io-uring-network-bench
//!
//! Reports req/s, p50/p99 latency and CPU seconds for bodyless (16-byte
//! header) and 1 KiB bodies at concurrency 1/16/64. When io_uring is not
//! available the run is skipped with a clear message.
#![cfg(all(feature = "io-uring", target_os = "linux"))]

use anyhow::{Context, Result};
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use waf_ingress::waf::io::{IoBackend, IoConfig, IoUringNetworkHandler, NetworkIoHandler};

const HEADER: usize = 16;
const RESPONSE: usize = 16;
const ROUNDS: usize = 2000;

#[derive(Debug, Clone, Copy)]
struct Stats {
    rps: f64,
    p50_us: f64,
    p99_us: f64,
    cpu_s: f64,
}

#[tokio::main]
async fn main() -> Result<()> {
    for body in [0usize, 1024] {
        for concurrency in [1usize, 16, 64] {
            let std_stats = run_case(false, body, concurrency).await?;
            let uring_stats = match run_case(true, body, concurrency).await {
                Ok(s) => Some(s),
                Err(e) => {
                    eprintln!("io_uring case skipped (body={body} c={concurrency}): {e}");
                    None
                }
            };
            println!(
                "body={body:>4}B c={concurrency:>2} | tokio rps={:>8.0} p50={:>6.1}us p99={:>7.1}us cpu={:.2}s",
                std_stats.rps, std_stats.p50_us, std_stats.p99_us, std_stats.cpu_s
            );
            if let Some(u) = uring_stats {
                println!(
                    "body={body:>4}B c={concurrency:>2} | uring rps={:>8.0} p50={:>6.1}us p99={:>7.1}us cpu={:.2}s",
                    u.rps, u.p50_us, u.p99_us, u.cpu_s
                );
            }
        }
    }
    Ok(())
}

async fn run_case(use_uring: bool, body: usize, concurrency: usize) -> Result<Stats> {
    let listener = Arc::new(
        TcpListener::bind("127.0.0.1:0")
            .await
            .context("bind benchmark listener")?,
    );
    let addr = listener.local_addr()?;
    let request = vec![0u8; HEADER + body];
    let server_handler = if use_uring {
        let config = IoConfig {
            backend: IoBackend::IoUring,
            enable_zero_copy: true,
            buffer_size: 8192,
            concurrency,
        };
        Some(Arc::new(IoUringNetworkHandler::new(config)?))
    } else {
        None
    };
    let std_handler = Arc::new(NetworkIoHandler::new(IoConfig {
        backend: IoBackend::Standard,
        enable_zero_copy: true,
        buffer_size: 8192,
        concurrency,
    }));

    let cpu_before = cpu_seconds();
    let start = Instant::now();
    let mut server_tasks = Vec::with_capacity(concurrency);
    let mut client_tasks = Vec::with_capacity(concurrency);

    for _ in 0..concurrency {
        let std_handler = Arc::clone(&std_handler);
        let uring_handler = server_handler.clone();
        let listener = Arc::clone(&listener);
        let listener_fd = listener.as_raw_fd();
        let server_request = request.clone();
        let client_request = request.clone();

        let server = tokio::spawn(async move {
            if let Some(handler) = uring_handler {
                let fd = handler.accept_fd(listener_fd).await?;
                for _ in 0..ROUNDS {
                    let mut need = server_request.len();
                    while need > 0 {
                        let (_, n) = handler.read_fd(fd, need).await?;
                        if n == 0 {
                            anyhow::bail!("client closed");
                        }
                        need -= n;
                    }
                    handler.write_fd(fd, &vec![0u8; RESPONSE]).await?;
                }
                unsafe { libc::close(fd) };
            } else {
                let (mut stream, _) = listener.accept().await?;
                let mut buf = vec![0u8; server_request.len()];
                for _ in 0..ROUNDS {
                    stream.read_exact(&mut buf).await?;
                    std_handler
                        .write_with_chunking(&mut stream, &vec![0u8; RESPONSE])
                        .await?;
                }
            }
            Ok::<(), anyhow::Error>(())
        });

        let client = tokio::spawn(async move {
            let mut stream = TcpStream::connect(addr).await?;
            let mut response = [0u8; RESPONSE];
            let mut latencies = Vec::with_capacity(ROUNDS);
            for _ in 0..ROUNDS {
                let t = Instant::now();
                stream.write_all(&client_request).await?;
                stream.read_exact(&mut response).await?;
                latencies.push(t.elapsed().as_micros() as u64);
            }
            Ok::<Vec<u64>, anyhow::Error>(latencies)
        });

        server_tasks.push(server);
        client_tasks.push(client);
    }

    let mut all = Vec::with_capacity(concurrency * ROUNDS);
    for task in client_tasks {
        all.extend(task.await??);
    }
    for task in server_tasks {
        task.await??;
    }
    let elapsed = start.elapsed();
    let cpu = cpu_seconds() - cpu_before;

    all.sort_unstable();
    let p50 = percentile(&all, 0.50);
    let p99 = percentile(&all, 0.99);
    let rps = (concurrency * ROUNDS) as f64 / elapsed.as_secs_f64();

    Ok(Stats {
        rps,
        p50_us: p50,
        p99_us: p99,
        cpu_s: cpu,
    })
}

fn percentile(sorted: &[u64], q: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((sorted.len() - 1) as f64 * q).round() as usize;
    sorted[idx] as f64
}

fn cpu_seconds() -> f64 {
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };
    let user = usage.ru_utime.tv_sec as f64 + usage.ru_utime.tv_usec as f64 / 1_000_000.0;
    let sys = usage.ru_stime.tv_sec as f64 + usage.ru_stime.tv_usec as f64 / 1_000_000.0;
    user + sys
}
