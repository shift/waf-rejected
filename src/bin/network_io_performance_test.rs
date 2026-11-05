/// Network I/O Performance Test for WAF Proxy Operations
///
/// This binary tests the performance of network I/O optimizations:
/// - Zero-copy operations
/// - Optimized buffering
/// - Stream forwarding
/// - Bidirectional copying
///
/// It measures network latency and throughput to validate
/// the P2-02 network I/O optimization implementation.
use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tracing::{info, warn};
use waf_ingress::waf::io::{IoBackend, IoConfig, NetworkIoHandler};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    info!("🚀 Starting Network I/O Performance Test");

    // Test configurations
    let test_configs = vec![
        (
            "Standard Network I/O",
            IoConfig {
                backend: IoBackend::Standard,
                enable_zero_copy: false,
                buffer_size: 8192,
                concurrency: 4,
            },
        ),
        (
            "Optimized Network I/O",
            IoConfig {
                backend: IoBackend::Standard,
                enable_zero_copy: true,
                buffer_size: 64 * 1024, // Larger buffer for better performance
                concurrency: 8,
            },
        ),
    ];

    for (name, config) in test_configs {
        info!("\n📊 Testing {}", name);

        match test_network_io(&config).await {
            Ok(stats) => {
                info!("✅ {} Results:", name);
                info!("  📖 Read Operations: {} ops", stats.read_ops);
                info!("  ✍️  Write Operations: {} ops", stats.write_ops);
                info!("  📈 Bytes Read: {} bytes", stats.bytes_read);
                info!("  📉 Bytes Written: {} bytes", stats.bytes_written);
                info!("  📦 Bytes Forwarded: {} bytes", stats.bytes_forwarded);
                info!("  ⏱️  Avg Read Latency: {}μs", stats.avg_read_latency_us);
                info!("  ⏱️  Avg Write Latency: {}μs", stats.avg_write_latency_us);
                info!("  🔄 Zero-copy Operations: {}", stats.zero_copy_ops);
                info!("  🎯 Total Operations: {}", stats.total_ops());
                info!("  💾 Total Bytes: {}", stats.total_bytes());

                if stats.total_bytes() > 0 {
                    info!(
                        "  📊 Estimated Throughput: {:.2} MB/s",
                        stats.total_bytes() as f64 / 1_000_000.0 / 2.0
                    ); // Rough estimate over 2 seconds
                }
            }
            Err(e) => {
                warn!("❌ {} failed: {}", name, e);
            }
        }
    }

    info!("✨ Network I/O Performance Test completed");
    Ok(())
}

async fn test_network_io(config: &IoConfig) -> Result<waf_ingress::waf::io::NetworkIoStats> {
    let handler = NetworkIoHandler::new(config.clone());

    // Test parameters
    const PORT_BASE: u16 = 18080;
    const MESSAGE_SIZE: usize = 1024; // 1KB messages
    const NUM_MESSAGES: usize = 100;
    const NUM_CONNECTIONS: usize = 10;

    let test_data = vec![0xABu8; MESSAGE_SIZE];

    info!("  🔧 Test Parameters:");
    info!(
        "    - Messages: {} x {}KB",
        NUM_MESSAGES,
        MESSAGE_SIZE / 1024
    );
    info!("    - Connections: {}", NUM_CONNECTIONS);
    info!("    - Buffer Size: {}KB", config.buffer_size / 1024);
    info!("    - Zero-copy: {}", config.enable_zero_copy);

    // Start test server
    let server_addr: SocketAddr = format!("127.0.0.1:{}", PORT_BASE).parse()?;
    let listener = TcpListener::bind(server_addr)
        .await
        .with_context(|| format!("Failed to bind to {}", server_addr))?;

    info!("  🖥️  Test server listening on {}", server_addr);

    // Spawn echo server task
    let server_handler = handler.clone();
    let server_task = tokio::spawn(async move {
        let mut connection_count = 0;

        while connection_count < NUM_CONNECTIONS {
            match listener.accept().await {
                Ok((mut socket, _)) => {
                    connection_count += 1;
                    let handler = server_handler.clone();

                    tokio::spawn(async move {
                        // Echo server: read and write back data
                        for _ in 0..NUM_MESSAGES {
                            let mut buffer = handler.allocate_buffer();

                            // Read from client
                            match handler.read_with_buffer(&mut socket, &mut buffer).await {
                                Ok(bytes_read) => {
                                    if bytes_read == 0 {
                                        break; // Connection closed
                                    }

                                    // Echo back to client
                                    if let Err(e) = handler
                                        .write_with_chunking(&mut socket, &buffer[..bytes_read])
                                        .await
                                    {
                                        eprintln!("Echo write error: {}", e);
                                        break;
                                    }
                                }
                                Err(e) => {
                                    eprintln!("Echo read error: {}", e);
                                    break;
                                }
                            }
                        }
                    });
                }
                Err(e) => {
                    eprintln!("Server accept error: {}", e);
                    break;
                }
            }
        }
    });

    // Give server time to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Run client tests
    let start = Instant::now();
    let mut client_tasks = Vec::new();

    for client_id in 0..NUM_CONNECTIONS {
        let _handler = handler.clone();
        let data = test_data.clone();
        let addr = server_addr;

        let task = tokio::spawn(async move {
            // Connect to server
            let mut stream = timeout(Duration::from_secs(5), TcpStream::connect(addr))
                .await
                .map_err(|_| anyhow::anyhow!("Connection timeout"))?
                .with_context(|| format!("Failed to connect to server for client {}", client_id))?;

            // Send and receive messages
            for _ in 0..NUM_MESSAGES {
                // Send message
                stream
                    .write_all(&data)
                    .await
                    .with_context(|| format!("Failed to send message from client {}", client_id))?;

                // Receive echo
                let mut response = vec![0u8; data.len()];
                stream
                    .read_exact(&mut response)
                    .await
                    .with_context(|| format!("Failed to receive echo for client {}", client_id))?;

                // Verify echo
                if response != data {
                    anyhow::bail!("Echo mismatch for client {}", client_id);
                }
            }

            Ok::<(), anyhow::Error>(())
        });

        client_tasks.push(task);
    }

    // Wait for all clients to complete
    for (i, task) in client_tasks.into_iter().enumerate() {
        if let Err(e) = task.await? {
            warn!("Client {} failed: {}", i, e);
        }
    }

    let total_duration = start.elapsed();

    // Stop server task
    server_task.abort();

    info!("  ⏱️  Total Test Duration: {:?}", total_duration);
    info!(
        "  📊 Expected Messages: {} ({}KB each)",
        NUM_MESSAGES * NUM_CONNECTIONS,
        MESSAGE_SIZE / 1024
    );

    Ok(handler.get_stats())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncWrite};
    use waf_ingress::waf::io::NetworkIo;

    // Mock stream for testing
    struct MockStream {
        read_data: Vec<u8>,
        write_data: Vec<u8>,
        read_pos: usize,
    }

    impl MockStream {
        fn new(data: Vec<u8>) -> Self {
            Self {
                read_data: data,
                write_data: Vec::new(),
                read_pos: 0,
            }
        }
    }

    impl AsyncRead for MockStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<tokio::io::Result<()>> {
            let remaining = self.read_data.len() - self.read_pos;
            let to_read = remaining.min(buf.remaining());

            if to_read == 0 {
                return Poll::Ready(Ok(()));
            }

            buf.put_slice(&self.read_data[self.read_pos..self.read_pos + to_read]);
            self.read_pos += to_read;

            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for MockStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<Result<usize, tokio::io::Error>> {
            self.write_data.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), tokio::io::Error>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), tokio::io::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn test_network_handler_basic_operations() -> Result<()> {
        let config = IoConfig {
            backend: IoBackend::Standard,
            enable_zero_copy: true,
            buffer_size: 1024,
            concurrency: 2,
        };

        let handler = NetworkIoHandler::new(config);

        // Test data
        let test_data = b"Hello, Network I/O!";
        let mut mock_stream = MockStream::new(test_data.to_vec());

        // Test read_stream
        let read_result = handler.read_stream(&mut mock_stream).await?;
        assert_eq!(read_result.as_ref(), test_data);

        // Test write_stream
        handler.write_stream(&mut mock_stream, test_data).await?;
        assert_eq!(mock_stream.write_data, test_data);

        // Check stats
        let stats = handler.get_stats();
        assert!(stats.read_ops > 0);
        assert!(stats.write_ops > 0);
        assert!(stats.zero_copy_ops > 0);

        Ok(())
    }

    #[tokio::test]
    async fn test_buffer_allocation() {
        let config = IoConfig {
            backend: IoBackend::Standard,
            enable_zero_copy: false,
            buffer_size: 2048,
            concurrency: 1,
        };

        let handler = NetworkIoHandler::new(config);
        let buffer = handler.allocate_buffer();

        assert_eq!(buffer.capacity(), 2048);
        assert_eq!(buffer.len(), 0);
    }

    #[tokio::test]
    async fn test_stats_calculation() {
        let config = IoConfig::default();
        let handler = NetworkIoHandler::new(config);

        // Perform some operations to generate stats
        let test_data = b"test data";
        let mut mock_stream = MockStream::new(test_data.to_vec());

        handler.read_stream(&mut mock_stream).await.unwrap();
        handler
            .write_stream(&mut mock_stream, test_data)
            .await
            .unwrap();

        let stats = handler.get_stats();

        assert_eq!(stats.total_ops(), 2); // 1 read + 1 write
        assert_eq!(stats.total_bytes(), test_data.len() as u64 * 2); // read + write
    }
}
