//! End-to-end WebTransport (HTTP/3) session tests.
//!
//! Requires the `webtransport` feature. The test terminates sessions locally
//! and verifies the bounded echo plus the Origin allowlist rejection path.

use std::sync::Arc;
use std::time::Duration;

use rcgen::generate_simple_self_signed;
use tokio::net::TcpListener;

use waf_ingress::proxy::WafProxyService;
use waf_ingress::Config;
use wtransport::endpoint::ConnectOptions;
use wtransport::{ClientConfig, Endpoint};

const ORIGIN: &str = "https://app.example";

fn write_identity(dir: &std::path::Path) -> (String, String) {
    let certified = generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
    let cert_path = dir.join("webtransport-cert.pem");
    let key_path = dir.join("webtransport-key.pem");
    std::fs::write(&cert_path, certified.cert.pem()).unwrap();
    std::fs::write(&key_path, certified.signing_key.serialize_pem()).unwrap();
    (
        cert_path.to_string_lossy().into_owned(),
        key_path.to_string_lossy().into_owned(),
    )
}

async fn spawn_proxy(origin_allowlist: Vec<String>) -> u16 {
    // Reserve an ephemeral UDP port, then release it for the listener.
    let probe = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);

    let dir = tempfile::tempdir().unwrap();
    let (cert_path, key_path) = write_identity(dir.path());

    let mut config = Config::default();
    config.server.enable_http3 = false;
    config.server.tls.enabled = true;
    config.server.tls.cert_path = cert_path;
    config.server.tls.key_path = key_path;
    config.server.tls.min_version = "1.3".to_string();
    config.server.tls.max_version = "1.3".to_string();

    config.server.webtransport.enabled = true;
    config.server.webtransport.bind_addr = format!("127.0.0.1:{}", port).parse().unwrap();
    config.server.webtransport.allowed_origins = origin_allowlist;
    config.server.webtransport.allowed_paths = vec!["/echo".to_string()];
    config.waf.rate_limit.per_ip_enabled = false;
    config.waf.rate_limit.global_enabled = false;

    let service = Arc::new(WafProxyService::new(config).unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    tokio::spawn(async move {
        let _ = service.start_with_listener(listener).await;
    });

    // Keep the certificate alive for the duration of the test process.
    std::mem::forget(dir);
    port
}

fn client() -> Endpoint<wtransport::endpoint::endpoint_side::Client> {
    let config = ClientConfig::builder()
        .with_bind_default()
        .with_no_cert_validation()
        .build();
    Endpoint::client(config).unwrap()
}

async fn connect(
    endpoint: &Endpoint<wtransport::endpoint::endpoint_side::Client>,
    port: u16,
    origin: &str,
) -> Result<wtransport::Connection, wtransport::error::ConnectingError> {
    let url = format!("https://127.0.0.1:{}/echo", port);
    endpoint
        .connect(
            ConnectOptions::builder(url)
                .add_header("origin", origin)
                .build(),
        )
        .await
}

#[tokio::test]
async fn allowed_session_echoes_bidirectional_stream() {
    let port = spawn_proxy(vec![ORIGIN.to_string()]).await;
    let endpoint = client();

    let connection = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match connect(&endpoint, port, ORIGIN).await {
                Ok(connection) => break connection,
                Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
            }
        }
    })
    .await
    .expect("WebTransport listener did not start");

    let (mut send, mut recv) = connection.open_bi().await.unwrap().await.unwrap();
    send.write_all(b"hello-webtransport").await.unwrap();
    send.finish().await.unwrap();

    let mut echoed = [0u8; 18];
    tokio::time::timeout(Duration::from_secs(5), recv.read_exact(&mut echoed))
        .await
        .expect("echo timeout")
        .unwrap();
    assert_eq!(&echoed, b"hello-webtransport");

    connection.close(0u32.into(), b"done");
}

#[tokio::test]
async fn disallowed_origin_is_rejected() {
    let port = spawn_proxy(vec![ORIGIN.to_string()]).await;
    let endpoint = client();

    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match connect(&endpoint, port, "https://evil.example").await {
                // A rejected CONNECT surfaces as a connect error (403 response).
                Err(error) if format!("{}", error).contains("rejected") => break,
                Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
                Ok(connection) => {
                    connection.close(0u32.into(), b"unexpected");
                    panic!("disallowed Origin was accepted");
                }
            }
        }
    })
    .await
    .expect("WebTransport listener did not start or did not reject the Origin");
}
