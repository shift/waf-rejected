//! End-to-end WebSocket upgrade/tunnel test.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use tokio::net::TcpListener;
use tokio_rustls::rustls;
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::tungstenite::Message;

use waf_ingress::proxy::WafProxyService;
use waf_ingress::Config;

async fn spawn_ws_upstream() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
        while let Some(Ok(message)) = ws.next().await {
            if message.is_text() {
                if ws.send(message).await.is_err() {
                    break;
                }
            }
        }
    });

    addr
}

async fn spawn_proxy(upstream: std::net::SocketAddr) -> String {
    let mut config = Config::default();
    config.upstream_uri = format!("http://{}", upstream);
    config.server.max_body_size = 4096;
    config.waf.rate_limit.per_ip_enabled = false;
    config.waf.rate_limit.global_enabled = false;

    let service = Arc::new(WafProxyService::new(config).unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = service.start_with_listener(listener).await;
    });

    format!("{}", addr)
}

#[tokio::test]
async fn websocket_upgrade_is_tunneled_to_upstream() {
    let upstream = spawn_ws_upstream().await;
    let proxy = spawn_proxy(upstream).await;

    let (mut client, _) = tokio_tungstenite::connect_async(format!("ws://{}/ws", proxy))
        .await
        .expect("websocket handshake through proxy");

    client
        .send(Message::Text("hello-through-waf".into()))
        .await
        .unwrap();

    let echoed = tokio::time::timeout(std::time::Duration::from_secs(3), client.next())
        .await
        .expect("echo timeout")
        .expect("stream closed")
        .expect("websocket error");

    assert_eq!(echoed, Message::Text("hello-through-waf".into()));
}

#[tokio::test]
async fn websocket_frame_payload_is_inspected_by_waf() {
    let upstream = spawn_ws_upstream().await;
    let proxy = spawn_proxy(upstream).await;

    let (mut client, _) = tokio_tungstenite::connect_async(format!("ws://{}/ws", proxy))
        .await
        .expect("websocket handshake through proxy");

    client
        .send(Message::Text("id=1 UNION SELECT * FROM users".into()))
        .await
        .unwrap();

    let next = tokio::time::timeout(std::time::Duration::from_secs(3), client.next()).await;
    match next {
        Ok(Some(Ok(Message::Close(_)))) | Ok(None) | Ok(Some(Err(_))) | Err(_) => {}
        Ok(Some(Ok(other))) => panic!("malicious frame was forwarded: {:?}", other),
    }
}

#[tokio::test]
async fn websocket_upgrade_is_blocked_by_waf() {
    let upstream = spawn_ws_upstream().await;
    let proxy = spawn_proxy(upstream).await;

    let result =
        tokio_tungstenite::connect_async(format!("ws://{}/ws?id=1%20UNION%20SELECT%201", proxy))
            .await;

    assert!(result.is_err(), "WAF should block the upgrade handshake");
}

/// Generate a self-signed test CA and a server certificate for 127.0.0.1
/// signed by that CA. Returns `(ca_path, cert_path, key_path)`.
fn generate_test_ca_and_server_cert(dir: &Path) -> (PathBuf, PathBuf, PathBuf) {
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "waf-websocket-test-ca");
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

    let ca_key = KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();

    let mut server_params = CertificateParams::new(vec!["127.0.0.1".to_string()]).unwrap();
    server_params.is_ca = IsCa::NoCa;
    server_params
        .distinguished_name
        .push(DnType::CommonName, "127.0.0.1");
    server_params.use_authority_key_identifier_extension = true;
    server_params
        .key_usages
        .push(KeyUsagePurpose::DigitalSignature);
    server_params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ServerAuth);

    let server_key = KeyPair::generate().unwrap();
    let issuer = Issuer::from_params(&ca_params, &ca_key);
    let server_cert = server_params.signed_by(&server_key, &issuer).unwrap();

    let ca_path = dir.join("ca.pem");
    let cert_path = dir.join("server.pem");
    let key_path = dir.join("server.key");
    std::fs::write(&ca_path, ca_cert.pem()).unwrap();
    std::fs::write(&cert_path, server_cert.pem()).unwrap();
    std::fs::write(&key_path, server_key.serialize_pem()).unwrap();

    (ca_path, cert_path, key_path)
}

async fn spawn_tls_ws_upstream(dir: &Path) -> (std::net::SocketAddr, PathBuf) {
    let (ca_path, cert_path, key_path) = generate_test_ca_and_server_cert(dir);

    let cert_pem = std::fs::read(&cert_path).unwrap();
    let certs = rustls::pki_types::CertificateDer::pem_slice_iter(&cert_pem)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key_pem = std::fs::read(&key_path).unwrap();
    let key = rustls::pki_types::PrivateKeyDer::from_pem_slice(&key_pem).expect("server key");

    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(config));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let tls = acceptor.accept(stream).await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(tls).await.unwrap();
        while let Some(Ok(message)) = ws.next().await {
            if message.is_text() && ws.send(message).await.is_err() {
                break;
            }
        }
    });

    (addr, ca_path)
}

async fn spawn_proxy_with_upstream_ca(upstream: std::net::SocketAddr, ca_path: &Path) -> String {
    let mut config = Config::default();
    config.upstream_uri = format!("https://127.0.0.1:{}", upstream.port());
    config.proxy.upstream_ca_path = Some(ca_path.to_string_lossy().into_owned());
    config.server.max_body_size = 4096;
    config.waf.rate_limit.per_ip_enabled = false;
    config.waf.rate_limit.global_enabled = false;

    let service = Arc::new(WafProxyService::new(config).unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = service.start_with_listener(listener).await;
    });

    format!("{}", addr)
}

#[tokio::test]
async fn websocket_tls_upstream_with_custom_ca_is_tunneled() {
    let cert_dir = tempfile::tempdir().unwrap();
    let (upstream, ca_path) = spawn_tls_ws_upstream(cert_dir.path()).await;
    let proxy = spawn_proxy_with_upstream_ca(upstream, &ca_path).await;

    let (mut client, _) = tokio_tungstenite::connect_async(format!("ws://{}/ws", proxy))
        .await
        .expect("websocket handshake through proxy to TLS upstream");

    client
        .send(Message::Text("hello-over-tls".into()))
        .await
        .unwrap();

    let echoed = tokio::time::timeout(std::time::Duration::from_secs(3), client.next())
        .await
        .expect("echo timeout")
        .expect("stream closed")
        .expect("websocket error");

    assert_eq!(echoed, Message::Text("hello-over-tls".into()));

    drop(client);
    drop(cert_dir);
    assert!(!ca_path.exists(), "temporary CA file should be removed");
}
