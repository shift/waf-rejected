//! End-to-end HTTPS/HTTP upstream forwarding tests.

use std::convert::Infallible;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::Full;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use tokio::net::TcpListener;
use tokio_rustls::rustls;
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::TlsAcceptor;

use waf_ingress::proxy::WafProxyService;
use waf_ingress::Config;

async fn upstream_response(req: Request<hyper::body::Incoming>) -> Response<Full<Bytes>> {
    let host = req
        .headers()
        .get(hyper::header::HOST)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    let xff = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    let body = format!("upstream-ok host={} xff={}", host, xff);
    Response::builder()
        .status(StatusCode::OK)
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

async fn spawn_http_upstream() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(value) => value,
                Err(_) => break,
            };
            tokio::spawn(async move {
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(
                        TokioIo::new(stream),
                        service_fn(|req: Request<hyper::body::Incoming>| async move {
                            Ok::<_, Infallible>(upstream_response(req).await)
                        }),
                    )
                    .await;
            });
        }
    });

    addr
}

/// Generate a self-signed test CA, a server certificate for 127.0.0.1, and a
/// client certificate signed by the same CA.
/// Returns `(ca_path, server_cert_path, server_key_path, client_cert_path,
/// client_key_path)`.
fn generate_test_certificates(dir: &Path) -> (PathBuf, PathBuf, PathBuf, PathBuf, PathBuf) {
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "waf-https-upstream-test-ca");
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

    let mut client_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    client_params.is_ca = IsCa::NoCa;
    client_params
        .distinguished_name
        .push(DnType::CommonName, "waf-upstream-mtls-client");
    client_params.use_authority_key_identifier_extension = true;
    client_params
        .key_usages
        .push(KeyUsagePurpose::DigitalSignature);
    client_params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ClientAuth);

    let client_key = KeyPair::generate().unwrap();
    let client_cert = client_params.signed_by(&client_key, &issuer).unwrap();

    let ca_path = dir.join("ca.pem");
    let server_cert_path = dir.join("server.pem");
    let server_key_path = dir.join("server.key");
    let client_cert_path = dir.join("client.pem");
    let client_key_path = dir.join("client.key");
    std::fs::write(&ca_path, ca_cert.pem()).unwrap();
    std::fs::write(&server_cert_path, server_cert.pem()).unwrap();
    std::fs::write(&server_key_path, server_key.serialize_pem()).unwrap();
    std::fs::write(&client_cert_path, client_cert.pem()).unwrap();
    std::fs::write(&client_key_path, client_key.serialize_pem()).unwrap();

    (
        ca_path,
        server_cert_path,
        server_key_path,
        client_cert_path,
        client_key_path,
    )
}

async fn spawn_tls_upstream(dir: &Path) -> (std::net::SocketAddr, PathBuf) {
    let (ca_path, cert_path, key_path, _client_cert, _client_key) = generate_test_certificates(dir);

    let cert_pem = std::fs::read(&cert_path).unwrap();
    let certs = rustls::pki_types::CertificateDer::pem_slice_iter(&cert_pem)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key_pem = std::fs::read(&key_path).unwrap();
    let key = rustls::pki_types::PrivateKeyDer::from_pem_slice(&key_pem).expect("server key");

    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .unwrap();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(config));

    let addr = spawn_tls_listener(acceptor).await;
    (addr, ca_path)
}

/// Spawn a TLS upstream that requires a client certificate signed by the test CA.
/// Returns `(addr, ca_path, client_cert_path, client_key_path)`.
async fn spawn_mtls_tls_upstream(dir: &Path) -> (std::net::SocketAddr, PathBuf, PathBuf, PathBuf) {
    let (ca_path, cert_path, key_path, client_cert_path, client_key_path) =
        generate_test_certificates(dir);

    let cert_pem = std::fs::read(&cert_path).unwrap();
    let certs = rustls::pki_types::CertificateDer::pem_slice_iter(&cert_pem)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key_pem = std::fs::read(&key_path).unwrap();
    let key = rustls::pki_types::PrivateKeyDer::from_pem_slice(&key_pem).expect("server key");

    let ca_pem = std::fs::read(&ca_path).unwrap();
    let mut client_roots = rustls::RootCertStore::empty();
    for cert in rustls::pki_types::CertificateDer::pem_slice_iter(&ca_pem) {
        client_roots.add(cert.unwrap()).unwrap();
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(client_roots),
        provider.clone(),
    )
    .build()
    .unwrap();

    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .unwrap();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(config));

    let addr = spawn_tls_listener(acceptor).await;
    (addr, ca_path, client_cert_path, client_key_path)
}

async fn spawn_tls_listener(acceptor: TlsAcceptor) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(value) => value,
                Err(_) => break,
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let tls = match acceptor.accept(stream).await {
                    Ok(tls) => tls,
                    Err(_) => return,
                };
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(
                        TokioIo::new(tls),
                        service_fn(|req: Request<hyper::body::Incoming>| async move {
                            Ok::<_, Infallible>(upstream_response(req).await)
                        }),
                    )
                    .await;
            });
        }
    });

    addr
}

async fn spawn_proxy(
    upstream_uri: String,
    ca_path: Option<&Path>,
    client_identity: Option<(&Path, &Path)>,
) -> String {
    let mut config = Config {
        upstream_uri,
        ..Config::default()
    };
    config.proxy.upstream_ca_path = ca_path.map(|path| path.to_string_lossy().into_owned());
    if let Some((cert_path, key_path)) = client_identity {
        config.proxy.upstream_client_cert_path = Some(cert_path.to_string_lossy().into_owned());
        config.proxy.upstream_client_key_path = Some(key_path.to_string_lossy().into_owned());
    }
    config.server.max_body_size = 4096;
    config.waf.rate_limit.per_ip_enabled = false;
    config.waf.rate_limit.global_enabled = false;
    config.waf.coraza.enabled = false;

    let service = Arc::new(WafProxyService::new(config).unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = service.start_with_listener(listener).await;
    });

    format!("http://{}", addr)
}

#[tokio::test]
async fn https_upstream_with_custom_ca_is_forwarded() {
    let cert_dir = tempfile::tempdir().unwrap();
    let (upstream, ca_path) = spawn_tls_upstream(cert_dir.path()).await;
    let proxy = spawn_proxy(
        format!("https://127.0.0.1:{}", upstream.port()),
        Some(&ca_path),
        None,
    )
    .await;

    let response = reqwest::get(format!("{}/hello?id=42", proxy))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await.unwrap();
    assert!(body.starts_with("upstream-ok "), "unexpected body: {body}");
    assert!(body.contains("xff=127.0.0.1"), "XFF not forwarded: {body}");
}

#[tokio::test]
async fn https_upstream_mutual_tls_with_client_certificate_is_forwarded() {
    let cert_dir = tempfile::tempdir().unwrap();
    let (upstream, ca_path, client_cert, client_key) =
        spawn_mtls_tls_upstream(cert_dir.path()).await;
    let proxy = spawn_proxy(
        format!("https://127.0.0.1:{}", upstream.port()),
        Some(&ca_path),
        Some((&client_cert, &client_key)),
    )
    .await;

    let response = reqwest::get(format!("{}/hello", proxy)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await.unwrap();
    assert!(body.starts_with("upstream-ok "), "unexpected body: {body}");
}

#[tokio::test]
async fn https_upstream_mutual_tls_without_client_certificate_fails() {
    let cert_dir = tempfile::tempdir().unwrap();
    let (upstream, ca_path, _client_cert, _client_key) =
        spawn_mtls_tls_upstream(cert_dir.path()).await;
    let proxy = spawn_proxy(
        format!("https://127.0.0.1:{}", upstream.port()),
        Some(&ca_path),
        None,
    )
    .await;

    let response = reqwest::get(format!("{}/hello", proxy)).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
}

#[test]
fn upstream_mutual_tls_requires_cert_and_key_together() {
    let mut config = Config::default();
    config.waf.coraza.enabled = false;
    config.proxy.upstream_client_cert_path = Some("/nonexistent/client.pem".to_string());
    let error = WafProxyService::new(config)
        .err()
        .expect("expected startup error")
        .to_string();
    assert!(
        error.contains("upstream_client_key_path is missing"),
        "unexpected error: {error}"
    );

    let mut config = Config::default();
    config.waf.coraza.enabled = false;
    config.proxy.upstream_client_key_path = Some("/nonexistent/client.key".to_string());
    let error = WafProxyService::new(config)
        .err()
        .expect("expected startup error")
        .to_string();
    assert!(
        error.contains("upstream_client_cert_path is missing"),
        "unexpected error: {error}"
    );
}

#[tokio::test]
async fn http_upstream_still_works() {
    let upstream = spawn_http_upstream().await;
    let proxy = spawn_proxy(format!("http://{}", upstream), None, None).await;

    let response = reqwest::get(format!("{}/hello", proxy)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await.unwrap();
    assert!(body.starts_with("upstream-ok "), "unexpected body: {body}");
}
