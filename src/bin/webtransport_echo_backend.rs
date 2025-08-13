use std::net::SocketAddr;

use anyhow::Result;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio::task::JoinSet;
use tracing::{info, warn};
use web_transport_quinn as wtq;

// Simple Rust WebTransport echo backend: echoes bidi/unidi streams and datagrams
#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_max_level(tracing::Level::INFO).init();

    let bind: SocketAddr = std::env::var("WT_BACKEND_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:4444".to_string())
        .parse()?;

    let (certs, key) = self_signed_cert()?;

    let mut server = wtq::ServerBuilder::new()
        .with_addr(bind)
        // Prefer throughput for perf scenarios (micro-messages, high rate)
        .with_congestion_control(wtq::CongestionControl::Throughput)
        .with_certificate(certs, key)?;

    info!("WebTransport echo backend listening on {} (HTTP/3/QUIC)", bind);

    let mut tasks = JoinSet::new();
    loop {
        match server.accept().await {
            Some(request) => {
                tasks.spawn(async move {
                    let url = request.url().clone();
                    match request.ok().await {
                        Ok(session) => {
                            info!("WT session accepted: {}", url);

                            // Handle bidirectional streams
                            let s = session.clone();
                            tokio::spawn(async move {
                                while let Ok((mut send, mut recv)) = s.accept_bi().await {
                                    tokio::spawn(async move {
                                        let mut buf = vec![0u8; 16 * 1024];
                                        loop {
                                            match recv.read(&mut buf).await {
                                                Ok(None) | Err(_) => { let _ = send.finish(); break; }
                                                Ok(Some(n)) => {
                                                    if send.write_all(&buf[..n]).await.is_err() { break; }
                                                }
                                            }
                                        }
                                    });
                                }
                            });

                            // Handle unidirectional receive streams (echo back on new uni)
                            let s2 = session.clone();
                            tokio::spawn(async move {
                                while let Ok(mut recv) = s2.accept_uni().await {
                                    let mut buf = vec![0u8; 16 * 1024];
                                    let mut data = Vec::with_capacity(16 * 1024);
                                    loop {
                                        match recv.read(&mut buf).await {
                                            Ok(None) | Err(_) => break,
                                            Ok(Some(n)) => data.extend_from_slice(&buf[..n]),
                                        }
                                    }
                                    if let Ok(mut send) = s2.open_uni().await {
                                        let _ = send.write_all(&data).await;
                                        let _ = send.finish();
                                    }
                                }
                            });

                            // Handle datagrams echo
                            let s3 = session.clone();
                            tokio::spawn(async move {
                                loop {
                                    match s3.read_datagram().await {
                                        Ok(d) => { let _ = s3.send_datagram(d); }
                                        Err(_) => break,
                                    }
                                }
                            });
                        }
                        Err(e) => warn!("Failed to accept WT session: {}", e),
                    }
                });
            }
            None => { /* no new session */ }
        }
    }
}

fn self_signed_cert() -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    use rcgen::{Certificate, CertificateParams, KeyPair, SanType};

    let mut params = CertificateParams::default();
    params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
    params.distinguished_name.push(rcgen::DnType::CommonName, "waf-rejected WT backend");
    params.subject_alt_names = vec![
        SanType::DnsName("localhost".to_string()),
        SanType::IpAddress("127.0.0.1".parse().unwrap()),
    ];

    let key = KeyPair::generate(params.alg)?;
    params.key_pair = Some(key);
    let cert = Certificate::from_params(params)?;

    let cert_der = CertificateDer::from(cert.serialize_der()?);
    let key_der = PrivateKeyDer::Pkcs8(cert.serialize_private_key_der().into());

    Ok((vec![cert_der], key_der))
}
