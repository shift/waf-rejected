use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tracing::{info, warn, debug};
use web_transport_quinn as wtq;

use waf_ingress::waf::{Decision, RequestContext, WafEngine};
use waf_ingress::config::Config;

#[tokio::main]
async fn main() -> Result<()> {
    // Lower log level to minimize overhead during perf runs
    tracing_subscriber::fmt().with_max_level(tracing::Level::WARN).init();

    // Load config and WAF
    let config = Config::default();
    let waf = Arc::new(WafEngine::with_config(&config));

    // Bind WT address
    let bind: SocketAddr = std::env::var("WT_WAF_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:4443".to_string())
        .parse()?;

    let (certs, key) = self_signed_cert()?;

    let mut server = wtq::ServerBuilder::new()
        .with_addr(bind)
        // Prefer higher throughput for micro-messages in perf tests
        .with_congestion_control(wtq::CongestionControl::Throughput)
        .with_certificate(certs, key)?;

    info!("WAF WebTransport proxy listening on {}", bind);

    loop {
        match server.accept().await {
            Some(request) => {
                let waf = Arc::clone(&waf);
                tokio::spawn(async move {
                    let url = request.url().clone();
                    // Build an http::Uri from the URL for the WAF context
                    let path = url.path().to_string();
                    let pq = match url.query() {
                        Some(q) => format!("{}?{}", path, q),
                        None => path,
                    };
                    let uri: http::Uri = http::Uri::builder()
                        .scheme("https")
                        .authority(url.host_str().unwrap_or("localhost"))
                        .path_and_query(pq.as_str())
                        .build()
                        .unwrap();

                    // WAF gate using the :authority and path from the request URL
                    let headers = http::HeaderMap::new();
                    let rctx = RequestContext::new(
                        "127.0.0.1".parse().unwrap(),
                        http::Method::CONNECT,
                        uri,
                        headers,
                        None,
                    );
                    match waf.fast_evaluate(&rctx).await {
                        Decision::Allow => {
                            match request.ok().await {
                                Ok(session) => {
                                    // Remove per-session logs to minimize overhead during perf runs
                                    // Minimal proxy loop: echo within the session (acts like passthrough for benchmark)
                                    // Bidi streams
                                    let s = session.clone();
                                    tokio::spawn(async move {
                                        while let Ok((mut send, mut recv)) = s.accept_bi().await {
                                            tokio::spawn(async move {
                                                let mut buf = vec![0u8; 16 * 1024];
                                                loop {
                                                    match recv.read(&mut buf).await {
                                                        Ok(None) | Err(_) => { let _ = send.finish(); break; }
                                                        Ok(Some(n)) => { let _ = send.write_all(&buf[..n]).await; }
                                                    }
                                                }
                                            });
                                        }
                                    });
                                    // Datagrams echo
                                    let s2 = session.clone();
                                    tokio::spawn(async move {
                                        loop {
                                            match s2.read_datagram().await {
                                                Ok(d) => { let _ = s2.send_datagram(d); }
                                                Err(_) => break,
                                            }
                                        }
                                    });
                                }
                                Err(e) => warn!("WT accept failed: {}", e),
                            }
                        }
                        Decision::Block { status, reason } => {
                            warn!("WAF blocked WT session ({}): {}", status, reason);
                            let _ = request.close(http::StatusCode::FORBIDDEN).await;
                        }
                        Decision::RateLimit { reason } => {
                            warn!("WAF rate-limited WT session: {}", reason);
                            let _ = request.close(http::StatusCode::TOO_MANY_REQUESTS).await;
                        }
                    }
                });
            }
            None => {}
        }
    }
}

fn self_signed_cert() -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    use rcgen::{Certificate, CertificateParams, KeyPair, SanType};

    let mut params = CertificateParams::default();
    params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
    params.distinguished_name.push(rcgen::DnType::CommonName, "waf-rejected WT WAF");
    params.subject_alt_names = vec![
        SanType::DnsName("localhost".to_string()),
        SanType::IpAddress("127.0.0.1".parse().unwrap()),
    ];

    let key = KeyPair::generate(params.alg)?;
    params.key_pair = Some(key);
    let cert = Certificate::from_params(params)?;

    let cert_der = rustls_pki_types::CertificateDer::from(cert.serialize_der()?);
    let key_der = rustls_pki_types::PrivateKeyDer::Pkcs8(cert.serialize_private_key_der().into());

    Ok((vec![cert_der], key_der))
}
