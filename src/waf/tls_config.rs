use crate::config::TlsConfig;
use crate::error::WafError;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ServerConfig as RustlsServerConfig, WebPkiClientVerifier};
use rustls::version::{TLS12, TLS13};
use rustls::RootCertStore;
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor as TokioTlsAcceptor;
use tracing::{debug, info};

pub struct TlsManager {
    acceptor: Option<TokioTlsAcceptor>,
    config: TlsConfig,
}

impl TlsManager {
    pub fn new(config: TlsConfig) -> Result<Self, WafError> {
        if !config.enabled {
            info!("TLS disabled in configuration");
            return Ok(Self {
                acceptor: None,
                config,
            });
        }

        debug!(
            "Initializing TLS with cert: {}, key: {}",
            config.cert_path, config.key_path
        );

        let certs = load_certs(&config.cert_path)?;
        let key = load_private_key(&config.key_path)?;

        let versions = selected_versions(&config.min_version, &config.max_version)?;
        // Both ring and aws-lc-rs may be enabled by transitive dependencies;
        // select ring explicitly instead of relying on an ambiguous default.
        let builder = RustlsServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&versions)
        .map_err(|e| {
            WafError::Configuration(format!("TLS protocol version configuration error: {}", e))
        })?;

        let mut server_config = if config.require_client_cert {
            let ca_path = config.client_ca_path.as_deref().ok_or_else(|| {
                WafError::Configuration(
                    "server.tls.require_client_cert is true but client_ca_path is not set"
                        .to_string(),
                )
            })?;
            let mut roots = RootCertStore::empty();
            for cert in load_certs(ca_path)? {
                roots.add(cert).map_err(|e| {
                    WafError::Configuration(format!("Invalid client CA certificate: {}", e))
                })?;
            }
            let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
                .build()
                .map_err(|e| {
                    WafError::Configuration(format!("Failed to build client verifier: {}", e))
                })?;
            builder
                .with_client_cert_verifier(verifier)
                .with_single_cert(certs, key)
        } else {
            builder.with_no_client_auth().with_single_cert(certs, key)
        }
        .map_err(|e| WafError::Configuration(format!("TLS configuration error: {}", e)))?;

        if !config.alpn_protocols.is_empty() {
            let alpn: Vec<Vec<u8>> = config
                .alpn_protocols
                .iter()
                .map(|s| s.as_bytes().to_vec())
                .collect();
            server_config.alpn_protocols = alpn;
        }

        let acceptor = TokioTlsAcceptor::from(Arc::new(server_config));

        info!(
            "TLS initialized successfully - TLS {}-{}",
            config.min_version, config.max_version
        );

        Ok(Self {
            acceptor: Some(acceptor),
            config,
        })
    }

    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Build a rustls `ServerConfig` suitable for QUIC/HTTP/3 and WebTransport.
    ///
    /// QUIC mandates TLS 1.3, so this ignores the configured version range
    /// except to reject a configuration that cannot negotiate 1.3. ALPN is
    /// restricted to `h3` (also the WebTransport ALPN); the TCP ALPN list is
    /// left untouched.
    #[cfg(any(feature = "http3", feature = "webtransport"))]
    pub fn quic_server_config(&self) -> Result<Arc<RustlsServerConfig>, WafError> {
        if !self.config.enabled {
            return Err(WafError::Configuration(
                "QUIC (HTTP/3/WebTransport) requires TLS, but TLS is disabled".to_string(),
            ));
        }
        if tls_rank(&self.config.max_version)? < 3 {
            return Err(WafError::Configuration(format!(
                "QUIC (HTTP/3/WebTransport) requires TLS 1.3, but server.tls.max_version is {}",
                self.config.max_version
            )));
        }

        let certs = load_certs(&self.config.cert_path)?;
        let key = load_private_key(&self.config.key_path)?;

        let builder = RustlsServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&TLS13])
        .map_err(|e| {
            WafError::Configuration(format!("QUIC TLS protocol configuration error: {}", e))
        })?;

        let mut server_config = if self.config.require_client_cert {
            let ca_path = self.config.client_ca_path.as_deref().ok_or_else(|| {
                WafError::Configuration(
                    "server.tls.require_client_cert is true but client_ca_path is not set"
                        .to_string(),
                )
            })?;
            let mut roots = RootCertStore::empty();
            for cert in load_certs(ca_path)? {
                roots.add(cert).map_err(|e| {
                    WafError::Configuration(format!("Invalid client CA certificate: {}", e))
                })?;
            }
            let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
                .build()
                .map_err(|e| {
                    WafError::Configuration(format!("Failed to build client verifier: {}", e))
                })?;
            builder
                .with_client_cert_verifier(verifier)
                .with_single_cert(certs, key)
        } else {
            builder.with_no_client_auth().with_single_cert(certs, key)
        }
        .map_err(|e| WafError::Configuration(format!("QUIC TLS configuration error: {}", e)))?;

        // HTTP/3 only. `h3` must never be advertised on the TCP listener.
        server_config.alpn_protocols = vec![b"h3".to_vec()];

        Ok(Arc::new(server_config))
    }

    pub async fn accept(&self, stream: TcpStream) -> Result<TlsStream<TcpStream>, WafError> {
        match &self.acceptor {
            Some(acceptor) => acceptor
                .accept(stream)
                .await
                .map_err(|e| WafError::TlsHandshake(e.to_string())),
            None => Err(WafError::Configuration(
                "TLS not enabled, cannot accept TLS connections".to_string(),
            )),
        }
    }
}

fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>, WafError> {
    let cert_file = File::open(path).map_err(|e| {
        WafError::Configuration(format!("Failed to open certificate file {}: {}", path, e))
    })?;

    let mut reader = BufReader::new(cert_file);

    rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| WafError::Configuration(format!("Failed to parse certificate: {}", e)))
}

fn load_private_key(path: &str) -> Result<PrivateKeyDer<'static>, WafError> {
    let key_file = File::open(path).map_err(|e| {
        WafError::Configuration(format!("Failed to open private key file {}: {}", path, e))
    })?;

    let mut reader = BufReader::new(key_file);

    rustls_pemfile::private_key(&mut reader)
        .map_err(|e| WafError::Configuration(format!("Failed to parse private key: {}", e)))?
        .ok_or_else(|| WafError::Configuration("No private key found in file".to_string()))
}

fn selected_versions(
    min: &str,
    max: &str,
) -> Result<Vec<&'static rustls::SupportedProtocolVersion>, WafError> {
    let min_rank = tls_rank(min)?;
    let max_rank = tls_rank(max)?;
    if min_rank > max_rank {
        return Err(WafError::Configuration(format!(
            "TLS min_version {} is higher than max_version {}",
            min, max
        )));
    }

    let mut versions = Vec::new();
    if max_rank >= 3 {
        versions.push(&TLS13);
    }
    if min_rank <= 2 {
        versions.push(&TLS12);
    }
    Ok(versions)
}

pub(crate) fn tls_rank(version: &str) -> Result<u8, WafError> {
    match version {
        "1.2" => Ok(2),
        "1.3" => Ok(3),
        _ => Err(WafError::Configuration(format!(
            "Unsupported TLS version: {}. Supported versions: 1.2, 1.3",
            version
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_respect_min_and_max() {
        assert_eq!(selected_versions("1.3", "1.3").unwrap().len(), 1);
        assert_eq!(selected_versions("1.2", "1.3").unwrap().len(), 2);
        assert!(selected_versions("1.3", "1.2").is_err());
        assert!(selected_versions("1.1", "1.3").is_err());
    }

    #[cfg(any(feature = "http3", feature = "webtransport"))]
    #[test]
    fn quic_config_is_tls13_only_with_h3_alpn() {
        let dir = tempfile::tempdir().unwrap();
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        std::fs::write(&cert_path, certified.cert.pem()).unwrap();
        std::fs::write(&key_path, certified.signing_key.serialize_pem()).unwrap();

        let manager = TlsManager::new(TlsConfig {
            enabled: true,
            cert_path: cert_path.to_string_lossy().into_owned(),
            key_path: key_path.to_string_lossy().into_owned(),
            min_version: "1.2".to_string(),
            max_version: "1.3".to_string(),
            ..TlsConfig::default()
        })
        .unwrap();

        let config = manager.quic_server_config().unwrap();
        assert_eq!(config.alpn_protocols, vec![b"h3".to_vec()]);
    }

    #[cfg(any(feature = "http3", feature = "webtransport"))]
    #[test]
    fn quic_config_rejects_tls_12_max_version() {
        let dir = tempfile::tempdir().unwrap();
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        std::fs::write(&cert_path, certified.cert.pem()).unwrap();
        std::fs::write(&key_path, certified.signing_key.serialize_pem()).unwrap();

        let manager = TlsManager::new(TlsConfig {
            enabled: true,
            cert_path: cert_path.to_string_lossy().into_owned(),
            key_path: key_path.to_string_lossy().into_owned(),
            max_version: "1.2".to_string(),
            ..TlsConfig::default()
        })
        .unwrap();

        let error = manager.quic_server_config().unwrap_err();
        assert!(format!("{}", error).contains("TLS 1.3"));
    }
}
