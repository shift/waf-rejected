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
        let builder = RustlsServerConfig::builder_with_protocol_versions(&versions);

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

fn tls_rank(version: &str) -> Result<u8, WafError> {
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
}
