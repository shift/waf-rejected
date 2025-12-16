use crate::config::TlsConfig;
use crate::error::WafError;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::ServerConfig as RustlsServerConfig;
use rustls::version::{TLS12, TLS13};
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor as TokioTlsAcceptor;
use tracing::{debug, error, info};

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

        debug!("Initializing TLS with cert: {}, key: {}", config.cert_path, config.key_path);

        let certs = load_certs(&config.cert_path)?;
        let key = load_private_key(&config.key_path)?;

        let mut server_config = RustlsServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| WafError::Configuration(format!("TLS configuration error: {}", e)))?;

        if !config.alpn_protocols.is_empty() {
            let alpn: Vec<Vec<u8>> = config.alpn_protocols
                .iter()
                .map(|s| s.as_bytes().to_vec())
                .collect();
            server_config.alpn_protocols = alpn;
        }

        let min_version = parse_tls_version(&config.min_version)?;
        let max_version = parse_tls_version(&config.max_version)?;

        server_config.versions = vec![min_version, max_version]
            .into_iter()
            .collect();

        let acceptor = TokioTlsAcceptor::from(Arc::new(server_config));

        info!("TLS initialized successfully - TLS {}-{}", config.min_version, config.max_version);

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
            Some(acceptor) => {
                acceptor
                    .accept(stream)
                    .await
                    .map_err(|e| WafError::TlsHandshake(e.to_string()))
            }
            None => Err(WafError::Configuration(
                "TLS not enabled, cannot accept TLS connections".to_string(),
            )),
        }
    }
}

fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>, WafError> {
    let cert_file = File::open(path)
        .map_err(|e| WafError::Configuration(format!("Failed to open certificate file {}: {}", path, e)))?;

    let mut reader = BufReader::new(cert_file);

    rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| WafError::Configuration(format!("Failed to parse certificate: {}", e)))
}

fn load_private_key(path: &str) -> Result<PrivateKeyDer<'static>, WafError> {
    let key_file = File::open(path)
        .map_err(|e| WafError::Configuration(format!("Failed to open private key file {}: {}", path, e)))?;

    let mut reader = BufReader::new(key_file);

    rustls_pemfile::private_key(&mut reader)
        .map_err(|e| WafError::Configuration(format!("Failed to parse private key: {}", e)))?
        .ok_or_else(|| WafError::Configuration("No private key found in file".to_string()))
}

fn parse_tls_version(version: &str) -> Result<&'static rustls::SupportedProtocolVersion, WafError> {
    match version {
        "1.2" => Ok(&TLS12),
        "1.3" => Ok(&TLS13),
        _ => Err(WafError::Configuration(format!(
            "Unsupported TLS version: {}. Supported versions: 1.2, 1.3",
            version
        ))),
    }
}
