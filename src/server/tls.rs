//! Loads the TLS certificate and key into a rustls acceptor.

use super::BoxError;
use crate::config::TlsConfig;
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::pki_types::pem::{Error as PemError, PemObject};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::{self, ServerConfig};

pub(super) fn load_tls(tls: &TlsConfig, http2: bool) -> Result<TlsAcceptor, BoxError> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(&tls.cert)
        .map_err(|e| {
            BoxError::from(format!(
                "cannot open TLS certificate {}: {e}",
                tls.cert.display()
            ))
        })?
        .collect::<Result<_, _>>()
        .map_err(|e| {
            BoxError::from(format!(
                "invalid TLS certificate {}: {e}",
                tls.cert.display()
            ))
        })?;
    if certs.is_empty() {
        return Err(format!("no certificate found in {}", tls.cert.display()).into());
    }
    let key = PrivateKeyDer::from_pem_file(&tls.key).map_err(|e| match e {
        PemError::NoItemsFound => {
            BoxError::from(format!("no private key found in {}", tls.key.display()))
        }
        PemError::Io(_) => {
            BoxError::from(format!("cannot open TLS key {}: {e}", tls.key.display()))
        }
        _ => BoxError::from(format!("invalid TLS key {}: {e}", tls.key.display())),
    })?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut cfg = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|e| BoxError::from(format!("TLS protocol setup failed: {e}")))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| {
            BoxError::from(format!(
                "TLS certificate {} does not match key {}: {e}",
                tls.cert.display(),
                tls.key.display()
            ))
        })?;
    cfg.alpn_protocols = if http2 {
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    } else {
        vec![b"http/1.1".to_vec()]
    };
    Ok(TlsAcceptor::from(Arc::new(cfg)))
}
