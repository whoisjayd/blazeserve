//! Loads the TLS certificate and key into a rustls acceptor.

use super::BoxError;
use crate::config::TlsConfig;
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::pki_types::CertificateDer;
use tokio_rustls::rustls::{self, ServerConfig};

pub(super) fn load_tls(tls: &TlsConfig, http2: bool) -> Result<TlsAcceptor, BoxError> {
    let open = |what: &str, path: &std::path::Path| {
        File::open(path)
            .map(BufReader::new)
            .map_err(|e| BoxError::from(format!("cannot open TLS {what} {}: {e}", path.display())))
    };
    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut open("certificate", &tls.cert)?)
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
    let key = rustls_pemfile::private_key(&mut open("key", &tls.key)?)
        .map_err(|e| BoxError::from(format!("invalid TLS key {}: {e}", tls.key.display())))?
        .ok_or_else(|| BoxError::from(format!("no private key found in {}", tls.key.display())))?;
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
