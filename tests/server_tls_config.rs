use blazeserve::config::{Config, TlsConfig};
use blazeserve::server;
use tempfile::TempDir;

const CERT_MARKER: &str = "CERT-BODY-MUST-NOT-LEAK";
const KEY_MARKER: &str = "KEY-BODY-MUST-NOT-LEAK";

fn base_config(dir: &TempDir) -> Config {
    Config {
        host: "127.0.0.1".into(),
        port: 0,
        base: dir.path().to_path_buf(),
        ..Config::default()
    }
}

async fn start_error(config: Config) -> String {
    match server::start(config).await {
        Ok(_) => panic!("server must refuse to start"),
        Err(e) => e.to_string(),
    }
}

#[tokio::test]
async fn half_configured_pair_is_rejected_before_binding() {
    let cert = std::path::PathBuf::from("cert.pem");
    assert!(Config::tls_pair(Some(cert.clone()), None).is_err());
    assert!(Config::tls_pair(None, Some(cert)).is_err());
}

#[tokio::test]
async fn missing_files_fail_with_option_name() {
    let dir = TempDir::new().unwrap();
    let tls = TlsConfig {
        cert: dir.path().join("absent-cert.pem"),
        key: dir.path().join("absent-key.pem"),
    };
    let message = start_error(Config {
        tls: Some(tls),
        ..base_config(&dir)
    })
    .await;
    assert!(message.contains("--tls-cert"), "{message}");
}

#[tokio::test]
async fn garbage_pem_names_the_file_but_never_prints_contents() {
    let dir = TempDir::new().unwrap();
    let cert = dir.path().join("cert.pem");
    let key = dir.path().join("key.pem");
    std::fs::write(
        &cert,
        format!("-----BEGIN CERTIFICATE-----\n{CERT_MARKER}\n-----END CERTIFICATE-----\n"),
    )
    .unwrap();
    std::fs::write(
        &key,
        format!("-----BEGIN PRIVATE KEY-----\n{KEY_MARKER}\n-----END PRIVATE KEY-----\n"),
    )
    .unwrap();

    let message = start_error(Config {
        tls: Some(TlsConfig {
            cert: cert.clone(),
            key,
        }),
        ..base_config(&dir)
    })
    .await;
    assert!(
        message.contains("cert.pem") || message.contains("key.pem"),
        "{message}"
    );
    assert!(
        !message.contains(CERT_MARKER) && !message.contains(KEY_MARKER),
        "{message}"
    );
}

#[tokio::test]
async fn empty_certificate_file_is_rejected() {
    let dir = TempDir::new().unwrap();
    let cert = dir.path().join("empty-cert.pem");
    let key = dir.path().join("empty-key.pem");
    std::fs::write(&cert, "").unwrap();
    std::fs::write(&key, "").unwrap();
    let message = start_error(Config {
        tls: Some(TlsConfig { cert, key }),
        ..base_config(&dir)
    })
    .await;
    assert!(message.contains("no certificate found"), "{message}");
}
