mod http_common;

use blazeserve::config::{Config, TlsConfig};
use blazeserve::server::{self, ServerHandle};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http2::SendRequest;
use hyper::{Request, StatusCode, Version};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore, crypto::ring::default_provider};

const SIZE: usize = 256 * 1024;

type Client = SendRequest<Full<Bytes>>;

struct Reply {
    status: StatusCode,
    version: Version,
    headers: hyper::HeaderMap,
    body: Bytes,
}

impl Reply {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }
}

async fn start(tweak: impl FnOnce(&mut Config)) -> (TempDir, ServerHandle) {
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("big.bin"), http_common::pattern(SIZE)).unwrap();
    std::fs::create_dir_all(dir.path().join("docs")).unwrap();
    std::fs::write(dir.path().join("docs").join("a.md"), b"alpha").unwrap();
    let mut config = Config {
        host: "127.0.0.1".into(),
        port: 0,
        base: dir.path().to_path_buf(),
        ..Config::default()
    };
    tweak(&mut config);
    let handle = server::start(config).await.unwrap();
    (dir, handle)
}

async fn handshake<I>(io: I) -> Client
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (send, conn) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(io))
            .await
            .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    send
}

async fn h2c(addr: SocketAddr) -> Client {
    handshake(TcpStream::connect(addr).await.unwrap()).await
}

async fn fetch(
    client: &mut Client,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> Reply {
    client.ready().await.unwrap();
    let mut req = Request::builder()
        .method(method)
        .uri(format!("http://localhost{path}"));
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let req = req.body(Full::new(Bytes::copy_from_slice(body))).unwrap();
    let resp = client.send_request(req).await.unwrap();
    let (parts, incoming) = resp.into_parts();
    Reply {
        status: parts.status,
        version: parts.version,
        headers: parts.headers,
        body: incoming.collect().await.unwrap().to_bytes(),
    }
}

async fn wait_idle(handle: &ServerHandle) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while handle.state().metrics.stats().requests_active != 0 {
        assert!(
            Instant::now() < deadline,
            "active gauge never returned to zero"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h2c_get_range_and_head() {
    let (_dir, handle) = start(|_| {}).await;
    let mut c = h2c(handle.local_addr()).await;
    let expected = http_common::pattern(SIZE);

    let r = fetch(&mut c, "GET", "/big.bin", &[], b"").await;
    assert_eq!((r.status, r.version), (StatusCode::OK, Version::HTTP_2));
    assert_eq!(r.header("content-length"), Some(SIZE.to_string().as_str()));
    assert_eq!(r.body.as_ref(), expected.as_slice());

    let r = fetch(&mut c, "GET", "/big.bin", &[("range", "bytes=10-19")], b"").await;
    assert_eq!(r.status, StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        r.header("content-range"),
        Some(format!("bytes 10-19/{SIZE}").as_str())
    );
    assert_eq!(r.body.as_ref(), &expected[10..20]);

    let r = fetch(&mut c, "HEAD", "/big.bin", &[], b"").await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.header("content-length"), Some(SIZE.to_string().as_str()));
    assert!(r.body.is_empty());

    let before = handle.state().metrics.stats().requests_total;
    fetch(&mut c, "GET", "/__health__", &[], b"").await;
    assert_eq!(handle.state().metrics.stats().requests_total, before + 1);
    wait_idle(&handle).await;
    handle.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http1_keeps_working_and_a_bad_preface_is_http1() {
    let (_dir, handle) = start(|_| {}).await;
    let addr = handle.local_addr();
    let r = http_common::get(addr, "/big.bin");
    assert_eq!((r.status, r.body.len()), (200, SIZE));

    let mut raw = TcpStream::connect(addr).await.unwrap();
    raw.write_all(b"PRI * HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut out = Vec::new();
    raw.read_to_end(&mut out).await.unwrap();
    assert!(
        out.starts_with(b"HTTP/1.1 405"),
        "{}",
        String::from_utf8_lossy(&out)
    );
    handle.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn disabled_http2_treats_the_preface_as_http1() {
    let (_dir, handle) = start(|c| c.http2 = false).await;
    let mut raw = TcpStream::connect(handle.local_addr()).await.unwrap();
    raw.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        .await
        .unwrap();
    let mut out = vec![0u8; 64];
    // An HTTP/2 server answers a preface with a SETTINGS frame at once; HTTP/1 never does.
    if let Ok(Ok(n)) = tokio::time::timeout(Duration::from_secs(2), raw.read(&mut out)).await {
        assert!(n == 0 || out.starts_with(b"HTTP/1.1 "), "{:?}", &out[..n]);
    }
    handle.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn many_streams_on_one_connection_succeed_beyond_the_stream_limit() {
    let (_dir, handle) = start(|_| {}).await;
    let expected = http_common::pattern(SIZE);
    let c = h2c(handle.local_addr()).await;

    let mut tasks = Vec::new();
    for i in 0..200usize {
        let mut c = c.clone();
        tasks.push(tokio::spawn(async move {
            let start = (i % 20) * 1000;
            let range = format!("bytes={start}-{}", start + 999);
            let r = fetch(&mut c, "GET", "/big.bin", &[("range", range.as_str())], b"").await;
            (start, r)
        }));
    }
    for t in tasks {
        let (start, r) = t.await.unwrap();
        assert_eq!(r.status, StatusCode::PARTIAL_CONTENT);
        assert_eq!(r.body.as_ref(), &expected[start..start + 1000]);
    }
    drop(c);

    let r = http_common::get(handle.local_addr(), "/__health__");
    assert_eq!(r.status, 200);
    wait_idle(&handle).await;
    assert_eq!(handle.state().metrics.stats().errors_total, 0);
    handle.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_connection_that_opens_streams_too_fast_gets_429_while_others_are_served() {
    let (_dir, handle) = start(|_| {}).await;
    let mut flooder = h2c(handle.local_addr()).await;

    let mut statuses = Vec::new();
    for _ in 0..1500 {
        statuses.push(
            fetch(&mut flooder, "GET", "/__live__", &[], b"")
                .await
                .status,
        );
    }
    // The burst allowance is always granted before any refill can matter.
    assert!(
        statuses[..256].iter().all(|s| *s == StatusCode::OK),
        "burst was not honoured"
    );
    assert!(
        statuses.contains(&StatusCode::TOO_MANY_REQUESTS),
        "1500 back-to-back streams were never throttled"
    );

    let mut other = h2c(handle.local_addr()).await;
    let r = fetch(&mut other, "GET", "/__live__", &[], b"").await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(
        http_common::get(handle.local_addr(), "/__live__").status,
        200
    );
    wait_idle(&handle).await;
    handle.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn zip_download_works_over_h2_and_http1_still_closes() {
    let (_dir, handle) = start(|_| {}).await;
    let mut c = h2c(handle.local_addr()).await;
    let r = fetch(&mut c, "GET", "/__zip__?path=docs", &[], b"").await;
    assert_eq!((r.status, r.version), (StatusCode::OK, Version::HTTP_2));
    assert_eq!(r.header("content-type"), Some("application/zip"));
    assert!(r.header("connection").is_none());
    assert!(r.body.starts_with(b"PK"));
    let again = fetch(&mut c, "GET", "/__health__", &[], b"").await;
    assert_eq!(again.status, StatusCode::OK);
    wait_idle(&handle).await;

    let h1 = http_common::get(handle.local_addr(), "/__zip__?path=docs");
    assert_eq!(h1.header("connection"), Some("close"));
    assert!(h1.body.starts_with(b"PK"));
    handle.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejected_upload_over_h2_leaves_the_connection_usable() {
    let (dir, handle) = start(|c| c.max_upload_bytes = 10).await;
    let mut c = h2c(handle.local_addr()).await;
    let r = fetch(
        &mut c,
        "PUT",
        "/__upload__/new.bin",
        &[("content-length", "100")],
        &[7u8; 100],
    )
    .await;
    assert_eq!(r.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert!(r.header("connection").is_none());
    assert!(!dir.path().join("new.bin").exists());

    let ok = fetch(&mut c, "GET", "/docs/a.md", &[], b"").await;
    assert_eq!(
        (ok.status, ok.body.as_ref()),
        (StatusCode::OK, b"alpha".as_slice())
    );
    wait_idle(&handle).await;
    handle.shutdown().await;
}

fn tls_fixture(dir: &TempDir) -> (TlsConfig, CertificateDer<'static>) {
    let key = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let cert = dir.path().join("cert.pem");
    let keyfile = dir.path().join("key.pem");
    std::fs::write(&cert, key.cert.pem()).unwrap();
    std::fs::write(&keyfile, key.signing_key.serialize_pem()).unwrap();
    (TlsConfig { cert, key: keyfile }, key.cert.der().clone())
}

fn connector(cert: CertificateDer<'static>, alpn: &[&[u8]]) -> TlsConnector {
    let mut roots = RootCertStore::empty();
    roots.add(cert).unwrap();
    let mut cfg = ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    TlsConnector::from(Arc::new(cfg))
}

async fn tls_connect(
    addr: SocketAddr,
    cert: &CertificateDer<'static>,
    alpn: &[&[u8]],
) -> tokio_rustls::client::TlsStream<TcpStream> {
    let tcp = TcpStream::connect(addr).await.unwrap();
    connector(cert.clone(), alpn)
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_alpn_negotiates_h2_or_http1() {
    let certs = TempDir::new().unwrap();
    let (tls, cert) = tls_fixture(&certs);
    let (_dir, handle) = start(|c| c.tls = Some(tls)).await;
    let addr = handle.local_addr();

    let stream = tls_connect(addr, &cert, &[b"h2", b"http/1.1"]).await;
    assert_eq!(stream.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
    let mut c = handshake(stream).await;
    let r = fetch(&mut c, "GET", "/big.bin", &[("range", "bytes=0-99")], b"").await;
    assert_eq!(
        (r.status, r.version),
        (StatusCode::PARTIAL_CONTENT, Version::HTTP_2)
    );
    assert_eq!(r.body.len(), 100);
    assert!(r.header("strict-transport-security").is_some());

    let mut stream = tls_connect(addr, &cert, &[b"http/1.1"]).await;
    assert_eq!(
        stream.get_ref().1.alpn_protocol(),
        Some(b"http/1.1".as_slice())
    );
    stream
        .write_all(b"GET /docs/a.md HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut out = Vec::new();
    let _ = stream.read_to_end(&mut out).await;
    assert!(out.starts_with(b"HTTP/1.1 200"));
    assert!(out.ends_with(b"alpha"));

    let stream = tls_connect(addr, &cert, &[]).await;
    assert_eq!(stream.get_ref().1.alpn_protocol(), None);
    handle.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_with_http2_disabled_never_offers_h2() {
    let certs = TempDir::new().unwrap();
    let (tls, cert) = tls_fixture(&certs);
    let (_dir, handle) = start(|c| {
        c.tls = Some(tls);
        c.http2 = false;
    })
    .await;
    let stream = tls_connect(handle.local_addr(), &cert, &[b"h2", b"http/1.1"]).await;
    assert_eq!(
        stream.get_ref().1.alpn_protocol(),
        Some(b"http/1.1".as_slice())
    );
    handle.shutdown().await;
}
