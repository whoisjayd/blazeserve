use blazeserve::config::Config;
use blazeserve::server::{self, ServerHandle, StopReason};
use std::future::{pending, ready};
use std::net::SocketAddr;
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tokio::time::timeout;

const BOUND: Duration = Duration::from_secs(20);
const BIG: usize = 24 * 1024 * 1024;

fn config(dir: &TempDir) -> Config {
    Config {
        host: "127.0.0.1".into(),
        port: 0,
        base: dir.path().to_path_buf(),
        ..Config::default()
    }
}

async fn read_head(stream: &mut TcpStream) -> (String, Vec<u8>) {
    let mut buf = Vec::new();
    timeout(BOUND, async {
        let mut chunk = [0u8; 4096];
        loop {
            let n = stream.read(&mut chunk).await.expect("read");
            assert!(n > 0, "closed before the response head");
            buf.extend_from_slice(&chunk[..n]);
            if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                let rest = buf.split_off(end + 4);
                return (String::from_utf8_lossy(&buf).into_owned(), rest);
            }
        }
    })
    .await
    .expect("response head in time")
}

async fn until_refused(addr: SocketAddr) {
    timeout(BOUND, async {
        while TcpStream::connect(addr).await.is_ok() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("listener closed in time");
}

/// Runs the handle's wait in a task and hands back the reason once shutdown has finished.
fn drive(
    mut handle: ServerHandle,
    expiry: oneshot::Receiver<()>,
) -> tokio::task::JoinHandle<StopReason> {
    tokio::spawn(async move {
        let reason = handle
            .wait_until(async { expiry.await.unwrap_or(()) }, pending())
            .await;
        handle.shutdown().await;
        reason
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn timed_expiry_stops_an_idle_share_and_releases_the_port() {
    let dir = TempDir::new().unwrap();
    let cfg = config(&dir);
    let (tx, rx) = std::sync::mpsc::channel();
    let runner = std::thread::spawn(move || {
        server::run_expiring(cfg, Some(Duration::from_millis(150)), |h| {
            tx.send(h.local_addr()).unwrap();
        })
    });
    let addr = rx.recv_timeout(BOUND).expect("bound");
    let reason = tokio::task::spawn_blocking(move || runner.join().unwrap())
        .await
        .unwrap()
        .expect("clean stop");
    assert_eq!(reason, StopReason::Expired);
    assert!(TcpStream::connect(addr).await.is_err());
    std::net::TcpListener::bind(addr).expect("port released");
}

#[tokio::test(flavor = "multi_thread")]
async fn interrupt_before_expiry_stops_the_share_and_releases_the_port() {
    let dir = TempDir::new().unwrap();
    let mut handle = server::start(config(&dir)).await.unwrap();
    let addr = handle.local_addr();
    let reason = handle.wait_until(pending(), ready(())).await;
    assert_eq!(reason, StopReason::Signal);
    handle.shutdown().await;
    assert!(TcpStream::connect(addr).await.is_err());
    std::net::TcpListener::bind(addr).expect("port released");
}

#[tokio::test(flavor = "multi_thread")]
async fn expiry_closes_keep_alive_connections_and_refuses_new_ones() {
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("a.txt"), b"hello").unwrap();
    let handle = server::start(config(&dir)).await.unwrap();
    let addr = handle.local_addr();
    let (expire, rx) = oneshot::channel();
    let task = drive(handle, rx);

    let mut kept = TcpStream::connect(addr).await.unwrap();
    kept.write_all(b"GET /a.txt HTTP/1.1\r\nHost: t\r\n\r\n")
        .await
        .unwrap();
    let (head, mut body) = read_head(&mut kept).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    while body.len() < 5 {
        let mut chunk = [0u8; 16];
        let n = kept.read(&mut chunk).await.unwrap();
        body.extend_from_slice(&chunk[..n]);
    }
    assert_eq!(body, b"hello");

    expire.send(()).unwrap();
    assert_eq!(
        timeout(BOUND, task).await.unwrap().unwrap(),
        StopReason::Expired
    );

    let _ = kept
        .write_all(b"GET /a.txt HTTP/1.1\r\nHost: t\r\n\r\n")
        .await;
    let mut rest = Vec::new();
    let _ = timeout(BOUND, kept.read_to_end(&mut rest)).await.unwrap();
    assert!(rest.is_empty(), "no new request may be served after expiry");
    assert!(TcpStream::connect(addr).await.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn expiry_lets_a_response_in_flight_finish_within_the_drain() {
    let dir = TempDir::new().unwrap();
    let data = vec![0xA5u8; BIG];
    std::fs::write(dir.path().join("big.bin"), &data).unwrap();
    let handle = server::start(config(&dir)).await.unwrap();
    let addr = handle.local_addr();
    let (expire, rx) = oneshot::channel();
    let task = drive(handle, rx);

    let mut client = TcpStream::connect(addr).await.unwrap();
    client
        .write_all(b"GET /big.bin HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let (head, mut body) = read_head(&mut client).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert!(body.len() < BIG, "transfer must still be in progress");

    expire.send(()).unwrap();
    until_refused(addr).await;

    let mut rest = Vec::new();
    timeout(BOUND, client.read_to_end(&mut rest))
        .await
        .expect("drain in time")
        .unwrap();
    body.extend_from_slice(&rest);
    assert_eq!(body.len(), BIG, "the in-flight response must complete");
    assert!(body == data);
    assert_eq!(
        timeout(BOUND, task).await.unwrap().unwrap(),
        StopReason::Expired
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn without_an_expiry_the_share_keeps_serving() {
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("a.txt"), b"hello").unwrap();
    let mut handle = server::start(config(&dir)).await.unwrap();
    let addr = handle.local_addr();
    let waited = timeout(
        Duration::from_millis(200),
        handle.wait_until(pending(), pending()),
    )
    .await;
    assert!(waited.is_err(), "no expiry means no stop");
    let mut c = TcpStream::connect(addr).await.unwrap();
    c.write_all(b"GET /a.txt HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut out = Vec::new();
    timeout(BOUND, c.read_to_end(&mut out))
        .await
        .unwrap()
        .unwrap();
    assert!(String::from_utf8_lossy(&out).starts_with("HTTP/1.1 200"));
    handle.shutdown().await;
}
