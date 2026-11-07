use blazeserve::config::Config;
use blazeserve::server::{self, ServerHandle};
use std::time::{Duration, Instant};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout};

const LIVE_REQUEST: &[u8] = b"GET /__live__ HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n";
const BOUND: Duration = Duration::from_secs(5);

fn config(dir: &TempDir) -> Config {
    Config {
        host: "127.0.0.1".into(),
        port: 0,
        base: dir.path().to_path_buf(),
        max_connections: 2,
        header_timeout_secs: 30,
        timeout_secs: 60,
        ..Config::default()
    }
}

async fn connect(server: &ServerHandle) -> TcpStream {
    TcpStream::connect(server.local_addr())
        .await
        .expect("connect")
}

async fn read_response(stream: &mut TcpStream) -> String {
    let mut out = Vec::new();
    timeout(BOUND, async {
        let mut chunk = [0u8; 1024];
        loop {
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(n) => out.extend_from_slice(&chunk[..n]),
            }
        }
    })
    .await
    .expect("response not received in time");
    String::from_utf8_lossy(&out).into_owned()
}

async fn wait_until(what: &str, mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + BOUND;
    while !condition() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn saturated_server_rejects_then_recovers() {
    let dir = TempDir::new().unwrap();
    let server = server::start(config(&dir)).await.unwrap();
    let state = server.state().clone();

    let first = connect(&server).await;
    let second = connect(&server).await;
    wait_until("two admitted connections", || {
        state.metrics.connections_active() == 2
    })
    .await;

    let mut rejected = connect(&server).await;
    rejected.write_all(LIVE_REQUEST).await.unwrap();
    let response = read_response(&mut rejected).await;
    assert!(response.starts_with("HTTP/1.1 503"), "{response}");
    assert!(response.contains("Retry-After: 1"), "{response}");
    assert!(
        state
            .metrics
            .to_prometheus()
            .contains("blazeserve_connections_rejected_total 1\n")
    );
    assert_eq!(
        state.metrics.connections_active(),
        2,
        "rejected connection must not take a slot"
    );

    drop(first);
    let deadline = Instant::now() + BOUND;
    loop {
        let mut retry = connect(&server).await;
        retry.write_all(LIVE_REQUEST).await.unwrap();
        let response = read_response(&mut retry).await;
        if response.starts_with("HTTP/1.1 200") {
            break;
        }
        assert!(
            response.starts_with("HTTP/1.1 503") || response.is_empty(),
            "{response}"
        );
        assert!(Instant::now() < deadline, "capacity never returned");
        sleep(Duration::from_millis(20)).await;
    }

    drop(second);
    wait_until("connection gauge to drain", || {
        state.metrics.connections_active() == 0
    })
    .await;
    assert_eq!(state.metrics.requests_active(), 0);
    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn slow_header_connection_is_dropped() {
    let dir = TempDir::new().unwrap();
    let server = server::start(Config {
        header_timeout_secs: 1,
        ..config(&dir)
    })
    .await
    .unwrap();
    let state = server.state().clone();

    let mut slow = connect(&server).await;
    slow.write_all(b"GET / HTTP/1.1\r\nHost:").await.unwrap();
    let _ = read_response(&mut slow).await;

    wait_until("slow connection slot release", || {
        state.metrics.connections_active() == 0
    })
    .await;
    assert_eq!(state.metrics.requests_active(), 0);
    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn shutdown_is_prompt_with_idle_clients() {
    let dir = TempDir::new().unwrap();
    let server = server::start(Config {
        max_connections: 16,
        ..config(&dir)
    })
    .await
    .unwrap();
    let state = server.state().clone();

    let mut idle = vec![
        connect(&server).await,
        connect(&server).await,
        connect(&server).await,
    ];
    wait_until("idle connections admitted", || {
        state.metrics.connections_active() == 3
    })
    .await;

    let started = Instant::now();
    timeout(Duration::from_secs(3), server.shutdown())
        .await
        .expect("shutdown hung on idle clients");
    assert!(started.elapsed() < Duration::from_secs(3));

    for client in &mut idle {
        let closed = read_response(client).await;
        assert!(
            closed.is_empty(),
            "idle client got unexpected data: {closed}"
        );
    }
    assert_eq!(state.metrics.connections_active(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn port_zero_reports_the_bound_port_and_stops_listening() {
    let dir = TempDir::new().unwrap();
    let server = server::start(config(&dir)).await.unwrap();
    let addr = server.local_addr();
    assert_ne!(addr.port(), 0);
    server.shutdown().await;
    assert!(
        TcpStream::connect(addr).await.is_err(),
        "listener must be closed after shutdown"
    );
}
