#![cfg(feature = "otel")]

mod http_common;

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use blazeserve::config::Config;
use blazeserve::server::{self, ServerHandle};
use blazeserve::telemetry::{Settings, Telemetry};
use http_common::{get_with, populate};

const TRACE_HEX: &str = "4bf92f3577b34da6a3ce929d0e0e4736";
const SECRET_HEADER: &str = "Bearer tok-s3cr3t-value";

struct Received {
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Received {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Minimal OTLP/HTTP receiver: records every POST and answers 200 with an empty protobuf.
struct Mock {
    addr: SocketAddr,
    received: Arc<Mutex<Vec<Received>>>,
    connections: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
}

impl Mock {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let received = Arc::new(Mutex::new(Vec::new()));
        let connections = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let (r, c, s) = (received.clone(), connections.clone(), stop.clone());
        thread::spawn(move || {
            while !s.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        c.fetch_add(1, Ordering::SeqCst);
                        let _ = stream.set_nonblocking(false);
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
                        let r = r.clone();
                        thread::spawn(move || serve(stream, &r));
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            addr,
            received,
            connections,
            stop,
        }
    }

    fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }

    fn matching(&self, path: &str) -> Vec<(Vec<u8>, Option<String>, Option<String>)> {
        self.received
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.path == path)
            .map(|r| {
                (
                    r.body.clone(),
                    r.header("authorization").map(str::to_owned),
                    r.header("content-type").map(str::to_owned),
                )
            })
            .collect()
    }

    fn wait_for(&self, path: &str) -> bool {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if !self.matching(path).is_empty() {
                return true;
            }
            thread::sleep(Duration::from_millis(20));
        }
        false
    }
}

impl Drop for Mock {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn contains(hay: &[u8], needle: &str) -> bool {
    find(hay, needle.as_bytes()).is_some()
}

fn fill(stream: &mut TcpStream, buf: &mut Vec<u8>) -> bool {
    let mut tmp = [0u8; 16 * 1024];
    match stream.read(&mut tmp) {
        Ok(0) | Err(_) => false,
        Ok(n) => {
            buf.extend_from_slice(&tmp[..n]);
            true
        }
    }
}

fn read_chunked(stream: &mut TcpStream, buf: &mut Vec<u8>) -> Option<Vec<u8>> {
    let mut body = Vec::new();
    loop {
        let eol = loop {
            if let Some(p) = find(buf, b"\r\n") {
                break p;
            }
            if !fill(stream, buf) {
                return None;
            }
        };
        let size = usize::from_str_radix(std::str::from_utf8(&buf[..eol]).ok()?.trim(), 16).ok()?;
        buf.drain(..eol + 2);
        while buf.len() < size + 2 {
            if !fill(stream, buf) {
                return None;
            }
        }
        body.extend_from_slice(&buf[..size]);
        buf.drain(..size + 2);
        if size == 0 {
            return Some(body);
        }
    }
}

fn read_request(stream: &mut TcpStream) -> Option<Received> {
    let mut buf = Vec::new();
    let head_end = loop {
        if let Some(p) = find(&buf, b"\r\n\r\n") {
            break p + 4;
        }
        if !fill(stream, &mut buf) {
            return None;
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let mut lines = head.split("\r\n");
    let path = lines.next()?.split_whitespace().nth(1)?.to_owned();
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
        .collect();
    let mut rest = buf[head_end..].to_vec();
    let header = |name: &str| {
        headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.clone())
    };
    let body = if header("transfer-encoding").is_some_and(|v| v.contains("chunked")) {
        read_chunked(stream, &mut rest)?
    } else {
        let len: usize = header("content-length")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        while rest.len() < len {
            if !fill(stream, &mut rest) {
                return None;
            }
        }
        rest.truncate(len);
        rest
    };
    Some(Received {
        path,
        headers,
        body,
    })
}

fn serve(mut stream: TcpStream, received: &Mutex<Vec<Received>>) {
    while let Some(req) = read_request(&mut stream) {
        received.lock().unwrap().push(req);
        let reply =
            b"HTTP/1.1 200 OK\r\nContent-Type: application/x-protobuf\r\nContent-Length: 0\r\n\r\n";
        if stream.write_all(reply).is_err() {
            return;
        }
    }
}

fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
    let map: HashMap<String, String> = pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect();
    move |k| map.get(k).cloned()
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

struct Running {
    _dir: tempfile::TempDir,
    server: ServerHandle,
    addr: SocketAddr,
}

async fn start(settings: Option<Settings>, tweak: impl FnOnce(&mut Config)) -> Running {
    let dir = tempfile::tempdir().unwrap();
    let root: PathBuf = dir.path().canonicalize().unwrap();
    populate(&root);
    let mut config = Config {
        host: "127.0.0.1".into(),
        port: 0,
        base: root,
        otlp_endpoint: settings.as_ref().map(|_| String::new()),
        ..Config::default()
    };
    tweak(&mut config);
    let telemetry = match settings {
        Some(s) => Telemetry::init_with(&config, s).expect("telemetry builds"),
        None => Telemetry::disabled(),
    };
    let server = server::start_with(config, telemetry)
        .await
        .expect("server starts");
    let addr = server.local_addr();
    Running {
        _dir: dir,
        server,
        addr,
    }
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    tokio::task::spawn_blocking(f).await.unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exports_spans_and_metrics_and_continues_the_incoming_trace() {
    let mock = Mock::start();
    let headers_env = format!("authorization={SECRET_HEADER}");
    let settings = Settings::resolve(
        &mock.url(),
        &env(&[
            ("OTEL_EXPORTER_OTLP_HEADERS", &headers_env),
            ("OTEL_SERVICE_NAME", "blaze-under-test"),
        ]),
    )
    .unwrap()
    .unwrap();
    let running = start(Some(settings), |_| {}).await;
    assert!(running.server.state().telemetry.is_enabled());

    let addr = running.addr;
    let traceparent = format!("00-{TRACE_HEX}-00f067aa0ba902b7-01");
    let (ok, missing) = blocking(move || {
        let ok = get_with(
            addr,
            "/hello.txt?token=supersecretquery",
            &[
                ("traceparent", traceparent.as_str()),
                ("User-Agent", "otel-test/1.0"),
                ("X-Request-ID", "req-otel-1"),
            ],
        );
        let missing = get_with(addr, "/missing.txt", &[]);
        (ok, missing)
    })
    .await;
    assert_eq!(ok.status, 200);
    assert_eq!(missing.status, 404);

    running.server.shutdown().await;
    assert!(
        mock.wait_for("/v1/traces"),
        "no span export reached the collector"
    );
    assert!(
        mock.wait_for("/v1/metrics"),
        "no metric export reached the collector"
    );

    let traces = mock.matching("/v1/traces");
    let metrics = mock.matching("/v1/metrics");
    let span_payload: Vec<u8> = traces.iter().flat_map(|(b, _, _)| b.clone()).collect();
    let metric_payload: Vec<u8> = metrics.iter().flat_map(|(b, _, _)| b.clone()).collect();
    assert!(!span_payload.is_empty() && !metric_payload.is_empty());

    assert!(
        find(&span_payload, &hex_to_bytes(TRACE_HEX)).is_some(),
        "the incoming trace id must appear in the exported span"
    );
    for needle in [
        "GET",
        "http.request.method",
        "http.response.status_code",
        "blaze.request_id",
        "req-otel-1",
        "otel-test/1.0",
        "blaze-under-test",
    ] {
        assert!(
            contains(&span_payload, needle),
            "span payload lacks {needle}"
        );
    }

    for needle in [
        "http.server.request.duration",
        "http.server.active_requests",
        "http.server.response.body.size",
        "blaze.status_class",
        "2xx",
        "4xx",
        "blaze-under-test",
    ] {
        assert!(
            contains(&metric_payload, needle),
            "metric payload lacks {needle}"
        );
    }

    for (name, payload) in [("traces", &span_payload), ("metrics", &metric_payload)] {
        assert!(
            !contains(payload, "supersecretquery"),
            "{name} leaked the query string"
        );
        assert!(
            !contains(payload, "tok-s3cr3t-value"),
            "{name} leaked a header value"
        );
    }
    assert!(
        !contains(&metric_payload, "hello.txt") && !contains(&metric_payload, "127.0.0.1"),
        "metric labels must not carry paths or client addresses"
    );

    for (_, auth, content_type) in traces.iter().chain(metrics.iter()) {
        assert_eq!(auth.as_deref(), Some(SECRET_HEADER));
        assert_eq!(content_type.as_deref(), Some("application/x-protobuf"));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_an_endpoint_nothing_is_started_or_sent() {
    let mock = Mock::start();
    let config = Config::default();
    assert!(!Telemetry::init(&config).unwrap().is_enabled());

    let running = start(None, |_| {}).await;
    assert!(!running.server.state().telemetry.is_enabled());
    let addr = running.addr;
    let status = blocking(move || get_with(addr, "/hello.txt", &[]).status).await;
    assert_eq!(status, 200);
    running.server.shutdown().await;

    thread::sleep(Duration::from_millis(200));
    assert_eq!(mock.connections(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unreachable_collector_never_slows_requests() {
    let dead = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap()
    };
    let settings = Settings::resolve(&format!("http://{dead}"), &env(&[]))
        .unwrap()
        .unwrap();
    let running = start(Some(settings), |_| {}).await;
    let addr = running.addr;

    let started = Instant::now();
    let statuses = blocking(move || {
        (0..40)
            .map(|_| get_with(addr, "/hello.txt", &[]).status)
            .collect::<Vec<_>>()
    })
    .await;
    assert!(statuses.iter().all(|s| *s == 200));
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "requests were slowed by export"
    );

    let stopping = Instant::now();
    running.server.shutdown().await;
    assert!(
        stopping.elapsed() < Duration::from_secs(8),
        "shutdown hung on a dead collector"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stalled_collector_cannot_hang_shutdown() {
    let stalled = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", stalled.local_addr().unwrap());
    let held = Arc::new(Mutex::new(Vec::new()));
    let sink = held.clone();
    stalled.set_nonblocking(true).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_flag = stop.clone();
    let acceptor = thread::spawn(move || {
        while !stop_flag.load(Ordering::SeqCst) {
            if let Ok((s, _)) = stalled.accept() {
                sink.lock().unwrap().push(s);
            }
            thread::sleep(Duration::from_millis(5));
        }
    });

    let settings = Settings::resolve(&url, &env(&[])).unwrap().unwrap();
    let running = start(Some(settings), |_| {}).await;
    let addr = running.addr;
    let status = blocking(move || get_with(addr, "/hello.txt", &[]).status).await;
    assert_eq!(status, 200);

    let stopping = Instant::now();
    running.server.shutdown().await;
    assert!(
        stopping.elapsed() < Duration::from_secs(8),
        "shutdown waited on a stalled collector"
    );

    stop.store(true, Ordering::SeqCst);
    acceptor.join().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejected_connections_are_exported() {
    let mock = Mock::start();
    let settings = Settings::resolve(&mock.url(), &env(&[])).unwrap().unwrap();
    let running = start(Some(settings), |c| c.max_connections = 1).await;
    let addr = running.addr;

    let holder = TcpStream::connect(addr).unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    while running.server.state().metrics.connections_active() < 1 {
        assert!(
            Instant::now() < deadline,
            "first connection was never admitted"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let reply = blocking(move || {
        let mut second = TcpStream::connect(addr).unwrap();
        second
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut out = Vec::new();
        let _ = second.read_to_end(&mut out);
        String::from_utf8_lossy(&out).into_owned()
    })
    .await;
    assert!(reply.starts_with("HTTP/1.1 503"), "got {reply:?}");
    drop(holder);

    running.server.shutdown().await;
    assert!(mock.wait_for("/v1/metrics"));
    let payload: Vec<u8> = mock
        .matching("/v1/metrics")
        .into_iter()
        .flat_map(|(b, _, _)| b)
        .collect();
    assert!(contains(&payload, "blazeserve.connections.rejected"));
}

#[tokio::test]
async fn invalid_telemetry_settings_fail_before_binding() {
    for (endpoint, expect) in [
        ("not a url", "--otlp-endpoint"),
        ("ftp://collector:1", "--otlp-endpoint"),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let config = Config {
            host: "127.0.0.1".into(),
            port: 0,
            base: dir.path().canonicalize().unwrap(),
            otlp_endpoint: Some(endpoint.into()),
            ..Config::default()
        };
        let err = match server::start(config).await {
            Ok(_) => panic!("{endpoint:?} must be rejected"),
            Err(e) => e.to_string(),
        };
        assert!(err.contains(expect), "{err}");
        assert!(!err.contains("collector:1"), "{err}");
    }
}

#[test]
fn grpc_protocol_is_rejected_with_the_variable_name() {
    let err = Settings::resolve(
        "http://collector:4318",
        &env(&[("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc")]),
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("OTEL_EXPORTER_OTLP_PROTOCOL"), "{err}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn telemetry_debug_output_never_contains_credentials() {
    let mock = Mock::start();
    let settings = Settings::resolve(
        &mock.url(),
        &env(&[(
            "OTEL_EXPORTER_OTLP_HEADERS",
            "authorization=Bearer tok-s3cr3t-value",
        )]),
    )
    .unwrap()
    .unwrap();
    assert!(!format!("{settings:?}").contains("tok-s3cr3t-value"));
    let running = start(Some(settings), |_| {}).await;
    let debug = format!("{:?}", running.server.state());
    assert!(!debug.contains("tok-s3cr3t-value"), "{debug}");
    running.server.shutdown().await;
}
