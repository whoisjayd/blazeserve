mod cli_support;

use cli_support::{blaze, code, stderr};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::process::Output;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const MIB: u64 = 1024 * 1024;

struct Req {
    method: String,
    /// Position among all requests the stub has received, from zero.
    index: usize,
}

enum Reply {
    /// A refusal; `retry_after` is sent verbatim when present.
    Refuse {
        status: u16,
        retry_after: Option<String>,
    },
    /// The normal answer, held back for `delay` first.
    Serve { delay: Duration },
}

/// A tiny origin whose answers a test scripts per request, so retry timing can be observed
/// from the arrival times it records.
struct Stub {
    addr: SocketAddr,
    arrivals: Arc<Mutex<Vec<(Instant, String)>>>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

fn byte_at(i: u64) -> u8 {
    (i % 251) as u8
}

fn body(start: u64, end: u64) -> Vec<u8> {
    (start..=end).map(byte_at).collect()
}

impl Stub {
    fn start(total: u64, script: impl Fn(&Req) -> Reply + Send + Sync + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let arrivals = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let script = Arc::new(script);
        let counter = Arc::new(AtomicUsize::new(0));
        let thread = {
            let (arrivals, stop) = (arrivals.clone(), stop.clone());
            std::thread::spawn(move || {
                for conn in listener.incoming() {
                    if stop.load(Ordering::SeqCst) {
                        return;
                    }
                    let Ok(conn) = conn else { continue };
                    let (arrivals, script, counter) =
                        (arrivals.clone(), script.clone(), counter.clone());
                    std::thread::spawn(move || {
                        let _ = serve_one(conn, total, &arrivals, &*script, &counter);
                    });
                }
            })
        };
        Self {
            addr,
            arrivals,
            stop,
            thread: Some(thread),
        }
    }

    fn url(&self, name: &str) -> String {
        format!("http://{}/{name}", self.addr)
    }

    fn arrivals(&self, method: &str) -> Vec<Instant> {
        self.arrivals
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, m)| m == method)
            .map(|(t, _)| *t)
            .collect()
    }
}

impl Drop for Stub {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.addr);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

fn serve_one(
    conn: TcpStream,
    total: u64,
    arrivals: &Mutex<Vec<(Instant, String)>>,
    script: &(dyn Fn(&Req) -> Reply + Send + Sync),
    counter: &AtomicUsize,
) -> std::io::Result<()> {
    let mut reader = BufReader::new(conn.try_clone()?);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let method = line.split(' ').next().unwrap_or("").to_owned();
    let (mut range, mut length) = (None, 0usize);
    loop {
        line.clear();
        reader.read_line(&mut line)?;
        let lower = line.trim().to_ascii_lowercase();
        if lower.is_empty() {
            break;
        }
        if let Some(v) = lower.strip_prefix("range: bytes=") {
            let (a, b) = v.split_once('-').unwrap_or(("0", ""));
            let start: u64 = a.parse().unwrap_or(0);
            range = Some((start, b.parse().unwrap_or(total - 1)));
        } else if let Some(v) = lower.strip_prefix("content-length:") {
            length = v.trim().parse().unwrap_or(0);
        }
    }
    let mut sink = vec![0u8; length];
    reader.read_exact(&mut sink)?;
    arrivals
        .lock()
        .unwrap()
        .push((Instant::now(), method.clone()));
    let index = counter.fetch_add(1, Ordering::SeqCst);
    let mut out = conn;
    let req = Req {
        method: method.clone(),
        index,
    };
    match script(&req) {
        Reply::Refuse {
            status,
            retry_after,
        } => {
            let extra = retry_after
                .map(|v| format!("Retry-After: {v}\r\n"))
                .unwrap_or_default();
            write!(
                out,
                "HTTP/1.1 {status} Refused\r\n{extra}Connection: close\r\nContent-Length: 0\r\n\r\n"
            )?;
        }
        Reply::Serve { delay } => {
            std::thread::sleep(delay);
            match (method.as_str(), range) {
                ("PUT", _) => write!(
                    out,
                    "HTTP/1.1 201 Created\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
                )?,
                ("HEAD", _) => write!(
                    out,
                    "HTTP/1.1 200 OK\r\nETag: \"stub\"\r\nAccept-Ranges: bytes\r\nConnection: close\r\nContent-Length: {total}\r\n\r\n"
                )?,
                (_, Some((s, e))) => {
                    write!(
                        out,
                        "HTTP/1.1 206 Partial Content\r\nETag: \"stub\"\r\nContent-Range: bytes {s}-{e}/{total}\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
                        e - s + 1
                    )?;
                    out.write_all(&body(s, e))?;
                }
                _ => {
                    write!(
                        out,
                        "HTTP/1.1 200 OK\r\nETag: \"stub\"\r\nConnection: close\r\nContent-Length: {total}\r\n\r\n"
                    )?;
                    out.write_all(&body(0, total - 1))?;
                }
            }
        }
    }
    out.flush()
}

fn refuse_first(
    n: usize,
    status: u16,
    retry_after: impl Fn() -> Option<String> + Send + Sync + 'static,
) -> impl Fn(&Req) -> Reply {
    move |req| {
        if req.index < n {
            Reply::Refuse {
                status,
                retry_after: retry_after(),
            }
        } else {
            Reply::Serve {
                delay: Duration::ZERO,
            }
        }
    }
}

async fn run(args: Vec<String>) -> Output {
    tokio::task::spawn_blocking(move || blaze().args(args).output().expect("spawn blaze"))
        .await
        .unwrap()
}

fn s(p: &Path) -> String {
    p.to_str().unwrap().to_owned()
}

fn http_date_in(secs: u64) -> String {
    httpdate::fmt_http_date(std::time::SystemTime::now() + Duration::from_secs(secs))
}

async fn get_once(stub: &Stub, extra: &[&str]) -> (Output, Vec<u8>) {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("f.bin");
    let mut args = vec![
        "get".into(),
        stub.url("f.bin"),
        "-o".into(),
        s(&dest),
        "-c".into(),
        "1".into(),
    ];
    args.extend(extra.iter().map(|a| (*a).to_owned()));
    let out = run(args).await;
    (out, std::fs::read(&dest).unwrap_or_default())
}

fn gap(times: &[Instant]) -> Duration {
    times[1].duration_since(times[0])
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn get_waits_for_an_integer_retry_after() {
    let stub = Stub::start(1000, refuse_first(1, 503, || Some("1".into())));
    let (out, data) = get_once(&stub, &[]).await;
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert_eq!(data, body(0, 999));
    assert!(stderr(&out).contains("Retry-After 1s"), "{}", stderr(&out));
    // The local backoff alone would be half a second.
    assert!(gap(&stub.arrivals("GET")) >= Duration::from_millis(990));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn get_waits_for_an_http_date_retry_after_on_429() {
    let stub = Stub::start(1000, refuse_first(1, 429, || Some(http_date_in(3))));
    let (out, data) = get_once(&stub, &[]).await;
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert_eq!(data, body(0, 999));
    // The date has whole-second resolution, so between two and three seconds remain.
    assert!(gap(&stub.arrivals("GET")) >= Duration::from_millis(1900));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn get_ignores_retry_after_that_is_malformed_or_in_the_past() {
    for hint in ["soon", "-5", "Sun, 06 Nov 1994 08:49:37 GMT"] {
        let stub = Stub::start(1000, refuse_first(1, 503, move || Some(hint.into())));
        let (out, data) = get_once(&stub, &[]).await;
        assert_eq!(code(&out), 0, "{hint}: {}", stderr(&out));
        assert_eq!(data, body(0, 999));
        assert!(!stderr(&out).contains("Retry-After"), "{hint}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn get_ignores_retry_after_on_other_statuses() {
    let stub = Stub::start(1000, refuse_first(1, 500, || Some("120".into())));
    let (out, _) = get_once(&stub, &[]).await;
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(!stderr(&out).contains("Retry-After"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn get_fails_clearly_when_the_server_asks_for_too_long_a_wait() {
    for hint in ["100000", "99999999999999999999999999"] {
        let stub = Stub::start(1000, refuse_first(1, 503, move || Some(hint.into())));
        let started = Instant::now();
        let (out, _) = get_once(&stub, &[]).await;
        assert_eq!(code(&out), 1, "{hint}");
        assert!(stderr(&out).contains("longer than"), "{}", stderr(&out));
        assert!(started.elapsed() < Duration::from_secs(10));
        assert_eq!(stub.arrivals("GET").len(), 1);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn get_with_no_retries_does_not_wait_for_retry_after() {
    let stub = Stub::start(1000, refuse_first(1, 503, || Some("1".into())));
    let (out, _) = get_once(&stub, &["--retries", "0"]).await;
    assert_eq!(code(&out), 1);
    assert!(stderr(&out).contains("after 0 retries"), "{}", stderr(&out));
    assert_eq!(stub.arrivals("GET").len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn segmented_workers_share_one_cooldown() {
    let total = 40 * MIB;
    // The first request is refused at once. The others are held for a moment, so the
    // workers that finish them reach for new segments while the cooldown is running.
    let stub = Stub::start(total, |req| {
        if req.method == "HEAD" {
            Reply::Serve {
                delay: Duration::ZERO,
            }
        } else if req.index == 1 {
            Reply::Refuse {
                status: 503,
                retry_after: Some("1".into()),
            }
        } else {
            Reply::Serve {
                delay: Duration::from_millis(300),
            }
        }
    });
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("big.bin");
    let out = run(vec![
        "get".into(),
        stub.url("big.bin"),
        "-o".into(),
        s(&dest),
        "-c".into(),
        "4".into(),
    ])
    .await;
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert_eq!(std::fs::metadata(&dest).unwrap().len(), total);
    assert_eq!(std::fs::read(&dest).unwrap(), body(0, total - 1));

    let gets = stub.arrivals("GET");
    let refused = gets[0];
    // Four workers start together and 40 MiB is five segments: one request is refused, up
    // to three more were already in flight, and nothing else may start inside the cooldown.
    let late: Vec<_> = gets
        .iter()
        .filter(|t| t.duration_since(refused) > Duration::from_millis(100))
        .collect();
    assert!(!late.is_empty());
    for t in late {
        assert!(
            t.duration_since(refused) >= Duration::from_millis(950),
            "a request began {:?} after the refusal",
            t.duration_since(refused)
        );
    }
}

fn source(dir: &Path) -> std::path::PathBuf {
    let src = dir.join("up.bin");
    std::fs::write(&src, body(0, 9)).unwrap();
    src
}

async fn put_to(stub: &Stub, src: &Path, extra: &[&str]) -> Output {
    let mut args = vec!["put".into(), s(src), stub.url("__upload__/up.bin")];
    args.extend(extra.iter().map(|a| (*a).to_owned()));
    run(args).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn put_waits_for_retry_after_on_a_chunk_and_on_the_offset_probe() {
    let dir = tempfile::tempdir().unwrap();
    let src = source(dir.path());

    // Request 0 is the opening HEAD probe, request 1 the chunk. Refuse the probe first.
    let probe = Stub::start(10, |req| match (req.index, req.method.as_str()) {
        (0, "HEAD") => Reply::Refuse {
            status: 503,
            retry_after: Some("1".into()),
        },
        (_, "HEAD") => Reply::Refuse {
            status: 404,
            retry_after: None,
        },
        _ => Reply::Serve {
            delay: Duration::ZERO,
        },
    });
    let out = put_to(&probe, &src, &[]).await;
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(gap(&probe.arrivals("HEAD")) >= Duration::from_millis(990));

    let chunk = Stub::start(10, |req| match req.method.as_str() {
        "HEAD" => Reply::Refuse {
            status: 404,
            retry_after: None,
        },
        _ if req.index == 1 => Reply::Refuse {
            status: 429,
            retry_after: Some(http_date_in(3)),
        },
        _ => Reply::Serve {
            delay: Duration::ZERO,
        },
    });
    let out = put_to(&chunk, &src, &[]).await;
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(gap(&chunk.arrivals("PUT")) >= Duration::from_millis(1900));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn put_fails_clearly_on_an_excessive_retry_after() {
    let dir = tempfile::tempdir().unwrap();
    let src = source(dir.path());
    let stub = Stub::start(10, |req| match req.method.as_str() {
        "HEAD" => Reply::Refuse {
            status: 404,
            retry_after: None,
        },
        _ => Reply::Refuse {
            status: 503,
            retry_after: Some("100000".into()),
        },
    });
    let out = put_to(&stub, &src, &[]).await;
    assert_eq!(code(&out), 1);
    assert!(stderr(&out).contains("longer than"), "{}", stderr(&out));
    assert_eq!(stub.arrivals("PUT").len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn put_with_no_retries_fails_without_waiting() {
    let dir = tempfile::tempdir().unwrap();
    let src = source(dir.path());
    let stub = Stub::start(10, |req| match req.method.as_str() {
        "HEAD" => Reply::Refuse {
            status: 404,
            retry_after: None,
        },
        _ => Reply::Refuse {
            status: 503,
            retry_after: Some("1".into()),
        },
    });
    let out = put_to(&stub, &src, &["--retries", "0"]).await;
    assert_eq!(code(&out), 1);
    assert_eq!(stub.arrivals("PUT").len(), 1);
}
