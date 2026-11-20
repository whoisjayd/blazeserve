mod cli_support;

use blazeserve::config::Config;
use cli_support::{blaze, canonical, code, pattern, stderr};
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::process::Output;
use std::time::{Duration, Instant};

const MIB: u64 = 1024 * 1024;

fn byte_at(i: u64) -> u8 {
    (i % 251) as u8
}

enum Mode {
    /// Sends headers and `after` bytes, then goes silent.
    StallAfter { total: u64, after: u64 },
    /// Sends the body one byte at a time, `gap` apart.
    Trickle { total: u64, gap: Duration },
    /// Always answers `503`.
    Unavailable,
    /// Answers the offset probe with `404`, then reads the request head of the upload and
    /// never reads the body or answers.
    DeafToUploads,
    /// Answers the offset probe with `404` and every upload with `503`.
    UploadUnavailable,
}

/// A scripted origin on a loopback port picked by the OS.
struct Stub {
    addr: SocketAddr,
}

impl Stub {
    fn start(mode: Mode) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mode = std::sync::Arc::new(mode);
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(conn) = conn else { continue };
                let mode = mode.clone();
                std::thread::spawn(move || {
                    let _ = serve(conn, &mode);
                });
            }
        });
        Self { addr }
    }

    fn url(&self, name: &str) -> String {
        format!("http://{}/{name}", self.addr)
    }
}

type Head = (String, Option<(u64, u64)>);

fn read_head(conn: &TcpStream) -> std::io::Result<Option<Head>> {
    let mut reader = BufReader::new(conn);
    let mut line = String::new();
    if reader.read_line(&mut line)? == 0 {
        return Ok(None);
    }
    let method = line.split(' ').next().unwrap_or("").to_owned();
    let mut range = None;
    loop {
        line.clear();
        reader.read_line(&mut line)?;
        let lower = line.to_ascii_lowercase();
        if let Some(spec) = lower.trim().strip_prefix("range: bytes=")
            && let Some((a, b)) = spec.split_once('-')
        {
            range = Some((a.parse().unwrap_or(0), b.parse().unwrap_or(u64::MAX)));
        }
        if line == "\r\n" || line.is_empty() {
            break;
        }
    }
    Ok(Some((method, range)))
}

fn serve(mut conn: TcpStream, mode: &Mode) -> std::io::Result<()> {
    conn.set_nodelay(true)?;
    let Some((method, range)) = read_head(&conn)? else {
        return Ok(());
    };
    let hold = Duration::from_secs(60);
    match mode {
        Mode::Unavailable => {
            write!(
                conn,
                "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )?;
        }
        Mode::DeafToUploads | Mode::UploadUnavailable => {
            if method == "HEAD" {
                write!(
                    conn,
                    "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )?;
            } else if matches!(mode, Mode::DeafToUploads) {
                std::thread::sleep(hold);
            } else {
                write!(
                    conn,
                    "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )?;
            }
        }
        Mode::StallAfter { total, .. } | Mode::Trickle { total, .. } => {
            let (start, end) = range.map_or((0, total - 1), |(a, b)| (a, b.min(total - 1)));
            let status = if range.is_some() {
                "206 Partial Content"
            } else {
                "200 OK"
            };
            let content_range = if range.is_some() {
                format!("Content-Range: bytes {start}-{end}/{total}\r\n")
            } else {
                String::new()
            };
            let len = if method == "HEAD" {
                *total
            } else {
                end - start + 1
            };
            write!(
                conn,
                "HTTP/1.1 {status}\r\nContent-Length: {len}\r\n{content_range}Accept-Ranges: bytes\r\nETag: \"v1\"\r\nConnection: close\r\n\r\n"
            )?;
            if method == "HEAD" {
                return Ok(());
            }
            match mode {
                Mode::StallAfter { after, .. } => {
                    let body: Vec<u8> = (start..start + *after).map(byte_at).collect();
                    conn.write_all(&body)?;
                    std::thread::sleep(hold);
                }
                Mode::Trickle { gap, .. } => {
                    for i in start..=end {
                        conn.write_all(&[byte_at(i)])?;
                        std::thread::sleep(*gap);
                    }
                }
                _ => {}
            }
        }
    }
    Ok(())
}

fn timed(args: &[&str], cwd: Option<&Path>) -> (Output, Duration) {
    let mut cmd = blaze();
    cmd.args(args);
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    let start = Instant::now();
    let out = cmd.output().expect("spawn blaze");
    (out, start.elapsed())
}

fn s(p: &Path) -> String {
    p.to_str().unwrap().to_owned()
}

#[test]
fn get_stalled_after_headers_is_bounded_by_the_idle_timeout() {
    let origin = Stub::start(Mode::StallAfter {
        total: 1000,
        after: 100,
    });
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("a.bin");
    let (out, took) = timed(
        &[
            "get",
            &origin.url("a.bin"),
            "-c",
            "1",
            "--retries",
            "0",
            "--idle-timeout",
            "1s",
            "-o",
            &s(&dest),
        ],
        None,
    );

    assert_eq!(code(&out), 1, "{}", stderr(&out));
    assert!(stderr(&out).contains("--idle-timeout"), "{}", stderr(&out));
    assert!(took < Duration::from_secs(15), "{took:?}");
    assert!(!dest.exists());
    let part = std::fs::read(dir.path().join("a.bin.part")).unwrap();
    assert_eq!(part, (0..100).map(byte_at).collect::<Vec<_>>());
    assert!(dir.path().join("a.bin.part.meta").exists());
}

#[test]
fn get_that_keeps_moving_is_not_an_idle_failure() {
    let origin = Stub::start(Mode::Trickle {
        total: 10,
        gap: Duration::from_millis(300),
    });
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("slow.bin");
    let (out, took) = timed(
        &[
            "get",
            &origin.url("slow.bin"),
            "-c",
            "1",
            "--retries",
            "0",
            "--idle-timeout",
            "1s",
            "-o",
            &s(&dest),
        ],
        None,
    );

    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(took > Duration::from_secs(2), "{took:?}");
    assert_eq!(
        std::fs::read(&dest).unwrap(),
        (0..10).map(byte_at).collect::<Vec<_>>()
    );
}

#[test]
fn get_stops_when_max_time_runs_out_and_keeps_the_partial_file() {
    let origin = Stub::start(Mode::Trickle {
        total: 1000,
        gap: Duration::from_millis(100),
    });
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("long.bin");
    let (out, took) = timed(
        &[
            "get",
            &origin.url("long.bin"),
            "-c",
            "1",
            "--max-time",
            "2s",
            "-o",
            &s(&dest),
        ],
        None,
    );

    assert_eq!(code(&out), 1, "{}", stderr(&out));
    assert!(stderr(&out).contains("--max-time"), "{}", stderr(&out));
    assert!(took < Duration::from_secs(10), "{took:?}");
    assert!(!dest.exists());
    assert!(dir.path().join("long.bin.part").exists());
    assert!(dir.path().join("long.bin.part.meta").exists());
}

#[test]
fn retries_cannot_stretch_max_time() {
    let origin = Stub::start(Mode::Unavailable);
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("x.bin");
    // Five retries would wait 15 seconds in total without the budget.
    let (out, took) = timed(
        &[
            "get",
            &origin.url("x.bin"),
            "-c",
            "1",
            "--max-time",
            "2s",
            "-o",
            &s(&dest),
        ],
        None,
    );

    assert_eq!(code(&out), 1, "{}", stderr(&out));
    assert!(stderr(&out).contains("--max-time"), "{}", stderr(&out));
    assert!(took < Duration::from_secs(8), "{took:?}");
}

#[test]
fn segment_workers_stop_together_when_max_time_runs_out() {
    let total = 3 * 8 * MIB;
    let origin = Stub::start(Mode::Trickle {
        total,
        gap: Duration::from_millis(20),
    });
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("seg.bin");
    let (out, took) = timed(
        &[
            "get",
            &origin.url("seg.bin"),
            "-c",
            "3",
            "--max-time",
            "2s",
            "-o",
            &s(&dest),
        ],
        None,
    );

    assert_eq!(code(&out), 1, "{}", stderr(&out));
    assert!(stderr(&out).contains("--max-time"), "{}", stderr(&out));
    assert!(took < Duration::from_secs(10), "{took:?}");
    assert!(!dest.exists());
    assert!(dir.path().join("seg.bin.part.meta").exists());
}

#[test]
fn put_stalled_while_sending_is_bounded_by_the_idle_timeout() {
    let origin = Stub::start(Mode::DeafToUploads);
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("big.bin");
    // Larger than any socket buffer, so the writes block once the peer stops reading.
    std::fs::write(&file, vec![7u8; 48 * MIB as usize]).unwrap();
    let (out, took) = timed(
        &[
            "put",
            &s(&file),
            &format!("http://{}/", origin.addr),
            "--chunk-mb",
            "48",
            "--retries",
            "0",
            "--idle-timeout",
            "1s",
        ],
        None,
    );

    assert_eq!(code(&out), 1, "{}", stderr(&out));
    assert!(stderr(&out).contains("--idle-timeout"), "{}", stderr(&out));
    assert!(took < Duration::from_secs(15), "{took:?}");
}

#[test]
fn put_retries_cannot_stretch_max_time() {
    let origin = Stub::start(Mode::UploadUnavailable);
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("small.bin");
    std::fs::write(&file, pattern(1000)).unwrap();
    let (out, took) = timed(
        &[
            "put",
            &s(&file),
            &format!("http://{}/", origin.addr),
            "--max-time",
            "2s",
        ],
        None,
    );

    assert_eq!(code(&out), 1, "{}", stderr(&out));
    assert!(stderr(&out).contains("--max-time"), "{}", stderr(&out));
    assert!(took < Duration::from_secs(8), "{took:?}");
}

#[test]
fn durations_must_be_unambiguous() {
    for bad in ["30", "0s", "abc", "1.5s", "-1s", ""] {
        for opt in ["--connect-timeout", "--idle-timeout", "--max-time"] {
            let out = blaze()
                .args(["get", "http://127.0.0.1:9/x", opt, bad])
                .output()
                .unwrap();
            assert_eq!(code(&out), 2, "{opt} {bad:?}: {}", stderr(&out));
        }
    }
    let out = blaze()
        .args([
            "put",
            "Cargo.toml",
            "http://127.0.0.1:9/",
            "--max-time",
            "5",
        ])
        .output()
        .unwrap();
    assert_eq!(code(&out), 2, "{}", stderr(&out));
}

#[test]
fn off_disables_a_limit_and_help_says_so() {
    let out = blaze().args(["get", "--help"]).output().unwrap();
    let help = String::from_utf8_lossy(&out.stdout).into_owned();
    for opt in ["--connect-timeout", "--idle-timeout", "--max-time"] {
        assert!(help.contains(opt), "{help}");
    }
    assert!(help.contains("off"), "{help}");

    let origin = Stub::start(Mode::Trickle {
        total: 3,
        gap: Duration::from_millis(1),
    });
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("t.bin");
    let (out, _) = timed(
        &[
            "get",
            &origin.url("t.bin"),
            "-c",
            "1",
            "--connect-timeout",
            "off",
            "--idle-timeout",
            "off",
            "--max-time",
            "off",
            "-o",
            &s(&dest),
        ],
        None,
    );
    assert_eq!(code(&out), 0, "{}", stderr(&out));
}

async fn serve_dir(dir: &Path, upload_mb: u64) -> blazeserve::server::ServerHandle {
    let config = Config {
        host: "127.0.0.1".into(),
        port: 0,
        base: canonical(dir),
        max_upload_bytes: upload_mb * MIB,
        ..Config::default()
    };
    blazeserve::server::start(config)
        .await
        .expect("start server")
}

async fn run(args: Vec<String>) -> (Output, Duration) {
    tokio::task::spawn_blocking(move || {
        let start = Instant::now();
        let out = blaze().args(args).output().expect("spawn blaze");
        (out, start.elapsed())
    })
    .await
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rate_limited_get_is_not_an_idle_failure() {
    let served = tempfile::tempdir().unwrap();
    let data = pattern(3 * 1024);
    std::fs::write(served.path().join("r.bin"), &data).unwrap();
    let server = serve_dir(served.path(), 0).await;
    let out_dir = tempfile::tempdir().unwrap();
    let dest = out_dir.path().join("r.bin");

    let (out, took) = run(vec![
        "get".into(),
        format!("http://{}/r.bin", server.local_addr()),
        "-c".into(),
        "1".into(),
        "--limit-rate".into(),
        "1K".into(),
        "--idle-timeout".into(),
        "1s".into(),
        "-o".into(),
        s(&dest),
    ])
    .await;

    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(took > Duration::from_secs(2), "{took:?}");
    assert_eq!(std::fs::read(&dest).unwrap(), data);
    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rate_limit_waits_count_against_max_time() {
    let served = tempfile::tempdir().unwrap();
    std::fs::write(served.path().join("r.bin"), pattern(60 * 1024)).unwrap();
    let server = serve_dir(served.path(), 0).await;
    let out_dir = tempfile::tempdir().unwrap();
    let dest = out_dir.path().join("r.bin");

    let (out, took) = run(vec![
        "get".into(),
        format!("http://{}/r.bin", server.local_addr()),
        "-c".into(),
        "1".into(),
        "--limit-rate".into(),
        "1K".into(),
        "--max-time".into(),
        "2s".into(),
        "-o".into(),
        s(&dest),
    ])
    .await;

    assert_eq!(code(&out), 1, "{}", stderr(&out));
    assert!(stderr(&out).contains("--max-time"), "{}", stderr(&out));
    assert!(took < Duration::from_secs(10), "{took:?}");
    assert!(!dest.exists());
    assert!(out_dir.path().join("r.bin.part").exists());
    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rate_limited_put_is_not_an_idle_failure() {
    let served = tempfile::tempdir().unwrap();
    let server = serve_dir(served.path(), 1).await;
    let src = tempfile::tempdir().unwrap();
    let file = src.path().join("up.bin");
    let data = pattern(3 * 1024);
    std::fs::write(&file, &data).unwrap();

    let (out, took) = run(vec![
        "put".into(),
        s(&file),
        format!("http://{}/", server.local_addr()),
        "--limit-rate".into(),
        "1K".into(),
        "--idle-timeout".into(),
        "1s".into(),
    ])
    .await;

    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(took > Duration::from_secs(2), "{took:?}");
    assert_eq!(std::fs::read(served.path().join("up.bin")).unwrap(), data);
    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn put_stops_when_max_time_runs_out_without_publishing() {
    let served = tempfile::tempdir().unwrap();
    let server = serve_dir(served.path(), 1).await;
    let src = tempfile::tempdir().unwrap();
    let file = src.path().join("up.bin");
    std::fs::write(&file, pattern(60 * 1024)).unwrap();

    let (out, took) = run(vec![
        "put".into(),
        s(&file),
        format!("http://{}/", server.local_addr()),
        "--limit-rate".into(),
        "1K".into(),
        "--max-time".into(),
        "2s".into(),
    ])
    .await;

    assert_eq!(code(&out), 1, "{}", stderr(&out));
    assert!(stderr(&out).contains("--max-time"), "{}", stderr(&out));
    assert!(took < Duration::from_secs(10), "{took:?}");
    assert!(!served.path().join("up.bin").exists());
    server.shutdown().await;
}
