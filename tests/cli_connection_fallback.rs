mod cli_support;

use cli_support::{blaze, code, stderr};
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

const MIB: u64 = 1024 * 1024;

fn byte_at(i: u64) -> u8 {
    (i % 251) as u8
}

/// An origin that answers a ranged request only while no other one is in flight, and
/// refuses the rest with `503`, the way a server with a per-client connection cap does.
struct OneAtATime {
    addr: std::net::SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl OneAtATime {
    fn start(total: u64) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let active = Arc::new(AtomicUsize::new(0));
        let thread = {
            let stop = stop.clone();
            std::thread::spawn(move || {
                for conn in listener.incoming() {
                    if stop.load(Ordering::SeqCst) {
                        return;
                    }
                    let Ok(conn) = conn else { continue };
                    let active = active.clone();
                    std::thread::spawn(move || {
                        let _ = handle(conn, total, &active);
                    });
                }
            })
        };
        Self {
            addr,
            stop,
            thread: Some(thread),
        }
    }
}

impl Drop for OneAtATime {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.addr);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

fn handle(conn: TcpStream, total: u64, active: &AtomicUsize) -> std::io::Result<()> {
    let mut reader = BufReader::new(conn.try_clone()?);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    let mut range = None;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        if line.trim().is_empty() {
            break;
        }
        if let Some(v) = line.to_ascii_lowercase().strip_prefix("range: bytes=") {
            let (a, b) = v.trim().split_once('-').unwrap();
            range = Some((a.parse::<u64>().unwrap(), b.parse::<u64>().unwrap()));
        }
    }
    let mut out = conn;
    if request_line.starts_with("HEAD") {
        write!(
            out,
            "HTTP/1.1 200 OK\r\nContent-Length: {total}\r\nAccept-Ranges: bytes\r\nETag: \"v1\"\r\nConnection: close\r\n\r\n"
        )?;
        return Ok(());
    }
    let Some((start, end)) = range else {
        write!(
            out,
            "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )?;
        return Ok(());
    };
    if active.fetch_add(1, Ordering::SeqCst) > 0 {
        active.fetch_sub(1, Ordering::SeqCst);
        write!(
            out,
            "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )?;
        return Ok(());
    }
    // Hold the slot long enough for the other workers' requests to overlap with it.
    std::thread::sleep(Duration::from_millis(150));
    let body: Vec<u8> = (start..=end).map(byte_at).collect();
    let sent = write!(
        out,
        "HTTP/1.1 206 Partial Content\r\nContent-Length: {}\r\nContent-Range: bytes {start}-{end}/{total}\r\nETag: \"v1\"\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .and_then(|()| out.write_all(&body));
    active.fetch_sub(1, Ordering::SeqCst);
    sent
}

#[test]
fn get_steps_down_to_fewer_connections_when_many_are_refused() {
    let total = 3 * 8 * MIB + 5;
    let origin = OneAtATime::start(total);
    let out_dir = tempfile::tempdir().unwrap();
    let dest = out_dir.path().join("big.bin");

    let out = blaze()
        .args([
            "get",
            &format!("http://{}/big.bin", origin.addr),
            "-c",
            "32",
            "--retries",
            "1",
            "-o",
        ])
        .arg(&dest)
        .output()
        .unwrap();

    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let err = stderr(&out);
    assert!(err.contains("Fewer connections"), "{err}");
    assert!(err.contains("32"), "{err}");
    let saved = std::fs::read(&dest).unwrap();
    assert_eq!(saved.len() as u64, total);
    assert!(
        saved
            .iter()
            .enumerate()
            .all(|(i, b)| *b == byte_at(i as u64))
    );
}

#[test]
fn get_does_not_step_down_for_permanent_errors() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let thread = {
        let stop = stop.clone();
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                if stop.load(Ordering::SeqCst) {
                    return;
                }
                let Ok(mut conn) = conn else { continue };
                let mut reader = BufReader::new(conn.try_clone().unwrap());
                let mut line = String::new();
                let _ = reader.read_line(&mut line);
                loop {
                    let mut h = String::new();
                    if reader.read_line(&mut h).unwrap_or(0) == 0 || h.trim().is_empty() {
                        break;
                    }
                }
                let reply = if line.starts_with("HEAD") {
                    "HTTP/1.1 200 OK\r\nContent-Length: 25165829\r\nAccept-Ranges: bytes\r\nETag: \"v1\"\r\nConnection: close\r\n\r\n"
                } else {
                    "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                };
                let _ = conn.write_all(reply.as_bytes());
            }
        })
    };
    let out_dir = tempfile::tempdir().unwrap();
    let out = blaze()
        .args([
            "get",
            &format!("http://{addr}/big.bin"),
            "-c",
            "32",
            "--retries",
            "1",
            "-o",
        ])
        .arg(out_dir.path().join("big.bin"))
        .output()
        .unwrap();
    stop.store(true, Ordering::SeqCst);
    let _ = TcpStream::connect(addr);
    let _ = thread.join();

    assert_ne!(code(&out), 0);
    assert!(
        !stderr(&out).contains("Fewer connections"),
        "{}",
        stderr(&out)
    );
}
