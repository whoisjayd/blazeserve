mod cli_support;

use blazeserve::config::{Config, Credentials};
use cli_support::{blaze, canonical, code, pattern, stderr, stdout};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::Output;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

const MIB: usize = 1024 * 1024;

async fn serve(dir: &Path, auth: Option<(&str, &str)>) -> blazeserve::server::ServerHandle {
    let config = Config {
        host: "127.0.0.1".into(),
        port: 0,
        base: canonical(dir),
        auth: auth.map(|(user, password)| Credentials {
            user: user.into(),
            password: password.into(),
        }),
        ..Config::default()
    };
    blazeserve::server::start(config)
        .await
        .expect("start server")
}

async fn get(args: Vec<String>) -> Output {
    tokio::task::spawn_blocking(move || {
        blaze().arg("get").args(args).output().expect("spawn blaze")
    })
    .await
    .unwrap()
}

fn s(p: &Path) -> String {
    p.to_str().unwrap().to_owned()
}

fn sha256_hex(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn no_leftovers(dir: &Path, name: &str) {
    assert!(!dir.join(name).exists(), "{name} must not be published");
    assert!(!dir.join(format!("{name}.part")).exists());
    assert!(!dir.join(format!("{name}.part.meta")).exists());
}

type Reply = (u16, &'static str, String);

/// A tiny origin that answers every request with `handler(request_line)` and records the
/// request heads it saw.
struct Stub {
    addr: std::net::SocketAddr,
    seen: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
}

impl Stub {
    fn start(handler: impl Fn(&str) -> Reply + Send + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let (seen_t, stop_t) = (Arc::clone(&seen), Arc::clone(&stop));
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                if stop_t.load(Ordering::SeqCst) {
                    return;
                }
                let Ok(mut conn) = conn else { continue };
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if conn.read(&mut byte).unwrap_or(0) == 0 {
                        break;
                    }
                    head.push(byte[0]);
                }
                let head = String::from_utf8_lossy(&head).into_owned();
                let line = head.lines().next().unwrap_or("").to_owned();
                seen_t.lock().unwrap().push(head);
                let (status, ctype, body) = handler(&line);
                let _ = write!(
                    conn,
                    "HTTP/1.1 {status} X\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            }
        });
        Self { addr, seen, stop }
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }

    fn heads(&self) -> Vec<String> {
        self.seen.lock().unwrap().clone()
    }
}

impl Drop for Stub {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.addr);
    }
}

const BODY: &str = "abc";
const ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

fn json(sha: &str, size: u64) -> Reply {
    (
        200,
        "application/json",
        format!(r#"{{"path":"/f.bin","size":{size},"sha256":"{sha}"}}"#),
    )
}

/// Downloads `/f.bin` from a stub whose `?hash` answer is `hash_reply`, expecting failure.
fn expect_failure(hash_reply: Reply) -> (Output, tempfile::TempDir, Stub) {
    let stub = Stub::start(move |line| {
        if line.contains("hash") {
            hash_reply.clone()
        } else {
            (200, "application/octet-stream", BODY.to_owned())
        }
    });
    let out_dir = tempfile::tempdir().unwrap();
    let dest = out_dir.path().join("f.bin");
    let out = blaze()
        .args(["get", &stub.url("/f.bin"), "-c", "1", "-o", &s(&dest)])
        .args(["--verify", "server-sha256"])
        .output()
        .unwrap();
    (out, out_dir, stub)
}

fn assert_refused(out: &Output, dir: &tempfile::TempDir, needle: &str) {
    assert_eq!(code(out), 1, "{}", stderr(out));
    assert!(stderr(out).contains(needle), "{}", stderr(out));
    assert!(!stdout(out).contains("Saved"));
    no_leftovers(dir.path(), "f.bin");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn verifies_single_stream_downloads() {
    let served = tempfile::tempdir().unwrap();
    let data = pattern(MIB + 5);
    std::fs::write(served.path().join("a.bin"), &data).unwrap();
    let server = serve(served.path(), None).await;
    let out_dir = tempfile::tempdir().unwrap();
    let dest = out_dir.path().join("a.bin");

    let out = get(vec![
        format!("http://{}/a.bin", server.local_addr()),
        "-c".into(),
        "1".into(),
        "-o".into(),
        s(&dest),
        "--verify".into(),
        "server-sha256".into(),
    ])
    .await;

    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert_eq!(std::fs::read(&dest).unwrap(), data);
    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn verifies_segmented_downloads() {
    let served = tempfile::tempdir().unwrap();
    let data = pattern(20 * MIB + 3);
    std::fs::write(served.path().join("big.bin"), &data).unwrap();
    let server = serve(served.path(), None).await;
    let out_dir = tempfile::tempdir().unwrap();
    let dest = out_dir.path().join("big.bin");

    let out = get(vec![
        format!("http://{}/big.bin", server.local_addr()),
        "-c".into(),
        "4".into(),
        "-o".into(),
        s(&dest),
        "--verify".into(),
        "server-sha256".into(),
    ])
    .await;

    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(stderr(&out).contains("parts"), "{}", stderr(&out));
    assert_eq!(
        sha256_hex(&std::fs::read(&dest).unwrap()),
        sha256_hex(&data)
    );
    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn verifies_resumed_downloads() {
    let served = tempfile::tempdir().unwrap();
    let data = pattern(3 * MIB);
    std::fs::write(served.path().join("r.bin"), &data).unwrap();
    let server = serve(served.path(), None).await;
    let url = format!("http://{}/r.bin", server.local_addr());
    let out_dir = tempfile::tempdir().unwrap();
    let dest = out_dir.path().join("r.bin");
    std::fs::write(out_dir.path().join("r.bin.part"), &data[..MIB]).unwrap();
    let meta =
        serde_json::json!({ "url": url, "etag": null, "last_modified": null, "total": null });
    std::fs::write(out_dir.path().join("r.bin.part.meta"), meta.to_string()).unwrap();

    let out = get(vec![
        url,
        "-c".into(),
        "1".into(),
        "-o".into(),
        s(&dest),
        "--verify".into(),
        "server-sha256".into(),
    ])
    .await;

    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert_eq!(std::fs::read(&dest).unwrap(), data);
    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_resumed_part_that_is_corrupt_fails_verification() {
    let served = tempfile::tempdir().unwrap();
    let data = pattern(3 * MIB);
    std::fs::write(served.path().join("r.bin"), &data).unwrap();
    let server = serve(served.path(), None).await;
    let url = format!("http://{}/r.bin", server.local_addr());
    let out_dir = tempfile::tempdir().unwrap();
    let dest = out_dir.path().join("r.bin");
    std::fs::write(out_dir.path().join("r.bin.part"), vec![0u8; MIB]).unwrap();
    let meta =
        serde_json::json!({ "url": url, "etag": null, "last_modified": null, "total": null });
    std::fs::write(out_dir.path().join("r.bin.part.meta"), meta.to_string()).unwrap();

    let out = get(vec![
        url,
        "-c".into(),
        "1".into(),
        "-o".into(),
        s(&dest),
        "--verify".into(),
        "server-sha256".into(),
    ])
    .await;

    assert_eq!(code(&out), 1, "{}", stderr(&out));
    assert!(
        stderr(&out).contains("SHA-256 mismatch"),
        "{}",
        stderr(&out)
    );
    no_leftovers(out_dir.path(), "r.bin");
    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn verifies_empty_files() {
    let served = tempfile::tempdir().unwrap();
    std::fs::write(served.path().join("empty.bin"), b"").unwrap();
    let server = serve(served.path(), None).await;
    let out_dir = tempfile::tempdir().unwrap();
    let dest = out_dir.path().join("empty.bin");

    let out = get(vec![
        format!("http://{}/empty.bin", server.local_addr()),
        "-o".into(),
        s(&dest),
        "--verify".into(),
        "server-sha256".into(),
    ])
    .await;

    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert_eq!(std::fs::metadata(&dest).unwrap().len(), 0);
    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authenticates_discovery_without_leaking_the_password() {
    let served = tempfile::tempdir().unwrap();
    std::fs::write(served.path().join("a.txt"), BODY).unwrap();
    let server = serve(served.path(), Some(("alice", "s3cret-pw"))).await;
    let url = format!("http://{}/a.txt", server.local_addr());
    let out_dir = tempfile::tempdir().unwrap();
    let dest = out_dir.path().join("a.txt");

    let ok = get(vec![
        url.clone(),
        "-o".into(),
        s(&dest),
        "--auth".into(),
        "alice:s3cret-pw".into(),
        "--verify".into(),
        "server-sha256".into(),
    ])
    .await;
    assert_eq!(code(&ok), 0, "{}", stderr(&ok));
    assert_eq!(std::fs::read_to_string(&dest).unwrap(), BODY);

    let denied_dest = out_dir.path().join("denied.txt");
    let denied = get(vec![
        url,
        "-o".into(),
        s(&denied_dest),
        "--auth".into(),
        "alice:wrong-pw".into(),
        "--verify".into(),
        "server-sha256".into(),
    ])
    .await;
    assert_eq!(code(&denied), 1);
    assert!(stderr(&denied).contains("SHA-256"), "{}", stderr(&denied));
    for text in [stderr(&denied), stdout(&denied)] {
        assert!(!text.contains("wrong-pw") && !text.contains("s3cret-pw"));
    }
    no_leftovers(out_dir.path(), "denied.txt");
    server.shutdown().await;
}

#[test]
fn hash_request_keeps_query_asks_for_identity_and_stays_quiet() {
    let stub = Stub::start(|line| {
        if line.contains("hash") {
            json(ABC, 3)
        } else {
            (200, "application/octet-stream", BODY.to_owned())
        }
    });
    let out_dir = tempfile::tempdir().unwrap();
    let dest = out_dir.path().join("f.bin");
    let out = blaze()
        .args(["get", &stub.url("/f.bin?sig=topsecret"), "-c", "1", "-o"])
        .arg(&dest)
        .args(["--verify", "server-sha256"])
        .output()
        .unwrap();

    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let heads = stub.heads();
    let hash_head = heads
        .iter()
        .find(|h| h.starts_with("GET /f.bin?sig=topsecret&hash "))
        .expect("hash request");
    assert!(
        hash_head
            .to_ascii_lowercase()
            .contains("accept-encoding: identity"),
        "{hash_head}"
    );
    assert!(!stdout(&out).contains("topsecret") && !stderr(&out).contains("topsecret"));
    assert!(!out_dir.path().join("f.bin.part.meta").exists());
}

#[test]
fn unsupported_endpoint_fails() {
    let (out, dir, _stub) = expect_failure((404, "text/plain", "nope".into()));
    assert_refused(&out, &dir, "BlazeServe");
}

#[test]
fn non_json_reply_fails() {
    let (out, dir, _stub) = expect_failure((200, "text/html", "<html>".into()));
    assert_refused(&out, &dir, "JSON");
}

#[test]
fn malformed_digest_fails() {
    let (out, dir, _stub) = expect_failure(json("not-hex", 3));
    assert_refused(&out, &dir, "hash reply");
}

#[test]
fn oversized_reply_fails() {
    let (out, dir, _stub) = expect_failure((200, "application/json", " ".repeat(64 * 1024)));
    assert_refused(&out, &dir, "hash reply");
}

#[test]
fn unauthorized_discovery_fails() {
    let (out, dir, _stub) = expect_failure((401, "text/plain", "no".into()));
    assert_refused(&out, &dir, "401");
}

#[test]
fn size_change_fails() {
    let (out, dir, _stub) = expect_failure(json(ABC, 99));
    assert_refused(&out, &dir, "size");
}

#[test]
fn hash_mismatch_fails_and_keeps_an_existing_destination() {
    let stub = Stub::start(|line| {
        if line.contains("hash") {
            json(&"0".repeat(64), 3)
        } else {
            (200, "application/octet-stream", BODY.to_owned())
        }
    });
    let out_dir = tempfile::tempdir().unwrap();
    let dest = out_dir.path().join("f.bin");
    std::fs::write(&dest, b"old").unwrap();
    let out = blaze()
        .args(["get", &stub.url("/f.bin"), "-c", "1", "--force", "-o"])
        .arg(&dest)
        .args(["--verify", "server-sha256"])
        .output()
        .unwrap();

    assert_eq!(code(&out), 1);
    assert!(
        stderr(&out).contains("SHA-256 mismatch"),
        "{}",
        stderr(&out)
    );
    assert_eq!(std::fs::read(&dest).unwrap(), b"old");
    assert!(!out_dir.path().join("f.bin.part").exists());
}

#[test]
fn conflicts_with_manual_sha256() {
    let out = blaze()
        .args(["get", "http://127.0.0.1:1/f", "--verify", "server-sha256"])
        .args(["--sha256", ABC])
        .output()
        .unwrap();
    assert_eq!(code(&out), 2, "{}", stderr(&out));
    assert!(
        stderr(&out).contains("cannot be used with"),
        "{}",
        stderr(&out)
    );
}
