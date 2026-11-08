#![allow(dead_code)]

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use blazeserve::config::Config;
use blazeserve::{AppState, Body, PeerInfo, upload, zip_stream};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

pub struct TestServer {
    pub addr: SocketAddr,
    pub state: Arc<AppState>,
    stop: Option<oneshot::Sender<()>>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        if let Some(tx) = self.stop.take() {
            let _ = tx.send(());
        }
    }
}

fn not_found() -> Response<Body> {
    let mut r = Response::new(
        Full::new(Bytes::from_static(b"nf"))
            .map_err(|n| match n {})
            .boxed(),
    );
    *r.status_mut() = StatusCode::NOT_FOUND;
    r
}

async fn route(
    state: Arc<AppState>,
    peer: PeerInfo,
    req: Request<Incoming>,
) -> Result<Response<Body>, std::convert::Infallible> {
    let path = req.uri().path().to_owned();
    let resp = if path.starts_with("/__upload__/") {
        upload::handle_upload(&state, &peer, req).await
    } else if path == "/__zip__" {
        let head = req.method() == Method::HEAD;
        zip_stream::handle_zip(&state, req.uri().query(), head).await
    } else {
        not_found()
    };
    Ok(resp)
}

pub async fn spawn(base: &Path, tweak: impl FnOnce(&mut Config)) -> TestServer {
    spawn_unmodified(base, |c| {
        c.max_upload_bytes = 256 * 1024 * 1024;
        tweak(c);
    })
    .await
}

pub async fn spawn_unmodified(base: &Path, tweak: impl FnOnce(&mut Config)) -> TestServer {
    let mut config = Config {
        base: base.to_path_buf(),
        host: "127.0.0.1".into(),
        port: 0,
        ..Config::default()
    };
    tweak(&mut config);
    let state = AppState::new(config);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let (stop, mut stopped) = oneshot::channel::<()>();
    let st = state.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut stopped => break,
                accepted = listener.accept() => {
                    let Ok((stream, socket_addr)) = accepted else { continue };
                    let st = st.clone();
                    let peer = PeerInfo { socket_addr, client_ip: socket_addr.ip(), tls: false };
                    tokio::spawn(async move {
                        let svc = service_fn(move |req| route(st.clone(), peer.clone(), req));
                        let _ = hyper::server::conn::http1::Builder::new()
                            .serve_connection(TokioIo::new(stream), svc)
                            .await;
                    });
                }
            }
        }
    });
    TestServer {
        addr,
        state,
        stop: Some(stop),
    }
}

#[derive(Debug)]
pub struct Resp {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Resp {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

pub fn request(method: &str, path: &str, headers: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
    let mut head = format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\n");
    let mut has_len = false;
    for (k, v) in headers {
        has_len |= k.eq_ignore_ascii_case("content-length");
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    if !has_len && !matches!(method, "GET" | "HEAD" | "DELETE") {
        head.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    head.push_str("\r\n");
    let mut out = head.into_bytes();
    out.extend_from_slice(body);
    out
}

pub struct Conn {
    pub stream: TcpStream,
    buf: Vec<u8>,
}

impl Conn {
    pub async fn open(addr: SocketAddr) -> Self {
        Self {
            stream: TcpStream::connect(addr).await.expect("connect"),
            buf: Vec::new(),
        }
    }

    pub async fn send(&mut self, raw: &[u8]) {
        self.stream.write_all(raw).await.expect("send");
    }

    async fn fill(&mut self) -> bool {
        let mut tmp = [0u8; 16 * 1024];
        match tokio::time::timeout(Duration::from_secs(10), self.stream.read(&mut tmp)).await {
            Ok(Ok(n)) if n > 0 => {
                self.buf.extend_from_slice(&tmp[..n]);
                true
            }
            _ => false,
        }
    }

    pub async fn read_response(&mut self, head_request: bool) -> Resp {
        let end = loop {
            if let Some(i) = self.buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break i;
            }
            assert!(
                self.fill().await,
                "connection closed before response headers"
            );
        };
        let head = String::from_utf8_lossy(&self.buf[..end]).into_owned();
        self.buf.drain(..end + 4);
        let mut lines = head.split("\r\n");
        let status: u16 = lines
            .next()
            .unwrap()
            .split(' ')
            .nth(1)
            .unwrap()
            .parse()
            .unwrap();
        let headers: Vec<(String, String)> = lines
            .filter_map(|l| {
                l.split_once(':')
                    .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
            })
            .collect();
        let find = |n: &str| {
            headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(n))
                .map(|(_, v)| v.clone())
        };
        let body = if head_request || status == 204 || status == 304 {
            Vec::new()
        } else if let Some(len) = find("content-length") {
            let len: usize = len.parse().unwrap();
            while self.buf.len() < len {
                assert!(self.fill().await, "body truncated");
            }
            self.buf.drain(..len).collect()
        } else if find("transfer-encoding").is_some_and(|v| v.contains("chunked")) {
            self.read_chunked().await
        } else {
            while self.fill().await {}
            std::mem::take(&mut self.buf)
        };
        Resp {
            status,
            headers,
            body,
        }
    }

    async fn read_chunked(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let line_end = loop {
                if let Some(i) = self.buf.windows(2).position(|w| w == b"\r\n") {
                    break i;
                }
                assert!(self.fill().await, "chunk header truncated");
            };
            let size =
                usize::from_str_radix(String::from_utf8_lossy(&self.buf[..line_end]).trim(), 16)
                    .unwrap();
            self.buf.drain(..line_end + 2);
            while self.buf.len() < size + 2 {
                assert!(self.fill().await, "chunk truncated");
            }
            if size == 0 {
                self.buf.drain(..2);
                return out;
            }
            out.extend_from_slice(&self.buf[..size]);
            self.buf.drain(..size + 2);
        }
    }

    pub async fn is_closed_by_peer(&mut self) -> bool {
        if !self.buf.is_empty() {
            return false;
        }
        let mut tmp = [0u8; 1];
        matches!(
            tokio::time::timeout(Duration::from_secs(5), self.stream.read(&mut tmp)).await,
            Ok(Ok(0) | Err(_))
        )
    }
}

pub async fn roundtrip(addr: SocketAddr, raw: &[u8]) -> Resp {
    let mut c = Conn::open(addr).await;
    c.send(raw).await;
    c.read_response(raw.starts_with(b"HEAD")).await
}

pub async fn wait_until(what: &str, mut cond: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !cond() {
        assert!(Instant::now() < deadline, "timed out waiting for: {what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

pub fn dir_names(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .map(|r| {
            r.filter_map(Result::ok)
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

#[cfg(unix)]
pub fn symlink_dir(src: &Path, dst: &Path) -> bool {
    std::os::unix::fs::symlink(src, dst).is_ok()
}
#[cfg(windows)]
pub fn symlink_dir(src: &Path, dst: &Path) -> bool {
    std::os::windows::fs::symlink_dir(src, dst).is_ok()
}

#[cfg(unix)]
pub fn symlink_file(src: &Path, dst: &Path) -> bool {
    std::os::unix::fs::symlink(src, dst).is_ok()
}
#[cfg(windows)]
pub fn symlink_file(src: &Path, dst: &Path) -> bool {
    std::os::windows::fs::symlink_file(src, dst).is_ok()
}

pub fn sha256_b64(data: &[u8]) -> String {
    use base64::Engine as _;
    use sha2::{Digest, Sha256};
    base64::engine::general_purpose::STANDARD.encode(Sha256::digest(data))
}
