#![allow(dead_code)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

use blazeserve::config::Config;
use blazeserve::server::{self, ServerHandle};

pub const HELLO: &[u8] = b"Hello, BlazeServe!";

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

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    pub fn tokens(&self, name: &str) -> Vec<String> {
        self.headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case(name))
            .flat_map(|(_, v)| v.split(','))
            .map(|t| t.trim().to_ascii_lowercase())
            .filter(|t| !t.is_empty())
            .collect()
    }

    pub fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).expect("response body is JSON")
    }
}

pub fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| ((i * 31 + i / 251) % 251) as u8).collect()
}

fn write_request(
    stream: &mut TcpStream,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    close: bool,
) {
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\n");
    if close {
        req.push_str("Connection: close\r\n");
    }
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes()).expect("send request");
}

fn read_response(reader: &mut BufReader<TcpStream>, head: bool) -> Resp {
    let mut line = String::new();
    reader.read_line(&mut line).expect("status line");
    let status: u16 = line
        .split_whitespace()
        .nth(1)
        .expect("status code")
        .parse()
        .expect("numeric status");
    let mut headers = Vec::new();
    loop {
        line.clear();
        reader.read_line(&mut line).expect("header line");
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            break;
        }
        let (k, v) = trimmed.split_once(':').expect("header colon");
        headers.push((k.trim().to_owned(), v.trim().to_owned()));
    }
    let find = |name: &str| {
        headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.clone())
    };
    let mut body = Vec::new();
    if head || status == 204 || status == 304 || (100..200).contains(&status) {
        return Resp {
            status,
            headers,
            body,
        };
    }
    if find("transfer-encoding").is_some_and(|v| v.eq_ignore_ascii_case("chunked")) {
        loop {
            line.clear();
            reader.read_line(&mut line).expect("chunk size");
            let size = usize::from_str_radix(line.trim().split(';').next().unwrap_or("0"), 16)
                .expect("hex chunk size");
            if size == 0 {
                line.clear();
                reader.read_line(&mut line).expect("chunk trailer");
                break;
            }
            let mut chunk = vec![0u8; size];
            reader.read_exact(&mut chunk).expect("chunk body");
            body.extend_from_slice(&chunk);
            let mut crlf = [0u8; 2];
            reader.read_exact(&mut crlf).expect("chunk crlf");
        }
    } else if let Some(len) = find("content-length") {
        body.resize(len.parse().expect("numeric length"), 0);
        reader.read_exact(&mut body).expect("sized body");
    } else {
        reader.read_to_end(&mut body).expect("body until close");
    }
    Resp {
        status,
        headers,
        body,
    }
}

fn connect(addr: SocketAddr) -> TcpStream {
    let stream = TcpStream::connect(addr).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .expect("read timeout");
    stream.set_nodelay(true).ok();
    stream
}

pub fn request(addr: SocketAddr, method: &str, path: &str, headers: &[(&str, &str)]) -> Resp {
    let mut stream = connect(addr);
    write_request(&mut stream, method, path, headers, true);
    let mut reader = BufReader::new(stream);
    read_response(&mut reader, method == "HEAD")
}

pub fn get(addr: SocketAddr, path: &str) -> Resp {
    request(addr, "GET", path, &[])
}

pub fn get_with(addr: SocketAddr, path: &str, headers: &[(&str, &str)]) -> Resp {
    request(addr, "GET", path, headers)
}

pub fn basic(user: &str, pass: &str) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let raw = format!("{user}:{pass}").into_bytes();
    let mut out = String::from("Basic ");
    for chunk in raw.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(TABLE[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

pub struct Conn {
    reader: BufReader<TcpStream>,
}

impl Conn {
    pub fn open(addr: SocketAddr) -> Self {
        Self {
            reader: BufReader::new(connect(addr)),
        }
    }

    pub fn send(&mut self, method: &str, path: &str, headers: &[(&str, &str)]) -> Resp {
        write_request(self.reader.get_mut(), method, path, headers, false);
        read_response(&mut self.reader, method == "HEAD")
    }

    pub fn start(&mut self, method: &str, path: &str, headers: &[(&str, &str)]) {
        write_request(self.reader.get_mut(), method, path, headers, false);
    }

    pub fn read_some(&mut self, n: usize) -> Vec<u8> {
        let mut buf = vec![0u8; n];
        self.reader.read_exact(&mut buf).expect("partial read");
        buf
    }
}

pub struct Fixture {
    pub dir: tempfile::TempDir,
    pub root: PathBuf,
    pub server: ServerHandle,
    pub addr: SocketAddr,
}

impl Fixture {
    pub fn path(&self, rel: &str) -> PathBuf {
        rel.split('/').fold(self.root.clone(), |p, c| p.join(c))
    }

    pub fn get(&self, path: &str) -> Resp {
        get(self.addr, path)
    }

    pub fn get_with(&self, path: &str, headers: &[(&str, &str)]) -> Resp {
        get_with(self.addr, path, headers)
    }

    pub fn head(&self, path: &str, headers: &[(&str, &str)]) -> Resp {
        request(self.addr, "HEAD", path, headers)
    }

    pub fn conn(&self) -> Conn {
        Conn::open(self.addr)
    }

    pub async fn stop(self) {
        self.server.shutdown().await;
    }
}

pub fn populate(root: &Path) {
    std::fs::write(root.join("hello.txt"), HELLO).unwrap();
    std::fs::create_dir_all(root.join("sub")).unwrap();
    std::fs::write(root.join("sub").join("nested.txt"), b"nested").unwrap();
    std::fs::write(root.join("plain.txt"), b"Precompressed plain content").unwrap();
    std::fs::write(root.join("plain.txt.gz"), b"GZIP-BYTES").unwrap();
    std::fs::write(root.join("plain.txt.br"), b"BROTLI-BYTES").unwrap();
}

pub async fn start_with(setup: impl FnOnce(&Path, &mut Config)) -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().canonicalize().expect("canonical root");
    populate(&root);
    let mut config = Config {
        host: "127.0.0.1".into(),
        port: 0,
        base: root.clone(),
        ..Config::default()
    };
    setup(&root, &mut config);
    let server = server::start(config).await.expect("server starts");
    let addr = server.local_addr();
    Fixture {
        dir,
        root,
        server,
        addr,
    }
}

pub async fn start() -> Fixture {
    start_with(|_, _| {}).await
}
