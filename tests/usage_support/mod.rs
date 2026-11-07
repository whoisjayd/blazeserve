#![allow(dead_code)]

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

pub struct Env(pub HashMap<String, String>);

impl Env {
    pub fn new(pairs: &[(&str, &str)]) -> Self {
        Self(
            pairs
                .iter()
                .map(|(k, v)| ((*k).into(), (*v).into()))
                .collect(),
        )
    }

    pub fn with(mut self, k: &str, v: &str) -> Self {
        self.0.insert(k.into(), v.into());
        self
    }

    pub fn lookup(&self) -> impl Fn(&str) -> Option<String> + '_ {
        move |k| self.0.get(k).cloned()
    }
}

pub struct Request {
    pub head: String,
    pub body: String,
}

pub struct Mock {
    pub addr: SocketAddr,
    pub requests: Receiver<Request>,
    pub connections: Arc<Mutex<usize>>,
}

impl Mock {
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub fn connection_count(&self) -> usize {
        *self.connections.lock().unwrap()
    }
}

fn read_request(stream: &mut TcpStream) -> Option<Request> {
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    let mut data = Vec::new();
    let mut buf = [0u8; 1024];
    let split = loop {
        let n = stream.read(&mut buf).ok()?;
        if n == 0 {
            return None;
        }
        data.extend_from_slice(&buf[..n]);
        if let Some(i) = data.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
    };
    let head = String::from_utf8_lossy(&data[..split]).into_owned();
    let length = head
        .lines()
        .find_map(|l| {
            l.to_ascii_lowercase()
                .strip_prefix("content-length:")
                .map(|v| v.trim().parse::<usize>().ok())
        })
        .flatten()
        .unwrap_or(0);
    while data.len() < split + length {
        let n = stream.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        data.extend_from_slice(&buf[..n]);
    }
    Some(Request {
        head,
        body: String::from_utf8_lossy(&data[split..]).into_owned(),
    })
}

/// Accepts connections forever. When `respond` is false the connection is held open and
/// never answered, which models a relay that hangs.
pub fn mock(respond: bool) -> Mock {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, requests) = mpsc::channel();
    let connections = Arc::new(Mutex::new(0usize));
    let counter = connections.clone();
    thread::spawn(move || {
        let mut held = Vec::new();
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            *counter.lock().unwrap() += 1;
            if !respond {
                held.push(stream);
                continue;
            }
            let tx = tx.clone();
            thread::spawn(move || {
                if let Some(req) = read_request(&mut stream) {
                    let _ = stream.write_all(
                        b"HTTP/1.1 204 No Content\r\nconnection: close\r\ncontent-length: 0\r\n\r\n",
                    );
                    let _ = tx.send(req);
                }
            });
        }
    });
    Mock {
        addr,
        requests,
        connections,
    }
}

pub fn wait_for<T>(rx: &Receiver<T>, secs: u64) -> Option<T> {
    rx.recv_timeout(Duration::from_secs(secs)).ok()
}

pub fn elapsed<R>(f: impl FnOnce() -> R) -> (R, Duration) {
    let start = Instant::now();
    let out = f();
    (out, start.elapsed())
}
