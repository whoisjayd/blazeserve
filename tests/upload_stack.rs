mod http_common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use http_common::start_with;

struct Reply {
    status: u16,
    head: String,
}

impl Reply {
    fn header(&self, name: &str) -> Option<String> {
        self.head.lines().skip(1).find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.eq_ignore_ascii_case(name).then(|| v.trim().to_owned())
        })
    }
}

fn send(
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> Reply {
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n");
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    if !body.is_empty() || method == "PUT" {
        req.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes()).unwrap();
    stream.write_all(body).unwrap();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).unwrap();
    let text = String::from_utf8_lossy(&raw).into_owned();
    let (head, _) = text.split_once("\r\n\r\n").expect("response head");
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .expect("status code");
    Reply {
        status,
        head: head.to_owned(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upload_etag_matches_served_etag_and_replace_is_conditional() {
    let fx = start_with(|_, c| c.max_upload_bytes = 1024 * 1024).await;

    let created = send(fx.addr, "PUT", "/__upload__/doc.txt", &[], b"version one");
    assert_eq!(created.status, 201);
    let upload_etag = created.header("etag").expect("upload returns an ETag");

    let served = fx.get("/doc.txt");
    assert_eq!(served.header("etag"), Some(upload_etag.as_str()));

    let stale = send(
        fx.addr,
        "PUT",
        "/__upload__/doc.txt",
        &[("If-Match", "\"stale\"")],
        b"clobbered",
    );
    assert_eq!(stale.status, 412);
    assert_eq!(fx.get("/doc.txt").body, b"version one");

    let replaced = send(
        fx.addr,
        "PUT",
        "/__upload__/doc.txt",
        &[("If-Match", upload_etag.as_str())],
        b"version two",
    );
    assert_eq!(replaced.status, 200);
    assert_eq!(fx.get("/doc.txt").body, b"version two");

    let again = send(
        fx.addr,
        "PUT",
        "/__upload__/doc.txt",
        &[],
        b"no precondition",
    );
    assert_eq!(again.status, 409);
    assert_eq!(fx.get("/doc.txt").body, b"version two");

    fx.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn delete_reaches_the_upload_handler_and_staging_files_stay_hidden() {
    let fx = start_with(|_, c| c.max_upload_bytes = 1024 * 1024).await;
    std::fs::write(fx.path(".x.blaze-part-abc"), b"partial").unwrap();
    std::fs::write(fx.path(".y.blaze-resume"), b"partial").unwrap();

    let listing = fx.get_with("/", &[("Accept", "application/json")]);
    let text = listing.text();
    assert!(text.contains("hello.txt"));
    assert!(
        !text.contains("blaze-part") && !text.contains("blaze-resume"),
        "{text}"
    );

    let html = fx.get("/").text();
    assert!(!html.contains("blaze-part") && !html.contains("blaze-resume"));

    let deleted = send(fx.addr, "DELETE", "/__upload__/never-started.bin", &[], b"");
    assert_ne!(
        deleted.status, 405,
        "DELETE must be routed to the upload handler"
    );

    let outside = send(fx.addr, "DELETE", "/hello.txt", &[], b"");
    assert_eq!(outside.status, 405);
    assert!(fx.path("hello.txt").exists());

    fx.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn uploads_are_refused_with_the_default_configuration() {
    let fx = start_with(|_, _| {}).await;
    let reply = send(fx.addr, "PUT", "/__upload__/x.txt", &[], b"data");
    assert_eq!(reply.status, 403);
    assert!(!fx.path("x.txt").exists());
    fx.stop().await;
}
