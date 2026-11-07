mod cli_support;

use blazeserve::config::Config;
use cli_support::{blaze, canonical, code, pattern, stderr, stdout};
use std::path::Path;
use std::process::Output;

const MIB: usize = 1024 * 1024;

async fn serve(dir: &Path, upload_mb: u64) -> blazeserve::server::ServerHandle {
    let config = Config {
        host: "127.0.0.1".into(),
        port: 0,
        base: canonical(dir),
        max_upload_bytes: upload_mb * MIB as u64,
        ..Config::default()
    };
    blazeserve::server::start(config)
        .await
        .expect("start server")
}

async fn blaze_async(args: Vec<String>) -> Output {
    tokio::task::spawn_blocking(move || blaze().args(args).output().expect("spawn blaze"))
        .await
        .unwrap()
}

fn s(p: &Path) -> String {
    p.to_str().unwrap().to_owned()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn get_downloads_a_file() {
    let served = tempfile::tempdir().unwrap();
    let data = pattern(2 * MIB + 17);
    std::fs::write(served.path().join("big.bin"), &data).unwrap();
    let server = serve(served.path(), 0).await;
    let url = format!("http://{}/big.bin", server.local_addr());

    let out_dir = tempfile::tempdir().unwrap();
    let dest = out_dir.path().join("big.bin");
    let out = blaze_async(vec!["get".into(), url, "-o".into(), s(&dest)]).await;

    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(stdout(&out).contains("Saved"));
    assert_eq!(std::fs::read(&dest).unwrap(), data);
    assert!(!out_dir.path().join("big.bin.part").exists());
    assert!(!out_dir.path().join("big.bin.part.meta").exists());
    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn get_resumes_from_a_partial_file() {
    let served = tempfile::tempdir().unwrap();
    let data = pattern(3 * MIB);
    std::fs::write(served.path().join("big.bin"), &data).unwrap();
    let server = serve(served.path(), 0).await;
    let url = format!("http://{}/big.bin", server.local_addr());

    let out_dir = tempfile::tempdir().unwrap();
    let dest = out_dir.path().join("big.bin");
    std::fs::write(out_dir.path().join("big.bin.part"), &data[..MIB]).unwrap();
    let meta =
        serde_json::json!({ "url": url, "etag": null, "last_modified": null, "total": null });
    std::fs::write(out_dir.path().join("big.bin.part.meta"), meta.to_string()).unwrap();

    let before = server.state().metrics.bytes_sent();
    let out = blaze_async(vec!["get".into(), url, "-o".into(), s(&dest)]).await;
    let sent = server.state().metrics.bytes_sent() - before;

    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert_eq!(std::fs::read(&dest).unwrap(), data);
    assert_eq!(
        sent,
        2 * MIB as u64,
        "only the missing tail should cross the wire"
    );
    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn get_restarts_when_the_part_belongs_to_another_url() {
    let served = tempfile::tempdir().unwrap();
    let data = pattern(MIB);
    std::fs::write(served.path().join("a.bin"), &data).unwrap();
    let server = serve(served.path(), 0).await;
    let url = format!("http://{}/a.bin", server.local_addr());

    let out_dir = tempfile::tempdir().unwrap();
    let dest = out_dir.path().join("a.bin");
    std::fs::write(out_dir.path().join("a.bin.part"), vec![0xEE; 1000]).unwrap();
    let meta = serde_json::json!({ "url": "http://elsewhere/a.bin", "etag": null, "last_modified": null, "total": null });
    std::fs::write(out_dir.path().join("a.bin.part.meta"), meta.to_string()).unwrap();

    let out = blaze_async(vec!["get".into(), url, "-o".into(), s(&dest)]).await;
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert_eq!(std::fs::read(&dest).unwrap(), data);
    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn get_completes_when_the_part_is_already_whole() {
    let served = tempfile::tempdir().unwrap();
    let data = pattern(512 * 1024);
    std::fs::write(served.path().join("done.bin"), &data).unwrap();
    let server = serve(served.path(), 0).await;
    let url = format!("http://{}/done.bin", server.local_addr());

    let out_dir = tempfile::tempdir().unwrap();
    let dest = out_dir.path().join("done.bin");
    std::fs::write(out_dir.path().join("done.bin.part"), &data).unwrap();
    let meta =
        serde_json::json!({ "url": url, "etag": null, "last_modified": null, "total": data.len() });
    std::fs::write(out_dir.path().join("done.bin.part.meta"), meta.to_string()).unwrap();

    let out = blaze_async(vec!["get".into(), url, "-o".into(), s(&dest)]).await;
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert_eq!(std::fs::read(&dest).unwrap(), data);
    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn get_verifies_sha256_and_discards_bad_downloads() {
    let served = tempfile::tempdir().unwrap();
    std::fs::write(served.path().join("abc.txt"), b"abc").unwrap();
    let server = serve(served.path(), 0).await;
    let url = format!("http://{}/abc.txt", server.local_addr());
    let out_dir = tempfile::tempdir().unwrap();

    let good = out_dir.path().join("good.txt");
    let ok = blaze_async(vec![
        "get".into(),
        url.clone(),
        "-o".into(),
        s(&good),
        "--sha256".into(),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".into(),
    ])
    .await;
    assert_eq!(code(&ok), 0, "{}", stderr(&ok));

    let bad = out_dir.path().join("bad.txt");
    let fail = blaze_async(vec![
        "get".into(),
        url,
        "-o".into(),
        s(&bad),
        "--sha256".into(),
        "0".repeat(64),
    ])
    .await;
    assert_eq!(code(&fail), 1);
    assert!(stderr(&fail).contains("SHA-256 mismatch"));
    assert!(!bad.exists());
    assert!(!out_dir.path().join("bad.txt.part").exists());
    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn get_refuses_to_overwrite_without_force() {
    let served = tempfile::tempdir().unwrap();
    std::fs::write(served.path().join("f.txt"), b"new").unwrap();
    let server = serve(served.path(), 0).await;
    let url = format!("http://{}/f.txt", server.local_addr());
    let out_dir = tempfile::tempdir().unwrap();
    let dest = out_dir.path().join("f.txt");
    std::fs::write(&dest, b"old").unwrap();

    let refused = blaze_async(vec!["get".into(), url.clone(), "-o".into(), s(&dest)]).await;
    assert_eq!(code(&refused), 1);
    assert_eq!(std::fs::read(&dest).unwrap(), b"old");

    let forced = blaze_async(vec![
        "get".into(),
        url,
        "-o".into(),
        s(&dest),
        "--force".into(),
    ])
    .await;
    assert_eq!(code(&forced), 0, "{}", stderr(&forced));
    assert_eq!(std::fs::read(&dest).unwrap(), b"new");
    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn get_does_not_retry_permanent_errors() {
    let served = tempfile::tempdir().unwrap();
    let server = serve(served.path(), 0).await;
    let url = format!("http://{}/missing.bin", server.local_addr());
    let out_dir = tempfile::tempdir().unwrap();
    let dest = out_dir.path().join("missing.bin");

    let started = std::time::Instant::now();
    let out = blaze_async(vec!["get".into(), url, "-o".into(), s(&dest)]).await;
    assert_eq!(code(&out), 1);
    assert!(stderr(&out).contains("HTTP 404"));
    assert!(!stderr(&out).contains("Retrying"));
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
    assert!(!dest.exists());
    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn get_sends_basic_auth_from_the_environment() {
    let served = tempfile::tempdir().unwrap();
    std::fs::write(served.path().join("secret.txt"), b"s3cret").unwrap();
    let config = Config {
        host: "127.0.0.1".into(),
        port: 0,
        base: canonical(served.path()),
        auth: Some(blazeserve::config::Credentials::parse("alice:pw").unwrap()),
        ..Config::default()
    };
    let server = blazeserve::server::start(config).await.unwrap();
    let url = format!("http://{}/secret.txt", server.local_addr());
    let out_dir = tempfile::tempdir().unwrap();
    let dest = out_dir.path().join("secret.txt");

    let denied = blaze_async(vec!["get".into(), url.clone(), "-o".into(), s(&dest)]).await;
    assert_eq!(code(&denied), 1);
    assert!(stderr(&denied).contains("HTTP 401"));

    let (dest2, url2) = (dest.clone(), url.clone());
    let allowed = tokio::task::spawn_blocking(move || {
        blaze()
            .args([
                "get",
                &url2,
                "-o",
                dest2.to_str().unwrap(),
                "--auth-env",
                "BLAZE_TEST_GET_AUTH",
            ])
            .env("BLAZE_TEST_GET_AUTH", "alice:pw")
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert_eq!(code(&allowed), 0, "{}", stderr(&allowed));
    assert_eq!(std::fs::read(&dest).unwrap(), b"s3cret");
    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn put_uploads_a_file_in_chunks() {
    let served = tempfile::tempdir().unwrap();
    let server = serve(served.path(), 64).await;
    let origin = format!("http://{}", server.local_addr());

    let src_dir = tempfile::tempdir().unwrap();
    let src = src_dir.path().join("payload.bin");
    let data = pattern(MIB + MIB / 2 + 5);
    std::fs::write(&src, &data).unwrap();

    let out = blaze_async(vec![
        "put".into(),
        s(&src),
        origin,
        "--chunk-mb".into(),
        "1".into(),
    ])
    .await;
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert_eq!(
        std::fs::read(served.path().join("payload.bin")).unwrap(),
        data
    );
    server.shutdown().await;
}

const SEGMENT: usize = 8 * MIB;

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn get_downloads_in_parallel_segments() {
    let served = tempfile::tempdir().unwrap();
    let data = pattern(40 * MIB + 123);
    std::fs::write(served.path().join("big.bin"), &data).unwrap();
    let server = serve(served.path(), 0).await;
    let url = format!("http://{}/big.bin", server.local_addr());

    let out_dir = tempfile::tempdir().unwrap();
    let dest = out_dir.path().join("big.bin");
    let out = blaze_async(vec![
        "get".into(),
        url,
        "-o".into(),
        s(&dest),
        "--connections".into(),
        "4".into(),
        "--sha256".into(),
        sha256_hex(&data),
    ])
    .await;

    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(stderr(&out).contains("in 4 parts"), "{}", stderr(&out));
    assert_eq!(
        sha256_hex(&std::fs::read(&dest).unwrap()),
        sha256_hex(&data)
    );
    assert!(!out_dir.path().join("big.bin.part").exists());
    assert!(!out_dir.path().join("big.bin.part.meta").exists());
    assert!(!out_dir.path().join("big.bin.part.meta.tmp").exists());
    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn segmented_get_fetches_only_missing_segments_on_resume() {
    let served = tempfile::tempdir().unwrap();
    let data = pattern(5 * SEGMENT);
    std::fs::write(served.path().join("big.bin"), &data).unwrap();
    let server = serve(served.path(), 0).await;
    let url = format!("http://{}/big.bin", server.local_addr());

    let head_url = url.clone();
    let (etag, last_modified) = tokio::task::spawn_blocking(move || {
        let resp = ureq::head(&head_url).call().unwrap();
        let get = |n: &str| {
            resp.headers()
                .get(n)
                .map(|v| v.to_str().unwrap().to_owned())
        };
        (get("etag"), get("last-modified"))
    })
    .await
    .unwrap();

    let out_dir = tempfile::tempdir().unwrap();
    let dest = out_dir.path().join("big.bin");
    let mut part = vec![0u8; data.len()];
    part[..3 * SEGMENT].copy_from_slice(&data[..3 * SEGMENT]);
    std::fs::write(out_dir.path().join("big.bin.part"), &part).unwrap();
    let meta = serde_json::json!({
        "url": url, "etag": etag, "last_modified": last_modified, "total": data.len(),
        "seg": { "version": 1, "size": SEGMENT, "done": [[0, 3]] },
    });
    std::fs::write(out_dir.path().join("big.bin.part.meta"), meta.to_string()).unwrap();

    let before = server.state().metrics.bytes_sent();
    let out = blaze_async(vec!["get".into(), url, "-o".into(), s(&dest)]).await;
    let sent = server.state().metrics.bytes_sent() - before;

    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(stderr(&out).contains("Resuming"), "{}", stderr(&out));
    assert_eq!(std::fs::read(&dest).unwrap(), data);
    assert_eq!(
        sent,
        2 * SEGMENT as u64,
        "only missing segments are fetched"
    );
    assert!(!out_dir.path().join("big.bin.part.meta").exists());
    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn get_falls_back_when_the_origin_does_not_advertise_ranges() {
    use std::io::{BufRead, BufReader, Write};
    let data = pattern(9 * MIB);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let body = data.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut reader = BufReader::new(stream);
            let mut request_line = String::new();
            if reader.read_line(&mut request_line).is_err() {
                continue;
            }
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                    break;
                }
            }
            let mut stream = reader.into_inner();
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nETag: \"v1\"\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(head.as_bytes());
            if request_line.starts_with("GET") {
                let _ = stream.write_all(&body);
            }
        }
    });

    let out_dir = tempfile::tempdir().unwrap();
    let dest = out_dir.path().join("plain.bin");
    let out = blaze_async(vec![
        "get".into(),
        format!("http://{addr}/plain.bin"),
        "-o".into(),
        s(&dest),
    ])
    .await;

    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(!stderr(&out).contains("parts"), "{}", stderr(&out));
    assert_eq!(std::fs::read(&dest).unwrap(), data);
}

#[test]
fn get_rejects_connection_counts_outside_1_to_16() {
    for n in ["0", "17"] {
        let out = blaze()
            .args(["get", "http://127.0.0.1:1/x", "--connections", n])
            .output()
            .unwrap();
        assert_eq!(code(&out), 2, "{n}: {}", stderr(&out));
    }
}
