mod upload_support;

use std::io::{Cursor, Read};
use std::time::Duration;

use upload_support::*;

fn get(path: &str) -> Vec<u8> {
    request("GET", path, &[], b"")
}

fn read_zip(bytes: Vec<u8>) -> Vec<(String, Vec<u8>)> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).expect("valid archive");
    let mut out = Vec::new();
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).expect("entry");
        let mut data = Vec::new();
        entry.read_to_end(&mut data).expect("crc-checked read");
        out.push((entry.name().expect("utf-8 entry name").into_owned(), data));
    }
    out.sort();
    out
}

fn tree(root: &std::path::Path) {
    std::fs::create_dir_all(root.join("docs").join("deep")).unwrap();
    std::fs::write(root.join("top.txt"), b"top").unwrap();
    std::fs::write(root.join("docs").join("a.md"), b"alpha").unwrap();
    std::fs::write(
        root.join("docs").join("deep").join("b.bin"),
        [0u8, 1, 2, 255],
    )
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn directory_archive_has_headers_and_all_files() {
    let dir = tempfile::tempdir().unwrap();
    tree(dir.path());
    let srv = spawn(dir.path(), |_| {}).await;
    let r = roundtrip(srv.addr, &get("/__zip__?path=docs")).await;
    assert_eq!(r.status, 200);
    assert_eq!(r.header("content-type"), Some("application/zip"));
    assert_eq!(r.header("connection"), Some("close"));
    assert_eq!(
        r.header("content-disposition"),
        Some("attachment; filename=\"docs.zip\"")
    );
    assert_eq!(r.header("cache-control"), Some("no-store"));
    let sent = r.body.len() as u64;
    assert_eq!(
        read_zip(r.body),
        [
            ("a.md".to_owned(), b"alpha".to_vec()),
            ("deep/b.bin".to_owned(), vec![0, 1, 2, 255]),
        ]
    );
    wait_until("bytes_sent accounting", || {
        srv.state.metrics.stats().bytes_sent == sent
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn root_and_single_file_archives() {
    let dir = tempfile::tempdir().unwrap();
    tree(dir.path());
    let srv = spawn(dir.path(), |_| {}).await;
    let root = roundtrip(srv.addr, &get("/__zip__?path=.")).await;
    assert_eq!(root.status, 200);
    let names: Vec<String> = read_zip(root.body).into_iter().map(|(n, _)| n).collect();
    assert_eq!(names, ["docs/a.md", "docs/deep/b.bin", "top.txt"]);

    let single = roundtrip(srv.addr, &get("/__zip__?path=top.txt")).await;
    assert_eq!(single.status, 200);
    assert_eq!(
        read_zip(single.body),
        [("top.txt".to_owned(), b"top".to_vec())]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn head_returns_headers_without_body() {
    let dir = tempfile::tempdir().unwrap();
    tree(dir.path());
    let srv = spawn(dir.path(), |_| {}).await;
    let r = roundtrip(srv.addr, &request("HEAD", "/__zip__?path=docs", &[], b"")).await;
    assert_eq!(r.status, 200);
    assert_eq!(r.header("content-type"), Some("application/zip"));
    assert!(r.body.is_empty());
    assert_eq!(srv.state.metrics.stats().bytes_sent, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bad_requests_follow_documented_statuses() {
    let outer = tempfile::tempdir().unwrap();
    let root = outer.path().join("root");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(outer.path().join("secret.txt"), b"s").unwrap();
    let srv = spawn(&root, |_| {}).await;
    for (path, want) in [
        ("/__zip__", 400),
        ("/__zip__?path=", 400),
        ("/__zip__?path=..", 403),
        ("/__zip__?path=%2e%2e", 403),
        ("/__zip__?path=..%2fsecret.txt", 403),
        ("/__zip__?path=a%5C..%5C..", 403),
        ("/__zip__?path=missing", 404),
        ("/__zip__?path=%00", 400),
    ] {
        assert_eq!(roundtrip(srv.addr, &get(path)).await.status, want, "{path}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sibling_prefix_directory_is_not_reachable() {
    let outer = tempfile::tempdir().unwrap();
    let root = outer.path().join("root");
    let evil = outer.path().join("root-evil");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::create_dir_all(&evil).unwrap();
    std::fs::write(evil.join("s"), b"s").unwrap();
    let srv = spawn(&root, |_| {}).await;
    let r = roundtrip(srv.addr, &get("/__zip__?path=..%2Froot-evil")).await;
    assert_eq!(r.status, 403);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn symlinks_leaving_the_root_are_not_archived() {
    let outer = tempfile::tempdir().unwrap();
    let root = outer.path().join("root");
    let outside = outer.path().join("outside");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("secret.txt"), b"secret").unwrap();
    std::fs::write(root.join("inside.txt"), b"inside").unwrap();
    let dir_link = symlink_dir(&outside, &root.join("dirlink"));
    let file_link = symlink_file(&outside.join("secret.txt"), &root.join("filelink.txt"));
    if !dir_link && !file_link {
        eprintln!("skipped: symlink creation is not permitted in this environment");
        return;
    }
    let srv = spawn(&root, |_| {}).await;
    let r = roundtrip(srv.addr, &get("/__zip__?path=.")).await;
    assert_eq!(r.status, 200);
    let entries = read_zip(r.body);
    assert_eq!(entries, [("inside.txt".to_owned(), b"inside".to_vec())]);
    if dir_link {
        assert_eq!(
            roundtrip(srv.addr, &get("/__zip__?path=dirlink"))
                .await
                .status,
            403
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unusual_names_are_sanitized_in_content_disposition() {
    let dir = tempfile::tempdir().unwrap();
    let folder = dir.path().join("my;dir x");
    std::fs::create_dir_all(&folder).unwrap();
    std::fs::write(folder.join("f"), b"1").unwrap();
    let srv = spawn(dir.path(), |_| {}).await;
    let r = roundtrip(srv.addr, &get("/__zip__?path=my%3Bdir+x")).await;
    assert_eq!(r.status, 200);
    assert_eq!(
        r.header("content-disposition"),
        Some("attachment; filename=\"mydir x.zip\"")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_disconnect_stops_generation_and_frees_capacity() {
    let dir = tempfile::tempdir().unwrap();
    let size: usize = 48 * 1024 * 1024;
    {
        use std::io::Write;
        let mut f = std::fs::File::create(dir.path().join("big.bin")).unwrap();
        let block = vec![7u8; 1024 * 1024];
        for _ in 0..size / block.len() {
            f.write_all(&block).unwrap();
        }
    }
    let srv = spawn(dir.path(), |_| {}).await;
    {
        let mut c = Conn::open(srv.addr).await;
        c.send(&get("/__zip__?path=big.bin")).await;
        use tokio::io::AsyncReadExt;
        let mut first = [0u8; 4096];
        c.stream.read_exact(&mut first).await.unwrap();
    }
    let mut previous = u64::MAX;
    for _ in 0..200 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        let now = srv.state.metrics.stats().bytes_sent;
        if now == previous {
            break;
        }
        previous = now;
    }
    let delivered = srv.state.metrics.stats().bytes_sent;
    assert!(
        delivered < size as u64 / 2,
        "generation must abort, delivered {delivered}"
    );

    let again = roundtrip(srv.addr, &get("/__zip__?path=top-missing")).await;
    assert_eq!(again.status, 404);
    std::fs::write(dir.path().join("small.txt"), b"ok").unwrap();
    let ok = roundtrip(srv.addr, &get("/__zip__?path=small.txt")).await;
    assert_eq!(ok.status, 200);
    assert_eq!(
        read_zip(ok.body),
        [("small.txt".to_owned(), b"ok".to_vec())]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn large_file_round_trips_through_streaming_writer() {
    let dir = tempfile::tempdir().unwrap();
    let data: Vec<u8> = (0..3_000_000u32).map(|i| (i % 251) as u8).collect();
    std::fs::write(dir.path().join("blob"), &data).unwrap();
    let srv = spawn(dir.path(), |_| {}).await;
    let r = roundtrip(srv.addr, &get("/__zip__?path=blob")).await;
    assert_eq!(r.status, 200);
    assert_eq!(read_zip(r.body), [("blob".to_owned(), data)]);
}
