mod upload_support;

use std::time::Duration;

use tokio::io::AsyncWriteExt;
use upload_support::*;

fn put(path: &str, headers: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
    request("PUT", path, headers, body)
}

fn no_staging_left(dir: &std::path::Path) -> bool {
    dir_names(dir)
        .iter()
        .all(|n| !n.contains(".blaze-part-") && !n.contains(".blaze-resume"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn create_then_readback_with_integrity_headers() {
    let dir = tempfile::tempdir().unwrap();
    let srv = spawn(dir.path(), |_| {}).await;
    let body = b"hello upload".to_vec();
    let r = roundtrip(srv.addr, &put("/__upload__/a.txt", &[], &body)).await;
    assert_eq!(r.status, 201);
    assert_eq!(r.header("content-length"), Some("0"));
    assert_eq!(
        r.header("content-digest"),
        Some(format!("sha-256=:{}:", sha256_b64(&body)).as_str())
    );
    assert!(r.header("etag").is_some_and(|e| e.starts_with('"')));
    assert_eq!(r.header("location"), Some("/a.txt"));
    assert_eq!(std::fs::read(dir.path().join("a.txt")).unwrap(), body);
    assert_eq!(dir_names(dir.path()), ["a.txt"]);
    assert_eq!(srv.state.metrics.stats().bytes_received, body.len() as u64);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nested_names_create_directories_and_are_encoded_in_location() {
    let dir = tempfile::tempdir().unwrap();
    let srv = spawn(dir.path(), |_| {}).await;
    let r = roundtrip(
        srv.addr,
        &put("/__upload__/sub/dir/my%20file.bin", &[], b"x"),
    )
    .await;
    assert_eq!(r.status, 201);
    assert_eq!(r.header("location"), Some("/sub/dir/my%20file.bin"));
    assert_eq!(
        std::fs::read(dir.path().join("sub").join("dir").join("my file.bin")).unwrap(),
        b"x"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn existing_target_conflicts_and_stays_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let srv = spawn(dir.path(), |_| {}).await;
    assert_eq!(
        roundtrip(srv.addr, &put("/__upload__/f", &[], b"first"))
            .await
            .status,
        201
    );
    let r = roundtrip(srv.addr, &put("/__upload__/f", &[], b"second")).await;
    assert_eq!(r.status, 409);
    assert_eq!(std::fs::read(dir.path().join("f")).unwrap(), b"first");
    assert!(no_staging_left(dir.path()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn traversal_attempts_are_forbidden_and_write_nothing_outside() {
    let outer = tempfile::tempdir().unwrap();
    let root = outer.path().join("root");
    std::fs::create_dir_all(&root).unwrap();
    let srv = spawn(&root, |_| {}).await;
    for path in [
        "/__upload__/../evil",
        "/__upload__/%2e%2e/evil",
        "/__upload__/..%2Fevil",
        "/__upload__/a/..%2f..%2fevil",
        "/__upload__/a%5C..%5Cevil",
    ] {
        let r = roundtrip(srv.addr, &put(path, &[], b"pwn")).await;
        assert_eq!(r.status, 403, "{path}");
    }
    assert_eq!(dir_names(outer.path()), ["root"]);
    assert!(dir_names(&root).is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn percent_encoding_is_decoded_exactly_once() {
    let dir = tempfile::tempdir().unwrap();
    let srv = spawn(dir.path(), |_| {}).await;
    let r = roundtrip(srv.addr, &put("/__upload__/%252e%252e", &[], b"x")).await;
    assert_eq!(r.status, 201);
    assert_eq!(dir_names(dir.path()), ["%2e%2e"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_names_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let srv = spawn(dir.path(), |_| {}).await;
    for (path, want) in [
        ("/__upload__/", 400),
        ("/__upload__/%00x", 400),
        ("/__upload__/%ff", 400),
        ("/__upload__/.x.blaze-resume", 400),
        ("/__upload__/.x.blaze-part-abc", 400),
    ] {
        assert_eq!(
            roundtrip(srv.addr, &put(path, &[], b"x")).await.status,
            want,
            "{path}"
        );
    }
    assert!(dir_names(dir.path()).is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn content_length_rules() {
    let dir = tempfile::tempdir().unwrap();
    let srv = spawn(dir.path(), |c| c.max_upload_bytes = 10).await;

    let missing = b"PUT /__upload__/a HTTP/1.1\r\nHost: x\r\n\r\n".to_vec();
    assert_eq!(roundtrip(srv.addr, &missing).await.status, 411);

    let chunked = b"PUT /__upload__/a HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n0\r\n\r\n".to_vec();
    assert_eq!(roundtrip(srv.addr, &chunked).await.status, 411);

    let invalid = put("/__upload__/a", &[("Content-Length", "abc")], b"");
    assert_eq!(roundtrip(srv.addr, &invalid).await.status, 400);

    let negative = put("/__upload__/a", &[("Content-Length", "-5")], b"");
    assert_eq!(roundtrip(srv.addr, &negative).await.status, 400);

    let too_big = put("/__upload__/a", &[], &[0u8; 11]);
    assert_eq!(roundtrip(srv.addr, &too_big).await.status, 413);

    assert_eq!(
        roundtrip(srv.addr, &put("/__upload__/ok", &[], &[0u8; 10]))
            .await
            .status,
        201
    );
    assert_eq!(dir_names(dir.path()), ["ok"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn empty_upload_creates_empty_file() {
    let dir = tempfile::tempdir().unwrap();
    let srv = spawn(dir.path(), |_| {}).await;
    assert_eq!(
        roundtrip(srv.addr, &put("/__upload__/empty", &[], b""))
            .await
            .status,
        201
    );
    assert_eq!(
        std::fs::metadata(dir.path().join("empty")).unwrap().len(),
        0
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn short_body_leaves_no_file_and_counts_only_accepted_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let srv = spawn(dir.path(), |_| {}).await;
    {
        let mut c = Conn::open(srv.addr).await;
        let head = request(
            "PUT",
            "/__upload__/short",
            &[("Content-Length", "100")],
            b"",
        );
        c.send(&head).await;
        c.send(b"only ten b").await;
        c.stream.shutdown().await.unwrap();
    }
    wait_until("partial upload cleanup", || {
        dir_names(dir.path()).is_empty()
    })
    .await;
    assert!(!dir.path().join("short").exists());
    wait_until("accepted bytes counted", || {
        srv.state.metrics.stats().bytes_received == 10
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn digest_verification() {
    let dir = tempfile::tempdir().unwrap();
    let srv = spawn(dir.path(), |_| {}).await;
    let body = b"verified bytes";
    let good = format!("sha-256=:{}:", sha256_b64(body));
    let r = roundtrip(
        srv.addr,
        &put("/__upload__/ok", &[("Content-Digest", &good)], body),
    )
    .await;
    assert_eq!(r.status, 201);

    let hex: String = {
        use sha2::{Digest, Sha256};
        Sha256::digest(body)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    };
    let r = roundtrip(
        srv.addr,
        &put("/__upload__/hex", &[("X-Content-SHA256", &hex)], body),
    )
    .await;
    assert_eq!(r.status, 201);

    let r = roundtrip(
        srv.addr,
        &put(
            "/__upload__/legacy",
            &[("Digest", &format!("md5=zz, sha-256={}", sha256_b64(body)))],
            body,
        ),
    )
    .await;
    assert_eq!(r.status, 201);

    let wrong = format!("sha-256=:{}:", sha256_b64(b"something else"));
    let r = roundtrip(
        srv.addr,
        &put("/__upload__/bad", &[("Content-Digest", &wrong)], body),
    )
    .await;
    assert_eq!(r.status, 422);
    assert!(!dir.path().join("bad").exists());

    let r = roundtrip(
        srv.addr,
        &put(
            "/__upload__/mal",
            &[("Content-Digest", "sha-256=:AAAA:")],
            body,
        ),
    )
    .await;
    assert_eq!(r.status, 400);
    assert!(!dir.path().join("mal").exists());

    assert!(no_staging_left(dir.path()));
    assert_eq!(dir_names(dir.path()), ["hex", "legacy", "ok"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_writers_produce_exactly_one_winner() {
    let dir = tempfile::tempdir().unwrap();
    let srv = spawn(dir.path(), |_| {}).await;
    let addr = srv.addr;
    let mut tasks = Vec::new();
    for i in 0..8u8 {
        tasks.push(tokio::spawn(async move {
            let body = vec![i; 256 * 1024];
            let r = roundtrip(addr, &put("/__upload__/race.bin", &[], &body)).await;
            (i, r.status)
        }));
    }
    let mut winners = Vec::new();
    for t in tasks {
        let (i, status) = t.await.unwrap();
        match status {
            201 => winners.push(i),
            409 => {}
            other => panic!("unexpected status {other}"),
        }
    }
    assert_eq!(winners.len(), 1, "{winners:?}");
    let stored = std::fs::read(dir.path().join("race.bin")).unwrap();
    assert_eq!(stored, vec![winners[0]; 256 * 1024]);
    wait_until("staging cleanup", || no_staging_left(dir.path())).await;
    assert_eq!(dir_names(dir.path()), ["race.bin"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn conditional_replace_requires_current_etag() {
    let dir = tempfile::tempdir().unwrap();
    let srv = spawn(dir.path(), |_| {}).await;
    let created = roundtrip(srv.addr, &put("/__upload__/doc", &[], b"v1")).await;
    let etag = created.header("etag").unwrap().to_owned();

    let stale = roundtrip(
        srv.addr,
        &put("/__upload__/doc", &[("If-Match", "\"stale\"")], b"v2"),
    )
    .await;
    assert_eq!(stale.status, 412);
    assert_eq!(std::fs::read(dir.path().join("doc")).unwrap(), b"v1");

    let missing = roundtrip(
        srv.addr,
        &put("/__upload__/nothing", &[("If-Match", &etag)], b"v2"),
    )
    .await;
    assert_eq!(missing.status, 412);
    assert!(!dir.path().join("nothing").exists());

    let wildcard = roundtrip(
        srv.addr,
        &put("/__upload__/doc", &[("If-Match", "*")], b"v2"),
    )
    .await;
    assert_eq!(wildcard.status, 400);
    assert_eq!(std::fs::read(dir.path().join("doc")).unwrap(), b"v1");

    let ok = roundtrip(
        srv.addr,
        &put("/__upload__/doc", &[("If-Match", &etag)], b"version two"),
    )
    .await;
    assert_eq!(ok.status, 200);
    assert_eq!(
        std::fs::read(dir.path().join("doc")).unwrap(),
        b"version two"
    );
    let new_etag = ok.header("etag").unwrap().to_owned();
    assert_ne!(new_etag, etag);

    let replay = roundtrip(
        srv.addr,
        &put("/__upload__/doc", &[("If-Match", &etag)], b"v3"),
    )
    .await;
    assert_eq!(
        replay.status, 412,
        "the old validator must not replace the new version"
    );
    assert_eq!(
        std::fs::read(dir.path().join("doc")).unwrap(),
        b"version two"
    );
    assert!(no_staging_left(dir.path()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejected_request_closes_connection_so_body_cannot_desync() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("taken"), b"x").unwrap();
    let srv = spawn(dir.path(), |_| {}).await;
    let mut c = Conn::open(srv.addr).await;
    let smuggled = b"GET /__upload__/pwned HTTP/1.1\r\nHost: x\r\n\r\n";
    let mut body = b"ignored".to_vec();
    body.extend_from_slice(smuggled);
    c.send(&put("/__upload__/taken", &[], &body)).await;
    let r = c.read_response(false).await;
    assert_eq!(r.status, 409);
    assert_eq!(r.header("connection"), Some("close"));
    assert!(c.is_closed_by_peer().await);
    assert!(!dir.path().join("pwned").exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn keep_alive_connection_serves_consecutive_uploads() {
    let dir = tempfile::tempdir().unwrap();
    let srv = spawn(dir.path(), |_| {}).await;
    let mut c = Conn::open(srv.addr).await;
    for name in ["one", "two", "three"] {
        c.send(&put(&format!("/__upload__/{name}"), &[], name.as_bytes()))
            .await;
        assert_eq!(c.read_response(false).await.status, 201);
    }
    assert_eq!(dir_names(dir.path()), ["one", "three", "two"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unsupported_method_lists_allowed_ones() {
    let dir = tempfile::tempdir().unwrap();
    let srv = spawn(dir.path(), |_| {}).await;
    let r = roundtrip(srv.addr, &request("PATCH", "/__upload__/x", &[], b"")).await;
    assert_eq!(r.status, 405);
    assert!(r.header("allow").is_some_and(|a| a.contains("PUT")));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upload_through_symlinked_parent_is_forbidden() {
    let outer = tempfile::tempdir().unwrap();
    let root = outer.path().join("root");
    let outside = outer.path().join("outside");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    if !symlink_dir(&outside, &root.join("link")) {
        eprintln!("skipped: directory symlink creation is not permitted in this environment");
        return;
    }
    let srv = spawn(&root, |_| {}).await;
    let r = roundtrip(srv.addr, &put("/__upload__/link/pwn.txt", &[], b"pwn")).await;
    assert_eq!(r.status, 403);
    assert!(dir_names(&outside).is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn resumable_upload_flow() {
    let dir = tempfile::tempdir().unwrap();
    let srv = spawn(dir.path(), |_| {}).await;
    let full = b"0123456789";

    let status = roundtrip(srv.addr, &request("HEAD", "/__upload__/r.bin", &[], b"")).await;
    assert_eq!(status.status, 404);

    let first = roundtrip(
        srv.addr,
        &put(
            "/__upload__/r.bin",
            &[("Content-Range", "bytes 0-4/10")],
            &full[..5],
        ),
    )
    .await;
    assert_eq!(first.status, 202);
    assert_eq!(first.header("upload-offset"), Some("5"));
    assert!(!dir.path().join("r.bin").exists());

    let status = roundtrip(srv.addr, &request("HEAD", "/__upload__/r.bin", &[], b"")).await;
    assert_eq!(status.status, 200);
    assert_eq!(status.header("upload-offset"), Some("5"));
    assert_eq!(status.header("upload-complete"), Some("?0"));

    let replay = roundtrip(
        srv.addr,
        &put(
            "/__upload__/r.bin",
            &[("Content-Range", "bytes 0-4/10")],
            &full[..5],
        ),
    )
    .await;
    assert_eq!(replay.status, 409);
    assert_eq!(replay.header("upload-offset"), Some("5"));

    let gap = roundtrip(
        srv.addr,
        &put(
            "/__upload__/r.bin",
            &[("Content-Range", "bytes 7-9/10")],
            &full[7..],
        ),
    )
    .await;
    assert_eq!(gap.status, 409);
    assert_eq!(gap.header("upload-offset"), Some("5"));

    let repr = format!("sha-256=:{}:", sha256_b64(full));
    let last = roundtrip(
        srv.addr,
        &put(
            "/__upload__/r.bin",
            &[("Content-Range", "bytes 5-9/10"), ("Repr-Digest", &repr)],
            &full[5..],
        ),
    )
    .await;
    assert_eq!(last.status, 201);
    assert_eq!(
        last.header("content-digest"),
        Some(format!("sha-256=:{}:", sha256_b64(full)).as_str())
    );
    assert_eq!(std::fs::read(dir.path().join("r.bin")).unwrap(), full);
    assert_eq!(dir_names(dir.path()), ["r.bin"]);

    let done = roundtrip(srv.addr, &request("HEAD", "/__upload__/r.bin", &[], b"")).await;
    assert_eq!(done.header("upload-complete"), Some("?1"));
    assert_eq!(done.header("upload-offset"), Some("10"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn interrupted_chunk_keeps_accepted_prefix_for_resume() {
    let dir = tempfile::tempdir().unwrap();
    let srv = spawn(dir.path(), |_| {}).await;
    let data: Vec<u8> = (0..20u8).collect();
    {
        let mut c = Conn::open(srv.addr).await;
        let head = request(
            "PUT",
            "/__upload__/big",
            &[("Content-Range", "bytes 0-19/20"), ("Content-Length", "20")],
            b"",
        );
        c.send(&head).await;
        c.send(&data[..6]).await;
        c.stream.shutdown().await.unwrap();
    }
    let probe =
        || async { roundtrip(srv.addr, &request("HEAD", "/__upload__/big", &[], b"")).await };
    let mut offset = String::new();
    for _ in 0..200 {
        let r = probe().await;
        if r.status == 200 && r.header("upload-offset") == Some("6") {
            offset = "6".into();
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(offset, "6", "accepted prefix must be reported");

    let rest = roundtrip(
        srv.addr,
        &put(
            "/__upload__/big",
            &[("Content-Range", "bytes 6-19/20")],
            &data[6..],
        ),
    )
    .await;
    assert_eq!(rest.status, 201);
    assert_eq!(std::fs::read(dir.path().join("big")).unwrap(), data);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn resumable_digest_failures_roll_back_correctly() {
    let dir = tempfile::tempdir().unwrap();
    let srv = spawn(dir.path(), |_| {}).await;
    let wrong = format!("sha-256=:{}:", sha256_b64(b"nope"));

    let bad_chunk = roundtrip(
        srv.addr,
        &put(
            "/__upload__/d",
            &[("Content-Range", "bytes 0-3/8"), ("Content-Digest", &wrong)],
            b"abcd",
        ),
    )
    .await;
    assert_eq!(bad_chunk.status, 422);
    let st = roundtrip(srv.addr, &request("HEAD", "/__upload__/d", &[], b"")).await;
    assert_eq!(
        st.header("upload-offset"),
        Some("0"),
        "bad chunk must be rolled back"
    );

    assert_eq!(
        roundtrip(
            srv.addr,
            &put(
                "/__upload__/d",
                &[("Content-Range", "bytes 0-3/8")],
                b"abcd"
            )
        )
        .await
        .status,
        202
    );
    let bad_whole = roundtrip(
        srv.addr,
        &put(
            "/__upload__/d",
            &[("Content-Range", "bytes 4-7/8"), ("Repr-Digest", &wrong)],
            b"efgh",
        ),
    )
    .await;
    assert_eq!(bad_whole.status, 422);
    assert!(!dir.path().join("d").exists());
    assert!(no_staging_left(dir.path()), "{:?}", dir_names(dir.path()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn resumable_validation_and_abort() {
    let dir = tempfile::tempdir().unwrap();
    let srv = spawn(dir.path(), |c| c.max_upload_bytes = 100).await;

    let mismatch = roundtrip(
        srv.addr,
        &put(
            "/__upload__/v",
            &[("Content-Range", "bytes 0-4/10")],
            b"abc",
        ),
    )
    .await;
    assert_eq!(mismatch.status, 400);
    let junk = roundtrip(
        srv.addr,
        &put(
            "/__upload__/v",
            &[("Content-Range", "bytes 0-4/*")],
            b"abcde",
        ),
    )
    .await;
    assert_eq!(junk.status, 400);
    let big = roundtrip(
        srv.addr,
        &put(
            "/__upload__/v",
            &[("Content-Range", "bytes 0-4/1000")],
            b"abcde",
        ),
    )
    .await;
    assert_eq!(big.status, 413);
    let no_start = roundtrip(
        srv.addr,
        &put(
            "/__upload__/v",
            &[("Content-Range", "bytes 5-9/10")],
            b"abcde",
        ),
    )
    .await;
    assert_eq!(no_start.status, 409);
    assert_eq!(no_start.header("upload-offset"), Some("0"));

    assert_eq!(
        roundtrip(
            srv.addr,
            &put(
                "/__upload__/v",
                &[("Content-Range", "bytes 0-4/10")],
                b"abcde"
            )
        )
        .await
        .status,
        202
    );
    assert_eq!(
        roundtrip(srv.addr, &request("DELETE", "/__upload__/v", &[], b""))
            .await
            .status,
        204
    );
    assert_eq!(
        roundtrip(srv.addr, &request("DELETE", "/__upload__/v", &[], b""))
            .await
            .status,
        404
    );
    assert!(dir_names(dir.path()).is_empty());

    std::fs::write(dir.path().join("final"), b"keep").unwrap();
    assert_eq!(
        roundtrip(srv.addr, &request("DELETE", "/__upload__/final", &[], b""))
            .await
            .status,
        404
    );
    assert_eq!(std::fs::read(dir.path().join("final")).unwrap(), b"keep");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn resumable_replace_honours_if_match() {
    let dir = tempfile::tempdir().unwrap();
    let srv = spawn(dir.path(), |_| {}).await;
    let created = roundtrip(srv.addr, &put("/__upload__/doc", &[], b"old")).await;
    let etag = created.header("etag").unwrap().to_owned();

    let no_match = roundtrip(
        srv.addr,
        &put(
            "/__upload__/doc",
            &[("Content-Range", "bytes 0-2/3")],
            b"new",
        ),
    )
    .await;
    assert_eq!(no_match.status, 409);

    let stale = roundtrip(
        srv.addr,
        &put(
            "/__upload__/doc",
            &[("Content-Range", "bytes 0-2/6"), ("If-Match", "\"stale\"")],
            b"new",
        ),
    )
    .await;
    assert_eq!(stale.status, 412);

    let a = roundtrip(
        srv.addr,
        &put(
            "/__upload__/doc",
            &[("Content-Range", "bytes 0-2/6"), ("If-Match", &etag)],
            b"new",
        ),
    )
    .await;
    assert_eq!(a.status, 202);
    let b = roundtrip(
        srv.addr,
        &put(
            "/__upload__/doc",
            &[("Content-Range", "bytes 3-5/6"), ("If-Match", &etag)],
            b"ish",
        ),
    )
    .await;
    assert_eq!(b.status, 200);
    assert_eq!(std::fs::read(dir.path().join("doc")).unwrap(), b"newish");
    assert!(no_staging_left(dir.path()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn default_config_refuses_every_upload_request() {
    let dir = tempfile::tempdir().unwrap();
    let srv = spawn_unmodified(dir.path(), |_| {}).await;
    assert_eq!(srv.state.config.max_upload_bytes, 0);

    for raw in [
        put("/__upload__/a", &[], b"data"),
        request("POST", "/__upload__/a", &[], b"data"),
        request("GET", "/__upload__/a", &[], b""),
        request("DELETE", "/__upload__/a", &[], b""),
    ] {
        let r = roundtrip(srv.addr, &raw).await;
        assert_eq!(r.status, 403);
        assert_eq!(r.header("connection"), Some("close"));
        assert_eq!(String::from_utf8_lossy(&r.body), "Uploads are disabled");
    }
    let head = roundtrip(srv.addr, &request("HEAD", "/__upload__/a", &[], b"")).await;
    assert_eq!(head.status, 403);

    let mut c = Conn::open(srv.addr).await;
    let mut body = b"x".to_vec();
    body.extend_from_slice(
        b"PUT /__upload__/pwned HTTP/1.1\r\nHost: x\r\nContent-Length: 1\r\n\r\nz",
    );
    c.send(&put("/__upload__/a", &[], &body)).await;
    assert_eq!(c.read_response(false).await.status, 403);
    assert!(c.is_closed_by_peer().await);

    assert!(dir_names(dir.path()).is_empty());
    assert_eq!(srv.state.metrics.stats().bytes_received, 0);
}
