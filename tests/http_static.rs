mod http_common;

use http_common::*;

macro_rules! server_test {
    ($name:ident, $body:expr) => {
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn $name() {
            let run: fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = ()>>> =
                || Box::pin($body);
            run().await;
        }
    };
}

server_test!(serves_file_with_exact_bytes_and_headers, async {
    let fx = start().await;
    let r = fx.get("/hello.txt");
    assert_eq!(r.status, 200);
    assert_eq!(r.body, HELLO);
    assert_eq!(r.header("content-length"), Some("18"));
    assert_eq!(r.header("content-type"), Some("text/plain"));
    assert_eq!(r.header("accept-ranges"), Some("bytes"));
    fx.stop().await;
});

server_test!(serves_nested_file_and_ignores_query, async {
    let fx = start().await;
    let r = fx.get("/sub/nested.txt?cache=bust");
    assert_eq!((r.status, r.body.as_slice()), (200, b"nested".as_slice()));
    fx.stop().await;
});

server_test!(missing_file_is_404, async {
    let fx = start().await;
    assert_eq!(fx.get("/nope.txt").status, 404);
    fx.stop().await;
});

server_test!(percent_encoded_names_resolve, async {
    let fx = start().await;
    std::fs::write(fx.path("with space.txt"), b"spaced").unwrap();
    let r = fx.get("/with%20space.txt");
    assert_eq!((r.status, r.body.as_slice()), (200, b"spaced".as_slice()));
    fx.stop().await;
});

server_test!(traversal_attempts_never_escape_the_root, async {
    let outer = tempfile::tempdir().unwrap();
    let outer_root = outer.path().canonicalize().unwrap();
    std::fs::write(outer_root.join("secret.txt"), b"TOP-SECRET").unwrap();
    let served = outer_root.join("served");
    std::fs::create_dir(&served).unwrap();
    std::fs::write(served.join("ok.txt"), b"ok").unwrap();
    let evil_sibling = outer_root.join("served-evil");
    std::fs::create_dir(&evil_sibling).unwrap();
    std::fs::write(evil_sibling.join("loot.txt"), b"LOOT").unwrap();

    let fx = start_with(|_, c| c.base = served.clone()).await;
    let attempts = [
        "/../secret.txt",
        "/%2e%2e/secret.txt",
        "/%2E%2E%2Fsecret.txt",
        "/sub/../../secret.txt",
        "/..%2fsecret.txt",
        "/../served-evil/loot.txt",
        "/%252e%252e/secret.txt",
        "/..\\secret.txt",
        "/%5c..%5csecret.txt",
        "/ok.txt%00.png",
    ];
    for path in attempts {
        let r = fx.get(path);
        assert!(
            matches!(r.status, 400 | 403 | 404),
            "{path} -> {}",
            r.status
        );
        let text = r.text();
        assert!(
            !text.contains("TOP-SECRET") && !text.contains("LOOT"),
            "{path} leaked content"
        );
    }
    assert_eq!(fx.get("/ok.txt").status, 200);
    fx.stop().await;
});

server_test!(symlink_escape_is_refused, async {
    let outer = tempfile::tempdir().unwrap();
    let outer_root = outer.path().canonicalize().unwrap();
    let outside = outer_root.join("outside");
    std::fs::create_dir(&outside).unwrap();
    std::fs::write(outside.join("secret.txt"), b"TOP-SECRET").unwrap();
    let served = outer_root.join("served");
    std::fs::create_dir(&served).unwrap();

    #[cfg(unix)]
    let linked = std::os::unix::fs::symlink(&outside, served.join("link")).is_ok();
    #[cfg(windows)]
    let linked = std::os::windows::fs::symlink_dir(&outside, served.join("link")).is_ok();
    if !linked {
        eprintln!("skipped: this account cannot create symlinks");
        return;
    }

    let fx = start_with(|_, c| c.base = served.clone()).await;
    let r = fx.get("/link/secret.txt");
    assert_eq!(r.status, 403);
    assert!(!r.text().contains("TOP-SECRET"));
    let listing = fx.get_with("/", &[("Accept", "application/json")]);
    assert!(
        !listing.text().contains("link"),
        "escaping symlink must not be listed"
    );
    fx.stop().await;
});

server_test!(directory_listing_html_escapes_names, async {
    let fx = start().await;
    std::fs::write(fx.path("a&b.txt"), b"x").unwrap();
    let r = fx.get("/");
    assert_eq!(r.status, 200);
    assert!(r.header("content-type").unwrap().starts_with("text/html"));
    let html = r.text();
    assert!(html.contains("hello.txt"));
    assert!(html.contains("a&amp;b.txt"));
    assert!(!html.contains(">a&b.txt<"));
    fx.stop().await;
});

server_test!(directory_listing_json_when_requested, async {
    let fx = start().await;
    let r = fx.get_with("/", &[("Accept", "application/json")]);
    assert_eq!(r.status, 200);
    assert!(
        r.header("content-type")
            .unwrap()
            .starts_with("application/json")
    );
    let doc = r.json();
    let entries = doc["entries"].as_array().unwrap();
    assert_eq!(entries[0]["name"], "sub");
    assert_eq!(entries[0]["type"], "directory");
    let hello = entries.iter().find(|e| e["name"] == "hello.txt").unwrap();
    assert_eq!(hello["size"], 18);
    assert_eq!(doc["path"], "/");
    fx.stop().await;
});

server_test!(nested_listing_links_to_parent, async {
    let fx = start().await;
    let r = fx.get("/sub/");
    assert_eq!(r.status, 200);
    assert!(r.text().contains("nested.txt"));
    fx.stop().await;
});

server_test!(no_listing_forbids_directories_but_serves_files, async {
    let fx = start_with(|_, c| c.listing = false).await;
    assert_eq!(fx.get("/").status, 403);
    assert_eq!(fx.get("/sub/").status, 403);
    assert_eq!(fx.get("/hello.txt").status, 200);
    fx.stop().await;
});

server_test!(index_html_is_served_for_directories, async {
    let fx = start().await;
    std::fs::write(fx.path("sub/index.html"), b"<h1>home</h1>").unwrap();
    let r = fx.get("/sub/");
    assert_eq!(
        (r.status, r.body.as_slice()),
        (200, b"<h1>home</h1>".as_slice())
    );
    assert_eq!(r.header("content-type"), Some("text/html"));
    fx.stop().await;
});

server_test!(custom_index_names_are_tried, async {
    let fx = start_with(|_, c| c.index = vec!["start.txt".into()]).await;
    std::fs::write(fx.path("sub/start.txt"), b"custom").unwrap();
    assert_eq!(fx.get("/sub/").body, b"custom");
    fx.stop().await;
});

server_test!(single_file_mode_serves_only_that_file, async {
    let fx = start_with(|root, c| c.single = Some(root.join("hello.txt"))).await;
    for path in ["/", "/anything", "/hello.txt"] {
        let r = fx.get(path);
        assert_eq!((r.status, r.body.as_slice()), (200, HELLO), "{path}");
    }
    assert_eq!(fx.get("/__live__").status, 200);
    fx.stop().await;
});

server_test!(head_matches_get_without_a_body, async {
    let fx = start().await;
    for path in ["/hello.txt", "/", "/missing.txt", "/__health__"] {
        let get = fx.get(path);
        let head = fx.head(path, &[]);
        assert_eq!(head.status, get.status, "{path}");
        assert!(head.body.is_empty(), "{path}");
        for name in [
            "content-length",
            "content-type",
            "etag",
            "last-modified",
            "cache-control",
            "accept-ranges",
        ] {
            assert_eq!(head.header(name), get.header(name), "{path} {name}");
        }
    }
    fx.stop().await;
});

server_test!(download_query_sets_attachment_disposition, async {
    let fx = start().await;
    let r = fx.get("/hello.txt?download=1");
    let disposition = r.header("content-disposition").unwrap();
    assert!(
        disposition.starts_with("attachment; filename=\"hello.txt\""),
        "{disposition}"
    );
    assert!(fx.get("/hello.txt").header("content-disposition").is_none());
    fx.stop().await;
});

server_test!(security_headers_are_on_every_response, async {
    let fx = start().await;
    for path in ["/hello.txt", "/missing", "/", "/__live__", "/__metrics__"] {
        let r = fx.get(path);
        assert_eq!(
            r.header("x-content-type-options"),
            Some("nosniff"),
            "{path}"
        );
        assert_eq!(r.header("x-frame-options"), Some("DENY"), "{path}");
        assert!(
            r.header("referrer-policy")
                .unwrap()
                .contains("strict-origin"),
            "{path}"
        );
        assert!(
            r.header("permissions-policy")
                .unwrap()
                .contains("camera=()"),
            "{path}"
        );
        assert!(
            r.header("strict-transport-security").is_none(),
            "{path} HSTS on plain HTTP"
        );
        assert!(r.header("x-request-id").is_some(), "{path}");
    }
    fx.stop().await;
});

server_test!(request_id_is_validated_and_echoed_per_request, async {
    let fx = start().await;
    let mut conn = fx.conn();
    let first = conn.send("GET", "/hello.txt", &[("X-Request-ID", "first-request")]);
    let second = conn.send("GET", "/hello.txt", &[("X-Request-ID", "second-request")]);
    assert_eq!(first.header("x-request-id"), Some("first-request"));
    assert_eq!(second.header("x-request-id"), Some("second-request"));

    for bad in ["bad id!", "a_b", &"x".repeat(65), "---"] {
        let r = fx.get_with("/hello.txt", &[("X-Request-ID", bad)]);
        let id = r.header("x-request-id").unwrap();
        assert_ne!(id, bad);
        assert_eq!(id.len(), 12, "{id}");
        assert!(id.bytes().all(|b| b.is_ascii_hexdigit()));
    }
    let generated = fx.get("/hello.txt");
    assert_eq!(generated.header("x-request-id").unwrap().len(), 12);
    fx.stop().await;
});

server_test!(unsupported_methods_get_405_with_allow, async {
    let fx = start().await;
    for method in ["DELETE", "PATCH", "TRACE"] {
        let r = request(fx.addr, method, "/hello.txt", &[]);
        assert_eq!(r.status, 405, "{method}");
        assert!(r.header("allow").unwrap().contains("GET"));
    }
    fx.stop().await;
});

server_test!(put_outside_upload_prefix_is_rejected_and_closes, async {
    let fx = start().await;
    let r = request(fx.addr, "PUT", "/hello.txt", &[("Content-Length", "0")]);
    assert_eq!(r.status, 405);
    assert_eq!(r.header("connection"), Some("close"));
    assert_eq!(std::fs::read(fx.path("hello.txt")).unwrap(), HELLO);
    fx.stop().await;
});

server_test!(large_file_streams_intact_across_chunk_boundaries, async {
    let data = pattern(3 * 1024 * 1024 + 4321);
    let expected = data.clone();
    let fx = start_with(move |root, c| {
        std::fs::write(root.join("big.bin"), &data).unwrap();
        c.chunk_bytes = 64 * 1024;
    })
    .await;
    let r = fx.get("/big.bin");
    assert_eq!(r.status, 200);
    assert_eq!(r.body.len(), expected.len());
    assert!(r.body == expected, "body differs from file contents");
    fx.stop().await;
});

server_test!(empty_file_has_zero_length_body, async {
    let fx = start().await;
    std::fs::write(fx.path("empty.txt"), b"").unwrap();
    let r = fx.get("/empty.txt");
    assert_eq!((r.status, r.body.len()), (200, 0));
    assert_eq!(r.header("content-length"), Some("0"));
    fx.stop().await;
});

server_test!(dropped_client_releases_the_active_gauge, async {
    let fx = start().await;
    let mut conn = fx.conn();
    conn.start("GET", "/__speed__?bytes=200000000", &[]);
    let _ = conn.read_some(1024);
    drop(conn);
    let mut active = u64::MAX;
    for _ in 0..100 {
        active = fx.server.state().metrics.requests_active();
        if active == 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert_eq!(
        active, 0,
        "in-flight gauge must return to zero after a disconnect"
    );
    assert_eq!(fx.get("/hello.txt").status, 200);
    fx.stop().await;
});
