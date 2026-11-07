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

fn range(fx: &Fixture, spec: &str) -> Resp {
    fx.get_with("/hello.txt", &[("Range", spec)])
}

server_test!(single_range_returns_206_with_content_range, async {
    let fx = start().await;
    let r = range(&fx, "bytes=0-4");
    assert_eq!(r.status, 206);
    assert_eq!(r.body, b"Hello");
    assert_eq!(r.header("content-range"), Some("bytes 0-4/18"));
    assert_eq!(r.header("content-length"), Some("5"));
    fx.stop().await;
});

server_test!(suffix_and_open_ended_ranges, async {
    let fx = start().await;
    let suffix = range(&fx, "bytes=-5");
    assert_eq!(
        (suffix.status, suffix.body.as_slice()),
        (206, b"erve!".as_slice())
    );
    assert_eq!(suffix.header("content-range"), Some("bytes 13-17/18"));
    let open = range(&fx, "bytes=7-");
    assert_eq!(
        (open.status, open.body.as_slice()),
        (206, b"BlazeServe!".as_slice())
    );
    let clamped = range(&fx, "bytes=0-9999");
    assert_eq!(clamped.body, HELLO);
    assert_eq!(clamped.header("content-range"), Some("bytes 0-17/18"));
    fx.stop().await;
});

server_test!(multipart_has_exact_length_and_structure, async {
    let fx = start().await;
    let r = range(&fx, "bytes=0-4,7-11");
    assert_eq!(r.status, 206);
    let content_type = r.header("content-type").unwrap();
    let boundary = content_type
        .strip_prefix("multipart/byteranges; boundary=")
        .expect("multipart type");
    assert_eq!(
        r.header("content-length")
            .unwrap()
            .parse::<usize>()
            .unwrap(),
        r.body.len()
    );
    let text = r.text();
    assert!(text.starts_with(&format!("--{boundary}\r\n")));
    assert!(text.ends_with(&format!("\r\n--{boundary}--\r\n")));
    assert!(text.contains("Content-Range: bytes 0-4/18\r\n\r\nHello\r\n"));
    assert!(text.contains("Content-Range: bytes 7-11/18\r\n\r\nBlaze\r\n"));
    assert_eq!(text.matches("Content-Type: text/plain").count(), 2);
    fx.stop().await;
});

server_test!(unsatisfiable_range_is_416_with_size, async {
    let fx = start().await;
    for spec in ["bytes=100-200", "bytes=-0", "bytes=18-"] {
        let r = range(&fx, spec);
        assert_eq!(r.status, 416, "{spec}");
        assert_eq!(r.header("content-range"), Some("bytes */18"), "{spec}");
        assert!(r.body.is_empty());
    }
    fx.stop().await;
});

server_test!(malformed_ranges_are_ignored, async {
    let fx = start().await;
    for spec in [
        "bytes=abc",
        "bytes=",
        "bytes=1",
        "items=0-3",
        "bytes=+1-2",
        "bytes=1-x",
        "garbage",
    ] {
        let r = range(&fx, spec);
        assert_eq!((r.status, r.body.as_slice()), (200, HELLO), "{spec}");
        assert!(r.header("content-range").is_none(), "{spec}");
    }
    fx.stop().await;
});

server_test!(if_range_mismatch_falls_back_to_full_body, async {
    let fx = start().await;
    let etag = fx.get("/hello.txt").header("etag").unwrap().to_owned();
    let matched = fx.get_with("/hello.txt", &[("Range", "bytes=0-4"), ("If-Range", &etag)]);
    assert_eq!(
        (matched.status, matched.body.as_slice()),
        (206, b"Hello".as_slice())
    );

    let stale = fx.get_with(
        "/hello.txt",
        &[("Range", "bytes=0-4"), ("If-Range", "\"stale\"")],
    );
    assert_eq!((stale.status, stale.body.as_slice()), (200, HELLO));
    assert!(stale.header("content-range").is_none());

    let weak = fx.get_with(
        "/hello.txt",
        &[("Range", "bytes=0-4"), ("If-Range", &format!("W/{etag}"))],
    );
    assert_eq!(weak.status, 200, "weak validators never satisfy If-Range");

    let old_date = fx.get_with(
        "/hello.txt",
        &[
            ("Range", "bytes=0-4"),
            ("If-Range", "Sun, 06 Nov 1994 08:49:37 GMT"),
        ],
    );
    assert_eq!(old_date.status, 200);

    let last_modified = fx
        .get("/hello.txt")
        .header("last-modified")
        .unwrap()
        .to_owned();
    let by_date = fx.get_with(
        "/hello.txt",
        &[("Range", "bytes=0-4"), ("If-Range", &last_modified)],
    );
    assert_eq!(by_date.status, 206);
    fx.stop().await;
});

server_test!(
    unsatisfiable_range_with_stale_if_range_is_a_full_200,
    async {
        let fx = start().await;
        let r = fx.get_with(
            "/hello.txt",
            &[("Range", "bytes=100-200"), ("If-Range", "\"stale\"")],
        );
        assert_eq!((r.status, r.body.as_slice()), (200, HELLO));
        fx.stop().await;
    }
);

server_test!(range_requests_never_select_a_precompressed_sibling, async {
    let fx = start_with(|_, c| c.cors = true).await;
    let r = fx.get_with(
        "/plain.txt",
        &[("Range", "bytes=0-3"), ("Accept-Encoding", "gzip, br")],
    );
    assert_eq!((r.status, r.body.as_slice()), (206, b"Prec".as_slice()));
    assert!(r.header("content-encoding").is_none());
    assert_eq!(r.tokens("vary"), ["origin"]);
    fx.stop().await;
});

server_test!(head_with_range_reports_partial_headers_only, async {
    let fx = start().await;
    let r = fx.head("/hello.txt", &[("Range", "bytes=0-4")]);
    assert_eq!(r.status, 206);
    assert_eq!(r.header("content-length"), Some("5"));
    assert_eq!(r.header("content-range"), Some("bytes 0-4/18"));
    assert!(r.body.is_empty());
    fx.stop().await;
});

server_test!(excessive_range_lists_degrade_to_the_full_body, async {
    let fx = start().await;
    let spec = format!("bytes={}", vec!["0-0"; 100].join(","));
    let r = range(&fx, &spec);
    assert_eq!((r.status, r.body.as_slice()), (200, HELLO));

    let overlapping = range(&fx, "bytes=0-15,0-15");
    assert_eq!(
        overlapping.status, 200,
        "ranges summing past the file size are not honoured"
    );
    fx.stop().await;
});

server_test!(ranges_are_exact_across_chunk_boundaries, async {
    let data = pattern(200_000);
    let expected = data.clone();
    let fx = start_with(move |root, c| {
        std::fs::write(root.join("blob.bin"), &data).unwrap();
        c.chunk_bytes = 16 * 1024;
    })
    .await;

    let cases: [(u64, u64); 5] = [
        (0, 0),
        (16_383, 16_384),
        (16_384, 49_151),
        (1, 199_998),
        (199_999, 199_999),
    ];
    for (start, end) in cases {
        let r = fx.get_with("/blob.bin", &[("Range", &format!("bytes={start}-{end}"))]);
        assert_eq!(r.status, 206, "{start}-{end}");
        assert_eq!(
            r.body,
            &expected[start as usize..=end as usize],
            "{start}-{end}"
        );
    }

    let r = fx.get_with("/blob.bin", &[("Range", "bytes=10-20,16380-16390,199990-")]);
    assert_eq!(r.status, 206);
    assert_eq!(
        r.header("content-length")
            .unwrap()
            .parse::<usize>()
            .unwrap(),
        r.body.len()
    );
    for piece in [
        &expected[10..=20],
        &expected[16_380..=16_390],
        &expected[199_990..],
    ] {
        assert!(r.body.windows(piece.len()).any(|w| w == piece));
    }
    fx.stop().await;
});

server_test!(resume_download_from_an_offset_reassembles_the_file, async {
    let data = pattern(100_000);
    let expected = data.clone();
    let fx =
        start_with(move |root, _| std::fs::write(root.join("resume.bin"), &data).unwrap()).await;
    let first = fx.get_with("/resume.bin", &[("Range", "bytes=0-39999")]);
    assert_eq!(first.status, 206);
    let rest = fx.get_with("/resume.bin", &[("Range", "bytes=40000-")]);
    assert_eq!(rest.status, 206);
    assert_eq!(
        rest.header("content-range"),
        Some("bytes 40000-99999/100000")
    );
    let mut joined = first.body;
    joined.extend_from_slice(&rest.body);
    assert!(joined == expected);
    fx.stop().await;
});

server_test!(empty_file_range_is_unsatisfiable, async {
    let fx = start().await;
    std::fs::write(fx.path("empty.txt"), b"").unwrap();
    let r = fx.get_with("/empty.txt", &[("Range", "bytes=0-0")]);
    assert_eq!(r.status, 416);
    assert_eq!(r.header("content-range"), Some("bytes */0"));
    fx.stop().await;
});
