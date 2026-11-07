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

const ORIGIN: &str = "https://client.example.test";

server_test!(validators_and_cache_policy_are_present, async {
    let fx = start().await;
    let r = fx.get("/hello.txt");
    let etag = r.header("etag").unwrap();
    assert!(etag.starts_with('"') && etag.ends_with('"') && !etag.starts_with("W/"));
    assert!(r.header("last-modified").unwrap().ends_with("GMT"));
    assert_eq!(r.header("cache-control"), Some("public, max-age=3600"));
    fx.stop().await;
});

server_test!(etag_changes_when_the_file_changes, async {
    let fx = start().await;
    let before = fx.get("/hello.txt").header("etag").unwrap().to_owned();
    std::fs::write(fx.path("hello.txt"), b"Hello, changed content!").unwrap();
    let after = fx.get("/hello.txt").header("etag").unwrap().to_owned();
    assert_ne!(before, after);
    fx.stop().await;
});

server_test!(if_none_match_returns_304_with_validators, async {
    let fx = start().await;
    let first = fx.get("/hello.txt");
    let etag = first.header("etag").unwrap().to_owned();
    let r = fx.get_with("/hello.txt", &[("If-None-Match", &etag)]);
    assert_eq!(r.status, 304);
    assert!(r.body.is_empty());
    assert_eq!(r.header("etag"), Some(etag.as_str()));
    assert_eq!(r.header("last-modified"), first.header("last-modified"));
    assert_eq!(r.header("cache-control"), Some("public, max-age=3600"));
    assert!(r.header("content-length").is_none_or(|v| v == "0"));
    fx.stop().await;
});

server_test!(if_none_match_uses_weak_comparison_and_lists, async {
    let fx = start().await;
    let etag = fx.get("/hello.txt").header("etag").unwrap().to_owned();
    for value in [
        format!("W/{etag}"),
        format!("\"other\", {etag}"),
        "*".to_owned(),
    ] {
        let r = fx.get_with("/hello.txt", &[("If-None-Match", &value)]);
        assert_eq!(r.status, 304, "{value}");
    }
    let miss = fx.get_with("/hello.txt", &[("If-None-Match", "\"other\"")]);
    assert_eq!((miss.status, miss.body.as_slice()), (200, HELLO));
    fx.stop().await;
});

server_test!(if_modified_since_returns_304_only_when_unchanged, async {
    let fx = start().await;
    let last_modified = fx
        .get("/hello.txt")
        .header("last-modified")
        .unwrap()
        .to_owned();
    let fresh = fx.get_with("/hello.txt", &[("If-Modified-Since", &last_modified)]);
    assert_eq!(fresh.status, 304);
    assert!(fresh.body.is_empty());
    assert!(fresh.header("etag").is_some());

    let stale = fx.get_with(
        "/hello.txt",
        &[("If-Modified-Since", "Sun, 06 Nov 1994 08:49:37 GMT")],
    );
    assert_eq!(stale.status, 200);
    let garbage = fx.get_with("/hello.txt", &[("If-Modified-Since", "not a date")]);
    assert_eq!(garbage.status, 200);
    fx.stop().await;
});

server_test!(
    if_none_match_takes_precedence_over_if_modified_since,
    async {
        let fx = start().await;
        let last_modified = fx
            .get("/hello.txt")
            .header("last-modified")
            .unwrap()
            .to_owned();
        let r = fx.get_with(
            "/hello.txt",
            &[
                ("If-None-Match", "\"mismatch\""),
                ("If-Modified-Since", &last_modified),
            ],
        );
        assert_eq!((r.status, r.body.as_slice()), (200, HELLO));
        fx.stop().await;
    }
);

server_test!(conditional_head_is_also_304, async {
    let fx = start().await;
    let etag = fx.get("/hello.txt").header("etag").unwrap().to_owned();
    let r = fx.head("/hello.txt", &[("If-None-Match", &etag)]);
    assert_eq!(r.status, 304);
    fx.stop().await;
});

server_test!(no_cache_flag_disables_caching, async {
    let fx = start_with(|_, c| c.no_cache = true).await;
    let r = fx.get("/hello.txt");
    assert!(r.header("cache-control").unwrap().contains("no-cache"));
    let etag = r.header("etag").unwrap().to_owned();
    let not_modified = fx.get_with("/hello.txt", &[("If-None-Match", &etag)]);
    assert_eq!(not_modified.status, 304);
    assert!(
        not_modified
            .header("cache-control")
            .unwrap()
            .contains("no-cache")
    );
    fx.stop().await;
});

server_test!(gzip_sibling_is_served_when_accepted, async {
    let fx = start().await;
    let plain = fx.get("/plain.txt");
    assert_eq!(plain.body, b"Precompressed plain content");
    assert!(plain.header("content-encoding").is_none());

    let gz = fx.get_with("/plain.txt", &[("Accept-Encoding", "gzip")]);
    assert_eq!(gz.status, 200);
    assert_eq!(gz.body, b"GZIP-BYTES");
    assert_eq!(gz.header("content-encoding"), Some("gzip"));
    assert_eq!(gz.header("content-type"), Some("text/plain"));
    assert_eq!(gz.header("content-length"), Some("10"));
    assert_eq!(gz.tokens("vary"), ["accept-encoding"]);
    assert_ne!(gz.header("etag"), plain.header("etag"));
    fx.stop().await;
});

server_test!(
    brotli_is_preferred_over_gzip_and_q_zero_is_respected,
    async {
        let fx = start().await;
        let both = fx.get_with("/plain.txt", &[("Accept-Encoding", "gzip, deflate, br")]);
        assert_eq!(both.body, b"BROTLI-BYTES");
        assert_eq!(both.header("content-encoding"), Some("br"));

        let no_br = fx.get_with("/plain.txt", &[("Accept-Encoding", "br;q=0, gzip")]);
        assert_eq!(no_br.header("content-encoding"), Some("gzip"));

        let neither = fx.get_with("/plain.txt", &[("Accept-Encoding", "gzip;q=0, br;q=0")]);
        assert!(neither.header("content-encoding").is_none());
        assert_eq!(neither.body, b"Precompressed plain content");

        let identity = fx.get_with("/plain.txt", &[("Accept-Encoding", "identity")]);
        assert!(identity.header("content-encoding").is_none());
        fx.stop().await;
    }
);

server_test!(precompression_can_be_disabled, async {
    let fx = start_with(|_, c| c.precompress = false).await;
    let r = fx.get_with("/plain.txt", &[("Accept-Encoding", "gzip, br")]);
    assert!(r.header("content-encoding").is_none());
    assert_eq!(r.body, b"Precompressed plain content");
    fx.stop().await;
});

server_test!(
    conditional_requests_for_encoded_variants_use_their_own_etag,
    async {
        let fx = start().await;
        let gz = fx.get_with("/plain.txt", &[("Accept-Encoding", "gzip")]);
        let etag = gz.header("etag").unwrap().to_owned();
        let r = fx.get_with(
            "/plain.txt",
            &[("Accept-Encoding", "gzip"), ("If-None-Match", &etag)],
        );
        assert_eq!(r.status, 304);
        assert_eq!(r.tokens("vary"), ["accept-encoding"]);
        fx.stop().await;
    }
);

server_test!(cors_preflight_answers_204, async {
    let fx = start_with(|_, c| {
        c.cors = true;
        c.cors_origin = ORIGIN.into();
    })
    .await;
    let r = request(
        fx.addr,
        "OPTIONS",
        "/hello.txt",
        &[("Origin", ORIGIN), ("Access-Control-Request-Method", "GET")],
    );
    assert_eq!(r.status, 204);
    assert!(r.body.is_empty());
    assert_eq!(r.header("access-control-allow-origin"), Some(ORIGIN));
    let methods = r.tokens("access-control-allow-methods");
    for m in ["get", "head", "options", "put", "post"] {
        assert!(methods.contains(&m.to_owned()), "{m}");
    }
    let allowed = r.tokens("access-control-allow-headers");
    for h in ["range", "content-type", "authorization", "x-request-id"] {
        assert!(allowed.contains(&h.to_owned()), "{h}");
    }
    let exposed = r.tokens("access-control-expose-headers");
    for h in [
        "accept-ranges",
        "content-length",
        "content-range",
        "etag",
        "last-modified",
        "x-request-id",
    ] {
        assert!(exposed.contains(&h.to_owned()), "{h}");
    }
    assert_eq!(r.header("x-content-type-options"), Some("nosniff"));
    fx.stop().await;
});

server_test!(cors_get_and_head_vary_by_origin, async {
    let fx = start_with(|_, c| {
        c.cors = true;
        c.cors_origin = ORIGIN.into();
    })
    .await;
    let get = fx.get_with("/hello.txt", &[("Origin", ORIGIN)]);
    assert_eq!((get.status, get.body.as_slice()), (200, HELLO));
    assert_eq!(get.header("access-control-allow-origin"), Some(ORIGIN));
    assert_eq!(get.tokens("vary"), ["origin"]);

    let head = fx.head("/hello.txt", &[("Origin", ORIGIN)]);
    assert_eq!(head.status, 200);
    assert!(head.body.is_empty());
    assert_eq!(head.header("access-control-allow-origin"), Some(ORIGIN));
    assert_eq!(head.tokens("vary"), ["origin"]);

    let missing = fx.get_with("/nope", &[("Origin", ORIGIN)]);
    assert_eq!(missing.header("access-control-allow-origin"), Some(ORIGIN));
    fx.stop().await;
});

server_test!(cors_with_encoding_varies_on_both, async {
    let fx = start_with(|_, c| {
        c.cors = true;
        c.cors_origin = ORIGIN.into();
    })
    .await;
    let r = fx.get_with(
        "/plain.txt",
        &[("Accept-Encoding", "gzip"), ("Origin", ORIGIN)],
    );
    assert_eq!(r.header("content-encoding"), Some("gzip"));
    let mut vary = r.tokens("vary");
    vary.sort();
    assert_eq!(vary, ["accept-encoding", "origin"]);
    fx.stop().await;
});

server_test!(cors_disabled_omits_cors_headers_and_options_is_405, async {
    let fx = start().await;
    let r = fx.get_with("/hello.txt", &[("Origin", ORIGIN)]);
    for name in [
        "access-control-allow-origin",
        "access-control-allow-methods",
        "access-control-allow-headers",
        "access-control-expose-headers",
    ] {
        assert!(r.header(name).is_none(), "{name}");
    }
    assert!(!r.tokens("vary").contains(&"origin".to_owned()));
    let options = request(fx.addr, "OPTIONS", "/hello.txt", &[("Origin", ORIGIN)]);
    assert_eq!(options.status, 405);
    fx.stop().await;
});
