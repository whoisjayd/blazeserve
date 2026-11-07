mod http_common;

use std::time::{Duration, Instant};

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

fn auth_config(c: &mut blazeserve::config::Config) {
    c.auth = Some(blazeserve::config::Credentials::parse("admin:s3cret:pw").unwrap());
}

fn metric(body: &str, name: &str) -> u64 {
    body.lines()
        .find_map(|l| l.strip_prefix(name).and_then(|rest| rest.strip_prefix(' ')))
        .unwrap_or_else(|| panic!("metric {name} missing"))
        .trim()
        .parse()
        .unwrap()
}

server_test!(probe_endpoints_report_state, async {
    let fx = start().await;
    let live = fx.get("/__live__");
    assert_eq!(
        (live.status, live.json()["status"].clone()),
        (200, "alive".into())
    );
    let ready = fx.get("/__ready__");
    assert_eq!(
        (ready.status, ready.json()["status"].clone()),
        (200, "ready".into())
    );
    let health = fx.get("/__health__");
    let doc = health.json();
    assert_eq!(doc["status"], "ok");
    assert_eq!(doc["version"], blazeserve::VERSION);
    assert!(doc["uptime_seconds"].is_u64());
    for path in ["/__live__", "/__ready__", "/__health__"] {
        assert_eq!(
            fx.get(path).header("cache-control"),
            Some("no-store"),
            "{path}"
        );
    }
    fx.stop().await;
});

server_test!(ready_fails_when_the_root_disappears, async {
    let fx = start().await;
    std::fs::remove_dir_all(&fx.root).unwrap();
    let r = fx.get("/__ready__");
    assert_eq!(r.status, 503);
    assert_eq!(r.json()["status"], "not_ready");
    assert!(
        !r.text().contains(fx.root.to_str().unwrap()),
        "readiness must not disclose the root path"
    );
    std::fs::create_dir_all(&fx.root).unwrap();
    fx.stop().await;
});

server_test!(version_endpoint_identifies_the_build, async {
    let fx = start().await;
    let doc = fx.get("/__version__").json();
    assert_eq!(doc["name"], "blazeserve");
    assert_eq!(doc["version"], blazeserve::VERSION);
    assert!(doc["platform"].is_string());
    fx.stop().await;
});

server_test!(prometheus_exposition_has_stable_names_and_types, async {
    let fx = start().await;
    for path in ["/__metrics__", "/metrics"] {
        let r = fx.get(path);
        assert_eq!(r.status, 200);
        assert!(
            r.header("content-type")
                .unwrap()
                .starts_with("text/plain; version=0.0.4")
        );
        assert_eq!(r.header("cache-control"), Some("no-store"));
        let body = r.text();
        for (name, kind) in [
            ("blazeserve_uptime_seconds", "gauge"),
            ("blazeserve_bytes_sent_total", "counter"),
            ("blazeserve_bytes_received_total", "counter"),
            ("blazeserve_requests_total", "counter"),
            ("blazeserve_requests_active", "gauge"),
            ("blazeserve_errors_total", "counter"),
        ] {
            assert!(body.contains(&format!("# HELP {name} ")), "{name} help");
            assert!(
                body.contains(&format!("# TYPE {name} {kind}\n")),
                "{name} type"
            );
        }
    }
    fx.stop().await;
});

server_test!(only_the_scrape_itself_is_active, async {
    let fx = start().await;
    let _ = fx.get("/hello.txt");
    let body = fx.get("/__metrics__").text();
    assert_eq!(metric(&body, "blazeserve_requests_active"), 1);
    fx.stop().await;
});

server_test!(keep_alive_requests_are_each_counted, async {
    let fx = start().await;
    let mut conn = fx.conn();
    assert_eq!(conn.send("GET", "/hello.txt", &[]).status, 200);
    assert_eq!(conn.send("GET", "/hello.txt", &[]).status, 200);
    let body = conn.send("GET", "/__metrics__", &[]).text();
    assert_eq!(metric(&body, "blazeserve_requests_total"), 3);
    assert_eq!(metric(&body, "blazeserve_requests_active"), 1);
    fx.stop().await;
});

server_test!(bytes_sent_counts_actual_transfer, async {
    let fx = start().await;
    assert_eq!(fx.get("/hello.txt").body, HELLO);
    let stats = fx.get("/__stats__").json();
    assert!(stats["bytes_sent"].as_u64().unwrap() >= HELLO.len() as u64);

    let before = fx.get("/__stats__").json()["bytes_sent"].as_u64().unwrap();
    let _ = fx.get("/__speed__?bytes=65536");
    let after = fx.get("/__stats__").json()["bytes_sent"].as_u64().unwrap();
    assert!(after - before >= 65_536);

    fx.stop().await;
});

server_test!(perf_reports_config, async {
    let fx = start_with(|_, c| c.rate_mbps = Some(8.0)).await;
    let doc = fx.get("/__perf__").json();
    assert!(doc["uptime_seconds"].is_u64());
    assert_eq!(doc["config"]["rate_limit_mbps"], 8.0);
    assert!(doc["config"]["chunk_size_mb"].is_u64());
    assert!(doc["config"]["timeout_seconds"].is_u64());
    fx.stop().await;
});

server_test!(speed_endpoint_streams_zeros_and_validates, async {
    let fx = start().await;
    let r = fx.get("/__speed__?bytes=300000");
    assert_eq!(r.status, 200);
    assert_eq!(r.body.len(), 300_000);
    assert!(r.body.iter().all(|b| *b == 0));
    assert_eq!(r.header("content-type"), Some("application/octet-stream"));
    assert_eq!(r.header("cache-control"), Some("no-store"));
    assert_eq!(fx.get("/__speed__?bytes=0").body.len(), 0);
    for bad in [
        "bytes=abc",
        "bytes=-1",
        "bytes=1048576001",
        "bytes=99999999999999999999",
    ] {
        assert_eq!(fx.get(&format!("/__speed__?{bad}")).status, 400, "{bad}");
    }
    let head = fx.head("/__speed__?bytes=1234", &[]);
    assert_eq!(head.header("content-length"), Some("1234"));
    assert!(head.body.is_empty());
    fx.stop().await;
});

server_test!(operational_head_matches_get, async {
    let fx = start().await;
    for path in [
        "/__live__",
        "/__ready__",
        "/__version__",
        "/__speed__?bytes=10",
    ] {
        let get = fx.get(path);
        let head = fx.head(path, &[]);
        assert_eq!(head.status, get.status, "{path}");
        assert_eq!(
            head.header("content-length"),
            get.header("content-length"),
            "{path}"
        );
        assert_eq!(
            head.header("content-type"),
            get.header("content-type"),
            "{path}"
        );
        assert_eq!(
            head.header("cache-control"),
            get.header("cache-control"),
            "{path}"
        );
        assert!(head.body.is_empty(), "{path}");
    }
    fx.stop().await;
});

server_test!(basic_auth_gates_every_route_before_dispatch, async {
    let fx = start_with(|_, c| auth_config(c)).await;
    for path in [
        "/hello.txt",
        "/",
        "/__live__",
        "/__metrics__",
        "/__zip__?path=sub",
        "/missing",
        "/__speed__?bytes=1",
    ] {
        for method in ["GET", "HEAD"] {
            let r = request(fx.addr, method, path, &[]);
            assert_eq!(r.status, 401, "{method} {path}");
            assert_eq!(
                r.header("www-authenticate"),
                Some("Basic realm=\"blazeserve\"")
            );
            assert!(r.body.is_empty());
        }
    }
    for method in ["PUT", "POST"] {
        let r = request(
            fx.addr,
            method,
            "/__upload__/x.txt",
            &[("Content-Length", "0")],
        );
        assert_eq!(r.status, 401, "{method}");
        assert_eq!(r.header("connection"), Some("close"));
    }
    assert!(!fx.path("x.txt").exists());
    fx.stop().await;
});

server_test!(basic_auth_accepts_only_exact_credentials, async {
    let fx = start_with(|_, c| auth_config(c)).await;
    let good = basic("admin", "s3cret:pw");
    let ok = fx.get_with("/hello.txt", &[("Authorization", &good)]);
    assert_eq!((ok.status, ok.body.as_slice()), (200, HELLO));
    assert_eq!(
        fx.head("/hello.txt", &[("Authorization", &good)]).status,
        200
    );

    let wrong = [
        basic("admin", "wrong"),
        basic("root", "s3cret:pw"),
        basic("", ""),
        basic("admin", "s3cret"),
        basic("admin", "s3cret:pw "),
        basic("ADMIN", "s3cret:pw"),
        "Basic !!!not-base64!!!".to_owned(),
        "Basic YWRtaW4=".to_owned(),
        "Bearer abc".to_owned(),
        "Basic".to_owned(),
    ];
    for header in wrong {
        let r = fx.get_with("/hello.txt", &[("Authorization", &header)]);
        assert_eq!(r.status, 401, "{header}");
        assert!(!r.text().contains("Hello"));
    }
    fx.stop().await;
});

server_test!(options_preflight_does_not_require_credentials, async {
    let fx = start_with(|_, c| {
        auth_config(c);
        c.cors = true;
    })
    .await;
    assert_eq!(
        request(
            fx.addr,
            "OPTIONS",
            "/hello.txt",
            &[("Origin", "https://x.test")]
        )
        .status,
        204
    );
    fx.stop().await;
});

server_test!(
    throttled_responses_advertise_the_limit_and_take_time,
    async {
        let fx = start_with(|_, c| c.rate_mbps = Some(0.5)).await;
        let r = fx.get("/hello.txt");
        assert_eq!(r.header("x-ratelimit-limit"), Some("524288"));
        assert!(
            r.header("x-ratelimit-remaining")
                .unwrap()
                .parse::<u64>()
                .is_ok()
        );

        let started = Instant::now();
        let big = fx.get("/__speed__?bytes=1572864");
        let elapsed = started.elapsed();
        assert_eq!(big.body.len(), 1_572_864);
        assert!(
            elapsed >= Duration::from_millis(700),
            "throttle ignored: {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_secs(15),
            "throttle far too slow: {elapsed:?}"
        );
        fx.stop().await;
    }
);

server_test!(unthrottled_responses_carry_no_rate_headers, async {
    let fx = start().await;
    let r = fx.get("/hello.txt");
    assert!(r.header("x-ratelimit-limit").is_none());
    assert!(r.header("x-ratelimit-remaining").is_none());
    fx.stop().await;
});

server_test!(concurrent_clients_all_receive_complete_bodies, async {
    let data = pattern(1_500_000);
    let expected = std::sync::Arc::new(data.clone());
    let fx = start_with(move |root, c| {
        std::fs::write(root.join("shared.bin"), &data).unwrap();
        c.chunk_bytes = 32 * 1024;
    })
    .await;
    let addr = fx.addr;
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let expected = expected.clone();
        tasks.push(tokio::task::spawn_blocking(move || {
            let r = get(addr, "/shared.bin");
            assert_eq!(r.status, 200);
            assert!(r.body == *expected);
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
    let mut active = u64::MAX;
    for _ in 0..100 {
        active = fx.server.state().metrics.requests_active();
        if active == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(active, 0);
    fx.stop().await;
});
