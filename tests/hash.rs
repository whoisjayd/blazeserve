mod http_common;

use base64::Engine;
use http_common::*;
use sha2::{Digest, Sha256};

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

fn hex(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

server_test!(hash_returns_the_sha256_of_the_file, async {
    let fx =
        start_with(|root, _| std::fs::write(root.join("big.bin"), pattern(1_000_003)).unwrap())
            .await;
    let resp = fx.get("/big.bin?hash");
    assert_eq!(resp.status, 200);
    assert_eq!(resp.header("cache-control"), Some("no-store"));
    let doc = resp.json();
    assert_eq!(doc["path"], "/big.bin");
    assert_eq!(doc["size"], 1_000_003);
    assert_eq!(doc["sha256"], hex(&pattern(1_000_003)));
    let b64 = base64::engine::general_purpose::STANDARD.encode(Sha256::digest(pattern(1_000_003)));
    assert_eq!(
        resp.header("repr-digest"),
        Some(format!("sha-256=:{b64}:").as_str())
    );
    let hello = fx.get("/hello.txt?hash");
    assert_eq!(hello.json()["sha256"], hex(HELLO));
    fx.stop().await;
});

server_test!(hash_on_head_has_headers_and_no_body, async {
    let fx = start().await;
    let get = fx.get("/hello.txt?hash");
    let head = fx.head("/hello.txt?hash", &[]);
    assert_eq!(head.status, 200);
    assert!(head.body.is_empty());
    assert_eq!(head.header("repr-digest"), get.header("repr-digest"));
    assert_eq!(head.header("content-length"), get.header("content-length"));
    fx.stop().await;
});

server_test!(hash_requires_authentication, async {
    let fx = start_with(|_, c| {
        c.auth = Some(blazeserve::config::Credentials::parse("admin:s3cret:pw").unwrap());
    })
    .await;
    assert_eq!(fx.get("/hello.txt?hash").status, 401);
    let ok = fx.get_with(
        "/hello.txt?hash",
        &[("Authorization", &basic("admin", "s3cret:pw"))],
    );
    assert_eq!(ok.status, 200);
    assert_eq!(ok.json()["sha256"], hex(HELLO));
    fx.stop().await;
});

server_test!(hash_cannot_escape_the_root, async {
    let fx = start().await;
    for path in [
        "/../Cargo.toml?hash",
        "/%2e%2e/Cargo.toml?hash",
        "/sub/..%2f..%2fCargo.toml?hash",
    ] {
        assert_eq!(fx.get(path).status, 403, "{path}");
    }
    assert_eq!(fx.get("/missing.txt?hash").status, 404);
    fx.stop().await;
});

server_test!(hash_rejects_directories, async {
    let fx = start().await;
    assert_eq!(fx.get("/sub?hash").status, 400);
    assert_eq!(fx.get("/?hash").status, 400);
    fx.stop().await;
});

server_test!(hash_follows_file_modification, async {
    let fx = start().await;
    let first = fx.get("/hello.txt?hash").json()["sha256"].clone();
    assert_eq!(first, hex(HELLO));
    assert_eq!(fx.get("/hello.txt?hash").json()["sha256"], first);
    std::fs::write(fx.path("hello.txt"), b"changed content, different size").unwrap();
    let second = fx.get("/hello.txt?hash");
    assert_eq!(
        second.json()["sha256"],
        hex(b"changed content, different size")
    );
    assert_ne!(second.json()["sha256"], first);
    fx.stop().await;
});

server_test!(hash_does_not_hold_the_file_open, async {
    let fx = start().await;
    assert_eq!(fx.get("/hello.txt?hash").status, 200);
    std::fs::remove_file(fx.path("hello.txt")).unwrap();
    assert_eq!(fx.get("/hello.txt?hash").status, 404);
    fx.stop().await;
});
