mod http_common;

use std::io::{Cursor, Read};
use std::path::Path;

use blazeserve::config::Hide;
use http_common::*;

const PATTERNS: &[&str] = &["*.env", "secrets/**", ".git"];

fn tree(root: &Path, config: &mut blazeserve::config::Config) {
    std::fs::create_dir_all(root.join("secrets").join("deep")).unwrap();
    std::fs::create_dir_all(root.join("pub").join(".git")).unwrap();
    std::fs::write(root.join("index.txt"), b"visible").unwrap();
    std::fs::write(root.join("prod.env"), b"TOKEN=1").unwrap();
    std::fs::write(root.join("secrets").join("k.txt"), b"key").unwrap();
    std::fs::write(root.join("secrets").join("deep").join("d.txt"), b"d").unwrap();
    std::fs::write(root.join("pub").join("ok.txt"), b"ok").unwrap();
    std::fs::write(root.join("pub").join("nested.env"), b"x").unwrap();
    std::fs::write(root.join("pub").join(".git").join("HEAD"), b"ref").unwrap();
    config.hide = Hide::new(PATTERNS).unwrap();
}

fn zip_names(bytes: &[u8]) -> Vec<String> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).expect("valid archive");
    let mut names = Vec::new();
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).expect("entry");
        let mut data = Vec::new();
        entry.read_to_end(&mut data).unwrap();
        names.push(entry.name().expect("utf-8").into_owned());
    }
    names.sort();
    names
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn listing_omits_hidden_entries() {
    let fx = start_with(tree).await;
    let json = [("Accept", "application/json")];
    let r = fx.get_with("/", &json);
    assert_eq!(r.status, 200);
    let text = r.text();
    assert!(text.contains("index.txt") && text.contains("pub"));
    assert!(!text.contains("prod.env") && !text.contains("secrets"));

    let r = fx.get_with("/pub/", &json);
    let text = r.text();
    assert!(text.contains("ok.txt"));
    assert!(!text.contains("nested.env") && !text.contains(".git"));

    let html = fx.get("/");
    assert!(!html.text().contains("prod.env"));
    fx.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn direct_requests_for_hidden_entries_are_404() {
    let fx = start_with(tree).await;
    let missing = fx.get("/absent.txt");
    assert_eq!(missing.status, 404);
    for path in [
        "/prod.env",
        "/pub/nested.env",
        "/secrets/k.txt",
        "/secrets/deep/d.txt",
        "/secrets/",
        "/pub/.git/HEAD",
        "/pub/.git",
        "/secrets/%2e/k.txt",
        "/%70rod.env",
    ] {
        let r = fx.get(path);
        assert_eq!(r.status, 404, "{path}");
        assert_eq!(r.body, missing.body, "{path} must look like a missing file");
        assert_eq!(fx.get_with(path, &[("Range", "bytes=0-1")]).status, 404);
        assert_eq!(fx.head(path, &[]).status, 404, "head {path}");
    }
    fx.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn non_matching_entries_are_still_served() {
    let fx = start_with(tree).await;
    for (path, body) in [("/index.txt", "visible"), ("/pub/ok.txt", "ok")] {
        let r = fx.get(path);
        assert_eq!(r.status, 200, "{path}");
        assert_eq!(r.text(), body);
    }
    fx.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn zip_excludes_hidden_entries() {
    let fx = start_with(tree).await;
    let r = fx.get("/__zip__?path=.");
    assert_eq!(r.status, 200);
    let names = zip_names(&r.body);
    for gone in ["prod.env", "secrets", "nested.env", ".git"] {
        assert!(
            !names.iter().any(|n| n.contains(gone)),
            "{gone} in {names:?}"
        );
    }
    for kept in ["index.txt", "pub/ok.txt", "hello.txt"] {
        assert!(names.iter().any(|n| n == kept), "{kept} in {names:?}");
    }
    for path in ["secrets", "prod.env", "pub/.git"] {
        assert_eq!(
            fx.get(&format!("/__zip__?path={path}")).status,
            404,
            "{path}"
        );
    }
    fx.stop().await;
}

#[test]
fn invalid_pattern_is_a_config_error() {
    assert!(Hide::new(&["[oops"]).is_err());
}
