//! `blaze verify` against SHA-256 and SFV lists, as a user runs it.

mod cli_support;

use cli_support::{blaze, code, stderr, stdout};
use std::path::Path;
use std::process::Output;

const ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

fn verify_in(dir: &Path, args: &[&str]) -> Output {
    blaze()
        .arg("verify")
        .args(args)
        .current_dir(dir)
        .output()
        .expect("spawn blaze")
}

fn folder(files: &[(&str, &str)]) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    for (name, body) in files {
        std::fs::write(dir.path().join(name), body).unwrap();
    }
    dir
}

#[test]
fn a_matching_list_passes_and_a_changed_file_exits_4() {
    let sums = format!("{ABC}  a.bin\n{ABC} *b.bin\n");
    let dir = folder(&[("a.bin", "abc"), ("b.bin", "abc"), ("SHA256SUMS", &sums)]);
    let ok = verify_in(dir.path(), &["--check", "SHA256SUMS"]);
    assert_eq!(code(&ok), 0, "{}", stderr(&ok));

    std::fs::write(dir.path().join("b.bin"), "abd").unwrap();
    let bad = verify_in(dir.path(), &["--check", "SHA256SUMS"]);
    assert_eq!(code(&bad), 4, "{}", stderr(&bad));
    assert!(stdout(&bad).contains("FAILED   b.bin"), "{}", stdout(&bad));
    assert!(stdout(&bad).contains("ok       a.bin"), "{}", stdout(&bad));
}

#[test]
fn the_list_is_read_from_its_own_folder() {
    let dir = folder(&[("a.bin", "abc"), ("SHA256SUMS", &format!("{ABC}  a.bin\n"))]);
    let list = dir.path().join("SHA256SUMS");
    let elsewhere = tempfile::tempdir().unwrap();
    let out = verify_in(elsewhere.path(), &["--check", list.to_str().unwrap()]);
    assert_eq!(code(&out), 0, "{}", stdout(&out));
}

#[test]
fn a_missing_file_exits_1_and_a_mismatch_outranks_it() {
    let sums = format!("{ABC}  gone.bin\n");
    let dir = folder(&[("SHA256SUMS", &sums), ("bad.bin", "abd")]);
    let missing = verify_in(dir.path(), &["--check", "SHA256SUMS"]);
    assert_eq!(code(&missing), 1);
    assert!(stdout(&missing).contains("missing  gone.bin"));

    std::fs::write(
        dir.path().join("SHA256SUMS"),
        format!("{sums}{ABC}  bad.bin\n"),
    )
    .unwrap();
    assert_eq!(code(&verify_in(dir.path(), &["--check", "SHA256SUMS"])), 4);
}

#[test]
fn an_entry_outside_the_folder_is_looked_up_inside_it() {
    let outer = folder(&[("secret", "abc")]);
    let inner = outer.path().join("inner");
    std::fs::create_dir(&inner).unwrap();
    std::fs::write(inner.join("SHA256SUMS"), format!("{ABC}  ../secret\n")).unwrap();
    let out = verify_in(&inner, &["--check", "SHA256SUMS"]);
    assert_eq!(code(&out), 1);
    assert!(stdout(&out).contains("missing  secret"), "{}", stdout(&out));
}

#[test]
fn an_unusable_list_never_passes() {
    let dir = folder(&[
        ("a.bin", "abc"),
        ("empty", "# nothing\n"),
        ("page", "<html>not found</html>\n"),
        ("mixed", &format!("{ABC}  a.bin\ngarbage\n")),
        ("bare", ABC),
    ]);
    for list in ["empty", "page", "mixed", "bare", "no-such-list"] {
        let out = verify_in(dir.path(), &["--check", list]);
        assert_eq!(code(&out), 1, "{list}: {}", stdout(&out));
        assert!(stderr(&out).contains("error:"), "{list}");
    }
}

#[test]
fn a_file_uses_its_sidecar_before_sha256sums() {
    let wrong = format!("{}  a.bin\n", "0".repeat(64));
    let dir = folder(&[("a.bin", "abc"), ("b.bin", "abc"), ("SHA256SUMS", &wrong)]);
    assert_eq!(code(&verify_in(dir.path(), &["a.bin"])), 4);
    std::fs::write(dir.path().join("a.bin.sha256"), format!("{ABC}\n")).unwrap();
    let ok = verify_in(dir.path(), &["a.bin"]);
    assert_eq!(code(&ok), 0, "{}", stdout(&ok));

    let unlisted = verify_in(dir.path(), &["a.bin", "b.bin"]);
    assert_eq!(code(&unlisted), 1);
    assert!(
        stdout(&unlisted).contains("not listed"),
        "{}",
        stdout(&unlisted)
    );
}

#[test]
fn checks_sfv_lists() {
    let dir = folder(&[
        ("a.bin", "123456789"),
        ("x.sfv", "; c\r\na.bin CBF43926\r\n"),
    ]);
    let ok = verify_in(dir.path(), &["--sfv", "x.sfv"]);
    assert_eq!(code(&ok), 0, "{}", stdout(&ok));
    std::fs::write(dir.path().join("a.bin"), "123456780").unwrap();
    assert_eq!(code(&verify_in(dir.path(), &["--sfv", "x.sfv"])), 4);
}

#[test]
fn conflicting_or_absent_inputs_are_usage_errors() {
    let dir = folder(&[]);
    for args in [
        &[] as &[&str],
        &["a", "--check", "b"],
        &["--check", "a", "--sfv", "b"],
    ] {
        assert_eq!(code(&verify_in(dir.path(), args)), 2, "{args:?}");
    }
}
