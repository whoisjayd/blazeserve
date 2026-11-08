use std::path::Path;
use std::process::{Command, Output};

fn blaze(dir: &Path, relay: Option<&str>, args: &[&str], extra: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_blaze"));
    cmd.args(args)
        .env("BLAZE_CONFIG_DIR", dir)
        .env_remove("CI")
        .env_remove("DO_NOT_TRACK")
        .env_remove("BLAZE_TELEMETRY")
        .env_remove("BLAZE_TELEMETRY_URL")
        .env("NO_COLOR", "1");
    if let Some(url) = relay {
        cmd.env("BLAZE_TELEMETRY_URL", url);
    }
    for (k, v) in extra {
        cmd.env(k, v);
    }
    cmd.output().expect("run blaze")
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

const RELAY: &str = "https://relay.example.com";

#[test]
fn status_reports_enabled_with_a_relay() {
    let dir = tempfile::tempdir().unwrap();
    let out = blaze(dir.path(), Some(RELAY), &["telemetry", "status"], &[]);
    assert!(out.status.success());
    let text = stdout(&out);
    assert!(text.contains("enabled"), "{text}");
    assert!(text.contains("configured"), "{text}");
    assert!(
        !text.contains("relay.example.com"),
        "the relay host is not echoed"
    );
}

#[test]
fn status_explains_why_it_is_disabled() {
    let dir = tempfile::tempdir().unwrap();
    let out = blaze(
        dir.path(),
        Some(RELAY),
        &["telemetry", "status"],
        &[("DO_NOT_TRACK", "1")],
    );
    assert!(out.status.success());
    let text = stdout(&out);
    assert!(
        text.contains("disabled") && text.contains("DO_NOT_TRACK is set"),
        "{text}"
    );

    let out = blaze(
        dir.path(),
        Some(RELAY),
        &["telemetry", "status"],
        &[("CI", "true")],
    );
    assert!(stdout(&out).contains("CI is set"));

    if blazeserve::usage::build_time_url().is_none() {
        let out = blaze(dir.path(), None, &["telemetry", "status"], &[]);
        assert!(stdout(&out).contains("no relay URL"), "{}", stdout(&out));
    }
}

#[test]
fn disable_enable_and_reset_persist() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("telemetry.json");

    let out = blaze(dir.path(), Some(RELAY), &["telemetry", "disable"], &[]);
    assert!(out.status.success());
    assert!(
        stdout(&out).contains("disabled with `blaze telemetry disable`"),
        "{}",
        stdout(&out)
    );
    assert!(file.exists());

    let out = blaze(dir.path(), Some(RELAY), &["telemetry", "status"], &[]);
    assert!(stdout(&out).contains("disabled with `blaze telemetry disable`"));

    let out = blaze(dir.path(), Some(RELAY), &["telemetry", "enable"], &[]);
    assert!(out.status.success());
    assert!(stdout(&out).contains("enabled"));

    let out = blaze(dir.path(), Some(RELAY), &["telemetry", "reset"], &[]);
    assert!(out.status.success());
    assert!(!file.exists());
    let again = blaze(dir.path(), Some(RELAY), &["telemetry", "reset"], &[]);
    assert!(again.status.success(), "reset is idempotent");
}

#[test]
fn preview_shows_both_payloads_and_sends_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let out = blaze(dir.path(), Some(RELAY), &["telemetry", "preview"], &[]);
    assert!(out.status.success());
    let text = stdout(&out);
    assert!(
        text.contains("\"event\": \"start\"") && text.contains("\"event\": \"stop\""),
        "{text}"
    );
    assert!(text.contains("Nothing was sent"));
    assert!(!text.contains("install_id"));
    assert!(
        !dir.path().join("telemetry.json").exists(),
        "preview must not write settings"
    );
}
