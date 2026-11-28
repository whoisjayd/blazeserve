use std::path::Path;
use std::process::{Command, Output};

fn blaze(dir: &Path, key: Option<&str>, args: &[&str], extra: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_blaze"));
    cmd.args(args)
        .env("BLAZE_CONFIG_DIR", dir)
        .env_remove("CI")
        .env_remove("DO_NOT_TRACK")
        .env_remove("BLAZE_TELEMETRY")
        .env_remove("BLAZE_POSTHOG_KEY")
        .env_remove("BLAZE_POSTHOG_HOST")
        .env("NO_COLOR", "1");
    if let Some(key) = key {
        // A closed loopback port: nothing could leave the machine even by mistake.
        cmd.env("BLAZE_POSTHOG_KEY", key)
            .env("BLAZE_POSTHOG_HOST", "http://127.0.0.1:1");
    }
    for (k, v) in extra {
        cmd.env(k, v);
    }
    cmd.output().expect("run blaze")
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

const KEY: &str = "phc_test";

#[test]
fn status_reports_enabled_with_a_key() {
    let dir = tempfile::tempdir().unwrap();
    let out = blaze(dir.path(), Some(KEY), &["telemetry", "status"], &[]);
    assert!(out.status.success());
    let text = stdout(&out);
    assert!(text.contains("enabled"), "{text}");
    assert!(text.contains("configured"), "{text}");
    assert!(!text.contains(KEY), "the key is not echoed");
}

#[test]
fn status_explains_why_it_is_disabled() {
    let dir = tempfile::tempdir().unwrap();
    let out = blaze(
        dir.path(),
        Some(KEY),
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
        Some(KEY),
        &["telemetry", "status"],
        &[("CI", "true")],
    );
    assert!(stdout(&out).contains("CI is set"));

    if blazeserve::usage::build_time_key().is_none() {
        let out = blaze(dir.path(), None, &["telemetry", "status"], &[]);
        assert!(
            stdout(&out).contains("no PostHog project key"),
            "{}",
            stdout(&out)
        );
    }
}

#[test]
fn disable_enable_and_reset_persist() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("telemetry.json");

    let out = blaze(dir.path(), Some(KEY), &["telemetry", "disable"], &[]);
    assert!(out.status.success());
    assert!(
        stdout(&out).contains("disabled with `blaze telemetry disable`"),
        "{}",
        stdout(&out)
    );
    assert!(file.exists());

    let out = blaze(dir.path(), Some(KEY), &["telemetry", "status"], &[]);
    assert!(stdout(&out).contains("disabled with `blaze telemetry disable`"));

    let out = blaze(dir.path(), Some(KEY), &["telemetry", "enable"], &[]);
    assert!(out.status.success());
    assert!(stdout(&out).contains("enabled"));

    let out = blaze(dir.path(), Some(KEY), &["telemetry", "reset"], &[]);
    assert!(out.status.success());
    assert!(!file.exists());
    let again = blaze(dir.path(), Some(KEY), &["telemetry", "reset"], &[]);
    assert!(again.status.success(), "reset is idempotent");
}

#[test]
fn preview_shows_example_events_and_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let out = blaze(dir.path(), Some(KEY), &["telemetry", "preview"], &[]);
    assert!(out.status.success());
    let text = stdout(&out);
    assert!(
        text.contains("command finished") && text.contains("server stopped"),
        "{text}"
    );
    assert!(text.contains("Nothing was sent"));
    assert!(
        !dir.path().join("telemetry.json").exists(),
        "preview must not write settings"
    );
}
