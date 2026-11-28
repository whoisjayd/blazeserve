//! The reporter against a stand-in for PostHog: what is sent, when, and what never is.

mod usage_support;

use blazeserve::usage::{
    CommandReport, Features, QUEUE_FILE, Reporter, ServerCounters, Settings, load_settings,
    notice_text, open, reset_settings, save_settings, settings_path,
};
use serde_json::Value;
use std::path::Path;
use std::time::Duration;
use usage_support::{Env, Mock, elapsed, mock, wait_for};

fn env_for(dir: &Path, host: &str) -> Env {
    Env::new(&[
        ("BLAZE_CONFIG_DIR", dir.to_str().unwrap()),
        ("BLAZE_POSTHOG_KEY", "phc_test"),
        ("BLAZE_POSTHOG_HOST", host),
        ("BLAZE_INSTALL_CHANNEL", "pip"),
    ])
}

fn reporter(env: &Env, diag: &mut Vec<u8>) -> Option<Reporter> {
    open(&env.lookup(), None, None, diag, true, true)
}

fn report(kind: Option<&'static str>) -> CommandReport<'static> {
    CommandReport {
        command: "get",
        flags: vec!["connections".to_owned(), "url".to_owned()],
        background: false,
        exit_code: u8::from(kind.is_some()),
        error_kind: kind,
        log_id: None,
    }
}

fn batch(relay: &Mock) -> Vec<Value> {
    let request = wait_for(&relay.requests, 5).expect("nothing was delivered");
    assert!(
        request.head.starts_with("POST /batch/ HTTP/1.1"),
        "{}",
        request.head
    );
    let body: Value = serde_json::from_str(&request.body).unwrap();
    assert_eq!(body["api_key"], "phc_test");
    body["batch"].as_array().unwrap().clone()
}

fn quiet(relay: &Mock) {
    std::thread::sleep(Duration::from_millis(250));
    assert_eq!(relay.connection_count(), 0);
}

#[test]
fn a_command_is_sent_with_a_stable_install_id_and_the_notice_shows_once() {
    let dir = tempfile::tempdir().unwrap();
    let host = mock(true);
    let env = env_for(dir.path(), &host.url());

    let mut diag = Vec::new();
    let first = reporter(&env, &mut diag).expect("on by default");
    assert_eq!(String::from_utf8(diag.clone()).unwrap(), notice_text());
    first.command_finished(report(None), true, &mut diag);
    let events = batch(&host);
    assert_eq!(events.len(), 1);
    let sent = &events[0]["properties"];
    assert_eq!(events[0]["event"], "command finished");
    assert_eq!(sent["command"], "get");
    assert_eq!(sent["flags"], serde_json::json!(["connections", "url"]));
    assert_eq!(sent["outcome"], "ok");
    assert_eq!(sent["install_channel"], "pip");
    assert_eq!(sent["$process_person_profile"], false);

    let mut again = Vec::new();
    let second = reporter(&env, &mut again).expect("enabled");
    assert!(again.is_empty(), "the notice must be shown only once");
    second.command_finished(report(None), true, &mut again);
    let later = batch(&host);
    assert_eq!(later[0]["properties"]["distinct_id"], sent["distinct_id"]);
    assert_ne!(later[0]["properties"]["$session_id"], sent["$session_id"]);
}

#[test]
fn a_failure_also_reports_an_error_by_kind_only() {
    let dir = tempfile::tempdir().unwrap();
    let host = mock(true);
    let env = env_for(dir.path(), &host.url());
    let mut diag = Vec::new();
    reporter(&env, &mut diag)
        .unwrap()
        .command_finished(report(Some("network")), true, &mut diag);
    let events = batch(&host);
    assert_eq!(events[1]["event"], "$exception");
    assert_eq!(
        events[1]["properties"]["$exception_list"][0]["type"],
        "network"
    );
    assert_eq!(events[0]["properties"]["outcome"], "failed");
}

#[test]
fn quick_commands_wait_in_a_queue_until_something_is_sent() {
    let dir = tempfile::tempdir().unwrap();
    let host = mock(true);
    let env = env_for(dir.path(), &host.url());
    let mut diag = Vec::new();
    let queue = dir.path().join(QUEUE_FILE);
    reporter(&env, &mut diag)
        .unwrap()
        .command_finished(report(None), false, &mut diag);
    assert!(queue.exists());
    quiet(&host);

    reporter(&env, &mut diag)
        .unwrap()
        .command_finished(report(None), true, &mut diag);
    assert_eq!(batch(&host).len(), 2);
    assert!(!queue.exists());
}

#[test]
fn server_events_carry_features_and_every_counter() {
    let dir = tempfile::tempdir().unwrap();
    let host = mock(true);
    let env = env_for(dir.path(), &host.url());
    let mut diag = Vec::new();
    let reporter = reporter(&env, &mut diag).unwrap();
    let features = Features {
        listing: true,
        uploads_enabled: true,
        ..Features::default()
    };
    reporter.server_started("serve", features, &mut diag);
    let start = batch(&host);
    assert_eq!(start[0]["event"], "server started");
    assert_eq!(start[0]["properties"]["features"]["uploads_enabled"], true);

    let counters = ServerCounters {
        uptime_seconds: 7,
        requests_total: 42,
        requests_active: 0,
        bytes_sent: 3 * 1024 * 1024,
        bytes_received: 512,
        errors_total: 1,
        connections_rejected: 2,
    };
    reporter.server_heartbeat("serve", features, counters, &mut diag);
    assert_eq!(batch(&host)[0]["event"], "server heartbeat");
    reporter.server_stopped("serve", features, counters, &mut diag);
    let stop = batch(&host);
    let sent = &stop[0]["properties"];
    for (key, want) in [
        ("requests_total", 42),
        ("bytes_sent", 3_145_728),
        ("bytes_received", 512),
        ("errors_total", 1),
        ("connections_rejected", 2),
        ("uptime_seconds", 7),
    ] {
        assert_eq!(sent[key], want, "{key}");
    }
}

#[test]
fn disabled_runs_never_touch_the_network_print_or_save() {
    for (k, v) in [
        ("DO_NOT_TRACK", "1"),
        ("BLAZE_TELEMETRY", "0"),
        ("CI", "true"),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let host = mock(true);
        let env = env_for(dir.path(), &host.url()).with(k, v);
        let mut diag = Vec::new();
        assert!(reporter(&env, &mut diag).is_none());
        assert!(diag.is_empty(), "{k} must not print the notice");
        quiet(&host);
        assert!(!dir.path().join("telemetry.json").exists(), "{k}");
    }
}

#[test]
fn nothing_is_sent_before_the_notice_can_be_seen() {
    let dir = tempfile::tempdir().unwrap();
    let host = mock(true);
    let env = env_for(dir.path(), &host.url());
    let mut diag = Vec::new();
    assert!(open(&env.lookup(), None, None, &mut diag, false, false).is_none());
    assert!(diag.is_empty());
    assert!(!dir.path().join("telemetry.json").exists());
    quiet(&host);
}

#[test]
fn someone_shown_the_old_notice_sees_the_new_one_and_a_no_stays_no() {
    let dir = tempfile::tempdir().unwrap();
    let host = mock(true);
    let env = env_for(dir.path(), &host.url());
    let path = settings_path(&env.lookup()).unwrap();
    std::fs::write(&path, r#"{"enabled":true,"notice_shown":true}"#).unwrap();
    let mut diag = Vec::new();
    assert!(reporter(&env, &mut diag).is_some());
    assert_eq!(String::from_utf8(diag).unwrap(), notice_text());

    std::fs::write(&path, r#"{"enabled":false,"notice_shown":true}"#).unwrap();
    let mut diag = Vec::new();
    assert!(reporter(&env, &mut diag).is_none());
    assert!(diag.is_empty());
}

#[test]
fn the_persisted_choice_survives_and_reset_restores_the_notice() {
    let dir = tempfile::tempdir().unwrap();
    let host = mock(true);
    let env = env_for(dir.path(), &host.url());
    let path = settings_path(&env.lookup()).unwrap();
    let off = Settings {
        enabled: false,
        ..Settings::default()
    };
    save_settings(&path, &off).unwrap();
    let mut diag = Vec::new();
    assert!(reporter(&env, &mut diag).is_none());
    quiet(&host);

    reset_settings(&path).unwrap();
    assert_eq!(load_settings(&path), Ok(None));
    assert!(reporter(&env, &mut diag).is_some());
    assert!(!diag.is_empty(), "the question returns after a reset");
}

#[test]
fn unreadable_or_unwritable_state_means_no_send() {
    let dir = tempfile::tempdir().unwrap();
    let host = mock(true);
    std::fs::write(dir.path().join("telemetry.json"), "{not json").unwrap();
    let mut diag = Vec::new();
    assert!(reporter(&env_for(dir.path(), &host.url()), &mut diag).is_none());

    let blocker = dir.path().join("blocker");
    std::fs::write(&blocker, "a file, not a directory").unwrap();
    let nested = blocker.join("sub");
    assert!(reporter(&env_for(&nested, &host.url()), &mut diag).is_none());
    assert!(
        diag.is_empty(),
        "the notice must not print when it cannot be recorded"
    );
    quiet(&host);
}

#[test]
fn debug_mode_prints_the_event_and_sends_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let host = mock(true);
    let env = env_for(dir.path(), &host.url()).with("BLAZE_TELEMETRY_DEBUG", "1");
    let mut diag = Vec::new();
    reporter(&env, &mut diag)
        .unwrap()
        .command_finished(report(None), true, &mut diag);
    let out = String::from_utf8(diag).unwrap();
    let line = out
        .lines()
        .find_map(|l| l.strip_prefix("telemetry (not sent): "))
        .expect("event line");
    let event: Value = serde_json::from_str(line).unwrap();
    assert_eq!(event["event"], "command finished");
    quiet(&host);
}

#[test]
fn a_hanging_or_dead_host_never_delays_a_command() {
    let hanging = mock(false);
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let dead = format!("http://{}", closed.local_addr().unwrap());
    drop(closed);
    for url in [hanging.url(), dead] {
        let dir = tempfile::tempdir().unwrap();
        let env = env_for(dir.path(), &url);
        let mut diag = Vec::new();
        let reporter = reporter(&env, &mut diag).unwrap();
        let (_, start) = elapsed(|| {
            reporter.server_started("serve", Features::default(), &mut Vec::new());
        });
        assert!(start < Duration::from_millis(300), "start took {start:?}");
        let (_, end) = elapsed(|| reporter.command_finished(report(None), true, &mut Vec::new()));
        assert!(end < Duration::from_millis(1500), "exit took {end:?}");
    }
}

#[test]
fn the_notice_is_plain_and_complete() {
    let text = anstream::adapter::strip_str(&notice_text()).to_string();
    for needle in [
        "blaze telemetry disable",
        "BLAZE_TELEMETRY=0",
        "DO_NOT_TRACK=1",
        "blaze telemetry preview",
        "On by default",
        "Anonymous",
        "PostHog in the EU",
        "random install ID",
        "location",
        "Never",
        "https://github.com/whoisjayd/blazeserve#telemetry",
    ] {
        assert!(
            text.contains(needle),
            "notice is missing {needle:?}:\n{text}"
        );
    }
    assert!(
        text.lines().all(|l| l.chars().count() <= 80),
        "it must fit a narrow terminal:\n{text}"
    );
    assert!(!text.contains('!'));
}

#[test]
fn feedback_is_delivered_or_says_why_not() {
    let dir = tempfile::tempdir().unwrap();
    let host = mock(true);
    let env = env_for(dir.path(), &host.url()).with("DO_NOT_TRACK", "1");
    let extra: serde_json::Map<String, Value> = [("rating".to_owned(), Value::from(5))]
        .into_iter()
        .collect();
    blazeserve::usage::send_feedback(&env.lookup(), None, None, "feedback rating", extra.clone())
        .expect("a person's own act is sent even with analytics off");
    let events = batch(&host);
    assert_eq!(events[0]["event"], "feedback rating");
    assert_eq!(events[0]["properties"]["rating"], 5);
    assert!(!dir.path().join("telemetry.json").exists());

    let dead = env_for(dir.path(), "http://127.0.0.1:1");
    assert!(
        blazeserve::usage::send_feedback(&dead.lookup(), None, None, "feedback bug", extra)
            .is_err()
    );
}
