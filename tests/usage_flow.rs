mod usage_support;

use blazeserve::usage::{
    Command, Features, Settings, StopStats, begin, load_settings, notice_text, reset_settings,
    save_settings, settings_path,
};
use serde_json::Value;
use std::time::Duration;
use usage_support::{Env, elapsed, mock, wait_for};

fn features() -> Features {
    Features {
        listing: true,
        uploads_enabled: true,
        ..Features::default()
    }
}

fn env_for(dir: &std::path::Path, relay: &str) -> Env {
    Env::new(&[
        ("BLAZE_CONFIG_DIR", dir.to_str().unwrap()),
        ("BLAZE_TELEMETRY_URL", relay),
        ("BLAZE_INSTALL_CHANNEL", "pip"),
    ])
}

#[test]
fn start_posts_exactly_one_event_and_prints_the_notice_once() {
    let dir = tempfile::tempdir().unwrap();
    let relay = mock(true);
    let env = env_for(dir.path(), &relay.url());

    let mut diag = Vec::new();
    let session = begin(&env.lookup(), None, &mut diag, Command::Serve, features());
    assert!(session.is_some());
    let notice = String::from_utf8(diag).unwrap();
    assert_eq!(notice, notice_text());

    let req = wait_for(&relay.requests, 5).expect("start event was not delivered");
    assert!(
        req.head.starts_with("POST /v1/event HTTP/1.1"),
        "{}",
        req.head
    );
    let body: Value = serde_json::from_str(&req.body).unwrap();
    assert_eq!(body["event"], "start");
    assert_eq!(body["command"], "serve");
    assert_eq!(body["install_channel"], "pip");
    assert_eq!(body["features"]["uploads_enabled"], true);
    assert!(!req.body.contains("install_id"));
    assert!(
        relay
            .requests
            .recv_timeout(Duration::from_millis(300))
            .is_err(),
        "only one event"
    );

    let mut second = Vec::new();
    let again = begin(&env.lookup(), None, &mut second, Command::Serve, features());
    assert!(again.is_some());
    assert!(second.is_empty(), "the notice must be shown only once");
    assert!(wait_for(&relay.requests, 5).is_some());
}

#[test]
fn finish_posts_a_bucketed_stop_event() {
    let dir = tempfile::tempdir().unwrap();
    let relay = mock(true);
    let env = env_for(dir.path(), &relay.url());
    let mut diag = Vec::new();
    let session = begin(&env.lookup(), None, &mut diag, Command::Send, features()).unwrap();
    let _start = wait_for(&relay.requests, 5).unwrap();

    session.finish(
        StopStats {
            requests_total: 42,
            bytes_sent: 3 * 1024 * 1024,
            errors_total: 0,
        },
        &mut diag,
    );
    let stop = wait_for(&relay.requests, 5).expect("stop event was not delivered");
    let body: Value = serde_json::from_str(&stop.body).unwrap();
    assert_eq!(body["event"], "stop");
    assert_eq!(body["command"], "send");
    assert_eq!(body["requests_bucket"], "10-99");
    assert_eq!(body["bytes_sent_bucket"], "1-10MiB");
    assert_eq!(body["had_errors"], false);
    assert_eq!(body["install_channel"], "pip");
    assert!(!stop.body.contains("42,") && !stop.body.contains("3145728"));
}

#[test]
fn disabled_runs_never_touch_the_network_or_print() {
    for (k, v) in [
        ("DO_NOT_TRACK", "1"),
        ("BLAZE_TELEMETRY", "0"),
        ("CI", "true"),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let relay = mock(true);
        let env = env_for(dir.path(), &relay.url()).with(k, v);
        let mut diag = Vec::new();
        assert!(begin(&env.lookup(), None, &mut diag, Command::Serve, features()).is_none());
        assert!(diag.is_empty(), "{k} must not print the notice");
        std::thread::sleep(Duration::from_millis(250));
        assert_eq!(relay.connection_count(), 0, "{k} must not connect");
        assert!(
            !dir.path().join("telemetry.json").exists(),
            "{k} must not write settings"
        );
    }
}

#[test]
fn a_build_without_a_relay_is_inert_and_silent() {
    let dir = tempfile::tempdir().unwrap();
    let env = Env::new(&[("BLAZE_CONFIG_DIR", dir.path().to_str().unwrap())]);
    let mut diag = Vec::new();
    assert!(begin(&env.lookup(), None, &mut diag, Command::Serve, features()).is_none());
    assert!(diag.is_empty());
    assert!(!dir.path().join("telemetry.json").exists());
}

#[test]
fn the_persisted_choice_survives_and_reset_restores_the_notice() {
    let dir = tempfile::tempdir().unwrap();
    let relay = mock(true);
    let env = env_for(dir.path(), &relay.url());
    let path = settings_path(&env.lookup()).unwrap();

    save_settings(
        &path,
        Settings {
            enabled: false,
            notice_shown: true,
        },
    )
    .unwrap();
    let mut diag = Vec::new();
    assert!(begin(&env.lookup(), None, &mut diag, Command::Serve, features()).is_none());
    assert!(diag.is_empty());
    std::thread::sleep(Duration::from_millis(250));
    assert_eq!(relay.connection_count(), 0);

    reset_settings(&path).unwrap();
    assert_eq!(load_settings(&path), Ok(None));
    let mut diag = Vec::new();
    assert!(begin(&env.lookup(), None, &mut diag, Command::Serve, features()).is_some());
    assert!(!diag.is_empty(), "the notice returns after a reset");
}

#[test]
fn unreadable_or_unwritable_state_means_no_send() {
    let dir = tempfile::tempdir().unwrap();
    let relay = mock(true);
    let env = env_for(dir.path(), &relay.url());
    std::fs::write(dir.path().join("telemetry.json"), "{not json").unwrap();
    let mut diag = Vec::new();
    assert!(begin(&env.lookup(), None, &mut diag, Command::Serve, features()).is_none());
    assert!(diag.is_empty());

    let blocker = dir.path().join("blocker");
    std::fs::write(&blocker, "a file, not a directory").unwrap();
    let nested = blocker.join("sub");
    let env = env_for(&nested, &relay.url());
    let mut diag = Vec::new();
    assert!(begin(&env.lookup(), None, &mut diag, Command::Serve, features()).is_none());
    assert!(
        diag.is_empty(),
        "the notice must not print when it cannot be recorded"
    );
    std::thread::sleep(Duration::from_millis(250));
    assert_eq!(relay.connection_count(), 0);
}

#[test]
fn debug_mode_prints_the_payload_and_sends_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let relay = mock(true);
    let env = env_for(dir.path(), &relay.url()).with("BLAZE_TELEMETRY_DEBUG", "1");
    let mut diag = Vec::new();
    let session = begin(&env.lookup(), None, &mut diag, Command::Serve, features());
    assert!(session.is_some());
    let out = String::from_utf8(diag).unwrap();
    let line = out
        .lines()
        .find_map(|l| l.strip_prefix("telemetry (not sent): "))
        .expect("payload line");
    let body: Value = serde_json::from_str(line).unwrap();
    assert_eq!(body["event"], "start");
    std::thread::sleep(Duration::from_millis(250));
    assert_eq!(relay.connection_count(), 0);
}

#[test]
fn a_hanging_relay_never_delays_start_or_shutdown() {
    let dir = tempfile::tempdir().unwrap();
    let relay = mock(false);
    let env = env_for(dir.path(), &relay.url());
    let mut diag = Vec::new();
    let (session, start_took) =
        elapsed(|| begin(&env.lookup(), None, &mut diag, Command::Serve, features()));
    assert!(
        start_took < Duration::from_secs(1),
        "start took {start_took:?}"
    );
    let (_, stop_took) = elapsed(|| session.unwrap().finish(StopStats::default(), &mut diag));
    assert!(
        stop_took < Duration::from_millis(1500),
        "shutdown was delayed by {stop_took:?}"
    );
}

#[test]
fn a_dead_relay_is_silent_and_fast() {
    let dir = tempfile::tempdir().unwrap();
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", closed.local_addr().unwrap());
    drop(closed);
    let env = env_for(dir.path(), &url);
    let mut diag = Vec::new();
    let (session, took) =
        elapsed(|| begin(&env.lookup(), None, &mut diag, Command::Serve, features()));
    assert!(took < Duration::from_secs(1));
    let (_, stop_took) = elapsed(|| session.unwrap().finish(StopStats::default(), &mut diag));
    assert!(stop_took < Duration::from_millis(1500));
    assert_eq!(String::from_utf8(diag).unwrap(), notice_text());
}

#[test]
fn the_notice_is_plain_and_complete() {
    let text = notice_text();
    for needle in [
        "blaze telemetry disable",
        "BLAZE_TELEMETRY=0",
        "DO_NOT_TRACK=1",
        "anonymous",
        "https://github.com/whoisjayd/blazeserve#telemetry",
    ] {
        assert!(text.contains(needle), "notice is missing {needle:?}");
    }
    assert!(text.is_ascii());
    assert!(!text.contains('!'));
}
