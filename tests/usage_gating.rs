mod usage_support;

use blazeserve::usage::{Decision, Reason, Settings, config_dir, decide, relay_url};
use usage_support::Env;

const RELAY: &str = "https://relay.example.com";

fn enabled_settings() -> Option<Settings> {
    Some(Settings::default())
}

fn decision(env: &Env, persisted: Option<Settings>, relay: Option<&str>) -> Decision {
    decide(&env.lookup(), persisted, relay)
}

#[test]
fn enabled_by_default_when_a_relay_exists() {
    assert_eq!(
        decision(&Env::new(&[]), enabled_settings(), Some(RELAY)),
        Decision::Enabled
    );
}

#[test]
fn do_not_track_is_honored_for_any_nonzero_value() {
    for v in ["1", "true", "yes", "anything"] {
        let env = Env::new(&[("DO_NOT_TRACK", v)]);
        assert_eq!(
            decision(&env, enabled_settings(), Some(RELAY)),
            Decision::Disabled(Reason::DoNotTrack),
            "DO_NOT_TRACK={v}"
        );
    }
    for v in ["", "0"] {
        let env = Env::new(&[("DO_NOT_TRACK", v)]);
        assert_eq!(
            decision(&env, enabled_settings(), Some(RELAY)),
            Decision::Enabled
        );
    }
}

#[test]
fn blaze_telemetry_off_values() {
    for v in ["0", "false", "off", "no", "OFF", "False"] {
        let env = Env::new(&[("BLAZE_TELEMETRY", v)]);
        assert_eq!(
            decision(&env, enabled_settings(), Some(RELAY)),
            Decision::Disabled(Reason::EnvDisabled),
            "BLAZE_TELEMETRY={v}"
        );
    }
    let on = Env::new(&[("BLAZE_TELEMETRY", "1")]);
    assert_eq!(
        decision(&on, enabled_settings(), Some(RELAY)),
        Decision::Enabled
    );
}

#[test]
fn explicit_on_never_overrides_a_stronger_off() {
    let env = Env::new(&[("BLAZE_TELEMETRY", "1"), ("DO_NOT_TRACK", "1")]);
    assert_eq!(
        decision(&env, enabled_settings(), Some(RELAY)),
        Decision::Disabled(Reason::DoNotTrack)
    );
    let disabled = Some(Settings {
        enabled: false,
        notice_shown: true,
    });
    let env = Env::new(&[("BLAZE_TELEMETRY", "1")]);
    assert_eq!(
        decision(&env, disabled, Some(RELAY)),
        Decision::Disabled(Reason::SettingDisabled)
    );
}

#[test]
fn ci_disables_unless_it_is_false_or_zero() {
    for v in ["1", "true", "github"] {
        let env = Env::new(&[("CI", v)]);
        assert_eq!(
            decision(&env, enabled_settings(), Some(RELAY)),
            Decision::Disabled(Reason::Ci),
            "CI={v}"
        );
    }
    for v in ["", "0", "false", "FALSE"] {
        let env = Env::new(&[("CI", v)]);
        assert_eq!(
            decision(&env, enabled_settings(), Some(RELAY)),
            Decision::Enabled,
            "CI={v}"
        );
    }
}

#[test]
fn gate_order_first_match_wins() {
    let env = Env::new(&[("DO_NOT_TRACK", "1"), ("BLAZE_TELEMETRY", "0"), ("CI", "1")]);
    let disabled = Some(Settings {
        enabled: false,
        notice_shown: true,
    });
    assert_eq!(
        decision(&env, disabled, None),
        Decision::Disabled(Reason::DoNotTrack)
    );

    let env = Env::new(&[("BLAZE_TELEMETRY", "0"), ("CI", "1")]);
    assert_eq!(
        decision(&env, disabled, None),
        Decision::Disabled(Reason::EnvDisabled)
    );

    let env = Env::new(&[("CI", "1")]);
    assert_eq!(
        decision(&env, disabled, None),
        Decision::Disabled(Reason::Ci)
    );

    let env = Env::new(&[]);
    assert_eq!(
        decision(&env, disabled, None),
        Decision::Disabled(Reason::SettingDisabled)
    );
    assert_eq!(
        decision(&env, None, None),
        Decision::Disabled(Reason::SettingsUnreadable)
    );
    assert_eq!(
        decision(&env, enabled_settings(), None),
        Decision::Disabled(Reason::NoRelay)
    );
}

#[test]
fn relay_must_be_https_except_on_loopback() {
    let env = Env::new(&[]);
    for url in [
        "http://relay.example.com",
        "ftp://x",
        "relay.example.com",
        "https://",
        "http://127.0.0.1.evil.com",
    ] {
        assert_eq!(
            decision(&env, enabled_settings(), Some(url)),
            Decision::Disabled(Reason::RelayInvalid),
            "{url}"
        );
    }
    for url in [
        "https://relay.example.com/base",
        "http://127.0.0.1:9000",
        "http://localhost:8787",
        "http://[::1]:80",
    ] {
        assert_eq!(
            decision(&env, enabled_settings(), Some(url)),
            Decision::Enabled,
            "{url}"
        );
    }
}

#[test]
fn runtime_relay_overrides_the_build_time_one() {
    let env = Env::new(&[("BLAZE_TELEMETRY_URL", "https://override.example")]);
    assert_eq!(
        relay_url(&env.lookup(), Some("https://baked.example")).as_deref(),
        Some("https://override.example")
    );
    let empty = Env::new(&[("BLAZE_TELEMETRY_URL", "  ")]);
    assert_eq!(
        relay_url(&empty.lookup(), Some("https://baked.example")).as_deref(),
        Some("https://baked.example")
    );
    assert_eq!(relay_url(&Env::new(&[]).lookup(), None), None);
}

#[test]
fn config_dir_override_wins() {
    let env = Env::new(&[("BLAZE_CONFIG_DIR", "/tmp/blaze-test")]);
    assert_eq!(
        config_dir(&env.lookup()).unwrap(),
        std::path::PathBuf::from("/tmp/blaze-test")
    );
    assert!(config_dir(&Env::new(&[]).lookup()).is_none_or(|p| p.ends_with("blazeserve")));
}
