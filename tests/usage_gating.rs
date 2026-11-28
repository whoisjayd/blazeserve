mod usage_support;

use blazeserve::usage::{
    DEFAULT_HOST, Decision, Reason, Settings, Target, config_dir, decide, target,
};
use usage_support::Env;

const HOST: &str = "https://eu.i.posthog.com";
const KEY: &str = "phc_test";

fn enabled_settings() -> Option<Settings> {
    Some(Settings::default())
}

fn decision(env: &Env, persisted: Option<Settings>, host: Option<&str>) -> Decision {
    let target = host.map(|host| Target {
        key: KEY.to_owned(),
        host: host.to_owned(),
    });
    decide(&env.lookup(), persisted.as_ref(), target.as_ref())
}

#[test]
fn enabled_by_default_when_a_relay_exists() {
    assert_eq!(
        decision(&Env::new(&[]), enabled_settings(), Some(HOST)),
        Decision::Enabled
    );
}

#[test]
fn do_not_track_is_honored_for_any_nonzero_value() {
    for v in ["1", "true", "yes", "anything"] {
        let env = Env::new(&[("DO_NOT_TRACK", v)]);
        assert_eq!(
            decision(&env, enabled_settings(), Some(HOST)),
            Decision::Disabled(Reason::DoNotTrack),
            "DO_NOT_TRACK={v}"
        );
    }
    for v in ["", "0"] {
        let env = Env::new(&[("DO_NOT_TRACK", v)]);
        assert_eq!(
            decision(&env, enabled_settings(), Some(HOST)),
            Decision::Enabled
        );
    }
}

#[test]
fn blaze_telemetry_off_values() {
    for v in ["0", "false", "off", "no", "OFF", "False"] {
        let env = Env::new(&[("BLAZE_TELEMETRY", v)]);
        assert_eq!(
            decision(&env, enabled_settings(), Some(HOST)),
            Decision::Disabled(Reason::EnvDisabled),
            "BLAZE_TELEMETRY={v}"
        );
    }
    let on = Env::new(&[("BLAZE_TELEMETRY", "1")]);
    assert_eq!(
        decision(&on, enabled_settings(), Some(HOST)),
        Decision::Enabled
    );
}

#[test]
fn explicit_on_never_overrides_a_stronger_off() {
    let env = Env::new(&[("BLAZE_TELEMETRY", "1"), ("DO_NOT_TRACK", "1")]);
    assert_eq!(
        decision(&env, enabled_settings(), Some(HOST)),
        Decision::Disabled(Reason::DoNotTrack)
    );
    let disabled = Some(Settings {
        enabled: false,
        ..Settings::default()
    });
    let env = Env::new(&[("BLAZE_TELEMETRY", "1")]);
    assert_eq!(
        decision(&env, disabled.clone(), Some(HOST)),
        Decision::Disabled(Reason::SettingDisabled)
    );
}

#[test]
fn ci_disables_unless_it_is_false_or_zero() {
    for v in ["1", "true", "github"] {
        let env = Env::new(&[("CI", v)]);
        assert_eq!(
            decision(&env, enabled_settings(), Some(HOST)),
            Decision::Disabled(Reason::Ci),
            "CI={v}"
        );
    }
    for v in ["", "0", "false", "FALSE"] {
        let env = Env::new(&[("CI", v)]);
        assert_eq!(
            decision(&env, enabled_settings(), Some(HOST)),
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
        ..Settings::default()
    });
    assert_eq!(
        decision(&env, disabled.clone(), None),
        Decision::Disabled(Reason::DoNotTrack)
    );

    let env = Env::new(&[("BLAZE_TELEMETRY", "0"), ("CI", "1")]);
    assert_eq!(
        decision(&env, disabled.clone(), None),
        Decision::Disabled(Reason::EnvDisabled)
    );

    let env = Env::new(&[("CI", "1")]);
    assert_eq!(
        decision(&env, disabled.clone(), None),
        Decision::Disabled(Reason::Ci)
    );

    let env = Env::new(&[]);
    assert_eq!(
        decision(&env, disabled.clone(), None),
        Decision::Disabled(Reason::SettingDisabled)
    );
    assert_eq!(
        decision(&env, None, None),
        Decision::Disabled(Reason::SettingsUnreadable)
    );
    assert_eq!(
        decision(&env, enabled_settings(), None),
        Decision::Disabled(Reason::NoKey)
    );
}

#[test]
fn the_host_must_be_https_except_on_loopback() {
    let env = Env::new(&[]);
    for url in [
        "http://posthog.example.com",
        "ftp://x",
        "posthog.example.com",
        "https://",
        "http://127.0.0.1.evil.com",
    ] {
        assert_eq!(
            decision(&env, enabled_settings(), Some(url)),
            Decision::Disabled(Reason::HostInvalid),
            "{url}"
        );
    }
    for url in [
        "https://us.i.posthog.com",
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
fn only_a_public_project_key_is_ever_used() {
    for key in ["phx_secret", "sk_live", "token"] {
        let target = Target {
            key: key.to_owned(),
            host: HOST.to_owned(),
        };
        assert_eq!(
            decide(
                &Env::new(&[]).lookup(),
                enabled_settings().as_ref(),
                Some(&target)
            ),
            Decision::Disabled(Reason::KeyInvalid),
            "{key}"
        );
    }
}

#[test]
fn runtime_values_override_the_built_in_ones() {
    let env = Env::new(&[("BLAZE_POSTHOG_KEY", "phc_override")]);
    let got = target(&env.lookup(), Some("phc_baked"), None).unwrap();
    assert_eq!(
        (got.key.as_str(), got.host.as_str()),
        ("phc_override", DEFAULT_HOST)
    );
    let blank = Env::new(&[("BLAZE_POSTHOG_KEY", "  ")]);
    assert_eq!(
        target(&blank.lookup(), Some("phc_baked"), Some("https://baked")).map(|t| (t.key, t.host)),
        Some(("phc_baked".to_owned(), "https://baked".to_owned()))
    );
    assert_eq!(
        target(&Env::new(&[]).lookup(), None, Some("https://baked")),
        None
    );
    assert_eq!(target(&Env::new(&[]).lookup(), Some(""), None), None);
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
