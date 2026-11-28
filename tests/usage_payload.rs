//! What an event may carry. `docs/telemetry.md` is the contract these tests hold.

mod usage_support;

use blazeserve::usage::{ALLOWED_PROPERTIES, CHANNELS, FEATURE_KEYS, Features, preview};
use serde_json::Value;
use usage_support::Env;

fn properties(event: &Value) -> &serde_json::Map<String, Value> {
    event["properties"].as_object().expect("properties")
}

#[test]
fn every_example_property_is_on_the_allowlist() {
    let events = preview(&Env::new(&[]).lookup());
    assert!(!events.is_empty());
    for event in &events {
        for key in properties(event).keys() {
            assert!(ALLOWED_PROPERTIES.contains(&key.as_str()), "{key}");
        }
        assert_eq!(event["properties"]["$process_person_profile"], false);
        assert!(event["timestamp"].as_str().unwrap().ends_with('Z'));
    }
}

#[test]
fn nothing_on_the_allowlist_can_name_a_file_or_a_machine() {
    for key in ALLOWED_PROPERTIES {
        for word in [
            "path", "file", "url", "host", "ip", "user", "name", "message",
        ] {
            assert!(
                !key.trim_start_matches('$')
                    .split('_')
                    .any(|part| part == word),
                "{key} may carry something private"
            );
        }
    }
}

#[test]
fn features_are_only_yes_or_no() {
    let value = serde_json::to_value(Features::default()).unwrap();
    let object = value.as_object().unwrap();
    let keys: Vec<&str> = object.keys().map(String::as_str).collect();
    let mut expected = FEATURE_KEYS.to_vec();
    expected.sort_unstable();
    let mut got = keys;
    got.sort_unstable();
    assert_eq!(got, expected);
    assert!(object.values().all(Value::is_boolean));
}

#[test]
fn install_channel_comes_only_from_a_known_value() {
    for (given, want) in [
        ("pip", "pip"),
        ("DOCKER", "docker"),
        ("cargo", "cargo"),
        ("homebrew", "unknown"),
        ("", "unknown"),
    ] {
        let env = Env::new(&[("BLAZE_INSTALL_CHANNEL", given)]);
        let events = preview(&env.lookup());
        let channel = events[0]["properties"]["install_channel"].as_str().unwrap();
        assert_eq!(channel, want, "given {given:?}");
        assert!(CHANNELS.contains(&channel));
    }
}
