mod usage_support;

use blazeserve::usage::{
    ALLOWED_KEYS, ARCHES, BYTES_BUCKETS, CHANNELS, COMMANDS, COUNT_BUCKETS, Command, EVENTS,
    FEATURE_KEYS, Features, OSES, StopStats, UPTIME_BUCKETS, bytes_bucket, count_bucket,
    start_event, stop_event, uptime_bucket,
};
use serde_json::Value;
use std::collections::BTreeSet;
use std::time::Duration;
use usage_support::Env;

fn keys(v: &Value) -> BTreeSet<String> {
    v.as_object().unwrap().keys().cloned().collect()
}

fn set(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| (*s).to_owned()).collect()
}

fn sample_features() -> Features {
    Features {
        tls: true,
        listing: true,
        ..Features::default()
    }
}

#[test]
fn start_payload_has_exactly_the_documented_keys() {
    let env = Env::new(&[]);
    let v = serde_json::to_value(start_event(
        &env.lookup(),
        Command::Serve,
        sample_features(),
    ))
    .unwrap();
    assert_eq!(
        keys(&v),
        set(&[
            "schema_version",
            "event",
            "version",
            "os",
            "arch",
            "command",
            "install_channel",
            "features"
        ])
    );
    assert_eq!(v["event"], "start");
    assert_eq!(v["schema_version"], 1);
    assert_eq!(v["install_channel"], "unknown");
}

#[test]
fn stop_payload_adds_only_bucketed_fields() {
    let env = Env::new(&[]);
    let stats = StopStats {
        requests_total: 12_345,
        bytes_sent: 7_777_777_777,
        errors_total: 3,
    };
    let v = serde_json::to_value(stop_event(
        &env.lookup(),
        Command::Send,
        sample_features(),
        Duration::from_secs(4000),
        stats,
    ))
    .unwrap();
    assert_eq!(
        keys(&v),
        ALLOWED_KEYS.iter().map(|s| (*s).to_owned()).collect()
    );
    assert_eq!(v["uptime_bucket"], "1-24h");
    assert_eq!(v["requests_bucket"], "10k-99k");
    assert_eq!(v["bytes_sent_bucket"], "1-10GiB");
    assert_eq!(v["had_errors"], true);
    let text = v.to_string();
    for exact in ["12345", "7777777777", "4000"] {
        assert!(
            !text.contains(exact),
            "exact counter {exact} leaked into {text}"
        );
    }
}

#[test]
fn no_field_can_be_added_without_updating_the_allowlist() {
    let env = Env::new(&[]);
    let full = serde_json::to_value(stop_event(
        &env.lookup(),
        Command::Serve,
        Features::default(),
        Duration::ZERO,
        StopStats::default(),
    ))
    .unwrap();
    assert_eq!(
        keys(&full),
        ALLOWED_KEYS.iter().map(|s| (*s).to_owned()).collect()
    );
    assert_eq!(
        keys(&full["features"]),
        FEATURE_KEYS.iter().map(|s| (*s).to_owned()).collect()
    );
    assert!(
        full["features"]
            .as_object()
            .unwrap()
            .values()
            .all(Value::is_boolean)
    );
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
        let v = serde_json::to_value(start_event(
            &env.lookup(),
            Command::Serve,
            Features::default(),
        ))
        .unwrap();
        assert_eq!(v["install_channel"], want, "given {given:?}");
    }
}

#[test]
fn every_emitted_value_is_in_its_enumerated_set() {
    let env = Env::new(&[("BLAZE_INSTALL_CHANNEL", "binary")]);
    let v = serde_json::to_value(start_event(
        &env.lookup(),
        Command::Serve,
        Features::default(),
    ))
    .unwrap();
    assert!(OSES.contains(&v["os"].as_str().unwrap()));
    assert!(ARCHES.contains(&v["arch"].as_str().unwrap()));
    assert!(COMMANDS.contains(&v["command"].as_str().unwrap()));
    assert!(CHANNELS.contains(&v["install_channel"].as_str().unwrap()));
    assert!(EVENTS.contains(&v["event"].as_str().unwrap()));
}

#[test]
fn buckets_cover_the_range_and_stay_in_their_tables() {
    let samples = [
        0u64,
        1,
        9,
        10,
        99,
        100,
        999,
        1_000,
        9_999,
        10_000,
        99_999,
        100_000,
        999_999,
        1_000_000,
        u64::MAX,
    ];
    for n in samples {
        assert!(COUNT_BUCKETS.contains(&count_bucket(n)), "count {n}");
        assert!(BYTES_BUCKETS.contains(&bytes_bucket(n)), "bytes {n}");
        assert!(UPTIME_BUCKETS.contains(&uptime_bucket(n)), "uptime {n}");
    }
    assert_eq!(count_bucket(0), "0");
    assert_eq!(count_bucket(99), "10-99");
    assert_eq!(count_bucket(100), "100-999");
    assert_eq!(bytes_bucket(1024 * 1024 * 1024), "1-10GiB");
    assert_eq!(bytes_bucket(1024 * 1024 * 1024 - 1), "100MiB-1GiB");
    assert_eq!(uptime_bucket(3599), "10-60m");
    assert_eq!(uptime_bucket(3600), "1-24h");
}

#[test]
fn relay_allowlist_matches_the_client() {
    let worker = include_str!("../deploy/telemetry-relay/worker.js");
    let all = ALLOWED_KEYS
        .iter()
        .chain(FEATURE_KEYS)
        .chain(UPTIME_BUCKETS)
        .chain(COUNT_BUCKETS)
        .chain(BYTES_BUCKETS)
        .chain(CHANNELS)
        .chain(OSES)
        .chain(ARCHES)
        .chain(COMMANDS)
        .chain(EVENTS);
    for item in all {
        assert!(
            worker.contains(&format!("\"{item}\"")),
            "relay worker.js does not mention {item:?}; update the allowlist in both places"
        );
    }
}
