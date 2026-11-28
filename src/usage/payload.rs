//! The event shape, the closed list of properties and the coarse buckets that keep reports
//! anonymous.

use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use serde_json::{Map, Value};

use super::Env;
use crate::config::Config;

pub const BYTES_BUCKETS: &[&str] = &[
    "0",
    "<1MiB",
    "1-10MiB",
    "10-100MiB",
    "100MiB-1GiB",
    "1-10GiB",
    "10-100GiB",
    ">100GiB",
];
pub const CHANNELS: &[&str] = &["pip", "cargo", "docker", "binary", "unknown"];

/// Every property an event may carry. A new one must be added here on purpose.
pub const ALLOWED_PROPERTIES: &[&str] = &[
    // PostHog
    "distinct_id",
    "$session_id",
    "$process_person_profile",
    "$lib",
    "$lib_version",
    "$os",
    "$exception_list",
    "$exception_fingerprint",
    // Where it runs
    "version",
    "os",
    "arch",
    "install_channel",
    "interactive",
    "os_distribution",
    "os_version",
    "cpu_count",
    "memory_bucket",
    "disk_total_bucket",
    "disk_free_bucket",
    "language",
    "libc",
    "terminal",
    "shell",
    "container",
    "wsl",
    "ssh",
    "python",
    // What a person chose to send: a rating, or a bug report
    "rating",
    "feedback_text",
    "contact",
    "report_id",
    "steps",
    "expected",
    "run_log",
    "run_session_id",
    "log_id",
    // What ran
    "command",
    "flags",
    "background",
    "features",
    // How it went
    "outcome",
    "exit_code",
    "error_kind",
    "duration_ms",
    // A server's own counters
    "uptime_seconds",
    "requests_total",
    "requests_active",
    "bytes_sent",
    "bytes_received",
    "errors_total",
    "connections_rejected",
    // Transfer tracing
    "size_bucket",
    "connections",
    "segmented",
    "resumed",
    "retries",
    "throughput_mib_s",
    "probe_ms",
    "transfer_ms",
    "verify_ms",
    "extract_ms",
    "hash_ms",
];

pub const FEATURE_KEYS: &[&str] = &[
    "tls",
    "auth",
    "uploads_enabled",
    "rate_limit",
    "cors",
    "trust_proxy",
    "single_file",
    "listing",
];

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Features {
    pub tls: bool,
    pub auth: bool,
    pub uploads_enabled: bool,
    pub rate_limit: bool,
    pub cors: bool,
    pub trust_proxy: bool,
    pub single_file: bool,
    pub listing: bool,
}

impl Features {
    pub fn from_config(cfg: &Config) -> Self {
        Self {
            tls: cfg.tls.is_some(),
            auth: cfg.auth.is_some(),
            uploads_enabled: cfg.max_upload_bytes > 0,
            rate_limit: cfg.rate_mbps.is_some(),
            cors: cfg.cors,
            trust_proxy: !cfg.trusted_proxies.is_empty(),
            single_file: cfg.single.is_some(),
            listing: cfg.listing,
        }
    }
}

/// The counters of a running server: totals since it started, never per visitor.
#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct ServerCounters {
    pub uptime_seconds: u64,
    pub requests_total: u64,
    pub requests_active: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub errors_total: u64,
    pub connections_rejected: u64,
}

impl ServerCounters {
    pub fn of(metrics: &crate::metrics::Metrics) -> Self {
        let stats = metrics.stats();
        Self {
            uptime_seconds: stats.uptime_seconds,
            requests_total: stats.requests_total,
            requests_active: stats.requests_active,
            bytes_sent: stats.bytes_sent,
            bytes_received: stats.bytes_received,
            errors_total: stats.errors_total,
            connections_rejected: metrics.connections_rejected(),
        }
    }
}

/// One item of a PostHog `/batch/` request.
#[derive(Debug, Clone, Serialize)]
pub struct Event {
    event: String,
    timestamp: String,
    properties: Map<String, Value>,
}

impl Event {
    /// `common` identifies the run; `extra` is cut down to the allowed properties.
    pub(super) fn new(name: &str, common: &Map<String, Value>, extra: Map<String, Value>) -> Self {
        let mut properties = common.clone();
        properties.extend(
            extra
                .into_iter()
                .filter(|(k, _)| ALLOWED_PROPERTIES.contains(&k.as_str())),
        );
        Self {
            event: name.to_owned(),
            timestamp: timestamp(),
            properties,
        }
    }
}

fn timestamp() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let seconds = crate::logging::format_utc(now.as_secs());
    format!(
        "{}.{:03}Z",
        seconds.trim_end_matches('Z'),
        now.subsec_millis()
    )
}

pub fn bytes_bucket(n: u64) -> &'static str {
    const MIB: u64 = 1024 * 1024;
    const GIB: u64 = 1024 * MIB;
    let i = match n {
        0 => 0,
        1..=0xF_FFFF => 1,
        x if x < 10 * MIB => 2,
        x if x < 100 * MIB => 3,
        x if x < GIB => 4,
        x if x < 10 * GIB => 5,
        x if x < 100 * GIB => 6,
        _ => 7,
    };
    BYTES_BUCKETS[i]
}

fn os_name() -> &'static str {
    match std::env::consts::OS {
        "windows" => "windows",
        "linux" => "linux",
        "macos" => "macos",
        _ => "other",
    }
}

fn arch_name() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "x86_64",
        "aarch64" => "aarch64",
        _ => "other",
    }
}

fn channel(env: &Env) -> &'static str {
    let v = env("BLAZE_INSTALL_CHANNEL")
        .unwrap_or_default()
        .to_ascii_lowercase();
    CHANNELS
        .iter()
        .copied()
        .find(|c| *c == v && *c != "unknown")
        .unwrap_or("unknown")
}

/// The properties every event of one run shares.
pub(super) fn common(
    env: &Env,
    install_id: &str,
    session_id: &str,
    interactive: bool,
) -> Map<String, Value> {
    let pairs: [(&str, Value); 11] = [
        ("distinct_id", install_id.into()),
        ("$session_id", session_id.into()),
        // Anonymous events: PostHog builds no person profile.
        ("$process_person_profile", false.into()),
        ("$lib", "blazeserve".into()),
        ("$lib_version", crate::VERSION.into()),
        ("$os", os_name().into()),
        ("version", crate::VERSION.into()),
        ("os", os_name().into()),
        ("arch", arch_name().into()),
        ("install_channel", channel(env).into()),
        ("interactive", interactive.into()),
    ];
    let mut out: Map<String, Value> = pairs.into_iter().map(|(k, v)| (k.to_owned(), v)).collect();
    out.extend(super::environment::facts(env));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_edges() {
        assert_eq!(bytes_bucket(0), "0");
        assert_eq!(bytes_bucket(1), "<1MiB");
        assert_eq!(bytes_bucket(1024 * 1024), "1-10MiB");
        assert_eq!(bytes_bucket(1024 * 1024 * 1024 - 1), "100MiB-1GiB");
        assert_eq!(bytes_bucket(u64::MAX), ">100GiB");
    }

    #[test]
    fn properties_outside_the_list_are_dropped() {
        let common = common(&|_| None, "i", "s", true);
        let extra: Map<String, Value> = [
            ("command".to_owned(), Value::from("get")),
            ("url".to_owned(), Value::from("http://secret/")),
            ("path".to_owned(), Value::from("/home/x")),
        ]
        .into_iter()
        .collect();
        let event = Event::new("e", &common, extra);
        assert_eq!(event.properties["command"], "get");
        assert!(!event.properties.contains_key("url"));
        assert!(!event.properties.contains_key("path"));
        for key in common.keys() {
            assert!(ALLOWED_PROPERTIES.contains(&key.as_str()), "{key}");
        }
        assert!(event.timestamp.ends_with('Z') && event.timestamp.len() == 24);
    }
}
