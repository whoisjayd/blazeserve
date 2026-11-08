//! The event schema, its allowed keys and the coarse buckets that keep payloads anonymous.

use super::Env;
use crate::config::Config;
use serde::Serialize;
use std::time::Duration;

pub const SCHEMA_VERSION: u32 = 1;

pub const UPTIME_BUCKETS: &[&str] = &["<1m", "1-10m", "10-60m", "1-24h", ">24h"];
pub const COUNT_BUCKETS: &[&str] = &[
    "0",
    "1-9",
    "10-99",
    "100-999",
    "1k-9k",
    "10k-99k",
    "100k-999k",
    "1M+",
];
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
pub const OSES: &[&str] = &["windows", "linux", "macos", "other"];
pub const ARCHES: &[&str] = &["x86_64", "aarch64", "other"];
pub const COMMANDS: &[&str] = &["serve", "send"];
pub const EVENTS: &[&str] = &["start", "stop"];

/// Every key a payload may contain. A new field must be added here on purpose.
pub const ALLOWED_KEYS: &[&str] = &[
    "schema_version",
    "event",
    "version",
    "os",
    "arch",
    "command",
    "install_channel",
    "features",
    "uptime_bucket",
    "requests_bucket",
    "bytes_sent_bucket",
    "had_errors",
];
pub const FEATURE_KEYS: &[&str] = &[
    "tls",
    "auth",
    "uploads_enabled",
    "rate_limit",
    "cors",
    "trust_proxy",
    "otlp",
    "single_file",
    "listing",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Serve,
    Send,
}

impl Command {
    fn as_str(self) -> &'static str {
        match self {
            Command::Serve => "serve",
            Command::Send => "send",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Features {
    pub tls: bool,
    pub auth: bool,
    pub uploads_enabled: bool,
    pub rate_limit: bool,
    pub cors: bool,
    pub trust_proxy: bool,
    pub otlp: bool,
    pub single_file: bool,
    pub listing: bool,
}

impl Features {
    pub fn from_config(cfg: &Config, otlp: bool) -> Self {
        Self {
            tls: cfg.tls.is_some(),
            auth: cfg.auth.is_some(),
            uploads_enabled: cfg.max_upload_bytes > 0,
            rate_limit: cfg.rate_mbps.is_some(),
            cors: cfg.cors,
            trust_proxy: !cfg.trusted_proxies.is_empty(),
            otlp,
            single_file: cfg.single.is_some(),
            listing: cfg.listing,
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct StopStats {
    pub requests_total: u64,
    pub bytes_sent: u64,
    pub errors_total: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Event {
    schema_version: u32,
    event: &'static str,
    version: &'static str,
    os: &'static str,
    arch: &'static str,
    command: &'static str,
    install_channel: &'static str,
    features: Features,
    #[serde(skip_serializing_if = "Option::is_none")]
    uptime_bucket: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    requests_bucket: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bytes_sent_bucket: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    had_errors: Option<bool>,
}

pub fn uptime_bucket(secs: u64) -> &'static str {
    match secs {
        0..=59 => UPTIME_BUCKETS[0],
        60..=599 => UPTIME_BUCKETS[1],
        600..=3599 => UPTIME_BUCKETS[2],
        3600..=86399 => UPTIME_BUCKETS[3],
        _ => UPTIME_BUCKETS[4],
    }
}

pub fn count_bucket(n: u64) -> &'static str {
    let i = match n {
        0 => 0,
        1..=9 => 1,
        10..=99 => 2,
        100..=999 => 3,
        1_000..=9_999 => 4,
        10_000..=99_999 => 5,
        100_000..=999_999 => 6,
        _ => 7,
    };
    COUNT_BUCKETS[i]
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

pub fn start_event(env: &Env, command: Command, features: Features) -> Event {
    Event {
        schema_version: SCHEMA_VERSION,
        event: "start",
        version: crate::VERSION,
        os: os_name(),
        arch: arch_name(),
        command: command.as_str(),
        install_channel: channel(env),
        features,
        uptime_bucket: None,
        requests_bucket: None,
        bytes_sent_bucket: None,
        had_errors: None,
    }
}

pub fn stop_event(
    env: &Env,
    command: Command,
    features: Features,
    uptime: Duration,
    stats: StopStats,
) -> Event {
    Event {
        event: "stop",
        uptime_bucket: Some(uptime_bucket(uptime.as_secs())),
        requests_bucket: Some(count_bucket(stats.requests_total)),
        bytes_sent_bucket: Some(bytes_bucket(stats.bytes_sent)),
        had_errors: Some(stats.errors_total > 0),
        ..start_event(env, command, features)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_edges() {
        assert_eq!(uptime_bucket(59), "<1m");
        assert_eq!(uptime_bucket(60), "1-10m");
        assert_eq!(uptime_bucket(86_400), ">24h");
        assert_eq!(count_bucket(0), "0");
        assert_eq!(count_bucket(9), "1-9");
        assert_eq!(count_bucket(1_000_000), "1M+");
        assert_eq!(bytes_bucket(1), "<1MiB");
        assert_eq!(bytes_bucket(1024 * 1024), "1-10MiB");
        assert_eq!(bytes_bucket(u64::MAX), ">100GiB");
    }
}
