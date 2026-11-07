//! Anonymous, opt-out usage telemetry. The README "Telemetry" section is the public contract.
//!
//! Nothing here may block, slow or fail a command: every error degrades to "do not send".

use crate::config::Config;
use serde::Serialize;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, Instant};

pub const SCHEMA_VERSION: u32 = 1;
const SETTINGS_FILE: &str = "telemetry.json";
const SEND_TIMEOUT: Duration = Duration::from_secs(2);
const STOP_CAP: Duration = Duration::from_millis(500);
const DOCS_URL: &str = "https://github.com/whoisjayd/blazeserve#telemetry";

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

pub type Env<'a> = dyn Fn(&str) -> Option<String> + 'a;

pub fn process_env(key: &str) -> Option<String> {
    std::env::var(key).ok()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    DoNotTrack,
    EnvDisabled,
    Ci,
    SettingDisabled,
    SettingsUnreadable,
    NoRelay,
    RelayInvalid,
}

impl Reason {
    pub fn why(self) -> &'static str {
        match self {
            Reason::DoNotTrack => "DO_NOT_TRACK is set",
            Reason::EnvDisabled => "BLAZE_TELEMETRY turns it off",
            Reason::Ci => "CI is set",
            Reason::SettingDisabled => "disabled with `blaze telemetry disable`",
            Reason::SettingsUnreadable => "the settings file could not be read",
            Reason::NoRelay => "no relay URL is configured in this build",
            Reason::RelayInvalid => "the relay URL must be https (http only for loopback)",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Enabled,
    Disabled(Reason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Settings {
    pub enabled: bool,
    pub notice_shown: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            enabled: true,
            notice_shown: false,
        }
    }
}

fn set_and_not_zero(v: Option<String>) -> bool {
    v.is_some_and(|v| {
        let v = v.trim();
        !v.is_empty() && v != "0"
    })
}

fn ci_set(v: Option<String>) -> bool {
    v.is_some_and(|v| {
        let v = v.trim().to_ascii_lowercase();
        !v.is_empty() && v != "0" && v != "false"
    })
}

fn loopback(host: &str) -> bool {
    let host = host.trim_matches(['[', ']']);
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

fn relay_valid(url: &str) -> bool {
    if let Some(rest) = url.strip_prefix("https://") {
        return !rest.is_empty() && !rest.starts_with('/');
    }
    let Some(rest) = url.strip_prefix("http://") else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = match authority.rsplit_once(':') {
        Some((h, port)) if port.chars().all(|c| c.is_ascii_digit()) => h,
        _ => authority,
    };
    loopback(host)
}

/// Runtime override first, then the URL baked in at build time.
pub fn relay_url(env: &Env, build_time: Option<&str>) -> Option<String> {
    env("BLAZE_TELEMETRY_URL")
        .filter(|v| !v.trim().is_empty())
        .or_else(|| {
            build_time
                .filter(|v| !v.trim().is_empty())
                .map(str::to_owned)
        })
        .map(|v| v.trim().to_owned())
}

/// Gate order is part of the public contract: the first matching rule wins.
pub fn decide(env: &Env, persisted: Option<Settings>, relay: Option<&str>) -> Decision {
    if set_and_not_zero(env("DO_NOT_TRACK")) {
        return Decision::Disabled(Reason::DoNotTrack);
    }
    if env("BLAZE_TELEMETRY").is_some_and(|v| {
        matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "0" | "false" | "off" | "no"
        )
    }) {
        return Decision::Disabled(Reason::EnvDisabled);
    }
    if ci_set(env("CI")) {
        return Decision::Disabled(Reason::Ci);
    }
    match persisted {
        None => return Decision::Disabled(Reason::SettingsUnreadable),
        Some(s) if !s.enabled => return Decision::Disabled(Reason::SettingDisabled),
        Some(_) => {}
    }
    match relay {
        None => Decision::Disabled(Reason::NoRelay),
        Some(url) if !relay_valid(url) => Decision::Disabled(Reason::RelayInvalid),
        Some(_) => Decision::Enabled,
    }
}

pub fn config_dir(env: &Env) -> Option<PathBuf> {
    if let Some(dir) = env("BLAZE_CONFIG_DIR").filter(|v| !v.is_empty()) {
        return Some(PathBuf::from(dir));
    }
    let base = if cfg!(windows) {
        PathBuf::from(env("APPDATA").filter(|v| !v.is_empty())?)
    } else if cfg!(target_os = "macos") {
        PathBuf::from(env("HOME").filter(|v| !v.is_empty())?).join("Library/Application Support")
    } else {
        match env("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
            Some(x) => PathBuf::from(x),
            None => PathBuf::from(env("HOME").filter(|v| !v.is_empty())?).join(".config"),
        }
    };
    Some(base.join("blazeserve"))
}

pub fn settings_path(env: &Env) -> Option<PathBuf> {
    config_dir(env).map(|d| d.join(SETTINGS_FILE))
}

#[derive(serde::Deserialize, Serialize)]
struct SettingsFile {
    enabled: bool,
    notice_shown: bool,
}

/// The settings file exists but cannot be trusted, so nothing may be sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SettingsUnreadable;

/// `Ok(None)` is a missing file (defaults apply); `Err` means the state is unknown.
pub fn load_settings(path: &Path) -> Result<Option<Settings>, SettingsUnreadable> {
    match std::fs::read_to_string(path) {
        Ok(text) => serde_json::from_str::<SettingsFile>(&text)
            .map(|f| {
                Some(Settings {
                    enabled: f.enabled,
                    notice_shown: f.notice_shown,
                })
            })
            .map_err(|_| SettingsUnreadable),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(SettingsUnreadable),
    }
}

pub fn save_settings(path: &Path, s: Settings) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let body = serde_json::to_string(&SettingsFile {
        enabled: s.enabled,
        notice_shown: s.notice_shown,
    })
    .map_err(std::io::Error::other)?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, body)?;
    std::fs::rename(&tmp, path)
}

pub fn reset_settings(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

/// Effective state with the persisted file resolved, for `status` and the start hook.
pub fn effective(env: &Env, build_time: Option<&str>) -> (Decision, Option<Settings>) {
    let persisted = match settings_path(env) {
        Some(p) => load_settings(&p).map(|s| s.unwrap_or_default()).ok(),
        None => None,
    };
    let relay = relay_url(env, build_time);
    (decide(env, persisted, relay.as_deref()), persisted)
}

pub fn notice_text() -> String {
    format!(
        "BlazeServe sends anonymous usage statistics: version, OS, CPU architecture, which \
         features are on, and rough run size. No paths, addresses or file names.\n\
         Turn it off with `blaze telemetry disable`, BLAZE_TELEMETRY=0 or DO_NOT_TRACK=1. \
         Details: {DOCS_URL}\n"
    )
}

fn debug_on(env: &Env) -> bool {
    env("BLAZE_TELEMETRY_DEBUG").is_some_and(|v| matches!(v.trim(), "1" | "true" | "yes"))
}

fn post(url: &str, body: &str) {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(SEND_TIMEOUT))
        .build()
        .into();
    let endpoint = format!("{}/v1/event", url.trim_end_matches('/'));
    let _ = agent
        .post(&endpoint)
        .header("content-type", "application/json")
        .header(
            "user-agent",
            concat!("blazeserve/", env!("CARGO_PKG_VERSION")),
        )
        .send(body);
}

#[derive(Debug)]
pub struct Session {
    command: Command,
    features: Features,
    started: Instant,
    relay: String,
    debug: bool,
    channel_env: Option<String>,
}

fn dispatch(
    relay: &str,
    event: &Event,
    debug: bool,
    diag: &mut dyn Write,
) -> Option<mpsc::Receiver<()>> {
    let body = serde_json::to_string(event).ok()?;
    if debug {
        let _ = writeln!(diag, "telemetry (not sent): {body}");
        return None;
    }
    let (tx, rx) = mpsc::channel();
    let relay = relay.to_owned();
    std::thread::Builder::new()
        .name("blaze-usage".into())
        .spawn(move || {
            post(&relay, &body);
            let _ = tx.send(());
        })
        .ok()?;
    Some(rx)
}

/// Decide, show the one-time notice, and fire the `start` event. Returns `None` whenever
/// telemetry is off or any step fails.
pub fn begin(
    env: &Env,
    build_time: Option<&str>,
    diag: &mut dyn Write,
    command: Command,
    features: Features,
) -> Option<Session> {
    let (decision, persisted) = effective(env, build_time);
    if decision != Decision::Enabled {
        return None;
    }
    let persisted = persisted?;
    let path = settings_path(env)?;
    if !persisted.notice_shown {
        if save_settings(
            &path,
            Settings {
                notice_shown: true,
                ..persisted
            },
        )
        .is_err()
        {
            return None;
        }
        let _ = diag.write_all(notice_text().as_bytes());
        let _ = diag.flush();
    }
    let relay = relay_url(env, build_time)?;
    let debug = debug_on(env);
    dispatch(&relay, &start_event(env, command, features), debug, diag);
    Some(Session {
        command,
        features,
        started: Instant::now(),
        relay,
        debug,
        channel_env: env("BLAZE_INSTALL_CHANNEL"),
    })
}

impl Session {
    /// Best-effort `stop` event; never waits longer than the hard cap.
    pub fn finish(self, stats: StopStats, diag: &mut dyn Write) {
        let channel_env = self.channel_env.clone();
        let lookup = move |k: &str| {
            (k == "BLAZE_INSTALL_CHANNEL")
                .then(|| channel_env.clone())
                .flatten()
        };
        let event = stop_event(
            &lookup,
            self.command,
            self.features,
            self.started.elapsed(),
            stats,
        );
        if let Some(rx) = dispatch(&self.relay, &event, self.debug, diag) {
            let _ = rx.recv_timeout(STOP_CAP);
        }
    }
}

/// Process-level entry used by the CLI: contained against panics and writes the notice to stderr.
pub fn begin_from_process(command: Command, features: Features) -> Option<Session> {
    std::panic::catch_unwind(|| {
        begin(
            &process_env,
            option_env!("BLAZE_TELEMETRY_URL"),
            &mut std::io::stderr(),
            command,
            features,
        )
    })
    .ok()
    .flatten()
}

pub fn finish_from_process(session: Session, stats: StopStats) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        session.finish(stats, &mut std::io::stderr());
    }));
}

pub fn build_time_url() -> Option<&'static str> {
    option_env!("BLAZE_TELEMETRY_URL")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_http_only() {
        assert!(relay_valid("https://relay.example.com"));
        assert!(relay_valid("http://127.0.0.1:9000"));
        assert!(relay_valid("http://localhost:8787/x"));
        assert!(relay_valid("http://[::1]:1"));
        assert!(!relay_valid("http://relay.example.com"));
        assert!(!relay_valid("ftp://127.0.0.1"));
        assert!(!relay_valid("https://"));
        assert!(!relay_valid("http://127.0.0.1.evil.com"));
    }

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
