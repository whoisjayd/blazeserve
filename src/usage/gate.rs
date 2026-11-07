//! The ordered decision of whether telemetry may be sent, and relay URL validation.

use super::Env;
use super::settings::{Settings, load_settings, settings_path};

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

pub fn effective(env: &Env, build_time: Option<&str>) -> (Decision, Option<Settings>) {
    let persisted = match settings_path(env) {
        Some(p) => load_settings(&p).map(|s| s.unwrap_or_default()).ok(),
        None => None,
    };
    let relay = relay_url(env, build_time);
    (decide(env, persisted, relay.as_deref()), persisted)
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
}
