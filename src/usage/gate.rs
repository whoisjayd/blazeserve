//! The ordered decision of whether analytics may be sent, and where to.

use super::Env;
use super::settings::{Settings, load_settings, settings_path};

pub const DEFAULT_HOST: &str = "https://eu.i.posthog.com";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    DoNotTrack,
    EnvDisabled,
    Ci,
    SettingDisabled,
    SettingsUnreadable,
    NoKey,
    KeyInvalid,
    HostInvalid,
}

impl Reason {
    pub fn why(self) -> &'static str {
        match self {
            Reason::DoNotTrack => "DO_NOT_TRACK is set",
            Reason::EnvDisabled => "BLAZE_TELEMETRY turns it off",
            Reason::Ci => "CI is set",
            Reason::SettingDisabled => "disabled with `blaze telemetry disable`",
            Reason::SettingsUnreadable => "the settings file could not be read",
            Reason::NoKey => "this build has no PostHog project key",
            Reason::KeyInvalid => "the key is not a PostHog project key (phc_...)",
            Reason::HostInvalid => "the host must be https (http only for loopback)",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Enabled,
    Disabled(Reason),
}

/// Where events go: a PostHog host and the project's public, write-only key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub key: String,
    pub host: String,
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

pub(super) fn host_valid(url: &str) -> bool {
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

/// A runtime value first, then the one built into the binary.
fn setting(env: &Env, name: &str, built_in: Option<&str>) -> Option<String> {
    env(name)
        .filter(|v| !v.trim().is_empty())
        .or_else(|| built_in.map(str::to_owned))
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty())
}

pub fn target(env: &Env, built_key: Option<&str>, built_host: Option<&str>) -> Option<Target> {
    Some(Target {
        key: setting(env, "BLAZE_POSTHOG_KEY", built_key)?,
        host: setting(env, "BLAZE_POSTHOG_HOST", built_host)
            .unwrap_or_else(|| DEFAULT_HOST.to_owned()),
    })
}

/// Gate order is part of the public contract: the first matching rule wins.
pub fn decide(env: &Env, persisted: Option<&Settings>, target: Option<&Target>) -> Decision {
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
    match target {
        None => Decision::Disabled(Reason::NoKey),
        // A personal key is a secret and must never be shipped or sent as a project key.
        Some(t) if !t.key.starts_with("phc_") => Decision::Disabled(Reason::KeyInvalid),
        Some(t) if !host_valid(&t.host) => Decision::Disabled(Reason::HostInvalid),
        Some(_) => Decision::Enabled,
    }
}

pub fn effective(
    env: &Env,
    built_key: Option<&str>,
    built_host: Option<&str>,
) -> (Decision, Option<Settings>) {
    let persisted = match settings_path(env) {
        Some(p) => load_settings(&p).map(|s| s.unwrap_or_default()).ok(),
        None => None,
    };
    let target = target(env, built_key, built_host);
    (decide(env, persisted.as_ref(), target.as_ref()), persisted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_http_only() {
        assert!(host_valid("https://eu.i.posthog.com"));
        assert!(host_valid("http://127.0.0.1:9000"));
        assert!(host_valid("http://localhost:8787/x"));
        assert!(host_valid("http://[::1]:1"));
        assert!(!host_valid("http://posthog.example.com"));
        assert!(!host_valid("ftp://127.0.0.1"));
        assert!(!host_valid("https://"));
        assert!(!host_valid("http://127.0.0.1.evil.com"));
    }
}
