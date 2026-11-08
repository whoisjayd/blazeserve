//! The persisted opt-out settings file, its location and the one-time notice text.

use super::Env;
use serde::Serialize;
use std::path::{Path, PathBuf};

const SETTINGS_FILE: &str = "telemetry.json";
const DOCS_URL: &str = "https://github.com/whoisjayd/blazeserve#telemetry";

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

pub fn notice_text() -> String {
    format!(
        "BlazeServe sends anonymous usage statistics: version, OS, CPU architecture, which \
         features are on, and rough run size. No paths, addresses or file names.\n\
         Turn it off with `blaze telemetry disable`, BLAZE_TELEMETRY=0 or DO_NOT_TRACK=1. \
         Details: {DOCS_URL}\n"
    )
}
