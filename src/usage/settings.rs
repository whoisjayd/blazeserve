//! The persisted choice, the anonymous install ID and the one-time notice.

use super::Env;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const SETTINGS_FILE: &str = "telemetry.json";
const DOCS_URL: &str = "https://github.com/whoisjayd/blazeserve#telemetry";

/// Raised whenever more is collected, so the notice is shown again before it is sent.
pub const NOTICE_VERSION: u32 = 2;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Settings {
    pub enabled: bool,
    /// The newest notice the user has been shown; 0 for none.
    #[serde(default)]
    pub notice_version: u32,
    /// A random ID that links one install's events. It identifies nothing else.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub install_id: Option<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            enabled: true,
            notice_version: 0,
            install_id: None,
        }
    }
}

pub fn config_dir(env: &Env) -> Option<PathBuf> {
    if let Some(dir) = env("BLAZE_CONFIG_DIR").filter(|v| !v.is_empty()) {
        return Some(PathBuf::from(dir));
    }
    let base = if crate::platform::IS_WINDOWS {
        PathBuf::from(env("APPDATA").filter(|v| !v.is_empty())?)
    } else if crate::platform::IS_MACOS {
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

/// The settings file exists but cannot be trusted, so nothing may be sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SettingsUnreadable;

/// `Ok(None)` is a missing file (defaults apply); `Err` means the state is unknown.
pub fn load_settings(path: &Path) -> Result<Option<Settings>, SettingsUnreadable> {
    match std::fs::read_to_string(path) {
        Ok(text) => serde_json::from_str(&text)
            .map(Some)
            .map_err(|_| SettingsUnreadable),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(SettingsUnreadable),
    }
}

pub fn save_settings(path: &Path, s: &Settings) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let body = serde_json::to_string(s).map_err(std::io::Error::other)?;
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

/// The notice, with colour codes that the terminal writer removes where they cannot be shown.
pub fn notice_text() -> String {
    const BOLD: &str = "\x1b[1m";
    const DIM: &str = "\x1b[2m";
    const GREEN: &str = "\x1b[32;1m";
    const RED: &str = "\x1b[31;1m";
    const CYAN: &str = "\x1b[36m";
    const OFF: &str = "\x1b[0m";
    let bar = format!("{CYAN}\u{2502}{OFF}");
    format!(
        "\n{CYAN}\u{256d}\u{2500}{OFF} {BOLD}Help improve BlazeServe{OFF}\n\
         {bar}\n\
         {bar}  Anonymous usage analytics, stored by PostHog in the EU. On by default.\n\
         {bar}\n\
         {bar}  {GREEN}\u{2713} Sent{OFF}   commands and option names, timings, size ranges,\n\
         {bar}           server totals, error kinds, crashes, version, install type\n\
         {bar}           OS, CPU, memory, disk size ranges, language, terminal\n\
         {bar}           a random install ID and an approximate location\n\
         {bar}\n\
         {bar}  {RED}\u{2717} Never{OFF}  file names, paths, URLs, addresses, option values,\n\
         {bar}           passwords or anything inside your files\n\
         {bar}\n\
         {bar}  Turn it off   {BOLD}blaze telemetry disable{OFF}\n\
         {bar}                or set {BOLD}BLAZE_TELEMETRY=0{OFF} or {BOLD}DO_NOT_TRACK=1{OFF}\n\
         {bar}  See it        {BOLD}blaze telemetry preview{OFF}\n\
         {bar}  {DIM}{DOCS_URL}{OFF}\n\
         {CYAN}\u{2570}\u{2500}{OFF}\n"
    )
}
