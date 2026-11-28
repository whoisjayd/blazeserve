//! Anonymous, opt-out usage analytics sent to PostHog. `docs/telemetry.md` is the public
//! contract.
//!
//! Nothing here may block, slow or fail a command: every error degrades to "do not send".
//! No event may carry a file name, path, URL, host name, address, argument value or error
//! message; properties are chosen from a closed list (`ALLOWED_PROPERTIES`).

mod environment;
mod gate;
mod ids;
mod payload;
mod session;
mod settings;
pub mod trace;

pub use gate::{DEFAULT_HOST, Decision, Reason, Target, decide, effective, target};
pub use payload::{
    ALLOWED_PROPERTIES, CHANNELS, Event, FEATURE_KEYS, Features, ServerCounters, bytes_bucket,
};
pub use session::{
    CommandReport, QUEUE_FILE, Reporter, build_time_host, build_time_key, clear_queue,
    install_panic_hook, open, preview, queued, send_feedback,
};
pub use settings::{
    NOTICE_VERSION, Settings, SettingsUnreadable, config_dir, load_settings, notice_text,
    reset_settings, save_settings, settings_path,
};

pub type Env<'a> = dyn Fn(&str) -> Option<String> + 'a;

pub fn process_env(key: &str) -> Option<String> {
    std::env::var(key).ok()
}
