//! Anonymous, opt-out usage telemetry. `docs/telemetry.md` is the public contract.
//!
//! Nothing here may block, slow or fail a command: every error degrades to "do not send".

mod gate;
mod payload;
mod session;
mod settings;

pub use gate::{Decision, Reason, decide, effective, relay_url};
pub use payload::{
    ALLOWED_KEYS, ARCHES, BYTES_BUCKETS, CHANNELS, COMMANDS, COUNT_BUCKETS, Command, EVENTS, Event,
    FEATURE_KEYS, Features, OSES, SCHEMA_VERSION, StopStats, UPTIME_BUCKETS, bytes_bucket,
    count_bucket, start_event, stop_event, uptime_bucket,
};
pub use session::{Session, begin, begin_from_process, build_time_url, finish_from_process};
pub use settings::{
    Settings, SettingsUnreadable, config_dir, load_settings, notice_text, reset_settings,
    save_settings, settings_path,
};

pub type Env<'a> = dyn Fn(&str) -> Option<String> + 'a;

pub fn process_env(key: &str) -> Option<String> {
    std::env::var(key).ok()
}
