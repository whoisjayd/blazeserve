//! The background sender and the start/stop session hooks the CLI calls.

use super::gate::{Decision, effective, relay_url};
use super::payload::{Command, Event, Features, StopStats, start_event, stop_event};
use super::settings::{Settings, notice_text, save_settings, settings_path};
use super::{Env, process_env};
use std::io::Write;
use std::sync::mpsc;
use std::time::{Duration, Instant};

const SEND_TIMEOUT: Duration = Duration::from_secs(2);
const STOP_CAP: Duration = Duration::from_millis(500);

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
