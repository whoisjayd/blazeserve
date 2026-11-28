//! One run's reporter: shows the notice, sends events from a background thread, and spools
//! the events of quick commands so that they never wait on the network.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use serde_json::{Map, Value, json};

use super::gate::{Decision, Target, effective, host_valid, target};
use super::payload::{Event, Features, ServerCounters, common};
use super::settings::{NOTICE_VERSION, notice_text, save_settings, settings_path};
use super::{Env, ids, trace};

pub const QUEUE_FILE: &str = "telemetry-queue.jsonl";
const SEND_TIMEOUT: Duration = Duration::from_secs(2);
/// The longest an exiting command waits for its events to leave.
const EXIT_CAP: Duration = Duration::from_millis(500);
/// Oldest events are dropped beyond this.
const QUEUE_MAX: usize = 50;
/// A queue this long is sent even by a quick command.
const QUEUE_SEND_AT: usize = 10;
/// PostHog allows one session ID 24 hours; a server outlives that.
const SESSION_LIMIT: Duration = Duration::from_secs(23 * 60 * 60);

pub fn build_time_key() -> Option<&'static str> {
    option_env!("BLAZE_POSTHOG_KEY")
}

pub fn build_time_host() -> Option<&'static str> {
    option_env!("BLAZE_POSTHOG_HOST")
}

/// What a finished command says about itself. Names and numbers only, never values.
#[derive(Debug, Clone)]
pub struct CommandReport<'a> {
    pub command: &'a str,
    /// Names of the options that were given.
    pub flags: Vec<String>,
    pub background: bool,
    pub exit_code: u8,
    /// A fixed word such as `network` or `integrity`.
    pub error_kind: Option<&'static str>,
    /// Names the run's local log, so a bug report can be matched to this event.
    pub log_id: Option<&'a str>,
}

#[derive(Debug, Clone)]
pub struct Reporter {
    target: Target,
    debug: bool,
    queue: PathBuf,
    common: Map<String, Value>,
    started: Instant,
}

/// Decides whether this run may report, showing the notice first when it is new. `None`
/// whenever analytics are off or any step fails. `announce` is false when the notice could
/// not be seen, in which case nothing is sent until it has been.
pub fn open(
    env: &Env,
    built_key: Option<&str>,
    built_host: Option<&str>,
    diag: &mut dyn Write,
    announce: bool,
    interactive: bool,
) -> Option<Reporter> {
    let (decision, persisted) = effective(env, built_key, built_host);
    if decision != Decision::Enabled {
        return None;
    }
    let mut settings = persisted?;
    let path = settings_path(env)?;
    let new_notice = settings.notice_version < NOTICE_VERSION;
    if new_notice && !announce {
        return None;
    }
    if new_notice || settings.install_id.is_none() {
        settings.notice_version = NOTICE_VERSION;
        if settings.install_id.is_none() {
            settings.install_id = Some(ids::install_id()?);
        }
        // Saved first: a notice that cannot be remembered would repeat for ever.
        save_settings(&path, &settings).ok()?;
        if new_notice {
            let _ = diag.write_all(notice_text().as_bytes());
            let _ = diag.flush();
        }
    }
    let debug =
        env("BLAZE_TELEMETRY_DEBUG").is_some_and(|v| matches!(v.trim(), "1" | "true" | "yes"));
    Some(Reporter {
        target: target(env, built_key, built_host)?,
        debug,
        queue: path.with_file_name(QUEUE_FILE),
        common: common(
            env,
            settings.install_id.as_deref()?,
            &ids::session_id()?,
            interactive,
        ),
        started: Instant::now(),
    })
}

fn read_queue(path: &Path) -> Vec<Value> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect()
}

fn write_queue(path: &Path, events: &[Value]) {
    let keep = &events[events.len().saturating_sub(QUEUE_MAX)..];
    let text: String = keep.iter().map(|e| format!("{e}\n")).collect();
    let _ = std::fs::write(path, text);
}

/// The status PostHog answered with.
fn post(target: &Target, batch: &[Value]) -> Result<u16, String> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(SEND_TIMEOUT))
        .build()
        .into();
    let endpoint = format!("{}/batch/", target.host.trim_end_matches('/'));
    let body = json!({ "api_key": target.key, "batch": batch }).to_string();
    agent
        .post(&endpoint)
        .header("content-type", "application/json")
        .header(
            "user-agent",
            concat!("blazeserve/", env!("CARGO_PKG_VERSION")),
        )
        .send(&body)
        .map(|response| response.status().as_u16())
        .map_err(|e| e.to_string())
}

impl Reporter {
    /// The ID that links this run's events.
    pub fn session_id(&self) -> Option<String> {
        self.common
            .get("$session_id")
            .and_then(Value::as_str)
            .map(str::to_owned)
    }

    fn event(&self, name: &str, extra: Map<String, Value>) -> Option<Value> {
        let mut common = self.common.clone();
        if self.started.elapsed() > SESSION_LIMIT {
            common.remove("$session_id");
        }
        serde_json::to_value(Event::new(name, &common, extra)).ok()
    }

    /// Sends the queue and `events` from a background thread. The receiver fires when the
    /// request has finished.
    fn send(&self, events: Vec<Value>, diag: &mut dyn Write) -> Option<mpsc::Receiver<()>> {
        if self.debug {
            for event in &events {
                let _ = writeln!(diag, "telemetry (not sent): {event}");
            }
            return None;
        }
        let mut batch = read_queue(&self.queue);
        let _ = std::fs::remove_file(&self.queue);
        batch.extend(events);
        if batch.is_empty() {
            return None;
        }
        let (done, finished) = mpsc::channel();
        let target = self.target.clone();
        std::thread::Builder::new()
            .name("blaze-usage".into())
            .spawn(move || {
                // Analytics never matter enough to report a failure.
                let _ = post(&target, &batch);
                let _ = done.send(());
            })
            .ok()?;
        Some(finished)
    }

    fn send_and_wait(&self, events: Vec<Value>, diag: &mut dyn Write) {
        if let Some(finished) = self.send(events, diag) {
            let _ = finished.recv_timeout(EXIT_CAP);
        }
    }

    /// Spools `events` unless there is enough to be worth a request.
    fn queue_or_send(&self, events: Vec<Value>, diag: &mut dyn Write) {
        if self.debug {
            self.send(events, diag);
            return;
        }
        let mut queued = read_queue(&self.queue);
        if queued.len() + events.len() >= QUEUE_SEND_AT {
            self.send_and_wait(events, diag);
            return;
        }
        queued.extend(events);
        write_queue(&self.queue, &queued);
    }

    pub fn server_started(&self, command: &str, features: Features, diag: &mut dyn Write) {
        let extra = object(json!({ "command": command, "features": features }));
        let events = self.event("server started", extra).into_iter().collect();
        self.send(events, diag);
    }

    fn server_event(
        &self,
        name: &str,
        command: &str,
        features: Features,
        counters: ServerCounters,
    ) -> Vec<Value> {
        let mut extra = object(json!(counters));
        extra.extend(object(json!({ "command": command, "features": features })));
        self.event(name, extra).into_iter().collect()
    }

    /// The counters of a server still running, so one that is killed has still reported.
    pub fn server_heartbeat(
        &self,
        command: &str,
        features: Features,
        counters: ServerCounters,
        diag: &mut dyn Write,
    ) {
        let events = self.server_event("server heartbeat", command, features, counters);
        self.send(events, diag);
    }

    pub fn server_stopped(
        &self,
        command: &str,
        features: Features,
        counters: ServerCounters,
        diag: &mut dyn Write,
    ) {
        let events = self.server_event("server stopped", command, features, counters);
        self.send_and_wait(events, diag);
    }

    /// The closing event of a command, with its timings, and an error report when it failed
    /// for a reason that is not the user's input. `wait` sends now instead of spooling.
    pub fn command_finished(&self, report: CommandReport<'_>, wait: bool, diag: &mut dyn Write) {
        let millis = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let mut extra = trace::take();
        extra.extend(object(json!({
            "command": report.command,
            "flags": report.flags,
            "background": report.background,
            "exit_code": report.exit_code,
            "outcome": if report.exit_code == 0 { "ok" } else { "failed" },
            "duration_ms": millis,
        })));
        if let Some(kind) = report.error_kind {
            extra.insert("error_kind".to_owned(), kind.into());
        }
        if let Some(log_id) = report.log_id {
            extra.insert("log_id".to_owned(), log_id.into());
        }
        let mut events: Vec<Value> = self.event("command finished", extra).into_iter().collect();
        if let Some(kind) = report
            .error_kind
            .filter(|k| !matches!(*k, "usage" | "interrupted"))
        {
            let exception = object(json!({
                "command": report.command,
                "$exception_list": [{
                    "type": kind,
                    "value": format!("blaze {} failed: {kind}", report.command),
                    "mechanism": { "handled": true, "synthetic": true },
                }],
                "$exception_fingerprint": format!("{}:{kind}", report.command),
            }));
            events.extend(self.event("$exception", exception));
        }
        if wait {
            self.send_and_wait(events, diag);
        } else {
            self.queue_or_send(events, diag);
        }
    }

    /// Help that was read, or a command line that was refused: where the tool is unclear.
    pub fn command_line(
        &self,
        event: &str,
        command: &str,
        kind: Option<&str>,
        diag: &mut dyn Write,
    ) {
        let mut extra = object(json!({ "command": command }));
        if let Some(kind) = kind {
            extra.insert("error_kind".to_owned(), kind.into());
        }
        let events = self.event(event, extra).into_iter().collect();
        self.queue_or_send(events, diag);
    }

    /// A crash. Only the place in the source is recorded; the message could hold anything.
    fn panicked(&self, location: &str) {
        let extra = object(json!({
            "$exception_list": [{
                "type": "panic",
                "value": location,
                "mechanism": { "handled": false, "synthetic": false },
            }],
            "$exception_fingerprint": location,
        }));
        if let Some(event) = self.event("$exception", extra) {
            let mut queued = read_queue(&self.queue);
            queued.push(event);
            write_queue(&self.queue, &queued);
        }
    }
}

/// Sends what a person typed and confirmed, and waits to learn whether it arrived. This is
/// the user's own act, so it works when analytics are off; it then carries a one-off ID.
pub fn send_feedback(
    env: &Env,
    built_key: Option<&str>,
    built_host: Option<&str>,
    event: &str,
    extra: Map<String, Value>,
) -> Result<(), String> {
    let target = target(env, built_key, built_host)
        .filter(|t| t.key.starts_with("phc_") && host_valid(&t.host))
        .ok_or("this build has no PostHog project key")?;
    let enabled = effective(env, built_key, built_host);
    let install_id = match enabled {
        (Decision::Enabled, Some(settings)) => settings.install_id,
        _ => None,
    };
    let install_id = install_id
        .or_else(ids::install_id)
        .ok_or("cannot create an ID")?;
    let common = common(
        env,
        &install_id,
        &ids::session_id().ok_or("cannot create an ID")?,
        true,
    );
    let item =
        serde_json::to_value(Event::new(event, &common, extra)).map_err(|e| e.to_string())?;
    if env("BLAZE_TELEMETRY_DEBUG").is_some_and(|v| v.trim() == "1") {
        eprintln!("telemetry (not sent): {item}");
        return Ok(());
    }
    let status = post(&target, &[item])?;
    if (200..300).contains(&status) {
        Ok(())
    } else {
        Err(format!("the server answered {status}"))
    }
}

fn object(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map,
        _ => Map::new(),
    }
}

/// `crate-1.0/src/x.rs:3` from a source path, which can otherwise name the builder's home.
fn source_location(file: &str, line: u32) -> String {
    let file = file.replace('\\', "/");
    let short = match file.rfind("/src/") {
        Some(at) => {
            let start = file[..at].rfind('/').map_or(0, |i| i + 1);
            &file[start..]
        }
        None => file.as_str(),
    };
    format!("{short}:{line}")
}

/// Spools a report when the process panics, then lets the usual hook run. It writes a local
/// file only, so it is safe even when the process is about to abort.
pub fn install_panic_hook(reporter: &Reporter) {
    let reporter = reporter.clone();
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if let Some(at) = info.location() {
            reporter.panicked(&source_location(at.file(), at.line()));
        }
        previous(info);
    }));
}

/// Forgets anything waiting to be sent.
pub fn clear_queue(env: &Env) {
    if let Some(path) = settings_path(env) {
        let _ = std::fs::remove_file(path.with_file_name(QUEUE_FILE));
    }
}

/// How many events wait to be sent.
pub fn queued(env: &Env) -> usize {
    settings_path(env).map_or(0, |p| read_queue(&p.with_file_name(QUEUE_FILE)).len())
}

/// Examples of what a run sends, with placeholder IDs. Nothing is sent or saved.
pub fn preview(env: &Env) -> Vec<Value> {
    let common = common(env, "<random install id>", "<random run id>", true);
    let examples = [
        (
            "command finished",
            json!({
                "command": "get", "flags": ["connections", "url"], "background": false,
                "exit_code": 0, "outcome": "ok", "duration_ms": 4120, "size_bucket": "100MiB-1GiB",
                "connections": 4, "segmented": true, "probe_ms": 38, "transfer_ms": 3980,
            }),
        ),
        (
            "server stopped",
            json!({
                "command": "serve", "features": Features { listing: true, ..Features::default() },
                "uptime_seconds": 5400, "requests_total": 318, "requests_active": 0,
                "bytes_sent": 5_368_709_120_u64, "bytes_received": 0, "errors_total": 0,
                "connections_rejected": 0,
            }),
        ),
    ];
    examples
        .into_iter()
        .filter_map(|(name, extra)| {
            serde_json::to_value(Event::new(name, &common, object(extra))).ok()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_locations_do_not_name_a_home_folder() {
        assert_eq!(
            source_location("/home/ann/.cargo/registry/src/x/ureq-3.1/src/run.rs", 9),
            "ureq-3.1/src/run.rs:9"
        );
        assert_eq!(
            source_location(r"C:\Users\Ann\blazeserve\src\cli\mod.rs", 2),
            "blazeserve/src/cli/mod.rs:2"
        );
        assert_eq!(source_location("src/lib.rs", 1), "src/lib.rs:1");
    }
}
