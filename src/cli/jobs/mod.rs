//! Background jobs: `--background`, `blaze status` and `blaze stop`.
//!
//! A launching command starts this same program again as a detached worker. The worker runs
//! the command, and keeps one small JSON record per job in a private per-user folder. The
//! other commands only read that folder, or drop a stop request into it.

mod launch;
mod record;
mod status;
mod stop;
mod store;
pub(super) mod tracker;
mod worker;

pub use record::{Direction, Kind, Phase};
pub use status::StatusArgs;
pub use stop::StopArgs;
pub use worker::Info;

use clap::Args;
use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

static STANDALONE: AtomicBool = AtomicBool::new(false);

/// The arguments of an embedded call (`main_from`), which are not the process's own.
static EMBEDDED_ARGS: Mutex<Option<Vec<OsString>>> = Mutex::new(None);

/// Marks the process as the `blaze` program itself. Embedders that call `main_from` cannot
/// start a worker because their executable is not `blaze`.
pub fn mark_standalone() {
    STANDALONE.store(true, Ordering::Relaxed);
}

fn is_standalone() -> bool {
    STANDALONE.load(Ordering::Relaxed)
}

/// Remembers the arguments of an embedded call so a background worker can repeat them.
pub fn set_embedded_args(args: Vec<OsString>) {
    if let Ok(mut slot) = EMBEDDED_ARGS.lock() {
        *slot = Some(args);
    }
}

/// What to repeat in a worker: the embedded call's arguments, else this process's own.
fn invocation_args() -> Vec<OsString> {
    EMBEDDED_ARGS
        .lock()
        .ok()
        .and_then(|slot| slot.clone())
        .unwrap_or_else(|| std::env::args_os().skip(1).collect())
}

/// The program that starts a worker, and the arguments that go before the repeated ones.
/// The `blaze` program starts itself. Inside Python the interpreter that is running
/// BlazeServe starts `python -m blazeserve`, because the process's own executable is not `blaze`.
fn worker_program() -> Result<(PathBuf, Vec<OsString>), String> {
    if is_standalone() {
        let exe = std::env::current_exe()
            .map_err(|e| format!("cannot find the blaze executable to start a worker: {e}"))?;
        return Ok((exe, Vec::new()));
    }
    match std::env::var_os("BLAZE_PYTHON").filter(|p| !p.is_empty()) {
        Some(python) => Ok((PathBuf::from(python), vec!["-m".into(), "blazeserve".into()])),
        None => Err(
            "--background needs the blaze program or the blazeserve Python package; set BLAZE_PYTHON to the interpreter when embedding"
                .to_owned(),
        ),
    }
}

#[derive(Args, Debug, Clone, Default)]
pub struct BackgroundArgs {
    /// Run in the background and print a job ID (see `blaze status` and `blaze stop`)
    #[arg(long, conflicts_with = "background_worker")]
    pub background: bool,
    #[arg(long, hide = true, value_name = "JOB")]
    pub background_worker: Option<String>,
}

/// Runs `body` as the command itself, as a background launch, or as the background worker.
pub fn run<E: std::fmt::Display + From<String>>(
    kind: Kind,
    bg: &BackgroundArgs,
    body: impl FnOnce() -> Result<u8, E>,
) -> Result<u8, E> {
    if let Some(id) = &bg.background_worker {
        worker::run(id, kind, body)
    } else if bg.background {
        Ok(launch::launch(kind)?)
    } else {
        body()
    }
}

/// Called once a command's arguments are valid (and a server is bound).
/// A no-op in the foreground.
pub fn ready(info: impl FnOnce() -> Info) {
    worker::ready(info);
}

/// Resolves when a stop is requested: by `blaze stop` for a worker, or by an embedder through
/// [`request_stop`]. A foreground `blaze` run is stopped by Ctrl+C instead.
pub async fn stop_requested() {
    while !tracker::cancelled() {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

/// Asks the running command to stop at its next safe point. Transfers keep their resume data.
pub fn request_stop() {
    tracker::request_cancel();
}

/// Forgets an earlier stop request, so each run starts clean.
pub(super) fn clear_stop() {
    tracker::clear_cancel();
}

pub fn status(args: StatusArgs) -> Result<u8, String> {
    status::run(args)
}

pub fn stop(args: StopArgs) -> Result<u8, String> {
    stop::run(args)
}
