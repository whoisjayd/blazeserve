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
use std::sync::atomic::{AtomicBool, Ordering};

static STANDALONE: AtomicBool = AtomicBool::new(false);

/// Marks the process as the `blaze` program itself. Embedders that call `main_from` cannot
/// start a worker because their executable is not `blaze`.
pub fn mark_standalone() {
    STANDALONE.store(true, Ordering::Relaxed);
}

fn is_standalone() -> bool {
    STANDALONE.load(Ordering::Relaxed)
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
pub fn run(
    kind: Kind,
    bg: &BackgroundArgs,
    body: impl FnOnce() -> Result<u8, String>,
) -> Result<u8, String> {
    if let Some(id) = &bg.background_worker {
        worker::run(id, kind, body)
    } else if bg.background {
        launch::launch(kind)
    } else {
        body()
    }
}

/// Called once a command's arguments are valid (and a server is bound).
/// A no-op in the foreground.
pub fn ready(info: impl FnOnce() -> Info) {
    worker::ready(info);
}

/// Resolves when `blaze stop` asks this worker to stop; never resolves in the foreground.
pub async fn stop_requested() {
    if !worker::is_worker() {
        return std::future::pending().await;
    }
    while !tracker::cancelled() {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

pub fn status(args: StatusArgs) -> Result<u8, String> {
    status::run(args)
}

pub fn stop(args: StopArgs) -> Result<u8, String> {
    stop::run(args)
}
