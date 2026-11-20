//! `blaze stop JOB`: ask a worker to stop and wait for it to record the outcome.
//!
//! The request is a file the worker polls for, so no process is ever signalled or killed by
//! PID. Only the worker that owns the job can act on it, which makes a reused PID harmless.

use super::record::{Record, State, valid_id};
use super::status::{describe, span};
use super::store::{Store, now};
use clap::Args;
use std::time::{Duration, Instant};

/// Longer than the worker's own grace period, so a worker that must end itself still
/// has time to record the outcome.
const WAIT: Duration = Duration::from_secs(45);

#[derive(Args, Debug)]
pub struct StopArgs {
    /// Job ID from `blaze status`
    pub job: String,
    /// Stop without asking for confirmation
    #[arg(short, long)]
    pub yes: bool,
}

/// Shows what is about to be stopped and asks. Anything but an explicit yes declines.
fn confirm(rec: &Record, yes: bool) -> Result<bool, String> {
    anstream::eprint!("{}", describe(rec, now(), false));
    if yes {
        return Ok(true);
    }
    if !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        return Err(
            "stopping needs confirmation but input is not a terminal; add --yes to stop without asking"
                .to_owned(),
        );
    }
    anstream::eprint!("Stop this job? [y/N] ");
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|e| format!("cannot read the answer: {e}"))?;
    Ok(matches!(
        line.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

fn current(store: &Store, id: &str) -> Result<Record, String> {
    store.read(id)?.map(|r| r.effective(now())).ok_or_else(|| {
        format!("no job {id}: the ID is wrong, or the job was removed after finishing")
    })
}

fn report(rec: &Record) -> Result<u8, String> {
    let result = rec.result.as_deref().unwrap_or("");
    match rec.state {
        State::Failed => Err(format!("job {} failed: {result}", rec.id)),
        state => {
            anstream::println!("Job {} {}: {result}", rec.id, state.name());
            Ok(0)
        }
    }
}

pub fn run(args: StopArgs) -> Result<u8, String> {
    if !valid_id(&args.job) {
        return Err(format!(
            "'{}' is not a job ID (expected 8 characters, 0-9 and a-f)",
            args.job
        ));
    }
    let store = Store::open()?;
    let first = current(&store, &args.job)?;
    if !first.state.is_active() {
        return report(&first);
    }
    if !confirm(&first, args.yes)? {
        anstream::eprintln!("Not stopped.");
        return Ok(1);
    }
    store
        .request_stop(&args.job)
        .map_err(|e| format!("cannot send the stop request: {e}"))?;
    let started = Instant::now();
    loop {
        std::thread::sleep(Duration::from_millis(100));
        let rec = current(&store, &args.job)?;
        if !rec.state.is_active() {
            store.remove_stop(&args.job);
            return report(&rec);
        }
        if started.elapsed() > WAIT {
            return Err(format!(
                "job {} did not stop within {}; it is still marked {}. Check `blaze status {}`",
                args.job,
                span(WAIT.as_secs()),
                rec.state.name(),
                args.job
            ));
        }
    }
}
