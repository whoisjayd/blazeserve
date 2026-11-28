//! `--background`: start this same executable as a detached worker, wait until it has
//! checked its arguments (and bound its socket, for servers), then print the job ID.

use super::record::{Kind, State};
use super::store::{Store, now};
use crate::cli::ansi::{Style, announce};
use std::ffi::OsString;
use std::fs::File;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const START_TIMEOUT: Duration = Duration::from_secs(30);
const POLL: Duration = Duration::from_millis(40);

/// The worker's command line: ours without `--background`, plus the worker marker. Anything
/// after a `--` is a value, never an option, so the marker is placed before it.
pub fn worker_args(args: impl IntoIterator<Item = OsString>, id: &str) -> Vec<OsString> {
    let mut out: Vec<OsString> = Vec::new();
    let mut values_only = false;
    for arg in args {
        if arg == "--" {
            values_only = true;
        }
        if values_only || arg != "--background" {
            out.push(arg);
        }
    }
    let at = out.iter().position(|a| a == "--").unwrap_or(out.len());
    out.splice(at..at, ["--background-worker".into(), id.into()]);
    out
}

fn spawn_detached(args: &[OsString], log: &File) -> Result<Child, String> {
    let (program, prefix) = super::worker_program()?;
    let build = || -> std::io::Result<Command> {
        let mut c = Command::new(&program);
        c.args(&prefix)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::from(log.try_clone()?))
            .stderr(Stdio::from(log.try_clone()?));
        Ok(c)
    };
    crate::platform::spawn_detached(build)
        .map_err(|e| format!("cannot start the background worker: {e}"))
}

enum Seen {
    Ready,
    LaunchFailed(String),
    Waiting,
}

fn inspect(store: &Store, id: &str) -> Seen {
    match store.read(id) {
        Ok(Some(rec)) if rec.state != State::Starting => match rec.ready_at {
            Some(_) => Seen::Ready,
            None => Seen::LaunchFailed(
                rec.result
                    .unwrap_or_else(|| "the background worker failed to start".to_owned()),
            ),
        },
        _ => Seen::Waiting,
    }
}

/// Says a job is running: its bare ID for a script, what to do with it for a person.
fn started(kind: Kind, id: &str) {
    let person = std::io::IsTerminal::is_terminal(&std::io::stdout());
    if !person || crate::cli::ansi::quiet() || crate::cli::ansi::json_progress() {
        anstream::println!("{id}");
        announce(
            "Started",
            &format!("{} job {id}; check it with: blaze status {id}", kind.name()),
        );
        return;
    }
    crate::cli::runlog::note(&format!("Started {} job {id}", kind.name()));
    let style = Style::stdout();
    let body = crate::cli::ansi::rows(
        style,
        &[
            ("Watch", "blaze status --watch".to_owned()),
            ("Attach", format!("blaze attach {id}")),
            ("Stop", format!("blaze stop {id}")),
        ],
    );
    let title = format!("Started {} job {id} in the background", kind.name());
    crate::cli::ansi::card(&title, &format!("{body}  "), &body);
}

pub fn launch(kind: Kind) -> Result<u8, String> {
    let store = Store::open()?;
    store.sweep(now());
    let (id, log) = store.reserve()?;
    let args = worker_args(super::invocation_args(), &id);
    crate::platform::stop_inheriting_std_handles();
    let mut child = match spawn_detached(&args, &log) {
        Ok(c) => c,
        Err(e) => {
            store.remove(&id);
            return Err(e);
        }
    };
    drop(log);

    let deadline = Instant::now() + START_TIMEOUT;
    let failure = loop {
        match inspect(&store, &id) {
            Seen::Ready => {
                started(kind, &id);
                return Ok(0);
            }
            Seen::LaunchFailed(why) => break why,
            Seen::Waiting => {}
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                // The worker may have written its verdict just before exiting.
                break match inspect(&store, &id) {
                    Seen::LaunchFailed(why) => why,
                    Seen::Ready => {
                        anstream::println!("{id}");
                        return Ok(0);
                    }
                    Seen::Waiting => format!(
                        "the background worker exited ({status}) before it started; see {}",
                        store.log_path(&id).display()
                    ),
                };
            }
            Ok(None) => {}
            Err(e) => break format!("cannot watch the background worker: {e}"),
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            break format!(
                "the background worker did not start within {}s",
                START_TIMEOUT.as_secs()
            );
        }
        std::thread::sleep(POLL);
    };
    store.remove(&id);
    Err(failure)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker_args_drop_the_flag_and_add_the_marker() {
        let args = ["get", "http://h/x", "--background", "-o", "x.bin"].map(OsString::from);
        let out = worker_args(args, "0123abcd");
        let out: Vec<_> = out.iter().map(|a| a.to_str().unwrap()).collect();
        assert_eq!(
            out,
            [
                "get",
                "http://h/x",
                "-o",
                "x.bin",
                "--background-worker",
                "0123abcd"
            ]
        );
    }

    #[test]
    fn the_marker_goes_before_a_separator_so_it_is_not_a_positional() {
        let args = ["get", "--background", "-o", "x.bin", "--", "--odd-name"].map(OsString::from);
        let out = worker_args(args, "0123abcd");
        let out: Vec<_> = out.iter().map(|a| a.to_str().unwrap()).collect();
        assert_eq!(
            out,
            [
                "get",
                "-o",
                "x.bin",
                "--background-worker",
                "0123abcd",
                "--",
                "--odd-name"
            ]
        );
    }
}
