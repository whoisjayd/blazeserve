//! `--background`: start this same executable as a detached worker, wait until it has
//! checked its arguments (and bound its socket, for servers), then print the job ID.

use super::record::{Kind, State};
use super::store::{Store, now};
use crate::cli::ansi::announce;
use std::ffi::OsString;
use std::fs::File;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const START_TIMEOUT: Duration = Duration::from_secs(30);
const POLL: Duration = Duration::from_millis(40);

/// The worker's command line: ours without `--background`, plus the worker marker.
pub fn worker_args(args: impl IntoIterator<Item = OsString>, id: &str) -> Vec<OsString> {
    let mut out: Vec<OsString> = args.into_iter().filter(|a| a != "--background").collect();
    out.push("--background-worker".into());
    out.push(id.into());
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
    let fail = |e: std::io::Error| format!("cannot start the background worker: {e}");
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;
        let base = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP;
        // Leave a job object that would end the worker with the terminal; if the job
        // forbids breakaway, fall back to a plain detached start.
        let first = build()
            .map_err(fail)?
            .creation_flags(base | CREATE_BREAKAWAY_FROM_JOB)
            .spawn();
        match first {
            Ok(child) => Ok(child),
            Err(_) => build()
                .map_err(fail)?
                .creation_flags(base)
                .spawn()
                .map_err(fail),
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // A process group of its own keeps terminal signals away; the worker also ignores
        // hangups itself.
        build()
            .map_err(fail)?
            .process_group(0)
            .spawn()
            .map_err(fail)
    }
    #[cfg(not(any(windows, unix)))]
    {
        build().map_err(fail)?.spawn().map_err(fail)
    }
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

/// CreateProcess hands the worker every inheritable handle, including this process's own
/// output pipes. A caller capturing our output (`id=$(blaze get ... --background)`) would then
/// wait until the job ends. The worker gets its own log handles explicitly instead.
#[cfg(windows)]
fn stop_inheriting_std_handles() {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::{HANDLE_FLAG_INHERIT, SetHandleInformation};
    let handles = [
        std::io::stdin().as_raw_handle(),
        std::io::stdout().as_raw_handle(),
        std::io::stderr().as_raw_handle(),
    ];
    for handle in handles.into_iter().filter(|h| !h.is_null()) {
        // SAFETY: the handle is one of this process's standard handles, which stay open for
        // its whole life; clearing the inherit flag changes nothing else about it.
        unsafe {
            SetHandleInformation(handle.cast(), HANDLE_FLAG_INHERIT, 0);
        }
    }
}

#[cfg(not(windows))]
fn stop_inheriting_std_handles() {}

pub fn launch(kind: Kind) -> Result<u8, String> {
    let store = Store::open()?;
    store.sweep(now());
    let (id, log) = store.reserve()?;
    let args = worker_args(super::invocation_args(), &id);
    stop_inheriting_std_handles();
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
                anstream::println!("{id}");
                announce(
                    "Started",
                    &format!("{} job {id}; check it with: blaze status {id}", kind.name()),
                );
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
}
