//! A crash report: gathered when the program panics, and sent only if the user says yes,
//! either at once or, when nobody could be asked, at the next run in a terminal.

use std::io::{BufRead, IsTerminal, Write};
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::ansi::Style;
use super::runlog;
use crate::usage;

const ANSWER_WITHIN: Duration = Duration::from_secs(60);
const PENDING_FILE: &str = "crash.json";

#[derive(Serialize, Deserialize, Clone)]
struct Crash {
    location: String,
    message: String,
    log_id: String,
    session: Option<String>,
    command: String,
}

fn pending_path() -> Option<PathBuf> {
    usage::config_dir(&usage::process_env).map(|d| d.join(PENDING_FILE))
}

/// The end of a source path, which otherwise names a folder on the machine that built it.
fn source_place(file: &str, line: u32) -> String {
    let file = file.replace('\\', "/");
    let short = file.rfind("/src/").map_or(file.as_str(), |at| {
        &file[file[..at].rfind('/').map_or(0, |i| i + 1)..]
    });
    format!("{short}:{line}")
}

fn send(crash: &Crash) -> Result<String, String> {
    let report_id = runlog::new_id().ok_or("cannot create a report ID")?;
    let mut extra = Map::new();
    let mut put = |key: &str, value: Value| {
        extra.insert(key.to_owned(), value);
    };
    put("report_id", report_id.clone().into());
    put("command", crash.command.clone().into());
    put(
        "feedback_text",
        format!("crash at {}: {}", crash.location, crash.message).into(),
    );
    put("log_id", crash.log_id.clone().into());
    if let Some(session) = &crash.session {
        put("run_session_id", session.clone().into());
    }
    if let Some(saved) = runlog::find(Some(&crash.log_id)) {
        put(
            "run_log",
            saved.text.chars().take(8000).collect::<String>().into(),
        );
    }
    usage::send_feedback(
        &usage::process_env,
        usage::build_time_key(),
        usage::build_time_host(),
        "feedback crash",
        extra,
    )?;
    Ok(report_id)
}

/// Reads one line, giving up after a while: a crash must never leave the program hanging.
fn answer() -> Option<String> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut line = String::new();
        if std::io::stdin()
            .lock()
            .read_line(&mut line)
            .is_ok_and(|n| n > 0)
        {
            let _ = tx.send(line);
        }
    });
    rx.recv_timeout(ANSWER_WITHIN).ok()
}

/// Shows what would be sent and asks. Either answer settles it.
fn offer(crash: &Crash) {
    if !(std::io::stdin().is_terminal() && std::io::stderr().is_terminal()) {
        return;
    }
    let style = Style::stderr();
    anstream::eprintln!(
        "\n{}\n  where  {}\n  what   {}\n  log    {} (paths and addresses removed)\n{}",
        style.bold("BlazeServe crashed. Send a report so it can be fixed?"),
        crash.location,
        crash.message,
        crash.log_id,
        style
            .dim("  It includes the run log and the machine details of `blaze telemetry preview`.")
    );
    anstream::eprint!("Send the report? [y/N] ");
    let _ = std::io::stderr().flush();
    let Some(line) = answer() else {
        return;
    };
    if matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
        match send(crash) {
            Ok(id) => anstream::eprintln!("{} Report {id}.", style.green("Sent. Thank you.")),
            Err(why) => {
                anstream::eprintln!("Could not send the report: {why}. It is kept for next time.");
                return;
            }
        }
    }
    if let Some(path) = pending_path() {
        let _ = std::fs::remove_file(path);
    }
}

/// Offers a report left over from a crash that nobody could be asked about.
pub(super) fn offer_pending() {
    let Some(crash) = pending_path()
        .and_then(|p| std::fs::read(p).ok())
        .and_then(|raw| serde_json::from_slice::<Crash>(&raw).ok())
    else {
        return;
    };
    offer(&crash);
}

/// Records a crash of this run: the log, a pending report, and the offer to send it.
pub(super) fn install(command: String, log_id: String, session: Option<String>) {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        previous(info);
        let location = info.location().map_or_else(
            || "unknown".to_owned(),
            |l| source_place(l.file(), l.line()),
        );
        let payload = info.payload();
        let message = payload
            .downcast_ref::<&str>()
            .map(|s| (*s).to_owned())
            .or_else(|| payload.downcast_ref::<String>().cloned())
            .unwrap_or_default();
        let crash = Crash {
            location,
            message: runlog::redact(&message),
            log_id: log_id.clone(),
            session: session.clone(),
            command: command.clone(),
        };
        runlog::save(
            &crash.log_id,
            &[
                ("command", crash.command.clone()),
                ("crash", format!("{} {}", crash.location, crash.message)),
                ("session", crash.session.clone().unwrap_or_default()),
            ],
        );
        if let Some(path) = pending_path()
            && let Ok(raw) = serde_json::to_vec(&crash)
        {
            let _ = std::fs::write(path, raw);
        }
        offer(&crash);
    }));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_places_do_not_name_a_home_folder() {
        assert_eq!(
            source_place(r"C:\Users\Ann\blazeserve\src\cli\mod.rs", 2),
            "blazeserve/src/cli/mod.rs:2"
        );
        assert_eq!(source_place("src/lib.rs", 1), "src/lib.rs:1");
    }
}
