//! What a person chooses to tell the maintainer: a guided bug report, and a rating asked now
//! and then until one is given. Everything is shown before it is sent.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::Args;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::ansi::{self, Style};
use super::{pick, prompt, runlog};
use crate::usage;

const MAX_TEXT: usize = 2000;
const MAX_LOG: usize = 8000;
const ISSUES_URL: &str = "https://github.com/whoisjayd/blazeserve/issues/new/choose";

/// Successful runs before the first question, and the least time between two.
const RUNS_BEFORE_ASKING: u32 = 5;
const BETWEEN_QUESTIONS: u64 = 7 * 24 * 60 * 60;
/// One eligible run in this many is asked, so the moment is not predictable.
const ONE_IN: u8 = 4;
/// Stop for good after this many skipped questions.
const MAX_SKIPS: u32 = 3;

#[derive(Args, Debug)]
pub struct BugArgs {
    /// What went wrong; asked for when left out
    #[arg(short, long, value_name = "TEXT")]
    pub message: Option<String>,
    /// A step to reproduce the problem (repeatable, in order)
    #[arg(long = "step", value_name = "TEXT")]
    pub steps: Vec<String>,
    /// What you expected to happen
    #[arg(long, value_name = "TEXT")]
    pub expected: Option<String>,
    /// Attach the run with this log ID instead of the latest
    #[arg(long, value_name = "ID", conflicts_with = "no_log")]
    pub log: Option<String>,
    /// Do not attach a run log
    #[arg(long)]
    pub no_log: bool,
    /// How to reach you for a reply (optional)
    #[arg(long, value_name = "EMAIL_OR_HANDLE")]
    pub contact: Option<String>,
    /// Send without asking for confirmation
    #[arg(short, long)]
    pub yes: bool,
}

/// Typed text, bounded, with credentials in any URL masked and no terminal controls.
fn clean(text: &str) -> String {
    crate::logging::redact(text.trim())
        .chars()
        .filter(|c| !c.is_control() || *c == '\n')
        .take(MAX_TEXT)
        .collect()
}

fn send(event: &str, extra: Map<String, Value>) -> Result<(), String> {
    usage::send_feedback(
        &usage::process_env,
        usage::build_time_key(),
        usage::build_time_host(),
        event,
        extra,
    )
}

/// Lets the user choose which recent run the report is about, showing it before it counts.
/// `None` means the report goes without a run.
fn pick_run() -> Option<runlog::Saved> {
    let mut runs = runlog::recent(10);
    if runs.is_empty() {
        return None;
    }
    let style = Style::stderr();
    let mut labels: Vec<String> = runs.iter().map(runlog::Saved::label).collect();
    labels.push("None of these: report without a run".to_owned());
    let mut at = runs.iter().position(runlog::Saved::failed).unwrap_or(0);
    loop {
        let chosen = pick::pick("Which run is the problem in?", &labels, at)?;
        let run = runs.get(chosen)?;
        anstream::eprintln!("\n{}", ansi::rows(style, &run.details()).trim_end());
        // A closed input counts as yes: the run can still be refused at the final question.
        if prompt::yes("\nIs this the run you mean?", true) != Some(false) {
            anstream::eprintln!();
            return Some(runs.swap_remove(chosen));
        }
        at = chosen;
    }
}

pub fn bug(args: BugArgs) -> Result<u8, String> {
    let person = prompt::person();
    let style = Style::stderr();
    if person && args.message.is_none() {
        anstream::eprintln!(
            "{}\n{}\n",
            style.bold("Report a problem"),
            style.dim("Everything is shown to you before anything is sent. Ctrl+C cancels.")
        );
    }
    // Choose the run first: it is the part the user is least able to describe.
    let picked = if person && !args.no_log && args.log.is_none() {
        Some(pick_run())
    } else {
        None
    };
    let message = match &args.message {
        Some(text) => clean(text),
        None => clean(
            &prompt::ask("What went wrong?")
                .ok_or("describe the problem with --message \"...\"")?,
        ),
    };
    if message.is_empty() {
        return Err("a report needs a description of what went wrong".to_owned());
    }
    let steps: Vec<String> = if args.steps.is_empty() {
        prompt::list("Steps to reproduce it")
    } else {
        args.steps.clone()
    }
    .iter()
    .map(|s| clean(s))
    .collect();
    let expected = args
        .expected
        .clone()
        .or_else(|| prompt::ask("What did you expect to happen?"))
        .map(|e| clean(&e))
        .filter(|e| !e.is_empty());

    let log = match picked {
        Some(chosen) => chosen,
        None => (!args.no_log)
            .then(|| runlog::find(args.log.as_deref()))
            .flatten(),
    };
    if let (Some(id), None) = (&args.log, &log) {
        return Err(format!("there is no run log with the ID {id}"));
    }
    let contact = args
        .contact
        .clone()
        .or_else(|| prompt::ask("Email or handle for a reply? (Enter to skip)"))
        .map(|c| clean(&c))
        .filter(|c| !c.is_empty());

    let mut rows = vec![("Problem", message.clone())];
    for (i, step) in steps.iter().enumerate() {
        rows.push((
            if i == 0 { "Steps" } else { "" },
            format!("{}. {step}", i + 1),
        ));
    }
    if let Some(expected) = &expected {
        rows.push(("Expected", expected.clone()));
    }
    if let Some(saved) = &log {
        rows.push(("Log file", saved.path.display().to_string()));
    }
    if let Some(contact) = &contact {
        rows.push(("Contact", contact.clone()));
    }
    rows.push((
        "Also sent",
        "version and the machine details of `blaze telemetry preview`".to_owned(),
    ));
    anstream::eprintln!(
        "\n{}\n{}",
        style.bold("This will be sent"),
        ansi::rows(style, &rows).trim_end()
    );
    anstream::eprintln!(
        "{}\n",
        style.dim(
            "Your words go as written. The log has paths and addresses removed; open it to check."
        )
    );
    if !args.yes {
        let confirmed = prompt::yes("Send this report?", false).ok_or(
            "nothing was sent: run in a terminal to confirm, or add --yes to send without asking",
        )?;
        if !confirmed {
            anstream::eprintln!("Nothing was sent.");
            return Ok(0);
        }
    }

    let report_id = runlog::new_id().ok_or("cannot create a report ID")?;
    let mut extra = Map::new();
    extra.insert("report_id".to_owned(), report_id.clone().into());
    extra.insert("feedback_text".to_owned(), message.into());
    extra.insert("steps".to_owned(), steps.into());
    if let Some(expected) = expected {
        extra.insert("expected".to_owned(), expected.into());
    }
    if let Some(saved) = log {
        if let Some(session) = saved.field("session") {
            extra.insert("run_session_id".to_owned(), session.to_owned().into());
        }
        extra.insert("log_id".to_owned(), saved.id.into());
        let text: String = saved.text.chars().take(MAX_LOG).collect();
        extra.insert("run_log".to_owned(), text.into());
    }
    if let Some(contact) = contact {
        extra.insert("contact".to_owned(), contact.into());
    }
    send("feedback bug", extra)
        .map_err(|why| format!("could not send: {why}. You can report it at {ISSUES_URL}"))?;
    anstream::eprintln!(
        "{} Report {report_id}. Quote this number if you also open an issue: {ISSUES_URL}",
        Style::stderr().green("Sent. Thank you.")
    );
    Ok(0)
}

#[derive(Default, Serialize, Deserialize)]
#[serde(default)]
struct Asking {
    runs: u32,
    asked_at: u64,
    skips: u32,
    rated: bool,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Whether to ask now. `roll` is a random byte.
fn due(state: &Asking, now: u64, roll: u8) -> bool {
    !state.rated
        && state.skips < MAX_SKIPS
        && state.runs >= RUNS_BEFORE_ASKING
        && now.saturating_sub(state.asked_at) >= BETWEEN_QUESTIONS
        && roll.is_multiple_of(ONE_IN)
}

fn state_path() -> Option<PathBuf> {
    usage::config_dir(&usage::process_env).map(|d| d.join("rating.json"))
}

fn stars(n: u8) -> String {
    "★".repeat(n.into()) + &"☆".repeat(5usize.saturating_sub(n.into()))
}

/// After a successful transfer at a terminal: now and then asks how BlazeServe is doing.
/// Once an answer is given it never asks again.
pub(super) fn maybe_ask_rating() {
    let Some(path) = state_path().filter(|_| prompt::person()) else {
        return;
    };
    let mut state: Asking = std::fs::read(&path)
        .ok()
        .and_then(|raw| serde_json::from_slice(&raw).ok())
        .unwrap_or_default();
    if state.rated {
        return;
    }
    state.runs = state.runs.saturating_add(1);
    let mut roll = [0u8; 1];
    let ask = getrandom::fill(&mut roll).is_ok() && due(&state, now(), roll[0]);
    let save = |state: &Asking| {
        serde_json::to_vec(state)
            .ok()
            .is_some_and(|raw| std::fs::write(&path, raw).is_ok())
    };
    if ask {
        state.asked_at = now();
    }
    // Saved first, so a question interrupted with Ctrl+C is not repeated at once.
    if !save(&state) || !ask {
        return;
    }
    let style = Style::stderr();
    anstream::eprintln!(
        "\n{} {}",
        style.yellow("★"),
        style.bold("How is BlazeServe working for you?")
    );
    let answer = prompt::ask("  1 (poor) to 5 (great), Enter to skip:").unwrap_or_default();
    let Some(rating) = answer.parse::<u8>().ok().filter(|n| (1..=5).contains(n)) else {
        state.skips += 1;
        save(&state);
        return;
    };
    let comment = prompt::ask("  Anything to add? (Enter to skip)")
        .map(|c| clean(&c))
        .filter(|c| !c.is_empty());
    state.rated = true;
    save(&state);
    let mut extra = Map::new();
    extra.insert("rating".to_owned(), rating.into());
    if let Some(comment) = comment {
        extra.insert("feedback_text".to_owned(), comment.into());
    }
    // A thank-you either way: a failed send is not the user's problem.
    let _ = send("feedback rating", extra);
    anstream::eprintln!(
        "  {} {}\n",
        style.yellow(&stars(rating)),
        style.dim("Thank you.")
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn asks_now_and_then_and_never_after_a_rating() {
        let week = BETWEEN_QUESTIONS;
        let ready = Asking {
            runs: RUNS_BEFORE_ASKING,
            ..Asking::default()
        };
        assert!(due(&ready, week, 0));
        assert!(!due(&ready, week, 1), "only some eligible runs");
        assert!(!due(&Asking::default(), week, 0), "not on first use");
        let recent = Asking {
            asked_at: week,
            ..ready
        };
        assert!(!due(&recent, week + 60, 0));
        assert!(!due(
            &Asking {
                rated: true,
                runs: 99,
                asked_at: 0,
                skips: 0
            },
            week,
            0
        ));
        assert!(!due(
            &Asking {
                rated: false,
                runs: 99,
                asked_at: 0,
                skips: MAX_SKIPS
            },
            week,
            0
        ));
    }

    #[test]
    fn typed_text_is_bounded_and_credentials_are_masked() {
        assert_eq!(clean(&"x".repeat(5000)).len(), MAX_TEXT);
        assert!(!clean("get http://ann:s3cret@host/x failed").contains("s3cret"));
        assert_eq!(clean("a\u{1b}[2Jb"), "a[2Jb");
        assert_eq!(stars(2), "★★☆☆☆");
    }
}
