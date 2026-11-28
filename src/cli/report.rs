//! What happens around a command: its redacted local log, its anonymous usage report, and
//! now and then a request for a rating. See `docs/telemetry.md`.

use std::io::IsTerminal;
use std::sync::Mutex;

use clap::ArgMatches;
use clap::error::ErrorKind;
use clap::parser::ValueSource;

use super::ansi::Style;
use super::{crash, feedback, runlog};
use crate::usage::{self, CommandReport, Reporter};

/// Commands that manage reporting itself or only print scripts for other tools.
const SILENT: &[&str] = &["telemetry", "completions", "man", "upgrade", "bug"];
/// Commands that already take long enough for sending at the end to go unnoticed.
const SENDS_AT_EXIT: &[&str] = &["serve", "send", "get", "put", "benchmark"];
/// Commands after which a rating may be asked: finished work, with a person watching.
const ASKS_AFTER: &[&str] = &["get", "put", "verify"];

static CURRENT: Mutex<Option<Reporter>> = Mutex::new(None);

/// The reporter of the running command, for events inside it.
pub(super) fn current() -> Option<Reporter> {
    CURRENT.lock().ok().and_then(|r| r.clone())
}

fn open(command: &str) -> Option<Reporter> {
    let terminal = std::io::stderr().is_terminal();
    // A server prints its notice into its log; elsewhere it must be seen by a person.
    let announce = terminal || matches!(command, "serve" | "send");
    usage::open(
        &usage::process_env,
        usage::build_time_key(),
        usage::build_time_host(),
        // Removes the notice's colour codes where they cannot be shown.
        &mut anstream::stderr(),
        announce,
        terminal,
    )
}

/// The names of the options typed; their values are never read here. Clap also lists a
/// group for each argument struct, named after the type, which is not an option.
fn option_names(args: &ArgMatches) -> Vec<String> {
    let mut names: Vec<String> = args
        .ids()
        .map(clap::Id::as_str)
        .filter(|id| {
            !id.starts_with("background")
                && !id.contains(|c: char| c.is_ascii_uppercase())
                && args.value_source(id) == Some(ValueSource::CommandLine)
        })
        .map(str::to_owned)
        .collect();
    names.sort();
    names
}

/// A command that is running.
pub(super) struct Run {
    command: String,
    flags: Vec<String>,
    background: bool,
    log_id: String,
    reporter: Option<Reporter>,
}

pub(super) fn begin(matches: &ArgMatches) -> Option<Run> {
    let (command, args) = matches.subcommand()?;
    if SILENT.contains(&command) {
        return None;
    }
    let given = |id: &str| {
        args.try_contains_id(id).is_ok() && args.value_source(id) == Some(ValueSource::CommandLine)
    };
    // The launcher of a background job does nothing itself; its worker reports.
    if given("background") {
        return None;
    }
    let flags = option_names(args);
    let reporter = open(command);
    if let Some(reporter) = &reporter {
        usage::install_panic_hook(reporter);
    }
    if let Ok(mut current) = CURRENT.lock() {
        current.clone_from(&reporter);
    }
    let background = given("background_worker");
    if !background {
        crash::offer_pending();
    }
    let log_id = runlog::new_id()?;
    crash::install(
        command.to_owned(),
        log_id.clone(),
        reporter.as_ref().and_then(Reporter::session_id),
    );
    Some(Run {
        command: command.to_owned(),
        flags,
        background,
        log_id,
        reporter,
    })
}

impl Run {
    pub(super) fn finish(
        self,
        exit_code: u8,
        error_kind: Option<&'static str>,
        error: Option<&str>,
    ) {
        let mut header = vec![
            ("command", self.command.clone()),
            ("options", self.flags.join(" ")),
            ("exit", exit_code.to_string()),
        ];
        if let Some(session) = self.reporter.as_ref().and_then(Reporter::session_id) {
            header.push(("session", session));
        }
        if let Some(kind) = error_kind {
            header.push(("error kind", kind.to_owned()));
        }
        if let Some(error) = error {
            header.push(("error", runlog::redact(error)));
        }
        header.push((
            "timings",
            serde_json::Value::from(usage::trace::peek()).to_string(),
        ));
        runlog::save(&self.log_id, &header);

        if let Some(reporter) = &self.reporter {
            let wait = SENDS_AT_EXIT.contains(&self.command.as_str());
            reporter.command_finished(
                CommandReport {
                    command: &self.command,
                    flags: self.flags.clone(),
                    background: self.background,
                    exit_code,
                    error_kind,
                    log_id: Some(&self.log_id),
                },
                wait,
                &mut std::io::stderr(),
            );
        }
        if !std::io::stderr().is_terminal() || self.background {
            return;
        }
        if exit_code != 0 && !matches!(error_kind, Some("usage" | "interrupted" | "auth")) {
            let style = Style::stderr();
            anstream::eprintln!(
                "{}",
                style.dim(&format!(
                    "  If this looks like a bug: blaze bug --log {}",
                    self.log_id
                ))
            );
        }
        if exit_code == 0 && ASKS_AFTER.contains(&self.command.as_str()) && self.reporter.is_some()
        {
            feedback::maybe_ask_rating();
        }
    }
}

/// Records that help was read or a command line refused, which shows where `blaze` is unclear.
pub(super) fn unparsed(command: &str, kind: ErrorKind) {
    let (event, reason) = match kind {
        ErrorKind::DisplayVersion => return,
        ErrorKind::DisplayHelp | ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand => {
            ("help viewed", None)
        }
        ErrorKind::UnknownArgument => ("command rejected", Some("unknown_argument")),
        ErrorKind::InvalidSubcommand => ("command rejected", Some("unknown_command")),
        ErrorKind::MissingRequiredArgument => ("command rejected", Some("missing_argument")),
        ErrorKind::ArgumentConflict => ("command rejected", Some("conflicting_arguments")),
        ErrorKind::InvalidValue | ErrorKind::ValueValidation => {
            ("command rejected", Some("invalid_value"))
        }
        _ => ("command rejected", Some("usage")),
    };
    if !SILENT.contains(&command)
        && let Some(reporter) = open(command)
    {
        reporter.command_line(event, command, reason, &mut std::io::stderr());
    }
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    #[test]
    fn only_typed_options_are_named() {
        let matches = crate::cli::Cli::command()
            .try_get_matches_from(["blaze", "checksum", "Cargo.toml"])
            .unwrap();
        let (_, args) = matches.subcommand().unwrap();
        assert_eq!(option_names(args), ["files"]);
    }
}
