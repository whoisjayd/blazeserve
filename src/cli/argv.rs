//! Builds a command line from `(command, positional values, options)`, using the live clap
//! definition as the only source of truth. The Python package relies on this, so a new
//! command or option is reachable from Python the day it exists, without a second list to keep
//! in step.

use clap::{Arg, Command, CommandFactory};

use super::Cli;

/// The value of one option.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OptValue {
    /// A switch: `true` turns it on, `false` turns it off.
    Flag(bool),
    /// One value, or several for an option that may repeat.
    Values(Vec<String>),
}

fn long_of(arg: &Arg) -> Option<&str> {
    arg.get_long()
}

fn takes_value(arg: &Arg) -> bool {
    arg.get_action().takes_values()
}

fn find<'a>(cmd: &'a Command, long: &str) -> Option<&'a Arg> {
    cmd.get_arguments().find(|a| long_of(a) == Some(long))
}

fn visible_options(cmd: &Command) -> Vec<String> {
    let mut names: Vec<String> = cmd
        .get_arguments()
        .filter(|a| !a.is_hide_set())
        .filter_map(long_of)
        .map(|l| l.replace('-', "_"))
        .collect();
    names.sort();
    names
}

/// `name` as written on the command line: `max_time` becomes `max-time`.
fn dashed(name: &str) -> String {
    name.trim_start_matches('-').replace('_', "-")
}

/// The visible commands and their one-line descriptions, for discovery.
pub fn commands() -> Vec<(String, String)> {
    Cli::command()
        .get_subcommands()
        .filter(|c| !c.is_hide_set() && c.get_name() != "help")
        .map(|c| {
            (
                c.get_name().to_owned(),
                c.get_about().map(ToString::to_string).unwrap_or_default(),
            )
        })
        .collect()
}

/// Everything after the program name. Options come first and positional values follow a `--`,
/// so a value that starts with a dash is never read as an option.
pub fn build(
    command: &str,
    positional: &[String],
    options: &[(String, OptValue)],
) -> Result<Vec<String>, String> {
    let root = Cli::command();
    let sub = root.find_subcommand(command).ok_or_else(|| {
        let names: Vec<String> = commands().into_iter().map(|(n, _)| n).collect();
        format!(
            "unknown command '{command}'; the commands are {}",
            names.join(", ")
        )
    })?;

    let mut global: Vec<String> = Vec::new();
    let mut local: Vec<String> = Vec::new();
    for (name, value) in options {
        let long = dashed(name);
        let target = if find(sub, &long).is_some() {
            Some((sub, &mut local))
        } else if find(&root, &long).is_some() {
            Some((&root, &mut global))
        } else {
            None
        };
        match target {
            Some((owner, out)) => push_option(owner, &long, name, value, out)?,
            None => push_negation_only(sub, &long, name, value, command, &mut local)?,
        }
    }

    let mut argv = global;
    argv.push(command.to_owned());
    argv.extend(local);
    if !positional.is_empty() {
        argv.push("--".to_owned());
        argv.extend(positional.iter().cloned());
    }
    Ok(argv)
}

fn push_option(
    owner: &Command,
    long: &str,
    name: &str,
    value: &OptValue,
    out: &mut Vec<String>,
) -> Result<(), String> {
    let arg = find(owner, long).expect("checked by the caller");
    match value {
        OptValue::Flag(on) => {
            if takes_value(arg) {
                return Err(format!(
                    "option '{name}' needs a value, not a true or false"
                ));
            }
            if *on {
                out.push(format!("--{long}"));
            } else if find(owner, &format!("no-{long}")).is_some() {
                out.push(format!("--no-{long}"));
            }
            // A switch that is off is the default, so there is nothing to pass.
        }
        OptValue::Values(values) => {
            if !takes_value(arg) {
                return Err(format!("option '{name}' is a switch; pass True or False"));
            }
            for v in values {
                out.push(format!("--{long}"));
                out.push(v.clone());
            }
        }
    }
    Ok(())
}

/// An option written positively whose command line form is only the negation, such as
/// `listing=False` for `--no-listing`.
fn push_negation_only(
    sub: &Command,
    long: &str,
    name: &str,
    value: &OptValue,
    command: &str,
    out: &mut Vec<String>,
) -> Result<(), String> {
    if let (OptValue::Flag(on), Some(_)) = (value, find(sub, &format!("no-{long}"))) {
        if !*on {
            out.push(format!("--no-{long}"));
        }
        return Ok(());
    }
    Err(format!(
        "'{command}' has no option '{name}'; the options are {}",
        visible_options(sub).join(", ")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn values(v: &[&str]) -> OptValue {
        OptValue::Values(v.iter().map(|s| (*s).to_owned()).collect())
    }

    fn strings(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn options_come_first_and_positionals_follow_a_separator() {
        let argv = build(
            "get",
            &strings(&["http://h/x"]),
            &[
                ("connections".into(), values(&["8"])),
                ("extract".into(), OptValue::Flag(true)),
            ],
        )
        .unwrap();
        assert_eq!(
            argv,
            strings(&["get", "--connections", "8", "--extract", "--", "http://h/x"])
        );
    }

    #[test]
    fn underscores_become_dashes_and_lists_repeat() {
        let argv = build(
            "serve",
            &[],
            &[
                ("max_upload_mb".into(), values(&["50"])),
                ("hide".into(), values(&["*.env", ".git"])),
            ],
        )
        .unwrap();
        assert_eq!(
            argv,
            strings(&[
                "serve",
                "--max-upload-mb",
                "50",
                "--hide",
                "*.env",
                "--hide",
                ".git"
            ])
        );
    }

    #[test]
    fn a_false_switch_uses_its_negation_when_there_is_one() {
        let off = build("serve", &[], &[("listing".into(), OptValue::Flag(false))]).unwrap();
        assert_eq!(off, strings(&["serve", "--no-listing"]));
        let on = build("serve", &[], &[("listing".into(), OptValue::Flag(true))]).unwrap();
        assert_eq!(on, strings(&["serve"]));
        // `cors` has a `--no-cors`, so an explicit false is passed on; `open` has none.
        let cors = build("serve", &[], &[("cors".into(), OptValue::Flag(false))]).unwrap();
        assert_eq!(cors, strings(&["serve", "--no-cors"]));
        let plain = build("serve", &[], &[("open".into(), OptValue::Flag(false))]).unwrap();
        assert_eq!(plain, strings(&["serve"]));
    }

    #[test]
    fn a_value_that_looks_like_an_option_stays_a_value() {
        let argv = build("get", &strings(&["--not-an-option"]), &[]).unwrap();
        assert_eq!(argv, strings(&["get", "--", "--not-an-option"]));
    }

    #[test]
    fn mistakes_are_reported_with_the_valid_names() {
        let unknown = build("get", &[], &[("conections".into(), values(&["8"]))]).unwrap_err();
        assert!(unknown.contains("no option 'conections'") && unknown.contains("connections"));
        let command = build("fetch", &[], &[]).unwrap_err();
        assert!(command.contains("unknown command") && command.contains("get"));
        let switch = build("get", &[], &[("extract".into(), values(&["yes"]))]).unwrap_err();
        assert!(switch.contains("switch"));
        let needs = build("get", &[], &[("connections".into(), OptValue::Flag(true))]).unwrap_err();
        assert!(needs.contains("needs a value"));
    }

    #[test]
    fn global_options_go_before_the_command() {
        let argv = build("get", &[], &[("color".into(), values(&["never"]))]).unwrap();
        assert_eq!(argv, strings(&["--color", "never", "get"]));
    }

    #[test]
    fn every_built_command_line_parses() {
        use clap::Parser;
        let line = build(
            "get",
            &strings(&["http://h/x"]),
            &[("connections".into(), values(&["8"]))],
        )
        .unwrap();
        let full: Vec<String> = std::iter::once("blaze".to_owned()).chain(line).collect();
        assert!(Cli::try_parse_from(full).is_ok());
    }

    #[test]
    fn the_command_list_matches_the_definition() {
        let names: Vec<String> = commands().into_iter().map(|(n, _)| n).collect();
        for expected in ["serve", "send", "get", "put", "checksum", "doctor"] {
            assert!(
                names.iter().any(|n| n == expected),
                "{expected} in {names:?}"
            );
        }
    }
}
