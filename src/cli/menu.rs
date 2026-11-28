//! `blaze` on its own at a terminal: asks what to do, collects the details, then runs the
//! matching command and shows it, so the next time it can be typed directly.

use std::path::PathBuf;

use super::ansi::Style;
use super::{pick, prompt};

const CHOICES: &[&str] = &[
    "Share a folder        people open a link and download (or upload) files",
    "Send one file         a link just for that file, with a QR code",
    "Download a file       resumes if interrupted, several connections at once",
    "Upload a file         to a BlazeServe server that accepts uploads",
    "Check files           against SHA256SUMS, .sha256 or .sfv lists",
    "Background jobs       see what is running and how far it got",
    "Report a problem      tell the maintainer what went wrong",
    "Show every command    the full help",
];

/// A typed or dropped path: without the quotes a drag adds, with `~` expanded.
fn path(typed: &str) -> String {
    let typed = typed.trim().trim_matches(['"', '\'']).trim();
    let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"));
    match (typed.strip_prefix("~/"), home) {
        (Some(rest), Some(home)) => PathBuf::from(home).join(rest).display().to_string(),
        _ => typed.to_owned(),
    }
}

/// Asks until the answer names something that exists, or is left empty.
fn existing(question: &str, folder: bool, default: Option<&str>) -> Option<String> {
    loop {
        let typed = path(&prompt::ask(question)?);
        let typed = match (typed.is_empty(), default) {
            (true, Some(default)) => default.to_owned(),
            (true, None) => return None,
            _ => typed,
        };
        let found = std::path::Path::new(&typed);
        if if folder {
            found.is_dir()
        } else {
            found.is_file()
        } {
            return Some(typed);
        }
        anstream::eprintln!(
            "  {}",
            Style::stderr().red(&format!(
                "no such {}: {typed}",
                if folder { "folder" } else { "file" }
            ))
        );
    }
}

fn required(question: &str) -> Option<String> {
    Some(prompt::ask(question)?).filter(|a| !a.is_empty())
}

/// The arguments for the chosen task; `None` when the user backs out.
fn build(choice: usize) -> Option<Vec<String>> {
    let word = |s: &str| s.to_owned();
    let mut args;
    match choice {
        0 => {
            let folder = existing("Folder to share [.]:", true, Some("."))?;
            args = vec![word("serve"), folder];
            if prompt::yes("Let people upload files too?", false)? {
                args.push(word("--uploads"));
            }
            if prompt::yes("Show a QR code for phones?", false)? {
                args.push(word("--qr"));
            }
        }
        1 => {
            let file = existing("File to send (you can drag it here):", false, None)?;
            args = vec![word("send"), file, word("--qr")];
        }
        2 => {
            let url = required("Address to download:")?;
            args = vec![word("get"), url];
            let name = path(&prompt::ask("Save as [name from the server]:")?);
            if !name.is_empty() {
                args.extend([word("--output"), name]);
            }
        }
        3 => {
            let file = existing("File to upload:", false, None)?;
            let url = required("Server address, such as http://host:5949:")?;
            args = vec![word("put"), file, url];
            let login = prompt::secret("user:password (hidden, Enter if none):")?;
            if !login.is_empty() {
                args.extend([word("--auth"), login]);
            }
        }
        4 => {
            let file = existing("File or checksum list to check:", false, None)?;
            let lower = file.to_ascii_lowercase();
            args = vec![word("verify")];
            if lower.ends_with(".sfv") {
                args.push(word("--sfv"));
            } else if lower.ends_with("sha256sums") || lower.ends_with("sums.txt") {
                args.push(word("--check"));
            }
            args.push(file);
        }
        5 => args = vec![word("status")],
        6 => args = vec![word("bug")],
        _ => args = vec![word("--help")],
    }
    Some(args)
}

/// The command line to show: secrets hidden, words with spaces quoted.
fn shown(args: &[String]) -> String {
    let mut secret = false;
    let words: Vec<String> = args
        .iter()
        .map(|arg| {
            let hide = std::mem::replace(&mut secret, arg == "--auth");
            if hide {
                "USER:PASS".to_owned()
            } else if arg.contains([' ', '&', '?', '(', ')']) {
                format!("\"{arg}\"")
            } else {
                arg.clone()
            }
        })
        .collect();
    format!("blaze {}", words.join(" "))
}

/// The arguments to run, or `None` to leave without doing anything.
pub(super) fn run() -> Option<Vec<String>> {
    let style = Style::stderr();
    anstream::eprintln!(
        "{} {}\n",
        style.bold(&format!("BlazeServe {}", crate::VERSION)),
        style.dim("fast file sharing and transfers")
    );
    let choices: Vec<String> = CHOICES.iter().map(|s| (*s).to_owned()).collect();
    let choice = pick::pick("What would you like to do?", &choices, 0)?;
    let args = build(choice)?;
    anstream::eprintln!(
        "\n{} {}\n",
        style.dim("Next time you can type:"),
        style.green(&shown(&args))
    );
    Some(args)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_shown_command_hides_the_password_and_quotes_spaces() {
        let args: Vec<String> = ["put", "my file", "http://h", "--auth", "a:secret"]
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        assert_eq!(
            shown(&args),
            "blaze put \"my file\" http://h --auth USER:PASS"
        );
        assert_eq!(path("  \"/tmp/a b\" "), "/tmp/a b");
    }
}
