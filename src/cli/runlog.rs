//! A short, redacted record of each run, kept on this machine for debugging and attached to
//! a bug report only when the user says so. `BLAZE_RUN_LOG=0` turns it off.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Instant;

use crate::usage;

const KEEP: usize = 20;
const MAX_LINES: usize = 500;

static NOTES: Mutex<VecDeque<String>> = Mutex::new(VecDeque::new());

/// Keeps a line of what the command said, for the log of this run.
pub(crate) fn note(line: &str) {
    static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    let at = START.get_or_init(Instant::now).elapsed().as_secs_f64();
    if let Ok(mut notes) = NOTES.lock() {
        // The latest lines matter most when something goes wrong.
        if notes.len() == MAX_LINES {
            notes.pop_front();
        }
        notes.push_back(format!("{at:>8.3}s {}", redact(line)));
    }
}

fn is_address(word: &str) -> bool {
    word.trim_matches(['[', ']'])
        .parse::<std::net::IpAddr>()
        .is_ok()
        || word.parse::<std::net::SocketAddr>().is_ok()
}

/// `name.ext`, as opposed to a version such as `1.1.0`.
fn is_file_name(word: &str) -> bool {
    word.rsplit_once('.').is_some_and(|(stem, ext)| {
        !stem.is_empty()
            && (1..=8).contains(&ext.len())
            && ext.chars().all(|c| c.is_ascii_alphanumeric())
            && ext.chars().any(|c| c.is_ascii_alphabetic())
    })
}

/// Replaces anything that looks like a URL, path, file name, address, e-mail or secret.
pub(super) fn redact(line: &str) -> String {
    let line = crate::logging::redact(line);
    line.split_whitespace()
        .map(|word| {
            let core = word.trim_matches(|c: char| ",;:()'\"`".contains(c));
            let placeholder = if core.contains("://") {
                "<url>"
            } else if core.contains(['/', '\\']) {
                "<path>"
            } else if core.contains('@') {
                "<email>"
            } else if is_address(core) {
                "<address>"
            } else if is_file_name(core) {
                "<file>"
            } else {
                return word.to_owned();
            };
            word.replace(core, placeholder)
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn folder() -> Option<PathBuf> {
    usage::config_dir(&usage::process_env).map(|d| d.join("logs"))
}

fn disabled() -> bool {
    std::env::var("BLAZE_RUN_LOG").is_ok_and(|v| matches!(v.trim(), "0" | "false" | "off"))
}

/// Log files, newest last. Their names start with the time, so they sort by it.
fn files() -> Vec<PathBuf> {
    let Some(dir) = folder() else {
        return Vec::new();
    };
    let mut found: Vec<PathBuf> = std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|x| x == "log"))
                .collect()
        })
        .unwrap_or_default();
    found.sort();
    found
}

pub(super) struct Saved {
    pub id: String,
    pub path: PathBuf,
    pub text: String,
}

impl Saved {
    pub(super) fn field(&self, name: &str) -> Option<&str> {
        self.text
            .lines()
            .find_map(|l| l.strip_prefix(name)?.strip_prefix(": "))
    }

    pub(super) fn failed(&self) -> bool {
        self.field("exit").is_some_and(|code| code != "0") || self.field("crash").is_some()
    }

    /// What the run was, as labelled rows for showing it to the user.
    pub(super) fn details(&self) -> Vec<(&'static str, String)> {
        let mut rows = Vec::new();
        for (label, field) in [
            ("Name", "name"),
            ("Command", "command"),
            ("Options", "options"),
            ("Ended", "ended"),
            ("Exit code", "exit"),
            ("Crash", "crash"),
            ("Error", "error"),
            ("Timings", "timings"),
            ("Session", "session"),
        ] {
            if let Some(value) = self.field(field).filter(|v| !v.is_empty() && *v != "{}") {
                rows.push((label, value.to_owned()));
            }
        }
        let notes: Vec<&str> = self
            .text
            .lines()
            .filter_map(|l| l.strip_prefix("| "))
            .collect();
        for (i, note) in notes.iter().rev().take(4).rev().enumerate() {
            rows.push((if i == 0 { "Last said" } else { "" }, (*note).to_owned()));
        }
        rows
    }

    /// One line for a list: when, what, how it ended and the ID.
    pub(super) fn label(&self) -> String {
        let when = self
            .field("ended")
            .map(|t| t.trim_end_matches('Z').replace('T', " "))
            .unwrap_or_default();
        let outcome = if self.field("crash").is_some() {
            "crashed".to_owned()
        } else if !self.failed() {
            "ok".to_owned()
        } else {
            format!("failed ({})", self.field("error kind").unwrap_or("error"))
        };
        format!(
            "{when}  {:<10} {outcome:<20} {}  {}",
            self.field("command").unwrap_or("?"),
            self.id,
            self.field("name").unwrap_or("")
        )
    }
}

/// The latest `count` runs, newest first.
pub(super) fn recent(count: usize) -> Vec<Saved> {
    files().iter().rev().filter_map(load).take(count).collect()
}

fn load(path: &PathBuf) -> Option<Saved> {
    let id = path.file_stem()?.to_str()?.rsplit_once('-')?.1.to_owned();
    Some(Saved {
        id,
        path: path.clone(),
        text: std::fs::read_to_string(path).ok()?,
    })
}

/// The log of the most recent run, or the one with this ID.
pub(super) fn find(id: Option<&str>) -> Option<Saved> {
    files()
        .iter()
        .rev()
        .filter_map(load)
        .find(|saved| id.is_none_or(|id| saved.id == id))
}

/// A new ID for the log of this run.
pub(super) fn new_id() -> Option<String> {
    let mut raw = [0u8; 4];
    getrandom::fill(&mut raw).ok()?;
    Some(super::util::hex(&raw))
}

/// Writes the log of the run that just ended.
pub(super) fn save(id: &str, header: &[(&str, String)]) {
    if disabled() {
        return;
    }
    let Some(dir) = folder() else { return };
    let when = crate::logging::utc_timestamp();
    let mut text = format!(
        "blazeserve {} on {} {}\nlog: {id}\nended: {when}\n",
        crate::VERSION,
        std::env::consts::OS,
        std::env::consts::ARCH
    );
    if let Some(name) = crate::cli::run_name() {
        text.push_str(&format!("name: {name}\n"));
    }
    for (key, value) in header {
        text.push_str(&format!("{key}: {value}\n"));
    }
    if let Ok(notes) = NOTES.lock() {
        for line in notes.iter() {
            text.push_str(&format!("| {line}\n"));
        }
    }
    let stamp: String = when.chars().filter(char::is_ascii_digit).collect();
    if crate::platform::create_private_dir(&dir).is_err() {
        return;
    }
    let _ = std::fs::write(dir.join(format!("{stamp}-{id}.log")), text);
    let old = files();
    for path in &old[..old.len().saturating_sub(KEEP)] {
        let _ = std::fs::remove_file(path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_private_survives_redaction() {
        let line = redact(
            "cannot write C:\\Users\\Ann\\notes.txt from http://ann:pw@host/x.iso \
             (10.1.2.3:5949, ann@example.com, report.pdf) after 1.1.0",
        );
        for private in [
            "Ann", "ann:", "ann@", "pw", "host", "10.1.2.3", "report", "notes",
        ] {
            assert!(!line.contains(private), "{private} survived: {line}");
        }
        assert!(line.contains("cannot write"), "{line}");
        assert!(line.contains("1.1.0"), "{line}");
    }
}
