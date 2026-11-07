//! Terminal styling that follows `--color`, `NO_COLOR`, `CLICOLOR(_FORCE)` and the stream's capabilities.

use anstream::{AutoStream, ColorChoice};
use anstyle::{AnsiColor, Style as Paint};

const STATUS_WIDTH: usize = 12;

#[derive(Clone, Copy, Debug)]
pub struct Style {
    color: bool,
}

impl Style {
    pub fn stdout() -> Self {
        Self {
            color: AutoStream::choice(&std::io::stdout()) != ColorChoice::Never,
        }
    }

    pub fn stderr() -> Self {
        Self {
            color: AutoStream::choice(&std::io::stderr()) != ColorChoice::Never,
        }
    }

    fn paint(self, paint: Paint, s: &str) -> String {
        if self.color {
            format!("{paint}{s}{paint:#}")
        } else {
            s.to_owned()
        }
    }

    pub fn bold(self, s: &str) -> String {
        self.paint(Paint::new().bold(), s)
    }

    pub fn dim(self, s: &str) -> String {
        self.paint(Paint::new().dimmed(), s)
    }

    pub fn green(self, s: &str) -> String {
        self.paint(AnsiColor::Green.on_default(), s)
    }

    pub fn red(self, s: &str) -> String {
        self.paint(AnsiColor::Red.on_default().bold(), s)
    }

    pub fn yellow(self, s: &str) -> String {
        self.paint(AnsiColor::Yellow.on_default().bold(), s)
    }
}

pub fn rows(style: Style, rows: &[(&str, String)]) -> String {
    let width = rows
        .iter()
        .map(|(l, _)| l.chars().count())
        .max()
        .unwrap_or(0);
    let mut out = String::new();
    for (label, value) in rows {
        let pad = " ".repeat(width - label.chars().count());
        out.push_str(&format!("  {}{pad}  {value}\n", style.dim(label)));
    }
    out
}

/// A progress line in cargo's layout: the verb right-aligned in a fixed column, then the message.
pub fn status_line(style: Style, verb: &str, message: &str) -> String {
    let pad = " ".repeat(STATUS_WIDTH.saturating_sub(verb.chars().count()));
    format!("{pad}{} {message}", style.green(verb))
}

pub fn announce(verb: &str, message: &str) {
    anstream::eprintln!("{}", status_line(Style::stderr(), verb, message));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_verbs_align_on_one_column() {
        let plain = Style { color: false };
        assert_eq!(
            status_line(plain, "Resuming", "big.iso"),
            "    Resuming big.iso"
        );
        assert_eq!(status_line(plain, "Downloading", "x"), " Downloading x");
        assert_eq!(status_line(plain, "Verification", "ok"), "Verification ok");
    }

    #[test]
    fn colour_off_leaves_text_untouched_and_on_wraps_it() {
        let off = Style { color: false };
        let on = Style { color: true };
        assert_eq!(off.red("error:"), "error:");
        let painted = on.red("error:");
        assert!(painted.starts_with("\u{1b}[") && painted.ends_with("\u{1b}[0m"));
        assert!(painted.contains("error:"));
    }
}
