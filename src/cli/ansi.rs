//! Terminal styling that follows `--color`, `NO_COLOR`, `CLICOLOR(_FORCE)` and the stream's capabilities.

use anstream::{AutoStream, ColorChoice};
use anstyle::{AnsiColor, Style as Paint};
use indicatif::ProgressBar;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

const STATUS_WIDTH: usize = 12;

/// The transfer dashboard currently on screen, so notices can be printed above it without
/// tearing its redraw.
static ACTIVE_BAR: Mutex<Option<ProgressBar>> = Mutex::new(None);

/// `--quiet`: only errors and warnings. Process-wide because one process runs one command.
static QUIET: AtomicBool = AtomicBool::new(false);

pub(super) fn set_quiet(quiet: bool) {
    QUIET.store(quiet, Ordering::Relaxed);
}

pub(crate) fn quiet() -> bool {
    QUIET.load(Ordering::Relaxed)
}

/// `--progress json`: progress and the result as JSON lines for programs.
static JSON: AtomicBool = AtomicBool::new(false);

pub(super) fn set_json_progress(json: bool) {
    JSON.store(json, Ordering::Relaxed);
}

pub(crate) fn json_progress() -> bool {
    JSON.load(Ordering::Relaxed)
}

/// The last line of a JSON run, on standard output.
pub(crate) fn done_event(path: &std::path::Path, bytes: u64) {
    if json_progress() {
        println!(
            "{}",
            serde_json::json!({ "event": "done", "path": path.display().to_string(), "bytes": bytes })
        );
    }
}

pub(super) fn set_active_bar(bar: Option<ProgressBar>) {
    if let Ok(mut slot) = ACTIVE_BAR.lock() {
        *slot = bar;
    }
}

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

    pub fn enabled(self) -> bool {
        self.color
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

    /// Black on bright white, so it reads the same on light and dark themes.
    pub fn on_white(self, s: &str) -> String {
        self.paint(
            Paint::new()
                .fg_color(Some(AnsiColor::Black.into()))
                .bg_color(Some(AnsiColor::BrightWhite.into())),
            s,
        )
    }
}

/// `body` in a titled box, or `None` when it would not fit `width` columns.
pub fn boxed(style: Style, title: &str, body: &str, width: usize) -> Option<String> {
    let lines: Vec<&str> = body.trim_end().lines().collect();
    let measure = console::measure_text_width;
    let inner = lines
        .iter()
        .map(|l| measure(l))
        .chain([measure(title) + 1])
        .max()?
        + 2;
    if inner + 2 > width {
        return None;
    }
    let edge = |s: &str| style.dim(s);
    let mut out = format!(
        "{} {} {}\n",
        edge("\u{256d}\u{2500}"),
        style.bold(title),
        edge(&format!(
            "{}\u{256e}",
            "\u{2500}".repeat(inner.saturating_sub(measure(title) + 3))
        ))
    );
    for line in lines {
        out.push_str(&format!(
            "{}{line}{}{}\n",
            edge("\u{2502}"),
            " ".repeat(inner - measure(line)),
            edge("\u{2502}")
        ));
    }
    out.push_str(&edge(&format!(
        "\u{2570}{}\u{256f}",
        "\u{2500}".repeat(inner)
    )));
    out.push('\n');
    Some(out)
}

/// Prints `body` as a titled card at a terminal wide enough for it, else prints `plain`
/// exactly, so piped output never changes shape.
pub fn card(title: &str, body: &str, plain: &str) {
    let term = console::Term::stdout();
    let framed = term
        .is_term()
        .then(|| boxed(Style::stdout(), title, body, usize::from(term.size().1)))
        .flatten();
    anstream::print!("{}", framed.as_deref().unwrap_or(plain));
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
    super::runlog::note(&format!("{verb} {message}"));
    // JSON runs keep standard error to JSON lines.
    if (quiet() || json_progress()) && verb != "Warning" {
        return;
    }
    let line = status_line(Style::stderr(), verb, message);
    let bar = ACTIVE_BAR.lock().ok().and_then(|slot| slot.clone());
    match bar {
        Some(bar) => bar.suspend(|| anstream::eprintln!("{line}")),
        None => anstream::eprintln!("{line}"),
    }
}

#[cfg(test)]
impl Style {
    pub const PLAIN: Self = Self { color: false };
    pub const COLOR: Self = Self { color: true };
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
    fn a_card_lines_up_whatever_the_colour_codes() {
        for style in [Style::PLAIN, Style::COLOR] {
            let body = format!("  {}  one\n  longer label  two\n", style.dim("a"));
            let card = boxed(style, "Title", &body, 80).unwrap();
            let widths: Vec<usize> = card.lines().map(console::measure_text_width).collect();
            assert!(
                widths.windows(2).all(|w| w[0] == w[1]),
                "{widths:?}\n{card}"
            );
        }
        assert!(boxed(Style::PLAIN, "Title", &"x".repeat(100), 80).is_none());
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
