use std::io::IsTerminal;

#[derive(Clone, Copy, Debug)]
pub struct Style {
    color: bool,
}

fn color_enabled(is_tty: bool) -> bool {
    if !is_tty || std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty()) {
        return false;
    }
    if std::env::var("TERM").is_ok_and(|t| t == "dumb") {
        return false;
    }
    // Legacy Windows consoles print raw escapes unless virtual terminal mode is on;
    // only terminals that announce themselves are trusted.
    !cfg!(windows)
        || [
            "WT_SESSION",
            "TERM",
            "ANSICON",
            "ConEmuANSI",
            "TERM_PROGRAM",
        ]
        .iter()
        .any(|k| std::env::var_os(k).is_some())
}

impl Style {
    pub fn stdout() -> Self {
        Self {
            color: color_enabled(std::io::stdout().is_terminal()),
        }
    }

    pub fn stderr() -> Self {
        Self {
            color: color_enabled(std::io::stderr().is_terminal()),
        }
    }

    fn paint(self, code: &str, s: &str) -> String {
        if self.color {
            format!("\x1b[{code}m{s}\x1b[0m")
        } else {
            s.to_owned()
        }
    }

    pub fn bold(self, s: &str) -> String {
        self.paint("1", s)
    }

    pub fn dim(self, s: &str) -> String {
        self.paint("2", s)
    }

    pub fn green(self, s: &str) -> String {
        self.paint("32", s)
    }

    pub fn red(self, s: &str) -> String {
        self.paint("31", s)
    }

    pub fn yellow(self, s: &str) -> String {
        self.paint("33", s)
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
