//! Questions asked of a person at a terminal: a line, a yes or no, a secret or a list. Every
//! call answers `None` when nobody is there, so scripts are never left waiting.

use std::io::{BufRead, IsTerminal, Write};

use super::ansi::Style;

/// Whether someone can both read a question and type an answer.
pub(super) fn person() -> bool {
    std::io::stdin().is_terminal() && std::io::stderr().is_terminal()
}

/// One trimmed line, or `None` when nobody is there or the input is closed.
pub(super) fn ask(question: &str) -> Option<String> {
    if !person() {
        return None;
    }
    anstream::eprint!("{} ", Style::stderr().bold(question));
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    let read = std::io::stdin().lock().read_line(&mut line).ok()?;
    (read > 0).then(|| line.trim().to_owned())
}

/// Like [`ask`], without showing what is typed.
pub(super) fn secret(question: &str) -> Option<String> {
    if !person() {
        return None;
    }
    anstream::eprint!("{} ", Style::stderr().bold(question));
    let _ = std::io::stderr().flush();
    console::Term::stderr().read_secure_line().ok()
}

/// A yes or no; Enter takes `default`.
pub(super) fn yes(question: &str, default: bool) -> Option<bool> {
    let hint = if default { "[Y/n]" } else { "[y/N]" };
    let answer = ask(&format!("{question} {hint}"))?;
    Some(match answer.to_ascii_lowercase().as_str() {
        "" => default,
        "y" | "yes" => true,
        _ => false,
    })
}

/// Numbered lines until an empty one.
pub(super) fn list(title: &str) -> Vec<String> {
    if !person() {
        return Vec::new();
    }
    let style = Style::stderr();
    anstream::eprintln!(
        "{} {}",
        style.bold(title),
        style.dim("(one per line, empty line to finish)")
    );
    let mut items = Vec::new();
    while items.len() < 20 {
        match ask(&format!("  {}.", items.len() + 1)) {
            Some(line) if !line.is_empty() => items.push(line),
            _ => break,
        }
    }
    items
}
