//! A list to choose from with the arrow keys, drawn on standard error.

use std::io::IsTerminal;

use console::{Key, Term};

use super::ansi::Style;

/// The chosen index, or `None` when the user backs out or nobody is at a terminal.
pub(super) fn pick(title: &str, items: &[String], preselected: usize) -> Option<usize> {
    if items.is_empty() || !(std::io::stdin().is_terminal() && std::io::stderr().is_terminal()) {
        return None;
    }
    let term = Term::stderr();
    let style = Style::stderr();
    let mut at = preselected.min(items.len() - 1);
    let _ = term.hide_cursor();
    anstream::eprintln!(
        "{} {}",
        style.bold(title),
        style.dim("(\u{2191}/\u{2193} to move, Enter to choose, Esc to skip)")
    );
    let width = usize::from(term.size().1).saturating_sub(4).max(20);
    let chosen = loop {
        for (i, item) in items.iter().enumerate() {
            // One line each, so the redraw knows how far to go back.
            let item: String = item.chars().take(width).collect();
            if i == at {
                anstream::eprintln!("  {} {}", style.green("\u{276f}"), style.bold(&item));
            } else {
                anstream::eprintln!("    {}", style.dim(&item));
            }
        }
        let key = term.read_key();
        let _ = term.clear_last_lines(items.len());
        match key {
            Ok(Key::ArrowUp | Key::Char('k')) => at = at.checked_sub(1).unwrap_or(items.len() - 1),
            Ok(Key::ArrowDown | Key::Char('j') | Key::Tab) => at = (at + 1) % items.len(),
            Ok(Key::Enter) => break Some(at),
            Ok(Key::Escape | Key::Char('q')) | Err(_) => break None,
            Ok(Key::CtrlC) => {
                let _ = term.show_cursor();
                std::process::exit(130);
            }
            Ok(_) => {}
        }
    };
    let _ = term.show_cursor();
    match chosen {
        Some(i) => anstream::eprintln!("  {} {}", style.green("\u{2713}"), items[i]),
        None => anstream::eprintln!("  {}", style.dim("skipped")),
    }
    chosen
}
