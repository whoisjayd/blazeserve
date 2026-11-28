//! The frame shared by the live views of transfers and servers.

use std::collections::VecDeque;

use super::ansi::Style;

/// How many speed samples a graph keeps.
pub const HISTORY: usize = 32;

/// Recent speeds as a row of bars, scaled to the fastest of them.
pub fn graph(speeds: &VecDeque<u64>) -> String {
    const BARS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
    let top = speeds.iter().copied().max().unwrap_or(0);
    if top == 0 {
        return String::new();
    }
    speeds
        .iter()
        .map(|&s| BARS[(s.saturating_mul(7).div_ceil(top) as usize).min(7)])
        .collect()
}

/// A label in its column, then its value.
pub fn field(style: Style, label: &str, value: &str) -> String {
    format!("{}{value}", style.dim(&format!("{label:<13}")))
}

/// `rows` in a titled box as wide as the terminal allows, cut where they do not fit.
pub fn frame(title: &str, rows: &[String], style: Style) -> String {
    let columns = usize::from(console::Term::stderr().size().1);
    boxed(title, rows, columns.saturating_sub(1).clamp(40, 92), style)
}

fn boxed(title: &str, rows: &[String], width: usize, style: Style) -> String {
    let title = console::truncate_str(title, width - 6, "…");
    let rest = width - console::measure_text_width(&title) - 5;
    let mut out = format!(
        "{} {} {}",
        style.dim("╭─"),
        style.bold(&title),
        style.dim(&format!("{}╮", "─".repeat(rest)))
    );
    for row in rows {
        let row = console::truncate_str(row, width - 6, "…");
        let pad = " ".repeat(width - 6 - console::measure_text_width(&row));
        out.push_str(&format!(
            "\n{}  {row}{pad}  {}",
            style.dim("│"),
            style.dim("│")
        ));
    }
    out.push('\n');
    out.push_str(&style.dim(&format!("╰{}╯", "─".repeat(width - 2))));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_line_of_a_frame_is_as_wide_whatever_it_holds() {
        let rows = [String::new(), "x".repeat(200), "short".to_owned()];
        let long = "t".repeat(200);
        for style in [Style::PLAIN, Style::COLOR] {
            let text = boxed(&long, &rows, 50, style);
            let widths: Vec<usize> = text.lines().map(console::measure_text_width).collect();
            assert_eq!(widths, [50; 5], "{text}");
        }
    }

    #[test]
    fn the_graph_scales_to_the_fastest_and_is_empty_when_idle() {
        assert_eq!(graph(&[0, 50, 100].into()), "▁▅█");
        assert_eq!(graph(&[0, 0].into()), "");
    }
}
