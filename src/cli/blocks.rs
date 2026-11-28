//! The block map of a parallel download: one cell for each part, or for a run of parts when
//! there are more than fit, showing which are done, arriving or still waiting.

use std::sync::Mutex;

use super::ansi::Style;

const WIDTH: usize = 56;
const MAX_ROWS: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Part {
    Waiting,
    Arriving,
    Done,
}

#[derive(Debug)]
pub struct BlockMap {
    parts: Mutex<Vec<Part>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cell {
    Waiting,
    Arriving,
    /// A run of parts of which some are done.
    Partly,
    Done,
}

fn combine(parts: &[Part]) -> Cell {
    if parts.iter().all(|p| *p == Part::Done) {
        Cell::Done
    } else if parts.contains(&Part::Arriving) {
        Cell::Arriving
    } else if parts.contains(&Part::Done) {
        Cell::Partly
    } else {
        Cell::Waiting
    }
}

/// Rows of at most `width` cells covering every part.
fn cells(parts: &[Part], width: usize) -> Vec<Vec<Cell>> {
    let capacity = width * MAX_ROWS;
    let per_cell = parts.len().div_ceil(capacity).max(1);
    let all: Vec<Cell> = parts.chunks(per_cell).map(combine).collect();
    all.chunks(width.max(1)).map(<[Cell]>::to_vec).collect()
}

fn paint(style: Style, cell: Cell) -> String {
    match cell {
        Cell::Done => style.green("\u{2588}"),
        Cell::Arriving => style.yellow("\u{2593}"),
        Cell::Partly => style.green("\u{2592}"),
        Cell::Waiting => style.dim("\u{2591}"),
    }
}

impl BlockMap {
    pub fn new(count: usize, done: impl Iterator<Item = usize>) -> Self {
        let mut parts = vec![Part::Waiting; count];
        for i in done {
            if let Some(part) = parts.get_mut(i) {
                *part = Part::Done;
            }
        }
        Self {
            parts: Mutex::new(parts),
        }
    }

    pub fn set(&self, index: usize, to: Part) {
        if let Ok(mut parts) = self.parts.lock()
            && let Some(part) = parts.get_mut(index)
        {
            *part = to;
        }
    }

    pub fn rows(&self) -> usize {
        self.parts.lock().map_or(0, |p| cells(&p, WIDTH).len())
    }

    /// One row of the map, painted.
    pub fn row(&self, row: usize, style: Style) -> String {
        let Ok(parts) = self.parts.lock() else {
            return String::new();
        };
        cells(&parts, WIDTH)
            .get(row)
            .map(|cells| cells.iter().map(|&c| paint(style, c)).collect())
            .unwrap_or_default()
    }

    /// What the marks mean and how far it has come.
    pub fn legend(&self, style: Style) -> String {
        let Ok(parts) = self.parts.lock() else {
            return String::new();
        };
        let count = |kind| parts.iter().filter(|&&p| p == kind).count();
        format!(
            "{} {} of {} parts   {} {} arriving   {} waiting",
            paint(style, Cell::Done),
            count(Part::Done),
            parts.len(),
            paint(style, Cell::Arriving),
            count(Part::Arriving),
            paint(style, Cell::Waiting),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_downloads_show_a_cell_per_part() {
        let map = BlockMap::new(5, [0, 1].into_iter());
        map.set(2, Part::Arriving);
        assert_eq!(map.rows(), 1);
        assert_eq!(map.row(0, Style::PLAIN), "██▓░░");
        assert!(map.legend(Style::PLAIN).contains("2 of 5 parts"));
    }

    #[test]
    fn large_downloads_are_grouped_into_at_most_four_rows() {
        let parts = WIDTH * MAX_ROWS * 3 + 1;
        let map = BlockMap::new(parts, 0..3);
        assert!(map.rows() <= MAX_ROWS);
        assert!(map.row(0, Style::PLAIN).chars().count() <= WIDTH);
        assert!(
            map.row(0, Style::PLAIN).starts_with('▒') || map.row(0, Style::PLAIN).starts_with('█')
        );
    }

    #[test]
    fn an_empty_map_is_empty() {
        let map = BlockMap::new(0, std::iter::empty());
        assert_eq!(map.rows(), 0);
        assert_eq!(map.row(0, Style::PLAIN), "");
    }
}
