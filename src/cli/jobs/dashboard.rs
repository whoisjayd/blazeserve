//! A live full-screen view of background jobs: a table, the selected job's details and its
//! log. Leaving it never stops a job.

use std::io::{Read, Seek, SeekFrom};
use std::time::{Duration, Instant};

use ratatui::Frame;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Cell, Padding, Paragraph, Row, Table, TableState};

use super::record::{Record, State, escape_control};
use super::status::{snapshot, span};
use super::store::{Store, now};
use crate::cli::util::human_size;

const REFRESH: Duration = Duration::from_millis(500);
const LOG_TAIL: u64 = 16 * 1024;
const BAR: usize = 16;

struct View {
    jobs: Vec<Record>,
    selected: usize,
    /// What waits for a yes.
    confirming: Option<Ask>,
    message: String,
    /// One job on its own, as `blaze attach` shows it.
    focus: bool,
}

impl View {
    fn current(&self) -> Option<&Record> {
        self.jobs.get(self.selected)
    }

    /// Keeps the same job selected when the list changes.
    fn replace(&mut self, mut jobs: Vec<Record>) {
        jobs.sort_by_key(|j| (!j.state.is_active(), std::cmp::Reverse(j.started_at)));
        let id = self.current().map(|j| j.id.clone());
        self.jobs = jobs;
        self.selected = id
            .and_then(|id| self.jobs.iter().position(|j| j.id == id))
            .unwrap_or(self.selected)
            .min(self.jobs.len().saturating_sub(1));
    }
}

fn colour(state: State) -> Color {
    if state.is_active() {
        Color::Green
    } else if state == State::Failed {
        Color::Red
    } else {
        Color::Gray
    }
}

fn bar(percent: f64) -> String {
    let filled = ((percent / 100.0) * BAR as f64)
        .round()
        .clamp(0.0, BAR as f64) as usize;
    format!(
        "{}{} {percent:>3.0}%",
        "█".repeat(filled),
        "░".repeat(BAR - filled)
    )
}

fn progress(r: &Record) -> String {
    if r.kind.is_server() {
        return r.listen.clone().unwrap_or_default();
    }
    match r.percent() {
        Some(p) => bar(p),
        None => human_size(r.bytes_done),
    }
}

fn name(r: &Record) -> String {
    if let Some(name) = &r.name {
        return format!("{name}  ({})", escape_control(&r.label));
    }
    if r.label.is_empty() {
        "(starting)".to_owned()
    } else {
        escape_control(&r.label)
    }
}

/// The table has room for one: the name given, else the file.
fn short_name(r: &Record) -> String {
    r.name.clone().unwrap_or_else(|| name(r))
}

fn tail(path: &str, lines: usize) -> Vec<String> {
    let read = || -> std::io::Result<String> {
        let mut file = std::fs::File::open(path)?;
        let len = file.metadata()?.len();
        file.seek(SeekFrom::Start(len.saturating_sub(LOG_TAIL)))?;
        let mut raw = Vec::new();
        file.take(LOG_TAIL).read_to_end(&mut raw)?;
        Ok(String::from_utf8_lossy(&raw).into_owned())
    };
    let text = read().unwrap_or_default();
    let all: Vec<&str> = text
        // A progress redraw ends with a carriage return; only its last state matters.
        .lines()
        .map(|l| l.rsplit('\r').next().unwrap_or(l))
        .filter(|l| !l.trim().is_empty())
        .collect();
    all[all.len().saturating_sub(lines)..]
        .iter()
        .map(|l| escape_control(l))
        .collect()
}

fn pane(title: String) -> Block<'static> {
    Block::bordered()
        .title(title)
        .padding(Padding::horizontal(1))
}

fn details(r: &Record, at: u64) -> Vec<Line<'static>> {
    let mut rows: Vec<(&str, String)> = vec![
        ("Job", format!("{}  {}  pid {}", r.id, r.kind.name(), r.pid)),
        (
            "State",
            match r.phase {
                Some(phase) if r.state.is_active() => {
                    format!("{} ({})", r.state.name(), phase.name())
                }
                _ => r.state.name().to_owned(),
            },
        ),
        ("Name", name(r)),
    ];
    if let Some(remote) = &r.remote {
        rows.push(("Remote", escape_control(remote)));
    }
    if let Some(listen) = &r.listen {
        rows.push(("Listening", listen.clone()));
    }
    if !r.kind.is_server() {
        let size = r
            .bytes_total
            .map_or_else(|| "unknown size".to_owned(), human_size);
        rows.push(("Done", format!("{} of {size}", human_size(r.bytes_done))));
        if let Some(percent) = r.percent() {
            let mut line = bar(percent);
            if r.state.is_active() {
                if let Some(speed) = r.speed_bps {
                    line.push_str(&format!("  {}/s", human_size(speed)));
                }
                if let Some(eta) = r.eta_secs() {
                    line.push_str(&format!("  ETA {}", span(eta)));
                }
            }
            rows.push(("Progress", line));
        }
    }
    rows.push((
        "Started",
        format!("{} ago", span(at.saturating_sub(r.started_at))),
    ));
    if let Some(result) = &r.result {
        rows.push(("Result", escape_control(result)));
    }
    rows.into_iter()
        .map(|(label, value)| {
            Line::from(vec![
                Span::styled(
                    format!("{label:<10}"),
                    Style::new().add_modifier(Modifier::DIM),
                ),
                Span::raw(value),
            ])
        })
        .collect()
}

fn draw(frame: &mut Frame, view: &View, at: u64) {
    let info = view.current().map_or_else(
        || {
            vec![Line::from(
                "No background jobs. Start one with --background.",
            )]
        },
        |r| details(r, at),
    );
    let table_height = if view.focus {
        0
    } else {
        u16::try_from(view.jobs.len())
            .unwrap_or(u16::MAX)
            .clamp(1, 10)
            + 3
    };
    let info_height = u16::try_from(info.len()).unwrap_or(10) + 2;
    let [top, middle, log, help] = Layout::vertical([
        Constraint::Length(table_height),
        Constraint::Length(info_height),
        Constraint::Min(3),
        Constraint::Length(1),
    ])
    .areas(frame.area());

    let active = view.jobs.iter().filter(|j| j.state.is_active()).count();
    let rows = view.jobs.iter().map(|r| {
        let speed = r
            .speed_bps
            .filter(|_| r.state.is_active())
            .map_or_else(String::new, |s| format!("{}/s", human_size(s)));
        let eta = r
            .eta_secs()
            .filter(|_| r.state.is_active())
            .map_or_else(String::new, span);
        Row::new(vec![
            Cell::from(r.id.clone()),
            Cell::from(r.kind.name()),
            Cell::from(r.state.name()).style(Style::new().fg(colour(r.state))),
            Cell::from(progress(r)),
            Cell::from(speed),
            Cell::from(eta),
            Cell::from(short_name(r)),
        ])
    });
    let table = Table::new(
        rows,
        [
            Constraint::Length(8),
            Constraint::Length(6),
            Constraint::Length(11),
            Constraint::Length(u16::try_from(BAR).unwrap_or(16) + 6),
            Constraint::Length(12),
            Constraint::Length(8),
            Constraint::Min(8),
        ],
    )
    .header(Row::new(["ID", "KIND", "STATE", "PROGRESS", "SPEED", "ETA", "NAME"]).bold())
    .block(Block::bordered().title(format!(
        " BlazeServe jobs · {active} running · {} finished ",
        view.jobs.len() - active
    )))
    .row_highlight_style(Style::new().add_modifier(Modifier::REVERSED))
    .highlight_symbol("❯ ");
    let mut state =
        TableState::default().with_selected((!view.jobs.is_empty()).then_some(view.selected));
    if !view.focus {
        frame.render_stateful_widget(table, top, &mut state);
    }

    let detail_title = match view.current() {
        Some(job) if view.focus => format!(" Job {} · q leaves it running ", job.id),
        _ => " Details ".to_owned(),
    };
    frame.render_widget(Paragraph::new(info).block(pane(detail_title)), middle);
    let lines = view.current().map_or_else(Vec::new, |r| {
        tail(&r.log, usize::from(log.height.saturating_sub(2)))
    });
    frame.render_widget(
        Paragraph::new(lines.into_iter().map(Line::from).collect::<Vec<_>>())
            .block(pane(" Log ".to_owned())),
        log,
    );

    let footer = match &view.confirming {
        Some(ask) => Line::from(match ask {
            Ask::Stop(id) => {
                format!("Stop job {id}? Its progress is kept. y to stop, any other key to keep it")
            }
            Ask::Delete(id) => format!(
                "Delete job {id} and its log? Files stay. y to delete, any other key to keep it"
            ),
        })
        .yellow()
        .bold(),
        None if !view.message.is_empty() => Line::from(view.message.clone()).green(),
        None if view.focus => {
            Line::from("s stop   d delete   q leave (a running job keeps running)").dim()
        }
        None => Line::from("↑/↓ select   s stop   d delete   q leave (jobs keep running)").dim(),
    };
    frame.render_widget(Paragraph::new(footer), help);
}

/// Something that happens to a job only after a yes.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Ask {
    Stop(String),
    /// Takes a finished job and its log off the list; downloaded files stay.
    Delete(String),
}

/// What a key asks for.
enum Next {
    Stay,
    Leave,
    Do(Ask),
}

fn on_key(view: &mut View, code: KeyCode, control: bool) -> Next {
    if control && code == KeyCode::Char('c') {
        return Next::Leave;
    }
    if let Some(ask) = view.confirming.take() {
        return if code == KeyCode::Char('y') {
            Next::Do(ask)
        } else {
            Next::Stay
        };
    }
    view.message.clear();
    match code {
        KeyCode::Char('q') | KeyCode::Esc => return Next::Leave,
        KeyCode::Up | KeyCode::Char('k') if !view.focus => {
            view.selected = view.selected.saturating_sub(1)
        }
        KeyCode::Down | KeyCode::Char('j') if !view.focus => {
            view.selected = (view.selected + 1).min(view.jobs.len().saturating_sub(1));
        }
        KeyCode::Char('s') => {
            view.confirming = view
                .current()
                .filter(|j| j.state.is_active())
                .map(|j| Ask::Stop(j.id.clone()));
        }
        KeyCode::Char('d') => match view.current() {
            Some(job) if job.state.is_active() => {
                view.message = "That job is still running: stop it with s first.".to_owned();
            }
            job => view.confirming = job.map(|j| Ask::Delete(j.id.clone())),
        },
        _ => {}
    }
    Next::Stay
}

/// Shows the dashboard until the user leaves, starting on `job` when given.
pub(super) fn run(store: &Store, job: Option<&str>) -> Result<(), String> {
    let load = || snapshot(store, now(), None, true).map(|s| s.records);
    let mut view = View {
        jobs: Vec::new(),
        selected: 0,
        confirming: None,
        message: String::new(),
        focus: job.is_some(),
    };
    view.replace(load()?);
    if let Some(id) = job {
        view.selected = view
            .jobs
            .iter()
            .position(|j| j.id == id)
            .ok_or_else(|| format!("no job {id}; `blaze status --all` lists them"))?;
    }
    let mut terminal = ratatui::try_init().map_err(|e| format!("cannot draw here: {e}"))?;
    let outcome = (|| -> Result<(), String> {
        let mut loaded = Instant::now();
        loop {
            terminal
                .draw(|frame| draw(frame, &view, now()))
                .map_err(|e| e.to_string())?;
            if event::poll(REFRESH).map_err(|e| e.to_string())?
                && let Event::Key(key) = event::read().map_err(|e| e.to_string())?
                && key.kind == KeyEventKind::Press
            {
                match on_key(
                    &mut view,
                    key.code,
                    key.modifiers.contains(KeyModifiers::CONTROL),
                ) {
                    Next::Leave => return Ok(()),
                    Next::Do(Ask::Stop(id)) => {
                        store
                            .request_stop(&id)
                            .map_err(|e| format!("cannot send the stop request: {e}"))?;
                        view.message = format!("Asked job {id} to stop.");
                    }
                    Next::Do(Ask::Delete(id)) => {
                        store.remove(&id);
                        view.message = format!("Deleted job {id}.");
                        view.replace(load()?);
                    }
                    Next::Stay => {}
                }
            }
            if loaded.elapsed() >= REFRESH {
                view.replace(load()?);
                loaded = Instant::now();
            }
        }
    })();
    ratatui::restore();
    outcome
}

#[cfg(test)]
mod tests {
    use super::super::record::Kind;
    use super::*;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn job(id: &str, state: State, done: u64) -> Record {
        let mut r = Record::new(id, Kind::Get, 1, 100, "no-such.log");
        r.state = state;
        r.label = "archive.tar".into();
        r.bytes_done = done;
        r.bytes_total = Some(100);
        r
    }

    fn view(jobs: Vec<Record>) -> View {
        let mut view = View {
            jobs: Vec::new(),
            selected: 0,
            confirming: None,
            message: String::new(),
            focus: false,
        };
        view.replace(jobs);
        view
    }

    fn screen(view: &View) -> String {
        let mut terminal = Terminal::new(TestBackend::new(100, 24)).unwrap();
        terminal.draw(|f| draw(f, view, 160)).unwrap();
        let buffer = terminal.backend().buffer();
        buffer
            .content
            .chunks(100)
            .map(|row| row.iter().map(|c| c.symbol()).collect::<String>())
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn shows_jobs_progress_details_and_keys() {
        let v = view(vec![
            job("0000000b", State::Completed, 100),
            job("0000000a", State::Running, 68),
        ]);
        assert_eq!(v.current().unwrap().id, "0000000a", "running first");
        let text = screen(&v);
        println!("{text}");
        for needle in [
            "1 running",
            "1 finished",
            "68%",
            "archive.tar",
            "Details",
            "Log",
            "q leave",
        ] {
            assert!(text.contains(needle), "{needle}:\n{text}");
        }
    }

    #[test]
    fn one_attached_job_has_no_table() {
        let mut v = view(vec![job("0000000a", State::Running, 68)]);
        v.focus = true;
        let text = screen(&v);
        assert!(!text.contains("BlazeServe jobs"), "{text}");
        assert!(
            text.contains("Job 0000000a") && text.contains("68%"),
            "{text}"
        );
    }

    #[test]
    fn stopping_asks_first_and_only_y_confirms() {
        let mut v = view(vec![job("0000000a", State::Running, 1)]);
        assert!(matches!(
            on_key(&mut v, KeyCode::Char('s'), false),
            Next::Stay
        ));
        assert!(screen(&v).contains("Stop job 0000000a?"));
        assert!(matches!(
            on_key(&mut v, KeyCode::Char('n'), false),
            Next::Stay
        ));
        assert!(v.confirming.is_none());
        on_key(&mut v, KeyCode::Char('s'), false);
        assert!(
            matches!(on_key(&mut v, KeyCode::Char('y'), false), Next::Do(Ask::Stop(id)) if id == "0000000a")
        );
        assert!(matches!(
            on_key(&mut v, KeyCode::Char('q'), false),
            Next::Leave
        ));
    }

    #[test]
    fn only_a_finished_job_can_be_deleted_and_only_after_a_yes() {
        let mut v = view(vec![job("0000000a", State::Running, 1)]);
        on_key(&mut v, KeyCode::Char('d'), false);
        assert!(v.confirming.is_none() && v.message.contains("stop it"));

        let mut v = view(vec![job("0000000b", State::Completed, 100)]);
        on_key(&mut v, KeyCode::Char('d'), false);
        assert!(screen(&v).contains("Delete job 0000000b"));
        assert!(matches!(
            on_key(&mut v, KeyCode::Char('y'), false),
            Next::Do(Ask::Delete(id)) if id == "0000000b"
        ));
    }

    #[test]
    fn an_empty_list_explains_how_to_start_one() {
        assert!(screen(&view(Vec::new())).contains("--background"));
    }
}
