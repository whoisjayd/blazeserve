//! A live panel under the startup banner while a server runs, drawn only on a terminal.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};

use super::ansi::Style;
use super::panel::{self, field};
use super::util::human_size;
use crate::AppState;
use crate::metrics::{Metrics, Stats};

const TICK: Duration = Duration::from_millis(500);

pub struct Live {
    bar: ProgressBar,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Live {
    /// `None` when stderr is not a terminal, so piped and logged runs stay clean.
    pub fn start(state: Arc<AppState>) -> Option<Self> {
        let bar = ProgressBar::with_draw_target(None, ProgressDrawTarget::stderr_with_hz(4))
            .with_style(
                ProgressStyle::with_template("{msg}")
                    .unwrap_or_else(|_| ProgressStyle::default_bar()),
            );
        if bar.is_hidden() {
            return None;
        }
        bar.set_message(view(&state.metrics, 0, ""));
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let (bar, stop) = (bar.clone(), stop.clone());
            std::thread::spawn(move || {
                let mut last = (Instant::now(), state.metrics.stats().bytes_sent);
                let mut rates = VecDeque::with_capacity(panel::HISTORY);
                while !stop.load(Ordering::Relaxed) {
                    std::thread::sleep(TICK);
                    let stats = state.metrics.stats();
                    let secs = last.0.elapsed().as_secs_f64().max(0.001);
                    let rate = (stats.bytes_sent.saturating_sub(last.1) as f64 / secs) as u64;
                    last = (Instant::now(), stats.bytes_sent);
                    if rates.len() == panel::HISTORY {
                        rates.pop_front();
                    }
                    rates.push_back(rate);
                    bar.set_message(view(&state.metrics, rate, &panel::graph(&rates)));
                }
            })
        };
        Some(Self {
            bar,
            stop,
            thread: Some(thread),
        })
    }

    pub fn finish(mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        self.bar.finish_and_clear();
    }
}

fn view(metrics: &Metrics, rate: u64, graph: &str) -> String {
    let style = Style::stderr();
    let stats = metrics.stats();
    let title = if stats.requests_total == 0 {
        "● Live: waiting for the first request"
    } else {
        "● Live"
    };
    let connections = (metrics.connections_active(), metrics.connections_rejected());
    panel::frame(title, &rows(&stats, connections, rate, graph, style), style)
}

fn rows(
    stats: &Stats,
    (open, refused): (u64, u64),
    rate: u64,
    graph: &str,
    style: Style,
) -> Vec<String> {
    let speed = format!(
        "{:<16}{}",
        format!("{}/s", human_size(rate)),
        style.green(graph)
    );
    let requests = format!(
        "{} total, {} active",
        stats.requests_total, stats.requests_active
    );
    let errors = stats.errors_total.to_string();
    let errors = if stats.errors_total > 0 {
        style.red(&errors)
    } else {
        errors
    };
    vec![
        field(style, "Speed", &speed),
        field(style, "Requests", &requests),
        field(
            style,
            "Connections",
            &format!("{open} open, {refused} refused"),
        ),
        field(style, "Sent", &human_size(stats.bytes_sent)),
        field(style, "Received", &human_size(stats.bytes_received)),
        field(style, "Errors", &errors),
        field(style, "Uptime", &super::jobs::span(stats.uptime_seconds)),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_panel_reports_activity_volume_speed_and_errors() {
        let stats = Stats {
            uptime_seconds: 65,
            bytes_sent: 3 * 1024 * 1024,
            bytes_received: 2048,
            requests_total: 14,
            requests_active: 2,
            errors_total: 1,
            bytes_per_second: 0,
        };
        let text = rows(&stats, (3, 1), 1024 * 1024, "", Style::PLAIN).join("\n");
        for needle in [
            "1.00 MiB/s",
            "14 total, 2 active",
            "3 open, 1 refused",
            "3.00 MiB",
            "2.00 KiB",
            "1m 05s",
        ] {
            assert!(text.contains(needle), "{needle}:\n{text}");
        }
    }
}
