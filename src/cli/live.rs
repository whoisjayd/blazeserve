//! One status line under the startup banner while a server runs, drawn only on a terminal.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};

use super::util::human_size;
use crate::AppState;
use crate::metrics::Stats;

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
                ProgressStyle::with_template("  {msg}")
                    .unwrap_or_else(|_| ProgressStyle::default_bar()),
            );
        if bar.is_hidden() {
            return None;
        }
        bar.set_message(line(&state.metrics.stats(), 0));
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let (bar, stop) = (bar.clone(), stop.clone());
            std::thread::spawn(move || {
                let mut last = (Instant::now(), state.metrics.stats().bytes_sent);
                while !stop.load(Ordering::Relaxed) {
                    std::thread::sleep(TICK);
                    let stats = state.metrics.stats();
                    let secs = last.0.elapsed().as_secs_f64().max(0.001);
                    let rate = (stats.bytes_sent.saturating_sub(last.1) as f64 / secs) as u64;
                    last = (Instant::now(), stats.bytes_sent);
                    bar.set_message(line(&stats, rate));
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

fn line(stats: &Stats, rate: u64) -> String {
    if stats.requests_total == 0 {
        return "● waiting for the first request".to_owned();
    }
    let mut parts = vec![
        format!("● {} active", stats.requests_active),
        format!("{} requests", stats.requests_total),
        format!("{} sent", human_size(stats.bytes_sent)),
    ];
    if rate > 0 {
        parts.push(format!("{}/s", human_size(rate)));
    }
    if stats.errors_total > 0 {
        parts.push(format!(
            "{} {}",
            stats.errors_total,
            if stats.errors_total == 1 {
                "error"
            } else {
                "errors"
            }
        ));
    }
    parts.join("  ·  ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stats(requests: u64, active: u64, sent: u64, errors: u64) -> Stats {
        Stats {
            uptime_seconds: 10,
            bytes_sent: sent,
            bytes_received: 0,
            requests_total: requests,
            requests_active: active,
            errors_total: errors,
            bytes_per_second: 0,
        }
    }

    #[test]
    fn idle_server_says_it_is_waiting() {
        assert_eq!(
            line(&stats(0, 0, 0, 0), 0),
            "● waiting for the first request"
        );
    }

    #[test]
    fn busy_server_shows_activity_volume_and_speed() {
        assert_eq!(
            line(&stats(14, 2, 3 * 1024 * 1024, 0), 1024 * 1024),
            "● 2 active  ·  14 requests  ·  3.00 MiB sent  ·  1.00 MiB/s"
        );
    }

    #[test]
    fn speed_is_omitted_when_idle_and_errors_only_when_present() {
        assert_eq!(
            line(&stats(5, 0, 2048, 1), 0),
            "● 0 active  ·  5 requests  ·  2.00 KiB sent  ·  1 error"
        );
    }
}
