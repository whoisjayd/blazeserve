use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::net::UdpSocket;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub fn human_size(n: u64) -> String {
    indicatif::HumanBytes(n).to_string()
}

pub fn sha256_file(path: &Path) -> std::io::Result<String> {
    sha256_file_within(path, || Ok(()))
}

/// Hashes a file, asking `proceed` before each block so a caller can stop it early.
pub fn sha256_file_within(
    path: &Path,
    mut proceed: impl FnMut() -> std::io::Result<()>,
) -> std::io::Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1024 * 1024];
    loop {
        proceed()?;
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex(&hasher.finalize()))
}

pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

pub fn env_truthy(name: &str) -> bool {
    std::env::var(name).is_ok_and(|v| {
        matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}

pub fn existing_path(s: &str) -> Result<PathBuf, String> {
    let p = PathBuf::from(s);
    if p.exists() {
        Ok(p)
    } else {
        Err(format!("'{s}' does not exist"))
    }
}

pub fn existing_file(s: &str) -> Result<PathBuf, String> {
    let p = existing_path(s)?;
    if p.is_file() {
        Ok(p)
    } else {
        Err(format!("'{s}' is not a file"))
    }
}

pub fn canonical(p: &Path) -> Result<PathBuf, String> {
    std::fs::canonicalize(p).map_err(|e| format!("cannot resolve {}: {e}", p.display()))
}

/// Windows canonical paths carry a `\\?\` prefix that is noise for people.
pub fn display_path(p: &Path) -> String {
    let s = p.display().to_string();
    if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
        return format!(r"\\{rest}");
    }
    s.strip_prefix(r"\\?\").map(str::to_owned).unwrap_or(s)
}

/// A path as people read it: relative to here, or from `~`. Piped output keeps the whole
/// path, which a script may need.
pub fn friendly_path(p: &Path) -> String {
    if !std::io::IsTerminal::is_terminal(&std::io::stdout()) {
        return display_path(p);
    }
    let plain = |p: &Path| std::path::PathBuf::from(display_path(p));
    shorten(
        &plain(p),
        std::env::current_dir().ok().map(|d| plain(&d)).as_deref(),
        std::env::home_dir().as_deref(),
    )
}

fn shorten(p: &Path, here: Option<&Path>, home: Option<&Path>) -> String {
    let under = |root: Option<&Path>| {
        root.and_then(|root| p.strip_prefix(root).ok())
            .filter(|rest| !rest.as_os_str().is_empty())
    };
    if let Some(rest) = under(here) {
        return rest.display().to_string();
    }
    match under(home) {
        Some(rest) => Path::new("~").join(rest).display().to_string(),
        None => p.display().to_string(),
    }
}

pub fn lan_ip() -> String {
    // Connecting a UDP socket sends nothing; it only selects the outbound interface.
    UdpSocket::bind("0.0.0.0:0")
        .and_then(|s| s.connect("8.8.8.8:80").map(|()| s))
        .and_then(|s| s.local_addr())
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|_| "127.0.0.1".to_owned())
}

pub fn open_browser(url: &str) {
    use std::process::{Command, Stdio};
    let mut cmd = if crate::platform::IS_WINDOWS {
        let mut c = Command::new("cmd");
        c.args(["/C", "start", "", url]);
        c
    } else if crate::platform::IS_MACOS {
        let mut c = Command::new("open");
        c.arg(url);
        c
    } else {
        let mut c = Command::new("xdg-open");
        c.arg(url);
        c
    };
    let _ = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
}

/// The line under a finished transfer: how long it took, how fast, and what was checked.
pub fn transfer_summary(bytes: u64, millis: u64, connections: u64, verified: bool) -> String {
    let seconds = millis as f64 / 1000.0;
    let mut parts = vec![if seconds < 60.0 {
        format!("{seconds:.1}s")
    } else {
        super::jobs::span(millis / 1000)
    }];
    if millis > 0 {
        let rate = (u128::from(bytes) * 1000 / u128::from(millis)).min(u128::from(u64::MAX));
        parts.push(format!("{}/s", human_size(rate as u64)));
    }
    if connections > 1 {
        parts.push(format!("{connections} connections"));
    }
    if verified {
        parts.push("SHA-256 verified".to_owned());
    }
    parts.join("  \u{b7}  ")
}

/// Prints [`transfer_summary`] for the run's recorded timings, at a terminal only.
pub fn print_summary(bytes: u64, verified: bool) {
    if super::ansi::quiet() || !std::io::IsTerminal::is_terminal(&std::io::stderr()) {
        return;
    }
    let recorded = crate::usage::trace::peek();
    let number = |key: &str| recorded.get(key).and_then(serde_json::Value::as_u64);
    let connections = match recorded
        .get("segmented")
        .and_then(serde_json::Value::as_bool)
    {
        Some(true) => number("connections").unwrap_or(1),
        _ => 1,
    };
    let line = transfer_summary(
        bytes,
        number("transfer_ms").unwrap_or(0),
        connections,
        verified,
    );
    anstream::eprintln!("  {}", super::ansi::Style::stderr().dim(&line));
}

pub fn backoff(fails: u32) -> Duration {
    Duration::from_millis(500u64.saturating_mul(1 << fails.saturating_sub(1).min(4)))
        .min(Duration::from_secs(8))
}

/// `↓ name` or `↑ name` for the dashboard title; a `.part` suffix is not shown.
pub fn transfer_title(arrow: &str, path: &std::path::Path) -> String {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    format!("{arrow} {}", name.strip_suffix(".part").unwrap_or(&name))
}

/// Transfer progress on stderr. It draws only on a terminal and stays silent when piped,
/// so logs never fill with redraws.
pub struct Progress {
    bar: ProgressBar,
    extra: std::sync::Arc<Extra>,
    /// When the last JSON progress line went out, in milliseconds since the start.
    reported: std::sync::atomic::AtomicU64,
    started: std::time::Instant,
}

fn progress_template(known_total: bool) -> &'static str {
    if known_total {
        "  {bar:40.green/dim} {percent:>3}%  {binary_bytes:>9} / {binary_total_bytes}  {binary_bytes_per_sec:>11}  ETA {eta}"
    } else {
        "  {spinner} {binary_bytes}  {binary_bytes_per_sec}  ·  {elapsed_precise} elapsed"
    }
}

/// What the live view shows beside the numbers the bar already keeps.
#[derive(Default)]
struct Extra {
    note: std::sync::Mutex<String>,
    map: std::sync::OnceLock<std::sync::Arc<super::blocks::BlockMap>>,
    /// When the speed was last sampled, and the samples.
    speeds: std::sync::Mutex<(Option<std::time::Instant>, std::collections::VecDeque<u64>)>,
}

impl Extra {
    /// The framed view of a transfer, drawn again at every refresh.
    fn view(&self, title: &str, state: &indicatif::ProgressState) -> String {
        use super::panel::{self, field};
        let style = super::ansi::Style::stderr();
        let speed = state.per_sec() as u64;
        let graph = self.speeds.lock().map_or_else(
            |_| String::new(),
            |mut s| {
                if s.0
                    .is_none_or(|at| at.elapsed() >= Duration::from_millis(500))
                {
                    s.0 = Some(std::time::Instant::now());
                    if s.1.len() == panel::HISTORY {
                        s.1.pop_front();
                    }
                    s.1.push_back(speed);
                }
                panel::graph(&s.1)
            },
        );
        let span = |d: Duration| super::jobs::span(d.as_secs());
        let mut rows = vec![String::new()];
        let left = match state.len() {
            Some(total) if total > 0 => {
                let done = state.pos().min(total);
                let filled = (u128::from(done) * 40 / u128::from(total)) as usize;
                rows.push(format!(
                    "{}{} {:>3}%",
                    style.green(&"█".repeat(filled)),
                    style.dim(&"░".repeat(40 - filled)),
                    u128::from(done) * 100 / u128::from(total)
                ));
                rows.push(format!("{} of {}", human_size(done), human_size(total)));
                span(state.eta())
            }
            _ => {
                rows.push(format!("{} so far", human_size(state.pos())));
                "unknown".to_owned()
            }
        };
        let note = self.note.lock().map(|n| n.clone()).unwrap_or_default();
        let speed = format!(
            "{:<16}{}",
            format!("{}/s", human_size(speed)),
            style.green(&graph)
        );
        rows.push(String::new());
        rows.push(field(style, "Speed", &speed));
        rows.push(field(style, "Time left", &left));
        rows.push(field(style, "Elapsed", &span(state.elapsed())));
        if !note.is_empty() {
            rows.push(field(style, "Using", &note));
        }
        if let Some(map) = self.map.get() {
            rows.push(String::new());
            rows.extend((0..map.rows()).map(|i| map.row(i, style)));
            rows.push(map.legend(style));
        }
        panel::frame(title, &rows, style)
    }
}

impl Drop for Progress {
    fn drop(&mut self) {
        super::ansi::set_active_bar(None);
    }
}

impl Progress {
    pub fn new(total: Option<u64>, base: u64) -> Self {
        Self::build(None, total, base)
    }

    /// A small dashboard: a title, the bar with sizes, then speed, ETA, elapsed time and an
    /// optional note such as the connection count.
    pub fn titled(title: &str, total: Option<u64>, base: u64) -> Self {
        Self::build(Some(title), total, base)
    }

    fn build(title: Option<&str>, total: Option<u64>, base: u64) -> Self {
        let target = if super::ansi::quiet() || super::ansi::json_progress() {
            ProgressDrawTarget::hidden()
        } else {
            ProgressDrawTarget::stderr_with_hz(20)
        };
        let reported = total;
        let total = total.filter(|t| *t > 0);
        let extra = std::sync::Arc::new(Extra::default());
        let template = match title {
            Some(_) => "{view}",
            None => progress_template(total.is_some()),
        };
        let mut style = ProgressStyle::with_template(template)
            .unwrap_or_else(|_| ProgressStyle::default_bar())
            .progress_chars("━╸─");
        if let Some(title) = title {
            let (title, extra) = (title.to_owned(), extra.clone());
            style = style.with_key(
                "view",
                move |state: &indicatif::ProgressState, out: &mut dyn std::fmt::Write| {
                    let _ = out.write_str(&extra.view(&title, state));
                },
            );
        }
        let bar = ProgressBar::with_draw_target(total, target).with_style(style);
        if title.is_some() {
            // Keeps the time and speed moving while nothing arrives.
            bar.enable_steady_tick(Duration::from_millis(250));
        }
        bar.set_position(base);
        super::ansi::set_active_bar(Some(bar.clone()));
        super::jobs::tracker::begin(reported, base);
        Self {
            bar,
            extra,
            reported: std::sync::atomic::AtomicU64::new(0),
            started: std::time::Instant::now(),
        }
    }

    /// The position moved to `pos` without those bytes being transferred now, such as an
    /// upload resuming at the offset the server already holds.
    pub fn rebase(&mut self, pos: u64) {
        self.bar.set_position(pos);
        super::jobs::tracker::rebase(pos);
    }

    fn publish(&self) {
        super::jobs::tracker::set_done(self.bar.position());
        if super::ansi::json_progress() {
            self.json_line(false);
        }
    }

    /// At most two lines a second, plus a last one when `always`.
    fn json_line(&self, always: bool) {
        use std::sync::atomic::Ordering::Relaxed;
        let now = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let last = self.reported.load(Relaxed);
        if !always && now.saturating_sub(last) < 500 {
            return;
        }
        // Parts report from several threads; one of them writes.
        if self
            .reported
            .compare_exchange(last, now, Relaxed, Relaxed)
            .is_ok()
        {
            eprintln!(
                "{}",
                serde_json::json!({
                    "event": "progress",
                    "bytes": self.bar.position(),
                    "total": self.bar.length(),
                    "elapsed_ms": now,
                })
            );
        }
    }

    /// Adds `map` to the view; it is read again at every redraw.
    pub fn show_map(&self, map: &std::sync::Arc<super::blocks::BlockMap>) {
        let _ = self.extra.map.set(map.clone());
    }

    /// Says what the transfer is using, such as the connection count.
    pub fn set_note(&self, note: &str) {
        if let Ok(mut current) = self.extra.note.lock() {
            note.clone_into(&mut current);
        }
    }

    pub fn update(&mut self, done: u64) {
        self.bar.set_position(done);
        self.publish();
    }

    /// Safe to call from several threads at once.
    pub fn inc(&self, delta: u64) {
        self.bar.inc(delta);
        self.publish();
    }

    pub fn dec(&self, delta: u64) {
        self.bar.dec(delta);
        self.publish();
    }

    pub fn finish(&mut self, done: u64) {
        super::ansi::set_active_bar(None);
        self.bar.set_position(done);
        super::jobs::tracker::set_done(self.bar.position());
        if super::ansi::json_progress() {
            self.json_line(true);
        }
        self.bar.finish_and_clear();
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn paths_are_shortened_from_here_then_from_home() {
        let home = Path::new("home").join("sam");
        let here = home.join("projects");
        let short = |p: &Path| shorten(p, Some(&here), Some(&home));
        assert_eq!(short(&here.join("site")), "site");
        assert_eq!(
            short(&home.join("other")),
            Path::new("~").join("other").display().to_string()
        );
        assert_eq!(short(Path::new("elsewhere")), "elsewhere");
    }

    use super::*;

    #[test]
    fn human_size_uses_binary_units() {
        assert_eq!(human_size(0), "0 B");
        assert_eq!(human_size(1024), "1.00 KiB");
        assert_eq!(human_size(1536), "1.50 KiB");
        assert_eq!(human_size(1024 * 1024 * 1024), "1.00 GiB");
    }

    #[test]
    fn every_progress_template_parses() {
        for known in [true, false] {
            assert!(ProgressStyle::with_template(progress_template(known)).is_ok());
        }
    }

    #[test]
    fn title_drops_the_part_suffix() {
        let p = std::path::Path::new("dir/big.iso.part");
        assert_eq!(transfer_title("↓", p), "↓ big.iso");
        assert_eq!(
            transfer_title("↑", std::path::Path::new("a.txt")),
            "↑ a.txt"
        );
    }

    #[test]
    fn the_summary_reads_like_a_sentence_of_facts() {
        assert_eq!(
            transfer_summary(200 * 1024 * 1024, 2000, 4, true),
            "2.0s  ·  100.00 MiB/s  ·  4 connections  ·  SHA-256 verified"
        );
        assert_eq!(transfer_summary(10, 0, 1, false), "0.0s");
        assert!(transfer_summary(0, 90_000, 1, false).starts_with("1m 30s"));
    }

    #[test]
    fn backoff_is_capped() {
        assert_eq!(backoff(1), Duration::from_millis(500));
        assert_eq!(backoff(2), Duration::from_secs(1));
        assert_eq!(backoff(40), Duration::from_secs(8));
    }

    #[test]
    fn verbatim_prefix_is_stripped() {
        assert_eq!(display_path(Path::new(r"\\?\C:\data")), r"C:\data");
        assert_eq!(
            display_path(Path::new(r"\\?\UNC\srv\share")),
            r"\\srv\share"
        );
    }
}
