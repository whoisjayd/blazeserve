use sha2::{Digest, Sha256};
use std::io::{IsTerminal, Read, Write};
use std::net::UdpSocket;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub fn human_size(n: u64) -> String {
    const UNITS: [&str; 7] = ["B", "KB", "MB", "GB", "TB", "PB", "EB"];
    let mut x = n as f64;
    for u in UNITS {
        if x < 1024.0 {
            return format!("{x:.2}{u}");
        }
        x /= 1024.0;
    }
    format!("{x:.2}ZB")
}

pub fn sha256_file(path: &Path) -> std::io::Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1024 * 1024];
    loop {
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
    let mut cmd = if cfg!(windows) {
        let mut c = Command::new("cmd");
        c.args(["/C", "start", "", url]);
        c
    } else if cfg!(target_os = "macos") {
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

pub fn backoff(fails: u32) -> Duration {
    Duration::from_millis(500u64.saturating_mul(1 << fails.saturating_sub(1).min(4)))
        .min(Duration::from_secs(8))
}

/// Single-line transfer progress on stderr, active only on a terminal.
pub struct Progress {
    enabled: bool,
    total: Option<u64>,
    start: Instant,
    last_draw: Instant,
    base: u64,
}

impl Progress {
    pub fn new(total: Option<u64>, base: u64) -> Self {
        let now = Instant::now();
        Self {
            enabled: std::io::stderr().is_terminal(),
            total,
            start: now,
            last_draw: now.checked_sub(Duration::from_secs(1)).unwrap_or(now),
            base,
        }
    }

    pub fn update(&mut self, done: u64) {
        if !self.enabled || self.last_draw.elapsed() < Duration::from_millis(100) {
            return;
        }
        self.last_draw = Instant::now();
        self.draw(done);
    }

    pub fn finish(&mut self, done: u64) {
        if self.enabled {
            self.draw(done);
            eprintln!();
        }
    }

    fn draw(&self, done: u64) {
        let secs = self.start.elapsed().as_secs_f64().max(0.001);
        let rate = (done.saturating_sub(self.base) as f64 / secs) as u64;
        let total = self
            .total
            .map(|t| format!(" / {}", human_size(t)))
            .unwrap_or_default();
        let mut err = std::io::stderr().lock();
        let _ = write!(
            err,
            "\r  {}{total}  {}/s    ",
            human_size(done),
            human_size(rate)
        );
        let _ = err.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn human_size_matches_reference() {
        assert_eq!(human_size(100), "100.00B");
        assert_eq!(human_size(1024), "1.00KB");
        assert_eq!(human_size(1536), "1.50KB");
        assert_eq!(human_size(1024 * 1024), "1.00MB");
        assert_eq!(human_size(1024 * 1024 * 1024), "1.00GB");
        assert_eq!(human_size(0), "0.00B");
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
