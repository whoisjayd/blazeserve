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

/// Transfer progress on stderr. It draws only on a terminal and stays silent when piped,
/// so logs never fill with redraws.
pub struct Progress {
    bar: ProgressBar,
}

impl Progress {
    pub fn new(total: Option<u64>, base: u64) -> Self {
        let target = ProgressDrawTarget::stderr_with_hz(20);
        let bar = match total.filter(|t| *t > 0) {
            Some(total) => ProgressBar::with_draw_target(Some(total), target).with_style(
                ProgressStyle::with_template(
                    "  {bar:28.green/dim} {percent:>3}%  {binary_bytes:>9} / {binary_total_bytes}  {binary_bytes_per_sec:>11}  ETA {eta}",
                )
                .unwrap_or_else(|_| ProgressStyle::default_bar())
                .progress_chars("━╸─"),
            ),
            None => ProgressBar::with_draw_target(None, target).with_style(
                ProgressStyle::with_template("  {spinner} {binary_bytes}  {binary_bytes_per_sec}")
                    .unwrap_or_else(|_| ProgressStyle::default_spinner()),
            ),
        };
        bar.set_position(base);
        Self { bar }
    }

    pub fn update(&mut self, done: u64) {
        self.bar.set_position(done);
    }

    pub fn finish(&mut self, done: u64) {
        self.bar.set_position(done);
        self.bar.finish_and_clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn human_size_uses_binary_units() {
        assert_eq!(human_size(0), "0 B");
        assert_eq!(human_size(1024), "1.00 KiB");
        assert_eq!(human_size(1536), "1.50 KiB");
        assert_eq!(human_size(1024 * 1024 * 1024), "1.00 GiB");
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
