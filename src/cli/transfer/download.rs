//! Resumable `blaze get`: sidecar metadata, range handling and verified finish.

use super::READ_BUF;
use super::discover::{self, ServerDigest};
use super::filename::suggested_name;
use super::http::{
    agent, basic_header, cannot_write, describe_error, describe_io, header, http_failure, http_url,
    retry_hint, transient_error, transient_status, write_failure,
};
use super::limits::{self, TimeoutArgs};
use super::retry::{jitter, plan_wait, retry_note};
use super::segmented::{self, SegMeta};
use super::throttle::{Throttle, parse_rate};
use crate::cli::ansi::{Style, announce};
use crate::cli::util::{Progress, human_size, sha256_file_within, transfer_title};
use clap::Args;
use percent_encoding::percent_decode_str;
use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

pub(super) const MAX_RESTARTS: u32 = 3;
/// Accepts a byte count with an optional `K`, `M` or `G` suffix (powers of 1024). Zero is allowed.
fn parse_free_space(raw: &str) -> Result<u64, String> {
    let text = raw.trim();
    let (digits, unit) = match text.char_indices().last() {
        Some((i, 'k' | 'K')) => (&text[..i], 1u64 << 10),
        Some((i, 'm' | 'M')) => (&text[..i], 1 << 20),
        Some((i, 'g' | 'G')) => (&text[..i], 1 << 30),
        _ => (text, 1),
    };
    let value: f64 = digits.parse().map_err(|_| {
        format!("invalid size '{raw}'; use bytes with an optional K, M or G, such as 500M or 2G")
    })?;
    if !value.is_finite() || value < 0.0 {
        return Err(format!("invalid size '{raw}'"));
    }
    Ok((value * unit as f64) as u64)
}

/// Each connection is a thread and a socket, and many servers refuse more than a handful.
const MAX_CONNECTIONS: u16 = 128;
/// Above this, say that the server may object.
const POLITE_CONNECTIONS: u16 = 16;

fn parse_connections(text: &str) -> Result<u16, String> {
    if text.eq_ignore_ascii_case("max") {
        return Ok(MAX_CONNECTIONS);
    }
    match text.parse::<u16>() {
        Ok(n) if (1..=MAX_CONNECTIONS).contains(&n) => Ok(n),
        _ => Err(format!(
            "`{text}` is not a number from 1 to {MAX_CONNECTIONS}, or `max`"
        )),
    }
}

#[derive(clap::ValueEnum, Clone, Copy, Debug)]
pub enum VerifyMode {
    /// Ask the server for the file's SHA-256 with `?hash` before downloading
    ServerSha256,
}

#[derive(Args, Debug)]
pub struct GetArgs {
    /// URL to download
    pub url: String,
    /// Destination file (default: the name the server suggests, else the last URL path segment)
    #[arg(short, long)]
    pub output: Option<PathBuf>,
    /// Continue a previous partial download (default)
    #[arg(long, overrides_with = "no_resume")]
    pub resume: bool,
    /// Always start from the beginning
    #[arg(long, overrides_with = "resume")]
    pub no_resume: bool,
    /// Expected SHA-256 of the finished file
    #[arg(long, value_name = "HEX")]
    pub sha256: Option<String>,
    /// Take the expected SHA-256 from the server and fail if it cannot be verified
    #[arg(long, value_enum, value_name = "MODE", conflicts_with = "sha256")]
    pub verify: Option<VerifyMode>,
    /// Load USER:PASS from an environment variable
    #[arg(long, value_name = "ENVVAR")]
    pub auth_env: Option<String>,
    /// HTTP Basic Auth credentials
    #[arg(long, value_name = "USER:PASS")]
    pub auth: Option<String>,
    /// Consecutive failed attempts allowed before giving up
    #[arg(long, default_value_t = 5, value_parser = clap::value_parser!(u32).range(0..=100))]
    pub retries: u32,
    /// Replace an existing destination file
    #[arg(long)]
    pub force: bool,
    /// Parallel connections for large files: 1 to 128 or `max` (1 downloads in a single stream)
    #[arg(short = 'c', long, value_name = "N", default_value_t = 4, value_parser = parse_connections)]
    pub connections: u16,
    /// Cap total download speed in bytes per second, e.g. 500K, 2M or 1.5M (minimum 1K)
    #[arg(long, value_name = "RATE", value_parser = parse_rate)]
    pub limit_rate: Option<u64>,
    /// After the download, extract the archive in place, so about the extracted size is enough free space
    ///
    /// Works on zip, 7z and tar archives. The archive is consumed as its files come out;
    /// the files go to a folder named after it. An interrupted extraction resumes when you
    /// run the same command again.
    #[arg(long)]
    pub extract: bool,
    /// With --extract, keep the archive instead of consuming it
    #[arg(long, requires = "extract")]
    pub keep_archive: bool,
    /// With --extract, skip the check of the whole archive that runs before it is consumed
    #[arg(long, requires = "extract")]
    pub no_verify_first: bool,
    /// With --extract, free space to leave untouched, e.g. 500M or 2G [default: 1G]
    #[arg(long, value_name = "SIZE", requires = "extract", value_parser = parse_free_space)]
    pub keep_free: Option<u64>,
    #[command(flatten)]
    pub timeouts: TimeoutArgs,
}

#[derive(Serialize, Deserialize, Default)]
pub(super) struct Meta {
    pub(super) url: String,
    pub(super) etag: Option<String>,
    pub(super) last_modified: Option<String>,
    pub(super) total: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) seg: Option<SegMeta>,
}

pub(super) fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut s: OsString = path.as_os_str().to_owned();
    s.push(suffix);
    PathBuf::from(s)
}

/// Security software and indexers briefly hold new files open on Windows, which makes
/// an immediate rename fail with a sharing violation.
pub(super) fn rename_with_retry(from: &Path, to: &Path) -> std::io::Result<()> {
    let mut last = None;
    for attempt in 0..8u64 {
        match std::fs::rename(from, to) {
            Ok(()) => return Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                last = Some(e);
                std::thread::sleep(Duration::from_millis(50 * (attempt + 1)));
            }
            Err(e) => return Err(e),
        }
    }
    Err(last.unwrap_or_else(|| std::io::Error::other("rename failed")))
}

/// The name the server suggests, asked with a `HEAD` before any resume state is looked
/// up so a re-run lands on the same files. Any failure falls back to the URL's name.
fn server_file_name(agent: &ureq::Agent, url: &str, auth: Option<&str>) -> Option<String> {
    let mut req = agent.head(url);
    if let Some(a) = auth {
        req = req.header("Authorization", a);
    }
    let resp = limits::bound(req).call().ok()?;
    if !resp.status().is_success() {
        return None;
    }
    suggested_name(&header(&resp, "content-disposition")?)
}

fn default_destination(url: &str) -> Result<PathBuf, String> {
    let without_scheme = url.split_once("://").map_or(url, |(_, rest)| rest);
    let path = without_scheme.split(['?', '#']).next().unwrap_or("");
    let last = path
        .split_once('/')
        .map_or("", |(_, p)| p)
        .rsplit('/')
        .next()
        .unwrap_or("");
    let decoded = percent_decode_str(last).decode_utf8_lossy().into_owned();
    let name = if decoded.is_empty() {
        "index.html".to_owned()
    } else {
        decoded
    };
    if name == "." || name == ".." || name.contains(['/', '\\']) || name.contains(':') {
        return Err("Cannot derive a safe file name from the URL; pass --output".to_owned());
    }
    Ok(PathBuf::from(name))
}

pub(super) fn parse_content_range(v: &str) -> Option<(u64, u64, Option<u64>)> {
    let rest = v.trim().strip_prefix("bytes ")?;
    let (range, total) = rest.split_once('/')?;
    let total = if total == "*" {
        None
    } else {
        Some(total.parse().ok()?)
    };
    let (s, e) = range.split_once('-')?;
    Some((s.parse().ok()?, e.parse().ok()?, total))
}

fn parse_unsatisfied_total(v: &str) -> Option<u64> {
    v.trim().strip_prefix("bytes */")?.parse().ok()
}

enum Step {
    Complete,
    Restart,
    Transient {
        msg: String,
        progressed: bool,
        retry_after: Option<Duration>,
    },
}

pub(super) struct Download<'a> {
    pub(super) agent: ureq::Agent,
    pub(super) url: &'a str,
    pub(super) part: PathBuf,
    pub(super) meta_path: PathBuf,
    pub(super) auth: Option<String>,
    pub(super) resume: bool,
    pub(super) throttle: Option<Arc<Throttle>>,
}

impl Download<'_> {
    /// Read size for the next read, shrunk under a low rate cap.
    pub(super) fn read_len(&self) -> usize {
        self.throttle
            .as_ref()
            .map_or(READ_BUF, |t| t.chunk(READ_BUF))
    }

    pub(super) fn pace(&self, bytes: usize) -> Result<(), String> {
        if let Some(t) = &self.throttle {
            t.throttle(bytes).map_err(|e| e.to_string())?;
        }
        limits::check()
    }

    pub(super) fn reset(&self) {
        let _ = std::fs::remove_file(&self.part);
        let _ = std::fs::remove_file(&self.meta_path);
    }

    pub(super) fn part_len(&self) -> u64 {
        std::fs::metadata(&self.part).map_or(0, |m| m.len())
    }

    pub(super) fn load_meta(&self) -> Option<Meta> {
        let raw = std::fs::read(&self.meta_path).ok()?;
        serde_json::from_slice(&raw).ok()
    }

    fn save_meta(&self, meta: &Meta) {
        if let Ok(raw) = serde_json::to_vec(meta) {
            let _ = std::fs::write(&self.meta_path, raw);
        }
    }

    fn step(&self) -> Result<Step, String> {
        let known = self
            .load_meta()
            .filter(|m| m.url == self.url && m.seg.is_none());
        let mut offset = if self.resume && known.is_some() {
            self.part_len()
        } else {
            0
        };
        if offset == 0 || known.is_none() {
            self.reset();
            offset = 0;
        }

        let mut req = self.agent.get(self.url);
        if let Some(a) = &self.auth {
            req = req.header("Authorization", a);
        }
        if offset > 0 {
            req = req.header("Range", format!("bytes={offset}-"));
            let validator = known
                .as_ref()
                .and_then(|m| m.etag.clone().or_else(|| m.last_modified.clone()));
            if let Some(v) = validator {
                req = req.header("If-Range", v);
            }
        }

        let resp = match limits::bound(req).call() {
            Ok(r) => r,
            Err(e) if transient_error(&e) => {
                return Ok(Step::Transient {
                    msg: describe_error(&e),
                    progressed: false,
                    retry_after: None,
                });
            }
            Err(e) => return Err(describe_error(&e)),
        };
        let status = resp.status().as_u16();

        match status {
            200 | 206 => {}
            416 => {
                let total =
                    header(&resp, "content-range").and_then(|v| parse_unsatisfied_total(&v));
                return Ok(if total == Some(offset) && offset > 0 {
                    Step::Complete
                } else {
                    self.reset();
                    Step::Restart
                });
            }
            code if transient_status(code) => {
                return Ok(Step::Transient {
                    msg: format!("server returned HTTP {code}"),
                    progressed: false,
                    retry_after: retry_hint(&resp, code),
                });
            }
            code => return Err(http_failure(code, false)),
        }

        // A 200 means the server ignored the range or the validator changed: start over.
        let (resume_from, total) = if status == 206 {
            match header(&resp, "content-range").and_then(|v| parse_content_range(&v)) {
                Some((start, _, total)) if start == offset => (offset, total),
                _ => {
                    self.reset();
                    return Ok(Step::Restart);
                }
            }
        } else {
            let len = header(&resp, "content-length").and_then(|v| v.parse::<u64>().ok());
            (0, len)
        };

        self.save_meta(&Meta {
            url: self.url.to_owned(),
            etag: header(&resp, "etag"),
            last_modified: header(&resp, "last-modified"),
            total,
            seg: None,
        });

        let mut file = if resume_from > 0 {
            OpenOptions::new().append(true).open(&self.part)
        } else {
            OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&self.part)
        }
        .map_err(|e| cannot_write(&self.part, &e))?;

        if resume_from > 0 {
            announce("Resuming", &format!("at {}", human_size(resume_from)));
        }
        let mut progress = Progress::titled(&transfer_title("↓", &self.part), total, resume_from);
        let mut reader = resp.into_body().into_reader();
        let mut buf = vec![0u8; READ_BUF];
        let mut have = resume_from;
        let mut got = 0u64;
        loop {
            match reader.read(&mut buf[..self.read_len()]) {
                Ok(0) => break,
                Ok(n) => {
                    if let Err(why) = self.pace(n) {
                        progress.finish(have);
                        return Err(why);
                    }
                    file.write_all(&buf[..n]).map_err(|e| write_failure(&e))?;
                    have += n as u64;
                    got += n as u64;
                    progress.update(have);
                }
                Err(e) => {
                    progress.finish(have);
                    limits::check()?;
                    return Ok(Step::Transient {
                        msg: describe_io(&e),
                        progressed: got > 0,
                        retry_after: None,
                    });
                }
            }
        }
        progress.finish(have);
        file.sync_data().map_err(|e| write_failure(&e))?;

        match total {
            Some(t) if have < t => Ok(Step::Transient {
                msg: format!(
                    "connection closed after {} of {}",
                    human_size(have),
                    human_size(t)
                ),
                progressed: got > 0,
                retry_after: None,
            }),
            Some(t) if have > t => {
                self.reset();
                Ok(Step::Restart)
            }
            _ => Ok(Step::Complete),
        }
    }
}

/// Verifies and publishes the download, then extracts it when asked.
fn complete(
    d: &Download<'_>,
    dest: &Path,
    args: &GetArgs,
    server: Option<&ServerDigest>,
) -> Result<u8, String> {
    let expected = server.map_or(args.sha256.as_deref(), |s| Some(s.sha256.as_str()));
    let code = finish_download(d, dest, expected, server.map(|s| s.size))?;
    if code == 0 && args.extract {
        extract_archive(dest, args)
            .map_err(|e| format!("downloaded {}, but extraction failed: {e}", dest.display()))?;
    }
    Ok(code)
}

#[cfg(feature = "extract")]
fn extract_archive(dest: &Path, args: &GetArgs) -> Result<(), String> {
    let options = super::extract::Options {
        keep_archive: args.keep_archive,
        verify_first: !args.no_verify_first,
        keep_free: args.keep_free.unwrap_or(1 << 30),
    };
    super::extract::extract(dest, &options).map(|_| ())
}

#[cfg(not(feature = "extract"))]
fn extract_archive(_dest: &Path, _args: &GetArgs) -> Result<(), String> {
    Err("this build of blaze was made without extraction support".to_owned())
}

fn finish_download(
    d: &Download<'_>,
    dest: &Path,
    sha256: Option<&str>,
    size: Option<u64>,
) -> Result<u8, String> {
    if let Some(expected) = size
        && d.part_len() != expected
    {
        let actual = d.part_len();
        d.reset();
        crate::cli::exit::record(crate::cli::exit::INTEGRITY);
        return Err(format!(
            "size mismatch: the server hashed {expected} bytes but the download has {actual}; the file may have changed"
        ));
    }
    if let Some(expected) = sha256 {
        let actual = sha256_file_within(&d.part, limits::check_io).map_err(|e| {
            if e.kind() == std::io::ErrorKind::TimedOut {
                e.to_string()
            } else {
                format!("cannot hash download: {e}")
            }
        })?;
        if !actual.eq_ignore_ascii_case(expected) {
            d.reset();
            crate::cli::exit::record(crate::cli::exit::INTEGRITY);
            return Err(format!(
                "SHA-256 mismatch: expected {expected}, got {actual}"
            ));
        }
    }
    limits::check()?;
    let size = d.part_len();
    rename_with_retry(&d.part, dest)
        .map_err(|e| format!("cannot move download to {}: {e}", dest.display()))?;
    let _ = std::fs::remove_file(&d.meta_path);
    anstream::println!(
        "{} {} ({})",
        Style::stdout().green("Saved"),
        dest.display(),
        human_size(size)
    );
    Ok(0)
}

pub fn get(args: GetArgs) -> Result<u8, String> {
    http_url(&args.url)?;
    if let Some(h) = &args.sha256
        && (h.len() != 64 || !h.chars().all(|c| c.is_ascii_hexdigit()))
    {
        return Err("--sha256 must be 64 hexadecimal characters".to_owned());
    }
    let auth = basic_header(args.auth.as_deref(), args.auth_env.as_deref())?;
    limits::install(&args.timeouts);
    let agent = agent();
    let dest = match &args.output {
        Some(p) => p.clone(),
        None => match server_file_name(&agent, &args.url, auth.as_deref()) {
            Some(name) => PathBuf::from(name),
            None => default_destination(&args.url)?,
        },
    };
    if dest.exists() && !args.force {
        return Err(format!(
            "{} already exists; use --force to replace it",
            dest.display()
        ));
    }

    let server_digest = match args.verify {
        Some(VerifyMode::ServerSha256) => {
            announce("Verifying", "asking the server for the file's SHA-256");
            Some(discover::discover(&args.url, auth.as_deref())?)
        }
        None => None,
    };

    let d = Download {
        agent,
        url: &args.url,
        part: sibling(&dest, ".part"),
        meta_path: sibling(&dest, ".part.meta"),
        auth,
        resume: !args.no_resume,
        throttle: args.limit_rate.map(|r| Arc::new(Throttle::new(r))),
    };
    if !d.resume {
        d.reset();
    }

    if args.connections > POLITE_CONNECTIONS {
        announce(
            "Note",
            &format!(
                "{} connections; some servers limit or block parallel downloads",
                args.connections
            ),
        );
    }
    if args.connections > 1 && segmented::run(&d, usize::from(args.connections), args.retries)? {
        return complete(&d, &dest, &args, server_digest.as_ref());
    }

    let mut fails = 0u32;
    let mut restarts = 0u32;
    loop {
        limits::check()?;
        match d.step()? {
            Step::Complete => return complete(&d, &dest, &args, server_digest.as_ref()),
            Step::Restart => {
                restarts += 1;
                if restarts > MAX_RESTARTS {
                    return Err("server keeps changing the file; giving up".to_owned());
                }
            }
            Step::Transient {
                msg,
                progressed,
                retry_after,
            } => {
                fails = if progressed { 1 } else { fails + 1 };
                if fails > args.retries {
                    return Err(format!(
                        "download failed after {} retries: {msg}",
                        args.retries
                    ));
                }
                let wait = plan_wait(fails, retry_after, jitter())
                    .map_err(|why| format!("download failed: {msg}; {why}"))?;
                limits::fits(wait)?;
                announce(
                    "Retrying",
                    &format!(
                        "{}: {msg}",
                        retry_note(wait, retry_after, fails, args.retries)
                    ),
                );
                std::thread::sleep(wait);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn free_space_accepts_suffixes_and_zero() {
        assert_eq!(parse_free_space("0").unwrap(), 0);
        assert_eq!(parse_free_space("500M").unwrap(), 500 << 20);
        assert_eq!(parse_free_space("2g").unwrap(), 2 << 30);
        assert_eq!(parse_free_space("1.5K").unwrap(), 1536);
        assert!(parse_free_space("lots").is_err());
        assert!(parse_free_space("-1G").is_err());
    }

    #[test]
    fn destination_from_url() {
        assert_eq!(
            default_destination("http://h:1/a/b%20c.bin?x=1").unwrap(),
            PathBuf::from("b c.bin")
        );
        assert_eq!(
            default_destination("http://h:1/").unwrap(),
            PathBuf::from("index.html")
        );
        assert_eq!(
            default_destination("http://h:1").unwrap(),
            PathBuf::from("index.html")
        );
        assert!(default_destination("http://h/a/..%2f..").is_err());
        assert!(default_destination("http://h/a/c%3Ad").is_err());
    }

    #[test]
    fn content_range_parsing() {
        assert_eq!(parse_content_range("bytes 5-9/10"), Some((5, 9, Some(10))));
        assert_eq!(parse_content_range("bytes 5-9/*"), Some((5, 9, None)));
        assert_eq!(parse_content_range("items 5-9/10"), None);
        assert_eq!(parse_unsatisfied_total("bytes */10"), Some(10));
    }
}
