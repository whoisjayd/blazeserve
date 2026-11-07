//! Resumable `blaze get`: sidecar metadata, range handling and verified finish.

use super::READ_BUF;
use super::http::{
    agent, basic_header, describe_error, header, http_failure, http_url, transient_error,
    transient_status,
};
use super::segmented::{self, SegMeta};
use crate::cli::ansi::{Style, announce};
use crate::cli::util::{Progress, backoff, human_size, sha256_file};
use clap::Args;
use percent_encoding::percent_decode_str;
use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

pub(super) const MAX_RESTARTS: u32 = 3;

#[derive(Args, Debug)]
pub struct GetArgs {
    /// URL to download
    pub url: String,
    /// Destination file (default: last URL path segment)
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
    /// Parallel connections for large files (1 downloads in a single stream)
    #[arg(short = 'c', long, value_name = "N", default_value_t = 4, value_parser = clap::value_parser!(u8).range(1..=16))]
    pub connections: u8,
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
    Transient { msg: String, progressed: bool },
}

pub(super) struct Download<'a> {
    pub(super) agent: ureq::Agent,
    pub(super) url: &'a str,
    pub(super) part: PathBuf,
    pub(super) meta_path: PathBuf,
    pub(super) auth: Option<String>,
    pub(super) resume: bool,
}

impl Download<'_> {
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

        let resp = match req.call() {
            Ok(r) => r,
            Err(e) if transient_error(&e) => {
                return Ok(Step::Transient {
                    msg: describe_error(&e),
                    progressed: false,
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
        .map_err(|e| format!("cannot write {}: {e}", self.part.display()))?;

        if resume_from > 0 {
            announce("Resuming", &format!("at {}", human_size(resume_from)));
        }
        let mut progress = Progress::new(total, resume_from);
        let mut reader = resp.into_body().into_reader();
        let mut buf = vec![0u8; READ_BUF];
        let mut have = resume_from;
        let mut got = 0u64;
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    file.write_all(&buf[..n])
                        .map_err(|e| format!("write failed: {e}"))?;
                    have += n as u64;
                    got += n as u64;
                    progress.update(have);
                }
                Err(e) => {
                    progress.finish(have);
                    return Ok(Step::Transient {
                        msg: e.to_string(),
                        progressed: got > 0,
                    });
                }
            }
        }
        progress.finish(have);
        file.sync_data().map_err(|e| format!("write failed: {e}"))?;

        match total {
            Some(t) if have < t => Ok(Step::Transient {
                msg: format!(
                    "connection closed after {} of {}",
                    human_size(have),
                    human_size(t)
                ),
                progressed: got > 0,
            }),
            Some(t) if have > t => {
                self.reset();
                Ok(Step::Restart)
            }
            _ => Ok(Step::Complete),
        }
    }
}

fn finish_download(d: &Download<'_>, dest: &Path, sha256: Option<&str>) -> Result<u8, String> {
    if let Some(expected) = sha256 {
        let actual = sha256_file(&d.part).map_err(|e| format!("cannot hash download: {e}"))?;
        if !actual.eq_ignore_ascii_case(expected) {
            d.reset();
            return Err(format!(
                "SHA-256 mismatch: expected {expected}, got {actual}"
            ));
        }
    }
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
    let dest = match &args.output {
        Some(p) => p.clone(),
        None => default_destination(&args.url)?,
    };
    if dest.exists() && !args.force {
        return Err(format!(
            "{} already exists; use --force to replace it",
            dest.display()
        ));
    }

    let d = Download {
        agent: agent(),
        url: &args.url,
        part: sibling(&dest, ".part"),
        meta_path: sibling(&dest, ".part.meta"),
        auth,
        resume: !args.no_resume,
    };
    if !d.resume {
        d.reset();
    }

    if args.connections > 1 && segmented::run(&d, usize::from(args.connections), args.retries)? {
        return finish_download(&d, &dest, args.sha256.as_deref());
    }

    let mut fails = 0u32;
    let mut restarts = 0u32;
    loop {
        match d.step()? {
            Step::Complete => return finish_download(&d, &dest, args.sha256.as_deref()),
            Step::Restart => {
                restarts += 1;
                if restarts > MAX_RESTARTS {
                    return Err("server keeps changing the file; giving up".to_owned());
                }
            }
            Step::Transient { msg, progressed } => {
                fails = if progressed { 1 } else { fails + 1 };
                if fails > args.retries {
                    return Err(format!(
                        "download failed after {} retries: {msg}",
                        args.retries
                    ));
                }
                let wait = backoff(fails);
                announce(
                    "Retrying",
                    &format!(
                        "in {}s (attempt {fails} of {}): {msg}",
                        wait.as_secs().max(1),
                        args.retries
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
