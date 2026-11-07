use super::serve::resolve_auth;
use super::util::{Progress, backoff, existing_file, human_size, sha256_file};
use base64::Engine as _;
use clap::Args;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, percent_decode_str, utf8_percent_encode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

const READ_BUF: usize = 256 * 1024;
const SEGMENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'.')
    .remove(b'-')
    .remove(b'_')
    .remove(b'~');
const MAX_RESTARTS: u32 = 3;

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
}

#[derive(Args, Debug)]
pub struct PutArgs {
    /// File to upload
    #[arg(value_parser = existing_file)]
    pub file: PathBuf,
    /// Destination URL, or a server origin to upload under /__upload__/
    pub url: String,
    /// Bytes sent per request in MB
    #[arg(long, default_value_t = 8, value_parser = clap::value_parser!(u64).range(1..=256))]
    pub chunk_mb: u64,
    /// Load USER:PASS from an environment variable
    #[arg(long, value_name = "ENVVAR")]
    pub auth_env: Option<String>,
    /// HTTP Basic Auth credentials
    #[arg(long, value_name = "USER:PASS")]
    pub auth: Option<String>,
    /// Consecutive failed attempts allowed before giving up
    #[arg(long, default_value_t = 5, value_parser = clap::value_parser!(u32).range(0..=100))]
    pub retries: u32,
}

#[derive(Serialize, Deserialize, Default)]
struct Meta {
    url: String,
    etag: Option<String>,
    last_modified: Option<String>,
    total: Option<u64>,
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(None)
        .timeout_connect(Some(Duration::from_secs(15)))
        .timeout_recv_response(Some(Duration::from_secs(60)))
        .build()
        .into()
}

fn basic_header(auth: Option<&str>, auth_env: Option<&str>) -> Result<Option<String>, String> {
    Ok(resolve_auth(auth, auth_env)?.map(|c| {
        let raw = format!("{}:{}", c.user, c.password);
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(raw)
        )
    }))
}

fn http_url(url: &str) -> Result<(), String> {
    if url.starts_with("http://") || url.starts_with("https://") {
        Ok(())
    } else {
        Err("URL must start with http:// or https://".to_owned())
    }
}

fn transient_error(e: &ureq::Error) -> bool {
    !matches!(e, ureq::Error::BadUri(_) | ureq::Error::Http(_))
}

fn transient_status(code: u16) -> bool {
    matches!(code, 408 | 425 | 429) || (500..=599).contains(&code)
}

fn header(resp: &ureq::http::Response<ureq::Body>, name: &str) -> Option<String> {
    resp.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
}

fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut s: OsString = path.as_os_str().to_owned();
    s.push(suffix);
    PathBuf::from(s)
}

/// Security software and indexers briefly hold new files open on Windows, which makes
/// an immediate rename fail with a sharing violation.
fn rename_with_retry(from: &Path, to: &Path) -> std::io::Result<()> {
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

fn parse_content_range(v: &str) -> Option<(u64, u64, Option<u64>)> {
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

struct Download<'a> {
    agent: ureq::Agent,
    url: &'a str,
    part: PathBuf,
    meta_path: PathBuf,
    auth: Option<String>,
    resume: bool,
}

impl Download<'_> {
    fn reset(&self) {
        let _ = std::fs::remove_file(&self.part);
        let _ = std::fs::remove_file(&self.meta_path);
    }

    fn part_len(&self) -> u64 {
        std::fs::metadata(&self.part).map_or(0, |m| m.len())
    }

    fn load_meta(&self) -> Option<Meta> {
        let raw = std::fs::read(&self.meta_path).ok()?;
        serde_json::from_slice(&raw).ok()
    }

    fn save_meta(&self, meta: &Meta) {
        if let Ok(raw) = serde_json::to_vec(meta) {
            let _ = std::fs::write(&self.meta_path, raw);
        }
    }

    fn step(&self) -> Result<Step, String> {
        let known = self.load_meta().filter(|m| m.url == self.url);
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
                    msg: e.to_string(),
                    progressed: false,
                });
            }
            Err(e) => return Err(e.to_string()),
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
            code => return Err(format!("server returned HTTP {code}")),
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

fn finish_download(
    d: &Download<'_>,
    dest: &Path,
    sha256: Option<&str>,
) -> Result<ExitCode, String> {
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
    println!("Saved {} ({})", dest.display(), human_size(size));
    Ok(ExitCode::SUCCESS)
}

pub fn get(args: GetArgs) -> Result<ExitCode, String> {
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
                eprintln!(
                    "Retrying in {}s (attempt {fails} of {}): {msg}",
                    wait.as_secs().max(1),
                    args.retries
                );
                std::thread::sleep(wait);
            }
        }
    }
}

fn upload_target(url: &str, file: &Path) -> Result<String, String> {
    http_url(url)?;
    if url.contains("/__upload__/") {
        return Ok(url.to_owned());
    }
    let name = file
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| "file name is not valid UTF-8".to_owned())?;
    Ok(format!(
        "{}/__upload__/{}",
        url.trim_end_matches('/'),
        utf8_percent_encode(name, SEGMENT)
    ))
}

fn digest_header(bytes: &[u8]) -> String {
    let d = Sha256::digest(bytes);
    format!(
        "sha-256=:{}:",
        base64::engine::general_purpose::STANDARD.encode(d)
    )
}

fn whole_file_digest(path: &Path) -> Result<String, String> {
    let fail = |e: std::io::Error| format!("cannot hash {}: {e}", path.display());
    let mut file = File::open(path).map_err(fail)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; READ_BUF];
    loop {
        let n = file.read(&mut buf).map_err(fail)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!(
        "sha-256=:{}:",
        base64::engine::general_purpose::STANDARD.encode(hasher.finalize())
    ))
}

enum Sent {
    Done,
    Advanced(u64),
    Retry { msg: String, resync: bool },
}

struct Upload<'a> {
    agent: ureq::Agent,
    url: &'a str,
    auth: Option<String>,
    total: u64,
    repr_digest: String,
}

impl Upload<'_> {
    fn authorize<B>(&self, mut req: ureq::RequestBuilder<B>) -> ureq::RequestBuilder<B> {
        if let Some(a) = &self.auth {
            req = req.header("Authorization", a);
        }
        req
    }

    fn remote_offset(&self) -> Result<Result<u64, String>, String> {
        let resp = match self.authorize(self.agent.head(self.url)).call() {
            Ok(r) => r,
            Err(e) if transient_error(&e) => return Ok(Err(e.to_string())),
            Err(e) => return Err(e.to_string()),
        };
        match resp.status().as_u16() {
            404 => Ok(Ok(0)),
            200 => match header(&resp, "upload-offset").and_then(|v| v.parse().ok()) {
                Some(n) => Ok(Ok(n)),
                None => Err("destination already exists on the server".to_owned()),
            },
            code if transient_status(code) => Ok(Err(format!("server returned HTTP {code}"))),
            code => Err(format!("server returned HTTP {code}")),
        }
    }

    fn send(&self, offset: u64, chunk: &[u8]) -> Result<Sent, String> {
        let end = offset + chunk.len() as u64;
        let last = end >= self.total;
        let mut req = self
            .agent
            .put(self.url)
            .header("Content-Digest", digest_header(chunk));
        req = if chunk.is_empty() {
            req.header("Content-Range", format!("bytes */{}", self.total))
        } else {
            req.header(
                "Content-Range",
                format!("bytes {offset}-{}/{}", end - 1, self.total),
            )
        };
        if last {
            req = req.header("Repr-Digest", &self.repr_digest);
        }
        let resp = match self.authorize(req).send(chunk) {
            Ok(r) => r,
            Err(e) if transient_error(&e) => {
                return Ok(Sent::Retry {
                    msg: e.to_string(),
                    resync: true,
                });
            }
            Err(e) => return Err(e.to_string()),
        };
        match resp.status().as_u16() {
            200 | 201 | 204 if last => Ok(Sent::Done),
            200..=299 => {
                let next = header(&resp, "upload-offset")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(end);
                Ok(Sent::Advanced(next))
            }
            409 | 416 => Ok(Sent::Retry {
                msg: "server offset changed".to_owned(),
                resync: true,
            }),
            code if transient_status(code) => Ok(Sent::Retry {
                msg: format!("server returned HTTP {code}"),
                resync: true,
            }),
            code => Err(format!("server returned HTTP {code}")),
        }
    }
}

pub fn put(args: PutArgs) -> Result<ExitCode, String> {
    let url = upload_target(&args.url, &args.file)?;
    let auth = basic_header(args.auth.as_deref(), args.auth_env.as_deref())?;
    let total = std::fs::metadata(&args.file)
        .map_err(|e| e.to_string())?
        .len();
    let up = Upload {
        agent: agent(),
        url: &url,
        auth,
        total,
        repr_digest: whole_file_digest(&args.file)?,
    };

    let mut file =
        File::open(&args.file).map_err(|e| format!("cannot open {}: {e}", args.file.display()))?;
    let chunk_size = (args.chunk_mb * 1024 * 1024) as usize;
    let mut buf = vec![0u8; chunk_size.min(total.max(1) as usize)];
    let mut offset = 0u64;
    let mut fails = 0u32;
    let mut need_sync = true;
    let mut progress = Progress::new(Some(total), 0);

    loop {
        if need_sync {
            match up.remote_offset()? {
                Ok(n) => offset = n.min(total),
                Err(msg) => {
                    fails += 1;
                    if fails > args.retries {
                        return Err(format!(
                            "upload failed after {} retries: {msg}",
                            args.retries
                        ));
                    }
                    std::thread::sleep(backoff(fails));
                    continue;
                }
            }
            need_sync = false;
        }

        let want = ((total - offset) as usize).min(buf.len());
        file.seek(SeekFrom::Start(offset))
            .map_err(|e| e.to_string())?;
        file.read_exact(&mut buf[..want])
            .map_err(|e| format!("read failed: {e}"))?;

        match up.send(offset, &buf[..want])? {
            Sent::Done => {
                progress.finish(total);
                println!("Uploaded {} ({})", args.file.display(), human_size(total));
                return Ok(ExitCode::SUCCESS);
            }
            Sent::Advanced(next) => {
                fails = 0;
                offset = next.min(total);
                progress.update(offset);
            }
            Sent::Retry { msg, resync } => {
                fails += 1;
                if fails > args.retries {
                    return Err(format!(
                        "upload failed after {} retries: {msg}",
                        args.retries
                    ));
                }
                eprintln!(
                    "Retrying in {}s (attempt {fails} of {}): {msg}",
                    backoff(fails).as_secs().max(1),
                    args.retries
                );
                std::thread::sleep(backoff(fails));
                need_sync = resync;
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

    #[test]
    fn upload_target_appends_name() {
        let t = upload_target("http://h:8000/", Path::new("dir/my file.bin")).unwrap();
        assert_eq!(t, "http://h:8000/__upload__/my%20file.bin");
        assert_eq!(
            upload_target("http://h/__upload__/x", Path::new("y")).unwrap(),
            "http://h/__upload__/x"
        );
    }

    #[test]
    fn digest_header_format() {
        assert_eq!(
            digest_header(b""),
            "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:"
        );
    }
}
