//! Chunked `blaze put` with server-offset resync and content digests.

use super::READ_BUF;
use super::error::TransferError;
use super::http::{
    agent, basic_header, describe_error, header, http_failure, http_url, retry_hint,
    transient_error, transient_status,
};
use super::limits::{self, TimeoutArgs};
use super::retry::{jitter, plan_wait, retry_note};
use super::throttle::{Paced, Throttle, parse_rate};
use crate::cli::ansi::{Style, announce};
use crate::cli::jobs::{self, tracker};
use crate::cli::util::{Progress, existing_file, human_size, print_summary, transfer_title};
use crate::usage::{self, trace};
use base64::Engine as _;
use clap::Args;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::Duration;
use ureq::SendBody;

const SEGMENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'.')
    .remove(b'-')
    .remove(b'_')
    .remove(b'~');

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
    /// Replace an existing file only if its current ETag is this value, e.g. '"3f2a9c"'
    ///
    /// Read the current ETag from a HEAD or GET response (curl -I URL). The upload fails
    /// with HTTP 412 if the file changed or is missing, and is never retried against a
    /// newer version. Without this option an existing file is never replaced.
    #[arg(long, value_name = "ETAG", value_parser = parse_etag)]
    pub if_match: Option<String>,
    /// Cap upload body speed in bytes per second, e.g. 500K, 2M or 1.5M (minimum 1K)
    ///
    /// Counts request-body bytes, including any that are sent again after a retry. It is
    /// not an exact cap on TLS and TCP overhead.
    #[arg(long, value_name = "RATE", value_parser = parse_rate)]
    pub limit_rate: Option<u64>,
    #[command(flatten)]
    pub timeouts: TimeoutArgs,
    #[command(flatten)]
    pub bg: jobs::BackgroundArgs,
}

/// A single strong entity tag. Weak tags and `*` cannot guard a replacement.
fn parse_etag(raw: &str) -> Result<String, String> {
    let tag = raw.trim();
    let inner = tag
        .strip_prefix('"')
        .and_then(|t| t.strip_suffix('"'))
        .ok_or("the ETag must be a quoted strong validator such as '\"abc\"'")?;
    if inner.contains('"') || inner.contains(',') || inner.chars().any(|c| c.is_ascii_control()) {
        return Err("the ETag must be exactly one quoted validator".to_owned());
    }
    Ok(tag.to_owned())
}

fn upload_target(url: &str, file: &Path) -> Result<String, TransferError> {
    http_url(url)?;
    if url.contains("/__upload__/") {
        return Ok(url.to_owned());
    }
    let name = file
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| TransferError::Usage("file name is not valid UTF-8".to_owned()))?;
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

fn whole_file_digest(path: &Path) -> Result<String, TransferError> {
    let fail =
        |e: std::io::Error| TransferError::Io(format!("cannot hash {}: {e}", path.display()));
    let mut file = File::open(path).map_err(fail)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; READ_BUF];
    loop {
        limits::check()?;
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

/// An offset, or a transient failure with the server's `Retry-After` if it sent one.
type Probed = Result<u64, (String, Option<Duration>)>;

enum Sent {
    Done,
    Advanced(u64),
    Retry {
        msg: String,
        resync: bool,
        retry_after: Option<Duration>,
    },
}

struct Upload<'a> {
    agent: ureq::Agent,
    url: &'a str,
    auth: Option<String>,
    total: u64,
    repr_digest: String,
    if_match: Option<String>,
    throttle: Option<Throttle>,
}

impl Upload<'_> {
    fn authorize<B>(&self, mut req: ureq::RequestBuilder<B>) -> ureq::RequestBuilder<B> {
        if let Some(a) = &self.auth {
            req = req.header("Authorization", a);
        }
        req
    }

    /// The server says what it stored; a different digest means the copy is not the file.
    fn check_stored(&self, stored: Option<&str>) -> Result<(), TransferError> {
        match stored {
            Some(stored) if stored.starts_with("sha-256=") && stored != self.repr_digest => {
                Err(TransferError::Integrity(
                    "the server stored something other than the file that was sent".to_owned(),
                ))
            }
            _ => Ok(()),
        }
    }

    /// `staged_is_ours` says this run already sent a chunk, so a staged partial can only be
    /// its own. A replacement never adopts a staged partial it cannot identify.
    fn remote_offset(&self, staged_is_ours: bool) -> Result<Probed, TransferError> {
        let resp = match limits::bound(self.authorize(self.agent.head(self.url))).call() {
            Ok(r) => r,
            Err(e) if transient_error(&e) => return Ok(Err((describe_error(&e), None))),
            Err(e) => return Err(TransferError::Network(describe_error(&e))),
        };
        if self.if_match.is_some() {
            return match resp.status().as_u16() {
                404 => Err(TransferError::Http(
                    "nothing to replace: the destination does not exist".to_owned(),
                )),
                200 if header(&resp, "upload-complete").as_deref() == Some("?1") => Ok(Ok(0)),
                200 => match header(&resp, "upload-offset").and_then(|v| v.parse().ok()) {
                    Some(0) => Ok(Ok(0)),
                    Some(n) if staged_is_ours => Ok(Ok(n)),
                    _ => Err(TransferError::Unstable(
                        "a partial upload of unknown origin is staged at the destination; \
                              finish or discard it, then retry"
                            .to_owned(),
                    )),
                },
                code if transient_status(code) => Ok(Err((
                    format!("server returned HTTP {code}"),
                    retry_hint(&resp, code),
                ))),
                code => Err(http_failure(code, true)),
            };
        }
        match resp.status().as_u16() {
            404 => Ok(Ok(0)),
            200 => match header(&resp, "upload-offset").and_then(|v| v.parse().ok()) {
                Some(n) => Ok(Ok(n)),
                None => Err(TransferError::Http(
                    "destination already exists on the server".to_owned(),
                )),
            },
            code if transient_status(code) => Ok(Err((
                format!("server returned HTTP {code}"),
                retry_hint(&resp, code),
            ))),
            code => Err(http_failure(code, true)),
        }
    }

    fn send(&self, offset: u64, chunk: &[u8]) -> Result<Sent, TransferError> {
        let end = offset + chunk.len() as u64;
        let last = end >= self.total;
        let mut req = self
            .agent
            .put(self.url)
            .header("Content-Digest", digest_header(chunk));
        // The server has no range form for zero bytes, so an empty file is a plain PUT.
        req = if self.total == 0 {
            req
        } else {
            req.header(
                "Content-Range",
                format!("bytes {offset}-{}/{}", end - 1, self.total),
            )
        };
        if let Some(tag) = &self.if_match {
            req = req.header("If-Match", tag);
        }
        if last {
            req = req.header("Repr-Digest", &self.repr_digest);
        }
        let sent = match &self.throttle {
            Some(throttle) => {
                let mut body = Paced {
                    inner: chunk,
                    throttle,
                };
                limits::bound(self.authorize(req.header("Content-Length", chunk.len().to_string())))
                    .send(SendBody::from_reader(&mut body))
            }
            None => limits::bound(self.authorize(req)).send(chunk),
        };
        let resp = match sent {
            Ok(r) => r,
            Err(e) if transient_error(&e) => {
                return Ok(Sent::Retry {
                    msg: describe_error(&e),
                    resync: true,
                    retry_after: None,
                });
            }
            Err(e) => return Err(TransferError::Network(describe_error(&e))),
        };
        match resp.status().as_u16() {
            200 | 201 | 204 if last => {
                self.check_stored(header(&resp, "content-digest").as_deref())?;
                Ok(Sent::Done)
            }
            200..=299 => {
                let next = header(&resp, "upload-offset")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(end);
                Ok(Sent::Advanced(next))
            }
            409 | 416 => Ok(Sent::Retry {
                msg: "server offset changed".to_owned(),
                resync: true,
                retry_after: None,
            }),
            code if transient_status(code) => Ok(Sent::Retry {
                msg: format!("server returned HTTP {code}"),
                resync: true,
                retry_after: retry_hint(&resp, code),
            }),
            code => Err(http_failure(code, true)),
        }
    }
}

pub fn put(args: PutArgs) -> Result<u8, TransferError> {
    let url = upload_target(&args.url, &args.file)?;
    let auth = basic_header(args.auth.as_deref(), args.auth_env.as_deref())?;
    limits::install(&args.timeouts);
    let total = std::fs::metadata(&args.file)
        .map_err(|e| TransferError::Io(e.to_string()))?
        .len();
    jobs::ready(|| jobs::Info {
        label: args
            .file
            .file_name()
            .map_or_else(String::new, |n| n.to_string_lossy().into_owned()),
        url: Some(url.clone()),
        direction: Some(jobs::Direction::Upload),
        listen: None,
    });
    trace::note("size_bucket", usage::bytes_bucket(total));
    let repr_digest = {
        let _hashing = trace::phase("hash_ms");
        whole_file_digest(&args.file)?
    };
    let up = Upload {
        agent: agent(),
        url: &url,
        auth,
        total,
        repr_digest,
        if_match: args.if_match.clone(),
        throttle: args.limit_rate.map(Throttle::new),
    };

    let mut file = File::open(&args.file)
        .map_err(|e| TransferError::Io(format!("cannot open {}: {e}", args.file.display())))?;
    let chunk_size = (args.chunk_mb * 1024 * 1024) as usize;
    let mut buf = vec![0u8; chunk_size.min(total.max(1) as usize)];
    let mut offset = 0u64;
    let mut fails = 0u32;
    let mut need_sync = true;
    let mut sent_any = false;
    let mut progress = Progress::titled(&transfer_title("↑", &args.file), Some(total), 0);
    let mut transferring = Some(trace::phase("transfer_ms"));
    let mut retries = 0u32;

    loop {
        limits::check()?;
        tracker::check().map_err(TransferError::Interrupted)?;
        if need_sync {
            match up.remote_offset(sent_any)? {
                Ok(n) => {
                    offset = n.min(total);
                    progress.rebase(offset);
                }
                Err((msg, retry_after)) => {
                    fails += 1;
                    pause(fails, args.retries, &msg, retry_after)?;
                    continue;
                }
            }
            need_sync = false;
        }

        let want = ((total - offset) as usize).min(buf.len());
        file.seek(SeekFrom::Start(offset))
            .map_err(|e| TransferError::Io(e.to_string()))?;
        file.read_exact(&mut buf[..want])
            .map_err(|e| TransferError::Io(format!("read failed: {e}")))?;

        if offset + want as u64 >= total {
            tracker::set_phase(jobs::Phase::Finalizing);
        }
        sent_any = true;
        match up.send(offset, &buf[..want])? {
            Sent::Done => {
                progress.finish(total);
                drop(transferring.take());
                if !crate::cli::ansi::quiet() && !crate::cli::ansi::json_progress() {
                    anstream::println!(
                        "{} {} ({})",
                        Style::stdout().green("Uploaded"),
                        args.file.display(),
                        human_size(total)
                    );
                    print_summary(total, true);
                }
                crate::cli::ansi::done_event(&args.file, total);
                return Ok(0);
            }
            Sent::Advanced(next) => {
                fails = 0;
                offset = next.min(total);
                progress.update(offset);
            }
            Sent::Retry {
                msg,
                resync,
                retry_after,
            } => {
                retries += 1;
                trace::note("retries", retries);
                fails += 1;
                pause(fails, args.retries, &msg, retry_after)?;
                need_sync = resync;
            }
        }
    }
}

/// Fails once the retries are spent or the server asks for more time than is accepted,
/// otherwise announces and sits out the wait.
fn pause(
    fails: u32,
    retries: u32,
    msg: &str,
    retry_after: Option<Duration>,
) -> Result<(), TransferError> {
    if fails > retries {
        return Err(TransferError::Network(format!(
            "upload failed after {retries} retries: {msg}"
        )));
    }
    let wait = plan_wait(fails, retry_after, jitter())
        .map_err(|why| TransferError::Network(format!("upload failed: {msg}; {why}")))?;
    limits::fits(wait)?;
    announce(
        "Retrying",
        &format!("{}: {msg}", retry_note(wait, retry_after, fails, retries)),
    );
    tracker::retry_wait(wait).map_err(TransferError::Interrupted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upload_target_appends_name() {
        let t = upload_target("http://h:5949/", Path::new("dir/my file.bin")).unwrap();
        assert_eq!(t, "http://h:5949/__upload__/my%20file.bin");
        assert_eq!(
            upload_target("http://h/__upload__/x", Path::new("y")).unwrap(),
            "http://h/__upload__/x"
        );
    }

    #[test]
    fn a_different_stored_digest_is_an_integrity_failure() {
        let up = Upload {
            agent: agent(),
            url: "http://h",
            auth: None,
            total: 0,
            repr_digest: digest_header(b""),
            if_match: None,
            throttle: None,
        };
        assert!(up.check_stored(Some(&digest_header(b""))).is_ok());
        assert!(up.check_stored(None).is_ok(), "older servers send none");
        let err = up.check_stored(Some(&digest_header(b"x"))).unwrap_err();
        assert_eq!(err.code(), crate::cli::exit::INTEGRITY);
    }

    #[test]
    fn digest_header_format() {
        assert_eq!(
            digest_header(b""),
            "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:"
        );
    }
}
