//! Chunked `blaze put` with server-offset resync and content digests.

use super::READ_BUF;
use super::http::{
    agent, basic_header, describe_error, header, http_failure, http_url, transient_error,
    transient_status,
};
use crate::cli::ansi::{Style, announce};
use crate::cli::util::{Progress, backoff, existing_file, human_size};
use base64::Engine as _;
use clap::Args;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

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
            Err(e) if transient_error(&e) => return Ok(Err(describe_error(&e))),
            Err(e) => return Err(describe_error(&e)),
        };
        match resp.status().as_u16() {
            404 => Ok(Ok(0)),
            200 => match header(&resp, "upload-offset").and_then(|v| v.parse().ok()) {
                Some(n) => Ok(Ok(n)),
                None => Err("destination already exists on the server".to_owned()),
            },
            code if transient_status(code) => Ok(Err(format!("server returned HTTP {code}"))),
            code => Err(http_failure(code, true)),
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
                    msg: describe_error(&e),
                    resync: true,
                });
            }
            Err(e) => return Err(describe_error(&e)),
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
            code => Err(http_failure(code, true)),
        }
    }
}

pub fn put(args: PutArgs) -> Result<u8, String> {
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
                anstream::println!(
                    "{} {} ({})",
                    Style::stdout().green("Uploaded"),
                    args.file.display(),
                    human_size(total)
                );
                return Ok(0);
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
                announce(
                    "Retrying",
                    &format!(
                        "in {}s (attempt {fails} of {}): {msg}",
                        backoff(fails).as_secs().max(1),
                        args.retries
                    ),
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
